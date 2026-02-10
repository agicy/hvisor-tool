// SPDX-License-Identifier: GPL-2.0-only
/**
 * Copyright (c) 2025 Syswonder
 *
 * Syswonder Website:
 *      https://www.syswonder.org
 *
 * Authors:
 *      Guowei Li <2401213322@stu.pku.edu.cn>
 */
#define _GNU_SOURCE

#include "virtio_console.h"
#include "log.h"
#include "virtio.h"
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <termios.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <pthread.h>
#include <liburing.h>

static uint8_t trashbuf[1024];

ConsoleDev *init_console_dev() {
    ConsoleDev *dev = (ConsoleDev *)malloc(sizeof(ConsoleDev));
    dev->config.cols = 80;
    dev->config.rows = 25;
    dev->master_fd = -1;
    dev->rx_ready = -1;
    dev->event = NULL;
    dev->pending_rx_req = NULL;
    return dev;
}

static void virtio_console_rx_completion_handler(void *param, int res) {
    struct console_req *req = (struct console_req *)param;
    VirtIODevice *vdev = req->vdev;
    // ConsoleDev *dev = vdev->dev;
    VirtQueue *vq = req->vq;

    if (res == -EAGAIN) {
        ConsoleDev *dev = (ConsoleDev *)vdev->dev;
        dev->pending_rx_req = req;
        return;
    }

    if (res < 0) {
        if (res != -ECANCELED)
             log_trace("console rx error: %d", res);
        res = 0;
    }
    
    update_used_ring(vq, req->idx, res);
    virtio_inject_irq(vq);
    
    free(req->iov);
    free(req);
}

static void virtio_console_event_handler(int fd, int epoll_type, void *param) {
    // log_debug("%s", __func__);
    VirtIODevice *vdev = (VirtIODevice *)param;
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;
    VirtQueue *vq = &vdev->vqs[CONSOLE_QUEUE_RX];
    
    if (epoll_type != POLLIN || fd != dev->master_fd) {
        log_error("Invalid console event");
        return;
    }
    if (dev->master_fd <= 0 || vdev->type != VirtioTConsole) {
        log_error("console event handler should not be called");
        return;
    }

    if (dev->pending_rx_req) {
        struct console_req *req = dev->pending_rx_req;
        dev->pending_rx_req = NULL;
        
        struct io_uring *ring = get_global_ring();
        pthread_mutex_t *ring_mutex = get_global_ring_mutex();
        pthread_mutex_lock(ring_mutex);
        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
        io_uring_prep_readv(sqe, dev->master_fd, req->iov, req->iovcnt, 0);
        io_uring_sqe_set_data(sqe, &req->hevent);
        io_uring_submit(ring);
        pthread_mutex_unlock(ring_mutex);
        return;
    }

    if (dev->rx_ready <= 0) {
        read(dev->master_fd, trashbuf, sizeof(trashbuf));
        return;
    }
    if (virtqueue_is_empty(vq)) {
        disable_event_poll(dev->event);
        virtio_inject_irq(vq);
        return;
    }

    struct console_req *req = calloc(1, sizeof(struct console_req));
    uint16_t idx;
    struct iovec *iov = NULL;
    int n = process_descriptor_chain(vq, &idx, &iov, NULL, 0, false);
    if (n < 1) {
        free(req);
        // log_error("process_descriptor_chain failed");
        return;
    }

    req->iov = iov;
    req->iovcnt = n;
    req->idx = idx;
    req->vdev = vdev;
    req->vq = vq;
    req->hevent.completion_handler = virtio_console_rx_completion_handler;
    req->hevent.param = req;
    req->hevent.free_on_completion = false;

    struct io_uring *ring = get_global_ring();
    pthread_mutex_t *ring_mutex = get_global_ring_mutex();
    pthread_mutex_lock(ring_mutex);
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_readv(sqe, dev->master_fd, req->iov, req->iovcnt, 0);
    io_uring_sqe_set_data(sqe, &req->hevent);
    io_uring_submit(ring);
    pthread_mutex_unlock(ring_mutex);
}

static void virtio_console_kick_handler(int fd, int epoll_type, void *param) {
    VirtIODevice *vdev = (VirtIODevice *)param;
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;
    uint64_t val;
    read(fd, &val, sizeof(val));
    virtio_console_txq_process(vdev, &vdev->vqs[CONSOLE_QUEUE_TX]);
    virtio_console_rxq_process(vdev, &vdev->vqs[CONSOLE_QUEUE_RX]);
}

int virtio_console_init(VirtIODevice *vdev) {
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;
    int master_fd, slave_fd;
    char *slave_name;
    struct termios term_io;

    master_fd = posix_openpt(O_RDWR | O_NOCTTY);
    if (master_fd < 0) {
        log_error("Failed to open master pty, errno is %d", errno);
    }
    if (grantpt(master_fd) < 0) {
        log_error("Failed to grant pty, errno is %d", errno);
    }
    if (unlockpt(master_fd) < 0) {
        log_error("Failed to unlock pty, errno is %d", errno);
    }
    dev->master_fd = master_fd;

    slave_name = ptsname(master_fd);
    if (slave_name == NULL) {
        log_error("Failed to get slave name, errno is %d", errno);
    }
    log_info("char device redirected to %s", slave_name);
    // Disable line discipline to prevent the TTY
    // from echoing the characters sent from the master back to the master.
    slave_fd = open(slave_name, O_RDWR);
    tcgetattr(slave_fd, &term_io);
    cfmakeraw(&term_io);
    tcsetattr(slave_fd, TCSAFLUSH, &term_io);
    close(slave_fd);

    if (set_nonblocking(dev->master_fd) < 0) {
        dev->master_fd = -1;
        close(dev->master_fd);
        log_error("Failed to set nonblocking mode, fd closed!");
    }

    // Init worker
    dev->kick_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (dev->kick_fd < 0) {
        log_error("eventfd failed");
        return -1;
    }

    add_event(dev->kick_fd, POLLIN, virtio_console_kick_handler, vdev);
    dev->event = add_event(dev->master_fd, POLLIN, virtio_console_event_handler, vdev);

    vdev->virtio_close = virtio_console_close;
    return 0;
}

static void virtio_console_rxq_process(VirtIODevice *vdev, VirtQueue *vq) {
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;
    virtio_console_event_handler(dev->master_fd, POLLIN, vdev);
}

static void virtio_console_txq_process(VirtIODevice *vdev, VirtQueue *vq) {
    int quota = 64;
    while (!virtqueue_is_empty(vq) && quota > 0) {
        virtqueue_disable_notify(vq);
        while (!virtqueue_is_empty(vq) && quota > 0) {
            virtq_tx_handle_one_request(vdev->dev, vq);
            quota--;
        }
        virtqueue_enable_notify(vq);
    }
    if (!virtqueue_is_empty(vq)) {
        ConsoleDev *dev = (ConsoleDev *)vdev->dev;
        uint64_t val = 1;
        write(dev->kick_fd, &val, sizeof(val));
    }
}

int virtio_console_rxq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    log_debug("%s", __func__);
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;
    uint64_t val = 1;
    enable_event_poll(dev->event);
    write(dev->kick_fd, &val, sizeof(val));
    return 0;
}

static void virtio_console_tx_completion_handler(void *param, int res) {
    struct console_req *req = (struct console_req *)param;
    VirtQueue *vq = req->vq;
    
    if (res < 0) {
        log_error("console tx error: %d", res);
        res = 0;
    }
    
    update_used_ring(vq, req->idx, 0); 
    free(req->iov);
    free(req);
}

static void virtq_tx_handle_one_request(ConsoleDev *dev, VirtQueue *vq) {
    VirtIODevice *vdev = vq->dev;
    int n;
    uint16_t idx;
    struct iovec *iov = NULL;
    if (dev->master_fd <= 0) {
        log_error("Console master fd is not ready");
        return;
    }

    n = process_descriptor_chain(vq, &idx, &iov, NULL, 0, false);

    if (n < 1) {
        return;
    }

    struct console_req *req = calloc(1, sizeof(struct console_req));
    req->iov = iov;
    req->iovcnt = n;
    req->idx = idx;
    req->vdev = vdev;
    req->vq = vq;
    req->hevent.completion_handler = virtio_console_tx_completion_handler;
    req->hevent.param = req;
    req->hevent.free_on_completion = false;
    
    struct io_uring *ring = get_global_ring();
    pthread_mutex_t *ring_mutex = get_global_ring_mutex();
    pthread_mutex_lock(ring_mutex);
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_writev(sqe, dev->master_fd, req->iov, req->iovcnt, 0);
    io_uring_sqe_set_data(sqe, &req->hevent);
    io_uring_submit(ring);
    pthread_mutex_unlock(ring_mutex);
}

int virtio_console_txq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    log_debug("%s", __func__);
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;
    uint64_t val = 1;
    write(dev->kick_fd, &val, sizeof(val));
    return 0;
}

void virtio_console_close(VirtIODevice *vdev) {
    ConsoleDev *dev = vdev->dev;
    close(dev->master_fd);
    close(dev->kick_fd);
    free(dev->event);
    free(dev);
    free(vdev->vqs);
    free(vdev);
}