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
#include <liburing.h>
#include <math.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/time.h>
#include <termios.h>

static uint8_t trashbuf[1024];

/// @brief Initialize the console device.
/// @return Pointer to the initialized ConsoleDev structure.
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

/// @brief Handler for console RX completion events.
/// @param param Pointer to the console request structure.
/// @param res Result of the I/O operation.
static void virtio_console_rx_completion_handler(void *param, int res) {
    struct console_req *req = (struct console_req *)param;

    VirtIODevice *vdev = req->vdev;
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

    // Update the virtqueue used ring
    update_used_ring(vq, req->idx, res);

    // Inject an interrupt to signal the guest that data is available
    virtio_inject_irq(vq);

    // Free the request structure
    free(req->iov);
    free(req);
}

/// @brief Event handler for console events
/// @param fd The file descriptor associated with the event.
/// @param epoll_type The type of event (e.g., POLLIN).
/// @param param Pointer to the VirtIODevice structure.
static void virtio_console_event_handler(int fd, int epoll_type, void *param) {
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

    // Handle pending RX request
    if (dev->pending_rx_req) {
        struct console_req *req = dev->pending_rx_req;
        dev->pending_rx_req = NULL;

        struct io_uring *ring = get_global_ring();
        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

        io_uring_prep_readv(sqe, dev->master_fd, req->iov, req->iovcnt, 0);
        io_uring_sqe_set_data(sqe, &req->hevent);
        io_uring_submit(ring);
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
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_readv(sqe, dev->master_fd, req->iov, req->iovcnt, 0);
    io_uring_sqe_set_data(sqe, &req->hevent);
    io_uring_submit(ring);
}

/// @brief Initialize the virtio console device.
/// @param vdev Pointer to the VirtIODevice structure.
/// @return 0 on success, -1 on failure.
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

    // Register master_fd to event loop for RX (Host -> Guest)
    dev->event =
        add_event(dev->master_fd, POLLIN, virtio_console_event_handler, vdev);

    vdev->virtio_close = virtio_console_close;
    return 0;
}

/// @brief Process the RX queue for the console device.
/// @param vdev Pointer to the VirtIODevice structure.
/// @param vq Pointer to the VirtQueue structure.
static void virtio_console_rxq_process(VirtIODevice *vdev, VirtQueue *vq) {
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;
    virtio_console_event_handler(dev->master_fd, POLLIN, vdev);
}

/// @brief Process the TX queue for the console device.
/// @param vdev Pointer to the VirtIODevice structure.
/// @param vq Pointer to the VirtQueue structure.
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
}

/// @brief Notify handler for the TX queue.
/// @param vdev Pointer to the VirtIODevice structure.
/// @param vq Pointer to the VirtQueue structure.
/// @return 0 on success.
int virtio_console_txq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    virtio_console_txq_process(vdev, vq);
    return 0;
}

/// @brief Notify handler for the RX queue.
/// @param vdev Pointer to the VirtIODevice structure.
/// @param vq Pointer to the VirtQueue structure.
/// @return 0 on success.
int virtio_console_rxq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    log_debug("%s", __func__);
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;
    enable_event_poll(dev->event);
    virtio_console_rxq_process(vdev, vq);
    return 0;
}

/// @brief Handler for console TX completion events.
/// @param param Pointer to the console request structure.
/// @param res Result of the I/O operation.
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

/// @brief Handle a single request from the TX queue.
/// @param dev Pointer to the ConsoleDev structure.
/// @param vq Pointer to the VirtQueue structure.
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
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_writev(sqe, dev->master_fd, req->iov, req->iovcnt, 0);
    io_uring_sqe_set_data(sqe, &req->hevent);
    io_uring_submit(ring);
}

/// @brief Close the virtio console device and release resources.
/// @param vdev Pointer to the VirtIODevice structure.
void virtio_console_close(VirtIODevice *vdev) {
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;
    if (dev->master_fd >= 0) {
        close(dev->master_fd);
    }
    free(dev);
    free(vdev->vqs);
    free(vdev);
}