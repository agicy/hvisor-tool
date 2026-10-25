// SPDX-License-Identifier: GPL-2.0-only
/**
 * Copyright (c) 2025 Syswonder
 *
 * Syswonder Website:
 *      https://www.syswonder.org
 *
 * Authors:
 *      Guowei Li <2401213322@stu.pku.edu.cn>
 */
#define _GNU_SOURCE

#include "virtio_console.h"
#include "log.h"
#include "virtio.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <termios.h>
#include <unistd.h>

/*
 * Threading model
 * ---------------
 * A console device has two queues and gives each queue its own worker thread:
 *
 *   RX worker (CONSOLE_QUEUE_RX, host pty -> guest)
 *     - owns the RX virtqueue and the pty master fd;
 *     - reads bytes from the pty into a host-side ring buffer and copies them
 *       into guest receive buffers as the guest posts them;
 *     - when the ring is full it stops reading the pty, so unsent input stays
 *       in the pty and the guest's console writer is throttled instead of
 *       having its bytes discarded.
 *
 *   TX worker (CONSOLE_QUEUE_TX, guest -> host pty)
 *     - owns the TX virtqueue;
 *     - writes guest output descriptors to the pty and completes a chain only
 *       after every byte has been accepted; when the pty is full the pending
 *       chain is kept and the worker waits for POLLOUT.
 *
 * The MMIO thread (the daemon's virtio request loop) never touches either
 * queue. It only forwards queue kicks through an eventfd and runs the quiesce
 * handshake around device reset:
 *
 *   queue notify  wake the queue's worker
 *   STATUS=0      set dev->reset, wait until both workers report paused, then
 *                 let virtio_dev_reset() re-initialize the queue structs
 *   next kick     clear dev->reset and wake both workers
 *   close         set dev->close and join both workers
 *
 * The old single-threaded handler lost data in two ways that this model fixes:
 * it read pty bytes into a trash buffer when the guest had not posted receive
 * buffers, and it completed TX chains with length 0 even when the pty write
 * failed with EAGAIN.
 */

static void console_wake(int efd) {
    uint64_t one = 1;
    ssize_t ret;

    if (efd < 0)
        return;
    do {
        ret = write(efd, &one, sizeof(one));
    } while (ret < 0 && errno == EINTR);
}

static void console_drain_wakeup(int efd) {
    uint64_t val;
    ssize_t ret;

    do {
        ret = read(efd, &val, sizeof(val));
    } while (ret < 0 && errno == EINTR);
    (void)ret;
}

/*
 * Wait at a worker loop boundary. Blocks while the device is being reset and
 * returns true once dev->close is set. @drop, when given, discards per-worker
 * state that must not survive the reset (called with dev->mtx held).
 */
static bool console_worker_gate(ConsoleDev *dev, bool *paused,
                                void (*drop)(ConsoleDev *)) {
    bool closing;

    pthread_mutex_lock(&dev->mtx);
    if (dev->reset) {
        if (drop)
            drop(dev);
        *paused = true;
        pthread_cond_broadcast(&dev->cond);
        while (dev->reset && !dev->close)
            pthread_cond_wait(&dev->cond, &dev->mtx);
        *paused = false;
    }
    closing = dev->close;
    pthread_mutex_unlock(&dev->mtx);
    return closing;
}

static void console_end_reset(ConsoleDev *dev) {
    pthread_mutex_lock(&dev->mtx);
    if (dev->reset) {
        dev->reset = false;
        pthread_cond_broadcast(&dev->cond);
    }
    pthread_mutex_unlock(&dev->mtx);
}

/* --------------------------------------------------------------------- */
/* RX path: pty -> staging ring -> guest receive buffers                  */
/* --------------------------------------------------------------------- */

static inline size_t console_rx_used(const ConsoleDev *dev) {
    return dev->rx_head - dev->rx_tail;
}

static inline size_t console_rx_space(const ConsoleDev *dev) {
    return CONSOLE_RX_RING_SIZE - console_rx_used(dev);
}

/* Copy up to @len pending bytes out of the ring, consuming them. */
static size_t console_rx_ring_pop(ConsoleDev *dev, void *dst, size_t len) {
    size_t used = console_rx_used(dev);
    size_t off, first;

    if (len > used)
        len = used;
    if (len == 0)
        return 0;

    off = dev->rx_tail & (CONSOLE_RX_RING_SIZE - 1);
    first = CONSOLE_RX_RING_SIZE - off;
    if (first > len)
        first = len;
    memcpy(dst, dev->rx_buf + off, first);
    if (len > first)
        memcpy((uint8_t *)dst + first, dev->rx_buf, len - first);
    dev->rx_tail += len;
    return len;
}

/* Drain the pty into the staging ring, stopping when it is full or empty. */
static void console_rx_read_pty(ConsoleDev *dev) {
    for (;;) {
        size_t space = console_rx_space(dev);
        size_t off, chunk;
        ssize_t n;

        if (space == 0)
            return;
        off = dev->rx_head & (CONSOLE_RX_RING_SIZE - 1);
        chunk = CONSOLE_RX_RING_SIZE - off;
        if (chunk > space)
            chunk = space;

        n = read(dev->master_fd, dev->rx_buf + off, chunk);
        if (n > 0) {
            dev->rx_head += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;
        if (n == 0)
            log_error("console rx: pty master reached EOF");
        else
            log_error("console rx: read from pty failed, errno=%d", errno);
        return;
    }
}

/* Move one available chain's worth of staged input into the guest. */
static void console_rx_deliver_one(ConsoleDev *dev, VirtQueue *vq) {
    struct VirtioBufConfig cfg = {
        .in_iov = dev->rx_iov,
        .max_in = VIRTQUEUE_CONSOLE_MAX_SIZE,
    };
    uint16_t idx =
        vq->avail_ring->ring[vq->last_avail_idx & (vq->num - 1)];
    struct VirtioRequest req;
    size_t total = 0;
    int n;

    n = process_descriptor_chain_buf(vq, idx, &cfg, &req);
    if (n < 1) {
        log_error("console rx: invalid descriptor chain at %u", idx);
        vq->last_avail_idx++;
        update_used_ring(vq, idx, 0);
        return;
    }

    for (unsigned int i = 0; i < req.in_count; i++) {
        size_t got = console_rx_ring_pop(dev, req.in_iov[i].iov_base,
                                         req.in_iov[i].iov_len);
        total += got;
        if (got < req.in_iov[i].iov_len)
            break; /* ring drained, the rest of this chain stays empty */
    }
    update_used_ring(vq, idx, (uint32_t)total);
}

/* Returns true if at least one used-ring entry was written. */
static bool console_rx_pump(ConsoleDev *dev, VirtQueue *vq) {
    bool completed = false;

    if (!vq->avail_ring || !vq->used_ring || console_rx_used(dev) == 0 ||
        vq_is_empty(vq))
        return false;

    for (;;) {
        virtqueue_disable_notify(vq);
        while (console_rx_used(dev) > 0 && !vq_is_empty(vq)) {
            console_rx_deliver_one(dev, vq);
            completed = true;
        }
        virtqueue_enable_notify(vq);
        /* Re-check the enable/empty race before going to sleep. */
        if (console_rx_used(dev) == 0 || vq_is_empty(vq))
            break;
    }
    return completed;
}

static void console_rx_drop_pending(ConsoleDev *dev) {
    dev->rx_head = 0;
    dev->rx_tail = 0;
}

static void *console_rx_worker(void *arg) {
    VirtIODevice *vdev = (VirtIODevice *)arg;
    ConsoleDev *dev = vdev->dev;
    VirtQueue *vq = &vdev->vqs[CONSOLE_QUEUE_RX];
    bool pty_ok = true;

    while (!console_worker_gate(dev, &dev->rx_paused,
                                console_rx_drop_pending)) {
        struct pollfd fds[2];
        bool ring_full;
        int ret;

        if (console_rx_pump(dev, vq))
            virtio_inject_irq(vq);
        if (pty_ok)
            console_rx_read_pty(dev);
        if (console_rx_used(dev) > 0 && !vq_is_empty(vq))
            continue; /* deliver the freshly read bytes without sleeping */

        /*
         * Only poll the pty while there is room for its data. Otherwise the
         * fd stays readable and poll would spin.
         */
        ring_full = console_rx_space(dev) == 0;
        fds[0].fd = dev->rx_kick_efd;
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        fds[1].fd = (pty_ok && !ring_full) ? dev->master_fd : -1;
        fds[1].events = POLLIN;
        fds[1].revents = 0;

        ret = poll(fds, 2, -1);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            log_error("console rx: poll failed, errno=%d", errno);
            continue;
        }
        if (fds[0].revents & POLLIN)
            console_drain_wakeup(dev->rx_kick_efd);
        if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            log_error("console rx: pty master error, revents=%#x",
                      fds[1].revents);
            pty_ok = false;
        }
    }
    return NULL;
}

/* --------------------------------------------------------------------- */
/* TX path: guest output buffers -> pty                                   */
/* --------------------------------------------------------------------- */

enum console_tx_step {
    CONSOLE_TX_IDLE,     /* no queued request */
    CONSOLE_TX_PROGRESS, /* one chain completed, more work may exist */
    CONSOLE_TX_BLOCKED,  /* pty full, pending chain kept for POLLOUT */
};

/* Account @len bytes accepted by the pty against the pending chain. */
static void console_tx_advance(ConsoleDev *dev, size_t len) {
    while (len > 0 && dev->tx_iov_pos < dev->tx_iov_count) {
        struct iovec *iov = &dev->tx_iov[dev->tx_iov_pos];

        if (len >= iov->iov_len) {
            len -= iov->iov_len;
            dev->tx_iov_pos++;
        } else {
            iov->iov_base = (uint8_t *)iov->iov_base + len;
            iov->iov_len -= len;
            len = 0;
        }
    }
}

static enum console_tx_step console_tx_step(ConsoleDev *dev, VirtQueue *vq) {
    if (dev->tx_iov_count == 0) {
        struct VirtioBufConfig cfg = {
            .out_iov = dev->tx_iov,
            .max_out = VIRTQUEUE_CONSOLE_MAX_SIZE,
        };
        struct VirtioRequest req;
        uint16_t idx;
        int n;

        if (vq_is_empty(vq))
            return CONSOLE_TX_IDLE;

        idx = vq->avail_ring->ring[vq->last_avail_idx & (vq->num - 1)];
        n = process_descriptor_chain_buf(vq, idx, &cfg, &req);
        if (n < 1 || req.out_count == 0) {
            log_error("console tx: invalid descriptor chain at %u", idx);
            if (n < 1)
                vq->last_avail_idx++;
            update_used_ring(vq, idx, 0);
            return CONSOLE_TX_PROGRESS;
        }
        dev->tx_iov_count = req.out_count;
        dev->tx_iov_pos = 0;
        dev->tx_desc_idx = idx;
        dev->tx_written = 0;
    }

    while (dev->tx_iov_count > 0) {
        ssize_t len = writev(dev->master_fd, &dev->tx_iov[dev->tx_iov_pos],
                             (int)(dev->tx_iov_count - dev->tx_iov_pos));

        if (len > 0) {
            dev->tx_written += (size_t)len;
            console_tx_advance(dev, (size_t)len);
            if (dev->tx_iov_pos == dev->tx_iov_count) {
                dev->tx_iov_count = 0;
                break;
            }
            continue;
        }
        if (len == 0) {
            /* Remaining segments are empty; nothing left to write. */
            dev->tx_iov_count = 0;
            break;
        }
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return CONSOLE_TX_BLOCKED;

        log_error("console tx: write to pty failed, errno=%d", errno);
        dev->tx_iov_count = 0; /* drop the remainder, report what was sent */
        break;
    }

    update_used_ring(vq, dev->tx_desc_idx, (uint32_t)dev->tx_written);
    dev->tx_iov_count = 0;
    dev->tx_written = 0;
    return CONSOLE_TX_PROGRESS;
}

/* Returns true if at least one used-ring entry was written. */
static bool console_tx_pump(ConsoleDev *dev, VirtQueue *vq, bool *blocked) {
    bool completed = false;

    *blocked = false;
    if (!vq->avail_ring || !vq->used_ring)
        return false;
    if (dev->tx_iov_count == 0 && vq_is_empty(vq))
        return false;

    for (;;) {
        enum console_tx_step step;

        virtqueue_disable_notify(vq);
        for (;;) {
            step = console_tx_step(dev, vq);
            if (step != CONSOLE_TX_PROGRESS) {
                *blocked = (step == CONSOLE_TX_BLOCKED);
                break;
            }
            completed = true;
        }
        virtqueue_enable_notify(vq);
        /* Re-check the enable/empty race before going to sleep. */
        if (*blocked || vq_is_empty(vq))
            break;
    }
    return completed;
}

static void console_tx_drop_pending(ConsoleDev *dev) {
    dev->tx_iov_count = 0;
    dev->tx_written = 0;
}

static void *console_tx_worker(void *arg) {
    VirtIODevice *vdev = (VirtIODevice *)arg;
    ConsoleDev *dev = vdev->dev;
    VirtQueue *vq = &vdev->vqs[CONSOLE_QUEUE_TX];

    while (!console_worker_gate(dev, &dev->tx_paused,
                                console_tx_drop_pending)) {
        struct pollfd fds[2];
        bool blocked = false;
        int ret;

        if (console_tx_pump(dev, vq, &blocked))
            virtio_inject_irq(vq);

        fds[0].fd = dev->tx_kick_efd;
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        fds[1].fd = blocked ? dev->master_fd : -1;
        fds[1].events = POLLOUT;
        fds[1].revents = 0;

        ret = poll(fds, 2, -1);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            log_error("console tx: poll failed, errno=%d", errno);
            continue;
        }
        if (fds[0].revents & POLLIN)
            console_drain_wakeup(dev->tx_kick_efd);
        if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            /*
             * The pty is gone. Leave the pending chain in place: the next
             * writev() fails and completes it through the normal error path
             * with the byte count already accepted.
             */
            log_error("console tx: pty master error, revents=%#x",
                      fds[1].revents);
        }
    }
    return NULL;
}

/* --------------------------------------------------------------------- */
/* Device lifecycle                                                       */
/* --------------------------------------------------------------------- */

static ConsoleDev *init_console_dev(void) {
    ConsoleDev *dev = calloc(1, sizeof(ConsoleDev));

    if (!dev)
        return NULL;
    dev->config.cols = 80;
    dev->config.rows = 25;
    dev->master_fd = -1;
    dev->slave_keepalive_fd = -1;
    dev->rx_kick_efd = -1;
    dev->tx_kick_efd = -1;
    return dev;
}

static int console_start_workers(ConsoleDev *dev, VirtIODevice *vdev) {
    if (pthread_create(&dev->rx_tid, NULL, console_rx_worker, vdev) != 0) {
        log_error("console: failed to create the RX worker");
        return -1;
    }
    dev->rx_thread_started = true;

    if (pthread_create(&dev->tx_tid, NULL, console_tx_worker, vdev) != 0) {
        log_error("console: failed to create the TX worker");
        return -1;
    }
    dev->tx_thread_started = true;
    return 0;
}

static int virtio_console_init(VirtIODevice *vdev) {
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;
    int master_fd, slave_fd;
    char *slave_name;
    struct termios term_io;

    master_fd = posix_openpt(O_RDWR | O_NOCTTY);
    if (master_fd < 0) {
        log_error("Failed to open master pty, errno is %d", errno);
        return -1;
    }
    if (grantpt(master_fd) < 0) {
        log_error("Failed to grant pty, errno is %d", errno);
        close(master_fd);
        return -1;
    }
    if (unlockpt(master_fd) < 0) {
        log_error("Failed to unlock pty, errno is %d", errno);
        close(master_fd);
        return -1;
    }
    dev->master_fd = master_fd;

    slave_name = ptsname(master_fd);
    if (slave_name == NULL) {
        log_error("Failed to get slave name, errno is %d", errno);
        close(master_fd);
        dev->master_fd = -1;
        return -1;
    }
    log_info("char device redirected to %s", slave_name);
    // Open and keep a slave fd in this process. Without a slave peer,
    // master poll/epoll keeps reporting EPOLLHUP and can cause busy loops.
    slave_fd = open(slave_name, O_RDWR);
    if (slave_fd < 0) {
        log_error("Failed to open slave pty, errno is %d", errno);
        close(master_fd);
        dev->master_fd = -1;
        return -1;
    }

    // Disable line discipline to prevent the TTY
    // from echoing the characters sent from the master back to the master.
    tcgetattr(slave_fd, &term_io);
    cfmakeraw(&term_io);
    term_io.c_oflag |= ONLCR;
    tcsetattr(slave_fd, TCSAFLUSH, &term_io);
    dev->slave_keepalive_fd = slave_fd;

    if (set_nonblocking(dev->master_fd) < 0) {
        log_error("Failed to set nonblocking mode");
        return -1;
    }

    dev->rx_buf = malloc(CONSOLE_RX_RING_SIZE);
    if (!dev->rx_buf) {
        log_error("console: failed to allocate the RX ring");
        return -1;
    }

    if (pthread_mutex_init(&dev->mtx, NULL) != 0) {
        log_error("console: failed to initialize the mutex");
        return -1;
    }
    dev->mtx_initialized = true;

    if (pthread_cond_init(&dev->cond, NULL) != 0) {
        log_error("console: failed to initialize the condvar");
        return -1;
    }
    dev->cond_initialized = true;

    dev->rx_kick_efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    dev->tx_kick_efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (dev->rx_kick_efd < 0 || dev->tx_kick_efd < 0) {
        log_error("console: failed to create eventfd, errno is %d", errno);
        return -1;
    }

    return console_start_workers(dev, vdev);
}

static int virtio_console_rxq_notify_handler(VirtIODevice *vdev,
                                             VirtQueue *vq) {
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;

    (void)vq;
    console_end_reset(dev);
    console_wake(dev->rx_kick_efd);
    return 0;
}

static int virtio_console_txq_notify_handler(VirtIODevice *vdev,
                                             VirtQueue *vq) {
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;

    (void)vq;
    console_end_reset(dev);
    console_wake(dev->tx_kick_efd);
    return 0;
}

/*
 * Called from virtio_dev_reset() before the virtqueues are re-initialized.
 * Park both workers so virtqueue_reset() can safely memset the queue structs;
 * they stay parked until the guest kicks a queue again.
 */
static void virtio_console_reset(VirtIODevice *vdev) {
    ConsoleDev *dev = vdev ? vdev->dev : NULL;

    if (!dev || !dev->mtx_initialized)
        return;

    pthread_mutex_lock(&dev->mtx);
    dev->reset = true;
    pthread_mutex_unlock(&dev->mtx);
    console_wake(dev->rx_kick_efd);
    console_wake(dev->tx_kick_efd);

    pthread_mutex_lock(&dev->mtx);
    while (((dev->rx_thread_started && !dev->rx_paused) ||
            (dev->tx_thread_started && !dev->tx_paused)) &&
           !dev->close)
        pthread_cond_wait(&dev->cond, &dev->mtx);
    pthread_mutex_unlock(&dev->mtx);
}

static void virtio_console_close(VirtIODevice *vdev) {
    if (!vdev)
        return;

    ConsoleDev *dev = vdev->dev;
    if (dev) {
        if (dev->mtx_initialized) {
            pthread_mutex_lock(&dev->mtx);
            dev->close = true;
            if (dev->cond_initialized)
                pthread_cond_broadcast(&dev->cond);
            pthread_mutex_unlock(&dev->mtx);
        }
        console_wake(dev->rx_kick_efd);
        console_wake(dev->tx_kick_efd);
        if (dev->rx_thread_started)
            pthread_join(dev->rx_tid, NULL);
        if (dev->tx_thread_started)
            pthread_join(dev->tx_tid, NULL);
        if (dev->rx_kick_efd >= 0)
            close(dev->rx_kick_efd);
        if (dev->tx_kick_efd >= 0)
            close(dev->tx_kick_efd);
        if (dev->cond_initialized)
            pthread_cond_destroy(&dev->cond);
        if (dev->mtx_initialized)
            pthread_mutex_destroy(&dev->mtx);
        if (dev->master_fd >= 0)
            close(dev->master_fd);
        if (dev->slave_keepalive_fd >= 0)
            close(dev->slave_keepalive_fd);
        free(dev->rx_buf);
        free(dev);
        vdev->dev = NULL;
    }
    free(vdev->vqs);
    vdev->vqs = NULL;
    free(vdev);
}

static int virtio_console_do_init(VirtIODevice *vdev, const void *params) {
    (void)params;
    vdev->dev = init_console_dev();
    if (!vdev->dev)
        return -ENOMEM;
    return virtio_console_init(vdev);
}

const struct virtio_device_ops virtio_console_ops = {
    .type = VirtioTConsole,
    .features = CONSOLE_SUPPORTED_FEATURES,
    .num_queues = CONSOLE_MAX_QUEUES,
    .queue_max_size = VIRTQUEUE_CONSOLE_MAX_SIZE,
    .init = virtio_console_do_init,
    .close = virtio_console_close,
    .reset = virtio_console_reset,
    .notify_handlers =
        {
            [CONSOLE_QUEUE_RX] = virtio_console_rxq_notify_handler,
            [CONSOLE_QUEUE_TX] = virtio_console_txq_notify_handler,
        },
};

static int virtio_console_parse_params(const cJSON *json, void **out) {
    (void)json;
    *out = NULL;
    return 0;
}

static void virtio_console_free_params(void *params) { (void)params; }

const struct virtio_config_ops virtio_console_config_ops = {
    .parse = virtio_console_parse_params,
    .free = virtio_console_free_params,
};
