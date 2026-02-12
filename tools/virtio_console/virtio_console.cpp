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

#define CONSOLE_TRASH_BUF_SIZE 1024
#define CONSOLE_TX_BATCH_QUOTA 64

static uint8_t trashbuf[CONSOLE_TRASH_BUF_SIZE];

/// @brief Initialize the console device.
/// @return Pointer to the initialized ConsoleDev structure.
ConsoleDev *virtio_console_alloc() {
    ConsoleDev *dev = (ConsoleDev *)malloc(sizeof(ConsoleDev));
    dev->config.cols = CONSOLE_DEFAULT_COLS;
    dev->config.rows = CONSOLE_DEFAULT_ROWS;
    dev->master_fd = -1;
    dev->slave_fd = -1;
    dev->rx_ready = -1;
    dev->event = NULL;
    dev->pending_rx_req = NULL;
    return dev;
}

/// @brief Initialize the virtio console device.
/// @param vdev Pointer to the VirtIODevice structure.
/// @return 0 on success, -1 on failure.
int virtio_console_init(VirtIODevice *vdev) {
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;
    int master_fd, slave_fd;
    char *slave_name;
    struct termios term_io;

    // Open a new pty pair (master and slave)
    // - master: Used by the Host to write or read from the Guest.
    // - slave: Used to temporarily configure the terminal attributes.
    // Flags:
    // - O_RDWR: Open for reading and writing.
    // - O_NOCTTY: If the device is a terminal, do not make it the controlling
    // terminal for the process.
    master_fd = posix_openpt(O_RDWR | O_NOCTTY);
    if (master_fd < 0) {
        log_error("Failed to open master pty, errno is %d", errno);
    }

    // Change the mode and owner of the slave PTY device
    if (grantpt(master_fd) < 0) {
        log_error("Failed to grant pty, errno is %d", errno);
    }

    // Unlock the slave PTY device to allow it to be opened
    if (unlockpt(master_fd) < 0) {
        log_error("Failed to unlock pty, errno is %d", errno);
    }

    dev->master_fd = master_fd;

    // Get the name of the slave PTY device
    slave_name = ptsname(master_fd);
    if (!slave_name) {
        log_error("Failed to get slave name, errno is %d", errno);
    }
    log_info("char device redirected to %s", slave_name);

    // Configure the Slave PTY to "Raw Mode".
    // We open the slave side temporarily just to configure the terminal
    // attributes. Raw Mode is essential for a virtio-console because the Guest
    // OS expects a raw byte stream. We don't want the Host kernel to process:
    // - Echoing (printing back what is typed)
    // - Line buffering (waiting for Enter key)
    // - Signal generation (Ctrl-C sending SIGINT)
    slave_fd = open(slave_name, O_RDWR);
    tcgetattr(slave_fd, &term_io);
    cfmakeraw(&term_io); // Set the terminal to raw mode
    tcsetattr(slave_fd, TCSAFLUSH, &term_io);
    // Note: We intentionally do NOT close slave_fd here.
    // By keeping the slave fd open in this process, we ensure that the master
    // PTY always has at least one active client. This prevents read(master_fd)
    // from returning EIO when no external user is connected, which would cause
    // the io_uring loop to busy-spin.
    dev->slave_fd = slave_fd;

    // Set the master FD to non-blocking mode
    // This allows us to use io_uring for asynchronous I/O operations
    if (set_nonblocking(dev->master_fd) < 0) {
        close(dev->master_fd);
        dev->master_fd = -1;
        close(dev->slave_fd);
        dev->slave_fd = -1;
        log_error("Failed to set nonblocking mode, fd closed!");
    }

    // Register master_fd to event loop for RX (Host -> Guest)
    dev->master_fd = master_fd;
    dev->rx_ready = 1;
    dev->pending_rx_req = NULL;

    vdev->virtio_close = virtio_console_close;

    // Start coroutines
    virtio_console_rxq_coroutine(vdev, &vdev->vqs[CONSOLE_QUEUE_RX]);
    virtio_console_txq_coroutine(vdev, &vdev->vqs[CONSOLE_QUEUE_TX]);

    return 0;
}

#include "coroutine_utils.h"

/// @brief Process the console TX queue (Guest -> Host).
/// @param vdev Pointer to the VirtIODevice structure.
/// @param vq Pointer to the VirtQueue structure.
static Task virtio_console_txq_coroutine(VirtIODevice *vdev, VirtQueue *vq) {
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;
    virtqueue_disable_notify(vq);

    const int BATCH_SIZE = 32;
    std::vector<std::pair<struct iovec *, int>> batch_reqs; // iov, n_iov
    std::vector<uint16_t> batch_idxs;
    
    // Pre-allocate IOV buffers for the batch
    const int PER_REQ_IOV_CAP = VIRTQUEUE_CONSOLE_MAX_SIZE + 2;
    std::vector<std::vector<struct iovec>> iov_pool(BATCH_SIZE);
    for (int i = 0; i < BATCH_SIZE; ++i) {
        iov_pool[i].resize(PER_REQ_IOV_CAP);
    }

    while (true) {
        batch_reqs.clear();
        batch_idxs.clear();

        while (batch_reqs.size() < BATCH_SIZE && !virtqueue_is_empty(vq)) {
            uint16_t idx;
            struct iovec *iov = iov_pool[batch_reqs.size()].data();
            int n = process_descriptor_chain(vq, &idx, &iov, PER_REQ_IOV_CAP, NULL, 0, 0, false);

            if (n < 1) {
                if (iov != iov_pool[batch_reqs.size()].data()) free(iov);
                continue;
            }

            batch_reqs.push_back({iov, n});
            batch_idxs.push_back(idx);
        }

        if (batch_reqs.empty()) {
            virtqueue_enable_notify(vq);
            if (virtqueue_is_empty(vq)) {
                co_await WaitForNotify{vq};
            } else {
                co_await YieldAwaitable{};
            }
            virtqueue_disable_notify(vq);
            continue;
        }

        // Submit batch
        std::vector<int> results = co_await BatchIoUringAwaitable<std::pair<struct iovec *, int>>(
            get_global_ring(), batch_reqs,
            [dev](struct io_uring_sqe *sqe, std::pair<struct iovec *, int> req) {
                io_uring_prep_writev(sqe, dev->master_fd, req.first, req.second, 0);
            });

        // Process results
        for (size_t i = 0; i < batch_reqs.size(); ++i) {
            int res = results[i];
            if (res < 0) {
                log_error("console tx error: %d", res);
                res = 0;
            }
            update_used_ring(vq, batch_idxs[i], 0);
            
            if (batch_reqs[i].first != iov_pool[i].data()) {
                free(batch_reqs[i].first);
            }
        }
        
        co_await virtio_inject_irq(vq);
    }
}

static Task virtio_console_rxq_coroutine(VirtIODevice *vdev, VirtQueue *vq) {
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;
    virtqueue_disable_notify(vq);

    const int BATCH_SIZE = 32;
    std::vector<std::pair<struct iovec *, int>> batch_reqs; // iov, n_iov
    std::vector<uint16_t> batch_idxs;
    
    // Pre-allocate IOV buffers for the batch
    const int PER_REQ_IOV_CAP = VIRTQUEUE_CONSOLE_MAX_SIZE + 2;
    std::vector<std::vector<struct iovec>> iov_pool(BATCH_SIZE);
    for (int i = 0; i < BATCH_SIZE; ++i) {
        iov_pool[i].resize(PER_REQ_IOV_CAP);
    }

    while (true) {
        batch_reqs.clear();
        batch_idxs.clear();

        while (batch_reqs.size() < BATCH_SIZE && !virtqueue_is_empty(vq)) {
            uint16_t idx;
            struct iovec *iov = iov_pool[batch_reqs.size()].data();
            int n = process_descriptor_chain(vq, &idx, &iov, PER_REQ_IOV_CAP, NULL, 0, 0, false);

            if (n < 1) {
                if (iov != iov_pool[batch_reqs.size()].data()) free(iov);
                continue;
            }

            batch_reqs.push_back({iov, n});
            batch_idxs.push_back(idx);
        }

        if (batch_reqs.empty()) {
            virtqueue_enable_notify(vq);
            if (virtqueue_is_empty(vq)) {
                co_await WaitForNotify{vq};
            } else {
                co_await YieldAwaitable{};
            }
            virtqueue_disable_notify(vq);
            continue;
        }

        // Submit batch
        std::vector<int> results = co_await BatchIoUringAwaitable<std::pair<struct iovec *, int>>(
            get_global_ring(), batch_reqs,
            [dev](struct io_uring_sqe *sqe, std::pair<struct iovec *, int> req) {
                io_uring_prep_readv(sqe, dev->master_fd, req.first, req.second, 0);
            });

        // Process results
        bool any_success = false;
        for (size_t i = 0; i < batch_reqs.size(); ++i) {
            int res = results[i];
            
            // Handle EAGAIN: If we got no data, we should not return a 0-length buffer
            // to the guest immediately, as that might cause a busy loop in the guest or host.
            // Instead, we should wait for data to be available.
            // However, BatchIoUringAwaitable doesn't support partial retries easily.
            // But if ALL requests failed with EAGAIN, we can definitely wait.
            // If SOME succeeded, we process them.
            
            if (res == -EAGAIN) {
                // We treat this as 0 bytes read for now, but we need to check if we should poll.
                res = 0;
            } else if (res < 0) {
                log_trace("console rx error: %d", res);
                res = 0;
            } else {
                any_success = true;
            }

            update_used_ring(vq, batch_idxs[i], res);
            
            if (batch_reqs[i].first != iov_pool[i].data()) {
                free(batch_reqs[i].first);
            }
        }

        co_await virtio_inject_irq(vq);
        
        // If no data was read (likely EAGAIN), wait for the file descriptor to be ready
        if (!any_success) {
            co_await PollAwaitable(dev->master_fd, POLLIN);
        }
    }
}

// Re-implement virtio_console_txq_process to satisfy linker/existing calls
/// @param vdev Pointer to the VirtIODevice structure.
/// @param vq Pointer to the VirtQueue structure.
/// @return 0 on success.
int virtio_console_txq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    if (vq->waiter) {
        std::coroutine_handle<>::from_address(vq->waiter).resume();
    }
    return 0;
}

/// @brief Notify handler for the RX queue.
///
/// This function is called by the virtio core when the Guest refills the RX
/// queue (e.g., via virtqueue_kick). It is crucial for the backpressure
/// mechanism: if we previously disabled PTY polling because the Guest had no
/// buffers, this handler re-enables polling to resume data flow from Host to
/// Guest.
///
/// @param vdev Pointer to the VirtIODevice structure.
/// @param vq Pointer to the VirtQueue structure.
/// @return 0 on success.
int virtio_console_rxq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    log_debug("%s", __func__);
    if (vq->waiter) {
        std::coroutine_handle<>::from_address(vq->waiter).resume();
    }
    return 0;
}

/// @brief Close the virtio console device and release resources.
/// @param vdev Pointer to the VirtIODevice structure.
void virtio_console_close(VirtIODevice *vdev) {
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;
    if (dev->master_fd >= 0) {
        close(dev->master_fd);
    }
    if (dev->slave_fd >= 0) {
        close(dev->slave_fd);
    }
    free(dev);
    free(vdev->vqs);
    free(vdev);
}
