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
#include "event_monitor.h"
#include "io_uring_context.hpp"
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <termios.h>
#include <new>
#include <vector>

static uint8_t trashbuf[1024];

ConsoleDev *virtio_console_alloc_dev() {
    log_info("virtio_console_alloc_dev enter");
    ConsoleDev *dev = (ConsoleDev *)calloc(1, sizeof(ConsoleDev));
    dev->config.cols = 80;
    dev->config.rows = 25;
    dev->master_fd = -1;
    dev->rx_ready = -1;
    dev->pending_rx = 0;
    dev->rx_poll_active = false;
    dev->rx_ctxs = (struct console_read_ctx*)calloc(VIRTQUEUE_CONSOLE_MAX_SIZE, sizeof(struct console_read_ctx));
    dev->tx_ctxs = (struct console_tx_ctx*)calloc(VIRTQUEUE_CONSOLE_MAX_SIZE, sizeof(struct console_tx_ctx));
    dev->stalled_read_ctx = NULL;

    return dev;
}

/*
extern "C" int virtio_console_rxq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    ConsoleDev *dev = (ConsoleDev*)vdev->dev;
    if (dev->rx_ready <= 0) {
        dev->rx_ready = 1;
        virtqueue_disable_notify(vq);
    }
    dev->rx_event.signal();
    return 0;
}
*/

virtio::Task console_rx_task(VirtIODevice *vdev) {
    log_info("console_rx_task enter");
    ConsoleDev *dev = (ConsoleDev*)vdev->dev;
    VirtQueue *vq = &vdev->vqs[CONSOLE_QUEUE_RX];
    virtio::IoUringContext* io_ctx = get_io_context();

    // Move vectors outside loop
    const int MAX_BATCH = 64;
    std::vector<virtio::IoUringContext::IoAwaitable> awaitables; 
    std::vector<struct console_read_ctx*> batch_ctxs;
    awaitables.reserve(MAX_BATCH);
    batch_ctxs.reserve(MAX_BATCH);

    log_info("console_rx_task looping");
    while (true) {
        if (virtqueue_is_empty(vq)) {
            virtqueue_enable_notify(vq);
            if (virtqueue_is_empty(vq)) {
                if (vq->notification_event)
                    co_await *(virtio::CoroutineEvent*)vq->notification_event;
            }
            virtqueue_disable_notify(vq);
        }

        if (dev->rx_ready <= 0) {
             co_await io_ctx->async_read(dev->master_fd, trashbuf, sizeof(trashbuf), 0);
             continue;
        }

        co_await io_ctx->async_poll(dev->master_fd);

        virtio::IoUringContext::BatchAwaitable batch;
        batch.ctx = io_ctx;
        
        awaitables.clear();
        batch_ctxs.clear();

        int loop_count = 0;
        while (loop_count < MAX_BATCH) {
            if (virtqueue_is_empty(vq)) break;
            
            uint16_t last_avail_idx = vq->last_avail_idx;
            uint16_t head_idx = vq->avail_ring->ring[last_avail_idx & (vq->num - 1)];
            struct console_read_ctx *ctx = &dev->rx_ctxs[head_idx];
            ctx->vq = vq;
            
            int n = process_descriptor_chain_into(vq, &ctx->idx, ctx->iov, CONSOLE_IOV_MAX, NULL, 0, false);
            if (n < 1) break;
            ctx->iovcnt = n;
            
            awaitables.emplace_back();
            virtio::IoUringContext::IoAwaitable& op = awaitables.back();
            io_ctx->prep_readv(op, dev->master_fd, ctx->iov, n, 0);
            
            batch_ctxs.push_back(ctx);
            
            loop_count++;
        }
        
        if (!awaitables.empty()) {
            for (size_t i = 0; i < awaitables.size(); i++) {
                batch.ops.push_back(&awaitables[i]);
            }
            
            co_await batch;
            
            for (size_t i = 0; i < awaitables.size(); i++) {
                int res = awaitables[i].result;
                struct console_read_ctx *ctx = batch_ctxs[i];
                
                if (res > 0) {
                    update_used_ring(vq, ctx->idx, res);
                    virtio_inject_irq(vq);
                } else {
                    // For batching simplicity, drop or complete with 0 on error/EAGAIN
                    update_used_ring(vq, ctx->idx, 0);
                    virtio_inject_irq(vq);
                }
            }
        }
    }
}

virtio::Task console_tx_task(VirtIODevice *vdev) {
    log_info("console_tx_task enter");
    ConsoleDev *dev = (ConsoleDev*)vdev->dev;
    VirtQueue *vq = &vdev->vqs[CONSOLE_QUEUE_TX];
    virtio::IoUringContext* io_ctx = get_io_context();

    // Move vectors outside loop
    const int MAX_BATCH = 64;
    std::vector<virtio::IoUringContext::IoAwaitable> awaitables; 
    std::vector<struct console_tx_ctx*> batch_ctxs;
    awaitables.reserve(MAX_BATCH);
    batch_ctxs.reserve(MAX_BATCH);

    log_info("console_tx_task looping");
    while (true) {
        while (virtqueue_is_empty(vq)) {
            virtqueue_enable_notify(vq);
            if (virtqueue_is_empty(vq)) {
                 if (vq->notification_event)
                     co_await *(virtio::CoroutineEvent*)vq->notification_event;
            }
            virtqueue_disable_notify(vq);
        }

        virtio::IoUringContext::BatchAwaitable batch;
        batch.ctx = io_ctx;
        
        awaitables.clear();
        batch_ctxs.clear();

        int loop_count = 0;
        while (!virtqueue_is_empty(vq) && loop_count < MAX_BATCH) {
            uint16_t last_avail_idx = vq->last_avail_idx;
            uint16_t head_idx = vq->avail_ring->ring[last_avail_idx & (vq->num - 1)];
            struct console_tx_ctx *ctx = &dev->tx_ctxs[head_idx];
            ctx->vq = vq;
            
            int n = process_descriptor_chain_into(vq, &ctx->idx, ctx->iov, CONSOLE_IOV_MAX, NULL, 1, false);
            if (n < 1) break;
            ctx->iovcnt = n;
            
            awaitables.emplace_back();
            virtio::IoUringContext::IoAwaitable& op = awaitables.back();
            io_ctx->prep_writev(op, dev->master_fd, ctx->iov, n, 0);
            
            batch_ctxs.push_back(ctx);
            
            loop_count++;
        }
        
        if (!awaitables.empty()) {
             for (size_t i = 0; i < awaitables.size(); i++) {
                batch.ops.push_back(&awaitables[i]);
            }
            
            co_await batch;
            
            for (size_t i = 0; i < awaitables.size(); i++) {
                struct console_tx_ctx *ctx = batch_ctxs[i];
                update_used_ring(vq, ctx->idx, 0);
                virtio_inject_irq(vq);
            }
        }
        io_flush();
    }
}

/*
extern "C" int virtio_console_txq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    ConsoleDev *dev = (ConsoleDev*)vdev->dev;
    dev->tx_event.signal();
    return 0;
}
*/

int virtio_console_init(VirtIODevice *vdev) {
    log_info("virtio_console_init enter");
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;
    dev->master_fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    if (dev->master_fd < 0) {
        log_error("open ptmx failed");
        return -1;
    }
    
    grantpt(dev->master_fd);
    unlockpt(dev->master_fd);
    log_warn("virtio-console pty path: %s", ptsname(dev->master_fd));

    if (set_nonblocking(dev->master_fd) < 0) {
        log_error("set_nonblocking failed");
        close(dev->master_fd);
        return -1;
    }

    struct termios tio;
    tcgetattr(dev->master_fd, &tio);
    cfmakeraw(&tio);
    tio.c_cc[VMIN] = 1;
    tio.c_cc[VTIME] = 0;
    tcsetattr(dev->master_fd, TCSANOW, &tio);

    vdev->virtio_close = virtio_console_close;
    
    return 0;
}

int virtio_console_queue_resize(VirtIODevice *vdev, int queue_idx, int new_num) {
    log_info("virtio_console_queue_resize enter");
    ConsoleDev *dev = (ConsoleDev*)vdev->dev;
    if (new_num > VIRTQUEUE_CONSOLE_MAX_SIZE) {
        struct console_read_ctx *new_rx = (struct console_read_ctx*)realloc(dev->rx_ctxs, sizeof(struct console_read_ctx) * new_num);
        struct console_tx_ctx *new_tx = (struct console_tx_ctx*)realloc(dev->tx_ctxs, sizeof(struct console_tx_ctx) * new_num);
        if (new_rx) dev->rx_ctxs = new_rx;
        if (new_tx) dev->tx_ctxs = new_tx;
    }
    return 0;
}

void virtio_console_close(VirtIODevice *vdev) {
    log_info("virtio_console_close enter");
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;
    if (dev->master_fd >= 0) close(dev->master_fd);
    free(dev->rx_ctxs);
    free(dev->tx_ctxs);
    free(dev);
    free(vdev->vqs);
    free(vdev);
}

void virtio_console_run(VirtIODevice *vdev) {
    log_info("virtio_console_run enter");
    console_rx_task(vdev);
    console_tx_task(vdev);
}
