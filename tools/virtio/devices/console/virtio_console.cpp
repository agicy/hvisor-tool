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
#include <cstring>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <termios.h>
#include <new>
#include <vector>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <limits.h> // for PATH_MAX
#include <errno.h>

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
        while (!vq->ready || !vq->avail_ring) {
            if (vq->notification_event) {
                log_info("console_rx_task waiting ready");
                co_await *(virtio::CoroutineEvent*)vq->notification_event;
                log_info("console_rx_task signaled by ready");
            }
            else
                break; // 理论上不会走到这里
        }

        while (virtqueue_is_empty(vq)) {
            virtqueue_enable_notify(vq);
            if (virtqueue_is_empty(vq)) {
                if (vq->notification_event){
                    log_info("console_rx_task waiting virtqueue_notify");
                    co_await *(virtio::CoroutineEvent*)vq->notification_event;
                    log_info("console_rx_task signaled by virtqueue_notify");
                }
            }
            virtqueue_disable_notify(vq);
            if (!vq->ready)
                break; // 退出内部 while 触发外层 ready 检查
        }

        if (!vq->ready)
            continue; // 醒来后如果 ready 没了，回到最上面等待

        dev->rx_ready = 1;

        if (dev->rx_ready <= 0) {
             co_await io_ctx->async_read(dev->master_fd, trashbuf, sizeof(trashbuf), 0);
             continue;
        }

        log_info("console_rx_task waiting poll");
        co_await io_ctx->async_poll(dev->master_fd);
        log_info("console_rx_task signaled by poll");

        int processed_count = 0;
        // Process available descriptors one by one
        while (!virtqueue_is_empty(vq)) {
            uint16_t head_idx;
            struct console_read_ctx *ctx = &dev->rx_ctxs[vq->last_avail_idx & (vq->num - 1)];

            int n = virtqueue_peek(vq, &head_idx, ctx->iov, CONSOLE_IOV_MAX, NULL, 0, false);
            if (n < 1) {
                break; // Should not happen if not empty, but as a safeguard
            }

            ctx->vq = vq;
            ctx->idx = head_idx;
            ctx->iovcnt = n;

            // Perform a single asynchronous read
            auto awaitable = io_ctx->async_readv(dev->master_fd, ctx->iov, n, 0);
            co_await awaitable;
            int res = awaitable.result;

            if (res > 0) {
                // I/O was successful, now we can pop the descriptor
                virtqueue_pop(vq);
                update_used_ring(vq, ctx->idx, res);
                processed_count++;
            } else {
                // I/O failed or would block (EAGAIN). Do not pop the descriptor.
                // It will be retried on the next poll notification.
                log_warn("Console read failed or got EAGAIN, result: %d. Descriptor will be retried.", res);
                break; // Stop processing more descriptors for now
            }
        }

        if (processed_count > 0) {
            virtio_inject_irq(vq);
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
        while (!vq->ready || !vq->avail_ring) {
            if (vq->notification_event) {
                log_info("console_tx_task waiting ready");
                co_await *(virtio::CoroutineEvent*)vq->notification_event;
                log_info("console_tx_task signaled by ready");
            }
            else
                break;
        }

        while (virtqueue_is_empty(vq)) {
            virtqueue_enable_notify(vq);
            if (virtqueue_is_empty(vq)) {
                if (vq->notification_event){
                    log_info("console_tx_task waiting virtqueue notify");
                    co_await *(virtio::CoroutineEvent*)vq->notification_event;
                    log_info("console_tx_task signaled by virtqueue notify");
                }
            }
            virtqueue_disable_notify(vq);
            if (!vq->ready)
                break; // 退出内部 while 触发外层 ready 检查
        }
        
        if (!vq->ready) continue; // 醒来后如果 ready 没了，回到最上面等待

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
            
            log_info("console_tx_task waiting batch");
            co_await batch;
            log_info("console_tx_task signaled by batch");
            
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
    
    // 1. 打开 PTY 主设备 (Master)
    // O_NOCTTY: 防止该设备成为当前进程的控制终端
    // O_RDWR: 读写模式
    int master_fd = posix_openpt(O_RDWR | O_NOCTTY);
    if (master_fd < 0) {
        log_error("posix_openpt failed: %s", strerror(errno));
        return -1;
    }

    // 2. 授权 (Grant) 和 解锁 (Unlock)
    // grantpt: 修改从设备的权限
    // unlockpt: 允许打开从设备
    if (grantpt(master_fd) < 0) {
        log_error("grantpt failed: %s", strerror(errno));
        close(master_fd);
        return -1;
    }
    
    if (unlockpt(master_fd) < 0) {
        log_error("unlockpt failed: %s", strerror(errno));
        close(master_fd);
        return -1;
    }

    // 3. 获取从设备名称 (Slave Name) - 使用线程安全的 ptsname_r
    char slave_path[PATH_MAX];
    if (ptsname_r(master_fd, slave_path, sizeof(slave_path)) != 0) {
        log_error("ptsname_r failed: %s", strerror(errno));
        close(master_fd);
        return -1;
    }
    
    log_warn("virtio-console pty path: %s", slave_path);

    // 4. 【关键步骤】配置从设备 (Slave)
    // 必须打开 Slave 才能设置 Termios 属性 (cfmakeraw)
    // 如果不这样做，PTY 默认处于 "Canonical Mode"（行缓冲+回显），会导致 Console 卡住或显示异常
    int slave_fd = open(slave_path, O_RDWR | O_NOCTTY);
    if (slave_fd < 0) {
        log_error("failed to open slave pty '%s' for config: %s", slave_path, strerror(errno));
        close(master_fd);
        return -1;
    }

    struct termios tio;
    if (tcgetattr(slave_fd, &tio) < 0) {
        log_error("tcgetattr on slave failed");
        close(slave_fd);
        close(master_fd);
        return -1;
    }

    // 设置 Raw 模式：
    // - 禁用输入/输出处理 (如回车转换行)
    // - 禁用回显 (ECHO)
    // - 禁用信号字符 (如 Ctrl+C 发送 SIGINT)
    cfmakeraw(&tio);
    
    // 应用设置
    if (tcsetattr(slave_fd, TCSANOW, &tio) < 0) {
        log_error("tcsetattr on slave failed");
        close(slave_fd);
        close(master_fd);
        return -1;
    }

    // 配置完成后关闭 Slave FD
    // 只要 Master FD 保持打开，PTY 会话就会一直存在
    // 外部工具 (如 screen/minicom) 稍后会再次打开这个 slave_path
    close(slave_fd);

    // 5. 设置 Master FD 为非阻塞
    // 这是为了配合 io_uring 或 epoll 使用
    if (set_nonblocking(master_fd) < 0) {
        log_error("failed to set master_fd non-blocking");
        close(master_fd);
        return -1;
    }

    // 6. 保存到设备结构体
    dev->master_fd = master_fd;
    vdev->virtio_close = virtio_console_close;
    
    return 0;
}

int virtio_console_queue_resize(VirtIODevice *vdev, int queue_idx, int new_num) {
    log_info("virtio_console_queue_resize called: vdev=%p, queue_idx=%d, new_num=%d",
             vdev, queue_idx, new_num);
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
