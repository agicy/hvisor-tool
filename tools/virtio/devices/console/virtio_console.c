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
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <termios.h>

static uint8_t trashbuf[1024];

// 分配 virtio console 设备结构体
// 
// 初始化 ConsoleDev 结构体并返回指针。
// 
// 返回值：
//   分配并初始化后的 ConsoleDev 指针
ConsoleDev *virtio_console_alloc_dev() {
    ConsoleDev *dev = (ConsoleDev *)calloc(1, sizeof(ConsoleDev));
    dev->config.cols = 80;
    dev->config.rows = 25;
    dev->master_fd = -1;
    dev->rx_ready = -1;
    dev->pending_rx = 0;
    dev->rx_poll_active = false;
    dev->rx_ctxs = calloc(VIRTQUEUE_CONSOLE_MAX_SIZE, sizeof(struct console_read_ctx));
    dev->tx_ctxs = calloc(VIRTQUEUE_CONSOLE_MAX_SIZE, sizeof(struct console_tx_ctx));
    dev->stalled_read_ctx = NULL;
    return dev;
}

static void virtio_console_event_handler(int fd, void *param);

// 异步读取完成回调
// 
// 处理异步读取完成后的逻辑，包括更新 used ring，注入中断，以及重新注册读事件。
// 
// 参数：
//   param: 回调上下文，包含 virtqueue 和 iovec 信息
//   res: 读取结果，大于 0 表示读取字节数，小于 0 表示错误码
static void virtio_console_async_read_done(void *param, int res) {
    struct console_read_ctx *ctx = param;
    VirtQueue *vq = ctx->vq;
    VirtIODevice *vdev = vq->dev;
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;
    ssize_t len = res;

    if (len < 0 && len != -EWOULDBLOCK && len != -EAGAIN) {
        log_trace("Failed to read from console, error is %d", -len);
        // Even on error, we might need to return the buffer? 
        // Or just reuse it? For now, behave like sync:
        vq->last_avail_idx--; 
    } else if (len > 0) {
        update_used_ring(vq, ctx->idx, len);
        virtio_inject_irq(vq);
    } else {
        // EOF or EAGAIN (0 or negative)
        // Store the context as stalled, do not update ring, do not rollback last_avail_idx
        log_debug("Console read EAGAIN, stalling context");
        dev->stalled_read_ctx = ctx;
    }

    // No need to free iov or ctx as they are statically allocated

    // Re-arm poll if all pending requests are done
    dev->pending_rx--;
    if (dev->pending_rx <= 0) {
        dev->pending_rx = 0; // Safety
        if (virtqueue_is_empty(vq) && !dev->stalled_read_ctx) {
            dev->rx_poll_active = false;
        } else if (!dev->rx_poll_active) {
            // Only re-arm if not already active
            add_event_read_prealloc(dev->master_fd, virtio_console_event_handler, vdev, &dev->poll_req);
            dev->rx_poll_active = true;
        }
    }
}

// 处理控制台主设备的读事件
// 
// 当 PTY master 有数据可读时被调用。该函数检查 virtqueue 是否有可用缓冲区，
// 如果有，则提交异步读取请求将数据读入客户机提供的缓冲区。
// 如果 virtqueue 为空，则暂停轮询以避免数据丢失。
// 
// 参数：
//   fd: 文件描述符 (master_fd)
//   param: VirtIODevice 指针
static void virtio_console_event_handler(int fd, void *param) {
    VirtIODevice *vdev = (VirtIODevice *)param;
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;
    VirtQueue *vq = &vdev->vqs[CONSOLE_QUEUE_RX];
    int n;
    uint16_t idx;

    if (fd != dev->master_fd) {
        log_error("Invalid console event");
        return;
    }
    if (dev->master_fd <= 0 || vdev->type != VirtioTConsole) {
        log_error("console event handler should not be called");
        return;
    }

    // Reset poll active flag because the poll event has triggered
    dev->rx_poll_active = false;

    // Handle stalled context first if any
    if (dev->stalled_read_ctx) {
        struct console_read_ctx *ctx = dev->stalled_read_ctx;
        dev->stalled_read_ctx = NULL;
        int ret = submit_async_readv_prealloc(dev->master_fd, ctx->iov, ctx->iovcnt, 0, virtio_console_async_read_done, ctx, &ctx->req_data);
        if (ret < 0) {
            log_error("Failed to resubmit stalled read for console: %d", ret);
            update_used_ring(vq, ctx->idx, 0);
            virtio_inject_irq(vq);
        } else {
            dev->pending_rx++;
        }
        // If we processed a stalled request, we might want to return or continue.
    // If we assume single-threaded and batching, we can continue to fill more if available.
    // But for safety and simplicity with EAGAIN logic, let's process one batch or just return if pending > 0?
    // Let's continue to fill pipeline if possible.
    }

    if (dev->rx_ready <= 0) {
        // Stop polling to implement backpressure.
        // When the driver provides buffers (via notify), we will re-arm the poll.
        log_trace("Console rx not ready, pausing poll");
        dev->rx_poll_active = false;
        return;
    }
    if (virtqueue_is_empty(vq) && dev->pending_rx == 0) { // Check pending_rx to avoid premature sleep if stalled was submitted
        // Already set to false above
        virtio_inject_irq(vq);
        return;
    }

    // Process multiple descriptor chains
    int loop_count = 0;
    while (loop_count < VIRTQUEUE_CONSOLE_MAX_SIZE) {
        if (virtqueue_is_empty(vq)) {
            break;
        }

        // We need to peek at the next idx to get the context
        // But process_descriptor_chain_into increments last_avail_idx.
        // That is fine.
        
        // However, we don't know the idx BEFORE calling process...
        // Wait, process_descriptor_chain_into returns the desc_idx via pointer.
        // We can use a temporary buffer or just use the ctx buffer after getting idx?
        // No, we need to know WHICH ctx to use.
        // But wait, the ctx is indexed by `idx` (descriptor head index).
        // And `process_descriptor_chain_into` TELLS us the `idx`.
        // So we can:
        // 1. Call process_descriptor_chain_into with a temporary stack buffer?
        //    No, that defeats the purpose of zero copy/alloc.
        //    Actually, we can't use `idx` to select `ctx` BEFORE calling it if we don't know `idx`.
        //    But `process_descriptor_chain_into` fills `idx`.
        //    So we can pass a dummy iov first? No.
        
        // Solution:
        // We can peek the ring manually to get `idx`?
        // Or we can just use `dev->rx_ctxs[something]`?
        // The issue is: `idx` is returned by `process...`.
        // But we need to pass `iov` pointer to `process...`.
        // 
        // Let's look at `process_descriptor_chain_into` implementation again.
        // It reads `idx` from ring: `*desc_idx = next = vq->avail_ring->ring[...]`.
        // 
        // We can duplicate that logic here to peek `idx`?
        // Or we can modify `process_descriptor_chain_into` to accept a callback to get buffer? No too complex.
        
        // Correct approach:
        // The `idx` (descriptor index) is within 0..QueueSize-1.
        // We can just peek it!
        uint16_t last_avail_idx = vq->last_avail_idx;
        uint16_t head_idx = vq->avail_ring->ring[last_avail_idx & (vq->num - 1)];
        if (head_idx >= vq->num) {
            log_error("head_idx %d out of bounds (queue num %d)", head_idx, vq->num);
            break;
        }
        
        struct console_read_ctx *ctx = &dev->rx_ctxs[head_idx];
        ctx->vq = vq;
        // ctx->idx will be set by process... or we set it.
        
        n = process_descriptor_chain_into(vq, &idx, ctx->iov, CONSOLE_IOV_MAX, NULL, 0, false);
        
        if (n < 1) {
            log_error("process_descriptor_chain failed or buffer too small");
            if (n == -1) {
                update_used_ring(vq, idx, 0);
                virtio_inject_irq(vq);
            }
            break;
        }
        
        ctx->idx = idx; // Should match head_idx
        ctx->iovcnt = n;

        // Submit async read
        int ret = submit_async_readv_prealloc(dev->master_fd, ctx->iov, n, 0, virtio_console_async_read_done, ctx, &ctx->req_data);
        if (ret < 0) {
            log_error("Failed to submit async read for console: %d", ret);
            update_used_ring(vq, idx, 0);
            virtio_inject_irq(vq);
        } else {
            dev->pending_rx++;
        }
        loop_count++;
    }

        if (loop_count > 0) {
        io_flush();
        // Pipeline optimization: if we still have buffers, re-arm poll immediately
        // instead of waiting for all IOs to complete.
        if (!dev->rx_poll_active && (!virtqueue_is_empty(vq) || dev->stalled_read_ctx)) {
            add_event_read_prealloc(dev->master_fd, virtio_console_event_handler, vdev, &dev->poll_req);
            dev->rx_poll_active = true;
        }
    } else {
        if (dev->pending_rx == 0 && !dev->stalled_read_ctx) {
             add_event_read_prealloc(dev->master_fd, virtio_console_event_handler, vdev, &dev->poll_req);
             dev->rx_poll_active = true;
        }
    }
}

// 初始化 virtio console 设备
// 
// 打开并配置 PTY 设备，设置非阻塞模式，并注册读事件监听。
// 
// 参数：
//   vdev: VirtIODevice 指针
// 
// 返回值：
//   成功返回 0，失败返回 -1
int virtio_console_init(VirtIODevice *vdev) {
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
    // Disable line discipline to prevent the TTY
    // from echoing the characters sent from the master back to the master.
    slave_fd = open(slave_name, O_RDWR);
    if (slave_fd < 0) {
        log_error("Failed to open slave pty, errno is %d", errno);
        close(master_fd);
        dev->master_fd = -1;
        return -1;
    }

    if (tcgetattr(slave_fd, &term_io) < 0) {
        log_error("Failed to get slave pty attrs");
        close(slave_fd);
        close(master_fd);
        dev->master_fd = -1;
        return -1;
    }
    cfmakeraw(&term_io);
    if (tcsetattr(slave_fd, TCSAFLUSH, &term_io) < 0) {
        log_error("Failed to set slave pty attrs");
        close(slave_fd);
        close(master_fd);
        dev->master_fd = -1;
        return -1;
    }
    close(slave_fd);

    if (set_nonblocking(dev->master_fd) < 0) {
        log_error("Failed to set nonblocking mode, fd closed!");
        close(dev->master_fd);
        dev->master_fd = -1;
        return -1;
    }

    int ret = add_event_read_prealloc(dev->master_fd, virtio_console_event_handler, vdev, &dev->poll_req);

    if (ret < 0) {
        log_error("Can't register console event");
        close(master_fd);
        dev->master_fd = -1;
        return -1;
    }
    dev->rx_poll_active = true;
    // We don't store struct hvisor_event* anymore, add_event_read returns int (0 or -1)
    // dev->event = NULL;

    vdev->virtio_close = virtio_console_close;
    return 0;
}

// RX 队列通知处理函数
// 
// 当客户机向 RX 队列添加缓冲区并通知设备时被调用。
// 如果之前因为队列为空而暂停了轮询，这里会恢复轮询。
// 
// 参数：
//   vdev: VirtIODevice 指针
//   vq: 接收队列 (RX Queue)
// 
// 返回值：
//   总是返回 0
int virtio_console_rxq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    log_debug("%s", __func__);
    ConsoleDev *dev = (ConsoleDev *)vdev->dev;
    if (dev->rx_ready <= 0) {
        dev->rx_ready = 1;
        virtqueue_disable_notify(vq);
        // We might want to trigger a read here if we were blocked on empty queue?
        // But poll handler handles "virtqueue_is_empty" check.
        // If data comes, poll triggers.
    }

    if (!dev->rx_poll_active && !virtqueue_is_empty(vq)) {
        add_event_read_prealloc(dev->master_fd, virtio_console_event_handler, vdev, &dev->poll_req);
        dev->rx_poll_active = true;
    }
    return 0;
}

// 异步写入完成回调
// 
// 处理异步写入完成后的逻辑，更新 used ring 并释放资源。
// 
// 参数：
//   param: 回调上下文
//   res: 写入结果
static void virtio_console_async_tx_done(void *param, int res) {
    struct console_tx_ctx *ctx = param;
    if (res < 0) {
        log_error("Failed to write to console, error is %d", -res);
    }
    update_used_ring(ctx->vq, ctx->idx, 0);
    virtio_inject_irq(ctx->vq);
    // No free needed
}

// 处理 TX 队列请求
// 
// 从 TX 队列获取数据并写入到 PTY master。
// 
// 参数：
//   dev: ConsoleDev 指针
//   vq: 发送队列 (TX Queue)
static void virtio_console_handle_tx_request(ConsoleDev *dev, VirtQueue *vq) {
    int n;
    uint16_t idx;
    if (dev->master_fd <= 0) {
        log_error("Console master fd is not ready");
        return;
    }

    // Peek head_idx to get ctx
    uint16_t last_avail_idx = vq->last_avail_idx;
    uint16_t head_idx = vq->avail_ring->ring[last_avail_idx & (vq->num - 1)];
    struct console_tx_ctx *ctx = &dev->tx_ctxs[head_idx];
    ctx->vq = vq;

    n = process_descriptor_chain_into(vq, &idx, ctx->iov, CONSOLE_IOV_MAX, NULL, 0, false);

    if (n < 1) {
        return;
    }
    
    ctx->idx = idx;
    ctx->iovcnt = n;

    int ret = submit_async_writev_prealloc(dev->master_fd, ctx->iov, n, 0, virtio_console_async_tx_done, ctx, &ctx->req_data);
    if (ret < 0) {
        log_error("Failed to submit async write for console: %d", ret);
        update_used_ring(ctx->vq, ctx->idx, 0);
        virtio_inject_irq(ctx->vq);
    }
}

// TX 队列通知处理函数
// 
// 当客户机向 TX 队列添加数据并通知设备时被调用。
// 处理队列中的所有挂起请求。
// 
// 参数：
//   vdev: VirtIODevice 指针
//   vq: 发送队列 (TX Queue)
// 
// 返回值：
//   总是返回 0
int virtio_console_txq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    log_debug("%s", __func__);
    while (!virtqueue_is_empty(vq)) {
        virtqueue_disable_notify(vq);
        while (!virtqueue_is_empty(vq)) {
            virtio_console_handle_tx_request(vdev->dev, vq);
        }
        virtqueue_enable_notify(vq);
    }
    io_flush(); // Flush TX requests
    return 0;
}

int virtio_console_queue_resize(VirtIODevice *vdev, int queue_idx, int new_num) {
    ConsoleDev *con = vdev->dev;
    if (new_num > VIRTQUEUE_CONSOLE_MAX_SIZE) {
        log_info("Resizing Console Queue contexts to %d", new_num);
        struct console_read_ctx *new_rx = realloc(con->rx_ctxs, sizeof(struct console_read_ctx) * new_num);
        struct console_tx_ctx *new_tx = realloc(con->tx_ctxs, sizeof(struct console_tx_ctx) * new_num);
        if (new_rx) con->rx_ctxs = new_rx;
        if (new_tx) con->tx_ctxs = new_tx;
        if (!new_rx || !new_tx) {
            log_error("Failed to realloc console queue contexts");
            return -1;
        }
    }
    return 0;
}

// 关闭 virtio console 设备
// 
// 关闭 PTY master 文件描述符并释放设备资源。
// 
// 参数：
//   vdev: VirtIODevice 指针
void virtio_console_close(VirtIODevice *vdev) {
    ConsoleDev *dev = vdev->dev;
    close(dev->master_fd);
    free(dev->rx_ctxs);
    free(dev->tx_ctxs);
    free(dev);
    free(vdev->vqs);
    free(vdev);
}
