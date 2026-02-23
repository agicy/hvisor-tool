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
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "coroutine_utils.hpp"
#include "event_monitor.h"
#include "hvisor.h"
#include "io_uring_context.hpp"
#include "log.h"
#include "virtio.h"

static virtio::IoUringContext *g_io_context = nullptr;
static int signal_fd = -1;
static int irq_event_fd = -1;
static int irq_inject_fd = -1;
static uint64_t irq_notify_val = 1;
static virtio::CoroutineEvent irq_inject_event;

extern int ko_fd;
extern volatile struct virtio_bridge *virtio_bridge;
void virtio_close(void);

virtio::IoUringContext *get_io_context() { return g_io_context; }

// Coroutine to handle signals
virtio::Task signal_handler_task(int fd) {
    log_info("signal_handler_task started");
    
    struct signalfd_siginfo fdsi;

    while (true) {
        log_info("signal_handler_task waiting");

        auto res =
            co_await g_io_context->async_read(fd, &fdsi, sizeof(fdsi), 0);

        log_info("signal_handler_task signaled");

        if (res == sizeof(fdsi)) {
            if (fdsi.ssi_signo == SIGINT || fdsi.ssi_signo == SIGTERM) {
                log_info("Received signal %d, exiting...", fdsi.ssi_signo);
                virtio_close();
                exit(0);
            }
        }
    }
}

// Coroutine to handle IRQ injection (persistent)
virtio::Task irq_inject_worker_task(int fd) {
    log_info("irq_inject_worker_task started");

    uint64_t val = 1;
    while (true) {
        // TODO
        log_info("waiting irq_inject_event");

        // Wait for signal
        co_await irq_inject_event;

        // TODO
        log_info("irq_inject_event signaled");

        // Perform async write to inject irq
        co_await g_io_context->async_write(fd, &val, sizeof(val), 0);
    }
}

// Coroutine to handle IRQ event (driver kick from Hypervisor)
virtio::Task irq_event_task(int fd) {
    log_info("irq_event_task started");

    uint64_t val;
    while (true) {
        // 1. 准备进入等待状态：设置 need_wakeup = 1
        virtio_bridge->need_wakeup = 1;
        write_barrier(); // 确保内核能立即看到该标志

        // 2. 在真正挂起前，最后检查一次队列，防止“丢失唤醒” (Lost Wakeup)
        // 也就是防止内核在设置 need_wakeup 之前塞入请求且没发信号
        unsigned int head = virtio_bridge->req_front;
        unsigned int tail = virtio_bridge->req_rear;
        read_barrier();

        if (is_queue_empty(head, tail)) {
            log_trace("waiting irq_event_task (queue empty)");
            // 真正挂起协程，等待内核通过 eventfd/signalfd 唤醒
            auto res = co_await g_io_context->async_read(fd, &val, sizeof(val), 0);
            if (res < 0) {
                log_error("irq_event_task read error: %s", strerror(errno));
                continue;
            }
            log_trace("irq_event_task signaled (notified by kernel)");
        } else {
            log_trace("irq_event_task: data arrived before sleep, skip waiting");
        }

        // 3. 已经被唤醒或发现有数据：设置 need_wakeup = 0
        // 告诉内核：我现在正在忙碌处理，你往队列里放数据即可，不用再发信号
        virtio_bridge->need_wakeup = 0;
        write_barrier();

        // 4. 批量处理队列中的所有请求
        head = virtio_bridge->req_front;
        tail = virtio_bridge->req_rear;
        read_barrier();

        while (!is_queue_empty(head, tail)) {
            volatile struct device_req *req = &virtio_bridge->req_list[head];
            
            // 处理具体的 MMIO 读写请求
            virtio_handle_req(req);

            // 移动指针并写屏障，让内核知道我们处理到哪了
            head = (head + 1) & (MAX_REQ - 1);
            virtio_bridge->req_front = head;
            write_barrier();

            // 重新获取 tail。因为在处理期间，内核可能又塞入了新请求
            tail = virtio_bridge->req_rear;
            read_barrier();
        }
    }
}

int initialize_event_monitor(void) {
    try {
        g_io_context = new virtio::IoUringContext();
    } catch (...) {
        log_error("Failed to create io_uring context");
        return -1;
    }

    // Setup signalfd to handle SIGINT and SIGTERM
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    // Block SIGINT and SIGTERM to avoid signal handler conflicts
    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
        log_error("sigprocmask failed");
        return -1;
    }
    signal_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (signal_fd == -1) {
        log_error("signalfd failed");
        return -1;
    }

    // Setup eventfd for driver wake up
    irq_event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (irq_event_fd == -1) {
        log_error("eventfd failed");
        return -1;
    }
    // Register irq_event_fd with HVISOR_SET_EVENTFD ioctl
    if (ioctl(ko_fd, HVISOR_SET_EVENTFD, irq_event_fd) < 0) {
        log_error("ioctl HVISOR_SET_EVENTFD failed");
        return -1;
    }

    // Setup irq inject fd
    irq_inject_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (irq_inject_fd == -1) {
        log_error("irq_inject_fd failed");
        return -1;
    }
    // Register irq_inject_fd with HVISOR_SET_IRQFD ioctl
    if (ioctl(ko_fd, HVISOR_SET_IRQFD, irq_inject_fd) < 0) {
        log_error("ioctl HVISOR_SET_IRQFD failed");
        return -1;
    }

    // Start signal handler task (detached)
    signal_handler_task(signal_fd);
    // Start irq event task (detached)
    irq_event_task(irq_event_fd);
    // Start irq inject worker task (persistent)
    irq_inject_worker_task(irq_inject_fd);

    return 0;
}

void monitor_loop(void) {
    log_info("Starting io_uring monitor loop");
    while (true) {
        g_io_context->run_once();
    }
}

void io_flush(void) {
    if (g_io_context)
        g_io_context->submit();
}

void destroy_event_monitor(void) {
    if (signal_fd != -1)
        close(signal_fd);
    if (irq_event_fd != -1)
        close(irq_event_fd);
    if (irq_inject_fd != -1)
        close(irq_inject_fd);
    delete g_io_context;
    g_io_context = nullptr;
}

void submit_irq_inject_async(void) {
    // Signal the persistent worker to perform the injection
    // This avoids allocating a new coroutine frame for every injection
    irq_inject_event.signal();
}

// Wrapper coroutines for legacy callbacks
virtio::Task wrapper_readv_task(int fd, const struct iovec *iov, int iovcnt,
                                uint64_t offset, io_completion_t cb,
                                void *param) {
    auto res = co_await g_io_context->async_readv(fd, iov, iovcnt, offset);
    if (cb)
        cb(param, res);
}

virtio::Task wrapper_writev_task(int fd, const struct iovec *iov, int iovcnt,
                                 uint64_t offset, io_completion_t cb,
                                 void *param) {
    auto res = co_await g_io_context->async_writev(fd, iov, iovcnt, offset);
    if (cb)
        cb(param, res);
}

virtio::Task wrapper_poll_task(int fd, event_handler_t handler, void *param) {
    auto res = co_await g_io_context->async_poll(fd);
    if (res >= 0 && handler)
        handler(fd, param);
}

// Legacy API implementations
int submit_async_readv(int fd, const struct iovec *iov, int iovcnt,
                                  uint64_t offset, io_completion_t cb,
                                  void *param) {
    wrapper_readv_task(fd, iov, iovcnt, offset, cb, param);
    return 0;
}

int submit_async_readv_prealloc(int fd, const struct iovec *iov,
                                           int iovcnt, uint64_t offset,
                                           io_completion_t cb, void *param,
                                           struct request_data *req) {
    // Ignore req, we rely on coroutine frame
    wrapper_readv_task(fd, iov, iovcnt, offset, cb, param);
    return 0;
}

int submit_async_writev(int fd, const struct iovec *iov, int iovcnt,
                                   uint64_t offset, io_completion_t cb,
                                   void *param) {
    wrapper_writev_task(fd, iov, iovcnt, offset, cb, param);
    return 0;
}

int submit_async_writev_prealloc(int fd, const struct iovec *iov,
                                            int iovcnt, uint64_t offset,
                                            io_completion_t cb, void *param,
                                            struct request_data *req) {
    wrapper_writev_task(fd, iov, iovcnt, offset, cb, param);
    return 0;
}

int add_event_read(int fd, event_handler_t handler, void *param) {
    wrapper_poll_task(fd, handler, param);
    return 0;
}

int add_event_read_prealloc(int fd, event_handler_t handler,
                                       void *param, struct request_data *req) {
    wrapper_poll_task(fd, handler, param);
    return 0;
}
