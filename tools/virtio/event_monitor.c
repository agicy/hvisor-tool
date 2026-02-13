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
#include <sys/signalfd.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "event_monitor.h"
#include "log.h"
#include "hvisor.h"
#include "virtio.h"

#define QUEUE_DEPTH 256

static struct io_uring ring;
static int signal_fd = -1;
static int irq_event_fd = -1;
static int irq_inject_fd = -1;
static uint64_t irq_notify_val = 1;
// Pre-allocated request data for injection
static struct request_data inject_req = { 
    .type = REQ_TYPE_IO_WRITE, 
    .fd = -1, 
    .cb = NULL, 
    .param = NULL, 
    .dynamic = false 
};

extern int ko_fd; // defined in hvisor.c or virtio.c
extern volatile struct virtio_bridge *virtio_bridge;

void io_flush(void) {
    io_uring_submit(&ring);
}

static struct io_uring_sqe *get_sqe_safe(void) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        // SQ is full, submit current entries to make space
        io_uring_submit(&ring);
        sqe = io_uring_get_sqe(&ring);
        if (!sqe) {
            log_error("SQ ring is full even after submit");
            return NULL;
        }
    }
    return sqe;
}

static void resubmit_poll_read(struct request_data *req) {
    // Only resubmit for persistent monitors like signal and eventfd
    struct io_uring_sqe *sqe = get_sqe_safe();
    if (!sqe) {
        log_error("Failed to get sqe for resubmit");
        return;
    }
    io_uring_prep_poll_add(sqe, req->fd, POLL_IN);
    io_uring_sqe_set_data(sqe, req);
    // Auto-flush for internal maintenance
    io_uring_submit(&ring);
}

static void handle_signal(int fd) {
    struct signalfd_siginfo fdsi;
    ssize_t s = read(fd, &fdsi, sizeof(struct signalfd_siginfo));
    if (s != sizeof(struct signalfd_siginfo)) {
        log_error("read signalfd failed");
        return;
    }
    if (fdsi.ssi_signo == SIGINT || fdsi.ssi_signo == SIGTERM) {
        log_info("Received signal %d, exiting...", fdsi.ssi_signo);
        destroy_event_monitor();
        exit(0);
    }
}

static void handle_eventfd(int fd) {
    uint64_t u;
    ssize_t s = read(fd, &u, sizeof(uint64_t));
    if (s != sizeof(uint64_t)) {
        log_error("read eventfd failed");
        return;
    }
    // Process requests from shared memory
    // Access virtio_bridge
    if (virtio_bridge) {
         unsigned int head = virtio_bridge->req_front;
         unsigned int tail = virtio_bridge->req_rear;
         while (!is_queue_empty(head, tail)) {
             volatile struct device_req *req = &virtio_bridge->req_list[head];
             virtio_handle_req(req);
             read_barrier();
             head = (head + 1) & (MAX_REQ - 1);
         }
         virtio_bridge->req_front = head;
         write_barrier();
    }
}

int initialize_event_monitor(void) {
    int ret;
    
    // Initialize io_uring
    ret = io_uring_queue_init(QUEUE_DEPTH, &ring, 0);
    if (ret < 0) {
        log_error("io_uring_queue_init failed: %d", ret);
        return -1;
    }

    // Setup signalfd
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
        log_error("sigprocmask failed");
        return -1;
    }
    signal_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (signal_fd == -1) {
        log_error("signalfd failed");
        return -1;
    }

    struct request_data *sig_req = malloc(sizeof(struct request_data));
    sig_req->type = REQ_TYPE_SIGNAL;
    sig_req->fd = signal_fd;
    sig_req->dynamic = true;
    
    struct io_uring_sqe *sqe = get_sqe_safe();
    io_uring_prep_poll_add(sqe, signal_fd, POLL_IN);
    io_uring_sqe_set_data(sqe, sig_req);

    // Setup eventfd for driver wake up
    irq_event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (irq_event_fd == -1) {
        log_error("eventfd failed");
        return -1;
    }
    
    if (ioctl(ko_fd, HVISOR_SET_EVENTFD, irq_event_fd) < 0) {
        log_error("ioctl HVISOR_SET_EVENTFD failed");
        return -1;
    }

    struct request_data *evt_req = malloc(sizeof(struct request_data));
    evt_req->type = REQ_TYPE_EVENTFD;
    evt_req->fd = irq_event_fd;
    evt_req->dynamic = true;

    sqe = get_sqe_safe();
    io_uring_prep_poll_add(sqe, irq_event_fd, POLL_IN);
    io_uring_sqe_set_data(sqe, evt_req);

    // Setup irq inject fd
    irq_inject_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (irq_inject_fd == -1) {
        log_error("irq_inject_fd failed");
        return -1;
    }
    
    if (ioctl(ko_fd, HVISOR_SET_IRQFD, irq_inject_fd) < 0) {
        log_error("ioctl HVISOR_SET_IRQFD failed");
        // We can fallback to sync ioctl, so maybe not return -1?
        // But for this task we assume kernel supports it.
        return -1;
    }
    inject_req.fd = irq_inject_fd;

    io_uring_submit(&ring);
    return 0;
}

void monitor_loop(void) {
    struct io_uring_cqe *cqe;
    struct request_data *req;
    
    log_info("Starting io_uring monitor loop");
    
    for (;;) {
        // Use io_uring_submit_and_wait to ensure any pending SQEs are submitted
        int ret = io_uring_submit_and_wait(&ring, 1);
        if (ret < 0) {
            if (ret == -EINTR) continue;
            log_error("io_uring_submit_and_wait failed: %d", ret);
            break;
        }

        // Process all available CQEs
        unsigned head;
        int count = 0;
        io_uring_for_each_cqe(&ring, head, cqe) {
            req = io_uring_cqe_get_data(cqe);
            int res = cqe->res;
            
            if (req) {
                switch (req->type) {
                    case REQ_TYPE_POLL_READ:
                        if (res >= 0) {
                            event_handler_t handler = (event_handler_t)req->cb;
                            handler(req->fd, req->param);
                            // Do NOT automatically resubmit for POLL_READ
                            // The handler is responsible for re-arming or submitting async read
                            if (req->dynamic) free(req); 
                        } else {
                            log_error("POLL_READ error: %d", res);
                            // Handle error, maybe free req or retry?
                            // For now, assume fatal for this poll req
                            if (req->dynamic) free(req);
                        }
                        break;
                    case REQ_TYPE_SIGNAL:
                        if (res >= 0) {
                            handle_signal(req->fd);
                            resubmit_poll_read(req);
                        }
                        break;
                    case REQ_TYPE_EVENTFD:
                        if (res >= 0) {
                            handle_eventfd(req->fd);
                            resubmit_poll_read(req);
                        }
                        break;
                    case REQ_TYPE_IO_READ:
                    case REQ_TYPE_IO_WRITE:
                        {
                            if (req->cb) {
                                io_completion_t cb = (io_completion_t)req->cb;
                                cb(req->param, res);
                            }
                            if (req->dynamic) free(req); // Free per-IO request data if dynamic
                        }
                        break;
                }
            }
            count++;
        }
        io_uring_cq_advance(&ring, count);
    }
}

int add_event_read(int fd, event_handler_t handler, void *param) {
    struct request_data *req = malloc(sizeof(struct request_data));
    if (!req) return -1;
    req->type = REQ_TYPE_POLL_READ;
    req->fd = fd;
    req->cb = handler;
    req->param = param;
    req->dynamic = true;

    struct io_uring_sqe *sqe = get_sqe_safe();
    if (!sqe) {
        free(req);
        return -1;
    }
    io_uring_prep_poll_add(sqe, fd, POLL_IN);
    io_uring_sqe_set_data(sqe, req);
    // Do NOT submit immediately
    return 0;
}

int add_event_read_prealloc(int fd, event_handler_t handler, void *param, struct request_data *req) {
    if (!req) return -1;
    req->type = REQ_TYPE_POLL_READ;
    req->fd = fd;
    req->cb = handler;
    req->param = param;
    req->dynamic = false;

    struct io_uring_sqe *sqe = get_sqe_safe();
    if (!sqe) {
        return -1;
    }
    io_uring_prep_poll_add(sqe, fd, POLL_IN);
    io_uring_sqe_set_data(sqe, req);
    return 0;
}

int submit_async_readv(int fd, const struct iovec *iov, int iovcnt, uint64_t offset, io_completion_t cb, void *param) {
    struct request_data *req = malloc(sizeof(struct request_data));
    if (!req) return -1;
    req->type = REQ_TYPE_IO_READ;
    req->fd = fd;
    req->cb = cb;
    req->param = param;
    req->dynamic = true;

    struct io_uring_sqe *sqe = get_sqe_safe();
    if (!sqe) {
        free(req);
        return -1;
    }
    io_uring_prep_readv(sqe, fd, iov, iovcnt, offset);
    io_uring_sqe_set_data(sqe, req);
    // Do NOT submit immediately
    return 0;
}

int submit_async_readv_prealloc(int fd, const struct iovec *iov, int iovcnt, uint64_t offset, io_completion_t cb, void *param, struct request_data *req) {
    if (!req) return -1;
    req->type = REQ_TYPE_IO_READ;
    req->fd = fd;
    req->cb = cb;
    req->param = param;
    req->dynamic = false;

    struct io_uring_sqe *sqe = get_sqe_safe();
    if (!sqe) {
        return -1;
    }
    io_uring_prep_readv(sqe, fd, iov, iovcnt, offset);
    io_uring_sqe_set_data(sqe, req);
    return 0;
}

int submit_async_writev(int fd, const struct iovec *iov, int iovcnt, uint64_t offset, io_completion_t cb, void *param) {
    struct request_data *req = malloc(sizeof(struct request_data));
    if (!req) return -1;
    req->type = REQ_TYPE_IO_WRITE;
    req->fd = fd;
    req->cb = cb;
    req->param = param;
    req->dynamic = true;

    struct io_uring_sqe *sqe = get_sqe_safe();
    if (!sqe) {
        free(req);
        return -1;
    }
    io_uring_prep_writev(sqe, fd, iov, iovcnt, offset);
    io_uring_sqe_set_data(sqe, req);
    // Do NOT submit immediately
    return 0;
}

int submit_async_writev_prealloc(int fd, const struct iovec *iov, int iovcnt, uint64_t offset, io_completion_t cb, void *param, struct request_data *req) {
    if (!req) return -1;
    req->type = REQ_TYPE_IO_WRITE;
    req->fd = fd;
    req->cb = cb;
    req->param = param;
    req->dynamic = false;

    struct io_uring_sqe *sqe = get_sqe_safe();
    if (!sqe) {
        return -1;
    }
    io_uring_prep_writev(sqe, fd, iov, iovcnt, offset);
    io_uring_sqe_set_data(sqe, req);
    return 0;
}

void submit_irq_inject_async(void) {
    if (irq_inject_fd == -1) {
        // Fallback to sync ioctl if eventfd is not ready
        ioctl(ko_fd, HVISOR_FINISH_REQ);
        return;
    }
    
    struct io_uring_sqe *sqe = get_sqe_safe();
    if (!sqe) {
        // Fallback to sync ioctl if SQ is full
        ioctl(ko_fd, HVISOR_FINISH_REQ);
        return;
    }
    
    io_uring_prep_write(sqe, irq_inject_fd, &irq_notify_val, sizeof(uint64_t), 0);
    io_uring_sqe_set_data(sqe, &inject_req);
    // We don't flush immediately to allow batching. 
    // The main loop or subsequent IOs will flush.
}

void destroy_event_monitor(void) {
    if (signal_fd != -1) close(signal_fd);
    if (irq_event_fd != -1) close(irq_event_fd);
    if (irq_inject_fd != -1) close(irq_inject_fd);
    io_uring_queue_exit(&ring);
}
