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
#include <errno.h>
#include <liburing.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "event_monitor.h"
#include "log.h"

static struct io_uring ring;
static int events_num;
int closing;
#define MAX_EVENTS 4096 // Increased for high concurrency
struct hvisor_event *events[MAX_EVENTS];

struct io_uring *get_global_ring(void) { return &ring; }

/**
 * Run the io_uring event loop
 *
 * This is the core reactor loop for the single-threaded virtio daemon.
 * It blocks waiting for io_uring completion queue events (CQEs), which can be:
 * 1. Completion of submitted I/O operations (Disk read/write)
 * 2. Notification events from eventfds (e.g., interrupts from kernel, signalfd)
 *
 * The loop runs indefinitely until the process is terminated via signal or
 * fatal error.
 */
void run_event_loop(void) {
    struct io_uring_cqe *cqe;
    struct hvisor_event *hevent;
    int ret;

    for (;;) {
        // Wait for at least one event. This is a blocking call.
        // In a single-threaded model, this is where the CPU yields when idle.
        ret = io_uring_wait_cqe(&ring, &cqe);
        
        // Handle errors from wait
        if (ret < 0) {
            // EINTR (Interrupted system call) is normal if a signal is caught
            // by a registered signal handler, but since we use signalfd,
            // standard signals shouldn't interrupt us in a way that sets errno=EINTR
            // unless it's a signal we didn't mask.
            if (ret != -EINTR)
                log_error("io_uring_wait_cqe failed, errno is %d", -ret);
            continue;
        }

        // Get the user data associated with the event
        hevent = io_uring_cqe_get_data(cqe);
        
        if (hevent != NULL) {
            if (hevent->completion_handler) {
                // --- Case 1: Async I/O Completion ---
                // This event represents the completion of a disk I/O or network I/O
                // operation that was previously submitted (e.g., io_uring_prep_readv).
                
                bool free_on_completion = hevent->free_on_completion;
                
                // Call the specific completion handler (e.g., virtio_blk_completion_handler)
                // The 'res' field contains the result of the operation (e.g., bytes read)
                hevent->completion_handler(hevent->param, cqe->res);
                
                // Clean up the event structure if it was allocated for a single-shot I/O
                if (free_on_completion) {
                    free(hevent);
                }
            } else if (hevent->handler) {
                // --- Case 2: Poll Event Notification ---
                // This event represents a file descriptor becoming ready (e.g., POLLIN).
                // Typically used for:
                // - eventfd (kernel interrupt notification)
                // - signalfd (process termination signals)
                
                // Check for errors or cancellation in the poll result
                if (cqe->res < 0) {
                    // -ECANCELED happens when we remove the poll request.
                    // Other errors might indicate a bad FD or other issues.
                    if (cqe->res != -ECANCELED && cqe->res != -EAGAIN && cqe->res != -EINTR)
                        log_debug("poll event error: %d", cqe->res);
                } else {
                    // The FD is ready. Call the registered handler (e.g., virtio_irq_handler).
                    // This handler will process the actual business logic (e.g., virtio queue).
                    hevent->handler(hevent->fd, hevent->epoll_type,
                                    hevent->param);
                }
                
                // Note: We use IORING_POLL_ADD_MULTI, so the poll request remains active
                // and will trigger again when the FD becomes ready again.
                // No need to re-arm.
            }
        } else {
            // This should technically not happen if we always set user data
            log_error("hevent shouldn't be null");
        }

        // Mark the CQE as seen so the kernel can reuse the ring slot
        io_uring_cqe_seen(&ring, cqe);
    }
}

struct hvisor_event *add_completion_event(void (*handler)(void *, int),
                                          void *param) {
    struct hvisor_event *hevent = calloc(1, sizeof(struct hvisor_event));
    if (!hevent)
        return NULL;
    hevent->completion_handler = handler;
    hevent->param = param;
    hevent->free_on_completion = true;
    return hevent;
}

struct hvisor_event *add_event(int fd, int epoll_type,
                               void (*handler)(int, int, void *), void *param) {
    struct hvisor_event *hevent;
    struct io_uring_sqe *sqe;

    if (events_num >= MAX_EVENTS) {
        log_error("events are full");
        return NULL;
    }
    if (fd < 0 || handler == NULL) {
        log_error("invalid fd or handler");
        return NULL;
    }
    hevent = calloc(1, sizeof(struct hvisor_event));
    hevent->handler = handler;
    hevent->param = param;
    hevent->fd = fd;
    hevent->epoll_type = epoll_type;
    hevent->polling = true;

    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_poll_add(sqe, fd, epoll_type);
    // Enable Multishot Poll
    sqe->len |= IORING_POLL_ADD_MULTI;
    io_uring_sqe_set_data(sqe, hevent);
    io_uring_submit(&ring);

    events[events_num] = hevent;
    events_num++;
    return hevent;
}

void enable_event_poll(struct hvisor_event *hevent) {
    if (hevent->polling) {
        return;
    }
    hevent->polling = true;
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_poll_add(sqe, hevent->fd, hevent->epoll_type);
    sqe->len |= IORING_POLL_ADD_MULTI;
    io_uring_sqe_set_data(sqe, hevent);
    io_uring_submit(&ring);
}

void disable_event_poll(struct hvisor_event *hevent) {
    if (!hevent->polling) {
        return;
    }
    hevent->polling = false;
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_poll_remove(sqe, (__u64)hevent);
    io_uring_sqe_set_data(
        sqe, hevent); // Not strictly necessary for remove but good practice
    io_uring_submit(&ring);
}

// Initialize io_uring
int initialize_event_monitor() {
    int ret = io_uring_queue_init(MAX_EVENTS, &ring, 0);
    if (ret < 0) {
        log_error("io_uring_queue_init failed");
        return -1;
    }
    log_debug("io_uring initialized");
    return 0;
}

void destroy_event_monitor() { io_uring_queue_exit(&ring); }
