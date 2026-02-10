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
#include "event_monitor.h"
#include "log.h"

#include <errno.h>
#include <liburing.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

/// @brief The global io_uring ring instance.
static struct io_uring ring;

/// @brief The number of events currently registered.
static int events_num;

/// @brief Array to store registered events.
static struct hvisor_event *events[MAX_EVENTS];

static void handle_cqe(struct io_uring_cqe *cqe);

int initialize_event_monitor(void) {
    log_debug("initializing io_uring");

    int ret = io_uring_queue_init(MAX_EVENTS, &ring, 0);
    if (ret < 0) {
        log_error("io_uring_queue_init failed");
        return -1;
    }

    log_debug("io_uring initialized");
    return 0;
}

void destroy_event_monitor(void) {
    log_debug("destroying io_uring");

    for (int i = 0; i < events_num; i++) {
        free(events[i]);
    }
    io_uring_queue_exit(&ring);

    log_debug("io_uring destroyed");
    return;
}

struct io_uring *get_global_ring(void) { return &ring; }

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

struct hvisor_event *add_persistent_event(int fd, int epoll_type,
                                          void (*handler)(int, int, void *),
                                          void *param) {
    if (events_num >= MAX_EVENTS) {
        log_error("events are full, max events is %d", MAX_EVENTS);
        return NULL;
    }

    if (fd < 0) {
        log_error("invalid fd %d", fd);
        return NULL;
    }

    if (!handler) {
        log_error("handler is NULL");
        return NULL;
    }

    struct hvisor_event *hevent = calloc(1, sizeof(struct hvisor_event));
    if (!hevent) {
        log_debug("calloc hvisor_event failed");
        return NULL;
    }

    hevent->handler = handler;
    hevent->param = param;
    hevent->fd = fd;
    hevent->epoll_type = epoll_type;

    enable_event_poll(hevent);

    events[events_num] = hevent;
    events_num++;
    return hevent;
}

struct hvisor_event *add_completion_event(void (*handler)(void *, int),
                                          void *param) {
    struct hvisor_event *hevent = calloc(1, sizeof(struct hvisor_event));
    if (!hevent) {
        log_debug("calloc hvisor_event failed");
        return NULL;
    }

    hevent->completion_handler = handler;
    hevent->param = param;
    hevent->free_on_completion = true;
    return hevent;
}

void run_event_loop(void) {
    struct io_uring_cqe *cqes[IO_URING_BATCH_SIZE];
    struct io_uring_cqe *cqe;

    for (;;) {
        // Try peeking a batch of events
        int count = io_uring_peek_batch_cqe(&ring, cqes, IO_URING_BATCH_SIZE);

        // If no events are ready, wait for at least one (blocking)
        if (!count) {
            // Blocks until at least 1 event is ready
            int ret = io_uring_submit_and_wait(&ring, 1);

            if (ret < 0) {
                if (ret != -EINTR)
                    log_error("io_uring_submit_and_wait failed, errno is %d",
                              -ret);
                continue;
            }

            // Events are ready, pick them up in batch
            count = io_uring_peek_batch_cqe(&ring, cqes, IO_URING_BATCH_SIZE);
        }

        // Process all events in the batch
        for (int i = 0; i < count; i++) {
            handle_cqe(cqes[i]);
        }

        // Mark all CQEs as seen at once
        io_uring_cq_advance(&ring, count);
    }

    // Unreachable: If the loop exits, it means something went wrong
    log_error("run_event_loop should not reach here");
    exit(EXIT_FAILURE);
}

/// @brief Handle a completion queue event (CQE).
/// @param cqe The completion queue event to handle.
static void handle_cqe(struct io_uring_cqe *cqe) {
    // Get the hvisor_event associated with this CQE
    struct hvisor_event *hevent = io_uring_cqe_get_data(cqe);
    if (!hevent) {
        log_error("hevent shouldn't be null");
        return;
    }

    // There are two types of events:
    // 1. Completion events: CQEs for completed I/O operations
    //    - For disk I/O: CQEs for completed read/write operations
    //    - For network I/O: CQEs for completed receive/send operations
    // 2. Poll events: CQEs for notification events
    //    - For eventfds: CQEs for notification of events (e.g., interrupts)
    //    - For signalfds: CQEs for notification of signals (e.g., SIGINT)
    if (hevent->completion_handler) {
        // --- Case 1: Async I/O Completion ---
        bool free_on_completion = hevent->free_on_completion;
        hevent->completion_handler(hevent->param, cqe->res);
        if (free_on_completion) {
            free(hevent);
        }
    } else if (hevent->handler) {
        // --- Case 2: Poll Event Notification ---
        if (cqe->res < 0) {
            if (cqe->res != -ECANCELED && cqe->res != -EAGAIN &&
                cqe->res != -EINTR) {
                log_debug("poll event error: %d", cqe->res);
            }
        } else {
            // Call the handler for poll events
            hevent->handler(hevent->fd, hevent->epoll_type, hevent->param);
        }
    }
}
