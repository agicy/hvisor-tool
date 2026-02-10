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

// Removed global events array as caller manages memory now
// static struct poll_event *events[MAX_EVENTS];

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
    // No need to free events[] as we don't own them anymore
    io_uring_queue_exit(&ring);

    log_debug("io_uring destroyed");
    return;
}

struct io_uring *get_global_ring(void) { return &ring; }

/// @brief Safely get an SQE, submitting and retrying if the ring is full.
/// @param ring Pointer to the io_uring structure.
/// @return A valid pointer to an io_uring_sqe.
struct io_uring_sqe *get_sqe_safe(struct io_uring *ring) {
    struct io_uring_sqe *sqe;
    do {
        sqe = io_uring_get_sqe(ring);
        if (!sqe) {
            // SQ full, force submission to clear space
            log_debug("io_uring ring full, force submission");
            io_uring_submit(ring);
        }
    } while (!sqe);
    return sqe;
}

void enable_event_poll(struct poll_event *pevent) {
    if (pevent->active) {
        log_error("poll event %d is already active", pevent->fd);
        return;
    }

    // Set the event as active
    pevent->active = true;

    // Enable event polling by adding the event to the io_uring ring
    struct io_uring_sqe *sqe = get_sqe_safe(&ring);
    io_uring_prep_poll_add(sqe, pevent->fd, pevent->epoll_type);
    sqe->len |= IORING_POLL_ADD_MULTI;
    io_uring_sqe_set_data(sqe, pevent);
    io_uring_submit(&ring);

    return;
}

void disable_event_poll(struct poll_event *pevent) {
    if (!pevent->active) {
        log_error("poll event %d is not active", pevent->fd);
        return;
    }

    // Set the event as inactive
    pevent->active = false;

    // Disable event polling by removing the event from the io_uring ring
    struct io_uring_sqe *sqe = get_sqe_safe(&ring);
    io_uring_prep_poll_remove(sqe, (__u64)pevent);
    io_uring_sqe_set_data(sqe, NULL); // No need to handle the result
    io_uring_submit(&ring);

    return;
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

        // Submit any generated requests immediately to keep the pipeline full
        // This prevents starvation of SQEs when the CQ ring is busy
        if (count > 0) {
            io_uring_submit(&ring);
        }
    }

    // Unreachable: If the loop exits, it means something went wrong
    log_error("run_event_loop should not reach here");
    exit(EXIT_FAILURE);
}

/// @brief Handle a completion queue event (CQE).
/// @param cqe The completion queue event to handle.
static void handle_cqe(struct io_uring_cqe *cqe) {
    // Get the event base associated with this CQE
    struct event_base *base = io_uring_cqe_get_data(cqe);

    if (!base) {
        // user_data is NULL, which means we don't care about the result
        return;
    }

    // Handle the event based on its type
    switch (base->type) {
    case EVENT_TYPE_IO_COMPLETION: {
        // Async I/O Completion
        struct io_completion_event *cevent = (struct io_completion_event *)base;
        bool free_on_completion = cevent->free_on_completion;
        cevent->handler(cevent->param, cqe->res);
        if (free_on_completion) {
            free(cevent);
        }
        break;
    }
    case EVENT_TYPE_POLL: {
        // Poll Event Notification
        struct poll_event *pevent = (struct poll_event *)base;

        // If the event has been deactivated by the user (e.g., via
        // disable_event_poll), ignore any stale CQEs that might have been
        // generated before the removal was processed.
        if (!pevent->active) {
            return;
        }

        if (cqe->res < 0) {
            switch (cqe->res) {
            case -ECANCELED:
            case -EAGAIN:
            case -EINTR:
                // These are expected errors, just ignore
                break;
            default:
                log_debug("poll event error: %d", cqe->res);
                break;
            }
        } else {
            // Call the handler for poll events
            pevent->handler(pevent->fd, pevent->epoll_type, pevent->param);
        }
        break;
    }
    default:
        log_error("Unknown event type: %d", base->type);
        break;
    }
}
