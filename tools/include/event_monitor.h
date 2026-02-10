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

#ifndef HVISOR_EVENT_H
#define HVISOR_EVENT_H

#include <liburing.h>
#include <stdbool.h>

#define MAX_EVENTS 4096 // Increased for high concurrency

#define IO_URING_BATCH_SIZE 32

/**
 * @brief Event Type Tag
 *
 * Distinguishes between different event categories handled by the event
 * monitor.
 */
typedef enum { EVENT_TYPE_POLL, EVENT_TYPE_IO_COMPLETION } EventType;

/**
 * @brief Base Event Structure
 *
 * Common header for all event types handled by the event monitor.
 * This allows safe casting from void* user_data retrieved from io_uring CQEs.
 */
struct event_base {
    EventType type; /**< Type tag to identify the specific event structure. */
};

/**
 * @brief Persistent Poll Event
 *
 * Represents a persistent request to monitor a file descriptor for readiness
 * (e.g., POLLIN on a PTY or TAP device).
 * Maps to IORING_OP_POLL_ADD.
 */
struct poll_event {
    struct event_base base; /**< Base header (type = EVENT_TYPE_POLL). */

    /**
     * @brief Handler for Poll events.
     * Called when the monitored fd becomes ready.
     * @param fd The file descriptor triggering the event.
     * @param type The poll event type (e.g., POLLIN).
     * @param param User-defined parameter.
     */
    void (*handler)(int fd, int type, void *param);

    void *param;    /**< User data passed to the handler. */
    int fd;         /**< File descriptor to monitor. */
    int epoll_type; /**< Poll events mask (e.g., POLLIN). */
    bool active;    /**< Tracks if the poll request is currently active in
                       io_uring. */
};

/**
 * @brief Async I/O Completion Event
 *
 * Represents a one-shot callback for an asynchronous I/O operation completion
 * (e.g., read/write finished).
 * Maps to IORING_OP_READV / IORING_OP_WRITEV etc.
 */
struct io_completion_event {
    struct event_base
        base; /**< Base header (type = EVENT_TYPE_IO_COMPLETION). */

    /**
     * @brief Handler for Async I/O completion.
     * Called when an I/O operation completes.
     * @param param User-defined parameter (typically the request struct).
     * @param res The result of the operation (e.g., bytes read, or -errno).
     */
    void (*handler)(void *param, int res);

    void *param;             /**< User data passed to the handler. */
    bool free_on_completion; /**< If true, free(this) is called after handler.
                              */
};

/**
 * @brief Initialize the event monitor.
 * @details This function initializes the event monitor by setting up the
 * io_uring ring and other necessary data structures.
 * @return 0 on success, or a negative error code on failure.
 */
int initialize_event_monitor(void);

/**
 * @brief Destroy the event monitor.
 * @details This function destroys the event monitor by cleaning up the
 * io_uring ring and other resources.
 */
void destroy_event_monitor(void);

/**
 * @brief Get the global io_uring ring instance.
 * @return The global io_uring ring instance.
 */
struct io_uring *get_global_ring(void);

/**
 * @brief Enable polling for the specified event.
 * @param pevent The poll_event struct representing the event to enable
 * polling for.
 */
void enable_event_poll(struct poll_event *pevent);

/**
 * @brief Safely get an SQE, submitting and retrying if the ring is full.
 * @param ring Pointer to the io_uring structure.
 * @return A valid pointer to an io_uring_sqe.
 */
struct io_uring_sqe *get_sqe_safe(struct io_uring *ring);

/**
 * @brief Disable polling for the specified event.
 * @param pevent The poll_event struct representing the event to disable
 * polling for.
 */
void disable_event_poll(struct poll_event *pevent);

/**
 * @brief Run the event loop in the current thread.
 * @details This function runs the event loop in the current thread, blocking
 * until events occur.
 */
void run_event_loop(void);

#endif // HVISOR_EVENT_H
