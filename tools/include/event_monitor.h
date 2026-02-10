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

struct hvisor_event {
    void (*handler)(int, int, void *);
    void (*completion_handler)(void *,
                               int); // New handler for completion events
    void *param;
    int fd;
    int epoll_type;
    bool free_on_completion;
    bool polling;
};

/// @brief Initialize the event monitor.
/// @details This function initializes the event monitor by setting up the
/// io_uring ring and other necessary data structures.
/// @return 0 on success, or a negative error code on failure.
int initialize_event_monitor(void);

/// @brief Destroy the event monitor.
/// @details This function destroys the event monitor by cleaning up the
/// io_uring ring and other resources.
void destroy_event_monitor(void);

/// @brief Get the global io_uring ring instance.
/// @return The global io_uring ring instance.
struct io_uring *get_global_ring(void);

/// @brief Add a new persistent event to the event monitor.
/// @param fd The file descriptor to monitor.
/// @param epoll_type The epoll event type to monitor.
/// @param handler The handler function to call when the event occurs.
/// @param param The parameter to pass to the handler function.
/// @return The hvisor_event struct representing the added event, or NULL on
/// failure.
struct hvisor_event *add_persistent_event(int fd, int epoll_type,
                                          void (*handler)(int, int, void *),
                                          void *param);

/// @brief Add a new completion event to the event monitor.
/// @param handler The handler function to call when the completion event
/// occurs.
/// @param param The parameter to pass to the handler function.
/// @return The hvisor_event struct representing the added completion event, or
/// NULL on failure.
struct hvisor_event *add_completion_event(void (*handler)(void *, int),
                                          void *param);

/// @brief Enable polling for the specified event.
/// @param hevent The hvisor_event struct representing the event to enable
/// polling for.
void enable_event_poll(struct hvisor_event *hevent);

/// @brief Disable polling for the specified event.
/// @param hevent The hvisor_event struct representing the event to disable
/// polling for.
void disable_event_poll(struct hvisor_event *hevent);

/// @brief Run the event loop in the current thread.
/// @details This function runs the event loop in the current thread, blocking
/// until events occur. It should be called in a separate thread from the
/// main thread.
void run_event_loop(void);

#endif // HVISOR_EVENT_H
