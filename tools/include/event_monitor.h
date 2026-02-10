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

enum EventType {
    EVENT_POLL,
    EVENT_IO_ONESHOT
};

struct hvisor_event {
    void (*handler)(int, int, void *);
    void *param;
    int fd;
    int epoll_type;
    enum EventType type;
};

int initialize_event_monitor(void);
void destroy_event_monitor();
struct hvisor_event *add_event(int fd, int epoll_type,
                               void (*handler)(int, int, void *), void *param);

// Thread-safe ring access
void event_monitor_lock(void);
void event_monitor_unlock(void);
struct io_uring *event_monitor_get_ring(void);

#endif // HVISOR_EVENT_H
