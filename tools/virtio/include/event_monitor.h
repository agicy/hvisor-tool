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
#ifndef HVISOR_EVENT_H
#define HVISOR_EVENT_H
#include <sys/epoll.h>

struct hvisor_event {
    void (*handler)(int, int, void *);
    void *param;
    int fd;
    int epoll_type;
    /* set under the event lock when the event is detached; the epoll thread
     * never dispatches a removed event and the struct is only freed at
     * destroy_event_monitor(), so teardown can never race a live handler. */
    int removed;
};

int initialize_event_monitor(void);
void destroy_event_monitor(void);
struct hvisor_event *add_event(int fd, int epoll_type,
                               void (*handler)(int, int, void *), void *param);
void remove_event(struct hvisor_event *hevent);
/* Change the epoll interest set of a registered event (EPOLL_CTL_MOD). */
int update_event_interest(struct hvisor_event *hevent, int epoll_type);
/* Block until no event handler is executing. Call before freeing resources
 * (vdev/dev) that a handler may still touch. */
void event_barrier(void);
#endif // HVISOR_EVENT_H
