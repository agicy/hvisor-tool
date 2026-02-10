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

struct hvisor_event {
    void (*handler)(int, int, void *);
    void (*completion_handler)(void *, int); // New handler for completion events
    void *param;
    int fd;
    int epoll_type;
    bool free_on_completion;
    bool polling;
};

struct io_uring *get_global_ring(void);
pthread_mutex_t *get_global_ring_mutex(void);
struct hvisor_event *add_event(int fd, int epoll_type,
                               void (*handler)(int, int, void *), void *param);
struct hvisor_event *add_completion_event(void (*handler)(void *, int), void *param);
void enable_event_poll(struct hvisor_event *hevent);
void disable_event_poll(struct hvisor_event *hevent);
#endif // HVISOR_EVENT_H
