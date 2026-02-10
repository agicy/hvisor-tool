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
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <liburing.h>

#include "event_monitor.h"
#include "log.h"

static struct io_uring ring;
static int events_num;
pthread_t emonitor_tid;
int closing;
#define MAX_EVENTS 64 // Increased from 16 to accommodate more events
struct hvisor_event *events[MAX_EVENTS];

struct io_uring *get_global_ring(void) {
    return &ring;
}

static void *io_uring_loop() {
    struct io_uring_cqe *cqe;
    struct hvisor_event *hevent;
    int ret;

    for (;;) {
        ret = io_uring_wait_cqe(&ring, &cqe);
        if (ret < 0) {
            if (ret != -EINTR)
                log_error("io_uring_wait_cqe failed, errno is %d", -ret);
            continue;
        }

        hevent = io_uring_cqe_get_data(cqe);
        if (hevent != NULL) {
            if (hevent->completion_handler) {
                // Handle completion event (e.g., disk I/O completion)
                bool free_on_completion = hevent->free_on_completion;
                hevent->completion_handler(hevent->param, cqe->res);
                if (free_on_completion) {
                    free(hevent);
                }
            } else if (hevent->handler) {
                // Handle poll event (e.g., network, console)
                hevent->handler(hevent->fd, hevent->epoll_type, hevent->param);
                
                // Re-arm the poll request
                struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
                io_uring_prep_poll_add(sqe, hevent->fd, hevent->epoll_type);
                io_uring_sqe_set_data(sqe, hevent);
                io_uring_submit(&ring);
            }
        } else {
            log_error("hevent shouldn't be null");
        }
        
        io_uring_cqe_seen(&ring, cqe);
    }
    pthread_exit(NULL);
    return NULL;
}

struct hvisor_event *add_completion_event(void (*handler)(void *, int), void *param) {
    struct hvisor_event *hevent = calloc(1, sizeof(struct hvisor_event));
    if (!hevent) return NULL;
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

    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_poll_add(sqe, fd, epoll_type);
    io_uring_sqe_set_data(sqe, hevent);
    io_uring_submit(&ring);

    events[events_num] = hevent;
    events_num++;
    return hevent;
}

// Create a thread monitoring events.
int initialize_event_monitor() {
    int ret = io_uring_queue_init(MAX_EVENTS, &ring, 0);
    if (ret < 0) {
        log_error("io_uring_queue_init failed");
        return -1;
    }
    log_debug("io_uring initialized");
    pthread_create(&emonitor_tid, NULL, io_uring_loop, NULL);
    return 0;
}

void destroy_event_monitor() {
    io_uring_queue_exit(&ring);
    // When the main thread exits, the io_uring thread will also exit. Therefore,
    // we do not directly terminate the io_uring thread here.
}
