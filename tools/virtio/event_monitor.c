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
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>

#include "event_monitor.h"
#include "log.h"

static int epoll_fd;
static int events_num;
pthread_t emonitor_tid;
int closing;
#define MAX_EVENTS 16
struct hvisor_event *events[MAX_EVENTS];

/*
 * events[] is shared between the epoll thread (dispatch), the control thread
 * (device add/remove at zone start/stop) and any thread that tears a device
 * down. Two locks keep it safe:
 *
 *  - event_lock protects events[]/events_num and the epoll_ctl calls, so an
 *    add/remove can never interleave with a dispatch on the same slot.
 *  - dispatch_lock is held for the whole duration of a handler invocation.
 *    remove_event()/update_event_interest() only take event_lock, so a
 *    handler is free to change its own interest set. A device close that
 *    frees handler state must call event_barrier() after remove_event() to
 *    make sure no handler is still executing on that state.
 *
 * A removed event is never freed until destroy_event_monitor(): the epoll
 * thread may already have dequeued it (epoll_wait returned it before the
 * EPOLL_CTL_DEL), and dispatching on a freed hvisor_event would crash.
 */
static pthread_mutex_t event_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t dispatch_lock = PTHREAD_MUTEX_INITIALIZER;

static void *epoll_loop() {
    struct epoll_event ep_events[MAX_EVENTS];
    struct hvisor_event *hevent;
    int ret, i;
    for (;;) {
        ret = epoll_wait(epoll_fd, ep_events, MAX_EVENTS, -1);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            /* epoll fd closed (shutdown): nothing left to dispatch */
            break;
        }
        for (i = 0; i < ret; ++i) {
            hevent = ep_events[i].data.ptr;
            pthread_mutex_lock(&dispatch_lock);
            /* hevent is never freed while the monitor is alive; a removed
             * event must simply not be dispatched any more. */
            if (hevent != NULL && !hevent->removed && hevent->handler)
                hevent->handler(hevent->fd, ep_events[i].events,
                                hevent->param);
            pthread_mutex_unlock(&dispatch_lock);
        }
    }
    pthread_exit(NULL);
    return NULL;
}

struct hvisor_event *add_event(int fd, int epoll_type,
                               void (*handler)(int, int, void *), void *param) {
    struct hvisor_event *hevent;
    struct epoll_event eevent;
    int ret;
    int slot = -1;

    if (fd < 0 || handler == NULL) {
        log_error("invalid fd or handler");
        return NULL;
    }

    pthread_mutex_lock(&event_lock);
    if (events_num >= MAX_EVENTS) {
        /* find a recycled slot first */
        for (int i = 0; i < events_num; i++) {
            if (events[i] == NULL) {
                slot = i;
                break;
            }
        }
    }
    if (slot < 0 && events_num >= MAX_EVENTS) {
        pthread_mutex_unlock(&event_lock);
        log_error("events are full");
        return NULL;
    }
    if (slot < 0)
        slot = events_num++;

    hevent = calloc(1, sizeof(struct hvisor_event));
    hevent->handler = handler;
    hevent->param = param;
    hevent->fd = fd;
    hevent->epoll_type = epoll_type;
    hevent->removed = 0;

    eevent.events = epoll_type;
    eevent.data.ptr = hevent;
    ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, hevent->fd, &eevent);
    if (ret < 0) {
        log_error("epoll_ctl failed, errno is %d", errno);
        free(hevent);
        events[slot] = NULL;
        if (slot == events_num - 1)
            events_num--;
        pthread_mutex_unlock(&event_lock);
        return NULL;
    }
    events[slot] = hevent;
    pthread_mutex_unlock(&event_lock);
    return hevent;
}

// Create a thread monitoring events.
int initialize_event_monitor() {
    epoll_fd = epoll_create1(0);
    log_debug("create epoll_fd %d", epoll_fd);
    pthread_create(&emonitor_tid, NULL, epoll_loop, NULL);
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    if (sched_getaffinity(0, sizeof(cpu_set_t), &cpuset) == 0) {
        int last_cpu = -1;
        for (int i = CPU_SETSIZE - 1; i >= 1; i--) {
            if (CPU_ISSET(i, &cpuset)) {
                last_cpu = i;
                break;
            }
        }

        if (last_cpu != -1) {
            cpu_set_t set;
            CPU_ZERO(&set);
            CPU_SET(last_cpu, &set);
            if (pthread_setaffinity_np(emonitor_tid, sizeof(cpu_set_t), &set) !=
                0) {
                log_warn("failed to set epoll_loop thread to cpu %d", last_cpu);
            } else {
                log_info("epoll_loop thread set to cpu %d", last_cpu);
            }
        } else {
            log_warn("No available CPU other than CPU0");
        }
    } else {
        log_warn("failed to get cpu affinity: %d", errno);
    }
    if (epoll_fd >= 0)
        return 0;
    else {
        log_error("hvisor_event init failed");
        return -1;
    }
}

void remove_event(struct hvisor_event *hevent) {
    int i;

    if (!hevent)
        return;

    pthread_mutex_lock(&event_lock);
    for (i = 0; i < events_num; i++) {
        if (events[i] == hevent) {
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, hevent->fd, NULL);
            events[i] = NULL;
            break;
        }
    }
    hevent->removed = 1;
    pthread_mutex_unlock(&event_lock);
}

int update_event_interest(struct hvisor_event *hevent, int epoll_type) {
    struct epoll_event eevent;
    int ret;

    if (!hevent)
        return -1;

    pthread_mutex_lock(&event_lock);
    if (hevent->removed) {
        pthread_mutex_unlock(&event_lock);
        return -1;
    }
    eevent.events = epoll_type;
    eevent.data.ptr = hevent;
    ret = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, hevent->fd, &eevent);
    if (ret == 0)
        hevent->epoll_type = epoll_type;
    pthread_mutex_unlock(&event_lock);
    return ret;
}

void event_barrier(void) {
    /* Acquire/release dispatch_lock: any handler running right now must
     * finish before we return, and no new dispatch can start in between. */
    pthread_mutex_lock(&dispatch_lock);
    pthread_mutex_unlock(&dispatch_lock);
}

void destroy_event_monitor() {
    int i;
    pthread_mutex_lock(&event_lock);
    for (i = 0; i < events_num; i++) {
        if (events[i] != NULL) {
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i]->fd, NULL);
            events[i]->removed = 1;
            free(events[i]);
        }
        events[i] = NULL;
    }
    events_num = 0;
    if (epoll_fd >= 0) {
        close(epoll_fd);
        epoll_fd = -1;
    }
    pthread_mutex_unlock(&event_lock);
    // When the main thread exits, the epoll thread will also exit. Therefore,
    // we do not directly terminate the epoll thread here.
}
