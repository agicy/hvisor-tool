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

#include <liburing.h>
#include <sys/uio.h>

typedef void (*event_handler_t)(int fd, void *param);
typedef void (*io_completion_t)(void *param, int res);

enum req_type {
    REQ_TYPE_POLL_READ,
    REQ_TYPE_IO_READ,
    REQ_TYPE_IO_WRITE,
    REQ_TYPE_SIGNAL,
    REQ_TYPE_EVENTFD
};

struct request_data {
    enum req_type type;
    int fd;
    void *cb; // event_handler_t or io_completion_t
    void *param;
    bool dynamic; // true if allocated by malloc, false if embedded
};

struct hvisor_event {
    event_handler_t handler;
    void *param;
    int fd;
};

// Initialize io_uring, signalfd, and eventfd
int initialize_event_monitor(void);

// Run the main event loop
void monitor_loop(void);

// Add a file descriptor to be monitored for readability (poll)
int add_event_read(int fd, event_handler_t handler, void *param);

// Add a file descriptor to be monitored for readability (poll) with preallocated request data
int add_event_read_prealloc(int fd, event_handler_t handler, void *param, struct request_data *req);

// Submit an async readv request
int submit_async_readv(int fd, const struct iovec *iov, int iovcnt, uint64_t offset, io_completion_t cb, void *param);

// Submit an async readv request with preallocated request data
int submit_async_readv_prealloc(int fd, const struct iovec *iov, int iovcnt, uint64_t offset, io_completion_t cb, void *param, struct request_data *req);

// Submit an async writev request
int submit_async_writev(int fd, const struct iovec *iov, int iovcnt, uint64_t offset, io_completion_t cb, void *param);

// Submit an async writev request with preallocated request data
int submit_async_writev_prealloc(int fd, const struct iovec *iov, int iovcnt, uint64_t offset, io_completion_t cb, void *param, struct request_data *req);

// Explicitly flush pending requests to io_uring
void io_flush(void);

void destroy_event_monitor(void);

#endif // HVISOR_EVENT_H
