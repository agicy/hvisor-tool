#ifndef HVISOR_COROUTINE_H
#define HVISOR_COROUTINE_H

#include "event_monitor.h"
#include "virtio.h"
#include <atomic>
#include <coroutine>
#include <exception>
#include <functional>
#include <liburing.h>
#include <vector>

// Simple Task for coroutines that don't return a value to caller immediately
// but run asynchronously.
struct Task {
    struct promise_type {
        Task get_return_object() { return {}; }
        std::suspend_never initial_suspend() { return {}; }
        std::suspend_never final_suspend() noexcept { return {}; }
        void return_void() {}
        void unhandled_exception() { std::terminate(); }
    };
};

// Awaitable for io_uring operations
struct IoUringAwaitable {
    struct io_uring *ring;
    std::function<void(struct io_uring_sqe *)> prep_func;
    int res;
    struct io_completion_event event;

    IoUringAwaitable(struct io_uring *r,
                     std::function<void(struct io_uring_sqe *)> func)
        : ring(r), prep_func(func), res(0) {}

    bool await_ready() { return false; }

    void await_suspend(std::coroutine_handle<> h) {
        handle = h;
        struct io_uring_sqe *sqe = get_sqe_safe(ring);
        prep_func(sqe);

        event.base.type = EVENT_TYPE_IO_COMPLETION;
        event.param = this;
        event.handler = [](void *p, int r) {
            IoUringAwaitable *self = (IoUringAwaitable *)p;
            self->res = r;
            if (self->handle) self->handle.resume();
        };
        event.free_on_completion = false;

        io_uring_sqe_set_data(sqe, &event);
    }
    
    // We need to store the handle to resume it later
    std::coroutine_handle<> handle;

    int await_resume() { return res; }
};

// Awaitable for batch io_uring operations
// T is the request context type pointer
template <typename T>
struct BatchIoUringAwaitable {
    struct io_uring *ring;
    const std::vector<T>& requests;
    std::vector<int> results;
    std::function<void(struct io_uring_sqe *, T)> prep_func;

    struct BatchOpContext {
        struct io_completion_event event;
        BatchIoUringAwaitable *parent;
        int index;
    };
    // Use vector to store contexts, ensuring stable addresses
    std::vector<BatchOpContext> contexts;
    size_t pending_count;
    std::coroutine_handle<> handle;

    BatchIoUringAwaitable(struct io_uring *r, const std::vector<T>& reqs,
                          std::function<void(struct io_uring_sqe *, T)> func)
        : ring(r), requests(reqs), prep_func(func) {
        results.resize(requests.size());
        contexts.resize(requests.size());
        pending_count = requests.size();
    }

    bool await_ready() { return requests.empty(); }

    void await_suspend(std::coroutine_handle<> h) {
        handle = h;
        // pending_count is already initialized in constructor

        for (size_t i = 0; i < requests.size(); ++i) {
            struct io_uring_sqe *sqe = get_sqe_safe(ring);
            prep_func(sqe, requests[i]);

            contexts[i].parent = this;
            contexts[i].index = i;
            contexts[i].event.base.type = EVENT_TYPE_IO_COMPLETION;
            contexts[i].event.param = &contexts[i];
            contexts[i].event.handler = [](void *p, int r) {
                BatchOpContext *ctx = (BatchOpContext *)p;
                BatchIoUringAwaitable *parent = ctx->parent;
                
                parent->results[ctx->index] = r;

                parent->pending_count--;
                if (parent->pending_count == 0) {
                    if (parent->handle) parent->handle.resume();
                }
            };
            contexts[i].event.free_on_completion = false;
            
            io_uring_sqe_set_data(sqe, &contexts[i].event);
        }
    }

    std::vector<int> await_resume() { return results; }
};

// Helper to submit IO
inline IoUringAwaitable async_read(int fd, void *buf, unsigned nbytes,
                                   off_t offset) {
    return IoUringAwaitable(get_global_ring(), [=](struct io_uring_sqe *sqe) {
        io_uring_prep_read(sqe, fd, buf, nbytes, offset);
    });
}

inline IoUringAwaitable async_readv(int fd, const struct iovec *iovecs,
                                    unsigned nr_vecs, off_t offset) {
    return IoUringAwaitable(get_global_ring(), [=](struct io_uring_sqe *sqe) {
        io_uring_prep_readv(sqe, fd, iovecs, nr_vecs, offset);
    });
}

inline IoUringAwaitable async_write(int fd, const void *buf, unsigned nbytes,
                                    off_t offset) {
    return IoUringAwaitable(get_global_ring(), [=](struct io_uring_sqe *sqe) {
        io_uring_prep_write(sqe, fd, buf, nbytes, offset);
    });
}

inline IoUringAwaitable async_writev(int fd, const struct iovec *iovecs,
                                     unsigned nr_vecs, off_t offset) {
    return IoUringAwaitable(get_global_ring(), [=](struct io_uring_sqe *sqe) {
        io_uring_prep_writev(sqe, fd, iovecs, nr_vecs, offset);
    });
}

// Awaitable for waiting on a VirtQueue
struct VirtQueueAwaitable {
    VirtQueue *vq;

    bool await_ready() { return !virtqueue_is_empty(vq); }

    void await_suspend(std::coroutine_handle<> h) {
        // Register a notify handler or poll event that resumes this handle
        // This requires modifying VirtQueue or the event loop to support
        // coroutine resumption on kick. For now, let's assume we have a
        // mechanism to set a callback on the VQ. Since VQ logic is complex, we
        // might just poll or wait for the existing notify_handler to be called.

        // In the new architecture, the notify_handler should resume the
        // coroutine. We can store the handle in the VirtQueue structure (void
        // *private_data).
        vq->private_data = h.address();
    }

    void await_resume() {}
};

// Awaitable to yield execution to the event loop
struct YieldAwaitable {
    bool await_ready() { return false; }
    
    struct io_completion_event event;
    std::coroutine_handle<> handle;

    void await_suspend(std::coroutine_handle<> h) {
        handle = h;
        // Submit a NOP to io_uring to wake up and process later
        struct io_uring_sqe *sqe = get_sqe_safe(get_global_ring());
        io_uring_prep_nop(sqe);

        event.base.type = EVENT_TYPE_IO_COMPLETION;

        event.param = this;
        event.handler = [](void *p, int r) {
            YieldAwaitable *self = (YieldAwaitable *)p;
            if (self->handle) self->handle.resume();
        };
        event.free_on_completion = false;

        io_uring_sqe_set_data(sqe, &event);
    }

    void await_resume() {}
};

// Awaitable for waiting on a VirtQueue notification
struct WaitForNotify {
    VirtQueue *vq;

    bool await_ready() {
        // If the queue is not empty, we don't need to suspend.
        return !virtqueue_is_empty(vq);
    }

    void await_suspend(std::coroutine_handle<> h) {
        // Store the coroutine handle in the VirtQueue structure.
        // This allows the notify handler to resume this coroutine.
        vq->waiter = h.address();
    }

    void await_resume() {
        // Clear the waiter field upon resumption to indicate we are no longer
        // waiting.
        vq->waiter = NULL;
    }
};

// Awaitable to sleep for a specified duration (in milliseconds)
struct SleepAwaitable {
    struct __kernel_timespec ts;
    struct io_completion_event event;
    std::coroutine_handle<> handle;

    SleepAwaitable(unsigned int ms) {
        ts.tv_sec = ms / 1000;
        ts.tv_nsec = (ms % 1000) * 1000000;
    }

    bool await_ready() { return false; }

    void await_suspend(std::coroutine_handle<> h) {
        handle = h;
        struct io_uring_sqe *sqe = get_sqe_safe(get_global_ring());
        io_uring_prep_timeout(sqe, &ts, 0, 0);

        event.base.type = EVENT_TYPE_IO_COMPLETION;
        event.param = this;
        event.handler = [](void *p, int r) {
            SleepAwaitable *self = (SleepAwaitable *)p;
            if (self->handle) self->handle.resume();
        };
        event.free_on_completion = false;

        io_uring_sqe_set_data(sqe, &event);
    }

    void await_resume() {}
};

// Awaitable for polling a file descriptor
struct PollAwaitable {
    int fd;
    int events;
    int res;
    struct io_completion_event event;
    std::coroutine_handle<> handle;

    PollAwaitable(int f, int e) : fd(f), events(e), res(0) {}

    bool await_ready() { return false; }

    void await_suspend(std::coroutine_handle<> h) {
        handle = h;
        struct io_uring_sqe *sqe = get_sqe_safe(get_global_ring());
        io_uring_prep_poll_add(sqe, fd, events);

        event.base.type = EVENT_TYPE_IO_COMPLETION;
        event.param = this;
        event.handler = [](void *p, int r) {
            PollAwaitable *self = (PollAwaitable *)p;
            self->res = r;
            if (self->handle) self->handle.resume();
        };
        event.free_on_completion = false;

        io_uring_sqe_set_data(sqe, &event);
    }

    int await_resume() { return res; }
};

#endif // HVISOR_COROUTINE_H
