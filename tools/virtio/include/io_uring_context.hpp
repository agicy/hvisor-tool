#pragma once

#ifndef IO_URING_CONTEXT_HPP
#define IO_URING_CONTEXT_HPP

#include "log.h"

#include <coroutine>
#include <functional>
#include <liburing.h>
#include <memory>
#include <stdexcept>
#include <vector>

namespace virtio {

class IoUringContext {
  public:
    IoUringContext(unsigned entries = 256) {
        if (io_uring_queue_init(entries, &ring, 0) < 0) {
            log_error("Failed to init io_uring");
            throw std::runtime_error("io_uring init failed");
        }
    }

    ~IoUringContext() { io_uring_queue_exit(&ring); }

    // Forward declaration
    struct BatchAwaitable;

    enum class Op { Read = 0, Write = 1, Poll = 2, Readv = 3, Writev = 4 };

    struct IoAwaitable {
        IoUringContext *ctx;
        int fd;
        union {
            void *buf;
            const struct iovec *iov;
        };
        union {
            unsigned nbytes;
            int iovcnt;
        };
        off_t offset;
        Op op; // Op::Read, Op::Write, etc.
        int result;
        std::coroutine_handle<> handle;
        BatchAwaitable *batch = nullptr;

        IoAwaitable() = default;

        IoAwaitable(IoUringContext *ctx, int fd, void *buf, unsigned nbytes,
                    off_t offset, Op op)
            : ctx(ctx), fd(fd), buf(buf), nbytes(nbytes), offset(offset),
              op(op), result(0), batch(nullptr) {}

        IoAwaitable(IoUringContext *ctx, int fd, const struct iovec *iov,
                    int iovcnt, off_t offset, Op op)
            : ctx(ctx), fd(fd), iov(iov), iovcnt(iovcnt), offset(offset),
              op(op), result(0), batch(nullptr) {}

        bool await_ready() { return false; }

        void await_suspend(std::coroutine_handle<> h) {
            handle = h;
            struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
            if (!sqe) {
                io_uring_submit(&ctx->ring);
                sqe = io_uring_get_sqe(&ctx->ring);
                if (!sqe) {
                    log_error("Ring full");
                    return;
                }
            }

            switch (op) {
            case Op::Read:
                io_uring_prep_read(sqe, fd, buf, nbytes, offset);
                break;
            case Op::Write:
                io_uring_prep_write(sqe, fd, buf, nbytes, offset);
                break;
            case Op::Poll:
                io_uring_prep_poll_add(sqe, fd, POLL_IN);
                break;
            case Op::Readv:
                io_uring_prep_readv(sqe, fd, iov, iovcnt, offset);
                break;
            case Op::Writev:
                io_uring_prep_writev(sqe, fd, iov, iovcnt, offset);
                break;
            }

            io_uring_sqe_set_data(sqe, this);
        }

        int await_resume() { return result; }
    };

    // Batch Awaitable
    struct BatchAwaitable {
        IoUringContext *ctx;
        std::vector<IoAwaitable *> ops;
        std::coroutine_handle<> handle;
        int pending_count = 0;

        bool await_ready() { return ops.empty(); }

        void await_suspend(std::coroutine_handle<> h) {
            handle = h;
            pending_count = ops.size();

            for (auto *op : ops) {
                op->batch = this;
                op->handle = std::coroutine_handle<>(); // No individual resume

                struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
                if (!sqe) {
                    io_uring_submit(&ctx->ring);
                    sqe = io_uring_get_sqe(&ctx->ring);
                    if (!sqe) {
                        log_error("Ring full in batch");
                        if (--pending_count == 0) {
                            // Should schedule resume? Or resume immediately?
                            // Can't resume immediately in await_suspend
                            // returning void. But this is edge case. We should
                            // just fail this op.
                        }
                        continue;
                    }
                }

                switch (op->op) {
                case Op::Read:
                    io_uring_prep_read(sqe, op->fd, op->buf, op->nbytes,
                                       op->offset);
                    break;
                case Op::Write:
                    io_uring_prep_write(sqe, op->fd, op->buf, op->nbytes,
                                        op->offset);
                    break;
                case Op::Poll:
                    io_uring_prep_poll_add(sqe, op->fd, POLL_IN);
                    break;
                case Op::Readv:
                    io_uring_prep_readv(sqe, op->fd, op->iov, op->iovcnt,
                                        op->offset);
                    break;
                case Op::Writev:
                    io_uring_prep_writev(sqe, op->fd, op->iov, op->iovcnt,
                                         op->offset);
                    break;
                }

                io_uring_sqe_set_data(sqe, op);
            }
        }

        void await_resume() {}

        void on_op_complete() {
            if (--pending_count == 0) {
                if (handle)
                    handle.resume();
            }
        }
    };

    IoAwaitable async_read(int fd, void *buf, unsigned nbytes, off_t offset) {
        return IoAwaitable(this, fd, buf, nbytes, offset, Op::Read);
    }

    IoAwaitable async_write(int fd, const void *buf, unsigned nbytes,
                            off_t offset) {
        return IoAwaitable(this, fd, (void *)buf, nbytes, offset, Op::Write);
    }

    IoAwaitable async_poll(int fd) {
        return IoAwaitable(this, fd, (void *)nullptr, 0, 0, Op::Poll);
    }

    IoAwaitable async_readv(int fd, const struct iovec *iov, int iovcnt,
                            off_t offset) {
        return IoAwaitable(this, fd, iov, iovcnt, offset, Op::Readv);
    }

    IoAwaitable async_writev(int fd, const struct iovec *iov, int iovcnt,
                             off_t offset) {
        return IoAwaitable(this, fd, iov, iovcnt, offset, Op::Writev);
    }

    void prep_readv(IoAwaitable &a, int fd, const struct iovec *iov, int iovcnt,
                    off_t offset) {
        a = IoAwaitable(this, fd, iov, iovcnt, offset, Op::Readv);
    }

    void prep_writev(IoAwaitable &a, int fd, const struct iovec *iov,
                     int iovcnt, off_t offset) {
        a = IoAwaitable(this, fd, iov, iovcnt, offset, Op::Writev);
    }

    void submit() { io_uring_submit(&ring); }

    void run_once() {
        io_uring_submit_and_wait(&ring, 1);

        struct io_uring_cqe *cqe;
        unsigned head;
        unsigned count = 0;

        io_uring_for_each_cqe(&ring, head, cqe) {
            auto *awaitable =
                static_cast<IoAwaitable *>(io_uring_cqe_get_data(cqe));
            if (awaitable) {
                awaitable->result = cqe->res;
                if (awaitable->batch) {
                    awaitable->batch->on_op_complete();
                } else if (awaitable->handle) {
                    awaitable->handle.resume();
                }
            }
            count++;
        }
        io_uring_cq_advance(&ring, count);
    }

    struct io_uring ring;
};

} // namespace virtio

#endif // IO_URING_CONTEXT_HPP
