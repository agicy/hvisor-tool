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
#include "virtio_blk.h"
#include "log.h"
#include "virtio.h"
#include <errno.h>
#include <fcntl.h>
#include <liburing.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>

// 用于区分 io_uring 返回的 CQE 是 IO 完成还是 Guest Kick 事件
#define KICK_EVENT_MARKER ((uint64_t)1)

// 将 Guest Kick Eventfd 加入 io_uring 进行轮询
static void add_kick_poll_sqe(BlkDev *dev) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&dev->ring);
    if (!sqe) {
        // 如果 SQE 队列满了，先 submit 腾出空间再取
        io_uring_submit(&dev->ring);
        sqe = io_uring_get_sqe(&dev->ring);
    }
    if (sqe) {
        // 监听 POLLIN 可读事件
        io_uring_prep_poll_add(sqe, dev->kick_fd, POLLIN);
        // 使用 KICK_EVENT_MARKER 作为标识符
        io_uring_sqe_set_data(sqe, (void *)(uintptr_t)KICK_EVENT_MARKER);
    }
}

static void complete_block_operation(BlkDev *dev, struct blkp_req *req,
                                     VirtQueue *vq, int err,
                                     ssize_t written_len) {
    uint8_t *vstatus = (uint8_t *)(req->iov[req->iovcnt - 1].iov_base);

    if (err == EOPNOTSUPP)
        *vstatus = VIRTIO_BLK_S_UNSUPP;
    else if (err != 0)
        *vstatus = VIRTIO_BLK_S_IOERR;
    else
        *vstatus = VIRTIO_BLK_S_OK;

    if (err != 0) {
        log_error("virt blk err, num is %d", err);
    }

    // 直接更新 Used Ring，此时在独立的 Worker 线程中，天然无锁
    update_used_ring(vq, req->idx, written_len + 1);

    free(req->iov);
    free(req);
}

// handle one descriptor list
static struct blkp_req *virtq_blk_handle_one_request(VirtQueue *vq) {
    log_debug("virtq_blk_handle_one_request enter");
    struct blkp_req *breq;
    struct iovec *iov = NULL;
    uint16_t *flags;
    int i, n;
    BlkReqHead *hdr;
    breq = malloc(sizeof(struct blkp_req));
    n = process_descriptor_chain(vq, &breq->idx, &iov, &flags, 0, true);
    breq->iov = iov;

    if (n < 2 || n > BLK_SEG_MAX + 2) {
        log_error("iov's num is wrong, n is %d", n);
        goto err_out;
    }

    if ((flags[0] & VRING_DESC_F_WRITE) != 0) {
        log_error("virt queue's desc chain header should not be writable!");
        goto err_out;
    }

    if (iov[0].iov_len != sizeof(BlkReqHead)) {
        log_error("the size of blk header is %d, it should be %ld!",
                  iov[0].iov_len, sizeof(BlkReqHead));
        goto err_out;
    }

    if (iov[n - 1].iov_len != 1 || ((flags[n - 1] & VRING_DESC_F_WRITE) == 0)) {
        log_error(
            "status iov is invalid!, status len is %ld, flag is %d, n is %d",
            iov[n - 1].iov_len, flags[n - 1], n);
        goto err_out;
    }

    hdr = (BlkReqHead *)(iov[0].iov_base);
    uint64_t offset = hdr->sector * SECTOR_BSIZE;
    breq->type = hdr->type;
    breq->iovcnt = n;
    breq->offset = offset;

    for (i = 1; i < n - 1; i++) {
        if (((flags[i] & VRING_DESC_F_WRITE) == 0) !=
            (breq->type == VIRTIO_BLK_T_OUT)) {
            log_error("flag is conflict with operation");
            goto err_out;
        }
    }

    free(flags);
    return breq;

err_out:
    free(flags);
    free(iov);
    free(breq);
    return NULL;
}

// 核心 I/O 轮询线程 (Pure io_uring 实现)
static void *blkproc_thread(void *arg) {
    VirtIODevice *vdev = arg;
    BlkDev *dev = vdev->dev;
    struct io_uring *ring = &dev->ring;
    struct io_uring_cqe *cqe;
    unsigned head;
    int ret;

    // 1. 初始化：挂载第一次 eventfd 轮询
    add_kick_poll_sqe(dev);

    for (;;) {
        // 2. 阻塞等待：可以是被 io_uring I/O 完成唤醒，或者是被 Guest Kick 唤醒
        ret = io_uring_submit_and_wait(ring, 1);
        if (ret < 0 && ret != -EINTR) {
            log_error("io_uring_submit_and_wait failed: %d", ret);
            continue;
        }

        if (dev->close) {
            break;
        }

        bool need_irq = false;
        int count = 0;

        // 3. 遍历所有的完成事件 (CQEs)
        io_uring_for_each_cqe(ring, head, cqe) {
            count++;
            void* user_data = io_uring_cqe_get_data(cqe);

            // 场景 A: 收到 Guest 发来的 Kick 通知
            if (user_data == (void *)KICK_EVENT_MARKER) {
                uint64_t val;
                // 清除 eventfd 中的信号量，避免持续触发
                if (read(dev->kick_fd, &val, sizeof(val)) < 0) {
                    log_error("failed to drain eventfd");
                }

                VirtQueue *vq = vdev->vqs;
                struct blkp_req *breq;

                do {
                    // 批量处理 VirtQueue 中所有的请求
                    virtqueue_disable_notify(vq);
                    while (!virtqueue_is_empty(vq)) {
                        breq = virtq_blk_handle_one_request(vq);
                        if (!breq)
                            continue;

                        // 处理无需进行磁盘 IO 的同步请求
                        if (breq->type == VIRTIO_BLK_T_GET_ID) {
                            char s[20] = "hvisor-virblk";
                            strncpy(breq->iov[1].iov_base, s,
                                    MIN(sizeof(s), breq->iov[1].iov_len));
                            complete_block_operation(dev, breq, vq, 0, 0);
                            need_irq = true;
                            continue;
                        }

                        // 为底层 I/O 请求申请一个 SQE
                        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
                        if (!sqe) {
                            io_uring_submit(ring); // 队列满了就先提交一批
                            sqe = io_uring_get_sqe(ring);
                        }

                        if (breq->type == VIRTIO_BLK_T_IN) {
                            io_uring_prep_readv(sqe, dev->img_fd, &breq->iov[1],
                                                breq->iovcnt - 2, breq->offset);
                        } else if (breq->type == VIRTIO_BLK_T_OUT) {
                            io_uring_prep_writev(sqe, dev->img_fd, &breq->iov[1],
                                                breq->iovcnt - 2, breq->offset);
                        } else {
                            log_fatal("Operation is not supported");
                            complete_block_operation(dev, breq, vq, EOPNOTSUPP, 0);
                            need_irq = true;
                            continue;
                        }

                        // 将 breq 指针塞入 user_data，作为后续完成时的上下文
                        io_uring_sqe_set_data(sqe, breq);
                    }
                    virtqueue_enable_notify(vq);
                } while(!virtqueue_is_empty(vq));

                // 因为 Linux 5.10 是 One-shot poll，触发过一次必须重新挂载！
                add_kick_poll_sqe(dev);

            }
            // 场景 B: 收到底层磁盘 I/O 的完成通知
            else {
                struct blkp_req *breq = (struct blkp_req *)user_data;
                int err = 0;
                ssize_t written_len = 0;

                if (cqe->res < 0) {
                    err = -cqe->res; // 返回的是负数错误码
                    log_error("io_uring io failed, err: %d", err);
                } else {
                    written_len = cqe->res;
                }

                complete_block_operation(dev, breq, vdev->vqs, err,
                                         written_len);
                need_irq = true; // 积累需要中断的标志
            }
        }

        // 4. 批量推进 io_uring 的 CQ 环
        io_uring_cq_advance(ring, count);

        // 5. 中断聚合 (Interrupt Coalescing): 每批次只发一次中断
        if (need_irq) {
            virtio_inject_irq(vdev->vqs);
        }
    }

    pthread_exit(NULL);
    return NULL;
}

// 初始化块设备
BlkDev *init_blk_dev(VirtIODevice *vdev) {
    BlkDev *dev = malloc(sizeof(BlkDev));
    vdev->dev = dev;
    dev->config.capacity = -1;
    dev->config.size_max = -1;
    dev->config.seg_max = BLK_SEG_MAX;
    dev->img_fd = -1;
    dev->close = 0;

    // 1. 初始化 io_uring，设置 256 深度的队列 (现代 NVMe 的标配)
    if (io_uring_queue_init(256, &dev->ring, 0) < 0) {
        log_fatal("io_uring_queue_init failed");
        free(dev);
        return NULL;
    }

    // 2. 初始化用于事件通知的 eventfd
    dev->kick_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (dev->kick_fd < 0) {
        log_fatal("eventfd creation failed");
        io_uring_queue_exit(&dev->ring);
        free(dev);
        return NULL;
    }

    pthread_create(&dev->tid, NULL, blkproc_thread, vdev);
    return dev;
}

int virtio_blk_init(VirtIODevice *vdev, const char *img_path) {
    // [这部分无需更改，与原版一致]
    int img_fd = open(img_path, O_RDWR);
    BlkDev *dev = vdev->dev;
    struct stat st;
    uint64_t blk_size;
    if (img_fd == -1) {
        log_error("cannot open %s, Error code is %d", img_path, errno);
        return -1;
    }
    if (fstat(img_fd, &st) == -1) {
        log_error("cannot stat %s, Error code is %d", img_path, errno);
        close(img_fd);
        return -1;
    }
    blk_size = st.st_size / 512;
    dev->config.capacity = blk_size;
    dev->config.size_max = blk_size;
    dev->img_fd = img_fd;
    vdev->virtio_close = virtio_blk_close;
    log_info("virtio_blk_init: %s, size is %lld", img_path,
             dev->config.capacity);
    return 0;
}

// 对应 Guest kick virtqueue 时的回调
int virtio_blk_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    log_debug("virtio blk notify handler enter");
    BlkDev *dev = (BlkDev *)vdev->dev;
    uint64_t val = 1;

    // 直接写入 kick_fd，立刻返回！绝不阻塞 VCPU 线程！
    if (write(dev->kick_fd, &val, sizeof(val)) < 0) {
        log_error("failed to kick eventfd: %s", strerror(errno));
    }
    return 0;
}

void virtio_blk_close(VirtIODevice *vdev) {
    BlkDev *dev = vdev->dev;
    uint64_t val = 1;

    // 通知退出循环
    dev->close = 1;

    // 写入 kick_fd 以唤醒阻塞在 io_uring_submit_and_wait 的线程
    if (write(dev->kick_fd, &val, sizeof(val)) < 0) {
        // Handle error implicitly
    }

    pthread_join(dev->tid, NULL);

    // 销毁资源
    io_uring_queue_exit(&dev->ring);
    close(dev->kick_fd);
    close(dev->img_fd);

    free(dev);
    free(vdev->vqs);
    free(vdev);
}
