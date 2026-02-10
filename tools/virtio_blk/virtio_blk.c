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

#include "event_monitor.h"
#include "log.h"
#include "virtio.h"

#include <errno.h>
#include <fcntl.h>
#include <liburing.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/param.h>
#include <sys/stat.h>

static void virtio_blk_completion_handler(void *param, int res);

static void complete_block_operation(BlkDev *dev, struct blkp_req *req,
                                     VirtQueue *vq, int err,
                                     ssize_t written_len) {
    uint8_t *vstatus = (uint8_t *)(req->iov[req->iovcnt - 1].iov_base);
    int is_empty = 0;
    if (err == EOPNOTSUPP)
        *vstatus = VIRTIO_BLK_S_UNSUPP;
    else if (err != 0)
        *vstatus = VIRTIO_BLK_S_IOERR;
    else
        *vstatus = VIRTIO_BLK_S_OK;
    if (err != 0) {
        log_error("virt blk err, num is %d", err);
    }
    update_used_ring(vq, req->idx, written_len + 1);
    virtio_inject_irq(vq);
    free(req->iov);
    free(req);
}

static void virtio_blk_completion_handler(void *param, int res) {
    struct blkp_req *req = (struct blkp_req *)param;
    BlkDev *dev = req->dev;
    VirtQueue *vq = req->vq;
    ssize_t written_len = 0;
    int err = 0;

    if (res < 0) {
        log_error("virtio blk op failed: %d", res);
        err = -res;
    } else {
        written_len = res;
    }

    complete_block_operation(dev, req, vq, err, written_len);
}

static void blkproc(BlkDev *dev, struct blkp_req *req, VirtQueue *vq) {
    struct iovec *iov = req->iov;
    int n = req->iovcnt;

    struct io_uring *ring = get_global_ring();
    struct io_uring_sqe *sqe;

    req->dev = dev;
    req->vq = vq;

    switch (req->type) {
    case VIRTIO_BLK_T_IN:
        sqe = io_uring_get_sqe(ring);
        req->hevent.completion_handler = virtio_blk_completion_handler;
        req->hevent.param = req;
        req->hevent.free_on_completion = false;
        io_uring_prep_readv(sqe, dev->img_fd, &iov[1], n - 2, req->offset);
        io_uring_sqe_set_data(sqe, &req->hevent);
        io_uring_submit(ring);
        break;
    case VIRTIO_BLK_T_OUT:
        sqe = io_uring_get_sqe(ring);
        req->hevent.completion_handler = virtio_blk_completion_handler;
        req->hevent.param = req;
        req->hevent.free_on_completion = false;
        io_uring_prep_writev(sqe, dev->img_fd, &iov[1], n - 2, req->offset);
        io_uring_sqe_set_data(sqe, &req->hevent);
        io_uring_submit(ring);
        break;
    case VIRTIO_BLK_T_GET_ID: {
        char s[20] = "hvisor-virblk";
        strncpy(iov[1].iov_base, s, MIN(sizeof(s), iov[1].iov_len));
        complete_block_operation(dev, req, vq, 0, 0);
        break;
    }
    default:
        log_fatal("Operation is not supported");
        complete_block_operation(dev, req, vq, EOPNOTSUPP, 0);
        break;
    }
}

// create blk dev.
BlkDev *init_blk_dev(VirtIODevice *vdev) {
    BlkDev *dev = malloc(sizeof(BlkDev));
    vdev->dev = dev;
    dev->config.capacity = -1;
    dev->config.size_max = -1;
    dev->config.seg_max = BLK_SEG_MAX;
    dev->img_fd = -1;
    return dev;
}

int virtio_blk_init(VirtIODevice *vdev, const char *img_path) {
    int img_fd = open(img_path, O_RDWR);
    BlkDev *dev = vdev->dev;
    struct stat st;
    uint64_t blk_size;
    if (img_fd == -1) {
        log_error("cannot open %s, Error code is %d", img_path, errno);
        close(img_fd);
        return -1;
    }
    if (fstat(img_fd, &st) == -1) {
        log_error("cannot stat %s, Error code is %d", img_path, errno);
        close(img_fd);
        return -1;
    }
    blk_size = st.st_size / 512; // 512 bytes per block
    dev->config.capacity = blk_size;
    dev->config.size_max = blk_size;
    dev->img_fd = img_fd;
    vdev->virtio_close = virtio_blk_close;
    log_info("debug: virtio_blk_init: %s, size is %lld", img_path,
             dev->config.capacity);

    // In single-threaded model, we don't need kick_fd for self-notification
    // We can call processing functions directly.
    dev->kick_fd = -1;

    return 0;
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
        log_error("the size of blk header is %d, it should be %d!",
                  iov[0].iov_len, sizeof(BlkReqHead));
        goto err_out;
    }

    if (iov[n - 1].iov_len != 1 || ((flags[n - 1] & VRING_DESC_F_WRITE) == 0)) {
        log_error(
            "status iov is invalid!, status len is %d, flag is %d, n is %d",
            iov[n - 1].iov_len, flags[n - 1], n);
        goto err_out;
    }

    hdr = (BlkReqHead *)(iov[0].iov_base);
    uint64_t offset = hdr->sector * SECTOR_BSIZE;
    breq->type = hdr->type;
    breq->iovcnt = n;
    breq->offset = offset;

    for (i = 1; i < n - 1; i++)
        if (((flags[i] & VRING_DESC_F_WRITE) == 0) !=
            (breq->type == VIRTIO_BLK_T_OUT)) {
            log_error("flag is conflict with operation");
            goto err_out;
        }

    free(flags);
    return breq;

err_out:
    free(flags);
    free(iov);
    free(breq);
    return NULL;
}

static void virtio_blk_process_queue(VirtIODevice *vdev, VirtQueue *vq) {
    BlkDev *blkDev = (BlkDev *)vdev->dev;
    struct blkp_req *breq;
    int quota = 64;

    while (!virtqueue_is_empty(vq) && quota > 0) {
        virtqueue_disable_notify(vq);
        while (!virtqueue_is_empty(vq) && quota > 0) {
            breq = virtq_blk_handle_one_request(vq);
            if (breq)
                blkproc(blkDev, breq, vq);
            quota--;
        }
        virtqueue_enable_notify(vq);
    }

    // In single-threaded model, we don't need to kick ourselves.
    // If there are more requests, they will be processed in next iteration
    // or by direct call if we loop here.
}

int virtio_blk_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    virtio_blk_process_queue(vdev, vq);
    return 0;
}

void virtio_blk_close(VirtIODevice *vdev) {
    BlkDev *dev = (BlkDev *)vdev->dev;
    close(dev->img_fd);
    if (dev->kick_fd >= 0)
        close(dev->kick_fd);
    free(dev);
    free(vdev->vqs);
    free(vdev);
}