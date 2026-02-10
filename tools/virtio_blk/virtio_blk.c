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
static int virtio_blk_handle_one_req(BlkDev *dev, struct blkp_req *req,
                                     VirtQueue *vq);

/** @brief Complete a block device operation.
 * @details Updates the virtio queue, injects an interrupt, and frees the
 * request.
 * @param dev Pointer to the BlkDev structure.
 * @param req Pointer to the block request structure.
 * @param vq Pointer to the VirtQueue structure.
 * @param err Error code (0 for success).
 * @param written_len Number of bytes written/read.
 */
static void complete_block_operation(BlkDev *dev, struct blkp_req *req,
                                     VirtQueue *vq, int err,
                                     ssize_t written_len) {
    uint8_t *vstatus = (uint8_t *)(req->req.iov[req->req.iovcnt - 1].iov_base);
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
    update_used_ring(vq, req->req.idx, written_len + 1);
    virtio_inject_irq(vq);
    free(req->req.iov);
    free(req);
}

/** @brief Handler for block I/O completion events.
 * @details Called when a block I/O operation completes. Updates the virtio
 * queue, injects an interrupt, and frees the request.
 * @param param Pointer to the block request structure.
 * @param res Result of the I/O operation.
 */
static void virtio_blk_completion_handler(void *param, int res) {
    struct blkp_req *req = (struct blkp_req *)param;
    BlkDev *dev = (BlkDev *)req->req.vdev->dev;
    VirtQueue *vq = req->req.vq;
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

/** @brief Process a block device request.
 * @details Submits the block I/O request to the io_uring ring.
 * @param dev Pointer to the BlkDev structure.
 * @param req Pointer to the block request structure.
 * @param vq Pointer to the VirtQueue structure.
 */
static int virtio_blk_handle_one_req(BlkDev *dev, struct blkp_req *req,
                                     VirtQueue *vq) {
    struct iovec *iov = req->req.iov;
    int n = req->req.iovcnt;

    struct io_uring *ring = get_global_ring();
    struct io_uring_sqe *sqe;

    req->req.vdev = vq->dev;
    req->req.vq = vq;

    switch (req->type) {
    case VIRTIO_BLK_T_IN:
        sqe = get_sqe_safe(ring);
        req->req.io_completion_event.base.type = EVENT_TYPE_IO_COMPLETION;
        req->req.io_completion_event.handler = virtio_blk_completion_handler;
        req->req.io_completion_event.param = req;
        req->req.io_completion_event.free_on_completion = false;
        io_uring_prep_readv(sqe, dev->img_fd, &iov[1], n - 2, req->offset);
        io_uring_sqe_set_data(sqe, &req->req.io_completion_event);
        return 1;
    case VIRTIO_BLK_T_OUT:
        sqe = get_sqe_safe(ring);
        req->req.io_completion_event.base.type = EVENT_TYPE_IO_COMPLETION;
        req->req.io_completion_event.handler = virtio_blk_completion_handler;
        req->req.io_completion_event.param = req;
        req->req.io_completion_event.free_on_completion = false;
        io_uring_prep_writev(sqe, dev->img_fd, &iov[1], n - 2, req->offset);
        io_uring_sqe_set_data(sqe, &req->req.io_completion_event);
        return 1;
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
    return 0;
}

// handle one descriptor list
static struct blkp_req *virtio_blk_pop_request(VirtQueue *vq) {
    log_debug("virtio_blk_pop_request enter");
    struct blkp_req *breq;
    struct iovec *iov = NULL;
    uint16_t *flags;
    int i, n;
    BlkReqHead *hdr;
    breq = malloc(sizeof(struct blkp_req));
    n = process_descriptor_chain(vq, &breq->req.idx, &iov, &flags, 0, true);
    breq->req.iov = iov;
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
    breq->req.iovcnt = n;
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
    int submitted = 0;

    while (!virtqueue_is_empty(vq) && quota > 0) {
        virtqueue_disable_notify(vq);
        while (!virtqueue_is_empty(vq) && quota > 0) {
            breq = virtio_blk_pop_request(vq);
            if (breq) {
                if (virtio_blk_handle_one_req(blkDev, breq, vq))
                    submitted++;
            }
            quota--;
        }
        virtqueue_enable_notify(vq);
    }

    if (submitted > 0) {
        // io_uring_submit(get_global_ring());
    }

    // In single-threaded model, we don't need to kick ourselves.
    // If there are more requests, they will be processed in next iteration
    // or by direct call if we loop here.
}

BlkDev *virtio_blk_alloc(void) {
    BlkDev *dev = malloc(sizeof(BlkDev));
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
    blk_size = st.st_size / SECTOR_BSIZE;
    dev->config.capacity = blk_size;
    dev->config.size_max = blk_size;

    // Set non-blocking mode for safety, though io_uring handles regular files
    // well. This is critical if img_path refers to a character device or block
    // device.
    if (set_nonblocking(img_fd) < 0) {
        log_warn("Failed to set nonblocking mode for block device %s",
                 img_path);
        // We continue even if this fails, as regular files might not support it
        // but io_uring will still work.
    }

    dev->img_fd = img_fd;
    vdev->virtio_close = virtio_blk_close;
    log_info("debug: virtio_blk_init: %s, size is %lld", img_path,
             dev->config.capacity);

    return 0;
}

int virtio_blk_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    virtio_blk_process_queue(vdev, vq);
    return 0;
}

void virtio_blk_close(VirtIODevice *vdev) {
    BlkDev *dev = (BlkDev *)vdev->dev;
    close(dev->img_fd);
    free(dev);
    free(vdev->vqs);
    free(vdev);
}