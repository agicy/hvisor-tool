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
#include "virtio_blk.h"
#include "log.h"
#include "virtio.h"
#include "event_monitor.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>

static void virtio_blk_completion_callback(void *param, int res) {
    struct blkp_req *req = param;
    BlkDev *dev = req->dev;
    VirtQueue *vq = req->vq;
    ssize_t written_len = 0;
    int err = 0;

    if (res < 0) {
        log_error("virt blk async io error: %d", res);
        err = -res;
    } else {
        if (req->type == VIRTIO_BLK_T_IN) {
            written_len = res;
        }
    }

    uint8_t *vstatus = (uint8_t *)(req->iov[req->iovcnt - 1].iov_base);
    if (err == EOPNOTSUPP)
        *vstatus = VIRTIO_BLK_S_UNSUPP;
    else if (err != 0)
        *vstatus = VIRTIO_BLK_S_IOERR;
    else
        *vstatus = VIRTIO_BLK_S_OK;

    update_used_ring(vq, req->idx, (req->type == VIRTIO_BLK_T_IN ? written_len : 0) + 1);
    
    // In single-threaded mode, we inject IRQ immediately if needed or at the end of loop
    virtio_inject_irq(vq);

    // No free(req->iov) or free(req) as they are preallocated
}

static void virtio_blk_process_request_async(BlkDev *dev, struct blkp_req *req, VirtQueue *vq) {
    struct iovec *iov = req->iov;
    int n = req->iovcnt;
    req->dev = dev;
    req->vq = vq;

    switch (req->type) {
    case VIRTIO_BLK_T_IN:
        if (submit_async_readv_prealloc(dev->img_fd, &iov[1], n - 2, req->offset, virtio_blk_completion_callback, req, &req->req_data) < 0) {
            log_error("Failed to submit async read for blk");
            virtio_blk_completion_callback(req, -EIO);
        }
        break;
    case VIRTIO_BLK_T_OUT:
        if (submit_async_writev_prealloc(dev->img_fd, &iov[1], n - 2, req->offset, virtio_blk_completion_callback, req, &req->req_data) < 0) {
            log_error("Failed to submit async write for blk");
            virtio_blk_completion_callback(req, -EIO);
        }
        break;
    case VIRTIO_BLK_T_GET_ID: {
        char s[20] = "hvisor-virblk";
        strncpy(iov[1].iov_base, s, MIN(sizeof(s), iov[1].iov_len));
        // Synchronous completion for GET_ID as it's just memory copy
        virtio_blk_completion_callback(req, 0);
        break;
    }
    default:
        log_fatal("Operation is not supported");
        virtio_blk_completion_callback(req, -EOPNOTSUPP);
        break;
    }
}

// create blk dev.
BlkDev *virtio_blk_alloc_dev(VirtIODevice *vdev) {
    BlkDev *dev = malloc(sizeof(BlkDev));
    vdev->dev = dev;
    dev->config.capacity = -1;
    dev->config.size_max = -1;
    dev->config.seg_max = BLK_SEG_MAX;
    dev->img_fd = -1;
    dev->close = 0;
    // Initial alloc
    dev->reqs = calloc(VIRTQUEUE_BLK_MAX_SIZE, sizeof(struct blkp_req));
    return dev;
}

int virtio_blk_init(VirtIODevice *vdev, const char *img_path) {
    int img_fd = open(img_path, O_RDWR /*| O_DIRECT*/); // Use O_DIRECT for io_uring if possible, or just O_RDWR
    if (img_fd == -1) {
        img_fd = open(img_path, O_RDWR); // Fallback
    }
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
    blk_size = st.st_size / 512; // 512 bytes per block
    dev->config.capacity = blk_size;
    dev->config.size_max = blk_size;
    dev->img_fd = img_fd;
    vdev->virtio_close = virtio_blk_close;
    log_info("debug: virtio_blk_init: %s, size is %lld", img_path,
             dev->config.capacity);
    return 0;
}

// handle one descriptor list
static struct blkp_req *virtio_blk_handle_request(VirtQueue *vq) {
    BlkDev *dev = (BlkDev *)vq->dev->dev;
    struct blkp_req *breq;
    int i, n;
    BlkReqHead *hdr;
    uint16_t idx;
    
    // Use peek logic to determine which slot to use
    uint16_t last_avail_idx = vq->last_avail_idx;
    uint16_t head_idx = vq->avail_ring->ring[last_avail_idx & (vq->num - 1)];
    if (head_idx >= vq->num) {
        log_error("head_idx %d out of bounds (queue num %d)", head_idx, vq->num);
        return NULL;
    }

    breq = &dev->reqs[head_idx];
    
    // Use process_descriptor_chain_into with preallocated iov and flags
    n = process_descriptor_chain_into(vq, &breq->idx, breq->iov, BLK_SEG_MAX + 2, breq->flags, 0, true);
    
    if (n < 2 || n > BLK_SEG_MAX + 2) {
        log_error("iov's num is wrong, n is %d", n);
        if (n == -1) {
            update_used_ring(vq, breq->idx, 0);
            virtio_inject_irq(vq);
        }
        return NULL;
    }

    if ((breq->flags[0] & VRING_DESC_F_WRITE) != 0) {
        log_error("virt queue's desc chain header should not be writable!");
        update_used_ring(vq, breq->idx, 0);
        virtio_inject_irq(vq);
        return NULL;
    }

    if (breq->iov[0].iov_len != sizeof(BlkReqHead)) {
        log_error("the size of blk header is %d, it should be %d!",
                  breq->iov[0].iov_len, sizeof(BlkReqHead));
        update_used_ring(vq, breq->idx, 0);
        virtio_inject_irq(vq);
        return NULL;
    }

    if (breq->iov[n - 1].iov_len != 1 || ((breq->flags[n - 1] & VRING_DESC_F_WRITE) == 0)) {
        log_error(
            "status iov is invalid!, status len is %d, flag is %d, n is %d",
            breq->iov[n - 1].iov_len, breq->flags[n - 1], n);
        update_used_ring(vq, breq->idx, 0);
        virtio_inject_irq(vq);
        return NULL;
    }

    hdr = (BlkReqHead *)(breq->iov[0].iov_base);
    uint64_t offset = hdr->sector * SECTOR_BSIZE;
    breq->type = hdr->type;
    breq->iovcnt = n;
    breq->offset = offset;

    for (i = 1; i < n - 1; i++)
        if (((breq->flags[i] & VRING_DESC_F_WRITE) == 0) !=
            (breq->type == VIRTIO_BLK_T_OUT)) {
            log_error("flag is conflict with operation");
            return NULL;
        }

    return breq;
}

int virtio_blk_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    BlkDev *dev = (BlkDev *)vdev->dev;
    struct blkp_req *breq;
    while (!virtqueue_is_empty(vq)) {
        virtqueue_disable_notify(vq);
        while (!virtqueue_is_empty(vq)) {
            breq = virtio_blk_handle_request(vq);
            if (breq) {
                virtio_blk_process_request_async(dev, breq, vq);
            }
        }
        virtqueue_enable_notify(vq);
    }
    io_flush(); // Batch submit all async requests
    return 0;
}

int virtio_blk_queue_resize(VirtIODevice *vdev, int queue_idx, int new_num) {
    BlkDev *dev = vdev->dev;
    if (new_num > VIRTQUEUE_BLK_MAX_SIZE) {
        log_info("Resizing Blk Queue contexts to %d", new_num);
        struct blkp_req *new_reqs = realloc(dev->reqs, sizeof(struct blkp_req) * new_num);
        if (new_reqs) {
            dev->reqs = new_reqs;
        } else {
            log_error("Failed to realloc blk queue contexts");
            return -1;
        }
    }
    return 0;
}

void virtio_blk_close(VirtIODevice *vdev) {
    BlkDev *dev = vdev->dev;
    dev->close = 1;
    close(dev->img_fd);
    free(dev->reqs);
    free(dev);
    free(vdev->vqs);
    free(vdev);
}
