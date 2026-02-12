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
#include "coroutine_utils.h"
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

static int virtio_blk_pop_request(VirtQueue *vq, struct blkp_req *breq, struct iovec *iov, int iov_cap, uint16_t *flags, int flags_cap);

static Task virtio_blk_coroutine(BlkDev *dev, VirtQueue *vq) {
    virtqueue_disable_notify(vq);

    // Batch size
    const int BATCH_SIZE = 16;
    std::vector<struct blkp_req> req_storage(BATCH_SIZE);
    
    // Pre-allocate IOV buffers for each request in the batch
    // We allocate worst-case size for each request to avoid re-allocation
    const int PER_REQ_IOV_CAP = BLK_SEG_MAX + 2;
    std::vector<std::vector<struct iovec>> iov_pool(BATCH_SIZE);
    std::vector<std::vector<uint16_t>> flags_pool(BATCH_SIZE);
    for (int i = 0; i < BATCH_SIZE; ++i) {
        iov_pool[i].resize(PER_REQ_IOV_CAP);
        flags_pool[i].resize(PER_REQ_IOV_CAP);
    }
    
    std::vector<struct blkp_req *> batch_reqs;
    batch_reqs.reserve(BATCH_SIZE);

    std::vector<struct blkp_req *> async_batch;
    async_batch.reserve(BATCH_SIZE);

    while (true) {
        batch_reqs.clear();

        // Collect a batch of requests
        while (batch_reqs.size() < BATCH_SIZE && !virtqueue_is_empty(vq)) {
            int idx = batch_reqs.size();
            struct blkp_req *breq = &req_storage[idx];
            struct iovec *iov_buf = iov_pool[idx].data();
            uint16_t *flags_buf = flags_pool[idx].data();
            
            int ret = virtio_blk_pop_request(vq, breq, iov_buf, PER_REQ_IOV_CAP, flags_buf, PER_REQ_IOV_CAP);
            if (ret == 0) {
                batch_reqs.push_back(breq);
            } else {
                // Empty (ret > 0) or Error (ret < 0). 
                // If error, it's handled in pop_request (replied with error status or just consumed).
                // In either case, we stop batching.
                break;
            }
        }

        if (batch_reqs.empty()) {
            virtqueue_enable_notify(vq);
            if (virtqueue_is_empty(vq)) {
                co_await WaitForNotify{vq};
            } else {
                co_await YieldAwaitable{};
            }
            virtqueue_disable_notify(vq);
            continue;
        }

        // Process batch using BatchIoUringAwaitable
        // We only batch async READ/WRITE.
        // For simplicity, we handle GET_ID and unsupported immediately (synchronously relative to batch)
        // or filter them. But to keep order, it's better to batch everything and use NOP or just handle completion.
        // However, io_uring doesn't have a "copy memory" opcode easily accessible without registered buffers.
        // So we will split the batch if we encounter non-IO requests, OR we just do them and push a NOP to io_uring to keep counting simple?
        // Actually, mixing sync and async in a batch awaitable is hard.
        // Let's iterate and separate.
        
        // Strategy: Filter out sync requests and process them immediately? 
        // No, that reorders if we are not careful. But GET_ID is rare.
        // Let's assume most are IO.
        
        // We will create a list of "Async Ops" to submit.
        // We need to map results back to requests.
        
        // Let's use a simpler approach: 
        // Create a vector of requests that NEED io_uring.
        // Process others immediately.
        // But wait... if req 1 is IO, req 2 is GET_ID. 
        // If we start IO 1, do GET_ID 2, then wait for IO 1. This is fine. Order of completion to guest is what matters?
        // Actually, virtio-blk doesn't strictly require in-order completion unless VIRTIO_F_ORDER_PLATFORM etc.
        
        async_batch.clear();

        for (size_t i = 0; i < batch_reqs.size(); ++i) {
            struct blkp_req *breq = batch_reqs[i];
            
            if (breq->type == VIRTIO_BLK_T_IN || breq->type == VIRTIO_BLK_T_OUT) {
                async_batch.push_back(breq);
            } else {
                // Handle synchronous requests immediately
                if (breq->type == VIRTIO_BLK_T_GET_ID) {
                    struct iovec *iov = breq->req.iov;
                    char s[20] = "hvisor-virblk";
                    strncpy((char *)iov[1].iov_base, s,
                            MIN(sizeof(s), iov[1].iov_len));
                    
                    uint8_t *vstatus = (uint8_t *)(breq->req.iov[breq->req.iovcnt - 1].iov_base);
                    *vstatus = VIRTIO_BLK_S_OK;
                    update_used_ring(vq, breq->req.idx, 0); // Len is tricky for GET_ID?
                } else {
                    uint8_t *vstatus = (uint8_t *)(breq->req.iov[breq->req.iovcnt - 1].iov_base);
                    *vstatus = VIRTIO_BLK_S_UNSUPP;
                    update_used_ring(vq, breq->req.idx, 0);
                }
                
                // Check if iov was malloced (fallback) and free it if so
                if (breq->req.iov != iov_pool[i].data()) {
                    free(breq->req.iov);
                }
            }
        }

        if (!async_batch.empty()) {
            std::vector<int> results = co_await BatchIoUringAwaitable<struct blkp_req *>(
                get_global_ring(), async_batch,
                [dev](struct io_uring_sqe *sqe, struct blkp_req *breq) {
                    struct iovec *iov = breq->req.iov;
                    int n = breq->req.iovcnt;
                    // Note: iov[0] is header, iov[n-1] is status. 
                    // Data is iov[1] to iov[n-2].
                    // But wait, virtio_blk_pop_request sets up iov.
                    // Let's check logic in original code:
                    // async_readv(dev->img_fd, &iov[1], n - 2, breq->offset);
                    
                    if (breq->type == VIRTIO_BLK_T_IN) {
                        io_uring_prep_readv(sqe, dev->img_fd, &iov[1], n - 2, breq->offset);
                    } else {
                        io_uring_prep_writev(sqe, dev->img_fd, &iov[1], n - 2, breq->offset);
                    }
                });

            // Process results
            for (size_t i = 0; i < async_batch.size(); ++i) {
                struct blkp_req *breq = async_batch[i];
                int res = results[i];
                int err = 0;
                ssize_t written_len = 0;
                
                if (res < 0) {
                    err = -res;
                } else {
                    written_len = res;
                }

                uint8_t *vstatus =
                    (uint8_t *)(breq->req.iov[breq->req.iovcnt - 1].iov_base);
                
                if (err != 0)
                    *vstatus = VIRTIO_BLK_S_IOERR;
                else
                    *vstatus = VIRTIO_BLK_S_OK;

                update_used_ring(vq, breq->req.idx, written_len + 1);
                
                // Check if iov was malloced (fallback) and free it if so
                // We need to find the original index in batch_reqs to compare pointers
                // But async_batch is a subset.
                // However, we know breq is one of the pointers in req_storage.
                // We can calculate offset.
                ptrdiff_t idx = breq - &req_storage[0];
                if (idx >= 0 && idx < BATCH_SIZE) {
                    if (breq->req.iov != iov_pool[idx].data()) {
                        free(breq->req.iov);
                    }
                } else {
                    // Should not happen
                    free(breq->req.iov);
                }
            }
        } else {
            co_await YieldAwaitable{};
        }

        // Inject IRQ once for the whole batch
        co_await virtio_inject_irq(vq);
    }
}

int virtio_blk_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    if (vq->waiter) {
        std::coroutine_handle<>::from_address(vq->waiter).resume();
    }
    return 0;
}

// handle one descriptor list
// Returns: 0 on success, >0 if empty, <0 on fatal error
static int virtio_blk_pop_request(VirtQueue *vq, struct blkp_req *breq, struct iovec *iov, int iov_cap, uint16_t *flags, int flags_cap) {
    // log_debug("virtio_blk_pop_request enter");
    int i, n;
    BlkReqHead *hdr;
    
    // Pass pre-allocated buffers
    struct iovec *iov_ptr = iov;
    uint16_t *flags_ptr = flags;
    
    n = process_descriptor_chain(vq, &breq->req.idx, &iov_ptr, iov_cap, &flags_ptr, flags_cap, 0, true);
    breq->req.iov = iov_ptr;
    
    if (n == 0) return 1; // Empty
    if (n < 0) return -1; // Fatal error
    
    // Check if malloc fallback happened (flags_ptr != flags)
    // We should free flags if it was malloced, as we don't need it outside this function?
    // Actually, flags is used for validation below.
    
    // Validation
    bool error = false;
    if (n < 2 || n > BLK_SEG_MAX + 2) {
        log_error("iov's num is wrong, n is %d", n);
        error = true;
    } else if ((flags_ptr[0] & VRING_DESC_F_WRITE) != 0) {
        log_error("virt queue's desc chain header should not be writable!");
        error = true;
    } else if (iov_ptr[0].iov_len != sizeof(BlkReqHead)) {
        log_error("the size of blk header is %d, it should be %d!",
                  iov_ptr[0].iov_len, sizeof(BlkReqHead));
        error = true;
    } else if (iov_ptr[n - 1].iov_len != 1 || ((flags_ptr[n - 1] & VRING_DESC_F_WRITE) == 0)) {
        log_error(
            "status iov is invalid!, status len is %d, flag is %d, n is %d",
            iov_ptr[n - 1].iov_len, flags_ptr[n - 1], n);
        error = true;
    }

    if (error) {
        goto err_out;
    }

    hdr = (BlkReqHead *)(iov_ptr[0].iov_base);
    uint64_t offset = hdr->sector * SECTOR_BSIZE;
    breq->type = hdr->type;
    breq->req.iovcnt = n;
    breq->offset = offset;

    for (i = 1; i < n - 1; i++)
        if (((flags_ptr[i] & VRING_DESC_F_WRITE) == 0) !=
            (breq->type == VIRTIO_BLK_T_OUT)) {
            log_error("flag is conflict with operation");
            goto err_out;
        }

    if (flags_ptr != flags) free(flags_ptr);
    return 0;

err_out:
    // Try to report error if status byte is accessible
    if (n >= 2 && iov_ptr && iov_ptr[n-1].iov_len == 1 && (flags_ptr[n-1] & VRING_DESC_F_WRITE)) {
         uint8_t *vstatus = (uint8_t *)iov_ptr[n-1].iov_base;
         *vstatus = VIRTIO_BLK_S_IOERR;
         update_used_ring(vq, breq->req.idx, 1);
    } else {
         // Just consume it
         update_used_ring(vq, breq->req.idx, 0);
    }
    
    if (flags_ptr != flags) free(flags_ptr);
    if (iov_ptr != iov) free(iov_ptr);
    breq->req.iov = NULL;
    return -1;
}

BlkDev *virtio_blk_alloc(void) {
    BlkDev *dev = (BlkDev *)malloc(sizeof(BlkDev));
    dev->config.capacity = -1;
    dev->config.size_max = -1;
    dev->config.seg_max = BLK_SEG_MAX;
    dev->img_fd = -1;
    return dev;
}

int virtio_blk_init(VirtIODevice *vdev, const char *img_path) {
    int img_fd = open(img_path, O_RDWR);
    BlkDev *dev = (BlkDev *)vdev->dev;
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

    if (set_nonblocking(img_fd) < 0) {
        log_warn("Failed to set nonblocking mode for block device %s",
                 img_path);
    }

    dev->img_fd = img_fd;
    vdev->virtio_close = virtio_blk_close;
    log_info("debug: virtio_blk_init: %s, size is %lld", img_path,
             dev->config.capacity);

    // Start the coroutine for the single queue
    virtio_blk_coroutine(dev, &vdev->vqs[0]);

    return 0;
}

void virtio_blk_close(VirtIODevice *vdev) {
    BlkDev *dev = (BlkDev *)vdev->dev;
    close(dev->img_fd);
    free(dev);
    free(vdev->vqs);
    free(vdev);
}