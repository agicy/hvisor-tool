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
#include "io_uring_context.hpp"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <new>
#include <vector>

// Helper to update ring after batch completion
void virtio_blk_complete_request(BlkDev *dev, struct blkp_req *req, VirtQueue *vq, int res) {
    int err = 0;
    ssize_t written_len = 0;

    if (res < 0) {
        log_error("blk io error: %d", res);
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
}

virtio::Task blk_worker_task(VirtIODevice *vdev) {
    log_info("blk_worker_task enter");
    BlkDev *dev = (BlkDev*)vdev->dev;
    VirtQueue *vq = &vdev->vqs[0];
    virtio::IoUringContext* io_ctx = get_io_context();

    const int MAX_BATCH = 64;
    std::vector<virtio::IoUringContext::IoAwaitable> awaitables; 
    std::vector<struct blkp_req*> batch_reqs;
    awaitables.reserve(MAX_BATCH);
    batch_reqs.reserve(MAX_BATCH);

    log_info("blk_worker_task looping");
    while (true) {
        // 阶段 1：等待设备进入 Ready 状态 (处理初始化和重置)
        // 使用 while 而非 if，可以防止伪唤醒
        while (!vq->ready || !vq->avail_ring) {
            if (vq->notification_event) {
                co_await *(virtio::CoroutineEvent*)vq->notification_event;
            } else {
                // 如果没有事件，通常意味着严重错误或处于同步模式
                break; 
            }
        }

        // 阶段 2：等待队列中有数据 (处理正常的 IO 请求)
        while (virtqueue_is_empty(vq)) {
            virtqueue_enable_notify(vq);
            if (virtqueue_is_empty(vq)) {
                if (vq->notification_event)
                    co_await *(virtio::CoroutineEvent*)vq->notification_event;
            }
            virtqueue_disable_notify(vq);
            
            // 唤醒后，如果发现是因为 Reset 导致 ready 没了，
            // 则 continue 回到阶段 1 重新等待
            if (!vq->ready) break;
            
            // 如果依然为空（伪唤醒），也继续循环
            if (virtqueue_is_empty(vq)) continue;
        }

        if (!vq->ready) continue; // 醒来后如果 ready 没了，回到最上面等待

        virtio::IoUringContext::BatchAwaitable batch;
        batch.ctx = io_ctx;
        
        awaitables.clear();
        batch_reqs.clear();

        int loop_count = 0;
        while (!virtqueue_is_empty(vq) && loop_count < MAX_BATCH) {
             uint16_t last_avail_idx = vq->last_avail_idx;
             uint16_t head_idx = vq->avail_ring->ring[last_avail_idx & (vq->num - 1)];
             struct blkp_req *req = &dev->reqs[head_idx];
             
             int n = process_descriptor_chain_into(vq, &req->idx, req->iov, BLK_SEG_MAX + 2, NULL, 0, false);
             if (n < 1) break;
             
             req->iovcnt = n;
             struct virtio_blk_outhdr *out_hdr = (struct virtio_blk_outhdr *)req->iov[0].iov_base;
             req->type = out_hdr->type;
             req->offset = out_hdr->sector * SECTOR_BSIZE;
             
             if (req->type == VIRTIO_BLK_T_GET_ID) {
                 char s[20] = "hvisor-virblk";
                 strncpy((char*)req->iov[1].iov_base, s, MIN(sizeof(s), req->iov[1].iov_len));
                 virtio_blk_complete_request(dev, req, vq, 0);
                 continue; 
             } else if (req->type != VIRTIO_BLK_T_IN && req->type != VIRTIO_BLK_T_OUT) {
                 virtio_blk_complete_request(dev, req, vq, -EOPNOTSUPP);
                 continue;
             }
             
             awaitables.emplace_back();
             virtio::IoUringContext::IoAwaitable& op = awaitables.back();
             
             if (req->type == VIRTIO_BLK_T_IN) {
                 io_ctx->prep_readv(op, dev->img_fd, &req->iov[1], n - 2, req->offset);
             } else if (req->type == VIRTIO_BLK_T_OUT) {
                 io_ctx->prep_writev(op, dev->img_fd, &req->iov[1], n - 2, req->offset);
             }
             
             batch_reqs.push_back(req);
             loop_count++;
        }
        
        if (!awaitables.empty()) {
            for (size_t i = 0; i < awaitables.size(); i++) {
                batch.ops.push_back(&awaitables[i]);
            }
            
            co_await batch;
            
            for (size_t i = 0; i < awaitables.size(); i++) {
                virtio_blk_complete_request(dev, batch_reqs[i], vq, awaitables[i].result);
            }
            virtio_inject_irq(vq);
        }
        
        io_flush();
    }
}

BlkDev *virtio_blk_alloc_dev(VirtIODevice *vdev) {
    log_info("virtio_blk_alloc_dev enter");
    BlkDev *dev = (BlkDev*)malloc(sizeof(BlkDev));
    vdev->dev = dev;
    dev->config.capacity = -1;
    dev->config.size_max = -1;
    dev->config.seg_max = BLK_SEG_MAX;
    dev->img_fd = -1;
    
    dev->reqs = (struct blkp_req*)calloc(VIRTQUEUE_BLK_MAX_SIZE, sizeof(struct blkp_req));
    
    return dev;
}

int virtio_blk_init(VirtIODevice *vdev, const char *img_path) {
    log_info("virtio_blk_init enter");
    BlkDev *dev = (BlkDev*)vdev->dev;
    if (img_path == NULL) return -1;
    
    dev->img_fd = open(img_path, O_RDWR | O_DIRECT);
    if (dev->img_fd < 0) {
        dev->img_fd = open(img_path, O_RDWR);
        if (dev->img_fd < 0) return -1;
    }
    
    struct stat st;
    fstat(dev->img_fd, &st);
    dev->config.capacity = st.st_size / SECTOR_BSIZE;

    vdev->virtio_close = virtio_blk_close;
    
    return 0;
}

/*
extern "C" int virtio_blk_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    BlkDev *dev = (BlkDev*)vdev->dev;
    dev->event.signal();
    return 0;
}
*/

int virtio_blk_queue_resize(VirtIODevice *vdev, int queue_idx, int new_num) {
    log_info("virtio_blk_queue_resize enter");
    BlkDev *dev = (BlkDev*)vdev->dev;
    if (new_num > VIRTQUEUE_BLK_MAX_SIZE) {
         struct blkp_req *new_reqs = (struct blkp_req*)realloc(dev->reqs, sizeof(struct blkp_req) * new_num);
         if (new_reqs) dev->reqs = new_reqs;
    }
    return 0;
}

void virtio_blk_close(VirtIODevice *vdev) {
    log_info("virtio_blk_close enter");
    BlkDev *dev = (BlkDev *)vdev->dev;
    if (dev->img_fd >= 0) {
        close(dev->img_fd);
        dev->img_fd = -1;
    }
    free(dev->reqs);
    free(dev);
    free(vdev->vqs);
    free(vdev);
}

void virtio_blk_run(VirtIODevice *vdev) {
    log_info("virtio_blk_run enter");
    blk_worker_task(vdev);
}
