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

#ifndef _HVISOR_VIRTIO_BLK_H
#define _HVISOR_VIRTIO_BLK_H

#include "event_monitor.h"
#include "virtio.h"

#include <liburing.h>
#include <linux/virtio_blk.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/queue.h>

/// @brief Maximum number of segments in a request.
#define BLK_SEG_MAX 512

/// @brief Maximum number of requests in a virtqueue.
#define VIRTQUEUE_BLK_MAX_SIZE 512

/// @brief A blk sector size
#define SECTOR_BSIZE 512

// VIRTIO_RING_F_INDIRECT_DESC and VIRTIO_RING_F_EVENT_IDX are also supported,
// for some reason we disable them for now.
#define BLK_SUPPORTED_FEATURES                                                 \
    ((1ULL << VIRTIO_BLK_F_SEG_MAX) | (1ULL << VIRTIO_BLK_F_SIZE_MAX) |        \
     (1ULL << VIRTIO_F_VERSION_1))

/// @brief VirtIO Block Device Configuration
typedef struct virtio_blk_config BlkConfig;

/// @brief VirtIO Block Device Request Header
typedef struct virtio_blk_outhdr BlkReqHead;

/**
 * @brief VirtIO Block Device Request
 *
 * This structure represents a block I/O request (Read, Write, or Get ID)
 * submitted by the Guest driver. It extends the generic VirtioIOReq with
 * block-specific metadata like offset and operation type.
 */
struct blkp_req {
    VirtioIOReq req; /**< Base I/O request context. */
    TAILQ_ENTRY(blkp_req)
    link;            /**< Linkage for tail queue (if queueing is needed). */
    uint64_t offset; /**< Sector offset (in bytes) for the I/O operation. */
    uint32_t type;   /**< Request type: VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT, or
                        VIRTIO_BLK_T_GET_ID. */
};

/**
 * @brief VirtIO Block Device Context
 *
 * This structure holds the runtime state of a VirtIO block device backend,
 * including the backing file descriptor and configuration.
 */
typedef struct {
    BlkConfig
        config;  /**< VirtIO Block Configuration (capacity, geometry, etc.). */
    int img_fd;  /**< File descriptor for the backing image file. */
    char *image; /**< Path to the backing image file. */
} BlkDev;

/// @brief Initialize the block device structure.
/// @return Pointer to the initialized BlkDev structure.
BlkDev *virtio_blk_alloc(void);

/**
 * @brief Initialize the virtio block device backend.
 * @param vdev Pointer to the VirtIODevice structure.
 * @param img_path Path to the backing image file.
 * @return 0 on success, -1 on failure.
 */
int virtio_blk_init(VirtIODevice *vdev, const char *img_path);

/**
 * @brief Notify handler for the block device queue.
 * @details Called when the Guest kicks the virtqueue.
 * @param vdev Pointer to the VirtIODevice structure.
 * @param vq Pointer to the VirtQueue structure.
 * @return 0 on success.
 */
int virtio_blk_notify_handler(VirtIODevice *vdev, VirtQueue *vq);

/**
 * @brief Close the virtio block device and release resources.
 * @param vdev Pointer to the VirtIODevice structure.
 */
void virtio_blk_close(VirtIODevice *vdev);

#endif /* _HVISOR_VIRTIO_BLK_H */
