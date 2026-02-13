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
#ifndef _HVISOR_VIRTIO_CONSOLE_H
#define _HVISOR_VIRTIO_CONSOLE_H
#include "event_monitor.h"
#include "virtio.h"
#include <linux/virtio_console.h>

#ifdef __cplusplus
#include "coroutine_utils.hpp"
#endif

#define CONSOLE_SUPPORTED_FEATURES                                             \
    ((1ULL << VIRTIO_F_VERSION_1) | (1ULL << VIRTIO_CONSOLE_F_SIZE))
#define CONSOLE_MAX_QUEUES 2
#define VIRTQUEUE_CONSOLE_MAX_SIZE 64
#define CONSOLE_QUEUE_RX 0
#define CONSOLE_QUEUE_TX 1
#define CONSOLE_IOV_MAX 16

struct console_read_ctx {
    VirtQueue *vq;
    uint16_t idx;
    struct iovec iov[CONSOLE_IOV_MAX];
    int iovcnt;
#ifndef __cplusplus
    struct request_data req_data;
#endif
};

struct console_tx_ctx {
    VirtQueue *vq;
    uint16_t idx;
    struct iovec iov[CONSOLE_IOV_MAX];
    int iovcnt;
#ifndef __cplusplus
    struct request_data req_data;
#endif
};

typedef struct virtio_console_config ConsoleConfig;
typedef struct virtio_console_dev {
    ConsoleConfig config;
    int master_fd;
    int rx_ready;
    int pending_rx;
    bool rx_poll_active;
    struct console_read_ctx *rx_ctxs;
    struct console_tx_ctx *tx_ctxs;
    struct console_read_ctx *stalled_read_ctx;
    struct request_data poll_req;
} ConsoleDev;

ConsoleDev *virtio_console_alloc_dev();
int virtio_console_init(VirtIODevice *vdev);
int virtio_console_rxq_notify_handler(VirtIODevice *vdev, VirtQueue *vq);
int virtio_console_txq_notify_handler(VirtIODevice *vdev, VirtQueue *vq);
int virtio_console_queue_resize(VirtIODevice *vdev, int queue_idx, int new_num);
void virtio_console_close(VirtIODevice *vdev);

#endif
