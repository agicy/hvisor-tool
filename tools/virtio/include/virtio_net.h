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
#ifndef _HVISOR_VIRTIO_NET_H
#define _HVISOR_VIRTIO_NET_H
#include "event_monitor.h"
#include "virtio.h"
#include <linux/virtio_net.h>

// Queue idx for virtio net.
#define NET_QUEUE_RX 0
#define NET_QUEUE_TX 1

// Maximum number of queues for Virtio net
#define NET_MAX_QUEUES 2

#define VIRTQUEUE_NET_MAX_SIZE 1024
#define NET_IOV_MAX 64

// VIRTIO_RING_F_INDIRECT_DESC and VIRTIO_RING_F_EVENT_IDX are supported, for
// some reason we cancel them.
#define NET_SUPPORTED_FEATURES                                                 \
    ((1ULL << VIRTIO_F_VERSION_1) | (1ULL << VIRTIO_NET_F_MAC) |               \
     (1ULL << VIRTIO_NET_F_STATUS))

typedef struct virtio_net_config NetConfig;
typedef struct virtio_net_hdr_v1 NetHdr;
typedef struct virtio_net_hdr NetHdrLegacy;

struct net_rx_ctx {
    VirtQueue *vq;
    uint16_t idx;
    struct iovec iov[NET_IOV_MAX];
    int iovcnt;
    void *vnet_header;
    size_t header_len;
    VirtIODevice *vdev;
    struct request_data req_data;
};

struct net_tx_ctx {
    VirtQueue *vq;
    uint16_t idx;
    struct iovec iov[NET_IOV_MAX];
    int iovcnt;
    struct request_data req_data;
};

typedef struct virtio_net_dev {
    NetConfig config;
    int tapfd;
    int rx_ready;
    int pending_rx;
    bool rx_poll_active;
    struct net_rx_ctx *rx_ctxs;
    struct net_tx_ctx *tx_ctxs;
    struct request_data poll_req;
} NetDev;

NetDev *virtio_net_alloc_dev(uint8_t mac[]);
int virtio_net_init(VirtIODevice *vdev, char *devname);
int virtio_net_rxq_notify_handler(VirtIODevice *vdev, VirtQueue *vq);
int virtio_net_txq_notify_handler(VirtIODevice *vdev, VirtQueue *vq);
int virtio_net_queue_resize(VirtIODevice *vdev, int queue_idx, int new_num);
void virtio_net_close(VirtIODevice *vdev);

#endif //_HVISOR_VIRTIO_NET_H
