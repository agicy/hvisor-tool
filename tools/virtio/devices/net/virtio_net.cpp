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
#include "virtio_net.h"
#include "event_monitor.h"
#include "log.h"
#include "virtio.h"
#include "io_uring_context.hpp"
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <new>
#include <vector>

// The max bytes of a packet in data link layer is 1518 bytes.
static uint8_t trashbuf[1600];

NetDev *virtio_net_alloc_dev(uint8_t mac[]) {
    NetDev *dev = (NetDev*)malloc(sizeof(NetDev));
    memset(dev, 0, sizeof(NetDev));
    dev->config.mac[0] = mac[0];
    dev->config.mac[1] = mac[1];
    dev->config.mac[2] = mac[2];
    dev->config.mac[3] = mac[3];
    dev->config.mac[4] = mac[4];
    dev->config.mac[5] = mac[5];
    dev->config.status = VIRTIO_NET_S_LINK_UP;
    dev->tapfd = -1;
    dev->rx_ready = 0;
    dev->pending_rx = 0;
    dev->rx_poll_active = false;
    
    dev->rx_ctxs = (struct net_rx_ctx*)calloc(VIRTQUEUE_NET_MAX_SIZE, sizeof(struct net_rx_ctx));
    dev->tx_ctxs = (struct net_tx_ctx*)calloc(VIRTQUEUE_NET_MAX_SIZE, sizeof(struct net_tx_ctx));
    dev->stalled_read_ctx = NULL;

    return dev;
}

static int virtio_net_open_tap(const char *devname) {
    log_info("virtio net tap open");
    int tunfd;
    struct ifreq ifr;
    tunfd = open("/dev/net/tun", O_RDWR);
    if (tunfd < 0) {
        log_error("Failed to open tap device");
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, devname, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(tunfd, TUNSETIFF, (void *)&ifr) < 0) {
        log_error("open of tap device %s fail", devname);
        close(tunfd);
        return -1;
    }
    log_info("open virtio net tap succeed");
    return tunfd;
}

/*
extern "C" int virtio_net_rxq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    NetDev *net = (NetDev*)vdev->dev;
    if (net->rx_ready <= 0) {
        net->rx_ready = 1;
        virtqueue_disable_notify(vq);
    }
    net->rx_event.signal();
    return 0;
}
*/

static inline struct iovec *virtio_net_remove_iov_header(struct iovec *iov, int *niov,
                                          int header_len) {
    if (iov == NULL || *niov == 0 || iov[0].iov_len < (size_t)header_len) {
        log_error("invalid iov");
        return NULL;
    }

    iov[0].iov_len -= header_len;
    if (iov[0].iov_len > 0) {
        iov[0].iov_base = (char *)iov[0].iov_base + header_len;
        return iov;
    } else {
        *niov = *niov - 1;
        if (*niov == 0)
            return NULL;
        return iov + 1;
    }
}

static size_t virtio_net_get_hdr_size(VirtIODevice *vdev) {
    if (vdev->regs.drv_feature & (1ULL << VIRTIO_F_VERSION_1)) {
        return sizeof(NetHdr);
    } else {
        return sizeof(NetHdrLegacy);
    }
}

virtio::Task net_rx_task(VirtIODevice *vdev) {
    NetDev *net = (NetDev*)vdev->dev;
    VirtQueue *vq = &vdev->vqs[NET_QUEUE_RX];
    virtio::IoUringContext* io_ctx = get_io_context();
    size_t header_len = virtio_net_get_hdr_size(vdev);

    // Reuse vectors to reduce allocation
    const int MAX_BATCH = 64;
    std::vector<virtio::IoUringContext::IoAwaitable> awaitables; 
    std::vector<struct net_rx_ctx*> batch_ctxs;
    awaitables.reserve(MAX_BATCH);
    batch_ctxs.reserve(MAX_BATCH);

    while (true) {
        // 1. Wait for descriptors if empty
        if (virtqueue_is_empty(vq)) {
            virtqueue_enable_notify(vq);
            if (virtqueue_is_empty(vq)) { // check again to avoid race
                if (vq->notification_event)
                    co_await *(virtio::CoroutineEvent*)vq->notification_event;
            }
            virtqueue_disable_notify(vq);
        }

        if (!net->rx_ready) {
            // Drop packet if not ready
             co_await io_ctx->async_read(net->tapfd, trashbuf, sizeof(trashbuf), 0);
             continue;
        }

        // 2. Wait for Tap readable
        co_await io_ctx->async_poll(net->tapfd);

        // 3. Process packets
        virtio::IoUringContext::BatchAwaitable batch;
        batch.ctx = io_ctx;
        
        awaitables.clear();
        batch_ctxs.clear();
        
        int loop_count = 0;
        while (loop_count < MAX_BATCH) {
            if (virtqueue_is_empty(vq)) break;
            
            uint16_t last_avail_idx = vq->last_avail_idx;
            uint16_t head_idx = vq->avail_ring->ring[last_avail_idx & (vq->num - 1)];
            struct net_rx_ctx *ctx = &net->rx_ctxs[head_idx];
            
            ctx->vq = vq;
            ctx->vdev = vdev;
            
            int n = process_descriptor_chain_into(vq, &ctx->idx, ctx->iov, NET_IOV_MAX, NULL, 0, false);
            if (n < 1) {
                 break;
            }
            ctx->iovcnt = n;
            ctx->vnet_header = ctx->iov[0].iov_base;
            
            struct iovec *iov_packet = virtio_net_remove_iov_header(ctx->iov, &n, header_len);
            
            if (iov_packet) {
                awaitables.emplace_back();
                virtio::IoUringContext::IoAwaitable& op = awaitables.back();
                io_ctx->prep_readv(op, net->tapfd, iov_packet, n, 0);
                batch_ctxs.push_back(ctx);
            } else {
                 update_used_ring(vq, ctx->idx, 0);
                 virtio_inject_irq(vq);
            }
            loop_count++;
        }
        
        if (!awaitables.empty()) {
            for (size_t i = 0; i < awaitables.size(); i++) {
                batch.ops.push_back(&awaitables[i]);
            }
            
            co_await batch;
            
            for (size_t i = 0; i < awaitables.size(); i++) {
                int res = awaitables[i].result;
                struct net_rx_ctx *ctx = batch_ctxs[i];
                
                if (res > 0) {
                    memset(ctx->vnet_header, 0, header_len);
                    if (vdev->regs.drv_feature & (1ULL << VIRTIO_F_VERSION_1)) {
                        ((NetHdr *)ctx->vnet_header)->num_buffers = 1;
                    }
                    update_used_ring(vq, ctx->idx, res + header_len);
                    virtio_inject_irq(vq);
                } else {
                    update_used_ring(vq, ctx->idx, 0);
                    virtio_inject_irq(vq);
                }
            }
        }
    }
}

virtio::Task net_tx_task(VirtIODevice *vdev) {
    NetDev *net = (NetDev*)vdev->dev;
    VirtQueue *vq = &vdev->vqs[NET_QUEUE_TX];
    virtio::IoUringContext* io_ctx = get_io_context();
    size_t header_len = virtio_net_get_hdr_size(vdev);

    // Reuse vectors
    const int MAX_BATCH = 64;
    std::vector<virtio::IoUringContext::IoAwaitable> awaitables; 
    std::vector<struct net_tx_ctx*> batch_ctxs;
    awaitables.reserve(MAX_BATCH);
    batch_ctxs.reserve(MAX_BATCH);

    while (true) {
        while (virtqueue_is_empty(vq)) {
            virtqueue_enable_notify(vq);
            if (virtqueue_is_empty(vq)) {
                 if (vq->notification_event)
                     co_await *(virtio::CoroutineEvent*)vq->notification_event;
            }
            virtqueue_disable_notify(vq);
        }

        virtio::IoUringContext::BatchAwaitable batch;
        batch.ctx = io_ctx;
        
        awaitables.clear();
        batch_ctxs.clear();

        int loop_count = 0;
        while (!virtqueue_is_empty(vq) && loop_count < MAX_BATCH) {
            uint16_t last_avail_idx = vq->last_avail_idx;
            uint16_t head_idx = vq->avail_ring->ring[last_avail_idx & (vq->num - 1)];
            struct net_tx_ctx *ctx = &net->tx_ctxs[head_idx];
            ctx->vq = vq;
            
            int n = process_descriptor_chain_into(vq, &ctx->idx, ctx->iov, NET_IOV_MAX, NULL, 1, false);
            if (n < 1) break;
            
            // Skip header
            ctx->iov[0].iov_base = (char*)ctx->iov[0].iov_base + header_len;
            ctx->iov[0].iov_len -= header_len;
            
            awaitables.emplace_back();
            virtio::IoUringContext::IoAwaitable& op = awaitables.back();
            io_ctx->prep_writev(op, net->tapfd, ctx->iov, n, 0);
            
            batch_ctxs.push_back(ctx);
            
            loop_count++;
        }
        
        if (!awaitables.empty()) {
            for (size_t i = 0; i < awaitables.size(); i++) {
                batch.ops.push_back(&awaitables[i]);
            }
            
            co_await batch;
            
            for (size_t i = 0; i < awaitables.size(); i++) {
                struct net_tx_ctx *ctx = batch_ctxs[i];
                update_used_ring(vq, ctx->idx, 0);
                virtio_inject_irq(vq);
            }
        }
        io_flush();
    }
}

/*
extern "C" int virtio_net_txq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    NetDev *net = (NetDev*)vdev->dev;
    net->tx_event.signal();
    return 0;
}
*/

int virtio_net_init(VirtIODevice *vdev, char *devname) {
    NetDev *net = (NetDev*)vdev->dev;
    net->tapfd = virtio_net_open_tap(devname);
    if (net->tapfd < 0) return -1;
    if (set_nonblocking(net->tapfd) < 0) {
        close(net->tapfd);
        return -1;
    }

    vdev->virtio_close = virtio_net_close;
    
    // Start tasks
    net_rx_task(vdev);
    net_tx_task(vdev);
    
    return 0;
}

int virtio_net_queue_resize(VirtIODevice *vdev, int queue_idx, int new_num) {
    NetDev *net = (NetDev*)vdev->dev;
    if (new_num > VIRTQUEUE_NET_MAX_SIZE) {
        struct net_rx_ctx *new_rx = (struct net_rx_ctx*)realloc(net->rx_ctxs, sizeof(struct net_rx_ctx) * new_num);
        struct net_tx_ctx *new_tx = (struct net_tx_ctx*)realloc(net->tx_ctxs, sizeof(struct net_tx_ctx) * new_num);
        if (new_rx) net->rx_ctxs = new_rx;
        if (new_tx) net->tx_ctxs = new_tx;
    }
    return 0;
}

void virtio_net_close(VirtIODevice *vdev) {
    NetDev *dev = (NetDev*)vdev->dev;
    close(dev->tapfd);
    free(dev->rx_ctxs);
    free(dev->tx_ctxs);
    free(dev);
    free(vdev->vqs);
    free(vdev);
}
