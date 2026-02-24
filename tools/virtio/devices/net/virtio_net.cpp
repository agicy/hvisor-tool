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
    log_info("virtio_net_alloc_dev enter");
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

// 专用包装器，防止多次解析 vnet header 导致偏移被破坏
struct StashedNetRx {
    struct net_rx_ctx *ctx;
    struct iovec *payload_iov;
    int payload_iovcnt;
};

virtio::Task net_rx_task(VirtIODevice *vdev) {
    log_info("net_rx_task enter");
    NetDev *net = (NetDev*)vdev->dev;
    VirtQueue *vq = &vdev->vqs[NET_QUEUE_RX];
    virtio::IoUringContext* io_ctx = get_io_context();
    size_t header_len = virtio_net_get_hdr_size(vdev);

    const int MAX_BATCH = 64;
    std::vector<virtio::IoUringContext::IoAwaitable> awaitables; 
    std::vector<StashedNetRx> batch_ctxs;
    std::vector<StashedNetRx> stashed_ctxs; 

    awaitables.reserve(MAX_BATCH);
    batch_ctxs.reserve(MAX_BATCH);
    stashed_ctxs.reserve(MAX_BATCH);

    log_info("net_rx_task looping");
    while (true) {
        while (!vq->ready || !vq->avail_ring) {
            if (vq->notification_event) co_await *(virtio::CoroutineEvent*)vq->notification_event;
            else break;
        }

        while (stashed_ctxs.empty() && virtqueue_is_empty(vq)) {
            virtqueue_enable_notify(vq);
            if (virtqueue_is_empty(vq) && vq->notification_event) {
                co_await *(virtio::CoroutineEvent*)vq->notification_event;
            }
            virtqueue_disable_notify(vq);
            if (!vq->ready) break;
        }
        if (!vq->ready) continue;

        if (!net->rx_ready) {
             co_await io_ctx->async_read(net->tapfd, trashbuf, sizeof(trashbuf), 0);
             continue;
        }

        co_await io_ctx->async_poll(net->tapfd);

        while (!virtqueue_is_empty(vq) && stashed_ctxs.size() < MAX_BATCH) {
            uint16_t head_idx;
            struct net_rx_ctx *ctx = &net->rx_ctxs[vq->last_avail_idx & (vq->num - 1)];

            int n = virtqueue_peek(vq, &head_idx, ctx->iov, NET_IOV_MAX, NULL, 0, false);
            if (n < 1) break;
            virtqueue_pop(vq);

            ctx->vq = vq;
            ctx->vdev = vdev;
            ctx->idx = head_idx;
            ctx->iovcnt = n;
            ctx->vnet_header = ctx->iov[0].iov_base;

            // 这里做剥离 header 动作，只做一次。无论是否 EAGAIN 重试都不再变动
            struct iovec *payload_iov = virtio_net_remove_iov_header(ctx->iov, &n, header_len);
            if (!payload_iov) {
                update_used_ring(vq, ctx->idx, 0);
                continue;
            }

            stashed_ctxs.push_back({ctx, payload_iov, n});
        }

        if (stashed_ctxs.empty()) continue;

        virtio::IoUringContext::BatchAwaitable batch;
        batch.ctx = io_ctx;
        awaitables.clear();
        batch_ctxs.clear();
        int processed_count = 0;

        for (auto& stashed : stashed_ctxs) {
            awaitables.emplace_back();
            virtio::IoUringContext::IoAwaitable& op = awaitables.back();
            
            io_ctx->prep_readv(op, net->tapfd, stashed.payload_iov, stashed.payload_iovcnt, 0);
            
            // 同样使用 NOWAIT，拒绝阻塞
            op.rw_flags = RWF_NOWAIT;
            batch_ctxs.push_back(stashed);
        }

        for (auto& op : awaitables) batch.ops.push_back(&op);
        if (!batch.ops.empty()) co_await batch;

        std::vector<StashedNetRx> next_stash;
        next_stash.reserve(MAX_BATCH);

        for (size_t i = 0; i < awaitables.size(); i++) {
            int res = awaitables[i].result;
            StashedNetRx& stashed = batch_ctxs[i];
            struct net_rx_ctx *ctx = stashed.ctx;

            if (res > 0) {
                // 读取到有效的网络包，安全回填 Virtio 网络头
                memset(ctx->vnet_header, 0, header_len);
                if (vdev->regs.drv_feature & (1ULL << VIRTIO_F_VERSION_1)) {
                    ((NetHdr *)ctx->vnet_header)->num_buffers = 1;
                }
                update_used_ring(vq, ctx->idx, res + header_len);
                processed_count++;
            } 
            else if (res == -EAGAIN || res == -EWOULDBLOCK) {
                next_stash.push_back(stashed);
            } 
            else {
                log_warn("Net RX async_readv failed: %d", res);
                update_used_ring(vq, ctx->idx, 0);
                processed_count++;
            }
        }

        stashed_ctxs = std::move(next_stash);

        if (processed_count > 0) virtio_inject_irq(vq);
    }
}

virtio::Task net_tx_task(VirtIODevice *vdev) {
    log_info("net_tx_task enter");
    NetDev *net = (NetDev*)vdev->dev;
    VirtQueue *vq = &vdev->vqs[NET_QUEUE_TX];
    virtio::IoUringContext* io_ctx = get_io_context();
    size_t header_len = virtio_net_get_hdr_size(vdev);

    const int MAX_BATCH = 64;
    std::vector<virtio::IoUringContext::IoAwaitable> awaitables; 
    std::vector<struct net_tx_ctx*> batch_ctxs;
    awaitables.reserve(MAX_BATCH);
    batch_ctxs.reserve(MAX_BATCH);

    log_info("net_tx_task looping");
    while (true) {
        while (!vq->ready || !vq->avail_ring) {
            if (vq->notification_event) co_await *(virtio::CoroutineEvent*)vq->notification_event;
            else break;
        }

        while (virtqueue_is_empty(vq)) {
            virtqueue_enable_notify(vq);
            if (virtqueue_is_empty(vq) && vq->notification_event) {
                 co_await *(virtio::CoroutineEvent*)vq->notification_event;
            }
            virtqueue_disable_notify(vq);
            if (!vq->ready) break; 
        }
        if (!vq->ready) continue;

        virtio::IoUringContext::BatchAwaitable batch;
        batch.ctx = io_ctx;
        awaitables.clear();
        batch_ctxs.clear();

        while (!virtqueue_is_empty(vq) && awaitables.size() < MAX_BATCH) {
            uint16_t last_avail_idx = vq->last_avail_idx;
            uint16_t head_idx = vq->avail_ring->ring[last_avail_idx & (vq->num - 1)];
            struct net_tx_ctx *ctx = &net->tx_ctxs[head_idx];
            
            int n = process_descriptor_chain_into(vq, &ctx->idx, ctx->iov, NET_IOV_MAX, NULL, 1, false);
            if (n < 1) break;
            virtqueue_pop(vq);

            // 跳过包头，TX 发送给宿主机 TAP 时无需头部
            ctx->iov[0].iov_base = (char*)ctx->iov[0].iov_base + header_len;
            ctx->iov[0].iov_len -= header_len;
            
            awaitables.emplace_back();
            virtio::IoUringContext::IoAwaitable& op = awaitables.back();
            io_ctx->prep_writev(op, net->tapfd, ctx->iov, n, 0);
            
            batch_ctxs.push_back(ctx);
        }
        
        for (auto& op : awaitables) batch.ops.push_back(&op);
        
        if (!batch.ops.empty()) {
            co_await batch;
            for (size_t i = 0; i < awaitables.size(); i++) {
                struct net_tx_ctx *ctx = batch_ctxs[i];
                update_used_ring(vq, ctx->idx, 0);
            }
            virtio_inject_irq(vq);
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
    log_info("virtio_net_init enter");
    NetDev *net = (NetDev*)vdev->dev;
    net->tapfd = virtio_net_open_tap(devname);
    if (net->tapfd < 0) return -1;
    if (set_nonblocking(net->tapfd) < 0) {
        close(net->tapfd);
        return -1;
    }

    vdev->virtio_close = virtio_net_close;
    
    return 0;
}

int virtio_net_queue_resize(VirtIODevice *vdev, int queue_idx, int new_num) {
    log_info("virtio_net_queue_resize enter");
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
    log_info("virtio_net_close enter");
    NetDev *dev = (NetDev*)vdev->dev;
    close(dev->tapfd);
    free(dev->rx_ctxs);
    free(dev->tx_ctxs);
    free(dev);
    free(vdev->vqs);
    free(vdev);
}

void virtio_net_run(VirtIODevice *vdev) {
    log_info("virtio_net_run enter");
    net_rx_task(vdev);
    net_tx_task(vdev);
}
