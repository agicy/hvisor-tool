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
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <unistd.h>
// The max bytes of a packet in data link layer is 1518 bytes.
static uint8_t trashbuf[1600];

// 分配 virtio net 设备结构体
// 
// 初始化 NetDev 结构体并返回指针。
// 
// 参数：
//   mac: MAC 地址数组 (6 bytes)
// 
// 返回值：
//   分配并初始化后的 NetDev 指针
NetDev *virtio_net_alloc_dev(uint8_t mac[]) {
    NetDev *dev = malloc(sizeof(NetDev));
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
    // Allocate contexts based on default size initially, 
    // real implementation should realloc on queue resize but here we just alloc MAX
    // Or better, alloc VIRTQUEUE_NET_MAX_SIZE for now as "supported max".
    dev->rx_ctxs = calloc(VIRTQUEUE_NET_MAX_SIZE, sizeof(struct net_rx_ctx));
    dev->tx_ctxs = calloc(VIRTQUEUE_NET_MAX_SIZE, sizeof(struct net_tx_ctx));
    dev->stalled_read_ctx = NULL;
    return dev;
}

// open tap device
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
    // IFF_NO_PI tells kernel do not provide message header
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

static void virtio_net_event_handler(int fd, void *param);

// RX 队列通知处理函数
// 
// 当客户机向 RX 队列添加缓冲区并通知设备时被调用。
// 如果之前因为队列为空而暂停了轮询，这里会恢复轮询。
// 
// 参数：
//   vdev: VirtIODevice 指针
//   vq: 接收队列 (RX Queue)
// 
// 返回值：
//   总是返回 0
int virtio_net_rxq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    log_debug("virtio_net_rxq_notify_handler");
    NetDev *net = vdev->dev;
    if (net->rx_ready <= 0) {
        net->rx_ready = 1;
        // When buffers are all used, virtio_net_event_handler will notify the
        // driver.
        virtqueue_disable_notify(vq);
    }
    
    if (!net->rx_poll_active && !virtqueue_is_empty(vq)) {
        add_event_read_prealloc(net->tapfd, virtio_net_event_handler, vdev, &net->poll_req);
        net->rx_poll_active = true;
    }
    return 0;
}
/// remove the header in iov, return the new iov. the new iov num is in niov.
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
    // Virtio 1.0 specifies the header as NetHdr. But the legacy version
    // specifies the headr as NetHdrLegacy
    if (vdev->regs.drv_feature & (1ULL << VIRTIO_F_VERSION_1)) {
        return sizeof(NetHdr);
    } else {
        return sizeof(NetHdrLegacy);
    }
}

// 异步读取完成回调
// 
// 处理异步读取完成后的逻辑，包括更新 used ring，注入中断，以及重新注册读事件。
// 
// 参数：
//   param: 回调上下文，包含 virtqueue 和 iovec 信息
//   res: 读取结果，大于 0 表示读取字节数，小于 0 表示错误码
static void virtio_net_async_rx_done(void *param, int res) {
    struct net_rx_ctx *ctx = param;
    VirtQueue *vq = ctx->vq;
    VirtIODevice *vdev = ctx->vdev;
    NetDev *net = vdev->dev;
    ssize_t len = res;

    if (len < 0 && len != -EWOULDBLOCK && len != -EAGAIN) {
        log_info("Failed to read packet: %d", -len);
        vq->last_avail_idx--;
    } else if (len > 0) {
        memset(ctx->vnet_header, 0, ctx->header_len);
        if (vdev->regs.drv_feature & (1ULL << VIRTIO_F_VERSION_1)) {
            ((NetHdr *)ctx->vnet_header)->num_buffers = 1;
        }
        update_used_ring(vq, ctx->idx, len + ctx->header_len);
        virtio_inject_irq(vq);
    } else {
        // EOF or EAGAIN
        // Store as stalled
        log_debug("Net read EAGAIN, stalling context");
        net->stalled_read_ctx = ctx;
    }
    
    // No free(ctx->iov) or free(ctx)

    // Re-arm poll if all pending requests are done
    net->pending_rx--;
    if (net->pending_rx <= 0) {
        net->pending_rx = 0; // Safety
        if (virtqueue_is_empty(vq) && !net->stalled_read_ctx) {
            net->rx_poll_active = false;
        } else if (!net->rx_poll_active) {
            // Only re-arm if not already active (avoid double poll)
            add_event_read_prealloc(net->tapfd, virtio_net_event_handler, vdev, &net->poll_req);
            net->rx_poll_active = true;
        }
    }
}

// 处理网络设备的读事件
// 
// 当 TAP 设备有数据可读时被调用。该函数检查 virtqueue 是否有可用缓冲区，
// 如果有，则提交异步读取请求将数据读入客户机提供的缓冲区。
// 如果 virtqueue 为空，则暂停轮询以避免数据丢失。
// 
// 参数：
//   fd: 文件描述符 (tapfd)
//   param: VirtIODevice 指针
static void virtio_net_event_handler(int fd, void *param) {
    VirtIODevice *vdev = param;
    void *vnet_header;
    struct iovec *iov_packet;
    NetDev *net = vdev->dev;
    VirtQueue *vq = &vdev->vqs[NET_QUEUE_RX];
    int n;
    size_t header_len = virtio_net_get_hdr_size(vdev);
    if (fd != net->tapfd) {
        log_error("invalid event");
        return;
    }
    if (net->tapfd == -1 || vdev->type != VirtioTNet) {
        log_error("net rx callback should not be called");
        return;
    }

    // Reset poll active flag because the poll event has triggered
    net->rx_poll_active = false;

    // Handle stalled context first if any
    if (net->stalled_read_ctx) {
        struct net_rx_ctx *ctx = net->stalled_read_ctx;
        net->stalled_read_ctx = NULL;
        
        // Use effective_iov which was calculated and saved before stalling
        int ret = submit_async_readv_prealloc(net->tapfd, ctx->effective_iov, ctx->effective_iovcnt, 0, virtio_net_async_rx_done, ctx, &ctx->req_data);
        if (ret < 0) {
            log_error("Failed to resubmit stalled read for net: %d", ret);
            update_used_ring(vq, ctx->idx, 0);
            virtio_inject_irq(vq);
        } else {
            net->pending_rx++;
        }
    }

    // if vq is not setup, drop the packet
    if (!net->rx_ready) {
        read(net->tapfd, trashbuf, sizeof(trashbuf));
        add_event_read_prealloc(net->tapfd, virtio_net_event_handler, vdev, &net->poll_req);
        net->rx_poll_active = true;
        return;
    }
    // if rx_vq is empty, drop the packet
    if (virtqueue_is_empty(vq)) {
        net->rx_poll_active = false;
        virtio_inject_irq(vq);
        return;
    }

    // Process packets in batch
    int loop_count = 0;
    while (loop_count < VIRTQUEUE_NET_MAX_SIZE) {
        if (virtqueue_is_empty(vq)) {
            // No more buffers available in the guest
            break;
        }
        
        // Peek head index
        uint16_t last_avail_idx = vq->last_avail_idx;
        uint16_t head_idx = vq->avail_ring->ring[last_avail_idx & (vq->num - 1)];
        // Check against current queue size (vq->num) instead of static MAX
        // Because we now realloc to match vq->num if it's larger.
        // Actually, if we realloc, rx_ctxs size is at least vq->num (or MAX if num < MAX).
        // Safest is to check against vq->num because that's what limits the ring index.
        if (head_idx >= vq->num) {
             log_error("head_idx %d out of bounds (queue num %d)", head_idx, vq->num);
             break;
        }
        struct net_rx_ctx *ctx = &net->rx_ctxs[head_idx];
        
        ctx->vq = vq;
        ctx->vdev = vdev;
        ctx->header_len = header_len;

        n = process_descriptor_chain_into(vq, &ctx->idx, ctx->iov, NET_IOV_MAX, NULL, 0, false);
        if (n < 1 || n > VIRTQUEUE_NET_MAX_SIZE) {
            if (n < 1) {
                 // No more descriptors or error
                 if (n == -1) {
                     // Buffer too small, but descriptor consumed.
                     update_used_ring(vq, ctx->idx, 0);
                     virtio_inject_irq(vq);
                 }
                 break;
            }
            log_error("process_descriptor_chain failed, n=%d", n);
            update_used_ring(vq, ctx->idx, 0);
            virtio_inject_irq(vq);
            continue; 
        }
        ctx->iovcnt = n;
        
        vnet_header = ctx->iov[0].iov_base;
        ctx->vnet_header = vnet_header;
        
        // virtio_net_remove_iov_header modifies the iov pointer logic, but since we have iov array,
        // we can just pass a pointer to the array element if it's contiguous.
        // However, virtio_net_remove_iov_header logic is:
        // returns iov (modified) or iov+1.
        // Since ctx->iov is an array, we can't "return iov+1" and overwrite ctx->iov.
        // We need a local pointer.
        struct iovec *temp_iov = ctx->iov;
        int temp_n = n;
        
        iov_packet = virtio_net_remove_iov_header(temp_iov, &temp_n, header_len);
        if (iov_packet == NULL) {
            update_used_ring(vq, ctx->idx, 0);
            virtio_inject_irq(vq);
            continue;
        }

        // Save for potential retry (EAGAIN/stalled)
        ctx->effective_iov = iov_packet;
        ctx->effective_iovcnt = temp_n;
        
        // Async Read
        int ret = submit_async_readv_prealloc(net->tapfd, iov_packet, temp_n, 0, virtio_net_async_rx_done, ctx, &ctx->req_data);
        if (ret < 0) {
            log_error("Failed to submit async read for net rx: %d", ret);
            update_used_ring(vq, ctx->idx, 0);
            virtio_inject_irq(vq);
        } else {
            net->pending_rx++;
        }
        loop_count++;
    }

        if (loop_count > 0) {
        io_flush();
        // Pipeline optimization: if we still have buffers, re-arm poll immediately
        // instead of waiting for all IOs to complete.
        if (!net->rx_poll_active && (!virtqueue_is_empty(vq) || net->stalled_read_ctx)) {
            add_event_read_prealloc(net->tapfd, virtio_net_event_handler, vdev, &net->poll_req);
            net->rx_poll_active = true;
        }
    } else {
        if (net->pending_rx == 0 && !net->stalled_read_ctx) {
             add_event_read_prealloc(net->tapfd, virtio_net_event_handler, vdev, &net->poll_req);
             net->rx_poll_active = true;
        }
    }
}

static void virtio_net_async_tx_done(void *param, int res) {
    struct net_tx_ctx *ctx = param;
    // update_used_ring is done after async write completes
    // Actually for TX, we can update ring earlier if we don't care about result,
    // but correct way is to wait.
    update_used_ring(ctx->vq, ctx->idx, 0); // TX len is 0 or len? Usually 0 for TX to Guest? No, Guest doesn't read len.
    virtio_inject_irq(ctx->vq);
    // No free
}

// 处理 TX 队列请求
// 
// 从 TX 队列获取数据并写入到 TAP 设备。
// 
// 参数：
//   vdev: VirtIODevice 指针
//   vq: 发送队列 (TX Queue)
static void virtio_net_handle_tx_request(VirtIODevice *vdev, VirtQueue *vq) {
    int i, n;
    int packet_len, all_len; // all_len include the header length.
    NetDev *net = vdev->dev;
    size_t header_len = virtio_net_get_hdr_size(vdev);
    if (net->tapfd == -1) {
        log_error("tap device is invalid");
        return;
    }
    
    // Peek head index
    uint16_t last_avail_idx = vq->last_avail_idx;
    uint16_t head_idx = vq->avail_ring->ring[last_avail_idx & (vq->num - 1)];
    struct net_tx_ctx *ctx = &net->tx_ctxs[head_idx];
    
    ctx->vq = vq;

    n = process_descriptor_chain_into(vq, &ctx->idx, ctx->iov, NET_IOV_MAX, NULL, 1, false);
    if (n < 1) {
        return;
    }
    ctx->iovcnt = n;

    for (i = 0, all_len = 0; i < n; i++)
        all_len += ctx->iov[i].iov_len;

    packet_len = all_len - header_len;
    ctx->iov[0].iov_base += header_len;
    ctx->iov[0].iov_len -= header_len;
    log_debug("packet send: %d bytes", packet_len);

    int ret = submit_async_writev_prealloc(net->tapfd, ctx->iov, n, 0, virtio_net_async_tx_done, ctx, &ctx->req_data);
    if (ret < 0) {
        log_error("Failed to submit async write for net tx: %d", ret);
        // Even if failed, we must return the descriptor to guest
        update_used_ring(vq, ctx->idx, 0);
        virtio_inject_irq(vq);
    }
}

// TX 队列通知处理函数
// 
// 当客户机向 TX 队列添加数据并通知设备时被调用。
// 处理队列中的所有挂起请求。
// 
// 参数：
//   vdev: VirtIODevice 指针
//   vq: 发送队列 (TX Queue)
// 
// 返回值：
//   总是返回 0
int virtio_net_txq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    log_debug("virtio_net_txq_notify_handler");
    while (!virtqueue_is_empty(vq)) {
        virtqueue_disable_notify(vq);
        while (!virtqueue_is_empty(vq)) {
            virtio_net_handle_tx_request(vdev, vq);
        }
        virtqueue_enable_notify(vq);
    }
    io_flush(); // Flush TX batch
    return 0;
}

// 初始化 virtio net 设备
// 
// 打开并配置 TAP 设备，设置非阻塞模式，并注册读事件监听。
// 
// 参数：
//   vdev: VirtIODevice 指针
// 
// 返回值：
//   成功返回 0，失败返回 -1
int virtio_net_init(VirtIODevice *vdev, char *devname) {
    NetDev *net = vdev->dev;
    net->tapfd = virtio_net_open_tap(devname);
    if (net->tapfd < 0) {
        log_error("virtio_net_open_tap failed");
        return -1;
    }
    if (set_nonblocking(net->tapfd) < 0) {
        log_error("set_nonblocking failed");
        close(net->tapfd);
        return -1;
    }

    // register an epoll read event for tap device
    int ret = add_event_read_prealloc(net->tapfd, virtio_net_event_handler, vdev, &net->poll_req);
    if (ret < 0) {
        log_error("Can't register net event");
        close(net->tapfd);
        net->tapfd = -1;
        return -1;
    }
    net->rx_poll_active = true;
    // net->event = NULL;
    vdev->virtio_close = virtio_net_close;
    return 0;
}

int virtio_net_queue_resize(VirtIODevice *vdev, int queue_idx, int new_num) {
    NetDev *net = vdev->dev;
    if (new_num > VIRTQUEUE_NET_MAX_SIZE) {
        log_info("Resizing Net Queue contexts to %d", new_num);
        struct net_rx_ctx *new_rx = realloc(net->rx_ctxs, sizeof(struct net_rx_ctx) * new_num);
        struct net_tx_ctx *new_tx = realloc(net->tx_ctxs, sizeof(struct net_tx_ctx) * new_num);
        if (new_rx) net->rx_ctxs = new_rx;
        if (new_tx) net->tx_ctxs = new_tx;
        if (!new_rx || !new_tx) {
            log_error("Failed to realloc net queue contexts");
            return -1;
        }
    }
    return 0;
}

// 关闭 virtio net 设备
// 
// 关闭 TAP 设备文件描述符并释放设备资源。
// 
// 参数：
//   vdev: VirtIODevice 指针
void virtio_net_close(VirtIODevice *vdev) {
    NetDev *dev = vdev->dev;
    close(dev->tapfd);
    free(dev->rx_ctxs);
    free(dev->tx_ctxs);
    free(dev);
    free(vdev->vqs);
    free(vdev);
}
