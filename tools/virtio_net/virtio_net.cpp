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

#include "virtio_net.h"
#include "event_monitor.h"
#include "log.h"
#include "virtio.h"

#include <errno.h>
#include <fcntl.h>
#include <liburing.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <unistd.h>

// The max bytes of a packet in data link layer is 1518 bytes.
static uint8_t trashbuf[1600];

static int virtio_net_open_tap(char *devname);
static size_t virtio_net_get_nethdr_size(VirtIODevice *vdev);
static inline struct iovec *virtio_net_rm_iov_header(struct iovec *iov,
                                                     int *niov, int header_len);

/// @brief Initialize a network device structure.
/// @param mac The MAC address for the device.
/// @return Pointer to the initialized NetDev structure.
NetDev *virtio_net_alloc(uint8_t mac[]) {
    NetDev *dev = malloc(sizeof(NetDev));
    dev->config.mac[0] = mac[0];
    dev->config.mac[1] = mac[1];
    dev->config.mac[2] = mac[2];
    dev->config.mac[3] = mac[3];
    dev->config.mac[4] = mac[4];
    dev->config.mac[5] = mac[5];
    dev->config.status = VIRTIO_NET_S_LINK_UP;
    dev->tapfd = -1;
    dev->rx_ready = 1;
    dev->event = NULL;
    dev->pending_rx_req = NULL;
    return dev;
}

// open tap device
/// @brief Open a TAP device.
/// @param devname The name of the TAP device.
/// @return The file descriptor of the TAP device, or -1 on error.
static int virtio_net_open_tap(char *devname) {
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

#include "coroutine_utils.h"

/// @brief Process the TX queue for the network device.
/// @param vdev Pointer to the VirtIODevice structure.
/// @param vq Pointer to the VirtQueue structure.
static Task virtio_net_txq_coroutine(VirtIODevice *vdev, VirtQueue *vq) {
    NetDev *net = (NetDev *)vdev->dev;
    size_t header_len = virtio_net_get_nethdr_size(vdev);
    static char pad[64] = {0};

    virtqueue_disable_notify(vq);

    const int BATCH_SIZE = 32;
    std::vector<std::pair<struct iovec *, int>> batch_reqs; // iov, n_iov
    std::vector<uint16_t> batch_idxs;
    std::vector<int> batch_lens; // To store lengths for update_used_ring
    
    // Pre-allocate IOV buffers for the batch
    const int PER_REQ_IOV_CAP = VIRTQUEUE_NET_MAX_SIZE + 2;
    std::vector<std::vector<struct iovec>> iov_pool(BATCH_SIZE);
    for (int i = 0; i < BATCH_SIZE; ++i) {
        iov_pool[i].resize(PER_REQ_IOV_CAP);
    }

    while (true) {
        batch_reqs.clear();
        batch_idxs.clear();
        batch_lens.clear();

        while (batch_reqs.size() < BATCH_SIZE && !virtqueue_is_empty(vq)) {
            struct iovec *iov = iov_pool[batch_reqs.size()].data();
            uint16_t idx;
            int n = process_descriptor_chain(vq, &idx, &iov, PER_REQ_IOV_CAP, NULL, 0, 1, false);
            if (n < 1) {
                if (iov != iov_pool[batch_reqs.size()].data()) free(iov);
                continue;
            }

            int all_len = 0;
            for (int i = 0; i < n; i++)
                all_len += iov[i].iov_len;

            int packet_len = all_len - header_len;
            iov[0].iov_base = (char *)iov[0].iov_base + header_len;
            iov[0].iov_len -= header_len;

            if (packet_len < 64) {
                iov[n].iov_base = pad;
                iov[n].iov_len = 64 - packet_len;
                n++;
            }
            
            batch_reqs.push_back({iov, n});
            batch_idxs.push_back(idx);
            // We need header_len for update_used_ring later, but it's constant
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

        // Submit batch
        std::vector<int> results = co_await BatchIoUringAwaitable<std::pair<struct iovec *, int>>(
            get_global_ring(), batch_reqs,
            [net](struct io_uring_sqe *sqe, std::pair<struct iovec *, int> req) {
                io_uring_prep_writev(sqe, net->tapfd, req.first, req.second, 0);
            });

        // Process results
        for (size_t i = 0; i < batch_reqs.size(); ++i) {
            int res = results[i];
            if (res < 0) {
                log_debug("net tx error: %d", res);
                res = 0;
            }
            update_used_ring(vq, batch_idxs[i], res + header_len);
            
            if (batch_reqs[i].first != iov_pool[i].data()) {
                free(batch_reqs[i].first);
            }
        }

        co_await virtio_inject_irq(vq);
    }
}

static Task virtio_net_rxq_coroutine(VirtIODevice *vdev, VirtQueue *vq) {
    NetDev *net = (NetDev *)vdev->dev;
    virtqueue_disable_notify(vq);

    // Batch size
    const int BATCH_SIZE = 64;
    // We need to store context for each request in batch
    struct RxReqContext {
        struct iovec *iov;
        struct iovec *iov_packet;
        int packet_n;
        uint16_t idx;
        void *vnet_header;
    };
    
    // Pre-allocate IOV buffers for each request in the batch
    const int PER_REQ_IOV_CAP = NET_SEG_MAX + 2;
    std::vector<std::vector<struct iovec>> iov_pool(BATCH_SIZE);
    for (int i = 0; i < BATCH_SIZE; ++i) {
        iov_pool[i].resize(PER_REQ_IOV_CAP);
    }
    
    std::vector<RxReqContext> batch_reqs;
    batch_reqs.reserve(BATCH_SIZE);

    while (true) {
        // Only fetch new requests if we have no pending requests from previous run
        // This avoids complex iov_pool management when shifting batch_reqs
        if (batch_reqs.empty()) {
            while (batch_reqs.size() < BATCH_SIZE && !virtqueue_is_empty(vq)) {
                struct iovec *iov = iov_pool[batch_reqs.size()].data();
            uint16_t idx;
            int n = process_descriptor_chain(vq, &idx, &iov, PER_REQ_IOV_CAP, NULL, 0, 0, false);
            if (n < 1) {
                if (iov != iov_pool[batch_reqs.size()].data()) free(iov);
                continue;
            }

            size_t header_len = virtio_net_get_nethdr_size(vdev);
            void *vnet_header = iov[0].iov_base;
            int packet_n = n;
            struct iovec *iov_packet = virtio_net_rm_iov_header(iov, &packet_n, header_len);

            if (!iov_packet) {
                log_warn("net rx packet too short");
                update_used_ring(vq, idx, 0); // Consumed but failed
                if (iov != iov_pool[batch_reqs.size()].data()) free(iov);
                continue;
            }
            
            batch_reqs.push_back({iov, iov_packet, packet_n, idx, vnet_header});
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

        // Submit batch
        std::vector<int> results = co_await BatchIoUringAwaitable<RxReqContext>(
            get_global_ring(), batch_reqs,
            [net](struct io_uring_sqe *sqe, RxReqContext req) {
                io_uring_prep_readv(sqe, net->tapfd, req.iov_packet, req.packet_n, 0);
            });

        // Process results
        size_t completed_cnt = 0;
        bool need_wait = false;
        for (size_t i = 0; i < batch_reqs.size(); ++i) {
            int res = results[i];
            size_t header_len = virtio_net_get_nethdr_size(vdev);
            
            // Handle EAGAIN: Stop processing and wait for data
            if (res == -EAGAIN) {
                need_wait = true;
                break;
            } 
            
            if (res < 0) {
                log_debug("net rx error: %d", res);
                res = 0;
            }

            // Fill header
            memset(batch_reqs[i].vnet_header, 0, header_len);
            if (vdev->regs.drv_feature & (1ULL << VIRTIO_F_VERSION_1)) {
                ((NetHdr *)batch_reqs[i].vnet_header)->num_buffers = 1;
            }

            update_used_ring(vq, batch_reqs[i].idx, res + header_len);
            
            // Check if iov was malloced (not in pool) and free it
            bool is_in_pool = false;
            for (const auto& pool_vec : iov_pool) {
                if (batch_reqs[i].iov == pool_vec.data()) {
                    is_in_pool = true;
                    break;
                }
            }
            if (!is_in_pool) {
                free(batch_reqs[i].iov);
            }

            completed_cnt++;
        }

        // Remove completed requests
        if (completed_cnt > 0) {
            batch_reqs.erase(batch_reqs.begin(), batch_reqs.begin() + completed_cnt);
        }

        co_await virtio_inject_irq(vq);

        // If we hit EAGAIN, wait for the file descriptor to be ready
        if (need_wait) {
            co_await PollAwaitable(net->tapfd, POLLIN);
        }
    }
}

/// @brief Initialize the virtio network device.
/// @param vdev Pointer to the VirtIODevice structure.
/// @param devname The name of the TAP device.
/// @return 0 on success, -1 on failure.
int virtio_net_init(VirtIODevice *vdev, char *devname) {
    NetDev *dev = vdev->dev;
    dev->tapfd = virtio_net_open_tap(devname);
    if (dev->tapfd < 0) {
        return -1;
    }
    set_nonblocking(dev->tapfd);

    vdev->virtio_close = virtio_net_close;

    // Start coroutines
    virtio_net_rxq_coroutine(vdev, &vdev->vqs[NET_QUEUE_RX]);
    virtio_net_txq_coroutine(vdev, &vdev->vqs[NET_QUEUE_TX]);

    return 0;
}

/// @brief Close the virtio network device.
/// @param vdev Pointer to the VirtIODevice structure.
void virtio_net_close(VirtIODevice *vdev) {
    NetDev *dev = vdev->dev;
    close(dev->tapfd);
    free(dev);
    free(vdev->vqs);
    free(vdev);
}
static inline struct iovec *virtio_net_rm_iov_header(struct iovec *iov, int *niov,
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

static size_t virtio_net_get_nethdr_size(VirtIODevice *vdev) {
    // Virtio 1.0 specifies the header as NetHdr. But the legacy version
    // specifies the headr as NetHdrLegacy
    if (vdev->regs.drv_feature & (1ULL << VIRTIO_F_VERSION_1)) {
        return sizeof(NetHdr);
    } else {
        return sizeof(NetHdrLegacy);
    }
}

/// @brief Notify handler for the RX queue.
/// @param vdev Pointer to the VirtIODevice structure.
/// @param vq Pointer to the VirtQueue structure.
/// @return 0 on success.
int virtio_net_rxq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    if (vq->waiter) {
        std::coroutine_handle<>::from_address(vq->waiter).resume();
    }
    return 0;
}

/// @brief Notify handler for the TX queue.
/// @param vdev Pointer to the VirtIODevice structure.
/// @param vq Pointer to the VirtQueue structure.
/// @return 0 on success.
int virtio_net_txq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    if (vq->waiter) {
        std::coroutine_handle<>::from_address(vq->waiter).resume();
    }
    return 0;
}
