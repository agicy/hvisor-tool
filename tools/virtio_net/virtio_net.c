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

static void virtio_net_rx_completion_handler(void *param, int res);
static void virtio_net_tx_completion_handler(void *param, int res);
static int virtio_net_handle_one_tx_req(VirtIODevice *vdev, VirtQueue *vq);

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
static int open_tap(char *devname) {
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

/// @brief Process the TX queue for the network device.
/// @param vdev Pointer to the VirtIODevice structure.
/// @param vq Pointer to the VirtQueue structure.
static void virtio_net_txq_process(VirtIODevice *vdev, VirtQueue *vq) {
    // TX Logic
    int quota = 64;
    int submitted = 0;
    while (!virtqueue_is_empty(vq) && quota > 0) {
        virtqueue_disable_notify(vq);
        while (!virtqueue_is_empty(vq) && quota > 0) {
            if (virtio_net_handle_one_tx_req(vdev, vq) == 0) {
                submitted++;
            }
            quota--;
        }
        virtqueue_enable_notify(vq);
    }
    if (submitted > 0) {
        // io_uring_submit(get_global_ring());
    }
}

/// @brief Initialize the virtio network device.
/// @param vdev Pointer to the VirtIODevice structure.
/// @param devname The name of the TAP device.
/// @return 0 on success, -1 on failure.
int virtio_net_init(VirtIODevice *vdev, char *devname) {
    NetDev *dev = vdev->dev;
    dev->tapfd = open_tap(devname);
    if (dev->tapfd < 0) {
        return -1;
    }
    set_nonblocking(dev->tapfd);

    dev->rx_poll_event = (struct poll_event){
        .base = {.type = EVENT_TYPE_POLL},
        .fd = dev->tapfd,
        .epoll_type = POLLIN,
        .handler = virtio_net_tap_rx_handler,
        .param = vdev,
        .active = false,
    };
    enable_event_poll(&dev->rx_poll_event);

    vdev->virtio_close = virtio_net_close;
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
static inline struct iovec *rm_iov_header(struct iovec *iov, int *niov,
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

static size_t get_nethdr_size(VirtIODevice *vdev) {
    // Virtio 1.0 specifies the header as NetHdr. But the legacy version
    // specifies the headr as NetHdrLegacy
    if (vdev->regs.drv_feature & (1ULL << VIRTIO_F_VERSION_1)) {
        return sizeof(NetHdr);
    } else {
        return sizeof(NetHdrLegacy);
    }
}

/// @brief Handler for RX completion events.
/// @param param Pointer to the network request structure.
/// @param res Result of the I/O operation.
static void virtio_net_rx_completion_handler(void *param, int res) {
    struct net_req *req = (struct net_req *)param;
    VirtIODevice *vdev = req->req.vdev;
    NetDev *net = vdev->dev;
    VirtQueue *vq = req->req.vq;

    if (res == -EAGAIN) {
        net->pending_rx_req = req;
        return;
    }

    if (res < 0) {
        if (res != -ECANCELED)
            log_debug("net rx error: %d", res);
        res = 0;
    }

    size_t header_len = get_nethdr_size(vdev);
    void *vnet_header = req->req.iov[0].iov_base;
    memset(vnet_header, 0, header_len);
    if (vdev->regs.drv_feature & (1ULL << VIRTIO_F_VERSION_1)) {
        ((NetHdr *)vnet_header)->num_buffers = 1;
    }

    update_used_ring(vq, req->req.idx, res + header_len);
    virtio_inject_irq(vq);

    free(req->req.iov);
    free(req);
}

/// @brief Handler for network events (POLLIN).
/// @param fd The file descriptor.
/// @param epoll_type The poll event type.
/// @param param User parameter (VirtIODevice pointer).
static void virtio_net_tap_rx_handler(int fd, int epoll_type, void *param) {
    VirtIODevice *vdev = (VirtIODevice *)param;
    NetDev *net = vdev->dev;
    VirtQueue *vq = &vdev->vqs[NET_QUEUE_RX];

    if (net->pending_rx_req) {
        struct net_req *req = net->pending_rx_req;
        net->pending_rx_req = NULL;

        struct io_uring *ring = get_global_ring();
        struct io_uring_sqe *sqe = get_sqe_safe(ring);

        io_uring_prep_readv(sqe, net->tapfd, req->iov_packet,
                        req->packet_iovcnt, 0);
    io_uring_sqe_set_data(sqe, &req->req.io_completion_event);
    // io_uring_submit(ring);
    return;
}

    if (!net->rx_ready || virtqueue_is_empty(vq)) {
        disable_event_poll(&net->rx_poll_event);
        virtio_inject_irq(vq);
        return;
    }

    struct net_req *req = calloc(1, sizeof(struct net_req));
    uint16_t idx;
    struct iovec *iov = NULL;
    int n = process_descriptor_chain(vq, &idx, &iov, NULL, 0, false);
    if (n < 1) {
        free(req);
        return;
    }

    size_t header_len = get_nethdr_size(vdev);
    int packet_n = n;
    struct iovec *iov_packet = rm_iov_header(iov, &packet_n, header_len);
    if (!iov_packet) {
        free(iov);
        free(req);
        return;
    }

    req->req.iov = iov;
    req->iov_packet = iov_packet;
    req->packet_iovcnt = packet_n;
    req->req.iovcnt = n;
    req->req.idx = idx;
    req->req.vdev = vdev;
    req->req.vq = vq;
    req->req.io_completion_event.base.type = EVENT_TYPE_IO_COMPLETION;
    req->req.io_completion_event.handler = virtio_net_rx_completion_handler;
    req->req.io_completion_event.param = req;
    req->req.io_completion_event.free_on_completion = false;

    struct io_uring *ring = get_global_ring();

    struct io_uring_sqe *sqe = get_sqe_safe(ring);
    io_uring_prep_readv(sqe, net->tapfd, req->iov_packet, req->packet_iovcnt,
                        0);
    io_uring_sqe_set_data(sqe, &req->req.io_completion_event);
    // io_uring_submit(ring);
}

/// @brief Handler for TX completion events.
/// @param param Pointer to the network request structure.
/// @param res Result of the I/O operation.
static void virtio_net_tx_completion_handler(void *param, int res) {
    struct net_req *req = (struct net_req *)param;
    VirtQueue *vq = req->req.vq;

    if (res < 0) {
        log_debug("net tx error: %d", res);
        res = 0;
    }

    size_t header_len = get_nethdr_size(req->req.vdev);
    update_used_ring(vq, req->req.idx, res + header_len);
    virtio_inject_irq(vq);

    free(req->req.iov);
    free(req);
}

static int virtio_net_handle_one_tx_req(VirtIODevice *vdev, VirtQueue *vq) {
    struct iovec *iov = NULL;
    int i, n;
    int all_len; // all_len include the header length.
    uint16_t idx;
    static char pad[64] = {0};
    NetDev *net = vdev->dev;
    size_t header_len = get_nethdr_size(vdev);
    if (net->tapfd == -1) {
        log_error("tap device is invalid");
        return -1;
    }

    n = process_descriptor_chain(vq, &idx, &iov, NULL, 1, false);
    if (n < 1) {
        return -1;
    }

    struct net_req *req = calloc(1, sizeof(struct net_req));
    req->req.iov = iov;
    req->req.idx = idx;
    req->req.vdev = vdev;
    req->req.vq = vq;

    for (i = 0, all_len = 0; i < n; i++)
        all_len += iov[i].iov_len;

    int packet_len = all_len - header_len;
    iov[0].iov_base += header_len;
    iov[0].iov_len -= header_len;
    log_debug("packet send: %d bytes", packet_len);

    // The mininum packet for data link layer is 64 bytes.
    if (packet_len < 64) {
        iov[n].iov_base = pad;
        iov[n].iov_len = 64 - packet_len;
        n++;
    }

    req->iov_packet = iov;
    req->packet_iovcnt = n;
    req->req.iovcnt = n;

    req->req.io_completion_event.base.type = EVENT_TYPE_IO_COMPLETION;
    req->req.io_completion_event.handler = virtio_net_tx_completion_handler;
    req->req.io_completion_event.param = req;
    req->req.io_completion_event.free_on_completion = false;

    struct io_uring *ring = get_global_ring();

    struct io_uring_sqe *sqe = get_sqe_safe(ring);
    io_uring_prep_writev(sqe, net->tapfd, req->iov_packet, req->packet_iovcnt,
                         0);
    io_uring_sqe_set_data(sqe, &req->req.io_completion_event);
    // Batching: do not submit here
    return 0;
}

/// @brief Notify handler for the RX queue.
/// @param vdev Pointer to the VirtIODevice structure.
/// @param vq Pointer to the VirtQueue structure.
/// @return 0 on success.
int virtio_net_rxq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    NetDev *dev = (NetDev *)vdev->dev;
    // Guest added new RX buffers, re-enable tap polling if it was disabled due
    // to backpressure
    enable_event_poll(&dev->rx_poll_event);
    return 0;
}

/// @brief Notify handler for the TX queue.
/// @param vdev Pointer to the VirtIODevice structure.
/// @param vq Pointer to the VirtQueue structure.
/// @return 0 on success.
int virtio_net_txq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    virtio_net_txq_process(vdev, vq);
    return 0;
}
