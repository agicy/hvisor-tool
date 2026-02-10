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
#include <linux/if_tun.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <pthread.h>
#include <liburing.h>

// The max bytes of a packet in data link layer is 1518 bytes.
static uint8_t trashbuf[1600];

static void virtio_net_rx_completion_handler(void *param, int res);
static void virtio_net_tx_completion_handler(void *param, int res);

NetDev *init_net_dev(uint8_t mac[]) {
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
    dev->event = NULL;
    dev->pending_rx_req = NULL;
    return dev;
}

// open tap device
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

void virtio_net_rxq_process(VirtIODevice *vdev, VirtQueue *vq) {
    // Current virtio_net_event_handler logic but called from worker
    // Re-use virtio_net_event_handler code but fix args
    NetDev *net = vdev->dev;
    virtio_net_event_handler(net->tapfd, POLLIN, vdev);
}

void virtio_net_txq_process(VirtIODevice *vdev, VirtQueue *vq) {
    // TX Logic
    int quota = 64;
    while (!virtqueue_is_empty(vq) && quota > 0) {
        virtqueue_disable_notify(vq);
        while (!virtqueue_is_empty(vq) && quota > 0) {
            virtq_tx_handle_one_request(vdev, vq);
            quota--;
        }
        virtqueue_enable_notify(vq);
    }
    if (!virtqueue_is_empty(vq)) {
        NetDev *dev = (NetDev *)vdev->dev;
        uint64_t val = 1;
        write(dev->kick_fd, &val, sizeof(val));
    }
}

static void virtio_net_kick_handler(int fd, int epoll_type, void *param) {
    VirtIODevice *vdev = (VirtIODevice *)param;
    NetDev *dev = (NetDev *)vdev->dev;
    uint64_t val;
    read(fd, &val, sizeof(val));
    // Process TX
    virtio_net_txq_process(vdev, &vdev->vqs[NET_QUEUE_TX]);
    // Process RX (if buffers added)
    virtio_net_rxq_process(vdev, &vdev->vqs[NET_QUEUE_RX]);
}

int virtio_net_init(VirtIODevice *vdev, char *devname) {
    NetDev *dev = vdev->dev;
    dev->tapfd = open_tap(devname);
    if (dev->tapfd < 0) {
        return -1;
    }
    set_nonblocking(dev->tapfd);

    // Init kick fd
    dev->kick_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (dev->kick_fd < 0) {
        log_error("eventfd failed");
        return -1;
    }

    add_event(dev->kick_fd, POLLIN, virtio_net_kick_handler, vdev);
    dev->event = add_event(dev->tapfd, POLLIN, virtio_net_event_handler, vdev);

    vdev->virtio_close = virtio_net_close;
    return 0;
}

void virtio_net_close(VirtIODevice *vdev) {
    NetDev *dev = vdev->dev;
    close(dev->tapfd);
    close(dev->kick_fd);
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

size_t get_nethdr_size(VirtIODevice *vdev) {
    // Virtio 1.0 specifies the header as NetHdr. But the legacy version
    // specifies the headr as NetHdrLegacy
    if (vdev->regs.drv_feature & (1ULL << VIRTIO_F_VERSION_1)) {
        return sizeof(NetHdr);
    } else {
        return sizeof(NetHdrLegacy);
    }
}

void virtio_net_event_handler(int fd, int epoll_type, void *param);

static void virtio_net_rx_completion_handler(void *param, int res) {
    struct net_req *req = (struct net_req *)param;
    VirtIODevice *vdev = req->vdev;
    NetDev *net = vdev->dev;
    VirtQueue *vq = req->vq;

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
    void *vnet_header = req->iov[0].iov_base;
    memset(vnet_header, 0, header_len);
    if (vdev->regs.drv_feature & (1ULL << VIRTIO_F_VERSION_1)) {
        ((NetHdr *)vnet_header)->num_buffers = 1;
    }

    update_used_ring(vq, req->idx, res + header_len);
    virtio_inject_irq(vq);

    free(req->iov);
    free(req);
}

/// Called when tap device received packets
void virtio_net_event_handler(int fd, int epoll_type, void *param) {
    // log_debug("virtio_net_event_handler");
    VirtIODevice *vdev = param;
    NetDev *net = vdev->dev;
    VirtQueue *vq = &vdev->vqs[NET_QUEUE_RX];
    
    if (net->pending_rx_req) {
        struct net_req *req = net->pending_rx_req;
        net->pending_rx_req = NULL;
        
        struct io_uring *ring = get_global_ring();
        pthread_mutex_t *ring_mutex = get_global_ring_mutex();
        
        pthread_mutex_lock(ring_mutex);
        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
        io_uring_prep_readv(sqe, net->tapfd, req->iov_packet, req->iovcnt, 0);
        io_uring_sqe_set_data(sqe, &req->hevent);
        io_uring_submit(ring);
        pthread_mutex_unlock(ring_mutex);
        return;
    }

    if (!net->rx_ready || virtqueue_is_empty(vq)) {
        disable_event_poll(net->event);
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
    struct iovec *iov_packet = rm_iov_header(iov, &n, header_len);
    if (!iov_packet) {
        free(iov);
        free(req);
        return;
    }

    req->iov = iov;
    req->iov_packet = iov_packet;
    req->iovcnt = n;
    req->idx = idx;
    req->vdev = vdev;
    req->vq = vq;
    req->hevent.completion_handler = virtio_net_rx_completion_handler;
    req->hevent.param = req;
    req->hevent.free_on_completion = false;

    struct io_uring *ring = get_global_ring();
    pthread_mutex_t *ring_mutex = get_global_ring_mutex();

    pthread_mutex_lock(ring_mutex);
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_readv(sqe, net->tapfd, req->iov_packet, req->iovcnt, 0);
    io_uring_sqe_set_data(sqe, &req->hevent);
    io_uring_submit(ring);
    pthread_mutex_unlock(ring_mutex);
}

static void virtio_net_tx_completion_handler(void *param, int res) {
    struct net_req *req = (struct net_req *)param;
    VirtQueue *vq = req->vq;
    
    if (res < 0) {
        log_debug("net tx error: %d", res);
        res = 0; 
    }
    
    size_t header_len = get_nethdr_size(req->vdev);
    update_used_ring(vq, req->idx, res + header_len);
    virtio_inject_irq(vq);
    
    free(req->iov);
    free(req);
}

static void virtq_tx_handle_one_request(VirtIODevice *vdev, VirtQueue *vq) {
    struct iovec *iov = NULL;
    int i, n;
    int all_len; // all_len include the header length.
    uint16_t idx;
    static char pad[64] = {0};
    NetDev *net = vdev->dev;
    size_t header_len = get_nethdr_size(vdev);
    if (net->tapfd == -1) {
        log_error("tap device is invalid");
        return;
    }

    n = process_descriptor_chain(vq, &idx, &iov, NULL, 1, false);
    if (n < 1) {
        return;
    }
    
    struct net_req *req = calloc(1, sizeof(struct net_req));
    req->iov = iov;
    req->idx = idx;
    req->vdev = vdev;
    req->vq = vq;

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
    req->iovcnt = n;
    
    req->hevent.completion_handler = virtio_net_tx_completion_handler;
    req->hevent.param = req;
    req->hevent.free_on_completion = false;
    
    struct io_uring *ring = get_global_ring();
    pthread_mutex_t *ring_mutex = get_global_ring_mutex();
    
    pthread_mutex_lock(ring_mutex);
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_writev(sqe, net->tapfd, req->iov_packet, req->iovcnt, 0);
    io_uring_sqe_set_data(sqe, &req->hevent);
    io_uring_submit(ring);
    pthread_mutex_unlock(ring_mutex);
}

int virtio_net_rxq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    NetDev *dev = (NetDev *)vdev->dev;
    uint64_t val = 1;
    enable_event_poll(dev->event);
    write(dev->kick_fd, &val, sizeof(val));
    return 0;
}

int virtio_net_txq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    log_debug("virtio_net_txq_notify_handler");
    NetDev *dev = (NetDev *)vdev->dev;
    uint64_t val = 1;
    write(dev->kick_fd, &val, sizeof(val));
    return 0;
}

