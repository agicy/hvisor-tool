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

#define VIRTQUEUE_NET_MAX_SIZE 256
// VIRTIO_RING_F_INDIRECT_DESC and VIRTIO_RING_F_EVENT_IDX are supported, for
// some reason we cancel them.
#define NET_SUPPORTED_FEATURES                                                 \
    ((1ULL << VIRTIO_F_VERSION_1) | (1ULL << VIRTIO_NET_F_MAC) |               \
     (1ULL << VIRTIO_NET_F_STATUS))

typedef struct virtio_net_config NetConfig;
typedef struct virtio_net_hdr NetHdr;
typedef struct virtio_net_hdr_mrg_rxbuf NetHdrMrgRxbuf;
// Legacy version of net hdr
typedef struct virtio_net_hdr_legacy {
    uint8_t flags;
    uint8_t gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
} NetHdrLegacy;

/**
 * @brief VirtIO Network Request
 *
 * This structure represents a network packet transmission or reception request.
 * Since network packets may have VirtIO headers that need to be stripped or
 * prepended, this structure maintains pointers to both the raw Guest buffers
 * and the actual packet data payload.
 */
struct net_req {
    VirtioIOReq req; /**< Base I/O request context (pointing to full Guest
                        buffer chain). */
    struct iovec
        *iov_packet;   /**< Pointer to the iovec array representing the actual
                          packet data (excluding VirtIO Net Header). This may
                          point   inside req.iov or be a modified copy. */
    int packet_iovcnt; /**< Number of segments in iov_packet. */
};

/**
 * @brief VirtIO Network Device Context
 *
 * This structure holds the runtime state of a VirtIO network device backend.
 * It manages the TAP interface file descriptor and RX flow control.
 */
typedef struct {
    NetConfig config; /**< VirtIO Net Configuration (MAC address, status). */
    int tapfd;        /**< File descriptor for the TAP interface. */
    int rx_ready; /**< Flag indicating if the Guest has provided RX buffers. */
    struct poll_event
        rx_poll_event; /**< Persistent event handler for TAP input (POLLIN). */
    struct net_req *pending_rx_req; /**< Pending RX request if previous read
                                       returned EAGAIN. */
} NetDev;

/** @brief Initialize a network device structure.
 * @details Initializes the network device context with the given MAC address.
 * @param mac The MAC address for the device.
 * @return Pointer to the initialized NetDev structure.
 */
NetDev *virtio_net_alloc(uint8_t mac[]);

/** @brief Notify handler for the RX queue.
 * @details Called when the Guest signals readiness for more RX packets.
 * @param vdev Pointer to the VirtIODevice structure.
 * @param vq Pointer to the VirtQueue structure.
 * @return 0 on success.
 */
int virtio_net_rxq_notify_handler(VirtIODevice *vdev, VirtQueue *vq);

/** @brief Notify handler for the TX queue.
 * @details Called when the Guest signals readiness for more TX packets.
 * @param vdev Pointer to the VirtIODevice structure.
 * @param vq Pointer to the VirtQueue structure.
 * @return 0 on success.
 */
int virtio_net_txq_notify_handler(VirtIODevice *vdev, VirtQueue *vq);

/** @brief Initialize the virtio network device backend.
 * @details Initializes the network device backend with the given TAP device
 * name.
 * @param vdev Pointer to the VirtIODevice structure.
 * @param devname The name of the TAP device (e.g., "tap0").
 * @return 0 on success, -1 on failure.
 */
int virtio_net_init(VirtIODevice *vdev, char *devname);

/** @brief Close the virtio network device and release resources.
 * @details Closes the TAP interface and frees allocated resources.
 * @param vdev Pointer to the VirtIODevice structure.
 */
void virtio_net_close(VirtIODevice *vdev);

#endif //_HVISOR_VIRTIO_NET_H
