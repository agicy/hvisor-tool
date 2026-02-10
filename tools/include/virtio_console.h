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

#define CONSOLE_SUPPORTED_FEATURES                                             \
    ((1ULL << VIRTIO_F_VERSION_1) | (1ULL << VIRTIO_CONSOLE_F_SIZE))
#define CONSOLE_MAX_QUEUES 2
#define VIRTQUEUE_CONSOLE_MAX_SIZE 64
#define CONSOLE_QUEUE_RX 0
#define CONSOLE_QUEUE_TX 1

#define CONSOLE_DEFAULT_COLS 80
#define CONSOLE_DEFAULT_ROWS 25

typedef struct virtio_console_config ConsoleConfig;

/**
 * @brief VirtIO Console Request
 *
 * This structure represents a console I/O request. Since console I/O is
 * stream-based and simple, it currently only wraps the base VirtioIOReq.
 */
struct console_req {
    VirtioIOReq req; /**< Base I/O request context. */
};

/**
 * @brief VirtIO Console Device Context
 *
 * This structure holds the runtime state of a VirtIO console device backend.
 * It manages the PTY master file descriptor and handles flow control flags.
 */
typedef struct {
    ConsoleConfig config; /**< VirtIO Console Configuration. */
    int master_fd; /**< File descriptor for the PTY Master side (Host side). */
    int rx_ready;  /**< Flag indicating if the Guest is ready to receive data
                      (has buffers in RX Queue). */
    struct poll_event
        rx_poll_event; /**< Persistent event handler for PTY input (POLLIN). */
    struct console_req *pending_rx_req; /**< Pending RX request if previous read
                                           returned EAGAIN. */
} ConsoleDev;

/** @brief Initialize the console device structure.
 * @details Initializes the console device context.
 * @return Pointer to the initialized ConsoleDev structure.
 */
ConsoleDev *virtio_console_alloc(void);

/** @brief Initialize the virtio console device backend.
 * @details Initializes the console device backend with the given VirtIODevice
 * structure.
 * @param vdev Pointer to the VirtIODevice structure.
 * @return 0 on success, -1 on failure.
 */
int virtio_console_init(VirtIODevice *vdev);

/** @brief Notify handler for the RX queue.
 * @details Called when the Guest signals readiness for more RX packets.
 * @param vdev Pointer to the VirtIODevice structure.
 * @param vq Pointer to the VirtQueue structure.
 * @return 0 on success.
 */
int virtio_console_rxq_notify_handler(VirtIODevice *vdev, VirtQueue *vq);

/** @brief Notify handler for the TX queue.
 * @details Called when the Guest signals readiness for more TX packets.
 * @param vdev Pointer to the VirtIODevice structure.
 * @param vq Pointer to the VirtQueue structure.
 * @return 0 on success.
 */
int virtio_console_txq_notify_handler(VirtIODevice *vdev, VirtQueue *vq);

/** @brief Close the virtio console device and release resources.
 * @details Closes the PTY master interface and frees allocated resources.
 * @param vdev Pointer to the VirtIODevice structure.
 */
void virtio_console_close(VirtIODevice *vdev);

#endif
