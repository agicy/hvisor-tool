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
#ifndef _HVISOR_VIRTIO_CONSOLE_H
#define _HVISOR_VIRTIO_CONSOLE_H
#include "virtio.h"
#include <linux/virtio_console.h>

#define CONSOLE_SUPPORTED_FEATURES                                             \
    ((1ULL << VIRTIO_F_VERSION_1) | (1ULL << VIRTIO_CONSOLE_F_SIZE))
#define CONSOLE_MAX_QUEUES 2
#define VIRTQUEUE_CONSOLE_MAX_SIZE 64
#define CONSOLE_QUEUE_RX 0
#define CONSOLE_QUEUE_TX 1

/*
 * Host-side staging ring for console input (pty -> guest). Bytes are read
 * from the pty as they arrive and handed to the guest when it posts receive
 * buffers. When the ring is full the RX worker stops reading the pty, which
 * pushes back on the guest's console writer instead of dropping input.
 * Must be a power of two.
 */
#define CONSOLE_RX_RING_SIZE (64 * 1024)

typedef struct virtio_console_config ConsoleConfig;
typedef struct virtio_console_dev {
    ConsoleConfig config;
    int master_fd;
    int slave_keepalive_fd;

    /* RX queue worker (pty -> guest). It owns the RX virtqueue. */
    int rx_kick_efd;   /* eventfd: guest added receive buffers */
    pthread_t rx_tid;
    bool rx_thread_started;
    bool rx_paused;    /* parked in the reset wait, queues untouched */
    uint8_t *rx_buf;   /* staging ring, [rx_tail, rx_head) is pending data */
    size_t rx_head;
    size_t rx_tail;
    struct iovec rx_iov[VIRTQUEUE_CONSOLE_MAX_SIZE];

    /* TX queue worker (guest -> pty). It owns the TX virtqueue. */
    int tx_kick_efd;   /* eventfd: guest queued output descriptors */
    pthread_t tx_tid;
    bool tx_thread_started;
    bool tx_paused;    /* parked in the reset wait, queues untouched */
    struct iovec tx_iov[VIRTQUEUE_CONSOLE_MAX_SIZE];
    unsigned int tx_iov_count;
    unsigned int tx_iov_pos;
    uint16_t tx_desc_idx;
    size_t tx_written;

    /* Lifecycle state, shared by the workers and the MMIO thread. */
    pthread_mutex_t mtx;
    pthread_cond_t cond;
    bool mtx_initialized;
    bool cond_initialized;
    bool close;
    bool reset;        /* device reset in progress */
} ConsoleDev;

extern const struct virtio_device_ops virtio_console_ops;
extern const struct virtio_config_ops virtio_console_config_ops;

#endif
