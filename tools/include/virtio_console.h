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
typedef struct virtio_console_dev {
    ConsoleConfig config;
    int master_fd;
    int rx_ready;
    struct hvisor_event *event;
    struct termios old_termios;
    struct console_req *pending_rx_req;
} ConsoleDev;

struct console_req {
    struct iovec *iov;
    int iovcnt;
    uint16_t idx;
    struct hvisor_event hevent;
    VirtIODevice *vdev;
    VirtQueue *vq;
};

ConsoleDev *init_console_dev();
int virtio_console_init(VirtIODevice *vdev);
int virtio_console_rxq_notify_handler(VirtIODevice *vdev, VirtQueue *vq);
int virtio_console_txq_notify_handler(VirtIODevice *vdev, VirtQueue *vq);
void virtio_console_close(VirtIODevice *vdev);
#endif