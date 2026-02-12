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

#include "event_monitor.h"
#include "hvisor.h"
#include "log.h"
#include "virtio.h"

#include <fcntl.h>
#include <liburing.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <unistd.h>

/// @brief File descriptor for the virtio kernel module.
int ko_fd;

/// @brief Event file descriptor for the virtio interrupt event.
int virtio_irq_fd = -1;

/// @brief Pointer to the virtio bridge structure.
volatile struct virtio_bridge *virtio_bridge;

/// @brief Array of virtio devices.
VirtIODevice *vdevs[MAX_DEVS];

/// @brief Number of virtio devices.
int vdevs_num;

/// @brief Memory layout for virtio devices.
unsigned long long zone_mem[MAX_ZONES][MAX_RAMS][4];

/// @brief Value for virtio interrupt event.
static uint64_t virtio_irq_val;

/// @brief Event structure for virtio interrupt completion.
static struct io_completion_event virtio_irq_event;

/// @brief Set a file descriptor to non-blocking mode.
/// @param fd The file descriptor.
/// @return 0 on success, -1 on error.
int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        log_error("fcntl(F_GETFL) failed");
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        log_error("fcntl(F_SETFL) failed");
        return -1;
    }
    return 0;
}

/// @brief Check if a circular queue is full.
/// @param front The front index.
/// @param rear The rear index.
/// @param size The size of the queue (must be power of 2).
/// @return 1 if full, 0 otherwise.
inline int is_queue_full(unsigned int front, unsigned int rear,
                         unsigned int size) {
    if (((rear + 1) & (size - 1)) == front) {
        return 1;
    } else {
        return 0;
    }
}

/// @brief Check if a circular queue is empty.
/// @param front The front index.
/// @param rear The rear index.
/// @return 1 if empty, 0 otherwise.
inline int is_queue_empty(unsigned int front, unsigned int rear) {
    return rear == front;
}

/// @brief Memory barrier for write operations.
inline void write_barrier(void) {
#ifdef ARM64
    asm volatile("dmb ishst" ::: "memory");
#endif
#ifdef RISCV64
    asm volatile("fence w,w" ::: "memory");
#endif
#ifdef LOONGARCH64
    asm volatile("dbar 0" ::: "memory");
#endif
#ifdef X86_64
    asm volatile("" ::: "memory");
#endif
}

/// @brief Memory barrier for read operations.
inline void read_barrier(void) {
#ifdef ARM64
    asm volatile("dmb ishld" ::: "memory");
#endif
#ifdef RISCV64
    asm volatile("fence r,r" ::: "memory");
#endif
#ifdef LOONGARCH64
    asm volatile("dbar 0" ::: "memory");
#endif
#ifdef X86_64
    asm volatile("" ::: "memory");
#endif
}

/// @brief Memory barrier for both read and write operations.
inline void rw_barrier(void) {
#ifdef ARM64
    asm volatile("dmb ish" ::: "memory");
#endif
#ifdef RISCV64
    asm volatile("fence rw,rw" ::: "memory");
#endif
#ifdef LOONGARCH64
    asm volatile("dbar 0" ::: "memory");
#endif
#ifdef X86_64
    asm volatile("" ::: "memory");
#endif
}

/// @brief Initialize virtio queues for a device.
/// @param vdev Pointer to the VirtIODevice structure.
/// @param type The type of the virtio device.
void init_virtio_queue(VirtIODevice *vdev, VirtioDeviceType type) {
    VirtQueue *vqs = NULL;

    log_info("Initializing virtio queue for zone: %d, device type: %s",
             vdev->zone_id, virtio_device_type_to_string(type));

    switch (type) {
    case VirtioTBlock:
        vdev->vqs_len = 1;
        vqs = malloc(sizeof(VirtQueue));
        virtqueue_reset(vqs, 0);
        vqs->queue_num_max = VIRTQUEUE_BLK_MAX_SIZE;
        vqs->notify_handler = virtio_blk_notify_handler;
        vqs->dev = vdev;
        vdev->vqs = vqs;
        break;

    case VirtioTNet:
        vdev->vqs_len = NET_MAX_QUEUES;
        vqs = malloc(sizeof(VirtQueue) * NET_MAX_QUEUES);
        for (int i = 0; i < NET_MAX_QUEUES; ++i) {
            virtqueue_reset(vqs, i);
            vqs[i].queue_num_max = VIRTQUEUE_NET_MAX_SIZE;
            vqs[i].dev = vdev;
        }
        vqs[NET_QUEUE_RX].notify_handler = virtio_net_rxq_notify_handler;
        vqs[NET_QUEUE_TX].notify_handler = virtio_net_txq_notify_handler;
        vdev->vqs = vqs;
        break;

    case VirtioTConsole:
        vdev->vqs_len = CONSOLE_MAX_QUEUES;
        vqs = malloc(sizeof(VirtQueue) * CONSOLE_MAX_QUEUES);
        for (int i = 0; i < CONSOLE_MAX_QUEUES; ++i) {
            virtqueue_reset(vqs, i);
            vqs[i].queue_num_max = VIRTQUEUE_CONSOLE_MAX_SIZE;
            vqs[i].dev = vdev;
        }
        vqs[CONSOLE_QUEUE_RX].notify_handler =
            virtio_console_rxq_notify_handler;
        vqs[CONSOLE_QUEUE_TX].notify_handler =
            virtio_console_txq_notify_handler;
        vdev->vqs = vqs;
        break;

    case VirtioTGPU:
#ifdef ENABLE_VIRTIO_GPU
        vdev->vqs_len = GPU_MAX_QUEUES;
        vqs = malloc(sizeof(VirtQueue) * GPU_MAX_QUEUES);
        for (int i = 0; i < GPU_MAX_QUEUES; ++i) {
            virtqueue_reset(vqs, i);
            vqs[i].queue_num_max = VIRTQUEUE_GPU_MAX_SIZE;
            vqs[i].dev = vdev;
        }
        vqs[GPU_CONTROL_QUEUE].notify_handler = virtio_gpu_ctrl_notify_handler;
        vqs[GPU_CURSOR_QUEUE].notify_handler = virtio_gpu_cursor_notify_handler;
        vdev->vqs = vqs;
#else
        log_error("virtio gpu is not enabled");
#endif
        break;

    default:
        break;
    }
}

/// @brief Initialize MMIO registers for a virtio device.
/// @param regs Pointer to the VirtMmioRegs structure.
/// @param type The type of the virtio device.
void init_mmio_regs(VirtMmioRegs *regs, VirtioDeviceType type) {
    log_info("initializing mmio registers for %s",
             virtio_device_type_to_string(type));
    regs->device_id = type;
    regs->queue_sel = 0;
}

/// @brief Reset a virtio device.
/// @param vdev Pointer to the VirtIODevice structure.
void virtio_dev_reset(VirtIODevice *vdev) {
    // When driver read first 4 encoded messages, it will reset dev.
    log_trace("virtio dev reset");
    vdev->regs.status = 0;
    vdev->regs.interrupt_status = 0;
    vdev->regs.interrupt_count = 0;
    int idx = vdev->regs.queue_sel;
    vdev->vqs[idx].ready = 0;
    for (uint32_t i = 0; i < vdev->vqs_len; i++) {
        virtqueue_reset(&vdev->vqs[i], i);
    }
    vdev->activated = false;
}

/// @brief Reset a virtqueue.
/// @param vq Pointer to the VirtQueue structure.
/// @param idx The index of the queue.
void virtqueue_reset(VirtQueue *vq, int idx) {
    // Reserve these fields
    void *addr = vq->notify_handler;
    VirtIODevice *dev = vq->dev;
    uint32_t queue_num_max = vq->queue_num_max;

    // Clear others
    memset(vq, 0, sizeof(VirtQueue));
    vq->vq_idx = idx;
    vq->notify_handler = addr;
    vq->dev = dev;
    vq->queue_num_max = queue_num_max;
}

/// @brief Check if a virtqueue has new available descriptors.
/// @param vq Pointer to the VirtQueue structure.
/// @return true if the queue is empty (no new descriptors), false otherwise.
bool virtqueue_is_empty(VirtQueue *vq) {
    if (vq->avail_ring == NULL) {
        log_error("virtqueue's avail ring is invalid");
        return true;
    }
    // read_barrier();
    log_debug("vq->last_avail_idx is %d, vq->avail_ring->idx is %d",
              vq->last_avail_idx, vq->avail_ring->idx);
    if (vq->last_avail_idx == vq->avail_ring->idx)
        return true;
    else
        return false;
}

/// @brief Check if a descriptor is writable.
/// @param desc_table The descriptor table.
/// @param idx The index of the descriptor.
/// @return true if writable, false otherwise.
bool desc_is_writable(volatile VirtqDesc *desc_table, uint16_t idx) {
    if (desc_table[idx].flags & VRING_DESC_F_WRITE)
        return true;
    return false;
}

/// @brief Get the host virtual address from a guest physical address (IPA).
/// @param zonex_ipa The guest physical address.
/// @param zone_id The zone ID.
/// @return The host virtual address.
void *get_virt_addr(void *zonex_ipa, int zone_id) {
    int ram_idx = get_zone_ram_index(zonex_ipa, zone_id);
    return (void *)(zone_mem[zone_id][ram_idx][VIRT_ADDR] -
                    zone_mem[zone_id][ram_idx][ZONEX_IPA] +
                    (uintptr_t)zonex_ipa);
}

/// @brief Disable notification for a virtqueue.
/// @param vq Pointer to the VirtQueue structure.
void virtqueue_disable_notify(VirtQueue *vq) {
    if (vq->event_idx_enabled) {
        VQ_AVAIL_EVENT(vq) = vq->last_avail_idx - 1;
    } else {
        vq->used_ring->flags |= (uint16_t)VRING_USED_F_NO_NOTIFY;
    }
    write_barrier();
}

/// @brief Enable notification for a virtqueue.
/// @param vq Pointer to the VirtQueue structure.
void virtqueue_enable_notify(VirtQueue *vq) {
    if (vq->event_idx_enabled) {
        VQ_AVAIL_EVENT(vq) = vq->avail_ring->idx;
    } else {
        vq->used_ring->flags &= !(uint16_t)VRING_USED_F_NO_NOTIFY;
    }
    write_barrier();
}

/// @brief Set the descriptor table address for a virtqueue.
/// @param vq Pointer to the VirtQueue structure.
void virtqueue_set_desc_table(VirtQueue *vq) {
    int zone_id = vq->dev->zone_id;
    log_debug("zone %d set dev %s desc table ipa at %#x", zone_id,
              virtio_device_type_to_string(vq->dev->type), vq->desc_table_addr);
    vq->desc_table = (VirtqDesc *)get_virt_addr(
        (void *)(uintptr_t)vq->desc_table_addr, zone_id);
}

/// @brief Set the available ring address for a virtqueue.
/// @param vq Pointer to the VirtQueue structure.
void virtqueue_set_avail(VirtQueue *vq) {
    int zone_id = vq->dev->zone_id;
    log_debug("zone %d set dev %s avail ring ipa at %#x", zone_id,
              virtio_device_type_to_string(vq->dev->type), vq->avail_addr);
    vq->avail_ring =
        (VirtqAvail *)get_virt_addr((void *)(uintptr_t)vq->avail_addr, zone_id);
}

/// @brief Set the used ring address for a virtqueue.
/// @param vq Pointer to the VirtQueue structure.
void virtqueue_set_used(VirtQueue *vq) {
    int zone_id = vq->dev->zone_id;
    log_debug("zone %d set dev %s used ring ipa at %#x", zone_id,
              virtio_device_type_to_string(vq->dev->type), vq->used_addr);
    vq->used_ring =
        (VirtqUsed *)get_virt_addr((void *)(uintptr_t)vq->used_addr, zone_id);
}

/// @brief Record one descriptor to iov.
/// @param i The index in the iov array.
/// @param vd Pointer to the VirtqDesc structure.
/// @param iov The iovec array.
/// @param flags Array to store descriptor flags.
/// @param zone_id The zone ID.
/// @param copy_flags Whether to copy flags.
/// @return 0 on success.
int descriptor2iov(int i, volatile VirtqDesc *vd, struct iovec *iov,
                   uint16_t *flags, int zone_id, bool copy_flags) {
    void *host_addr;

    host_addr = get_virt_addr((void *)vd->addr, zone_id);
    iov[i].iov_base = host_addr;
    iov[i].iov_len = vd->len;
    // log_debug("vd->addr ipa is %x, iov_base is %x, iov_len is %d", vd->addr,
    // host_addr, vd->len);
    if (copy_flags)
        flags[i] = vd->flags;

    return 0;
}

/// @brief Record one descriptor list to iov.
/// @param vq Pointer to the VirtQueue structure.
/// @param desc_idx Pointer to store the first descriptor's index.
/// @param iov Pointer to the iovec array pointer. If *iov is not NULL, it points to a pre-allocated buffer.
/// @param iov_cap Capacity of the pre-allocated iov buffer.
/// @param flags Pointer to the flags array pointer. If *flags is not NULL, it points to a pre-allocated buffer.
/// @param flags_cap Capacity of the pre-allocated flags buffer.
/// @param append_len The number of iovs to append.
/// @param copy_flags Whether to copy flags.
/// @return The length of iovs.
int process_descriptor_chain(VirtQueue *vq, uint16_t *desc_idx,
                             struct iovec **iov, int iov_cap,
                             uint16_t **flags, int flags_cap,
                             int append_len, bool copy_flags) {
    uint16_t next, last_avail_idx;
    volatile VirtqDesc *vdesc, *ind_table, *ind_desc;
    int chain_len = 0, i, table_len;

    // idx is the last available index processed during the last kick
    last_avail_idx = vq->last_avail_idx;

    // No new requests
    if (last_avail_idx == vq->avail_ring->idx)
        return 0;

    // Update to the index to be processed during this kick
    vq->last_avail_idx++;

    // Get the index of the first available descriptor
    *desc_idx = next = vq->avail_ring->ring[last_avail_idx & (vq->num - 1)];
    // Record the length of the descriptor chain to chain_len
    vdesc = &vq->desc_table[next]; // Initialize vdesc for the loop
    for (i = 0; i < (int)vq->num; i++, next = vdesc->next) {
        // Get a descriptor
        vdesc = &vq->desc_table[next];
        // TODO: vdesc->len may not be chain_len, virtio specification doesn't
        // say it.

        // Check if this descriptor supports the VRING_DESC_F_INDIRECT feature
        // If supported, it means that the descriptor points to a set of
        // descriptors, i.e., one descriptor can describe multiple scattered
        // buffers
        if (vdesc->flags & VRING_DESC_F_INDIRECT) {
            chain_len +=
                vdesc->len / 16; // This descriptor points to 16 descriptors
            i--;
        }
        // Exit if there is no next descriptor
        if ((vdesc->flags & VRING_DESC_F_NEXT) == 0)
            break;
    }

    // Update chain length and reset next to the first descriptor
    chain_len += i + 1, next = *desc_idx;

    // Allocate a buffer for each descriptor, using iov to manage them uniformly
    int total_len = chain_len + append_len;
    
    if (*iov == NULL || iov_cap < total_len) {
        if (*iov != NULL) {
             // log_warn("preallocated iov buffer too small: %d < %d", iov_cap, total_len);
        }
        *iov = (struct iovec *)malloc(sizeof(struct iovec) * total_len);
    }
    
    if (copy_flags) {
        if (flags == NULL) {
            // Should not happen if copy_flags is true
        } else if (*flags == NULL || flags_cap < total_len) {
            if (*flags != NULL) {
                 // log_warn("preallocated flags buffer too small: %d < %d", flags_cap, total_len);
            }
            *flags = (uint16_t *)malloc(sizeof(uint16_t) * total_len);
        }
    }

    // Traverse the descriptor chain and copy the buffer pointed to by each
    // descriptor to iov
    for (i = 0; i < chain_len; i++, next = vdesc->next) {
        vdesc = &vq->desc_table[next];
        // If the descriptor supports the VRING_DESC_F_INDIRECT feature
        if (vdesc->flags & VRING_DESC_F_INDIRECT) {
            // Get the address of the indirect table pointed to by this
            // descriptor
            ind_table = (VirtqDesc *)(get_virt_addr((void *)vdesc->addr,
                                                    vq->dev->zone_id));
            table_len = vdesc->len / 16;
            log_debug("find indirect desc, table_len is %d", table_len);
            next = 0;
            for (;;) {
                // log_debug("indirect desc next is %d", next);
                ind_desc = &ind_table[next];
                descriptor2iov(i, ind_desc, *iov, flags == NULL ? NULL : *flags,
                               vq->dev->zone_id, copy_flags);
                table_len--;
                i++;
                // No more next descriptor
                if ((ind_desc->flags & VRING_DESC_F_NEXT) == 0)
                    break;
                next = ind_desc->next;
            }
            if (table_len != 0) {
                log_error("invalid indirect descriptor chain");
                break;
            }
        } else {
            // For a normal descriptor, copy it directly to iov
            descriptor2iov(i, vdesc, *iov, flags == NULL ? NULL : *flags,
                           vq->dev->zone_id, copy_flags);
        }
    }
    return chain_len;
}

/// @brief Update the used ring with the processed descriptor chain.
/// @param vq Pointer to the VirtQueue structure.
/// @param idx The index of the first descriptor in the chain.
/// @param iolen The length of data written to the buffer.
void update_used_ring(VirtQueue *vq, uint16_t idx, uint32_t iolen) {
    volatile VirtqUsed *used_ring;
    volatile VirtqUsedElem *elem;
    uint16_t used_idx, mask;
    // There is no need to worry about if used_ring is full, because used_ring's
    // len is equal to descriptor table's.
    write_barrier();
    // pthread_mutex_lock(&vq->used_ring_lock);
    used_ring = vq->used_ring;
    used_idx = used_ring->idx;
    mask = vq->num - 1;
    elem = &used_ring->ring[used_idx++ & mask];
    elem->id = idx;
    elem->len = iolen;
    used_ring->idx = used_idx;
    write_barrier();
    // pthread_mutex_unlock(&vq->used_ring_lock);
    log_debug(
        "update used ring: used_idx is %d, elem->idx is %d, vq->num is %d",
        used_idx, idx, vq->num);
}

/// @brief Get the string representation of a VirtIO MMIO register offset.
/// @param offset The register offset.
/// @return The string representation.
static const char *virtio_mmio_reg_name(uint64_t offset) {
    switch (offset) {
    case VIRTIO_MMIO_MAGIC_VALUE:
        return "VIRTIO_MMIO_MAGIC_VALUE";
    case VIRTIO_MMIO_VERSION:
        return "VIRTIO_MMIO_VERSION";
    case VIRTIO_MMIO_DEVICE_ID:
        return "VIRTIO_MMIO_DEVICE_ID";
    case VIRTIO_MMIO_VENDOR_ID:
        return "VIRTIO_MMIO_VENDOR_ID";
    case VIRTIO_MMIO_DEVICE_FEATURES:
        return "VIRTIO_MMIO_DEVICE_FEATURES";
    case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
        return "VIRTIO_MMIO_DEVICE_FEATURES_SEL";
    case VIRTIO_MMIO_DRIVER_FEATURES:
        return "VIRTIO_MMIO_DRIVER_FEATURES";
    case VIRTIO_MMIO_DRIVER_FEATURES_SEL:
        return "VIRTIO_MMIO_DRIVER_FEATURES_SEL";
    case VIRTIO_MMIO_GUEST_PAGE_SIZE:
        return "VIRTIO_MMIO_GUEST_PAGE_SIZE";
    case VIRTIO_MMIO_QUEUE_SEL:
        return "VIRTIO_MMIO_QUEUE_SEL";
    case VIRTIO_MMIO_QUEUE_NUM_MAX:
        return "VIRTIO_MMIO_QUEUE_NUM_MAX";
    case VIRTIO_MMIO_QUEUE_NUM:
        return "VIRTIO_MMIO_QUEUE_NUM";
    case VIRTIO_MMIO_QUEUE_ALIGN:
        return "VIRTIO_MMIO_QUEUE_ALIGN";
    case VIRTIO_MMIO_QUEUE_PFN:
        return "VIRTIO_MMIO_QUEUE_PFN";
    case VIRTIO_MMIO_QUEUE_READY:
        return "VIRTIO_MMIO_QUEUE_READY";
    case VIRTIO_MMIO_QUEUE_NOTIFY:
        return "VIRTIO_MMIO_QUEUE_NOTIFY";
    case VIRTIO_MMIO_INTERRUPT_STATUS:
        return "VIRTIO_MMIO_INTERRUPT_STATUS";
    case VIRTIO_MMIO_INTERRUPT_ACK:
        return "VIRTIO_MMIO_INTERRUPT_ACK";
    case VIRTIO_MMIO_STATUS:
        return "VIRTIO_MMIO_STATUS";
    case VIRTIO_MMIO_QUEUE_DESC_LOW:
        return "VIRTIO_MMIO_QUEUE_DESC_LOW";
    case VIRTIO_MMIO_QUEUE_DESC_HIGH:
        return "VIRTIO_MMIO_QUEUE_DESC_HIGH";
    case VIRTIO_MMIO_QUEUE_AVAIL_LOW:
        return "VIRTIO_MMIO_QUEUE_AVAIL_LOW";
    case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
        return "VIRTIO_MMIO_QUEUE_AVAIL_HIGH";
    case VIRTIO_MMIO_QUEUE_USED_LOW:
        return "VIRTIO_MMIO_QUEUE_USED_LOW";
    case VIRTIO_MMIO_QUEUE_USED_HIGH:
        return "VIRTIO_MMIO_QUEUE_USED_HIGH";
    case VIRTIO_MMIO_CONFIG_GENERATION:
        return "VIRTIO_MMIO_CONFIG_GENERATION";
    case VIRTIO_MMIO_CONFIG:
        return "VIRTIO_MMIO_CONFIG";
    default:
        return "UNKNOWN";
    }
}

/// @brief Read from a VirtIO MMIO register.
/// @param vdev Pointer to the VirtIODevice structure.
/// @param offset The register offset.
/// @param size The size of the read.
/// @return The value read from the register.
uint64_t virtio_mmio_read(VirtIODevice *vdev, uint64_t offset, unsigned size) {
    log_debug("virtio mmio read at %#x", offset);
    log_info("READ virtio mmio at offset=%#x[%s], size=%d, vdev=%p, type=%d",
             offset, virtio_mmio_reg_name(offset), size, vdev, vdev->type);

    if (!vdev) {
        switch (offset) {
        case VIRTIO_MMIO_MAGIC_VALUE:
            log_debug("read VIRTIO_MMIO_MAGIC_VALUE");
            return VIRT_MAGIC;
        case VIRTIO_MMIO_VERSION:
            log_debug("read VIRTIO_MMIO_VERSION");
            return VIRT_VERSION;
        case VIRTIO_MMIO_VENDOR_ID:
            log_debug("read VIRTIO_MMIO_VENDOR_ID");
            return VIRT_VENDOR;
        default:
            return 0;
        }
    }

    if (offset >= VIRTIO_MMIO_CONFIG) {
        offset -= VIRTIO_MMIO_CONFIG;
        // the first member of vdev->dev must be config.
        log_debug("read virtio dev config");
        return *(uint64_t *)(vdev->dev + offset);
    }

    if (size != 4) {
        log_error("virtio-mmio-read: wrong size access to register!");
        return 0;
    }

    switch (offset) {
    case VIRTIO_MMIO_MAGIC_VALUE:
        log_debug("read VIRTIO_MMIO_MAGIC_VALUE");
        return VIRT_MAGIC;
    case VIRTIO_MMIO_VERSION:
        log_debug("read VIRTIO_MMIO_VERSION");
        return VIRT_VERSION;
    case VIRTIO_MMIO_DEVICE_ID:
        log_debug("read VIRTIO_MMIO_DEVICE_ID");
        return vdev->regs.device_id;
    case VIRTIO_MMIO_VENDOR_ID:
        log_debug("read VIRTIO_MMIO_VENDOR_ID");
        return VIRT_VENDOR;
    case VIRTIO_MMIO_DEVICE_FEATURES:
        log_debug("read VIRTIO_MMIO_DEVICE_FEATURES");

        if (vdev->regs.dev_feature_sel) {
            return vdev->regs.dev_feature >> 32;
        } else {
            return vdev->regs.dev_feature;
        }
    case VIRTIO_MMIO_QUEUE_NUM_MAX:
        log_debug("read VIRTIO_MMIO_QUEUE_NUM_MAX");
        return vdev->vqs[vdev->regs.queue_sel].queue_num_max;
    case VIRTIO_MMIO_QUEUE_READY:
        log_debug("read VIRTIO_MMIO_QUEUE_READY");
        return vdev->vqs[vdev->regs.queue_sel].ready;
    case VIRTIO_MMIO_INTERRUPT_STATUS:
        log_info("debug: (%s) current interrupt status is %d", __func__,
                 vdev->regs.interrupt_status);
#ifdef LOONGARCH64
        // clear lvz gintc irq injection bit to avoid endless interrupt...
        log_warn(
            "clear lvz gintc irq injection bit to avoid endless interrupt...");
        ioctl(ko_fd, HVISOR_CLEAR_INJECT_IRQ);
#endif
        if (vdev->regs.interrupt_status == 0) {
            log_error("virtio-mmio-read: interrupt status is 0, type is %d",
                      vdev->type);
        }
        return vdev->regs.interrupt_status;
    case VIRTIO_MMIO_STATUS:
        log_debug("read VIRTIO_MMIO_STATUS");
        return vdev->regs.status;
    case VIRTIO_MMIO_CONFIG_GENERATION:
        log_debug("read VIRTIO_MMIO_CONFIG_GENERATION");
        return vdev->regs.generation;
    case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
    case VIRTIO_MMIO_DRIVER_FEATURES:
    case VIRTIO_MMIO_DRIVER_FEATURES_SEL:
    case VIRTIO_MMIO_QUEUE_SEL:
    case VIRTIO_MMIO_QUEUE_NUM:
    case VIRTIO_MMIO_QUEUE_NOTIFY:
    case VIRTIO_MMIO_INTERRUPT_ACK:
    case VIRTIO_MMIO_QUEUE_DESC_LOW:
    case VIRTIO_MMIO_QUEUE_DESC_HIGH:
    case VIRTIO_MMIO_QUEUE_AVAIL_LOW:
    case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
    case VIRTIO_MMIO_QUEUE_USED_LOW:
    case VIRTIO_MMIO_QUEUE_USED_HIGH:
        log_error("read of write-only register");
        return 0;
    default:
        log_error("bad register offset %#x", offset);
        return 0;
    }
    return 0;
}

/// @brief Write to a VirtIO MMIO register.
/// @param vdev Pointer to the VirtIODevice structure.
/// @param offset The register offset.
/// @param value The value to write.
/// @param size The size of the write.
void virtio_mmio_write(VirtIODevice *vdev, uint64_t offset, uint64_t value,
                       unsigned size) {
    log_debug("virtio mmio write at %#x, value is %#x", offset, value);

    log_info("WRITE virtio mmio at offset=%#x[%s], value=%#x, size=%d, "
             "vdev=%p, type=%d",
             offset, virtio_mmio_reg_name(offset), value, size, vdev,
             vdev->type);

    VirtMmioRegs *regs = &vdev->regs;
    VirtQueue *vqs = vdev->vqs;
    if (!vdev) {
        return;
    }

    if (offset >= VIRTIO_MMIO_CONFIG) {
        offset -= VIRTIO_MMIO_CONFIG;
        log_error("virtio_mmio_write: can't write config space");
        return;
    }
    if (size != 4) {
        log_error("virtio_mmio_write: wrong size access to register!");
        return;
    }

    switch (offset) {
    case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
        log_debug("write VIRTIO_MMIO_DEVICE_FEATURES_SEL");
        if (value) {
            regs->dev_feature_sel = 1;
        } else {
            regs->dev_feature_sel = 0;
        }
        break;
    case VIRTIO_MMIO_DRIVER_FEATURES:
        log_debug("zone %d driver set device %s, accepted features %d",
                  vdev->zone_id, virtio_device_type_to_string(vdev->type),
                  value);
        if (regs->drv_feature_sel) {
            regs->drv_feature |= value << 32;
        } else {
            regs->drv_feature |= value;
        }

        // If the driver frontend has activated VIRTIO_RING_F_EVENT_IDX, enable
        // the related settings
        if (regs->drv_feature & (1ULL << VIRTIO_RING_F_EVENT_IDX)) {
            log_debug("zone %d driver accepted VIRTIO_RING_F_EVENT_IDX",
                      vdev->zone_id);
            int len = vdev->vqs_len;
            for (int i = 0; i < len; i++)
                vqs[i].event_idx_enabled = 1;
        }
        break;
    case VIRTIO_MMIO_DRIVER_FEATURES_SEL:
        log_debug("write VIRTIO_MMIO_DRIVER_FEATURES_SEL");

        if (value) {
            regs->drv_feature_sel = 1;
        } else {
            regs->drv_feature_sel = 0;
        }
        break;
    case VIRTIO_MMIO_QUEUE_SEL:
        log_debug("zone %d driver set device %s, selecting queue %d",
                  vdev->zone_id, virtio_device_type_to_string(vdev->type),
                  value);

        if (value < vdev->vqs_len) {
            regs->queue_sel = value;
        }
        break;
    case VIRTIO_MMIO_QUEUE_NUM:
        log_debug("zone %d driver set device %s, use virtqueue num %d",
                  vdev->zone_id, virtio_device_type_to_string(vdev->type),
                  value);

        vqs[regs->queue_sel].num = value;
        break;
    case VIRTIO_MMIO_QUEUE_READY:
        log_debug("write VIRTIO_MMIO_QUEUE_READY");

        vqs[regs->queue_sel].ready = value;
        break;
    case VIRTIO_MMIO_QUEUE_NOTIFY:
        log_debug("****** zone %d %s queue notify begin ******", vdev->zone_id,
                  virtio_device_type_to_string(vdev->type));

        if (value < vdev->vqs_len) {
            if (vqs[value].notify_handler) {
                log_trace("queue notify ready, handler addr is %#x",
                          vqs[value].notify_handler);
                vqs[value].notify_handler(vdev, &vqs[value]);
            } else {
                log_warn("queue notify for queue %d but no handler set", value);
            }
        }

        log_debug("****** zone %d %s queue notify end ******", vdev->zone_id,
                  virtio_device_type_to_string(vdev->type));

        break;
    case VIRTIO_MMIO_INTERRUPT_ACK:
        log_debug("write VIRTIO_MMIO_INTERRUPT_ACK");

        if (value == regs->interrupt_status && regs->interrupt_count > 0) {
            regs->interrupt_count--;
            break;
        } else if (value != regs->interrupt_status) {
            log_error("interrupt_status %d is not equal to ack %d, type is %d",
                      regs->interrupt_status, value, vdev->type);
        }
        regs->interrupt_status &= ~value;
        log_info("debug: (%s) clearing! interrupt_status -> %d", __func__,
                 regs->interrupt_status);
        break;
    case VIRTIO_MMIO_STATUS:
        log_debug("write VIRTIO_MMIO_STATUS");

        regs->status = value;
        if (regs->status == 0) {
            virtio_dev_reset(vdev);
        }
        break;
    case VIRTIO_MMIO_QUEUE_DESC_LOW:
        log_debug("write VIRTIO_MMIO_QUEUE_DESC_LOW");

        vqs[regs->queue_sel].desc_table_addr |= value & UINT32_MAX;
        break;
    case VIRTIO_MMIO_QUEUE_DESC_HIGH:
        log_debug("write VIRTIO_MMIO_QUEUE_DESC_HIGH");

        vqs[regs->queue_sel].desc_table_addr |= value << 32;
        virtqueue_set_desc_table(&vqs[regs->queue_sel]);
        break;
    case VIRTIO_MMIO_QUEUE_AVAIL_LOW:
        log_debug("write VIRTIO_MMIO_QUEUE_AVAIL_LOW");

        vqs[regs->queue_sel].avail_addr |= value & UINT32_MAX;
        break;
    case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
        log_debug("write VIRTIO_MMIO_QUEUE_AVAIL_HIGH");

        vqs[regs->queue_sel].avail_addr |= value << 32;
        virtqueue_set_avail(&vqs[regs->queue_sel]);
        break;
    case VIRTIO_MMIO_QUEUE_USED_LOW:
        log_debug("write VIRTIO_MMIO_QUEUE_USED_LOW");

        vqs[regs->queue_sel].used_addr |= value & UINT32_MAX;
        break;
    case VIRTIO_MMIO_QUEUE_USED_HIGH:
        log_debug("write VIRTIO_MMIO_QUEUE_USED_HIGH");

        vqs[regs->queue_sel].used_addr |= value << 32;
        virtqueue_set_used(&vqs[regs->queue_sel]);
        break;
    case VIRTIO_MMIO_MAGIC_VALUE:
    case VIRTIO_MMIO_VERSION:
    case VIRTIO_MMIO_DEVICE_ID:
    case VIRTIO_MMIO_VENDOR_ID:
    case VIRTIO_MMIO_DEVICE_FEATURES:
    case VIRTIO_MMIO_QUEUE_NUM_MAX:
    case VIRTIO_MMIO_INTERRUPT_STATUS:
    case VIRTIO_MMIO_CONFIG_GENERATION:
        log_error("%s: write to read-only register 0#x", __func__, offset);
        break;

    default:
        log_error("%s: bad register offset 0#x", __func__, offset);
    }
}

/// @brief Check if a value is in a range.
/// @param value The value to check.
/// @param lower The lower bound of the range.
/// @param len The length of the range.
/// @return true if value is in range, false otherwise.
inline bool in_range(uint64_t value, uint64_t lower, uint64_t len) {
    return ((value >= lower) && (value < (lower + len)));
}

#include "coroutine_utils.h"

/// @brief Inject an interrupt to the Guest.
/// @details This function checks if an interrupt is needed based on event index
/// or flags, and if so, notifies the hypervisor or writes to the irqfd.
/// @param vq Pointer to the VirtQueue structure.
Task virtio_inject_irq(VirtQueue *vq) {
    uint16_t last_used_idx, idx, event_idx;
    last_used_idx = vq->last_used_idx;
    vq->last_used_idx = idx = vq->used_ring->idx;
    // read_barrier();
    if (idx == last_used_idx) {
        log_debug("idx equals last_used_idx");
        co_return;
    }
    if (!vq->event_idx_enabled &&
        (vq->avail_ring->flags & VRING_AVAIL_F_NO_INTERRUPT)) {
        log_debug("no interrupt");
        co_return;
    }
    if (vq->event_idx_enabled) {
        event_idx = VQ_USED_EVENT(vq);
        log_debug("idx is %d, event_idx is %d, last_used_idx is %d", idx,
                  event_idx, last_used_idx);
        if (!vring_need_event(event_idx, idx, last_used_idx)) {
            co_return;
        }
    }
    volatile struct device_res *res;

    // virtio_bridge is a global resource located in shared memory.
    // Since we are now running in a single-threaded reactor model (via
    // io_uring), and the shared resources related to res_list are only accessed
    // here in the event loop, we no longer need a mutex lock. The previous lock
    // was to protect against concurrent access between main thread and signal
    // thread, which are now merged.

    while (is_queue_full(virtio_bridge->res_front, virtio_bridge->res_rear,
                         MAX_REQ)) {
        // Yield execution to avoid busy waiting
        // Use SleepAwaitable to avoid busy loop (1ms sleep)
        // TODO: Add kernel notification to remove this sleep
        co_await SleepAwaitable(1);
    }
    unsigned int res_rear = virtio_bridge->res_rear;
    res = &virtio_bridge->res_list[res_rear];
    res->irq_id = vq->dev->irq_id;
    res->target_zone = vq->dev->zone_id;
    write_barrier();
    virtio_bridge->res_rear = (res_rear + 1) & (MAX_REQ - 1);
    write_barrier();
    vq->dev->regs.interrupt_status = VIRTIO_MMIO_INT_VRING;
    vq->dev->regs.interrupt_count++;

    log_debug("inject irq to device %s, vq is %d",
              virtio_device_type_to_string(vq->dev->type), vq->vq_idx);
    ioctl(ko_fd, HVISOR_FINISH_REQ);
    co_return;
}

/// @brief Notify the hypervisor that a config request is finished.
/// @param target_cpu The CPU that initiated the request.
/// @param value The value returned by the request (if any).
void virtio_finish_cfg_req(uint32_t target_cpu, uint64_t value) {
    virtio_bridge->cfg_values[target_cpu] = value;
    write_barrier();
    virtio_bridge->cfg_flags[target_cpu]++;
    write_barrier();
}

/// @brief Handle a device request from the hypervisor.
/// @param req Pointer to the device request structure.
/// @return 0 on success, -1 on failure.
int virtio_handle_req(volatile struct device_req *req) {
    int i;
    uint64_t value = 0;

    // Check if the request corresponds to a virtio device in a specific zone
    for (i = 0; i < vdevs_num; ++i) {
        if ((req->src_zone == vdevs[i]->zone_id) &&
            in_range(req->address, vdevs[i]->base_addr,
                     vdevs[i]->len)) // Check if memory regions overlap
            break;
    }

    if (i == vdevs_num) {
        log_warn("no matched virtio dev in zone %d, address is 0x%x",
                 req->src_zone, req->address);
        value = virtio_mmio_read(NULL, 0, 0);
        virtio_finish_cfg_req(req->src_cpu, value);
        return -1;
    }

    VirtIODevice *vdev = vdevs[i];

    uint64_t offs = req->address - vdev->base_addr;

    // Write or read the device's MMIO register
    if (req->is_write) {
        virtio_mmio_write(vdev, offs, req->value, req->size);
    } else {
        value = virtio_mmio_read(vdev, offs, req->size);
        log_debug("read value is 0x%x", value);
    }

    // Control instructions do not require interrupts to return data
    // The requester will block and wait
    if (!req->need_interrupt) {
        // If a request is a control not a data request
        virtio_finish_cfg_req(req->src_cpu, value);
    }

    log_trace("src_zone is %d, src_cpu is %lld", req->src_zone, req->src_cpu);
    return 0;
}

/// @brief Close all virtio devices and clean up resources.
void virtio_close() {
    log_warn("virtio devices will be closed");
    destroy_event_monitor();
    for (int i = 0; i < vdevs_num; i++)
        vdevs[i]->virtio_close(vdevs[i]);
    close(ko_fd);
    if (virtio_irq_fd >= 0)
        close(virtio_irq_fd);
    munmap((void *)virtio_bridge, MMAP_SIZE);
    for (int i = 0; i < MAX_ZONES; i++) {
        for (int j = 0; j < MAX_RAMS; j++)
            if (zone_mem[i][j][MEM_SIZE] != 0) {
                munmap((void *)zone_mem[i][j][VIRT_ADDR],
                       zone_mem[i][j][MEM_SIZE]);
            }
    }
    multithread_log_exit();
    log_warn("virtio daemon exit successfully");
}

#define VIRTIO_IRQ_QUOTA 64

static struct io_completion_event virtio_nop_event;
static void virtio_process_req_queue(void *param, int res);

static void virtio_yield_req_processing(void) {
    struct io_uring *ring = get_global_ring();
    struct io_uring_sqe *sqe = get_sqe_safe(ring);

    io_uring_prep_nop(sqe);

    virtio_nop_event.base.type = EVENT_TYPE_IO_COMPLETION;
    virtio_nop_event.handler = virtio_process_req_queue;
    virtio_nop_event.param = NULL;
    virtio_nop_event.free_on_completion = false;

    io_uring_sqe_set_data(sqe, &virtio_nop_event);
    // Do not submit here, let event loop handle it to batch syscalls
}

static Task virtio_req_coroutine(void) {
    while (true) {
        // Wait for notification (this part is tricky as we need to bridge poll
        // event to coroutine resume) For now, let's keep the poll handler
        // separate and have it resume/notify this coroutine. Or simpler: The
        // poll handler just spawns this task (fire and forget) if it's not
        // running? Actually, let's keep the structure but remove the manual
        // quota loop with callback. We can just loop and yield.

        unsigned int req_front = virtio_bridge->req_front;
        volatile struct device_req *req;
        int processed = 0;

        while (!is_queue_full(req_front, virtio_bridge->req_rear, MAX_REQ)) {
            req = &virtio_bridge->req_list[req_front];
            virtio_bridge->need_wakeup = 0;
            virtio_handle_req(req);
            req_front = (req_front + 1) & (MAX_REQ - 1);
            virtio_bridge->req_front = req_front;
            write_barrier();
            processed++;

            // Yield every 64 requests to prevent starvation
            if (processed >= 64) {
                co_await YieldAwaitable{};
                processed = 0;
            }
        }

        // Ensure we are ready for next interrupt
        virtio_bridge->need_wakeup = 1;
        write_barrier();

        if (is_queue_empty(req_front, virtio_bridge->req_rear)) {
            // No more requests, suspend until next event
            // This requires an awaitable that is resumed by the poll handler
            // For now, let's just return. The poll handler will call us again.
            co_return;
        }

        // If we have more requests (race condition check), continue loop
        // But we returned above? No, we need a loop.
        // Re-check logic similar to original.
    }
}

static void virtio_process_req_queue(void *param, int res) {
    unsigned int req_front = virtio_bridge->req_front;
    volatile struct device_req *req;
    int processed = 0;
    const int BATCH_LIMIT = 64;

    // Process requests until queue is empty or batch limit reached
    while (!is_queue_empty(req_front, virtio_bridge->req_rear)) {
        req = &virtio_bridge->req_list[req_front];
        virtio_bridge->need_wakeup = 0;
        virtio_handle_req(req);
        req_front = (req_front + 1) & (MAX_REQ - 1);
        virtio_bridge->req_front = req_front;
        write_barrier();

        processed++;
        if (processed >= BATCH_LIMIT) {
            // Yield to event loop to prevent starvation
            virtio_yield_req_processing();
            return;
        }
    }

    virtio_bridge->need_wakeup = 1;
    write_barrier();

    // Double check to avoid race condition:
    // If new requests arrived after the loop but before we set need_wakeup,
    // we might miss them if we don't check again.
    if (!is_queue_empty(req_front, virtio_bridge->req_rear)) {
        virtio_yield_req_processing();
    }
}

/// @brief Handler for virtio IRQ poll events.
/// @details Called when the virtio_irq_fd becomes readable.
/// @param fd The file descriptor.
/// @param type The poll event type.
/// @param param User parameter (unused).
static void virtio_irq_poll_handler(int fd, int type, void *param) {
    uint64_t val;
    int ret;

    if (type != POLLIN) {
        log_error("virtio irq poll handler: unexpected event type %d", type);
        return;
    }

    // Read the eventfd to clear the counter
    ret = read(fd, &val, sizeof(uint64_t));
    if (ret < 0) {
        if (errno == EAGAIN || errno == EINTR) {
            return;
        }
        log_fatal("read eventfd failed: %d, exiting...", errno);
        exit(EXIT_FAILURE);
    }

    virtio_process_req_queue(NULL, 0);
}

static struct poll_event virtio_irq_poll_event;

/// @brief Enable polling for the virtio IRQ file descriptor.
void virtio_enable_irq_poll(void) {
    if (virtio_irq_fd < 0)
        return;

    virtio_irq_poll_event.base.type = EVENT_TYPE_POLL;
    virtio_irq_poll_event.fd = virtio_irq_fd;
    virtio_irq_poll_event.epoll_type = POLLIN;
    virtio_irq_poll_event.handler = virtio_irq_poll_handler;
    virtio_irq_poll_event.param = NULL;
    virtio_irq_poll_event.active = false;

    enable_event_poll(&virtio_irq_poll_event);
}

/// @brief Signal handler for the virtio daemon.
/// @param fd The signal file descriptor.
/// @param type The poll event type.
/// @param param User parameter (unused).
void virtio_sig_handler(int fd, int type, void *param) {
    struct signalfd_siginfo fdsi;
    ssize_t s;

    s = read(fd, &fdsi, sizeof(struct signalfd_siginfo));
    if (s != sizeof(struct signalfd_siginfo)) {
        log_error("read signalfd failed");
        return;
    }

    if (fdsi.ssi_signo == SIGTERM || fdsi.ssi_signo == SIGINT) {
        log_warn("Received signal %d, exiting...", fdsi.ssi_signo);
        virtio_close();
        exit(0);
    }
}
