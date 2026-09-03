// SPDX-License-Identifier: GPL-2.0-only
/**
 * Copyright (c) 2025 Syswonder
 *
 * Syswonder Website:
 *      https://www.syswonder.org
 *
 * Authors:
 *      Linkun Chen <lkchen01@foxmail.com>
 */
#define _GNU_SOURCE

#include "virtio_scmi.h"
#include "hvisor.h"
#include "json_parse.h"
#include "log.h"
#include "safe_cjson.h"
#include "virtio.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static int parse_id_array(const cJSON *json_array, uint32_t **ids_out,
                          uint32_t *count_out) {
    if (!json_array || !cJSON_IsArray(json_array)) {
        *ids_out = NULL;
        *count_out = 0;
        return 0;
    }

    int count = cJSON_GetArraySize(json_array);
    if (count == 0) {
        *ids_out = NULL;
        *count_out = 0;
        return 0;
    }

    uint32_t *ids = malloc(sizeof(uint32_t) * count);
    if (!ids) {
        log_error("Failed to allocate ID array");
        return -ENOMEM;
    }

    for (int i = 0; i < count; i++) {
        cJSON *item = cJSON_GetArrayItem(json_array, i);
        if (parse_json_u32(item, &ids[i]) != 0) {
            log_error("Failed to parse ID at index %d", i);
            free(ids);
            return -EINVAL;
        }
    }

    *ids_out = ids;
    *count_out = (uint32_t)count;
    return 0;
}

SCMIDev *scmi_dev_create(void) { return calloc(1, sizeof(SCMIDev)); }

void scmi_dev_free(SCMIDev *dev) {
    if (!dev)
        return;
    free(dev->clock_ids);
    free(dev->reset_ids);
    free(dev->power_ids);
    free(dev->clk_en_cnt);
    free(dev->pwr_on_cnt);
    pthread_mutex_destroy(&dev->res_lock);
    free(dev);
}

int scmi_dev_parse_clock_ids(struct virtio_scmi_init_params *p,
                             const cJSON *json_array) {
    return parse_id_array(json_array, &p->clock_ids, &p->clock_count);
}

int scmi_dev_parse_reset_ids(struct virtio_scmi_init_params *p,
                             const cJSON *json_array) {
    return parse_id_array(json_array, &p->reset_ids, &p->reset_count);
}

int scmi_dev_parse_power_ids(struct virtio_scmi_init_params *p,
                             const cJSON *json_array) {
    return parse_id_array(json_array, &p->power_ids, &p->power_count);
}

void scmi_dev_free_params(struct virtio_scmi_init_params *p) {
    if (!p)
        return;
    free(p->clock_ids);
    free(p->reset_ids);
    free(p->power_ids);
    free(p);
}

static int virtq_tx_handle_one_request(void *dev, VirtQueue *vq) {
    struct iovec out_iov[2], in_iov[2];
    struct VirtioBufConfig cfg = {
        .out_iov = out_iov,
        .max_out = 2,
        .in_iov = in_iov,
        .max_in = 2,
    };
    struct VirtioRequest vreq;

    uint16_t desc_idx =
        vq->avail_ring->ring[vq->last_avail_idx & (vq->num - 1)];
    int ret = process_descriptor_chain_buf(vq, desc_idx, &cfg, &vreq);
    if (ret <= 0) {
        log_error("Failed to process descriptor chain");
        // process_descriptor_chain_buf failed without advancing last_avail_idx
        // or completing the descriptor: consume it and report a zero-length
        // completion so the guest request does not hang forever.
        vq->last_avail_idx++;
        update_used_ring(vq, desc_idx, 0);
        return -EINVAL;
    }

    // SCMI expects: one readable (request header+payload) and one writable
    // (response buffer).  More than that is a malformed chain.
    if (vreq.out_count != 1 || vreq.in_count != 1) {
        log_error("Invalid descriptor chain layout: out=%d, in=%d",
                  vreq.out_count, vreq.in_count);
        update_used_ring(vq, desc_idx, 0);
        return -EINVAL;
    }

    struct iovec *req_iov = &vreq.out_iov[0];
    struct iovec *resp_iov = &vreq.in_iov[0];

    // Check the request buffer: must have a 4-byte packed header
    if (req_iov->iov_len < sizeof(uint32_t) || req_iov->iov_base == NULL ||
        req_iov->iov_len > SCMI_MAX_BUFFER_SIZE) {
        log_error("Invalid request buffer");
        update_used_ring(vq, desc_idx, 0);
        return -EINVAL;
    }

    // Parse packed 32-bit header via bitfield struct
    struct scmi_msg_header *hdr = req_iov->iov_base;

    log_debug("SCMI request: protocol=0x%x, msg=0x%x, type=%d, token=0x%x",
              hdr->protocol_id, hdr->msg_id, hdr->msg_type, hdr->token);

    if (hdr->msg_type != SCMI_MSG_TYPE_COMMAND) {
        log_error("Invalid message type: %d", hdr->msg_type);
        update_used_ring(vq, desc_idx, 0);
        return -EINVAL;
    }

    struct scmi_resp_ctx ctx;
    scmi_resp_ctx_init(&ctx, resp_iov);

    if (scmi_handle_message(dev, hdr->protocol_id, hdr->msg_id, hdr->token,
                            req_iov, &ctx) != 0) {
        log_error("Protocol handler failed");
        update_used_ring(vq, desc_idx, 0);
        return -EINVAL;
    }

    update_used_ring(vq, desc_idx, ctx.written);
    return 0;
}

static int virtio_scmi_txq_notify_handler(VirtIODevice *vdev, VirtQueue *vq) {
    while (!virtqueue_is_empty(vq)) {
        virtqueue_disable_notify(vq);
        while (!virtqueue_is_empty(vq)) {
            if (virtq_tx_handle_one_request(vdev->dev, vq) < 0) {
                // The failed request was already consumed and completed
                // inside virtq_tx_handle_one_request; stop this batch but
                // still re-enable notifications and inject the completion
                // interrupt so the guest is not left waiting forever.
                log_error("Failed to handle SCMI request");
                break;
            }
        }
        virtqueue_enable_notify(vq);
    }
    virtio_inject_irq(vq);
    return 0;
}

static void virtio_scmi_reset(VirtIODevice *vdev) { (void)vdev; }

static void virtio_scmi_close(VirtIODevice *vdev) {
    if (!vdev)
        return;

    SCMIDev *dev = vdev->dev;
    if (dev) {
        scmi_dev_free(dev);
        vdev->dev = NULL;
    }
    free(vdev->vqs);
    vdev->vqs = NULL;
    free(vdev);
}

/*
 * Deep-copy a count-sized uint32 id array; count == 0 keeps *dst NULL.
 * Failure cleanup is deferred to ops->close (scmi_dev_free tolerates
 * NULL id arrays), so a non-zero return just needs to propagate.
 */
static int scmi_copy_id_array(uint32_t **dst, const uint32_t *src,
                              uint32_t count) {
    if (count == 0)
        return 0;
    *dst = calloc(count, sizeof(uint32_t));
    if (!*dst)
        return -ENOMEM;
    memcpy(*dst, src, count * sizeof(uint32_t));
    return 0;
}

static int virtio_scmi_do_init(VirtIODevice *vdev, const void *params) {
    const struct virtio_scmi_init_params *p = params;
    SCMIDev *dev;

    if (p) {
        dev = calloc(1, sizeof(SCMIDev));
        if (!dev)
            return -ENOMEM;
        vdev->dev = dev;

        // Deep-copy id arrays so that SCMIDev and the caller each own their
        // copies — no ownership transfer, no double-free risk.
        if (scmi_copy_id_array(&dev->clock_ids, p->clock_ids, p->clock_count) ||
            scmi_copy_id_array(&dev->reset_ids, p->reset_ids, p->reset_count) ||
            scmi_copy_id_array(&dev->power_ids, p->power_ids, p->power_count))
            return -ENOMEM;
    pthread_mutex_init(&dev->res_lock, NULL);
    if (p->clock_count &&
        !(dev->clk_en_cnt = calloc(p->clock_count, sizeof(uint32_t))))
        return -ENOMEM;
    if (p->power_count &&
        !(dev->pwr_on_cnt = calloc(p->power_count, sizeof(uint32_t))))
        return -ENOMEM;
        dev->clock_count = p->clock_count;
        dev->reset_count = p->reset_count;
        dev->power_count = p->power_count;

        scmi_dev_register_protocol(dev, SCMI_PROTO_ID_BASE,
                                   virtio_scmi_base_handle_req);
        if (dev->clock_count > 0)
            scmi_dev_register_protocol(dev, SCMI_PROTO_ID_CLOCK,
                                       virtio_scmi_clock_handle_req);
        if (dev->power_count > 0)
            scmi_dev_register_protocol(dev, SCMI_PROTO_ID_POWER,
                                       virtio_scmi_power_handle_req);
        if (dev->reset_count > 0)
            scmi_dev_register_protocol(dev, SCMI_PROTO_ID_RESET,
                                       virtio_scmi_reset_handle_req);
    } else {
        dev = scmi_dev_create();
        if (!dev)
            return -ENOMEM;
        vdev->dev = dev;
    }

    return 0;
}

const struct virtio_device_ops virtio_scmi_ops = {
    .type = VirtioTSCMI,
    .features = SCMI_SUPPORTED_FEATURES,
    .num_queues = SCMI_MAX_QUEUES,
    .queue_max_size = VIRTQUEUE_SCMI_MAX_SIZE,
    .init = virtio_scmi_do_init,
    .close = virtio_scmi_close,
    .reset = virtio_scmi_reset,
    .notify_handlers =
        {
            [SCMI_QUEUE_TX] = virtio_scmi_txq_notify_handler,
        },
};

static int virtio_scmi_parse_params(const cJSON *json, void **out) {
    struct virtio_scmi_init_params *p = calloc(1, sizeof(*p));
    if (!p)
        return -ENOMEM;

    cJSON *clock_ids = cJSON_GetObjectItem(json, "clock_ids");
    cJSON *reset_ids = cJSON_GetObjectItem(json, "reset_ids");
    cJSON *power_ids = cJSON_GetObjectItem(json, "power_ids");

    if (scmi_dev_parse_clock_ids(p, clock_ids) < 0 ||
        scmi_dev_parse_reset_ids(p, reset_ids) < 0 ||
        scmi_dev_parse_power_ids(p, power_ids) < 0) {
        scmi_dev_free_params(p);
        return -EINVAL;
    }

    *out = p;
    return 0;
}

static void virtio_scmi_free_params(void *params) {
    scmi_dev_free_params(params);
}

const struct virtio_config_ops virtio_scmi_config_ops = {
    .parse = virtio_scmi_parse_params,
    .free = virtio_scmi_free_params,
};

int scmi_dev_release_zone(SCMIDev *dev) {
    struct hvisor_scmi_clock_args cargs;
    struct hvisor_scmi_power_args pargs;
    uint32_t i;
    int n_disabled = 0, n_off = 0;

    if (!dev)
        return -1;

    pthread_mutex_lock(&dev->res_lock);

    /* Undo exactly what this zone did: only clocks it enabled (and that are
     * still counted as enabled by it) are disabled. Clocks the zone never
     * touched, or that are shared with another zone / the root OS, keep
     * their own reference counts untouched. */
    for (i = 0; i < dev->clock_count && dev->clk_en_cnt; i++) {
        while (dev->clk_en_cnt[i] > 0) {
            memset(&cargs, 0, sizeof(cargs));
            cargs.u.clock_config_info.clock_id = dev->clock_ids[i];
            cargs.u.clock_config_info.config = 0;
            if (hvisor_scmi_ioctl_cmd(HVISOR_SCMI_CLOCK_IOCTL, &cargs,
                                      sizeof(cargs),
                                      HVISOR_SCMI_CLOCK_CONFIG_SET,
                                      "clock") < 0) {
                log_warn("scmi release: failed to disable clock %u",
                         dev->clock_ids[i]);
                break;
            }
            dev->clk_en_cnt[i]--;
            n_disabled++;
        }
    }

    /* Likewise power domains: only ones this zone powered on are turned
     * off. This acts as the hardware reset of passthrough devices. */
    for (i = 0; i < dev->power_count && dev->pwr_on_cnt; i++) {
        while (dev->pwr_on_cnt[i] > 0) {
            memset(&pargs, 0, sizeof(pargs));
            pargs.u.power_state_info.domain_id = dev->power_ids[i];
            pargs.u.power_state_info.power_state = SCMI_POWER_STATE_GENERIC_OFF;
            if (hvisor_scmi_ioctl_cmd(HVISOR_SCMI_POWER_IOCTL, &pargs,
                                      sizeof(pargs),
                                      HVISOR_SCMI_POWER_STATE_SET,
                                      "power") < 0) {
                log_warn("scmi release: failed to power off domain %u",
                         dev->power_ids[i]);
                break;
            }
            dev->pwr_on_cnt[i]--;
            n_off++;
        }
    }

    pthread_mutex_unlock(&dev->res_lock);
    log_info("scmi release: disabled %d clock(s), powered off %d domain(s)",
             n_disabled, n_off);
    return 0;
}
