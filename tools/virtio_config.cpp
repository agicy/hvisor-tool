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

#include "hvisor.h"
#include "log.h"
#include "safe_cjson.h"
#include "virtio.h"
#include "virtio_blk.h"
#include "virtio_console.h"
#include "virtio_gpu.h"
#include "virtio_net.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// External variables from virtio_core.c
extern int ko_fd;
extern int virtio_irq_fd;
extern volatile struct virtio_bridge *virtio_bridge;
extern VirtIODevice *vdevs[MAX_DEVS];
extern int vdevs_num;
extern unsigned long long zone_mem[MAX_ZONES][MAX_RAMS][4];

static struct poll_event sig_poll_event;

// the index of `zone_mem[i]`
#define VIRT_ADDR 0
#define ZONE0_IPA 1
#define ZONEX_IPA 2
#define MEM_SIZE 3

/// @brief Initialize the logging system.
void initialize_log() {
    int log_level;
#ifdef HLOG
    log_level = HLOG;
#else
    log_level = LOG_WARN;
#endif
    log_set_level(log_level);
}

/// @brief Read the content of a file into a buffer.
/// @param filename The path to the file.
/// @param filesize Pointer to store the size of the file.
/// @return Pointer to the allocated buffer containing file content, or NULL on
/// failure.
void *read_file(char *filename, uint64_t *filesize) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        log_error("Failed to open file %s", filename);
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    *filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    void *buffer = malloc(*filesize + 1);
    if (buffer == NULL) {
        log_error("Failed to allocate memory for file %s", filename);
        fclose(fp);
        return NULL;
    }

    if (fread(buffer, 1, *filesize, fp) != *filesize) {
        log_error("Failed to read file %s", filename);
        free(buffer);
        fclose(fp);
        return NULL;
    }

    fclose(fp);
    return buffer;
}

// create a virtio device.
/// @brief Create and initialize a new virtio device.
/// @param dev_type The type of the virtio device.
/// @param zone_id The zone ID.
/// @param base_addr The base MMIO address.
/// @param len The size of the MMIO region.
/// @param irq_id The interrupt ID.
/// @param arg0 First initialization argument (device specific).
/// @param arg1 Second initialization argument (device specific).
/// @return Pointer to the created VirtIODevice structure, or NULL on failure.
VirtIODevice *create_virtio_device(VirtioDeviceType dev_type, uint32_t zone_id,
                                   uint64_t base_addr, uint64_t len,
                                   uint32_t irq_id, void *arg0, void *arg1) {
    log_info(
        "create virtio device type %s, zone id %d, base addr %lx, len %lx, "
        "irq id %d",
        virtio_device_type_to_string(dev_type), zone_id, base_addr, len,
        irq_id);
    VirtIODevice *vdev = NULL;
    int is_err;
    vdev = calloc(1, sizeof(VirtIODevice));
    if (vdev == NULL) {
        log_error("failed to allocate virtio device");
        return NULL;
    }
    init_mmio_regs(&vdev->regs, dev_type);
    vdev->base_addr = base_addr;
    vdev->len = len;
    vdev->zone_id = zone_id;
    vdev->irq_id = irq_id;
    vdev->type = dev_type;

    log_info("debug: vdev->base_addr is %lx, vdev->len is %lx, vdev->zone_id "
             "is %d, vdev->irq_id is %d",
             vdev->base_addr, vdev->len, vdev->zone_id, vdev->irq_id);

    switch (dev_type) {
    case VirtioTBlock:
        vdev->regs.dev_feature = BLK_SUPPORTED_FEATURES;
        vdev->dev = virtio_blk_alloc();
        if (!vdev->dev) {
            log_error("failed to init blk dev");
            goto err;
        }
        init_virtio_queue(vdev, dev_type);
        is_err = virtio_blk_init(vdev, (const char *)arg0);
        break;

    case VirtioTNet:
        vdev->regs.dev_feature = NET_SUPPORTED_FEATURES;
        vdev->dev = virtio_net_alloc(arg0);
        if (!vdev->dev) {
            log_error("failed to init net dev");
            goto err;
        }
        init_virtio_queue(vdev, dev_type);
        is_err = virtio_net_init(vdev, (char *)arg1);
        break;

    case VirtioTConsole:
        vdev->regs.dev_feature = CONSOLE_SUPPORTED_FEATURES;
        vdev->dev = virtio_console_alloc();
        if (!vdev->dev) {
            log_error("failed to init console dev");
            goto err;
        }
        init_virtio_queue(vdev, dev_type);
        is_err = virtio_console_init(vdev);
        break;

    case VirtioTGPU:
#ifdef ENABLE_VIRTIO_GPU
        vdev->regs.dev_feature = GPU_SUPPORTED_FEATURES;
        vdev->dev = init_gpu_dev((GPURequestedState *)arg0);
        if (!vdev->dev) {
            log_error("failed to init gpu dev");
            free(arg0);
            goto err;
        }
        free(arg0);
        init_virtio_queue(vdev, dev_type);
        is_err = virtio_gpu_init(vdev);
#else
        log_error("virtio gpu is not enabled");
        goto err;
#endif
        break;

    default:
        log_error("unsupported virtio device type");
        goto err;
    }

    if (is_err)

        goto err;

    // If reaches max number of virtual devices
    if (vdevs_num == MAX_DEVS) {
        log_error("virtio device num exceed max limit");
        goto err;
    }

    if (vdev->dev == NULL) {
        log_error("failed to init dev");
        goto err;
    }

    log_info("create %s success", virtio_device_type_to_string(dev_type));
    vdevs[vdevs_num++] = vdev;

    return vdev;

err:
    if (vdev) {
        if (vdev->vqs) {
            free(vdev->vqs);
        }
        free(vdev);
    }
    return NULL;
}

/// @brief Create a virtio device from a JSON configuration object.
/// @param device_json Pointer to the cJSON object containing device config.
/// @param zone_id The zone ID.
/// @return 0 on success, -1 on failure.
int create_virtio_device_from_json(cJSON *device_json, int zone_id) {
    VirtioDeviceType dev_type = VirtioTNone;
    uint64_t base_addr = 0, len = 0;
    uint32_t irq_id = 0;

    char *status =
        SAFE_CJSON_GET_OBJECT_ITEM(device_json, "status")->valuestring;
    if (strcmp(status, "disable") == 0)
        return 0;

    // Get device type
    char *type = SAFE_CJSON_GET_OBJECT_ITEM(device_json, "type")->valuestring;
    void *arg0, *arg1;

    // Match the device type field in json
    if (strcmp(type, "blk") == 0) {
        dev_type = VirtioTBlock;
    } else if (strcmp(type, "net") == 0) {
        dev_type = VirtioTNet;
    } else if (strcmp(type, "console") == 0) {
        dev_type = VirtioTConsole;
    } else if (strcmp(type, "gpu") == 0) {
        dev_type = VirtioTGPU;
    } else {
        log_error("unknown device type %s", type);
        return -1;
    }

    // Get base_addr, len, irq_id (mmio region base address and length, device
    // interrupt number)
    base_addr = strtoul(
        SAFE_CJSON_GET_OBJECT_ITEM(device_json, "addr")->valuestring, NULL, 16);
    len = strtoul(SAFE_CJSON_GET_OBJECT_ITEM(device_json, "len")->valuestring,
                  NULL, 16);
    irq_id = SAFE_CJSON_GET_OBJECT_ITEM(device_json, "irq")->valueint;

    // Handle other fields according to the device type
    if (dev_type == VirtioTBlock) {
        // virtio-blk
        char *img = SAFE_CJSON_GET_OBJECT_ITEM(device_json, "img")->valuestring;
        arg0 = img, arg1 = NULL;
        log_info("debug: img is %s", img);
    } else if (dev_type == VirtioTNet) {
        // virtio-net
        char *tap = SAFE_CJSON_GET_OBJECT_ITEM(device_json, "tap")->valuestring;
        cJSON *mac_json = SAFE_CJSON_GET_OBJECT_ITEM(device_json, "mac");
        uint8_t mac[6];
        for (int i = 0; i < 6; i++) {
            mac[i] = strtoul(
                SAFE_CJSON_GET_ARRAY_ITEM(mac_json, i)->valuestring, NULL, 16);
        }
        arg0 = mac, arg1 = tap;
    } else if (dev_type == VirtioTConsole) {
        // virtio-console
        arg0 = arg1 = NULL;
    } else if (dev_type == VirtioTGPU) {
// virtio-gpu
#ifdef ENABLE_VIRTIO_GPU
        // TODO: Add display device settings
        GPURequestedState *requested_state = NULL;
        requested_state =
            (GPURequestedState *)malloc(sizeof(GPURequestedState));
        memset(requested_state, 0, sizeof(GPURequestedState));
        requested_state->width =
            SAFE_CJSON_GET_OBJECT_ITEM(device_json, "width")->valueint;
        requested_state->height =
            SAFE_CJSON_GET_OBJECT_ITEM(device_json, "height")->valueint;
        arg0 = requested_state;
        arg1 = NULL;
#else
        log_error(
            "virtio-gpu is not enabled, please add VIRTIO_GPU=y in make cmd");
        return -1;
#endif
    }

    // Check for missing fields
    if (base_addr == 0 || len == 0 || irq_id == 0) {
        log_error("missing arguments");
        return -1;
    }

    // Create virtio_device
    if (!create_virtio_device(dev_type, zone_id, base_addr, len, irq_id, arg0,
                              arg1)) {
        return -1;
    }

    return 0;
}

/// @brief Start the virtio backend using a JSON configuration file.
/// @param json_path The path to the JSON configuration file.
/// @return 0 on success, -1 on failure.
int virtio_start_from_json(char *json_path) {
    char *buffer = NULL;
    uint64_t file_size;
    int zone_id, num_devices = 0, err = 0, num_zones = 0;
    void *zone0_ipa, *zonex_ipa, *virt_addr;
    unsigned long long mem_size;
    buffer = read_file(json_path, &file_size);
    buffer[file_size] = '\0';

    // Read zones
    cJSON *root = SAFE_CJSON_PARSE(buffer);
    cJSON *zones_json = SAFE_CJSON_GET_OBJECT_ITEM(root, "zones");
    num_zones = SAFE_CJSON_GET_ARRAY_SIZE(zones_json);
    if (num_zones > MAX_ZONES) {
        log_error("Exceed maximum zone number");
        err = -1;
        goto err_out;
    }

    // Match zone information
    for (int i = 0; i < num_zones; i++) {
        cJSON *zone_json = SAFE_CJSON_GET_ARRAY_ITEM(zones_json, i);
        cJSON *zone_id_json = SAFE_CJSON_GET_OBJECT_ITEM(zone_json, "id");
        cJSON *memory_region_json =
            SAFE_CJSON_GET_OBJECT_ITEM(zone_json, "memory_region");
        cJSON *devices_json = SAFE_CJSON_GET_OBJECT_ITEM(zone_json, "devices");
        zone_id = zone_id_json->valueint;
        if (zone_id >= MAX_ZONES) {
            log_error("Exceed maximum zone number");
            err = -1;
            goto err_out;
        }
        int num_mems = SAFE_CJSON_GET_ARRAY_SIZE(memory_region_json);

        // Memory regions
        for (int j = 0; j < num_mems; j++) {
            cJSON *mem_json = SAFE_CJSON_GET_ARRAY_ITEM(memory_region_json, j);
            virt_addr = (void *)strtoul(
                SAFE_CJSON_GET_OBJECT_ITEM(mem_json, "virt_addr")->valuestring,
                NULL, 16);
            zone0_ipa = (void *)strtoul(
                SAFE_CJSON_GET_OBJECT_ITEM(mem_json, "phys_addr")->valuestring,
                NULL, 16);
            mem_size = strtoul(
                SAFE_CJSON_GET_OBJECT_ITEM(mem_json, "size")->valuestring, NULL,
                16);

            // We only need to store the memory region that is not root zone's
            if (zone_id != 0) {
                zone_mem[zone_id][j][VIRT_ADDR] = (uintptr_t)virt_addr;
                zone_mem[zone_id][j][ZONE0_IPA] = (uintptr_t)zone0_ipa;
                zone_mem[zone_id][j][MEM_SIZE] = mem_size;
                // Currently, we use 1:1 mapping for zone0 and zonex
                zone_mem[zone_id][j][ZONEX_IPA] = (uintptr_t)zone0_ipa;
            }
        }

        // Devices
        num_devices = SAFE_CJSON_GET_ARRAY_SIZE(devices_json);
        for (int j = 0; j < num_devices; j++) {
            cJSON *device_json = SAFE_CJSON_GET_ARRAY_ITEM(devices_json, j);
            if (create_virtio_device_from_json(device_json, zone_id) != 0) {
                log_error("failed to create virtio device from json");
                err = -1;
                goto err_out;
            }
        }
    }

    free(buffer);
    SAFE_CJSON_DELETE(root);
    return 0;

err_out:
    free(buffer);
    SAFE_CJSON_DELETE(root);
    return err;
}

/// @brief Initialize the virtio backend.
/// @param device_path The path to the hvisor device (e.g., /dev/hvisor).
/// @return 0 on success, -1 on failure.
int virtio_init(const char *device_path) {
    int ret;
    log_info("virtio backend init...");

    if (device_path == NULL) {
        log_error("device path is NULL");
        return -1;
    }

    ko_fd = open(device_path, O_RDWR);
    if (ko_fd < 0) {
        log_error("open %s failed", device_path);
        return -1;
    }

    virtio_bridge = (volatile struct virtio_bridge *)mmap(
        NULL, MMAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, ko_fd, 0);
    if (virtio_bridge == MAP_FAILED) {
        log_error("mmap failed");
        close(ko_fd);
        return -1;
    }
    virtio_bridge->req_front = 0;
    virtio_bridge->res_rear = 0;

    virtio_irq_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (virtio_irq_fd < 0) {
        log_error("eventfd failed");
        return -1;
    }

    log_info("virtio irq fd is %d", virtio_irq_fd);

    ret = ioctl(ko_fd, HVISOR_SET_EVENTFD, virtio_irq_fd);
    if (ret < 0) {
        log_error("ioctl HVISOR_SET_EVENTFD failed");
        return -1;
    }

    // Register event handlers to io_uring monitor
    // Use persistent poll event for virtio irq
    virtio_enable_irq_poll();

    // Register signal handler for SIGTERM and SIGINT
    int sig_fd;
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
        log_error("sigprocmask failed");
        return -1;
    }

    sig_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (sig_fd == -1) {
        log_error("signalfd failed");
        return -1;
    }

    sig_poll_event = (struct poll_event){
        .base = {.type = EVENT_TYPE_POLL},
        .fd = sig_fd,
        .epoll_type = POLLIN,
        .handler = virtio_sig_handler,
        .param = NULL,
        .active = false,
    };
    enable_event_poll(&sig_poll_event);

    log_info("virtio backend init success");
    return 0;
}

/// @brief Start the virtio backend (entry point).
/// @param argc Argument count.
/// @param argv Argument vector.
/// @return 0 on success, 1 on failure.
int virtio_start(int argc, char *argv[]) {
    char *config_path = NULL;
    char *device_path = "/dev/hvisor";

    int opt;
    while ((opt = getopt(argc, argv, "c:d:h")) != -1) {
        switch (opt) {
        case 'c':
            config_path = optarg;
            break;
        case 'd':
            device_path = optarg;
            break;
        case 'h':
            printf("Usage: %s -c <config_path> [-d <device_path>]\n", argv[0]);
            return 0;
        default:
            fprintf(stderr, "Usage: %s -c <config_path> [-d <device_path>]\n",
                    argv[0]);
            return 1;
        }
    }

    if (config_path == NULL) {
        log_error("config path is NULL");
        fprintf(stderr, "Usage: %s -c <config_path> [-d <device_path>]\n",
                argv[0]);
        return 1;
    }

    initialize_log();

    if (init_event_monitor() < 0) {
        log_error("init_event_monitor failed");
        return 1;
    }

    if (virtio_init(device_path) < 0) {
        log_error("virtio_init failed");
        return 1;
    }

    if (virtio_start_from_json(config_path) < 0) {
        log_error("virtio_start_from_json failed");
        return 1;
    }

    log_info("virtio backend start loop...");
    run_event_loop();

    return 0;
}
