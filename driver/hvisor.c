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
#include <asm/cacheflush.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/of_reserved_mem.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/eventfd.h>
#include <linux/platform_device.h>

#include "hvisor.h"
#include "zone_config.h"

struct hvisor_device {
    struct miscdevice misc_dev;
    struct virtio_bridge *virtio_bridge;
    int virtio_irq;
    struct task_struct *task;
    struct eventfd_ctx *virtio_irq_ctx;
};

// initial virtio el2 shared region
static int hvisor_init_virtio(struct hvisor_device *dev) {
    int err;
    if (dev->virtio_irq == -1) {
        pr_err("virtio device is not available\n");
        return ENOTTY;
    }
    dev->virtio_bridge = (struct virtio_bridge *)__get_free_pages(GFP_KERNEL, 0);
    if (dev->virtio_bridge == NULL)
        return -ENOMEM;
    SetPageReserved(virt_to_page(dev->virtio_bridge));
    // init device region
    memset(dev->virtio_bridge, 0, sizeof(struct virtio_bridge));
    err = hvisor_call(HVISOR_HC_INIT_VIRTIO, __pa(dev->virtio_bridge), 0);
    if (err)
        return err;
    return 0;
}

// finish virtio req and send result to el2
static int hvisor_finish_req(void) {
    int err;
    err = hvisor_call(HVISOR_HC_FINISH_REQ, 0, 0);
    if (err)
        return err;
    return 0;
}

static int hvisor_zone_start(zone_config_t __user *arg) {
    int err = 0;
    zone_config_t *zone_config = kmalloc(sizeof(zone_config_t), GFP_KERNEL);

    if (zone_config == NULL) {
        pr_err("hvisor.ko: failed to allocate memory for zone_config\n");
    }

    if (copy_from_user(zone_config, arg, sizeof(zone_config_t))) {
        pr_err("hvisor.ko: failed to copy from user\n");
        kfree(zone_config);
        return -EFAULT;
    }

    // flush_cache(zone_config->kernel_load_paddr, zone_config->kernel_size);
    // flush_cache(zone_config->dtb_load_paddr, zone_config->dtb_size);

    pr_info("hvisor.ko: invoking hypercall to start the zone\n");

    err = hvisor_call(HVISOR_HC_START_ZONE, __pa(zone_config),
                      sizeof(zone_config_t));
    kfree(zone_config);
    return err;
}

static int hvisor_config_check(u64 __user *arg) {
    int err = 0;
    u64 *config;
    config = kmalloc(sizeof(u64), GFP_KERNEL);
    err = hvisor_call(HVISOR_HC_CONFIG_CHECK, __pa(config), 0);

    if (err != 0) {
        pr_err("hvisor.ko: failed to get hvisor config\n");
    }

    if (copy_to_user(arg, config, sizeof(u64))) {
        pr_err("hvisor.ko: failed to copy to user\n");
        kfree(config);
        return -EFAULT;
    }

    kfree(config);
    return err;
}

static int hvisor_zone_list(zone_list_args_t __user *arg) {
    int ret;
    zone_info_t *zones;
    zone_list_args_t args;

    /* Copy user provided arguments to kernel space */
    if (copy_from_user(&args, arg, sizeof(zone_list_args_t))) {
        pr_err("hvisor.ko: failed to copy from user\n");
        return -EFAULT;
    }

    zones = kmalloc(args.cnt * sizeof(zone_info_t), GFP_KERNEL);
    memset(zones, 0, args.cnt * sizeof(zone_info_t));

    ret = hvisor_call(HVISOR_HC_ZONE_LIST, __pa(zones), args.cnt);
    if (ret < 0) {
        pr_err("hvisor.ko: failed to get zone list\n");
        goto out;
    }
    // copy result back to user space
    if (copy_to_user(args.zones, zones, ret * sizeof(zone_info_t))) {
        pr_err("hvisor.ko: failed to copy to user\n");
        goto out;
    }
out:
    kfree(zones);
    return ret;
}

static long hvisor_ioctl(struct file *file, unsigned int ioctl,
                         unsigned long arg) {
    int err = 0;
    struct miscdevice *mdev = file->private_data;
    struct hvisor_device *dev = container_of(mdev, struct hvisor_device, misc_dev);

    switch (ioctl) {
    case HVISOR_INIT_VIRTIO:
        err = hvisor_init_virtio(dev);
        dev->task = get_current(); // get hvisor user process
        break;
    case HVISOR_ZONE_START:
        err = hvisor_zone_start((zone_config_t __user *)arg);
        break;
    case HVISOR_ZONE_SHUTDOWN:
        err = hvisor_call(HVISOR_HC_SHUTDOWN_ZONE, arg, 0);
        break;
    case HVISOR_ZONE_LIST:
        err = hvisor_zone_list((zone_list_args_t __user *)arg);
        break;
    case HVISOR_FINISH_REQ:
        err = hvisor_finish_req();
        break;
    case HVISOR_CONFIG_CHECK:
        err = hvisor_config_check((u64 __user *)arg);
        break;
    case HVISOR_SET_EVENTFD: {
        struct eventfd_ctx *ctx = eventfd_ctx_fdget((int)arg);
        if (IS_ERR(ctx)) {
            err = PTR_ERR(ctx);
        } else {
            if (dev->virtio_irq_ctx)
                eventfd_ctx_put(dev->virtio_irq_ctx);
            dev->virtio_irq_ctx = ctx;
        }
        break;
    }
#ifdef LOONGARCH64
    case HVISOR_CLEAR_INJECT_IRQ:
        err = hvisor_call(HVISOR_HC_CLEAR_INJECT_IRQ, 0, 0);
        break;
#endif
    default:
        err = -EINVAL;
        break;
    }
    return err;
}

// Kernel mmap handler
static int hvisor_map(struct file *filp, struct vm_area_struct *vma) {
    unsigned long phys;
    int err;
    struct miscdevice *mdev = filp->private_data;
    struct hvisor_device *dev = container_of(mdev, struct hvisor_device, misc_dev);

    if (vma->vm_pgoff == 0) {
        // virtio_bridge must be aligned to one page.
        phys = virt_to_phys(dev->virtio_bridge);
        // vma->vm_flags |= (VM_IO | VM_LOCKED | (VM_DONTEXPAND | VM_DONTDUMP));
        // Not sure should we add this line.
        err = remap_pfn_range(vma, vma->vm_start, phys >> PAGE_SHIFT,
                              vma->vm_end - vma->vm_start, vma->vm_page_prot);
        if (err)
            return err;
        pr_info("virtio bridge mmap succeed!\n");
    } else {
        size_t size = vma->vm_end - vma->vm_start;
        // TODO: add check for non root memory region.
        // memremap(0x50000000, 0x30000000, MEMREMAP_WB);
        // vm_pgoff is the physical page number.
        // if (!is_reserved_memory(vma->vm_pgoff << PAGE_SHIFT, size)) {
        //     pr_err("The physical address to be mapped is not within the
        //     reserved memory\n"); return -EFAULT;
        // }
        err = remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, size,
                              vma->vm_page_prot);
        if (err)
            return err;
        pr_info("non root region mmap succeed!\n");
    }
    return 0;
}

static const struct file_operations hvisor_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = hvisor_ioctl,
    .compat_ioctl = hvisor_ioctl,
    .mmap = hvisor_map,
};

// Interrupt handler for Virtio device.
static irqreturn_t virtio_irq_handler(int irq, void *dev_id) {
    struct siginfo info;
    struct hvisor_device *dev = (struct hvisor_device *)dev_id;

    if (dev == NULL) {
        return IRQ_NONE;
    }

    memset(&info, 0, sizeof(struct siginfo));
    info.si_signo = SIGHVI;
    info.si_code = SI_QUEUE;
    info.si_int = 1;
    // Send signal SIGHVI to hvisor user task
    if (dev->virtio_irq_ctx) {
        eventfd_signal(dev->virtio_irq_ctx, 1);
    } else if (dev->task != NULL) {
        // pr_info("send signal to hvisor device\n");
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(4, 20, 0))
        if (send_sig_info(SIGHVI, (struct siginfo *)&info, dev->task) < 0) {
            pr_err("Unable to send signal\n");
        }
#else
        if (send_sig_info(SIGHVI, (struct kernel_siginfo *)&info, dev->task) < 0) {
            pr_err("Unable to send signal\n");
        }
#endif
    }
    return IRQ_HANDLED;
}

static int hvisor_probe(struct platform_device *pdev) {
    struct hvisor_device *dev;
    int err;
    const char *dev_name;

    dev = devm_kzalloc(&pdev->dev, sizeof(*dev), GFP_KERNEL);
    if (!dev)
        return -ENOMEM;

    dev->virtio_irq = -1;
    platform_set_drvdata(pdev, dev);

#ifndef X86_64
    dev->virtio_irq = platform_get_irq(pdev, 0);
    if (dev->virtio_irq < 0) {
        return dev->virtio_irq;
    }
#else
    {
        u32 *irq = kmalloc(sizeof(u32), GFP_KERNEL);
        if (!irq) return -ENOMEM;
        err = hvisor_call(HVISOR_HC_GET_VIRTIO_IRQ, __pa(irq), 0);
        dev->virtio_irq = *irq;
        kfree(irq);
    }
#endif

    // Use device id for unique naming if available
    if (pdev->id != -1)
        dev_name = devm_kasprintf(&pdev->dev, GFP_KERNEL, "hvisor%d", pdev->id);
    else
        dev_name = "hvisor";

    dev->misc_dev.minor = MISC_DYNAMIC_MINOR;
    dev->misc_dev.name = dev_name;
    dev->misc_dev.fops = &hvisor_fops;

    err = misc_register(&dev->misc_dev);
    if (err) {
        pr_err("hvisor_misc_register failed for %s!!!\n", dev_name);
        return err;
    }

    err = devm_request_irq(&pdev->dev, dev->virtio_irq, virtio_irq_handler,
                           IRQF_SHARED | IRQF_TRIGGER_RISING, dev_name,
                           dev);
    if (err) {
        misc_deregister(&dev->misc_dev);
        return err;
    }
    
    pr_info("hvisor device %s probed, irq %d\n", dev_name, dev->virtio_irq);
    return 0;
}

static int hvisor_remove(struct platform_device *pdev) {
    struct hvisor_device *dev = platform_get_drvdata(pdev);

    if (dev->virtio_irq_ctx)
        eventfd_ctx_put(dev->virtio_irq_ctx);

    if (dev->virtio_bridge != NULL) {
        ClearPageReserved(virt_to_page(dev->virtio_bridge));
        free_pages((unsigned long)dev->virtio_bridge, 0);
    }

    misc_deregister(&dev->misc_dev);
    return 0;
}

static const struct of_device_id hvisor_dt_ids[] = {
    { .compatible = "hvisor", },
    { /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, hvisor_dt_ids);

static struct platform_driver hvisor_driver = {
    .probe = hvisor_probe,
    .remove = hvisor_remove,
    .driver = {
        .name = "hvisor",
        .of_match_table = hvisor_dt_ids,
    },
};

#ifdef X86_64
static struct platform_device *hvisor_pdev;
#endif

/*
** Module Init function
*/
static int __init hvisor_init(void) {
    int ret;
    ret = platform_driver_register(&hvisor_driver);
    if (ret)
        return ret;

#ifdef X86_64
    // Manually register device for x86 to trigger probe
    hvisor_pdev = platform_device_register_simple("hvisor", 0, NULL, 0);
    if (IS_ERR(hvisor_pdev)) {
        platform_driver_unregister(&hvisor_driver);
        return PTR_ERR(hvisor_pdev);
    }
#endif
    pr_info("hvisor driver initialized\n");
    return 0;
}

/*
** Module Exit function
*/
static void __exit hvisor_exit(void) {
#ifdef X86_64
    platform_device_unregister(hvisor_pdev);
#endif
    platform_driver_unregister(&hvisor_driver);
    pr_info("hvisor exit!!!\n");
}

module_init(hvisor_init);
module_exit(hvisor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KouweiLee <15035660024@163.com>");
MODULE_DESCRIPTION("The hvisor device driver");
MODULE_VERSION("1:0.0");
