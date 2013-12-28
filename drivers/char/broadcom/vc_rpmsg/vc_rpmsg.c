/*
 * Copyright (C) 2013 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/dma-mapping.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/rpmsg.h>
#include <linux/slab.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_ring.h>

#include "debug_sym.h"
#include "mach/vc_mem.h"
#include "mach/vc_rpmsg.h"

/*
 * Latest vc_rpmsg protocol version supported by this driver.
 * This should be incremented whenever a change is made to VC or the kernel,
 * that makes new kernels incompatible with old VCs or new VCs incompatible
 * with old kernels. Ideally, new VC/kernel code should detect that the other
 * side is an old version, and fall back to some compatible behaviour. If
 * that is not possible, VC_RPMSG_VERSION_MIN should be updated to match
 * VC_RPMSG_VERSION.
 */
#define VC_RPMSG_VERSION 1
#define VC_RPMSG_VERSION_MIN 1

/* This must match the value in virtio_rpmsg_bus.c */
#define RPMSG_NUM_BUFS (512)

struct vc_rpmsg_vring {
	void *va;
	int len;
	u32 align;
	struct vc_rpmsg_device *vcdev;
	struct virtqueue *vq;
};

struct vc_rpmsg_device {
	struct virtio_device vdev;
	struct virtio_rpmsg_config config;
	u8 status;
	struct vc_rpmsg_vring vring[2];

	/* Maximum version supported by both kernel and VC */
	int32_t version;

	void __iomem *rpmsg_vrings;
	void __iomem *rpmsg_buffers;
	size_t rpmsg_vrings_size;
	size_t rpmsg_buffers_size;
};

#define to_vcdev(vd) container_of(vd, struct vc_rpmsg_device, vdev)

static void vc_rpmsg_get(struct virtio_device *vdev, unsigned offset,
			void *buf, unsigned len)
{
	struct device *dev = &vdev->dev;
	struct vc_rpmsg_device *vcdev = to_vcdev(vdev);

	dev_dbg(dev, "%s %d %p %d\n", __func__, offset, buf, len);

	memcpy(buf, (uint8_t *)&vcdev->config + offset, len);
}

static void vc_rpmsg_set(struct virtio_device *vdev, unsigned offset,
			const void *buf, unsigned len)
{
	struct device *dev = &vdev->dev;

	dev_dbg(dev, "%s %d %p %d\n", __func__, offset, buf, len);
}

/*
 * get_status/set_status/reset can't use dev_dbg as they are
 * called before vcdev->dev is set up.
 */

static u8 vc_rpmsg_get_status(struct virtio_device *vdev)
{
	pr_debug("%s = 0x%x\n", __func__, to_vcdev(vdev)->status);
	return to_vcdev(vdev)->status;
}

static void vc_rpmsg_set_status(struct virtio_device *vdev, u8 status)
{
	pr_debug("%s 0x%x\n", __func__, status);
	to_vcdev(vdev)->status = status;
}

static void vc_rpmsg_reset(struct virtio_device *vdev)
{
	pr_debug("%s\n", __func__);
	to_vcdev(vdev)->status = 0;
}

/*
 * "Allocate" a vring by returning the statically-allocated-by-VC memory.
 * (This should eventually be replaced with something like ion allocation.)
 */
static int vc_rpmsg_alloc_vring(struct vc_rpmsg_device *vcdev, int i)
{
	struct device *dev = &vcdev->vdev.dev;
	struct vc_rpmsg_vring *vring = &vcdev->vring[i];
	void *va;
	int size;

	vring->len = RPMSG_NUM_BUFS / 2;
	vring->align = PAGE_SIZE;
	vring->vcdev = vcdev;

	/* Actual size of vring (in bytes) */
	size = PAGE_ALIGN(vring_size(vring->len, vring->align));

	if (size * (i + 1) > vcdev->rpmsg_vrings_size) {
		dev_err(dev, "rpmsg_vrings too small (%d total; need %d per vring)",
			     (int)vcdev->rpmsg_vrings_size, size);
		return -ENOMEM;
	}

	/*
	 * Get the memory for the vring (statically allocated on VC). Also
	 * drop the __iomem, since we assume ioremap_nocache on ARM returns
	 * pointers that are directly usable as kernel virtual addresses.
	 */
	va = (void *)vcdev->rpmsg_vrings + size * i;

	dev_dbg(dev, "vring%d: va=%p size=0x%x\n", i, va, size);

	vring->va = va;

	memset(vring->va, 0, vring_size(vring->len, vring->align));

	return 0;
}

static void vc_rpmsg_free_vring(struct vc_rpmsg_vring *vring)
{
	/* Nothing to do here since the memory is statically allocated */
}

static void vc_rpmsg_virtio_notify_rx(struct virtqueue *vq)
{
	struct vc_rpmsg_vring *vring = vq->priv;
	struct device *dev = &vring->vcdev->vdev.dev;
	dev_dbg(dev, "%s\n", __func__);
	vc_rpmsg_doorbell_signal_rx();
}

static void vc_rpmsg_virtio_notify_tx(struct virtqueue *vq)
{
	struct vc_rpmsg_vring *vring = vq->priv;
	struct device *dev = &vring->vcdev->vdev.dev;
	dev_dbg(dev, "%s\n", __func__);
	vc_rpmsg_doorbell_signal_tx();
}

static struct virtqueue *vc_rpmsg_find_vq(struct virtio_device *vdev,
					  unsigned id,
					  void (*callback)
						  (struct virtqueue *vq),
					  const char *name)
{
	struct device *dev = &vdev->dev;
	struct vc_rpmsg_device *vcdev = to_vcdev(vdev);
	struct vc_rpmsg_vring *vring;
	struct virtqueue *vq;
	int ret;
	void (*notify)(struct virtqueue *);

	dev_dbg(dev, "%s id=%d cb=%p \"%s\"\n", __func__, id, callback, name);

	if (id >= ARRAY_SIZE(vcdev->vring))
		return ERR_PTR(-EINVAL);

	ret = vc_rpmsg_alloc_vring(vcdev, id);
	if (ret)
		return ERR_PTR(ret);

	vring = &vcdev->vring[id];

	if (id == 0)
		notify = vc_rpmsg_virtio_notify_rx;
	else
		notify = vc_rpmsg_virtio_notify_tx;

	/*
	 * Create the new vq, and tell virtio we're not interested in
	 * the 'weak' smp barriers, since we're talking with a real device.
	 */
	vq = vring_new_virtqueue(0, vring->len, vring->align, vdev, false,
			vring->va, notify, callback, name);
	if (!vq) {
		dev_err(dev, "vring_new_virtqueue \"%s\" failed\n", name);
		vc_rpmsg_free_vring(vring);
		return ERR_PTR(-ENOMEM);
	}

	vq->priv = vring;
	vring->vq = vq;

	return vq;
}

static void vc_rpmsg_del_vqs(struct virtio_device *vdev)
{
	struct device *dev = &vdev->dev;
	struct virtqueue *vq, *n;

	dev_dbg(dev, "%s\n", __func__);

	list_for_each_entry_safe(vq, n, &vdev->vqs, list) {
		struct vc_rpmsg_vring *vring = vq->priv;
		vring_del_virtqueue(vq);
		vc_rpmsg_free_vring(vring);
	}
}

static int vc_rpmsg_find_vqs(struct virtio_device *vdev, unsigned nvqs,
		struct virtqueue *vqs[], vq_callback_t *callbacks[],
		const char *names[])
{
	struct device *dev = &vdev->dev;
	int i, ret;

	dev_dbg(dev, "%s %d\n", __func__, nvqs);

	if (nvqs != 2) {
		dev_err(dev, "unexpected nvqs=%d\n", nvqs);
		return -EINVAL;
	}

	for (i = 0; i < nvqs; ++i) {
		vqs[i] = vc_rpmsg_find_vq(vdev, i, callbacks[i], names[i]);
		if (IS_ERR(vqs[i])) {
			ret = PTR_ERR(vqs[i]);
			goto error;
		}
	}

	return 0;

error:
	vc_rpmsg_del_vqs(vdev);
	return ret;
}

static u32 vc_rpmsg_get_features(struct virtio_device *vdev)
{
	struct device *dev = &vdev->dev;

	dev_dbg(dev, "%s\n", __func__);

	return (1 << VIRTIO_RPMSG_F_NS) | (1 << VIRTIO_RPMSG_F_BUFS_ALLOC);
}

static void vc_rpmsg_finalize_features(struct virtio_device *vdev)
{
	struct device *dev = &vdev->dev;

	dev_dbg(dev, "%s\n", __func__);

	/* Give virtio_ring a chance to accept features */
	vring_transport_features(vdev);
}

static struct virtio_config_ops vc_rpmsg_config_ops = {
	.get_features = vc_rpmsg_get_features,
	.finalize_features = vc_rpmsg_finalize_features,
	.get = vc_rpmsg_get,
	.set = vc_rpmsg_set,
	.get_status = vc_rpmsg_get_status,
	.set_status = vc_rpmsg_set_status,
	.reset = vc_rpmsg_reset,
	.find_vqs = vc_rpmsg_find_vqs,
	.del_vqs = vc_rpmsg_del_vqs,
};

static void vc_rpmsg_vdev_release(struct device *dev)
{
	struct virtio_device *vdev = dev_to_virtio(dev);
	struct vc_rpmsg_device *vcdev = to_vcdev(vdev);

	dev_dbg(dev, "%s\n", __func__);

	if (vcdev->rpmsg_vrings)
		iounmap(vcdev->rpmsg_vrings);
	if (vcdev->rpmsg_buffers)
		iounmap(vcdev->rpmsg_buffers);

	kfree(vcdev);
}

static int read_vc_debug_var_ptr(struct vc_mem_access_handle *handle,
				 const char *symbol,
				 void __iomem **buf, size_t *bufsize)
{
	VC_MEM_ADDR_T vc_mem_addr;
	size_t vc_mem_size;
	unsigned long vc_map_addr;
	void __iomem *map_addr;

	if (!LookupVideoCoreSymbol(handle, symbol,
			&vc_mem_addr, &vc_mem_size)) {
		pr_err("failed to find VC symbol \"%s\"\n", symbol);
		return -ENOENT;
	}

	vc_map_addr = (unsigned long)vc_mem_addr & VC_MEM_TO_ARM_ADDR_MASK;
	vc_map_addr += mm_vc_mem_phys_addr;
	map_addr = ioremap_nocache(vc_map_addr, vc_mem_size);

	pr_debug("ioremapped \"%s\" to %p (VC phys %x, ARM phys %lx, size %zu)\n",
		symbol, map_addr, vc_mem_addr, vc_map_addr, vc_mem_size);

	if (map_addr == NULL) {
		pr_err("failed to ioremap \"%s\" (VC phys %x, ARM phys %lx, size %zu)\n",
			symbol, vc_mem_addr, vc_map_addr, vc_mem_size);
		return -ENOMEM;
	}

	*buf = map_addr;
	*bufsize = vc_mem_size;

	return 0;
}

static int read_vc_debug_var(struct vc_mem_access_handle *handle,
			     const char *symbol,
			     void *buf, size_t bufsize)
{
	VC_MEM_ADDR_T vc_mem_addr;
	size_t vc_mem_size;

	if (!LookupVideoCoreSymbol(handle, symbol,
			&vc_mem_addr, &vc_mem_size)) {
		pr_err("failed to find VC symbol \"%s\"\n", symbol);
		return -ENOENT;
	}

	if (bufsize > vc_mem_size) {
		pr_err("cannot read %zu bytes from VC symbol \"%s\" (size %zu)\n",
			bufsize, symbol, vc_mem_size);
		return -EINVAL;
	}

	if (!ReadVideoCoreMemory(handle, buf, vc_mem_addr, bufsize)) {
		pr_err("failed to read to VC symbol \"%s\"\n", symbol);
		return -EIO;
	}

	return 0;
}

static int write_vc_debug_var(struct vc_mem_access_handle *handle,
			      const char *symbol,
			      void *buf, size_t bufsize)
{
	VC_MEM_ADDR_T vc_mem_addr;
	size_t vc_mem_size;

	if (!LookupVideoCoreSymbol(handle, symbol,
			&vc_mem_addr, &vc_mem_size)) {
		pr_err("failed to find VC symbol \"%s\"\n", symbol);
		return -ENOENT;
	}

	if (bufsize > vc_mem_size) {
		pr_err("cannot write %zu bytes to VC symbol \"%s\" (size %zu)\n",
			bufsize, symbol, vc_mem_size);
		return -EINVAL;
	}

	if (!WriteVideoCoreMemory(handle, buf, vc_mem_addr, bufsize)) {
		pr_err("failed to write to VC symbol \"%s\"\n", symbol);
		return -EIO;
	}

	return 0;
}

static int vc_rpmsg_read_vc_config(struct vc_rpmsg_device *vcdev)
{
	struct vc_mem_access_handle *mem_hndl = NULL;
	int32_t rpmsg_version;
	int32_t rpmsg_version_min;
	void __iomem *rpmsg_vrings = NULL;
	void __iomem *rpmsg_buffers = NULL;
	size_t rpmsg_vrings_size;
	size_t rpmsg_buffers_size;
	struct scatterlist sg;
	u64 rpmsg_buffers_phys;
	int err = -ENOENT;

	if (OpenVideoCoreMemory(&mem_hndl) != 0)
		goto out;

	err = read_vc_debug_var(mem_hndl, "rpmsg_version",
			&rpmsg_version, sizeof(rpmsg_version));
	if (err)
		goto out;

	err = read_vc_debug_var(mem_hndl, "rpmsg_version_min",
			&rpmsg_version_min, sizeof(rpmsg_version_min));
	if (err)
		goto out;

	if (rpmsg_version < VC_RPMSG_VERSION_MIN) {
		pr_err("vc_rpmsg: VideoCore firmware protocol version %d too old for this kernel (version %d, min %d)",
				rpmsg_version, VC_RPMSG_VERSION,
				VC_RPMSG_VERSION_MIN);
		err = -EINVAL;
		goto out;
	}

	if (VC_RPMSG_VERSION < rpmsg_version_min) {
		pr_err("vc_rpmsg: Kernel protocol version %d too old for this VideoCore firmware (version %d, min %d)",
				VC_RPMSG_VERSION, rpmsg_version,
				rpmsg_version_min);
		err = -EINVAL;
		goto out;
	}

	vcdev->version = min(rpmsg_version, VC_RPMSG_VERSION);
	err = write_vc_debug_var(mem_hndl, "rpmsg_version_common",
			&vcdev->version, sizeof(vcdev->version));
	if (err)
		goto out;

	err = read_vc_debug_var_ptr(mem_hndl, "rpmsg_vrings",
			&rpmsg_vrings, &rpmsg_vrings_size);
	if (err)
		goto out;

	err = read_vc_debug_var_ptr(mem_hndl, "rpmsg_buffers",
			&rpmsg_buffers, &rpmsg_buffers_size);
	if (err)
		goto out;

	/*
	 * Tell VC how to map from the kernel's physical addresses onto
	 * VC's address space
	 */
	sg_init_one(&sg, (void *)rpmsg_buffers, rpmsg_buffers_size);
	rpmsg_buffers_phys = sg_phys(&sg);
	err = write_vc_debug_var(mem_hndl, "rpmsg_buffers_phys",
			&rpmsg_buffers_phys, sizeof(rpmsg_buffers_phys));
	if (err)
		goto out;

	pr_debug("%s: vrings=%p(%zu) buffers=%p(%zu) buffers_phys=%llx\n",
			 __func__,
			rpmsg_vrings, rpmsg_vrings_size,
			rpmsg_buffers, rpmsg_buffers_size,
			(unsigned long long)rpmsg_buffers_phys);

	vcdev->rpmsg_vrings = rpmsg_vrings;
	vcdev->rpmsg_vrings_size = rpmsg_vrings_size;
	vcdev->rpmsg_buffers = rpmsg_buffers;
	vcdev->rpmsg_buffers_size = rpmsg_buffers_size;
	err = 0;

out:
	if (err)
		pr_err("%s: failed to read VC config\n", __func__);

	if (mem_hndl)
		CloseVideoCoreMemory(mem_hndl);

	if (err && rpmsg_vrings)
		iounmap(rpmsg_vrings);
	if (err && rpmsg_buffers)
		iounmap(rpmsg_buffers);

	return err;
}

/*
 * "Allocate" buffers by returning the statically-allocated-by-VC memory.
 */
static void *vc_rpmsg_bufs_alloc(struct virtio_device *vdev, size_t size)
{
	struct device *dev = &vdev->dev;
	struct vc_rpmsg_device *vcdev = to_vcdev(vdev);

	if (size > vcdev->rpmsg_buffers_size) {
		dev_err(dev, "%s: size %zu > rpmsg_buffers_size %zu",
			     __func__, size, vcdev->rpmsg_buffers_size);
		return NULL;
	}

	return (void *)vcdev->rpmsg_buffers;
}

static void vc_rpmsg_bufs_free(struct virtio_device *vdev, void *desc)
{
}

static atomic_t vc_rpmsg_interrupt_rx = ATOMIC_INIT(0);
static atomic_t vc_rpmsg_interrupt_tx = ATOMIC_INIT(0);

/* Runs in hard interrupt context */
static irqreturn_t vc_rpmsg_interrupt(int irq, void *dev_id)
{
	uint32_t status;

	status = vc_rpmsg_doorbell_status();

	if ((status & VC_RPMSG_DOORBELL_MASK) == 0)
		return IRQ_NONE;

	if (status & (1 << VC_RPMSG_IPC_DOORBELL_HOST_RX_TO_ARM)) {
		vc_rpmsg_doorbell_clear(VC_RPMSG_IPC_DOORBELL_HOST_RX_TO_ARM);
		atomic_set(&vc_rpmsg_interrupt_rx, 1);
	}

	if (status & (1 << VC_RPMSG_IPC_DOORBELL_HOST_TX_TO_ARM)) {
		vc_rpmsg_doorbell_clear(VC_RPMSG_IPC_DOORBELL_HOST_TX_TO_ARM);
		atomic_set(&vc_rpmsg_interrupt_tx, 1);
	}

	return IRQ_WAKE_THREAD;
}

/* Runs in handler thread, so it can safely call vring_interrupt */
static irqreturn_t vc_rpmsg_interrupt_thread(int irq, void *dev_id)
{
	struct vc_rpmsg_device *vcdev = dev_id;

	if (!vcdev->vring[0].vq || !vcdev->vring[1].vq) {
		/*
		 * This shouldn't happen unless VC triggers an interrupt
		 * before we told it we were ready
		 */
		pr_warn("%s: interrupt before vqs set up", __func__);
		return IRQ_HANDLED;
	}

	if (atomic_cmpxchg(&vc_rpmsg_interrupt_rx, 1, 0))
		vring_interrupt(irq, vcdev->vring[0].vq);

	if (atomic_cmpxchg(&vc_rpmsg_interrupt_tx, 1, 0))
		vring_interrupt(irq, vcdev->vring[1].vq);

	return IRQ_HANDLED;
}

static struct device *vc_rpmsg_root;

static struct vc_rpmsg_device *vc_rpmsg_vcdev;

static int __init vc_rpmsg_init(void)
{
	int err;

	pr_info("vc_rpmsg: loading\n");

	vc_rpmsg_root = root_device_register("vc_rpmsg");
	if (IS_ERR(vc_rpmsg_root)) {
		pr_err("%s: could not register vc_rpmsg root\n", __func__);
		err = PTR_ERR(vc_rpmsg_root);
		vc_rpmsg_root = NULL;
		goto fail;
	}

	vc_rpmsg_vcdev = kzalloc(sizeof(*vc_rpmsg_vcdev), GFP_KERNEL);
	if (!vc_rpmsg_vcdev) {
		err = -ENOMEM;
		goto fail;
	}

	vc_rpmsg_doorbell_init();

	err = vc_rpmsg_read_vc_config(vc_rpmsg_vcdev);
	if (err)
		goto fail_after_vcdev;

	vc_rpmsg_vcdev->config.bufs_alloc = vc_rpmsg_bufs_alloc;
	vc_rpmsg_vcdev->config.bufs_free = vc_rpmsg_bufs_free;
	vc_rpmsg_vcdev->vdev.dev.parent = vc_rpmsg_root;
	vc_rpmsg_vcdev->vdev.dev.release = vc_rpmsg_vdev_release;
	vc_rpmsg_vcdev->vdev.id.device = VIRTIO_ID_RPMSG;
	vc_rpmsg_vcdev->vdev.config = &vc_rpmsg_config_ops;

	/*
	 * Set up interrupt handlers before registering the device, so we
	 * don't miss any messages sent by VC before register_virtio_device
	 * returns
	 */
	err = request_threaded_irq(VC_RPMSG_IRQ, vc_rpmsg_interrupt,
			vc_rpmsg_interrupt_thread, IRQF_SHARED,
			"vc_rpmsg_irq", vc_rpmsg_vcdev);
	if (err) {
		pr_err("%s: failed to request doorbell irq\n", __func__);
		goto fail_after_vcdev;
	}

	err = register_virtio_device(&vc_rpmsg_vcdev->vdev);
	if (err) {
		pr_err("%s: failed to register vc_rpmsg\n", __func__);
		goto fail_after_irq;
	}

	return 0;

fail_after_irq:
	free_irq(VC_RPMSG_IRQ, vc_rpmsg_vcdev);
fail_after_vcdev:
	kfree(vc_rpmsg_vcdev);
fail:
	if (vc_rpmsg_root)
		root_device_unregister(vc_rpmsg_root);
	return err;
}

static void __exit vc_rpmsg_exit(void)
{
	/*
	 * Disable interrupts before unregistering the device, to avoid races
	 * if an interrupt is received while the virtqs are being deleted
	 */
	free_irq(VC_RPMSG_IRQ, vc_rpmsg_vcdev);

	unregister_virtio_device(&vc_rpmsg_vcdev->vdev);

	root_device_unregister(vc_rpmsg_root);
}

module_init(vc_rpmsg_init);
module_exit(vc_rpmsg_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Broadcom Corporation");
