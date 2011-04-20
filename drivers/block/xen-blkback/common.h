/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef __BLKIF__BACKEND__COMMON_H__
#define __BLKIF__BACKEND__COMMON_H__

#include <linux/version.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/io.h>
#include <asm/setup.h>
#include <asm/pgalloc.h>
#include <asm/hypervisor.h>
#include <xen/blkif.h>
#include <xen/grant_table.h>
#include <xen/xenbus.h>

#define DPRINTK(_f, _a...)			\
	pr_debug("(file=%s, line=%d) " _f,	\
		 __FILE__ , __LINE__ , ## _a)

struct vbd {
	blkif_vdev_t   handle;      /* what the domain refers to this vbd as */
	unsigned char  readonly;    /* Non-zero -> read-only */
	unsigned char  type;        /* VDISK_xxx */
	u32            pdevice;     /* phys device that this vbd maps to */
	struct block_device *bdev;
	sector_t       size;        /* Cached size parameter */
};

struct backend_info;

struct blkif_st {
	/* Unique identifier for this interface. */
	domid_t           domid;
	unsigned int      handle;
	/* Physical parameters of the comms window. */
	unsigned int      irq;
	/* Comms information. */
	enum blkif_protocol blk_protocol;
	union blkif_back_rings blk_rings;
	struct vm_struct *blk_ring_area;
	/* The VBD attached to this interface. */
	struct vbd        vbd;
	/* Back pointer to the backend_info. */
	struct backend_info *be;
	/* Private fields. */
	spinlock_t       blk_ring_lock;
	atomic_t         refcnt;

	wait_queue_head_t   wq;
	/* One thread per one blkif. */
	struct task_struct  *xenblkd;
	unsigned int        waiting_reqs;

	/* statistics */
	unsigned long       st_print;
	int                 st_rd_req;
	int                 st_wr_req;
	int                 st_oo_req;
	int                 st_br_req;
	int                 st_rd_sect;
	int                 st_wr_sect;

	wait_queue_head_t waiting_to_free;

	grant_handle_t shmem_handle;
	grant_ref_t    shmem_ref;
};


#define vbd_sz(_v)	((_v)->bdev->bd_part ? \
			 (_v)->bdev->bd_part->nr_sects : \
			  get_capacity((_v)->bdev->bd_disk))

#define xen_blkif_get(_b) (atomic_inc(&(_b)->refcnt))
#define xen_blkif_put(_b)				\
	do {						\
		if (atomic_dec_and_test(&(_b)->refcnt))	\
			wake_up(&(_b)->waiting_to_free);\
	} while (0)

struct phys_req {
	unsigned short       dev;
	unsigned short       nr_sects;
	struct block_device *bdev;
	blkif_sector_t       sector_number;
};
int xen_blkif_interface_init(void);

int xen_blkif_xenbus_init(void);

irqreturn_t xen_blkif_be_int(int irq, void *dev_id);
int xen_blkif_schedule(void *arg);

int xen_blkbk_barrier(struct xenbus_transaction xbt,
			struct backend_info *be, int state);

struct xenbus_device *xen_blkbk_xenbus(struct backend_info *be);

#endif /* __BLKIF__BACKEND__COMMON_H__ */
