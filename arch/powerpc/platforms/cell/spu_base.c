/*
 * Low-level SPU handling
 *
 * (C) Copyright IBM Deutschland Entwicklung GmbH 2005
 *
 * Author: Arnd Bergmann <arndb@de.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#undef DEBUG

#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/mutex.h>
#include <linux/linux_logo.h>
#include <asm/spu.h>
#include <asm/spu_priv1.h>
#include <asm/xmon.h>
#include <asm/prom.h>
#include "spu_priv1_mmio.h"

const struct spu_management_ops *spu_management_ops;
EXPORT_SYMBOL_GPL(spu_management_ops);

const struct spu_priv1_ops *spu_priv1_ops;
EXPORT_SYMBOL_GPL(spu_priv1_ops);

struct cbe_spu_info cbe_spu_info[MAX_NUMNODES];
EXPORT_SYMBOL_GPL(cbe_spu_info);

/*
 * Protects cbe_spu_info and spu->number.
 */
static DEFINE_SPINLOCK(spu_lock);

/*
 * List of all spus in the system.
 *
 * This list is iterated by callers from irq context and callers that
 * want to sleep.  Thus modifications need to be done with both
 * spu_full_list_lock and spu_full_list_mutex held, while iterating
 * through it requires either of these locks.
 *
 * In addition spu_full_list_lock protects all assignmens to
 * spu->mm.
 */
static LIST_HEAD(spu_full_list);
static DEFINE_SPINLOCK(spu_full_list_lock);
static DEFINE_MUTEX(spu_full_list_mutex);

void spu_invalidate_slbs(struct spu *spu)
{
	struct spu_priv2 __iomem *priv2 = spu->priv2;

	if (spu_mfc_sr1_get(spu) & MFC_STATE1_RELOCATE_MASK)
		out_be64(&priv2->slb_invalidate_all_W, 0UL);
}
EXPORT_SYMBOL_GPL(spu_invalidate_slbs);

/* This is called by the MM core when a segment size is changed, to
 * request a flush of all the SPEs using a given mm
 */
void spu_flush_all_slbs(struct mm_struct *mm)
{
	struct spu *spu;
	unsigned long flags;

	spin_lock_irqsave(&spu_full_list_lock, flags);
	list_for_each_entry(spu, &spu_full_list, full_list) {
		if (spu->mm == mm)
			spu_invalidate_slbs(spu);
	}
	spin_unlock_irqrestore(&spu_full_list_lock, flags);
}

/* The hack below stinks... try to do something better one of
 * these days... Does it even work properly with NR_CPUS == 1 ?
 */
static inline void mm_needs_global_tlbie(struct mm_struct *mm)
{
	int nr = (NR_CPUS > 1) ? NR_CPUS : NR_CPUS + 1;

	/* Global TLBIE broadcast required with SPEs. */
	__cpus_setall(&mm->cpu_vm_mask, nr);
}

void spu_associate_mm(struct spu *spu, struct mm_struct *mm)
{
	unsigned long flags;

	spin_lock_irqsave(&spu_full_list_lock, flags);
	spu->mm = mm;
	spin_unlock_irqrestore(&spu_full_list_lock, flags);
	if (mm)
		mm_needs_global_tlbie(mm);
}
EXPORT_SYMBOL_GPL(spu_associate_mm);

static int __spu_trap_invalid_dma(struct spu *spu)
{
	pr_debug("%s\n", __FUNCTION__);
	spu->dma_callback(spu, SPE_EVENT_INVALID_DMA);
	return 0;
}

static int __spu_trap_dma_align(struct spu *spu)
{
	pr_debug("%s\n", __FUNCTION__);
	spu->dma_callback(spu, SPE_EVENT_DMA_ALIGNMENT);
	return 0;
}

static int __spu_trap_error(struct spu *spu)
{
	pr_debug("%s\n", __FUNCTION__);
	spu->dma_callback(spu, SPE_EVENT_SPE_ERROR);
	return 0;
}

static void spu_restart_dma(struct spu *spu)
{
	struct spu_priv2 __iomem *priv2 = spu->priv2;

	if (!test_bit(SPU_CONTEXT_SWITCH_PENDING, &spu->flags))
		out_be64(&priv2->mfc_control_RW, MFC_CNTL_RESTART_DMA_COMMAND);
}

static int __spu_trap_data_seg(struct spu *spu, unsigned long ea)
{
	struct spu_priv2 __iomem *priv2 = spu->priv2;
	struct mm_struct *mm = spu->mm;
	u64 esid, vsid, llp;
	int psize;

	pr_debug("%s\n", __FUNCTION__);

	if (test_bit(SPU_CONTEXT_SWITCH_ACTIVE, &spu->flags)) {
		/* SLBs are pre-loaded for context switch, so
		 * we should never get here!
		 */
		printk("%s: invalid access during switch!\n", __func__);
		return 1;
	}
	esid = (ea & ESID_MASK) | SLB_ESID_V;

	switch(REGION_ID(ea)) {
	case USER_REGION_ID:
#ifdef CONFIG_PPC_MM_SLICES
		psize = get_slice_psize(mm, ea);
#else
		psize = mm->context.user_psize;
#endif
		vsid = (get_vsid(mm->context.id, ea) << SLB_VSID_SHIFT) |
				SLB_VSID_USER;
		break;
	case VMALLOC_REGION_ID:
		if (ea < VMALLOC_END)
			psize = mmu_vmalloc_psize;
		else
			psize = mmu_io_psize;
		vsid = (get_kernel_vsid(ea) << SLB_VSID_SHIFT) |
			SLB_VSID_KERNEL;
		break;
	case KERNEL_REGION_ID:
		psize = mmu_linear_psize;
		vsid = (get_kernel_vsid(ea) << SLB_VSID_SHIFT) |
			SLB_VSID_KERNEL;
		break;
	default:
		/* Future: support kernel segments so that drivers
		 * can use SPUs.
		 */
		pr_debug("invalid region access at %016lx\n", ea);
		return 1;
	}
	llp = mmu_psize_defs[psize].sllp;

	out_be64(&priv2->slb_index_W, spu->slb_replace);
	out_be64(&priv2->slb_vsid_RW, vsid | llp);
	out_be64(&priv2->slb_esid_RW, esid);

	spu->slb_replace++;
	if (spu->slb_replace >= 8)
		spu->slb_replace = 0;

	spu_restart_dma(spu);
	spu->stats.slb_flt++;
	return 0;
}

extern int hash_page(unsigned long ea, unsigned long access, unsigned long trap); //XXX
static int __spu_trap_data_map(struct spu *spu, unsigned long ea, u64 dsisr)
{
	pr_debug("%s, %lx, %lx\n", __FUNCTION__, dsisr, ea);

	/* Handle kernel space hash faults immediately.
	   User hash faults need to be deferred to process context. */
	if ((dsisr & MFC_DSISR_PTE_NOT_FOUND)
	    && REGION_ID(ea) != USER_REGION_ID
	    && hash_page(ea, _PAGE_PRESENT, 0x300) == 0) {
		spu_restart_dma(spu);
		return 0;
	}

	if (test_bit(SPU_CONTEXT_SWITCH_ACTIVE, &spu->flags)) {
		printk("%s: invalid access during switch!\n", __func__);
		return 1;
	}

	spu->dar = ea;
	spu->dsisr = dsisr;
	mb();
	spu->stop_callback(spu);
	return 0;
}

static irqreturn_t
spu_irq_class_0(int irq, void *data)
{
	struct spu *spu;

	spu = data;
	spu->class_0_pending = 1;
	spu->stop_callback(spu);

	return IRQ_HANDLED;
}

int
spu_irq_class_0_bottom(struct spu *spu)
{
	unsigned long stat, mask;
	unsigned long flags;

	spu->class_0_pending = 0;

	spin_lock_irqsave(&spu->register_lock, flags);
	mask = spu_int_mask_get(spu, 0);
	stat = spu_int_stat_get(spu, 0);

	stat &= mask;

	if (stat & 1) /* invalid DMA alignment */
		__spu_trap_dma_align(spu);

	if (stat & 2) /* invalid MFC DMA */
		__spu_trap_invalid_dma(spu);

	if (stat & 4) /* error on SPU */
		__spu_trap_error(spu);

	spu_int_stat_clear(spu, 0, stat);
	spin_unlock_irqrestore(&spu->register_lock, flags);

	return (stat & 0x7) ? -EIO : 0;
}
EXPORT_SYMBOL_GPL(spu_irq_class_0_bottom);

static irqreturn_t
spu_irq_class_1(int irq, void *data)
{
	struct spu *spu;
	unsigned long stat, mask, dar, dsisr;

	spu = data;

	/* atomically read & clear class1 status. */
	spin_lock(&spu->register_lock);
	mask  = spu_int_mask_get(spu, 1);
	stat  = spu_int_stat_get(spu, 1) & mask;
	dar   = spu_mfc_dar_get(spu);
	dsisr = spu_mfc_dsisr_get(spu);
	if (stat & 2) /* mapping fault */
		spu_mfc_dsisr_set(spu, 0ul);
	spu_int_stat_clear(spu, 1, stat);
	spin_unlock(&spu->register_lock);
	pr_debug("%s: %lx %lx %lx %lx\n", __FUNCTION__, mask, stat,
			dar, dsisr);

	if (stat & 1) /* segment fault */
		__spu_trap_data_seg(spu, dar);

	if (stat & 2) { /* mapping fault */
		__spu_trap_data_map(spu, dar, dsisr);
	}

	if (stat & 4) /* ls compare & suspend on get */
		;

	if (stat & 8) /* ls compare & suspend on put */
		;

	return stat ? IRQ_HANDLED : IRQ_NONE;
}

static irqreturn_t
spu_irq_class_2(int irq, void *data)
{
	struct spu *spu;
	unsigned long stat;
	unsigned long mask;

	spu = data;
	spin_lock(&spu->register_lock);
	stat = spu_int_stat_get(spu, 2);
	mask = spu_int_mask_get(spu, 2);
	/* ignore interrupts we're not waiting for */
	stat &= mask;
	/*
	 * mailbox interrupts (0x1 and 0x10) are level triggered.
	 * mask them now before acknowledging.
	 */
	if (stat & 0x11)
		spu_int_mask_and(spu, 2, ~(stat & 0x11));
	/* acknowledge all interrupts before the callbacks */
	spu_int_stat_clear(spu, 2, stat);
	spin_unlock(&spu->register_lock);

	pr_debug("class 2 interrupt %d, %lx, %lx\n", irq, stat, mask);

	if (stat & 1)  /* PPC core mailbox */
		spu->ibox_callback(spu);

	if (stat & 2) /* SPU stop-and-signal */
		spu->stop_callback(spu);

	if (stat & 4) /* SPU halted */
		spu->stop_callback(spu);

	if (stat & 8) /* DMA tag group complete */
		spu->mfc_callback(spu);

	if (stat & 0x10) /* SPU mailbox threshold */
		spu->wbox_callback(spu);

	spu->stats.class2_intr++;
	return stat ? IRQ_HANDLED : IRQ_NONE;
}

static int spu_request_irqs(struct spu *spu)
{
	int ret = 0;

	if (spu->irqs[0] != NO_IRQ) {
		snprintf(spu->irq_c0, sizeof (spu->irq_c0), "spe%02d.0",
			 spu->number);
		ret = request_irq(spu->irqs[0], spu_irq_class_0,
				  IRQF_DISABLED,
				  spu->irq_c0, spu);
		if (ret)
			goto bail0;
	}
	if (spu->irqs[1] != NO_IRQ) {
		snprintf(spu->irq_c1, sizeof (spu->irq_c1), "spe%02d.1",
			 spu->number);
		ret = request_irq(spu->irqs[1], spu_irq_class_1,
				  IRQF_DISABLED,
				  spu->irq_c1, spu);
		if (ret)
			goto bail1;
	}
	if (spu->irqs[2] != NO_IRQ) {
		snprintf(spu->irq_c2, sizeof (spu->irq_c2), "spe%02d.2",
			 spu->number);
		ret = request_irq(spu->irqs[2], spu_irq_class_2,
				  IRQF_DISABLED,
				  spu->irq_c2, spu);
		if (ret)
			goto bail2;
	}
	return 0;

bail2:
	if (spu->irqs[1] != NO_IRQ)
		free_irq(spu->irqs[1], spu);
bail1:
	if (spu->irqs[0] != NO_IRQ)
		free_irq(spu->irqs[0], spu);
bail0:
	return ret;
}

static void spu_free_irqs(struct spu *spu)
{
	if (spu->irqs[0] != NO_IRQ)
		free_irq(spu->irqs[0], spu);
	if (spu->irqs[1] != NO_IRQ)
		free_irq(spu->irqs[1], spu);
	if (spu->irqs[2] != NO_IRQ)
		free_irq(spu->irqs[2], spu);
}

static void spu_init_channels(struct spu *spu)
{
	static const struct {
		 unsigned channel;
		 unsigned count;
	} zero_list[] = {
		{ 0x00, 1, }, { 0x01, 1, }, { 0x03, 1, }, { 0x04, 1, },
		{ 0x18, 1, }, { 0x19, 1, }, { 0x1b, 1, }, { 0x1d, 1, },
	}, count_list[] = {
		{ 0x00, 0, }, { 0x03, 0, }, { 0x04, 0, }, { 0x15, 16, },
		{ 0x17, 1, }, { 0x18, 0, }, { 0x19, 0, }, { 0x1b, 0, },
		{ 0x1c, 1, }, { 0x1d, 0, }, { 0x1e, 1, },
	};
	struct spu_priv2 __iomem *priv2;
	int i;

	priv2 = spu->priv2;

	/* initialize all channel data to zero */
	for (i = 0; i < ARRAY_SIZE(zero_list); i++) {
		int count;

		out_be64(&priv2->spu_chnlcntptr_RW, zero_list[i].channel);
		for (count = 0; count < zero_list[i].count; count++)
			out_be64(&priv2->spu_chnldata_RW, 0);
	}

	/* initialize channel counts to meaningful values */
	for (i = 0; i < ARRAY_SIZE(count_list); i++) {
		out_be64(&priv2->spu_chnlcntptr_RW, count_list[i].channel);
		out_be64(&priv2->spu_chnlcnt_RW, count_list[i].count);
	}
}

struct spu *spu_alloc_spu(struct spu *req_spu)
{
	struct spu *spu, *ret = NULL;

	spin_lock(&spu_lock);
	list_for_each_entry(spu, &cbe_spu_info[req_spu->node].free_spus, list) {
		if (spu == req_spu) {
			list_del_init(&spu->list);
			pr_debug("Got SPU %d %d\n", spu->number, spu->node);
			spu_init_channels(spu);
			ret = spu;
			break;
		}
	}
	spin_unlock(&spu_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(spu_alloc_spu);

struct spu *spu_alloc_node(int node)
{
	struct spu *spu = NULL;

	spin_lock(&spu_lock);
	if (!list_empty(&cbe_spu_info[node].free_spus)) {
		spu = list_entry(cbe_spu_info[node].free_spus.next, struct spu,
									list);
		list_del_init(&spu->list);
		pr_debug("Got SPU %d %d\n", spu->number, spu->node);
	}
	spin_unlock(&spu_lock);

	if (spu)
		spu_init_channels(spu);
	return spu;
}
EXPORT_SYMBOL_GPL(spu_alloc_node);

struct spu *spu_alloc(void)
{
	struct spu *spu = NULL;
	int node;

	for (node = 0; node < MAX_NUMNODES; node++) {
		spu = spu_alloc_node(node);
		if (spu)
			break;
	}

	return spu;
}

void spu_free(struct spu *spu)
{
	spin_lock(&spu_lock);
	list_add_tail(&spu->list, &cbe_spu_info[spu->node].free_spus);
	spin_unlock(&spu_lock);
}
EXPORT_SYMBOL_GPL(spu_free);

static int spu_shutdown(struct sys_device *sysdev)
{
	struct spu *spu = container_of(sysdev, struct spu, sysdev);

	spu_free_irqs(spu);
	spu_destroy_spu(spu);
	return 0;
}

struct sysdev_class spu_sysdev_class = {
	set_kset_name("spu"),
	.shutdown = spu_shutdown,
};

int spu_add_sysdev_attr(struct sysdev_attribute *attr)
{
	struct spu *spu;

	mutex_lock(&spu_full_list_mutex);
	list_for_each_entry(spu, &spu_full_list, full_list)
		sysdev_create_file(&spu->sysdev, attr);
	mutex_unlock(&spu_full_list_mutex);

	return 0;
}
EXPORT_SYMBOL_GPL(spu_add_sysdev_attr);

int spu_add_sysdev_attr_group(struct attribute_group *attrs)
{
	struct spu *spu;

	mutex_lock(&spu_full_list_mutex);
	list_for_each_entry(spu, &spu_full_list, full_list)
		sysfs_create_group(&spu->sysdev.kobj, attrs);
	mutex_unlock(&spu_full_list_mutex);

	return 0;
}
EXPORT_SYMBOL_GPL(spu_add_sysdev_attr_group);


void spu_remove_sysdev_attr(struct sysdev_attribute *attr)
{
	struct spu *spu;

	mutex_lock(&spu_full_list_mutex);
	list_for_each_entry(spu, &spu_full_list, full_list)
		sysdev_remove_file(&spu->sysdev, attr);
	mutex_unlock(&spu_full_list_mutex);
}
EXPORT_SYMBOL_GPL(spu_remove_sysdev_attr);

void spu_remove_sysdev_attr_group(struct attribute_group *attrs)
{
	struct spu *spu;

	mutex_lock(&spu_full_list_mutex);
	list_for_each_entry(spu, &spu_full_list, full_list)
		sysfs_remove_group(&spu->sysdev.kobj, attrs);
	mutex_unlock(&spu_full_list_mutex);
}
EXPORT_SYMBOL_GPL(spu_remove_sysdev_attr_group);

static int spu_create_sysdev(struct spu *spu)
{
	int ret;

	spu->sysdev.id = spu->number;
	spu->sysdev.cls = &spu_sysdev_class;
	ret = sysdev_register(&spu->sysdev);
	if (ret) {
		printk(KERN_ERR "Can't register SPU %d with sysfs\n",
				spu->number);
		return ret;
	}

	sysfs_add_device_to_node(&spu->sysdev, spu->node);

	return 0;
}

static int __init create_spu(void *data)
{
	struct spu *spu;
	int ret;
	static int number;
	unsigned long flags;
	struct timespec ts;

	ret = -ENOMEM;
	spu = kzalloc(sizeof (*spu), GFP_KERNEL);
	if (!spu)
		goto out;

	spin_lock_init(&spu->register_lock);
	spin_lock(&spu_lock);
	spu->number = number++;
	spin_unlock(&spu_lock);

	ret = spu_create_spu(spu, data);

	if (ret)
		goto out_free;

	spu_mfc_sdr_setup(spu);
	spu_mfc_sr1_set(spu, 0x33);
	ret = spu_request_irqs(spu);
	if (ret)
		goto out_destroy;

	ret = spu_create_sysdev(spu);
	if (ret)
		goto out_free_irqs;

	spin_lock(&spu_lock);
	list_add(&spu->list, &cbe_spu_info[spu->node].free_spus);
	list_add(&spu->cbe_list, &cbe_spu_info[spu->node].spus);
	cbe_spu_info[spu->node].n_spus++;
	spin_unlock(&spu_lock);

	mutex_lock(&spu_full_list_mutex);
	spin_lock_irqsave(&spu_full_list_lock, flags);
	list_add(&spu->full_list, &spu_full_list);
	spin_unlock_irqrestore(&spu_full_list_lock, flags);
	mutex_unlock(&spu_full_list_mutex);

	spu->stats.util_state = SPU_UTIL_IDLE_LOADED;
	ktime_get_ts(&ts);
	spu->stats.tstamp = timespec_to_ns(&ts);

	INIT_LIST_HEAD(&spu->aff_list);

	goto out;

out_free_irqs:
	spu_free_irqs(spu);
out_destroy:
	spu_destroy_spu(spu);
out_free:
	kfree(spu);
out:
	return ret;
}

static const char *spu_state_names[] = {
	"user", "system", "iowait", "idle"
};

static unsigned long long spu_acct_time(struct spu *spu,
		enum spu_utilization_state state)
{
	struct timespec ts;
	unsigned long long time = spu->stats.times[state];

	/*
	 * If the spu is idle or the context is stopped, utilization
	 * statistics are not updated.  Apply the time delta from the
	 * last recorded state of the spu.
	 */
	if (spu->stats.util_state == state) {
		ktime_get_ts(&ts);
		time += timespec_to_ns(&ts) - spu->stats.tstamp;
	}

	return time / NSEC_PER_MSEC;
}


static ssize_t spu_stat_show(struct sys_device *sysdev, char *buf)
{
	struct spu *spu = container_of(sysdev, struct spu, sysdev);

	return sprintf(buf, "%s %llu %llu %llu %llu "
		      "%llu %llu %llu %llu %llu %llu %llu %llu\n",
		spu_state_names[spu->stats.util_state],
		spu_acct_time(spu, SPU_UTIL_USER),
		spu_acct_time(spu, SPU_UTIL_SYSTEM),
		spu_acct_time(spu, SPU_UTIL_IOWAIT),
		spu_acct_time(spu, SPU_UTIL_IDLE_LOADED),
		spu->stats.vol_ctx_switch,
		spu->stats.invol_ctx_switch,
		spu->stats.slb_flt,
		spu->stats.hash_flt,
		spu->stats.min_flt,
		spu->stats.maj_flt,
		spu->stats.class2_intr,
		spu->stats.libassist);
}

static SYSDEV_ATTR(stat, 0644, spu_stat_show, NULL);

/* Hardcoded affinity idxs for QS20 */
#define SPES_PER_BE 8
static int QS20_reg_idxs[SPES_PER_BE] =   { 0, 2, 4, 6, 7, 5, 3, 1 };
static int QS20_reg_memory[SPES_PER_BE] = { 1, 1, 0, 0, 0, 0, 0, 0 };

static struct spu *spu_lookup_reg(int node, u32 reg)
{
	struct spu *spu;

	list_for_each_entry(spu, &cbe_spu_info[node].spus, cbe_list) {
		if (*(u32 *)get_property(spu_devnode(spu), "reg", NULL) == reg)
			return spu;
	}
	return NULL;
}

static void init_aff_QS20_harcoded(void)
{
	int node, i;
	struct spu *last_spu, *spu;
	u32 reg;

	for (node = 0; node < MAX_NUMNODES; node++) {
		last_spu = NULL;
		for (i = 0; i < SPES_PER_BE; i++) {
			reg = QS20_reg_idxs[i];
			spu = spu_lookup_reg(node, reg);
			if (!spu)
				continue;
			spu->has_mem_affinity = QS20_reg_memory[reg];
			if (last_spu)
				list_add_tail(&spu->aff_list,
						&last_spu->aff_list);
			last_spu = spu;
		}
	}
}

static int of_has_vicinity(void)
{
	struct spu* spu;

	spu = list_entry(cbe_spu_info[0].spus.next, struct spu, cbe_list);
	return of_find_property(spu_devnode(spu), "vicinity", NULL) != NULL;
}

static struct spu *aff_devnode_spu(int cbe, struct device_node *dn)
{
	struct spu *spu;

	list_for_each_entry(spu, &cbe_spu_info[cbe].spus, cbe_list)
		if (spu_devnode(spu) == dn)
			return spu;
	return NULL;
}

static struct spu *
aff_node_next_to(int cbe, struct device_node *target, struct device_node *avoid)
{
	struct spu *spu;
	const phandle *vic_handles;
	int lenp, i;

	list_for_each_entry(spu, &cbe_spu_info[cbe].spus, cbe_list) {
		if (spu_devnode(spu) == avoid)
			continue;
		vic_handles = get_property(spu_devnode(spu), "vicinity", &lenp);
		for (i=0; i < (lenp / sizeof(phandle)); i++) {
			if (vic_handles[i] == target->linux_phandle)
				return spu;
		}
	}
	return NULL;
}

static void init_aff_fw_vicinity_node(int cbe)
{
	struct spu *spu, *last_spu;
	struct device_node *vic_dn, *last_spu_dn;
	phandle avoid_ph;
	const phandle *vic_handles;
	const char *name;
	int lenp, i, added, mem_aff;

	last_spu = list_entry(cbe_spu_info[cbe].spus.next, struct spu, cbe_list);
	avoid_ph = 0;
	for (added = 1; added < cbe_spu_info[cbe].n_spus; added++) {
		last_spu_dn = spu_devnode(last_spu);
		vic_handles = get_property(last_spu_dn, "vicinity", &lenp);

		for (i = 0; i < (lenp / sizeof(phandle)); i++) {
			if (vic_handles[i] == avoid_ph)
				continue;

			vic_dn = of_find_node_by_phandle(vic_handles[i]);
			if (!vic_dn)
				continue;

			name = get_property(vic_dn, "name", NULL);
			if (strcmp(name, "spe") == 0) {
				spu = aff_devnode_spu(cbe, vic_dn);
				avoid_ph = last_spu_dn->linux_phandle;
			}
			else {
				mem_aff = strcmp(name, "mic-tm") == 0;
				spu = aff_node_next_to(cbe, vic_dn, last_spu_dn);
				if (!spu)
					continue;
				if (mem_aff) {
					last_spu->has_mem_affinity = 1;
					spu->has_mem_affinity = 1;
				}
				avoid_ph = vic_dn->linux_phandle;
			}
			list_add_tail(&spu->aff_list, &last_spu->aff_list);
			last_spu = spu;
			break;
		}
	}
}

static void init_aff_fw_vicinity(void)
{
	int cbe;

	/* sets has_mem_affinity for each spu, as long as the
	 * spu->aff_list list, linking each spu to its neighbors
	 */
	for (cbe = 0; cbe < MAX_NUMNODES; cbe++)
		init_aff_fw_vicinity_node(cbe);
}

static int __init init_spu_base(void)
{
	int i, ret = 0;

	for (i = 0; i < MAX_NUMNODES; i++) {
		INIT_LIST_HEAD(&cbe_spu_info[i].spus);
		INIT_LIST_HEAD(&cbe_spu_info[i].free_spus);
	}

	if (!spu_management_ops)
		goto out;

	/* create sysdev class for spus */
	ret = sysdev_class_register(&spu_sysdev_class);
	if (ret)
		goto out;

	ret = spu_enumerate_spus(create_spu);

	if (ret < 0) {
		printk(KERN_WARNING "%s: Error initializing spus\n",
			__FUNCTION__);
		goto out_unregister_sysdev_class;
	}

	if (ret > 0) {
		/*
		 * We cannot put the forward declaration in
		 * <linux/linux_logo.h> because of conflicting session type
		 * conflicts for const and __initdata with different compiler
		 * versions
		 */
		extern const struct linux_logo logo_spe_clut224;

		fb_append_extra_logo(&logo_spe_clut224, ret);
	}

	mutex_lock(&spu_full_list_mutex);
	xmon_register_spus(&spu_full_list);
	crash_register_spus(&spu_full_list);
	mutex_unlock(&spu_full_list_mutex);
	spu_add_sysdev_attr(&attr_stat);

	if (of_has_vicinity()) {
		init_aff_fw_vicinity();
	} else {
		long root = of_get_flat_dt_root();
		if (of_flat_dt_is_compatible(root, "IBM,CPBW-1.0"))
			init_aff_QS20_harcoded();
	}

	return 0;

 out_unregister_sysdev_class:
	sysdev_class_unregister(&spu_sysdev_class);
 out:
	return ret;
}
module_init(init_spu_base);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arnd Bergmann <arndb@de.ibm.com>");
