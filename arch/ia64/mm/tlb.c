/*
 * TLB support routines.
 *
 * Copyright (C) 1998-2001, 2003 Hewlett-Packard Co
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 *
 * 08/02/00 A. Mallick <asit.k.mallick@intel.com>
 *		Modified RID allocation for SMP
 *          Goutham Rao <goutham.rao@intel.com>
 *              IPI based ptc implementation and A-step IPI implementation.
 * Rohit Seth <rohit.seth@intel.com>
 * Ken Chen <kenneth.w.chen@intel.com>
 * Christophe de Dinechin <ddd@hp.com>: Avoid ptc.e on memory allocation
 * Copyright (C) 2007 Intel Corp
 *	Fenghua Yu <fenghua.yu@intel.com>
 *	Add multiple ptc.g/ptc.ga instruction support in global tlb purge.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/mm.h>
#include <linux/bootmem.h>

#include <asm/delay.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/pal.h>
#include <asm/tlbflush.h>
#include <asm/dma.h>
#include <asm/sal.h>

static struct {
	unsigned long mask;	/* mask of supported purge page-sizes */
	unsigned long max_bits;	/* log2 of largest supported purge page-size */
} purge;

struct ia64_ctx ia64_ctx = {
	.lock =	__SPIN_LOCK_UNLOCKED(ia64_ctx.lock),
	.next =	1,
	.max_ctx = ~0U
};

DEFINE_PER_CPU(u8, ia64_need_tlb_flush);

/*
 * Initializes the ia64_ctx.bitmap array based on max_ctx+1.
 * Called after cpu_init() has setup ia64_ctx.max_ctx based on
 * maximum RID that is supported by boot CPU.
 */
void __init
mmu_context_init (void)
{
	ia64_ctx.bitmap = alloc_bootmem((ia64_ctx.max_ctx+1)>>3);
	ia64_ctx.flushmap = alloc_bootmem((ia64_ctx.max_ctx+1)>>3);
}

/*
 * Acquire the ia64_ctx.lock before calling this function!
 */
void
wrap_mmu_context (struct mm_struct *mm)
{
	int i, cpu;
	unsigned long flush_bit;

	for (i=0; i <= ia64_ctx.max_ctx / BITS_PER_LONG; i++) {
		flush_bit = xchg(&ia64_ctx.flushmap[i], 0);
		ia64_ctx.bitmap[i] ^= flush_bit;
	}
 
	/* use offset at 300 to skip daemons */
	ia64_ctx.next = find_next_zero_bit(ia64_ctx.bitmap,
				ia64_ctx.max_ctx, 300);
	ia64_ctx.limit = find_next_bit(ia64_ctx.bitmap,
				ia64_ctx.max_ctx, ia64_ctx.next);

	/*
	 * can't call flush_tlb_all() here because of race condition
	 * with O(1) scheduler [EF]
	 */
	cpu = get_cpu(); /* prevent preemption/migration */
	for_each_online_cpu(i)
		if (i != cpu)
			per_cpu(ia64_need_tlb_flush, i) = 1;
	put_cpu();
	local_flush_tlb_all();
}

/*
 * Implement "spinaphores" ... like counting semaphores, but they
 * spin instead of sleeping.  If there are ever any other users for
 * this primitive it can be moved up to a spinaphore.h header.
 */
struct spinaphore {
	atomic_t	cur;
};

static inline void spinaphore_init(struct spinaphore *ss, int val)
{
	atomic_set(&ss->cur, val);
}

static inline void down_spin(struct spinaphore *ss)
{
	while (unlikely(!atomic_add_unless(&ss->cur, -1, 0)))
		while (atomic_read(&ss->cur) == 0)
			cpu_relax();
}

static inline void up_spin(struct spinaphore *ss)
{
	atomic_add(1, &ss->cur);
}

static struct spinaphore ptcg_sem;
static u16 nptcg = 1;
static int need_ptcg_sem = 1;
static int toolatetochangeptcgsem = 0;

/*
 * Kernel parameter "nptcg=" overrides max number of concurrent global TLB
 * purges which is reported from either PAL or SAL PALO.
 *
 * We don't have sanity checking for nptcg value. It's the user's responsibility
 * for valid nptcg value on the platform. Otherwise, kernel may hang in some
 * cases.
 */
static int __init
set_nptcg(char *str)
{
	int value = 0;

	get_option(&str, &value);
	setup_ptcg_sem(value, NPTCG_FROM_KERNEL_PARAMETER);

	return 1;
}

__setup("nptcg=", set_nptcg);

/*
 * Maximum number of simultaneous ptc.g purges in the system can
 * be defined by PAL_VM_SUMMARY (in which case we should take
 * the smallest value for any cpu in the system) or by the PAL
 * override table (in which case we should ignore the value from
 * PAL_VM_SUMMARY).
 *
 * Kernel parameter "nptcg=" overrides maximum number of simultanesous ptc.g
 * purges defined in either PAL_VM_SUMMARY or PAL override table. In this case,
 * we should ignore the value from either PAL_VM_SUMMARY or PAL override table.
 *
 * Complicating the logic here is the fact that num_possible_cpus()
 * isn't fully setup until we start bringing cpus online.
 */
void
setup_ptcg_sem(int max_purges, int nptcg_from)
{
	static int kp_override;
	static int palo_override;
	static int firstcpu = 1;

	if (toolatetochangeptcgsem) {
		BUG_ON(max_purges < nptcg);
		return;
	}

	if (nptcg_from == NPTCG_FROM_KERNEL_PARAMETER) {
		kp_override = 1;
		nptcg = max_purges;
		goto resetsema;
	}
	if (kp_override) {
		need_ptcg_sem = num_possible_cpus() > nptcg;
		return;
	}

	if (nptcg_from == NPTCG_FROM_PALO) {
		palo_override = 1;

		/* In PALO max_purges == 0 really means it! */
		if (max_purges == 0)
			panic("Whoa! Platform does not support global TLB purges.\n");
		nptcg = max_purges;
		if (nptcg == PALO_MAX_TLB_PURGES) {
			need_ptcg_sem = 0;
			return;
		}
		goto resetsema;
	}
	if (palo_override) {
		if (nptcg != PALO_MAX_TLB_PURGES)
			need_ptcg_sem = (num_possible_cpus() > nptcg);
		return;
	}

	/* In PAL_VM_SUMMARY max_purges == 0 actually means 1 */
	if (max_purges == 0) max_purges = 1;

	if (firstcpu) {
		nptcg = max_purges;
		firstcpu = 0;
	}
	if (max_purges < nptcg)
		nptcg = max_purges;
	if (nptcg == PAL_MAX_PURGES) {
		need_ptcg_sem = 0;
		return;
	} else
		need_ptcg_sem = (num_possible_cpus() > nptcg);

resetsema:
	spinaphore_init(&ptcg_sem, max_purges);
}

void
ia64_global_tlb_purge (struct mm_struct *mm, unsigned long start,
		       unsigned long end, unsigned long nbits)
{
	struct mm_struct *active_mm = current->active_mm;

	toolatetochangeptcgsem = 1;

	if (mm != active_mm) {
		/* Restore region IDs for mm */
		if (mm && active_mm) {
			activate_context(mm);
		} else {
			flush_tlb_all();
			return;
		}
	}

	if (need_ptcg_sem)
		down_spin(&ptcg_sem);

	do {
		/*
		 * Flush ALAT entries also.
		 */
		ia64_ptcga(start, (nbits << 2));
		ia64_srlz_i();
		start += (1UL << nbits);
	} while (start < end);

	if (need_ptcg_sem)
		up_spin(&ptcg_sem);

        if (mm != active_mm) {
                activate_context(active_mm);
        }
}

void
local_flush_tlb_all (void)
{
	unsigned long i, j, flags, count0, count1, stride0, stride1, addr;

	addr    = local_cpu_data->ptce_base;
	count0  = local_cpu_data->ptce_count[0];
	count1  = local_cpu_data->ptce_count[1];
	stride0 = local_cpu_data->ptce_stride[0];
	stride1 = local_cpu_data->ptce_stride[1];

	local_irq_save(flags);
	for (i = 0; i < count0; ++i) {
		for (j = 0; j < count1; ++j) {
			ia64_ptce(addr);
			addr += stride1;
		}
		addr += stride0;
	}
	local_irq_restore(flags);
	ia64_srlz_i();			/* srlz.i implies srlz.d */
}

void
flush_tlb_range (struct vm_area_struct *vma, unsigned long start,
		 unsigned long end)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long size = end - start;
	unsigned long nbits;

#ifndef CONFIG_SMP
	if (mm != current->active_mm) {
		mm->context = 0;
		return;
	}
#endif

	nbits = ia64_fls(size + 0xfff);
	while (unlikely (((1UL << nbits) & purge.mask) == 0) &&
			(nbits < purge.max_bits))
		++nbits;
	if (nbits > purge.max_bits)
		nbits = purge.max_bits;
	start &= ~((1UL << nbits) - 1);

	preempt_disable();
#ifdef CONFIG_SMP
	if (mm != current->active_mm || cpus_weight(mm->cpu_vm_mask) != 1) {
		platform_global_tlb_purge(mm, start, end, nbits);
		preempt_enable();
		return;
	}
#endif
	do {
		ia64_ptcl(start, (nbits<<2));
		start += (1UL << nbits);
	} while (start < end);
	preempt_enable();
	ia64_srlz_i();			/* srlz.i implies srlz.d */
}
EXPORT_SYMBOL(flush_tlb_range);

void __devinit
ia64_tlb_init (void)
{
	ia64_ptce_info_t uninitialized_var(ptce_info); /* GCC be quiet */
	unsigned long tr_pgbits;
	long status;

	if ((status = ia64_pal_vm_page_size(&tr_pgbits, &purge.mask)) != 0) {
		printk(KERN_ERR "PAL_VM_PAGE_SIZE failed with status=%ld; "
		       "defaulting to architected purge page-sizes.\n", status);
		purge.mask = 0x115557000UL;
	}
	purge.max_bits = ia64_fls(purge.mask);

	ia64_get_ptce(&ptce_info);
	local_cpu_data->ptce_base = ptce_info.base;
	local_cpu_data->ptce_count[0] = ptce_info.count[0];
	local_cpu_data->ptce_count[1] = ptce_info.count[1];
	local_cpu_data->ptce_stride[0] = ptce_info.stride[0];
	local_cpu_data->ptce_stride[1] = ptce_info.stride[1];

	local_flush_tlb_all();	/* nuke left overs from bootstrapping... */
}
