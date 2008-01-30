/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * derived from drivers/kvm/kvm_main.c
 *
 * Copyright (C) 2006 Qumranet, Inc.
 *
 * Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "kvm.h"
#include "x86.h"
#include "segment_descriptor.h"
#include "irq.h"

#include <linux/kvm.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/module.h>

#include <asm/uaccess.h>

#define MAX_IO_MSRS 256
#define CR0_RESERVED_BITS						\
	(~(unsigned long)(X86_CR0_PE | X86_CR0_MP | X86_CR0_EM | X86_CR0_TS \
			  | X86_CR0_ET | X86_CR0_NE | X86_CR0_WP | X86_CR0_AM \
			  | X86_CR0_NW | X86_CR0_CD | X86_CR0_PG))
#define CR4_RESERVED_BITS						\
	(~(unsigned long)(X86_CR4_VME | X86_CR4_PVI | X86_CR4_TSD | X86_CR4_DE\
			  | X86_CR4_PSE | X86_CR4_PAE | X86_CR4_MCE	\
			  | X86_CR4_PGE | X86_CR4_PCE | X86_CR4_OSFXSR	\
			  | X86_CR4_OSXMMEXCPT | X86_CR4_VMXE))

#define CR8_RESERVED_BITS (~(unsigned long)X86_CR8_TPR)
#define EFER_RESERVED_BITS 0xfffffffffffff2fe

#define STAT_OFFSET(x) offsetof(struct kvm_vcpu, stat.x)

struct kvm_stats_debugfs_item debugfs_entries[] = {
	{ "pf_fixed", STAT_OFFSET(pf_fixed) },
	{ "pf_guest", STAT_OFFSET(pf_guest) },
	{ "tlb_flush", STAT_OFFSET(tlb_flush) },
	{ "invlpg", STAT_OFFSET(invlpg) },
	{ "exits", STAT_OFFSET(exits) },
	{ "io_exits", STAT_OFFSET(io_exits) },
	{ "mmio_exits", STAT_OFFSET(mmio_exits) },
	{ "signal_exits", STAT_OFFSET(signal_exits) },
	{ "irq_window", STAT_OFFSET(irq_window_exits) },
	{ "halt_exits", STAT_OFFSET(halt_exits) },
	{ "halt_wakeup", STAT_OFFSET(halt_wakeup) },
	{ "request_irq", STAT_OFFSET(request_irq_exits) },
	{ "irq_exits", STAT_OFFSET(irq_exits) },
	{ "light_exits", STAT_OFFSET(light_exits) },
	{ "efer_reload", STAT_OFFSET(efer_reload) },
	{ NULL }
};


unsigned long segment_base(u16 selector)
{
	struct descriptor_table gdt;
	struct segment_descriptor *d;
	unsigned long table_base;
	unsigned long v;

	if (selector == 0)
		return 0;

	asm("sgdt %0" : "=m"(gdt));
	table_base = gdt.base;

	if (selector & 4) {           /* from ldt */
		u16 ldt_selector;

		asm("sldt %0" : "=g"(ldt_selector));
		table_base = segment_base(ldt_selector);
	}
	d = (struct segment_descriptor *)(table_base + (selector & ~7));
	v = d->base_low | ((unsigned long)d->base_mid << 16) |
		((unsigned long)d->base_high << 24);
#ifdef CONFIG_X86_64
	if (d->system == 0 && (d->type == 2 || d->type == 9 || d->type == 11))
		v |= ((unsigned long) \
		      ((struct segment_descriptor_64 *)d)->base_higher) << 32;
#endif
	return v;
}
EXPORT_SYMBOL_GPL(segment_base);

u64 kvm_get_apic_base(struct kvm_vcpu *vcpu)
{
	if (irqchip_in_kernel(vcpu->kvm))
		return vcpu->apic_base;
	else
		return vcpu->apic_base;
}
EXPORT_SYMBOL_GPL(kvm_get_apic_base);

void kvm_set_apic_base(struct kvm_vcpu *vcpu, u64 data)
{
	/* TODO: reserve bits check */
	if (irqchip_in_kernel(vcpu->kvm))
		kvm_lapic_set_base(vcpu, data);
	else
		vcpu->apic_base = data;
}
EXPORT_SYMBOL_GPL(kvm_set_apic_base);

static void inject_gp(struct kvm_vcpu *vcpu)
{
	kvm_x86_ops->inject_gp(vcpu, 0);
}

/*
 * Load the pae pdptrs.  Return true is they are all valid.
 */
int load_pdptrs(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	gfn_t pdpt_gfn = cr3 >> PAGE_SHIFT;
	unsigned offset = ((cr3 & (PAGE_SIZE-1)) >> 5) << 2;
	int i;
	int ret;
	u64 pdpte[ARRAY_SIZE(vcpu->pdptrs)];

	mutex_lock(&vcpu->kvm->lock);
	ret = kvm_read_guest_page(vcpu->kvm, pdpt_gfn, pdpte,
				  offset * sizeof(u64), sizeof(pdpte));
	if (ret < 0) {
		ret = 0;
		goto out;
	}
	for (i = 0; i < ARRAY_SIZE(pdpte); ++i) {
		if ((pdpte[i] & 1) && (pdpte[i] & 0xfffffff0000001e6ull)) {
			ret = 0;
			goto out;
		}
	}
	ret = 1;

	memcpy(vcpu->pdptrs, pdpte, sizeof(vcpu->pdptrs));
out:
	mutex_unlock(&vcpu->kvm->lock);

	return ret;
}

void set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	if (cr0 & CR0_RESERVED_BITS) {
		printk(KERN_DEBUG "set_cr0: 0x%lx #GP, reserved bits 0x%lx\n",
		       cr0, vcpu->cr0);
		inject_gp(vcpu);
		return;
	}

	if ((cr0 & X86_CR0_NW) && !(cr0 & X86_CR0_CD)) {
		printk(KERN_DEBUG "set_cr0: #GP, CD == 0 && NW == 1\n");
		inject_gp(vcpu);
		return;
	}

	if ((cr0 & X86_CR0_PG) && !(cr0 & X86_CR0_PE)) {
		printk(KERN_DEBUG "set_cr0: #GP, set PG flag "
		       "and a clear PE flag\n");
		inject_gp(vcpu);
		return;
	}

	if (!is_paging(vcpu) && (cr0 & X86_CR0_PG)) {
#ifdef CONFIG_X86_64
		if ((vcpu->shadow_efer & EFER_LME)) {
			int cs_db, cs_l;

			if (!is_pae(vcpu)) {
				printk(KERN_DEBUG "set_cr0: #GP, start paging "
				       "in long mode while PAE is disabled\n");
				inject_gp(vcpu);
				return;
			}
			kvm_x86_ops->get_cs_db_l_bits(vcpu, &cs_db, &cs_l);
			if (cs_l) {
				printk(KERN_DEBUG "set_cr0: #GP, start paging "
				       "in long mode while CS.L == 1\n");
				inject_gp(vcpu);
				return;

			}
		} else
#endif
		if (is_pae(vcpu) && !load_pdptrs(vcpu, vcpu->cr3)) {
			printk(KERN_DEBUG "set_cr0: #GP, pdptrs "
			       "reserved bits\n");
			inject_gp(vcpu);
			return;
		}

	}

	kvm_x86_ops->set_cr0(vcpu, cr0);
	vcpu->cr0 = cr0;

	mutex_lock(&vcpu->kvm->lock);
	kvm_mmu_reset_context(vcpu);
	mutex_unlock(&vcpu->kvm->lock);
	return;
}
EXPORT_SYMBOL_GPL(set_cr0);

void lmsw(struct kvm_vcpu *vcpu, unsigned long msw)
{
	set_cr0(vcpu, (vcpu->cr0 & ~0x0ful) | (msw & 0x0f));
}
EXPORT_SYMBOL_GPL(lmsw);

void set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	if (cr4 & CR4_RESERVED_BITS) {
		printk(KERN_DEBUG "set_cr4: #GP, reserved bits\n");
		inject_gp(vcpu);
		return;
	}

	if (is_long_mode(vcpu)) {
		if (!(cr4 & X86_CR4_PAE)) {
			printk(KERN_DEBUG "set_cr4: #GP, clearing PAE while "
			       "in long mode\n");
			inject_gp(vcpu);
			return;
		}
	} else if (is_paging(vcpu) && !is_pae(vcpu) && (cr4 & X86_CR4_PAE)
		   && !load_pdptrs(vcpu, vcpu->cr3)) {
		printk(KERN_DEBUG "set_cr4: #GP, pdptrs reserved bits\n");
		inject_gp(vcpu);
		return;
	}

	if (cr4 & X86_CR4_VMXE) {
		printk(KERN_DEBUG "set_cr4: #GP, setting VMXE\n");
		inject_gp(vcpu);
		return;
	}
	kvm_x86_ops->set_cr4(vcpu, cr4);
	vcpu->cr4 = cr4;
	mutex_lock(&vcpu->kvm->lock);
	kvm_mmu_reset_context(vcpu);
	mutex_unlock(&vcpu->kvm->lock);
}
EXPORT_SYMBOL_GPL(set_cr4);

void set_cr3(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	if (is_long_mode(vcpu)) {
		if (cr3 & CR3_L_MODE_RESERVED_BITS) {
			printk(KERN_DEBUG "set_cr3: #GP, reserved bits\n");
			inject_gp(vcpu);
			return;
		}
	} else {
		if (is_pae(vcpu)) {
			if (cr3 & CR3_PAE_RESERVED_BITS) {
				printk(KERN_DEBUG
				       "set_cr3: #GP, reserved bits\n");
				inject_gp(vcpu);
				return;
			}
			if (is_paging(vcpu) && !load_pdptrs(vcpu, cr3)) {
				printk(KERN_DEBUG "set_cr3: #GP, pdptrs "
				       "reserved bits\n");
				inject_gp(vcpu);
				return;
			}
		}
		/*
		 * We don't check reserved bits in nonpae mode, because
		 * this isn't enforced, and VMware depends on this.
		 */
	}

	mutex_lock(&vcpu->kvm->lock);
	/*
	 * Does the new cr3 value map to physical memory? (Note, we
	 * catch an invalid cr3 even in real-mode, because it would
	 * cause trouble later on when we turn on paging anyway.)
	 *
	 * A real CPU would silently accept an invalid cr3 and would
	 * attempt to use it - with largely undefined (and often hard
	 * to debug) behavior on the guest side.
	 */
	if (unlikely(!gfn_to_memslot(vcpu->kvm, cr3 >> PAGE_SHIFT)))
		inject_gp(vcpu);
	else {
		vcpu->cr3 = cr3;
		vcpu->mmu.new_cr3(vcpu);
	}
	mutex_unlock(&vcpu->kvm->lock);
}
EXPORT_SYMBOL_GPL(set_cr3);

void set_cr8(struct kvm_vcpu *vcpu, unsigned long cr8)
{
	if (cr8 & CR8_RESERVED_BITS) {
		printk(KERN_DEBUG "set_cr8: #GP, reserved bits 0x%lx\n", cr8);
		inject_gp(vcpu);
		return;
	}
	if (irqchip_in_kernel(vcpu->kvm))
		kvm_lapic_set_tpr(vcpu, cr8);
	else
		vcpu->cr8 = cr8;
}
EXPORT_SYMBOL_GPL(set_cr8);

unsigned long get_cr8(struct kvm_vcpu *vcpu)
{
	if (irqchip_in_kernel(vcpu->kvm))
		return kvm_lapic_get_cr8(vcpu);
	else
		return vcpu->cr8;
}
EXPORT_SYMBOL_GPL(get_cr8);

/*
 * List of msr numbers which we expose to userspace through KVM_GET_MSRS
 * and KVM_SET_MSRS, and KVM_GET_MSR_INDEX_LIST.
 *
 * This list is modified at module load time to reflect the
 * capabilities of the host cpu.
 */
static u32 msrs_to_save[] = {
	MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_ESP, MSR_IA32_SYSENTER_EIP,
	MSR_K6_STAR,
#ifdef CONFIG_X86_64
	MSR_CSTAR, MSR_KERNEL_GS_BASE, MSR_SYSCALL_MASK, MSR_LSTAR,
#endif
	MSR_IA32_TIME_STAMP_COUNTER,
};

static unsigned num_msrs_to_save;

static u32 emulated_msrs[] = {
	MSR_IA32_MISC_ENABLE,
};

#ifdef CONFIG_X86_64

static void set_efer(struct kvm_vcpu *vcpu, u64 efer)
{
	if (efer & EFER_RESERVED_BITS) {
		printk(KERN_DEBUG "set_efer: 0x%llx #GP, reserved bits\n",
		       efer);
		inject_gp(vcpu);
		return;
	}

	if (is_paging(vcpu)
	    && (vcpu->shadow_efer & EFER_LME) != (efer & EFER_LME)) {
		printk(KERN_DEBUG "set_efer: #GP, change LME while paging\n");
		inject_gp(vcpu);
		return;
	}

	kvm_x86_ops->set_efer(vcpu, efer);

	efer &= ~EFER_LMA;
	efer |= vcpu->shadow_efer & EFER_LMA;

	vcpu->shadow_efer = efer;
}

#endif

/*
 * Writes msr value into into the appropriate "register".
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
int kvm_set_msr(struct kvm_vcpu *vcpu, u32 msr_index, u64 data)
{
	return kvm_x86_ops->set_msr(vcpu, msr_index, data);
}

/*
 * Adapt set_msr() to msr_io()'s calling convention
 */
static int do_set_msr(struct kvm_vcpu *vcpu, unsigned index, u64 *data)
{
	return kvm_set_msr(vcpu, index, *data);
}


int kvm_set_msr_common(struct kvm_vcpu *vcpu, u32 msr, u64 data)
{
	switch (msr) {
#ifdef CONFIG_X86_64
	case MSR_EFER:
		set_efer(vcpu, data);
		break;
#endif
	case MSR_IA32_MC0_STATUS:
		pr_unimpl(vcpu, "%s: MSR_IA32_MC0_STATUS 0x%llx, nop\n",
		       __FUNCTION__, data);
		break;
	case MSR_IA32_MCG_STATUS:
		pr_unimpl(vcpu, "%s: MSR_IA32_MCG_STATUS 0x%llx, nop\n",
			__FUNCTION__, data);
		break;
	case MSR_IA32_UCODE_REV:
	case MSR_IA32_UCODE_WRITE:
	case 0x200 ... 0x2ff: /* MTRRs */
		break;
	case MSR_IA32_APICBASE:
		kvm_set_apic_base(vcpu, data);
		break;
	case MSR_IA32_MISC_ENABLE:
		vcpu->ia32_misc_enable_msr = data;
		break;
	default:
		pr_unimpl(vcpu, "unhandled wrmsr: 0x%x\n", msr);
		return 1;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_set_msr_common);


/*
 * Reads an msr value (of 'msr_index') into 'pdata'.
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
int kvm_get_msr(struct kvm_vcpu *vcpu, u32 msr_index, u64 *pdata)
{
	return kvm_x86_ops->get_msr(vcpu, msr_index, pdata);
}

int kvm_get_msr_common(struct kvm_vcpu *vcpu, u32 msr, u64 *pdata)
{
	u64 data;

	switch (msr) {
	case 0xc0010010: /* SYSCFG */
	case 0xc0010015: /* HWCR */
	case MSR_IA32_PLATFORM_ID:
	case MSR_IA32_P5_MC_ADDR:
	case MSR_IA32_P5_MC_TYPE:
	case MSR_IA32_MC0_CTL:
	case MSR_IA32_MCG_STATUS:
	case MSR_IA32_MCG_CAP:
	case MSR_IA32_MC0_MISC:
	case MSR_IA32_MC0_MISC+4:
	case MSR_IA32_MC0_MISC+8:
	case MSR_IA32_MC0_MISC+12:
	case MSR_IA32_MC0_MISC+16:
	case MSR_IA32_UCODE_REV:
	case MSR_IA32_PERF_STATUS:
	case MSR_IA32_EBL_CR_POWERON:
		/* MTRR registers */
	case 0xfe:
	case 0x200 ... 0x2ff:
		data = 0;
		break;
	case 0xcd: /* fsb frequency */
		data = 3;
		break;
	case MSR_IA32_APICBASE:
		data = kvm_get_apic_base(vcpu);
		break;
	case MSR_IA32_MISC_ENABLE:
		data = vcpu->ia32_misc_enable_msr;
		break;
#ifdef CONFIG_X86_64
	case MSR_EFER:
		data = vcpu->shadow_efer;
		break;
#endif
	default:
		pr_unimpl(vcpu, "unhandled rdmsr: 0x%x\n", msr);
		return 1;
	}
	*pdata = data;
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_get_msr_common);

/*
 * Read or write a bunch of msrs. All parameters are kernel addresses.
 *
 * @return number of msrs set successfully.
 */
static int __msr_io(struct kvm_vcpu *vcpu, struct kvm_msrs *msrs,
		    struct kvm_msr_entry *entries,
		    int (*do_msr)(struct kvm_vcpu *vcpu,
				  unsigned index, u64 *data))
{
	int i;

	vcpu_load(vcpu);

	for (i = 0; i < msrs->nmsrs; ++i)
		if (do_msr(vcpu, entries[i].index, &entries[i].data))
			break;

	vcpu_put(vcpu);

	return i;
}

/*
 * Read or write a bunch of msrs. Parameters are user addresses.
 *
 * @return number of msrs set successfully.
 */
static int msr_io(struct kvm_vcpu *vcpu, struct kvm_msrs __user *user_msrs,
		  int (*do_msr)(struct kvm_vcpu *vcpu,
				unsigned index, u64 *data),
		  int writeback)
{
	struct kvm_msrs msrs;
	struct kvm_msr_entry *entries;
	int r, n;
	unsigned size;

	r = -EFAULT;
	if (copy_from_user(&msrs, user_msrs, sizeof msrs))
		goto out;

	r = -E2BIG;
	if (msrs.nmsrs >= MAX_IO_MSRS)
		goto out;

	r = -ENOMEM;
	size = sizeof(struct kvm_msr_entry) * msrs.nmsrs;
	entries = vmalloc(size);
	if (!entries)
		goto out;

	r = -EFAULT;
	if (copy_from_user(entries, user_msrs->entries, size))
		goto out_free;

	r = n = __msr_io(vcpu, &msrs, entries, do_msr);
	if (r < 0)
		goto out_free;

	r = -EFAULT;
	if (writeback && copy_to_user(user_msrs->entries, entries, size))
		goto out_free;

	r = n;

out_free:
	vfree(entries);
out:
	return r;
}

long kvm_arch_dev_ioctl(struct file *filp,
			unsigned int ioctl, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	long r;

	switch (ioctl) {
	case KVM_GET_MSR_INDEX_LIST: {
		struct kvm_msr_list __user *user_msr_list = argp;
		struct kvm_msr_list msr_list;
		unsigned n;

		r = -EFAULT;
		if (copy_from_user(&msr_list, user_msr_list, sizeof msr_list))
			goto out;
		n = msr_list.nmsrs;
		msr_list.nmsrs = num_msrs_to_save + ARRAY_SIZE(emulated_msrs);
		if (copy_to_user(user_msr_list, &msr_list, sizeof msr_list))
			goto out;
		r = -E2BIG;
		if (n < num_msrs_to_save)
			goto out;
		r = -EFAULT;
		if (copy_to_user(user_msr_list->indices, &msrs_to_save,
				 num_msrs_to_save * sizeof(u32)))
			goto out;
		if (copy_to_user(user_msr_list->indices
				 + num_msrs_to_save * sizeof(u32),
				 &emulated_msrs,
				 ARRAY_SIZE(emulated_msrs) * sizeof(u32)))
			goto out;
		r = 0;
		break;
	}
	default:
		r = -EINVAL;
	}
out:
	return r;
}

void kvm_arch_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	kvm_x86_ops->vcpu_load(vcpu, cpu);
}

void kvm_arch_vcpu_put(struct kvm_vcpu *vcpu)
{
	kvm_x86_ops->vcpu_put(vcpu);
}

static void cpuid_fix_nx_cap(struct kvm_vcpu *vcpu)
{
	u64 efer;
	int i;
	struct kvm_cpuid_entry *e, *entry;

	rdmsrl(MSR_EFER, efer);
	entry = NULL;
	for (i = 0; i < vcpu->cpuid_nent; ++i) {
		e = &vcpu->cpuid_entries[i];
		if (e->function == 0x80000001) {
			entry = e;
			break;
		}
	}
	if (entry && (entry->edx & (1 << 20)) && !(efer & EFER_NX)) {
		entry->edx &= ~(1 << 20);
		printk(KERN_INFO "kvm: guest NX capability removed\n");
	}
}

static int kvm_vcpu_ioctl_set_cpuid(struct kvm_vcpu *vcpu,
				    struct kvm_cpuid *cpuid,
				    struct kvm_cpuid_entry __user *entries)
{
	int r;

	r = -E2BIG;
	if (cpuid->nent > KVM_MAX_CPUID_ENTRIES)
		goto out;
	r = -EFAULT;
	if (copy_from_user(&vcpu->cpuid_entries, entries,
			   cpuid->nent * sizeof(struct kvm_cpuid_entry)))
		goto out;
	vcpu->cpuid_nent = cpuid->nent;
	cpuid_fix_nx_cap(vcpu);
	return 0;

out:
	return r;
}

static int kvm_vcpu_ioctl_get_lapic(struct kvm_vcpu *vcpu,
				    struct kvm_lapic_state *s)
{
	vcpu_load(vcpu);
	memcpy(s->regs, vcpu->apic->regs, sizeof *s);
	vcpu_put(vcpu);

	return 0;
}

static int kvm_vcpu_ioctl_set_lapic(struct kvm_vcpu *vcpu,
				    struct kvm_lapic_state *s)
{
	vcpu_load(vcpu);
	memcpy(vcpu->apic->regs, s->regs, sizeof *s);
	kvm_apic_post_state_restore(vcpu);
	vcpu_put(vcpu);

	return 0;
}

long kvm_arch_vcpu_ioctl(struct file *filp,
			 unsigned int ioctl, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = (void __user *)arg;
	int r;

	switch (ioctl) {
	case KVM_GET_LAPIC: {
		struct kvm_lapic_state lapic;

		memset(&lapic, 0, sizeof lapic);
		r = kvm_vcpu_ioctl_get_lapic(vcpu, &lapic);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user(argp, &lapic, sizeof lapic))
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_LAPIC: {
		struct kvm_lapic_state lapic;

		r = -EFAULT;
		if (copy_from_user(&lapic, argp, sizeof lapic))
			goto out;
		r = kvm_vcpu_ioctl_set_lapic(vcpu, &lapic);;
		if (r)
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_CPUID: {
		struct kvm_cpuid __user *cpuid_arg = argp;
		struct kvm_cpuid cpuid;

		r = -EFAULT;
		if (copy_from_user(&cpuid, cpuid_arg, sizeof cpuid))
			goto out;
		r = kvm_vcpu_ioctl_set_cpuid(vcpu, &cpuid, cpuid_arg->entries);
		if (r)
			goto out;
		break;
	}
	case KVM_GET_MSRS:
		r = msr_io(vcpu, argp, kvm_get_msr, 1);
		break;
	case KVM_SET_MSRS:
		r = msr_io(vcpu, argp, do_set_msr, 0);
		break;
	default:
		r = -EINVAL;
	}
out:
	return r;
}

static int kvm_vm_ioctl_set_tss_addr(struct kvm *kvm, unsigned long addr)
{
	int ret;

	if (addr > (unsigned int)(-3 * PAGE_SIZE))
		return -1;
	ret = kvm_x86_ops->set_tss_addr(kvm, addr);
	return ret;
}

static int kvm_vm_ioctl_set_nr_mmu_pages(struct kvm *kvm,
					  u32 kvm_nr_mmu_pages)
{
	if (kvm_nr_mmu_pages < KVM_MIN_ALLOC_MMU_PAGES)
		return -EINVAL;

	mutex_lock(&kvm->lock);

	kvm_mmu_change_mmu_pages(kvm, kvm_nr_mmu_pages);
	kvm->n_requested_mmu_pages = kvm_nr_mmu_pages;

	mutex_unlock(&kvm->lock);
	return 0;
}

static int kvm_vm_ioctl_get_nr_mmu_pages(struct kvm *kvm)
{
	return kvm->n_alloc_mmu_pages;
}

/*
 * Set a new alias region.  Aliases map a portion of physical memory into
 * another portion.  This is useful for memory windows, for example the PC
 * VGA region.
 */
static int kvm_vm_ioctl_set_memory_alias(struct kvm *kvm,
					 struct kvm_memory_alias *alias)
{
	int r, n;
	struct kvm_mem_alias *p;

	r = -EINVAL;
	/* General sanity checks */
	if (alias->memory_size & (PAGE_SIZE - 1))
		goto out;
	if (alias->guest_phys_addr & (PAGE_SIZE - 1))
		goto out;
	if (alias->slot >= KVM_ALIAS_SLOTS)
		goto out;
	if (alias->guest_phys_addr + alias->memory_size
	    < alias->guest_phys_addr)
		goto out;
	if (alias->target_phys_addr + alias->memory_size
	    < alias->target_phys_addr)
		goto out;

	mutex_lock(&kvm->lock);

	p = &kvm->aliases[alias->slot];
	p->base_gfn = alias->guest_phys_addr >> PAGE_SHIFT;
	p->npages = alias->memory_size >> PAGE_SHIFT;
	p->target_gfn = alias->target_phys_addr >> PAGE_SHIFT;

	for (n = KVM_ALIAS_SLOTS; n > 0; --n)
		if (kvm->aliases[n - 1].npages)
			break;
	kvm->naliases = n;

	kvm_mmu_zap_all(kvm);

	mutex_unlock(&kvm->lock);

	return 0;

out:
	return r;
}

static int kvm_vm_ioctl_get_irqchip(struct kvm *kvm, struct kvm_irqchip *chip)
{
	int r;

	r = 0;
	switch (chip->chip_id) {
	case KVM_IRQCHIP_PIC_MASTER:
		memcpy(&chip->chip.pic,
			&pic_irqchip(kvm)->pics[0],
			sizeof(struct kvm_pic_state));
		break;
	case KVM_IRQCHIP_PIC_SLAVE:
		memcpy(&chip->chip.pic,
			&pic_irqchip(kvm)->pics[1],
			sizeof(struct kvm_pic_state));
		break;
	case KVM_IRQCHIP_IOAPIC:
		memcpy(&chip->chip.ioapic,
			ioapic_irqchip(kvm),
			sizeof(struct kvm_ioapic_state));
		break;
	default:
		r = -EINVAL;
		break;
	}
	return r;
}

static int kvm_vm_ioctl_set_irqchip(struct kvm *kvm, struct kvm_irqchip *chip)
{
	int r;

	r = 0;
	switch (chip->chip_id) {
	case KVM_IRQCHIP_PIC_MASTER:
		memcpy(&pic_irqchip(kvm)->pics[0],
			&chip->chip.pic,
			sizeof(struct kvm_pic_state));
		break;
	case KVM_IRQCHIP_PIC_SLAVE:
		memcpy(&pic_irqchip(kvm)->pics[1],
			&chip->chip.pic,
			sizeof(struct kvm_pic_state));
		break;
	case KVM_IRQCHIP_IOAPIC:
		memcpy(ioapic_irqchip(kvm),
			&chip->chip.ioapic,
			sizeof(struct kvm_ioapic_state));
		break;
	default:
		r = -EINVAL;
		break;
	}
	kvm_pic_update_irq(pic_irqchip(kvm));
	return r;
}

long kvm_arch_vm_ioctl(struct file *filp,
		       unsigned int ioctl, unsigned long arg)
{
	struct kvm *kvm = filp->private_data;
	void __user *argp = (void __user *)arg;
	int r = -EINVAL;

	switch (ioctl) {
	case KVM_SET_TSS_ADDR:
		r = kvm_vm_ioctl_set_tss_addr(kvm, arg);
		if (r < 0)
			goto out;
		break;
	case KVM_SET_MEMORY_REGION: {
		struct kvm_memory_region kvm_mem;
		struct kvm_userspace_memory_region kvm_userspace_mem;

		r = -EFAULT;
		if (copy_from_user(&kvm_mem, argp, sizeof kvm_mem))
			goto out;
		kvm_userspace_mem.slot = kvm_mem.slot;
		kvm_userspace_mem.flags = kvm_mem.flags;
		kvm_userspace_mem.guest_phys_addr = kvm_mem.guest_phys_addr;
		kvm_userspace_mem.memory_size = kvm_mem.memory_size;
		r = kvm_vm_ioctl_set_memory_region(kvm, &kvm_userspace_mem, 0);
		if (r)
			goto out;
		break;
	}
	case KVM_SET_NR_MMU_PAGES:
		r = kvm_vm_ioctl_set_nr_mmu_pages(kvm, arg);
		if (r)
			goto out;
		break;
	case KVM_GET_NR_MMU_PAGES:
		r = kvm_vm_ioctl_get_nr_mmu_pages(kvm);
		break;
	case KVM_SET_MEMORY_ALIAS: {
		struct kvm_memory_alias alias;

		r = -EFAULT;
		if (copy_from_user(&alias, argp, sizeof alias))
			goto out;
		r = kvm_vm_ioctl_set_memory_alias(kvm, &alias);
		if (r)
			goto out;
		break;
	}
	case KVM_CREATE_IRQCHIP:
		r = -ENOMEM;
		kvm->vpic = kvm_create_pic(kvm);
		if (kvm->vpic) {
			r = kvm_ioapic_init(kvm);
			if (r) {
				kfree(kvm->vpic);
				kvm->vpic = NULL;
				goto out;
			}
		} else
			goto out;
		break;
	case KVM_IRQ_LINE: {
		struct kvm_irq_level irq_event;

		r = -EFAULT;
		if (copy_from_user(&irq_event, argp, sizeof irq_event))
			goto out;
		if (irqchip_in_kernel(kvm)) {
			mutex_lock(&kvm->lock);
			if (irq_event.irq < 16)
				kvm_pic_set_irq(pic_irqchip(kvm),
					irq_event.irq,
					irq_event.level);
			kvm_ioapic_set_irq(kvm->vioapic,
					irq_event.irq,
					irq_event.level);
			mutex_unlock(&kvm->lock);
			r = 0;
		}
		break;
	}
	case KVM_GET_IRQCHIP: {
		/* 0: PIC master, 1: PIC slave, 2: IOAPIC */
		struct kvm_irqchip chip;

		r = -EFAULT;
		if (copy_from_user(&chip, argp, sizeof chip))
			goto out;
		r = -ENXIO;
		if (!irqchip_in_kernel(kvm))
			goto out;
		r = kvm_vm_ioctl_get_irqchip(kvm, &chip);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user(argp, &chip, sizeof chip))
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_IRQCHIP: {
		/* 0: PIC master, 1: PIC slave, 2: IOAPIC */
		struct kvm_irqchip chip;

		r = -EFAULT;
		if (copy_from_user(&chip, argp, sizeof chip))
			goto out;
		r = -ENXIO;
		if (!irqchip_in_kernel(kvm))
			goto out;
		r = kvm_vm_ioctl_set_irqchip(kvm, &chip);
		if (r)
			goto out;
		r = 0;
		break;
	}
	default:
		;
	}
out:
	return r;
}

static __init void kvm_init_msr_list(void)
{
	u32 dummy[2];
	unsigned i, j;

	for (i = j = 0; i < ARRAY_SIZE(msrs_to_save); i++) {
		if (rdmsr_safe(msrs_to_save[i], &dummy[0], &dummy[1]) < 0)
			continue;
		if (j < i)
			msrs_to_save[j] = msrs_to_save[i];
		j++;
	}
	num_msrs_to_save = j;
}

/*
 * Only apic need an MMIO device hook, so shortcut now..
 */
static struct kvm_io_device *vcpu_find_pervcpu_dev(struct kvm_vcpu *vcpu,
						gpa_t addr)
{
	struct kvm_io_device *dev;

	if (vcpu->apic) {
		dev = &vcpu->apic->dev;
		if (dev->in_range(dev, addr))
			return dev;
	}
	return NULL;
}


static struct kvm_io_device *vcpu_find_mmio_dev(struct kvm_vcpu *vcpu,
						gpa_t addr)
{
	struct kvm_io_device *dev;

	dev = vcpu_find_pervcpu_dev(vcpu, addr);
	if (dev == NULL)
		dev = kvm_io_bus_find_dev(&vcpu->kvm->mmio_bus, addr);
	return dev;
}

int emulator_read_std(unsigned long addr,
			     void *val,
			     unsigned int bytes,
			     struct kvm_vcpu *vcpu)
{
	void *data = val;

	while (bytes) {
		gpa_t gpa = vcpu->mmu.gva_to_gpa(vcpu, addr);
		unsigned offset = addr & (PAGE_SIZE-1);
		unsigned tocopy = min(bytes, (unsigned)PAGE_SIZE - offset);
		int ret;

		if (gpa == UNMAPPED_GVA)
			return X86EMUL_PROPAGATE_FAULT;
		ret = kvm_read_guest(vcpu->kvm, gpa, data, tocopy);
		if (ret < 0)
			return X86EMUL_UNHANDLEABLE;

		bytes -= tocopy;
		data += tocopy;
		addr += tocopy;
	}

	return X86EMUL_CONTINUE;
}
EXPORT_SYMBOL_GPL(emulator_read_std);

static int emulator_write_std(unsigned long addr,
			      const void *val,
			      unsigned int bytes,
			      struct kvm_vcpu *vcpu)
{
	pr_unimpl(vcpu, "emulator_write_std: addr %lx n %d\n", addr, bytes);
	return X86EMUL_UNHANDLEABLE;
}

static int emulator_read_emulated(unsigned long addr,
				  void *val,
				  unsigned int bytes,
				  struct kvm_vcpu *vcpu)
{
	struct kvm_io_device *mmio_dev;
	gpa_t                 gpa;

	if (vcpu->mmio_read_completed) {
		memcpy(val, vcpu->mmio_data, bytes);
		vcpu->mmio_read_completed = 0;
		return X86EMUL_CONTINUE;
	}

	gpa = vcpu->mmu.gva_to_gpa(vcpu, addr);

	/* For APIC access vmexit */
	if ((gpa & PAGE_MASK) == APIC_DEFAULT_PHYS_BASE)
		goto mmio;

	if (emulator_read_std(addr, val, bytes, vcpu)
			== X86EMUL_CONTINUE)
		return X86EMUL_CONTINUE;
	if (gpa == UNMAPPED_GVA)
		return X86EMUL_PROPAGATE_FAULT;

mmio:
	/*
	 * Is this MMIO handled locally?
	 */
	mmio_dev = vcpu_find_mmio_dev(vcpu, gpa);
	if (mmio_dev) {
		kvm_iodevice_read(mmio_dev, gpa, bytes, val);
		return X86EMUL_CONTINUE;
	}

	vcpu->mmio_needed = 1;
	vcpu->mmio_phys_addr = gpa;
	vcpu->mmio_size = bytes;
	vcpu->mmio_is_write = 0;

	return X86EMUL_UNHANDLEABLE;
}

static int emulator_write_phys(struct kvm_vcpu *vcpu, gpa_t gpa,
			       const void *val, int bytes)
{
	int ret;

	ret = kvm_write_guest(vcpu->kvm, gpa, val, bytes);
	if (ret < 0)
		return 0;
	kvm_mmu_pte_write(vcpu, gpa, val, bytes);
	return 1;
}

static int emulator_write_emulated_onepage(unsigned long addr,
					   const void *val,
					   unsigned int bytes,
					   struct kvm_vcpu *vcpu)
{
	struct kvm_io_device *mmio_dev;
	gpa_t                 gpa = vcpu->mmu.gva_to_gpa(vcpu, addr);

	if (gpa == UNMAPPED_GVA) {
		kvm_x86_ops->inject_page_fault(vcpu, addr, 2);
		return X86EMUL_PROPAGATE_FAULT;
	}

	/* For APIC access vmexit */
	if ((gpa & PAGE_MASK) == APIC_DEFAULT_PHYS_BASE)
		goto mmio;

	if (emulator_write_phys(vcpu, gpa, val, bytes))
		return X86EMUL_CONTINUE;

mmio:
	/*
	 * Is this MMIO handled locally?
	 */
	mmio_dev = vcpu_find_mmio_dev(vcpu, gpa);
	if (mmio_dev) {
		kvm_iodevice_write(mmio_dev, gpa, bytes, val);
		return X86EMUL_CONTINUE;
	}

	vcpu->mmio_needed = 1;
	vcpu->mmio_phys_addr = gpa;
	vcpu->mmio_size = bytes;
	vcpu->mmio_is_write = 1;
	memcpy(vcpu->mmio_data, val, bytes);

	return X86EMUL_CONTINUE;
}

int emulator_write_emulated(unsigned long addr,
				   const void *val,
				   unsigned int bytes,
				   struct kvm_vcpu *vcpu)
{
	/* Crossing a page boundary? */
	if (((addr + bytes - 1) ^ addr) & PAGE_MASK) {
		int rc, now;

		now = -addr & ~PAGE_MASK;
		rc = emulator_write_emulated_onepage(addr, val, now, vcpu);
		if (rc != X86EMUL_CONTINUE)
			return rc;
		addr += now;
		val += now;
		bytes -= now;
	}
	return emulator_write_emulated_onepage(addr, val, bytes, vcpu);
}
EXPORT_SYMBOL_GPL(emulator_write_emulated);

static int emulator_cmpxchg_emulated(unsigned long addr,
				     const void *old,
				     const void *new,
				     unsigned int bytes,
				     struct kvm_vcpu *vcpu)
{
	static int reported;

	if (!reported) {
		reported = 1;
		printk(KERN_WARNING "kvm: emulating exchange as write\n");
	}
	return emulator_write_emulated(addr, new, bytes, vcpu);
}

static unsigned long get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	return kvm_x86_ops->get_segment_base(vcpu, seg);
}

int emulate_invlpg(struct kvm_vcpu *vcpu, gva_t address)
{
	return X86EMUL_CONTINUE;
}

int emulate_clts(struct kvm_vcpu *vcpu)
{
	kvm_x86_ops->set_cr0(vcpu, vcpu->cr0 & ~X86_CR0_TS);
	return X86EMUL_CONTINUE;
}

int emulator_get_dr(struct x86_emulate_ctxt *ctxt, int dr, unsigned long *dest)
{
	struct kvm_vcpu *vcpu = ctxt->vcpu;

	switch (dr) {
	case 0 ... 3:
		*dest = kvm_x86_ops->get_dr(vcpu, dr);
		return X86EMUL_CONTINUE;
	default:
		pr_unimpl(vcpu, "%s: unexpected dr %u\n", __FUNCTION__, dr);
		return X86EMUL_UNHANDLEABLE;
	}
}

int emulator_set_dr(struct x86_emulate_ctxt *ctxt, int dr, unsigned long value)
{
	unsigned long mask = (ctxt->mode == X86EMUL_MODE_PROT64) ? ~0ULL : ~0U;
	int exception;

	kvm_x86_ops->set_dr(ctxt->vcpu, dr, value & mask, &exception);
	if (exception) {
		/* FIXME: better handling */
		return X86EMUL_UNHANDLEABLE;
	}
	return X86EMUL_CONTINUE;
}

void kvm_report_emulation_failure(struct kvm_vcpu *vcpu, const char *context)
{
	static int reported;
	u8 opcodes[4];
	unsigned long rip = vcpu->rip;
	unsigned long rip_linear;

	rip_linear = rip + get_segment_base(vcpu, VCPU_SREG_CS);

	if (reported)
		return;

	emulator_read_std(rip_linear, (void *)opcodes, 4, vcpu);

	printk(KERN_ERR "emulation failed (%s) rip %lx %02x %02x %02x %02x\n",
	       context, rip, opcodes[0], opcodes[1], opcodes[2], opcodes[3]);
	reported = 1;
}
EXPORT_SYMBOL_GPL(kvm_report_emulation_failure);

struct x86_emulate_ops emulate_ops = {
	.read_std            = emulator_read_std,
	.write_std           = emulator_write_std,
	.read_emulated       = emulator_read_emulated,
	.write_emulated      = emulator_write_emulated,
	.cmpxchg_emulated    = emulator_cmpxchg_emulated,
};

int emulate_instruction(struct kvm_vcpu *vcpu,
			struct kvm_run *run,
			unsigned long cr2,
			u16 error_code,
			int no_decode)
{
	int r;

	vcpu->mmio_fault_cr2 = cr2;
	kvm_x86_ops->cache_regs(vcpu);

	vcpu->mmio_is_write = 0;
	vcpu->pio.string = 0;

	if (!no_decode) {
		int cs_db, cs_l;
		kvm_x86_ops->get_cs_db_l_bits(vcpu, &cs_db, &cs_l);

		vcpu->emulate_ctxt.vcpu = vcpu;
		vcpu->emulate_ctxt.eflags = kvm_x86_ops->get_rflags(vcpu);
		vcpu->emulate_ctxt.cr2 = cr2;
		vcpu->emulate_ctxt.mode =
			(vcpu->emulate_ctxt.eflags & X86_EFLAGS_VM)
			? X86EMUL_MODE_REAL : cs_l
			? X86EMUL_MODE_PROT64 :	cs_db
			? X86EMUL_MODE_PROT32 : X86EMUL_MODE_PROT16;

		if (vcpu->emulate_ctxt.mode == X86EMUL_MODE_PROT64) {
			vcpu->emulate_ctxt.cs_base = 0;
			vcpu->emulate_ctxt.ds_base = 0;
			vcpu->emulate_ctxt.es_base = 0;
			vcpu->emulate_ctxt.ss_base = 0;
		} else {
			vcpu->emulate_ctxt.cs_base =
					get_segment_base(vcpu, VCPU_SREG_CS);
			vcpu->emulate_ctxt.ds_base =
					get_segment_base(vcpu, VCPU_SREG_DS);
			vcpu->emulate_ctxt.es_base =
					get_segment_base(vcpu, VCPU_SREG_ES);
			vcpu->emulate_ctxt.ss_base =
					get_segment_base(vcpu, VCPU_SREG_SS);
		}

		vcpu->emulate_ctxt.gs_base =
					get_segment_base(vcpu, VCPU_SREG_GS);
		vcpu->emulate_ctxt.fs_base =
					get_segment_base(vcpu, VCPU_SREG_FS);

		r = x86_decode_insn(&vcpu->emulate_ctxt, &emulate_ops);
		if (r)  {
			if (kvm_mmu_unprotect_page_virt(vcpu, cr2))
				return EMULATE_DONE;
			return EMULATE_FAIL;
		}
	}

	r = x86_emulate_insn(&vcpu->emulate_ctxt, &emulate_ops);

	if (vcpu->pio.string)
		return EMULATE_DO_MMIO;

	if ((r || vcpu->mmio_is_write) && run) {
		run->exit_reason = KVM_EXIT_MMIO;
		run->mmio.phys_addr = vcpu->mmio_phys_addr;
		memcpy(run->mmio.data, vcpu->mmio_data, 8);
		run->mmio.len = vcpu->mmio_size;
		run->mmio.is_write = vcpu->mmio_is_write;
	}

	if (r) {
		if (kvm_mmu_unprotect_page_virt(vcpu, cr2))
			return EMULATE_DONE;
		if (!vcpu->mmio_needed) {
			kvm_report_emulation_failure(vcpu, "mmio");
			return EMULATE_FAIL;
		}
		return EMULATE_DO_MMIO;
	}

	kvm_x86_ops->decache_regs(vcpu);
	kvm_x86_ops->set_rflags(vcpu, vcpu->emulate_ctxt.eflags);

	if (vcpu->mmio_is_write) {
		vcpu->mmio_needed = 0;
		return EMULATE_DO_MMIO;
	}

	return EMULATE_DONE;
}
EXPORT_SYMBOL_GPL(emulate_instruction);

static void free_pio_guest_pages(struct kvm_vcpu *vcpu)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(vcpu->pio.guest_pages); ++i)
		if (vcpu->pio.guest_pages[i]) {
			kvm_release_page(vcpu->pio.guest_pages[i]);
			vcpu->pio.guest_pages[i] = NULL;
		}
}

static int pio_copy_data(struct kvm_vcpu *vcpu)
{
	void *p = vcpu->pio_data;
	void *q;
	unsigned bytes;
	int nr_pages = vcpu->pio.guest_pages[1] ? 2 : 1;

	q = vmap(vcpu->pio.guest_pages, nr_pages, VM_READ|VM_WRITE,
		 PAGE_KERNEL);
	if (!q) {
		free_pio_guest_pages(vcpu);
		return -ENOMEM;
	}
	q += vcpu->pio.guest_page_offset;
	bytes = vcpu->pio.size * vcpu->pio.cur_count;
	if (vcpu->pio.in)
		memcpy(q, p, bytes);
	else
		memcpy(p, q, bytes);
	q -= vcpu->pio.guest_page_offset;
	vunmap(q);
	free_pio_guest_pages(vcpu);
	return 0;
}

int complete_pio(struct kvm_vcpu *vcpu)
{
	struct kvm_pio_request *io = &vcpu->pio;
	long delta;
	int r;

	kvm_x86_ops->cache_regs(vcpu);

	if (!io->string) {
		if (io->in)
			memcpy(&vcpu->regs[VCPU_REGS_RAX], vcpu->pio_data,
			       io->size);
	} else {
		if (io->in) {
			r = pio_copy_data(vcpu);
			if (r) {
				kvm_x86_ops->cache_regs(vcpu);
				return r;
			}
		}

		delta = 1;
		if (io->rep) {
			delta *= io->cur_count;
			/*
			 * The size of the register should really depend on
			 * current address size.
			 */
			vcpu->regs[VCPU_REGS_RCX] -= delta;
		}
		if (io->down)
			delta = -delta;
		delta *= io->size;
		if (io->in)
			vcpu->regs[VCPU_REGS_RDI] += delta;
		else
			vcpu->regs[VCPU_REGS_RSI] += delta;
	}

	kvm_x86_ops->decache_regs(vcpu);

	io->count -= io->cur_count;
	io->cur_count = 0;

	return 0;
}

static void kernel_pio(struct kvm_io_device *pio_dev,
		       struct kvm_vcpu *vcpu,
		       void *pd)
{
	/* TODO: String I/O for in kernel device */

	mutex_lock(&vcpu->kvm->lock);
	if (vcpu->pio.in)
		kvm_iodevice_read(pio_dev, vcpu->pio.port,
				  vcpu->pio.size,
				  pd);
	else
		kvm_iodevice_write(pio_dev, vcpu->pio.port,
				   vcpu->pio.size,
				   pd);
	mutex_unlock(&vcpu->kvm->lock);
}

static void pio_string_write(struct kvm_io_device *pio_dev,
			     struct kvm_vcpu *vcpu)
{
	struct kvm_pio_request *io = &vcpu->pio;
	void *pd = vcpu->pio_data;
	int i;

	mutex_lock(&vcpu->kvm->lock);
	for (i = 0; i < io->cur_count; i++) {
		kvm_iodevice_write(pio_dev, io->port,
				   io->size,
				   pd);
		pd += io->size;
	}
	mutex_unlock(&vcpu->kvm->lock);
}

static struct kvm_io_device *vcpu_find_pio_dev(struct kvm_vcpu *vcpu,
					       gpa_t addr)
{
	return kvm_io_bus_find_dev(&vcpu->kvm->pio_bus, addr);
}

int kvm_emulate_pio(struct kvm_vcpu *vcpu, struct kvm_run *run, int in,
		  int size, unsigned port)
{
	struct kvm_io_device *pio_dev;

	vcpu->run->exit_reason = KVM_EXIT_IO;
	vcpu->run->io.direction = in ? KVM_EXIT_IO_IN : KVM_EXIT_IO_OUT;
	vcpu->run->io.size = vcpu->pio.size = size;
	vcpu->run->io.data_offset = KVM_PIO_PAGE_OFFSET * PAGE_SIZE;
	vcpu->run->io.count = vcpu->pio.count = vcpu->pio.cur_count = 1;
	vcpu->run->io.port = vcpu->pio.port = port;
	vcpu->pio.in = in;
	vcpu->pio.string = 0;
	vcpu->pio.down = 0;
	vcpu->pio.guest_page_offset = 0;
	vcpu->pio.rep = 0;

	kvm_x86_ops->cache_regs(vcpu);
	memcpy(vcpu->pio_data, &vcpu->regs[VCPU_REGS_RAX], 4);
	kvm_x86_ops->decache_regs(vcpu);

	kvm_x86_ops->skip_emulated_instruction(vcpu);

	pio_dev = vcpu_find_pio_dev(vcpu, port);
	if (pio_dev) {
		kernel_pio(pio_dev, vcpu, vcpu->pio_data);
		complete_pio(vcpu);
		return 1;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_emulate_pio);

int kvm_emulate_pio_string(struct kvm_vcpu *vcpu, struct kvm_run *run, int in,
		  int size, unsigned long count, int down,
		  gva_t address, int rep, unsigned port)
{
	unsigned now, in_page;
	int i, ret = 0;
	int nr_pages = 1;
	struct page *page;
	struct kvm_io_device *pio_dev;

	vcpu->run->exit_reason = KVM_EXIT_IO;
	vcpu->run->io.direction = in ? KVM_EXIT_IO_IN : KVM_EXIT_IO_OUT;
	vcpu->run->io.size = vcpu->pio.size = size;
	vcpu->run->io.data_offset = KVM_PIO_PAGE_OFFSET * PAGE_SIZE;
	vcpu->run->io.count = vcpu->pio.count = vcpu->pio.cur_count = count;
	vcpu->run->io.port = vcpu->pio.port = port;
	vcpu->pio.in = in;
	vcpu->pio.string = 1;
	vcpu->pio.down = down;
	vcpu->pio.guest_page_offset = offset_in_page(address);
	vcpu->pio.rep = rep;

	if (!count) {
		kvm_x86_ops->skip_emulated_instruction(vcpu);
		return 1;
	}

	if (!down)
		in_page = PAGE_SIZE - offset_in_page(address);
	else
		in_page = offset_in_page(address) + size;
	now = min(count, (unsigned long)in_page / size);
	if (!now) {
		/*
		 * String I/O straddles page boundary.  Pin two guest pages
		 * so that we satisfy atomicity constraints.  Do just one
		 * transaction to avoid complexity.
		 */
		nr_pages = 2;
		now = 1;
	}
	if (down) {
		/*
		 * String I/O in reverse.  Yuck.  Kill the guest, fix later.
		 */
		pr_unimpl(vcpu, "guest string pio down\n");
		inject_gp(vcpu);
		return 1;
	}
	vcpu->run->io.count = now;
	vcpu->pio.cur_count = now;

	if (vcpu->pio.cur_count == vcpu->pio.count)
		kvm_x86_ops->skip_emulated_instruction(vcpu);

	for (i = 0; i < nr_pages; ++i) {
		mutex_lock(&vcpu->kvm->lock);
		page = gva_to_page(vcpu, address + i * PAGE_SIZE);
		vcpu->pio.guest_pages[i] = page;
		mutex_unlock(&vcpu->kvm->lock);
		if (!page) {
			inject_gp(vcpu);
			free_pio_guest_pages(vcpu);
			return 1;
		}
	}

	pio_dev = vcpu_find_pio_dev(vcpu, port);
	if (!vcpu->pio.in) {
		/* string PIO write */
		ret = pio_copy_data(vcpu);
		if (ret >= 0 && pio_dev) {
			pio_string_write(pio_dev, vcpu);
			complete_pio(vcpu);
			if (vcpu->pio.count == 0)
				ret = 1;
		}
	} else if (pio_dev)
		pr_unimpl(vcpu, "no string pio read support yet, "
		       "port %x size %d count %ld\n",
			port, size, count);

	return ret;
}
EXPORT_SYMBOL_GPL(kvm_emulate_pio_string);

__init void kvm_arch_init(void)
{
	kvm_init_msr_list();
}

int kvm_emulate_halt(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.halt_exits;
	if (irqchip_in_kernel(vcpu->kvm)) {
		vcpu->mp_state = VCPU_MP_STATE_HALTED;
		kvm_vcpu_block(vcpu);
		if (vcpu->mp_state != VCPU_MP_STATE_RUNNABLE)
			return -EINTR;
		return 1;
	} else {
		vcpu->run->exit_reason = KVM_EXIT_HLT;
		return 0;
	}
}
EXPORT_SYMBOL_GPL(kvm_emulate_halt);

int kvm_emulate_hypercall(struct kvm_vcpu *vcpu)
{
	unsigned long nr, a0, a1, a2, a3, ret;

	kvm_x86_ops->cache_regs(vcpu);

	nr = vcpu->regs[VCPU_REGS_RAX];
	a0 = vcpu->regs[VCPU_REGS_RBX];
	a1 = vcpu->regs[VCPU_REGS_RCX];
	a2 = vcpu->regs[VCPU_REGS_RDX];
	a3 = vcpu->regs[VCPU_REGS_RSI];

	if (!is_long_mode(vcpu)) {
		nr &= 0xFFFFFFFF;
		a0 &= 0xFFFFFFFF;
		a1 &= 0xFFFFFFFF;
		a2 &= 0xFFFFFFFF;
		a3 &= 0xFFFFFFFF;
	}

	switch (nr) {
	default:
		ret = -KVM_ENOSYS;
		break;
	}
	vcpu->regs[VCPU_REGS_RAX] = ret;
	kvm_x86_ops->decache_regs(vcpu);
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_emulate_hypercall);

int kvm_fix_hypercall(struct kvm_vcpu *vcpu)
{
	char instruction[3];
	int ret = 0;

	mutex_lock(&vcpu->kvm->lock);

	/*
	 * Blow out the MMU to ensure that no other VCPU has an active mapping
	 * to ensure that the updated hypercall appears atomically across all
	 * VCPUs.
	 */
	kvm_mmu_zap_all(vcpu->kvm);

	kvm_x86_ops->cache_regs(vcpu);
	kvm_x86_ops->patch_hypercall(vcpu, instruction);
	if (emulator_write_emulated(vcpu->rip, instruction, 3, vcpu)
	    != X86EMUL_CONTINUE)
		ret = -EFAULT;

	mutex_unlock(&vcpu->kvm->lock);

	return ret;
}

static u64 mk_cr_64(u64 curr_cr, u32 new_val)
{
	return (curr_cr & ~((1ULL << 32) - 1)) | new_val;
}

void realmode_lgdt(struct kvm_vcpu *vcpu, u16 limit, unsigned long base)
{
	struct descriptor_table dt = { limit, base };

	kvm_x86_ops->set_gdt(vcpu, &dt);
}

void realmode_lidt(struct kvm_vcpu *vcpu, u16 limit, unsigned long base)
{
	struct descriptor_table dt = { limit, base };

	kvm_x86_ops->set_idt(vcpu, &dt);
}

void realmode_lmsw(struct kvm_vcpu *vcpu, unsigned long msw,
		   unsigned long *rflags)
{
	lmsw(vcpu, msw);
	*rflags = kvm_x86_ops->get_rflags(vcpu);
}

unsigned long realmode_get_cr(struct kvm_vcpu *vcpu, int cr)
{
	kvm_x86_ops->decache_cr4_guest_bits(vcpu);
	switch (cr) {
	case 0:
		return vcpu->cr0;
	case 2:
		return vcpu->cr2;
	case 3:
		return vcpu->cr3;
	case 4:
		return vcpu->cr4;
	default:
		vcpu_printf(vcpu, "%s: unexpected cr %u\n", __FUNCTION__, cr);
		return 0;
	}
}

void realmode_set_cr(struct kvm_vcpu *vcpu, int cr, unsigned long val,
		     unsigned long *rflags)
{
	switch (cr) {
	case 0:
		set_cr0(vcpu, mk_cr_64(vcpu->cr0, val));
		*rflags = kvm_x86_ops->get_rflags(vcpu);
		break;
	case 2:
		vcpu->cr2 = val;
		break;
	case 3:
		set_cr3(vcpu, val);
		break;
	case 4:
		set_cr4(vcpu, mk_cr_64(vcpu->cr4, val));
		break;
	default:
		vcpu_printf(vcpu, "%s: unexpected cr %u\n", __FUNCTION__, cr);
	}
}

void kvm_emulate_cpuid(struct kvm_vcpu *vcpu)
{
	int i;
	u32 function;
	struct kvm_cpuid_entry *e, *best;

	kvm_x86_ops->cache_regs(vcpu);
	function = vcpu->regs[VCPU_REGS_RAX];
	vcpu->regs[VCPU_REGS_RAX] = 0;
	vcpu->regs[VCPU_REGS_RBX] = 0;
	vcpu->regs[VCPU_REGS_RCX] = 0;
	vcpu->regs[VCPU_REGS_RDX] = 0;
	best = NULL;
	for (i = 0; i < vcpu->cpuid_nent; ++i) {
		e = &vcpu->cpuid_entries[i];
		if (e->function == function) {
			best = e;
			break;
		}
		/*
		 * Both basic or both extended?
		 */
		if (((e->function ^ function) & 0x80000000) == 0)
			if (!best || e->function > best->function)
				best = e;
	}
	if (best) {
		vcpu->regs[VCPU_REGS_RAX] = best->eax;
		vcpu->regs[VCPU_REGS_RBX] = best->ebx;
		vcpu->regs[VCPU_REGS_RCX] = best->ecx;
		vcpu->regs[VCPU_REGS_RDX] = best->edx;
	}
	kvm_x86_ops->decache_regs(vcpu);
	kvm_x86_ops->skip_emulated_instruction(vcpu);
}
EXPORT_SYMBOL_GPL(kvm_emulate_cpuid);
