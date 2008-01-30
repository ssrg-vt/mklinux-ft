#/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This header defines architecture specific interfaces, x86 version
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef KVM_X86_H
#define KVM_X86_H

#include "kvm.h"

#include <linux/types.h>
#include <linux/mm.h>

#include <linux/kvm.h>
#include <linux/kvm_para.h>

struct kvm_vcpu {
	KVM_VCPU_COMM;
	u64 host_tsc;
	int interrupt_window_open;
	unsigned long irq_summary; /* bit vector: 1 per word in irq_pending */
	DECLARE_BITMAP(irq_pending, KVM_NR_INTERRUPTS);
	unsigned long regs[NR_VCPU_REGS]; /* for rsp: vcpu_load_rsp_rip() */
	unsigned long rip;      /* needs vcpu_load_rsp_rip() */

	unsigned long cr0;
	unsigned long cr2;
	unsigned long cr3;
	unsigned long cr4;
	unsigned long cr8;
	u64 pdptrs[4]; /* pae */
	u64 shadow_efer;
	u64 apic_base;
	struct kvm_lapic *apic;    /* kernel irqchip context */
#define VCPU_MP_STATE_RUNNABLE          0
#define VCPU_MP_STATE_UNINITIALIZED     1
#define VCPU_MP_STATE_INIT_RECEIVED     2
#define VCPU_MP_STATE_SIPI_RECEIVED     3
#define VCPU_MP_STATE_HALTED            4
	int mp_state;
	int sipi_vector;
	u64 ia32_misc_enable_msr;

	struct kvm_mmu mmu;

	struct kvm_mmu_memory_cache mmu_pte_chain_cache;
	struct kvm_mmu_memory_cache mmu_rmap_desc_cache;
	struct kvm_mmu_memory_cache mmu_page_cache;
	struct kvm_mmu_memory_cache mmu_page_header_cache;

	gfn_t last_pt_write_gfn;
	int   last_pt_write_count;
	u64  *last_pte_updated;


	struct i387_fxsave_struct host_fx_image;
	struct i387_fxsave_struct guest_fx_image;

	gva_t mmio_fault_cr2;
	struct kvm_pio_request pio;
	void *pio_data;

	struct {
		int active;
		u8 save_iopl;
		struct kvm_save_segment {
			u16 selector;
			unsigned long base;
			u32 limit;
			u32 ar;
		} tr, es, ds, fs, gs;
	} rmode;
	int halt_request; /* real mode on Intel only */

	int cpuid_nent;
	struct kvm_cpuid_entry cpuid_entries[KVM_MAX_CPUID_ENTRIES];

	/* emulate context */

	struct x86_emulate_ctxt emulate_ctxt;
};

extern struct kvm_x86_ops *kvm_x86_ops;

int kvm_mmu_page_fault(struct kvm_vcpu *vcpu, gva_t gva, u32 error_code);

static inline void kvm_mmu_free_some_pages(struct kvm_vcpu *vcpu)
{
	if (unlikely(vcpu->kvm->n_free_mmu_pages < KVM_MIN_FREE_MMU_PAGES))
		__kvm_mmu_free_some_pages(vcpu);
}

static inline int kvm_mmu_reload(struct kvm_vcpu *vcpu)
{
	if (likely(vcpu->mmu.root_hpa != INVALID_PAGE))
		return 0;

	return kvm_mmu_load(vcpu);
}

static inline int is_long_mode(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_X86_64
	return vcpu->shadow_efer & EFER_LME;
#else
	return 0;
#endif
}

static inline int is_pae(struct kvm_vcpu *vcpu)
{
	return vcpu->cr4 & X86_CR4_PAE;
}

static inline int is_pse(struct kvm_vcpu *vcpu)
{
	return vcpu->cr4 & X86_CR4_PSE;
}

static inline int is_paging(struct kvm_vcpu *vcpu)
{
	return vcpu->cr0 & X86_CR0_PG;
}

int load_pdptrs(struct kvm_vcpu *vcpu, unsigned long cr3);
int complete_pio(struct kvm_vcpu *vcpu);
#endif
