/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright IBM Corp. 2007
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 *          Christian Ehrhardt <ehrhardt@linux.vnet.ibm.com>
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <asm/cputable.h>
#include <asm/uaccess.h>
#include <asm/kvm_ppc.h>
#include <asm/cacheflush.h>

#include "booke.h"
#include "44x_tlb.h"

unsigned long kvmppc_booke_handlers;

#define VM_STAT(x) offsetof(struct kvm, stat.x), KVM_STAT_VM
#define VCPU_STAT(x) offsetof(struct kvm_vcpu, stat.x), KVM_STAT_VCPU

struct kvm_stats_debugfs_item debugfs_entries[] = {
	{ "mmio",       VCPU_STAT(mmio_exits) },
	{ "dcr",        VCPU_STAT(dcr_exits) },
	{ "sig",        VCPU_STAT(signal_exits) },
	{ "itlb_r",     VCPU_STAT(itlb_real_miss_exits) },
	{ "itlb_v",     VCPU_STAT(itlb_virt_miss_exits) },
	{ "dtlb_r",     VCPU_STAT(dtlb_real_miss_exits) },
	{ "dtlb_v",     VCPU_STAT(dtlb_virt_miss_exits) },
	{ "sysc",       VCPU_STAT(syscall_exits) },
	{ "isi",        VCPU_STAT(isi_exits) },
	{ "dsi",        VCPU_STAT(dsi_exits) },
	{ "inst_emu",   VCPU_STAT(emulated_inst_exits) },
	{ "dec",        VCPU_STAT(dec_exits) },
	{ "ext_intr",   VCPU_STAT(ext_intr_exits) },
	{ "halt_wakeup", VCPU_STAT(halt_wakeup) },
	{ NULL }
};

static const u32 interrupt_msr_mask[16] = {
	[BOOKE_INTERRUPT_CRITICAL]      = MSR_ME,
	[BOOKE_INTERRUPT_MACHINE_CHECK] = 0,
	[BOOKE_INTERRUPT_DATA_STORAGE]  = MSR_CE|MSR_ME|MSR_DE,
	[BOOKE_INTERRUPT_INST_STORAGE]  = MSR_CE|MSR_ME|MSR_DE,
	[BOOKE_INTERRUPT_EXTERNAL]      = MSR_CE|MSR_ME|MSR_DE,
	[BOOKE_INTERRUPT_ALIGNMENT]     = MSR_CE|MSR_ME|MSR_DE,
	[BOOKE_INTERRUPT_PROGRAM]       = MSR_CE|MSR_ME|MSR_DE,
	[BOOKE_INTERRUPT_FP_UNAVAIL]    = MSR_CE|MSR_ME|MSR_DE,
	[BOOKE_INTERRUPT_SYSCALL]       = MSR_CE|MSR_ME|MSR_DE,
	[BOOKE_INTERRUPT_AP_UNAVAIL]    = MSR_CE|MSR_ME|MSR_DE,
	[BOOKE_INTERRUPT_DECREMENTER]   = MSR_CE|MSR_ME|MSR_DE,
	[BOOKE_INTERRUPT_FIT]           = MSR_CE|MSR_ME|MSR_DE,
	[BOOKE_INTERRUPT_WATCHDOG]      = MSR_ME,
	[BOOKE_INTERRUPT_DTLB_MISS]     = MSR_CE|MSR_ME|MSR_DE,
	[BOOKE_INTERRUPT_ITLB_MISS]     = MSR_CE|MSR_ME|MSR_DE,
	[BOOKE_INTERRUPT_DEBUG]         = MSR_ME,
};

const unsigned char exception_priority[] = {
	[BOOKE_INTERRUPT_DATA_STORAGE] = 0,
	[BOOKE_INTERRUPT_INST_STORAGE] = 1,
	[BOOKE_INTERRUPT_ALIGNMENT] = 2,
	[BOOKE_INTERRUPT_PROGRAM] = 3,
	[BOOKE_INTERRUPT_FP_UNAVAIL] = 4,
	[BOOKE_INTERRUPT_SYSCALL] = 5,
	[BOOKE_INTERRUPT_AP_UNAVAIL] = 6,
	[BOOKE_INTERRUPT_DTLB_MISS] = 7,
	[BOOKE_INTERRUPT_ITLB_MISS] = 8,
	[BOOKE_INTERRUPT_MACHINE_CHECK] = 9,
	[BOOKE_INTERRUPT_DEBUG] = 10,
	[BOOKE_INTERRUPT_CRITICAL] = 11,
	[BOOKE_INTERRUPT_WATCHDOG] = 12,
	[BOOKE_INTERRUPT_EXTERNAL] = 13,
	[BOOKE_INTERRUPT_FIT] = 14,
	[BOOKE_INTERRUPT_DECREMENTER] = 15,
};

const unsigned char priority_exception[] = {
	BOOKE_INTERRUPT_DATA_STORAGE,
	BOOKE_INTERRUPT_INST_STORAGE,
	BOOKE_INTERRUPT_ALIGNMENT,
	BOOKE_INTERRUPT_PROGRAM,
	BOOKE_INTERRUPT_FP_UNAVAIL,
	BOOKE_INTERRUPT_SYSCALL,
	BOOKE_INTERRUPT_AP_UNAVAIL,
	BOOKE_INTERRUPT_DTLB_MISS,
	BOOKE_INTERRUPT_ITLB_MISS,
	BOOKE_INTERRUPT_MACHINE_CHECK,
	BOOKE_INTERRUPT_DEBUG,
	BOOKE_INTERRUPT_CRITICAL,
	BOOKE_INTERRUPT_WATCHDOG,
	BOOKE_INTERRUPT_EXTERNAL,
	BOOKE_INTERRUPT_FIT,
	BOOKE_INTERRUPT_DECREMENTER,
};


/* TODO: use vcpu_printf() */
void kvmppc_dump_vcpu(struct kvm_vcpu *vcpu)
{
	int i;

	printk("pc:   %08lx msr:  %08lx\n", vcpu->arch.pc, vcpu->arch.msr);
	printk("lr:   %08lx ctr:  %08lx\n", vcpu->arch.lr, vcpu->arch.ctr);
	printk("srr0: %08lx srr1: %08lx\n", vcpu->arch.srr0, vcpu->arch.srr1);

	printk("exceptions: %08lx\n", vcpu->arch.pending_exceptions);

	for (i = 0; i < 32; i += 4) {
		printk("gpr%02d: %08lx %08lx %08lx %08lx\n", i,
		       vcpu->arch.gpr[i],
		       vcpu->arch.gpr[i+1],
		       vcpu->arch.gpr[i+2],
		       vcpu->arch.gpr[i+3]);
	}
}

static void kvmppc_booke_queue_exception(struct kvm_vcpu *vcpu, int exception)
{
	unsigned int priority = exception_priority[exception];
	set_bit(priority, &vcpu->arch.pending_exceptions);
}

static void kvmppc_booke_clear_exception(struct kvm_vcpu *vcpu, int exception)
{
	unsigned int priority = exception_priority[exception];
	clear_bit(priority, &vcpu->arch.pending_exceptions);
}

void kvmppc_core_queue_program(struct kvm_vcpu *vcpu)
{
	kvmppc_booke_queue_exception(vcpu, BOOKE_INTERRUPT_PROGRAM);
}

void kvmppc_core_queue_dec(struct kvm_vcpu *vcpu)
{
	kvmppc_booke_queue_exception(vcpu, BOOKE_INTERRUPT_DECREMENTER);
}

int kvmppc_core_pending_dec(struct kvm_vcpu *vcpu)
{
	unsigned int priority = exception_priority[BOOKE_INTERRUPT_DECREMENTER];
	return test_bit(priority, &vcpu->arch.pending_exceptions);
}

void kvmppc_core_queue_external(struct kvm_vcpu *vcpu,
                                struct kvm_interrupt *irq)
{
	kvmppc_booke_queue_exception(vcpu, BOOKE_INTERRUPT_EXTERNAL);
}

/* Check if we are ready to deliver the interrupt */
static int kvmppc_can_deliver_interrupt(struct kvm_vcpu *vcpu, int interrupt)
{
	int r;

	switch (interrupt) {
	case BOOKE_INTERRUPT_CRITICAL:
		r = vcpu->arch.msr & MSR_CE;
		break;
	case BOOKE_INTERRUPT_MACHINE_CHECK:
		r = vcpu->arch.msr & MSR_ME;
		break;
	case BOOKE_INTERRUPT_EXTERNAL:
		r = vcpu->arch.msr & MSR_EE;
		break;
	case BOOKE_INTERRUPT_DECREMENTER:
		r = vcpu->arch.msr & MSR_EE;
		break;
	case BOOKE_INTERRUPT_FIT:
		r = vcpu->arch.msr & MSR_EE;
		break;
	case BOOKE_INTERRUPT_WATCHDOG:
		r = vcpu->arch.msr & MSR_CE;
		break;
	case BOOKE_INTERRUPT_DEBUG:
		r = vcpu->arch.msr & MSR_DE;
		break;
	default:
		r = 1;
	}

	return r;
}

static void kvmppc_booke_deliver_interrupt(struct kvm_vcpu *vcpu, int interrupt)
{
	switch (interrupt) {
	case BOOKE_INTERRUPT_DECREMENTER:
		vcpu->arch.tsr |= TSR_DIS;
		break;
	}

	vcpu->arch.srr0 = vcpu->arch.pc;
	vcpu->arch.srr1 = vcpu->arch.msr;
	vcpu->arch.pc = vcpu->arch.ivpr | vcpu->arch.ivor[interrupt];
	kvmppc_set_msr(vcpu, vcpu->arch.msr & interrupt_msr_mask[interrupt]);
}

/* Check pending exceptions and deliver one, if possible. */
void kvmppc_core_deliver_interrupts(struct kvm_vcpu *vcpu)
{
	unsigned long *pending = &vcpu->arch.pending_exceptions;
	unsigned int exception;
	unsigned int priority;

	priority = find_first_bit(pending, BITS_PER_BYTE * sizeof(*pending));
	while (priority <= BOOKE_MAX_INTERRUPT) {
		exception = priority_exception[priority];
		if (kvmppc_can_deliver_interrupt(vcpu, exception)) {
			kvmppc_booke_clear_exception(vcpu, exception);
			kvmppc_booke_deliver_interrupt(vcpu, exception);
			break;
		}

		priority = find_next_bit(pending,
		                         BITS_PER_BYTE * sizeof(*pending),
		                         priority + 1);
	}
}

/**
 * kvmppc_handle_exit
 *
 * Return value is in the form (errcode<<2 | RESUME_FLAG_HOST | RESUME_FLAG_NV)
 */
int kvmppc_handle_exit(struct kvm_run *run, struct kvm_vcpu *vcpu,
                       unsigned int exit_nr)
{
	enum emulation_result er;
	int r = RESUME_HOST;

	local_irq_enable();

	run->exit_reason = KVM_EXIT_UNKNOWN;
	run->ready_for_interrupt_injection = 1;

	switch (exit_nr) {
	case BOOKE_INTERRUPT_MACHINE_CHECK:
		printk("MACHINE CHECK: %lx\n", mfspr(SPRN_MCSR));
		kvmppc_dump_vcpu(vcpu);
		r = RESUME_HOST;
		break;

	case BOOKE_INTERRUPT_EXTERNAL:
		vcpu->stat.ext_intr_exits++;
		if (need_resched())
			cond_resched();
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_DECREMENTER:
		/* Since we switched IVPR back to the host's value, the host
		 * handled this interrupt the moment we enabled interrupts.
		 * Now we just offer it a chance to reschedule the guest. */

		/* XXX At this point the TLB still holds our shadow TLB, so if
		 * we do reschedule the host will fault over it. Perhaps we
		 * should politely restore the host's entries to minimize
		 * misses before ceding control. */
		vcpu->stat.dec_exits++;
		if (need_resched())
			cond_resched();
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_PROGRAM:
		if (vcpu->arch.msr & MSR_PR) {
			/* Program traps generated by user-level software must be handled
			 * by the guest kernel. */
			vcpu->arch.esr = vcpu->arch.fault_esr;
			kvmppc_booke_queue_exception(vcpu, BOOKE_INTERRUPT_PROGRAM);
			r = RESUME_GUEST;
			break;
		}

		er = kvmppc_emulate_instruction(run, vcpu);
		switch (er) {
		case EMULATE_DONE:
			/* Future optimization: only reload non-volatiles if
			 * they were actually modified by emulation. */
			vcpu->stat.emulated_inst_exits++;
			r = RESUME_GUEST_NV;
			break;
		case EMULATE_DO_DCR:
			run->exit_reason = KVM_EXIT_DCR;
			vcpu->stat.dcr_exits++;
			r = RESUME_HOST;
			break;
		case EMULATE_FAIL:
			/* XXX Deliver Program interrupt to guest. */
			printk(KERN_CRIT "%s: emulation at %lx failed (%08x)\n",
			       __func__, vcpu->arch.pc, vcpu->arch.last_inst);
			/* For debugging, encode the failing instruction and
			 * report it to userspace. */
			run->hw.hardware_exit_reason = ~0ULL << 32;
			run->hw.hardware_exit_reason |= vcpu->arch.last_inst;
			r = RESUME_HOST;
			break;
		default:
			BUG();
		}
		break;

	case BOOKE_INTERRUPT_FP_UNAVAIL:
		kvmppc_booke_queue_exception(vcpu, exit_nr);
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_DATA_STORAGE:
		vcpu->arch.dear = vcpu->arch.fault_dear;
		vcpu->arch.esr = vcpu->arch.fault_esr;
		kvmppc_booke_queue_exception(vcpu, exit_nr);
		vcpu->stat.dsi_exits++;
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_INST_STORAGE:
		vcpu->arch.esr = vcpu->arch.fault_esr;
		kvmppc_booke_queue_exception(vcpu, exit_nr);
		vcpu->stat.isi_exits++;
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_SYSCALL:
		kvmppc_booke_queue_exception(vcpu, exit_nr);
		vcpu->stat.syscall_exits++;
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_DTLB_MISS: {
		struct kvmppc_44x_tlbe *gtlbe;
		unsigned long eaddr = vcpu->arch.fault_dear;
		gfn_t gfn;

		/* Check the guest TLB. */
		gtlbe = kvmppc_44x_dtlb_search(vcpu, eaddr);
		if (!gtlbe) {
			/* The guest didn't have a mapping for it. */
			kvmppc_booke_queue_exception(vcpu, exit_nr);
			vcpu->arch.dear = vcpu->arch.fault_dear;
			vcpu->arch.esr = vcpu->arch.fault_esr;
			vcpu->stat.dtlb_real_miss_exits++;
			r = RESUME_GUEST;
			break;
		}

		vcpu->arch.paddr_accessed = tlb_xlate(gtlbe, eaddr);
		gfn = vcpu->arch.paddr_accessed >> PAGE_SHIFT;

		if (kvm_is_visible_gfn(vcpu->kvm, gfn)) {
			/* The guest TLB had a mapping, but the shadow TLB
			 * didn't, and it is RAM. This could be because:
			 * a) the entry is mapping the host kernel, or
			 * b) the guest used a large mapping which we're faking
			 * Either way, we need to satisfy the fault without
			 * invoking the guest. */
			kvmppc_mmu_map(vcpu, eaddr, gfn, gtlbe->tid,
			               gtlbe->word2);
			vcpu->stat.dtlb_virt_miss_exits++;
			r = RESUME_GUEST;
		} else {
			/* Guest has mapped and accessed a page which is not
			 * actually RAM. */
			r = kvmppc_emulate_mmio(run, vcpu);
			vcpu->stat.mmio_exits++;
		}

		break;
	}

	case BOOKE_INTERRUPT_ITLB_MISS: {
		struct kvmppc_44x_tlbe *gtlbe;
		unsigned long eaddr = vcpu->arch.pc;
		gfn_t gfn;

		r = RESUME_GUEST;

		/* Check the guest TLB. */
		gtlbe = kvmppc_44x_itlb_search(vcpu, eaddr);
		if (!gtlbe) {
			/* The guest didn't have a mapping for it. */
			kvmppc_booke_queue_exception(vcpu, exit_nr);
			vcpu->stat.itlb_real_miss_exits++;
			break;
		}

		vcpu->stat.itlb_virt_miss_exits++;

		gfn = tlb_xlate(gtlbe, eaddr) >> PAGE_SHIFT;

		if (kvm_is_visible_gfn(vcpu->kvm, gfn)) {
			/* The guest TLB had a mapping, but the shadow TLB
			 * didn't. This could be because:
			 * a) the entry is mapping the host kernel, or
			 * b) the guest used a large mapping which we're faking
			 * Either way, we need to satisfy the fault without
			 * invoking the guest. */
			kvmppc_mmu_map(vcpu, eaddr, gfn, gtlbe->tid,
			               gtlbe->word2);
		} else {
			/* Guest mapped and leaped at non-RAM! */
			kvmppc_booke_queue_exception(vcpu, BOOKE_INTERRUPT_MACHINE_CHECK);
		}

		break;
	}

	case BOOKE_INTERRUPT_DEBUG: {
		u32 dbsr;

		vcpu->arch.pc = mfspr(SPRN_CSRR0);

		/* clear IAC events in DBSR register */
		dbsr = mfspr(SPRN_DBSR);
		dbsr &= DBSR_IAC1 | DBSR_IAC2 | DBSR_IAC3 | DBSR_IAC4;
		mtspr(SPRN_DBSR, dbsr);

		run->exit_reason = KVM_EXIT_DEBUG;
		r = RESUME_HOST;
		break;
	}

	default:
		printk(KERN_EMERG "exit_nr %d\n", exit_nr);
		BUG();
	}

	local_irq_disable();

	kvmppc_core_deliver_interrupts(vcpu);

	if (!(r & RESUME_HOST)) {
		/* To avoid clobbering exit_reason, only check for signals if
		 * we aren't already exiting to userspace for some other
		 * reason. */
		if (signal_pending(current)) {
			run->exit_reason = KVM_EXIT_INTR;
			r = (-EINTR << 2) | RESUME_HOST | (r & RESUME_FLAG_NV);
			vcpu->stat.signal_exits++;
		}
	}

	return r;
}

/* Initial guest state: 16MB mapping 0 -> 0, PC = 0, MSR = 0, R1 = 16MB */
int kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu)
{
	vcpu->arch.pc = 0;
	vcpu->arch.msr = 0;
	vcpu->arch.gpr[1] = (16<<20) - 8; /* -8 for the callee-save LR slot */

	vcpu->arch.shadow_pid = 1;

	/* Eye-catching number so we know if the guest takes an interrupt
	 * before it's programmed its own IVPR. */
	vcpu->arch.ivpr = 0x55550000;

	return kvmppc_core_vcpu_setup(vcpu);
}

int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	int i;

	regs->pc = vcpu->arch.pc;
	regs->cr = vcpu->arch.cr;
	regs->ctr = vcpu->arch.ctr;
	regs->lr = vcpu->arch.lr;
	regs->xer = vcpu->arch.xer;
	regs->msr = vcpu->arch.msr;
	regs->srr0 = vcpu->arch.srr0;
	regs->srr1 = vcpu->arch.srr1;
	regs->pid = vcpu->arch.pid;
	regs->sprg0 = vcpu->arch.sprg0;
	regs->sprg1 = vcpu->arch.sprg1;
	regs->sprg2 = vcpu->arch.sprg2;
	regs->sprg3 = vcpu->arch.sprg3;
	regs->sprg5 = vcpu->arch.sprg4;
	regs->sprg6 = vcpu->arch.sprg5;
	regs->sprg7 = vcpu->arch.sprg6;

	for (i = 0; i < ARRAY_SIZE(regs->gpr); i++)
		regs->gpr[i] = vcpu->arch.gpr[i];

	return 0;
}

int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	int i;

	vcpu->arch.pc = regs->pc;
	vcpu->arch.cr = regs->cr;
	vcpu->arch.ctr = regs->ctr;
	vcpu->arch.lr = regs->lr;
	vcpu->arch.xer = regs->xer;
	kvmppc_set_msr(vcpu, regs->msr);
	vcpu->arch.srr0 = regs->srr0;
	vcpu->arch.srr1 = regs->srr1;
	vcpu->arch.sprg0 = regs->sprg0;
	vcpu->arch.sprg1 = regs->sprg1;
	vcpu->arch.sprg2 = regs->sprg2;
	vcpu->arch.sprg3 = regs->sprg3;
	vcpu->arch.sprg5 = regs->sprg4;
	vcpu->arch.sprg6 = regs->sprg5;
	vcpu->arch.sprg7 = regs->sprg6;

	for (i = 0; i < ARRAY_SIZE(vcpu->arch.gpr); i++)
		vcpu->arch.gpr[i] = regs->gpr[i];

	return 0;
}

int kvm_arch_vcpu_ioctl_get_sregs(struct kvm_vcpu *vcpu,
                                  struct kvm_sregs *sregs)
{
	return -ENOTSUPP;
}

int kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu *vcpu,
                                  struct kvm_sregs *sregs)
{
	return -ENOTSUPP;
}

int kvm_arch_vcpu_ioctl_get_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -ENOTSUPP;
}

int kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -ENOTSUPP;
}

int kvm_arch_vcpu_ioctl_translate(struct kvm_vcpu *vcpu,
                                  struct kvm_translation *tr)
{
	return kvmppc_core_vcpu_translate(vcpu, tr);
}

int kvmppc_booke_init(void)
{
	unsigned long ivor[16];
	unsigned long max_ivor = 0;
	int i;

	/* We install our own exception handlers by hijacking IVPR. IVPR must
	 * be 16-bit aligned, so we need a 64KB allocation. */
	kvmppc_booke_handlers = __get_free_pages(GFP_KERNEL | __GFP_ZERO,
	                                         VCPU_SIZE_ORDER);
	if (!kvmppc_booke_handlers)
		return -ENOMEM;

	/* XXX make sure our handlers are smaller than Linux's */

	/* Copy our interrupt handlers to match host IVORs. That way we don't
	 * have to swap the IVORs on every guest/host transition. */
	ivor[0] = mfspr(SPRN_IVOR0);
	ivor[1] = mfspr(SPRN_IVOR1);
	ivor[2] = mfspr(SPRN_IVOR2);
	ivor[3] = mfspr(SPRN_IVOR3);
	ivor[4] = mfspr(SPRN_IVOR4);
	ivor[5] = mfspr(SPRN_IVOR5);
	ivor[6] = mfspr(SPRN_IVOR6);
	ivor[7] = mfspr(SPRN_IVOR7);
	ivor[8] = mfspr(SPRN_IVOR8);
	ivor[9] = mfspr(SPRN_IVOR9);
	ivor[10] = mfspr(SPRN_IVOR10);
	ivor[11] = mfspr(SPRN_IVOR11);
	ivor[12] = mfspr(SPRN_IVOR12);
	ivor[13] = mfspr(SPRN_IVOR13);
	ivor[14] = mfspr(SPRN_IVOR14);
	ivor[15] = mfspr(SPRN_IVOR15);

	for (i = 0; i < 16; i++) {
		if (ivor[i] > max_ivor)
			max_ivor = ivor[i];

		memcpy((void *)kvmppc_booke_handlers + ivor[i],
		       kvmppc_handlers_start + i * kvmppc_handler_len,
		       kvmppc_handler_len);
	}
	flush_icache_range(kvmppc_booke_handlers,
	                   kvmppc_booke_handlers + max_ivor + kvmppc_handler_len);

	return 0;
}

void __exit kvmppc_booke_exit(void)
{
	free_pages(kvmppc_booke_handlers, VCPU_SIZE_ORDER);
	kvm_exit();
}
