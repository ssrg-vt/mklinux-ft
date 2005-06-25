/*
 * Architecture specific (i386) functions for kexec based crash dumps.
 *
 * Created by: Hariprasad Nellitheertha (hari@in.ibm.com)
 *
 * Copyright (C) IBM Corporation, 2004. All rights reserved.
 *
 */

#include <linux/init.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/smp.h>
#include <linux/irq.h>
#include <linux/reboot.h>
#include <linux/kexec.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/elf.h>
#include <linux/elfcore.h>

#include <asm/processor.h>
#include <asm/hardirq.h>
#include <asm/nmi.h>
#include <asm/hw_irq.h>
#include <asm/apic.h>
#include <mach_ipi.h>

#define MAX_NOTE_BYTES 1024
typedef u32 note_buf_t[MAX_NOTE_BYTES/4];

note_buf_t crash_notes[NR_CPUS];

static u32 *append_elf_note(u32 *buf,
	char *name, unsigned type, void *data, size_t data_len)
{
	struct elf_note note;
	note.n_namesz = strlen(name) + 1;
	note.n_descsz = data_len;
	note.n_type   = type;
	memcpy(buf, &note, sizeof(note));
	buf += (sizeof(note) +3)/4;
	memcpy(buf, name, note.n_namesz);
	buf += (note.n_namesz + 3)/4;
	memcpy(buf, data, note.n_descsz);
	buf += (note.n_descsz + 3)/4;
	return buf;
}

static void final_note(u32 *buf)
{
	struct elf_note note;
	note.n_namesz = 0;
	note.n_descsz = 0;
	note.n_type   = 0;
	memcpy(buf, &note, sizeof(note));
}


static void crash_save_this_cpu(struct pt_regs *regs, int cpu)
{
	struct elf_prstatus prstatus;
	u32 *buf;
	if ((cpu < 0) || (cpu >= NR_CPUS)) {
		return;
	}
	/* Using ELF notes here is opportunistic.
	 * I need a well defined structure format
	 * for the data I pass, and I need tags
	 * on the data to indicate what information I have
	 * squirrelled away.  ELF notes happen to provide
	 * all of that that no need to invent something new.
	 */
	buf = &crash_notes[cpu][0];
	memset(&prstatus, 0, sizeof(prstatus));
	prstatus.pr_pid = current->pid;
	elf_core_copy_regs(&prstatus.pr_reg, regs);
	buf = append_elf_note(buf, "CORE", NT_PRSTATUS,
		&prstatus, sizeof(prstatus));

	final_note(buf);
}

static void crash_get_current_regs(struct pt_regs *regs)
{
	__asm__ __volatile__("movl %%ebx,%0" : "=m"(regs->ebx));
	__asm__ __volatile__("movl %%ecx,%0" : "=m"(regs->ecx));
	__asm__ __volatile__("movl %%edx,%0" : "=m"(regs->edx));
	__asm__ __volatile__("movl %%esi,%0" : "=m"(regs->esi));
	__asm__ __volatile__("movl %%edi,%0" : "=m"(regs->edi));
	__asm__ __volatile__("movl %%ebp,%0" : "=m"(regs->ebp));
	__asm__ __volatile__("movl %%eax,%0" : "=m"(regs->eax));
	__asm__ __volatile__("movl %%esp,%0" : "=m"(regs->esp));
	__asm__ __volatile__("movw %%ss, %%ax;" :"=a"(regs->xss));
	__asm__ __volatile__("movw %%cs, %%ax;" :"=a"(regs->xcs));
	__asm__ __volatile__("movw %%ds, %%ax;" :"=a"(regs->xds));
	__asm__ __volatile__("movw %%es, %%ax;" :"=a"(regs->xes));
	__asm__ __volatile__("pushfl; popl %0" :"=m"(regs->eflags));

	regs->eip = (unsigned long)current_text_addr();
}

static void crash_save_self(void)
{
	struct pt_regs regs;
	int cpu;
	cpu = smp_processor_id();
	crash_get_current_regs(&regs);
	crash_save_this_cpu(&regs, cpu);
}

#ifdef CONFIG_SMP
static atomic_t waiting_for_crash_ipi;

static int crash_nmi_callback(struct pt_regs *regs, int cpu)
{
	local_irq_disable();
	crash_save_this_cpu(regs, cpu);
	disable_local_APIC();
	atomic_dec(&waiting_for_crash_ipi);
	/* Assume hlt works */
	__asm__("hlt");
	for(;;);
	return 1;
}

/*
 * By using the NMI code instead of a vector we just sneak thru the
 * word generator coming out with just what we want.  AND it does
 * not matter if clustered_apic_mode is set or not.
 */
static void smp_send_nmi_allbutself(void)
{
	send_IPI_allbutself(APIC_DM_NMI);
}

static void nmi_shootdown_cpus(void)
{
	unsigned long msecs;
	atomic_set(&waiting_for_crash_ipi, num_online_cpus() - 1);

	/* Would it be better to replace the trap vector here? */
	set_nmi_callback(crash_nmi_callback);
	/* Ensure the new callback function is set before sending
	 * out the NMI
	 */
	wmb();

	smp_send_nmi_allbutself();

	msecs = 1000; /* Wait at most a second for the other cpus to stop */
	while ((atomic_read(&waiting_for_crash_ipi) > 0) && msecs) {
		mdelay(1);
		msecs--;
	}

	/* Leave the nmi callback set */
	disable_local_APIC();
}
#else
static void nmi_shootdown_cpus(void)
{
	/* There are no cpus to shootdown */
}
#endif

void machine_crash_shutdown(void)
{
	/* This function is only called after the system
	 * has paniced or is otherwise in a critical state.
	 * The minimum amount of code to allow a kexec'd kernel
	 * to run successfully needs to happen here.
	 *
	 * In practice this means shooting down the other cpus in
	 * an SMP system.
	 */
	/* The kernel is broken so disable interrupts */
	local_irq_disable();
	nmi_shootdown_cpus();
	lapic_shutdown();
#if defined(CONFIG_X86_IO_APIC)
	disable_IO_APIC();
#endif
	crash_save_self();
}
