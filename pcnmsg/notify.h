/*
 * notify.h
 *
 *  Created on: Dec 8, 2015
 *      Author: root
 */

#ifndef PCNMSG_NOTIFY_H_
#define PCNMSG_NOTIFY_H_

#include <asm/apic.h>

// NOTE most of this code is pcn_kmsg_windows dependent ... and also x86 specific ... check APIC
// TODO move the code in arch specific

/* win_enable_int
 * win_disable_int
 * win_int_enabled
 *
 * These functions will inhibit senders to send a message while
 * the receiver is processing IPI from any sender.
 */
static inline void win_enable_int(struct pcn_kmsg_window *win) { // this is arch indep
	        win->int_enabled = 1;
	        wmb(); // enforce ordering
}
static inline void win_disable_int(struct pcn_kmsg_window *win) { // this is arch indep
	        win->int_enabled = 0;
	        wmb(); // enforce ordering
}
static inline unsigned char win_int_enabled(struct pcn_kmsg_window *win) { // this is arch indep
    		rmb(); //not sure this is required (Antonio)
	        return win->int_enabled;
}

// TODO
/*
 * when looking to instaurate two classes of interrupts high/normal
 * please consider https://blogs.oracle.com/anish/entry/hardware_interrupts_overview_for_solaris
 * "Hardware interrupts overview for Solaris X86"
 * Note that high prio have a id higher than normal prio
 */


static inline int notify_send (struct pcn_kmsg_window *dest_window)
{
// NOTIFICATION ---------------------------------------------------------------
	/* send IPI */
if (win_int_enabled(dest_window)) {
		KMSG_PRINTK("Interrupts enabled; sending IPI...\n");
		rdtscll(int_ts); // TODO
		apic->send_IPI_single(dest_cpu, POPCORN_KMSG_VECTOR);
	} else {
		KMSG_PRINTK("Interrupts not enabled; not sending IPI...\n");
	}
	return 0;
}

//void pcn_kmsg_do_tasklet(unsigned long);
//DECLARE_TASKLET(pcn_kmsg_tasklet, pcn_kmsg_do_tasklet, 0);

unsigned volatile long isr_ts = 0, isr_ts_2 = 0;

// and this is the callback! or interrupt service runtime!
/* top half */
void smp_popcorn_kmsg_interrupt(struct pt_regs *regs)
{
	//if (!isr_ts) {
		rdtscll(isr_ts);
	//}

	ack_APIC_irq();

	KMSG_PRINTK("Reached Popcorn KMSG interrupt handler!\n");

	inc_irq_stat(irq_popcorn_kmsg_count);
	irq_enter();

	/* We do as little work as possible in here (decoupling notification
	   from messaging) */

	/* disable further interrupts for now */
	win_disable_int(rkvirt[my_cpu]);

	//if (!isr_ts_2) {
	rdtscll(isr_ts_2);
	//}

	/* schedule bottom half */
	//__raise_softirq_irqoff(PCN_KMSG_SOFTIRQ);
	struct work_struct* kmsg_work = kmalloc(sizeof(struct work_struct), GFP_ATOMIC);
	if (kmsg_work) {
		INIT_WORK(kmsg_work,pcn_kmsg_action);
		queue_work(messaging_wq, kmsg_work);
	} else {
		KMSG_ERR("Failed to kmalloc work structure!\n");
	}
	//tasklet_schedule(&pcn_kmsg_tasklet);

	irq_exit();
	return;
}

/* the interrupt handler is registered in arch/x86/kernel/entry_64.S
 * in this way
 * #ifdef CONFIG_POPCORN_KMSG
apicinterrupt POPCORN_KMSG_VECTOR \
	popcorn_kmsg_interrupt smp_popcorn_kmsg_interrupt
apicinterrupt POPCORN_IPI_LATENCY_VECTOR \
	popcorn_ipi_latency_interrupt smp_popcorn_ipi_latency_interrupt
#endif  */ // note that I am not sure there are other ways to register an IPI

/* other files involved are arch/x86/kernel/irqinit.c and arch/x86/include/asm/irq_vectors.h  */

#endif /* PCNMSG_NOTIFY_H_ */
