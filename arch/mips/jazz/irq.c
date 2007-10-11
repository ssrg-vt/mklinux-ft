/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1992 Linus Torvalds
 * Copyright (C) 1994 - 2001, 2003 Ralf Baechle
 */
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>

#include <asm/irq_cpu.h>
#include <asm/i8259.h>
#include <asm/io.h>
#include <asm/jazz.h>
#include <asm/pgtable.h>

static DEFINE_SPINLOCK(r4030_lock);

static void enable_r4030_irq(unsigned int irq)
{
	unsigned int mask = 1 << (irq - JAZZ_IRQ_START);
	unsigned long flags;

	spin_lock_irqsave(&r4030_lock, flags);
	mask |= r4030_read_reg16(JAZZ_IO_IRQ_ENABLE);
	r4030_write_reg16(JAZZ_IO_IRQ_ENABLE, mask);
	spin_unlock_irqrestore(&r4030_lock, flags);
}

void disable_r4030_irq(unsigned int irq)
{
	unsigned int mask = ~(1 << (irq - JAZZ_IRQ_START));
	unsigned long flags;

	spin_lock_irqsave(&r4030_lock, flags);
	mask &= r4030_read_reg16(JAZZ_IO_IRQ_ENABLE);
	r4030_write_reg16(JAZZ_IO_IRQ_ENABLE, mask);
	spin_unlock_irqrestore(&r4030_lock, flags);
}

static struct irq_chip r4030_irq_type = {
	.name = "R4030",
	.ack = disable_r4030_irq,
	.mask = disable_r4030_irq,
	.mask_ack = disable_r4030_irq,
	.unmask = enable_r4030_irq,
};

void __init init_r4030_ints(void)
{
	int i;

	for (i = JAZZ_IRQ_START; i <= JAZZ_IRQ_END; i++)
		set_irq_chip_and_handler(i, &r4030_irq_type, handle_level_irq);

	r4030_write_reg16(JAZZ_IO_IRQ_ENABLE, 0);
	r4030_read_reg16(JAZZ_IO_IRQ_SOURCE);		/* clear pending IRQs */
	r4030_read_reg32(JAZZ_R4030_INVAL_ADDR);	/* clear error bits */
}

/*
 * On systems with i8259-style interrupt controllers we assume for
 * driver compatibility reasons interrupts 0 - 15 to be the i8259
 * interrupts even if the hardware uses a different interrupt numbering.
 */
void __init arch_init_irq(void)
{
	/*
	 * this is a hack to get back the still needed wired mapping
	 * killed by init_mm()
	 */

	/* Map 0xe0000000 -> 0x0:800005C0, 0xe0010000 -> 0x1:30000580 */
	add_wired_entry(0x02000017, 0x03c00017, 0xe0000000, PM_64K);
	/* Map 0xe2000000 -> 0x0:900005C0, 0xe3010000 -> 0x0:910005C0 */
	add_wired_entry(0x02400017, 0x02440017, 0xe2000000, PM_16M);
	/* Map 0xe4000000 -> 0x0:600005C0, 0xe4100000 -> 400005C0 */
	add_wired_entry(0x01800017, 0x01000017, 0xe4000000, PM_4M);

	init_i8259_irqs();			/* Integrated i8259  */
	mips_cpu_irq_init();
	init_r4030_ints();

	change_c0_status(ST0_IM, IE_IRQ2 | IE_IRQ1);
}

asmlinkage void plat_irq_dispatch(void)
{
	unsigned int pending = read_c0_cause() & read_c0_status();
	unsigned int irq;

	if (pending & IE_IRQ4) {
		r4030_read_reg32(JAZZ_TIMER_REGISTER);
		do_IRQ(JAZZ_TIMER_IRQ);
	} else if (pending & IE_IRQ2)
		do_IRQ(r4030_read_reg32(JAZZ_EISA_IRQ_ACK));
	else if (pending & IE_IRQ1) {
		irq = *(volatile u8 *)JAZZ_IO_IRQ_SOURCE >> 2;
		if (likely(irq > 0))
			do_IRQ(irq + JAZZ_IRQ_START - 1);
		else
			panic("Unimplemented loc_no_irq handler");
	}
}
