/*
 * arch/arm/mach-ep93xx/core.c
 * Core routines for Cirrus EP93xx chips.
 *
 * Copyright (C) 2006 Lennert Buytenhek <buytenh@wantstofly.org>
 *
 * Thanks go to Michael Burian and Ray Lehtiniemi for their key
 * role in the ep93xx linux community.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/serial.h>
#include <linux/tty.h>
#include <linux/bitops.h>
#include <linux/serial.h>
#include <linux/serial_8250.h>
#include <linux/serial_core.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/delay.h>
#include <linux/amba/bus.h>

#include <asm/types.h>
#include <asm/setup.h>
#include <asm/memory.h>
#include <asm/hardware.h>
#include <asm/irq.h>
#include <asm/system.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <asm/io.h>

#include <asm/mach/map.h>
#include <asm/mach/time.h>
#include <asm/mach/irq.h>
#include <asm/arch/gpio.h>

#include <asm/hardware/vic.h>


/*************************************************************************
 * Static I/O mappings that are needed for all EP93xx platforms
 *************************************************************************/
static struct map_desc ep93xx_io_desc[] __initdata = {
	{
		.virtual	= EP93XX_AHB_VIRT_BASE,
		.pfn		= __phys_to_pfn(EP93XX_AHB_PHYS_BASE),
		.length		= EP93XX_AHB_SIZE,
		.type		= MT_DEVICE,
	}, {
		.virtual	= EP93XX_APB_VIRT_BASE,
		.pfn		= __phys_to_pfn(EP93XX_APB_PHYS_BASE),
		.length		= EP93XX_APB_SIZE,
		.type		= MT_DEVICE,
	},
};

void __init ep93xx_map_io(void)
{
	iotable_init(ep93xx_io_desc, ARRAY_SIZE(ep93xx_io_desc));
}


/*************************************************************************
 * Timer handling for EP93xx
 *************************************************************************
 * The ep93xx has four internal timers.  Timers 1, 2 (both 16 bit) and
 * 3 (32 bit) count down at 508 kHz, are self-reloading, and can generate
 * an interrupt on underflow.  Timer 4 (40 bit) counts down at 983.04 kHz,
 * is free-running, and can't generate interrupts.
 *
 * The 508 kHz timers are ideal for use for the timer interrupt, as the
 * most common values of HZ divide 508 kHz nicely.  We pick one of the 16
 * bit timers (timer 1) since we don't need more than 16 bits of reload
 * value as long as HZ >= 8.
 *
 * The higher clock rate of timer 4 makes it a better choice than the
 * other timers for use in gettimeoffset(), while the fact that it can't
 * generate interrupts means we don't have to worry about not being able
 * to use this timer for something else.  We also use timer 4 for keeping
 * track of lost jiffies.
 */
static unsigned int last_jiffy_time;

#define TIMER4_TICKS_PER_JIFFY		((CLOCK_TICK_RATE + (HZ/2)) / HZ)

static int ep93xx_timer_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	write_seqlock(&xtime_lock);

	__raw_writel(1, EP93XX_TIMER1_CLEAR);
	while (__raw_readl(EP93XX_TIMER4_VALUE_LOW) - last_jiffy_time
						>= TIMER4_TICKS_PER_JIFFY) {
		last_jiffy_time += TIMER4_TICKS_PER_JIFFY;
		timer_tick(regs);
	}

	write_sequnlock(&xtime_lock);

	return IRQ_HANDLED;
}

static struct irqaction ep93xx_timer_irq = {
	.name		= "ep93xx timer",
	.flags		= SA_INTERRUPT | SA_TIMER,
	.handler	= ep93xx_timer_interrupt,
};

static void __init ep93xx_timer_init(void)
{
	/* Enable periodic HZ timer.  */
	__raw_writel(0x48, EP93XX_TIMER1_CONTROL);
	__raw_writel((508000 / HZ) - 1, EP93XX_TIMER1_LOAD);
	__raw_writel(0xc8, EP93XX_TIMER1_CONTROL);

	/* Enable lost jiffy timer.  */
	__raw_writel(0x100, EP93XX_TIMER4_VALUE_HIGH);

	setup_irq(IRQ_EP93XX_TIMER1, &ep93xx_timer_irq);
}

static unsigned long ep93xx_gettimeoffset(void)
{
	int offset;

	offset = __raw_readl(EP93XX_TIMER4_VALUE_LOW) - last_jiffy_time;

	/* Calculate (1000000 / 983040) * offset.  */
	return offset + (53 * offset / 3072);
}

struct sys_timer ep93xx_timer = {
	.init		= ep93xx_timer_init,
	.offset		= ep93xx_gettimeoffset,
};


/*************************************************************************
 * GPIO handling for EP93xx
 *************************************************************************/
static unsigned char data_register_offset[8] = {
	0x00, 0x04, 0x08, 0x0c, 0x20, 0x30, 0x38, 0x40,
};

static unsigned char data_direction_register_offset[8] = {
	0x10, 0x14, 0x18, 0x1c, 0x24, 0x34, 0x3c, 0x44,
};

void gpio_line_config(int line, int direction)
{
	unsigned int data_direction_register;
	unsigned long flags;
	unsigned char v;

	data_direction_register =
		EP93XX_GPIO_REG(data_direction_register_offset[line >> 3]);

	local_irq_save(flags);
	if (direction == GPIO_OUT) {
		v = __raw_readb(data_direction_register);
		v |= 1 << (line & 7);
		__raw_writeb(v, data_direction_register);
	} else if (direction == GPIO_IN) {
		v = __raw_readb(data_direction_register);
		v &= ~(1 << (line & 7));
		__raw_writeb(v, data_direction_register);
	}
	local_irq_restore(flags);
}
EXPORT_SYMBOL(gpio_line_config);

int gpio_line_get(int line)
{
	unsigned int data_register;

	data_register = EP93XX_GPIO_REG(data_register_offset[line >> 3]);

	return !!(__raw_readb(data_register) & (1 << (line & 7)));
}
EXPORT_SYMBOL(gpio_line_get);

void gpio_line_set(int line, int value)
{
	unsigned int data_register;
	unsigned long flags;
	unsigned char v;

	data_register = EP93XX_GPIO_REG(data_register_offset[line >> 3]);

	local_irq_save(flags);
	if (value == EP93XX_GPIO_HIGH) {
		v = __raw_readb(data_register);
		v |= 1 << (line & 7);
		__raw_writeb(v, data_register);
	} else if (value == EP93XX_GPIO_LOW) {
		v = __raw_readb(data_register);
		v &= ~(1 << (line & 7));
		__raw_writeb(v, data_register);
	}
	local_irq_restore(flags);
}
EXPORT_SYMBOL(gpio_line_set);


/*************************************************************************
 * EP93xx IRQ handling
 *************************************************************************/
void __init ep93xx_init_irq(void)
{
	vic_init((void *)EP93XX_VIC1_BASE, 0, EP93XX_VIC1_VALID_IRQ_MASK);
	vic_init((void *)EP93XX_VIC2_BASE, 32, EP93XX_VIC2_VALID_IRQ_MASK);
}


/*************************************************************************
 * EP93xx peripheral handling
 *************************************************************************/
void __init ep93xx_init_devices(void)
{
	unsigned int v;

	/*
	 * Disallow access to MaverickCrunch initially.
	 */
	v = __raw_readl(EP93XX_SYSCON_DEVICE_CONFIG);
	v &= ~EP93XX_SYSCON_DEVICE_CONFIG_CRUNCH_ENABLE;
	__raw_writel(0xaa, EP93XX_SYSCON_SWLOCK);
	__raw_writel(v, EP93XX_SYSCON_DEVICE_CONFIG);
}
