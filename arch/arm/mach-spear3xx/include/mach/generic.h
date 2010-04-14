/*
 * arch/arm/mach-spear3xx/generic.h
 *
 * SPEAr3XX machine family generic header file
 *
 * Copyright (C) 2009 ST Microelectronics
 * Viresh Kumar<viresh.kumar@st.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef __MACH_GENERIC_H
#define __MACH_GENERIC_H

#include <asm/mach/time.h>
#include <asm/mach/map.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/amba/bus.h>

/*
 * Each GPT has 2 timer channels
 * Following GPT channels will be used as clock source and clockevent
 */
#define SPEAR_GPT0_BASE		SPEAR3XX_ML1_TMR_BASE
#define SPEAR_GPT0_CHAN0_IRQ	IRQ_CPU_GPT1_1
#define SPEAR_GPT0_CHAN1_IRQ	IRQ_CPU_GPT1_2

/* Add spear3xx family device structure declarations here */
extern struct amba_device gpio_device;
extern struct amba_device uart_device;
extern struct sys_timer spear_sys_timer;

/* Add spear3xx family function declarations here */
void __init spear3xx_map_io(void);
void __init spear3xx_init_irq(void);
void __init spear3xx_init(void);
void __init spear300_init(void);
void __init spear310_init(void);
void __init spear320_init(void);
void __init clk_init(void);

/* Add spear300 machine device structure declarations here */
#ifdef CONFIG_MACH_SPEAR300
extern struct amba_device gpio1_device;
#endif /* CONFIG_MACH_SPEAR300 */

/* Add spear310 machine device structure declarations here */
#ifdef CONFIG_MACH_SPEAR310
#endif /* CONFIG_MACH_SPEAR310 */

/* Add spear320 machine device structure declarations here */
#ifdef CONFIG_MACH_SPEAR320
#endif /* CONFIG_MACH_SPEAR320 */

#endif /* __MACH_GENERIC_H */
