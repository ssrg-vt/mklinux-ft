/*
 * Copyright (C) ST-Ericsson SA 2010
 *
 * Author: Rabin Vincent <rabin.vincent@stericsson.com> for ST-Ericsson
 * License terms: GNU General Public License (GPL) version 2
 */

#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/clk.h>
#include <linux/mfd/db8500-prcmu.h>
#include <linux/mfd/db5500-prcmu.h>

#include <asm/hardware/gic.h>
#include <asm/mach/map.h>
#include <asm/localtimer.h>

#include <plat/mtu.h>
#include <mach/hardware.h>
#include <mach/setup.h>
#include <mach/devices.h>

#include "clock.h"

void __iomem *_PRCMU_BASE;

void __init ux500_init_irq(void)
{
	void __iomem *dist_base;
	void __iomem *cpu_base;

	if (cpu_is_u5500()) {
		dist_base = __io_address(U5500_GIC_DIST_BASE);
		cpu_base = __io_address(U5500_GIC_CPU_BASE);
	} else if (cpu_is_u8500()) {
		dist_base = __io_address(U8500_GIC_DIST_BASE);
		cpu_base = __io_address(U8500_GIC_CPU_BASE);
	} else
		ux500_unknown_soc();

	gic_init(0, 29, dist_base, cpu_base);

	/*
	 * Init clocks here so that they are available for system timer
	 * initialization.
	 */
	if (cpu_is_u5500())
		db5500_prcmu_early_init();
	if (cpu_is_u8500())
		prcmu_early_init();
	clk_init();
}

static void __init ux500_timer_init(void)
{
#ifdef CONFIG_LOCAL_TIMERS
	/* Setup the local timer base */
	if (cpu_is_u5500())
		twd_base = __io_address(U5500_TWD_BASE);
	else if (cpu_is_u8500())
		twd_base = __io_address(U8500_TWD_BASE);
	else
		ux500_unknown_soc();
#endif
	if (cpu_is_u5500())
		mtu_base = __io_address(U5500_MTU0_BASE);
	else if (cpu_is_u8500ed())
		mtu_base = __io_address(U8500_MTU0_BASE_ED);
	else if (cpu_is_u8500())
		mtu_base = __io_address(U8500_MTU0_BASE);
	else
		ux500_unknown_soc();

	nmdk_timer_init();
}

struct sys_timer ux500_timer = {
	.init	= ux500_timer_init,
};
