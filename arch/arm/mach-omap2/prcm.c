/*
 * linux/arch/arm/mach-omap2/prcm.c
 *
 * OMAP 24xx Power Reset and Clock Management (PRCM) functions
 *
 * Copyright (C) 2005 Nokia Corporation
 *
 * Written by Tony Lindgren <tony.lindgren@nokia.com>
 *
 * Some pieces of code Copyright (C) 2005 Texas Instruments, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/clk.h>
#include <linux/io.h>

#include <asm/arch/common.h>
#include <asm/arch/prcm.h>

#include "clock.h"
#include "prm.h"
#include "prm-regbits-24xx.h"

static void __iomem *prm_base;
static void __iomem *cm_base;

extern void omap2_clk_prepare_for_reboot(void);

u32 omap_prcm_get_reset_sources(void)
{
	return prm_read_mod_reg(WKUP_MOD, RM_RSTST) & 0x7f;
}
EXPORT_SYMBOL(omap_prcm_get_reset_sources);

/* Resets clock rates and reboots the system. Only called from system.h */
void omap_prcm_arch_reset(char mode)
{
	u32 wkup;
	omap2_clk_prepare_for_reboot();

	if (cpu_is_omap24xx()) {
		wkup = prm_read_mod_reg(WKUP_MOD, RM_RSTCTRL) | OMAP_RST_DPLL3;
		prm_write_mod_reg(wkup, WKUP_MOD, RM_RSTCTRL);
	}
}

static inline u32 __omap_prcm_read(void __iomem *base, s16 module, u16 reg)
{
	BUG_ON(!base);
	return __raw_readl(base + module + reg);
}

static inline void __omap_prcm_write(u32 value, void __iomem *base,
						s16 module, u16 reg)
{
	BUG_ON(!base);
	__raw_writel(value, base + module + reg);
}

/* Read a register in a PRM module */
u32 prm_read_mod_reg(s16 module, u16 idx)
{
	return __omap_prcm_read(prm_base, module, idx);
}
EXPORT_SYMBOL(prm_read_mod_reg);

/* Write into a register in a PRM module */
void prm_write_mod_reg(u32 val, s16 module, u16 idx)
{
	__omap_prcm_write(val, prm_base, module, idx);
}
EXPORT_SYMBOL(prm_write_mod_reg);

/* Read a register in a CM module */
u32 cm_read_mod_reg(s16 module, u16 idx)
{
	return __omap_prcm_read(cm_base, module, idx);
}
EXPORT_SYMBOL(cm_read_mod_reg);

/* Write into a register in a CM module */
void cm_write_mod_reg(u32 val, s16 module, u16 idx)
{
	__omap_prcm_write(val, cm_base, module, idx);
}
EXPORT_SYMBOL(cm_write_mod_reg);

void __init omap2_set_globals_prcm(struct omap_globals *omap2_globals)
{
	prm_base = omap2_globals->prm;
	cm_base = omap2_globals->cm;
}
