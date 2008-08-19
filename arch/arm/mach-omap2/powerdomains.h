/*
 * OMAP2/3 common powerdomain definitions
 *
 * Copyright (C) 2007-8 Texas Instruments, Inc.
 * Copyright (C) 2007-8 Nokia Corporation
 *
 * Written by Paul Walmsley
 * Debugging and integration fixes by Jouni Högander
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef ARCH_ARM_MACH_OMAP2_POWERDOMAINS
#define ARCH_ARM_MACH_OMAP2_POWERDOMAINS

/*
 * This file contains all of the powerdomains that have some element
 * of software control for the OMAP24xx and OMAP34XX chips.
 *
 * A few notes:
 *
 * This is not an exhaustive listing of powerdomains on the chips; only
 * powerdomains that can be controlled in software.
 *
 * A useful validation rule for struct powerdomain:
 * Any powerdomain referenced by a wkdep_srcs or sleepdep_srcs array
 * must have a dep_bit assigned.  So wkdep_srcs/sleepdep_srcs are really
 * just software-controllable dependencies.  Non-software-controllable
 * dependencies do exist, but they are not encoded below (yet).
 *
 * 24xx does not support programmable sleep dependencies (SLEEPDEP)
 *
 */

/*
 * The names for the DSP/IVA2 powerdomains are confusing.
 *
 * Most OMAP chips have an on-board DSP.
 *
 * On the 2420, this is a 'C55 DSP called, simply, the DSP.  Its
 * powerdomain is called the "DSP power domain."  On the 2430, the
 * on-board DSP is a 'C64 DSP, now called the IVA2 or IVA2.1.  Its
 * powerdomain is still called the "DSP power domain."	On the 3430,
 * the DSP is a 'C64 DSP like the 2430, also known as the IVA2; but
 * its powerdomain is now called the "IVA2 power domain."
 *
 * The 2420 also has something called the IVA, which is a separate ARM
 * core, and has nothing to do with the DSP/IVA2.
 *
 * Ideally the DSP/IVA2 could just be the same powerdomain, but the PRCM
 * address offset is different between the C55 and C64 DSPs.
 *
 * The overly-specific dep_bit names are due to a bit name collision
 * with CM_FCLKEN_{DSP,IVA2}.  The DSP/IVA2 PM_WKDEP and CM_SLEEPDEP shift
 * value are the same for all powerdomains: 2
 */

/*
 * XXX should dep_bit be a mask, so we can test to see if it is 0 as a
 * sanity check?
 * XXX encode hardware fixed wakeup dependencies -- esp. for 3430 CORE
 */

#include <mach/powerdomain.h>

#include "prcm-common.h"
#include "prm.h"
#include "cm.h"

/* OMAP2/3-common powerdomains and wakeup dependencies */

/*
 * 2420/2430 PM_WKDEP_GFX: CORE, MPU, WKUP
 * 3430ES1 PM_WKDEP_GFX: adds IVA2, removes CORE
 * 3430ES2 PM_WKDEP_SGX: adds IVA2, removes CORE
 */
static struct pwrdm_dep gfx_sgx_wkdeps[] = {
	{
		.pwrdm_name = "core_pwrdm",
		.omap_chip = OMAP_CHIP_INIT(CHIP_IS_OMAP24XX)
	},
	{
		.pwrdm_name = "iva2_pwrdm",
		.omap_chip = OMAP_CHIP_INIT(CHIP_IS_OMAP3430)
	},
	{
		.pwrdm_name = "mpu_pwrdm",
		.omap_chip = OMAP_CHIP_INIT(CHIP_IS_OMAP24XX |
					    CHIP_IS_OMAP3430)
	},
	{
		.pwrdm_name = "wkup_pwrdm",
		.omap_chip = OMAP_CHIP_INIT(CHIP_IS_OMAP24XX |
					    CHIP_IS_OMAP3430)
	},
	{ NULL },
};

/*
 * OMAP2/3 common powerdomains
 */

/* XXX add sleepdeps for this powerdomain : 3430 */

/*
 * The GFX powerdomain is not present on 3430ES2, but currently we do not
 * have a macro to filter it out at compile-time.
 */
static struct powerdomain gfx_pwrdm = {
	.name		  = "gfx_pwrdm",
	.prcm_offs	  = GFX_MOD,
	.omap_chip	  = OMAP_CHIP_INIT(CHIP_IS_OMAP24XX |
					   CHIP_IS_OMAP3430ES1),
	.wkdep_srcs	  = gfx_sgx_wkdeps,
	.pwrsts		  = PWRSTS_OFF_RET_ON,
	.pwrsts_logic_ret = PWRDM_POWER_RET,
	.banks		  = 1,
	.pwrsts_mem_ret	  = {
		[0] = PWRDM_POWER_RET, /* MEMRETSTATE */
	},
	.pwrsts_mem_on	  = {
		[0] = PWRDM_POWER_ON,  /* MEMONSTATE */
	},
};

static struct powerdomain wkup_pwrdm = {
	.name		= "wkup_pwrdm",
	.prcm_offs	= WKUP_MOD,
	.omap_chip	= OMAP_CHIP_INIT(CHIP_IS_OMAP24XX | CHIP_IS_OMAP3430),
	.dep_bit	= OMAP_EN_WKUP_SHIFT,
};



/* As powerdomains are added or removed above, this list must also be changed */
static struct powerdomain *powerdomains_omap[] __initdata = {

	&gfx_pwrdm,
	&wkup_pwrdm,

	NULL
};


#endif
