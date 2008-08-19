/*
 * Hardware definitions for the Toshiba eseries PDAs
 *
 * Copyright (c) 2003 Ian Molton <spyro@f2s.com>
 *
 * This file is licensed under
 * the terms of the GNU General Public License version 2. This program
 * is licensed "as is" without any warranty of any kind, whether express
 * or implied.
 *
 */

#include <linux/kernel.h>
#include <linux/init.h>

#include <asm/setup.h>
#include <asm/mach/arch.h>
#include <asm/mach-types.h>

#include <mach/mfp-pxa25x.h>
#include <mach/hardware.h>

#include "generic.h"
#include "eseries.h"

static unsigned long e740_pin_config[] __initdata = {
	/* Chip selects */
	GPIO15_nCS_1,   /* CS1 - Flash */
	GPIO79_nCS_3,   /* CS3 - IMAGEON */
	GPIO80_nCS_4,   /* CS4 - TMIO */

	/* Clocks */
	GPIO12_32KHz,

	/* BTUART */
	GPIO42_BTUART_RXD,
	GPIO43_BTUART_TXD,
	GPIO44_BTUART_CTS,
	GPIO45_GPIO, /* Used by TMIO for #SUSPEND */

	/* PC Card */
	GPIO8_GPIO,   /* CD0 */
	GPIO44_GPIO,  /* CD1 */
	GPIO11_GPIO,  /* IRQ0 */
	GPIO6_GPIO,   /* IRQ1 */
	GPIO27_GPIO,  /* RST0 */
	GPIO24_GPIO,  /* RST1 */
	GPIO20_GPIO,  /* PWR0 */
	GPIO23_GPIO,  /* PWR1 */
	GPIO48_nPOE,
	GPIO49_nPWE,
	GPIO50_nPIOR,
	GPIO51_nPIOW,
	GPIO52_nPCE_1,
	GPIO53_nPCE_2,
	GPIO54_nPSKTSEL,
	GPIO55_nPREG,
	GPIO56_nPWAIT,
	GPIO57_nIOIS16,

	/* wakeup */
	GPIO0_GPIO | WAKEUP_ON_EDGE_RISE,
};

static void __init e740_init(void)
{
	pxa2xx_mfp_config(ARRAY_AND_SIZE(e740_pin_config));
}

MACHINE_START(E740, "Toshiba e740")
	/* Maintainer: Ian Molton (spyro@f2s.com) */
	.phys_io	= 0x40000000,
	.io_pg_offst	= (io_p2v(0x40000000) >> 18) & 0xfffc,
	.boot_params	= 0xa0000100,
	.map_io		= pxa_map_io,
	.init_irq	= pxa25x_init_irq,
	.fixup		= eseries_fixup,
	.init_machine	= e740_init,
	.timer		= &pxa_timer,
MACHINE_END

