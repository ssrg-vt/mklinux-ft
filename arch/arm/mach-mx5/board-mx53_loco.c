/*
 * Copyright (C) 2011 Freescale Semiconductor, Inc. All Rights Reserved.
 */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/init.h>
#include <linux/clk.h>
#include <linux/fec.h>
#include <linux/delay.h>
#include <linux/gpio.h>

#include <mach/common.h>
#include <mach/hardware.h>
#include <mach/imx-uart.h>
#include <mach/iomux-mx53.h>

#include <asm/mach-types.h>
#include <asm/mach/arch.h>
#include <asm/mach/time.h>

#include "crm_regs.h"
#include "devices-imx53.h"

#define LOCO_FEC_PHY_RST		IMX_GPIO_NR(7, 6)

static iomux_v3_cfg_t mx53_loco_pads[] = {
	MX53_PAD_CSI0_DAT10__UART1_TXD_MUX,
	MX53_PAD_CSI0_DAT11__UART1_RXD_MUX,
};

static inline void mx53_loco_fec_reset(void)
{
	int ret;

	/* reset FEC PHY */
	ret = gpio_request(LOCO_FEC_PHY_RST, "fec-phy-reset");
	if (ret) {
		printk(KERN_ERR"failed to get GPIO_FEC_PHY_RESET: %d\n", ret);
		return;
	}
	gpio_direction_output(LOCO_FEC_PHY_RST, 0);
	msleep(1);
	gpio_set_value(LOCO_FEC_PHY_RST, 1);
}

static struct fec_platform_data mx53_loco_fec_data = {
	.phy = PHY_INTERFACE_MODE_RMII,
};

static void __init mx53_loco_board_init(void)
{
	mxc_iomux_v3_setup_multiple_pads(mx53_loco_pads,
					ARRAY_SIZE(mx53_loco_pads));
	imx53_add_imx_uart(0, NULL);
	mx53_loco_fec_reset();
	imx53_add_fec(&mx53_loco_fec_data);
}

static void __init mx53_loco_timer_init(void)
{
	mx53_clocks_init(32768, 24000000, 0, 0);
}

static struct sys_timer mx53_loco_timer = {
	.init	= mx53_loco_timer_init,
};

MACHINE_START(MX53_LOCO, "Freescale MX53 LOCO Board")
	.map_io = mx53_map_io,
	.init_early = imx53_init_early,
	.init_irq = mx53_init_irq,
	.timer = &mx53_loco_timer,
	.init_machine = mx53_loco_board_init,
MACHINE_END
