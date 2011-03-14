/*
 *
 * arch/arm/mach-u300/mmc.c
 *
 *
 * Copyright (C) 2009 ST-Ericsson AB
 * License terms: GNU General Public License (GPL) version 2
 *
 * Author: Linus Walleij <linus.walleij@stericsson.com>
 * Author: Johan Lundin <johan.lundin@stericsson.com>
 * Author: Jonas Aaberg <jonas.aberg@stericsson.com>
 */
#include <linux/device.h>
#include <linux/amba/bus.h>
#include <linux/mmc/host.h>
#include <linux/gpio.h>
#include <linux/amba/mmci.h>
#include <linux/slab.h>

#include "mmc.h"
#include "padmux.h"

static struct mmci_platform_data mmc0_plat_data = {
	/*
	 * Do not set ocr_mask or voltage translation function,
	 * we have a regulator we can control instead.
	 */
	/* Nominally 2.85V on our platform */
	.f_max = 24000000,
	.gpio_wp = -1,
	.gpio_cd = U300_GPIO_PIN_MMC_CD,
	.cd_invert = true,
	.capabilities = MMC_CAP_MMC_HIGHSPEED |
	MMC_CAP_SD_HIGHSPEED | MMC_CAP_4_BIT_DATA | MMC_CAP_8_BIT_DATA,
};

int __devinit mmc_init(struct amba_device *adev)
{
	struct device *mmcsd_device = &adev->dev;
	struct pmx *pmx;
	int ret = 0;

	mmcsd_device->platform_data = &mmc0_plat_data;

	/*
	 * Setup padmuxing for MMC. Since this must always be
	 * compiled into the kernel, pmx is never released.
	 */
	pmx = pmx_get(mmcsd_device, U300_APP_PMX_MMC_SETTING);

	if (IS_ERR(pmx))
		pr_warning("Could not get padmux handle\n");
	else {
		ret = pmx_activate(mmcsd_device, pmx);
		if (IS_ERR_VALUE(ret))
			pr_warning("Could not activate padmuxing\n");
	}

	return ret;
}
