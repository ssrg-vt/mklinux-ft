/****************************************************************************
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2007-2008 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/delay.h>
#include <linux/seq_file.h>
#include "efx.h"
#include "mdio_10g.h"
#include "falcon.h"
#include "phy.h"
#include "falcon_hwdefs.h"
#include "boards.h"

/* We expect these MMDs to be in the package */
#define TENXPRESS_REQUIRED_DEVS (MDIO_MMDREG_DEVS_PMAPMD	| \
				 MDIO_MMDREG_DEVS_PCS		| \
				 MDIO_MMDREG_DEVS_PHYXS		| \
				 MDIO_MMDREG_DEVS_AN)

#define TENXPRESS_LOOPBACKS ((1 << LOOPBACK_PHYXS) |	\
			     (1 << LOOPBACK_PCS) |	\
			     (1 << LOOPBACK_PMAPMD) |	\
			     (1 << LOOPBACK_NETWORK))

/* We complain if we fail to see the link partner as 10G capable this many
 * times in a row (must be > 1 as sampling the autoneg. registers is racy)
 */
#define MAX_BAD_LP_TRIES	(5)

/* Extended control register */
#define	PMA_PMD_XCONTROL_REG 0xc000
#define	PMA_PMD_LNPGA_POWERDOWN_LBN 8
#define	PMA_PMD_LNPGA_POWERDOWN_WIDTH 1

/* extended status register */
#define PMA_PMD_XSTATUS_REG 0xc001
#define PMA_PMD_XSTAT_FLP_LBN   (12)

/* LED control register */
#define PMA_PMD_LED_CTRL_REG	(0xc007)
#define PMA_PMA_LED_ACTIVITY_LBN	(3)

/* LED function override register */
#define PMA_PMD_LED_OVERR_REG	(0xc009)
/* Bit positions for different LEDs (there are more but not wired on SFE4001)*/
#define PMA_PMD_LED_LINK_LBN	(0)
#define PMA_PMD_LED_SPEED_LBN	(2)
#define PMA_PMD_LED_TX_LBN	(4)
#define PMA_PMD_LED_RX_LBN	(6)
/* Override settings */
#define	PMA_PMD_LED_AUTO	(0)	/* H/W control */
#define	PMA_PMD_LED_ON		(1)
#define	PMA_PMD_LED_OFF		(2)
#define PMA_PMD_LED_FLASH	(3)
#define PMA_PMD_LED_MASK	3
/* All LEDs under hardware control */
#define PMA_PMD_LED_FULL_AUTO	(0)
/* Green and Amber under hardware control, Red off */
#define PMA_PMD_LED_DEFAULT	(PMA_PMD_LED_OFF << PMA_PMD_LED_RX_LBN)


/* Special Software reset register */
#define PMA_PMD_EXT_CTRL_REG 49152
#define PMA_PMD_EXT_SSR_LBN 15

/* Misc register defines */
#define PCS_CLOCK_CTRL_REG 0xd801
#define PLL312_RST_N_LBN 2

#define PCS_SOFT_RST2_REG 0xd806
#define SERDES_RST_N_LBN 13
#define XGXS_RST_N_LBN 12

#define	PCS_TEST_SELECT_REG 0xd807	/* PRM 10.5.8 */
#define	CLK312_EN_LBN 3

/* PHYXS registers */
#define PHYXS_TEST1         (49162)
#define LOOPBACK_NEAR_LBN   (8)
#define LOOPBACK_NEAR_WIDTH (1)

/* Boot status register */
#define PCS_BOOT_STATUS_REG	(0xd000)
#define PCS_BOOT_FATAL_ERR_LBN	(0)
#define PCS_BOOT_PROGRESS_LBN	(1)
#define PCS_BOOT_PROGRESS_WIDTH	(2)
#define PCS_BOOT_COMPLETE_LBN	(3)
#define PCS_BOOT_MAX_DELAY	(100)
#define PCS_BOOT_POLL_DELAY	(10)

/* Time to wait between powering down the LNPGA and turning off the power
 * rails */
#define LNPGA_PDOWN_WAIT	(HZ / 5)

static int crc_error_reset_threshold = 100;
module_param(crc_error_reset_threshold, int, 0644);
MODULE_PARM_DESC(crc_error_reset_threshold,
		 "Max number of CRC errors before XAUI reset");

struct tenxpress_phy_data {
	enum efx_loopback_mode loopback_mode;
	atomic_t bad_crc_count;
	enum efx_phy_mode phy_mode;
	int bad_lp_tries;
};

void tenxpress_crc_err(struct efx_nic *efx)
{
	struct tenxpress_phy_data *phy_data = efx->phy_data;
	if (phy_data != NULL)
		atomic_inc(&phy_data->bad_crc_count);
}

/* Check that the C166 has booted successfully */
static int tenxpress_phy_check(struct efx_nic *efx)
{
	int phy_id = efx->mii.phy_id;
	int count = PCS_BOOT_MAX_DELAY / PCS_BOOT_POLL_DELAY;
	int boot_stat;

	/* Wait for the boot to complete (or not) */
	while (count) {
		boot_stat = mdio_clause45_read(efx, phy_id,
					       MDIO_MMD_PCS,
					       PCS_BOOT_STATUS_REG);
		if (boot_stat & (1 << PCS_BOOT_COMPLETE_LBN))
			break;
		count--;
		udelay(PCS_BOOT_POLL_DELAY);
	}

	if (!count) {
		EFX_ERR(efx, "%s: PHY boot timed out. Last status "
			"%x\n", __func__,
			(boot_stat >> PCS_BOOT_PROGRESS_LBN) &
			((1 << PCS_BOOT_PROGRESS_WIDTH) - 1));
		return -ETIMEDOUT;
	}

	return 0;
}

static int tenxpress_init(struct efx_nic *efx)
{
	int rc, reg;

	/* Turn on the clock  */
	reg = (1 << CLK312_EN_LBN);
	mdio_clause45_write(efx, efx->mii.phy_id,
			    MDIO_MMD_PCS, PCS_TEST_SELECT_REG, reg);

	rc = tenxpress_phy_check(efx);
	if (rc < 0)
		return rc;

	/* Set the LEDs up as: Green = Link, Amber = Link/Act, Red = Off */
	reg = mdio_clause45_read(efx, efx->mii.phy_id,
				 MDIO_MMD_PMAPMD, PMA_PMD_LED_CTRL_REG);
	reg |= (1 << PMA_PMA_LED_ACTIVITY_LBN);
	mdio_clause45_write(efx, efx->mii.phy_id, MDIO_MMD_PMAPMD,
			    PMA_PMD_LED_CTRL_REG, reg);

	reg = PMA_PMD_LED_DEFAULT;
	mdio_clause45_write(efx, efx->mii.phy_id, MDIO_MMD_PMAPMD,
			    PMA_PMD_LED_OVERR_REG, reg);

	return rc;
}

static int tenxpress_phy_init(struct efx_nic *efx)
{
	struct tenxpress_phy_data *phy_data;
	int rc = 0;

	phy_data = kzalloc(sizeof(*phy_data), GFP_KERNEL);
	if (!phy_data)
		return -ENOMEM;
	efx->phy_data = phy_data;
	phy_data->phy_mode = efx->phy_mode;

	rc = mdio_clause45_wait_reset_mmds(efx,
					   TENXPRESS_REQUIRED_DEVS);
	if (rc < 0)
		goto fail;

	rc = mdio_clause45_check_mmds(efx, TENXPRESS_REQUIRED_DEVS, 0);
	if (rc < 0)
		goto fail;

	rc = tenxpress_init(efx);
	if (rc < 0)
		goto fail;

	schedule_timeout_uninterruptible(HZ / 5); /* 200ms */

	/* Let XGXS and SerDes out of reset and resets 10XPress */
	falcon_reset_xaui(efx);

	return 0;

 fail:
	kfree(efx->phy_data);
	efx->phy_data = NULL;
	return rc;
}

static int tenxpress_special_reset(struct efx_nic *efx)
{
	int rc, reg;

	/* The XGMAC clock is driven from the SFC7101/SFT9001 312MHz clock, so
	 * a special software reset can glitch the XGMAC sufficiently for stats
	 * requests to fail. Since we don't ofen special_reset, just lock. */
	spin_lock(&efx->stats_lock);

	/* Initiate reset */
	reg = mdio_clause45_read(efx, efx->mii.phy_id,
				 MDIO_MMD_PMAPMD, PMA_PMD_EXT_CTRL_REG);
	reg |= (1 << PMA_PMD_EXT_SSR_LBN);
	mdio_clause45_write(efx, efx->mii.phy_id, MDIO_MMD_PMAPMD,
			    PMA_PMD_EXT_CTRL_REG, reg);

	mdelay(200);

	/* Wait for the blocks to come out of reset */
	rc = mdio_clause45_wait_reset_mmds(efx,
					   TENXPRESS_REQUIRED_DEVS);
	if (rc < 0)
		goto unlock;

	/* Try and reconfigure the device */
	rc = tenxpress_init(efx);
	if (rc < 0)
		goto unlock;

unlock:
	spin_unlock(&efx->stats_lock);
	return rc;
}

static void tenxpress_check_bad_lp(struct efx_nic *efx, bool link_ok)
{
	struct tenxpress_phy_data *pd = efx->phy_data;
	int phy_id = efx->mii.phy_id;
	bool bad_lp;
	int reg;

	if (link_ok) {
		bad_lp = false;
	} else {
		/* Check that AN has started but not completed. */
		reg = mdio_clause45_read(efx, phy_id, MDIO_MMD_AN,
					 MDIO_AN_STATUS);
		if (!(reg & (1 << MDIO_AN_STATUS_LP_AN_CAP_LBN)))
			return; /* LP status is unknown */
		bad_lp = !(reg & (1 << MDIO_AN_STATUS_AN_DONE_LBN));
		if (bad_lp)
			pd->bad_lp_tries++;
	}

	/* Nothing to do if all is well and was previously so. */
	if (!pd->bad_lp_tries)
		return;

	/* Use the RX (red) LED as an error indicator once we've seen AN
	 * failure several times in a row, and also log a message. */
	if (!bad_lp || pd->bad_lp_tries == MAX_BAD_LP_TRIES) {
		reg = mdio_clause45_read(efx, phy_id, MDIO_MMD_PMAPMD,
					 PMA_PMD_LED_OVERR_REG);
		reg &= ~(PMA_PMD_LED_MASK << PMA_PMD_LED_RX_LBN);
		if (!bad_lp) {
			reg |= PMA_PMD_LED_OFF << PMA_PMD_LED_RX_LBN;
		} else {
			reg |= PMA_PMD_LED_FLASH << PMA_PMD_LED_RX_LBN;
			EFX_ERR(efx, "appears to be plugged into a port"
				" that is not 10GBASE-T capable. The PHY"
				" supports 10GBASE-T ONLY, so no link can"
				" be established\n");
		}
		mdio_clause45_write(efx, phy_id, MDIO_MMD_PMAPMD,
				    PMA_PMD_LED_OVERR_REG, reg);
		pd->bad_lp_tries = bad_lp;
	}
}

static bool tenxpress_link_ok(struct efx_nic *efx)
{
	if (efx->loopback_mode == LOOPBACK_NONE)
		return mdio_clause45_links_ok(efx, MDIO_MMDREG_DEVS_AN);
	else
		return mdio_clause45_links_ok(efx,
					      MDIO_MMDREG_DEVS_PMAPMD |
					      MDIO_MMDREG_DEVS_PCS |
					      MDIO_MMDREG_DEVS_PHYXS);
}

static void tenxpress_phyxs_loopback(struct efx_nic *efx)
{
	int phy_id = efx->mii.phy_id;
	int ctrl1, ctrl2;

	ctrl1 = ctrl2 = mdio_clause45_read(efx, phy_id, MDIO_MMD_PHYXS,
					   PHYXS_TEST1);
	if (efx->loopback_mode == LOOPBACK_PHYXS)
		ctrl2 |= (1 << LOOPBACK_NEAR_LBN);
	else
		ctrl2 &= ~(1 << LOOPBACK_NEAR_LBN);
	if (ctrl1 != ctrl2)
		mdio_clause45_write(efx, phy_id, MDIO_MMD_PHYXS,
				    PHYXS_TEST1, ctrl2);
}

static void tenxpress_phy_reconfigure(struct efx_nic *efx)
{
	struct tenxpress_phy_data *phy_data = efx->phy_data;
	bool loop_change = LOOPBACK_OUT_OF(phy_data, efx,
					   TENXPRESS_LOOPBACKS);

	if (efx->phy_mode & PHY_MODE_SPECIAL) {
		phy_data->phy_mode = efx->phy_mode;
		return;
	}

	/* When coming out of transmit disable, coming out of low power
	 * mode, or moving out of any PHY internal loopback mode,
	 * perform a special software reset */
	if ((efx->phy_mode == PHY_MODE_NORMAL &&
	     phy_data->phy_mode != PHY_MODE_NORMAL) ||
	    loop_change) {
		tenxpress_special_reset(efx);
		falcon_reset_xaui(efx);
	}

	mdio_clause45_transmit_disable(efx);
	mdio_clause45_phy_reconfigure(efx);
	tenxpress_phyxs_loopback(efx);

	phy_data->loopback_mode = efx->loopback_mode;
	phy_data->phy_mode = efx->phy_mode;
	efx->link_up = tenxpress_link_ok(efx);
	efx->link_speed = 10000;
	efx->link_fd = true;
	efx->link_fc = mdio_clause45_get_pause(efx);
}

/* Poll PHY for interrupt */
static void tenxpress_phy_poll(struct efx_nic *efx)
{
	struct tenxpress_phy_data *phy_data = efx->phy_data;
	bool change = false, link_ok;
	unsigned link_fc;

	link_ok = tenxpress_link_ok(efx);
	if (link_ok != efx->link_up) {
		change = true;
	} else {
		link_fc = mdio_clause45_get_pause(efx);
		if (link_fc != efx->link_fc)
			change = true;
	}
	tenxpress_check_bad_lp(efx, link_ok);

	if (change)
		falcon_sim_phy_event(efx);

	if (phy_data->phy_mode != PHY_MODE_NORMAL)
		return;

	if (atomic_read(&phy_data->bad_crc_count) > crc_error_reset_threshold) {
		EFX_ERR(efx, "Resetting XAUI due to too many CRC errors\n");
		falcon_reset_xaui(efx);
		atomic_set(&phy_data->bad_crc_count, 0);
	}
}

static void tenxpress_phy_fini(struct efx_nic *efx)
{
	int reg;

	/* Power down the LNPGA */
	reg = (1 << PMA_PMD_LNPGA_POWERDOWN_LBN);
	mdio_clause45_write(efx, efx->mii.phy_id, MDIO_MMD_PMAPMD,
			    PMA_PMD_XCONTROL_REG, reg);

	/* Waiting here ensures that the board fini, which can turn off the
	 * power to the PHY, won't get run until the LNPGA powerdown has been
	 * given long enough to complete. */
	schedule_timeout_uninterruptible(LNPGA_PDOWN_WAIT); /* 200 ms */

	kfree(efx->phy_data);
	efx->phy_data = NULL;
}


/* Set the RX and TX LEDs and Link LED flashing. The other LEDs
 * (which probably aren't wired anyway) are left in AUTO mode */
void tenxpress_phy_blink(struct efx_nic *efx, bool blink)
{
	int reg;

	if (blink)
		reg = (PMA_PMD_LED_FLASH << PMA_PMD_LED_TX_LBN) |
			(PMA_PMD_LED_FLASH << PMA_PMD_LED_RX_LBN) |
			(PMA_PMD_LED_FLASH << PMA_PMD_LED_LINK_LBN);
	else
		reg = PMA_PMD_LED_DEFAULT;

	mdio_clause45_write(efx, efx->mii.phy_id, MDIO_MMD_PMAPMD,
			    PMA_PMD_LED_OVERR_REG, reg);
}

static int tenxpress_phy_test(struct efx_nic *efx)
{
	/* BIST is automatically run after a special software reset */
	return tenxpress_special_reset(efx);
}

static u32 tenxpress_get_xnp_lpa(struct efx_nic *efx)
{
	int phy = efx->mii.phy_id;
	u32 lpa = 0;
	int reg;

	reg = mdio_clause45_read(efx, phy, MDIO_MMD_AN, MDIO_AN_10GBT_STATUS);
	if (reg & (1 << MDIO_AN_10GBT_STATUS_LP_10G_LBN))
		lpa |= ADVERTISED_10000baseT_Full;
	return lpa;
}

static void
tenxpress_get_settings(struct efx_nic *efx, struct ethtool_cmd *ecmd)
{
	mdio_clause45_get_settings_ext(efx, ecmd, ADVERTISED_10000baseT_Full,
				       tenxpress_get_xnp_lpa(efx));
	ecmd->supported |= SUPPORTED_10000baseT_Full;
	ecmd->advertising |= ADVERTISED_10000baseT_Full;
}

struct efx_phy_operations falcon_tenxpress_phy_ops = {
	.macs		  = EFX_XMAC,
	.init             = tenxpress_phy_init,
	.reconfigure      = tenxpress_phy_reconfigure,
	.poll             = tenxpress_phy_poll,
	.fini             = tenxpress_phy_fini,
	.clear_interrupt  = efx_port_dummy_op_void,
	.test             = tenxpress_phy_test,
	.get_settings	  = tenxpress_get_settings,
	.set_settings	  = mdio_clause45_set_settings,
	.mmds             = TENXPRESS_REQUIRED_DEVS,
	.loopbacks        = TENXPRESS_LOOPBACKS,
};
