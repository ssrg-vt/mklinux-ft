/****************************************************************************
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2008 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/delay.h>
#include "net_driver.h"
#include "efx.h"
#include "falcon.h"
#include "regs.h"
#include "io.h"
#include "mac.h"
#include "mdio_10g.h"
#include "phy.h"
#include "workarounds.h"

/**************************************************************************
 *
 * MAC operations
 *
 *************************************************************************/

/* Configure the XAUI driver that is an output from Falcon */
static void falcon_setup_xaui(struct efx_nic *efx)
{
	efx_oword_t sdctl, txdrv;

	/* Move the XAUI into low power, unless there is no PHY, in
	 * which case the XAUI will have to drive a cable. */
	if (efx->phy_type == PHY_TYPE_NONE)
		return;

	efx_reado(efx, &sdctl, FR_AB_XX_SD_CTL);
	EFX_SET_OWORD_FIELD(sdctl, FRF_AB_XX_HIDRVD, FFE_AB_XX_SD_CTL_DRV_DEF);
	EFX_SET_OWORD_FIELD(sdctl, FRF_AB_XX_LODRVD, FFE_AB_XX_SD_CTL_DRV_DEF);
	EFX_SET_OWORD_FIELD(sdctl, FRF_AB_XX_HIDRVC, FFE_AB_XX_SD_CTL_DRV_DEF);
	EFX_SET_OWORD_FIELD(sdctl, FRF_AB_XX_LODRVC, FFE_AB_XX_SD_CTL_DRV_DEF);
	EFX_SET_OWORD_FIELD(sdctl, FRF_AB_XX_HIDRVB, FFE_AB_XX_SD_CTL_DRV_DEF);
	EFX_SET_OWORD_FIELD(sdctl, FRF_AB_XX_LODRVB, FFE_AB_XX_SD_CTL_DRV_DEF);
	EFX_SET_OWORD_FIELD(sdctl, FRF_AB_XX_HIDRVA, FFE_AB_XX_SD_CTL_DRV_DEF);
	EFX_SET_OWORD_FIELD(sdctl, FRF_AB_XX_LODRVA, FFE_AB_XX_SD_CTL_DRV_DEF);
	efx_writeo(efx, &sdctl, FR_AB_XX_SD_CTL);

	EFX_POPULATE_OWORD_8(txdrv,
			     FRF_AB_XX_DEQD, FFE_AB_XX_TXDRV_DEQ_DEF,
			     FRF_AB_XX_DEQC, FFE_AB_XX_TXDRV_DEQ_DEF,
			     FRF_AB_XX_DEQB, FFE_AB_XX_TXDRV_DEQ_DEF,
			     FRF_AB_XX_DEQA, FFE_AB_XX_TXDRV_DEQ_DEF,
			     FRF_AB_XX_DTXD, FFE_AB_XX_TXDRV_DTX_DEF,
			     FRF_AB_XX_DTXC, FFE_AB_XX_TXDRV_DTX_DEF,
			     FRF_AB_XX_DTXB, FFE_AB_XX_TXDRV_DTX_DEF,
			     FRF_AB_XX_DTXA, FFE_AB_XX_TXDRV_DTX_DEF);
	efx_writeo(efx, &txdrv, FR_AB_XX_TXDRV_CTL);
}

int falcon_reset_xaui(struct efx_nic *efx)
{
	efx_oword_t reg;
	int count;

	/* Start reset sequence */
	EFX_POPULATE_DWORD_1(reg, FRF_AB_XX_RST_XX_EN, 1);
	efx_writeo(efx, &reg, FR_AB_XX_PWR_RST);

	/* Wait up to 10 ms for completion, then reinitialise */
	for (count = 0; count < 1000; count++) {
		efx_reado(efx, &reg, FR_AB_XX_PWR_RST);
		if (EFX_OWORD_FIELD(reg, FRF_AB_XX_RST_XX_EN) == 0 &&
		    EFX_OWORD_FIELD(reg, FRF_AB_XX_SD_RST_ACT) == 0) {
			falcon_setup_xaui(efx);
			return 0;
		}
		udelay(10);
	}
	EFX_ERR(efx, "timed out waiting for XAUI/XGXS reset\n");
	return -ETIMEDOUT;
}

static void falcon_mask_status_intr(struct efx_nic *efx, bool enable)
{
	efx_oword_t reg;

	if ((falcon_rev(efx) != FALCON_REV_B0) || LOOPBACK_INTERNAL(efx))
		return;

	/* We expect xgmii faults if the wireside link is up */
	if (!EFX_WORKAROUND_5147(efx) || !efx->link_up)
		return;

	/* We can only use this interrupt to signal the negative edge of
	 * xaui_align [we have to poll the positive edge]. */
	if (!efx->mac_up)
		return;

	/* Flush the ISR */
	if (enable)
		efx_reado(efx, &reg, FR_AB_XM_MGT_INT_MSK);

	EFX_POPULATE_OWORD_2(reg,
			     FRF_AB_XM_MSK_RMTFLT, !enable,
			     FRF_AB_XM_MSK_LCLFLT, !enable);
	efx_writeo(efx, &reg, FR_AB_XM_MGT_INT_MASK);
}

/* Get status of XAUI link */
bool falcon_xaui_link_ok(struct efx_nic *efx)
{
	efx_oword_t reg;
	bool align_done, link_ok = false;
	int sync_status;

	if (LOOPBACK_INTERNAL(efx))
		return true;

	/* Read link status */
	efx_reado(efx, &reg, FR_AB_XX_CORE_STAT);

	align_done = EFX_OWORD_FIELD(reg, FRF_AB_XX_ALIGN_DONE);
	sync_status = EFX_OWORD_FIELD(reg, FRF_AB_XX_SYNC_STAT);
	if (align_done && (sync_status == FFE_AB_XX_STAT_ALL_LANES))
		link_ok = true;

	/* Clear link status ready for next read */
	EFX_SET_OWORD_FIELD(reg, FRF_AB_XX_COMMA_DET, FFE_AB_XX_STAT_ALL_LANES);
	EFX_SET_OWORD_FIELD(reg, FRF_AB_XX_CHAR_ERR, FFE_AB_XX_STAT_ALL_LANES);
	EFX_SET_OWORD_FIELD(reg, FRF_AB_XX_DISPERR, FFE_AB_XX_STAT_ALL_LANES);
	efx_writeo(efx, &reg, FR_AB_XX_CORE_STAT);

	/* If the link is up, then check the phy side of the xaui link */
	if (efx->link_up && link_ok)
		if (efx->phy_op->mmds & (1 << MDIO_MMD_PHYXS))
			link_ok = efx_mdio_phyxgxs_lane_sync(efx);

	return link_ok;
}

static void falcon_reconfigure_xmac_core(struct efx_nic *efx)
{
	unsigned int max_frame_len;
	efx_oword_t reg;
	bool rx_fc = !!(efx->link_fc & EFX_FC_RX);

	/* Configure MAC  - cut-thru mode is hard wired on */
	EFX_POPULATE_DWORD_3(reg,
			     FRF_AB_XM_RX_JUMBO_MODE, 1,
			     FRF_AB_XM_TX_STAT_EN, 1,
			     FRF_AB_XM_RX_STAT_EN, 1);
	efx_writeo(efx, &reg, FR_AB_XM_GLB_CFG);

	/* Configure TX */
	EFX_POPULATE_DWORD_6(reg,
			     FRF_AB_XM_TXEN, 1,
			     FRF_AB_XM_TX_PRMBL, 1,
			     FRF_AB_XM_AUTO_PAD, 1,
			     FRF_AB_XM_TXCRC, 1,
			     FRF_AB_XM_FCNTL, 1,
			     FRF_AB_XM_IPG, 0x3);
	efx_writeo(efx, &reg, FR_AB_XM_TX_CFG);

	/* Configure RX */
	EFX_POPULATE_DWORD_5(reg,
			     FRF_AB_XM_RXEN, 1,
			     FRF_AB_XM_AUTO_DEPAD, 0,
			     FRF_AB_XM_ACPT_ALL_MCAST, 1,
			     FRF_AB_XM_ACPT_ALL_UCAST, efx->promiscuous,
			     FRF_AB_XM_PASS_CRC_ERR, 1);
	efx_writeo(efx, &reg, FR_AB_XM_RX_CFG);

	/* Set frame length */
	max_frame_len = EFX_MAX_FRAME_LEN(efx->net_dev->mtu);
	EFX_POPULATE_DWORD_1(reg, FRF_AB_XM_MAX_RX_FRM_SIZE, max_frame_len);
	efx_writeo(efx, &reg, FR_AB_XM_RX_PARAM);
	EFX_POPULATE_DWORD_2(reg,
			     FRF_AB_XM_MAX_TX_FRM_SIZE, max_frame_len,
			     FRF_AB_XM_TX_JUMBO_MODE, 1);
	efx_writeo(efx, &reg, FR_AB_XM_TX_PARAM);

	EFX_POPULATE_DWORD_2(reg,
			     FRF_AB_XM_PAUSE_TIME, 0xfffe, /* MAX PAUSE TIME */
			     FRF_AB_XM_DIS_FCNTL, !rx_fc);
	efx_writeo(efx, &reg, FR_AB_XM_FC);

	/* Set MAC address */
	memcpy(&reg, &efx->net_dev->dev_addr[0], 4);
	efx_writeo(efx, &reg, FR_AB_XM_ADR_LO);
	memcpy(&reg, &efx->net_dev->dev_addr[4], 2);
	efx_writeo(efx, &reg, FR_AB_XM_ADR_HI);
}

static void falcon_reconfigure_xgxs_core(struct efx_nic *efx)
{
	efx_oword_t reg;
	bool xgxs_loopback = (efx->loopback_mode == LOOPBACK_XGXS);
	bool xaui_loopback = (efx->loopback_mode == LOOPBACK_XAUI);
	bool xgmii_loopback = (efx->loopback_mode == LOOPBACK_XGMII);

	/* XGXS block is flaky and will need to be reset if moving
	 * into our out of XGMII, XGXS or XAUI loopbacks. */
	if (EFX_WORKAROUND_5147(efx)) {
		bool old_xgmii_loopback, old_xgxs_loopback, old_xaui_loopback;
		bool reset_xgxs;

		efx_reado(efx, &reg, FR_AB_XX_CORE_STAT);
		old_xgxs_loopback = EFX_OWORD_FIELD(reg, FRF_AB_XX_XGXS_LB_EN);
		old_xgmii_loopback =
			EFX_OWORD_FIELD(reg, FRF_AB_XX_XGMII_LB_EN);

		efx_reado(efx, &reg, FR_AB_XX_SD_CTL);
		old_xaui_loopback = EFX_OWORD_FIELD(reg, FRF_AB_XX_LPBKA);

		/* The PHY driver may have turned XAUI off */
		reset_xgxs = ((xgxs_loopback != old_xgxs_loopback) ||
			      (xaui_loopback != old_xaui_loopback) ||
			      (xgmii_loopback != old_xgmii_loopback));

		if (reset_xgxs)
			falcon_reset_xaui(efx);
	}

	efx_reado(efx, &reg, FR_AB_XX_CORE_STAT);
	EFX_SET_OWORD_FIELD(reg, FRF_AB_XX_FORCE_SIG,
			    (xgxs_loopback || xaui_loopback) ?
			    FFE_AB_XX_FORCE_SIG_ALL_LANES : 0);
	EFX_SET_OWORD_FIELD(reg, FRF_AB_XX_XGXS_LB_EN, xgxs_loopback);
	EFX_SET_OWORD_FIELD(reg, FRF_AB_XX_XGMII_LB_EN, xgmii_loopback);
	efx_writeo(efx, &reg, FR_AB_XX_CORE_STAT);

	efx_reado(efx, &reg, FR_AB_XX_SD_CTL);
	EFX_SET_OWORD_FIELD(reg, FRF_AB_XX_LPBKD, xaui_loopback);
	EFX_SET_OWORD_FIELD(reg, FRF_AB_XX_LPBKC, xaui_loopback);
	EFX_SET_OWORD_FIELD(reg, FRF_AB_XX_LPBKB, xaui_loopback);
	EFX_SET_OWORD_FIELD(reg, FRF_AB_XX_LPBKA, xaui_loopback);
	efx_writeo(efx, &reg, FR_AB_XX_SD_CTL);
}


/* Try and bring the Falcon side of the Falcon-Phy XAUI link fails
 * to come back up. Bash it until it comes back up */
static void falcon_check_xaui_link_up(struct efx_nic *efx, int tries)
{
	efx->mac_up = falcon_xaui_link_ok(efx);

	if ((efx->loopback_mode == LOOPBACK_NETWORK) ||
	    efx_phy_mode_disabled(efx->phy_mode))
		/* XAUI link is expected to be down */
		return;

	while (!efx->mac_up && tries) {
		EFX_LOG(efx, "bashing xaui\n");
		falcon_reset_xaui(efx);
		udelay(200);

		efx->mac_up = falcon_xaui_link_ok(efx);
		--tries;
	}
}

static void falcon_reconfigure_xmac(struct efx_nic *efx)
{
	falcon_mask_status_intr(efx, false);

	falcon_reconfigure_xgxs_core(efx);
	falcon_reconfigure_xmac_core(efx);

	falcon_reconfigure_mac_wrapper(efx);

	falcon_check_xaui_link_up(efx, 5);
	falcon_mask_status_intr(efx, true);
}

static void falcon_update_stats_xmac(struct efx_nic *efx)
{
	struct efx_mac_stats *mac_stats = &efx->mac_stats;
	int rc;

	rc = falcon_dma_stats(efx, XgDmaDone_offset);
	if (rc)
		return;

	/* Update MAC stats from DMAed values */
	FALCON_STAT(efx, XgRxOctets, rx_bytes);
	FALCON_STAT(efx, XgRxOctetsOK, rx_good_bytes);
	FALCON_STAT(efx, XgRxPkts, rx_packets);
	FALCON_STAT(efx, XgRxPktsOK, rx_good);
	FALCON_STAT(efx, XgRxBroadcastPkts, rx_broadcast);
	FALCON_STAT(efx, XgRxMulticastPkts, rx_multicast);
	FALCON_STAT(efx, XgRxUnicastPkts, rx_unicast);
	FALCON_STAT(efx, XgRxUndersizePkts, rx_lt64);
	FALCON_STAT(efx, XgRxOversizePkts, rx_gtjumbo);
	FALCON_STAT(efx, XgRxJabberPkts, rx_bad_gtjumbo);
	FALCON_STAT(efx, XgRxUndersizeFCSerrorPkts, rx_bad_lt64);
	FALCON_STAT(efx, XgRxDropEvents, rx_overflow);
	FALCON_STAT(efx, XgRxFCSerrorPkts, rx_bad);
	FALCON_STAT(efx, XgRxAlignError, rx_align_error);
	FALCON_STAT(efx, XgRxSymbolError, rx_symbol_error);
	FALCON_STAT(efx, XgRxInternalMACError, rx_internal_error);
	FALCON_STAT(efx, XgRxControlPkts, rx_control);
	FALCON_STAT(efx, XgRxPausePkts, rx_pause);
	FALCON_STAT(efx, XgRxPkts64Octets, rx_64);
	FALCON_STAT(efx, XgRxPkts65to127Octets, rx_65_to_127);
	FALCON_STAT(efx, XgRxPkts128to255Octets, rx_128_to_255);
	FALCON_STAT(efx, XgRxPkts256to511Octets, rx_256_to_511);
	FALCON_STAT(efx, XgRxPkts512to1023Octets, rx_512_to_1023);
	FALCON_STAT(efx, XgRxPkts1024to15xxOctets, rx_1024_to_15xx);
	FALCON_STAT(efx, XgRxPkts15xxtoMaxOctets, rx_15xx_to_jumbo);
	FALCON_STAT(efx, XgRxLengthError, rx_length_error);
	FALCON_STAT(efx, XgTxPkts, tx_packets);
	FALCON_STAT(efx, XgTxOctets, tx_bytes);
	FALCON_STAT(efx, XgTxMulticastPkts, tx_multicast);
	FALCON_STAT(efx, XgTxBroadcastPkts, tx_broadcast);
	FALCON_STAT(efx, XgTxUnicastPkts, tx_unicast);
	FALCON_STAT(efx, XgTxControlPkts, tx_control);
	FALCON_STAT(efx, XgTxPausePkts, tx_pause);
	FALCON_STAT(efx, XgTxPkts64Octets, tx_64);
	FALCON_STAT(efx, XgTxPkts65to127Octets, tx_65_to_127);
	FALCON_STAT(efx, XgTxPkts128to255Octets, tx_128_to_255);
	FALCON_STAT(efx, XgTxPkts256to511Octets, tx_256_to_511);
	FALCON_STAT(efx, XgTxPkts512to1023Octets, tx_512_to_1023);
	FALCON_STAT(efx, XgTxPkts1024to15xxOctets, tx_1024_to_15xx);
	FALCON_STAT(efx, XgTxPkts1519toMaxOctets, tx_15xx_to_jumbo);
	FALCON_STAT(efx, XgTxUndersizePkts, tx_lt64);
	FALCON_STAT(efx, XgTxOversizePkts, tx_gtjumbo);
	FALCON_STAT(efx, XgTxNonTcpUdpPkt, tx_non_tcpudp);
	FALCON_STAT(efx, XgTxMacSrcErrPkt, tx_mac_src_error);
	FALCON_STAT(efx, XgTxIpSrcErrPkt, tx_ip_src_error);

	/* Update derived statistics */
	mac_stats->tx_good_bytes =
		(mac_stats->tx_bytes - mac_stats->tx_bad_bytes -
		 mac_stats->tx_control * 64);
	mac_stats->rx_bad_bytes =
		(mac_stats->rx_bytes - mac_stats->rx_good_bytes -
		 mac_stats->rx_control * 64);
}

static void falcon_xmac_irq(struct efx_nic *efx)
{
	/* The XGMII link has a transient fault, which indicates either:
	 *   - there's a transient xgmii fault
	 *   - falcon's end of the xaui link may need a kick
	 *   - the wire-side link may have gone down, but the lasi/poll()
	 *     hasn't noticed yet.
	 *
	 * We only want to even bother polling XAUI if we're confident it's
	 * not (1) or (3). In both cases, the only reliable way to spot this
	 * is to wait a bit. We do this here by forcing the mac link state
	 * to down, and waiting for the mac poll to come round and check
	 */
	efx->mac_up = false;
}

static void falcon_poll_xmac(struct efx_nic *efx)
{
	if (!EFX_WORKAROUND_5147(efx) || !efx->link_up || efx->mac_up)
		return;

	falcon_mask_status_intr(efx, false);
	falcon_check_xaui_link_up(efx, 1);
	falcon_mask_status_intr(efx, true);
}

struct efx_mac_operations falcon_xmac_operations = {
	.reconfigure	= falcon_reconfigure_xmac,
	.update_stats	= falcon_update_stats_xmac,
	.irq		= falcon_xmac_irq,
	.poll		= falcon_poll_xmac,
};
