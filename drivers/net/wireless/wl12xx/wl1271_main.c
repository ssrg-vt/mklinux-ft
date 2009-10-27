/*
 * This file is part of wl1271
 *
 * Copyright (C) 2008-2009 Nokia Corporation
 *
 * Contact: Luciano Coelho <luciano.coelho@nokia.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/firmware.h>
#include <linux/delay.h>
#include <linux/irq.h>
#include <linux/spi/spi.h>
#include <linux/crc32.h>
#include <linux/etherdevice.h>
#include <linux/vmalloc.h>
#include <linux/spi/wl12xx.h>

#include "wl1271.h"
#include "wl12xx_80211.h"
#include "wl1271_reg.h"
#include "wl1271_spi.h"
#include "wl1271_event.h"
#include "wl1271_tx.h"
#include "wl1271_rx.h"
#include "wl1271_ps.h"
#include "wl1271_init.h"
#include "wl1271_debugfs.h"
#include "wl1271_cmd.h"
#include "wl1271_boot.h"

static void wl1271_conf_init(struct wl1271 *wl)
{
	struct conf_drv_settings conf = {
		.sg = {
			.per_threshold              = 7500,
			.max_scan_compensation_time = 120000,
			.nfs_sample_interval        = 400,
			.load_ratio                 = 50,
			.auto_ps_mode               = 0,
			.probe_req_compensation     = 170,
			.scan_window_compensation   = 50,
			.antenna_config             = 0,
			.beacon_miss_threshold      = 60,
			.rate_adaptation_threshold  = CONF_HW_BIT_RATE_12MBPS,
			.rate_adaptation_snr        = 0
		},
		.rx = {
			.rx_msdu_life_time          = 512000,
			.packet_detection_threshold = 0,
			.ps_poll_timeout            = 15,
			.upsd_timeout               = 15,
			.rts_threshold              = 2347,
			.rx_cca_threshold           = 0xFFEF,
			.irq_blk_threshold          = 0,
			.irq_pkt_threshold          = USHORT_MAX,
			.irq_timeout                = 5,
			.queue_type           = CONF_RX_QUEUE_TYPE_LOW_PRIORITY,
		},
		.tx = {
			.tx_energy_detection        = 0,
			.rc_conf                    = {
				.enabled_rates      =
				CONF_TX_RATE_MASK_UNSPECIFIED,
				.short_retry_limit  = 10,
				.long_retry_limit   = 10,
				.aflags             = 0
			},
			.ac_conf_count              = 4,
			.ac_conf                    = {
				[0] = {
					.ac         = CONF_TX_AC_BE,
					.cw_min     = 15,
					.cw_max     = 63,
					.aifsn      = 3,
					.tx_op_limit = 0,
				},
				[1] = {
					.ac         = CONF_TX_AC_BK,
					.cw_min     = 15,
					.cw_max     = 63,
					.aifsn      = 7,
					.tx_op_limit = 0,
				},
				[2] = {
					.ac         = CONF_TX_AC_VI,
					.cw_min     = 15,
					.cw_max     = 63,
					.aifsn      = CONF_TX_AIFS_PIFS,
					.tx_op_limit = 3008,
				},
				[3] = {
					.ac         = CONF_TX_AC_VO,
					.cw_min     = 15,
					.cw_max     = 63,
					.aifsn      = CONF_TX_AIFS_PIFS,
					.tx_op_limit = 1504,
				},
			},
			.tid_conf_count = 7,
			.tid_conf = {
				[0] = {
					.queue_id   = 0,
					.channel_type = CONF_CHANNEL_TYPE_DCF,
					.tsid = CONF_TX_AC_BE,
					.ps_scheme  = CONF_PS_SCHEME_LEGACY,
					.ack_policy = CONF_ACK_POLICY_LEGACY,
					.apsd_conf  = {0, 0},
				},
				[1] = {
					.queue_id   = 1,
					.channel_type = CONF_CHANNEL_TYPE_DCF,
					.tsid = CONF_TX_AC_BE,
					.ps_scheme  = CONF_PS_SCHEME_LEGACY,
					.ack_policy = CONF_ACK_POLICY_LEGACY,
					.apsd_conf  = {0, 0},
				},
				[2] = {
					.queue_id   = 2,
					.channel_type = CONF_CHANNEL_TYPE_DCF,
					.tsid = CONF_TX_AC_BE,
					.ps_scheme  = CONF_PS_SCHEME_LEGACY,
					.ack_policy = CONF_ACK_POLICY_LEGACY,
					.apsd_conf  = {0, 0},
				},
				[3] = {
					.queue_id   = 3,
					.channel_type = CONF_CHANNEL_TYPE_DCF,
					.tsid = CONF_TX_AC_BE,
					.ps_scheme  = CONF_PS_SCHEME_LEGACY,
					.ack_policy = CONF_ACK_POLICY_LEGACY,
					.apsd_conf  = {0, 0},
				},
				[4] = {
					.queue_id   = 4,
					.channel_type = CONF_CHANNEL_TYPE_DCF,
					.tsid = CONF_TX_AC_BE,
					.ps_scheme  = CONF_PS_SCHEME_LEGACY,
					.ack_policy = CONF_ACK_POLICY_LEGACY,
					.apsd_conf  = {0, 0},
				},
				[5] = {
					.queue_id   = 5,
					.channel_type = CONF_CHANNEL_TYPE_DCF,
					.tsid = CONF_TX_AC_BE,
					.ps_scheme  = CONF_PS_SCHEME_LEGACY,
					.ack_policy = CONF_ACK_POLICY_LEGACY,
					.apsd_conf  = {0, 0},
				},
				[6] = {
					.queue_id   = 6,
					.channel_type = CONF_CHANNEL_TYPE_DCF,
					.tsid = CONF_TX_AC_BE,
					.ps_scheme  = CONF_PS_SCHEME_LEGACY,
					.ack_policy = CONF_ACK_POLICY_LEGACY,
					.apsd_conf  = {0, 0},
				}
			},
			.frag_threshold          = IEEE80211_MAX_FRAG_THRESHOLD,
			.tx_compl_timeout           = 5,
			.tx_compl_threshold         = 5
		}
	};

	/*
	 * This function applies the default configuration to the driver. This
	 * function is invoked upon driver load (spi probe.)
	 *
	 * The configuration is stored in a run-time structure in order to
	 * facilitate for run-time adjustment of any of the parameters. Making
	 * changes to the configuration structure will apply the new values on
	 * the next interface up (wl1271_op_start.)
	 */

	/* apply driver default configuration */
	memcpy(&wl->conf, &conf, sizeof(conf));
}


static int wl1271_plt_init(struct wl1271 *wl)
{
	int ret;

	ret = wl1271_acx_init_mem_config(wl);
	if (ret < 0)
		return ret;

	ret = wl1271_cmd_data_path(wl, wl->channel, 1);
	if (ret < 0)
		return ret;

	return 0;
}

static void wl1271_disable_interrupts(struct wl1271 *wl)
{
	disable_irq(wl->irq);
}

static void wl1271_power_off(struct wl1271 *wl)
{
	wl->set_power(false);
}

static void wl1271_power_on(struct wl1271 *wl)
{
	wl->set_power(true);
}

static void wl1271_fw_status(struct wl1271 *wl,
			     struct wl1271_fw_status *status)
{
	u32 total = 0;
	int i;

	wl1271_spi_read(wl, FW_STATUS_ADDR, status,
			sizeof(*status), false);

	wl1271_debug(DEBUG_IRQ, "intr: 0x%x (fw_rx_counter = %d, "
		     "drv_rx_counter = %d, tx_results_counter = %d)",
		     status->intr,
		     status->fw_rx_counter,
		     status->drv_rx_counter,
		     status->tx_results_counter);

	/* update number of available TX blocks */
	for (i = 0; i < NUM_TX_QUEUES; i++) {
		u32 cnt = status->tx_released_blks[i] - wl->tx_blocks_freed[i];
		wl->tx_blocks_freed[i] = status->tx_released_blks[i];
		wl->tx_blocks_available += cnt;
		total += cnt;
	}

	/* if more blocks are available now, schedule some tx work */
	if (total && !skb_queue_empty(&wl->tx_queue))
		ieee80211_queue_work(wl->hw, &wl->tx_work);

	/* update the host-chipset time offset */
	wl->time_offset = jiffies_to_usecs(jiffies) - status->fw_localtime;
}

static void wl1271_irq_work(struct work_struct *work)
{
	int ret;
	u32 intr;
	struct wl1271 *wl =
		container_of(work, struct wl1271, irq_work);

	mutex_lock(&wl->mutex);

	wl1271_debug(DEBUG_IRQ, "IRQ work");

	if (wl->state == WL1271_STATE_OFF)
		goto out;

	ret = wl1271_ps_elp_wakeup(wl, true);
	if (ret < 0)
		goto out;

	wl1271_spi_write32(wl, ACX_REG_INTERRUPT_MASK, WL1271_ACX_INTR_ALL);

	wl1271_fw_status(wl, wl->fw_status);
	intr = wl->fw_status->intr;
	if (!intr) {
		wl1271_debug(DEBUG_IRQ, "Zero interrupt received.");
		goto out_sleep;
	}

	intr &= WL1271_INTR_MASK;

	if (intr & (WL1271_ACX_INTR_EVENT_A |
		    WL1271_ACX_INTR_EVENT_B)) {
		wl1271_debug(DEBUG_IRQ,
			     "WL1271_ACX_INTR_EVENT (0x%x)", intr);
		if (intr & WL1271_ACX_INTR_EVENT_A)
			wl1271_event_handle(wl, 0);
		else
			wl1271_event_handle(wl, 1);
	}

	if (intr & WL1271_ACX_INTR_INIT_COMPLETE)
		wl1271_debug(DEBUG_IRQ,
			     "WL1271_ACX_INTR_INIT_COMPLETE");

	if (intr & WL1271_ACX_INTR_HW_AVAILABLE)
		wl1271_debug(DEBUG_IRQ, "WL1271_ACX_INTR_HW_AVAILABLE");

	if (intr & WL1271_ACX_INTR_DATA) {
		u8 tx_res_cnt = wl->fw_status->tx_results_counter -
			wl->tx_results_count;

		wl1271_debug(DEBUG_IRQ, "WL1271_ACX_INTR_DATA");

		/* check for tx results */
		if (tx_res_cnt)
			wl1271_tx_complete(wl, tx_res_cnt);

		wl1271_rx(wl, wl->fw_status);
	}

out_sleep:
	wl1271_spi_write32(wl, ACX_REG_INTERRUPT_MASK,
			   WL1271_ACX_INTR_ALL & ~(WL1271_INTR_MASK));
	wl1271_ps_elp_sleep(wl);

out:
	mutex_unlock(&wl->mutex);
}

static irqreturn_t wl1271_irq(int irq, void *cookie)
{
	struct wl1271 *wl;
	unsigned long flags;

	wl1271_debug(DEBUG_IRQ, "IRQ");

	wl = cookie;

	/* complete the ELP completion */
	spin_lock_irqsave(&wl->wl_lock, flags);
	if (wl->elp_compl) {
		complete(wl->elp_compl);
		wl->elp_compl = NULL;
	}

	ieee80211_queue_work(wl->hw, &wl->irq_work);
	spin_unlock_irqrestore(&wl->wl_lock, flags);

	return IRQ_HANDLED;
}

static int wl1271_fetch_firmware(struct wl1271 *wl)
{
	const struct firmware *fw;
	int ret;

	ret = request_firmware(&fw, WL1271_FW_NAME, &wl->spi->dev);

	if (ret < 0) {
		wl1271_error("could not get firmware: %d", ret);
		return ret;
	}

	if (fw->size % 4) {
		wl1271_error("firmware size is not multiple of 32 bits: %zu",
			     fw->size);
		ret = -EILSEQ;
		goto out;
	}

	wl->fw_len = fw->size;
	wl->fw = vmalloc(wl->fw_len);

	if (!wl->fw) {
		wl1271_error("could not allocate memory for the firmware");
		ret = -ENOMEM;
		goto out;
	}

	memcpy(wl->fw, fw->data, wl->fw_len);

	ret = 0;

out:
	release_firmware(fw);

	return ret;
}

static int wl1271_fetch_nvs(struct wl1271 *wl)
{
	const struct firmware *fw;
	int ret;

	ret = request_firmware(&fw, WL1271_NVS_NAME, &wl->spi->dev);

	if (ret < 0) {
		wl1271_error("could not get nvs file: %d", ret);
		return ret;
	}

	if (fw->size % 4) {
		wl1271_error("nvs size is not multiple of 32 bits: %zu",
			     fw->size);
		ret = -EILSEQ;
		goto out;
	}

	wl->nvs_len = fw->size;
	wl->nvs = kmalloc(wl->nvs_len, GFP_KERNEL);

	if (!wl->nvs) {
		wl1271_error("could not allocate memory for the nvs file");
		ret = -ENOMEM;
		goto out;
	}

	memcpy(wl->nvs, fw->data, wl->nvs_len);

	ret = 0;

out:
	release_firmware(fw);

	return ret;
}

static void wl1271_fw_wakeup(struct wl1271 *wl)
{
	u32 elp_reg;

	elp_reg = ELPCTRL_WAKE_UP;
	wl1271_raw_write32(wl, HW_ACCESS_ELP_CTRL_REG_ADDR, elp_reg);
}

static int wl1271_setup(struct wl1271 *wl)
{
	wl->fw_status = kmalloc(sizeof(*wl->fw_status), GFP_KERNEL);
	if (!wl->fw_status)
		return -ENOMEM;

	wl->tx_res_if = kmalloc(sizeof(*wl->tx_res_if), GFP_KERNEL);
	if (!wl->tx_res_if) {
		kfree(wl->fw_status);
		return -ENOMEM;
	}

	INIT_WORK(&wl->irq_work, wl1271_irq_work);
	INIT_WORK(&wl->tx_work, wl1271_tx_work);
	return 0;
}

static int wl1271_chip_wakeup(struct wl1271 *wl)
{
	struct wl1271_partition_set partition;
	int ret = 0;

	wl1271_power_on(wl);
	msleep(WL1271_POWER_ON_SLEEP);
	wl1271_spi_reset(wl);
	wl1271_spi_init(wl);

	/* We don't need a real memory partition here, because we only want
	 * to use the registers at this point. */
	memset(&partition, 0, sizeof(partition));
	partition.reg.start = REGISTERS_BASE;
	partition.reg.size = REGISTERS_DOWN_SIZE;
	wl1271_set_partition(wl, &partition);

	/* ELP module wake up */
	wl1271_fw_wakeup(wl);

	/* whal_FwCtrl_BootSm() */

	/* 0. read chip id from CHIP_ID */
	wl->chip.id = wl1271_spi_read32(wl, CHIP_ID_B);

	/* 1. check if chip id is valid */

	switch (wl->chip.id) {
	case CHIP_ID_1271_PG10:
		wl1271_warning("chip id 0x%x (1271 PG10) support is obsolete",
			       wl->chip.id);

		ret = wl1271_setup(wl);
		if (ret < 0)
			goto out;
		break;
	case CHIP_ID_1271_PG20:
		wl1271_debug(DEBUG_BOOT, "chip id 0x%x (1271 PG20)",
			     wl->chip.id);

		ret = wl1271_setup(wl);
		if (ret < 0)
			goto out;
		break;
	default:
		wl1271_error("unsupported chip id: 0x%x", wl->chip.id);
		ret = -ENODEV;
		goto out;
	}

	if (wl->fw == NULL) {
		ret = wl1271_fetch_firmware(wl);
		if (ret < 0)
			goto out;
	}

	/* No NVS from netlink, try to get it from the filesystem */
	if (wl->nvs == NULL) {
		ret = wl1271_fetch_nvs(wl);
		if (ret < 0)
			goto out;
	}

out:
	return ret;
}

struct wl1271_filter_params {
	unsigned int filters;
	unsigned int changed;
	int mc_list_length;
	u8 mc_list[ACX_MC_ADDRESS_GROUP_MAX][ETH_ALEN];
};

#define WL1271_SUPPORTED_FILTERS (FIF_PROMISC_IN_BSS | \
				  FIF_ALLMULTI | \
				  FIF_FCSFAIL | \
				  FIF_BCN_PRBRESP_PROMISC | \
				  FIF_CONTROL | \
				  FIF_OTHER_BSS)

static void wl1271_filter_work(struct work_struct *work)
{
	struct wl1271 *wl =
		container_of(work, struct wl1271, filter_work);
	struct wl1271_filter_params *fp;
	unsigned long flags;
	bool enabled = true;
	int ret;

	/* first, get the filter parameters */
	spin_lock_irqsave(&wl->wl_lock, flags);
	fp = wl->filter_params;
	wl->filter_params = NULL;
	spin_unlock_irqrestore(&wl->wl_lock, flags);

	if (!fp)
		return;

	/* then, lock the mutex without risk of lock-up */
	mutex_lock(&wl->mutex);

	if (wl->state == WL1271_STATE_OFF)
		goto out;

	ret = wl1271_ps_elp_wakeup(wl, false);
	if (ret < 0)
		goto out;

	/* configure the mc filter regardless of the changed flags */
	if (fp->filters & FIF_ALLMULTI)
		enabled = false;

	ret = wl1271_acx_group_address_tbl(wl, enabled,
					   fp->mc_list, fp->mc_list_length);
	if (ret < 0)
		goto out_sleep;

	/* determine, whether supported filter values have changed */
	if (fp->changed == 0)
		goto out;

	/* apply configured filters */
	ret = wl1271_acx_rx_config(wl, wl->rx_config, wl->rx_filter);
	if (ret < 0)
		goto out_sleep;

out_sleep:
	wl1271_ps_elp_sleep(wl);

out:
	mutex_unlock(&wl->mutex);
	kfree(fp);
}

int wl1271_plt_start(struct wl1271 *wl)
{
	int ret;

	mutex_lock(&wl->mutex);

	wl1271_notice("power up");

	if (wl->state != WL1271_STATE_OFF) {
		wl1271_error("cannot go into PLT state because not "
			     "in off state: %d", wl->state);
		ret = -EBUSY;
		goto out;
	}

	wl->state = WL1271_STATE_PLT;

	ret = wl1271_chip_wakeup(wl);
	if (ret < 0)
		goto out;

	ret = wl1271_boot(wl);
	if (ret < 0)
		goto out;

	wl1271_notice("firmware booted in PLT mode (%s)", wl->chip.fw_ver);

	ret = wl1271_plt_init(wl);
	if (ret < 0)
		goto out;

out:
	mutex_unlock(&wl->mutex);

	return ret;
}

int wl1271_plt_stop(struct wl1271 *wl)
{
	int ret = 0;

	mutex_lock(&wl->mutex);

	wl1271_notice("power down");

	if (wl->state != WL1271_STATE_PLT) {
		wl1271_error("cannot power down because not in PLT "
			     "state: %d", wl->state);
		ret = -EBUSY;
		goto out;
	}

	wl1271_disable_interrupts(wl);
	wl1271_power_off(wl);

	wl->state = WL1271_STATE_OFF;

out:
	mutex_unlock(&wl->mutex);

	return ret;
}


static int wl1271_op_tx(struct ieee80211_hw *hw, struct sk_buff *skb)
{
	struct wl1271 *wl = hw->priv;

	skb_queue_tail(&wl->tx_queue, skb);

	/*
	 * The chip specific setup must run before the first TX packet -
	 * before that, the tx_work will not be initialized!
	 */

	ieee80211_queue_work(wl->hw, &wl->tx_work);

	/*
	 * The workqueue is slow to process the tx_queue and we need stop
	 * the queue here, otherwise the queue will get too long.
	 */
	if (skb_queue_len(&wl->tx_queue) >= WL1271_TX_QUEUE_MAX_LENGTH) {
		ieee80211_stop_queues(wl->hw);

		/*
		 * FIXME: this is racy, the variable is not properly
		 * protected. Maybe fix this by removing the stupid
		 * variable altogether and checking the real queue state?
		 */
		wl->tx_queue_stopped = true;
	}

	return NETDEV_TX_OK;
}

static int wl1271_op_start(struct ieee80211_hw *hw)
{
	struct wl1271 *wl = hw->priv;
	int ret = 0;

	wl1271_debug(DEBUG_MAC80211, "mac80211 start");

	mutex_lock(&wl->mutex);

	if (wl->state != WL1271_STATE_OFF) {
		wl1271_error("cannot start because not in off state: %d",
			     wl->state);
		ret = -EBUSY;
		goto out;
	}

	ret = wl1271_chip_wakeup(wl);
	if (ret < 0)
		goto out;

	ret = wl1271_boot(wl);
	if (ret < 0)
		goto out;

	ret = wl1271_hw_init(wl);
	if (ret < 0)
		goto out;

	wl->state = WL1271_STATE_ON;

	wl1271_info("firmware booted (%s)", wl->chip.fw_ver);

out:
	if (ret < 0)
		wl1271_power_off(wl);

	mutex_unlock(&wl->mutex);

	return ret;
}

static void wl1271_op_stop(struct ieee80211_hw *hw)
{
	struct wl1271 *wl = hw->priv;
	unsigned long flags;
	int i;

	wl1271_info("down");

	wl1271_debug(DEBUG_MAC80211, "mac80211 stop");

	/* complete/cancel ongoing work */
	cancel_work_sync(&wl->filter_work);
	spin_lock_irqsave(&wl->wl_lock, flags);
	kfree(wl->filter_params);
	wl->filter_params = NULL;
	spin_unlock_irqrestore(&wl->wl_lock, flags);

	mutex_lock(&wl->mutex);

	WARN_ON(wl->state != WL1271_STATE_ON);

	if (wl->scanning) {
		mutex_unlock(&wl->mutex);
		ieee80211_scan_completed(wl->hw, true);
		mutex_lock(&wl->mutex);
		wl->scanning = false;
	}

	wl->state = WL1271_STATE_OFF;

	wl1271_disable_interrupts(wl);

	mutex_unlock(&wl->mutex);

	cancel_work_sync(&wl->irq_work);
	cancel_work_sync(&wl->tx_work);
	cancel_work_sync(&wl->filter_work);

	mutex_lock(&wl->mutex);

	/* let's notify MAC80211 about the remaining pending TX frames */
	wl1271_tx_flush(wl);
	wl1271_power_off(wl);

	memset(wl->bssid, 0, ETH_ALEN);
	memset(wl->ssid, 0, IW_ESSID_MAX_SIZE + 1);
	wl->ssid_len = 0;
	wl->listen_int = 1;
	wl->bss_type = MAX_BSS_TYPE;
	wl->band = IEEE80211_BAND_2GHZ;

	wl->rx_counter = 0;
	wl->elp = false;
	wl->psm = 0;
	wl->tx_queue_stopped = false;
	wl->power_level = WL1271_DEFAULT_POWER_LEVEL;
	wl->tx_blocks_available = 0;
	wl->tx_results_count = 0;
	wl->tx_packets_count = 0;
	wl->tx_security_last_seq = 0;
	wl->tx_security_seq_16 = 0;
	wl->tx_security_seq_32 = 0;
	wl->time_offset = 0;
	wl->session_counter = 0;
	wl->joined = false;

	for (i = 0; i < NUM_TX_QUEUES; i++)
		wl->tx_blocks_freed[i] = 0;

	wl1271_debugfs_reset(wl);
	mutex_unlock(&wl->mutex);
}

static int wl1271_op_add_interface(struct ieee80211_hw *hw,
				   struct ieee80211_if_init_conf *conf)
{
	struct wl1271 *wl = hw->priv;
	int ret = 0;

	wl1271_debug(DEBUG_MAC80211, "mac80211 add interface type %d mac %pM",
		     conf->type, conf->mac_addr);

	mutex_lock(&wl->mutex);
	if (wl->vif) {
		ret = -EBUSY;
		goto out;
	}

	wl->vif = conf->vif;

	switch (conf->type) {
	case NL80211_IFTYPE_STATION:
		wl->bss_type = BSS_TYPE_STA_BSS;
		break;
	case NL80211_IFTYPE_ADHOC:
		wl->bss_type = BSS_TYPE_IBSS;
		break;
	default:
		ret = -EOPNOTSUPP;
		goto out;
	}

	/* FIXME: what if conf->mac_addr changes? */

out:
	mutex_unlock(&wl->mutex);
	return ret;
}

static void wl1271_op_remove_interface(struct ieee80211_hw *hw,
					 struct ieee80211_if_init_conf *conf)
{
	struct wl1271 *wl = hw->priv;

	mutex_lock(&wl->mutex);
	wl1271_debug(DEBUG_MAC80211, "mac80211 remove interface");
	wl->vif = NULL;
	mutex_unlock(&wl->mutex);
}

#if 0
static int wl1271_op_config_interface(struct ieee80211_hw *hw,
				      struct ieee80211_vif *vif,
				      struct ieee80211_if_conf *conf)
{
	struct wl1271 *wl = hw->priv;
	struct sk_buff *beacon;
	int ret;

	wl1271_debug(DEBUG_MAC80211, "mac80211 config_interface bssid %pM",
		     conf->bssid);
	wl1271_dump_ascii(DEBUG_MAC80211, "ssid: ", conf->ssid,
			  conf->ssid_len);

	mutex_lock(&wl->mutex);

	ret = wl1271_ps_elp_wakeup(wl, false);
	if (ret < 0)
		goto out;

	if (memcmp(wl->bssid, conf->bssid, ETH_ALEN)) {
		wl1271_debug(DEBUG_MAC80211, "bssid changed");

		memcpy(wl->bssid, conf->bssid, ETH_ALEN);

		ret = wl1271_cmd_join(wl);
		if (ret < 0)
			goto out_sleep;
	}

	ret = wl1271_cmd_build_null_data(wl);
	if (ret < 0)
		goto out_sleep;

	wl->ssid_len = conf->ssid_len;
	if (wl->ssid_len)
		memcpy(wl->ssid, conf->ssid, wl->ssid_len);

	if (conf->changed & IEEE80211_IFCC_BEACON) {
		beacon = ieee80211_beacon_get(hw, vif);
		ret = wl1271_cmd_template_set(wl, CMD_TEMPL_BEACON,
					      beacon->data, beacon->len);

		if (ret < 0) {
			dev_kfree_skb(beacon);
			goto out_sleep;
		}

		ret = wl1271_cmd_template_set(wl, CMD_TEMPL_PROBE_RESPONSE,
					      beacon->data, beacon->len);

		dev_kfree_skb(beacon);

		if (ret < 0)
			goto out_sleep;
	}

out_sleep:
	wl1271_ps_elp_sleep(wl);

out:
	mutex_unlock(&wl->mutex);

	return ret;
}
#endif

static int wl1271_op_config(struct ieee80211_hw *hw, u32 changed)
{
	struct wl1271 *wl = hw->priv;
	struct ieee80211_conf *conf = &hw->conf;
	int channel, ret = 0;

	channel = ieee80211_frequency_to_channel(conf->channel->center_freq);

	wl1271_debug(DEBUG_MAC80211, "mac80211 config ch %d psm %s power %d",
		     channel,
		     conf->flags & IEEE80211_CONF_PS ? "on" : "off",
		     conf->power_level);

	mutex_lock(&wl->mutex);

	wl->band = conf->channel->band;

	ret = wl1271_ps_elp_wakeup(wl, false);
	if (ret < 0)
		goto out;

	if (channel != wl->channel) {
		/*
		 * We assume that the stack will configure the right channel
		 * before associating, so we don't need to send a join
		 * command here.  We will join the right channel when the
		 * BSSID changes
		 */
		wl->channel = channel;
	}

	ret = wl1271_cmd_build_null_data(wl);
	if (ret < 0)
		goto out_sleep;

	if (conf->flags & IEEE80211_CONF_PS && !wl->psm_requested) {
		wl1271_info("psm enabled");

		wl->psm_requested = true;

		/*
		 * We enter PSM only if we're already associated.
		 * If we're not, we'll enter it when joining an SSID,
		 * through the bss_info_changed() hook.
		 */
		ret = wl1271_ps_set_mode(wl, STATION_POWER_SAVE_MODE);
	} else if (!(conf->flags & IEEE80211_CONF_PS) &&
		   wl->psm_requested) {
		wl1271_info("psm disabled");

		wl->psm_requested = false;

		if (wl->psm)
			ret = wl1271_ps_set_mode(wl, STATION_ACTIVE_MODE);
	}

	if (conf->power_level != wl->power_level) {
		ret = wl1271_acx_tx_power(wl, conf->power_level);
		if (ret < 0)
			goto out;

		wl->power_level = conf->power_level;
	}

out_sleep:
	wl1271_ps_elp_sleep(wl);

out:
	mutex_unlock(&wl->mutex);

	return ret;
}

static u64 wl1271_op_prepare_multicast(struct ieee80211_hw *hw, int mc_count,
				       struct dev_addr_list *mc_list)
{
	struct wl1271 *wl = hw->priv;
	struct wl1271_filter_params *fp;
	unsigned long flags;
	int i;

	/*
	 * FIXME: we should return a hash that will be passed to
	 * configure_filter() instead of saving everything in the context.
	 */

	fp = kzalloc(sizeof(*fp), GFP_KERNEL);
	if (!fp) {
		wl1271_error("Out of memory setting filters.");
		return 0;
	}

	/* update multicast filtering parameters */
	if (mc_count > ACX_MC_ADDRESS_GROUP_MAX) {
		mc_count = 0;
		fp->filters |= FIF_ALLMULTI;
	}

	fp->mc_list_length = 0;
	for (i = 0; i < mc_count; i++) {
		if (mc_list->da_addrlen == ETH_ALEN) {
			memcpy(fp->mc_list[fp->mc_list_length],
			       mc_list->da_addr, ETH_ALEN);
			fp->mc_list_length++;
		} else
			wl1271_warning("Unknown mc address length.");
	}

	/* FIXME: We still need to set our filters properly */

	spin_lock_irqsave(&wl->wl_lock, flags);
	kfree(wl->filter_params);
	wl->filter_params = fp;
	spin_unlock_irqrestore(&wl->wl_lock, flags);

	return 1;
}

static void wl1271_op_configure_filter(struct ieee80211_hw *hw,
				       unsigned int changed,
				       unsigned int *total, u64 multicast)
{
	struct wl1271 *wl = hw->priv;

	wl1271_debug(DEBUG_MAC80211, "mac80211 configure filter");

	*total &= WL1271_SUPPORTED_FILTERS;
	changed &= WL1271_SUPPORTED_FILTERS;

	if (!multicast)
		return;

	/*
	 * FIXME: for now we are still using a workqueue for filter
	 * configuration, but with the new mac80211, this is not needed,
	 * since configure_filter can now sleep.  We now have
	 * prepare_multicast, which needs to be atomic instead.
	 */

	/* store current filter config */
	wl->filter_params->filters = *total;
	wl->filter_params->changed = changed;

	ieee80211_queue_work(wl->hw, &wl->filter_work);
}

static int wl1271_op_set_key(struct ieee80211_hw *hw, enum set_key_cmd cmd,
			     struct ieee80211_vif *vif,
			     struct ieee80211_sta *sta,
			     struct ieee80211_key_conf *key_conf)
{
	struct wl1271 *wl = hw->priv;
	const u8 *addr;
	int ret;
	u32 tx_seq_32 = 0;
	u16 tx_seq_16 = 0;
	u8 key_type;

	static const u8 bcast_addr[ETH_ALEN] =
		{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	wl1271_debug(DEBUG_MAC80211, "mac80211 set key");

	addr = sta ? sta->addr : bcast_addr;

	wl1271_debug(DEBUG_CRYPT, "CMD: 0x%x", cmd);
	wl1271_dump(DEBUG_CRYPT, "ADDR: ", addr, ETH_ALEN);
	wl1271_debug(DEBUG_CRYPT, "Key: algo:0x%x, id:%d, len:%d flags 0x%x",
		     key_conf->alg, key_conf->keyidx,
		     key_conf->keylen, key_conf->flags);
	wl1271_dump(DEBUG_CRYPT, "KEY: ", key_conf->key, key_conf->keylen);

	if (is_zero_ether_addr(addr)) {
		/* We dont support TX only encryption */
		ret = -EOPNOTSUPP;
		goto out;
	}

	mutex_lock(&wl->mutex);

	ret = wl1271_ps_elp_wakeup(wl, false);
	if (ret < 0)
		goto out_unlock;

	switch (key_conf->alg) {
	case ALG_WEP:
		key_type = KEY_WEP;

		key_conf->hw_key_idx = key_conf->keyidx;
		break;
	case ALG_TKIP:
		key_type = KEY_TKIP;

		key_conf->hw_key_idx = key_conf->keyidx;
		tx_seq_32 = wl->tx_security_seq_32;
		tx_seq_16 = wl->tx_security_seq_16;
		break;
	case ALG_CCMP:
		key_type = KEY_AES;

		key_conf->flags |= IEEE80211_KEY_FLAG_GENERATE_IV;
		tx_seq_32 = wl->tx_security_seq_32;
		tx_seq_16 = wl->tx_security_seq_16;
		break;
	default:
		wl1271_error("Unknown key algo 0x%x", key_conf->alg);

		ret = -EOPNOTSUPP;
		goto out_sleep;
	}

	switch (cmd) {
	case SET_KEY:
		ret = wl1271_cmd_set_key(wl, KEY_ADD_OR_REPLACE,
					 key_conf->keyidx, key_type,
					 key_conf->keylen, key_conf->key,
					 addr, tx_seq_32, tx_seq_16);
		if (ret < 0) {
			wl1271_error("Could not add or replace key");
			goto out_sleep;
		}
		break;

	case DISABLE_KEY:
		ret = wl1271_cmd_set_key(wl, KEY_REMOVE,
					 key_conf->keyidx, key_type,
					 key_conf->keylen, key_conf->key,
					 addr, 0, 0);
		if (ret < 0) {
			wl1271_error("Could not remove key");
			goto out_sleep;
		}
		break;

	default:
		wl1271_error("Unsupported key cmd 0x%x", cmd);
		ret = -EOPNOTSUPP;
		goto out_sleep;

		break;
	}

out_sleep:
	wl1271_ps_elp_sleep(wl);

out_unlock:
	mutex_unlock(&wl->mutex);

out:
	return ret;
}

static int wl1271_op_hw_scan(struct ieee80211_hw *hw,
			     struct cfg80211_scan_request *req)
{
	struct wl1271 *wl = hw->priv;
	int ret;
	u8 *ssid = NULL;
	size_t ssid_len = 0;

	wl1271_debug(DEBUG_MAC80211, "mac80211 hw scan");

	if (req->n_ssids) {
		ssid = req->ssids[0].ssid;
		ssid_len = req->ssids[0].ssid_len;
	}

	mutex_lock(&wl->mutex);

	ret = wl1271_ps_elp_wakeup(wl, false);
	if (ret < 0)
		goto out;

	ret = wl1271_cmd_scan(hw->priv, ssid, ssid_len, 1, 0, 13, 3);

	wl1271_ps_elp_sleep(wl);

out:
	mutex_unlock(&wl->mutex);

	return ret;
}

static int wl1271_op_set_rts_threshold(struct ieee80211_hw *hw, u32 value)
{
	struct wl1271 *wl = hw->priv;
	int ret;

	mutex_lock(&wl->mutex);

	ret = wl1271_ps_elp_wakeup(wl, false);
	if (ret < 0)
		goto out;

	ret = wl1271_acx_rts_threshold(wl, (u16) value);
	if (ret < 0)
		wl1271_warning("wl1271_op_set_rts_threshold failed: %d", ret);

	wl1271_ps_elp_sleep(wl);

out:
	mutex_unlock(&wl->mutex);

	return ret;
}

static u32 wl1271_enabled_rates_get(struct wl1271 *wl, u64 basic_rate_set)
{
	struct ieee80211_supported_band *band;
	u32 enabled_rates = 0;
	int bit;

	band = wl->hw->wiphy->bands[wl->band];
	for (bit = 0; bit < band->n_bitrates; bit++) {
		if (basic_rate_set & 0x1)
			enabled_rates |= band->bitrates[bit].hw_value;
		basic_rate_set >>= 1;
	}

	return enabled_rates;
}

static void wl1271_op_bss_info_changed(struct ieee80211_hw *hw,
				       struct ieee80211_vif *vif,
				       struct ieee80211_bss_conf *bss_conf,
				       u32 changed)
{
	enum wl1271_cmd_ps_mode mode;
	struct wl1271 *wl = hw->priv;
	int ret;

	wl1271_debug(DEBUG_MAC80211, "mac80211 bss info changed");

	mutex_lock(&wl->mutex);

	ret = wl1271_ps_elp_wakeup(wl, false);
	if (ret < 0)
		goto out;

	if (changed & BSS_CHANGED_ASSOC) {
		if (bss_conf->assoc) {
			wl->aid = bss_conf->aid;

			/*
			 * with wl1271, we don't need to update the
			 * beacon_int and dtim_period, because the firmware
			 * updates it by itself when the first beacon is
			 * received after a join.
			 */
			ret = wl1271_cmd_build_ps_poll(wl, wl->aid);
			if (ret < 0)
				goto out_sleep;

			ret = wl1271_acx_aid(wl, wl->aid);
			if (ret < 0)
				goto out_sleep;

			/* If we want to go in PSM but we're not there yet */
			if (wl->psm_requested && !wl->psm) {
				mode = STATION_POWER_SAVE_MODE;
				ret = wl1271_ps_set_mode(wl, mode);
				if (ret < 0)
					goto out_sleep;
			}
		} else {
			/* use defaults when not associated */
			wl->basic_rate_set = WL1271_DEFAULT_BASIC_RATE_SET;
			wl->aid = 0;
		}

	}

	if (changed & BSS_CHANGED_ERP_SLOT) {
		if (bss_conf->use_short_slot)
			ret = wl1271_acx_slot(wl, SLOT_TIME_SHORT);
		else
			ret = wl1271_acx_slot(wl, SLOT_TIME_LONG);
		if (ret < 0) {
			wl1271_warning("Set slot time failed %d", ret);
			goto out_sleep;
		}
	}

	if (changed & BSS_CHANGED_ERP_PREAMBLE) {
		if (bss_conf->use_short_preamble)
			wl1271_acx_set_preamble(wl, ACX_PREAMBLE_SHORT);
		else
			wl1271_acx_set_preamble(wl, ACX_PREAMBLE_LONG);
	}

	if (changed & BSS_CHANGED_ERP_CTS_PROT) {
		if (bss_conf->use_cts_prot)
			ret = wl1271_acx_cts_protect(wl, CTSPROTECT_ENABLE);
		else
			ret = wl1271_acx_cts_protect(wl, CTSPROTECT_DISABLE);
		if (ret < 0) {
			wl1271_warning("Set ctsprotect failed %d", ret);
			goto out_sleep;
		}
	}

	if (changed & BSS_CHANGED_BASIC_RATES) {
		wl->basic_rate_set = wl1271_enabled_rates_get(
			wl, bss_conf->basic_rates);

		ret = wl1271_acx_rate_policies(wl, wl->basic_rate_set);
		if (ret < 0) {
			wl1271_warning("Set rate policies failed %d", ret);
			goto out_sleep;
		}
	}

out_sleep:
	wl1271_ps_elp_sleep(wl);

out:
	mutex_unlock(&wl->mutex);
}


/* can't be const, mac80211 writes to this */
static struct ieee80211_rate wl1271_rates[] = {
	{ .bitrate = 10,
	  .hw_value = CONF_HW_BIT_RATE_1MBPS,
	  .hw_value_short = CONF_HW_BIT_RATE_1MBPS, },
	{ .bitrate = 20,
	  .hw_value = CONF_HW_BIT_RATE_2MBPS,
	  .hw_value_short = CONF_HW_BIT_RATE_2MBPS,
	  .flags = IEEE80211_RATE_SHORT_PREAMBLE },
	{ .bitrate = 55,
	  .hw_value = CONF_HW_BIT_RATE_5_5MBPS,
	  .hw_value_short = CONF_HW_BIT_RATE_5_5MBPS,
	  .flags = IEEE80211_RATE_SHORT_PREAMBLE },
	{ .bitrate = 110,
	  .hw_value = CONF_HW_BIT_RATE_11MBPS,
	  .hw_value_short = CONF_HW_BIT_RATE_11MBPS,
	  .flags = IEEE80211_RATE_SHORT_PREAMBLE },
	{ .bitrate = 60,
	  .hw_value = CONF_HW_BIT_RATE_6MBPS,
	  .hw_value_short = CONF_HW_BIT_RATE_6MBPS, },
	{ .bitrate = 90,
	  .hw_value = CONF_HW_BIT_RATE_9MBPS,
	  .hw_value_short = CONF_HW_BIT_RATE_9MBPS, },
	{ .bitrate = 120,
	  .hw_value = CONF_HW_BIT_RATE_12MBPS,
	  .hw_value_short = CONF_HW_BIT_RATE_12MBPS, },
	{ .bitrate = 180,
	  .hw_value = CONF_HW_BIT_RATE_18MBPS,
	  .hw_value_short = CONF_HW_BIT_RATE_18MBPS, },
	{ .bitrate = 240,
	  .hw_value = CONF_HW_BIT_RATE_24MBPS,
	  .hw_value_short = CONF_HW_BIT_RATE_24MBPS, },
	{ .bitrate = 360,
	 .hw_value = CONF_HW_BIT_RATE_36MBPS,
	 .hw_value_short = CONF_HW_BIT_RATE_36MBPS, },
	{ .bitrate = 480,
	  .hw_value = CONF_HW_BIT_RATE_48MBPS,
	  .hw_value_short = CONF_HW_BIT_RATE_48MBPS, },
	{ .bitrate = 540,
	  .hw_value = CONF_HW_BIT_RATE_54MBPS,
	  .hw_value_short = CONF_HW_BIT_RATE_54MBPS, },
};

/* can't be const, mac80211 writes to this */
static struct ieee80211_channel wl1271_channels[] = {
	{ .hw_value = 1, .center_freq = 2412},
	{ .hw_value = 2, .center_freq = 2417},
	{ .hw_value = 3, .center_freq = 2422},
	{ .hw_value = 4, .center_freq = 2427},
	{ .hw_value = 5, .center_freq = 2432},
	{ .hw_value = 6, .center_freq = 2437},
	{ .hw_value = 7, .center_freq = 2442},
	{ .hw_value = 8, .center_freq = 2447},
	{ .hw_value = 9, .center_freq = 2452},
	{ .hw_value = 10, .center_freq = 2457},
	{ .hw_value = 11, .center_freq = 2462},
	{ .hw_value = 12, .center_freq = 2467},
	{ .hw_value = 13, .center_freq = 2472},
};

/* can't be const, mac80211 writes to this */
static struct ieee80211_supported_band wl1271_band_2ghz = {
	.channels = wl1271_channels,
	.n_channels = ARRAY_SIZE(wl1271_channels),
	.bitrates = wl1271_rates,
	.n_bitrates = ARRAY_SIZE(wl1271_rates),
};

static const struct ieee80211_ops wl1271_ops = {
	.start = wl1271_op_start,
	.stop = wl1271_op_stop,
	.add_interface = wl1271_op_add_interface,
	.remove_interface = wl1271_op_remove_interface,
	.config = wl1271_op_config,
/* 	.config_interface = wl1271_op_config_interface, */
	.prepare_multicast = wl1271_op_prepare_multicast,
	.configure_filter = wl1271_op_configure_filter,
	.tx = wl1271_op_tx,
	.set_key = wl1271_op_set_key,
	.hw_scan = wl1271_op_hw_scan,
	.bss_info_changed = wl1271_op_bss_info_changed,
	.set_rts_threshold = wl1271_op_set_rts_threshold,
};

static int wl1271_register_hw(struct wl1271 *wl)
{
	int ret;

	if (wl->mac80211_registered)
		return 0;

	SET_IEEE80211_PERM_ADDR(wl->hw, wl->mac_addr);

	ret = ieee80211_register_hw(wl->hw);
	if (ret < 0) {
		wl1271_error("unable to register mac80211 hw: %d", ret);
		return ret;
	}

	wl->mac80211_registered = true;

	wl1271_notice("loaded");

	return 0;
}

static int wl1271_init_ieee80211(struct wl1271 *wl)
{
	/* The tx descriptor buffer and the TKIP space. */
	wl->hw->extra_tx_headroom = WL1271_TKIP_IV_SPACE +
		sizeof(struct wl1271_tx_hw_descr);

	/* unit us */
	/* FIXME: find a proper value */
	wl->hw->channel_change_time = 10000;

	wl->hw->flags = IEEE80211_HW_SIGNAL_DBM |
		IEEE80211_HW_NOISE_DBM |
		IEEE80211_HW_BEACON_FILTER;

	wl->hw->wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION);
	wl->hw->wiphy->max_scan_ssids = 1;
	wl->hw->wiphy->bands[IEEE80211_BAND_2GHZ] = &wl1271_band_2ghz;

	SET_IEEE80211_DEV(wl->hw, &wl->spi->dev);

	return 0;
}

static void wl1271_device_release(struct device *dev)
{

}

static struct platform_device wl1271_device = {
	.name           = "wl1271",
	.id             = -1,

	/* device model insists to have a release function */
	.dev            = {
		.release = wl1271_device_release,
	},
};

#define WL1271_DEFAULT_CHANNEL 0
static int __devinit wl1271_probe(struct spi_device *spi)
{
	struct wl12xx_platform_data *pdata;
	struct ieee80211_hw *hw;
	struct wl1271 *wl;
	int ret, i;
	static const u8 nokia_oui[3] = {0x00, 0x1f, 0xdf};

	pdata = spi->dev.platform_data;
	if (!pdata) {
		wl1271_error("no platform data");
		return -ENODEV;
	}

	hw = ieee80211_alloc_hw(sizeof(*wl), &wl1271_ops);
	if (!hw) {
		wl1271_error("could not alloc ieee80211_hw");
		return -ENOMEM;
	}

	wl = hw->priv;
	memset(wl, 0, sizeof(*wl));

	wl->hw = hw;
	dev_set_drvdata(&spi->dev, wl);
	wl->spi = spi;

	skb_queue_head_init(&wl->tx_queue);

	INIT_WORK(&wl->filter_work, wl1271_filter_work);
	INIT_DELAYED_WORK(&wl->elp_work, wl1271_elp_work);
	wl->channel = WL1271_DEFAULT_CHANNEL;
	wl->scanning = false;
	wl->default_key = 0;
	wl->listen_int = 1;
	wl->rx_counter = 0;
	wl->rx_config = WL1271_DEFAULT_RX_CONFIG;
	wl->rx_filter = WL1271_DEFAULT_RX_FILTER;
	wl->elp = false;
	wl->psm = 0;
	wl->psm_requested = false;
	wl->tx_queue_stopped = false;
	wl->power_level = WL1271_DEFAULT_POWER_LEVEL;
	wl->basic_rate_set = WL1271_DEFAULT_BASIC_RATE_SET;
	wl->band = IEEE80211_BAND_2GHZ;
	wl->vif = NULL;
	wl->joined = false;

	for (i = 0; i < ACX_TX_DESCRIPTORS; i++)
		wl->tx_frames[i] = NULL;

	spin_lock_init(&wl->wl_lock);

	/*
	 * In case our MAC address is not correctly set,
	 * we use a random but Nokia MAC.
	 */
	memcpy(wl->mac_addr, nokia_oui, 3);
	get_random_bytes(wl->mac_addr + 3, 3);

	wl->state = WL1271_STATE_OFF;
	mutex_init(&wl->mutex);

	wl->rx_descriptor = kmalloc(sizeof(*wl->rx_descriptor), GFP_KERNEL);
	if (!wl->rx_descriptor) {
		wl1271_error("could not allocate memory for rx descriptor");
		ret = -ENOMEM;
		goto out_free;
	}

	/* This is the only SPI value that we need to set here, the rest
	 * comes from the board-peripherals file */
	spi->bits_per_word = 32;

	ret = spi_setup(spi);
	if (ret < 0) {
		wl1271_error("spi_setup failed");
		goto out_free;
	}

	wl->set_power = pdata->set_power;
	if (!wl->set_power) {
		wl1271_error("set power function missing in platform data");
		ret = -ENODEV;
		goto out_free;
	}

	wl->irq = spi->irq;
	if (wl->irq < 0) {
		wl1271_error("irq missing in platform data");
		ret = -ENODEV;
		goto out_free;
	}

	ret = request_irq(wl->irq, wl1271_irq, 0, DRIVER_NAME, wl);
	if (ret < 0) {
		wl1271_error("request_irq() failed: %d", ret);
		goto out_free;
	}

	set_irq_type(wl->irq, IRQ_TYPE_EDGE_RISING);

	disable_irq(wl->irq);

	ret = platform_device_register(&wl1271_device);
	if (ret) {
		wl1271_error("couldn't register platform device");
		goto out_irq;
	}
	dev_set_drvdata(&wl1271_device.dev, wl);

	/* Apply default driver configuration. */
	wl1271_conf_init(wl);

	ret = wl1271_init_ieee80211(wl);
	if (ret)
		goto out_platform;

	ret = wl1271_register_hw(wl);
	if (ret)
		goto out_platform;

	wl1271_debugfs_init(wl);

	wl1271_notice("initialized");

	return 0;

 out_platform:
	platform_device_unregister(&wl1271_device);

 out_irq:
	free_irq(wl->irq, wl);

 out_free:
	kfree(wl->rx_descriptor);
	wl->rx_descriptor = NULL;

	ieee80211_free_hw(hw);

	return ret;
}

static int __devexit wl1271_remove(struct spi_device *spi)
{
	struct wl1271 *wl = dev_get_drvdata(&spi->dev);

	ieee80211_unregister_hw(wl->hw);

	wl1271_debugfs_exit(wl);
	platform_device_unregister(&wl1271_device);
	free_irq(wl->irq, wl);
	kfree(wl->target_mem_map);
	vfree(wl->fw);
	wl->fw = NULL;
	kfree(wl->nvs);
	wl->nvs = NULL;

	kfree(wl->rx_descriptor);
	wl->rx_descriptor = NULL;

	kfree(wl->fw_status);
	kfree(wl->tx_res_if);

	ieee80211_free_hw(wl->hw);

	return 0;
}


static struct spi_driver wl1271_spi_driver = {
	.driver = {
		.name		= "wl1271",
		.bus		= &spi_bus_type,
		.owner		= THIS_MODULE,
	},

	.probe		= wl1271_probe,
	.remove		= __devexit_p(wl1271_remove),
};

static int __init wl1271_init(void)
{
	int ret;

	ret = spi_register_driver(&wl1271_spi_driver);
	if (ret < 0) {
		wl1271_error("failed to register spi driver: %d", ret);
		goto out;
	}

out:
	return ret;
}

static void __exit wl1271_exit(void)
{
	spi_unregister_driver(&wl1271_spi_driver);

	wl1271_notice("unloaded");
}

module_init(wl1271_init);
module_exit(wl1271_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luciano Coelho <luciano.coelho@nokia.com>");
MODULE_AUTHOR("Juuso Oikarinen <juuso.oikarinen@nokia.com>");
