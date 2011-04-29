/*
 * Copyright (c) 2010-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "htc.h"

static int ath9k_debugfs_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;
	return 0;
}

static ssize_t read_file_tgt_int_stats(struct file *file, char __user *user_buf,
				       size_t count, loff_t *ppos)
{
	struct ath9k_htc_priv *priv = file->private_data;
	struct ath9k_htc_target_int_stats cmd_rsp;
	char buf[512];
	unsigned int len = 0;
	int ret = 0;

	memset(&cmd_rsp, 0, sizeof(cmd_rsp));

	ath9k_htc_ps_wakeup(priv);

	WMI_CMD(WMI_INT_STATS_CMDID);
	if (ret) {
		ath9k_htc_ps_restore(priv);
		return -EINVAL;
	}

	ath9k_htc_ps_restore(priv);

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "RX",
			be32_to_cpu(cmd_rsp.rx));

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "RXORN",
			be32_to_cpu(cmd_rsp.rxorn));

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "RXEOL",
			be32_to_cpu(cmd_rsp.rxeol));

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "TXURN",
			be32_to_cpu(cmd_rsp.txurn));

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "TXTO",
			be32_to_cpu(cmd_rsp.txto));

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "CST",
			be32_to_cpu(cmd_rsp.cst));

	if (len > sizeof(buf))
		len = sizeof(buf);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_tgt_int_stats = {
	.read = read_file_tgt_int_stats,
	.open = ath9k_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t read_file_tgt_tx_stats(struct file *file, char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	struct ath9k_htc_priv *priv = file->private_data;
	struct ath9k_htc_target_tx_stats cmd_rsp;
	char buf[512];
	unsigned int len = 0;
	int ret = 0;

	memset(&cmd_rsp, 0, sizeof(cmd_rsp));

	ath9k_htc_ps_wakeup(priv);

	WMI_CMD(WMI_TX_STATS_CMDID);
	if (ret) {
		ath9k_htc_ps_restore(priv);
		return -EINVAL;
	}

	ath9k_htc_ps_restore(priv);

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "Xretries",
			be32_to_cpu(cmd_rsp.xretries));

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "FifoErr",
			be32_to_cpu(cmd_rsp.fifoerr));

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "Filtered",
			be32_to_cpu(cmd_rsp.filtered));

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "TimerExp",
			be32_to_cpu(cmd_rsp.timer_exp));

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "ShortRetries",
			be32_to_cpu(cmd_rsp.shortretries));

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "LongRetries",
			be32_to_cpu(cmd_rsp.longretries));

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "QueueNull",
			be32_to_cpu(cmd_rsp.qnull));

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "EncapFail",
			be32_to_cpu(cmd_rsp.encap_fail));

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "NoBuf",
			be32_to_cpu(cmd_rsp.nobuf));

	if (len > sizeof(buf))
		len = sizeof(buf);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_tgt_tx_stats = {
	.read = read_file_tgt_tx_stats,
	.open = ath9k_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t read_file_tgt_rx_stats(struct file *file, char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	struct ath9k_htc_priv *priv = file->private_data;
	struct ath9k_htc_target_rx_stats cmd_rsp;
	char buf[512];
	unsigned int len = 0;
	int ret = 0;

	memset(&cmd_rsp, 0, sizeof(cmd_rsp));

	ath9k_htc_ps_wakeup(priv);

	WMI_CMD(WMI_RX_STATS_CMDID);
	if (ret) {
		ath9k_htc_ps_restore(priv);
		return -EINVAL;
	}

	ath9k_htc_ps_restore(priv);

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "NoBuf",
			be32_to_cpu(cmd_rsp.nobuf));

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "HostSend",
			be32_to_cpu(cmd_rsp.host_send));

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "HostDone",
			be32_to_cpu(cmd_rsp.host_done));

	if (len > sizeof(buf))
		len = sizeof(buf);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_tgt_rx_stats = {
	.read = read_file_tgt_rx_stats,
	.open = ath9k_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t read_file_xmit(struct file *file, char __user *user_buf,
			      size_t count, loff_t *ppos)
{
	struct ath9k_htc_priv *priv = file->private_data;
	char buf[512];
	unsigned int len = 0;

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "Buffers queued",
			priv->debug.tx_stats.buf_queued);
	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "Buffers completed",
			priv->debug.tx_stats.buf_completed);
	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "SKBs queued",
			priv->debug.tx_stats.skb_queued);
	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "SKBs success",
			priv->debug.tx_stats.skb_success);
	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "SKBs failed",
			priv->debug.tx_stats.skb_failed);
	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "CAB queued",
			priv->debug.tx_stats.cab_queued);

	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "BE queued",
			priv->debug.tx_stats.queue_stats[WME_AC_BE]);
	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "BK queued",
			priv->debug.tx_stats.queue_stats[WME_AC_BK]);
	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "VI queued",
			priv->debug.tx_stats.queue_stats[WME_AC_VI]);
	len += snprintf(buf + len, sizeof(buf) - len,
			"%20s : %10u\n", "VO queued",
			priv->debug.tx_stats.queue_stats[WME_AC_VO]);

	if (len > sizeof(buf))
		len = sizeof(buf);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_xmit = {
	.read = read_file_xmit,
	.open = ath9k_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

void ath9k_htc_err_stat_rx(struct ath9k_htc_priv *priv,
			   struct ath_htc_rx_status *rxs)
{
#define RX_PHY_ERR_INC(c) priv->debug.rx_stats.err_phy_stats[c]++

	if (rxs->rs_status & ATH9K_RXERR_CRC)
		priv->debug.rx_stats.err_crc++;
	if (rxs->rs_status & ATH9K_RXERR_DECRYPT)
		priv->debug.rx_stats.err_decrypt_crc++;
	if (rxs->rs_status & ATH9K_RXERR_MIC)
		priv->debug.rx_stats.err_mic++;
	if (rxs->rs_status & ATH9K_RX_DELIM_CRC_PRE)
		priv->debug.rx_stats.err_pre_delim++;
	if (rxs->rs_status & ATH9K_RX_DELIM_CRC_POST)
		priv->debug.rx_stats.err_post_delim++;
	if (rxs->rs_status & ATH9K_RX_DECRYPT_BUSY)
		priv->debug.rx_stats.err_decrypt_busy++;

	if (rxs->rs_status & ATH9K_RXERR_PHY) {
		priv->debug.rx_stats.err_phy++;
		if (rxs->rs_phyerr < ATH9K_PHYERR_MAX)
			RX_PHY_ERR_INC(rxs->rs_phyerr);
	}

#undef RX_PHY_ERR_INC
}

static ssize_t read_file_recv(struct file *file, char __user *user_buf,
			      size_t count, loff_t *ppos)
{
#define PHY_ERR(s, p)							\
	len += snprintf(buf + len, size - len, "%20s : %10u\n", s,	\
			priv->debug.rx_stats.err_phy_stats[p]);

	struct ath9k_htc_priv *priv = file->private_data;
	char *buf;
	unsigned int len = 0, size = 1500;
	ssize_t retval = 0;

	buf = kzalloc(size, GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;

	len += snprintf(buf + len, size - len,
			"%20s : %10u\n", "SKBs allocated",
			priv->debug.rx_stats.skb_allocated);
	len += snprintf(buf + len, size - len,
			"%20s : %10u\n", "SKBs completed",
			priv->debug.rx_stats.skb_completed);
	len += snprintf(buf + len, size - len,
			"%20s : %10u\n", "SKBs Dropped",
			priv->debug.rx_stats.skb_dropped);

	len += snprintf(buf + len, size - len,
			"%20s : %10u\n", "CRC ERR",
			priv->debug.rx_stats.err_crc);
	len += snprintf(buf + len, size - len,
			"%20s : %10u\n", "DECRYPT CRC ERR",
			priv->debug.rx_stats.err_decrypt_crc);
	len += snprintf(buf + len, size - len,
			"%20s : %10u\n", "MIC ERR",
			priv->debug.rx_stats.err_mic);
	len += snprintf(buf + len, size - len,
			"%20s : %10u\n", "PRE-DELIM CRC ERR",
			priv->debug.rx_stats.err_pre_delim);
	len += snprintf(buf + len, size - len,
			"%20s : %10u\n", "POST-DELIM CRC ERR",
			priv->debug.rx_stats.err_post_delim);
	len += snprintf(buf + len, size - len,
			"%20s : %10u\n", "DECRYPT BUSY ERR",
			priv->debug.rx_stats.err_decrypt_busy);
	len += snprintf(buf + len, size - len,
			"%20s : %10u\n", "TOTAL PHY ERR",
			priv->debug.rx_stats.err_phy);


	PHY_ERR("UNDERRUN", ATH9K_PHYERR_UNDERRUN);
	PHY_ERR("TIMING", ATH9K_PHYERR_TIMING);
	PHY_ERR("PARITY", ATH9K_PHYERR_PARITY);
	PHY_ERR("RATE", ATH9K_PHYERR_RATE);
	PHY_ERR("LENGTH", ATH9K_PHYERR_LENGTH);
	PHY_ERR("RADAR", ATH9K_PHYERR_RADAR);
	PHY_ERR("SERVICE", ATH9K_PHYERR_SERVICE);
	PHY_ERR("TOR", ATH9K_PHYERR_TOR);
	PHY_ERR("OFDM-TIMING", ATH9K_PHYERR_OFDM_TIMING);
	PHY_ERR("OFDM-SIGNAL-PARITY", ATH9K_PHYERR_OFDM_SIGNAL_PARITY);
	PHY_ERR("OFDM-RATE", ATH9K_PHYERR_OFDM_RATE_ILLEGAL);
	PHY_ERR("OFDM-LENGTH", ATH9K_PHYERR_OFDM_LENGTH_ILLEGAL);
	PHY_ERR("OFDM-POWER-DROP", ATH9K_PHYERR_OFDM_POWER_DROP);
	PHY_ERR("OFDM-SERVICE", ATH9K_PHYERR_OFDM_SERVICE);
	PHY_ERR("OFDM-RESTART", ATH9K_PHYERR_OFDM_RESTART);
	PHY_ERR("FALSE-RADAR-EXT", ATH9K_PHYERR_FALSE_RADAR_EXT);
	PHY_ERR("CCK-TIMING", ATH9K_PHYERR_CCK_TIMING);
	PHY_ERR("CCK-HEADER-CRC", ATH9K_PHYERR_CCK_HEADER_CRC);
	PHY_ERR("CCK-RATE", ATH9K_PHYERR_CCK_RATE_ILLEGAL);
	PHY_ERR("CCK-SERVICE", ATH9K_PHYERR_CCK_SERVICE);
	PHY_ERR("CCK-RESTART", ATH9K_PHYERR_CCK_RESTART);
	PHY_ERR("CCK-LENGTH", ATH9K_PHYERR_CCK_LENGTH_ILLEGAL);
	PHY_ERR("CCK-POWER-DROP", ATH9K_PHYERR_CCK_POWER_DROP);
	PHY_ERR("HT-CRC", ATH9K_PHYERR_HT_CRC_ERROR);
	PHY_ERR("HT-LENGTH", ATH9K_PHYERR_HT_LENGTH_ILLEGAL);
	PHY_ERR("HT-RATE", ATH9K_PHYERR_HT_RATE_ILLEGAL);

	if (len > size)
		len = size;

	retval = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	kfree(buf);

	return retval;

#undef PHY_ERR
}

static const struct file_operations fops_recv = {
	.read = read_file_recv,
	.open = ath9k_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t read_file_slot(struct file *file, char __user *user_buf,
			      size_t count, loff_t *ppos)
{
	struct ath9k_htc_priv *priv = file->private_data;
	char buf[512];
	unsigned int len = 0;

	spin_lock_bh(&priv->tx.tx_lock);

	len += snprintf(buf + len, sizeof(buf) - len, "TX slot bitmap : ");

	len += bitmap_scnprintf(buf + len, sizeof(buf) - len,
			       priv->tx.tx_slot, MAX_TX_BUF_NUM);

	len += snprintf(buf + len, sizeof(buf) - len, "\n");

	len += snprintf(buf + len, sizeof(buf) - len,
			"Used slots     : %d\n",
			bitmap_weight(priv->tx.tx_slot, MAX_TX_BUF_NUM));

	spin_unlock_bh(&priv->tx.tx_lock);

	if (len > sizeof(buf))
		len = sizeof(buf);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_slot = {
	.read = read_file_slot,
	.open = ath9k_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t read_file_queue(struct file *file, char __user *user_buf,
			       size_t count, loff_t *ppos)
{
	struct ath9k_htc_priv *priv = file->private_data;
	char buf[512];
	unsigned int len = 0;

	len += snprintf(buf + len, sizeof(buf) - len, "%20s : %10u\n",
			"Mgmt endpoint", skb_queue_len(&priv->tx.mgmt_ep_queue));

	len += snprintf(buf + len, sizeof(buf) - len, "%20s : %10u\n",
			"Cab endpoint", skb_queue_len(&priv->tx.cab_ep_queue));

	len += snprintf(buf + len, sizeof(buf) - len, "%20s : %10u\n",
			"Data BE endpoint", skb_queue_len(&priv->tx.data_be_queue));

	len += snprintf(buf + len, sizeof(buf) - len, "%20s : %10u\n",
			"Data BK endpoint", skb_queue_len(&priv->tx.data_bk_queue));

	len += snprintf(buf + len, sizeof(buf) - len, "%20s : %10u\n",
			"Data VI endpoint", skb_queue_len(&priv->tx.data_vi_queue));

	len += snprintf(buf + len, sizeof(buf) - len, "%20s : %10u\n",
			"Data VO endpoint", skb_queue_len(&priv->tx.data_vo_queue));

	len += snprintf(buf + len, sizeof(buf) - len, "%20s : %10u\n",
			"Failed queue", skb_queue_len(&priv->tx.tx_failed));

	spin_lock_bh(&priv->tx.tx_lock);
	len += snprintf(buf + len, sizeof(buf) - len, "%20s : %10u\n",
			"Queued count", priv->tx.queued_cnt);
	spin_unlock_bh(&priv->tx.tx_lock);

	if (len > sizeof(buf))
		len = sizeof(buf);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);

}

static const struct file_operations fops_queue = {
	.read = read_file_queue,
	.open = ath9k_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t read_file_debug(struct file *file, char __user *user_buf,
			       size_t count, loff_t *ppos)
{
	struct ath9k_htc_priv *priv = file->private_data;
	struct ath_common *common = ath9k_hw_common(priv->ah);
	char buf[32];
	unsigned int len;

	len = sprintf(buf, "0x%08x\n", common->debug_mask);
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t write_file_debug(struct file *file, const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath9k_htc_priv *priv = file->private_data;
	struct ath_common *common = ath9k_hw_common(priv->ah);
	unsigned long mask;
	char buf[32];
	ssize_t len;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (strict_strtoul(buf, 0, &mask))
		return -EINVAL;

	common->debug_mask = mask;
	return count;
}

static const struct file_operations fops_debug = {
	.read = read_file_debug,
	.write = write_file_debug,
	.open = ath9k_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t read_file_base_eeprom(struct file *file, char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	struct ath9k_htc_priv *priv = file->private_data;
	struct ath_common *common = ath9k_hw_common(priv->ah);
	struct base_eep_header *pBase = NULL;
	unsigned int len = 0, size = 1500;
	ssize_t retval = 0;
	char *buf;

	/*
	 * This can be done since all the 3 EEPROM families have the
	 * same base header upto a certain point, and we are interested in
	 * the data only upto that point.
	 */

	if (AR_SREV_9271(priv->ah))
		pBase = (struct base_eep_header *)
			&priv->ah->eeprom.map4k.baseEepHeader;
	else if (priv->ah->hw_version.usbdev == AR9280_USB)
		pBase = (struct base_eep_header *)
			&priv->ah->eeprom.def.baseEepHeader;
	else if (priv->ah->hw_version.usbdev == AR9287_USB)
		pBase = (struct base_eep_header *)
			&priv->ah->eeprom.map9287.baseEepHeader;

	if (pBase == NULL) {
		ath_err(common, "Unknown EEPROM type\n");
		return 0;
	}

	buf = kzalloc(size, GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;

	len += snprintf(buf + len, size - len,
			"%20s : %10d\n", "Major Version",
			pBase->version >> 12);
	len += snprintf(buf + len, size - len,
			"%20s : %10d\n", "Minor Version",
			pBase->version & 0xFFF);
	len += snprintf(buf + len, size - len,
			"%20s : %10d\n", "Checksum",
			pBase->checksum);
	len += snprintf(buf + len, size - len,
			"%20s : %10d\n", "Length",
			pBase->length);
	len += snprintf(buf + len, size - len,
			"%20s : %10d\n", "RegDomain1",
			pBase->regDmn[0]);
	len += snprintf(buf + len, size - len,
			"%20s : %10d\n", "RegDomain2",
			pBase->regDmn[1]);
	len += snprintf(buf + len, size - len,
			"%20s : %10d\n",
			"TX Mask", pBase->txMask);
	len += snprintf(buf + len, size - len,
			"%20s : %10d\n",
			"RX Mask", pBase->rxMask);
	len += snprintf(buf + len, size - len,
			"%20s : %10d\n",
			"Allow 5GHz",
			!!(pBase->opCapFlags & AR5416_OPFLAGS_11A));
	len += snprintf(buf + len, size - len,
			"%20s : %10d\n",
			"Allow 2GHz",
			!!(pBase->opCapFlags & AR5416_OPFLAGS_11G));
	len += snprintf(buf + len, size - len,
			"%20s : %10d\n",
			"Disable 2GHz HT20",
			!!(pBase->opCapFlags & AR5416_OPFLAGS_N_2G_HT20));
	len += snprintf(buf + len, size - len,
			"%20s : %10d\n",
			"Disable 2GHz HT40",
			!!(pBase->opCapFlags & AR5416_OPFLAGS_N_2G_HT40));
	len += snprintf(buf + len, size - len,
			"%20s : %10d\n",
			"Disable 5Ghz HT20",
			!!(pBase->opCapFlags & AR5416_OPFLAGS_N_5G_HT20));
	len += snprintf(buf + len, size - len,
			"%20s : %10d\n",
			"Disable 5Ghz HT40",
			!!(pBase->opCapFlags & AR5416_OPFLAGS_N_5G_HT40));
	len += snprintf(buf + len, size - len,
			"%20s : %10d\n",
			"Big Endian",
			!!(pBase->eepMisc & 0x01));
	len += snprintf(buf + len, size - len,
			"%20s : %10d\n",
			"Cal Bin Major Ver",
			(pBase->binBuildNumber >> 24) & 0xFF);
	len += snprintf(buf + len, size - len,
			"%20s : %10d\n",
			"Cal Bin Minor Ver",
			(pBase->binBuildNumber >> 16) & 0xFF);
	len += snprintf(buf + len, size - len,
			"%20s : %10d\n",
			"Cal Bin Build",
			(pBase->binBuildNumber >> 8) & 0xFF);

	/*
	 * UB91 specific data.
	 */
	if (AR_SREV_9271(priv->ah)) {
		struct base_eep_header_4k *pBase4k =
			&priv->ah->eeprom.map4k.baseEepHeader;

		len += snprintf(buf + len, size - len,
				"%20s : %10d\n",
				"TX Gain type",
				pBase4k->txGainType);
	}

	/*
	 * UB95 specific data.
	 */
	if (priv->ah->hw_version.usbdev == AR9287_USB) {
		struct base_eep_ar9287_header *pBase9287 =
			&priv->ah->eeprom.map9287.baseEepHeader;

		len += snprintf(buf + len, size - len,
				"%20s : %10ddB\n",
				"Power Table Offset",
				pBase9287->pwrTableOffset);

		len += snprintf(buf + len, size - len,
				"%20s : %10d\n",
				"OpenLoop Power Ctrl",
				pBase9287->openLoopPwrCntl);
	}

	len += snprintf(buf + len, size - len,
			"%20s : %02X:%02X:%02X:%02X:%02X:%02X\n",
			"MacAddress",
			pBase->macAddr[0], pBase->macAddr[1], pBase->macAddr[2],
			pBase->macAddr[3], pBase->macAddr[4], pBase->macAddr[5]);
	if (len > size)
		len = size;

	retval = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	kfree(buf);

	return retval;
}

static const struct file_operations fops_base_eeprom = {
	.read = read_file_base_eeprom,
	.open = ath9k_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

int ath9k_htc_init_debug(struct ath_hw *ah)
{
	struct ath_common *common = ath9k_hw_common(ah);
	struct ath9k_htc_priv *priv = (struct ath9k_htc_priv *) common->priv;

	priv->debug.debugfs_phy = debugfs_create_dir(KBUILD_MODNAME,
					     priv->hw->wiphy->debugfsdir);
	if (!priv->debug.debugfs_phy)
		return -ENOMEM;

	debugfs_create_file("tgt_int_stats", S_IRUSR, priv->debug.debugfs_phy,
			    priv, &fops_tgt_int_stats);
	debugfs_create_file("tgt_tx_stats", S_IRUSR, priv->debug.debugfs_phy,
			    priv, &fops_tgt_tx_stats);
	debugfs_create_file("tgt_rx_stats", S_IRUSR, priv->debug.debugfs_phy,
			    priv, &fops_tgt_rx_stats);
	debugfs_create_file("xmit", S_IRUSR, priv->debug.debugfs_phy,
			    priv, &fops_xmit);
	debugfs_create_file("recv", S_IRUSR, priv->debug.debugfs_phy,
			    priv, &fops_recv);
	debugfs_create_file("slot", S_IRUSR, priv->debug.debugfs_phy,
			    priv, &fops_slot);
	debugfs_create_file("queue", S_IRUSR, priv->debug.debugfs_phy,
			    priv, &fops_queue);
	debugfs_create_file("debug", S_IRUSR | S_IWUSR, priv->debug.debugfs_phy,
			    priv, &fops_debug);
	debugfs_create_file("base_eeprom", S_IRUSR, priv->debug.debugfs_phy,
			    priv, &fops_base_eeprom);

	return 0;
}
