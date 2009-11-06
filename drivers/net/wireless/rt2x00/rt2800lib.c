/*
	Copyright (C) 2009 Bartlomiej Zolnierkiewicz

	Based on the original rt2800pci.c and rt2800usb.c:

	  Copyright (C) 2004 - 2009 rt2x00 SourceForge Project
	  <http://rt2x00.serialmonkey.com>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the
	Free Software Foundation, Inc.,
	59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
	Module: rt2800lib
	Abstract: rt2800 generic device routines.
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include "rt2x00.h"
#include "rt2800lib.h"
#include "rt2800.h"

MODULE_AUTHOR("Bartlomiej Zolnierkiewicz");
MODULE_DESCRIPTION("rt2800 library");
MODULE_LICENSE("GPL");

/*
 * Register access.
 * All access to the CSR registers will go through the methods
 * rt2800_register_read and rt2800_register_write.
 * BBP and RF register require indirect register access,
 * and use the CSR registers BBPCSR and RFCSR to achieve this.
 * These indirect registers work with busy bits,
 * and we will try maximal REGISTER_BUSY_COUNT times to access
 * the register while taking a REGISTER_BUSY_DELAY us delay
 * between each attampt. When the busy bit is still set at that time,
 * the access attempt is considered to have failed,
 * and we will print an error.
 * The _lock versions must be used if you already hold the csr_mutex
 */
#define WAIT_FOR_BBP(__dev, __reg) \
	rt2800_regbusy_read((__dev), BBP_CSR_CFG, BBP_CSR_CFG_BUSY, (__reg))
#define WAIT_FOR_RFCSR(__dev, __reg) \
	rt2800_regbusy_read((__dev), RF_CSR_CFG, RF_CSR_CFG_BUSY, (__reg))
#define WAIT_FOR_RF(__dev, __reg) \
	rt2800_regbusy_read((__dev), RF_CSR_CFG0, RF_CSR_CFG0_BUSY, (__reg))
#define WAIT_FOR_MCU(__dev, __reg) \
	rt2800_regbusy_read((__dev), H2M_MAILBOX_CSR, \
			    H2M_MAILBOX_CSR_OWNER, (__reg))

void rt2800_bbp_write(struct rt2x00_dev *rt2x00dev,
		      const unsigned int word, const u8 value)
{
	u32 reg;

	mutex_lock(&rt2x00dev->csr_mutex);

	/*
	 * Wait until the BBP becomes available, afterwards we
	 * can safely write the new data into the register.
	 */
	if (WAIT_FOR_BBP(rt2x00dev, &reg)) {
		reg = 0;
		rt2x00_set_field32(&reg, BBP_CSR_CFG_VALUE, value);
		rt2x00_set_field32(&reg, BBP_CSR_CFG_REGNUM, word);
		rt2x00_set_field32(&reg, BBP_CSR_CFG_BUSY, 1);
		rt2x00_set_field32(&reg, BBP_CSR_CFG_READ_CONTROL, 0);
		if (rt2x00_intf_is_pci(rt2x00dev))
			rt2x00_set_field32(&reg, BBP_CSR_CFG_BBP_RW_MODE, 1);

		rt2800_register_write_lock(rt2x00dev, BBP_CSR_CFG, reg);
	}

	mutex_unlock(&rt2x00dev->csr_mutex);
}
EXPORT_SYMBOL_GPL(rt2800_bbp_write);

void rt2800_bbp_read(struct rt2x00_dev *rt2x00dev,
		     const unsigned int word, u8 *value)
{
	u32 reg;

	mutex_lock(&rt2x00dev->csr_mutex);

	/*
	 * Wait until the BBP becomes available, afterwards we
	 * can safely write the read request into the register.
	 * After the data has been written, we wait until hardware
	 * returns the correct value, if at any time the register
	 * doesn't become available in time, reg will be 0xffffffff
	 * which means we return 0xff to the caller.
	 */
	if (WAIT_FOR_BBP(rt2x00dev, &reg)) {
		reg = 0;
		rt2x00_set_field32(&reg, BBP_CSR_CFG_REGNUM, word);
		rt2x00_set_field32(&reg, BBP_CSR_CFG_BUSY, 1);
		rt2x00_set_field32(&reg, BBP_CSR_CFG_READ_CONTROL, 1);
		if (rt2x00_intf_is_pci(rt2x00dev))
			rt2x00_set_field32(&reg, BBP_CSR_CFG_BBP_RW_MODE, 1);

		rt2800_register_write_lock(rt2x00dev, BBP_CSR_CFG, reg);

		WAIT_FOR_BBP(rt2x00dev, &reg);
	}

	*value = rt2x00_get_field32(reg, BBP_CSR_CFG_VALUE);

	mutex_unlock(&rt2x00dev->csr_mutex);
}
EXPORT_SYMBOL_GPL(rt2800_bbp_read);

void rt2800_rfcsr_write(struct rt2x00_dev *rt2x00dev,
			const unsigned int word, const u8 value)
{
	u32 reg;

	mutex_lock(&rt2x00dev->csr_mutex);

	/*
	 * Wait until the RFCSR becomes available, afterwards we
	 * can safely write the new data into the register.
	 */
	if (WAIT_FOR_RFCSR(rt2x00dev, &reg)) {
		reg = 0;
		rt2x00_set_field32(&reg, RF_CSR_CFG_DATA, value);
		rt2x00_set_field32(&reg, RF_CSR_CFG_REGNUM, word);
		rt2x00_set_field32(&reg, RF_CSR_CFG_WRITE, 1);
		rt2x00_set_field32(&reg, RF_CSR_CFG_BUSY, 1);

		rt2800_register_write_lock(rt2x00dev, RF_CSR_CFG, reg);
	}

	mutex_unlock(&rt2x00dev->csr_mutex);
}
EXPORT_SYMBOL_GPL(rt2800_rfcsr_write);

void rt2800_rfcsr_read(struct rt2x00_dev *rt2x00dev,
		       const unsigned int word, u8 *value)
{
	u32 reg;

	mutex_lock(&rt2x00dev->csr_mutex);

	/*
	 * Wait until the RFCSR becomes available, afterwards we
	 * can safely write the read request into the register.
	 * After the data has been written, we wait until hardware
	 * returns the correct value, if at any time the register
	 * doesn't become available in time, reg will be 0xffffffff
	 * which means we return 0xff to the caller.
	 */
	if (WAIT_FOR_RFCSR(rt2x00dev, &reg)) {
		reg = 0;
		rt2x00_set_field32(&reg, RF_CSR_CFG_REGNUM, word);
		rt2x00_set_field32(&reg, RF_CSR_CFG_WRITE, 0);
		rt2x00_set_field32(&reg, RF_CSR_CFG_BUSY, 1);

		rt2800_register_write_lock(rt2x00dev, RF_CSR_CFG, reg);

		WAIT_FOR_RFCSR(rt2x00dev, &reg);
	}

	*value = rt2x00_get_field32(reg, RF_CSR_CFG_DATA);

	mutex_unlock(&rt2x00dev->csr_mutex);
}
EXPORT_SYMBOL_GPL(rt2800_rfcsr_read);

void rt2800_rf_write(struct rt2x00_dev *rt2x00dev,
		     const unsigned int word, const u32 value)
{
	u32 reg;

	mutex_lock(&rt2x00dev->csr_mutex);

	/*
	 * Wait until the RF becomes available, afterwards we
	 * can safely write the new data into the register.
	 */
	if (WAIT_FOR_RF(rt2x00dev, &reg)) {
		reg = 0;
		rt2x00_set_field32(&reg, RF_CSR_CFG0_REG_VALUE_BW, value);
		rt2x00_set_field32(&reg, RF_CSR_CFG0_STANDBYMODE, 0);
		rt2x00_set_field32(&reg, RF_CSR_CFG0_SEL, 0);
		rt2x00_set_field32(&reg, RF_CSR_CFG0_BUSY, 1);

		rt2800_register_write_lock(rt2x00dev, RF_CSR_CFG0, reg);
		rt2x00_rf_write(rt2x00dev, word, value);
	}

	mutex_unlock(&rt2x00dev->csr_mutex);
}
EXPORT_SYMBOL_GPL(rt2800_rf_write);

void rt2800_mcu_request(struct rt2x00_dev *rt2x00dev,
			const u8 command, const u8 token,
			const u8 arg0, const u8 arg1)
{
	u32 reg;

	if (rt2x00_intf_is_pci(rt2x00dev)) {
		/*
		* RT2880 and RT3052 don't support MCU requests.
		*/
		if (rt2x00_rt(&rt2x00dev->chip, RT2880) ||
		    rt2x00_rt(&rt2x00dev->chip, RT3052))
			return;
	}

	mutex_lock(&rt2x00dev->csr_mutex);

	/*
	 * Wait until the MCU becomes available, afterwards we
	 * can safely write the new data into the register.
	 */
	if (WAIT_FOR_MCU(rt2x00dev, &reg)) {
		rt2x00_set_field32(&reg, H2M_MAILBOX_CSR_OWNER, 1);
		rt2x00_set_field32(&reg, H2M_MAILBOX_CSR_CMD_TOKEN, token);
		rt2x00_set_field32(&reg, H2M_MAILBOX_CSR_ARG0, arg0);
		rt2x00_set_field32(&reg, H2M_MAILBOX_CSR_ARG1, arg1);
		rt2800_register_write_lock(rt2x00dev, H2M_MAILBOX_CSR, reg);

		reg = 0;
		rt2x00_set_field32(&reg, HOST_CMD_CSR_HOST_COMMAND, command);
		rt2800_register_write_lock(rt2x00dev, HOST_CMD_CSR, reg);
	}

	mutex_unlock(&rt2x00dev->csr_mutex);
}
EXPORT_SYMBOL_GPL(rt2800_mcu_request);

#ifdef CONFIG_RT2X00_LIB_DEBUGFS
const struct rt2x00debug rt2800_rt2x00debug = {
	.owner	= THIS_MODULE,
	.csr	= {
		.read		= rt2800_register_read,
		.write		= rt2800_register_write,
		.flags		= RT2X00DEBUGFS_OFFSET,
		.word_base	= CSR_REG_BASE,
		.word_size	= sizeof(u32),
		.word_count	= CSR_REG_SIZE / sizeof(u32),
	},
	.eeprom	= {
		.read		= rt2x00_eeprom_read,
		.write		= rt2x00_eeprom_write,
		.word_base	= EEPROM_BASE,
		.word_size	= sizeof(u16),
		.word_count	= EEPROM_SIZE / sizeof(u16),
	},
	.bbp	= {
		.read		= rt2800_bbp_read,
		.write		= rt2800_bbp_write,
		.word_base	= BBP_BASE,
		.word_size	= sizeof(u8),
		.word_count	= BBP_SIZE / sizeof(u8),
	},
	.rf	= {
		.read		= rt2x00_rf_read,
		.write		= rt2800_rf_write,
		.word_base	= RF_BASE,
		.word_size	= sizeof(u32),
		.word_count	= RF_SIZE / sizeof(u32),
	},
};
EXPORT_SYMBOL_GPL(rt2800_rt2x00debug);
#endif /* CONFIG_RT2X00_LIB_DEBUGFS */

int rt2800_rfkill_poll(struct rt2x00_dev *rt2x00dev)
{
	u32 reg;

	rt2800_register_read(rt2x00dev, GPIO_CTRL_CFG, &reg);
	return rt2x00_get_field32(reg, GPIO_CTRL_CFG_BIT2);
}
EXPORT_SYMBOL_GPL(rt2800_rfkill_poll);

#ifdef CONFIG_RT2X00_LIB_LEDS
static void rt2800_brightness_set(struct led_classdev *led_cdev,
				  enum led_brightness brightness)
{
	struct rt2x00_led *led =
	    container_of(led_cdev, struct rt2x00_led, led_dev);
	unsigned int enabled = brightness != LED_OFF;
	unsigned int bg_mode =
	    (enabled && led->rt2x00dev->curr_band == IEEE80211_BAND_2GHZ);
	unsigned int polarity =
		rt2x00_get_field16(led->rt2x00dev->led_mcu_reg,
				   EEPROM_FREQ_LED_POLARITY);
	unsigned int ledmode =
		rt2x00_get_field16(led->rt2x00dev->led_mcu_reg,
				   EEPROM_FREQ_LED_MODE);

	if (led->type == LED_TYPE_RADIO) {
		rt2800_mcu_request(led->rt2x00dev, MCU_LED, 0xff, ledmode,
				      enabled ? 0x20 : 0);
	} else if (led->type == LED_TYPE_ASSOC) {
		rt2800_mcu_request(led->rt2x00dev, MCU_LED, 0xff, ledmode,
				      enabled ? (bg_mode ? 0x60 : 0xa0) : 0x20);
	} else if (led->type == LED_TYPE_QUALITY) {
		/*
		 * The brightness is divided into 6 levels (0 - 5),
		 * The specs tell us the following levels:
		 *	0, 1 ,3, 7, 15, 31
		 * to determine the level in a simple way we can simply
		 * work with bitshifting:
		 *	(1 << level) - 1
		 */
		rt2800_mcu_request(led->rt2x00dev, MCU_LED_STRENGTH, 0xff,
				      (1 << brightness / (LED_FULL / 6)) - 1,
				      polarity);
	}
}

static int rt2800_blink_set(struct led_classdev *led_cdev,
			    unsigned long *delay_on, unsigned long *delay_off)
{
	struct rt2x00_led *led =
	    container_of(led_cdev, struct rt2x00_led, led_dev);
	u32 reg;

	rt2800_register_read(led->rt2x00dev, LED_CFG, &reg);
	rt2x00_set_field32(&reg, LED_CFG_ON_PERIOD, *delay_on);
	rt2x00_set_field32(&reg, LED_CFG_OFF_PERIOD, *delay_off);
	rt2x00_set_field32(&reg, LED_CFG_SLOW_BLINK_PERIOD, 3);
	rt2x00_set_field32(&reg, LED_CFG_R_LED_MODE, 3);
	rt2x00_set_field32(&reg, LED_CFG_G_LED_MODE, 12);
	rt2x00_set_field32(&reg, LED_CFG_Y_LED_MODE, 3);
	rt2x00_set_field32(&reg, LED_CFG_LED_POLAR, 1);
	rt2800_register_write(led->rt2x00dev, LED_CFG, reg);

	return 0;
}

void rt2800_init_led(struct rt2x00_dev *rt2x00dev,
		     struct rt2x00_led *led, enum led_type type)
{
	led->rt2x00dev = rt2x00dev;
	led->type = type;
	led->led_dev.brightness_set = rt2800_brightness_set;
	led->led_dev.blink_set = rt2800_blink_set;
	led->flags = LED_INITIALIZED;
}
EXPORT_SYMBOL_GPL(rt2800_init_led);
#endif /* CONFIG_RT2X00_LIB_LEDS */

/*
 * Configuration handlers.
 */
static void rt2800_config_wcid_attr(struct rt2x00_dev *rt2x00dev,
				    struct rt2x00lib_crypto *crypto,
				    struct ieee80211_key_conf *key)
{
	struct mac_wcid_entry wcid_entry;
	struct mac_iveiv_entry iveiv_entry;
	u32 offset;
	u32 reg;

	offset = MAC_WCID_ATTR_ENTRY(key->hw_key_idx);

	rt2800_register_read(rt2x00dev, offset, &reg);
	rt2x00_set_field32(&reg, MAC_WCID_ATTRIBUTE_KEYTAB,
			   !!(key->flags & IEEE80211_KEY_FLAG_PAIRWISE));
	rt2x00_set_field32(&reg, MAC_WCID_ATTRIBUTE_CIPHER,
			   (crypto->cmd == SET_KEY) * crypto->cipher);
	rt2x00_set_field32(&reg, MAC_WCID_ATTRIBUTE_BSS_IDX,
			   (crypto->cmd == SET_KEY) * crypto->bssidx);
	rt2x00_set_field32(&reg, MAC_WCID_ATTRIBUTE_RX_WIUDF, crypto->cipher);
	rt2800_register_write(rt2x00dev, offset, reg);

	offset = MAC_IVEIV_ENTRY(key->hw_key_idx);

	memset(&iveiv_entry, 0, sizeof(iveiv_entry));
	if ((crypto->cipher == CIPHER_TKIP) ||
	    (crypto->cipher == CIPHER_TKIP_NO_MIC) ||
	    (crypto->cipher == CIPHER_AES))
		iveiv_entry.iv[3] |= 0x20;
	iveiv_entry.iv[3] |= key->keyidx << 6;
	rt2800_register_multiwrite(rt2x00dev, offset,
				      &iveiv_entry, sizeof(iveiv_entry));

	offset = MAC_WCID_ENTRY(key->hw_key_idx);

	memset(&wcid_entry, 0, sizeof(wcid_entry));
	if (crypto->cmd == SET_KEY)
		memcpy(&wcid_entry, crypto->address, ETH_ALEN);
	rt2800_register_multiwrite(rt2x00dev, offset,
				      &wcid_entry, sizeof(wcid_entry));
}

int rt2800_config_shared_key(struct rt2x00_dev *rt2x00dev,
			     struct rt2x00lib_crypto *crypto,
			     struct ieee80211_key_conf *key)
{
	struct hw_key_entry key_entry;
	struct rt2x00_field32 field;
	u32 offset;
	u32 reg;

	if (crypto->cmd == SET_KEY) {
		key->hw_key_idx = (4 * crypto->bssidx) + key->keyidx;

		memcpy(key_entry.key, crypto->key,
		       sizeof(key_entry.key));
		memcpy(key_entry.tx_mic, crypto->tx_mic,
		       sizeof(key_entry.tx_mic));
		memcpy(key_entry.rx_mic, crypto->rx_mic,
		       sizeof(key_entry.rx_mic));

		offset = SHARED_KEY_ENTRY(key->hw_key_idx);
		rt2800_register_multiwrite(rt2x00dev, offset,
					      &key_entry, sizeof(key_entry));
	}

	/*
	 * The cipher types are stored over multiple registers
	 * starting with SHARED_KEY_MODE_BASE each word will have
	 * 32 bits and contains the cipher types for 2 bssidx each.
	 * Using the correct defines correctly will cause overhead,
	 * so just calculate the correct offset.
	 */
	field.bit_offset = 4 * (key->hw_key_idx % 8);
	field.bit_mask = 0x7 << field.bit_offset;

	offset = SHARED_KEY_MODE_ENTRY(key->hw_key_idx / 8);

	rt2800_register_read(rt2x00dev, offset, &reg);
	rt2x00_set_field32(&reg, field,
			   (crypto->cmd == SET_KEY) * crypto->cipher);
	rt2800_register_write(rt2x00dev, offset, reg);

	/*
	 * Update WCID information
	 */
	rt2800_config_wcid_attr(rt2x00dev, crypto, key);

	return 0;
}
EXPORT_SYMBOL_GPL(rt2800_config_shared_key);

int rt2800_config_pairwise_key(struct rt2x00_dev *rt2x00dev,
			       struct rt2x00lib_crypto *crypto,
			       struct ieee80211_key_conf *key)
{
	struct hw_key_entry key_entry;
	u32 offset;

	if (crypto->cmd == SET_KEY) {
		/*
		 * 1 pairwise key is possible per AID, this means that the AID
		 * equals our hw_key_idx. Make sure the WCID starts _after_ the
		 * last possible shared key entry.
		 */
		if (crypto->aid > (256 - 32))
			return -ENOSPC;

		key->hw_key_idx = 32 + crypto->aid;

		memcpy(key_entry.key, crypto->key,
		       sizeof(key_entry.key));
		memcpy(key_entry.tx_mic, crypto->tx_mic,
		       sizeof(key_entry.tx_mic));
		memcpy(key_entry.rx_mic, crypto->rx_mic,
		       sizeof(key_entry.rx_mic));

		offset = PAIRWISE_KEY_ENTRY(key->hw_key_idx);
		rt2800_register_multiwrite(rt2x00dev, offset,
					      &key_entry, sizeof(key_entry));
	}

	/*
	 * Update WCID information
	 */
	rt2800_config_wcid_attr(rt2x00dev, crypto, key);

	return 0;
}
EXPORT_SYMBOL_GPL(rt2800_config_pairwise_key);

void rt2800_config_filter(struct rt2x00_dev *rt2x00dev,
			  const unsigned int filter_flags)
{
	u32 reg;

	/*
	 * Start configuration steps.
	 * Note that the version error will always be dropped
	 * and broadcast frames will always be accepted since
	 * there is no filter for it at this time.
	 */
	rt2800_register_read(rt2x00dev, RX_FILTER_CFG, &reg);
	rt2x00_set_field32(&reg, RX_FILTER_CFG_DROP_CRC_ERROR,
			   !(filter_flags & FIF_FCSFAIL));
	rt2x00_set_field32(&reg, RX_FILTER_CFG_DROP_PHY_ERROR,
			   !(filter_flags & FIF_PLCPFAIL));
	rt2x00_set_field32(&reg, RX_FILTER_CFG_DROP_NOT_TO_ME,
			   !(filter_flags & FIF_PROMISC_IN_BSS));
	rt2x00_set_field32(&reg, RX_FILTER_CFG_DROP_NOT_MY_BSSD, 0);
	rt2x00_set_field32(&reg, RX_FILTER_CFG_DROP_VER_ERROR, 1);
	rt2x00_set_field32(&reg, RX_FILTER_CFG_DROP_MULTICAST,
			   !(filter_flags & FIF_ALLMULTI));
	rt2x00_set_field32(&reg, RX_FILTER_CFG_DROP_BROADCAST, 0);
	rt2x00_set_field32(&reg, RX_FILTER_CFG_DROP_DUPLICATE, 1);
	rt2x00_set_field32(&reg, RX_FILTER_CFG_DROP_CF_END_ACK,
			   !(filter_flags & FIF_CONTROL));
	rt2x00_set_field32(&reg, RX_FILTER_CFG_DROP_CF_END,
			   !(filter_flags & FIF_CONTROL));
	rt2x00_set_field32(&reg, RX_FILTER_CFG_DROP_ACK,
			   !(filter_flags & FIF_CONTROL));
	rt2x00_set_field32(&reg, RX_FILTER_CFG_DROP_CTS,
			   !(filter_flags & FIF_CONTROL));
	rt2x00_set_field32(&reg, RX_FILTER_CFG_DROP_RTS,
			   !(filter_flags & FIF_CONTROL));
	rt2x00_set_field32(&reg, RX_FILTER_CFG_DROP_PSPOLL,
			   !(filter_flags & FIF_PSPOLL));
	rt2x00_set_field32(&reg, RX_FILTER_CFG_DROP_BA, 1);
	rt2x00_set_field32(&reg, RX_FILTER_CFG_DROP_BAR, 0);
	rt2x00_set_field32(&reg, RX_FILTER_CFG_DROP_CNTL,
			   !(filter_flags & FIF_CONTROL));
	rt2800_register_write(rt2x00dev, RX_FILTER_CFG, reg);
}
EXPORT_SYMBOL_GPL(rt2800_config_filter);

void rt2800_config_intf(struct rt2x00_dev *rt2x00dev, struct rt2x00_intf *intf,
			struct rt2x00intf_conf *conf, const unsigned int flags)
{
	unsigned int beacon_base;
	u32 reg;

	if (flags & CONFIG_UPDATE_TYPE) {
		/*
		 * Clear current synchronisation setup.
		 * For the Beacon base registers we only need to clear
		 * the first byte since that byte contains the VALID and OWNER
		 * bits which (when set to 0) will invalidate the entire beacon.
		 */
		beacon_base = HW_BEACON_OFFSET(intf->beacon->entry_idx);
		rt2800_register_write(rt2x00dev, beacon_base, 0);

		/*
		 * Enable synchronisation.
		 */
		rt2800_register_read(rt2x00dev, BCN_TIME_CFG, &reg);
		rt2x00_set_field32(&reg, BCN_TIME_CFG_TSF_TICKING, 1);
		rt2x00_set_field32(&reg, BCN_TIME_CFG_TSF_SYNC, conf->sync);
		rt2x00_set_field32(&reg, BCN_TIME_CFG_TBTT_ENABLE, 1);
		rt2800_register_write(rt2x00dev, BCN_TIME_CFG, reg);
	}

	if (flags & CONFIG_UPDATE_MAC) {
		reg = le32_to_cpu(conf->mac[1]);
		rt2x00_set_field32(&reg, MAC_ADDR_DW1_UNICAST_TO_ME_MASK, 0xff);
		conf->mac[1] = cpu_to_le32(reg);

		rt2800_register_multiwrite(rt2x00dev, MAC_ADDR_DW0,
					      conf->mac, sizeof(conf->mac));
	}

	if (flags & CONFIG_UPDATE_BSSID) {
		reg = le32_to_cpu(conf->bssid[1]);
		rt2x00_set_field32(&reg, MAC_BSSID_DW1_BSS_ID_MASK, 0);
		rt2x00_set_field32(&reg, MAC_BSSID_DW1_BSS_BCN_NUM, 0);
		conf->bssid[1] = cpu_to_le32(reg);

		rt2800_register_multiwrite(rt2x00dev, MAC_BSSID_DW0,
					      conf->bssid, sizeof(conf->bssid));
	}
}
EXPORT_SYMBOL_GPL(rt2800_config_intf);

void rt2800_config_erp(struct rt2x00_dev *rt2x00dev, struct rt2x00lib_erp *erp)
{
	u32 reg;

	rt2800_register_read(rt2x00dev, TX_TIMEOUT_CFG, &reg);
	rt2x00_set_field32(&reg, TX_TIMEOUT_CFG_RX_ACK_TIMEOUT, 0x20);
	rt2800_register_write(rt2x00dev, TX_TIMEOUT_CFG, reg);

	rt2800_register_read(rt2x00dev, AUTO_RSP_CFG, &reg);
	rt2x00_set_field32(&reg, AUTO_RSP_CFG_BAC_ACK_POLICY,
			   !!erp->short_preamble);
	rt2x00_set_field32(&reg, AUTO_RSP_CFG_AR_PREAMBLE,
			   !!erp->short_preamble);
	rt2800_register_write(rt2x00dev, AUTO_RSP_CFG, reg);

	rt2800_register_read(rt2x00dev, OFDM_PROT_CFG, &reg);
	rt2x00_set_field32(&reg, OFDM_PROT_CFG_PROTECT_CTRL,
			   erp->cts_protection ? 2 : 0);
	rt2800_register_write(rt2x00dev, OFDM_PROT_CFG, reg);

	rt2800_register_write(rt2x00dev, LEGACY_BASIC_RATE,
				 erp->basic_rates);
	rt2800_register_write(rt2x00dev, HT_BASIC_RATE, 0x00008003);

	rt2800_register_read(rt2x00dev, BKOFF_SLOT_CFG, &reg);
	rt2x00_set_field32(&reg, BKOFF_SLOT_CFG_SLOT_TIME, erp->slot_time);
	rt2x00_set_field32(&reg, BKOFF_SLOT_CFG_CC_DELAY_TIME, 2);
	rt2800_register_write(rt2x00dev, BKOFF_SLOT_CFG, reg);

	rt2800_register_read(rt2x00dev, XIFS_TIME_CFG, &reg);
	rt2x00_set_field32(&reg, XIFS_TIME_CFG_CCKM_SIFS_TIME, erp->sifs);
	rt2x00_set_field32(&reg, XIFS_TIME_CFG_OFDM_SIFS_TIME, erp->sifs);
	rt2x00_set_field32(&reg, XIFS_TIME_CFG_OFDM_XIFS_TIME, 4);
	rt2x00_set_field32(&reg, XIFS_TIME_CFG_EIFS, erp->eifs);
	rt2x00_set_field32(&reg, XIFS_TIME_CFG_BB_RXEND_ENABLE, 1);
	rt2800_register_write(rt2x00dev, XIFS_TIME_CFG, reg);

	rt2800_register_read(rt2x00dev, BCN_TIME_CFG, &reg);
	rt2x00_set_field32(&reg, BCN_TIME_CFG_BEACON_INTERVAL,
			   erp->beacon_int * 16);
	rt2800_register_write(rt2x00dev, BCN_TIME_CFG, reg);
}
EXPORT_SYMBOL_GPL(rt2800_config_erp);

void rt2800_config_ant(struct rt2x00_dev *rt2x00dev, struct antenna_setup *ant)
{
	u8 r1;
	u8 r3;

	rt2800_bbp_read(rt2x00dev, 1, &r1);
	rt2800_bbp_read(rt2x00dev, 3, &r3);

	/*
	 * Configure the TX antenna.
	 */
	switch ((int)ant->tx) {
	case 1:
		rt2x00_set_field8(&r1, BBP1_TX_ANTENNA, 0);
		if (rt2x00_intf_is_pci(rt2x00dev))
			rt2x00_set_field8(&r3, BBP3_RX_ANTENNA, 0);
		break;
	case 2:
		rt2x00_set_field8(&r1, BBP1_TX_ANTENNA, 2);
		break;
	case 3:
		/* Do nothing */
		break;
	}

	/*
	 * Configure the RX antenna.
	 */
	switch ((int)ant->rx) {
	case 1:
		rt2x00_set_field8(&r3, BBP3_RX_ANTENNA, 0);
		break;
	case 2:
		rt2x00_set_field8(&r3, BBP3_RX_ANTENNA, 1);
		break;
	case 3:
		rt2x00_set_field8(&r3, BBP3_RX_ANTENNA, 2);
		break;
	}

	rt2800_bbp_write(rt2x00dev, 3, r3);
	rt2800_bbp_write(rt2x00dev, 1, r1);
}
EXPORT_SYMBOL_GPL(rt2800_config_ant);

static void rt2800_config_lna_gain(struct rt2x00_dev *rt2x00dev,
				   struct rt2x00lib_conf *libconf)
{
	u16 eeprom;
	short lna_gain;

	if (libconf->rf.channel <= 14) {
		rt2x00_eeprom_read(rt2x00dev, EEPROM_LNA, &eeprom);
		lna_gain = rt2x00_get_field16(eeprom, EEPROM_LNA_BG);
	} else if (libconf->rf.channel <= 64) {
		rt2x00_eeprom_read(rt2x00dev, EEPROM_LNA, &eeprom);
		lna_gain = rt2x00_get_field16(eeprom, EEPROM_LNA_A0);
	} else if (libconf->rf.channel <= 128) {
		rt2x00_eeprom_read(rt2x00dev, EEPROM_RSSI_BG2, &eeprom);
		lna_gain = rt2x00_get_field16(eeprom, EEPROM_RSSI_BG2_LNA_A1);
	} else {
		rt2x00_eeprom_read(rt2x00dev, EEPROM_RSSI_A2, &eeprom);
		lna_gain = rt2x00_get_field16(eeprom, EEPROM_RSSI_A2_LNA_A2);
	}

	rt2x00dev->lna_gain = lna_gain;
}

static void rt2800_config_channel_rt2x(struct rt2x00_dev *rt2x00dev,
				       struct ieee80211_conf *conf,
				       struct rf_channel *rf,
				       struct channel_info *info)
{
	rt2x00_set_field32(&rf->rf4, RF4_FREQ_OFFSET, rt2x00dev->freq_offset);

	if (rt2x00dev->default_ant.tx == 1)
		rt2x00_set_field32(&rf->rf2, RF2_ANTENNA_TX1, 1);

	if (rt2x00dev->default_ant.rx == 1) {
		rt2x00_set_field32(&rf->rf2, RF2_ANTENNA_RX1, 1);
		rt2x00_set_field32(&rf->rf2, RF2_ANTENNA_RX2, 1);
	} else if (rt2x00dev->default_ant.rx == 2)
		rt2x00_set_field32(&rf->rf2, RF2_ANTENNA_RX2, 1);

	if (rf->channel > 14) {
		/*
		 * When TX power is below 0, we should increase it by 7 to
		 * make it a positive value (Minumum value is -7).
		 * However this means that values between 0 and 7 have
		 * double meaning, and we should set a 7DBm boost flag.
		 */
		rt2x00_set_field32(&rf->rf3, RF3_TXPOWER_A_7DBM_BOOST,
				   (info->tx_power1 >= 0));

		if (info->tx_power1 < 0)
			info->tx_power1 += 7;

		rt2x00_set_field32(&rf->rf3, RF3_TXPOWER_A,
				   TXPOWER_A_TO_DEV(info->tx_power1));

		rt2x00_set_field32(&rf->rf4, RF4_TXPOWER_A_7DBM_BOOST,
				   (info->tx_power2 >= 0));

		if (info->tx_power2 < 0)
			info->tx_power2 += 7;

		rt2x00_set_field32(&rf->rf4, RF4_TXPOWER_A,
				   TXPOWER_A_TO_DEV(info->tx_power2));
	} else {
		rt2x00_set_field32(&rf->rf3, RF3_TXPOWER_G,
				   TXPOWER_G_TO_DEV(info->tx_power1));
		rt2x00_set_field32(&rf->rf4, RF4_TXPOWER_G,
				   TXPOWER_G_TO_DEV(info->tx_power2));
	}

	rt2x00_set_field32(&rf->rf4, RF4_HT40, conf_is_ht40(conf));

	rt2800_rf_write(rt2x00dev, 1, rf->rf1);
	rt2800_rf_write(rt2x00dev, 2, rf->rf2);
	rt2800_rf_write(rt2x00dev, 3, rf->rf3 & ~0x00000004);
	rt2800_rf_write(rt2x00dev, 4, rf->rf4);

	udelay(200);

	rt2800_rf_write(rt2x00dev, 1, rf->rf1);
	rt2800_rf_write(rt2x00dev, 2, rf->rf2);
	rt2800_rf_write(rt2x00dev, 3, rf->rf3 | 0x00000004);
	rt2800_rf_write(rt2x00dev, 4, rf->rf4);

	udelay(200);

	rt2800_rf_write(rt2x00dev, 1, rf->rf1);
	rt2800_rf_write(rt2x00dev, 2, rf->rf2);
	rt2800_rf_write(rt2x00dev, 3, rf->rf3 & ~0x00000004);
	rt2800_rf_write(rt2x00dev, 4, rf->rf4);
}

static void rt2800_config_channel_rt3x(struct rt2x00_dev *rt2x00dev,
				       struct ieee80211_conf *conf,
				       struct rf_channel *rf,
				       struct channel_info *info)
{
	u8 rfcsr;

	rt2800_rfcsr_write(rt2x00dev, 2, rf->rf1);
	rt2800_rfcsr_write(rt2x00dev, 2, rf->rf3);

	rt2800_rfcsr_read(rt2x00dev, 6, &rfcsr);
	rt2x00_set_field8(&rfcsr, RFCSR6_R, rf->rf2);
	rt2800_rfcsr_write(rt2x00dev, 6, rfcsr);

	rt2800_rfcsr_read(rt2x00dev, 12, &rfcsr);
	rt2x00_set_field8(&rfcsr, RFCSR12_TX_POWER,
			  TXPOWER_G_TO_DEV(info->tx_power1));
	rt2800_rfcsr_write(rt2x00dev, 12, rfcsr);

	rt2800_rfcsr_read(rt2x00dev, 23, &rfcsr);
	rt2x00_set_field8(&rfcsr, RFCSR23_FREQ_OFFSET, rt2x00dev->freq_offset);
	rt2800_rfcsr_write(rt2x00dev, 23, rfcsr);

	rt2800_rfcsr_write(rt2x00dev, 24,
			      rt2x00dev->calibration[conf_is_ht40(conf)]);

	rt2800_rfcsr_read(rt2x00dev, 23, &rfcsr);
	rt2x00_set_field8(&rfcsr, RFCSR7_RF_TUNING, 1);
	rt2800_rfcsr_write(rt2x00dev, 23, rfcsr);
}

static void rt2800_config_channel(struct rt2x00_dev *rt2x00dev,
				  struct ieee80211_conf *conf,
				  struct rf_channel *rf,
				  struct channel_info *info)
{
	u32 reg;
	unsigned int tx_pin;
	u8 bbp;

	if (rt2x00_rev(&rt2x00dev->chip) != RT3070_VERSION)
		rt2800_config_channel_rt2x(rt2x00dev, conf, rf, info);
	else
		rt2800_config_channel_rt3x(rt2x00dev, conf, rf, info);

	/*
	 * Change BBP settings
	 */
	rt2800_bbp_write(rt2x00dev, 62, 0x37 - rt2x00dev->lna_gain);
	rt2800_bbp_write(rt2x00dev, 63, 0x37 - rt2x00dev->lna_gain);
	rt2800_bbp_write(rt2x00dev, 64, 0x37 - rt2x00dev->lna_gain);
	rt2800_bbp_write(rt2x00dev, 86, 0);

	if (rf->channel <= 14) {
		if (test_bit(CONFIG_EXTERNAL_LNA_BG, &rt2x00dev->flags)) {
			rt2800_bbp_write(rt2x00dev, 82, 0x62);
			rt2800_bbp_write(rt2x00dev, 75, 0x46);
		} else {
			rt2800_bbp_write(rt2x00dev, 82, 0x84);
			rt2800_bbp_write(rt2x00dev, 75, 0x50);
		}
	} else {
		rt2800_bbp_write(rt2x00dev, 82, 0xf2);

		if (test_bit(CONFIG_EXTERNAL_LNA_A, &rt2x00dev->flags))
			rt2800_bbp_write(rt2x00dev, 75, 0x46);
		else
			rt2800_bbp_write(rt2x00dev, 75, 0x50);
	}

	rt2800_register_read(rt2x00dev, TX_BAND_CFG, &reg);
	rt2x00_set_field32(&reg, TX_BAND_CFG_HT40_PLUS, conf_is_ht40_plus(conf));
	rt2x00_set_field32(&reg, TX_BAND_CFG_A, rf->channel > 14);
	rt2x00_set_field32(&reg, TX_BAND_CFG_BG, rf->channel <= 14);
	rt2800_register_write(rt2x00dev, TX_BAND_CFG, reg);

	tx_pin = 0;

	/* Turn on unused PA or LNA when not using 1T or 1R */
	if (rt2x00dev->default_ant.tx != 1) {
		rt2x00_set_field32(&tx_pin, TX_PIN_CFG_PA_PE_A1_EN, 1);
		rt2x00_set_field32(&tx_pin, TX_PIN_CFG_PA_PE_G1_EN, 1);
	}

	/* Turn on unused PA or LNA when not using 1T or 1R */
	if (rt2x00dev->default_ant.rx != 1) {
		rt2x00_set_field32(&tx_pin, TX_PIN_CFG_LNA_PE_A1_EN, 1);
		rt2x00_set_field32(&tx_pin, TX_PIN_CFG_LNA_PE_G1_EN, 1);
	}

	rt2x00_set_field32(&tx_pin, TX_PIN_CFG_LNA_PE_A0_EN, 1);
	rt2x00_set_field32(&tx_pin, TX_PIN_CFG_LNA_PE_G0_EN, 1);
	rt2x00_set_field32(&tx_pin, TX_PIN_CFG_RFTR_EN, 1);
	rt2x00_set_field32(&tx_pin, TX_PIN_CFG_TRSW_EN, 1);
	rt2x00_set_field32(&tx_pin, TX_PIN_CFG_PA_PE_G0_EN, rf->channel <= 14);
	rt2x00_set_field32(&tx_pin, TX_PIN_CFG_PA_PE_A0_EN, rf->channel > 14);

	rt2800_register_write(rt2x00dev, TX_PIN_CFG, tx_pin);

	rt2800_bbp_read(rt2x00dev, 4, &bbp);
	rt2x00_set_field8(&bbp, BBP4_BANDWIDTH, 2 * conf_is_ht40(conf));
	rt2800_bbp_write(rt2x00dev, 4, bbp);

	rt2800_bbp_read(rt2x00dev, 3, &bbp);
	rt2x00_set_field8(&bbp, BBP3_HT40_PLUS, conf_is_ht40_plus(conf));
	rt2800_bbp_write(rt2x00dev, 3, bbp);

	if (rt2x00_rev(&rt2x00dev->chip) == RT2860C_VERSION) {
		if (conf_is_ht40(conf)) {
			rt2800_bbp_write(rt2x00dev, 69, 0x1a);
			rt2800_bbp_write(rt2x00dev, 70, 0x0a);
			rt2800_bbp_write(rt2x00dev, 73, 0x16);
		} else {
			rt2800_bbp_write(rt2x00dev, 69, 0x16);
			rt2800_bbp_write(rt2x00dev, 70, 0x08);
			rt2800_bbp_write(rt2x00dev, 73, 0x11);
		}
	}

	msleep(1);
}

static void rt2800_config_txpower(struct rt2x00_dev *rt2x00dev,
				  const int txpower)
{
	u32 reg;
	u32 value = TXPOWER_G_TO_DEV(txpower);
	u8 r1;

	rt2800_bbp_read(rt2x00dev, 1, &r1);
	rt2x00_set_field8(&reg, BBP1_TX_POWER, 0);
	rt2800_bbp_write(rt2x00dev, 1, r1);

	rt2800_register_read(rt2x00dev, TX_PWR_CFG_0, &reg);
	rt2x00_set_field32(&reg, TX_PWR_CFG_0_1MBS, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_0_2MBS, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_0_55MBS, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_0_11MBS, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_0_6MBS, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_0_9MBS, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_0_12MBS, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_0_18MBS, value);
	rt2800_register_write(rt2x00dev, TX_PWR_CFG_0, reg);

	rt2800_register_read(rt2x00dev, TX_PWR_CFG_1, &reg);
	rt2x00_set_field32(&reg, TX_PWR_CFG_1_24MBS, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_1_36MBS, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_1_48MBS, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_1_54MBS, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_1_MCS0, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_1_MCS1, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_1_MCS2, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_1_MCS3, value);
	rt2800_register_write(rt2x00dev, TX_PWR_CFG_1, reg);

	rt2800_register_read(rt2x00dev, TX_PWR_CFG_2, &reg);
	rt2x00_set_field32(&reg, TX_PWR_CFG_2_MCS4, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_2_MCS5, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_2_MCS6, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_2_MCS7, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_2_MCS8, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_2_MCS9, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_2_MCS10, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_2_MCS11, value);
	rt2800_register_write(rt2x00dev, TX_PWR_CFG_2, reg);

	rt2800_register_read(rt2x00dev, TX_PWR_CFG_3, &reg);
	rt2x00_set_field32(&reg, TX_PWR_CFG_3_MCS12, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_3_MCS13, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_3_MCS14, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_3_MCS15, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_3_UKNOWN1, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_3_UKNOWN2, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_3_UKNOWN3, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_3_UKNOWN4, value);
	rt2800_register_write(rt2x00dev, TX_PWR_CFG_3, reg);

	rt2800_register_read(rt2x00dev, TX_PWR_CFG_4, &reg);
	rt2x00_set_field32(&reg, TX_PWR_CFG_4_UKNOWN5, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_4_UKNOWN6, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_4_UKNOWN7, value);
	rt2x00_set_field32(&reg, TX_PWR_CFG_4_UKNOWN8, value);
	rt2800_register_write(rt2x00dev, TX_PWR_CFG_4, reg);
}

static void rt2800_config_retry_limit(struct rt2x00_dev *rt2x00dev,
				      struct rt2x00lib_conf *libconf)
{
	u32 reg;

	rt2800_register_read(rt2x00dev, TX_RTY_CFG, &reg);
	rt2x00_set_field32(&reg, TX_RTY_CFG_SHORT_RTY_LIMIT,
			   libconf->conf->short_frame_max_tx_count);
	rt2x00_set_field32(&reg, TX_RTY_CFG_LONG_RTY_LIMIT,
			   libconf->conf->long_frame_max_tx_count);
	rt2x00_set_field32(&reg, TX_RTY_CFG_LONG_RTY_THRE, 2000);
	rt2x00_set_field32(&reg, TX_RTY_CFG_NON_AGG_RTY_MODE, 0);
	rt2x00_set_field32(&reg, TX_RTY_CFG_AGG_RTY_MODE, 0);
	rt2x00_set_field32(&reg, TX_RTY_CFG_TX_AUTO_FB_ENABLE, 1);
	rt2800_register_write(rt2x00dev, TX_RTY_CFG, reg);
}

static void rt2800_config_ps(struct rt2x00_dev *rt2x00dev,
			     struct rt2x00lib_conf *libconf)
{
	enum dev_state state =
	    (libconf->conf->flags & IEEE80211_CONF_PS) ?
		STATE_SLEEP : STATE_AWAKE;
	u32 reg;

	if (state == STATE_SLEEP) {
		rt2800_register_write(rt2x00dev, AUTOWAKEUP_CFG, 0);

		rt2800_register_read(rt2x00dev, AUTOWAKEUP_CFG, &reg);
		rt2x00_set_field32(&reg, AUTOWAKEUP_CFG_AUTO_LEAD_TIME, 5);
		rt2x00_set_field32(&reg, AUTOWAKEUP_CFG_TBCN_BEFORE_WAKE,
				   libconf->conf->listen_interval - 1);
		rt2x00_set_field32(&reg, AUTOWAKEUP_CFG_AUTOWAKE, 1);
		rt2800_register_write(rt2x00dev, AUTOWAKEUP_CFG, reg);

		rt2x00dev->ops->lib->set_device_state(rt2x00dev, state);
	} else {
		rt2x00dev->ops->lib->set_device_state(rt2x00dev, state);

		rt2800_register_read(rt2x00dev, AUTOWAKEUP_CFG, &reg);
		rt2x00_set_field32(&reg, AUTOWAKEUP_CFG_AUTO_LEAD_TIME, 0);
		rt2x00_set_field32(&reg, AUTOWAKEUP_CFG_TBCN_BEFORE_WAKE, 0);
		rt2x00_set_field32(&reg, AUTOWAKEUP_CFG_AUTOWAKE, 0);
		rt2800_register_write(rt2x00dev, AUTOWAKEUP_CFG, reg);
	}
}

void rt2800_config(struct rt2x00_dev *rt2x00dev,
		   struct rt2x00lib_conf *libconf,
		   const unsigned int flags)
{
	/* Always recalculate LNA gain before changing configuration */
	rt2800_config_lna_gain(rt2x00dev, libconf);

	if (flags & IEEE80211_CONF_CHANGE_CHANNEL)
		rt2800_config_channel(rt2x00dev, libconf->conf,
				      &libconf->rf, &libconf->channel);
	if (flags & IEEE80211_CONF_CHANGE_POWER)
		rt2800_config_txpower(rt2x00dev, libconf->conf->power_level);
	if (flags & IEEE80211_CONF_CHANGE_RETRY_LIMITS)
		rt2800_config_retry_limit(rt2x00dev, libconf);
	if (flags & IEEE80211_CONF_CHANGE_PS)
		rt2800_config_ps(rt2x00dev, libconf);
}
EXPORT_SYMBOL_GPL(rt2800_config);

/*
 * Link tuning
 */
void rt2800_link_stats(struct rt2x00_dev *rt2x00dev, struct link_qual *qual)
{
	u32 reg;

	/*
	 * Update FCS error count from register.
	 */
	rt2800_register_read(rt2x00dev, RX_STA_CNT0, &reg);
	qual->rx_failed = rt2x00_get_field32(reg, RX_STA_CNT0_CRC_ERR);
}
EXPORT_SYMBOL_GPL(rt2800_link_stats);

static u8 rt2800_get_default_vgc(struct rt2x00_dev *rt2x00dev)
{
	if (rt2x00dev->curr_band == IEEE80211_BAND_2GHZ) {
		if (rt2x00_intf_is_usb(rt2x00dev) &&
		    rt2x00_rev(&rt2x00dev->chip) == RT3070_VERSION)
			return 0x1c + (2 * rt2x00dev->lna_gain);
		else
			return 0x2e + rt2x00dev->lna_gain;
	}

	if (!test_bit(CONFIG_CHANNEL_HT40, &rt2x00dev->flags))
		return 0x32 + (rt2x00dev->lna_gain * 5) / 3;
	else
		return 0x3a + (rt2x00dev->lna_gain * 5) / 3;
}

static inline void rt2800_set_vgc(struct rt2x00_dev *rt2x00dev,
				  struct link_qual *qual, u8 vgc_level)
{
	if (qual->vgc_level != vgc_level) {
		rt2800_bbp_write(rt2x00dev, 66, vgc_level);
		qual->vgc_level = vgc_level;
		qual->vgc_level_reg = vgc_level;
	}
}

void rt2800_reset_tuner(struct rt2x00_dev *rt2x00dev, struct link_qual *qual)
{
	rt2800_set_vgc(rt2x00dev, qual, rt2800_get_default_vgc(rt2x00dev));
}
EXPORT_SYMBOL_GPL(rt2800_reset_tuner);

void rt2800_link_tuner(struct rt2x00_dev *rt2x00dev, struct link_qual *qual,
		       const u32 count)
{
	if (rt2x00_rev(&rt2x00dev->chip) == RT2860C_VERSION)
		return;

	/*
	 * When RSSI is better then -80 increase VGC level with 0x10
	 */
	rt2800_set_vgc(rt2x00dev, qual,
		       rt2800_get_default_vgc(rt2x00dev) +
		       ((qual->rssi > -80) * 0x10));
}
EXPORT_SYMBOL_GPL(rt2800_link_tuner);
