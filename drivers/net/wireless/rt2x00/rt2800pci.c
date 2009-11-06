/*
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
	Module: rt2800pci
	Abstract: rt2800pci device specific routines.
	Supported chipsets: RT2800E & RT2800ED.
 */

#include <linux/crc-ccitt.h>
#include <linux/delay.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/eeprom_93cx6.h>

#include "rt2x00.h"
#include "rt2x00pci.h"
#include "rt2x00soc.h"
#include "rt2800lib.h"
#include "rt2800.h"
#include "rt2800pci.h"

#ifdef CONFIG_RT2800PCI_PCI_MODULE
#define CONFIG_RT2800PCI_PCI
#endif

#ifdef CONFIG_RT2800PCI_WISOC_MODULE
#define CONFIG_RT2800PCI_WISOC
#endif

/*
 * Allow hardware encryption to be disabled.
 */
static int modparam_nohwcrypt = 1;
module_param_named(nohwcrypt, modparam_nohwcrypt, bool, S_IRUGO);
MODULE_PARM_DESC(nohwcrypt, "Disable hardware encryption.");

static void rt2800pci_mcu_status(struct rt2x00_dev *rt2x00dev, const u8 token)
{
	unsigned int i;
	u32 reg;

	for (i = 0; i < 200; i++) {
		rt2800_register_read(rt2x00dev, H2M_MAILBOX_CID, &reg);

		if ((rt2x00_get_field32(reg, H2M_MAILBOX_CID_CMD0) == token) ||
		    (rt2x00_get_field32(reg, H2M_MAILBOX_CID_CMD1) == token) ||
		    (rt2x00_get_field32(reg, H2M_MAILBOX_CID_CMD2) == token) ||
		    (rt2x00_get_field32(reg, H2M_MAILBOX_CID_CMD3) == token))
			break;

		udelay(REGISTER_BUSY_DELAY);
	}

	if (i == 200)
		ERROR(rt2x00dev, "MCU request failed, no response from hardware\n");

	rt2800_register_write(rt2x00dev, H2M_MAILBOX_STATUS, ~0);
	rt2800_register_write(rt2x00dev, H2M_MAILBOX_CID, ~0);
}

#ifdef CONFIG_RT2800PCI_WISOC
static void rt2800pci_read_eeprom_soc(struct rt2x00_dev *rt2x00dev)
{
	u32 *base_addr = (u32 *) KSEG1ADDR(0x1F040000); /* XXX for RT3052 */

	memcpy_fromio(rt2x00dev->eeprom, base_addr, EEPROM_SIZE);
}
#else
static inline void rt2800pci_read_eeprom_soc(struct rt2x00_dev *rt2x00dev)
{
}
#endif /* CONFIG_RT2800PCI_WISOC */

#ifdef CONFIG_RT2800PCI_PCI
static void rt2800pci_eepromregister_read(struct eeprom_93cx6 *eeprom)
{
	struct rt2x00_dev *rt2x00dev = eeprom->data;
	u32 reg;

	rt2800_register_read(rt2x00dev, E2PROM_CSR, &reg);

	eeprom->reg_data_in = !!rt2x00_get_field32(reg, E2PROM_CSR_DATA_IN);
	eeprom->reg_data_out = !!rt2x00_get_field32(reg, E2PROM_CSR_DATA_OUT);
	eeprom->reg_data_clock =
	    !!rt2x00_get_field32(reg, E2PROM_CSR_DATA_CLOCK);
	eeprom->reg_chip_select =
	    !!rt2x00_get_field32(reg, E2PROM_CSR_CHIP_SELECT);
}

static void rt2800pci_eepromregister_write(struct eeprom_93cx6 *eeprom)
{
	struct rt2x00_dev *rt2x00dev = eeprom->data;
	u32 reg = 0;

	rt2x00_set_field32(&reg, E2PROM_CSR_DATA_IN, !!eeprom->reg_data_in);
	rt2x00_set_field32(&reg, E2PROM_CSR_DATA_OUT, !!eeprom->reg_data_out);
	rt2x00_set_field32(&reg, E2PROM_CSR_DATA_CLOCK,
			   !!eeprom->reg_data_clock);
	rt2x00_set_field32(&reg, E2PROM_CSR_CHIP_SELECT,
			   !!eeprom->reg_chip_select);

	rt2800_register_write(rt2x00dev, E2PROM_CSR, reg);
}

static void rt2800pci_read_eeprom_pci(struct rt2x00_dev *rt2x00dev)
{
	struct eeprom_93cx6 eeprom;
	u32 reg;

	rt2800_register_read(rt2x00dev, E2PROM_CSR, &reg);

	eeprom.data = rt2x00dev;
	eeprom.register_read = rt2800pci_eepromregister_read;
	eeprom.register_write = rt2800pci_eepromregister_write;
	eeprom.width = !rt2x00_get_field32(reg, E2PROM_CSR_TYPE) ?
	    PCI_EEPROM_WIDTH_93C46 : PCI_EEPROM_WIDTH_93C66;
	eeprom.reg_data_in = 0;
	eeprom.reg_data_out = 0;
	eeprom.reg_data_clock = 0;
	eeprom.reg_chip_select = 0;

	eeprom_93cx6_multiread(&eeprom, EEPROM_BASE, rt2x00dev->eeprom,
			       EEPROM_SIZE / sizeof(u16));
}

static void rt2800pci_efuse_read(struct rt2x00_dev *rt2x00dev,
				 unsigned int i)
{
	u32 reg;

	rt2800_register_read(rt2x00dev, EFUSE_CTRL, &reg);
	rt2x00_set_field32(&reg, EFUSE_CTRL_ADDRESS_IN, i);
	rt2x00_set_field32(&reg, EFUSE_CTRL_MODE, 0);
	rt2x00_set_field32(&reg, EFUSE_CTRL_KICK, 1);
	rt2800_register_write(rt2x00dev, EFUSE_CTRL, reg);

	/* Wait until the EEPROM has been loaded */
	rt2800_regbusy_read(rt2x00dev, EFUSE_CTRL, EFUSE_CTRL_KICK, &reg);

	/* Apparently the data is read from end to start */
	rt2800_register_read(rt2x00dev, EFUSE_DATA3,
				(u32 *)&rt2x00dev->eeprom[i]);
	rt2800_register_read(rt2x00dev, EFUSE_DATA2,
				(u32 *)&rt2x00dev->eeprom[i + 2]);
	rt2800_register_read(rt2x00dev, EFUSE_DATA1,
				(u32 *)&rt2x00dev->eeprom[i + 4]);
	rt2800_register_read(rt2x00dev, EFUSE_DATA0,
				(u32 *)&rt2x00dev->eeprom[i + 6]);
}

static void rt2800pci_read_eeprom_efuse(struct rt2x00_dev *rt2x00dev)
{
	unsigned int i;

	for (i = 0; i < EEPROM_SIZE / sizeof(u16); i += 8)
		rt2800pci_efuse_read(rt2x00dev, i);
}
#else
static inline void rt2800pci_read_eeprom_pci(struct rt2x00_dev *rt2x00dev)
{
}

static inline void rt2800pci_read_eeprom_efuse(struct rt2x00_dev *rt2x00dev)
{
}
#endif /* CONFIG_RT2800PCI_PCI */

/*
 * Firmware functions
 */
static char *rt2800pci_get_firmware_name(struct rt2x00_dev *rt2x00dev)
{
	return FIRMWARE_RT2860;
}

static int rt2800pci_check_firmware(struct rt2x00_dev *rt2x00dev,
				    const u8 *data, const size_t len)
{
	u16 fw_crc;
	u16 crc;

	/*
	 * Only support 8kb firmware files.
	 */
	if (len != 8192)
		return FW_BAD_LENGTH;

	/*
	 * The last 2 bytes in the firmware array are the crc checksum itself,
	 * this means that we should never pass those 2 bytes to the crc
	 * algorithm.
	 */
	fw_crc = (data[len - 2] << 8 | data[len - 1]);

	/*
	 * Use the crc ccitt algorithm.
	 * This will return the same value as the legacy driver which
	 * used bit ordering reversion on the both the firmware bytes
	 * before input input as well as on the final output.
	 * Obviously using crc ccitt directly is much more efficient.
	 */
	crc = crc_ccitt(~0, data, len - 2);

	/*
	 * There is a small difference between the crc-itu-t + bitrev and
	 * the crc-ccitt crc calculation. In the latter method the 2 bytes
	 * will be swapped, use swab16 to convert the crc to the correct
	 * value.
	 */
	crc = swab16(crc);

	return (fw_crc == crc) ? FW_OK : FW_BAD_CRC;
}

static int rt2800pci_load_firmware(struct rt2x00_dev *rt2x00dev,
				   const u8 *data, const size_t len)
{
	unsigned int i;
	u32 reg;

	/*
	 * Wait for stable hardware.
	 */
	for (i = 0; i < REGISTER_BUSY_COUNT; i++) {
		rt2800_register_read(rt2x00dev, MAC_CSR0, &reg);
		if (reg && reg != ~0)
			break;
		msleep(1);
	}

	if (i == REGISTER_BUSY_COUNT) {
		ERROR(rt2x00dev, "Unstable hardware.\n");
		return -EBUSY;
	}

	rt2800_register_write(rt2x00dev, PWR_PIN_CFG, 0x00000002);
	rt2800_register_write(rt2x00dev, AUTOWAKEUP_CFG, 0x00000000);

	/*
	 * Disable DMA, will be reenabled later when enabling
	 * the radio.
	 */
	rt2800_register_read(rt2x00dev, WPDMA_GLO_CFG, &reg);
	rt2x00_set_field32(&reg, WPDMA_GLO_CFG_ENABLE_TX_DMA, 0);
	rt2x00_set_field32(&reg, WPDMA_GLO_CFG_TX_DMA_BUSY, 0);
	rt2x00_set_field32(&reg, WPDMA_GLO_CFG_ENABLE_RX_DMA, 0);
	rt2x00_set_field32(&reg, WPDMA_GLO_CFG_RX_DMA_BUSY, 0);
	rt2x00_set_field32(&reg, WPDMA_GLO_CFG_TX_WRITEBACK_DONE, 1);
	rt2800_register_write(rt2x00dev, WPDMA_GLO_CFG, reg);

	/*
	 * enable Host program ram write selection
	 */
	reg = 0;
	rt2x00_set_field32(&reg, PBF_SYS_CTRL_HOST_RAM_WRITE, 1);
	rt2800_register_write(rt2x00dev, PBF_SYS_CTRL, reg);

	/*
	 * Write firmware to device.
	 */
	rt2800_register_multiwrite(rt2x00dev, FIRMWARE_IMAGE_BASE,
				      data, len);

	rt2800_register_write(rt2x00dev, PBF_SYS_CTRL, 0x00000);
	rt2800_register_write(rt2x00dev, PBF_SYS_CTRL, 0x00001);

	/*
	 * Wait for device to stabilize.
	 */
	for (i = 0; i < REGISTER_BUSY_COUNT; i++) {
		rt2800_register_read(rt2x00dev, PBF_SYS_CTRL, &reg);
		if (rt2x00_get_field32(reg, PBF_SYS_CTRL_READY))
			break;
		msleep(1);
	}

	if (i == REGISTER_BUSY_COUNT) {
		ERROR(rt2x00dev, "PBF system register not ready.\n");
		return -EBUSY;
	}

	/*
	 * Disable interrupts
	 */
	rt2x00dev->ops->lib->set_device_state(rt2x00dev, STATE_RADIO_IRQ_OFF);

	/*
	 * Initialize BBP R/W access agent
	 */
	rt2800_register_write(rt2x00dev, H2M_BBP_AGENT, 0);
	rt2800_register_write(rt2x00dev, H2M_MAILBOX_CSR, 0);

	return 0;
}

/*
 * Initialization functions.
 */
static bool rt2800pci_get_entry_state(struct queue_entry *entry)
{
	struct queue_entry_priv_pci *entry_priv = entry->priv_data;
	u32 word;

	if (entry->queue->qid == QID_RX) {
		rt2x00_desc_read(entry_priv->desc, 1, &word);

		return (!rt2x00_get_field32(word, RXD_W1_DMA_DONE));
	} else {
		rt2x00_desc_read(entry_priv->desc, 1, &word);

		return (!rt2x00_get_field32(word, TXD_W1_DMA_DONE));
	}
}

static void rt2800pci_clear_entry(struct queue_entry *entry)
{
	struct queue_entry_priv_pci *entry_priv = entry->priv_data;
	struct skb_frame_desc *skbdesc = get_skb_frame_desc(entry->skb);
	u32 word;

	if (entry->queue->qid == QID_RX) {
		rt2x00_desc_read(entry_priv->desc, 0, &word);
		rt2x00_set_field32(&word, RXD_W0_SDP0, skbdesc->skb_dma);
		rt2x00_desc_write(entry_priv->desc, 0, word);

		rt2x00_desc_read(entry_priv->desc, 1, &word);
		rt2x00_set_field32(&word, RXD_W1_DMA_DONE, 0);
		rt2x00_desc_write(entry_priv->desc, 1, word);
	} else {
		rt2x00_desc_read(entry_priv->desc, 1, &word);
		rt2x00_set_field32(&word, TXD_W1_DMA_DONE, 1);
		rt2x00_desc_write(entry_priv->desc, 1, word);
	}
}

static int rt2800pci_init_queues(struct rt2x00_dev *rt2x00dev)
{
	struct queue_entry_priv_pci *entry_priv;
	u32 reg;

	rt2800_register_read(rt2x00dev, WPDMA_RST_IDX, &reg);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX0, 1);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX1, 1);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX2, 1);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX3, 1);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX4, 1);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX5, 1);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DRX_IDX0, 1);
	rt2800_register_write(rt2x00dev, WPDMA_RST_IDX, reg);

	rt2800_register_write(rt2x00dev, PBF_SYS_CTRL, 0x00000e1f);
	rt2800_register_write(rt2x00dev, PBF_SYS_CTRL, 0x00000e00);

	/*
	 * Initialize registers.
	 */
	entry_priv = rt2x00dev->tx[0].entries[0].priv_data;
	rt2800_register_write(rt2x00dev, TX_BASE_PTR0, entry_priv->desc_dma);
	rt2800_register_write(rt2x00dev, TX_MAX_CNT0, rt2x00dev->tx[0].limit);
	rt2800_register_write(rt2x00dev, TX_CTX_IDX0, 0);
	rt2800_register_write(rt2x00dev, TX_DTX_IDX0, 0);

	entry_priv = rt2x00dev->tx[1].entries[0].priv_data;
	rt2800_register_write(rt2x00dev, TX_BASE_PTR1, entry_priv->desc_dma);
	rt2800_register_write(rt2x00dev, TX_MAX_CNT1, rt2x00dev->tx[1].limit);
	rt2800_register_write(rt2x00dev, TX_CTX_IDX1, 0);
	rt2800_register_write(rt2x00dev, TX_DTX_IDX1, 0);

	entry_priv = rt2x00dev->tx[2].entries[0].priv_data;
	rt2800_register_write(rt2x00dev, TX_BASE_PTR2, entry_priv->desc_dma);
	rt2800_register_write(rt2x00dev, TX_MAX_CNT2, rt2x00dev->tx[2].limit);
	rt2800_register_write(rt2x00dev, TX_CTX_IDX2, 0);
	rt2800_register_write(rt2x00dev, TX_DTX_IDX2, 0);

	entry_priv = rt2x00dev->tx[3].entries[0].priv_data;
	rt2800_register_write(rt2x00dev, TX_BASE_PTR3, entry_priv->desc_dma);
	rt2800_register_write(rt2x00dev, TX_MAX_CNT3, rt2x00dev->tx[3].limit);
	rt2800_register_write(rt2x00dev, TX_CTX_IDX3, 0);
	rt2800_register_write(rt2x00dev, TX_DTX_IDX3, 0);

	entry_priv = rt2x00dev->rx->entries[0].priv_data;
	rt2800_register_write(rt2x00dev, RX_BASE_PTR, entry_priv->desc_dma);
	rt2800_register_write(rt2x00dev, RX_MAX_CNT, rt2x00dev->rx[0].limit);
	rt2800_register_write(rt2x00dev, RX_CRX_IDX, rt2x00dev->rx[0].limit - 1);
	rt2800_register_write(rt2x00dev, RX_DRX_IDX, 0);

	/*
	 * Enable global DMA configuration
	 */
	rt2800_register_read(rt2x00dev, WPDMA_GLO_CFG, &reg);
	rt2x00_set_field32(&reg, WPDMA_GLO_CFG_ENABLE_TX_DMA, 0);
	rt2x00_set_field32(&reg, WPDMA_GLO_CFG_ENABLE_RX_DMA, 0);
	rt2x00_set_field32(&reg, WPDMA_GLO_CFG_TX_WRITEBACK_DONE, 1);
	rt2800_register_write(rt2x00dev, WPDMA_GLO_CFG, reg);

	rt2800_register_write(rt2x00dev, DELAY_INT_CFG, 0);

	return 0;
}

static int rt2800pci_init_registers(struct rt2x00_dev *rt2x00dev)
{
	u32 reg;
	unsigned int i;

	if (rt2x00_intf_is_pci(rt2x00dev))
		rt2800_register_write(rt2x00dev, PWR_PIN_CFG, 0x00000003);

	rt2800_register_read(rt2x00dev, MAC_SYS_CTRL, &reg);
	rt2x00_set_field32(&reg, MAC_SYS_CTRL_RESET_CSR, 1);
	rt2x00_set_field32(&reg, MAC_SYS_CTRL_RESET_BBP, 1);
	rt2800_register_write(rt2x00dev, MAC_SYS_CTRL, reg);

	rt2800_register_write(rt2x00dev, MAC_SYS_CTRL, 0x00000000);

	rt2800_register_read(rt2x00dev, BCN_OFFSET0, &reg);
	rt2x00_set_field32(&reg, BCN_OFFSET0_BCN0, 0xe0); /* 0x3800 */
	rt2x00_set_field32(&reg, BCN_OFFSET0_BCN1, 0xe8); /* 0x3a00 */
	rt2x00_set_field32(&reg, BCN_OFFSET0_BCN2, 0xf0); /* 0x3c00 */
	rt2x00_set_field32(&reg, BCN_OFFSET0_BCN3, 0xf8); /* 0x3e00 */
	rt2800_register_write(rt2x00dev, BCN_OFFSET0, reg);

	rt2800_register_read(rt2x00dev, BCN_OFFSET1, &reg);
	rt2x00_set_field32(&reg, BCN_OFFSET1_BCN4, 0xc8); /* 0x3200 */
	rt2x00_set_field32(&reg, BCN_OFFSET1_BCN5, 0xd0); /* 0x3400 */
	rt2x00_set_field32(&reg, BCN_OFFSET1_BCN6, 0x77); /* 0x1dc0 */
	rt2x00_set_field32(&reg, BCN_OFFSET1_BCN7, 0x6f); /* 0x1bc0 */
	rt2800_register_write(rt2x00dev, BCN_OFFSET1, reg);

	rt2800_register_write(rt2x00dev, LEGACY_BASIC_RATE, 0x0000013f);
	rt2800_register_write(rt2x00dev, HT_BASIC_RATE, 0x00008003);

	rt2800_register_write(rt2x00dev, MAC_SYS_CTRL, 0x00000000);

	rt2800_register_read(rt2x00dev, BCN_TIME_CFG, &reg);
	rt2x00_set_field32(&reg, BCN_TIME_CFG_BEACON_INTERVAL, 0);
	rt2x00_set_field32(&reg, BCN_TIME_CFG_TSF_TICKING, 0);
	rt2x00_set_field32(&reg, BCN_TIME_CFG_TSF_SYNC, 0);
	rt2x00_set_field32(&reg, BCN_TIME_CFG_TBTT_ENABLE, 0);
	rt2x00_set_field32(&reg, BCN_TIME_CFG_BEACON_GEN, 0);
	rt2x00_set_field32(&reg, BCN_TIME_CFG_TX_TIME_COMPENSATE, 0);
	rt2800_register_write(rt2x00dev, BCN_TIME_CFG, reg);

	rt2800_register_write(rt2x00dev, TX_SW_CFG0, 0x00000000);
	rt2800_register_write(rt2x00dev, TX_SW_CFG1, 0x00080606);

	rt2800_register_read(rt2x00dev, TX_LINK_CFG, &reg);
	rt2x00_set_field32(&reg, TX_LINK_CFG_REMOTE_MFB_LIFETIME, 32);
	rt2x00_set_field32(&reg, TX_LINK_CFG_MFB_ENABLE, 0);
	rt2x00_set_field32(&reg, TX_LINK_CFG_REMOTE_UMFS_ENABLE, 0);
	rt2x00_set_field32(&reg, TX_LINK_CFG_TX_MRQ_EN, 0);
	rt2x00_set_field32(&reg, TX_LINK_CFG_TX_RDG_EN, 0);
	rt2x00_set_field32(&reg, TX_LINK_CFG_TX_CF_ACK_EN, 1);
	rt2x00_set_field32(&reg, TX_LINK_CFG_REMOTE_MFB, 0);
	rt2x00_set_field32(&reg, TX_LINK_CFG_REMOTE_MFS, 0);
	rt2800_register_write(rt2x00dev, TX_LINK_CFG, reg);

	rt2800_register_read(rt2x00dev, TX_TIMEOUT_CFG, &reg);
	rt2x00_set_field32(&reg, TX_TIMEOUT_CFG_MPDU_LIFETIME, 9);
	rt2x00_set_field32(&reg, TX_TIMEOUT_CFG_TX_OP_TIMEOUT, 10);
	rt2800_register_write(rt2x00dev, TX_TIMEOUT_CFG, reg);

	rt2800_register_read(rt2x00dev, MAX_LEN_CFG, &reg);
	rt2x00_set_field32(&reg, MAX_LEN_CFG_MAX_MPDU, AGGREGATION_SIZE);
	if (rt2x00_rev(&rt2x00dev->chip) >= RT2880E_VERSION &&
	    rt2x00_rev(&rt2x00dev->chip) < RT3070_VERSION)
		rt2x00_set_field32(&reg, MAX_LEN_CFG_MAX_PSDU, 2);
	else
		rt2x00_set_field32(&reg, MAX_LEN_CFG_MAX_PSDU, 1);
	rt2x00_set_field32(&reg, MAX_LEN_CFG_MIN_PSDU, 0);
	rt2x00_set_field32(&reg, MAX_LEN_CFG_MIN_MPDU, 0);
	rt2800_register_write(rt2x00dev, MAX_LEN_CFG, reg);

	rt2800_register_write(rt2x00dev, PBF_MAX_PCNT, 0x1f3fbf9f);

	rt2800_register_read(rt2x00dev, AUTO_RSP_CFG, &reg);
	rt2x00_set_field32(&reg, AUTO_RSP_CFG_AUTORESPONDER, 1);
	rt2x00_set_field32(&reg, AUTO_RSP_CFG_CTS_40_MMODE, 0);
	rt2x00_set_field32(&reg, AUTO_RSP_CFG_CTS_40_MREF, 0);
	rt2x00_set_field32(&reg, AUTO_RSP_CFG_DUAL_CTS_EN, 0);
	rt2x00_set_field32(&reg, AUTO_RSP_CFG_ACK_CTS_PSM_BIT, 0);
	rt2800_register_write(rt2x00dev, AUTO_RSP_CFG, reg);

	rt2800_register_read(rt2x00dev, CCK_PROT_CFG, &reg);
	rt2x00_set_field32(&reg, CCK_PROT_CFG_PROTECT_RATE, 8);
	rt2x00_set_field32(&reg, CCK_PROT_CFG_PROTECT_CTRL, 0);
	rt2x00_set_field32(&reg, CCK_PROT_CFG_PROTECT_NAV, 1);
	rt2x00_set_field32(&reg, CCK_PROT_CFG_TX_OP_ALLOW_CCK, 1);
	rt2x00_set_field32(&reg, CCK_PROT_CFG_TX_OP_ALLOW_OFDM, 1);
	rt2x00_set_field32(&reg, CCK_PROT_CFG_TX_OP_ALLOW_MM20, 1);
	rt2x00_set_field32(&reg, CCK_PROT_CFG_TX_OP_ALLOW_MM40, 1);
	rt2x00_set_field32(&reg, CCK_PROT_CFG_TX_OP_ALLOW_GF20, 1);
	rt2x00_set_field32(&reg, CCK_PROT_CFG_TX_OP_ALLOW_GF40, 1);
	rt2800_register_write(rt2x00dev, CCK_PROT_CFG, reg);

	rt2800_register_read(rt2x00dev, OFDM_PROT_CFG, &reg);
	rt2x00_set_field32(&reg, OFDM_PROT_CFG_PROTECT_RATE, 8);
	rt2x00_set_field32(&reg, OFDM_PROT_CFG_PROTECT_CTRL, 0);
	rt2x00_set_field32(&reg, OFDM_PROT_CFG_PROTECT_NAV, 1);
	rt2x00_set_field32(&reg, OFDM_PROT_CFG_TX_OP_ALLOW_CCK, 1);
	rt2x00_set_field32(&reg, OFDM_PROT_CFG_TX_OP_ALLOW_OFDM, 1);
	rt2x00_set_field32(&reg, OFDM_PROT_CFG_TX_OP_ALLOW_MM20, 1);
	rt2x00_set_field32(&reg, OFDM_PROT_CFG_TX_OP_ALLOW_MM40, 1);
	rt2x00_set_field32(&reg, OFDM_PROT_CFG_TX_OP_ALLOW_GF20, 1);
	rt2x00_set_field32(&reg, OFDM_PROT_CFG_TX_OP_ALLOW_GF40, 1);
	rt2800_register_write(rt2x00dev, OFDM_PROT_CFG, reg);

	rt2800_register_read(rt2x00dev, MM20_PROT_CFG, &reg);
	rt2x00_set_field32(&reg, MM20_PROT_CFG_PROTECT_RATE, 0x4004);
	rt2x00_set_field32(&reg, MM20_PROT_CFG_PROTECT_CTRL, 0);
	rt2x00_set_field32(&reg, MM20_PROT_CFG_PROTECT_NAV, 1);
	rt2x00_set_field32(&reg, MM20_PROT_CFG_TX_OP_ALLOW_CCK, 1);
	rt2x00_set_field32(&reg, MM20_PROT_CFG_TX_OP_ALLOW_OFDM, 1);
	rt2x00_set_field32(&reg, MM20_PROT_CFG_TX_OP_ALLOW_MM20, 1);
	rt2x00_set_field32(&reg, MM20_PROT_CFG_TX_OP_ALLOW_MM40, 0);
	rt2x00_set_field32(&reg, MM20_PROT_CFG_TX_OP_ALLOW_GF20, 1);
	rt2x00_set_field32(&reg, MM20_PROT_CFG_TX_OP_ALLOW_GF40, 0);
	rt2800_register_write(rt2x00dev, MM20_PROT_CFG, reg);

	rt2800_register_read(rt2x00dev, MM40_PROT_CFG, &reg);
	rt2x00_set_field32(&reg, MM40_PROT_CFG_PROTECT_RATE, 0x4084);
	rt2x00_set_field32(&reg, MM40_PROT_CFG_PROTECT_CTRL, 0);
	rt2x00_set_field32(&reg, MM40_PROT_CFG_PROTECT_NAV, 1);
	rt2x00_set_field32(&reg, MM40_PROT_CFG_TX_OP_ALLOW_CCK, 1);
	rt2x00_set_field32(&reg, MM40_PROT_CFG_TX_OP_ALLOW_OFDM, 1);
	rt2x00_set_field32(&reg, MM40_PROT_CFG_TX_OP_ALLOW_MM20, 1);
	rt2x00_set_field32(&reg, MM40_PROT_CFG_TX_OP_ALLOW_MM40, 1);
	rt2x00_set_field32(&reg, MM40_PROT_CFG_TX_OP_ALLOW_GF20, 1);
	rt2x00_set_field32(&reg, MM40_PROT_CFG_TX_OP_ALLOW_GF40, 1);
	rt2800_register_write(rt2x00dev, MM40_PROT_CFG, reg);

	rt2800_register_read(rt2x00dev, GF20_PROT_CFG, &reg);
	rt2x00_set_field32(&reg, GF20_PROT_CFG_PROTECT_RATE, 0x4004);
	rt2x00_set_field32(&reg, GF20_PROT_CFG_PROTECT_CTRL, 0);
	rt2x00_set_field32(&reg, GF20_PROT_CFG_PROTECT_NAV, 1);
	rt2x00_set_field32(&reg, GF20_PROT_CFG_TX_OP_ALLOW_CCK, 1);
	rt2x00_set_field32(&reg, GF20_PROT_CFG_TX_OP_ALLOW_OFDM, 1);
	rt2x00_set_field32(&reg, GF20_PROT_CFG_TX_OP_ALLOW_MM20, 1);
	rt2x00_set_field32(&reg, GF20_PROT_CFG_TX_OP_ALLOW_MM40, 0);
	rt2x00_set_field32(&reg, GF20_PROT_CFG_TX_OP_ALLOW_GF20, 1);
	rt2x00_set_field32(&reg, GF20_PROT_CFG_TX_OP_ALLOW_GF40, 0);
	rt2800_register_write(rt2x00dev, GF20_PROT_CFG, reg);

	rt2800_register_read(rt2x00dev, GF40_PROT_CFG, &reg);
	rt2x00_set_field32(&reg, GF40_PROT_CFG_PROTECT_RATE, 0x4084);
	rt2x00_set_field32(&reg, GF40_PROT_CFG_PROTECT_CTRL, 0);
	rt2x00_set_field32(&reg, GF40_PROT_CFG_PROTECT_NAV, 1);
	rt2x00_set_field32(&reg, GF40_PROT_CFG_TX_OP_ALLOW_CCK, 1);
	rt2x00_set_field32(&reg, GF40_PROT_CFG_TX_OP_ALLOW_OFDM, 1);
	rt2x00_set_field32(&reg, GF40_PROT_CFG_TX_OP_ALLOW_MM20, 1);
	rt2x00_set_field32(&reg, GF40_PROT_CFG_TX_OP_ALLOW_MM40, 1);
	rt2x00_set_field32(&reg, GF40_PROT_CFG_TX_OP_ALLOW_GF20, 1);
	rt2x00_set_field32(&reg, GF40_PROT_CFG_TX_OP_ALLOW_GF40, 1);
	rt2800_register_write(rt2x00dev, GF40_PROT_CFG, reg);

	rt2800_register_write(rt2x00dev, TXOP_CTRL_CFG, 0x0000583f);
	rt2800_register_write(rt2x00dev, TXOP_HLDR_ET, 0x00000002);

	rt2800_register_read(rt2x00dev, TX_RTS_CFG, &reg);
	rt2x00_set_field32(&reg, TX_RTS_CFG_AUTO_RTS_RETRY_LIMIT, 32);
	rt2x00_set_field32(&reg, TX_RTS_CFG_RTS_THRES,
			   IEEE80211_MAX_RTS_THRESHOLD);
	rt2x00_set_field32(&reg, TX_RTS_CFG_RTS_FBK_EN, 0);
	rt2800_register_write(rt2x00dev, TX_RTS_CFG, reg);

	rt2800_register_write(rt2x00dev, EXP_ACK_TIME, 0x002400ca);
	rt2800_register_write(rt2x00dev, PWR_PIN_CFG, 0x00000003);

	/*
	 * ASIC will keep garbage value after boot, clear encryption keys.
	 */
	for (i = 0; i < 4; i++)
		rt2800_register_write(rt2x00dev,
					 SHARED_KEY_MODE_ENTRY(i), 0);

	for (i = 0; i < 256; i++) {
		u32 wcid[2] = { 0xffffffff, 0x00ffffff };
		rt2800_register_multiwrite(rt2x00dev, MAC_WCID_ENTRY(i),
					      wcid, sizeof(wcid));

		rt2800_register_write(rt2x00dev, MAC_WCID_ATTR_ENTRY(i), 1);
		rt2800_register_write(rt2x00dev, MAC_IVEIV_ENTRY(i), 0);
	}

	/*
	 * Clear all beacons
	 * For the Beacon base registers we only need to clear
	 * the first byte since that byte contains the VALID and OWNER
	 * bits which (when set to 0) will invalidate the entire beacon.
	 */
	rt2800_register_write(rt2x00dev, HW_BEACON_BASE0, 0);
	rt2800_register_write(rt2x00dev, HW_BEACON_BASE1, 0);
	rt2800_register_write(rt2x00dev, HW_BEACON_BASE2, 0);
	rt2800_register_write(rt2x00dev, HW_BEACON_BASE3, 0);
	rt2800_register_write(rt2x00dev, HW_BEACON_BASE4, 0);
	rt2800_register_write(rt2x00dev, HW_BEACON_BASE5, 0);
	rt2800_register_write(rt2x00dev, HW_BEACON_BASE6, 0);
	rt2800_register_write(rt2x00dev, HW_BEACON_BASE7, 0);

	rt2800_register_read(rt2x00dev, HT_FBK_CFG0, &reg);
	rt2x00_set_field32(&reg, HT_FBK_CFG0_HTMCS0FBK, 0);
	rt2x00_set_field32(&reg, HT_FBK_CFG0_HTMCS1FBK, 0);
	rt2x00_set_field32(&reg, HT_FBK_CFG0_HTMCS2FBK, 1);
	rt2x00_set_field32(&reg, HT_FBK_CFG0_HTMCS3FBK, 2);
	rt2x00_set_field32(&reg, HT_FBK_CFG0_HTMCS4FBK, 3);
	rt2x00_set_field32(&reg, HT_FBK_CFG0_HTMCS5FBK, 4);
	rt2x00_set_field32(&reg, HT_FBK_CFG0_HTMCS6FBK, 5);
	rt2x00_set_field32(&reg, HT_FBK_CFG0_HTMCS7FBK, 6);
	rt2800_register_write(rt2x00dev, HT_FBK_CFG0, reg);

	rt2800_register_read(rt2x00dev, HT_FBK_CFG1, &reg);
	rt2x00_set_field32(&reg, HT_FBK_CFG1_HTMCS8FBK, 8);
	rt2x00_set_field32(&reg, HT_FBK_CFG1_HTMCS9FBK, 8);
	rt2x00_set_field32(&reg, HT_FBK_CFG1_HTMCS10FBK, 9);
	rt2x00_set_field32(&reg, HT_FBK_CFG1_HTMCS11FBK, 10);
	rt2x00_set_field32(&reg, HT_FBK_CFG1_HTMCS12FBK, 11);
	rt2x00_set_field32(&reg, HT_FBK_CFG1_HTMCS13FBK, 12);
	rt2x00_set_field32(&reg, HT_FBK_CFG1_HTMCS14FBK, 13);
	rt2x00_set_field32(&reg, HT_FBK_CFG1_HTMCS15FBK, 14);
	rt2800_register_write(rt2x00dev, HT_FBK_CFG1, reg);

	rt2800_register_read(rt2x00dev, LG_FBK_CFG0, &reg);
	rt2x00_set_field32(&reg, LG_FBK_CFG0_OFDMMCS0FBK, 8);
	rt2x00_set_field32(&reg, LG_FBK_CFG0_OFDMMCS1FBK, 8);
	rt2x00_set_field32(&reg, LG_FBK_CFG0_OFDMMCS2FBK, 9);
	rt2x00_set_field32(&reg, LG_FBK_CFG0_OFDMMCS3FBK, 10);
	rt2x00_set_field32(&reg, LG_FBK_CFG0_OFDMMCS4FBK, 11);
	rt2x00_set_field32(&reg, LG_FBK_CFG0_OFDMMCS5FBK, 12);
	rt2x00_set_field32(&reg, LG_FBK_CFG0_OFDMMCS6FBK, 13);
	rt2x00_set_field32(&reg, LG_FBK_CFG0_OFDMMCS7FBK, 14);
	rt2800_register_write(rt2x00dev, LG_FBK_CFG0, reg);

	rt2800_register_read(rt2x00dev, LG_FBK_CFG1, &reg);
	rt2x00_set_field32(&reg, LG_FBK_CFG0_CCKMCS0FBK, 0);
	rt2x00_set_field32(&reg, LG_FBK_CFG0_CCKMCS1FBK, 0);
	rt2x00_set_field32(&reg, LG_FBK_CFG0_CCKMCS2FBK, 1);
	rt2x00_set_field32(&reg, LG_FBK_CFG0_CCKMCS3FBK, 2);
	rt2800_register_write(rt2x00dev, LG_FBK_CFG1, reg);

	/*
	 * We must clear the error counters.
	 * These registers are cleared on read,
	 * so we may pass a useless variable to store the value.
	 */
	rt2800_register_read(rt2x00dev, RX_STA_CNT0, &reg);
	rt2800_register_read(rt2x00dev, RX_STA_CNT1, &reg);
	rt2800_register_read(rt2x00dev, RX_STA_CNT2, &reg);
	rt2800_register_read(rt2x00dev, TX_STA_CNT0, &reg);
	rt2800_register_read(rt2x00dev, TX_STA_CNT1, &reg);
	rt2800_register_read(rt2x00dev, TX_STA_CNT2, &reg);

	return 0;
}

static int rt2800pci_wait_bbp_rf_ready(struct rt2x00_dev *rt2x00dev)
{
	unsigned int i;
	u32 reg;

	for (i = 0; i < REGISTER_BUSY_COUNT; i++) {
		rt2800_register_read(rt2x00dev, MAC_STATUS_CFG, &reg);
		if (!rt2x00_get_field32(reg, MAC_STATUS_CFG_BBP_RF_BUSY))
			return 0;

		udelay(REGISTER_BUSY_DELAY);
	}

	ERROR(rt2x00dev, "BBP/RF register access failed, aborting.\n");
	return -EACCES;
}

static int rt2800pci_wait_bbp_ready(struct rt2x00_dev *rt2x00dev)
{
	unsigned int i;
	u8 value;

	/*
	 * BBP was enabled after firmware was loaded,
	 * but we need to reactivate it now.
	 */
	rt2800_register_write(rt2x00dev, H2M_BBP_AGENT, 0);
	rt2800_register_write(rt2x00dev, H2M_MAILBOX_CSR, 0);
	msleep(1);

	for (i = 0; i < REGISTER_BUSY_COUNT; i++) {
		rt2800_bbp_read(rt2x00dev, 0, &value);
		if ((value != 0xff) && (value != 0x00))
			return 0;
		udelay(REGISTER_BUSY_DELAY);
	}

	ERROR(rt2x00dev, "BBP register access failed, aborting.\n");
	return -EACCES;
}

static int rt2800pci_init_bbp(struct rt2x00_dev *rt2x00dev)
{
	unsigned int i;
	u16 eeprom;
	u8 reg_id;
	u8 value;

	if (unlikely(rt2800pci_wait_bbp_rf_ready(rt2x00dev) ||
		     rt2800pci_wait_bbp_ready(rt2x00dev)))
		return -EACCES;

	rt2800_bbp_write(rt2x00dev, 65, 0x2c);
	rt2800_bbp_write(rt2x00dev, 66, 0x38);
	rt2800_bbp_write(rt2x00dev, 69, 0x12);
	rt2800_bbp_write(rt2x00dev, 70, 0x0a);
	rt2800_bbp_write(rt2x00dev, 73, 0x10);
	rt2800_bbp_write(rt2x00dev, 81, 0x37);
	rt2800_bbp_write(rt2x00dev, 82, 0x62);
	rt2800_bbp_write(rt2x00dev, 83, 0x6a);
	rt2800_bbp_write(rt2x00dev, 84, 0x99);
	rt2800_bbp_write(rt2x00dev, 86, 0x00);
	rt2800_bbp_write(rt2x00dev, 91, 0x04);
	rt2800_bbp_write(rt2x00dev, 92, 0x00);
	rt2800_bbp_write(rt2x00dev, 103, 0x00);
	rt2800_bbp_write(rt2x00dev, 105, 0x05);

	if (rt2x00_rev(&rt2x00dev->chip) == RT2860C_VERSION) {
		rt2800_bbp_write(rt2x00dev, 69, 0x16);
		rt2800_bbp_write(rt2x00dev, 73, 0x12);
	}

	if (rt2x00_rev(&rt2x00dev->chip) > RT2860D_VERSION)
		rt2800_bbp_write(rt2x00dev, 84, 0x19);

	if (rt2x00_intf_is_pci(rt2x00dev) &&
	    rt2x00_rt(&rt2x00dev->chip, RT3052)) {
		rt2800_bbp_write(rt2x00dev, 31, 0x08);
		rt2800_bbp_write(rt2x00dev, 78, 0x0e);
		rt2800_bbp_write(rt2x00dev, 80, 0x08);
	}

	for (i = 0; i < EEPROM_BBP_SIZE; i++) {
		rt2x00_eeprom_read(rt2x00dev, EEPROM_BBP_START + i, &eeprom);

		if (eeprom != 0xffff && eeprom != 0x0000) {
			reg_id = rt2x00_get_field16(eeprom, EEPROM_BBP_REG_ID);
			value = rt2x00_get_field16(eeprom, EEPROM_BBP_VALUE);
			rt2800_bbp_write(rt2x00dev, reg_id, value);
		}
	}

	return 0;
}

static u8 rt2800pci_init_rx_filter(struct rt2x00_dev *rt2x00dev,
				   bool bw40, u8 rfcsr24, u8 filter_target)
{
	unsigned int i;
	u8 bbp;
	u8 rfcsr;
	u8 passband;
	u8 stopband;
	u8 overtuned = 0;

	rt2800_rfcsr_write(rt2x00dev, 24, rfcsr24);

	rt2800_bbp_read(rt2x00dev, 4, &bbp);
	rt2x00_set_field8(&bbp, BBP4_BANDWIDTH, 2 * bw40);
	rt2800_bbp_write(rt2x00dev, 4, bbp);

	rt2800_rfcsr_read(rt2x00dev, 22, &rfcsr);
	rt2x00_set_field8(&rfcsr, RFCSR22_BASEBAND_LOOPBACK, 1);
	rt2800_rfcsr_write(rt2x00dev, 22, rfcsr);

	/*
	 * Set power & frequency of passband test tone
	 */
	rt2800_bbp_write(rt2x00dev, 24, 0);

	for (i = 0; i < 100; i++) {
		rt2800_bbp_write(rt2x00dev, 25, 0x90);
		msleep(1);

		rt2800_bbp_read(rt2x00dev, 55, &passband);
		if (passband)
			break;
	}

	/*
	 * Set power & frequency of stopband test tone
	 */
	rt2800_bbp_write(rt2x00dev, 24, 0x06);

	for (i = 0; i < 100; i++) {
		rt2800_bbp_write(rt2x00dev, 25, 0x90);
		msleep(1);

		rt2800_bbp_read(rt2x00dev, 55, &stopband);

		if ((passband - stopband) <= filter_target) {
			rfcsr24++;
			overtuned += ((passband - stopband) == filter_target);
		} else
			break;

		rt2800_rfcsr_write(rt2x00dev, 24, rfcsr24);
	}

	rfcsr24 -= !!overtuned;

	rt2800_rfcsr_write(rt2x00dev, 24, rfcsr24);
	return rfcsr24;
}

static int rt2800pci_init_rfcsr(struct rt2x00_dev *rt2x00dev)
{
	u8 rfcsr;
	u8 bbp;

	if (rt2x00_intf_is_pci(rt2x00dev)) {
		if (!rt2x00_rf(&rt2x00dev->chip, RF3020) &&
		    !rt2x00_rf(&rt2x00dev->chip, RF3021) &&
		    !rt2x00_rf(&rt2x00dev->chip, RF3022))
			return 0;
	}

	/*
	 * Init RF calibration.
	 */
	rt2800_rfcsr_read(rt2x00dev, 30, &rfcsr);
	rt2x00_set_field8(&rfcsr, RFCSR30_RF_CALIBRATION, 1);
	rt2800_rfcsr_write(rt2x00dev, 30, rfcsr);
	msleep(1);
	rt2x00_set_field8(&rfcsr, RFCSR30_RF_CALIBRATION, 0);
	rt2800_rfcsr_write(rt2x00dev, 30, rfcsr);

	if (rt2x00_intf_is_pci(rt2x00dev)) {
		rt2800_rfcsr_write(rt2x00dev, 0, 0x50);
		rt2800_rfcsr_write(rt2x00dev, 1, 0x01);
		rt2800_rfcsr_write(rt2x00dev, 2, 0xf7);
		rt2800_rfcsr_write(rt2x00dev, 3, 0x75);
		rt2800_rfcsr_write(rt2x00dev, 4, 0x40);
		rt2800_rfcsr_write(rt2x00dev, 5, 0x03);
		rt2800_rfcsr_write(rt2x00dev, 6, 0x02);
		rt2800_rfcsr_write(rt2x00dev, 7, 0x50);
		rt2800_rfcsr_write(rt2x00dev, 8, 0x39);
		rt2800_rfcsr_write(rt2x00dev, 9, 0x0f);
		rt2800_rfcsr_write(rt2x00dev, 10, 0x60);
		rt2800_rfcsr_write(rt2x00dev, 11, 0x21);
		rt2800_rfcsr_write(rt2x00dev, 12, 0x75);
		rt2800_rfcsr_write(rt2x00dev, 13, 0x75);
		rt2800_rfcsr_write(rt2x00dev, 14, 0x90);
		rt2800_rfcsr_write(rt2x00dev, 15, 0x58);
		rt2800_rfcsr_write(rt2x00dev, 16, 0xb3);
		rt2800_rfcsr_write(rt2x00dev, 17, 0x92);
		rt2800_rfcsr_write(rt2x00dev, 18, 0x2c);
		rt2800_rfcsr_write(rt2x00dev, 19, 0x02);
		rt2800_rfcsr_write(rt2x00dev, 20, 0xba);
		rt2800_rfcsr_write(rt2x00dev, 21, 0xdb);
		rt2800_rfcsr_write(rt2x00dev, 22, 0x00);
		rt2800_rfcsr_write(rt2x00dev, 23, 0x31);
		rt2800_rfcsr_write(rt2x00dev, 24, 0x08);
		rt2800_rfcsr_write(rt2x00dev, 25, 0x01);
		rt2800_rfcsr_write(rt2x00dev, 26, 0x25);
		rt2800_rfcsr_write(rt2x00dev, 27, 0x23);
		rt2800_rfcsr_write(rt2x00dev, 28, 0x13);
		rt2800_rfcsr_write(rt2x00dev, 29, 0x83);
	}

	/*
	 * Set RX Filter calibration for 20MHz and 40MHz
	 */
	rt2x00dev->calibration[0] =
	    rt2800pci_init_rx_filter(rt2x00dev, false, 0x07, 0x16);
	rt2x00dev->calibration[1] =
	    rt2800pci_init_rx_filter(rt2x00dev, true, 0x27, 0x19);

	/*
	 * Set back to initial state
	 */
	rt2800_bbp_write(rt2x00dev, 24, 0);

	rt2800_rfcsr_read(rt2x00dev, 22, &rfcsr);
	rt2x00_set_field8(&rfcsr, RFCSR22_BASEBAND_LOOPBACK, 0);
	rt2800_rfcsr_write(rt2x00dev, 22, rfcsr);

	/*
	 * set BBP back to BW20
	 */
	rt2800_bbp_read(rt2x00dev, 4, &bbp);
	rt2x00_set_field8(&bbp, BBP4_BANDWIDTH, 0);
	rt2800_bbp_write(rt2x00dev, 4, bbp);

	return 0;
}

/*
 * Device state switch handlers.
 */
static void rt2800pci_toggle_rx(struct rt2x00_dev *rt2x00dev,
				enum dev_state state)
{
	u32 reg;

	rt2800_register_read(rt2x00dev, MAC_SYS_CTRL, &reg);
	rt2x00_set_field32(&reg, MAC_SYS_CTRL_ENABLE_RX,
			   (state == STATE_RADIO_RX_ON) ||
			   (state == STATE_RADIO_RX_ON_LINK));
	rt2800_register_write(rt2x00dev, MAC_SYS_CTRL, reg);
}

static void rt2800pci_toggle_irq(struct rt2x00_dev *rt2x00dev,
				 enum dev_state state)
{
	int mask = (state == STATE_RADIO_IRQ_ON);
	u32 reg;

	/*
	 * When interrupts are being enabled, the interrupt registers
	 * should clear the register to assure a clean state.
	 */
	if (state == STATE_RADIO_IRQ_ON) {
		rt2800_register_read(rt2x00dev, INT_SOURCE_CSR, &reg);
		rt2800_register_write(rt2x00dev, INT_SOURCE_CSR, reg);
	}

	rt2800_register_read(rt2x00dev, INT_MASK_CSR, &reg);
	rt2x00_set_field32(&reg, INT_MASK_CSR_RXDELAYINT, mask);
	rt2x00_set_field32(&reg, INT_MASK_CSR_TXDELAYINT, mask);
	rt2x00_set_field32(&reg, INT_MASK_CSR_RX_DONE, mask);
	rt2x00_set_field32(&reg, INT_MASK_CSR_AC0_DMA_DONE, mask);
	rt2x00_set_field32(&reg, INT_MASK_CSR_AC1_DMA_DONE, mask);
	rt2x00_set_field32(&reg, INT_MASK_CSR_AC2_DMA_DONE, mask);
	rt2x00_set_field32(&reg, INT_MASK_CSR_AC3_DMA_DONE, mask);
	rt2x00_set_field32(&reg, INT_MASK_CSR_HCCA_DMA_DONE, mask);
	rt2x00_set_field32(&reg, INT_MASK_CSR_MGMT_DMA_DONE, mask);
	rt2x00_set_field32(&reg, INT_MASK_CSR_MCU_COMMAND, mask);
	rt2x00_set_field32(&reg, INT_MASK_CSR_RXTX_COHERENT, mask);
	rt2x00_set_field32(&reg, INT_MASK_CSR_TBTT, mask);
	rt2x00_set_field32(&reg, INT_MASK_CSR_PRE_TBTT, mask);
	rt2x00_set_field32(&reg, INT_MASK_CSR_TX_FIFO_STATUS, mask);
	rt2x00_set_field32(&reg, INT_MASK_CSR_AUTO_WAKEUP, mask);
	rt2x00_set_field32(&reg, INT_MASK_CSR_GPTIMER, mask);
	rt2x00_set_field32(&reg, INT_MASK_CSR_RX_COHERENT, mask);
	rt2x00_set_field32(&reg, INT_MASK_CSR_TX_COHERENT, mask);
	rt2800_register_write(rt2x00dev, INT_MASK_CSR, reg);
}

static int rt2800pci_wait_wpdma_ready(struct rt2x00_dev *rt2x00dev)
{
	unsigned int i;
	u32 reg;

	for (i = 0; i < REGISTER_BUSY_COUNT; i++) {
		rt2800_register_read(rt2x00dev, WPDMA_GLO_CFG, &reg);
		if (!rt2x00_get_field32(reg, WPDMA_GLO_CFG_TX_DMA_BUSY) &&
		    !rt2x00_get_field32(reg, WPDMA_GLO_CFG_RX_DMA_BUSY))
			return 0;

		msleep(1);
	}

	ERROR(rt2x00dev, "WPDMA TX/RX busy, aborting.\n");
	return -EACCES;
}

static int rt2800pci_enable_radio(struct rt2x00_dev *rt2x00dev)
{
	u32 reg;
	u16 word;

	/*
	 * Initialize all registers.
	 */
	if (unlikely(rt2800pci_wait_wpdma_ready(rt2x00dev) ||
		     rt2800pci_init_queues(rt2x00dev) ||
		     rt2800pci_init_registers(rt2x00dev) ||
		     rt2800pci_wait_wpdma_ready(rt2x00dev) ||
		     rt2800pci_init_bbp(rt2x00dev) ||
		     rt2800pci_init_rfcsr(rt2x00dev)))
		return -EIO;

	/*
	 * Send signal to firmware during boot time.
	 */
	rt2800_mcu_request(rt2x00dev, MCU_BOOT_SIGNAL, 0xff, 0, 0);

	/*
	 * Enable RX.
	 */
	rt2800_register_read(rt2x00dev, MAC_SYS_CTRL, &reg);
	rt2x00_set_field32(&reg, MAC_SYS_CTRL_ENABLE_TX, 1);
	rt2x00_set_field32(&reg, MAC_SYS_CTRL_ENABLE_RX, 0);
	rt2800_register_write(rt2x00dev, MAC_SYS_CTRL, reg);

	rt2800_register_read(rt2x00dev, WPDMA_GLO_CFG, &reg);
	rt2x00_set_field32(&reg, WPDMA_GLO_CFG_ENABLE_TX_DMA, 1);
	rt2x00_set_field32(&reg, WPDMA_GLO_CFG_ENABLE_RX_DMA, 1);
	rt2x00_set_field32(&reg, WPDMA_GLO_CFG_WP_DMA_BURST_SIZE, 2);
	rt2x00_set_field32(&reg, WPDMA_GLO_CFG_TX_WRITEBACK_DONE, 1);
	rt2800_register_write(rt2x00dev, WPDMA_GLO_CFG, reg);

	rt2800_register_read(rt2x00dev, MAC_SYS_CTRL, &reg);
	rt2x00_set_field32(&reg, MAC_SYS_CTRL_ENABLE_TX, 1);
	rt2x00_set_field32(&reg, MAC_SYS_CTRL_ENABLE_RX, 1);
	rt2800_register_write(rt2x00dev, MAC_SYS_CTRL, reg);

	/*
	 * Initialize LED control
	 */
	rt2x00_eeprom_read(rt2x00dev, EEPROM_LED1, &word);
	rt2800_mcu_request(rt2x00dev, MCU_LED_1, 0xff,
			      word & 0xff, (word >> 8) & 0xff);

	rt2x00_eeprom_read(rt2x00dev, EEPROM_LED2, &word);
	rt2800_mcu_request(rt2x00dev, MCU_LED_2, 0xff,
			      word & 0xff, (word >> 8) & 0xff);

	rt2x00_eeprom_read(rt2x00dev, EEPROM_LED3, &word);
	rt2800_mcu_request(rt2x00dev, MCU_LED_3, 0xff,
			      word & 0xff, (word >> 8) & 0xff);

	return 0;
}

static void rt2800pci_disable_radio(struct rt2x00_dev *rt2x00dev)
{
	u32 reg;

	rt2800_register_read(rt2x00dev, WPDMA_GLO_CFG, &reg);
	rt2x00_set_field32(&reg, WPDMA_GLO_CFG_ENABLE_TX_DMA, 0);
	rt2x00_set_field32(&reg, WPDMA_GLO_CFG_TX_DMA_BUSY, 0);
	rt2x00_set_field32(&reg, WPDMA_GLO_CFG_ENABLE_RX_DMA, 0);
	rt2x00_set_field32(&reg, WPDMA_GLO_CFG_RX_DMA_BUSY, 0);
	rt2x00_set_field32(&reg, WPDMA_GLO_CFG_TX_WRITEBACK_DONE, 1);
	rt2800_register_write(rt2x00dev, WPDMA_GLO_CFG, reg);

	rt2800_register_write(rt2x00dev, MAC_SYS_CTRL, 0);
	rt2800_register_write(rt2x00dev, PWR_PIN_CFG, 0);
	rt2800_register_write(rt2x00dev, TX_PIN_CFG, 0);

	rt2800_register_write(rt2x00dev, PBF_SYS_CTRL, 0x00001280);

	rt2800_register_read(rt2x00dev, WPDMA_RST_IDX, &reg);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX0, 1);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX1, 1);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX2, 1);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX3, 1);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX4, 1);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX5, 1);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DRX_IDX0, 1);
	rt2800_register_write(rt2x00dev, WPDMA_RST_IDX, reg);

	rt2800_register_write(rt2x00dev, PBF_SYS_CTRL, 0x00000e1f);
	rt2800_register_write(rt2x00dev, PBF_SYS_CTRL, 0x00000e00);

	/* Wait for DMA, ignore error */
	rt2800pci_wait_wpdma_ready(rt2x00dev);
}

static int rt2800pci_set_state(struct rt2x00_dev *rt2x00dev,
			       enum dev_state state)
{
	/*
	 * Always put the device to sleep (even when we intend to wakeup!)
	 * if the device is booting and wasn't asleep it will return
	 * failure when attempting to wakeup.
	 */
	rt2800_mcu_request(rt2x00dev, MCU_SLEEP, 0xff, 0, 2);

	if (state == STATE_AWAKE) {
		rt2800_mcu_request(rt2x00dev, MCU_WAKEUP, TOKEN_WAKUP, 0, 0);
		rt2800pci_mcu_status(rt2x00dev, TOKEN_WAKUP);
	}

	return 0;
}

static int rt2800pci_set_device_state(struct rt2x00_dev *rt2x00dev,
				      enum dev_state state)
{
	int retval = 0;

	switch (state) {
	case STATE_RADIO_ON:
		/*
		 * Before the radio can be enabled, the device first has
		 * to be woken up. After that it needs a bit of time
		 * to be fully awake and then the radio can be enabled.
		 */
		rt2800pci_set_state(rt2x00dev, STATE_AWAKE);
		msleep(1);
		retval = rt2800pci_enable_radio(rt2x00dev);
		break;
	case STATE_RADIO_OFF:
		/*
		 * After the radio has been disabled, the device should
		 * be put to sleep for powersaving.
		 */
		rt2800pci_disable_radio(rt2x00dev);
		rt2800pci_set_state(rt2x00dev, STATE_SLEEP);
		break;
	case STATE_RADIO_RX_ON:
	case STATE_RADIO_RX_ON_LINK:
	case STATE_RADIO_RX_OFF:
	case STATE_RADIO_RX_OFF_LINK:
		rt2800pci_toggle_rx(rt2x00dev, state);
		break;
	case STATE_RADIO_IRQ_ON:
	case STATE_RADIO_IRQ_OFF:
		rt2800pci_toggle_irq(rt2x00dev, state);
		break;
	case STATE_DEEP_SLEEP:
	case STATE_SLEEP:
	case STATE_STANDBY:
	case STATE_AWAKE:
		retval = rt2800pci_set_state(rt2x00dev, state);
		break;
	default:
		retval = -ENOTSUPP;
		break;
	}

	if (unlikely(retval))
		ERROR(rt2x00dev, "Device failed to enter state %d (%d).\n",
		      state, retval);

	return retval;
}

/*
 * TX descriptor initialization
 */
static void rt2800pci_write_tx_desc(struct rt2x00_dev *rt2x00dev,
				    struct sk_buff *skb,
				    struct txentry_desc *txdesc)
{
	struct skb_frame_desc *skbdesc = get_skb_frame_desc(skb);
	__le32 *txd = skbdesc->desc;
	__le32 *txwi = (__le32 *)(skb->data - rt2x00dev->hw->extra_tx_headroom);
	u32 word;

	/*
	 * Initialize TX Info descriptor
	 */
	rt2x00_desc_read(txwi, 0, &word);
	rt2x00_set_field32(&word, TXWI_W0_FRAG,
			   test_bit(ENTRY_TXD_MORE_FRAG, &txdesc->flags));
	rt2x00_set_field32(&word, TXWI_W0_MIMO_PS, 0);
	rt2x00_set_field32(&word, TXWI_W0_CF_ACK, 0);
	rt2x00_set_field32(&word, TXWI_W0_TS,
			   test_bit(ENTRY_TXD_REQ_TIMESTAMP, &txdesc->flags));
	rt2x00_set_field32(&word, TXWI_W0_AMPDU,
			   test_bit(ENTRY_TXD_HT_AMPDU, &txdesc->flags));
	rt2x00_set_field32(&word, TXWI_W0_MPDU_DENSITY, txdesc->mpdu_density);
	rt2x00_set_field32(&word, TXWI_W0_TX_OP, txdesc->ifs);
	rt2x00_set_field32(&word, TXWI_W0_MCS, txdesc->mcs);
	rt2x00_set_field32(&word, TXWI_W0_BW,
			   test_bit(ENTRY_TXD_HT_BW_40, &txdesc->flags));
	rt2x00_set_field32(&word, TXWI_W0_SHORT_GI,
			   test_bit(ENTRY_TXD_HT_SHORT_GI, &txdesc->flags));
	rt2x00_set_field32(&word, TXWI_W0_STBC, txdesc->stbc);
	rt2x00_set_field32(&word, TXWI_W0_PHYMODE, txdesc->rate_mode);
	rt2x00_desc_write(txwi, 0, word);

	rt2x00_desc_read(txwi, 1, &word);
	rt2x00_set_field32(&word, TXWI_W1_ACK,
			   test_bit(ENTRY_TXD_ACK, &txdesc->flags));
	rt2x00_set_field32(&word, TXWI_W1_NSEQ,
			   test_bit(ENTRY_TXD_GENERATE_SEQ, &txdesc->flags));
	rt2x00_set_field32(&word, TXWI_W1_BW_WIN_SIZE, txdesc->ba_size);
	rt2x00_set_field32(&word, TXWI_W1_WIRELESS_CLI_ID,
			   test_bit(ENTRY_TXD_ENCRYPT, &txdesc->flags) ?
			   txdesc->key_idx : 0xff);
	rt2x00_set_field32(&word, TXWI_W1_MPDU_TOTAL_BYTE_COUNT,
			   skb->len - txdesc->l2pad);
	rt2x00_set_field32(&word, TXWI_W1_PACKETID,
			   skbdesc->entry->queue->qid + 1);
	rt2x00_desc_write(txwi, 1, word);

	/*
	 * Always write 0 to IV/EIV fields, hardware will insert the IV
	 * from the IVEIV register when TXD_W3_WIV is set to 0.
	 * When TXD_W3_WIV is set to 1 it will use the IV data
	 * from the descriptor. The TXWI_W1_WIRELESS_CLI_ID indicates which
	 * crypto entry in the registers should be used to encrypt the frame.
	 */
	_rt2x00_desc_write(txwi, 2, 0 /* skbdesc->iv[0] */);
	_rt2x00_desc_write(txwi, 3, 0 /* skbdesc->iv[1] */);

	/*
	 * The buffers pointed by SD_PTR0/SD_LEN0 and SD_PTR1/SD_LEN1
	 * must contains a TXWI structure + 802.11 header + padding + 802.11
	 * data. We choose to have SD_PTR0/SD_LEN0 only contains TXWI and
	 * SD_PTR1/SD_LEN1 contains 802.11 header + padding + 802.11
	 * data. It means that LAST_SEC0 is always 0.
	 */

	/*
	 * Initialize TX descriptor
	 */
	rt2x00_desc_read(txd, 0, &word);
	rt2x00_set_field32(&word, TXD_W0_SD_PTR0, skbdesc->skb_dma);
	rt2x00_desc_write(txd, 0, word);

	rt2x00_desc_read(txd, 1, &word);
	rt2x00_set_field32(&word, TXD_W1_SD_LEN1, skb->len);
	rt2x00_set_field32(&word, TXD_W1_LAST_SEC1,
			   !test_bit(ENTRY_TXD_MORE_FRAG, &txdesc->flags));
	rt2x00_set_field32(&word, TXD_W1_BURST,
			   test_bit(ENTRY_TXD_BURST, &txdesc->flags));
	rt2x00_set_field32(&word, TXD_W1_SD_LEN0,
			   rt2x00dev->hw->extra_tx_headroom);
	rt2x00_set_field32(&word, TXD_W1_LAST_SEC0, 0);
	rt2x00_set_field32(&word, TXD_W1_DMA_DONE, 0);
	rt2x00_desc_write(txd, 1, word);

	rt2x00_desc_read(txd, 2, &word);
	rt2x00_set_field32(&word, TXD_W2_SD_PTR1,
			   skbdesc->skb_dma + rt2x00dev->hw->extra_tx_headroom);
	rt2x00_desc_write(txd, 2, word);

	rt2x00_desc_read(txd, 3, &word);
	rt2x00_set_field32(&word, TXD_W3_WIV,
			   !test_bit(ENTRY_TXD_ENCRYPT_IV, &txdesc->flags));
	rt2x00_set_field32(&word, TXD_W3_QSEL, 2);
	rt2x00_desc_write(txd, 3, word);
}

/*
 * TX data initialization
 */
static void rt2800pci_write_beacon(struct queue_entry *entry)
{
	struct rt2x00_dev *rt2x00dev = entry->queue->rt2x00dev;
	struct skb_frame_desc *skbdesc = get_skb_frame_desc(entry->skb);
	unsigned int beacon_base;
	u32 reg;

	/*
	 * Disable beaconing while we are reloading the beacon data,
	 * otherwise we might be sending out invalid data.
	 */
	rt2800_register_read(rt2x00dev, BCN_TIME_CFG, &reg);
	rt2x00_set_field32(&reg, BCN_TIME_CFG_BEACON_GEN, 0);
	rt2800_register_write(rt2x00dev, BCN_TIME_CFG, reg);

	/*
	 * Write entire beacon with descriptor to register.
	 */
	beacon_base = HW_BEACON_OFFSET(entry->entry_idx);
	rt2800_register_multiwrite(rt2x00dev,
				      beacon_base,
				      skbdesc->desc, skbdesc->desc_len);
	rt2800_register_multiwrite(rt2x00dev,
				      beacon_base + skbdesc->desc_len,
				      entry->skb->data, entry->skb->len);

	/*
	 * Clean up beacon skb.
	 */
	dev_kfree_skb_any(entry->skb);
	entry->skb = NULL;
}

static void rt2800pci_kick_tx_queue(struct rt2x00_dev *rt2x00dev,
				    const enum data_queue_qid queue_idx)
{
	struct data_queue *queue;
	unsigned int idx, qidx = 0;
	u32 reg;

	if (queue_idx == QID_BEACON) {
		rt2800_register_read(rt2x00dev, BCN_TIME_CFG, &reg);
		if (!rt2x00_get_field32(reg, BCN_TIME_CFG_BEACON_GEN)) {
			rt2x00_set_field32(&reg, BCN_TIME_CFG_TSF_TICKING, 1);
			rt2x00_set_field32(&reg, BCN_TIME_CFG_TBTT_ENABLE, 1);
			rt2x00_set_field32(&reg, BCN_TIME_CFG_BEACON_GEN, 1);
			rt2800_register_write(rt2x00dev, BCN_TIME_CFG, reg);
		}
		return;
	}

	if (queue_idx > QID_HCCA && queue_idx != QID_MGMT)
		return;

	queue = rt2x00queue_get_queue(rt2x00dev, queue_idx);
	idx = queue->index[Q_INDEX];

	if (queue_idx == QID_MGMT)
		qidx = 5;
	else
		qidx = queue_idx;

	rt2800_register_write(rt2x00dev, TX_CTX_IDX(qidx), idx);
}

static void rt2800pci_kill_tx_queue(struct rt2x00_dev *rt2x00dev,
				    const enum data_queue_qid qid)
{
	u32 reg;

	if (qid == QID_BEACON) {
		rt2800_register_write(rt2x00dev, BCN_TIME_CFG, 0);
		return;
	}

	rt2800_register_read(rt2x00dev, WPDMA_RST_IDX, &reg);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX0, (qid == QID_AC_BE));
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX1, (qid == QID_AC_BK));
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX2, (qid == QID_AC_VI));
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX3, (qid == QID_AC_VO));
	rt2800_register_write(rt2x00dev, WPDMA_RST_IDX, reg);
}

/*
 * RX control handlers
 */
static void rt2800pci_fill_rxdone(struct queue_entry *entry,
				  struct rxdone_entry_desc *rxdesc)
{
	struct rt2x00_dev *rt2x00dev = entry->queue->rt2x00dev;
	struct skb_frame_desc *skbdesc = get_skb_frame_desc(entry->skb);
	struct queue_entry_priv_pci *entry_priv = entry->priv_data;
	__le32 *rxd = entry_priv->desc;
	__le32 *rxwi = (__le32 *)entry->skb->data;
	u32 rxd3;
	u32 rxwi0;
	u32 rxwi1;
	u32 rxwi2;
	u32 rxwi3;

	rt2x00_desc_read(rxd, 3, &rxd3);
	rt2x00_desc_read(rxwi, 0, &rxwi0);
	rt2x00_desc_read(rxwi, 1, &rxwi1);
	rt2x00_desc_read(rxwi, 2, &rxwi2);
	rt2x00_desc_read(rxwi, 3, &rxwi3);

	if (rt2x00_get_field32(rxd3, RXD_W3_CRC_ERROR))
		rxdesc->flags |= RX_FLAG_FAILED_FCS_CRC;

	if (test_bit(CONFIG_SUPPORT_HW_CRYPTO, &rt2x00dev->flags)) {
		/*
		 * Unfortunately we don't know the cipher type used during
		 * decryption. This prevents us from correct providing
		 * correct statistics through debugfs.
		 */
		rxdesc->cipher = rt2x00_get_field32(rxwi0, RXWI_W0_UDF);
		rxdesc->cipher_status =
		    rt2x00_get_field32(rxd3, RXD_W3_CIPHER_ERROR);
	}

	if (rt2x00_get_field32(rxd3, RXD_W3_DECRYPTED)) {
		/*
		 * Hardware has stripped IV/EIV data from 802.11 frame during
		 * decryption. Unfortunately the descriptor doesn't contain
		 * any fields with the EIV/IV data either, so they can't
		 * be restored by rt2x00lib.
		 */
		rxdesc->flags |= RX_FLAG_IV_STRIPPED;

		if (rxdesc->cipher_status == RX_CRYPTO_SUCCESS)
			rxdesc->flags |= RX_FLAG_DECRYPTED;
		else if (rxdesc->cipher_status == RX_CRYPTO_FAIL_MIC)
			rxdesc->flags |= RX_FLAG_MMIC_ERROR;
	}

	if (rt2x00_get_field32(rxd3, RXD_W3_MY_BSS))
		rxdesc->dev_flags |= RXDONE_MY_BSS;

	if (rt2x00_get_field32(rxd3, RXD_W3_L2PAD)) {
		rxdesc->dev_flags |= RXDONE_L2PAD;
		skbdesc->flags |= SKBDESC_L2_PADDED;
	}

	if (rt2x00_get_field32(rxwi1, RXWI_W1_SHORT_GI))
		rxdesc->flags |= RX_FLAG_SHORT_GI;

	if (rt2x00_get_field32(rxwi1, RXWI_W1_BW))
		rxdesc->flags |= RX_FLAG_40MHZ;

	/*
	 * Detect RX rate, always use MCS as signal type.
	 */
	rxdesc->dev_flags |= RXDONE_SIGNAL_MCS;
	rxdesc->rate_mode = rt2x00_get_field32(rxwi1, RXWI_W1_PHYMODE);
	rxdesc->signal = rt2x00_get_field32(rxwi1, RXWI_W1_MCS);

	/*
	 * Mask of 0x8 bit to remove the short preamble flag.
	 */
	if (rxdesc->rate_mode == RATE_MODE_CCK)
		rxdesc->signal &= ~0x8;

	rxdesc->rssi =
	    (rt2x00_get_field32(rxwi2, RXWI_W2_RSSI0) +
	     rt2x00_get_field32(rxwi2, RXWI_W2_RSSI1)) / 2;

	rxdesc->noise =
	    (rt2x00_get_field32(rxwi3, RXWI_W3_SNR0) +
	     rt2x00_get_field32(rxwi3, RXWI_W3_SNR1)) / 2;

	rxdesc->size = rt2x00_get_field32(rxwi0, RXWI_W0_MPDU_TOTAL_BYTE_COUNT);

	/*
	 * Set RX IDX in register to inform hardware that we have handled
	 * this entry and it is available for reuse again.
	 */
	rt2800_register_write(rt2x00dev, RX_CRX_IDX, entry->entry_idx);

	/*
	 * Remove TXWI descriptor from start of buffer.
	 */
	skb_pull(entry->skb, RXWI_DESC_SIZE);
	skb_trim(entry->skb, rxdesc->size);
}

/*
 * Interrupt functions.
 */
static void rt2800pci_txdone(struct rt2x00_dev *rt2x00dev)
{
	struct data_queue *queue;
	struct queue_entry *entry;
	struct queue_entry *entry_done;
	struct queue_entry_priv_pci *entry_priv;
	struct txdone_entry_desc txdesc;
	u32 word;
	u32 reg;
	u32 old_reg;
	unsigned int type;
	unsigned int index;
	u16 mcs, real_mcs;

	/*
	 * During each loop we will compare the freshly read
	 * TX_STA_FIFO register value with the value read from
	 * the previous loop. If the 2 values are equal then
	 * we should stop processing because the chance it
	 * quite big that the device has been unplugged and
	 * we risk going into an endless loop.
	 */
	old_reg = 0;

	while (1) {
		rt2800_register_read(rt2x00dev, TX_STA_FIFO, &reg);
		if (!rt2x00_get_field32(reg, TX_STA_FIFO_VALID))
			break;

		if (old_reg == reg)
			break;
		old_reg = reg;

		/*
		 * Skip this entry when it contains an invalid
		 * queue identication number.
		 */
		type = rt2x00_get_field32(reg, TX_STA_FIFO_PID_TYPE) - 1;
		if (type >= QID_RX)
			continue;

		queue = rt2x00queue_get_queue(rt2x00dev, type);
		if (unlikely(!queue))
			continue;

		/*
		 * Skip this entry when it contains an invalid
		 * index number.
		 */
		index = rt2x00_get_field32(reg, TX_STA_FIFO_WCID) - 1;
		if (unlikely(index >= queue->limit))
			continue;

		entry = &queue->entries[index];
		entry_priv = entry->priv_data;
		rt2x00_desc_read((__le32 *)entry->skb->data, 0, &word);

		entry_done = rt2x00queue_get_entry(queue, Q_INDEX_DONE);
		while (entry != entry_done) {
			/*
			 * Catch up.
			 * Just report any entries we missed as failed.
			 */
			WARNING(rt2x00dev,
				"TX status report missed for entry %d\n",
				entry_done->entry_idx);

			txdesc.flags = 0;
			__set_bit(TXDONE_UNKNOWN, &txdesc.flags);
			txdesc.retry = 0;

			rt2x00lib_txdone(entry_done, &txdesc);
			entry_done = rt2x00queue_get_entry(queue, Q_INDEX_DONE);
		}

		/*
		 * Obtain the status about this packet.
		 */
		txdesc.flags = 0;
		if (rt2x00_get_field32(reg, TX_STA_FIFO_TX_SUCCESS))
			__set_bit(TXDONE_SUCCESS, &txdesc.flags);
		else
			__set_bit(TXDONE_FAILURE, &txdesc.flags);

		/*
		 * Ralink has a retry mechanism using a global fallback
		 * table. We setup this fallback table to try immediate
		 * lower rate for all rates. In the TX_STA_FIFO,
		 * the MCS field contains the MCS used for the successfull
		 * transmission. If the first transmission succeed,
		 * we have mcs == tx_mcs. On the second transmission,
		 * we have mcs = tx_mcs - 1. So the number of
		 * retry is (tx_mcs - mcs).
		 */
		mcs = rt2x00_get_field32(word, TXWI_W0_MCS);
		real_mcs = rt2x00_get_field32(reg, TX_STA_FIFO_MCS);
		__set_bit(TXDONE_FALLBACK, &txdesc.flags);
		txdesc.retry = mcs - min(mcs, real_mcs);

		rt2x00lib_txdone(entry, &txdesc);
	}
}

static irqreturn_t rt2800pci_interrupt(int irq, void *dev_instance)
{
	struct rt2x00_dev *rt2x00dev = dev_instance;
	u32 reg;

	/* Read status and ACK all interrupts */
	rt2800_register_read(rt2x00dev, INT_SOURCE_CSR, &reg);
	rt2800_register_write(rt2x00dev, INT_SOURCE_CSR, reg);

	if (!reg)
		return IRQ_NONE;

	if (!test_bit(DEVICE_STATE_ENABLED_RADIO, &rt2x00dev->flags))
		return IRQ_HANDLED;

	/*
	 * 1 - Rx ring done interrupt.
	 */
	if (rt2x00_get_field32(reg, INT_SOURCE_CSR_RX_DONE))
		rt2x00pci_rxdone(rt2x00dev);

	if (rt2x00_get_field32(reg, INT_SOURCE_CSR_TX_FIFO_STATUS))
		rt2800pci_txdone(rt2x00dev);

	return IRQ_HANDLED;
}

/*
 * Device probe functions.
 */
static int rt2800pci_validate_eeprom(struct rt2x00_dev *rt2x00dev)
{
	u16 word;
	u8 *mac;
	u8 default_lna_gain;

	/*
	 * Read EEPROM into buffer
	 */
	switch(rt2x00dev->chip.rt) {
	case RT2880:
	case RT3052:
		rt2800pci_read_eeprom_soc(rt2x00dev);
		break;
	case RT3090:
		rt2800pci_read_eeprom_efuse(rt2x00dev);
		break;
	default:
		rt2800pci_read_eeprom_pci(rt2x00dev);
		break;
	}

	/*
	 * Start validation of the data that has been read.
	 */
	mac = rt2x00_eeprom_addr(rt2x00dev, EEPROM_MAC_ADDR_0);
	if (!is_valid_ether_addr(mac)) {
		random_ether_addr(mac);
		EEPROM(rt2x00dev, "MAC: %pM\n", mac);
	}

	rt2x00_eeprom_read(rt2x00dev, EEPROM_ANTENNA, &word);
	if (word == 0xffff) {
		rt2x00_set_field16(&word, EEPROM_ANTENNA_RXPATH, 2);
		rt2x00_set_field16(&word, EEPROM_ANTENNA_TXPATH, 1);
		rt2x00_set_field16(&word, EEPROM_ANTENNA_RF_TYPE, RF2820);
		rt2x00_eeprom_write(rt2x00dev, EEPROM_ANTENNA, word);
		EEPROM(rt2x00dev, "Antenna: 0x%04x\n", word);
	} else if (rt2x00_rev(&rt2x00dev->chip) < RT2883_VERSION) {
		/*
		 * There is a max of 2 RX streams for RT2860 series
		 */
		if (rt2x00_get_field16(word, EEPROM_ANTENNA_RXPATH) > 2)
			rt2x00_set_field16(&word, EEPROM_ANTENNA_RXPATH, 2);
		rt2x00_eeprom_write(rt2x00dev, EEPROM_ANTENNA, word);
	}

	rt2x00_eeprom_read(rt2x00dev, EEPROM_NIC, &word);
	if (word == 0xffff) {
		rt2x00_set_field16(&word, EEPROM_NIC_HW_RADIO, 0);
		rt2x00_set_field16(&word, EEPROM_NIC_DYNAMIC_TX_AGC, 0);
		rt2x00_set_field16(&word, EEPROM_NIC_EXTERNAL_LNA_BG, 0);
		rt2x00_set_field16(&word, EEPROM_NIC_EXTERNAL_LNA_A, 0);
		rt2x00_set_field16(&word, EEPROM_NIC_CARDBUS_ACCEL, 0);
		rt2x00_set_field16(&word, EEPROM_NIC_BW40M_SB_BG, 0);
		rt2x00_set_field16(&word, EEPROM_NIC_BW40M_SB_A, 0);
		rt2x00_set_field16(&word, EEPROM_NIC_WPS_PBC, 0);
		rt2x00_set_field16(&word, EEPROM_NIC_BW40M_BG, 0);
		rt2x00_set_field16(&word, EEPROM_NIC_BW40M_A, 0);
		rt2x00_eeprom_write(rt2x00dev, EEPROM_NIC, word);
		EEPROM(rt2x00dev, "NIC: 0x%04x\n", word);
	}

	rt2x00_eeprom_read(rt2x00dev, EEPROM_FREQ, &word);
	if ((word & 0x00ff) == 0x00ff) {
		rt2x00_set_field16(&word, EEPROM_FREQ_OFFSET, 0);
		rt2x00_set_field16(&word, EEPROM_FREQ_LED_MODE,
				   LED_MODE_TXRX_ACTIVITY);
		rt2x00_set_field16(&word, EEPROM_FREQ_LED_POLARITY, 0);
		rt2x00_eeprom_write(rt2x00dev, EEPROM_FREQ, word);
		rt2x00_eeprom_write(rt2x00dev, EEPROM_LED1, 0x5555);
		rt2x00_eeprom_write(rt2x00dev, EEPROM_LED2, 0x2221);
		rt2x00_eeprom_write(rt2x00dev, EEPROM_LED3, 0xa9f8);
		EEPROM(rt2x00dev, "Freq: 0x%04x\n", word);
	}

	/*
	 * During the LNA validation we are going to use
	 * lna0 as correct value. Note that EEPROM_LNA
	 * is never validated.
	 */
	rt2x00_eeprom_read(rt2x00dev, EEPROM_LNA, &word);
	default_lna_gain = rt2x00_get_field16(word, EEPROM_LNA_A0);

	rt2x00_eeprom_read(rt2x00dev, EEPROM_RSSI_BG, &word);
	if (abs(rt2x00_get_field16(word, EEPROM_RSSI_BG_OFFSET0)) > 10)
		rt2x00_set_field16(&word, EEPROM_RSSI_BG_OFFSET0, 0);
	if (abs(rt2x00_get_field16(word, EEPROM_RSSI_BG_OFFSET1)) > 10)
		rt2x00_set_field16(&word, EEPROM_RSSI_BG_OFFSET1, 0);
	rt2x00_eeprom_write(rt2x00dev, EEPROM_RSSI_BG, word);

	rt2x00_eeprom_read(rt2x00dev, EEPROM_RSSI_BG2, &word);
	if (abs(rt2x00_get_field16(word, EEPROM_RSSI_BG2_OFFSET2)) > 10)
		rt2x00_set_field16(&word, EEPROM_RSSI_BG2_OFFSET2, 0);
	if (rt2x00_get_field16(word, EEPROM_RSSI_BG2_LNA_A1) == 0x00 ||
	    rt2x00_get_field16(word, EEPROM_RSSI_BG2_LNA_A1) == 0xff)
		rt2x00_set_field16(&word, EEPROM_RSSI_BG2_LNA_A1,
				   default_lna_gain);
	rt2x00_eeprom_write(rt2x00dev, EEPROM_RSSI_BG2, word);

	rt2x00_eeprom_read(rt2x00dev, EEPROM_RSSI_A, &word);
	if (abs(rt2x00_get_field16(word, EEPROM_RSSI_A_OFFSET0)) > 10)
		rt2x00_set_field16(&word, EEPROM_RSSI_A_OFFSET0, 0);
	if (abs(rt2x00_get_field16(word, EEPROM_RSSI_A_OFFSET1)) > 10)
		rt2x00_set_field16(&word, EEPROM_RSSI_A_OFFSET1, 0);
	rt2x00_eeprom_write(rt2x00dev, EEPROM_RSSI_A, word);

	rt2x00_eeprom_read(rt2x00dev, EEPROM_RSSI_A2, &word);
	if (abs(rt2x00_get_field16(word, EEPROM_RSSI_A2_OFFSET2)) > 10)
		rt2x00_set_field16(&word, EEPROM_RSSI_A2_OFFSET2, 0);
	if (rt2x00_get_field16(word, EEPROM_RSSI_A2_LNA_A2) == 0x00 ||
	    rt2x00_get_field16(word, EEPROM_RSSI_A2_LNA_A2) == 0xff)
		rt2x00_set_field16(&word, EEPROM_RSSI_A2_LNA_A2,
				   default_lna_gain);
	rt2x00_eeprom_write(rt2x00dev, EEPROM_RSSI_A2, word);

	return 0;
}

static int rt2800pci_init_eeprom(struct rt2x00_dev *rt2x00dev)
{
	u32 reg;
	u16 value;
	u16 eeprom;

	/*
	 * Read EEPROM word for configuration.
	 */
	rt2x00_eeprom_read(rt2x00dev, EEPROM_ANTENNA, &eeprom);

	/*
	 * Identify RF chipset.
	 */
	value = rt2x00_get_field16(eeprom, EEPROM_ANTENNA_RF_TYPE);
	rt2800_register_read(rt2x00dev, MAC_CSR0, &reg);
	rt2x00_set_chip_rf(rt2x00dev, value, reg);

	if (!rt2x00_rf(&rt2x00dev->chip, RF2820) &&
	    !rt2x00_rf(&rt2x00dev->chip, RF2850) &&
	    !rt2x00_rf(&rt2x00dev->chip, RF2720) &&
	    !rt2x00_rf(&rt2x00dev->chip, RF2750) &&
	    !rt2x00_rf(&rt2x00dev->chip, RF3020) &&
	    !rt2x00_rf(&rt2x00dev->chip, RF2020) &&
	    !rt2x00_rf(&rt2x00dev->chip, RF3021) &&
	    !rt2x00_rf(&rt2x00dev->chip, RF3022)) {
		ERROR(rt2x00dev, "Invalid RF chipset detected.\n");
		return -ENODEV;
	}

	/*
	 * Identify default antenna configuration.
	 */
	rt2x00dev->default_ant.tx =
	    rt2x00_get_field16(eeprom, EEPROM_ANTENNA_TXPATH);
	rt2x00dev->default_ant.rx =
	    rt2x00_get_field16(eeprom, EEPROM_ANTENNA_RXPATH);

	/*
	 * Read frequency offset and RF programming sequence.
	 */
	rt2x00_eeprom_read(rt2x00dev, EEPROM_FREQ, &eeprom);
	rt2x00dev->freq_offset = rt2x00_get_field16(eeprom, EEPROM_FREQ_OFFSET);

	/*
	 * Read external LNA informations.
	 */
	rt2x00_eeprom_read(rt2x00dev, EEPROM_NIC, &eeprom);

	if (rt2x00_get_field16(eeprom, EEPROM_NIC_EXTERNAL_LNA_A))
		__set_bit(CONFIG_EXTERNAL_LNA_A, &rt2x00dev->flags);
	if (rt2x00_get_field16(eeprom, EEPROM_NIC_EXTERNAL_LNA_BG))
		__set_bit(CONFIG_EXTERNAL_LNA_BG, &rt2x00dev->flags);

	/*
	 * Detect if this device has an hardware controlled radio.
	 */
	if (rt2x00_get_field16(eeprom, EEPROM_NIC_HW_RADIO))
		__set_bit(CONFIG_SUPPORT_HW_BUTTON, &rt2x00dev->flags);

	/*
	 * Store led settings, for correct led behaviour.
	 */
#ifdef CONFIG_RT2X00_LIB_LEDS
	rt2800_init_led(rt2x00dev, &rt2x00dev->led_radio, LED_TYPE_RADIO);
	rt2800_init_led(rt2x00dev, &rt2x00dev->led_assoc, LED_TYPE_ASSOC);
	rt2800_init_led(rt2x00dev, &rt2x00dev->led_qual, LED_TYPE_QUALITY);

	rt2x00_eeprom_read(rt2x00dev, EEPROM_FREQ, &rt2x00dev->led_mcu_reg);
#endif /* CONFIG_RT2X00_LIB_LEDS */

	return 0;
}

/*
 * RF value list for rt2860
 * Supports: 2.4 GHz (all) & 5.2 GHz (RF2850 & RF2750)
 */
static const struct rf_channel rf_vals[] = {
	{ 1,  0x18402ecc, 0x184c0786, 0x1816b455, 0x1800510b },
	{ 2,  0x18402ecc, 0x184c0786, 0x18168a55, 0x1800519f },
	{ 3,  0x18402ecc, 0x184c078a, 0x18168a55, 0x1800518b },
	{ 4,  0x18402ecc, 0x184c078a, 0x18168a55, 0x1800519f },
	{ 5,  0x18402ecc, 0x184c078e, 0x18168a55, 0x1800518b },
	{ 6,  0x18402ecc, 0x184c078e, 0x18168a55, 0x1800519f },
	{ 7,  0x18402ecc, 0x184c0792, 0x18168a55, 0x1800518b },
	{ 8,  0x18402ecc, 0x184c0792, 0x18168a55, 0x1800519f },
	{ 9,  0x18402ecc, 0x184c0796, 0x18168a55, 0x1800518b },
	{ 10, 0x18402ecc, 0x184c0796, 0x18168a55, 0x1800519f },
	{ 11, 0x18402ecc, 0x184c079a, 0x18168a55, 0x1800518b },
	{ 12, 0x18402ecc, 0x184c079a, 0x18168a55, 0x1800519f },
	{ 13, 0x18402ecc, 0x184c079e, 0x18168a55, 0x1800518b },
	{ 14, 0x18402ecc, 0x184c07a2, 0x18168a55, 0x18005193 },

	/* 802.11 UNI / HyperLan 2 */
	{ 36, 0x18402ecc, 0x184c099a, 0x18158a55, 0x180ed1a3 },
	{ 38, 0x18402ecc, 0x184c099e, 0x18158a55, 0x180ed193 },
	{ 40, 0x18402ec8, 0x184c0682, 0x18158a55, 0x180ed183 },
	{ 44, 0x18402ec8, 0x184c0682, 0x18158a55, 0x180ed1a3 },
	{ 46, 0x18402ec8, 0x184c0686, 0x18158a55, 0x180ed18b },
	{ 48, 0x18402ec8, 0x184c0686, 0x18158a55, 0x180ed19b },
	{ 52, 0x18402ec8, 0x184c068a, 0x18158a55, 0x180ed193 },
	{ 54, 0x18402ec8, 0x184c068a, 0x18158a55, 0x180ed1a3 },
	{ 56, 0x18402ec8, 0x184c068e, 0x18158a55, 0x180ed18b },
	{ 60, 0x18402ec8, 0x184c0692, 0x18158a55, 0x180ed183 },
	{ 62, 0x18402ec8, 0x184c0692, 0x18158a55, 0x180ed193 },
	{ 64, 0x18402ec8, 0x184c0692, 0x18158a55, 0x180ed1a3 },

	/* 802.11 HyperLan 2 */
	{ 100, 0x18402ec8, 0x184c06b2, 0x18178a55, 0x180ed783 },
	{ 102, 0x18402ec8, 0x184c06b2, 0x18578a55, 0x180ed793 },
	{ 104, 0x18402ec8, 0x185c06b2, 0x18578a55, 0x180ed1a3 },
	{ 108, 0x18402ecc, 0x185c0a32, 0x18578a55, 0x180ed193 },
	{ 110, 0x18402ecc, 0x184c0a36, 0x18178a55, 0x180ed183 },
	{ 112, 0x18402ecc, 0x184c0a36, 0x18178a55, 0x180ed19b },
	{ 116, 0x18402ecc, 0x184c0a3a, 0x18178a55, 0x180ed1a3 },
	{ 118, 0x18402ecc, 0x184c0a3e, 0x18178a55, 0x180ed193 },
	{ 120, 0x18402ec4, 0x184c0382, 0x18178a55, 0x180ed183 },
	{ 124, 0x18402ec4, 0x184c0382, 0x18178a55, 0x180ed193 },
	{ 126, 0x18402ec4, 0x184c0382, 0x18178a55, 0x180ed15b },
	{ 128, 0x18402ec4, 0x184c0382, 0x18178a55, 0x180ed1a3 },
	{ 132, 0x18402ec4, 0x184c0386, 0x18178a55, 0x180ed18b },
	{ 134, 0x18402ec4, 0x184c0386, 0x18178a55, 0x180ed193 },
	{ 136, 0x18402ec4, 0x184c0386, 0x18178a55, 0x180ed19b },
	{ 140, 0x18402ec4, 0x184c038a, 0x18178a55, 0x180ed183 },

	/* 802.11 UNII */
	{ 149, 0x18402ec4, 0x184c038a, 0x18178a55, 0x180ed1a7 },
	{ 151, 0x18402ec4, 0x184c038e, 0x18178a55, 0x180ed187 },
	{ 153, 0x18402ec4, 0x184c038e, 0x18178a55, 0x180ed18f },
	{ 157, 0x18402ec4, 0x184c038e, 0x18178a55, 0x180ed19f },
	{ 159, 0x18402ec4, 0x184c038e, 0x18178a55, 0x180ed1a7 },
	{ 161, 0x18402ec4, 0x184c0392, 0x18178a55, 0x180ed187 },
	{ 165, 0x18402ec4, 0x184c0392, 0x18178a55, 0x180ed197 },

	/* 802.11 Japan */
	{ 184, 0x15002ccc, 0x1500491e, 0x1509be55, 0x150c0a0b },
	{ 188, 0x15002ccc, 0x15004922, 0x1509be55, 0x150c0a13 },
	{ 192, 0x15002ccc, 0x15004926, 0x1509be55, 0x150c0a1b },
	{ 196, 0x15002ccc, 0x1500492a, 0x1509be55, 0x150c0a23 },
	{ 208, 0x15002ccc, 0x1500493a, 0x1509be55, 0x150c0a13 },
	{ 212, 0x15002ccc, 0x1500493e, 0x1509be55, 0x150c0a1b },
	{ 216, 0x15002ccc, 0x15004982, 0x1509be55, 0x150c0a23 },
};

static int rt2800pci_probe_hw_mode(struct rt2x00_dev *rt2x00dev)
{
	struct hw_mode_spec *spec = &rt2x00dev->spec;
	struct channel_info *info;
	char *tx_power1;
	char *tx_power2;
	unsigned int i;
	u16 eeprom;

	/*
	 * Initialize all hw fields.
	 */
	rt2x00dev->hw->flags =
	    IEEE80211_HW_HOST_BROADCAST_PS_BUFFERING |
	    IEEE80211_HW_SIGNAL_DBM |
	    IEEE80211_HW_SUPPORTS_PS |
	    IEEE80211_HW_PS_NULLFUNC_STACK;
	rt2x00dev->hw->extra_tx_headroom = TXWI_DESC_SIZE;

	SET_IEEE80211_DEV(rt2x00dev->hw, rt2x00dev->dev);
	SET_IEEE80211_PERM_ADDR(rt2x00dev->hw,
				rt2x00_eeprom_addr(rt2x00dev,
						   EEPROM_MAC_ADDR_0));

	rt2x00_eeprom_read(rt2x00dev, EEPROM_ANTENNA, &eeprom);

	/*
	 * Initialize hw_mode information.
	 */
	spec->supported_bands = SUPPORT_BAND_2GHZ;
	spec->supported_rates = SUPPORT_RATE_CCK | SUPPORT_RATE_OFDM;

	if (rt2x00_rf(&rt2x00dev->chip, RF2820) ||
	    rt2x00_rf(&rt2x00dev->chip, RF2720) ||
	    rt2x00_rf(&rt2x00dev->chip, RF3020) ||
	    rt2x00_rf(&rt2x00dev->chip, RF3021) ||
	    rt2x00_rf(&rt2x00dev->chip, RF3022) ||
	    rt2x00_rf(&rt2x00dev->chip, RF2020) ||
	    rt2x00_rf(&rt2x00dev->chip, RF3052)) {
		spec->num_channels = 14;
		spec->channels = rf_vals;
	} else if (rt2x00_rf(&rt2x00dev->chip, RF2850) ||
		   rt2x00_rf(&rt2x00dev->chip, RF2750)) {
		spec->supported_bands |= SUPPORT_BAND_5GHZ;
		spec->num_channels = ARRAY_SIZE(rf_vals);
		spec->channels = rf_vals;
	}

	/*
	 * Initialize HT information.
	 */
	spec->ht.ht_supported = true;
	spec->ht.cap =
	    IEEE80211_HT_CAP_SUP_WIDTH_20_40 |
	    IEEE80211_HT_CAP_GRN_FLD |
	    IEEE80211_HT_CAP_SGI_20 |
	    IEEE80211_HT_CAP_SGI_40 |
	    IEEE80211_HT_CAP_TX_STBC |
	    IEEE80211_HT_CAP_RX_STBC |
	    IEEE80211_HT_CAP_PSMP_SUPPORT;
	spec->ht.ampdu_factor = 3;
	spec->ht.ampdu_density = 4;
	spec->ht.mcs.tx_params =
	    IEEE80211_HT_MCS_TX_DEFINED |
	    IEEE80211_HT_MCS_TX_RX_DIFF |
	    ((rt2x00_get_field16(eeprom, EEPROM_ANTENNA_TXPATH) - 1) <<
		IEEE80211_HT_MCS_TX_MAX_STREAMS_SHIFT);

	switch (rt2x00_get_field16(eeprom, EEPROM_ANTENNA_RXPATH)) {
	case 3:
		spec->ht.mcs.rx_mask[2] = 0xff;
	case 2:
		spec->ht.mcs.rx_mask[1] = 0xff;
	case 1:
		spec->ht.mcs.rx_mask[0] = 0xff;
		spec->ht.mcs.rx_mask[4] = 0x1; /* MCS32 */
		break;
	}

	/*
	 * Create channel information array
	 */
	info = kzalloc(spec->num_channels * sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	spec->channels_info = info;

	tx_power1 = rt2x00_eeprom_addr(rt2x00dev, EEPROM_TXPOWER_BG1);
	tx_power2 = rt2x00_eeprom_addr(rt2x00dev, EEPROM_TXPOWER_BG2);

	for (i = 0; i < 14; i++) {
		info[i].tx_power1 = TXPOWER_G_FROM_DEV(tx_power1[i]);
		info[i].tx_power2 = TXPOWER_G_FROM_DEV(tx_power2[i]);
	}

	if (spec->num_channels > 14) {
		tx_power1 = rt2x00_eeprom_addr(rt2x00dev, EEPROM_TXPOWER_A1);
		tx_power2 = rt2x00_eeprom_addr(rt2x00dev, EEPROM_TXPOWER_A2);

		for (i = 14; i < spec->num_channels; i++) {
			info[i].tx_power1 = TXPOWER_A_FROM_DEV(tx_power1[i]);
			info[i].tx_power2 = TXPOWER_A_FROM_DEV(tx_power2[i]);
		}
	}

	return 0;
}

static const struct rt2800_ops rt2800pci_rt2800_ops = {
	.register_read		= rt2x00pci_register_read,
	.register_write		= rt2x00pci_register_write,
	.register_write_lock	= rt2x00pci_register_write, /* same for PCI */

	.register_multiread	= rt2x00pci_register_multiread,
	.register_multiwrite	= rt2x00pci_register_multiwrite,

	.regbusy_read		= rt2x00pci_regbusy_read,
};

static int rt2800pci_probe_hw(struct rt2x00_dev *rt2x00dev)
{
	int retval;

	rt2x00_set_chip_intf(rt2x00dev, RT2X00_CHIP_INTF_PCI);

	rt2x00dev->priv = (void *)&rt2800pci_rt2800_ops;

	/*
	 * Allocate eeprom data.
	 */
	retval = rt2800pci_validate_eeprom(rt2x00dev);
	if (retval)
		return retval;

	retval = rt2800pci_init_eeprom(rt2x00dev);
	if (retval)
		return retval;

	/*
	 * Initialize hw specifications.
	 */
	retval = rt2800pci_probe_hw_mode(rt2x00dev);
	if (retval)
		return retval;

	/*
	 * This device has multiple filters for control frames
	 * and has a separate filter for PS Poll frames.
	 */
	__set_bit(DRIVER_SUPPORT_CONTROL_FILTERS, &rt2x00dev->flags);
	__set_bit(DRIVER_SUPPORT_CONTROL_FILTER_PSPOLL, &rt2x00dev->flags);

	/*
	 * This device requires firmware.
	 */
	if (!rt2x00_rt(&rt2x00dev->chip, RT2880) &&
	    !rt2x00_rt(&rt2x00dev->chip, RT3052))
		__set_bit(DRIVER_REQUIRE_FIRMWARE, &rt2x00dev->flags);
	__set_bit(DRIVER_REQUIRE_DMA, &rt2x00dev->flags);
	__set_bit(DRIVER_REQUIRE_L2PAD, &rt2x00dev->flags);
	if (!modparam_nohwcrypt)
		__set_bit(CONFIG_SUPPORT_HW_CRYPTO, &rt2x00dev->flags);

	/*
	 * Set the rssi offset.
	 */
	rt2x00dev->rssi_offset = DEFAULT_RSSI_OFFSET;

	return 0;
}

/*
 * IEEE80211 stack callback functions.
 */
static void rt2800pci_get_tkip_seq(struct ieee80211_hw *hw, u8 hw_key_idx,
				   u32 *iv32, u16 *iv16)
{
	struct rt2x00_dev *rt2x00dev = hw->priv;
	struct mac_iveiv_entry iveiv_entry;
	u32 offset;

	offset = MAC_IVEIV_ENTRY(hw_key_idx);
	rt2800_register_multiread(rt2x00dev, offset,
				      &iveiv_entry, sizeof(iveiv_entry));

	memcpy(&iveiv_entry.iv[0], iv16, sizeof(iv16));
	memcpy(&iveiv_entry.iv[4], iv32, sizeof(iv32));
}

static int rt2800pci_set_rts_threshold(struct ieee80211_hw *hw, u32 value)
{
	struct rt2x00_dev *rt2x00dev = hw->priv;
	u32 reg;
	bool enabled = (value < IEEE80211_MAX_RTS_THRESHOLD);

	rt2800_register_read(rt2x00dev, TX_RTS_CFG, &reg);
	rt2x00_set_field32(&reg, TX_RTS_CFG_RTS_THRES, value);
	rt2800_register_write(rt2x00dev, TX_RTS_CFG, reg);

	rt2800_register_read(rt2x00dev, CCK_PROT_CFG, &reg);
	rt2x00_set_field32(&reg, CCK_PROT_CFG_RTS_TH_EN, enabled);
	rt2800_register_write(rt2x00dev, CCK_PROT_CFG, reg);

	rt2800_register_read(rt2x00dev, OFDM_PROT_CFG, &reg);
	rt2x00_set_field32(&reg, OFDM_PROT_CFG_RTS_TH_EN, enabled);
	rt2800_register_write(rt2x00dev, OFDM_PROT_CFG, reg);

	rt2800_register_read(rt2x00dev, MM20_PROT_CFG, &reg);
	rt2x00_set_field32(&reg, MM20_PROT_CFG_RTS_TH_EN, enabled);
	rt2800_register_write(rt2x00dev, MM20_PROT_CFG, reg);

	rt2800_register_read(rt2x00dev, MM40_PROT_CFG, &reg);
	rt2x00_set_field32(&reg, MM40_PROT_CFG_RTS_TH_EN, enabled);
	rt2800_register_write(rt2x00dev, MM40_PROT_CFG, reg);

	rt2800_register_read(rt2x00dev, GF20_PROT_CFG, &reg);
	rt2x00_set_field32(&reg, GF20_PROT_CFG_RTS_TH_EN, enabled);
	rt2800_register_write(rt2x00dev, GF20_PROT_CFG, reg);

	rt2800_register_read(rt2x00dev, GF40_PROT_CFG, &reg);
	rt2x00_set_field32(&reg, GF40_PROT_CFG_RTS_TH_EN, enabled);
	rt2800_register_write(rt2x00dev, GF40_PROT_CFG, reg);

	return 0;
}

static int rt2800pci_conf_tx(struct ieee80211_hw *hw, u16 queue_idx,
			     const struct ieee80211_tx_queue_params *params)
{
	struct rt2x00_dev *rt2x00dev = hw->priv;
	struct data_queue *queue;
	struct rt2x00_field32 field;
	int retval;
	u32 reg;
	u32 offset;

	/*
	 * First pass the configuration through rt2x00lib, that will
	 * update the queue settings and validate the input. After that
	 * we are free to update the registers based on the value
	 * in the queue parameter.
	 */
	retval = rt2x00mac_conf_tx(hw, queue_idx, params);
	if (retval)
		return retval;

	/*
	 * We only need to perform additional register initialization
	 * for WMM queues/
	 */
	if (queue_idx >= 4)
		return 0;

	queue = rt2x00queue_get_queue(rt2x00dev, queue_idx);

	/* Update WMM TXOP register */
	offset = WMM_TXOP0_CFG + (sizeof(u32) * (!!(queue_idx & 2)));
	field.bit_offset = (queue_idx & 1) * 16;
	field.bit_mask = 0xffff << field.bit_offset;

	rt2800_register_read(rt2x00dev, offset, &reg);
	rt2x00_set_field32(&reg, field, queue->txop);
	rt2800_register_write(rt2x00dev, offset, reg);

	/* Update WMM registers */
	field.bit_offset = queue_idx * 4;
	field.bit_mask = 0xf << field.bit_offset;

	rt2800_register_read(rt2x00dev, WMM_AIFSN_CFG, &reg);
	rt2x00_set_field32(&reg, field, queue->aifs);
	rt2800_register_write(rt2x00dev, WMM_AIFSN_CFG, reg);

	rt2800_register_read(rt2x00dev, WMM_CWMIN_CFG, &reg);
	rt2x00_set_field32(&reg, field, queue->cw_min);
	rt2800_register_write(rt2x00dev, WMM_CWMIN_CFG, reg);

	rt2800_register_read(rt2x00dev, WMM_CWMAX_CFG, &reg);
	rt2x00_set_field32(&reg, field, queue->cw_max);
	rt2800_register_write(rt2x00dev, WMM_CWMAX_CFG, reg);

	/* Update EDCA registers */
	offset = EDCA_AC0_CFG + (sizeof(u32) * queue_idx);

	rt2800_register_read(rt2x00dev, offset, &reg);
	rt2x00_set_field32(&reg, EDCA_AC0_CFG_TX_OP, queue->txop);
	rt2x00_set_field32(&reg, EDCA_AC0_CFG_AIFSN, queue->aifs);
	rt2x00_set_field32(&reg, EDCA_AC0_CFG_CWMIN, queue->cw_min);
	rt2x00_set_field32(&reg, EDCA_AC0_CFG_CWMAX, queue->cw_max);
	rt2800_register_write(rt2x00dev, offset, reg);

	return 0;
}

static u64 rt2800pci_get_tsf(struct ieee80211_hw *hw)
{
	struct rt2x00_dev *rt2x00dev = hw->priv;
	u64 tsf;
	u32 reg;

	rt2800_register_read(rt2x00dev, TSF_TIMER_DW1, &reg);
	tsf = (u64) rt2x00_get_field32(reg, TSF_TIMER_DW1_HIGH_WORD) << 32;
	rt2800_register_read(rt2x00dev, TSF_TIMER_DW0, &reg);
	tsf |= rt2x00_get_field32(reg, TSF_TIMER_DW0_LOW_WORD);

	return tsf;
}

static const struct ieee80211_ops rt2800pci_mac80211_ops = {
	.tx			= rt2x00mac_tx,
	.start			= rt2x00mac_start,
	.stop			= rt2x00mac_stop,
	.add_interface		= rt2x00mac_add_interface,
	.remove_interface	= rt2x00mac_remove_interface,
	.config			= rt2x00mac_config,
	.configure_filter	= rt2x00mac_configure_filter,
	.set_key		= rt2x00mac_set_key,
	.get_stats		= rt2x00mac_get_stats,
	.get_tkip_seq		= rt2800pci_get_tkip_seq,
	.set_rts_threshold	= rt2800pci_set_rts_threshold,
	.bss_info_changed	= rt2x00mac_bss_info_changed,
	.conf_tx		= rt2800pci_conf_tx,
	.get_tx_stats		= rt2x00mac_get_tx_stats,
	.get_tsf		= rt2800pci_get_tsf,
	.rfkill_poll		= rt2x00mac_rfkill_poll,
};

static const struct rt2x00lib_ops rt2800pci_rt2x00_ops = {
	.irq_handler		= rt2800pci_interrupt,
	.probe_hw		= rt2800pci_probe_hw,
	.get_firmware_name	= rt2800pci_get_firmware_name,
	.check_firmware		= rt2800pci_check_firmware,
	.load_firmware		= rt2800pci_load_firmware,
	.initialize		= rt2x00pci_initialize,
	.uninitialize		= rt2x00pci_uninitialize,
	.get_entry_state	= rt2800pci_get_entry_state,
	.clear_entry		= rt2800pci_clear_entry,
	.set_device_state	= rt2800pci_set_device_state,
	.rfkill_poll		= rt2800_rfkill_poll,
	.link_stats		= rt2800_link_stats,
	.reset_tuner		= rt2800_reset_tuner,
	.link_tuner		= rt2800_link_tuner,
	.write_tx_desc		= rt2800pci_write_tx_desc,
	.write_tx_data		= rt2x00pci_write_tx_data,
	.write_beacon		= rt2800pci_write_beacon,
	.kick_tx_queue		= rt2800pci_kick_tx_queue,
	.kill_tx_queue		= rt2800pci_kill_tx_queue,
	.fill_rxdone		= rt2800pci_fill_rxdone,
	.config_shared_key	= rt2800_config_shared_key,
	.config_pairwise_key	= rt2800_config_pairwise_key,
	.config_filter		= rt2800_config_filter,
	.config_intf		= rt2800_config_intf,
	.config_erp		= rt2800_config_erp,
	.config_ant		= rt2800_config_ant,
	.config			= rt2800_config,
};

static const struct data_queue_desc rt2800pci_queue_rx = {
	.entry_num		= RX_ENTRIES,
	.data_size		= AGGREGATION_SIZE,
	.desc_size		= RXD_DESC_SIZE,
	.priv_size		= sizeof(struct queue_entry_priv_pci),
};

static const struct data_queue_desc rt2800pci_queue_tx = {
	.entry_num		= TX_ENTRIES,
	.data_size		= AGGREGATION_SIZE,
	.desc_size		= TXD_DESC_SIZE,
	.priv_size		= sizeof(struct queue_entry_priv_pci),
};

static const struct data_queue_desc rt2800pci_queue_bcn = {
	.entry_num		= 8 * BEACON_ENTRIES,
	.data_size		= 0, /* No DMA required for beacons */
	.desc_size		= TXWI_DESC_SIZE,
	.priv_size		= sizeof(struct queue_entry_priv_pci),
};

static const struct rt2x00_ops rt2800pci_ops = {
	.name		= KBUILD_MODNAME,
	.max_sta_intf	= 1,
	.max_ap_intf	= 8,
	.eeprom_size	= EEPROM_SIZE,
	.rf_size	= RF_SIZE,
	.tx_queues	= NUM_TX_QUEUES,
	.rx		= &rt2800pci_queue_rx,
	.tx		= &rt2800pci_queue_tx,
	.bcn		= &rt2800pci_queue_bcn,
	.lib		= &rt2800pci_rt2x00_ops,
	.hw		= &rt2800pci_mac80211_ops,
#ifdef CONFIG_RT2X00_LIB_DEBUGFS
	.debugfs	= &rt2800_rt2x00debug,
#endif /* CONFIG_RT2X00_LIB_DEBUGFS */
};

/*
 * RT2800pci module information.
 */
static struct pci_device_id rt2800pci_device_table[] = {
	{ PCI_DEVICE(0x1462, 0x891a), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ PCI_DEVICE(0x1432, 0x7708), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ PCI_DEVICE(0x1432, 0x7727), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ PCI_DEVICE(0x1432, 0x7728), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ PCI_DEVICE(0x1432, 0x7738), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ PCI_DEVICE(0x1432, 0x7748), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ PCI_DEVICE(0x1432, 0x7758), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ PCI_DEVICE(0x1432, 0x7768), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ PCI_DEVICE(0x1814, 0x0601), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ PCI_DEVICE(0x1814, 0x0681), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ PCI_DEVICE(0x1814, 0x0701), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ PCI_DEVICE(0x1814, 0x0781), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ PCI_DEVICE(0x1814, 0x3060), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ PCI_DEVICE(0x1814, 0x3062), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ PCI_DEVICE(0x1814, 0x3090), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ PCI_DEVICE(0x1814, 0x3091), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ PCI_DEVICE(0x1814, 0x3092), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ PCI_DEVICE(0x1814, 0x3562), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ PCI_DEVICE(0x1814, 0x3592), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ PCI_DEVICE(0x1a3b, 0x1059), PCI_DEVICE_DATA(&rt2800pci_ops) },
	{ 0, }
};

MODULE_AUTHOR(DRV_PROJECT);
MODULE_VERSION(DRV_VERSION);
MODULE_DESCRIPTION("Ralink RT2800 PCI & PCMCIA Wireless LAN driver.");
MODULE_SUPPORTED_DEVICE("Ralink RT2860 PCI & PCMCIA chipset based cards");
#ifdef CONFIG_RT2800PCI_PCI
MODULE_FIRMWARE(FIRMWARE_RT2860);
MODULE_DEVICE_TABLE(pci, rt2800pci_device_table);
#endif /* CONFIG_RT2800PCI_PCI */
MODULE_LICENSE("GPL");

#ifdef CONFIG_RT2800PCI_WISOC
#if defined(CONFIG_RALINK_RT288X)
__rt2x00soc_probe(RT2880, &rt2800pci_ops);
#elif defined(CONFIG_RALINK_RT305X)
__rt2x00soc_probe(RT3052, &rt2800pci_ops);
#endif

static struct platform_driver rt2800soc_driver = {
	.driver		= {
		.name		= "rt2800_wmac",
		.owner		= THIS_MODULE,
		.mod_name	= KBUILD_MODNAME,
	},
	.probe		= __rt2x00soc_probe,
	.remove		= __devexit_p(rt2x00soc_remove),
	.suspend	= rt2x00soc_suspend,
	.resume		= rt2x00soc_resume,
};
#endif /* CONFIG_RT2800PCI_WISOC */

#ifdef CONFIG_RT2800PCI_PCI
static struct pci_driver rt2800pci_driver = {
	.name		= KBUILD_MODNAME,
	.id_table	= rt2800pci_device_table,
	.probe		= rt2x00pci_probe,
	.remove		= __devexit_p(rt2x00pci_remove),
	.suspend	= rt2x00pci_suspend,
	.resume		= rt2x00pci_resume,
};
#endif /* CONFIG_RT2800PCI_PCI */

static int __init rt2800pci_init(void)
{
	int ret = 0;

#ifdef CONFIG_RT2800PCI_WISOC
	ret = platform_driver_register(&rt2800soc_driver);
	if (ret)
		return ret;
#endif
#ifdef CONFIG_RT2800PCI_PCI
	ret = pci_register_driver(&rt2800pci_driver);
	if (ret) {
#ifdef CONFIG_RT2800PCI_WISOC
		platform_driver_unregister(&rt2800soc_driver);
#endif
		return ret;
	}
#endif

	return ret;
}

static void __exit rt2800pci_exit(void)
{
#ifdef CONFIG_RT2800PCI_PCI
	pci_unregister_driver(&rt2800pci_driver);
#endif
#ifdef CONFIG_RT2800PCI_WISOC
	platform_driver_unregister(&rt2800soc_driver);
#endif
}

module_init(rt2800pci_init);
module_exit(rt2800pci_exit);
