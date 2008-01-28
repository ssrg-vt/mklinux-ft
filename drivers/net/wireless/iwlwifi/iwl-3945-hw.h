/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2005 - 2007 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110,
 * USA
 *
 * The full GNU General Public License is included in this distribution
 * in the file called LICENSE.GPL.
 *
 * Contact Information:
 * James P. Ketrenos <ipw2100-admin@linux.intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 * BSD LICENSE
 *
 * Copyright(c) 2005 - 2007 Intel Corporation. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/

#ifndef __iwl_3945_hw__
#define __iwl_3945_hw__

/* uCode queue management definitions */
#define IWL_CMD_QUEUE_NUM       4
#define IWL_CMD_FIFO_NUM        4
#define IWL_BACK_QUEUE_FIRST_ID 7

/* Tx rates */
#define IWL_CCK_RATES 4
#define IWL_OFDM_RATES 8

#define IWL_HT_RATES 0

#define IWL_MAX_RATES  (IWL_CCK_RATES+IWL_OFDM_RATES+IWL_HT_RATES)

/* Time constants */
#define SHORT_SLOT_TIME 9
#define LONG_SLOT_TIME 20

/* RSSI to dBm */
#define IWL_RSSI_OFFSET	95

/*
 * This file defines EEPROM related constants, enums, and inline functions.
 *
 */

#define IWL_EEPROM_ACCESS_TIMEOUT	5000 /* uSec */
#define IWL_EEPROM_ACCESS_DELAY		10   /* uSec */
/* EEPROM field values */
#define ANTENNA_SWITCH_NORMAL     0
#define ANTENNA_SWITCH_INVERSE    1

enum {
	EEPROM_CHANNEL_VALID = (1 << 0),	/* usable for this SKU/geo */
	EEPROM_CHANNEL_IBSS = (1 << 1),	/* usable as an IBSS channel */
	/* Bit 2 Reserved */
	EEPROM_CHANNEL_ACTIVE = (1 << 3),	/* active scanning allowed */
	EEPROM_CHANNEL_RADAR = (1 << 4),	/* radar detection required */
	EEPROM_CHANNEL_WIDE = (1 << 5),
	EEPROM_CHANNEL_NARROW = (1 << 6),
	EEPROM_CHANNEL_DFS = (1 << 7),	/* dynamic freq selection candidate */
};

/* EEPROM field lengths */
#define EEPROM_BOARD_PBA_NUMBER_LENGTH                  11

/* EEPROM field lengths */
#define EEPROM_BOARD_PBA_NUMBER_LENGTH                  11
#define EEPROM_REGULATORY_SKU_ID_LENGTH                 4
#define EEPROM_REGULATORY_BAND1_CHANNELS_LENGTH         14
#define EEPROM_REGULATORY_BAND2_CHANNELS_LENGTH         13
#define EEPROM_REGULATORY_BAND3_CHANNELS_LENGTH         12
#define EEPROM_REGULATORY_BAND4_CHANNELS_LENGTH         11
#define EEPROM_REGULATORY_BAND5_CHANNELS_LENGTH         6

#define EEPROM_REGULATORY_CHANNELS_LENGTH ( \
	EEPROM_REGULATORY_BAND1_CHANNELS_LENGTH + \
	EEPROM_REGULATORY_BAND2_CHANNELS_LENGTH + \
	EEPROM_REGULATORY_BAND3_CHANNELS_LENGTH + \
	EEPROM_REGULATORY_BAND4_CHANNELS_LENGTH + \
	EEPROM_REGULATORY_BAND5_CHANNELS_LENGTH)

#define EEPROM_REGULATORY_NUMBER_OF_BANDS               5

/* SKU Capabilities */
#define EEPROM_SKU_CAP_SW_RF_KILL_ENABLE                (1 << 0)
#define EEPROM_SKU_CAP_HW_RF_KILL_ENABLE                (1 << 1)
#define EEPROM_SKU_CAP_OP_MODE_MRC                      (1 << 7)

/* *regulatory* channel data from eeprom, one for each channel */
struct iwl_eeprom_channel {
	u8 flags;		/* flags copied from EEPROM */
	s8 max_power_avg;	/* max power (dBm) on this chnl, limit 31 */
} __attribute__ ((packed));

/*
 * Mapping of a Tx power level, at factory calibration temperature,
 *   to a radio/DSP gain table index.
 * One for each of 5 "sample" power levels in each band.
 * v_det is measured at the factory, using the 3945's built-in power amplifier
 *   (PA) output voltage detector.  This same detector is used during Tx of
 *   long packets in normal operation to provide feedback as to proper output
 *   level.
 * Data copied from EEPROM.
 */
struct iwl_eeprom_txpower_sample {
	u8 gain_index;		/* index into power (gain) setup table ... */
	s8 power;		/* ... for this pwr level for this chnl group */
	u16 v_det;		/* PA output voltage */
} __attribute__ ((packed));

/*
 * Mappings of Tx power levels -> nominal radio/DSP gain table indexes.
 * One for each channel group (a.k.a. "band") (1 for BG, 4 for A).
 * Tx power setup code interpolates between the 5 "sample" power levels
 *    to determine the nominal setup for a requested power level.
 * Data copied from EEPROM.
 * DO NOT ALTER THIS STRUCTURE!!!
 */
struct iwl_eeprom_txpower_group {
	struct iwl_eeprom_txpower_sample samples[5];	/* 5 power levels */
	s32 a, b, c, d, e;	/* coefficients for voltage->power
				 * formula (signed) */
	s32 Fa, Fb, Fc, Fd, Fe;	/* these modify coeffs based on
					 * frequency (signed) */
	s8 saturation_power;	/* highest power possible by h/w in this
				 * band */
	u8 group_channel;	/* "representative" channel # in this band */
	s16 temperature;	/* h/w temperature at factory calib this band
				 * (signed) */
} __attribute__ ((packed));

/*
 * Temperature-based Tx-power compensation data, not band-specific.
 * These coefficients are use to modify a/b/c/d/e coeffs based on
 *   difference between current temperature and factory calib temperature.
 * Data copied from EEPROM.
 */
struct iwl_eeprom_temperature_corr {
	u32 Ta;
	u32 Tb;
	u32 Tc;
	u32 Td;
	u32 Te;
} __attribute__ ((packed));

struct iwl_eeprom {
	u8 reserved0[16];
#define EEPROM_DEVICE_ID                    (2*0x08)	/* 2 bytes */
	u16 device_id;	/* abs.ofs: 16 */
	u8 reserved1[2];
#define EEPROM_PMC                          (2*0x0A)	/* 2 bytes */
	u16 pmc;		/* abs.ofs: 20 */
	u8 reserved2[20];
#define EEPROM_MAC_ADDRESS                  (2*0x15)	/* 6  bytes */
	u8 mac_address[6];	/* abs.ofs: 42 */
	u8 reserved3[58];
#define EEPROM_BOARD_REVISION               (2*0x35)	/* 2  bytes */
	u16 board_revision;	/* abs.ofs: 106 */
	u8 reserved4[11];
#define EEPROM_BOARD_PBA_NUMBER             (2*0x3B+1)	/* 9  bytes */
	u8 board_pba_number[9];	/* abs.ofs: 119 */
	u8 reserved5[8];
#define EEPROM_VERSION                      (2*0x44)	/* 2  bytes */
	u16 version;		/* abs.ofs: 136 */
#define EEPROM_SKU_CAP                      (2*0x45)	/* 1  bytes */
	u8 sku_cap;		/* abs.ofs: 138 */
#define EEPROM_LEDS_MODE                    (2*0x45+1)	/* 1  bytes */
	u8 leds_mode;		/* abs.ofs: 139 */
#define EEPROM_OEM_MODE                     (2*0x46)	/* 2  bytes */
	u16 oem_mode;
#define EEPROM_WOWLAN_MODE                  (2*0x47)	/* 2  bytes */
	u16 wowlan_mode;	/* abs.ofs: 142 */
#define EEPROM_LEDS_TIME_INTERVAL           (2*0x48)	/* 2  bytes */
	u16 leds_time_interval;	/* abs.ofs: 144 */
#define EEPROM_LEDS_OFF_TIME                (2*0x49)	/* 1  bytes */
	u8 leds_off_time;	/* abs.ofs: 146 */
#define EEPROM_LEDS_ON_TIME                 (2*0x49+1)	/* 1  bytes */
	u8 leds_on_time;	/* abs.ofs: 147 */
#define EEPROM_ALMGOR_M_VERSION             (2*0x4A)	/* 1  bytes */
	u8 almgor_m_version;	/* abs.ofs: 148 */
#define EEPROM_ANTENNA_SWITCH_TYPE          (2*0x4A+1)	/* 1  bytes */
	u8 antenna_switch_type;	/* abs.ofs: 149 */
	u8 reserved6[42];
#define EEPROM_REGULATORY_SKU_ID            (2*0x60)	/* 4  bytes */
	u8 sku_id[4];		/* abs.ofs: 192 */
#define EEPROM_REGULATORY_BAND_1            (2*0x62)	/* 2  bytes */
	u16 band_1_count;	/* abs.ofs: 196 */
#define EEPROM_REGULATORY_BAND_1_CHANNELS   (2*0x63)	/* 28 bytes */
	struct iwl_eeprom_channel band_1_channels[14];	/* abs.ofs: 196 */
#define EEPROM_REGULATORY_BAND_2            (2*0x71)	/* 2  bytes */
	u16 band_2_count;	/* abs.ofs: 226 */
#define EEPROM_REGULATORY_BAND_2_CHANNELS   (2*0x72)	/* 26 bytes */
	struct iwl_eeprom_channel band_2_channels[13];	/* abs.ofs: 228 */
#define EEPROM_REGULATORY_BAND_3            (2*0x7F)	/* 2  bytes */
	u16 band_3_count;	/* abs.ofs: 254 */
#define EEPROM_REGULATORY_BAND_3_CHANNELS   (2*0x80)	/* 24 bytes */
	struct iwl_eeprom_channel band_3_channels[12];	/* abs.ofs: 256 */
#define EEPROM_REGULATORY_BAND_4            (2*0x8C)	/* 2  bytes */
	u16 band_4_count;	/* abs.ofs: 280 */
#define EEPROM_REGULATORY_BAND_4_CHANNELS   (2*0x8D)	/* 22 bytes */
	struct iwl_eeprom_channel band_4_channels[11];	/* abs.ofs: 282 */
#define EEPROM_REGULATORY_BAND_5            (2*0x98)	/* 2  bytes */
	u16 band_5_count;	/* abs.ofs: 304 */
#define EEPROM_REGULATORY_BAND_5_CHANNELS   (2*0x99)	/* 12 bytes */
	struct iwl_eeprom_channel band_5_channels[6];	/* abs.ofs: 306 */

	u8 reserved9[194];

#define EEPROM_TXPOWER_CALIB_GROUP0 0x200
#define EEPROM_TXPOWER_CALIB_GROUP1 0x240
#define EEPROM_TXPOWER_CALIB_GROUP2 0x280
#define EEPROM_TXPOWER_CALIB_GROUP3 0x2c0
#define EEPROM_TXPOWER_CALIB_GROUP4 0x300
#define IWL_NUM_TX_CALIB_GROUPS 5
	struct iwl_eeprom_txpower_group groups[IWL_NUM_TX_CALIB_GROUPS];
/* abs.ofs: 512 */
#define EEPROM_CALIB_TEMPERATURE_CORRECT 0x340
	struct iwl_eeprom_temperature_corr corrections;	/* abs.ofs: 832 */
	u8 reserved16[172];	/* fill out to full 1024 byte block */
} __attribute__ ((packed));

#define IWL_EEPROM_IMAGE_SIZE 1024


#include "iwl-3945-commands.h"

#define PCI_LINK_CTRL      0x0F0
#define PCI_POWER_SOURCE   0x0C8
#define PCI_REG_WUM8       0x0E8
#define PCI_CFG_PMC_PME_FROM_D3COLD_SUPPORT         (0x80000000)

/*=== CSR (control and status registers) ===*/
#define CSR_BASE    (0x000)

#define CSR_SW_VER              (CSR_BASE+0x000)
#define CSR_HW_IF_CONFIG_REG    (CSR_BASE+0x000) /* hardware interface config */
#define CSR_INT_COALESCING      (CSR_BASE+0x004) /* accum ints, 32-usec units */
#define CSR_INT                 (CSR_BASE+0x008) /* host interrupt status/ack */
#define CSR_INT_MASK            (CSR_BASE+0x00c) /* host interrupt enable */
#define CSR_FH_INT_STATUS       (CSR_BASE+0x010) /* busmaster int status/ack*/
#define CSR_GPIO_IN             (CSR_BASE+0x018) /* read external chip pins */
#define CSR_RESET               (CSR_BASE+0x020) /* busmaster enable, NMI, etc*/
#define CSR_GP_CNTRL            (CSR_BASE+0x024)
#define CSR_HW_REV              (CSR_BASE+0x028)
#define CSR_EEPROM_REG          (CSR_BASE+0x02c)
#define CSR_EEPROM_GP           (CSR_BASE+0x030)
#define CSR_GP_UCODE		(CSR_BASE+0x044)
#define CSR_UCODE_DRV_GP1       (CSR_BASE+0x054)
#define CSR_UCODE_DRV_GP1_SET   (CSR_BASE+0x058)
#define CSR_UCODE_DRV_GP1_CLR   (CSR_BASE+0x05c)
#define CSR_UCODE_DRV_GP2       (CSR_BASE+0x060)
#define CSR_LED_REG		(CSR_BASE+0x094)
#define CSR_DRAM_INT_TBL_CTL	(CSR_BASE+0x0A0)
#define CSR_GIO_CHICKEN_BITS    (CSR_BASE+0x100)
#define CSR_ANA_PLL_CFG         (CSR_BASE+0x20c)
#define CSR_HW_REV_WA_REG	(CSR_BASE+0x22C)

/* HW I/F configuration */
#define CSR_HW_IF_CONFIG_REG_BIT_ALMAGOR_MB         (0x00000100)
#define CSR_HW_IF_CONFIG_REG_BIT_ALMAGOR_MM         (0x00000200)
#define CSR_HW_IF_CONFIG_REG_BIT_SKU_MRC            (0x00000400)
#define CSR_HW_IF_CONFIG_REG_BIT_BOARD_TYPE         (0x00000800)
#define CSR_HW_IF_CONFIG_REG_BITS_SILICON_TYPE_A    (0x00000000)
#define CSR_HW_IF_CONFIG_REG_BITS_SILICON_TYPE_B    (0x00001000)
#define CSR_HW_IF_CONFIG_REG_BIT_EEPROM_OWN_SEM     (0x00200000)

/* interrupt flags in INTA, set by uCode or hardware (e.g. dma),
 * acknowledged (reset) by host writing "1" to flagged bits. */
#define CSR_INT_BIT_FH_RX        (1<<31) /* Rx DMA, cmd responses, FH_INT[17:16] */
#define CSR_INT_BIT_HW_ERR       (1<<29) /* DMA hardware error FH_INT[31] */
#define CSR_INT_BIT_DNLD         (1<<28) /* uCode Download */
#define CSR_INT_BIT_FH_TX        (1<<27) /* Tx DMA FH_INT[1:0] */
#define CSR_INT_BIT_MAC_CLK_ACTV (1<<26) /* NIC controller's clock toggled on/off */
#define CSR_INT_BIT_SW_ERR       (1<<25) /* uCode error */
#define CSR_INT_BIT_RF_KILL      (1<<7)  /* HW RFKILL switch GP_CNTRL[27] toggled */
#define CSR_INT_BIT_CT_KILL      (1<<6)  /* Critical temp (chip too hot) rfkill */
#define CSR_INT_BIT_SW_RX        (1<<3)  /* Rx, command responses, 3945 */
#define CSR_INT_BIT_WAKEUP       (1<<1)  /* NIC controller waking up (pwr mgmt) */
#define CSR_INT_BIT_ALIVE        (1<<0)  /* uCode interrupts once it initializes */

#define CSR_INI_SET_MASK	(CSR_INT_BIT_FH_RX   | \
				 CSR_INT_BIT_HW_ERR  | \
				 CSR_INT_BIT_FH_TX   | \
				 CSR_INT_BIT_SW_ERR  | \
				 CSR_INT_BIT_RF_KILL | \
				 CSR_INT_BIT_SW_RX   | \
				 CSR_INT_BIT_WAKEUP  | \
				 CSR_INT_BIT_ALIVE)

/* interrupt flags in FH (flow handler) (PCI busmaster DMA) */
#define CSR_FH_INT_BIT_ERR       (1<<31) /* Error */
#define CSR_FH_INT_BIT_HI_PRIOR  (1<<30) /* High priority Rx, bypass coalescing */
#define CSR_FH_INT_BIT_RX_CHNL2  (1<<18) /* Rx channel 2 (3945 only) */
#define CSR_FH_INT_BIT_RX_CHNL1  (1<<17) /* Rx channel 1 */
#define CSR_FH_INT_BIT_RX_CHNL0  (1<<16) /* Rx channel 0 */
#define CSR_FH_INT_BIT_TX_CHNL6  (1<<6)  /* Tx channel 6 (3945 only) */
#define CSR_FH_INT_BIT_TX_CHNL1  (1<<1)  /* Tx channel 1 */
#define CSR_FH_INT_BIT_TX_CHNL0  (1<<0)  /* Tx channel 0 */

#define CSR_FH_INT_RX_MASK	(CSR_FH_INT_BIT_HI_PRIOR | \
				 CSR_FH_INT_BIT_RX_CHNL2 | \
				 CSR_FH_INT_BIT_RX_CHNL1 | \
				 CSR_FH_INT_BIT_RX_CHNL0)

#define CSR_FH_INT_TX_MASK	(CSR_FH_INT_BIT_TX_CHNL6 | \
				 CSR_FH_INT_BIT_TX_CHNL1 | \
				 CSR_FH_INT_BIT_TX_CHNL0)


/* RESET */
#define CSR_RESET_REG_FLAG_NEVO_RESET                (0x00000001)
#define CSR_RESET_REG_FLAG_FORCE_NMI                 (0x00000002)
#define CSR_RESET_REG_FLAG_SW_RESET                  (0x00000080)
#define CSR_RESET_REG_FLAG_MASTER_DISABLED           (0x00000100)
#define CSR_RESET_REG_FLAG_STOP_MASTER               (0x00000200)

/* GP (general purpose) CONTROL */
#define CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY        (0x00000001)
#define CSR_GP_CNTRL_REG_FLAG_INIT_DONE              (0x00000004)
#define CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ         (0x00000008)
#define CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP         (0x00000010)

#define CSR_GP_CNTRL_REG_VAL_MAC_ACCESS_EN           (0x00000001)

#define CSR_GP_CNTRL_REG_MSK_POWER_SAVE_TYPE         (0x07000000)
#define CSR_GP_CNTRL_REG_FLAG_MAC_POWER_SAVE         (0x04000000)
#define CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW          (0x08000000)


/* EEPROM REG */
#define CSR_EEPROM_REG_READ_VALID_MSK	(0x00000001)
#define CSR_EEPROM_REG_BIT_CMD		(0x00000002)

/* EEPROM GP */
#define CSR_EEPROM_GP_VALID_MSK		(0x00000006)
#define CSR_EEPROM_GP_BAD_SIGNATURE	(0x00000000)
#define CSR_EEPROM_GP_IF_OWNER_MSK	(0x00000180)

/* UCODE DRV GP */
#define CSR_UCODE_DRV_GP1_BIT_MAC_SLEEP             (0x00000001)
#define CSR_UCODE_SW_BIT_RFKILL                     (0x00000002)
#define CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED           (0x00000004)
#define CSR_UCODE_DRV_GP1_REG_BIT_CT_KILL_EXIT      (0x00000008)

/* GPIO */
#define CSR_GPIO_IN_BIT_AUX_POWER                   (0x00000200)
#define CSR_GPIO_IN_VAL_VAUX_PWR_SRC                (0x00000000)
#define CSR_GPIO_IN_VAL_VMAIN_PWR_SRC		CSR_GPIO_IN_BIT_AUX_POWER

/* GI Chicken Bits */
#define CSR_GIO_CHICKEN_BITS_REG_BIT_L1A_NO_L0S_RX  (0x00800000)
#define CSR_GIO_CHICKEN_BITS_REG_BIT_DIS_L0S_EXIT_TIMER  (0x20000000)

/* CSR_ANA_PLL_CFG */
#define CSR_ANA_PLL_CFG_SH		(0x00880300)

#define CSR_LED_REG_TRUN_ON		(0x00000078)
#define CSR_LED_REG_TRUN_OFF		(0x00000038)
#define CSR_LED_BSM_CTRL_MSK		(0xFFFFFFDF)

/* DRAM_INT_TBL_CTRL */
#define CSR_DRAM_INT_TBL_CTRL_EN	(1<<31)
#define CSR_DRAM_INT_TBL_CTRL_WRAP_CHK	(1<<27)

/*=== HBUS (Host-side Bus) ===*/
#define HBUS_BASE	(0x400)

#define HBUS_TARG_MEM_RADDR     (HBUS_BASE+0x00c)
#define HBUS_TARG_MEM_WADDR     (HBUS_BASE+0x010)
#define HBUS_TARG_MEM_WDAT      (HBUS_BASE+0x018)
#define HBUS_TARG_MEM_RDAT      (HBUS_BASE+0x01c)
#define HBUS_TARG_PRPH_WADDR    (HBUS_BASE+0x044)
#define HBUS_TARG_PRPH_RADDR    (HBUS_BASE+0x048)
#define HBUS_TARG_PRPH_WDAT     (HBUS_BASE+0x04c)
#define HBUS_TARG_PRPH_RDAT     (HBUS_BASE+0x050)
#define HBUS_TARG_WRPTR         (HBUS_BASE+0x060)

#define HBUS_TARG_MBX_C         (HBUS_BASE+0x030)


/* SCD (Scheduler) */
#define SCD_BASE                        (CSR_BASE + 0x2E00)

#define SCD_MODE_REG                    (SCD_BASE + 0x000)
#define SCD_ARASTAT_REG                 (SCD_BASE + 0x004)
#define SCD_TXFACT_REG                  (SCD_BASE + 0x010)
#define SCD_TXF4MF_REG                  (SCD_BASE + 0x014)
#define SCD_TXF5MF_REG                  (SCD_BASE + 0x020)
#define SCD_SBYP_MODE_1_REG             (SCD_BASE + 0x02C)
#define SCD_SBYP_MODE_2_REG             (SCD_BASE + 0x030)

/*=== FH (data Flow Handler) ===*/
#define FH_BASE     (0x800)

#define FH_CBCC_TABLE           (FH_BASE+0x140)
#define FH_TFDB_TABLE           (FH_BASE+0x180)
#define FH_RCSR_TABLE           (FH_BASE+0x400)
#define FH_RSSR_TABLE           (FH_BASE+0x4c0)
#define FH_TCSR_TABLE           (FH_BASE+0x500)
#define FH_TSSR_TABLE           (FH_BASE+0x680)

/* TFDB (Transmit Frame Buffer Descriptor) */
#define FH_TFDB(_channel, buf) \
	(FH_TFDB_TABLE+((_channel)*2+(buf))*0x28)
#define ALM_FH_TFDB_CHNL_BUF_CTRL_REG(_channel) \
	(FH_TFDB_TABLE + 0x50 * _channel)
/* CBCC _channel is [0,2] */
#define FH_CBCC(_channel)           (FH_CBCC_TABLE+(_channel)*0x8)
#define FH_CBCC_CTRL(_channel)      (FH_CBCC(_channel)+0x00)
#define FH_CBCC_BASE(_channel)      (FH_CBCC(_channel)+0x04)

/* RCSR _channel is [0,2] */
#define FH_RCSR(_channel)           (FH_RCSR_TABLE+(_channel)*0x40)
#define FH_RCSR_CONFIG(_channel)    (FH_RCSR(_channel)+0x00)
#define FH_RCSR_RBD_BASE(_channel)  (FH_RCSR(_channel)+0x04)
#define FH_RCSR_WPTR(_channel)      (FH_RCSR(_channel)+0x20)
#define FH_RCSR_RPTR_ADDR(_channel) (FH_RCSR(_channel)+0x24)

#define FH_RSCSR_CHNL0_WPTR        (FH_RCSR_WPTR(0))

/* RSSR */
#define FH_RSSR_CTRL            (FH_RSSR_TABLE+0x000)
#define FH_RSSR_STATUS          (FH_RSSR_TABLE+0x004)
/* TCSR */
#define FH_TCSR(_channel)           (FH_TCSR_TABLE+(_channel)*0x20)
#define FH_TCSR_CONFIG(_channel)    (FH_TCSR(_channel)+0x00)
#define FH_TCSR_CREDIT(_channel)    (FH_TCSR(_channel)+0x04)
#define FH_TCSR_BUFF_STTS(_channel) (FH_TCSR(_channel)+0x08)
/* TSSR */
#define FH_TSSR_CBB_BASE        (FH_TSSR_TABLE+0x000)
#define FH_TSSR_MSG_CONFIG      (FH_TSSR_TABLE+0x008)
#define FH_TSSR_TX_STATUS       (FH_TSSR_TABLE+0x010)
/* 18 - reserved */

/* card static random access memory (SRAM) for processor data and instructs */
#define RTC_INST_LOWER_BOUND			(0x000000)
#define RTC_DATA_LOWER_BOUND			(0x800000)


/* DBM */

#define ALM_FH_SRVC_CHNL                            (6)

#define ALM_FH_RCSR_RX_CONFIG_REG_POS_RBDC_SIZE     (20)
#define ALM_FH_RCSR_RX_CONFIG_REG_POS_IRQ_RBTH      (4)

#define ALM_FH_RCSR_RX_CONFIG_REG_BIT_WR_STTS_EN    (0x08000000)

#define ALM_FH_RCSR_RX_CONFIG_REG_VAL_DMA_CHNL_EN_ENABLE        (0x80000000)

#define ALM_FH_RCSR_RX_CONFIG_REG_VAL_RDRBD_EN_ENABLE           (0x20000000)

#define ALM_FH_RCSR_RX_CONFIG_REG_VAL_MAX_FRAG_SIZE_128         (0x01000000)

#define ALM_FH_RCSR_RX_CONFIG_REG_VAL_IRQ_DEST_INT_HOST         (0x00001000)

#define ALM_FH_RCSR_RX_CONFIG_REG_VAL_MSG_MODE_FH               (0x00000000)

#define ALM_FH_TCSR_TX_CONFIG_REG_VAL_MSG_MODE_TXF              (0x00000000)
#define ALM_FH_TCSR_TX_CONFIG_REG_VAL_MSG_MODE_DRIVER           (0x00000001)

#define ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_DISABLE_VAL    (0x00000000)
#define ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE_VAL     (0x00000008)

#define ALM_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_IFTFD           (0x00200000)

#define ALM_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_RTC_NOINT            (0x00000000)

#define ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_PAUSE            (0x00000000)
#define ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE           (0x80000000)

#define ALM_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_VALID          (0x00004000)

#define ALM_FH_TCSR_CHNL_TX_BUF_STS_REG_BIT_TFDB_WPTR           (0x00000001)

#define ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_SNOOP_RD_TXPD_ON      (0xFF000000)
#define ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RD_TXPD_ON      (0x00FF0000)

#define ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_MAX_FRAG_SIZE_128B    (0x00000400)

#define ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_SNOOP_RD_TFD_ON       (0x00000100)
#define ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RD_CBB_ON       (0x00000080)

#define ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RSP_WAIT_TH     (0x00000020)
#define ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_RSP_WAIT_TH           (0x00000005)

#define ALM_TB_MAX_BYTES_COUNT      (0xFFF0)

#define ALM_FH_TSSR_TX_STATUS_REG_BIT_BUFS_EMPTY(_channel) \
	((1LU << _channel) << 24)
#define ALM_FH_TSSR_TX_STATUS_REG_BIT_NO_PEND_REQ(_channel) \
	((1LU << _channel) << 16)

#define ALM_FH_TSSR_TX_STATUS_REG_MSK_CHNL_IDLE(_channel) \
	(ALM_FH_TSSR_TX_STATUS_REG_BIT_BUFS_EMPTY(_channel) | \
	 ALM_FH_TSSR_TX_STATUS_REG_BIT_NO_PEND_REQ(_channel))
#define PCI_CFG_REV_ID_BIT_BASIC_SKU                (0x40)	/* bit 6    */
#define PCI_CFG_REV_ID_BIT_RTP                      (0x80)	/* bit 7    */

#define HBUS_TARG_MBX_C_REG_BIT_CMD_BLOCKED         (0x00000004)

#define TFD_QUEUE_MIN           0
#define TFD_QUEUE_MAX           6
#define TFD_QUEUE_SIZE_MAX      (256)

/* spectrum and channel data structures */
#define IWL_NUM_SCAN_RATES         (2)

#define IWL_SCAN_FLAG_24GHZ  (1<<0)
#define IWL_SCAN_FLAG_52GHZ  (1<<1)
#define IWL_SCAN_FLAG_ACTIVE (1<<2)
#define IWL_SCAN_FLAG_DIRECT (1<<3)

#define IWL_MAX_CMD_SIZE 1024

#define IWL_DEFAULT_TX_RETRY  15
#define IWL_MAX_TX_RETRY      16

/*********************************************/

#define RFD_SIZE                              4
#define NUM_TFD_CHUNKS                        4

#define RX_QUEUE_SIZE                         256
#define RX_QUEUE_MASK                         255
#define RX_QUEUE_SIZE_LOG                     8

/* QoS  definitions */

#define CW_MIN_OFDM          15
#define CW_MAX_OFDM          1023
#define CW_MIN_CCK           31
#define CW_MAX_CCK           1023

#define QOS_TX0_CW_MIN_OFDM      CW_MIN_OFDM
#define QOS_TX1_CW_MIN_OFDM      CW_MIN_OFDM
#define QOS_TX2_CW_MIN_OFDM      ((CW_MIN_OFDM + 1) / 2 - 1)
#define QOS_TX3_CW_MIN_OFDM      ((CW_MIN_OFDM + 1) / 4 - 1)

#define QOS_TX0_CW_MIN_CCK       CW_MIN_CCK
#define QOS_TX1_CW_MIN_CCK       CW_MIN_CCK
#define QOS_TX2_CW_MIN_CCK       ((CW_MIN_CCK + 1) / 2 - 1)
#define QOS_TX3_CW_MIN_CCK       ((CW_MIN_CCK + 1) / 4 - 1)

#define QOS_TX0_CW_MAX_OFDM      CW_MAX_OFDM
#define QOS_TX1_CW_MAX_OFDM      CW_MAX_OFDM
#define QOS_TX2_CW_MAX_OFDM      CW_MIN_OFDM
#define QOS_TX3_CW_MAX_OFDM      ((CW_MIN_OFDM + 1) / 2 - 1)

#define QOS_TX0_CW_MAX_CCK       CW_MAX_CCK
#define QOS_TX1_CW_MAX_CCK       CW_MAX_CCK
#define QOS_TX2_CW_MAX_CCK       CW_MIN_CCK
#define QOS_TX3_CW_MAX_CCK       ((CW_MIN_CCK + 1) / 2 - 1)

#define QOS_TX0_AIFS            3
#define QOS_TX1_AIFS            7
#define QOS_TX2_AIFS            2
#define QOS_TX3_AIFS            2

#define QOS_TX0_ACM             0
#define QOS_TX1_ACM             0
#define QOS_TX2_ACM             0
#define QOS_TX3_ACM             0

#define QOS_TX0_TXOP_LIMIT_CCK          0
#define QOS_TX1_TXOP_LIMIT_CCK          0
#define QOS_TX2_TXOP_LIMIT_CCK          6016
#define QOS_TX3_TXOP_LIMIT_CCK          3264

#define QOS_TX0_TXOP_LIMIT_OFDM      0
#define QOS_TX1_TXOP_LIMIT_OFDM      0
#define QOS_TX2_TXOP_LIMIT_OFDM      3008
#define QOS_TX3_TXOP_LIMIT_OFDM      1504

#define DEF_TX0_CW_MIN_OFDM      CW_MIN_OFDM
#define DEF_TX1_CW_MIN_OFDM      CW_MIN_OFDM
#define DEF_TX2_CW_MIN_OFDM      CW_MIN_OFDM
#define DEF_TX3_CW_MIN_OFDM      CW_MIN_OFDM

#define DEF_TX0_CW_MIN_CCK       CW_MIN_CCK
#define DEF_TX1_CW_MIN_CCK       CW_MIN_CCK
#define DEF_TX2_CW_MIN_CCK       CW_MIN_CCK
#define DEF_TX3_CW_MIN_CCK       CW_MIN_CCK

#define DEF_TX0_CW_MAX_OFDM      CW_MAX_OFDM
#define DEF_TX1_CW_MAX_OFDM      CW_MAX_OFDM
#define DEF_TX2_CW_MAX_OFDM      CW_MAX_OFDM
#define DEF_TX3_CW_MAX_OFDM      CW_MAX_OFDM

#define DEF_TX0_CW_MAX_CCK       CW_MAX_CCK
#define DEF_TX1_CW_MAX_CCK       CW_MAX_CCK
#define DEF_TX2_CW_MAX_CCK       CW_MAX_CCK
#define DEF_TX3_CW_MAX_CCK       CW_MAX_CCK

#define DEF_TX0_AIFS            (2)
#define DEF_TX1_AIFS            (2)
#define DEF_TX2_AIFS            (2)
#define DEF_TX3_AIFS            (2)

#define DEF_TX0_ACM             0
#define DEF_TX1_ACM             0
#define DEF_TX2_ACM             0
#define DEF_TX3_ACM             0

#define DEF_TX0_TXOP_LIMIT_CCK        0
#define DEF_TX1_TXOP_LIMIT_CCK        0
#define DEF_TX2_TXOP_LIMIT_CCK        0
#define DEF_TX3_TXOP_LIMIT_CCK        0

#define DEF_TX0_TXOP_LIMIT_OFDM       0
#define DEF_TX1_TXOP_LIMIT_OFDM       0
#define DEF_TX2_TXOP_LIMIT_OFDM       0
#define DEF_TX3_TXOP_LIMIT_OFDM       0

#define QOS_QOS_SETS                  3
#define QOS_PARAM_SET_ACTIVE          0
#define QOS_PARAM_SET_DEF_CCK         1
#define QOS_PARAM_SET_DEF_OFDM        2

#define CTRL_QOS_NO_ACK               (0x0020)
#define DCT_FLAG_EXT_QOS_ENABLED      (0x10)

#define U32_PAD(n)		((4-(n))&0x3)

/*
 * Generic queue structure
 *
 * Contains common data for Rx and Tx queues
 */
#define TFD_CTL_COUNT_SET(n)       (n<<24)
#define TFD_CTL_COUNT_GET(ctl)     ((ctl>>24) & 7)
#define TFD_CTL_PAD_SET(n)         (n<<28)
#define TFD_CTL_PAD_GET(ctl)       (ctl>>28)

#define TFD_TX_CMD_SLOTS 256
#define TFD_CMD_SLOTS 32

#define TFD_MAX_PAYLOAD_SIZE (sizeof(struct iwl_cmd) - \
			      sizeof(struct iwl_cmd_meta))

/*
 * RX related structures and functions
 */
#define RX_FREE_BUFFERS 64
#define RX_LOW_WATERMARK 8


#define IWL_RX_BUF_SIZE 3000
/* card static random access memory (SRAM) for processor data and instructs */
#define ALM_RTC_INST_UPPER_BOUND		(0x014000)
#define ALM_RTC_DATA_UPPER_BOUND		(0x808000)

#define ALM_RTC_INST_SIZE (ALM_RTC_INST_UPPER_BOUND - RTC_INST_LOWER_BOUND)
#define ALM_RTC_DATA_SIZE (ALM_RTC_DATA_UPPER_BOUND - RTC_DATA_LOWER_BOUND)

#define IWL_MAX_BSM_SIZE ALM_RTC_INST_SIZE
#define IWL_MAX_INST_SIZE ALM_RTC_INST_SIZE
#define IWL_MAX_DATA_SIZE ALM_RTC_DATA_SIZE
#define IWL_MAX_NUM_QUEUES	8

static inline int iwl_hw_valid_rtc_data_addr(u32 addr)
{
	return (addr >= RTC_DATA_LOWER_BOUND) &&
	       (addr < ALM_RTC_DATA_UPPER_BOUND);
}

/* Base physical address of iwl_shared is provided to FH_TSSR_CBB_BASE
 * and &iwl_shared.rx_read_ptr[0] is provided to FH_RCSR_RPTR_ADDR(0) */
struct iwl_shared {
	__le32 tx_base_ptr[8];
	__le32 rx_read_ptr[3];
} __attribute__ ((packed));

struct iwl_tfd_frame_data {
	__le32 addr;
	__le32 len;
} __attribute__ ((packed));

struct iwl_tfd_frame {
	__le32 control_flags;
	struct iwl_tfd_frame_data pa[4];
	u8 reserved[28];
} __attribute__ ((packed));

static inline u8 iwl_hw_get_rate(__le16 rate_n_flags)
{
	return le16_to_cpu(rate_n_flags) & 0xFF;
}

static inline u16 iwl_hw_get_rate_n_flags(__le16 rate_n_flags)
{
	return le16_to_cpu(rate_n_flags);
}

static inline __le16 iwl_hw_set_rate_n_flags(u8 rate, u16 flags)
{
	return cpu_to_le16((u16)rate|flags);
}
#endif
