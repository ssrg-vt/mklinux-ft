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
/*
 * Please use this file (iwl-4965-hw.h) only for hardware-related definitions.
 * Use iwl-4965-commands.h for uCode API definitions.
 * Use iwl-4965.h for driver implementation definitions.
 */

#ifndef __iwl_4965_hw_h__
#define __iwl_4965_hw_h__

/*
 * uCode queue management definitions ...
 * Queue #4 is the command queue for 3945 and 4965; map it to Tx FIFO chnl 4.
 * The first queue used for block-ack aggregation is #7 (4965 only).
 * All block-ack aggregation queues should map to Tx DMA/FIFO channel 7.
 */
#define IWL_CMD_QUEUE_NUM       4
#define IWL_CMD_FIFO_NUM        4
#define IWL_BACK_QUEUE_FIRST_ID 7

/* Tx rates */
#define IWL_CCK_RATES 4
#define IWL_OFDM_RATES 8
#define IWL_HT_RATES 16
#define IWL_MAX_RATES  (IWL_CCK_RATES+IWL_OFDM_RATES+IWL_HT_RATES)

/* Time constants */
#define SHORT_SLOT_TIME 9
#define LONG_SLOT_TIME 20

/* RSSI to dBm */
#define IWL_RSSI_OFFSET	44

/*
 * EEPROM related constants, enums, and structures.
 */

/*
 * EEPROM access time values:
 *
 * Driver initiates EEPROM read by writing byte address << 1 to CSR_EEPROM_REG,
 *   then clearing (with subsequent read/modify/write) CSR_EEPROM_REG bit
 *   CSR_EEPROM_REG_BIT_CMD (0x2).
 * Driver then polls CSR_EEPROM_REG for CSR_EEPROM_REG_READ_VALID_MSK (0x1).
 * When polling, wait 10 uSec between polling loops, up to a maximum 5000 uSec.
 * Driver reads 16-bit value from bits 31-16 of CSR_EEPROM_REG.
 */
#define IWL_EEPROM_ACCESS_TIMEOUT	5000 /* uSec */
#define IWL_EEPROM_ACCESS_DELAY		10   /* uSec */

/*
 * Regulatory channel usage flags in EEPROM struct iwl4965_eeprom_channel.flags.
 *
 * IBSS and/or AP operation is allowed *only* on those channels with
 * (VALID && IBSS && ACTIVE && !RADAR).  This restriction is in place because
 * RADAR detection is not supported by the 4965 driver, but is a
 * requirement for establishing a new network for legal operation on channels
 * requiring RADAR detection or restricting ACTIVE scanning.
 *
 * NOTE:  "WIDE" flag does not indicate anything about "FAT" 40 MHz channels.
 *        It only indicates that 20 MHz channel use is supported; FAT channel
 *        usage is indicated by a separate set of regulatory flags for each
 *        FAT channel pair.
 *
 * NOTE:  Using a channel inappropriately will result in a uCode error!
 */
enum {
	EEPROM_CHANNEL_VALID = (1 << 0),	/* usable for this SKU/geo */
	EEPROM_CHANNEL_IBSS = (1 << 1),		/* usable as an IBSS channel */
	/* Bit 2 Reserved */
	EEPROM_CHANNEL_ACTIVE = (1 << 3),	/* active scanning allowed */
	EEPROM_CHANNEL_RADAR = (1 << 4),	/* radar detection required */
	EEPROM_CHANNEL_WIDE = (1 << 5),		/* 20 MHz channel okay */
	EEPROM_CHANNEL_NARROW = (1 << 6),	/* 10 MHz channel (not used) */
	EEPROM_CHANNEL_DFS = (1 << 7),	/* dynamic freq selection candidate */
};

/* SKU Capabilities */
#define EEPROM_SKU_CAP_SW_RF_KILL_ENABLE                (1 << 0)
#define EEPROM_SKU_CAP_HW_RF_KILL_ENABLE                (1 << 1)

/* *regulatory* channel data format in eeprom, one for each channel.
 * There are separate entries for FAT (40 MHz) vs. normal (20 MHz) channels. */
struct iwl4965_eeprom_channel {
	u8 flags;		/* EEPROM_CHANNEL_* flags copied from EEPROM */
	s8 max_power_avg;	/* max power (dBm) on this chnl, limit 31 */
} __attribute__ ((packed));

/* 4965 has two radio transmitters (and 3 radio receivers) */
#define EEPROM_TX_POWER_TX_CHAINS      (2)

/* 4965 has room for up to 8 sets of txpower calibration data */
#define EEPROM_TX_POWER_BANDS          (8)

/* 4965 factory calibration measures txpower gain settings for
 * each of 3 target output levels */
#define EEPROM_TX_POWER_MEASUREMENTS   (3)

/* 4965 driver does not work with txpower calibration version < 5.
 * Look for this in calib_version member of struct iwl4965_eeprom. */
#define EEPROM_TX_POWER_VERSION_NEW    (5)


/*
 * 4965 factory calibration data for one txpower level, on one channel,
 * measured on one of the 2 tx chains (radio transmitter and associated
 * antenna).  EEPROM contains:
 *
 * 1)  Temperature (degrees Celsius) of device when measurement was made.
 *
 * 2)  Gain table index used to achieve the target measurement power.
 *     This refers to the "well-known" gain tables (see iwl-4965-hw.h).
 *
 * 3)  Actual measured output power, in half-dBm ("34" = 17 dBm).
 *
 * 4)  RF power amplifier detector level measurement (not used).
 */
struct iwl4965_eeprom_calib_measure {
	u8 temperature;		/* Device temperature (Celsius) */
	u8 gain_idx;		/* Index into gain table */
	u8 actual_pow;		/* Measured RF output power, half-dBm */
	s8 pa_det;		/* Power amp detector level (not used) */
} __attribute__ ((packed));


/*
 * 4965 measurement set for one channel.  EEPROM contains:
 *
 * 1)  Channel number measured
 *
 * 2)  Measurements for each of 3 power levels for each of 2 radio transmitters
 *     (a.k.a. "tx chains") (6 measurements altogether)
 */
struct iwl4965_eeprom_calib_ch_info {
	u8 ch_num;
	struct iwl4965_eeprom_calib_measure measurements[EEPROM_TX_POWER_TX_CHAINS]
		[EEPROM_TX_POWER_MEASUREMENTS];
} __attribute__ ((packed));

/*
 * 4965 txpower subband info.
 *
 * For each frequency subband, EEPROM contains the following:
 *
 * 1)  First and last channels within range of the subband.  "0" values
 *     indicate that this sample set is not being used.
 *
 * 2)  Sample measurement sets for 2 channels close to the range endpoints.
 */
struct iwl4965_eeprom_calib_subband_info {
	u8 ch_from;	/* channel number of lowest channel in subband */
	u8 ch_to;	/* channel number of highest channel in subband */
	struct iwl4965_eeprom_calib_ch_info ch1;
	struct iwl4965_eeprom_calib_ch_info ch2;
} __attribute__ ((packed));


/*
 * 4965 txpower calibration info.  EEPROM contains:
 *
 * 1)  Factory-measured saturation power levels (maximum levels at which
 *     tx power amplifier can output a signal without too much distortion).
 *     There is one level for 2.4 GHz band and one for 5 GHz band.  These
 *     values apply to all channels within each of the bands.
 *
 * 2)  Factory-measured power supply voltage level.  This is assumed to be
 *     constant (i.e. same value applies to all channels/bands) while the
 *     factory measurements are being made.
 *
 * 3)  Up to 8 sets of factory-measured txpower calibration values.
 *     These are for different frequency ranges, since txpower gain
 *     characteristics of the analog radio circuitry vary with frequency.
 *
 *     Not all sets need to be filled with data;
 *     struct iwl4965_eeprom_calib_subband_info contains range of channels
 *     (0 if unused) for each set of data.
 */
struct iwl4965_eeprom_calib_info {
	u8 saturation_power24;	/* half-dBm (e.g. "34" = 17 dBm) */
	u8 saturation_power52;	/* half-dBm */
	s16 voltage;		/* signed */
	struct iwl4965_eeprom_calib_subband_info band_info[EEPROM_TX_POWER_BANDS];
} __attribute__ ((packed));


/*
 * 4965 EEPROM map
 */
struct iwl4965_eeprom {
	u8 reserved0[16];
#define EEPROM_DEVICE_ID                    (2*0x08)	/* 2 bytes */
	u16 device_id;		/* abs.ofs: 16 */
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
	u8 reserved6[8];
#define EEPROM_4965_BOARD_REVISION          (2*0x4F)	/* 2 bytes */
	u16 board_revision_4965;	/* abs.ofs: 158 */
	u8 reserved7[13];
#define EEPROM_4965_BOARD_PBA               (2*0x56+1)	/* 9 bytes */
	u8 board_pba_number_4965[9];	/* abs.ofs: 173 */
	u8 reserved8[10];
#define EEPROM_REGULATORY_SKU_ID            (2*0x60)	/* 4  bytes */
	u8 sku_id[4];		/* abs.ofs: 192 */

/*
 * Per-channel regulatory data.
 *
 * Each channel that *might* be supported by 3945 or 4965 has a fixed location
 * in EEPROM containing EEPROM_CHANNEL_* usage flags (LSB) and max regulatory
 * txpower (MSB).
 *
 * Entries immediately below are for 20 MHz channel width.  FAT (40 MHz)
 * channels (only for 4965, not supported by 3945) appear later in the EEPROM.
 *
 * 2.4 GHz channels 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
 */
#define EEPROM_REGULATORY_BAND_1            (2*0x62)	/* 2  bytes */
	u16 band_1_count;	/* abs.ofs: 196 */
#define EEPROM_REGULATORY_BAND_1_CHANNELS   (2*0x63)	/* 28 bytes */
	struct iwl4965_eeprom_channel band_1_channels[14]; /* abs.ofs: 196 */

/*
 * 4.9 GHz channels 183, 184, 185, 187, 188, 189, 192, 196,
 * 5.0 GHz channels 7, 8, 11, 12, 16
 * (4915-5080MHz) (none of these is ever supported)
 */
#define EEPROM_REGULATORY_BAND_2            (2*0x71)	/* 2  bytes */
	u16 band_2_count;	/* abs.ofs: 226 */
#define EEPROM_REGULATORY_BAND_2_CHANNELS   (2*0x72)	/* 26 bytes */
	struct iwl4965_eeprom_channel band_2_channels[13]; /* abs.ofs: 228 */

/*
 * 5.2 GHz channels 34, 36, 38, 40, 42, 44, 46, 48, 52, 56, 60, 64
 * (5170-5320MHz)
 */
#define EEPROM_REGULATORY_BAND_3            (2*0x7F)	/* 2  bytes */
	u16 band_3_count;	/* abs.ofs: 254 */
#define EEPROM_REGULATORY_BAND_3_CHANNELS   (2*0x80)	/* 24 bytes */
	struct iwl4965_eeprom_channel band_3_channels[12]; /* abs.ofs: 256 */

/*
 * 5.5 GHz channels 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140
 * (5500-5700MHz)
 */
#define EEPROM_REGULATORY_BAND_4            (2*0x8C)	/* 2  bytes */
	u16 band_4_count;	/* abs.ofs: 280 */
#define EEPROM_REGULATORY_BAND_4_CHANNELS   (2*0x8D)	/* 22 bytes */
	struct iwl4965_eeprom_channel band_4_channels[11]; /* abs.ofs: 282 */

/*
 * 5.7 GHz channels 145, 149, 153, 157, 161, 165
 * (5725-5825MHz)
 */
#define EEPROM_REGULATORY_BAND_5            (2*0x98)	/* 2  bytes */
	u16 band_5_count;	/* abs.ofs: 304 */
#define EEPROM_REGULATORY_BAND_5_CHANNELS   (2*0x99)	/* 12 bytes */
	struct iwl4965_eeprom_channel band_5_channels[6]; /* abs.ofs: 306 */

	u8 reserved10[2];


/*
 * 2.4 GHz FAT channels 1 (5), 2 (6), 3 (7), 4 (8), 5 (9), 6 (10), 7 (11)
 *
 * The channel listed is the center of the lower 20 MHz half of the channel.
 * The overall center frequency is actually 2 channels (10 MHz) above that,
 * and the upper half of each FAT channel is centered 4 channels (20 MHz) away
 * from the lower half; e.g. the upper half of FAT channel 1 is channel 5,
 * and the overall FAT channel width centers on channel 3.
 *
 * NOTE:  The RXON command uses 20 MHz channel numbers to specify the
 *        control channel to which to tune.  RXON also specifies whether the
 *        control channel is the upper or lower half of a FAT channel.
 *
 * NOTE:  4965 does not support FAT channels on 2.4 GHz.
 */
#define EEPROM_REGULATORY_BAND_24_FAT_CHANNELS (2*0xA0)	/* 14 bytes */
	struct iwl4965_eeprom_channel band_24_channels[7]; /* abs.ofs: 320 */
	u8 reserved11[2];

/*
 * 5.2 GHz FAT channels 36 (40), 44 (48), 52 (56), 60 (64),
 * 100 (104), 108 (112), 116 (120), 124 (128), 132 (136), 149 (153), 157 (161)
 */
#define EEPROM_REGULATORY_BAND_52_FAT_CHANNELS (2*0xA8)	/* 22 bytes */
	struct iwl4965_eeprom_channel band_52_channels[11]; /* abs.ofs: 336 */
	u8 reserved12[6];

/*
 * 4965 driver requires txpower calibration format version 5 or greater.
 * Driver does not work with txpower calibration version < 5.
 * This value is simply a 16-bit number, no major/minor versions here.
 */
#define EEPROM_CALIB_VERSION_OFFSET            (2*0xB6)	/* 2 bytes */
	u16 calib_version;	/* abs.ofs: 364 */
	u8 reserved13[2];
	u8 reserved14[96];	/* abs.ofs: 368 */

/*
 * 4965 Txpower calibration data.
 */
#define EEPROM_IWL_CALIB_TXPOWER_OFFSET        (2*0xE8)	/* 48  bytes */
	struct iwl4965_eeprom_calib_info calib_info;	/* abs.ofs: 464 */

	u8 reserved16[140];	/* fill out to full 1024 byte block */


} __attribute__ ((packed));

#define IWL_EEPROM_IMAGE_SIZE 1024

/* End of EEPROM */

#include "iwl-4965-commands.h"

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

/*
 * Hardware revision info
 * Bit fields:
 * 31-8:  Reserved
 *  7-4:  Type of device:  0x0 = 4965, 0xd = 3945
 *  3-2:  Revision step:  0 = A, 1 = B, 2 = C, 3 = D
 *  1-0:  "Dash" value, as in A-1, etc.
 *
 * NOTE:  Revision step affects calculation of CCK txpower for 4965.
 */
#define CSR_HW_REV              (CSR_BASE+0x028)

/* EEPROM reads */
#define CSR_EEPROM_REG          (CSR_BASE+0x02c)
#define CSR_EEPROM_GP           (CSR_BASE+0x030)
#define CSR_GP_UCODE		(CSR_BASE+0x044)
#define CSR_UCODE_DRV_GP1       (CSR_BASE+0x054)
#define CSR_UCODE_DRV_GP1_SET   (CSR_BASE+0x058)
#define CSR_UCODE_DRV_GP1_CLR   (CSR_BASE+0x05c)
#define CSR_UCODE_DRV_GP2       (CSR_BASE+0x060)
#define CSR_GIO_CHICKEN_BITS    (CSR_BASE+0x100)

/*
 * Indicates hardware rev, to determine CCK backoff for txpower calculation.
 * Bit fields:
 *  3-2:  0 = A, 1 = B, 2 = C, 3 = D step
 */
#define CSR_HW_REV_WA_REG	(CSR_BASE+0x22C)

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
#define CSR_FH_INT_BIT_RX_CHNL1  (1<<17) /* Rx channel 1 */
#define CSR_FH_INT_BIT_RX_CHNL0  (1<<16) /* Rx channel 0 */
#define CSR_FH_INT_BIT_TX_CHNL1  (1<<1)  /* Tx channel 1 */
#define CSR_FH_INT_BIT_TX_CHNL0  (1<<0)  /* Tx channel 0 */

#define CSR_FH_INT_RX_MASK	(CSR_FH_INT_BIT_HI_PRIOR | \
				 CSR_FH_INT_BIT_RX_CHNL1 | \
				 CSR_FH_INT_BIT_RX_CHNL0)

#define CSR_FH_INT_TX_MASK	(CSR_FH_INT_BIT_TX_CHNL1 | \
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

/*=== HBUS (Host-side Bus) ===*/
#define HBUS_BASE	(0x400)

/*
 * Registers for accessing device's internal SRAM memory (e.g. SCD SRAM
 * structures, error log, event log, verifying uCode load).
 * First write to address register, then read from or write to data register
 * to complete the job.  Once the address register is set up, accesses to
 * data registers auto-increment the address by one dword.
 * Bit usage for address registers (read or write):
 *  0-31:  memory address within device
 */
#define HBUS_TARG_MEM_RADDR     (HBUS_BASE+0x00c)
#define HBUS_TARG_MEM_WADDR     (HBUS_BASE+0x010)
#define HBUS_TARG_MEM_WDAT      (HBUS_BASE+0x018)
#define HBUS_TARG_MEM_RDAT      (HBUS_BASE+0x01c)

/*
 * Registers for accessing device's internal peripheral registers
 * (e.g. SCD, BSM, etc.).  First write to address register,
 * then read from or write to data register to complete the job.
 * Bit usage for address registers (read or write):
 *  0-15:  register address (offset) within device
 * 24-25:  (# bytes - 1) to read or write (e.g. 3 for dword)
 */
#define HBUS_TARG_PRPH_WADDR    (HBUS_BASE+0x044)
#define HBUS_TARG_PRPH_RADDR    (HBUS_BASE+0x048)
#define HBUS_TARG_PRPH_WDAT     (HBUS_BASE+0x04c)
#define HBUS_TARG_PRPH_RDAT     (HBUS_BASE+0x050)

/*
 * Per-Tx-queue write pointer (index, really!) (3945 and 4965).
 * Indicates index to next TFD that driver will fill (1 past latest filled).
 * Bit usage:
 *  0-7:  queue write index (0-255)
 * 11-8:  queue selector (0-15)
 */
#define HBUS_TARG_WRPTR         (HBUS_BASE+0x060)

#define HBUS_TARG_MBX_C         (HBUS_BASE+0x030)

/*=== FH (data Flow Handler) ===*/
#define FH_BASE     (0x800)

#define FH_RSCSR_CHNL0_WPTR        (FH_RSCSR_CHNL0_RBDCB_WPTR_REG)

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


#define HBUS_TARG_MBX_C_REG_BIT_CMD_BLOCKED         (0x00000004)

#define TFD_QUEUE_SIZE_MAX      (256)

#define IWL_NUM_SCAN_RATES         (2)

#define IWL_DEFAULT_TX_RETRY  15

#define RX_QUEUE_SIZE                         256
#define RX_QUEUE_MASK                         255
#define RX_QUEUE_SIZE_LOG                     8

#define TFD_TX_CMD_SLOTS 256
#define TFD_CMD_SLOTS 32

#define TFD_MAX_PAYLOAD_SIZE (sizeof(struct iwl4965_cmd) - \
			      sizeof(struct iwl4965_cmd_meta))

/*
 * RX related structures and functions
 */
#define RX_FREE_BUFFERS 64
#define RX_LOW_WATERMARK 8

/* Size of one Rx buffer in host DRAM */
#define IWL_RX_BUF_SIZE (4 * 1024)

/* Sizes and addresses for instruction and data memory (SRAM) in
 * 4965's embedded processor.  Driver access is via HBUS_TARG_MEM_* regs. */
#define RTC_INST_LOWER_BOUND			(0x000000)
#define KDR_RTC_INST_UPPER_BOUND		(0x018000)

#define RTC_DATA_LOWER_BOUND			(0x800000)
#define KDR_RTC_DATA_UPPER_BOUND		(0x80A000)

#define KDR_RTC_INST_SIZE    (KDR_RTC_INST_UPPER_BOUND - RTC_INST_LOWER_BOUND)
#define KDR_RTC_DATA_SIZE    (KDR_RTC_DATA_UPPER_BOUND - RTC_DATA_LOWER_BOUND)

#define IWL_MAX_INST_SIZE KDR_RTC_INST_SIZE
#define IWL_MAX_DATA_SIZE KDR_RTC_DATA_SIZE

/* Size of uCode instruction memory in bootstrap state machine */
#define IWL_MAX_BSM_SIZE BSM_SRAM_SIZE

static inline int iwl4965_hw_valid_rtc_data_addr(u32 addr)
{
	return (addr >= RTC_DATA_LOWER_BOUND) &&
	       (addr < KDR_RTC_DATA_UPPER_BOUND);
}

/********************* START TEMPERATURE *************************************/

/*
 * 4965 temperature calculation.
 *
 * The driver must calculate the device temperature before calculating
 * a txpower setting (amplifier gain is temperature dependent).  The
 * calculation uses 4 measurements, 3 of which (R1, R2, R3) are calibration
 * values used for the life of the driver, and one of which (R4) is the
 * real-time temperature indicator.
 *
 * uCode provides all 4 values to the driver via the "initialize alive"
 * notification (see struct iwl4965_init_alive_resp).  After the runtime uCode
 * image loads, uCode updates the R4 value via statistics notifications
 * (see STATISTICS_NOTIFICATION), which occur after each received beacon
 * when associated, or can be requested via REPLY_STATISTICS_CMD.
 *
 * NOTE:  uCode provides the R4 value as a 23-bit signed value.  Driver
 *        must sign-extend to 32 bits before applying formula below.
 *
 * Formula:
 *
 * degrees Kelvin = ((97 * 259 * (R4 - R2) / (R3 - R1)) / 100) + 8
 *
 * NOTE:  The basic formula is 259 * (R4-R2) / (R3-R1).  The 97/100 is
 * an additional correction, which should be centered around 0 degrees
 * Celsius (273 degrees Kelvin).  The 8 (3 percent of 273) compensates for
 * centering the 97/100 correction around 0 degrees K.
 *
 * Add 273 to Kelvin value to find degrees Celsius, for comparing current
 * temperature with factory-measured temperatures when calculating txpower
 * settings.
 */
#define TEMPERATURE_CALIB_KELVIN_OFFSET 8
#define TEMPERATURE_CALIB_A_VAL 259

/* Limit range of calculated temperature to be between these Kelvin values */
#define IWL_TX_POWER_TEMPERATURE_MIN  (263)
#define IWL_TX_POWER_TEMPERATURE_MAX  (410)

#define IWL_TX_POWER_TEMPERATURE_OUT_OF_RANGE(t) \
	(((t) < IWL_TX_POWER_TEMPERATURE_MIN) || \
	 ((t) > IWL_TX_POWER_TEMPERATURE_MAX))

/********************* END TEMPERATURE ***************************************/

/********************* START TXPOWER *****************************************/

enum {
	CALIB_CH_GROUP_1 = 0,
	CALIB_CH_GROUP_2 = 1,
	CALIB_CH_GROUP_3 = 2,
	CALIB_CH_GROUP_4 = 3,
	CALIB_CH_GROUP_5 = 4,
	CALIB_CH_GROUP_MAX
};

#define IWL_TX_POWER_MIMO_REGULATORY_COMPENSATION (6)

#define IWL_TX_POWER_TARGET_POWER_MIN       (0)	/* 0 dBm = 1 milliwatt */
#define IWL_TX_POWER_TARGET_POWER_MAX      (16)	/* 16 dBm */

#define MIN_TX_GAIN_INDEX		(0)
#define MIN_TX_GAIN_INDEX_52GHZ_EXT	(-9)

#define IWL_TX_POWER_DEFAULT_REGULATORY_24   (34)
#define IWL_TX_POWER_DEFAULT_REGULATORY_52   (34)
#define IWL_TX_POWER_REGULATORY_MIN          (0)
#define IWL_TX_POWER_REGULATORY_MAX          (34)
#define IWL_TX_POWER_DEFAULT_SATURATION_24   (38)
#define IWL_TX_POWER_DEFAULT_SATURATION_52   (38)
#define IWL_TX_POWER_SATURATION_MIN          (20)
#define IWL_TX_POWER_SATURATION_MAX          (50)

/* First and last channels of all groups */
#define CALIB_IWL_TX_ATTEN_GR1_FCH 34
#define CALIB_IWL_TX_ATTEN_GR1_LCH 43
#define CALIB_IWL_TX_ATTEN_GR2_FCH 44
#define CALIB_IWL_TX_ATTEN_GR2_LCH 70
#define CALIB_IWL_TX_ATTEN_GR3_FCH 71
#define CALIB_IWL_TX_ATTEN_GR3_LCH 124
#define CALIB_IWL_TX_ATTEN_GR4_FCH 125
#define CALIB_IWL_TX_ATTEN_GR4_LCH 200
#define CALIB_IWL_TX_ATTEN_GR5_FCH 1
#define CALIB_IWL_TX_ATTEN_GR5_LCH 20

/********************* END TXPOWER *****************************************/

/* Flow Handler Definitions */

/**********************/
/*     Addresses      */
/**********************/

#define FH_MEM_LOWER_BOUND                   (0x1000)
#define FH_MEM_UPPER_BOUND                   (0x1EF0)

#define IWL_FH_REGS_LOWER_BOUND		     (0x1000)
#define IWL_FH_REGS_UPPER_BOUND		     (0x2000)

#define IWL_FH_KW_MEM_ADDR_REG		     (FH_MEM_LOWER_BOUND + 0x97C)

/* CBBC Area - Circular buffers base address cache pointers table */
#define FH_MEM_CBBC_LOWER_BOUND              (FH_MEM_LOWER_BOUND + 0x9D0)
#define FH_MEM_CBBC_UPPER_BOUND              (FH_MEM_LOWER_BOUND + 0xA10)
/* queues 0 - 15 */
#define FH_MEM_CBBC_QUEUE(x)  (FH_MEM_CBBC_LOWER_BOUND + (x) * 0x4)

/* RSCSR Area */
#define FH_MEM_RSCSR_LOWER_BOUND	(FH_MEM_LOWER_BOUND + 0xBC0)
#define FH_MEM_RSCSR_UPPER_BOUND	(FH_MEM_LOWER_BOUND + 0xC00)
#define FH_MEM_RSCSR_CHNL0		(FH_MEM_RSCSR_LOWER_BOUND)

#define FH_RSCSR_CHNL0_STTS_WPTR_REG		(FH_MEM_RSCSR_CHNL0)
#define FH_RSCSR_CHNL0_RBDCB_BASE_REG		(FH_MEM_RSCSR_CHNL0 + 0x004)
#define FH_RSCSR_CHNL0_RBDCB_WPTR_REG		(FH_MEM_RSCSR_CHNL0 + 0x008)

/* RCSR Area - Registers address map */
#define FH_MEM_RCSR_LOWER_BOUND      (FH_MEM_LOWER_BOUND + 0xC00)
#define FH_MEM_RCSR_UPPER_BOUND      (FH_MEM_LOWER_BOUND + 0xCC0)
#define FH_MEM_RCSR_CHNL0            (FH_MEM_RCSR_LOWER_BOUND)

#define FH_MEM_RCSR_CHNL0_CONFIG_REG	(FH_MEM_RCSR_CHNL0)

/* RSSR Area - Rx shared ctrl & status registers */
#define FH_MEM_RSSR_LOWER_BOUND                	(FH_MEM_LOWER_BOUND + 0xC40)
#define FH_MEM_RSSR_UPPER_BOUND               	(FH_MEM_LOWER_BOUND + 0xD00)
#define FH_MEM_RSSR_SHARED_CTRL_REG           	(FH_MEM_RSSR_LOWER_BOUND)
#define FH_MEM_RSSR_RX_STATUS_REG	(FH_MEM_RSSR_LOWER_BOUND + 0x004)
#define FH_MEM_RSSR_RX_ENABLE_ERR_IRQ2DRV  (FH_MEM_RSSR_LOWER_BOUND + 0x008)

/* TCSR */
#define IWL_FH_TCSR_LOWER_BOUND  (IWL_FH_REGS_LOWER_BOUND + 0xD00)
#define IWL_FH_TCSR_UPPER_BOUND  (IWL_FH_REGS_LOWER_BOUND + 0xE60)

#define IWL_FH_TCSR_CHNL_TX_CONFIG_REG(_chnl) \
	(IWL_FH_TCSR_LOWER_BOUND + 0x20 * _chnl)

/* TSSR Area - Tx shared status registers */
/* TSSR */
#define IWL_FH_TSSR_LOWER_BOUND		(IWL_FH_REGS_LOWER_BOUND + 0xEA0)
#define IWL_FH_TSSR_UPPER_BOUND		(IWL_FH_REGS_LOWER_BOUND + 0xEC0)

#define IWL_FH_TSSR_TX_STATUS_REG	(IWL_FH_TSSR_LOWER_BOUND + 0x010)

#define IWL_FH_TSSR_TX_STATUS_REG_BIT_BUFS_EMPTY(_chnl)	\
	((1 << (_chnl)) << 24)
#define IWL_FH_TSSR_TX_STATUS_REG_BIT_NO_PEND_REQ(_chnl) \
	((1 << (_chnl)) << 16)

#define IWL_FH_TSSR_TX_STATUS_REG_MSK_CHNL_IDLE(_chnl) \
	(IWL_FH_TSSR_TX_STATUS_REG_BIT_BUFS_EMPTY(_chnl) | \
	IWL_FH_TSSR_TX_STATUS_REG_BIT_NO_PEND_REQ(_chnl))

#define IWL_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE_VAL     (0x00000008)

#define IWL_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE           (0x80000000)

/* RCSR:  channel 0 rx_config register defines */

#define FH_RCSR_RX_CONFIG_RBDCB_SIZE_BITSHIFT       (20)

#define FH_RCSR_RX_CONFIG_CHNL_EN_ENABLE_VAL        (0x80000000)

#define IWL_FH_RCSR_RX_CONFIG_REG_VAL_RB_SIZE_4K    (0x00000000)

/* RCSR channel 0 config register values */
#define FH_RCSR_CHNL0_RX_CONFIG_IRQ_DEST_INT_HOST_VAL     (0x00001000)

#define SCD_WIN_SIZE				64
#define SCD_FRAME_LIMIT				64

/* SRAM structures */
#define SCD_CONTEXT_DATA_OFFSET			0x380
#define SCD_TX_STTS_BITMAP_OFFSET		0x400
#define SCD_TRANSLATE_TBL_OFFSET		0x500
#define SCD_CONTEXT_QUEUE_OFFSET(x)	(SCD_CONTEXT_DATA_OFFSET + ((x) * 8))
#define SCD_TRANSLATE_TBL_OFFSET_QUEUE(x) \
	((SCD_TRANSLATE_TBL_OFFSET + ((x) * 2)) & 0xfffffffc)

#define SCD_TXFACT_REG_TXFIFO_MASK(lo, hi) \
       ((1<<(hi))|((1<<(hi))-(1<<(lo))))

#define SCD_QUEUE_STTS_REG_POS_ACTIVE		(0)
#define SCD_QUEUE_STTS_REG_POS_TXF		(1)
#define SCD_QUEUE_STTS_REG_POS_WSL		(5)
#define SCD_QUEUE_STTS_REG_POS_SCD_ACK		(8)
#define SCD_QUEUE_STTS_REG_POS_SCD_ACT_EN	(10)
#define SCD_QUEUE_STTS_REG_MSK			(0x0007FC00)

#define SCD_QUEUE_CTX_REG1_WIN_SIZE_POS		(0)
#define SCD_QUEUE_CTX_REG1_WIN_SIZE_MSK		(0x0000007F)

#define SCD_QUEUE_CTX_REG2_FRAME_LIMIT_POS	(16)
#define SCD_QUEUE_CTX_REG2_FRAME_LIMIT_MSK	(0x007F0000)

#define CSR_HW_IF_CONFIG_REG_BIT_KEDRON_R	(0x00000010)
#define CSR_HW_IF_CONFIG_REG_MSK_BOARD_VER	(0x00000C00)
#define CSR_HW_IF_CONFIG_REG_BIT_MAC_SI		(0x00000100)
#define CSR_HW_IF_CONFIG_REG_BIT_RADIO_SI	(0x00000200)
#define CSR_HW_IF_CONFIG_REG_BIT_EEPROM_OWN_SEM (0x00200000)

static inline u8 iwl4965_hw_get_rate(__le32 rate_n_flags)
{
	return le32_to_cpu(rate_n_flags) & 0xFF;
}
static inline u16 iwl4965_hw_get_rate_n_flags(__le32 rate_n_flags)
{
	return le32_to_cpu(rate_n_flags) & 0xFFFF;
}
static inline __le32 iwl4965_hw_set_rate_n_flags(u8 rate, u16 flags)
{
	return cpu_to_le32(flags|(u16)rate);
}

struct iwl4965_tfd_frame_data {
	__le32 tb1_addr;

	__le32 val1;
	/* __le32 ptb1_32_35:4; */
#define IWL_tb1_addr_hi_POS 0
#define IWL_tb1_addr_hi_LEN 4
#define IWL_tb1_addr_hi_SYM val1
	/* __le32 tb_len1:12; */
#define IWL_tb1_len_POS 4
#define IWL_tb1_len_LEN 12
#define IWL_tb1_len_SYM val1
	/* __le32 ptb2_0_15:16; */
#define IWL_tb2_addr_lo16_POS 16
#define IWL_tb2_addr_lo16_LEN 16
#define IWL_tb2_addr_lo16_SYM val1

	__le32 val2;
	/* __le32 ptb2_16_35:20; */
#define IWL_tb2_addr_hi20_POS 0
#define IWL_tb2_addr_hi20_LEN 20
#define IWL_tb2_addr_hi20_SYM val2
	/* __le32 tb_len2:12; */
#define IWL_tb2_len_POS 20
#define IWL_tb2_len_LEN 12
#define IWL_tb2_len_SYM val2
} __attribute__ ((packed));

struct iwl4965_tfd_frame {
	__le32 val0;
	/* __le32 rsvd1:24; */
	/* __le32 num_tbs:5; */
#define IWL_num_tbs_POS 24
#define IWL_num_tbs_LEN 5
#define IWL_num_tbs_SYM val0
	/* __le32 rsvd2:1; */
	/* __le32 padding:2; */
	struct iwl4965_tfd_frame_data pa[10];
	__le32 reserved;
} __attribute__ ((packed));

#define IWL4965_MAX_WIN_SIZE              64
#define IWL4965_QUEUE_SIZE               256
#define IWL4965_NUM_FIFOS                  7
#define IWL_MAX_NUM_QUEUES                16

struct iwl4965_queue_byte_cnt_entry {
	__le16 val;
	/* __le16 byte_cnt:12; */
#define IWL_byte_cnt_POS 0
#define IWL_byte_cnt_LEN 12
#define IWL_byte_cnt_SYM val
	/* __le16 rsvd:4; */
} __attribute__ ((packed));

struct iwl4965_sched_queue_byte_cnt_tbl {
	struct iwl4965_queue_byte_cnt_entry tfd_offset[IWL4965_QUEUE_SIZE +
						       IWL4965_MAX_WIN_SIZE];
	u8 dont_care[1024 -
		     (IWL4965_QUEUE_SIZE + IWL4965_MAX_WIN_SIZE) *
		     sizeof(__le16)];
} __attribute__ ((packed));

/* Base physical address of iwl4965_shared is provided to KDR_SCD_DRAM_BASE_ADDR
 * and &iwl4965_shared.val0 is provided to FH_RSCSR_CHNL0_STTS_WPTR_REG */
struct iwl4965_shared {
	struct iwl4965_sched_queue_byte_cnt_tbl
	 queues_byte_cnt_tbls[IWL_MAX_NUM_QUEUES];
	__le32 val0;

	/* __le32 rb_closed_stts_rb_num:12; */
#define IWL_rb_closed_stts_rb_num_POS 0
#define IWL_rb_closed_stts_rb_num_LEN 12
#define IWL_rb_closed_stts_rb_num_SYM val0
	/* __le32 rsrv1:4; */
	/* __le32 rb_closed_stts_rx_frame_num:12; */
#define IWL_rb_closed_stts_rx_frame_num_POS 16
#define IWL_rb_closed_stts_rx_frame_num_LEN 12
#define IWL_rb_closed_stts_rx_frame_num_SYM val0
	/* __le32 rsrv2:4; */

	__le32 val1;
	/* __le32 frame_finished_stts_rb_num:12; */
#define IWL_frame_finished_stts_rb_num_POS 0
#define IWL_frame_finished_stts_rb_num_LEN 12
#define IWL_frame_finished_stts_rb_num_SYM val1
	/* __le32 rsrv3:4; */
	/* __le32 frame_finished_stts_rx_frame_num:12; */
#define IWL_frame_finished_stts_rx_frame_num_POS 16
#define IWL_frame_finished_stts_rx_frame_num_LEN 12
#define IWL_frame_finished_stts_rx_frame_num_SYM val1
	/* __le32 rsrv4:4; */

	__le32 padding1;  /* so that allocation will be aligned to 16B */
	__le32 padding2;
} __attribute__ ((packed));

#endif /* __iwl4965_4965_hw_h__ */
