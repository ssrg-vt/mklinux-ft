/*
 * mac80211 <-> driver interface
 *
 * Copyright 2002-2005, Devicescape Software, Inc.
 * Copyright 2006-2007	Jiri Benc <jbenc@suse.cz>
 * Copyright 2007	Johannes Berg <johannes@sipsolutions.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef MAC80211_H
#define MAC80211_H

#include <linux/kernel.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/wireless.h>
#include <linux/device.h>
#include <linux/ieee80211.h>
#include <net/wireless.h>
#include <net/cfg80211.h>

/* Note! Only ieee80211_tx_status_irqsafe() and ieee80211_rx_irqsafe() can be
 * called in hardware interrupt context. The low-level driver must not call any
 * other functions in hardware interrupt context. If there is a need for such
 * call, the low-level driver should first ACK the interrupt and perform the
 * IEEE 802.11 code call after this, e.g., from a scheduled tasklet (in
 * software interrupt context).
 */

/*
 * Frame format used when passing frame between low-level hardware drivers
 * and IEEE 802.11 driver the same as used in the wireless media, i.e.,
 * buffers start with IEEE 802.11 header and include the same octets that
 * are sent over air.
 *
 * If hardware uses IEEE 802.3 headers (and perform 802.3 <-> 802.11
 * conversion in firmware), upper layer 802.11 code needs to be changed to
 * support this.
 *
 * If the receive frame format is not the same as the real frame sent
 * on the wireless media (e.g., due to padding etc.), upper layer 802.11 code
 * could be updated to provide support for such format assuming this would
 * optimize the performance, e.g., by removing need to re-allocation and
 * copying of the data.
 */

#define IEEE80211_CHAN_W_SCAN 0x00000001
#define IEEE80211_CHAN_W_ACTIVE_SCAN 0x00000002
#define IEEE80211_CHAN_W_IBSS 0x00000004

/* Channel information structure. Low-level driver is expected to fill in chan,
 * freq, and val fields. Other fields will be filled in by 80211.o based on
 * hostapd information and low-level driver does not need to use them. The
 * limits for each channel will be provided in 'struct ieee80211_conf' when
 * configuring the low-level driver with hw->config callback. If a device has
 * a default regulatory domain, IEEE80211_HW_DEFAULT_REG_DOMAIN_CONFIGURED
 * can be set to let the driver configure all fields */
struct ieee80211_channel {
	short chan; /* channel number (IEEE 802.11) */
	short freq; /* frequency in MHz */
	int val; /* hw specific value for the channel */
	int flag; /* flag for hostapd use (IEEE80211_CHAN_*) */
	unsigned char power_level;
	unsigned char antenna_max;
};

#define IEEE80211_RATE_ERP 0x00000001
#define IEEE80211_RATE_BASIC 0x00000002
#define IEEE80211_RATE_PREAMBLE2 0x00000004
#define IEEE80211_RATE_SUPPORTED 0x00000010
#define IEEE80211_RATE_OFDM 0x00000020
#define IEEE80211_RATE_CCK 0x00000040
#define IEEE80211_RATE_MANDATORY 0x00000100

#define IEEE80211_RATE_CCK_2 (IEEE80211_RATE_CCK | IEEE80211_RATE_PREAMBLE2)
#define IEEE80211_RATE_MODULATION(f) \
	(f & (IEEE80211_RATE_CCK | IEEE80211_RATE_OFDM))

/* Low-level driver should set PREAMBLE2, OFDM and CCK flags.
 * BASIC, SUPPORTED, ERP, and MANDATORY flags are set in 80211.o based on the
 * configuration. */
struct ieee80211_rate {
	int rate; /* rate in 100 kbps */
	int val; /* hw specific value for the rate */
	int flags; /* IEEE80211_RATE_ flags */
	int val2; /* hw specific value for the rate when using short preamble
		   * (only when IEEE80211_RATE_PREAMBLE2 flag is set, i.e., for
		   * 2, 5.5, and 11 Mbps) */
	signed char min_rssi_ack;
	unsigned char min_rssi_ack_delta;

	/* following fields are set by 80211.o and need not be filled by the
	 * low-level driver */
	int rate_inv; /* inverse of the rate (LCM(all rates) / rate) for
		       * optimizing channel utilization estimates */
};

/**
 * enum ieee80211_phymode - PHY modes
 *
 * @MODE_IEEE80211A: 5GHz as defined by 802.11a/802.11h
 * @MODE_IEEE80211B: 2.4 GHz as defined by 802.11b
 * @MODE_IEEE80211G: 2.4 GHz as defined by 802.11g (with OFDM),
 *	backwards compatible with 11b mode
 * @NUM_IEEE80211_MODES: internal
 */
enum ieee80211_phymode {
	MODE_IEEE80211A,
	MODE_IEEE80211B,
	MODE_IEEE80211G,

	/* keep last */
	NUM_IEEE80211_MODES
};

/**
 * struct ieee80211_hw_mode - PHY mode definition
 *
 * This structure describes the capabilities supported by the device
 * in a single PHY mode.
 *
 * @mode: the PHY mode for this definition
 * @num_channels: number of supported channels
 * @channels: pointer to array of supported channels
 * @num_rates: number of supported bitrates
 * @rates: pointer to array of supported bitrates
 * @list: internal
 */
struct ieee80211_hw_mode {
	struct list_head list;
	struct ieee80211_channel *channels;
	struct ieee80211_rate *rates;
	enum ieee80211_phymode mode;
	int num_channels;
	int num_rates;
};

/**
 * struct ieee80211_tx_queue_params - transmit queue configuration
 *
 * The information provided in this structure is required for QoS
 * transmit queue configuration.
 *
 * @aifs: arbitration interface space [0..255, -1: use default]
 * @cw_min: minimum contention window [will be a value of the form
 *	2^n-1 in the range 1..1023; 0: use default]
 * @cw_max: maximum contention window [like @cw_min]
 * @burst_time: maximum burst time in units of 0.1ms, 0 meaning disabled
 */
struct ieee80211_tx_queue_params {
	int aifs;
	int cw_min;
	int cw_max;
	int burst_time;
};

/**
 * struct ieee80211_tx_queue_stats_data - transmit queue statistics
 *
 * @len: number of packets in queue
 * @limit: queue length limit
 * @count: number of frames sent
 */
struct ieee80211_tx_queue_stats_data {
	unsigned int len;
	unsigned int limit;
	unsigned int count;
};

/**
 * enum ieee80211_tx_queue - transmit queue number
 *
 * These constants are used with some callbacks that take a
 * queue number to set parameters for a queue.
 *
 * @IEEE80211_TX_QUEUE_DATA0: data queue 0
 * @IEEE80211_TX_QUEUE_DATA1: data queue 1
 * @IEEE80211_TX_QUEUE_DATA2: data queue 2
 * @IEEE80211_TX_QUEUE_DATA3: data queue 3
 * @IEEE80211_TX_QUEUE_DATA4: data queue 4
 * @IEEE80211_TX_QUEUE_SVP: ??
 * @NUM_TX_DATA_QUEUES: number of data queues
 * @IEEE80211_TX_QUEUE_AFTER_BEACON: transmit queue for frames to be
 *	sent after a beacon
 * @IEEE80211_TX_QUEUE_BEACON: transmit queue for beacon frames
 */
enum ieee80211_tx_queue {
	IEEE80211_TX_QUEUE_DATA0,
	IEEE80211_TX_QUEUE_DATA1,
	IEEE80211_TX_QUEUE_DATA2,
	IEEE80211_TX_QUEUE_DATA3,
	IEEE80211_TX_QUEUE_DATA4,
	IEEE80211_TX_QUEUE_SVP,

	NUM_TX_DATA_QUEUES,

/* due to stupidity in the sub-ioctl userspace interface, the items in
 * this struct need to have fixed values. As soon as it is removed, we can
 * fix these entries. */
	IEEE80211_TX_QUEUE_AFTER_BEACON = 6,
	IEEE80211_TX_QUEUE_BEACON = 7
};

struct ieee80211_tx_queue_stats {
	struct ieee80211_tx_queue_stats_data data[NUM_TX_DATA_QUEUES];
};

struct ieee80211_low_level_stats {
	unsigned int dot11ACKFailureCount;
	unsigned int dot11RTSFailureCount;
	unsigned int dot11FCSErrorCount;
	unsigned int dot11RTSSuccessCount;
};

/* Transmit control fields. This data structure is passed to low-level driver
 * with each TX frame. The low-level driver is responsible for configuring
 * the hardware to use given values (depending on what is supported). */

struct ieee80211_tx_control {
	int tx_rate; /* Transmit rate, given as the hw specific value for the
		      * rate (from struct ieee80211_rate) */
	int rts_cts_rate; /* Transmit rate for RTS/CTS frame, given as the hw
			   * specific value for the rate (from
			   * struct ieee80211_rate) */

#define IEEE80211_TXCTL_REQ_TX_STATUS	(1<<0)/* request TX status callback for
						* this frame */
#define IEEE80211_TXCTL_DO_NOT_ENCRYPT	(1<<1) /* send this frame without
						* encryption; e.g., for EAPOL
						* frames */
#define IEEE80211_TXCTL_USE_RTS_CTS	(1<<2) /* use RTS-CTS before sending
						* frame */
#define IEEE80211_TXCTL_USE_CTS_PROTECT	(1<<3) /* use CTS protection for the
						* frame (e.g., for combined
						* 802.11g / 802.11b networks) */
#define IEEE80211_TXCTL_NO_ACK		(1<<4) /* tell the low level not to
						* wait for an ack */
#define IEEE80211_TXCTL_RATE_CTRL_PROBE	(1<<5)
#define IEEE80211_TXCTL_CLEAR_DST_MASK	(1<<6)
#define IEEE80211_TXCTL_REQUEUE		(1<<7)
#define IEEE80211_TXCTL_FIRST_FRAGMENT	(1<<8) /* this is a first fragment of
						* the frame */
#define IEEE80211_TXCTL_LONG_RETRY_LIMIT (1<<10) /* this frame should be send
						  * using the through
						  * set_retry_limit configured
						  * long retry value */
	u32 flags;			       /* tx control flags defined
						* above */
	u8 key_idx;		/* keyidx from hw->set_key(), undefined if
				 * IEEE80211_TXCTL_DO_NOT_ENCRYPT is set */
	u8 retry_limit;		/* 1 = only first attempt, 2 = one retry, ..
				 * This could be used when set_retry_limit
				 * is not implemented by the driver */
	u8 power_level;		/* per-packet transmit power level, in dBm */
	u8 antenna_sel_tx; 	/* 0 = default/diversity, 1 = Ant0, 2 = Ant1 */
	u8 icv_len;		/* length of the ICV/MIC field in octets */
	u8 iv_len;		/* length of the IV field in octets */
	u8 queue;		/* hardware queue to use for this frame;
				 * 0 = highest, hw->queues-1 = lowest */
	struct ieee80211_rate *rate;		/* internal 80211.o rate */
	struct ieee80211_rate *rts_rate;	/* internal 80211.o rate
						 * for RTS/CTS */
	int alt_retry_rate; /* retry rate for the last retries, given as the
			     * hw specific value for the rate (from
			     * struct ieee80211_rate). To be used to limit
			     * packet dropping when probing higher rates, if hw
			     * supports multiple retry rates. -1 = not used */
	int type;	/* internal */
	int ifindex;	/* internal */
};


/**
 * enum mac80211_rx_flags - receive flags
 *
 * These flags are used with the @flag member of &struct ieee80211_rx_status.
 * @RX_FLAG_MMIC_ERROR: Michael MIC error was reported on this frame.
 *	Use together with %RX_FLAG_MMIC_STRIPPED.
 * @RX_FLAG_DECRYPTED: This frame was decrypted in hardware.
 * @RX_FLAG_RADIOTAP: This frame starts with a radiotap header.
 * @RX_FLAG_MMIC_STRIPPED: the Michael MIC is stripped off this frame,
 *	verification has been done by the hardware.
 * @RX_FLAG_IV_STRIPPED: The IV/ICV are stripped from this frame.
 *	If this flag is set, the stack cannot do any replay detection
 *	hence the driver or hardware will have to do that.
 * @RX_FLAG_FAILED_FCS_CRC: Set this flag if the FCS check failed on
 *	the frame.
 * @RX_FLAG_FAILED_PLCP_CRC: Set this flag if the PCLP check failed on
 *	the frame.
 */
enum mac80211_rx_flags {
	RX_FLAG_MMIC_ERROR	= 1<<0,
	RX_FLAG_DECRYPTED	= 1<<1,
	RX_FLAG_RADIOTAP	= 1<<2,
	RX_FLAG_MMIC_STRIPPED	= 1<<3,
	RX_FLAG_IV_STRIPPED	= 1<<4,
	RX_FLAG_FAILED_FCS_CRC	= 1<<5,
	RX_FLAG_FAILED_PLCP_CRC = 1<<6,
};

/**
 * struct ieee80211_rx_status - receive status
 *
 * The low-level driver should provide this information (the subset
 * supported by hardware) to the 802.11 code with each received
 * frame.
 * @mactime: MAC timestamp as defined by 802.11
 * @freq: frequency the radio was tuned to when receiving this frame, in MHz
 * @channel: channel the radio was tuned to
 * @phymode: active PHY mode
 * @ssi: signal strength when receiving this frame
 * @signal: used as 'qual' in statistics reporting
 * @noise: PHY noise when receiving this frame
 * @antenna: antenna used
 * @rate: data rate
 * @flag: %RX_FLAG_*
 */
struct ieee80211_rx_status {
	u64 mactime;
	int freq;
	int channel;
	enum ieee80211_phymode phymode;
	int ssi;
	int signal;
	int noise;
	int antenna;
	int rate;
	int flag;
};

/**
 * enum ieee80211_tx_status_flags - transmit status flags
 *
 * Status flags to indicate various transmit conditions.
 *
 * @IEEE80211_TX_STATUS_TX_FILTERED: The frame was not transmitted
 *	because the destination STA was in powersave mode.
 *
 * @IEEE80211_TX_STATUS_ACK: Frame was acknowledged
 */
enum ieee80211_tx_status_flags {
	IEEE80211_TX_STATUS_TX_FILTERED	= 1<<0,
	IEEE80211_TX_STATUS_ACK		= 1<<1,
};

/**
 * struct ieee80211_tx_status - transmit status
 *
 * As much information as possible should be provided for each transmitted
 * frame with ieee80211_tx_status().
 *
 * @control: a copy of the &struct ieee80211_tx_control passed to the driver
 *	in the tx() callback.
 *
 * @flags: transmit status flags, defined above
 *
 * @ack_signal: signal strength of the ACK frame
 *
 * @excessive_retries: set to 1 if the frame was retried many times
 *	but not acknowledged
 *
 * @retry_count: number of retries
 *
 * @queue_length: ?? REMOVE
 * @queue_number: ?? REMOVE
 */
struct ieee80211_tx_status {
	struct ieee80211_tx_control control;
	u8 flags;
	bool excessive_retries;
	u8 retry_count;
	int ack_signal;
	int queue_length;
	int queue_number;
};

/**
 * enum ieee80211_conf_flags - configuration flags
 *
 * Flags to define PHY configuration options
 *
 * @IEEE80211_CONF_SHORT_SLOT_TIME: use 802.11g short slot time
 * @IEEE80211_CONF_RADIOTAP: add radiotap header at receive time (if supported)
 *
 */
enum ieee80211_conf_flags {
	IEEE80211_CONF_SHORT_SLOT_TIME	= 1<<0,
	IEEE80211_CONF_RADIOTAP		= 1<<1,
};

/**
 * struct ieee80211_conf - configuration of the device
 *
 * This struct indicates how the driver shall configure the hardware.
 *
 * @radio_enabled: when zero, driver is required to switch off the radio.
 *	TODO make a flag
 * @channel: IEEE 802.11 channel number
 * @freq: frequency in MHz
 * @channel_val: hardware specific channel value for the channel
 * @phymode: PHY mode to activate (REMOVE)
 * @chan: channel to switch to, pointer to the channel information
 * @mode: pointer to mode definition
 * @regulatory_domain: ??
 * @beacon_int: beacon interval (TODO make interface config)
 * @flags: configuration flags defined above
 * @power_level: transmit power limit for current regulatory domain in dBm
 * @antenna_max: maximum antenna gain
 * @antenna_sel_tx: transmit antenna selection, 0: default/diversity,
 *	1/2: antenna 0/1
 * @antenna_sel_rx: receive antenna selection, like @antenna_sel_tx
 */
struct ieee80211_conf {
	int channel;			/* IEEE 802.11 channel number */
	int freq;			/* MHz */
	int channel_val;		/* hw specific value for the channel */

	enum ieee80211_phymode phymode;
	struct ieee80211_channel *chan;
	struct ieee80211_hw_mode *mode;
	unsigned int regulatory_domain;
	int radio_enabled;

	int beacon_int;
	u32 flags;
	u8 power_level;
	u8 antenna_max;
	u8 antenna_sel_tx;
	u8 antenna_sel_rx;
};

/**
 * enum ieee80211_if_types - types of 802.11 network interfaces
 *
 * @IEEE80211_IF_TYPE_AP: interface in AP mode.
 * @IEEE80211_IF_TYPE_MGMT: special interface for communication with hostap
 *	daemon. Drivers should never see this type.
 * @IEEE80211_IF_TYPE_STA: interface in STA (client) mode.
 * @IEEE80211_IF_TYPE_IBSS: interface in IBSS (ad-hoc) mode.
 * @IEEE80211_IF_TYPE_MNTR: interface in monitor (rfmon) mode.
 * @IEEE80211_IF_TYPE_WDS: interface in WDS mode.
 * @IEEE80211_IF_TYPE_VLAN: VLAN interface bound to an AP, drivers
 *	will never see this type.
 */
enum ieee80211_if_types {
	IEEE80211_IF_TYPE_AP,
	IEEE80211_IF_TYPE_MGMT,
	IEEE80211_IF_TYPE_STA,
	IEEE80211_IF_TYPE_IBSS,
	IEEE80211_IF_TYPE_MNTR,
	IEEE80211_IF_TYPE_WDS,
	IEEE80211_IF_TYPE_VLAN,
};

/**
 * struct ieee80211_if_init_conf - initial configuration of an interface
 *
 * @if_id: internal interface ID. This number has no particular meaning to
 *	drivers and the only allowed usage is to pass it to
 *	ieee80211_beacon_get() and ieee80211_get_buffered_bc() functions.
 *	This field is not valid for monitor interfaces
 *	(interfaces of %IEEE80211_IF_TYPE_MNTR type).
 * @type: one of &enum ieee80211_if_types constants. Determines the type of
 *	added/removed interface.
 * @mac_addr: pointer to MAC address of the interface. This pointer is valid
 *	until the interface is removed (i.e. it cannot be used after
 *	remove_interface() callback was called for this interface).
 *
 * This structure is used in add_interface() and remove_interface()
 * callbacks of &struct ieee80211_hw.
 *
 * When you allow multiple interfaces to be added to your PHY, take care
 * that the hardware can actually handle multiple MAC addresses. However,
 * also take care that when there's no interface left with mac_addr != %NULL
 * you remove the MAC address from the device to avoid acknowledging packets
 * in pure monitor mode.
 */
struct ieee80211_if_init_conf {
	int if_id;
	int type;
	void *mac_addr;
};

/**
 * struct ieee80211_if_conf - configuration of an interface
 *
 * @type: type of the interface. This is always the same as was specified in
 *	&struct ieee80211_if_init_conf. The type of an interface never changes
 *	during the life of the interface; this field is present only for
 *	convenience.
 * @bssid: BSSID of the network we are associated to/creating.
 * @ssid: used (together with @ssid_len) by drivers for hardware that
 *	generate beacons independently. The pointer is valid only during the
 *	config_interface() call, so copy the value somewhere if you need
 *	it.
 * @ssid_len: length of the @ssid field.
 * @generic_elem: used (together with @generic_elem_len) by drivers for
 *	hardware that generate beacons independently. The pointer is valid
 *	only during the config_interface() call, so copy the value somewhere
 *	if you need it.
 * @generic_elem_len: length of the generic element.
 * @beacon: beacon template. Valid only if @host_gen_beacon_template in
 *	&struct ieee80211_hw is set. The driver is responsible of freeing
 *	the sk_buff.
 * @beacon_control: tx_control for the beacon template, this field is only
 *	valid when the @beacon field was set.
 *
 * This structure is passed to the config_interface() callback of
 * &struct ieee80211_hw.
 */
struct ieee80211_if_conf {
	int type;
	u8 *bssid;
	u8 *ssid;
	size_t ssid_len;
	u8 *generic_elem;
	size_t generic_elem_len;
	struct sk_buff *beacon;
	struct ieee80211_tx_control *beacon_control;
};

/**
 * enum ieee80211_key_alg - key algorithm
 * @ALG_NONE: Unset key algorithm, will never be passed to the driver
 * @ALG_WEP: WEP40 or WEP104
 * @ALG_TKIP: TKIP
 * @ALG_CCMP: CCMP (AES)
 */
typedef enum ieee80211_key_alg {
	ALG_NONE,
	ALG_WEP,
	ALG_TKIP,
	ALG_CCMP,
} ieee80211_key_alg;


/**
 * enum ieee80211_key_flags - key flags
 *
 * These flags are used for communication about keys between the driver
 * and mac80211, with the @flags parameter of &struct ieee80211_key_conf.
 *
 * @IEEE80211_KEY_FLAG_WMM_STA: Set by mac80211, this flag indicates
 *	that the STA this key will be used with could be using QoS.
 * @IEEE80211_KEY_FLAG_GENERATE_IV: This flag should be set by the
 *	driver to indicate that it requires IV generation for this
 *	particular key.
 * @IEEE80211_KEY_FLAG_GENERATE_MMIC: This flag should be set by
 *	the driver for a TKIP key if it requires Michael MIC
 *	generation in software.
 */
enum ieee80211_key_flags {
	IEEE80211_KEY_FLAG_WMM_STA	= 1<<0,
	IEEE80211_KEY_FLAG_GENERATE_IV	= 1<<1,
	IEEE80211_KEY_FLAG_GENERATE_MMIC= 1<<2,
};

/**
 * struct ieee80211_key_conf - key information
 *
 * This key information is given by mac80211 to the driver by
 * the set_key() callback in &struct ieee80211_ops.
 *
 * @hw_key_idx: To be set by the driver, this is the key index the driver
 *	wants to be given when a frame is transmitted and needs to be
 *	encrypted in hardware.
 * @alg: The key algorithm.
 * @flags: key flags, see &enum ieee80211_key_flags.
 * @keyidx: the key index (0-3)
 * @keylen: key material length
 * @key: key material
 */
struct ieee80211_key_conf {
	ieee80211_key_alg alg;
	u8 hw_key_idx;
	u8 flags;
	s8 keyidx;
	u8 keylen;
	u8 key[0];
};

#define IEEE80211_SEQ_COUNTER_RX	0
#define IEEE80211_SEQ_COUNTER_TX	1

/**
 * enum set_key_cmd - key command
 *
 * Used with the set_key() callback in &struct ieee80211_ops, this
 * indicates whether a key is being removed or added.
 *
 * @SET_KEY: a key is set
 * @DISABLE_KEY: a key must be disabled
 */
typedef enum set_key_cmd {
	SET_KEY, DISABLE_KEY,
} set_key_cmd;

/**
 * struct ieee80211_hw - hardware information and state
 * TODO: move documentation into kernel-doc format
 */
struct ieee80211_hw {
	/* points to the cfg80211 wiphy for this piece. Note
	 * that you must fill in the perm_addr and dev fields
	 * of this structure, use the macros provided below. */
	struct wiphy *wiphy;

	/* assigned by mac80211, don't write */
	struct ieee80211_conf conf;

	/* Single thread workqueue available for driver use
	 * Allocated by mac80211 on registration */
	struct workqueue_struct *workqueue;

	/* Pointer to the private area that was
	 * allocated with this struct for you. */
	void *priv;

	/* The rest is information about your hardware */

	/* TODO: frame_type 802.11/802.3, sw_encryption requirements */

/* hole at 0 */

	/*
	 * The device only needs to be supplied with a beacon template.
	 * If you need the host to generate each beacon then don't use
	 * this flag and use ieee80211_beacon_get().
	 */
#define IEEE80211_HW_HOST_GEN_BEACON_TEMPLATE (1<<1)

/* hole at 2 */

	/* Whether RX frames passed to ieee80211_rx() include FCS in the end */
#define IEEE80211_HW_RX_INCLUDES_FCS (1<<3)

	/* Some wireless LAN chipsets buffer broadcast/multicast frames for
	 * power saving stations in the hardware/firmware and others rely on
	 * the host system for such buffering. This option is used to
	 * configure the IEEE 802.11 upper layer to buffer broadcast/multicast
	 * frames when there are power saving stations so that low-level driver
	 * can fetch them with ieee80211_get_buffered_bc(). */
#define IEEE80211_HW_HOST_BROADCAST_PS_BUFFERING (1<<4)

/* hole at 5 */

/* hole at 6 */

/* hole at 7 */

/* hole at 8 */

/* hole at 9 */

/* hole at 10 */

	/* Channels are already configured to the default regulatory domain
	 * specified in the device's EEPROM */
#define IEEE80211_HW_DEFAULT_REG_DOMAIN_CONFIGURED (1<<11)

	u32 flags;			/* hardware flags defined above */

	/* Set to the size of a needed device specific skb headroom for TX skbs. */
	unsigned int extra_tx_headroom;

	/* This is the time in us to change channels
	 */
	int channel_change_time;
	/* Maximum values for various statistics.
	 * Leave at 0 to indicate no support. Use negative numbers for dBm. */
	s8 max_rssi;
	s8 max_signal;
	s8 max_noise;

	/* Number of available hardware TX queues for data packets.
	 * WMM requires at least four queues. */
	int queues;
};

static inline void SET_IEEE80211_DEV(struct ieee80211_hw *hw, struct device *dev)
{
	set_wiphy_dev(hw->wiphy, dev);
}

static inline void SET_IEEE80211_PERM_ADDR(struct ieee80211_hw *hw, u8 *addr)
{
	memcpy(hw->wiphy->perm_addr, addr, ETH_ALEN);
}

/*
 * flags for change_filter_flags()
 *
 * Note that e.g. if PROMISC_IN_BSS is unset then
 * you should still do MAC address filtering if
 * possible even if OTHER_BSS is set to indicate
 * no BSSID filtering should be done.
 */
/*
 * promiscuous mode within your BSS,
 * think of the BSS as your network segment and then this corresponds
 * to the regular ethernet device promiscuous mode
 */
#define FIF_PROMISC_IN_BSS	0x01
/* show all multicast frames */
#define FIF_ALLMULTI		0x02
/* show frames with failed FCS, but set RX_FLAG_FAILED_FCS_CRC for them */
#define FIF_FCSFAIL		0x04
/* show frames with failed PLCP CRC, but set RX_FLAG_FAILED_PLCP_CRC for them */
#define FIF_PLCPFAIL		0x08
/*
 * This flag is set during scanning to indicate to the hardware
 * that it should not filter beacons or probe responses by BSSID.
 */
#define FIF_BCN_PRBRESP_PROMISC	0x10
/*
 * show control frames, if PROMISC_IN_BSS is not set then
 * only those addressed to this station
 */
#define FIF_CONTROL		0x20
/* show frames from other BSSes */
#define FIF_OTHER_BSS		0x40

/* Configuration block used by the low-level driver to tell the 802.11 code
 * about supported hardware features and to pass function pointers to callback
 * functions. */
struct ieee80211_ops {
	/* Handler that 802.11 module calls for each transmitted frame.
	 * skb contains the buffer starting from the IEEE 802.11 header.
	 * The low-level driver should send the frame out based on
	 * configuration in the TX control data.
	 * Must be atomic. */
	int (*tx)(struct ieee80211_hw *hw, struct sk_buff *skb,
		  struct ieee80211_tx_control *control);

	/*
	 * Called before the first netdevice attached to the hardware
	 * is enabled. This should turn on the hardware and must turn on
	 * frame reception (for possibly enabled monitor interfaces.)
	 * Returns negative error codes, these may be seen in userspace,
	 * or zero.
	 * When the device is started it should not have a MAC address
	 * to avoid acknowledging frames before a non-monitor device
	 * is added.
	 *
	 * Must be implemented.
	 */
	int (*start)(struct ieee80211_hw *hw);

	/*
	 * Called after last netdevice attached to the hardware
	 * is disabled. This should turn off the hardware (at least
	 * it must turn off frame reception.)
	 * May be called right after add_interface if that rejects
	 * an interface.
	 *
	 * Must be implemented.
	 */
	void (*stop)(struct ieee80211_hw *hw);

	/*
	 * Called when a netdevice attached to the hardware is enabled.
	 * Because it is not called for monitor mode devices, open()
	 * and stop() must be implemented.
	 * The driver should perform any initialization it needs before
	 * the device can be enabled. The initial configuration for the
	 * interface is given in the conf parameter.
	 *
	 * Must be implemented.
	 */
	int (*add_interface)(struct ieee80211_hw *hw,
			     struct ieee80211_if_init_conf *conf);

	/*
	 * Notifies a driver that an interface is going down. The stop() handler
	 * is called after this if it is the last interface and no monitor
	 * interfaces are present.
	 * When all interfaces are removed, the MAC address in the hardware
	 * must be cleared so the device no longer acknowledges packets,
	 * the mac_addr member of the conf structure is, however, set to the
	 * MAC address of the device going away.
	 *
	 * Hence, this callback must be implemented.
	 */
	void (*remove_interface)(struct ieee80211_hw *hw,
				 struct ieee80211_if_init_conf *conf);

	/* Handler for configuration requests. IEEE 802.11 code calls this
	 * function to change hardware configuration, e.g., channel. */
	int (*config)(struct ieee80211_hw *hw, struct ieee80211_conf *conf);

	/* Handler for configuration requests related to interfaces (e.g.
	 * BSSID). */
	int (*config_interface)(struct ieee80211_hw *hw,
				int if_id, struct ieee80211_if_conf *conf);

	/*
	 * Configure the device's RX filter.
	 *
	 * The multicast address filter must be changed if the hardware flags
	 * indicate that one is present.
	 *
	 * All unsupported flags in 'total_flags' must be cleared,
	 * clear all bits except those you honoured.
	 *
	 * The callback must be implemented and must be atomic.
	 */
	void (*configure_filter)(struct ieee80211_hw *hw,
				 unsigned int changed_flags,
				 unsigned int *total_flags,
				 int mc_count, struct dev_addr_list *mc_list);

	/* Set TIM bit handler. If the hardware/firmware takes care of beacon
	 * generation, IEEE 802.11 code uses this function to tell the
	 * low-level to set (or clear if set==0) TIM bit for the given aid. If
	 * host system is used to generate beacons, this handler is not used
	 * and low-level driver should set it to NULL.
	 * Must be atomic. */
	int (*set_tim)(struct ieee80211_hw *hw, int aid, int set);

	/*
	 * Set encryption key.
	 *
	 * This is called to enable hardware acceleration of encryption and
	 * decryption. The address will be the broadcast address for default
	 * keys, the other station's hardware address for individual keys or
	 * the zero address for keys that will be used only for transmission.
	 *
	 * The local_address parameter will always be set to our own address,
	 * this is only relevant if you support multiple local addresses.
	 *
	 * When transmitting, the TX control data will use the hw_key_idx
	 * selected by the low-level driver.
	 *
	 * Return 0 if the key is now in use, -EOPNOTSUPP or -ENOSPC if it
	 * couldn't be added; if you return 0 then hw_key_idx must be assigned
	 * to the hardware key index, you are free to use the full u8 range.
	 *
	 * When the cmd is DISABLE_KEY then it must succeed.
	 *
	 * Note that it is permissible to not decrypt a frame even if a key
	 * for it has been uploaded to hardware, the stack will not make any
	 * decision based on whether a key has been uploaded or not but rather
	 * based on the receive flags.
	 *
	 * This callback can sleep, and is only called between add_interface
	 * and remove_interface calls, i.e. while the interface with the
	 * given local_address is enabled.
	 *
	 * The ieee80211_key_conf structure pointed to by the key parameter
	 * is guaranteed to be valid until another call to set_key removes
	 * it, but it can only be used as a cookie to differentiate keys.
	 */
	int (*set_key)(struct ieee80211_hw *hw, set_key_cmd cmd,
		       const u8 *local_address, const u8 *address,
		       struct ieee80211_key_conf *key);

	/* Enable/disable IEEE 802.1X. This item requests wlan card to pass
	 * unencrypted EAPOL-Key frames even when encryption is configured.
	 * If the wlan card does not require such a configuration, this
	 * function pointer can be set to NULL. */
	int (*set_ieee8021x)(struct ieee80211_hw *hw, int use_ieee8021x);

	/* Set port authorization state (IEEE 802.1X PAE) to be authorized
	 * (authorized=1) or unauthorized (authorized=0). This function can be
	 * used if the wlan hardware or low-level driver implements PAE.
	 * 80211.o module will anyway filter frames based on authorization
	 * state, so this function pointer can be NULL if low-level driver does
	 * not require event notification about port state changes.
	 * Currently unused. */
	int (*set_port_auth)(struct ieee80211_hw *hw, u8 *addr,
			     int authorized);

	/* Ask the hardware to service the scan request, no need to start
	 * the scan state machine in stack. */
	int (*hw_scan)(struct ieee80211_hw *hw, u8 *ssid, size_t len);

	/* return low-level statistics */
	int (*get_stats)(struct ieee80211_hw *hw,
			 struct ieee80211_low_level_stats *stats);

	/* For devices that generate their own beacons and probe response
	 * or association responses this updates the state of privacy_invoked
	 * returns 0 for success or an error number */
	int (*set_privacy_invoked)(struct ieee80211_hw *hw,
				   int privacy_invoked);

	/* For devices that have internal sequence counters, allow 802.11
	 * code to access the current value of a counter */
	int (*get_sequence_counter)(struct ieee80211_hw *hw,
				    u8* addr, u8 keyidx, u8 txrx,
				    u32* iv32, u16* iv16);

	/* Configuration of RTS threshold (if device needs it) */
	int (*set_rts_threshold)(struct ieee80211_hw *hw, u32 value);

	/* Configuration of fragmentation threshold.
	 * Assign this if the device does fragmentation by itself,
	 * if this method is assigned then the stack will not do
	 * fragmentation. */
	int (*set_frag_threshold)(struct ieee80211_hw *hw, u32 value);

	/* Configuration of retry limits (if device needs it) */
	int (*set_retry_limit)(struct ieee80211_hw *hw,
			       u32 short_retry, u32 long_retr);

	/* Number of STAs in STA table notification (NULL = disabled).
	 * Must be atomic. */
	void (*sta_table_notification)(struct ieee80211_hw *hw,
				       int num_sta);

	/* Handle ERP IE change notifications. Must be atomic. */
	void (*erp_ie_changed)(struct ieee80211_hw *hw, u8 changes,
			       int cts_protection, int preamble);

	/* Flags for the erp_ie_changed changes parameter */
#define IEEE80211_ERP_CHANGE_PROTECTION (1<<0) /* protection flag changed */
#define IEEE80211_ERP_CHANGE_PREAMBLE (1<<1) /* barker preamble mode changed */

	/* Configure TX queue parameters (EDCF (aifs, cw_min, cw_max),
	 * bursting) for a hardware TX queue.
	 * queue = IEEE80211_TX_QUEUE_*.
	 * Must be atomic. */
	int (*conf_tx)(struct ieee80211_hw *hw, int queue,
		       const struct ieee80211_tx_queue_params *params);

	/* Get statistics of the current TX queue status. This is used to get
	 * number of currently queued packets (queue length), maximum queue
	 * size (limit), and total number of packets sent using each TX queue
	 * (count).
	 * Currently unused. */
	int (*get_tx_stats)(struct ieee80211_hw *hw,
			    struct ieee80211_tx_queue_stats *stats);

	/* Get the current TSF timer value from firmware/hardware. Currently,
	 * this is only used for IBSS mode debugging and, as such, is not a
	 * required function.
	 * Must be atomic. */
	u64 (*get_tsf)(struct ieee80211_hw *hw);

	/* Reset the TSF timer and allow firmware/hardware to synchronize with
	 * other STAs in the IBSS. This is only used in IBSS mode. This
	 * function is optional if the firmware/hardware takes full care of
	 * TSF synchronization. */
	void (*reset_tsf)(struct ieee80211_hw *hw);

	/* Setup beacon data for IBSS beacons. Unlike access point (Master),
	 * IBSS uses a fixed beacon frame which is configured using this
	 * function. This handler is required only for IBSS mode. */
	int (*beacon_update)(struct ieee80211_hw *hw,
			     struct sk_buff *skb,
			     struct ieee80211_tx_control *control);

	/* Determine whether the last IBSS beacon was sent by us. This is
	 * needed only for IBSS mode and the result of this function is used to
	 * determine whether to reply to Probe Requests. */
	int (*tx_last_beacon)(struct ieee80211_hw *hw);
};

/* Allocate a new hardware device. This must be called once for each
 * hardware device. The returned pointer must be used to refer to this
 * device when calling other functions. 802.11 code allocates a private data
 * area for the low-level driver. The size of this area is given as
 * priv_data_len.
 */
struct ieee80211_hw *ieee80211_alloc_hw(size_t priv_data_len,
					const struct ieee80211_ops *ops);

/* Register hardware device to the IEEE 802.11 code and kernel. Low-level
 * drivers must call this function before using any other IEEE 802.11
 * function except ieee80211_register_hwmode. */
int ieee80211_register_hw(struct ieee80211_hw *hw);

/* driver can use this and ieee80211_get_rx_led_name to get the
 * name of the registered LEDs after ieee80211_register_hw
 * was called.
 * This is useful to set the default trigger on the LED class
 * device that your driver should export for each LED the device
 * has, that way the default behaviour will be as expected but
 * the user can still change it/turn off the LED etc.
 */
#ifdef CONFIG_MAC80211_LEDS
extern char *__ieee80211_get_tx_led_name(struct ieee80211_hw *hw);
extern char *__ieee80211_get_rx_led_name(struct ieee80211_hw *hw);
#endif
static inline char *ieee80211_get_tx_led_name(struct ieee80211_hw *hw)
{
#ifdef CONFIG_MAC80211_LEDS
	return __ieee80211_get_tx_led_name(hw);
#else
	return NULL;
#endif
}

static inline char *ieee80211_get_rx_led_name(struct ieee80211_hw *hw)
{
#ifdef CONFIG_MAC80211_LEDS
	return __ieee80211_get_rx_led_name(hw);
#else
	return NULL;
#endif
}

/* Register a new hardware PHYMODE capability to the stack. */
int ieee80211_register_hwmode(struct ieee80211_hw *hw,
			      struct ieee80211_hw_mode *mode);

/* Unregister a hardware device. This function instructs 802.11 code to free
 * allocated resources and unregister netdevices from the kernel. */
void ieee80211_unregister_hw(struct ieee80211_hw *hw);

/* Free everything that was allocated including private data of a driver. */
void ieee80211_free_hw(struct ieee80211_hw *hw);

/* Receive frame callback function. The low-level driver uses this function to
 * send received frames to the IEEE 802.11 code. Receive buffer (skb) must
 * start with IEEE 802.11 header. */
void __ieee80211_rx(struct ieee80211_hw *hw, struct sk_buff *skb,
		    struct ieee80211_rx_status *status);
void ieee80211_rx_irqsafe(struct ieee80211_hw *hw,
			  struct sk_buff *skb,
			  struct ieee80211_rx_status *status);

/* Transmit status callback function. The low-level driver must call this
 * function to report transmit status for all the TX frames that had
 * req_tx_status set in the transmit control fields. In addition, this should
 * be called at least for all unicast frames to provide information for TX rate
 * control algorithm. In order to maintain all statistics, this function is
 * recommended to be called after each frame, including multicast/broadcast, is
 * sent. */
void ieee80211_tx_status(struct ieee80211_hw *hw,
			 struct sk_buff *skb,
			 struct ieee80211_tx_status *status);
void ieee80211_tx_status_irqsafe(struct ieee80211_hw *hw,
				 struct sk_buff *skb,
				 struct ieee80211_tx_status *status);

/**
 * ieee80211_beacon_get - beacon generation function
 * @hw: pointer obtained from ieee80211_alloc_hw().
 * @if_id: interface ID from &struct ieee80211_if_init_conf.
 * @control: will be filled with information needed to send this beacon.
 *
 * If the beacon frames are generated by the host system (i.e., not in
 * hardware/firmware), the low-level driver uses this function to receive
 * the next beacon frame from the 802.11 code. The low-level is responsible
 * for calling this function before beacon data is needed (e.g., based on
 * hardware interrupt). Returned skb is used only once and low-level driver
 * is responsible of freeing it.
 */
struct sk_buff *ieee80211_beacon_get(struct ieee80211_hw *hw,
				     int if_id,
				     struct ieee80211_tx_control *control);

/**
 * ieee80211_rts_get - RTS frame generation function
 * @hw: pointer obtained from ieee80211_alloc_hw().
 * @if_id: interface ID from &struct ieee80211_if_init_conf.
 * @frame: pointer to the frame that is going to be protected by the RTS.
 * @frame_len: the frame length (in octets).
 * @frame_txctl: &struct ieee80211_tx_control of the frame.
 * @rts: The buffer where to store the RTS frame.
 *
 * If the RTS frames are generated by the host system (i.e., not in
 * hardware/firmware), the low-level driver uses this function to receive
 * the next RTS frame from the 802.11 code. The low-level is responsible
 * for calling this function before and RTS frame is needed.
 */
void ieee80211_rts_get(struct ieee80211_hw *hw, int if_id,
		       const void *frame, size_t frame_len,
		       const struct ieee80211_tx_control *frame_txctl,
		       struct ieee80211_rts *rts);

/**
 * ieee80211_rts_duration - Get the duration field for an RTS frame
 * @hw: pointer obtained from ieee80211_alloc_hw().
 * @if_id: interface ID from &struct ieee80211_if_init_conf.
 * @frame_len: the length of the frame that is going to be protected by the RTS.
 * @frame_txctl: &struct ieee80211_tx_control of the frame.
 *
 * If the RTS is generated in firmware, but the host system must provide
 * the duration field, the low-level driver uses this function to receive
 * the duration field value in little-endian byteorder.
 */
__le16 ieee80211_rts_duration(struct ieee80211_hw *hw, int if_id,
			      size_t frame_len,
			      const struct ieee80211_tx_control *frame_txctl);

/**
 * ieee80211_ctstoself_get - CTS-to-self frame generation function
 * @hw: pointer obtained from ieee80211_alloc_hw().
 * @if_id: interface ID from &struct ieee80211_if_init_conf.
 * @frame: pointer to the frame that is going to be protected by the CTS-to-self.
 * @frame_len: the frame length (in octets).
 * @frame_txctl: &struct ieee80211_tx_control of the frame.
 * @cts: The buffer where to store the CTS-to-self frame.
 *
 * If the CTS-to-self frames are generated by the host system (i.e., not in
 * hardware/firmware), the low-level driver uses this function to receive
 * the next CTS-to-self frame from the 802.11 code. The low-level is responsible
 * for calling this function before and CTS-to-self frame is needed.
 */
void ieee80211_ctstoself_get(struct ieee80211_hw *hw, int if_id,
			     const void *frame, size_t frame_len,
			     const struct ieee80211_tx_control *frame_txctl,
			     struct ieee80211_cts *cts);

/**
 * ieee80211_ctstoself_duration - Get the duration field for a CTS-to-self frame
 * @hw: pointer obtained from ieee80211_alloc_hw().
 * @if_id: interface ID from &struct ieee80211_if_init_conf.
 * @frame_len: the length of the frame that is going to be protected by the CTS-to-self.
 * @frame_txctl: &struct ieee80211_tx_control of the frame.
 *
 * If the CTS-to-self is generated in firmware, but the host system must provide
 * the duration field, the low-level driver uses this function to receive
 * the duration field value in little-endian byteorder.
 */
__le16 ieee80211_ctstoself_duration(struct ieee80211_hw *hw, int if_id,
				    size_t frame_len,
				    const struct ieee80211_tx_control *frame_txctl);

/**
 * ieee80211_generic_frame_duration - Calculate the duration field for a frame
 * @hw: pointer obtained from ieee80211_alloc_hw().
 * @if_id: interface ID from &struct ieee80211_if_init_conf.
 * @frame_len: the length of the frame.
 * @rate: the rate (in 100kbps) at which the frame is going to be transmitted.
 *
 * Calculate the duration field of some generic frame, given its
 * length and transmission rate (in 100kbps).
 */
__le16 ieee80211_generic_frame_duration(struct ieee80211_hw *hw, int if_id,
					size_t frame_len,
					int rate);

/**
 * ieee80211_get_buffered_bc - accessing buffered broadcast and multicast frames
 * @hw: pointer as obtained from ieee80211_alloc_hw().
 * @if_id: interface ID from &struct ieee80211_if_init_conf.
 * @control: will be filled with information needed to send returned frame.
 *
 * Function for accessing buffered broadcast and multicast frames. If
 * hardware/firmware does not implement buffering of broadcast/multicast
 * frames when power saving is used, 802.11 code buffers them in the host
 * memory. The low-level driver uses this function to fetch next buffered
 * frame. In most cases, this is used when generating beacon frame. This
 * function returns a pointer to the next buffered skb or NULL if no more
 * buffered frames are available.
 *
 * Note: buffered frames are returned only after DTIM beacon frame was
 * generated with ieee80211_beacon_get() and the low-level driver must thus
 * call ieee80211_beacon_get() first. ieee80211_get_buffered_bc() returns
 * NULL if the previous generated beacon was not DTIM, so the low-level driver
 * does not need to check for DTIM beacons separately and should be able to
 * use common code for all beacons.
 */
struct sk_buff *
ieee80211_get_buffered_bc(struct ieee80211_hw *hw, int if_id,
			  struct ieee80211_tx_control *control);

/* Given an sk_buff with a raw 802.11 header at the data pointer this function
 * returns the 802.11 header length in bytes (not including encryption
 * headers). If the data in the sk_buff is too short to contain a valid 802.11
 * header the function returns 0.
 */
int ieee80211_get_hdrlen_from_skb(const struct sk_buff *skb);

/* Like ieee80211_get_hdrlen_from_skb() but takes a FC in CPU order. */
int ieee80211_get_hdrlen(u16 fc);

/**
 * ieee80211_wake_queue - wake specific queue
 * @hw: pointer as obtained from ieee80211_alloc_hw().
 * @queue: queue number (counted from zero).
 *
 * Drivers should use this function instead of netif_wake_queue.
 */
void ieee80211_wake_queue(struct ieee80211_hw *hw, int queue);

/**
 * ieee80211_stop_queue - stop specific queue
 * @hw: pointer as obtained from ieee80211_alloc_hw().
 * @queue: queue number (counted from zero).
 *
 * Drivers should use this function instead of netif_stop_queue.
 */
void ieee80211_stop_queue(struct ieee80211_hw *hw, int queue);

/**
 * ieee80211_start_queues - start all queues
 * @hw: pointer to as obtained from ieee80211_alloc_hw().
 *
 * Drivers should use this function instead of netif_start_queue.
 */
void ieee80211_start_queues(struct ieee80211_hw *hw);

/**
 * ieee80211_stop_queues - stop all queues
 * @hw: pointer as obtained from ieee80211_alloc_hw().
 *
 * Drivers should use this function instead of netif_stop_queue.
 */
void ieee80211_stop_queues(struct ieee80211_hw *hw);

/**
 * ieee80211_wake_queues - wake all queues
 * @hw: pointer as obtained from ieee80211_alloc_hw().
 *
 * Drivers should use this function instead of netif_wake_queue.
 */
void ieee80211_wake_queues(struct ieee80211_hw *hw);

/* called by driver to notify scan status completed */
void ieee80211_scan_completed(struct ieee80211_hw *hw);

/* return a pointer to the source address (SA) */
static inline u8 *ieee80211_get_SA(struct ieee80211_hdr *hdr)
{
	u8 *raw = (u8 *) hdr;
	u8 tofrom = (*(raw+1)) & 3; /* get the TODS and FROMDS bits */

	switch (tofrom) {
		case 2:
			return hdr->addr3;
		case 3:
			return hdr->addr4;
	}
	return hdr->addr2;
}

/* return a pointer to the destination address (DA) */
static inline u8 *ieee80211_get_DA(struct ieee80211_hdr *hdr)
{
	u8 *raw = (u8 *) hdr;
	u8 to_ds = (*(raw+1)) & 1; /* get the TODS bit */

	if (to_ds)
		return hdr->addr3;
	return hdr->addr1;
}

static inline int ieee80211_get_morefrag(struct ieee80211_hdr *hdr)
{
	return (le16_to_cpu(hdr->frame_control) &
		IEEE80211_FCTL_MOREFRAGS) != 0;
}

#endif /* MAC80211_H */
