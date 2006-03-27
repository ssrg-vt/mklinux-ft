/*

  Broadcom BCM43xx wireless driver

  Copyright (c) 2005 Martin Langer <martin-langer@gmx.de>,
                     Stefano Brivio <st3@riseup.net>
                     Michael Buesch <mbuesch@freenet.de>
                     Danny van Dyk <kugelfang@gentoo.org>
                     Andreas Jaggi <andreas.jaggi@waterwave.ch>

  Some parts of the code in this file are derived from the ipw2200
  driver  Copyright(c) 2003 - 2004 Intel Corporation.

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; see the file COPYING.  If not, write to
  the Free Software Foundation, Inc., 51 Franklin Steet, Fifth Floor,
  Boston, MA 02110-1301, USA.

*/

#include <linux/wireless.h>
#include <net/iw_handler.h>
#include <net/ieee80211softmac.h>
#include <net/ieee80211softmac_wx.h>
#include <linux/capability.h>
#include <linux/sched.h> /* for capable() */
#include <linux/delay.h>

#include "bcm43xx.h"
#include "bcm43xx_wx.h"
#include "bcm43xx_main.h"
#include "bcm43xx_radio.h"


/* The WIRELESS_EXT version, which is implemented by this driver. */
#define BCM43xx_WX_VERSION	18


/* Define to enable a printk on each wx handler function invocation */
//#define BCM43xx_WX_DEBUG


#ifdef BCM43xx_WX_DEBUG
# define printk_wx		printk
#else
# define printk_wx(x...)	do { /* nothing */ } while (0)
#endif
#define wx_enter()		printk_wx(KERN_INFO PFX "WX handler called: %s\n", __FUNCTION__);

#define MAX_WX_STRING		80


static int bcm43xx_wx_get_name(struct net_device *net_dev,
                               struct iw_request_info *info,
			       union iwreq_data *data,
			       char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	unsigned long flags;
	int i, nr_80211;
	struct bcm43xx_phyinfo *phy;
	char suffix[7] = { 0 };
	int have_a = 0, have_b = 0, have_g = 0;

	wx_enter();

	spin_lock_irqsave(&bcm->lock, flags);
	nr_80211 = bcm43xx_num_80211_cores(bcm);
	for (i = 0; i < nr_80211; i++) {
		phy = bcm->phy + i;
		switch (phy->type) {
		case BCM43xx_PHYTYPE_A:
			have_a = 1;
			break;
		case BCM43xx_PHYTYPE_G:
			have_g = 1;
		case BCM43xx_PHYTYPE_B:
			have_b = 1;
			break;
		default:
			assert(0);
		}
	}
	spin_unlock_irqrestore(&bcm->lock, flags);

	i = 0;
	if (have_a) {
		suffix[i++] = 'a';
		suffix[i++] = '/';
	}
	if (have_b) {
		suffix[i++] = 'b';
		suffix[i++] = '/';
	}
	if (have_g) {
		suffix[i++] = 'g';
		suffix[i++] = '/';
	}
	if (i != 0) 
		suffix[i - 1] = '\0';

	snprintf(data->name, IFNAMSIZ, "IEEE 802.11%s", suffix);

	return 0;
}

static int bcm43xx_wx_set_channelfreq(struct net_device *net_dev,
				      struct iw_request_info *info,
				      union iwreq_data *data,
				      char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	struct ieee80211softmac_device *softmac = bcm->softmac;
	unsigned long flags;
	u8 channel;
	int freq;
	int err = 0;

	wx_enter();

	if ((data->freq.m >= 0) && (data->freq.m <= 1000)) {
		channel = data->freq.m;
		freq = bcm43xx_channel_to_freq(bcm, channel);
	} else {
		channel = bcm43xx_freq_to_channel(bcm, data->freq.m);
		freq = data->freq.m;
	}
	if (!bcm43xx_is_valid_channel(bcm, channel))
		return -EINVAL;

	spin_lock_irqsave(&bcm->lock, flags);
	if (bcm->initialized) {
		//ieee80211softmac_disassoc(softmac, $REASON);
		bcm43xx_mac_suspend(bcm);
		err = bcm43xx_radio_selectchannel(bcm, channel, 0);
		bcm43xx_mac_enable(bcm);
	} else
		bcm->current_core->radio->initial_channel = channel;
	spin_unlock_irqrestore(&bcm->lock, flags);
	if (!err)
		printk_wx(KERN_INFO PFX "Selected channel: %d\n", channel);

	return err;
}

static int bcm43xx_wx_get_channelfreq(struct net_device *net_dev,
				      struct iw_request_info *info,
				      union iwreq_data *data,
				      char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	unsigned long flags;
	int err = -ENODEV;
	u16 channel;

	wx_enter();

	spin_lock_irqsave(&bcm->lock, flags);
	channel = bcm->current_core->radio->channel;
	if (channel == 0xFF) {
		assert(!bcm->initialized);
		channel = bcm->current_core->radio->initial_channel;
		if (channel == 0xFF)
			goto out_unlock;
	}
	assert(channel > 0 && channel <= 1000);
	data->freq.e = 1;
	data->freq.m = bcm43xx_channel_to_freq(bcm, channel) * 100000;
	data->freq.flags = 1;

	err = 0;
out_unlock:
	spin_unlock_irqrestore(&bcm->lock, flags);

	return err;
}

static int bcm43xx_wx_set_mode(struct net_device *net_dev,
			       struct iw_request_info *info,
			       union iwreq_data *data,
			       char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	unsigned long flags;
	int mode;

	wx_enter();

	mode = data->mode;
	if (mode == IW_MODE_AUTO)
		mode = BCM43xx_INITIAL_IWMODE;

	spin_lock_irqsave(&bcm->lock, flags);
	if (bcm->ieee->iw_mode != mode)
		bcm43xx_set_iwmode(bcm, mode);
	spin_unlock_irqrestore(&bcm->lock, flags);

	return 0;
}

static int bcm43xx_wx_get_mode(struct net_device *net_dev,
			       struct iw_request_info *info,
			       union iwreq_data *data,
			       char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	unsigned long flags;

	wx_enter();

	spin_lock_irqsave(&bcm->lock, flags);
	data->mode = bcm->ieee->iw_mode;
	spin_unlock_irqrestore(&bcm->lock, flags);

	return 0;
}

static int bcm43xx_wx_set_sensitivity(struct net_device *net_dev,
				      struct iw_request_info *info,
				      union iwreq_data *data,
				      char *extra)
{
	wx_enter();
	/*TODO*/
	return 0;
}

static int bcm43xx_wx_get_sensitivity(struct net_device *net_dev,
				      struct iw_request_info *info,
				      union iwreq_data *data,
				      char *extra)
{
	wx_enter();
	/*TODO*/
	return 0;
}

static int bcm43xx_wx_get_rangeparams(struct net_device *net_dev,
				      struct iw_request_info *info,
				      union iwreq_data *data,
				      char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	struct iw_range *range = (struct iw_range *)extra;
	const struct ieee80211_geo *geo;
	unsigned long flags;
	int i, j;

	wx_enter();

	data->data.length = sizeof(*range);
	memset(range, 0, sizeof(*range));

	//TODO: What about 802.11b?
	/* 54Mb/s == ~27Mb/s payload throughput (802.11g) */
	range->throughput = 27 * 1000 * 1000;

	range->max_qual.qual = 100;
	/* TODO: Real max RSSI */
	range->max_qual.level = 0;
	range->max_qual.noise = 0;
	range->max_qual.updated = 7;

	range->avg_qual.qual = 70;
	range->avg_qual.level = 0;
	range->avg_qual.noise = 0;
	range->avg_qual.updated = 7;

	range->min_rts = BCM43xx_MIN_RTS_THRESHOLD;
	range->max_rts = BCM43xx_MAX_RTS_THRESHOLD;
	range->min_frag = MIN_FRAG_THRESHOLD;
	range->max_frag = MAX_FRAG_THRESHOLD;

	range->encoding_size[0] = 5;
	range->encoding_size[1] = 13;
	range->num_encoding_sizes = 2;
	range->max_encoding_tokens = WEP_KEYS;

	range->we_version_compiled = WIRELESS_EXT;
	range->we_version_source = BCM43xx_WX_VERSION;

	range->enc_capa = IW_ENC_CAPA_WPA |
			  IW_ENC_CAPA_WPA2 |
			  IW_ENC_CAPA_CIPHER_TKIP |
			  IW_ENC_CAPA_CIPHER_CCMP;

	spin_lock_irqsave(&bcm->lock, flags);

	range->num_bitrates = 0;
	i = 0;
	if (bcm->current_core->phy->type == BCM43xx_PHYTYPE_A ||
	    bcm->current_core->phy->type == BCM43xx_PHYTYPE_G) {
		range->num_bitrates = 8;
		range->bitrate[i++] = IEEE80211_OFDM_RATE_6MB;
		range->bitrate[i++] = IEEE80211_OFDM_RATE_9MB;
		range->bitrate[i++] = IEEE80211_OFDM_RATE_12MB;
		range->bitrate[i++] = IEEE80211_OFDM_RATE_18MB;
		range->bitrate[i++] = IEEE80211_OFDM_RATE_24MB;
		range->bitrate[i++] = IEEE80211_OFDM_RATE_36MB;
		range->bitrate[i++] = IEEE80211_OFDM_RATE_48MB;
		range->bitrate[i++] = IEEE80211_OFDM_RATE_54MB;
	}
	if (bcm->current_core->phy->type == BCM43xx_PHYTYPE_B ||
	    bcm->current_core->phy->type == BCM43xx_PHYTYPE_G) {
		range->num_bitrates += 4;
		range->bitrate[i++] = IEEE80211_CCK_RATE_1MB;
		range->bitrate[i++] = IEEE80211_CCK_RATE_2MB;
		range->bitrate[i++] = IEEE80211_CCK_RATE_5MB;
		range->bitrate[i++] = IEEE80211_CCK_RATE_11MB;
	}

	geo = ieee80211_get_geo(bcm->ieee);
	range->num_channels = geo->a_channels + geo->bg_channels;
	j = 0;
	for (i = 0; i < geo->a_channels; i++) {
		if (j == IW_MAX_FREQUENCIES)
			break;
		range->freq[j].i = j + 1;
		range->freq[j].m = geo->a[i].freq;//FIXME?
		range->freq[j].e = 1;
		j++;
	}
	for (i = 0; i < geo->bg_channels; i++) {
		if (j == IW_MAX_FREQUENCIES)
			break;
		range->freq[j].i = j + 1;
		range->freq[j].m = geo->bg[i].freq;//FIXME?
		range->freq[j].e = 1;
		j++;
	}
	range->num_frequency = j;

	spin_unlock_irqrestore(&bcm->lock, flags);

	return 0;
}

static int bcm43xx_wx_set_nick(struct net_device *net_dev,
			       struct iw_request_info *info,
			       union iwreq_data *data,
			       char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	unsigned long flags;
	size_t len;

	wx_enter();

	spin_lock_irqsave(&bcm->lock, flags);
	len =  min((size_t)data->data.length, (size_t)IW_ESSID_MAX_SIZE);
	memcpy(bcm->nick, extra, len);
	bcm->nick[len] = '\0';
	spin_unlock_irqrestore(&bcm->lock, flags);

	return 0;
}

static int bcm43xx_wx_get_nick(struct net_device *net_dev,
			       struct iw_request_info *info,
			       union iwreq_data *data,
			       char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	unsigned long flags;
	size_t len;

	wx_enter();

	spin_lock_irqsave(&bcm->lock, flags);
	len = strlen(bcm->nick) + 1;
	memcpy(extra, bcm->nick, len);
	data->data.length = (__u16)len;
	data->data.flags = 1;
	spin_unlock_irqrestore(&bcm->lock, flags);

	return 0;
}

static int bcm43xx_wx_set_rts(struct net_device *net_dev,
			      struct iw_request_info *info,
			      union iwreq_data *data,
			      char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	unsigned long flags;
	int err = -EINVAL;

	wx_enter();

	spin_lock_irqsave(&bcm->lock, flags);
	if (data->rts.disabled) {
		bcm->rts_threshold = BCM43xx_MAX_RTS_THRESHOLD;
		err = 0;
	} else {
		if (data->rts.value >= BCM43xx_MIN_RTS_THRESHOLD &&
		    data->rts.value <= BCM43xx_MAX_RTS_THRESHOLD) {
			bcm->rts_threshold = data->rts.value;
			err = 0;
		}
	}
	spin_unlock_irqrestore(&bcm->lock, flags);

	return err;
}

static int bcm43xx_wx_get_rts(struct net_device *net_dev,
			      struct iw_request_info *info,
			      union iwreq_data *data,
			      char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	unsigned long flags;

	wx_enter();

	spin_lock_irqsave(&bcm->lock, flags);
	data->rts.value = bcm->rts_threshold;
	data->rts.fixed = 0;
	data->rts.disabled = (bcm->rts_threshold == BCM43xx_MAX_RTS_THRESHOLD);
	spin_unlock_irqrestore(&bcm->lock, flags);

	return 0;
}

static int bcm43xx_wx_set_frag(struct net_device *net_dev,
			       struct iw_request_info *info,
			       union iwreq_data *data,
			       char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	unsigned long flags;
	int err = -EINVAL;

	wx_enter();

	spin_lock_irqsave(&bcm->lock, flags);
	if (data->frag.disabled) {
		bcm->ieee->fts = MAX_FRAG_THRESHOLD;
		err = 0;
	} else {
		if (data->frag.value >= MIN_FRAG_THRESHOLD &&
		    data->frag.value <= MAX_FRAG_THRESHOLD) {
			bcm->ieee->fts = data->frag.value & ~0x1;
			err = 0;
		}
	}
	spin_unlock_irqrestore(&bcm->lock, flags);

	return err;
}

static int bcm43xx_wx_get_frag(struct net_device *net_dev,
			       struct iw_request_info *info,
			       union iwreq_data *data,
			       char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	unsigned long flags;

	wx_enter();

	spin_lock_irqsave(&bcm->lock, flags);
	data->frag.value = bcm->ieee->fts;
	data->frag.fixed = 0;
	data->frag.disabled = (bcm->ieee->fts == MAX_FRAG_THRESHOLD);
	spin_unlock_irqrestore(&bcm->lock, flags);

	return 0;
}

static int bcm43xx_wx_set_xmitpower(struct net_device *net_dev,
				    struct iw_request_info *info,
				    union iwreq_data *data,
				    char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	struct bcm43xx_radioinfo *radio;
	struct bcm43xx_phyinfo *phy;
	unsigned long flags;
	int err = -ENODEV;
	u16 maxpower;

	wx_enter();

	if ((data->txpower.flags & IW_TXPOW_TYPE) != IW_TXPOW_DBM) {
		printk(PFX KERN_ERR "TX power not in dBm.\n");
		return -EOPNOTSUPP;
	}

	spin_lock_irqsave(&bcm->lock, flags);
	if (!bcm->initialized)
		goto out_unlock;
	radio = bcm->current_core->radio;
	phy = bcm->current_core->phy;
	if (data->txpower.disabled != (!(radio->enabled))) {
		if (data->txpower.disabled)
			bcm43xx_radio_turn_off(bcm);
		else
			bcm43xx_radio_turn_on(bcm);
	}
	if (data->txpower.value > 0) {
		/* desired and maxpower dBm values are in Q5.2 */
		if (phy->type == BCM43xx_PHYTYPE_A)
			maxpower = bcm->sprom.maxpower_aphy;
		else
			maxpower = bcm->sprom.maxpower_bgphy;
		radio->txpower_desired = limit_value(data->txpower.value << 2,
						     0, maxpower);
		bcm43xx_phy_xmitpower(bcm);
	}
	err = 0;

out_unlock:
	spin_unlock_irqrestore(&bcm->lock, flags);

	return err;
}

static int bcm43xx_wx_get_xmitpower(struct net_device *net_dev,
				    struct iw_request_info *info,
				    union iwreq_data *data,
				    char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	struct bcm43xx_radioinfo *radio;
	unsigned long flags;
	int err = -ENODEV;

	wx_enter();

	spin_lock_irqsave(&bcm->lock, flags);
	if (!bcm->initialized)
		goto out_unlock;
	radio = bcm->current_core->radio;
	/* desired dBm value is in Q5.2 */
	data->txpower.value = radio->txpower_desired >> 2;
	data->txpower.fixed = 1;
	data->txpower.flags = IW_TXPOW_DBM;
	data->txpower.disabled = !(radio->enabled);

	err = 0;
out_unlock:
	spin_unlock_irqrestore(&bcm->lock, flags);

	return err;
}

static int bcm43xx_wx_set_retry(struct net_device *net_dev,
				struct iw_request_info *info,
				union iwreq_data *data,
				char *extra)
{
	wx_enter();
	/*TODO*/
	return 0;
}

static int bcm43xx_wx_get_retry(struct net_device *net_dev,
				struct iw_request_info *info,
				union iwreq_data *data,
				char *extra)
{
	wx_enter();
	/*TODO*/
	return 0;
}

static int bcm43xx_wx_set_encoding(struct net_device *net_dev,
				   struct iw_request_info *info,
				   union iwreq_data *data,
				   char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	int err;

	wx_enter();

	err = ieee80211_wx_set_encode(bcm->ieee, info, data, extra);

	return err;
}

static int bcm43xx_wx_set_encodingext(struct net_device *net_dev,
                                   struct iw_request_info *info,
                                   union iwreq_data *data,
                                   char *extra)
{
        struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
        int err;

        wx_enter();

        err = ieee80211_wx_set_encodeext(bcm->ieee, info, data, extra);

        return err;
}

static int bcm43xx_wx_get_encoding(struct net_device *net_dev,
				   struct iw_request_info *info,
				   union iwreq_data *data,
				   char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	int err;

	wx_enter();

	err = ieee80211_wx_get_encode(bcm->ieee, info, data, extra);

	return err;
}

static int bcm43xx_wx_get_encodingext(struct net_device *net_dev,
                                   struct iw_request_info *info,
                                   union iwreq_data *data,
                                   char *extra)
{
        struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
        int err;

        wx_enter();

        err = ieee80211_wx_get_encodeext(bcm->ieee, info, data, extra);

        return err;
}

static int bcm43xx_wx_set_power(struct net_device *net_dev,
				struct iw_request_info *info,
				union iwreq_data *data,
				char *extra)
{
	wx_enter();
	/*TODO*/
	return 0;
}

static int bcm43xx_wx_get_power(struct net_device *net_dev,
				struct iw_request_info *info,
				union iwreq_data *data,
				char *extra)
{
	wx_enter();
	/*TODO*/
	return 0;
}

static int bcm43xx_wx_set_interfmode(struct net_device *net_dev,
				     struct iw_request_info *info,
				     union iwreq_data *data,
				     char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	unsigned long flags;
	int mode, err = 0;

	wx_enter();

	mode = *((int *)extra);
	switch (mode) {
	case 0:
		mode = BCM43xx_RADIO_INTERFMODE_NONE;
		break;
	case 1:
		mode = BCM43xx_RADIO_INTERFMODE_NONWLAN;
		break;
	case 2:
		mode = BCM43xx_RADIO_INTERFMODE_MANUALWLAN;
		break;
	case 3:
		mode = BCM43xx_RADIO_INTERFMODE_AUTOWLAN;
		break;
	default:
		printk(KERN_ERR PFX "set_interfmode allowed parameters are: "
				    "0 => None,  1 => Non-WLAN,  2 => WLAN,  "
				    "3 => Auto-WLAN\n");
		return -EINVAL;
	}

	spin_lock_irqsave(&bcm->lock, flags);
	if (bcm->initialized) {
		err = bcm43xx_radio_set_interference_mitigation(bcm, mode);
		if (err) {
			printk(KERN_ERR PFX "Interference Mitigation not "
					    "supported by device\n");
		}
	} else {
		if (mode == BCM43xx_RADIO_INTERFMODE_AUTOWLAN) {
			printk(KERN_ERR PFX "Interference Mitigation mode Auto-WLAN "
					    "not supported while the interface is down.\n");
			err = -ENODEV;
		} else
			bcm->current_core->radio->interfmode = mode;
	}
	spin_unlock_irqrestore(&bcm->lock, flags);

	return err;
}

static int bcm43xx_wx_get_interfmode(struct net_device *net_dev,
				     struct iw_request_info *info,
				     union iwreq_data *data,
				     char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	unsigned long flags;
	int mode;

	wx_enter();

	spin_lock_irqsave(&bcm->lock, flags);
	mode = bcm->current_core->radio->interfmode;
	spin_unlock_irqrestore(&bcm->lock, flags);

	switch (mode) {
	case BCM43xx_RADIO_INTERFMODE_NONE:
		strncpy(extra, "0 (No Interference Mitigation)", MAX_WX_STRING);
		break;
	case BCM43xx_RADIO_INTERFMODE_NONWLAN:
		strncpy(extra, "1 (Non-WLAN Interference Mitigation)", MAX_WX_STRING);
		break;
	case BCM43xx_RADIO_INTERFMODE_MANUALWLAN:
		strncpy(extra, "2 (WLAN Interference Mitigation)", MAX_WX_STRING);
		break;
	default:
		assert(0);
	}
	data->data.length = strlen(extra) + 1;

	return 0;
}

static int bcm43xx_wx_set_shortpreamble(struct net_device *net_dev,
					struct iw_request_info *info,
					union iwreq_data *data,
					char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	unsigned long flags;
	int on;

	wx_enter();

	on = *((int *)extra);
	spin_lock_irqsave(&bcm->lock, flags);
	bcm->short_preamble = !!on;
	spin_unlock_irqrestore(&bcm->lock, flags);

	return 0;
}

static int bcm43xx_wx_get_shortpreamble(struct net_device *net_dev,
					struct iw_request_info *info,
					union iwreq_data *data,
					char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	unsigned long flags;
	int on;

	wx_enter();

	spin_lock_irqsave(&bcm->lock, flags);
	on = bcm->short_preamble;
	spin_unlock_irqrestore(&bcm->lock, flags);

	if (on)
		strncpy(extra, "1 (Short Preamble enabled)", MAX_WX_STRING);
	else
		strncpy(extra, "0 (Short Preamble disabled)", MAX_WX_STRING);
	data->data.length = strlen(extra) + 1;

	return 0;
}

static int bcm43xx_wx_set_swencryption(struct net_device *net_dev,
				       struct iw_request_info *info,
				       union iwreq_data *data,
				       char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	unsigned long flags;
	int on;
	
	wx_enter();
	
	on = *((int *)extra);
	spin_lock_irqsave(&bcm->lock, flags);
	bcm->ieee->host_encrypt = !!on;
	bcm->ieee->host_decrypt = !!on;
	bcm->ieee->host_build_iv = !on;
	
	spin_unlock_irqrestore(&bcm->lock, flags);
	
	return 0;
}

static int bcm43xx_wx_get_swencryption(struct net_device *net_dev,
				       struct iw_request_info *info,
				       union iwreq_data *data,
				       char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	unsigned long flags;
	int on;
	
	wx_enter();
	
	spin_lock_irqsave(&bcm->lock, flags);
	on = bcm->ieee->host_encrypt;
	spin_unlock_irqrestore(&bcm->lock, flags);
	
	if (on)
		strncpy(extra, "1 (SW encryption enabled) ", MAX_WX_STRING);
	else
		strncpy(extra, "0 (SW encryption disabled) ", MAX_WX_STRING);
	data->data.length = strlen(extra + 1);
	
	return 0;
}

/* Enough buffer to hold a hexdump of the sprom data. */
#define SPROM_BUFFERSIZE	512

static int sprom2hex(const u16 *sprom, char *dump)
{
	int i, pos = 0;

	for (i = 0; i < BCM43xx_SPROM_SIZE; i++) {
		pos += snprintf(dump + pos, SPROM_BUFFERSIZE - pos - 1,
				"%04X", swab16(sprom[i]) & 0xFFFF);
	}

	return pos + 1;
}

static int hex2sprom(u16 *sprom, const char *dump, unsigned int len)
{
	char tmp[5] = { 0 };
	int cnt = 0;
	unsigned long parsed;
	u8 crc, expected_crc;

	if (len < BCM43xx_SPROM_SIZE * sizeof(u16) * 2)
		return -EINVAL;
	while (cnt < BCM43xx_SPROM_SIZE) {
		memcpy(tmp, dump, 4);
		dump += 4;
		parsed = simple_strtoul(tmp, NULL, 16);
		sprom[cnt++] = swab16((u16)parsed);
	}

	crc = bcm43xx_sprom_crc(sprom);
	expected_crc = (sprom[BCM43xx_SPROM_VERSION] & 0xFF00) >> 8;
	if (crc != expected_crc) {
		printk(KERN_ERR PFX "SPROM input data: Invalid CRC\n");
		return -EINVAL;
	}

	return 0;
}

static int bcm43xx_wx_sprom_read(struct net_device *net_dev,
				 struct iw_request_info *info,
				 union iwreq_data *data,
				 char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	int err = -EPERM, i;
	u16 *sprom;
	unsigned long flags;

	if (!capable(CAP_SYS_RAWIO))
		goto out;

	err = -ENOMEM;
	sprom = kmalloc(BCM43xx_SPROM_SIZE * sizeof(*sprom),
			GFP_KERNEL);
	if (!sprom)
		goto out;

	spin_lock_irqsave(&bcm->lock, flags);
	err = -ENODEV;
	if (!bcm->initialized) {
		spin_unlock_irqrestore(&bcm->lock, flags);
		goto out_kfree;
	}
	for (i = 0; i < BCM43xx_SPROM_SIZE; i++)
		sprom[i] = bcm43xx_read16(bcm, BCM43xx_SPROM_BASE + (i * 2));
	spin_unlock_irqrestore(&bcm->lock, flags);

	data->data.length = sprom2hex(sprom, extra);

	err = 0;
out_kfree:
	kfree(sprom);
out:
	return err;
}

static int bcm43xx_wx_sprom_write(struct net_device *net_dev,
				  struct iw_request_info *info,
				  union iwreq_data *data,
				  char *extra)
{
	struct bcm43xx_private *bcm = bcm43xx_priv(net_dev);
	int err = -EPERM;
	u16 *sprom;
	unsigned long flags;
	char *input;
	unsigned int len;
	u32 spromctl;
	int i;

	if (!capable(CAP_SYS_RAWIO))
		goto out;

	err = -ENOMEM;
	sprom = kmalloc(BCM43xx_SPROM_SIZE * sizeof(*sprom),
			GFP_KERNEL);
	if (!sprom)
		goto out;

	len = data->data.length;
	extra[len - 1] = '\0';
	input = strchr(extra, ':');
	if (input) {
		input++;
		len -= input - extra;
	} else
		input = extra;
	err = hex2sprom(sprom, input, len);
	if (err)
		goto out_kfree;

	spin_lock_irqsave(&bcm->lock, flags);
	err = -ENODEV;
	if (!bcm->initialized) {
		spin_unlock_irqrestore(&bcm->lock, flags);
		goto out_kfree;
	}

	printk(KERN_INFO PFX "Writing SPROM. Do NOT turn off the power! Please stand by...\n");
	err = bcm43xx_pci_read_config32(bcm, BCM43xx_PCICFG_SPROMCTL, &spromctl);
	if (err) {
		printk(KERN_ERR PFX "Could not access SPROM control register.\n");
		goto out_unlock;
	}
	spromctl |= 0x10; /* SPROM WRITE enable. */
	bcm43xx_pci_write_config32(bcm, BCM43xx_PCICFG_SPROMCTL, spromctl);
	if (err) {
		printk(KERN_ERR PFX "Could not access SPROM control register.\n");
		goto out_unlock;
	}
	/* We must burn lots of CPU cycles here, but that does not
	 * really matter as one does not write the SPROM every other minute...
	 */
	printk(KERN_INFO PFX "[ 0%%");
	mdelay(500);
	for (i = 0; i < BCM43xx_SPROM_SIZE; i++) {
		if (i == 16)
			printk("25%%");
		else if (i == 32)
			printk("50%%");
		else if (i == 48)
			printk("75%%");
		else if (i % 2)
			printk(".");
		bcm43xx_write16(bcm, BCM43xx_SPROM_BASE + (i * 2), sprom[i]);
		mdelay(20);
	}
	spromctl &= ~0x10; /* SPROM WRITE enable. */
	bcm43xx_pci_write_config32(bcm, BCM43xx_PCICFG_SPROMCTL, spromctl);
	if (err) {
		printk(KERN_ERR PFX "Could not access SPROM control register.\n");
		goto out_unlock;
	}
	mdelay(500);
	printk("100%% ]\n");
	printk(KERN_INFO PFX "SPROM written.\n");
	err = 0;
out_unlock:
	spin_unlock_irqrestore(&bcm->lock, flags);
out_kfree:
	kfree(sprom);
out:
	return err;
}


#ifdef WX
# undef WX
#endif
#define WX(ioctl)  [(ioctl) - SIOCSIWCOMMIT]
static const iw_handler bcm43xx_wx_handlers[] = {
	/* Wireless Identification */
	WX(SIOCGIWNAME)		= bcm43xx_wx_get_name,
	/* Basic operations */
	WX(SIOCSIWFREQ)		= bcm43xx_wx_set_channelfreq,
	WX(SIOCGIWFREQ)		= bcm43xx_wx_get_channelfreq,
	WX(SIOCSIWMODE)		= bcm43xx_wx_set_mode,
	WX(SIOCGIWMODE)		= bcm43xx_wx_get_mode,
	/* Informative stuff */
	WX(SIOCGIWRANGE)	= bcm43xx_wx_get_rangeparams,
	/* Access Point manipulation */
	WX(SIOCSIWAP)           = ieee80211softmac_wx_set_wap,
	WX(SIOCGIWAP)           = ieee80211softmac_wx_get_wap,
	WX(SIOCSIWSCAN)		= ieee80211softmac_wx_trigger_scan,
	WX(SIOCGIWSCAN)		= ieee80211softmac_wx_get_scan_results,
	/* 802.11 specific support */
	WX(SIOCSIWESSID)	= ieee80211softmac_wx_set_essid,
	WX(SIOCGIWESSID)	= ieee80211softmac_wx_get_essid,
	WX(SIOCSIWNICKN)	= bcm43xx_wx_set_nick,
	WX(SIOCGIWNICKN)	= bcm43xx_wx_get_nick,
	/* Other parameters */
	WX(SIOCSIWRATE)		= ieee80211softmac_wx_set_rate,
	WX(SIOCGIWRATE)		= ieee80211softmac_wx_get_rate,
	WX(SIOCSIWRTS)		= bcm43xx_wx_set_rts,
	WX(SIOCGIWRTS)		= bcm43xx_wx_get_rts,
	WX(SIOCSIWFRAG)		= bcm43xx_wx_set_frag,
	WX(SIOCGIWFRAG)		= bcm43xx_wx_get_frag,
	WX(SIOCSIWTXPOW)	= bcm43xx_wx_set_xmitpower,
	WX(SIOCGIWTXPOW)	= bcm43xx_wx_get_xmitpower,
//TODO	WX(SIOCSIWRETRY)	= bcm43xx_wx_set_retry,
//TODO	WX(SIOCGIWRETRY)	= bcm43xx_wx_get_retry,
	/* Encoding */
	WX(SIOCSIWENCODE)	= bcm43xx_wx_set_encoding,
	WX(SIOCGIWENCODE)	= bcm43xx_wx_get_encoding,
	WX(SIOCSIWENCODEEXT)	= bcm43xx_wx_set_encodingext,
	WX(SIOCGIWENCODEEXT)	= bcm43xx_wx_get_encodingext,
	/* Power saving */
//TODO	WX(SIOCSIWPOWER)	= bcm43xx_wx_set_power,
//TODO	WX(SIOCGIWPOWER)	= bcm43xx_wx_get_power,
	WX(SIOCSIWGENIE)	= ieee80211softmac_wx_set_genie,
	WX(SIOCGIWGENIE)	= ieee80211softmac_wx_get_genie,
	WX(SIOCSIWAUTH)		= ieee80211_wx_set_auth,
	WX(SIOCGIWAUTH)		= ieee80211_wx_get_auth,
};
#undef WX

static const iw_handler bcm43xx_priv_wx_handlers[] = {
	/* Set Interference Mitigation Mode. */
	bcm43xx_wx_set_interfmode,
	/* Get Interference Mitigation Mode. */
	bcm43xx_wx_get_interfmode,
	/* Enable/Disable Short Preamble mode. */
	bcm43xx_wx_set_shortpreamble,
	/* Get Short Preamble mode. */
	bcm43xx_wx_get_shortpreamble,
	/* Enable/Disable Software Encryption mode */
	bcm43xx_wx_set_swencryption,
	/* Get Software Encryption mode */
	bcm43xx_wx_get_swencryption,
	/* Write SRPROM data. */
	bcm43xx_wx_sprom_write,
	/* Read SPROM data. */
	bcm43xx_wx_sprom_read,
};

#define PRIV_WX_SET_INTERFMODE		(SIOCIWFIRSTPRIV + 0)
#define PRIV_WX_GET_INTERFMODE		(SIOCIWFIRSTPRIV + 1)
#define PRIV_WX_SET_SHORTPREAMBLE	(SIOCIWFIRSTPRIV + 2)
#define PRIV_WX_GET_SHORTPREAMBLE	(SIOCIWFIRSTPRIV + 3)
#define PRIV_WX_SET_SWENCRYPTION	(SIOCIWFIRSTPRIV + 4)
#define PRIV_WX_GET_SWENCRYPTION	(SIOCIWFIRSTPRIV + 5)
#define PRIV_WX_SPROM_WRITE		(SIOCIWFIRSTPRIV + 6)
#define PRIV_WX_SPROM_READ		(SIOCIWFIRSTPRIV + 7)

#define PRIV_WX_DUMMY(ioctl)	\
	{					\
		.cmd		= (ioctl),	\
		.name		= "__unused"	\
	}

static const struct iw_priv_args bcm43xx_priv_wx_args[] = {
	{
		.cmd		= PRIV_WX_SET_INTERFMODE,
		.set_args	= IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,
		.name		= "set_interfmode",
	},
	{
		.cmd		= PRIV_WX_GET_INTERFMODE,
		.get_args	= IW_PRIV_TYPE_CHAR | IW_PRIV_SIZE_FIXED | MAX_WX_STRING,
		.name		= "get_interfmode",
	},
	{
		.cmd		= PRIV_WX_SET_SHORTPREAMBLE,
		.set_args	= IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,
		.name		= "set_shortpreambl",
	},
	{
		.cmd		= PRIV_WX_GET_SHORTPREAMBLE,
		.get_args	= IW_PRIV_TYPE_CHAR | IW_PRIV_SIZE_FIXED | MAX_WX_STRING,
		.name		= "get_shortpreambl",
	},
	{
		.cmd		= PRIV_WX_SET_SWENCRYPTION,
		.set_args	= IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,
		.name		= "set_swencryption",
	},
	{
		.cmd		= PRIV_WX_GET_SWENCRYPTION,
		.get_args	= IW_PRIV_TYPE_CHAR | IW_PRIV_SIZE_FIXED | MAX_WX_STRING,
		.name		= "get_swencryption",
	},
	{
		.cmd		= PRIV_WX_SPROM_WRITE,
		.set_args	= IW_PRIV_TYPE_CHAR | SPROM_BUFFERSIZE,
		.name		= "write_sprom",
	},
	{
		.cmd		= PRIV_WX_SPROM_READ,
		.get_args	= IW_PRIV_TYPE_CHAR | IW_PRIV_SIZE_FIXED | SPROM_BUFFERSIZE,
		.name		= "read_sprom",
	},
};

const struct iw_handler_def bcm43xx_wx_handlers_def = {
	.standard		= bcm43xx_wx_handlers,
	.num_standard		= ARRAY_SIZE(bcm43xx_wx_handlers),
	.num_private		= ARRAY_SIZE(bcm43xx_priv_wx_handlers),
	.num_private_args	= ARRAY_SIZE(bcm43xx_priv_wx_args),
	.private		= bcm43xx_priv_wx_handlers,
	.private_args		= bcm43xx_priv_wx_args,
};

/* vim: set ts=8 sw=8 sts=8: */
