/*
 * Copyright 2002-2005, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 * Copyright 2006-2007	Jiri Benc <jbenc@suse.cz>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <net/mac80211.h>
#include <net/ieee80211_radiotap.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/wireless.h>
#include <linux/rtnetlink.h>
#include <linux/bitmap.h>
#include <net/net_namespace.h>
#include <net/cfg80211.h>

#include "ieee80211_common.h"
#include "ieee80211_i.h"
#include "ieee80211_rate.h"
#include "wep.h"
#include "wme.h"
#include "aes_ccm.h"
#include "ieee80211_led.h"
#include "ieee80211_cfg.h"
#include "debugfs.h"
#include "debugfs_netdev.h"

/*
 * For seeing transmitted packets on monitor interfaces
 * we have a radiotap header too.
 */
struct ieee80211_tx_status_rtap_hdr {
	struct ieee80211_radiotap_header hdr;
	__le16 tx_flags;
	u8 data_retries;
} __attribute__ ((packed));

/* common interface routines */

static struct net_device_stats *ieee80211_get_stats(struct net_device *dev)
{
	struct ieee80211_sub_if_data *sdata;
	sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	return &(sdata->stats);
}

static int header_parse_80211(struct sk_buff *skb, unsigned char *haddr)
{
	memcpy(haddr, skb_mac_header(skb) + 10, ETH_ALEN); /* addr2 */
	return ETH_ALEN;
}

/* master interface */

static int ieee80211_master_open(struct net_device *dev)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata;
	int res = -EOPNOTSUPP;

	read_lock(&local->sub_if_lock);
	list_for_each_entry(sdata, &local->sub_if_list, list) {
		if (sdata->dev != dev && netif_running(sdata->dev)) {
			res = 0;
			break;
		}
	}
	read_unlock(&local->sub_if_lock);
	return res;
}

static int ieee80211_master_stop(struct net_device *dev)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata;

	read_lock(&local->sub_if_lock);
	list_for_each_entry(sdata, &local->sub_if_list, list)
		if (sdata->dev != dev && netif_running(sdata->dev))
			dev_close(sdata->dev);
	read_unlock(&local->sub_if_lock);

	return 0;
}

/* management interface */

static void
ieee80211_fill_frame_info(struct ieee80211_local *local,
			  struct ieee80211_frame_info *fi,
			  struct ieee80211_rx_status *status)
{
	if (status) {
		struct timespec ts;
		struct ieee80211_rate *rate;

		jiffies_to_timespec(jiffies, &ts);
		fi->hosttime = cpu_to_be64((u64) ts.tv_sec * 1000000 +
					   ts.tv_nsec / 1000);
		fi->mactime = cpu_to_be64(status->mactime);
		switch (status->phymode) {
		case MODE_IEEE80211A:
			fi->phytype = htonl(ieee80211_phytype_ofdm_dot11_a);
			break;
		case MODE_IEEE80211B:
			fi->phytype = htonl(ieee80211_phytype_dsss_dot11_b);
			break;
		case MODE_IEEE80211G:
			fi->phytype = htonl(ieee80211_phytype_pbcc_dot11_g);
			break;
		case MODE_ATHEROS_TURBO:
			fi->phytype =
				htonl(ieee80211_phytype_dsss_dot11_turbo);
			break;
		default:
			fi->phytype = htonl(0xAAAAAAAA);
			break;
		}
		fi->channel = htonl(status->channel);
		rate = ieee80211_get_rate(local, status->phymode,
					  status->rate);
		if (rate) {
			fi->datarate = htonl(rate->rate);
			if (rate->flags & IEEE80211_RATE_PREAMBLE2) {
				if (status->rate == rate->val)
					fi->preamble = htonl(2); /* long */
				else if (status->rate == rate->val2)
					fi->preamble = htonl(1); /* short */
			} else
				fi->preamble = htonl(0);
		} else {
			fi->datarate = htonl(0);
			fi->preamble = htonl(0);
		}

		fi->antenna = htonl(status->antenna);
		fi->priority = htonl(0xffffffff); /* no clue */
		fi->ssi_type = htonl(ieee80211_ssi_raw);
		fi->ssi_signal = htonl(status->ssi);
		fi->ssi_noise = 0x00000000;
		fi->encoding = 0;
	} else {
		/* clear everything because we really don't know.
		 * the msg_type field isn't present on monitor frames
		 * so we don't know whether it will be present or not,
		 * but it's ok to not clear it since it'll be assigned
		 * anyway */
		memset(fi, 0, sizeof(*fi) - sizeof(fi->msg_type));

		fi->ssi_type = htonl(ieee80211_ssi_none);
	}
	fi->version = htonl(IEEE80211_FI_VERSION);
	fi->length = cpu_to_be32(sizeof(*fi) - sizeof(fi->msg_type));
}

/* this routine is actually not just for this, but also
 * for pushing fake 'management' frames into userspace.
 * it shall be replaced by a netlink-based system. */
void
ieee80211_rx_mgmt(struct ieee80211_local *local, struct sk_buff *skb,
		  struct ieee80211_rx_status *status, u32 msg_type)
{
	struct ieee80211_frame_info *fi;
	const size_t hlen = sizeof(struct ieee80211_frame_info);
	struct ieee80211_sub_if_data *sdata;

	skb->dev = local->apdev;

	sdata = IEEE80211_DEV_TO_SUB_IF(local->apdev);

	if (skb_headroom(skb) < hlen) {
		I802_DEBUG_INC(local->rx_expand_skb_head);
		if (pskb_expand_head(skb, hlen, 0, GFP_ATOMIC)) {
			dev_kfree_skb(skb);
			return;
		}
	}

	fi = (struct ieee80211_frame_info *) skb_push(skb, hlen);

	ieee80211_fill_frame_info(local, fi, status);
	fi->msg_type = htonl(msg_type);

	sdata->stats.rx_packets++;
	sdata->stats.rx_bytes += skb->len;

	skb_set_mac_header(skb, 0);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->pkt_type = PACKET_OTHERHOST;
	skb->protocol = htons(ETH_P_802_2);
	memset(skb->cb, 0, sizeof(skb->cb));
	netif_rx(skb);
}

void ieee80211_key_threshold_notify(struct net_device *dev,
				    struct ieee80211_key *key,
				    struct sta_info *sta)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct sk_buff *skb;
	struct ieee80211_msg_key_notification *msg;

	/* if no one will get it anyway, don't even allocate it.
	 * unlikely because this is only relevant for APs
	 * where the device must be open... */
	if (unlikely(!local->apdev))
		return;

	skb = dev_alloc_skb(sizeof(struct ieee80211_frame_info) +
			    sizeof(struct ieee80211_msg_key_notification));
	if (!skb)
		return;

	skb_reserve(skb, sizeof(struct ieee80211_frame_info));
	msg = (struct ieee80211_msg_key_notification *)
		skb_put(skb, sizeof(struct ieee80211_msg_key_notification));
	msg->tx_rx_count = key->tx_rx_count;
	memcpy(msg->ifname, dev->name, IFNAMSIZ);
	if (sta)
		memcpy(msg->addr, sta->addr, ETH_ALEN);
	else
		memset(msg->addr, 0xff, ETH_ALEN);

	key->tx_rx_count = 0;

	ieee80211_rx_mgmt(local, skb, NULL,
			  ieee80211_msg_key_threshold_notification);
}

static int ieee80211_mgmt_open(struct net_device *dev)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);

	if (!netif_running(local->mdev))
		return -EOPNOTSUPP;
	return 0;
}

static int ieee80211_mgmt_stop(struct net_device *dev)
{
	return 0;
}

static int ieee80211_change_mtu_apdev(struct net_device *dev, int new_mtu)
{
	/* FIX: what would be proper limits for MTU?
	 * This interface uses 802.11 frames. */
	if (new_mtu < 256 || new_mtu > IEEE80211_MAX_DATA_LEN) {
		printk(KERN_WARNING "%s: invalid MTU %d\n",
		       dev->name, new_mtu);
		return -EINVAL;
	}

#ifdef CONFIG_MAC80211_VERBOSE_DEBUG
	printk(KERN_DEBUG "%s: setting MTU %d\n", dev->name, new_mtu);
#endif /* CONFIG_MAC80211_VERBOSE_DEBUG */
	dev->mtu = new_mtu;
	return 0;
}

void ieee80211_if_mgmt_setup(struct net_device *dev)
{
	ether_setup(dev);
	dev->hard_start_xmit = ieee80211_mgmt_start_xmit;
	dev->change_mtu = ieee80211_change_mtu_apdev;
	dev->get_stats = ieee80211_get_stats;
	dev->open = ieee80211_mgmt_open;
	dev->stop = ieee80211_mgmt_stop;
	dev->type = ARPHRD_IEEE80211_PRISM;
	dev->hard_header_parse = header_parse_80211;
	dev->uninit = ieee80211_if_reinit;
	dev->destructor = ieee80211_if_free;
}

/* regular interfaces */

static int ieee80211_change_mtu(struct net_device *dev, int new_mtu)
{
	/* FIX: what would be proper limits for MTU?
	 * This interface uses 802.3 frames. */
	if (new_mtu < 256 || new_mtu > IEEE80211_MAX_DATA_LEN - 24 - 6) {
		printk(KERN_WARNING "%s: invalid MTU %d\n",
		       dev->name, new_mtu);
		return -EINVAL;
	}

#ifdef CONFIG_MAC80211_VERBOSE_DEBUG
	printk(KERN_DEBUG "%s: setting MTU %d\n", dev->name, new_mtu);
#endif /* CONFIG_MAC80211_VERBOSE_DEBUG */
	dev->mtu = new_mtu;
	return 0;
}

static inline int identical_mac_addr_allowed(int type1, int type2)
{
	return (type1 == IEEE80211_IF_TYPE_MNTR ||
		type2 == IEEE80211_IF_TYPE_MNTR ||
		(type1 == IEEE80211_IF_TYPE_AP &&
		 type2 == IEEE80211_IF_TYPE_WDS) ||
		(type1 == IEEE80211_IF_TYPE_WDS &&
		 (type2 == IEEE80211_IF_TYPE_WDS ||
		  type2 == IEEE80211_IF_TYPE_AP)) ||
		(type1 == IEEE80211_IF_TYPE_AP &&
		 type2 == IEEE80211_IF_TYPE_VLAN) ||
		(type1 == IEEE80211_IF_TYPE_VLAN &&
		 (type2 == IEEE80211_IF_TYPE_AP ||
		  type2 == IEEE80211_IF_TYPE_VLAN)));
}

/* Check if running monitor interfaces should go to a "soft monitor" mode
 * and switch them if necessary. */
static inline void ieee80211_start_soft_monitor(struct ieee80211_local *local)
{
	struct ieee80211_if_init_conf conf;

	if (local->open_count && local->open_count == local->monitors &&
	    !(local->hw.flags & IEEE80211_HW_MONITOR_DURING_OPER) &&
	    local->ops->remove_interface) {
		conf.if_id = -1;
		conf.type = IEEE80211_IF_TYPE_MNTR;
		conf.mac_addr = NULL;
		local->ops->remove_interface(local_to_hw(local), &conf);
	}
}

/* Check if running monitor interfaces should go to a "hard monitor" mode
 * and switch them if necessary. */
static void ieee80211_start_hard_monitor(struct ieee80211_local *local)
{
	struct ieee80211_if_init_conf conf;

	if (local->open_count && local->open_count == local->monitors &&
	    !(local->hw.flags & IEEE80211_HW_MONITOR_DURING_OPER)) {
		conf.if_id = -1;
		conf.type = IEEE80211_IF_TYPE_MNTR;
		conf.mac_addr = NULL;
		local->ops->add_interface(local_to_hw(local), &conf);
	}
}

static void ieee80211_if_open(struct net_device *dev)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);

	switch (sdata->type) {
	case IEEE80211_IF_TYPE_STA:
	case IEEE80211_IF_TYPE_IBSS:
		sdata->u.sta.flags &= ~IEEE80211_STA_PREV_BSSID_SET;
		break;
	}
}

static int ieee80211_open(struct net_device *dev)
{
	struct ieee80211_sub_if_data *sdata, *nsdata;
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_if_init_conf conf;
	int res;

	sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	read_lock(&local->sub_if_lock);
	list_for_each_entry(nsdata, &local->sub_if_list, list) {
		struct net_device *ndev = nsdata->dev;

		if (ndev != dev && ndev != local->mdev && netif_running(ndev) &&
		    compare_ether_addr(dev->dev_addr, ndev->dev_addr) == 0 &&
		    !identical_mac_addr_allowed(sdata->type, nsdata->type)) {
			read_unlock(&local->sub_if_lock);
			return -ENOTUNIQ;
		}
	}
	read_unlock(&local->sub_if_lock);

	if (sdata->type == IEEE80211_IF_TYPE_WDS &&
	    is_zero_ether_addr(sdata->u.wds.remote_addr))
		return -ENOLINK;

	if (sdata->type == IEEE80211_IF_TYPE_MNTR && local->open_count &&
	    !(local->hw.flags & IEEE80211_HW_MONITOR_DURING_OPER)) {
		/* run the interface in a "soft monitor" mode */
		local->monitors++;
		local->open_count++;
		local->hw.conf.flags |= IEEE80211_CONF_RADIOTAP;
		return 0;
	}
	ieee80211_if_open(dev);
	ieee80211_start_soft_monitor(local);

	conf.if_id = dev->ifindex;
	conf.type = sdata->type;
	if (sdata->type == IEEE80211_IF_TYPE_MNTR)
		conf.mac_addr = NULL;
	else
		conf.mac_addr = dev->dev_addr;
	res = local->ops->add_interface(local_to_hw(local), &conf);
	if (res) {
		if (sdata->type == IEEE80211_IF_TYPE_MNTR)
			ieee80211_start_hard_monitor(local);
		return res;
	}

	if (local->open_count == 0) {
		res = 0;
		tasklet_enable(&local->tx_pending_tasklet);
		tasklet_enable(&local->tasklet);
		if (local->ops->open)
			res = local->ops->open(local_to_hw(local));
		if (res == 0) {
			res = dev_open(local->mdev);
			if (res) {
				if (local->ops->stop)
					local->ops->stop(local_to_hw(local));
			} else {
				res = ieee80211_hw_config(local);
				if (res && local->ops->stop)
					local->ops->stop(local_to_hw(local));
				else if (!res && local->apdev)
					dev_open(local->apdev);
			}
		}
		if (res) {
			if (local->ops->remove_interface)
				local->ops->remove_interface(local_to_hw(local),
							    &conf);
			return res;
		}
	}
	local->open_count++;

	if (sdata->type == IEEE80211_IF_TYPE_MNTR) {
		local->monitors++;
		local->hw.conf.flags |= IEEE80211_CONF_RADIOTAP;
	} else {
		ieee80211_if_config(dev);
		ieee80211_reset_erp_info(dev);
		ieee80211_enable_keys(sdata);
	}

	if (sdata->type == IEEE80211_IF_TYPE_STA &&
	    !local->user_space_mlme)
		netif_carrier_off(dev);
	else
		netif_carrier_on(dev);

	netif_start_queue(dev);
	return 0;
}

static void ieee80211_if_shutdown(struct net_device *dev)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);

	ASSERT_RTNL();
	switch (sdata->type) {
	case IEEE80211_IF_TYPE_STA:
	case IEEE80211_IF_TYPE_IBSS:
		sdata->u.sta.state = IEEE80211_DISABLED;
		del_timer_sync(&sdata->u.sta.timer);
		/*
		 * Holding the sub_if_lock for writing here blocks
		 * out the receive path and makes sure it's not
		 * currently processing a packet that may get
		 * added to the queue.
		 */
		write_lock_bh(&local->sub_if_lock);
		skb_queue_purge(&sdata->u.sta.skb_queue);
		write_unlock_bh(&local->sub_if_lock);

		if (!local->ops->hw_scan &&
		    local->scan_dev == sdata->dev) {
			local->sta_scanning = 0;
			cancel_delayed_work(&local->scan_work);
		}
		flush_workqueue(local->hw.workqueue);
		break;
	}
}

static int ieee80211_stop(struct net_device *dev)
{
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);

	sdata = IEEE80211_DEV_TO_SUB_IF(dev);

	if (sdata->type == IEEE80211_IF_TYPE_MNTR &&
	    local->open_count > 1 &&
	    !(local->hw.flags & IEEE80211_HW_MONITOR_DURING_OPER)) {
		/* remove "soft monitor" interface */
		local->open_count--;
		local->monitors--;
		if (!local->monitors)
			local->hw.conf.flags &= ~IEEE80211_CONF_RADIOTAP;
		return 0;
	}

	netif_stop_queue(dev);
	ieee80211_if_shutdown(dev);

	if (sdata->type == IEEE80211_IF_TYPE_MNTR) {
		local->monitors--;
		if (!local->monitors)
			local->hw.conf.flags &= ~IEEE80211_CONF_RADIOTAP;
	} else {
		/* disable all keys for as long as this netdev is down */
		ieee80211_disable_keys(sdata);
	}

	local->open_count--;
	if (local->open_count == 0) {
		if (netif_running(local->mdev))
			dev_close(local->mdev);
		if (local->apdev)
			dev_close(local->apdev);
		if (local->ops->stop)
			local->ops->stop(local_to_hw(local));
		tasklet_disable(&local->tx_pending_tasklet);
		tasklet_disable(&local->tasklet);
	}
	if (local->ops->remove_interface) {
		struct ieee80211_if_init_conf conf;

		conf.if_id = dev->ifindex;
		conf.type = sdata->type;
		conf.mac_addr = dev->dev_addr;
		local->ops->remove_interface(local_to_hw(local), &conf);
	}

	ieee80211_start_hard_monitor(local);

	return 0;
}

enum netif_tx_lock_class {
	TX_LOCK_NORMAL,
	TX_LOCK_MASTER,
};

static inline void netif_tx_lock_nested(struct net_device *dev, int subclass)
{
	spin_lock_nested(&dev->_xmit_lock, subclass);
	dev->xmit_lock_owner = smp_processor_id();
}

static void ieee80211_set_multicast_list(struct net_device *dev)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	unsigned short flags;

	netif_tx_lock_nested(local->mdev, TX_LOCK_MASTER);
	if (((dev->flags & IFF_ALLMULTI) != 0) ^
	    ((sdata->flags & IEEE80211_SDATA_ALLMULTI) != 0)) {
		if (sdata->flags & IEEE80211_SDATA_ALLMULTI)
			local->iff_allmultis--;
		else
			local->iff_allmultis++;
		sdata->flags ^= IEEE80211_SDATA_ALLMULTI;
	}
	if (((dev->flags & IFF_PROMISC) != 0) ^
	    ((sdata->flags & IEEE80211_SDATA_PROMISC) != 0)) {
		if (sdata->flags & IEEE80211_SDATA_PROMISC)
			local->iff_promiscs--;
		else
			local->iff_promiscs++;
		sdata->flags ^= IEEE80211_SDATA_PROMISC;
	}
	if (dev->mc_count != sdata->mc_count) {
		local->mc_count = local->mc_count - sdata->mc_count +
				  dev->mc_count;
		sdata->mc_count = dev->mc_count;
	}
	if (local->ops->set_multicast_list) {
		flags = local->mdev->flags;
		if (local->iff_allmultis)
			flags |= IFF_ALLMULTI;
		if (local->iff_promiscs)
			flags |= IFF_PROMISC;
		read_lock(&local->sub_if_lock);
		local->ops->set_multicast_list(local_to_hw(local), flags,
					      local->mc_count);
		read_unlock(&local->sub_if_lock);
	}
	netif_tx_unlock(local->mdev);
}

/* Must not be called for mdev and apdev */
void ieee80211_if_setup(struct net_device *dev)
{
	ether_setup(dev);
	dev->hard_start_xmit = ieee80211_subif_start_xmit;
	dev->wireless_handlers = &ieee80211_iw_handler_def;
	dev->set_multicast_list = ieee80211_set_multicast_list;
	dev->change_mtu = ieee80211_change_mtu;
	dev->get_stats = ieee80211_get_stats;
	dev->open = ieee80211_open;
	dev->stop = ieee80211_stop;
	dev->uninit = ieee80211_if_reinit;
	dev->destructor = ieee80211_if_free;
}

/* WDS specialties */

int ieee80211_if_update_wds(struct net_device *dev, u8 *remote_addr)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct sta_info *sta;

	if (compare_ether_addr(remote_addr, sdata->u.wds.remote_addr) == 0)
		return 0;

	/* Create STA entry for the new peer */
	sta = sta_info_add(local, dev, remote_addr, GFP_KERNEL);
	if (!sta)
		return -ENOMEM;
	sta_info_put(sta);

	/* Remove STA entry for the old peer */
	sta = sta_info_get(local, sdata->u.wds.remote_addr);
	if (sta) {
		sta_info_free(sta);
		sta_info_put(sta);
	} else {
		printk(KERN_DEBUG "%s: could not find STA entry for WDS link "
		       "peer " MAC_FMT "\n",
		       dev->name, MAC_ARG(sdata->u.wds.remote_addr));
	}

	/* Update WDS link data */
	memcpy(&sdata->u.wds.remote_addr, remote_addr, ETH_ALEN);

	return 0;
}

/* everything else */

static int __ieee80211_if_config(struct net_device *dev,
				 struct sk_buff *beacon,
				 struct ieee80211_tx_control *control)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_if_conf conf;
	static u8 scan_bssid[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	if (!local->ops->config_interface || !netif_running(dev))
		return 0;

	memset(&conf, 0, sizeof(conf));
	conf.type = sdata->type;
	if (sdata->type == IEEE80211_IF_TYPE_STA ||
	    sdata->type == IEEE80211_IF_TYPE_IBSS) {
		if (local->sta_scanning &&
		    local->scan_dev == dev)
			conf.bssid = scan_bssid;
		else
			conf.bssid = sdata->u.sta.bssid;
		conf.ssid = sdata->u.sta.ssid;
		conf.ssid_len = sdata->u.sta.ssid_len;
		conf.generic_elem = sdata->u.sta.extra_ie;
		conf.generic_elem_len = sdata->u.sta.extra_ie_len;
	} else if (sdata->type == IEEE80211_IF_TYPE_AP) {
		conf.ssid = sdata->u.ap.ssid;
		conf.ssid_len = sdata->u.ap.ssid_len;
		conf.generic_elem = sdata->u.ap.generic_elem;
		conf.generic_elem_len = sdata->u.ap.generic_elem_len;
		conf.beacon = beacon;
		conf.beacon_control = control;
	}
	return local->ops->config_interface(local_to_hw(local),
					   dev->ifindex, &conf);
}

int ieee80211_if_config(struct net_device *dev)
{
	return __ieee80211_if_config(dev, NULL, NULL);
}

int ieee80211_if_config_beacon(struct net_device *dev)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_tx_control control;
	struct sk_buff *skb;

	if (!(local->hw.flags & IEEE80211_HW_HOST_GEN_BEACON_TEMPLATE))
		return 0;
	skb = ieee80211_beacon_get(local_to_hw(local), dev->ifindex, &control);
	if (!skb)
		return -ENOMEM;
	return __ieee80211_if_config(dev, skb, &control);
}

int ieee80211_hw_config(struct ieee80211_local *local)
{
	struct ieee80211_hw_mode *mode;
	struct ieee80211_channel *chan;
	int ret = 0;

	if (local->sta_scanning) {
		chan = local->scan_channel;
		mode = local->scan_hw_mode;
	} else {
		chan = local->oper_channel;
		mode = local->oper_hw_mode;
	}

	local->hw.conf.channel = chan->chan;
	local->hw.conf.channel_val = chan->val;
	local->hw.conf.power_level = chan->power_level;
	local->hw.conf.freq = chan->freq;
	local->hw.conf.phymode = mode->mode;
	local->hw.conf.antenna_max = chan->antenna_max;
	local->hw.conf.chan = chan;
	local->hw.conf.mode = mode;

#ifdef CONFIG_MAC80211_VERBOSE_DEBUG
	printk(KERN_DEBUG "HW CONFIG: channel=%d freq=%d "
	       "phymode=%d\n", local->hw.conf.channel, local->hw.conf.freq,
	       local->hw.conf.phymode);
#endif /* CONFIG_MAC80211_VERBOSE_DEBUG */

	if (local->ops->config)
		ret = local->ops->config(local_to_hw(local), &local->hw.conf);

	return ret;
}

void ieee80211_erp_info_change_notify(struct net_device *dev, u8 changes)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	if (local->ops->erp_ie_changed)
		local->ops->erp_ie_changed(local_to_hw(local), changes,
			!!(sdata->flags & IEEE80211_SDATA_USE_PROTECTION),
			!(sdata->flags & IEEE80211_SDATA_SHORT_PREAMBLE));
}

void ieee80211_reset_erp_info(struct net_device *dev)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);

	sdata->flags &= ~(IEEE80211_SDATA_USE_PROTECTION |
			IEEE80211_SDATA_SHORT_PREAMBLE);
	ieee80211_erp_info_change_notify(dev,
					 IEEE80211_ERP_CHANGE_PROTECTION |
					 IEEE80211_ERP_CHANGE_PREAMBLE);
}

struct dev_mc_list *ieee80211_get_mc_list_item(struct ieee80211_hw *hw,
					       struct dev_mc_list *prev,
					       void **ptr)
{
	struct ieee80211_local *local = hw_to_local(hw);
	struct ieee80211_sub_if_data *sdata = *ptr;
	struct dev_mc_list *mc;

	if (!prev) {
		WARN_ON(sdata);
		sdata = NULL;
	}
	if (!prev || !prev->next) {
		if (sdata)
			sdata = list_entry(sdata->list.next,
					   struct ieee80211_sub_if_data, list);
		else
			sdata = list_entry(local->sub_if_list.next,
					   struct ieee80211_sub_if_data, list);
		if (&sdata->list != &local->sub_if_list)
			mc = sdata->dev->mc_list;
		else
			mc = NULL;
	} else
		mc = prev->next;

	*ptr = sdata;
	return mc;
}
EXPORT_SYMBOL(ieee80211_get_mc_list_item);

void ieee80211_tx_status_irqsafe(struct ieee80211_hw *hw,
				 struct sk_buff *skb,
				 struct ieee80211_tx_status *status)
{
	struct ieee80211_local *local = hw_to_local(hw);
	struct ieee80211_tx_status *saved;
	int tmp;

	skb->dev = local->mdev;
	saved = kmalloc(sizeof(struct ieee80211_tx_status), GFP_ATOMIC);
	if (unlikely(!saved)) {
		if (net_ratelimit())
			printk(KERN_WARNING "%s: Not enough memory, "
			       "dropping tx status", skb->dev->name);
		/* should be dev_kfree_skb_irq, but due to this function being
		 * named _irqsafe instead of just _irq we can't be sure that
		 * people won't call it from non-irq contexts */
		dev_kfree_skb_any(skb);
		return;
	}
	memcpy(saved, status, sizeof(struct ieee80211_tx_status));
	/* copy pointer to saved status into skb->cb for use by tasklet */
	memcpy(skb->cb, &saved, sizeof(saved));

	skb->pkt_type = IEEE80211_TX_STATUS_MSG;
	skb_queue_tail(status->control.flags & IEEE80211_TXCTL_REQ_TX_STATUS ?
		       &local->skb_queue : &local->skb_queue_unreliable, skb);
	tmp = skb_queue_len(&local->skb_queue) +
		skb_queue_len(&local->skb_queue_unreliable);
	while (tmp > IEEE80211_IRQSAFE_QUEUE_LIMIT &&
	       (skb = skb_dequeue(&local->skb_queue_unreliable))) {
		memcpy(&saved, skb->cb, sizeof(saved));
		kfree(saved);
		dev_kfree_skb_irq(skb);
		tmp--;
		I802_DEBUG_INC(local->tx_status_drop);
	}
	tasklet_schedule(&local->tasklet);
}
EXPORT_SYMBOL(ieee80211_tx_status_irqsafe);

static void ieee80211_tasklet_handler(unsigned long data)
{
	struct ieee80211_local *local = (struct ieee80211_local *) data;
	struct sk_buff *skb;
	struct ieee80211_rx_status rx_status;
	struct ieee80211_tx_status *tx_status;

	while ((skb = skb_dequeue(&local->skb_queue)) ||
	       (skb = skb_dequeue(&local->skb_queue_unreliable))) {
		switch (skb->pkt_type) {
		case IEEE80211_RX_MSG:
			/* status is in skb->cb */
			memcpy(&rx_status, skb->cb, sizeof(rx_status));
			/* Clear skb->type in order to not confuse kernel
			 * netstack. */
			skb->pkt_type = 0;
			__ieee80211_rx(local_to_hw(local), skb, &rx_status);
			break;
		case IEEE80211_TX_STATUS_MSG:
			/* get pointer to saved status out of skb->cb */
			memcpy(&tx_status, skb->cb, sizeof(tx_status));
			skb->pkt_type = 0;
			ieee80211_tx_status(local_to_hw(local),
					    skb, tx_status);
			kfree(tx_status);
			break;
		default: /* should never get here! */
			printk(KERN_ERR "%s: Unknown message type (%d)\n",
			       local->mdev->name, skb->pkt_type);
			dev_kfree_skb(skb);
			break;
		}
	}
}

/* Remove added headers (e.g., QoS control), encryption header/MIC, etc. to
 * make a prepared TX frame (one that has been given to hw) to look like brand
 * new IEEE 802.11 frame that is ready to go through TX processing again.
 * Also, tx_packet_data in cb is restored from tx_control. */
static void ieee80211_remove_tx_extra(struct ieee80211_local *local,
				      struct ieee80211_key *key,
				      struct sk_buff *skb,
				      struct ieee80211_tx_control *control)
{
	int hdrlen, iv_len, mic_len;
	struct ieee80211_tx_packet_data *pkt_data;

	pkt_data = (struct ieee80211_tx_packet_data *)skb->cb;
	pkt_data->ifindex = control->ifindex;
	pkt_data->flags = 0;
	if (control->flags & IEEE80211_TXCTL_REQ_TX_STATUS)
		pkt_data->flags |= IEEE80211_TXPD_REQ_TX_STATUS;
	if (control->flags & IEEE80211_TXCTL_DO_NOT_ENCRYPT)
		pkt_data->flags |= IEEE80211_TXPD_DO_NOT_ENCRYPT;
	if (control->flags & IEEE80211_TXCTL_REQUEUE)
		pkt_data->flags |= IEEE80211_TXPD_REQUEUE;
	if (control->type == IEEE80211_IF_TYPE_MGMT)
		pkt_data->flags |= IEEE80211_TXPD_MGMT_IFACE;
	pkt_data->queue = control->queue;

	hdrlen = ieee80211_get_hdrlen_from_skb(skb);

	if (!key)
		goto no_key;

	switch (key->conf.alg) {
	case ALG_WEP:
		iv_len = WEP_IV_LEN;
		mic_len = WEP_ICV_LEN;
		break;
	case ALG_TKIP:
		iv_len = TKIP_IV_LEN;
		mic_len = TKIP_ICV_LEN;
		break;
	case ALG_CCMP:
		iv_len = CCMP_HDR_LEN;
		mic_len = CCMP_MIC_LEN;
		break;
	default:
		goto no_key;
	}

	if (skb->len >= mic_len &&
	    !(key->flags & KEY_FLAG_UPLOADED_TO_HARDWARE))
		skb_trim(skb, skb->len - mic_len);
	if (skb->len >= iv_len && skb->len > hdrlen) {
		memmove(skb->data + iv_len, skb->data, hdrlen);
		skb_pull(skb, iv_len);
	}

no_key:
	{
		struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb->data;
		u16 fc = le16_to_cpu(hdr->frame_control);
		if ((fc & 0x8C) == 0x88) /* QoS Control Field */ {
			fc &= ~IEEE80211_STYPE_QOS_DATA;
			hdr->frame_control = cpu_to_le16(fc);
			memmove(skb->data + 2, skb->data, hdrlen - 2);
			skb_pull(skb, 2);
		}
	}
}

void ieee80211_tx_status(struct ieee80211_hw *hw, struct sk_buff *skb,
			 struct ieee80211_tx_status *status)
{
	struct sk_buff *skb2;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb->data;
	struct ieee80211_local *local = hw_to_local(hw);
	u16 frag, type;
	u32 msg_type;
	struct ieee80211_tx_status_rtap_hdr *rthdr;
	struct ieee80211_sub_if_data *sdata;
	int monitors;

	if (!status) {
		printk(KERN_ERR
		       "%s: ieee80211_tx_status called with NULL status\n",
		       local->mdev->name);
		dev_kfree_skb(skb);
		return;
	}

	if (status->excessive_retries) {
		struct sta_info *sta;
		sta = sta_info_get(local, hdr->addr1);
		if (sta) {
			if (sta->flags & WLAN_STA_PS) {
				/* The STA is in power save mode, so assume
				 * that this TX packet failed because of that.
				 */
				status->excessive_retries = 0;
				status->flags |= IEEE80211_TX_STATUS_TX_FILTERED;
			}
			sta_info_put(sta);
		}
	}

	if (status->flags & IEEE80211_TX_STATUS_TX_FILTERED) {
		struct sta_info *sta;
		sta = sta_info_get(local, hdr->addr1);
		if (sta) {
			sta->tx_filtered_count++;

			/* Clear the TX filter mask for this STA when sending
			 * the next packet. If the STA went to power save mode,
			 * this will happen when it is waking up for the next
			 * time. */
			sta->clear_dst_mask = 1;

			/* TODO: Is the WLAN_STA_PS flag always set here or is
			 * the race between RX and TX status causing some
			 * packets to be filtered out before 80211.o gets an
			 * update for PS status? This seems to be the case, so
			 * no changes are likely to be needed. */
			if (sta->flags & WLAN_STA_PS &&
			    skb_queue_len(&sta->tx_filtered) <
			    STA_MAX_TX_BUFFER) {
				ieee80211_remove_tx_extra(local, sta->key,
							  skb,
							  &status->control);
				skb_queue_tail(&sta->tx_filtered, skb);
			} else if (!(sta->flags & WLAN_STA_PS) &&
				   !(status->control.flags & IEEE80211_TXCTL_REQUEUE)) {
				/* Software retry the packet once */
				status->control.flags |= IEEE80211_TXCTL_REQUEUE;
				ieee80211_remove_tx_extra(local, sta->key,
							  skb,
							  &status->control);
				dev_queue_xmit(skb);
			} else {
				if (net_ratelimit()) {
					printk(KERN_DEBUG "%s: dropped TX "
					       "filtered frame queue_len=%d "
					       "PS=%d @%lu\n",
					       local->mdev->name,
					       skb_queue_len(
						       &sta->tx_filtered),
					       !!(sta->flags & WLAN_STA_PS),
					       jiffies);
				}
				dev_kfree_skb(skb);
			}
			sta_info_put(sta);
			return;
		}
	} else {
		/* FIXME: STUPID to call this with both local and local->mdev */
		rate_control_tx_status(local, local->mdev, skb, status);
	}

	ieee80211_led_tx(local, 0);

	/* SNMP counters
	 * Fragments are passed to low-level drivers as separate skbs, so these
	 * are actually fragments, not frames. Update frame counters only for
	 * the first fragment of the frame. */

	frag = le16_to_cpu(hdr->seq_ctrl) & IEEE80211_SCTL_FRAG;
	type = le16_to_cpu(hdr->frame_control) & IEEE80211_FCTL_FTYPE;

	if (status->flags & IEEE80211_TX_STATUS_ACK) {
		if (frag == 0) {
			local->dot11TransmittedFrameCount++;
			if (is_multicast_ether_addr(hdr->addr1))
				local->dot11MulticastTransmittedFrameCount++;
			if (status->retry_count > 0)
				local->dot11RetryCount++;
			if (status->retry_count > 1)
				local->dot11MultipleRetryCount++;
		}

		/* This counter shall be incremented for an acknowledged MPDU
		 * with an individual address in the address 1 field or an MPDU
		 * with a multicast address in the address 1 field of type Data
		 * or Management. */
		if (!is_multicast_ether_addr(hdr->addr1) ||
		    type == IEEE80211_FTYPE_DATA ||
		    type == IEEE80211_FTYPE_MGMT)
			local->dot11TransmittedFragmentCount++;
	} else {
		if (frag == 0)
			local->dot11FailedCount++;
	}

	msg_type = (status->flags & IEEE80211_TX_STATUS_ACK) ?
		ieee80211_msg_tx_callback_ack : ieee80211_msg_tx_callback_fail;

	/* this was a transmitted frame, but now we want to reuse it */
	skb_orphan(skb);

	if ((status->control.flags & IEEE80211_TXCTL_REQ_TX_STATUS) &&
	    local->apdev) {
		if (local->monitors) {
			skb2 = skb_clone(skb, GFP_ATOMIC);
		} else {
			skb2 = skb;
			skb = NULL;
		}

		if (skb2)
			/* Send frame to hostapd */
			ieee80211_rx_mgmt(local, skb2, NULL, msg_type);

		if (!skb)
			return;
	}

	if (!local->monitors) {
		dev_kfree_skb(skb);
		return;
	}

	/* send frame to monitor interfaces now */

	if (skb_headroom(skb) < sizeof(*rthdr)) {
		printk(KERN_ERR "ieee80211_tx_status: headroom too small\n");
		dev_kfree_skb(skb);
		return;
	}

	rthdr = (struct ieee80211_tx_status_rtap_hdr*)
				skb_push(skb, sizeof(*rthdr));

	memset(rthdr, 0, sizeof(*rthdr));
	rthdr->hdr.it_len = cpu_to_le16(sizeof(*rthdr));
	rthdr->hdr.it_present =
		cpu_to_le32((1 << IEEE80211_RADIOTAP_TX_FLAGS) |
			    (1 << IEEE80211_RADIOTAP_DATA_RETRIES));

	if (!(status->flags & IEEE80211_TX_STATUS_ACK) &&
	    !is_multicast_ether_addr(hdr->addr1))
		rthdr->tx_flags |= cpu_to_le16(IEEE80211_RADIOTAP_F_TX_FAIL);

	if ((status->control.flags & IEEE80211_TXCTL_USE_RTS_CTS) &&
	    (status->control.flags & IEEE80211_TXCTL_USE_CTS_PROTECT))
		rthdr->tx_flags |= cpu_to_le16(IEEE80211_RADIOTAP_F_TX_CTS);
	else if (status->control.flags & IEEE80211_TXCTL_USE_RTS_CTS)
		rthdr->tx_flags |= cpu_to_le16(IEEE80211_RADIOTAP_F_TX_RTS);

	rthdr->data_retries = status->retry_count;

	read_lock(&local->sub_if_lock);
	monitors = local->monitors;
	list_for_each_entry(sdata, &local->sub_if_list, list) {
		/*
		 * Using the monitors counter is possibly racy, but
		 * if the value is wrong we simply either clone the skb
		 * once too much or forget sending it to one monitor iface
		 * The latter case isn't nice but fixing the race is much
		 * more complicated.
		 */
		if (!monitors || !skb)
			goto out;

		if (sdata->type == IEEE80211_IF_TYPE_MNTR) {
			if (!netif_running(sdata->dev))
				continue;
			monitors--;
			if (monitors)
				skb2 = skb_clone(skb, GFP_KERNEL);
			else
				skb2 = NULL;
			skb->dev = sdata->dev;
			/* XXX: is this sufficient for BPF? */
			skb_set_mac_header(skb, 0);
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb->pkt_type = PACKET_OTHERHOST;
			skb->protocol = htons(ETH_P_802_2);
			memset(skb->cb, 0, sizeof(skb->cb));
			netif_rx(skb);
			skb = skb2;
		}
	}
 out:
	read_unlock(&local->sub_if_lock);
	if (skb)
		dev_kfree_skb(skb);
}
EXPORT_SYMBOL(ieee80211_tx_status);

struct ieee80211_hw *ieee80211_alloc_hw(size_t priv_data_len,
					const struct ieee80211_ops *ops)
{
	struct net_device *mdev;
	struct ieee80211_local *local;
	struct ieee80211_sub_if_data *sdata;
	int priv_size;
	struct wiphy *wiphy;

	/* Ensure 32-byte alignment of our private data and hw private data.
	 * We use the wiphy priv data for both our ieee80211_local and for
	 * the driver's private data
	 *
	 * In memory it'll be like this:
	 *
	 * +-------------------------+
	 * | struct wiphy	    |
	 * +-------------------------+
	 * | struct ieee80211_local  |
	 * +-------------------------+
	 * | driver's private data   |
	 * +-------------------------+
	 *
	 */
	priv_size = ((sizeof(struct ieee80211_local) +
		      NETDEV_ALIGN_CONST) & ~NETDEV_ALIGN_CONST) +
		    priv_data_len;

	wiphy = wiphy_new(&mac80211_config_ops, priv_size);

	if (!wiphy)
		return NULL;

	wiphy->privid = mac80211_wiphy_privid;

	local = wiphy_priv(wiphy);
	local->hw.wiphy = wiphy;

	local->hw.priv = (char *)local +
			 ((sizeof(struct ieee80211_local) +
			   NETDEV_ALIGN_CONST) & ~NETDEV_ALIGN_CONST);

	BUG_ON(!ops->tx);
	BUG_ON(!ops->config);
	BUG_ON(!ops->add_interface);
	local->ops = ops;

	/* for now, mdev needs sub_if_data :/ */
	mdev = alloc_netdev(sizeof(struct ieee80211_sub_if_data),
			    "wmaster%d", ether_setup);
	if (!mdev) {
		wiphy_free(wiphy);
		return NULL;
	}

	sdata = IEEE80211_DEV_TO_SUB_IF(mdev);
	mdev->ieee80211_ptr = &sdata->wdev;
	sdata->wdev.wiphy = wiphy;

	local->hw.queues = 1; /* default */

	local->mdev = mdev;
	local->rx_pre_handlers = ieee80211_rx_pre_handlers;
	local->rx_handlers = ieee80211_rx_handlers;
	local->tx_handlers = ieee80211_tx_handlers;

	local->bridge_packets = 1;

	local->rts_threshold = IEEE80211_MAX_RTS_THRESHOLD;
	local->fragmentation_threshold = IEEE80211_MAX_FRAG_THRESHOLD;
	local->short_retry_limit = 7;
	local->long_retry_limit = 4;
	local->hw.conf.radio_enabled = 1;

	local->enabled_modes = (unsigned int) -1;

	INIT_LIST_HEAD(&local->modes_list);

	rwlock_init(&local->sub_if_lock);
	INIT_LIST_HEAD(&local->sub_if_list);

	INIT_DELAYED_WORK(&local->scan_work, ieee80211_sta_scan_work);
	ieee80211_rx_bss_list_init(mdev);

	sta_info_init(local);

	mdev->hard_start_xmit = ieee80211_master_start_xmit;
	mdev->open = ieee80211_master_open;
	mdev->stop = ieee80211_master_stop;
	mdev->type = ARPHRD_IEEE80211;
	mdev->hard_header_parse = header_parse_80211;

	sdata->type = IEEE80211_IF_TYPE_AP;
	sdata->dev = mdev;
	sdata->local = local;
	sdata->u.ap.force_unicast_rateidx = -1;
	sdata->u.ap.max_ratectrl_rateidx = -1;
	ieee80211_if_sdata_init(sdata);
	list_add_tail(&sdata->list, &local->sub_if_list);

	tasklet_init(&local->tx_pending_tasklet, ieee80211_tx_pending,
		     (unsigned long)local);
	tasklet_disable(&local->tx_pending_tasklet);

	tasklet_init(&local->tasklet,
		     ieee80211_tasklet_handler,
		     (unsigned long) local);
	tasklet_disable(&local->tasklet);

	skb_queue_head_init(&local->skb_queue);
	skb_queue_head_init(&local->skb_queue_unreliable);

	return local_to_hw(local);
}
EXPORT_SYMBOL(ieee80211_alloc_hw);

int ieee80211_register_hw(struct ieee80211_hw *hw)
{
	struct ieee80211_local *local = hw_to_local(hw);
	const char *name;
	int result;

	result = wiphy_register(local->hw.wiphy);
	if (result < 0)
		return result;

	name = wiphy_dev(local->hw.wiphy)->driver->name;
	local->hw.workqueue = create_singlethread_workqueue(name);
	if (!local->hw.workqueue) {
		result = -ENOMEM;
		goto fail_workqueue;
	}

	/*
	 * The hardware needs headroom for sending the frame,
	 * and we need some headroom for passing the frame to monitor
	 * interfaces, but never both at the same time.
	 */
	local->tx_headroom = max_t(unsigned int , local->hw.extra_tx_headroom,
				   sizeof(struct ieee80211_tx_status_rtap_hdr));

	debugfs_hw_add(local);

	local->hw.conf.beacon_int = 1000;

	local->wstats_flags |= local->hw.max_rssi ?
			       IW_QUAL_LEVEL_UPDATED : IW_QUAL_LEVEL_INVALID;
	local->wstats_flags |= local->hw.max_signal ?
			       IW_QUAL_QUAL_UPDATED : IW_QUAL_QUAL_INVALID;
	local->wstats_flags |= local->hw.max_noise ?
			       IW_QUAL_NOISE_UPDATED : IW_QUAL_NOISE_INVALID;
	if (local->hw.max_rssi < 0 || local->hw.max_noise < 0)
		local->wstats_flags |= IW_QUAL_DBM;

	result = sta_info_start(local);
	if (result < 0)
		goto fail_sta_info;

	rtnl_lock();
	result = dev_alloc_name(local->mdev, local->mdev->name);
	if (result < 0)
		goto fail_dev;

	memcpy(local->mdev->dev_addr, local->hw.wiphy->perm_addr, ETH_ALEN);
	SET_NETDEV_DEV(local->mdev, wiphy_dev(local->hw.wiphy));

	result = register_netdevice(local->mdev);
	if (result < 0)
		goto fail_dev;

	ieee80211_debugfs_add_netdev(IEEE80211_DEV_TO_SUB_IF(local->mdev));

	result = ieee80211_init_rate_ctrl_alg(local, NULL);
	if (result < 0) {
		printk(KERN_DEBUG "%s: Failed to initialize rate control "
		       "algorithm\n", local->mdev->name);
		goto fail_rate;
	}

	result = ieee80211_wep_init(local);

	if (result < 0) {
		printk(KERN_DEBUG "%s: Failed to initialize wep\n",
		       local->mdev->name);
		goto fail_wep;
	}

	ieee80211_install_qdisc(local->mdev);

	/* add one default STA interface */
	result = ieee80211_if_add(local->mdev, "wlan%d", NULL,
				  IEEE80211_IF_TYPE_STA);
	if (result)
		printk(KERN_WARNING "%s: Failed to add default virtual iface\n",
		       local->mdev->name);

	local->reg_state = IEEE80211_DEV_REGISTERED;
	rtnl_unlock();

	ieee80211_led_init(local);

	return 0;

fail_wep:
	rate_control_deinitialize(local);
fail_rate:
	ieee80211_debugfs_remove_netdev(IEEE80211_DEV_TO_SUB_IF(local->mdev));
	unregister_netdevice(local->mdev);
fail_dev:
	rtnl_unlock();
	sta_info_stop(local);
fail_sta_info:
	debugfs_hw_del(local);
	destroy_workqueue(local->hw.workqueue);
fail_workqueue:
	wiphy_unregister(local->hw.wiphy);
	return result;
}
EXPORT_SYMBOL(ieee80211_register_hw);

int ieee80211_register_hwmode(struct ieee80211_hw *hw,
			      struct ieee80211_hw_mode *mode)
{
	struct ieee80211_local *local = hw_to_local(hw);
	struct ieee80211_rate *rate;
	int i;

	INIT_LIST_HEAD(&mode->list);
	list_add_tail(&mode->list, &local->modes_list);

	local->hw_modes |= (1 << mode->mode);
	for (i = 0; i < mode->num_rates; i++) {
		rate = &(mode->rates[i]);
		rate->rate_inv = CHAN_UTIL_RATE_LCM / rate->rate;
	}
	ieee80211_prepare_rates(local, mode);

	if (!local->oper_hw_mode) {
		/* Default to this mode */
		local->hw.conf.phymode = mode->mode;
		local->oper_hw_mode = local->scan_hw_mode = mode;
		local->oper_channel = local->scan_channel = &mode->channels[0];
		local->hw.conf.mode = local->oper_hw_mode;
		local->hw.conf.chan = local->oper_channel;
	}

	if (!(hw->flags & IEEE80211_HW_DEFAULT_REG_DOMAIN_CONFIGURED))
		ieee80211_set_default_regdomain(mode);

	return 0;
}
EXPORT_SYMBOL(ieee80211_register_hwmode);

void ieee80211_unregister_hw(struct ieee80211_hw *hw)
{
	struct ieee80211_local *local = hw_to_local(hw);
	struct ieee80211_sub_if_data *sdata, *tmp;
	struct list_head tmp_list;
	int i;

	tasklet_kill(&local->tx_pending_tasklet);
	tasklet_kill(&local->tasklet);

	rtnl_lock();

	BUG_ON(local->reg_state != IEEE80211_DEV_REGISTERED);

	local->reg_state = IEEE80211_DEV_UNREGISTERED;
	if (local->apdev)
		ieee80211_if_del_mgmt(local);

	write_lock_bh(&local->sub_if_lock);
	list_replace_init(&local->sub_if_list, &tmp_list);
	write_unlock_bh(&local->sub_if_lock);

	list_for_each_entry_safe(sdata, tmp, &tmp_list, list)
		__ieee80211_if_del(local, sdata);

	rtnl_unlock();

	ieee80211_rx_bss_list_deinit(local->mdev);
	ieee80211_clear_tx_pending(local);
	sta_info_stop(local);
	rate_control_deinitialize(local);
	debugfs_hw_del(local);

	for (i = 0; i < NUM_IEEE80211_MODES; i++) {
		kfree(local->supp_rates[i]);
		kfree(local->basic_rates[i]);
	}

	if (skb_queue_len(&local->skb_queue)
			|| skb_queue_len(&local->skb_queue_unreliable))
		printk(KERN_WARNING "%s: skb_queue not empty\n",
		       local->mdev->name);
	skb_queue_purge(&local->skb_queue);
	skb_queue_purge(&local->skb_queue_unreliable);

	destroy_workqueue(local->hw.workqueue);
	wiphy_unregister(local->hw.wiphy);
	ieee80211_wep_free(local);
	ieee80211_led_exit(local);
}
EXPORT_SYMBOL(ieee80211_unregister_hw);

void ieee80211_free_hw(struct ieee80211_hw *hw)
{
	struct ieee80211_local *local = hw_to_local(hw);

	ieee80211_if_free(local->mdev);
	wiphy_free(local->hw.wiphy);
}
EXPORT_SYMBOL(ieee80211_free_hw);

struct net_device_stats *ieee80211_dev_stats(struct net_device *dev)
{
	struct ieee80211_sub_if_data *sdata;
	sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	return &sdata->stats;
}

static int __init ieee80211_init(void)
{
	struct sk_buff *skb;
	int ret;

	BUILD_BUG_ON(sizeof(struct ieee80211_tx_packet_data) > sizeof(skb->cb));

	ret = ieee80211_wme_register();
	if (ret) {
		printk(KERN_DEBUG "ieee80211_init: failed to "
		       "initialize WME (err=%d)\n", ret);
		return ret;
	}

	ieee80211_debugfs_netdev_init();
	ieee80211_regdomain_init();

	return 0;
}

static void __exit ieee80211_exit(void)
{
	ieee80211_wme_unregister();
	ieee80211_debugfs_netdev_exit();
}


subsys_initcall(ieee80211_init);
module_exit(ieee80211_exit);

MODULE_DESCRIPTION("IEEE 802.11 subsystem");
MODULE_LICENSE("GPL");
