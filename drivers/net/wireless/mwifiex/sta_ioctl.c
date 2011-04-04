/*
 * Marvell Wireless LAN device driver: functions for station ioctl
 *
 * Copyright (C) 2011, Marvell International Ltd.
 *
 * This software file (the "File") is distributed by Marvell International
 * Ltd. under the terms of the GNU General Public License Version 2, June 1991
 * (the "License").  You may use, redistribute and/or modify this File in
 * accordance with the terms and conditions of the License, a copy of which
 * is available by writing to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA or on the
 * worldwide web at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
 * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
 * this warranty disclaimer.
 */

#include "decl.h"
#include "ioctl.h"
#include "util.h"
#include "fw.h"
#include "main.h"
#include "wmm.h"
#include "11n.h"
#include "cfg80211.h"

/*
 * Copies the multicast address list from device to driver.
 *
 * This function does not validate the destination memory for
 * size, and the calling function must ensure enough memory is
 * available.
 */
static int
mwifiex_copy_mcast_addr(struct mwifiex_multicast_list *mlist,
			struct net_device *dev)
{
	int i = 0;
	struct netdev_hw_addr *ha;

	netdev_for_each_mc_addr(ha, dev)
		memcpy(&mlist->mac_list[i++], ha->addr, ETH_ALEN);

	return i;
}

/*
 * Allocate and fills a wait queue with proper parameters.
 *
 * This function needs to be called before an IOCTL request can be made.
 * It can handle the following wait options:
 *      MWIFIEX_NO_WAIT     - Waiting is disabled
 *      MWIFIEX_IOCTL_WAIT  - Waiting is done on IOCTL wait queue
 *      MWIFIEX_CMD_WAIT    - Waiting is done on command wait queue
 *      MWIFIEX_WSTATS_WAIT - Waiting is done on stats wait queue
 */
struct mwifiex_wait_queue *
mwifiex_alloc_fill_wait_queue(struct mwifiex_private *priv,
			      u8 wait_option)
{
	struct mwifiex_wait_queue *wait = NULL;

	wait = (struct mwifiex_wait_queue *)
		kzalloc(sizeof(struct mwifiex_wait_queue), GFP_ATOMIC);
	if (!wait) {
		dev_err(priv->adapter->dev, "%s: fail to alloc buffer\n",
						__func__);
		return wait;
	}

	wait->bss_index = priv->bss_index;

	switch (wait_option) {
	case MWIFIEX_NO_WAIT:
		wait->enabled = 0;
		break;
	case MWIFIEX_IOCTL_WAIT:
		priv->ioctl_wait_q_woken = false;
		wait->start_time = jiffies;
		wait->wait = &priv->ioctl_wait_q;
		wait->condition = &priv->ioctl_wait_q_woken;
		wait->enabled = 1;
		break;
	case MWIFIEX_CMD_WAIT:
		priv->cmd_wait_q_woken = false;
		wait->start_time = jiffies;
		wait->wait = &priv->cmd_wait_q;
		wait->condition = &priv->cmd_wait_q_woken;
		wait->enabled = 1;
		break;
	case MWIFIEX_WSTATS_WAIT:
		priv->w_stats_wait_q_woken = false;
		wait->start_time = jiffies;
		wait->wait = &priv->w_stats_wait_q;
		wait->condition = &priv->w_stats_wait_q_woken;
		wait->enabled = 1;
		break;
	}

	return wait;
}

/*
 * Wait queue completion handler.
 *
 * This function waits on a particular wait queue.
 * For NO_WAIT option, it returns immediately. It also cancels the
 * pending IOCTL request after waking up, in case of errors.
 */
static void
mwifiex_wait_ioctl_complete(struct mwifiex_private *priv,
			    struct mwifiex_wait_queue *wait,
			    u8 wait_option)
{
	bool cancel_flag = false;

	switch (wait_option) {
	case MWIFIEX_NO_WAIT:
		break;
	case MWIFIEX_IOCTL_WAIT:
		wait_event_interruptible(priv->ioctl_wait_q,
					 priv->ioctl_wait_q_woken);
		if (!priv->ioctl_wait_q_woken)
			cancel_flag = true;
		break;
	case MWIFIEX_CMD_WAIT:
		wait_event_interruptible(priv->cmd_wait_q,
					 priv->cmd_wait_q_woken);
		if (!priv->cmd_wait_q_woken)
			cancel_flag = true;
		break;
	case MWIFIEX_WSTATS_WAIT:
		wait_event_interruptible(priv->w_stats_wait_q,
					 priv->w_stats_wait_q_woken);
		if (!priv->w_stats_wait_q_woken)
			cancel_flag = true;
		break;
	}
	if (cancel_flag) {
		mwifiex_cancel_pending_ioctl(priv->adapter, wait);
		dev_dbg(priv->adapter->dev, "cmd: IOCTL cancel: wait=%p, wait_option=%d\n",
			wait, wait_option);
	}

	return;
}

/*
 * The function waits for the request to complete and issues the
 * completion handler, if required.
 */
int mwifiex_request_ioctl(struct mwifiex_private *priv,
			  struct mwifiex_wait_queue *wait,
			  int status, u8 wait_option)
{
	switch (status) {
	case -EINPROGRESS:
		dev_dbg(priv->adapter->dev, "cmd: IOCTL pending: wait=%p, wait_option=%d\n",
				wait, wait_option);
		atomic_inc(&priv->adapter->ioctl_pending);
		/* Status pending, wake up main process */
		queue_work(priv->adapter->workqueue, &priv->adapter->main_work);

		/* Wait for completion */
		if (wait_option) {
			mwifiex_wait_ioctl_complete(priv, wait, wait_option);
			status = wait->status;
		}
		break;
	case 0:
	case -1:
	case -EBUSY:
	default:
		break;
	}
	return status;
}
EXPORT_SYMBOL_GPL(mwifiex_request_ioctl);

/*
 * IOCTL request handler to set/get MAC address.
 *
 * This function prepares the correct firmware command and
 * issues it to get the extended version information.
 */
static int mwifiex_bss_ioctl_mac_address(struct mwifiex_private *priv,
					 struct mwifiex_wait_queue *wait,
					 u8 action, u8 *mac)
{
	int ret = 0;

	if ((action == HostCmd_ACT_GEN_GET) && mac) {
		memcpy(mac, priv->curr_addr, ETH_ALEN);
		return 0;
	}

	/* Send request to firmware */
	ret = mwifiex_prepare_cmd(priv, HostCmd_CMD_802_11_MAC_ADDRESS,
				  action, 0, wait, mac);
	if (!ret)
		ret = -EINPROGRESS;

	return ret;
}

/*
 * Sends IOCTL request to set MAC address.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
int mwifiex_request_set_mac_address(struct mwifiex_private *priv)
{
	struct mwifiex_wait_queue *wait = NULL;
	int status = 0;
	u8 wait_option = MWIFIEX_CMD_WAIT;

	/* Allocate wait buffer */
	wait = mwifiex_alloc_fill_wait_queue(priv, wait_option);
	if (!wait)
		return -ENOMEM;

	status = mwifiex_bss_ioctl_mac_address(priv, wait, HostCmd_ACT_GEN_SET,
					       NULL);

	status = mwifiex_request_ioctl(priv, wait, status, wait_option);
	if (!status)
		memcpy(priv->netdev->dev_addr, priv->curr_addr, ETH_ALEN);
	else
		dev_err(priv->adapter->dev, "set mac address failed: status=%d"
				" error_code=%#x\n", status, wait->status);

	kfree(wait);
	return status;
}

/*
 * IOCTL request handler to set multicast list.
 *
 * This function prepares the correct firmware command and
 * issues it to set the multicast list.
 *
 * This function can be used to enable promiscuous mode, or enable all
 * multicast packets, or to enable selective multicast.
 */
static int
mwifiex_bss_ioctl_multicast_list(struct mwifiex_private *priv,
				 struct mwifiex_wait_queue *wait,
				 u16 action,
				 struct mwifiex_multicast_list *mcast_list)
{
	int ret = 0;
	u16 old_pkt_filter;

	old_pkt_filter = priv->curr_pkt_filter;
	if (action == HostCmd_ACT_GEN_GET)
		return -1;

	if (mcast_list->mode == MWIFIEX_PROMISC_MODE) {
		dev_dbg(priv->adapter->dev, "info: Enable Promiscuous mode\n");
		priv->curr_pkt_filter |= HostCmd_ACT_MAC_PROMISCUOUS_ENABLE;
		priv->curr_pkt_filter &=
			~HostCmd_ACT_MAC_ALL_MULTICAST_ENABLE;
	} else {
		/* Multicast */
		priv->curr_pkt_filter &= ~HostCmd_ACT_MAC_PROMISCUOUS_ENABLE;
		if (mcast_list->mode == MWIFIEX_MULTICAST_MODE) {
			dev_dbg(priv->adapter->dev,
				"info: Enabling All Multicast!\n");
			priv->curr_pkt_filter |=
				HostCmd_ACT_MAC_ALL_MULTICAST_ENABLE;
		} else {
			priv->curr_pkt_filter &=
				~HostCmd_ACT_MAC_ALL_MULTICAST_ENABLE;
			if (mcast_list->num_multicast_addr) {
				dev_dbg(priv->adapter->dev,
					"info: Set multicast list=%d\n",
				       mcast_list->num_multicast_addr);
				/* Set multicast addresses to firmware */
				if (old_pkt_filter == priv->curr_pkt_filter) {
					/* Send request to firmware */
					ret = mwifiex_prepare_cmd(priv,
						HostCmd_CMD_MAC_MULTICAST_ADR,
						action, 0, wait, mcast_list);
					if (!ret)
						ret = -EINPROGRESS;
				} else {
					/* Send request to firmware */
					ret = mwifiex_prepare_cmd(priv,
						HostCmd_CMD_MAC_MULTICAST_ADR,
						action, 0, NULL,
						mcast_list);
				}
			}
		}
	}
	dev_dbg(priv->adapter->dev,
		"info: old_pkt_filter=%#x, curr_pkt_filter=%#x\n",
	       old_pkt_filter, priv->curr_pkt_filter);
	if (old_pkt_filter != priv->curr_pkt_filter) {
		ret = mwifiex_prepare_cmd(priv, HostCmd_CMD_MAC_CONTROL, action,
					  0, wait, &priv->curr_pkt_filter);
		if (!ret)
			ret = -EINPROGRESS;
	}

	return ret;
}

/*
 * Sends IOCTL request to set multicast list.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
void
mwifiex_request_set_multicast_list(struct mwifiex_private *priv,
				   struct net_device *dev)
{
	struct mwifiex_wait_queue *wait = NULL;
	struct mwifiex_multicast_list mcast_list;
	u8 wait_option = MWIFIEX_NO_WAIT;
	int status = 0;

	/* Allocate wait buffer */
	wait = mwifiex_alloc_fill_wait_queue(priv, wait_option);
	if (!wait)
		return;

	if (dev->flags & IFF_PROMISC) {
		mcast_list.mode = MWIFIEX_PROMISC_MODE;
	} else if (dev->flags & IFF_ALLMULTI ||
		   netdev_mc_count(dev) > MWIFIEX_MAX_MULTICAST_LIST_SIZE) {
		mcast_list.mode = MWIFIEX_ALL_MULTI_MODE;
	} else {
		mcast_list.mode = MWIFIEX_MULTICAST_MODE;
		if (netdev_mc_count(dev))
			mcast_list.num_multicast_addr =
				mwifiex_copy_mcast_addr(&mcast_list, dev);
	}
	status = mwifiex_bss_ioctl_multicast_list(priv, wait,
						  HostCmd_ACT_GEN_SET,
						  &mcast_list);

	status = mwifiex_request_ioctl(priv, wait, status, wait_option);
	if (wait && status != -EINPROGRESS)
		kfree(wait);

	return;
}

/*
 * IOCTL request handler to disconnect from a BSS/IBSS.
 */
static int mwifiex_bss_ioctl_stop(struct mwifiex_private *priv,
				  struct mwifiex_wait_queue *wait, u8 *mac)
{
	return mwifiex_deauthenticate(priv, wait, mac);
}

/*
 * Sends IOCTL request to disconnect from a BSS.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
int mwifiex_disconnect(struct mwifiex_private *priv, u8 wait_option, u8 *mac)
{
	struct mwifiex_wait_queue *wait = NULL;
	int status = 0;

	/* Allocate wait buffer */
	wait = mwifiex_alloc_fill_wait_queue(priv, wait_option);
	if (!wait)
		return -ENOMEM;

	status = mwifiex_bss_ioctl_stop(priv, wait, mac);

	status = mwifiex_request_ioctl(priv, wait, status, wait_option);

	kfree(wait);
	return status;
}
EXPORT_SYMBOL_GPL(mwifiex_disconnect);

/*
 * IOCTL request handler to join a BSS/IBSS.
 *
 * In Ad-Hoc mode, the IBSS is created if not found in scan list.
 * In both Ad-Hoc and infra mode, an deauthentication is performed
 * first.
 */
static int mwifiex_bss_ioctl_start(struct mwifiex_private *priv,
				   struct mwifiex_wait_queue *wait,
				   struct mwifiex_ssid_bssid *ssid_bssid)
{
	int ret = 0;
	struct mwifiex_adapter *adapter = priv->adapter;
	s32 i = -1;

	priv->scan_block = false;
	if (!ssid_bssid)
		return -1;

	if (priv->bss_mode == MWIFIEX_BSS_MODE_INFRA) {
		/* Infra mode */
		ret = mwifiex_deauthenticate(priv, NULL, NULL);
		if (ret)
			return ret;

		/* Search for the requested SSID in the scan table */
		if (ssid_bssid->ssid.ssid_len)
			i = mwifiex_find_ssid_in_list(priv, &ssid_bssid->ssid,
						NULL, MWIFIEX_BSS_MODE_INFRA);
		else
			i = mwifiex_find_bssid_in_list(priv,
						(u8 *) &ssid_bssid->bssid,
						MWIFIEX_BSS_MODE_INFRA);
		if (i < 0)
			return -1;

		dev_dbg(adapter->dev,
			"info: SSID found in scan list ... associating...\n");

		/* Clear any past association response stored for
		 * application retrieval */
		priv->assoc_rsp_size = 0;
		ret = mwifiex_associate(priv, wait, &adapter->scan_table[i]);
		if (ret)
			return ret;
	} else {
		/* Adhoc mode */
		/* If the requested SSID matches current SSID, return */
		if (ssid_bssid->ssid.ssid_len &&
		    (!mwifiex_ssid_cmp
		     (&priv->curr_bss_params.bss_descriptor.ssid,
		      &ssid_bssid->ssid)))
			return 0;

		/* Exit Adhoc mode first */
		dev_dbg(adapter->dev, "info: Sending Adhoc Stop\n");
		ret = mwifiex_deauthenticate(priv, NULL, NULL);
		if (ret)
			return ret;

		priv->adhoc_is_link_sensed = false;

		/* Search for the requested network in the scan table */
		if (ssid_bssid->ssid.ssid_len)
			i = mwifiex_find_ssid_in_list(priv,
						      &ssid_bssid->ssid, NULL,
						      MWIFIEX_BSS_MODE_IBSS);
		else
			i = mwifiex_find_bssid_in_list(priv,
						       (u8 *)&ssid_bssid->bssid,
						       MWIFIEX_BSS_MODE_IBSS);

		if (i >= 0) {
			dev_dbg(adapter->dev, "info: network found in scan"
							" list. Joining...\n");
			ret = mwifiex_adhoc_join(priv, wait,
						 &adapter->scan_table[i]);
			if (ret)
				return ret;
		} else {	/* i >= 0 */
			dev_dbg(adapter->dev, "info: Network not found in "
				"the list, creating adhoc with ssid = %s\n",
			       ssid_bssid->ssid.ssid);
			ret = mwifiex_adhoc_start(priv, wait,
						  &ssid_bssid->ssid);
			if (ret)
				return ret;
		}
	}

	if (!ret)
		ret = -EINPROGRESS;

	return ret;
}

/*
 * Sends IOCTL request to connect with a BSS.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
int mwifiex_bss_start(struct mwifiex_private *priv, u8 wait_option,
		      struct mwifiex_ssid_bssid *ssid_bssid)
{
	struct mwifiex_wait_queue *wait = NULL;
	struct mwifiex_ssid_bssid tmp_ssid_bssid;
	int status = 0;

	/* Stop the O.S. TX queue if needed */
	if (!netif_queue_stopped(priv->netdev))
		netif_stop_queue(priv->netdev);

	/* Allocate wait buffer */
	wait = mwifiex_alloc_fill_wait_queue(priv, wait_option);
	if (!wait)
		return -ENOMEM;

	if (ssid_bssid)
		memcpy(&tmp_ssid_bssid, ssid_bssid,
		       sizeof(struct mwifiex_ssid_bssid));
	status = mwifiex_bss_ioctl_start(priv, wait, &tmp_ssid_bssid);

	status = mwifiex_request_ioctl(priv, wait, status, wait_option);

	kfree(wait);
	return status;
}

/*
 * IOCTL request handler to set host sleep configuration.
 *
 * This function prepares the correct firmware command and
 * issues it.
 */
static int
mwifiex_pm_ioctl_hs_cfg(struct mwifiex_private *priv,
			struct mwifiex_wait_queue *wait,
			u16 action, struct mwifiex_ds_hs_cfg *hs_cfg)
{
	struct mwifiex_adapter *adapter = priv->adapter;
	int status = 0;
	u32 prev_cond = 0;

	switch (action) {
	case HostCmd_ACT_GEN_SET:
		if (adapter->pps_uapsd_mode) {
			dev_dbg(adapter->dev, "info: Host Sleep IOCTL"
				" is blocked in UAPSD/PPS mode\n");
			status = -1;
			break;
		}
		if (hs_cfg->is_invoke_hostcmd) {
			if (hs_cfg->conditions == HOST_SLEEP_CFG_CANCEL) {
				if (!adapter->is_hs_configured)
					/* Already cancelled */
					break;
				/* Save previous condition */
				prev_cond = le32_to_cpu(adapter->hs_cfg
							.conditions);
				adapter->hs_cfg.conditions =
						cpu_to_le32(hs_cfg->conditions);
			} else if (hs_cfg->conditions) {
				adapter->hs_cfg.conditions =
						cpu_to_le32(hs_cfg->conditions);
				adapter->hs_cfg.gpio = (u8)hs_cfg->gpio;
				if (hs_cfg->gap)
					adapter->hs_cfg.gap = (u8)hs_cfg->gap;
			} else if (adapter->hs_cfg.conditions ==
						cpu_to_le32(
						HOST_SLEEP_CFG_CANCEL)) {
				/* Return failure if no parameters for HS
				   enable */
				status = -1;
				break;
			}
			status = mwifiex_prepare_cmd(priv,
					HostCmd_CMD_802_11_HS_CFG_ENH,
					HostCmd_ACT_GEN_SET,
					0, wait, &adapter->hs_cfg);
			if (!status)
				status = -EINPROGRESS;
			if (hs_cfg->conditions == HOST_SLEEP_CFG_CANCEL)
				/* Restore previous condition */
				adapter->hs_cfg.conditions =
						cpu_to_le32(prev_cond);
		} else {
			adapter->hs_cfg.conditions =
				cpu_to_le32(hs_cfg->conditions);
			adapter->hs_cfg.gpio = (u8)hs_cfg->gpio;
			adapter->hs_cfg.gap = (u8)hs_cfg->gap;
		}
		break;
	case HostCmd_ACT_GEN_GET:
		hs_cfg->conditions = le32_to_cpu(adapter->hs_cfg.conditions);
		hs_cfg->gpio = adapter->hs_cfg.gpio;
		hs_cfg->gap = adapter->hs_cfg.gap;
		break;
	default:
		status = -1;
		break;
	}

	return status;
}

/*
 * Sends IOCTL request to set Host Sleep parameters.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
int mwifiex_set_hs_params(struct mwifiex_private *priv, u16 action,
			      u8 wait_option,
			      struct mwifiex_ds_hs_cfg *hscfg)
{
	int ret = 0;
	struct mwifiex_wait_queue *wait = NULL;

	if (!hscfg)
		return -ENOMEM;

	/* Allocate wait buffer */
	wait = mwifiex_alloc_fill_wait_queue(priv, wait_option);
	if (!wait)
		return -ENOMEM;

	ret = mwifiex_pm_ioctl_hs_cfg(priv, wait, action, hscfg);

	ret = mwifiex_request_ioctl(priv, wait, ret, wait_option);

	if (wait && (ret != -EINPROGRESS))
		kfree(wait);
	return ret;
}

/*
 * Sends IOCTL request to cancel the existing Host Sleep configuration.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
int mwifiex_cancel_hs(struct mwifiex_private *priv, u8 wait_option)
{
	int ret = 0;
	struct mwifiex_ds_hs_cfg hscfg;

	/* Cancel Host Sleep */
	hscfg.conditions = HOST_SLEEP_CFG_CANCEL;
	hscfg.is_invoke_hostcmd = true;
	ret = mwifiex_set_hs_params(priv, HostCmd_ACT_GEN_SET,
					wait_option, &hscfg);

	return ret;
}
EXPORT_SYMBOL_GPL(mwifiex_cancel_hs);

/*
 * Sends IOCTL request to cancel the existing Host Sleep configuration.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
int mwifiex_enable_hs(struct mwifiex_adapter *adapter)
{
	struct mwifiex_ds_hs_cfg hscfg;

	if (adapter->hs_activated) {
		dev_dbg(adapter->dev, "cmd: HS Already actived\n");
		return true;
	}

	/* Enable Host Sleep */
	adapter->hs_activate_wait_q_woken = false;

	memset(&hscfg, 0, sizeof(struct mwifiex_hs_config_param));
	hscfg.is_invoke_hostcmd = true;

	if (mwifiex_set_hs_params(mwifiex_get_priv(adapter,
						       MWIFIEX_BSS_ROLE_STA),
				      HostCmd_ACT_GEN_SET,
				      MWIFIEX_IOCTL_WAIT, &hscfg)) {
		dev_err(adapter->dev, "IOCTL request HS enable failed\n");
		return false;
	}

	wait_event_interruptible(adapter->hs_activate_wait_q,
			adapter->hs_activate_wait_q_woken);

	return true;
}
EXPORT_SYMBOL_GPL(mwifiex_enable_hs);

/*
 * IOCTL request handler to get signal information.
 *
 * This function prepares the correct firmware command and
 * issues it to get the signal (RSSI) information.
 *
 * This only works in the connected mode.
 */
static int mwifiex_get_info_signal(struct mwifiex_private *priv,
				   struct mwifiex_wait_queue *wait,
				   struct mwifiex_ds_get_signal *signal)
{
	int ret = 0;

	if (!wait) {
		dev_err(priv->adapter->dev, "WAIT information is not present\n");
		return -1;
	}

	/* Signal info can be obtained only if connected */
	if (!priv->media_connected) {
		dev_dbg(priv->adapter->dev,
			"info: Can not get signal in disconnected state\n");
		return -1;
	}

	/* Send request to firmware */
	ret = mwifiex_prepare_cmd(priv, HostCmd_CMD_RSSI_INFO,
				  HostCmd_ACT_GEN_GET, 0, wait, signal);

	if (!ret)
		ret = -EINPROGRESS;

	return ret;
}

/*
 * IOCTL request handler to get statistics.
 *
 * This function prepares the correct firmware command and
 * issues it to get the statistics (RSSI) information.
 */
static int mwifiex_get_info_stats(struct mwifiex_private *priv,
			   struct mwifiex_wait_queue *wait,
			   struct mwifiex_ds_get_stats *log)
{
	int ret = 0;

	if (!wait) {
		dev_err(priv->adapter->dev, "MWIFIEX IOCTL information is not present\n");
		return -1;
	}

	/* Send request to firmware */
	ret = mwifiex_prepare_cmd(priv, HostCmd_CMD_802_11_GET_LOG,
				  HostCmd_ACT_GEN_GET, 0, wait, log);

	if (!ret)
		ret = -EINPROGRESS;

	return ret;
}

/*
 * IOCTL request handler to get BSS information.
 *
 * This function collates the information from different driver structures
 * to send to the user.
 */
int mwifiex_get_bss_info(struct mwifiex_private *priv,
			 struct mwifiex_bss_info *info)
{
	struct mwifiex_adapter *adapter = priv->adapter;
	struct mwifiex_bssdescriptor *bss_desc;
	s32 tbl_idx = 0;

	if (!info)
		return -1;

	/* Get current BSS info */
	bss_desc = &priv->curr_bss_params.bss_descriptor;

	/* BSS mode */
	info->bss_mode = priv->bss_mode;

	/* SSID */
	memcpy(&info->ssid, &bss_desc->ssid,
	       sizeof(struct mwifiex_802_11_ssid));

	/* BSSID */
	memcpy(&info->bssid, &bss_desc->mac_address, ETH_ALEN);

	/* Channel */
	info->bss_chan = bss_desc->channel;

	/* Region code */
	info->region_code = adapter->region_code;

	/* Scan table index if connected */
	info->scan_table_idx = 0;
	if (priv->media_connected) {
		tbl_idx =
			mwifiex_find_ssid_in_list(priv, &bss_desc->ssid,
						  bss_desc->mac_address,
						  priv->bss_mode);
		if (tbl_idx >= 0)
			info->scan_table_idx = tbl_idx;
	}

	/* Connection status */
	info->media_connected = priv->media_connected;

	/* Radio status */
	info->radio_on = adapter->radio_on;

	/* Tx power information */
	info->max_power_level = priv->max_tx_power_level;
	info->min_power_level = priv->min_tx_power_level;

	/* AdHoc state */
	info->adhoc_state = priv->adhoc_state;

	/* Last beacon NF */
	info->bcn_nf_last = priv->bcn_nf_last;

	/* wep status */
	if (priv->sec_info.wep_status == MWIFIEX_802_11_WEP_ENABLED)
		info->wep_status = true;
	else
		info->wep_status = false;

	info->is_hs_configured = adapter->is_hs_configured;
	info->is_deep_sleep = adapter->is_deep_sleep;

	return 0;
}

/*
 * IOCTL request handler to get extended version information.
 *
 * This function prepares the correct firmware command and
 * issues it to get the extended version information.
 */
static int mwifiex_get_info_ver_ext(struct mwifiex_private *priv,
				    struct mwifiex_wait_queue *wait,
				    struct mwifiex_ver_ext *ver_ext)
{
	int ret = 0;

	/* Send request to firmware */
	ret = mwifiex_prepare_cmd(priv, HostCmd_CMD_VERSION_EXT,
				  HostCmd_ACT_GEN_GET, 0, wait, ver_ext);
	if (!ret)
		ret = -EINPROGRESS;

	return ret;
}

/*
 * IOCTL request handler to set/get SNMP MIB parameters.
 *
 * This function prepares the correct firmware command and
 * issues it.
 *
 * Currently the following parameters are supported -
 *      Set/get RTS Threshold
 *      Set/get fragmentation threshold
 *      Set/get retry count
 */
int mwifiex_snmp_mib_ioctl(struct mwifiex_private *priv,
			   struct mwifiex_wait_queue *wait,
			   u32 cmd_oid, u16 action, u32 *value)
{
	int ret = 0;

	if (!value)
		return -1;

	/* Send request to firmware */
	ret = mwifiex_prepare_cmd(priv, HostCmd_CMD_802_11_SNMP_MIB,
				  action, cmd_oid, wait, value);

	if (!ret)
		ret = -EINPROGRESS;

	return ret;
}

/*
 * IOCTL request handler to set/get band configurations.
 *
 * For SET operation, it performs extra checks to make sure the Ad-Hoc
 * band and channel are compatible. Otherwise it returns an error.
 *
 * For GET operation, this function retrieves the following information -
 *      - Infra bands
 *      - Ad-hoc band
 *      - Ad-hoc channel
 *      - Secondary channel offset
 */
int mwifiex_radio_ioctl_band_cfg(struct mwifiex_private *priv,
				 u16 action,
				 struct mwifiex_ds_band_cfg *radio_cfg)
{
	struct mwifiex_adapter *adapter = priv->adapter;
	u8 infra_band = 0;
	u8 adhoc_band = 0;
	u32 adhoc_channel = 0;

	if (action == HostCmd_ACT_GEN_GET) {
		/* Infra Bands */
		radio_cfg->config_bands = adapter->config_bands;
		/* Adhoc Band */
		radio_cfg->adhoc_start_band = adapter->adhoc_start_band;
		/* Adhoc channel */
		radio_cfg->adhoc_channel = priv->adhoc_channel;
		/* Secondary channel offset */
		radio_cfg->sec_chan_offset = adapter->chan_offset;
		return 0;
	}

	/* For action = SET */
	infra_band = (u8) radio_cfg->config_bands;
	adhoc_band = (u8) radio_cfg->adhoc_start_band;
	adhoc_channel = radio_cfg->adhoc_channel;

	/* SET Infra band */
	if ((infra_band | adapter->fw_bands) & ~adapter->fw_bands)
		return -1;

	adapter->config_bands = infra_band;

	/* SET Ad-hoc Band */
	if ((adhoc_band | adapter->fw_bands) & ~adapter->fw_bands)
		return -1;

	if (adhoc_band)
		adapter->adhoc_start_band = adhoc_band;
	adapter->chan_offset = (u8) radio_cfg->sec_chan_offset;
	/*
	 * If no adhoc_channel is supplied verify if the existing adhoc
	 * channel compiles with new adhoc_band
	 */
	if (!adhoc_channel) {
		if (!mwifiex_get_cfp_by_band_and_channel_from_cfg80211
		     (priv, adapter->adhoc_start_band,
		     priv->adhoc_channel)) {
			/* Pass back the default channel */
			radio_cfg->adhoc_channel = DEFAULT_AD_HOC_CHANNEL;
			if ((adapter->adhoc_start_band & BAND_A)
			    || (adapter->adhoc_start_band & BAND_AN))
				radio_cfg->adhoc_channel =
					DEFAULT_AD_HOC_CHANNEL_A;
		}
	} else {	/* Retrurn error if adhoc_band and
			   adhoc_channel combination is invalid */
		if (!mwifiex_get_cfp_by_band_and_channel_from_cfg80211
		    (priv, adapter->adhoc_start_band, (u16) adhoc_channel))
			return -1;
		priv->adhoc_channel = (u8) adhoc_channel;
	}
	if ((adhoc_band & BAND_GN) || (adhoc_band & BAND_AN))
		adapter->adhoc_11n_enabled = true;
	else
		adapter->adhoc_11n_enabled = false;

	return 0;
}

/*
 * IOCTL request handler to set/get active channel.
 *
 * This function performs validity checking on channel/frequency
 * compatibility and returns failure if not valid.
 */
int mwifiex_bss_ioctl_channel(struct mwifiex_private *priv, u16 action,
			      struct mwifiex_chan_freq_power *chan)
{
	struct mwifiex_adapter *adapter = priv->adapter;
	struct mwifiex_chan_freq_power *cfp = NULL;

	if (!chan)
		return -1;

	if (action == HostCmd_ACT_GEN_GET) {
		cfp = mwifiex_get_cfp_by_band_and_channel_from_cfg80211(priv,
				priv->curr_bss_params.band,
				(u16) priv->curr_bss_params.bss_descriptor.
					channel);
		chan->channel = cfp->channel;
		chan->freq = cfp->freq;

		return 0;
	}
	if (!chan->channel && !chan->freq)
		return -1;
	if (adapter->adhoc_start_band & BAND_AN)
		adapter->adhoc_start_band = BAND_G | BAND_B | BAND_GN;
	else if (adapter->adhoc_start_band & BAND_A)
		adapter->adhoc_start_band = BAND_G | BAND_B;
	if (chan->channel) {
		if (chan->channel <= MAX_CHANNEL_BAND_BG)
			cfp = mwifiex_get_cfp_by_band_and_channel_from_cfg80211
					(priv, 0, (u16) chan->channel);
		if (!cfp) {
			cfp = mwifiex_get_cfp_by_band_and_channel_from_cfg80211
					(priv, BAND_A, (u16) chan->channel);
			if (cfp) {
				if (adapter->adhoc_11n_enabled)
					adapter->adhoc_start_band = BAND_A
						| BAND_AN;
				else
					adapter->adhoc_start_band = BAND_A;
			}
		}
	} else {
		if (chan->freq <= MAX_FREQUENCY_BAND_BG)
			cfp = mwifiex_get_cfp_by_band_and_freq_from_cfg80211(
							priv, 0, chan->freq);
		if (!cfp) {
			cfp = mwifiex_get_cfp_by_band_and_freq_from_cfg80211
						  (priv, BAND_A, chan->freq);
			if (cfp) {
				if (adapter->adhoc_11n_enabled)
					adapter->adhoc_start_band = BAND_A
						| BAND_AN;
				else
					adapter->adhoc_start_band = BAND_A;
			}
		}
	}
	if (!cfp || !cfp->channel) {
		dev_err(adapter->dev, "invalid channel/freq\n");
		return -1;
	}
	priv->adhoc_channel = (u8) cfp->channel;
	chan->channel = cfp->channel;
	chan->freq = cfp->freq;

	return 0;
}

/*
 * IOCTL request handler to set/get BSS mode.
 *
 * This function prepares the correct firmware command and
 * issues it to set or get the BSS mode.
 *
 * In case the mode is changed, a deauthentication is performed
 * first by the function automatically.
 */
int mwifiex_bss_ioctl_mode(struct mwifiex_private *priv,
			   struct mwifiex_wait_queue *wait,
			   u16 action, int *mode)
{
	int ret = 0;

	if (!mode)
		return -1;

	if (action == HostCmd_ACT_GEN_GET) {
		*mode = priv->bss_mode;
		return 0;
	}

	if ((priv->bss_mode == *mode) || (*mode == MWIFIEX_BSS_MODE_AUTO)) {
		dev_dbg(priv->adapter->dev,
			"info: Already set to required mode! No change!\n");
		priv->bss_mode = *mode;
		return 0;
	}

	ret = mwifiex_deauthenticate(priv, wait, NULL);

	priv->sec_info.authentication_mode = MWIFIEX_AUTH_MODE_OPEN;
	priv->bss_mode = *mode;
	if (priv->bss_mode != MWIFIEX_BSS_MODE_AUTO) {
		ret = mwifiex_prepare_cmd(priv, HostCmd_CMD_SET_BSS_MODE,
					  HostCmd_ACT_GEN_SET, 0, wait, NULL);
		if (!ret)
			ret = -EINPROGRESS;
	}

	return ret;
}

/*
 * IOCTL request handler to set/get Ad-Hoc channel.
 *
 * This function prepares the correct firmware command and
 * issues it to set or get the ad-hoc channel.
 */
static int mwifiex_bss_ioctl_ibss_channel(struct mwifiex_private *priv,
					  struct mwifiex_wait_queue *wait,
					  u16 action, u16 *channel)
{
	int ret = 0;

	if (action == HostCmd_ACT_GEN_GET) {
		if (!priv->media_connected) {
			*channel = priv->adhoc_channel;
			return ret;
		}
	} else {
		priv->adhoc_channel = (u8) *channel;
	}

	/* Send request to firmware */
	ret = mwifiex_prepare_cmd(priv, HostCmd_CMD_802_11_RF_CHANNEL,
				  action, 0, wait, channel);
	if (!ret)
		ret = -EINPROGRESS;

	return ret;
}

/*
 * IOCTL request handler to find a particular BSS.
 *
 * The BSS can be searched with either a BSSID or a SSID. If none of
 * these are provided, just the best BSS (best RSSI) is returned.
 */
int mwifiex_bss_ioctl_find_bss(struct mwifiex_private *priv,
			       struct mwifiex_wait_queue *wait,
			       struct mwifiex_ssid_bssid *ssid_bssid)
{
	struct mwifiex_adapter *adapter = priv->adapter;
	int ret = 0;
	struct mwifiex_bssdescriptor *bss_desc;
	u8 zero_mac[ETH_ALEN] = { 0, 0, 0, 0, 0, 0 };
	u8 mac[ETH_ALEN];
	int i = 0;

	if (memcmp(ssid_bssid->bssid, zero_mac, sizeof(zero_mac))) {
		i = mwifiex_find_bssid_in_list(priv,
					       (u8 *) ssid_bssid->bssid,
					       priv->bss_mode);
		if (i < 0) {
			memcpy(mac, ssid_bssid->bssid, sizeof(mac));
			dev_err(adapter->dev, "cannot find bssid %pM\n", mac);
			return -1;
		}
		bss_desc = &adapter->scan_table[i];
		memcpy(&ssid_bssid->ssid, &bss_desc->ssid,
				sizeof(struct mwifiex_802_11_ssid));
	} else if (ssid_bssid->ssid.ssid_len) {
		i = mwifiex_find_ssid_in_list(priv, &ssid_bssid->ssid, NULL,
					      priv->bss_mode);
		if (i < 0) {
			dev_err(adapter->dev, "cannot find ssid %s\n",
					ssid_bssid->ssid.ssid);
			return -1;
		}
		bss_desc = &adapter->scan_table[i];
		memcpy(ssid_bssid->bssid, bss_desc->mac_address, ETH_ALEN);
	} else {
		ret = mwifiex_find_best_network(priv, ssid_bssid);
	}

	return ret;
}

/*
 * IOCTL request handler to change Ad-Hoc channel.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 *
 * The function follows the following steps to perform the change -
 *      - Get current IBSS information
 *      - Get current channel
 *      - If no change is required, return
 *      - If not connected, change channel and return
 *      - If connected,
 *          - Disconnect
 *          - Change channel
 *          - Perform specific SSID scan with same SSID
 *          - Start/Join the IBSS
 */
int
mwifiex_drv_change_adhoc_chan(struct mwifiex_private *priv, int channel)
{
	int ret = 0;
	int status = 0;
	struct mwifiex_bss_info bss_info;
	struct mwifiex_wait_queue *wait = NULL;
	u8 wait_option = MWIFIEX_IOCTL_WAIT;
	struct mwifiex_ssid_bssid ssid_bssid;
	u16 curr_chan = 0;

	memset(&bss_info, 0, sizeof(bss_info));

	/* Get BSS information */
	if (mwifiex_get_bss_info(priv, &bss_info))
		return -1;

	/* Allocate wait buffer */
	wait = mwifiex_alloc_fill_wait_queue(priv, wait_option);
	if (!wait)
		return -ENOMEM;

	/* Get current channel */
	status = mwifiex_bss_ioctl_ibss_channel(priv, wait, HostCmd_ACT_GEN_GET,
						&curr_chan);

	if (mwifiex_request_ioctl(priv, wait, status, wait_option)) {
		ret = -1;
		goto done;
	}
	if (curr_chan == channel) {
		ret = 0;
		goto done;
	}
	dev_dbg(priv->adapter->dev, "cmd: updating channel from %d to %d\n",
			curr_chan, channel);

	if (!bss_info.media_connected) {
		ret = 0;
		goto done;
	}

	/* Do disonnect */
	memset(&ssid_bssid, 0, ETH_ALEN);
	status = mwifiex_bss_ioctl_stop(priv, wait, ssid_bssid.bssid);

	if (mwifiex_request_ioctl(priv, wait, status, wait_option)) {
		ret = -1;
		goto done;
	}

	status = mwifiex_bss_ioctl_ibss_channel(priv, wait, HostCmd_ACT_GEN_SET,
						(u16 *) &channel);

	if (mwifiex_request_ioctl(priv, wait, status, wait_option)) {
		ret = -1;
		goto done;
	}

	/* Do specific SSID scanning */
	if (mwifiex_request_scan(priv, wait_option, &bss_info.ssid)) {
		ret = -1;
		goto done;
	}
	/* Start/Join Adhoc network */
	memset(&ssid_bssid, 0, sizeof(struct mwifiex_ssid_bssid));
	memcpy(&ssid_bssid.ssid, &bss_info.ssid,
	       sizeof(struct mwifiex_802_11_ssid));

	status = mwifiex_bss_ioctl_start(priv, wait, &ssid_bssid);

	if (mwifiex_request_ioctl(priv, wait, status, wait_option))
		ret = -1;

done:
	kfree(wait);
	return ret;
}

/*
 * IOCTL request handler to get current driver mode.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
int
mwifiex_drv_get_mode(struct mwifiex_private *priv, u8 wait_option)
{
	struct mwifiex_wait_queue *wait = NULL;
	int status = 0;
	int mode = -1;

	/* Allocate wait buffer */
	wait = mwifiex_alloc_fill_wait_queue(priv, wait_option);
	if (!wait)
		return -1;

	status = mwifiex_bss_ioctl_mode(priv, wait, HostCmd_ACT_GEN_GET, &mode);

	status = mwifiex_request_ioctl(priv, wait, status, wait_option);

	if (wait && (status != -EINPROGRESS))
		kfree(wait);
	return mode;
}

/*
 * IOCTL request handler to get rate.
 *
 * This function prepares the correct firmware command and
 * issues it to get the current rate if it is connected,
 * otherwise, the function returns the lowest supported rate
 * for the band.
 */
static int mwifiex_rate_ioctl_get_rate_value(struct mwifiex_private *priv,
					     struct mwifiex_wait_queue *wait,
					     struct mwifiex_rate_cfg *rate_cfg)
{
	struct mwifiex_adapter *adapter = priv->adapter;
	int ret = 0;

	rate_cfg->is_rate_auto = priv->is_data_rate_auto;
	if (!priv->media_connected) {
		switch (adapter->config_bands) {
		case BAND_B:
			/* Return the lowest supported rate for B band */
			rate_cfg->rate = supported_rates_b[0] & 0x7f;
			break;
		case BAND_G:
		case BAND_G | BAND_GN:
			/* Return the lowest supported rate for G band */
			rate_cfg->rate = supported_rates_g[0] & 0x7f;
			break;
		case BAND_B | BAND_G:
		case BAND_A | BAND_B | BAND_G:
		case BAND_A | BAND_B:
		case BAND_A | BAND_B | BAND_G | BAND_AN | BAND_GN:
		case BAND_B | BAND_G | BAND_GN:
			/* Return the lowest supported rate for BG band */
			rate_cfg->rate = supported_rates_bg[0] & 0x7f;
			break;
		case BAND_A:
		case BAND_A | BAND_G:
		case BAND_A | BAND_G | BAND_AN | BAND_GN:
		case BAND_A | BAND_AN:
			/* Return the lowest supported rate for A band */
			rate_cfg->rate = supported_rates_a[0] & 0x7f;
			break;
		case BAND_GN:
			/* Return the lowest supported rate for N band */
			rate_cfg->rate = supported_rates_n[0] & 0x7f;
			break;
		default:
			dev_warn(adapter->dev, "invalid band %#x\n",
			       adapter->config_bands);
			break;
		}
	} else {
		/* Send request to firmware */
		ret = mwifiex_prepare_cmd(priv,
					  HostCmd_CMD_802_11_TX_RATE_QUERY,
					  HostCmd_ACT_GEN_GET, 0, wait, NULL);
		if (!ret)
			ret = -EINPROGRESS;
	}

	return ret;
}

/*
 * IOCTL request handler to set rate.
 *
 * This function prepares the correct firmware command and
 * issues it to set the current rate.
 *
 * The function also performs validation checking on the supplied value.
 */
static int mwifiex_rate_ioctl_set_rate_value(struct mwifiex_private *priv,
					     struct mwifiex_wait_queue *wait,
					     struct mwifiex_rate_cfg *rate_cfg)
{
	u8 rates[MWIFIEX_SUPPORTED_RATES];
	u8 *rate = NULL;
	int rate_index = 0;
	u16 bitmap_rates[MAX_BITMAP_RATES_SIZE];
	u32 i = 0;
	int ret = 0;
	struct mwifiex_adapter *adapter = priv->adapter;

	if (rate_cfg->is_rate_auto) {
		memset(bitmap_rates, 0, sizeof(bitmap_rates));
		/* Support all HR/DSSS rates */
		bitmap_rates[0] = 0x000F;
		/* Support all OFDM rates */
		bitmap_rates[1] = 0x00FF;
		/* Support all HT-MCSs rate */
		for (i = 0; i < ARRAY_SIZE(priv->bitmap_rates) - 3; i++)
			bitmap_rates[i + 2] = 0xFFFF;
		bitmap_rates[9] = 0x3FFF;
	} else {
		memset(rates, 0, sizeof(rates));
		mwifiex_get_active_data_rates(priv, rates);
		rate = rates;
		for (i = 0; (rate[i] && i < MWIFIEX_SUPPORTED_RATES); i++) {
			dev_dbg(adapter->dev, "info: rate=%#x wanted=%#x\n",
				rate[i], rate_cfg->rate);
			if ((rate[i] & 0x7f) == (rate_cfg->rate & 0x7f))
				break;
		}
		if (!rate[i] || (i == MWIFIEX_SUPPORTED_RATES)) {
			dev_err(adapter->dev, "fixed data rate %#x is out "
			       "of range\n", rate_cfg->rate);
			return -1;
		}
		memset(bitmap_rates, 0, sizeof(bitmap_rates));

		rate_index =
			mwifiex_data_rate_to_index(adapter, rate_cfg->rate);

		/* Only allow b/g rates to be set */
		if (rate_index >= MWIFIEX_RATE_INDEX_HRDSSS0 &&
		    rate_index <= MWIFIEX_RATE_INDEX_HRDSSS3) {
			bitmap_rates[0] = 1 << rate_index;
		} else {
			rate_index -= 1; /* There is a 0x00 in the table */
			if (rate_index >= MWIFIEX_RATE_INDEX_OFDM0 &&
			    rate_index <= MWIFIEX_RATE_INDEX_OFDM7)
				bitmap_rates[1] = 1 << (rate_index -
						   MWIFIEX_RATE_INDEX_OFDM0);
		}
	}

	/* Send request to firmware */
	ret = mwifiex_prepare_cmd(priv, HostCmd_CMD_TX_RATE_CFG,
				  HostCmd_ACT_GEN_SET, 0, wait, bitmap_rates);
	if (!ret)
		ret = -EINPROGRESS;

	return ret;
}

/*
 * IOCTL request handler to set/get rate.
 *
 * This function can be used to set/get either the rate value or the
 * rate index.
 */
static int mwifiex_rate_ioctl_cfg(struct mwifiex_private *priv,
				  struct mwifiex_wait_queue *wait,
				  struct mwifiex_rate_cfg *rate_cfg)
{
	int status = 0;

	if (!rate_cfg)
		return -1;

	if (rate_cfg->action == HostCmd_ACT_GEN_GET)
		status = mwifiex_rate_ioctl_get_rate_value(
				priv, wait, rate_cfg);
	else
		status = mwifiex_rate_ioctl_set_rate_value(
				priv, wait, rate_cfg);

	return status;
}

/*
 * Sends IOCTL request to get the data rate.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
int mwifiex_drv_get_data_rate(struct mwifiex_private *priv,
			      struct mwifiex_rate_cfg *rate)
{
	int ret = 0;
	struct mwifiex_wait_queue *wait = NULL;
	u8 wait_option = MWIFIEX_IOCTL_WAIT;

	/* Allocate wait buffer */
	wait = mwifiex_alloc_fill_wait_queue(priv, wait_option);
	if (!wait)
		return -ENOMEM;

	memset(rate, 0, sizeof(struct mwifiex_rate_cfg));
	rate->action = HostCmd_ACT_GEN_GET;
	ret = mwifiex_rate_ioctl_cfg(priv, wait, rate);

	ret = mwifiex_request_ioctl(priv, wait, ret, wait_option);
	if (!ret) {
		if (rate && rate->is_rate_auto)
			rate->rate = mwifiex_index_to_data_rate(priv->adapter,
					priv->tx_rate, priv->tx_htinfo);
		else if (rate)
			rate->rate = priv->data_rate;
	} else {
		ret = -1;
	}

	kfree(wait);
	return ret;
}

/*
 * IOCTL request handler to set tx power configuration.
 *
 * This function prepares the correct firmware command and
 * issues it.
 *
 * For non-auto power mode, all the following power groups are set -
 *      - Modulation class HR/DSSS
 *      - Modulation class OFDM
 *      - Modulation class HTBW20
 *      - Modulation class HTBW40
 */
static int mwifiex_power_ioctl_set_power(struct mwifiex_private *priv,
					 struct mwifiex_wait_queue *wait,
					 struct mwifiex_power_cfg *power_cfg)
{
	int ret = 0;
	struct host_cmd_ds_txpwr_cfg *txp_cfg = NULL;
	struct mwifiex_types_power_group *pg_tlv = NULL;
	struct mwifiex_power_group *pg = NULL;
	u8 *buf = NULL;
	u16 dbm = 0;

	if (!power_cfg->is_power_auto) {
		dbm = (u16) power_cfg->power_level;
		if ((dbm < priv->min_tx_power_level) ||
		    (dbm > priv->max_tx_power_level)) {
			dev_err(priv->adapter->dev, "txpower value %d dBm"
					" is out of range (%d dBm-%d dBm)\n",
					dbm, priv->min_tx_power_level,
					priv->max_tx_power_level);
			return -1;
		}
	}
	buf = kzalloc(MWIFIEX_SIZE_OF_CMD_BUFFER, GFP_KERNEL);
	if (!buf) {
		dev_err(priv->adapter->dev, "%s: failed to alloc cmd buffer\n",
				__func__);
		return -1;
	}

	txp_cfg = (struct host_cmd_ds_txpwr_cfg *) buf;
	txp_cfg->action = cpu_to_le16(HostCmd_ACT_GEN_SET);
	if (!power_cfg->is_power_auto) {
		txp_cfg->mode = cpu_to_le32(1);
		pg_tlv = (struct mwifiex_types_power_group *) (buf +
				sizeof(struct host_cmd_ds_txpwr_cfg));
		pg_tlv->type = TLV_TYPE_POWER_GROUP;
		pg_tlv->length = 4 * sizeof(struct mwifiex_power_group);
		pg = (struct mwifiex_power_group *) (buf +
				sizeof(struct host_cmd_ds_txpwr_cfg) +
				sizeof(struct mwifiex_types_power_group));
		/* Power group for modulation class HR/DSSS */
		pg->first_rate_code = 0x00;
		pg->last_rate_code = 0x03;
		pg->modulation_class = MOD_CLASS_HR_DSSS;
		pg->power_step = 0;
		pg->power_min = (s8) dbm;
		pg->power_max = (s8) dbm;
		pg++;
		/* Power group for modulation class OFDM */
		pg->first_rate_code = 0x00;
		pg->last_rate_code = 0x07;
		pg->modulation_class = MOD_CLASS_OFDM;
		pg->power_step = 0;
		pg->power_min = (s8) dbm;
		pg->power_max = (s8) dbm;
		pg++;
		/* Power group for modulation class HTBW20 */
		pg->first_rate_code = 0x00;
		pg->last_rate_code = 0x20;
		pg->modulation_class = MOD_CLASS_HT;
		pg->power_step = 0;
		pg->power_min = (s8) dbm;
		pg->power_max = (s8) dbm;
		pg->ht_bandwidth = HT_BW_20;
		pg++;
		/* Power group for modulation class HTBW40 */
		pg->first_rate_code = 0x00;
		pg->last_rate_code = 0x20;
		pg->modulation_class = MOD_CLASS_HT;
		pg->power_step = 0;
		pg->power_min = (s8) dbm;
		pg->power_max = (s8) dbm;
		pg->ht_bandwidth = HT_BW_40;
	}
	/* Send request to firmware */
	ret = mwifiex_prepare_cmd(priv, HostCmd_CMD_TXPWR_CFG,
				  HostCmd_ACT_GEN_SET, 0, wait, buf);
	if (!ret)
		ret = -EINPROGRESS;
	kfree(buf);

	return ret;
}

/*
 * IOCTL request handler to get power save mode.
 *
 * This function prepares the correct firmware command and
 * issues it.
 */
static int mwifiex_pm_ioctl_ps_mode(struct mwifiex_private *priv,
				    struct mwifiex_wait_queue *wait,
				    u32 *ps_mode, u16 action)
{
	int ret = 0;
	struct mwifiex_adapter *adapter = priv->adapter;
	u16 sub_cmd;

	if (action == HostCmd_ACT_GEN_SET) {
		if (*ps_mode)
			adapter->ps_mode = MWIFIEX_802_11_POWER_MODE_PSP;
		else
			adapter->ps_mode = MWIFIEX_802_11_POWER_MODE_CAM;
		sub_cmd = (*ps_mode) ? EN_AUTO_PS : DIS_AUTO_PS;
		ret = mwifiex_prepare_cmd(priv, HostCmd_CMD_802_11_PS_MODE_ENH,
					  sub_cmd, BITMAP_STA_PS, wait, NULL);
		if ((!ret) && (sub_cmd == DIS_AUTO_PS))
			ret = mwifiex_prepare_cmd(priv,
					HostCmd_CMD_802_11_PS_MODE_ENH, GET_PS,
					0, NULL, NULL);
	} else {
		ret = mwifiex_prepare_cmd(priv, HostCmd_CMD_802_11_PS_MODE_ENH,
					  GET_PS, 0, wait, NULL);
	}

	if (!ret)
		ret = -EINPROGRESS;

	return ret;
}

/*
 * IOCTL request handler to set/reset WPA IE.
 *
 * The supplied WPA IE is treated as a opaque buffer. Only the first field
 * is checked to determine WPA version. If buffer length is zero, the existing
 * WPA IE is reset.
 */
static int mwifiex_set_wpa_ie_helper(struct mwifiex_private *priv,
				     u8 *ie_data_ptr, u16 ie_len)
{
	if (ie_len) {
		if (ie_len > sizeof(priv->wpa_ie)) {
			dev_err(priv->adapter->dev,
				"failed to copy WPA IE, too big\n");
			return -1;
		}
		memcpy(priv->wpa_ie, ie_data_ptr, ie_len);
		priv->wpa_ie_len = (u8) ie_len;
		dev_dbg(priv->adapter->dev, "cmd: Set Wpa_ie_len=%d IE=%#x\n",
				priv->wpa_ie_len, priv->wpa_ie[0]);

		if (priv->wpa_ie[0] == WLAN_EID_WPA) {
			priv->sec_info.wpa_enabled = true;
		} else if (priv->wpa_ie[0] == WLAN_EID_RSN) {
			priv->sec_info.wpa2_enabled = true;
		} else {
			priv->sec_info.wpa_enabled = false;
			priv->sec_info.wpa2_enabled = false;
		}
	} else {
		memset(priv->wpa_ie, 0, sizeof(priv->wpa_ie));
		priv->wpa_ie_len = 0;
		dev_dbg(priv->adapter->dev, "info: reset wpa_ie_len=%d IE=%#x\n",
			priv->wpa_ie_len, priv->wpa_ie[0]);
		priv->sec_info.wpa_enabled = false;
		priv->sec_info.wpa2_enabled = false;
	}

	return 0;
}

/*
 * IOCTL request handler to set/reset WAPI IE.
 *
 * The supplied WAPI IE is treated as a opaque buffer. Only the first field
 * is checked to internally enable WAPI. If buffer length is zero, the existing
 * WAPI IE is reset.
 */
static int mwifiex_set_wapi_ie(struct mwifiex_private *priv,
			       u8 *ie_data_ptr, u16 ie_len)
{
	if (ie_len) {
		if (ie_len > sizeof(priv->wapi_ie)) {
			dev_dbg(priv->adapter->dev,
				"info: failed to copy WAPI IE, too big\n");
			return -1;
		}
		memcpy(priv->wapi_ie, ie_data_ptr, ie_len);
		priv->wapi_ie_len = ie_len;
		dev_dbg(priv->adapter->dev, "cmd: Set wapi_ie_len=%d IE=%#x\n",
				priv->wapi_ie_len, priv->wapi_ie[0]);

		if (priv->wapi_ie[0] == WLAN_EID_BSS_AC_ACCESS_DELAY)
			priv->sec_info.wapi_enabled = true;
	} else {
		memset(priv->wapi_ie, 0, sizeof(priv->wapi_ie));
		priv->wapi_ie_len = ie_len;
		dev_dbg(priv->adapter->dev,
			"info: Reset wapi_ie_len=%d IE=%#x\n",
		       priv->wapi_ie_len, priv->wapi_ie[0]);
		priv->sec_info.wapi_enabled = false;
	}
	return 0;
}

/*
 * IOCTL request handler to set WAPI key.
 *
 * This function prepares the correct firmware command and
 * issues it.
 */
static int mwifiex_sec_ioctl_set_wapi_key(struct mwifiex_adapter *adapter,
			       struct mwifiex_wait_queue *wait,
			       struct mwifiex_ds_encrypt_key *encrypt_key)
{
	int ret = 0;
	struct mwifiex_private *priv = adapter->priv[wait->bss_index];

	ret = mwifiex_prepare_cmd(priv, HostCmd_CMD_802_11_KEY_MATERIAL,
				  HostCmd_ACT_GEN_SET, KEY_INFO_ENABLED,
				  wait, encrypt_key);
	if (!ret)
		ret = -EINPROGRESS;

	return ret;
}

/*
 * IOCTL request handler to set WEP network key.
 *
 * This function prepares the correct firmware command and
 * issues it, after validation checks.
 */
static int mwifiex_sec_ioctl_set_wep_key(struct mwifiex_adapter *adapter,
			      struct mwifiex_wait_queue *wait,
			      struct mwifiex_ds_encrypt_key *encrypt_key)
{
	int ret = 0;
	struct mwifiex_private *priv = adapter->priv[wait->bss_index];
	struct mwifiex_wep_key *wep_key = NULL;
	int index;

	if (priv->wep_key_curr_index >= NUM_WEP_KEYS)
		priv->wep_key_curr_index = 0;
	wep_key = &priv->wep_key[priv->wep_key_curr_index];
	index = encrypt_key->key_index;
	if (encrypt_key->key_disable) {
		priv->sec_info.wep_status = MWIFIEX_802_11_WEP_DISABLED;
	} else if (!encrypt_key->key_len) {
		/* Copy the required key as the current key */
		wep_key = &priv->wep_key[index];
		if (!wep_key->key_length) {
			dev_err(adapter->dev,
				"key not set, so cannot enable it\n");
			return -1;
		}
		priv->wep_key_curr_index = (u16) index;
		priv->sec_info.wep_status = MWIFIEX_802_11_WEP_ENABLED;
	} else {
		wep_key = &priv->wep_key[index];
		/* Cleanup */
		memset(wep_key, 0, sizeof(struct mwifiex_wep_key));
		/* Copy the key in the driver */
		memcpy(wep_key->key_material,
		       encrypt_key->key_material,
		       encrypt_key->key_len);
		wep_key->key_index = index;
		wep_key->key_length = encrypt_key->key_len;
		priv->sec_info.wep_status = MWIFIEX_802_11_WEP_ENABLED;
	}
	if (wep_key->key_length) {
		/* Send request to firmware */
		ret = mwifiex_prepare_cmd(priv, HostCmd_CMD_802_11_KEY_MATERIAL,
					  HostCmd_ACT_GEN_SET, 0, NULL, NULL);
		if (ret)
			return ret;
	}
	if (priv->sec_info.wep_status == MWIFIEX_802_11_WEP_ENABLED)
		priv->curr_pkt_filter |= HostCmd_ACT_MAC_WEP_ENABLE;
	else
		priv->curr_pkt_filter &= ~HostCmd_ACT_MAC_WEP_ENABLE;

	/* Send request to firmware */
	ret = mwifiex_prepare_cmd(priv, HostCmd_CMD_MAC_CONTROL,
				  HostCmd_ACT_GEN_SET, 0, wait,
				  &priv->curr_pkt_filter);
	if (!ret)
		ret = -EINPROGRESS;

	return ret;
}

/*
 * IOCTL request handler to set WPA key.
 *
 * This function prepares the correct firmware command and
 * issues it, after validation checks.
 *
 * Current driver only supports key length of up to 32 bytes.
 *
 * This function can also be used to disable a currently set key.
 */
static int mwifiex_sec_ioctl_set_wpa_key(struct mwifiex_adapter *adapter,
			      struct mwifiex_wait_queue *wait,
			      struct mwifiex_ds_encrypt_key *encrypt_key)
{
	int ret = 0;
	struct mwifiex_private *priv = adapter->priv[wait->bss_index];
	u8 remove_key = false;
	struct host_cmd_ds_802_11_key_material *ibss_key;

	/* Current driver only supports key length of up to 32 bytes */
	if (encrypt_key->key_len > MWIFIEX_MAX_KEY_LENGTH) {
		dev_err(adapter->dev, "key length too long\n");
		return -1;
	}

	if (priv->bss_mode == MWIFIEX_BSS_MODE_IBSS) {
		/*
		 * IBSS/WPA-None uses only one key (Group) for both receiving
		 * and sending unicast and multicast packets.
		 */
		/* Send the key as PTK to firmware */
		encrypt_key->key_index = MWIFIEX_KEY_INDEX_UNICAST;
		ret = mwifiex_prepare_cmd(priv, HostCmd_CMD_802_11_KEY_MATERIAL,
					  HostCmd_ACT_GEN_SET, KEY_INFO_ENABLED,
					  NULL, encrypt_key);
		if (ret)
			return ret;

		ibss_key = &priv->aes_key;
		memset(ibss_key, 0,
		       sizeof(struct host_cmd_ds_802_11_key_material));
		/* Copy the key in the driver */
		memcpy(ibss_key->key_param_set.key, encrypt_key->key_material,
		       encrypt_key->key_len);
		memcpy(&ibss_key->key_param_set.key_len, &encrypt_key->key_len,
		       sizeof(ibss_key->key_param_set.key_len));
		ibss_key->key_param_set.key_type_id
			= cpu_to_le16(KEY_TYPE_ID_TKIP);
		ibss_key->key_param_set.key_info
			= cpu_to_le16(KEY_INFO_TKIP_ENABLED);

		/* Send the key as GTK to firmware */
		encrypt_key->key_index = ~MWIFIEX_KEY_INDEX_UNICAST;
	}

	if (!encrypt_key->key_index)
		encrypt_key->key_index = MWIFIEX_KEY_INDEX_UNICAST;

	if (remove_key)
		/* Send request to firmware */
		ret = mwifiex_prepare_cmd(priv, HostCmd_CMD_802_11_KEY_MATERIAL,
					  HostCmd_ACT_GEN_SET,
					  !(KEY_INFO_ENABLED),
					  wait, encrypt_key);
	else
		/* Send request to firmware */
		ret = mwifiex_prepare_cmd(priv, HostCmd_CMD_802_11_KEY_MATERIAL,
					  HostCmd_ACT_GEN_SET, KEY_INFO_ENABLED,
					  wait, encrypt_key);

	if (!ret)
		ret = -EINPROGRESS;

	return ret;
}

/*
 * IOCTL request handler to set/get network keys.
 *
 * This is a generic key handling function which supports WEP, WPA
 * and WAPI.
 */
static int
mwifiex_sec_ioctl_encrypt_key(struct mwifiex_private *priv,
			      struct mwifiex_wait_queue *wait,
			      struct mwifiex_ds_encrypt_key *encrypt_key)
{
	int status = 0;
	struct mwifiex_adapter *adapter = priv->adapter;

	if (encrypt_key->is_wapi_key)
		status = mwifiex_sec_ioctl_set_wapi_key(adapter, wait,
							encrypt_key);
	else if (encrypt_key->key_len > WLAN_KEY_LEN_WEP104)
		status = mwifiex_sec_ioctl_set_wpa_key(adapter, wait,
						       encrypt_key);
	else
		status = mwifiex_sec_ioctl_set_wep_key(adapter, wait,
						       encrypt_key);
	return status;
}

/*
 * This function returns the driver version.
 */
int
mwifiex_drv_get_driver_version(struct mwifiex_adapter *adapter, char *version,
			       int max_len)
{
	union {
		u32 l;
		u8 c[4];
	} ver;
	char fw_ver[32];

	ver.l = adapter->fw_release_number;
	sprintf(fw_ver, "%u.%u.%u.p%u", ver.c[2], ver.c[1], ver.c[0], ver.c[3]);

	snprintf(version, max_len, driver_version, fw_ver);

	dev_dbg(adapter->dev, "info: MWIFIEX VERSION: %s\n", version);

	return 0;
}

/*
 * Sends IOCTL request to set Tx power. It can be set to either auto
 * or a fixed value.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
int
mwifiex_set_tx_power(struct mwifiex_private *priv, int type, int dbm)
{
	struct mwifiex_power_cfg power_cfg;
	struct mwifiex_wait_queue *wait = NULL;
	int status = 0;
	int ret = 0;

	wait = mwifiex_alloc_fill_wait_queue(priv, MWIFIEX_IOCTL_WAIT);
	if (!wait)
		return -ENOMEM;

	if (type == NL80211_TX_POWER_FIXED) {
		power_cfg.is_power_auto = 0;
		power_cfg.power_level = dbm;
	} else {
		power_cfg.is_power_auto = 1;
	}
	status = mwifiex_power_ioctl_set_power(priv, wait, &power_cfg);

	ret = mwifiex_request_ioctl(priv, wait, status, MWIFIEX_IOCTL_WAIT);

	kfree(wait);
	return ret;
}

/*
 * Sends IOCTL request to get scan table.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
int mwifiex_get_scan_table(struct mwifiex_private *priv, u8 wait_option,
			   struct mwifiex_scan_resp *scan_resp)
{
	struct mwifiex_wait_queue *wait = NULL;
	struct mwifiex_scan_resp scan;
	int status = 0;

	/* Allocate wait buffer */
	wait = mwifiex_alloc_fill_wait_queue(priv, wait_option);
	if (!wait)
		return -ENOMEM;

	status = mwifiex_scan_networks(priv, wait, HostCmd_ACT_GEN_GET,
				       NULL, &scan);

	status = mwifiex_request_ioctl(priv, wait, status, wait_option);
	if (!status) {
		if (scan_resp)
			memcpy(scan_resp, &scan,
			       sizeof(struct mwifiex_scan_resp));
	}

	if (wait && (status != -EINPROGRESS))
		kfree(wait);
	return status;
}

/*
 * Sends IOCTL request to get signal information.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
int mwifiex_get_signal_info(struct mwifiex_private *priv, u8 wait_option,
			    struct mwifiex_ds_get_signal *signal)
{
	struct mwifiex_ds_get_signal info;
	struct mwifiex_wait_queue *wait = NULL;
	int status = 0;

	/* Allocate wait buffer */
	wait = mwifiex_alloc_fill_wait_queue(priv, wait_option);
	if (!wait)
		return -ENOMEM;

	info.selector = ALL_RSSI_INFO_MASK;

	status = mwifiex_get_info_signal(priv, wait, &info);

	status = mwifiex_request_ioctl(priv, wait, status, wait_option);
	if (!status) {
		if (signal)
			memcpy(signal, &info,
			       sizeof(struct mwifiex_ds_get_signal));
		if (info.selector & BCN_RSSI_AVG_MASK)
			priv->w_stats.qual.level = info.bcn_rssi_avg;
		if (info.selector & BCN_NF_AVG_MASK)
			priv->w_stats.qual.noise = info.bcn_nf_avg;
	}

	if (wait && (status != -EINPROGRESS))
		kfree(wait);
	return status;
}

/*
 * Sends IOCTL request to set encoding parameters.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
int mwifiex_set_encode(struct mwifiex_private *priv, const u8 *key,
			int key_len, u8 key_index, int disable)
{
	struct mwifiex_wait_queue *wait = NULL;
	struct mwifiex_ds_encrypt_key encrypt_key;
	int status = 0;
	int ret = 0;

	wait = mwifiex_alloc_fill_wait_queue(priv, MWIFIEX_IOCTL_WAIT);
	if (!wait)
		return -ENOMEM;

	memset(&encrypt_key, 0, sizeof(struct mwifiex_ds_encrypt_key));
	encrypt_key.key_len = key_len;
	if (!disable) {
		encrypt_key.key_index = key_index;
		if (key_len)
			memcpy(encrypt_key.key_material, key, key_len);
	} else {
		encrypt_key.key_disable = true;
	}

	status = mwifiex_sec_ioctl_encrypt_key(priv, wait, &encrypt_key);

	if (mwifiex_request_ioctl(priv, wait, status, MWIFIEX_IOCTL_WAIT))
		ret = -EFAULT;

	kfree(wait);
	return ret;
}

/*
 * Sends IOCTL request to set power management parameters.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
int
mwifiex_drv_set_power(struct mwifiex_private *priv, bool power_on)
{
	int ret = 0;
	int status = 0;
	struct mwifiex_wait_queue *wait = NULL;
	u32 ps_mode;

	wait = mwifiex_alloc_fill_wait_queue(priv, MWIFIEX_IOCTL_WAIT);
	if (!wait)
		return -ENOMEM;

	ps_mode = power_on;
	status = mwifiex_pm_ioctl_ps_mode(priv, wait, &ps_mode,
					  HostCmd_ACT_GEN_SET);

	ret = mwifiex_request_ioctl(priv, wait, status, MWIFIEX_IOCTL_WAIT);

	kfree(wait);
	return ret;
}

/*
 * Sends IOCTL request to get extended version.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
int
mwifiex_get_ver_ext(struct mwifiex_private *priv)
{
	struct mwifiex_ver_ext ver_ext;
	struct mwifiex_wait_queue *wait = NULL;
	int status = 0;
	int ret = 0;
	u8 wait_option = MWIFIEX_IOCTL_WAIT;

	/* Allocate wait buffer */
	wait = mwifiex_alloc_fill_wait_queue(priv, wait_option);
	if (!wait)
		return -ENOMEM;

	/* get fw version */
	memset(&ver_ext, 0, sizeof(struct host_cmd_ds_version_ext));
	status = mwifiex_get_info_ver_ext(priv, wait, &ver_ext);

	ret = mwifiex_request_ioctl(priv, wait, status, wait_option);

	if (ret)
		ret = -1;

	kfree(wait);
	return ret;
}

/*
 * Sends IOCTL request to get statistics information.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
int
mwifiex_get_stats_info(struct mwifiex_private *priv,
		       struct mwifiex_ds_get_stats *log)
{
	int ret = 0;
	int status = 0;
	struct mwifiex_wait_queue *wait = NULL;
	struct mwifiex_ds_get_stats get_log;
	u8 wait_option = MWIFIEX_IOCTL_WAIT;

	/* Allocate wait buffer */
	wait = mwifiex_alloc_fill_wait_queue(priv, wait_option);
	if (!wait)
		return -ENOMEM;

	memset(&get_log, 0, sizeof(struct mwifiex_ds_get_stats));
	status = mwifiex_get_info_stats(priv, wait, &get_log);

	/* Send IOCTL request to MWIFIEX */
	ret = mwifiex_request_ioctl(priv, wait, status, wait_option);
	if (!ret) {
		if (log)
			memcpy(log, &get_log, sizeof(struct
					mwifiex_ds_get_stats));
		priv->w_stats.discard.fragment = get_log.fcs_error;
		priv->w_stats.discard.retries = get_log.retry;
		priv->w_stats.discard.misc = get_log.ack_failure;
	}

	kfree(wait);
	return ret;
}

/*
 * IOCTL request handler to read/write register.
 *
 * This function prepares the correct firmware command and
 * issues it.
 *
 * Access to the following registers are supported -
 *      - MAC
 *      - BBP
 *      - RF
 *      - PMIC
 *      - CAU
 */
static int mwifiex_reg_mem_ioctl_reg_rw(struct mwifiex_private *priv,
					struct mwifiex_wait_queue *wait,
					struct mwifiex_ds_reg_rw *reg_rw,
					u16 action)
{
	int ret = 0;
	u16 cmd_no;

	switch (le32_to_cpu(reg_rw->type)) {
	case MWIFIEX_REG_MAC:
		cmd_no = HostCmd_CMD_MAC_REG_ACCESS;
		break;
	case MWIFIEX_REG_BBP:
		cmd_no = HostCmd_CMD_BBP_REG_ACCESS;
		break;
	case MWIFIEX_REG_RF:
		cmd_no = HostCmd_CMD_RF_REG_ACCESS;
		break;
	case MWIFIEX_REG_PMIC:
		cmd_no = HostCmd_CMD_PMIC_REG_ACCESS;
		break;
	case MWIFIEX_REG_CAU:
		cmd_no = HostCmd_CMD_CAU_REG_ACCESS;
		break;
	default:
		return -1;
	}

	/* Send request to firmware */
	ret = mwifiex_prepare_cmd(priv, cmd_no, action, 0, wait, reg_rw);

	if (!ret)
		ret = -EINPROGRESS;

	return ret;
}

/*
 * Sends IOCTL request to write to a register.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
int
mwifiex_reg_write(struct mwifiex_private *priv, u32 reg_type,
		  u32 reg_offset, u32 reg_value)
{
	int ret = 0;
	int status = 0;
	struct mwifiex_wait_queue *wait = NULL;
	struct mwifiex_ds_reg_rw reg_rw;

	wait = mwifiex_alloc_fill_wait_queue(priv, MWIFIEX_IOCTL_WAIT);
	if (!wait)
		return -ENOMEM;

	reg_rw.type = cpu_to_le32(reg_type);
	reg_rw.offset = cpu_to_le32(reg_offset);
	reg_rw.value = cpu_to_le32(reg_value);
	status = mwifiex_reg_mem_ioctl_reg_rw(priv, wait, &reg_rw,
					      HostCmd_ACT_GEN_SET);

	ret = mwifiex_request_ioctl(priv, wait, status, MWIFIEX_IOCTL_WAIT);

	kfree(wait);
	return ret;
}

/*
 * Sends IOCTL request to read from a register.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
int
mwifiex_reg_read(struct mwifiex_private *priv, u32 reg_type,
		 u32 reg_offset, u32 *value)
{
	int ret = 0;
	int status = 0;
	struct mwifiex_wait_queue *wait = NULL;
	struct mwifiex_ds_reg_rw reg_rw;

	wait = mwifiex_alloc_fill_wait_queue(priv, MWIFIEX_IOCTL_WAIT);
	if (!wait)
		return -ENOMEM;

	reg_rw.type = cpu_to_le32(reg_type);
	reg_rw.offset = cpu_to_le32(reg_offset);
	status = mwifiex_reg_mem_ioctl_reg_rw(priv, wait, &reg_rw,
					      HostCmd_ACT_GEN_GET);

	ret = mwifiex_request_ioctl(priv, wait, status, MWIFIEX_IOCTL_WAIT);
	if (ret)
		goto done;

	*value = le32_to_cpu(reg_rw.value);

done:
	kfree(wait);
	return ret;
}

/*
 * IOCTL request handler to read EEPROM.
 *
 * This function prepares the correct firmware command and
 * issues it.
 */
static int
mwifiex_reg_mem_ioctl_read_eeprom(struct mwifiex_private *priv,
				  struct mwifiex_wait_queue *wait,
				  struct mwifiex_ds_read_eeprom *rd_eeprom)
{
	int ret = 0;

	/* Send request to firmware */
	ret = mwifiex_prepare_cmd(priv, HostCmd_CMD_802_11_EEPROM_ACCESS,
				  HostCmd_ACT_GEN_GET, 0, wait, rd_eeprom);

	if (!ret)
		ret = -EINPROGRESS;

	return ret;
}

/*
 * Sends IOCTL request to read from EEPROM.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
int
mwifiex_eeprom_read(struct mwifiex_private *priv, u16 offset, u16 bytes,
		    u8 *value)
{
	int ret = 0;
	int status = 0;
	struct mwifiex_wait_queue *wait = NULL;
	struct mwifiex_ds_read_eeprom rd_eeprom;

	wait = mwifiex_alloc_fill_wait_queue(priv, MWIFIEX_IOCTL_WAIT);
	if (!wait)
		return -ENOMEM;

	rd_eeprom.offset = cpu_to_le16((u16) offset);
	rd_eeprom.byte_count = cpu_to_le16((u16) bytes);
	status = mwifiex_reg_mem_ioctl_read_eeprom(priv, wait, &rd_eeprom);

	ret = mwifiex_request_ioctl(priv, wait, status, MWIFIEX_IOCTL_WAIT);
	if (ret)
		goto done;

	memcpy(value, rd_eeprom.value, MAX_EEPROM_DATA);
done:
	kfree(wait);
	return ret;
}

/*
 * This function sets a generic IE. In addition to generic IE, it can
 * also handle WPA, WPA2 and WAPI IEs.
 */
static int
mwifiex_set_gen_ie_helper(struct mwifiex_private *priv, u8 *ie_data_ptr,
			  u16 ie_len)
{
	int ret = 0;
	struct ieee_types_vendor_header *pvendor_ie;
	const u8 wpa_oui[] = { 0x00, 0x50, 0xf2, 0x01 };
	const u8 wps_oui[] = { 0x00, 0x50, 0xf2, 0x04 };

	/* If the passed length is zero, reset the buffer */
	if (!ie_len) {
		priv->gen_ie_buf_len = 0;
		priv->wps.session_enable = false;

		return 0;
	} else if (!ie_data_ptr) {
		return -1;
	}
	pvendor_ie = (struct ieee_types_vendor_header *) ie_data_ptr;
	/* Test to see if it is a WPA IE, if not, then it is a gen IE */
	if (((pvendor_ie->element_id == WLAN_EID_WPA)
	     && (!memcmp(pvendor_ie->oui, wpa_oui, sizeof(wpa_oui))))
			|| (pvendor_ie->element_id == WLAN_EID_RSN)) {

		/* IE is a WPA/WPA2 IE so call set_wpa function */
		ret = mwifiex_set_wpa_ie_helper(priv, ie_data_ptr, ie_len);
		priv->wps.session_enable = false;

		return ret;
	} else if (pvendor_ie->element_id == WLAN_EID_BSS_AC_ACCESS_DELAY) {
		/* IE is a WAPI IE so call set_wapi function */
		ret = mwifiex_set_wapi_ie(priv, ie_data_ptr, ie_len);

		return ret;
	}
	/*
	 * Verify that the passed length is not larger than the
	 * available space remaining in the buffer
	 */
	if (ie_len < (sizeof(priv->gen_ie_buf) - priv->gen_ie_buf_len)) {

		/* Test to see if it is a WPS IE, if so, enable
		 * wps session flag
		 */
		pvendor_ie = (struct ieee_types_vendor_header *) ie_data_ptr;
		if ((pvendor_ie->element_id == WLAN_EID_VENDOR_SPECIFIC)
				&& (!memcmp(pvendor_ie->oui, wps_oui,
						sizeof(wps_oui)))) {
			priv->wps.session_enable = true;
			dev_dbg(priv->adapter->dev,
				"info: WPS Session Enabled.\n");
		}

		/* Append the passed data to the end of the
		   genIeBuffer */
		memcpy(priv->gen_ie_buf + priv->gen_ie_buf_len, ie_data_ptr,
									ie_len);
		/* Increment the stored buffer length by the
		   size passed */
		priv->gen_ie_buf_len += ie_len;
	} else {
		/* Passed data does not fit in the remaining
		   buffer space */
		ret = -1;
	}

	/* Return 0, or -1 for error case */
	return ret;
}

/*
 * IOCTL request handler to set/get generic IE.
 *
 * In addition to various generic IEs, this function can also be
 * used to set the ARP filter.
 */
static int mwifiex_misc_ioctl_gen_ie(struct mwifiex_private *priv,
				     struct mwifiex_ds_misc_gen_ie *gen_ie,
				     u16 action)
{
	struct mwifiex_adapter *adapter = priv->adapter;

	switch (gen_ie->type) {
	case MWIFIEX_IE_TYPE_GEN_IE:
		if (action == HostCmd_ACT_GEN_GET) {
			gen_ie->len = priv->wpa_ie_len;
			memcpy(gen_ie->ie_data, priv->wpa_ie, gen_ie->len);
		} else {
			mwifiex_set_gen_ie_helper(priv, gen_ie->ie_data,
						  (u16) gen_ie->len);
		}
		break;
	case MWIFIEX_IE_TYPE_ARP_FILTER:
		memset(adapter->arp_filter, 0, sizeof(adapter->arp_filter));
		if (gen_ie->len > ARP_FILTER_MAX_BUF_SIZE) {
			adapter->arp_filter_size = 0;
			dev_err(adapter->dev, "invalid ARP filter size\n");
			return -1;
		} else {
			memcpy(adapter->arp_filter, gen_ie->ie_data,
								gen_ie->len);
			adapter->arp_filter_size = gen_ie->len;
		}
		break;
	default:
		dev_err(adapter->dev, "invalid IE type\n");
		return -1;
	}
	return 0;
}

/*
 * Sends IOCTL request to set a generic IE.
 *
 * This function allocates the IOCTL request buffer, fills it
 * with requisite parameters and calls the IOCTL handler.
 */
int
mwifiex_set_gen_ie(struct mwifiex_private *priv, u8 *ie, int ie_len)
{
	struct mwifiex_ds_misc_gen_ie gen_ie;
	int status = 0;

	if (ie_len > IW_CUSTOM_MAX)
		return -EFAULT;

	gen_ie.type = MWIFIEX_IE_TYPE_GEN_IE;
	gen_ie.len = ie_len;
	memcpy(gen_ie.ie_data, ie, ie_len);
	status = mwifiex_misc_ioctl_gen_ie(priv, &gen_ie, HostCmd_ACT_GEN_SET);
	if (status)
		return -EFAULT;

	return 0;
}
