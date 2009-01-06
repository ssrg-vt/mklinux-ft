/*
 * Copyright 2008 Pavel Machek <pavel@suse.cz>
 *
 * Distribute under GPLv2.
 */
#include <net/mac80211.h>
#include <linux/usb.h>

#include "core.h"
#include "mlmetxrx_f.h"
#include "wbhal_f.h"
#include "wblinux_f.h"

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

static struct usb_device_id wb35_table[] __devinitdata = {
	{USB_DEVICE(0x0416, 0x0035)},
	{USB_DEVICE(0x18E8, 0x6201)},
	{USB_DEVICE(0x18E8, 0x6206)},
	{USB_DEVICE(0x18E8, 0x6217)},
	{USB_DEVICE(0x18E8, 0x6230)},
	{USB_DEVICE(0x18E8, 0x6233)},
	{USB_DEVICE(0x1131, 0x2035)},
	{ 0, }
};

MODULE_DEVICE_TABLE(usb, wb35_table);

static struct ieee80211_rate wbsoft_rates[] = {
	{ .bitrate = 10, .flags = IEEE80211_RATE_SHORT_PREAMBLE },
};

static struct ieee80211_channel wbsoft_channels[] = {
	{ .center_freq = 2412},
};

static struct ieee80211_supported_band wbsoft_band_2GHz = {
	.channels	= wbsoft_channels,
	.n_channels	= ARRAY_SIZE(wbsoft_channels),
	.bitrates	= wbsoft_rates,
	.n_bitrates	= ARRAY_SIZE(wbsoft_rates),
};

int wbsoft_enabled;
struct ieee80211_hw *my_dev;

static int wbsoft_add_interface(struct ieee80211_hw *dev,
				 struct ieee80211_if_init_conf *conf)
{
	printk("wbsoft_add interface called\n");
	return 0;
}

static void wbsoft_remove_interface(struct ieee80211_hw *dev,
				     struct ieee80211_if_init_conf *conf)
{
	printk("wbsoft_remove interface called\n");
}

static void wbsoft_stop(struct ieee80211_hw *hw)
{
	printk(KERN_INFO "%s called\n", __func__);
}

static int wbsoft_get_stats(struct ieee80211_hw *hw,
			    struct ieee80211_low_level_stats *stats)
{
	printk(KERN_INFO "%s called\n", __func__);
	return 0;
}

static int wbsoft_get_tx_stats(struct ieee80211_hw *hw,
			       struct ieee80211_tx_queue_stats *stats)
{
	printk(KERN_INFO "%s called\n", __func__);
	return 0;
}

static void wbsoft_configure_filter(struct ieee80211_hw *dev,
				     unsigned int changed_flags,
				     unsigned int *total_flags,
				     int mc_count, struct dev_mc_list *mclist)
{
	unsigned int bit_nr, new_flags;
	u32 mc_filter[2];
	int i;

	new_flags = 0;

	if (*total_flags & FIF_PROMISC_IN_BSS) {
		new_flags |= FIF_PROMISC_IN_BSS;
		mc_filter[1] = mc_filter[0] = ~0;
	} else if ((*total_flags & FIF_ALLMULTI) || (mc_count > 32)) {
		new_flags |= FIF_ALLMULTI;
		mc_filter[1] = mc_filter[0] = ~0;
	} else {
		mc_filter[1] = mc_filter[0] = 0;
		for (i = 0; i < mc_count; i++) {
			if (!mclist)
				break;
			printk("Should call ether_crc here\n");
			//bit_nr = ether_crc(ETH_ALEN, mclist->dmi_addr) >> 26;
			bit_nr = 0;

			bit_nr &= 0x3F;
			mc_filter[bit_nr >> 5] |= 1 << (bit_nr & 31);
			mclist = mclist->next;
		}
	}

	dev->flags &= ~IEEE80211_HW_RX_INCLUDES_FCS;

	*total_flags = new_flags;
}

static int wbsoft_tx(struct ieee80211_hw *dev, struct sk_buff *skb)
{
	struct wbsoft_priv *priv = dev->priv;

	MLMESendFrame(priv, skb->data, skb->len, FRAME_TYPE_802_11_MANAGEMENT);

	return NETDEV_TX_OK;
}


static int wbsoft_start(struct ieee80211_hw *dev)
{
	wbsoft_enabled = 1;
	printk("wbsoft_start called\n");
	return 0;
}

static int wbsoft_config(struct ieee80211_hw *dev, struct ieee80211_conf *conf)
{
	struct wbsoft_priv *priv = dev->priv;

	ChanInfo ch;
	printk("wbsoft_config called\n");

	ch.band = 1;
	ch.ChanNo = 1;	/* Should use channel_num, or something, as that is already pre-translated */


	hal_set_current_channel(&priv->sHwData, ch);
	hal_set_beacon_period(&priv->sHwData, conf->beacon_int);
//	hal_set_cap_info(&priv->sHwData, ?? );
// hal_set_ssid(phw_data_t pHwData,  u8 * pssid,  u8 ssid_len); ??
	hal_set_accept_broadcast(&priv->sHwData, 1);
	hal_set_accept_promiscuous(&priv->sHwData,  1);
	hal_set_accept_multicast(&priv->sHwData,  1);
	hal_set_accept_beacon(&priv->sHwData,  1);
	hal_set_radio_mode(&priv->sHwData,  0);
	//hal_set_antenna_number(  phw_data_t pHwData, u8 number )
	//hal_set_rf_power(phw_data_t pHwData, u8 PowerIndex)


//	hal_start_bss(&priv->sHwData, WLAN_BSSTYPE_INFRASTRUCTURE);	??

//void hal_set_rates(phw_data_t pHwData, u8 * pbss_rates,
//		   u8 length, unsigned char basic_rate_set)

	return 0;
}

static int wbsoft_config_interface(struct ieee80211_hw *dev,
				    struct ieee80211_vif *vif,
				    struct ieee80211_if_conf *conf)
{
	printk("wbsoft_config_interface called\n");
	return 0;
}

static u64 wbsoft_get_tsf(struct ieee80211_hw *dev)
{
	printk("wbsoft_get_tsf called\n");
	return 0;
}

static const struct ieee80211_ops wbsoft_ops = {
	.tx			= wbsoft_tx,
	.start			= wbsoft_start,		/* Start can be pretty much empty as we do WbWLanInitialize() during probe? */
	.stop			= wbsoft_stop,
	.add_interface		= wbsoft_add_interface,
	.remove_interface	= wbsoft_remove_interface,
	.config			= wbsoft_config,
	.config_interface	= wbsoft_config_interface,
	.configure_filter	= wbsoft_configure_filter,
	.get_stats		= wbsoft_get_stats,
	.get_tx_stats		= wbsoft_get_tx_stats,
	.get_tsf		= wbsoft_get_tsf,
// conf_tx: hal_set_cwmin()/hal_set_cwmax;
};

static int wb35_probe(struct usb_interface *intf, const struct usb_device_id *id_table)
{
	PWBUSB		pWbUsb;
        struct usb_host_interface *interface;
	struct usb_endpoint_descriptor *endpoint;
	u32	ltmp;
	struct usb_device *udev = interface_to_usbdev(intf);
	struct wbsoft_priv *priv;
	struct ieee80211_hw *dev;
	int err;

	usb_get_dev(udev);

	// 20060630.2 Check the device if it already be opened
	err = usb_control_msg(udev, usb_rcvctrlpipe( udev, 0 ),
			      0x01, USB_TYPE_VENDOR|USB_RECIP_DEVICE|USB_DIR_IN,
			      0x0, 0x400, &ltmp, 4, HZ*100 );
	if (err)
		goto error;

	ltmp = cpu_to_le32(ltmp);
	if (ltmp) {  // Is already initialized?
		err = -EBUSY;
		goto error;
	}

	dev = ieee80211_alloc_hw(sizeof(*priv), &wbsoft_ops);
	if (!dev)
		goto error;

	priv = dev->priv;
	my_dev = dev;

	pWbUsb = &priv->sHwData.WbUsb;
	pWbUsb->udev = udev;

        interface = intf->cur_altsetting;
        endpoint = &interface->endpoint[0].desc;

	if (endpoint[2].wMaxPacketSize == 512) {
		printk("[w35und] Working on USB 2.0\n");
		pWbUsb->IsUsb20 = 1;
	}

	if (!WbWLanInitialize(priv)) {
		err = -EINVAL;
		goto error_free_hw;
	}

	SET_IEEE80211_DEV(dev, &udev->dev);
	{
		phw_data_t pHwData = &priv->sHwData;
		unsigned char		dev_addr[MAX_ADDR_LEN];
		hal_get_permanent_address(pHwData, dev_addr);
		SET_IEEE80211_PERM_ADDR(dev, dev_addr);
	}

	dev->extra_tx_headroom = 12;	/* FIXME */
	dev->flags = 0;

	dev->channel_change_time = 1000;
	dev->queues = 1;

	dev->wiphy->bands[IEEE80211_BAND_2GHZ] = &wbsoft_band_2GHz;

	err = ieee80211_register_hw(dev);
	if (err)
		goto error_free_hw;

	usb_set_intfdata(intf, priv);

	return 0;

error_free_hw:
	ieee80211_free_hw(dev);
error:
	usb_put_dev(udev);
	return err;
}

void packet_came(char *pRxBufferAddress, int PacketSize)
{
	struct sk_buff *skb;
	struct ieee80211_rx_status rx_status = {0};

	if (!wbsoft_enabled)
		return;

	skb = dev_alloc_skb(PacketSize);
	if (!skb) {
		printk("Not enough memory for packet, FIXME\n");
		return;
	}

	memcpy(skb_put(skb, PacketSize),
	       pRxBufferAddress,
	       PacketSize);

/*
	rx_status.rate = 10;
	rx_status.channel = 1;
	rx_status.freq = 12345;
	rx_status.phymode = MODE_IEEE80211B;
*/

	ieee80211_rx_irqsafe(my_dev, skb, &rx_status);
}

static void wb35_disconnect(struct usb_interface *intf)
{
	struct wbsoft_priv *priv = usb_get_intfdata(intf);

	WbWlanHalt(priv);

	usb_set_intfdata(intf, NULL);
	usb_put_dev(interface_to_usbdev(intf));
}

static struct usb_driver wb35_driver = {
	.name		= "w35und",
	.id_table	= wb35_table,
	.probe		= wb35_probe,
	.disconnect	= wb35_disconnect,
};

static int __init wb35_init(void)
{
	return usb_register(&wb35_driver);
}

static void __exit wb35_exit(void)
{
	usb_deregister(&wb35_driver);
}

module_init(wb35_init);
module_exit(wb35_exit);
