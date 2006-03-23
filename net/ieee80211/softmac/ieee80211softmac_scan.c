/*
 * Scanning routines.
 *
 * These are not exported because they're assigned to the function pointers.
 */

#include <linux/completion.h>
#include "ieee80211softmac_priv.h"

/* internal, use to trigger scanning if needed.
 * Returns -EBUSY if already scanning,
 * result of start_scan otherwise */
int
ieee80211softmac_start_scan(struct ieee80211softmac_device *sm)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&sm->lock, flags);
	if (sm->scanning)
	{
		spin_unlock_irqrestore(&sm->lock, flags);
		return -EINPROGRESS;
	}
	sm->scanning = 1;
	spin_unlock_irqrestore(&sm->lock, flags);

	ret = sm->start_scan(sm->dev);
	if (ret) {
		spin_lock_irqsave(&sm->lock, flags);
		sm->scanning = 0;
		spin_unlock_irqrestore(&sm->lock, flags);
	}
	return ret;
}

void
ieee80211softmac_stop_scan(struct ieee80211softmac_device *sm)
{
	unsigned long flags;

	spin_lock_irqsave(&sm->lock, flags);
	
	if (!sm->scanning) {
		spin_unlock_irqrestore(&sm->lock, flags);
		return;
	}
	
	spin_unlock_irqrestore(&sm->lock, flags);
	sm->stop_scan(sm->dev);
}

void
ieee80211softmac_wait_for_scan(struct ieee80211softmac_device *sm)
{
	unsigned long flags;

	spin_lock_irqsave(&sm->lock, flags);
	
	if (!sm->scanning) {
		spin_unlock_irqrestore(&sm->lock, flags);
		return;
	}
	
	spin_unlock_irqrestore(&sm->lock, flags);
	sm->wait_for_scan(sm->dev);
}


/* internal scanning implementation follows */
void ieee80211softmac_scan(void *d)
{
	int invalid_channel;
	u8 current_channel_idx;
	struct ieee80211softmac_device *sm = (struct ieee80211softmac_device *)d;
	struct ieee80211softmac_scaninfo *si = sm->scaninfo;
	unsigned long flags;

	while (!(si->stop) && (si->current_channel_idx < si->number_channels)) {
		current_channel_idx = si->current_channel_idx;
		si->current_channel_idx++; /* go to the next channel */

		invalid_channel = (si->skip_flags & si->channels[current_channel_idx].flags);

		if (!invalid_channel) {
			sm->set_channel(sm->dev, si->channels[current_channel_idx].channel);
			//TODO: Probe the channel
			// FIXME make this user configurable (active/passive)
			if(ieee80211softmac_send_mgt_frame(sm, NULL, IEEE80211_STYPE_PROBE_REQ, 0))
				printkl(KERN_DEBUG PFX "Sending Probe Request Failed\n");

			/* also send directed management frame for the network we're looking for */
			// TODO: is this if correct, or should we do this only if scanning from assoc request?
			if (sm->associnfo.req_essid.len)
				ieee80211softmac_send_mgt_frame(sm, &sm->associnfo.req_essid, IEEE80211_STYPE_PROBE_REQ, 0);
			queue_delayed_work(sm->workqueue, &si->softmac_scan, IEEE80211SOFTMAC_PROBE_DELAY);
			return;
		} else {
			dprintk(PFX "Not probing Channel %d (not allowed here)\n", si->channels[current_channel_idx].channel);
		}
	}

	spin_lock_irqsave(&sm->lock, flags);
	cancel_delayed_work(&si->softmac_scan);
	si->started = 0;
	spin_unlock_irqrestore(&sm->lock, flags);

	dprintk(PFX "Scanning finished\n");
	ieee80211softmac_scan_finished(sm);
	complete_all(&sm->scaninfo->finished);
}

static inline struct ieee80211softmac_scaninfo *allocate_scaninfo(struct ieee80211softmac_device *mac)
{
	/* ugh. can we call this without having the spinlock held? */
	struct ieee80211softmac_scaninfo *info = kmalloc(sizeof(struct ieee80211softmac_scaninfo), GFP_ATOMIC);
	if (unlikely(!info))
		return NULL;
	INIT_WORK(&info->softmac_scan, ieee80211softmac_scan, mac);
	init_completion(&info->finished);
	return info;
}

int ieee80211softmac_start_scan_implementation(struct net_device *dev)
{
	struct ieee80211softmac_device *sm = ieee80211_priv(dev);
	unsigned long flags;
	
	if (!(dev->flags & IFF_UP))
		return -ENODEV;

	assert(ieee80211softmac_scan_handlers_check_self(sm));
	if (!ieee80211softmac_scan_handlers_check_self(sm))
		return -EINVAL;
		
	spin_lock_irqsave(&sm->lock, flags);
	/* it looks like we need to hold the lock here
	 * to make sure we don't allocate two of these... */
	if (unlikely(!sm->scaninfo))
		sm->scaninfo = allocate_scaninfo(sm);
	if (unlikely(!sm->scaninfo)) {
		spin_unlock_irqrestore(&sm->lock, flags);
		return -ENOMEM;
	}

	sm->scaninfo->skip_flags = IEEE80211_CH_INVALID;
	if (0 /* not scanning in IEEE802.11b */)//TODO
		sm->scaninfo->skip_flags |= IEEE80211_CH_B_ONLY;
	if (0 /* IEEE802.11a */) {//TODO
		sm->scaninfo->channels = sm->ieee->geo.a;
		sm->scaninfo->number_channels = sm->ieee->geo.a_channels;
	} else {
		sm->scaninfo->channels = sm->ieee->geo.bg;
		sm->scaninfo->number_channels = sm->ieee->geo.bg_channels;
	}
	dprintk(PFX "Start scanning with channel: %d\n", sm->scaninfo->channels[0].channel);
	dprintk(PFX "Scanning %d channels\n", sm->scaninfo->number_channels);
	sm->scaninfo->current_channel_idx = 0;
	sm->scaninfo->started = 1;
	INIT_COMPLETION(sm->scaninfo->finished);
	queue_work(sm->workqueue, &sm->scaninfo->softmac_scan);
	spin_unlock_irqrestore(&sm->lock, flags);
	return 0;
}

void ieee80211softmac_stop_scan_implementation(struct net_device *dev)
{
	struct ieee80211softmac_device *sm = ieee80211_priv(dev);
	unsigned long flags;

	assert(ieee80211softmac_scan_handlers_check_self(sm));
	if (!ieee80211softmac_scan_handlers_check_self(sm))
		return;

	spin_lock_irqsave(&sm->lock, flags);
	assert(sm->scaninfo != NULL);
	if (sm->scaninfo) {
		if (sm->scaninfo->started)
			sm->scaninfo->stop = 1;
		else
			complete_all(&sm->scaninfo->finished);
	}
	spin_unlock_irqrestore(&sm->lock, flags);
}

void ieee80211softmac_wait_for_scan_implementation(struct net_device *dev)
{
	struct ieee80211softmac_device *sm = ieee80211_priv(dev);
	unsigned long flags;

	assert(ieee80211softmac_scan_handlers_check_self(sm));
	if (!ieee80211softmac_scan_handlers_check_self(sm))
		return;

	spin_lock_irqsave(&sm->lock, flags);
	if (!sm->scaninfo->started) {
		spin_unlock_irqrestore(&sm->lock, flags);
		return;
	}
	spin_unlock_irqrestore(&sm->lock, flags);
	wait_for_completion(&sm->scaninfo->finished);
}

/* this is what drivers (that do scanning) call when they're done */
void ieee80211softmac_scan_finished(struct ieee80211softmac_device *sm)
{
	unsigned long flags;

	spin_lock_irqsave(&sm->lock, flags);
	sm->scanning = 0;
	spin_unlock_irqrestore(&sm->lock, flags);
	
	ieee80211softmac_call_events(sm, IEEE80211SOFTMAC_EVENT_SCAN_FINISHED, NULL);
}

EXPORT_SYMBOL_GPL(ieee80211softmac_scan_finished);
