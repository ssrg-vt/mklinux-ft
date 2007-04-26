/* AFS Cache Manager Service
 *
 * Copyright (C) 2002 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/ip.h>
#include "internal.h"
#include "afs_cm.h"

struct workqueue_struct *afs_cm_workqueue;

static int afs_deliver_cb_init_call_back_state(struct afs_call *,
					       struct sk_buff *, bool);
static int afs_deliver_cb_probe(struct afs_call *, struct sk_buff *, bool);
static int afs_deliver_cb_callback(struct afs_call *, struct sk_buff *, bool);
static void afs_cm_destructor(struct afs_call *);

/*
 * CB.CallBack operation type
 */
static const struct afs_call_type afs_SRXCBCallBack = {
	.deliver	= afs_deliver_cb_callback,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_cm_destructor,
};

/*
 * CB.InitCallBackState operation type
 */
static const struct afs_call_type afs_SRXCBInitCallBackState = {
	.deliver	= afs_deliver_cb_init_call_back_state,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_cm_destructor,
};

/*
 * CB.Probe operation type
 */
static const struct afs_call_type afs_SRXCBProbe = {
	.deliver	= afs_deliver_cb_probe,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_cm_destructor,
};

/*
 * route an incoming cache manager call
 * - return T if supported, F if not
 */
bool afs_cm_incoming_call(struct afs_call *call)
{
	u32 operation_id = ntohl(call->operation_ID);

	_enter("{CB.OP %u}", operation_id);

	switch (operation_id) {
	case CBCallBack:
		call->type = &afs_SRXCBCallBack;
		return true;
	case CBInitCallBackState:
		call->type = &afs_SRXCBInitCallBackState;
		return true;
	case CBProbe:
		call->type = &afs_SRXCBProbe;
		return true;
	default:
		return false;
	}
}

/*
 * clean up a cache manager call
 */
static void afs_cm_destructor(struct afs_call *call)
{
	_enter("");

	afs_put_server(call->server);
	call->server = NULL;
	kfree(call->buffer);
	call->buffer = NULL;
}

/*
 * allow the fileserver to see if the cache manager is still alive
 */
static void SRXAFSCB_CallBack(struct work_struct *work)
{
	struct afs_call *call = container_of(work, struct afs_call, work);

	_enter("");

	/* be sure to send the reply *before* attempting to spam the AFS server
	 * with FSFetchStatus requests on the vnodes with broken callbacks lest
	 * the AFS server get into a vicious cycle of trying to break further
	 * callbacks because it hadn't received completion of the CBCallBack op
	 * yet */
	afs_send_empty_reply(call);

	afs_break_callbacks(call->server, call->count, call->request);
	_leave("");
}

/*
 * deliver request data to a CB.CallBack call
 */
static int afs_deliver_cb_callback(struct afs_call *call, struct sk_buff *skb,
				   bool last)
{
	struct afs_callback *cb;
	struct afs_server *server;
	struct in_addr addr;
	__be32 *bp;
	u32 tmp;
	int ret, loop;

	_enter("{%u},{%u},%d", call->unmarshall, skb->len, last);

	switch (call->unmarshall) {
	case 0:
		call->offset = 0;
		call->unmarshall++;

		/* extract the FID array and its count in two steps */
	case 1:
		_debug("extract FID count");
		ret = afs_extract_data(call, skb, last, &call->tmp, 4);
		switch (ret) {
		case 0:		break;
		case -EAGAIN:	return 0;
		default:	return ret;
		}

		call->count = ntohl(call->tmp);
		_debug("FID count: %u", call->count);
		if (call->count > AFSCBMAX)
			return -EBADMSG;

		call->buffer = kmalloc(call->count * 3 * 4, GFP_KERNEL);
		if (!call->buffer)
			return -ENOMEM;
		call->offset = 0;
		call->unmarshall++;

	case 2:
		_debug("extract FID array");
		ret = afs_extract_data(call, skb, last, call->buffer,
				       call->count * 3 * 4);
		switch (ret) {
		case 0:		break;
		case -EAGAIN:	return 0;
		default:	return ret;
		}

		_debug("unmarshall FID array");
		call->request = kcalloc(call->count,
					sizeof(struct afs_callback),
					GFP_KERNEL);
		if (!call->request)
			return -ENOMEM;

		cb = call->request;
		bp = call->buffer;
		for (loop = call->count; loop > 0; loop--, cb++) {
			cb->fid.vid	= ntohl(*bp++);
			cb->fid.vnode	= ntohl(*bp++);
			cb->fid.unique	= ntohl(*bp++);
			cb->type	= AFSCM_CB_UNTYPED;
		}

		call->offset = 0;
		call->unmarshall++;

		/* extract the callback array and its count in two steps */
	case 3:
		_debug("extract CB count");
		ret = afs_extract_data(call, skb, last, &call->tmp, 4);
		switch (ret) {
		case 0:		break;
		case -EAGAIN:	return 0;
		default:	return ret;
		}

		tmp = ntohl(call->tmp);
		_debug("CB count: %u", tmp);
		if (tmp != call->count && tmp != 0)
			return -EBADMSG;
		call->offset = 0;
		call->unmarshall++;
		if (tmp == 0)
			goto empty_cb_array;

	case 4:
		_debug("extract CB array");
		ret = afs_extract_data(call, skb, last, call->request,
				       call->count * 3 * 4);
		switch (ret) {
		case 0:		break;
		case -EAGAIN:	return 0;
		default:	return ret;
		}

		_debug("unmarshall CB array");
		cb = call->request;
		bp = call->buffer;
		for (loop = call->count; loop > 0; loop--, cb++) {
			cb->version	= ntohl(*bp++);
			cb->expiry	= ntohl(*bp++);
			cb->type	= ntohl(*bp++);
		}

	empty_cb_array:
		call->offset = 0;
		call->unmarshall++;

	case 5:
		_debug("trailer");
		if (skb->len != 0)
			return -EBADMSG;
		break;
	}

	if (!last)
		return 0;

	call->state = AFS_CALL_REPLYING;

	/* we'll need the file server record as that tells us which set of
	 * vnodes to operate upon */
	memcpy(&addr, &ip_hdr(skb)->saddr, 4);
	server = afs_find_server(&addr);
	if (!server)
		return -ENOTCONN;
	call->server = server;

	INIT_WORK(&call->work, SRXAFSCB_CallBack);
	schedule_work(&call->work);
	return 0;
}

/*
 * allow the fileserver to request callback state (re-)initialisation
 */
static void SRXAFSCB_InitCallBackState(struct work_struct *work)
{
	struct afs_call *call = container_of(work, struct afs_call, work);

	_enter("{%p}", call->server);

	afs_init_callback_state(call->server);
	afs_send_empty_reply(call);
	_leave("");
}

/*
 * deliver request data to a CB.InitCallBackState call
 */
static int afs_deliver_cb_init_call_back_state(struct afs_call *call,
					       struct sk_buff *skb,
					       bool last)
{
	struct afs_server *server;
	struct in_addr addr;

	_enter(",{%u},%d", skb->len, last);

	if (skb->len > 0)
		return -EBADMSG;
	if (!last)
		return 0;

	/* no unmarshalling required */
	call->state = AFS_CALL_REPLYING;

	/* we'll need the file server record as that tells us which set of
	 * vnodes to operate upon */
	memcpy(&addr, &ip_hdr(skb)->saddr, 4);
	server = afs_find_server(&addr);
	if (!server)
		return -ENOTCONN;
	call->server = server;

	INIT_WORK(&call->work, SRXAFSCB_InitCallBackState);
	schedule_work(&call->work);
	return 0;
}

/*
 * allow the fileserver to see if the cache manager is still alive
 */
static void SRXAFSCB_Probe(struct work_struct *work)
{
	struct afs_call *call = container_of(work, struct afs_call, work);

	_enter("");
	afs_send_empty_reply(call);
	_leave("");
}

/*
 * deliver request data to a CB.Probe call
 */
static int afs_deliver_cb_probe(struct afs_call *call, struct sk_buff *skb,
				bool last)
{
	_enter(",{%u},%d", skb->len, last);

	if (skb->len > 0)
		return -EBADMSG;
	if (!last)
		return 0;

	/* no unmarshalling required */
	call->state = AFS_CALL_REPLYING;

	INIT_WORK(&call->work, SRXAFSCB_Probe);
	schedule_work(&call->work);
	return 0;
}
