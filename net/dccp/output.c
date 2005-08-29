/*
 *  net/dccp/output.c
 * 
 *  An implementation of the DCCP protocol
 *  Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/dccp.h>
#include <linux/skbuff.h>

#include <net/sock.h>

#include "ccid.h"
#include "dccp.h"

static inline void dccp_event_ack_sent(struct sock *sk)
{
	inet_csk_clear_xmit_timer(sk, ICSK_TIME_DACK);
}

/*
 * All SKB's seen here are completely headerless. It is our
 * job to build the DCCP header, and pass the packet down to
 * IP so it can do the same plus pass the packet off to the
 * device.
 */
int dccp_transmit_skb(struct sock *sk, struct sk_buff *skb)
{
	if (likely(skb != NULL)) {
		const struct inet_sock *inet = inet_sk(sk);
		struct dccp_sock *dp = dccp_sk(sk);
		struct dccp_skb_cb *dcb = DCCP_SKB_CB(skb);
		struct dccp_hdr *dh;
		/* XXX For now we're using only 48 bits sequence numbers */
		const int dccp_header_size = sizeof(*dh) +
					     sizeof(struct dccp_hdr_ext) +
					     dccp_packet_hdr_len(dcb->dccpd_type);
		int err, set_ack = 1;
		u64 ackno = dp->dccps_gsr;

		/*
		 * FIXME: study DCCP_PKT_SYNC[ACK] to see what is the right thing 
		 * to do here...
		 */
		dccp_inc_seqno(&dp->dccps_gss);

		dcb->dccpd_seq = dp->dccps_gss;
		dccp_insert_options(sk, skb);

		switch (dcb->dccpd_type) {
		case DCCP_PKT_DATA:
			set_ack = 0;
			break;
		case DCCP_PKT_SYNC:
		case DCCP_PKT_SYNCACK:
			ackno = dcb->dccpd_seq;
			break;
		}
		
		skb->h.raw = skb_push(skb, dccp_header_size);
		dh = dccp_hdr(skb);
		/* Data packets are not cloned as they are never retransmitted */
		if (skb_cloned(skb))
			skb_set_owner_w(skb, sk);

		/* Build DCCP header and checksum it. */
		memset(dh, 0, dccp_header_size);
		dh->dccph_type	= dcb->dccpd_type;
		dh->dccph_sport	= inet->sport;
		dh->dccph_dport	= inet->dport;
		dh->dccph_doff	= (dccp_header_size + dcb->dccpd_opt_len) / 4;
		dh->dccph_ccval	= dcb->dccpd_ccval;
		/* XXX For now we're using only 48 bits sequence numbers */
		dh->dccph_x	= 1;

		dp->dccps_awh = dp->dccps_gss;
		dccp_hdr_set_seq(dh, dp->dccps_gss);
		if (set_ack)
			dccp_hdr_set_ack(dccp_hdr_ack_bits(skb), ackno);

		switch (dcb->dccpd_type) {
		case DCCP_PKT_REQUEST:
			dccp_hdr_request(skb)->dccph_req_service = dcb->dccpd_service;
			break;
		case DCCP_PKT_RESET:
			dccp_hdr_reset(skb)->dccph_reset_code = dcb->dccpd_reset_code;
			break;
		}

		dh->dccph_checksum = dccp_v4_checksum(skb, inet->saddr,
						      inet->daddr);

		if (dcb->dccpd_type == DCCP_PKT_ACK ||
		    dcb->dccpd_type == DCCP_PKT_DATAACK)
			dccp_event_ack_sent(sk);

		DCCP_INC_STATS(DCCP_MIB_OUTSEGS);

		err = ip_queue_xmit(skb, 0);
		if (err <= 0)
			return err;

		/* NET_XMIT_CN is special. It does not guarantee,
		 * that this packet is lost. It tells that device
		 * is about to start to drop packets or already
		 * drops some packets of the same priority and
		 * invokes us to send less aggressively.
		 */
		return err == NET_XMIT_CN ? 0 : err;
	}
	return -ENOBUFS;
}

unsigned int dccp_sync_mss(struct sock *sk, u32 pmtu)
{
	struct dccp_sock *dp = dccp_sk(sk);
	int mss_now;

	/*
	 * FIXME: we really should be using the af_specific thing to support IPv6.
	 * mss_now = pmtu - tp->af_specific->net_header_len - sizeof(struct dccp_hdr) - sizeof(struct dccp_hdr_ext);
	 */
	mss_now = pmtu - sizeof(struct iphdr) - sizeof(struct dccp_hdr) - sizeof(struct dccp_hdr_ext);

	/* Now subtract optional transport overhead */
	mss_now -= dp->dccps_ext_header_len;

	/*
	 * FIXME: this should come from the CCID infrastructure, where, say,
	 * TFRC will say it wants TIMESTAMPS, ELAPSED time, etc, for now lets
	 * put a rough estimate for NDP + TIMESTAMP + TIMESTAMP_ECHO + ELAPSED
	 * TIME + TFRC_OPT_LOSS_EVENT_RATE + TFRC_OPT_RECEIVE_RATE + padding to
	 * make it a multiple of 4
	 */

	mss_now -= ((5 + 6 + 10 + 6 + 6 + 6 + 3) / 4) * 4;

	/* And store cached results */
	dp->dccps_pmtu_cookie = pmtu;
	dp->dccps_mss_cache = mss_now;

	return mss_now;
}

int dccp_write_xmit(struct sock *sk, struct sk_buff *skb, const int len)
{
	const struct dccp_sock *dp = dccp_sk(sk);
	int err = ccid_hc_tx_send_packet(dp->dccps_hc_tx_ccid, sk, skb, len);

	if (err == 0) {
		const struct dccp_ackpkts *ap = dp->dccps_hc_rx_ackpkts;
		struct dccp_skb_cb *dcb = DCCP_SKB_CB(skb);

		if (sk->sk_state == DCCP_PARTOPEN) {
			/* See 8.1.5.  Handshake Completion */
			inet_csk_schedule_ack(sk);
			inet_csk_reset_xmit_timer(sk, ICSK_TIME_DACK,
						  inet_csk(sk)->icsk_rto,
						  DCCP_RTO_MAX);
			dcb->dccpd_type = DCCP_PKT_DATAACK;
			/*
			 * FIXME: we really should have a
			 * dccps_ack_pending or use icsk.
			 */
		} else if (inet_csk_ack_scheduled(sk) ||
			   (dp->dccps_options.dccpo_send_ack_vector &&
			    ap->dccpap_buf_ackno != DCCP_MAX_SEQNO + 1 &&
			    ap->dccpap_ack_seqno == DCCP_MAX_SEQNO + 1))
			dcb->dccpd_type = DCCP_PKT_DATAACK;
		else
			dcb->dccpd_type = DCCP_PKT_DATA;

		err = dccp_transmit_skb(sk, skb);
		ccid_hc_tx_packet_sent(dp->dccps_hc_tx_ccid, sk, 0, len);
	}

	return err;
}

int dccp_retransmit_skb(struct sock *sk, struct sk_buff *skb)
{
	if (inet_sk_rebuild_header(sk) != 0)
		return -EHOSTUNREACH; /* Routing failure or similar. */

	return dccp_transmit_skb(sk, (skb_cloned(skb) ?
				      pskb_copy(skb, GFP_ATOMIC):
				      skb_clone(skb, GFP_ATOMIC)));
}

struct sk_buff *dccp_make_response(struct sock *sk, struct dst_entry *dst,
				   struct request_sock *req)
{
	struct dccp_hdr *dh;
	const int dccp_header_size = sizeof(struct dccp_hdr) +
				     sizeof(struct dccp_hdr_ext) +
				     sizeof(struct dccp_hdr_response);
	struct sk_buff *skb = sock_wmalloc(sk, MAX_HEADER + DCCP_MAX_OPT_LEN +
					       dccp_header_size, 1,
					   GFP_ATOMIC);
	if (skb == NULL)
		return NULL;

	/* Reserve space for headers. */
	skb_reserve(skb, MAX_HEADER + DCCP_MAX_OPT_LEN + dccp_header_size);

	skb->dst = dst_clone(dst);
	skb->csum = 0;

	DCCP_SKB_CB(skb)->dccpd_type = DCCP_PKT_RESPONSE;
	DCCP_SKB_CB(skb)->dccpd_seq  = dccp_rsk(req)->dreq_iss;
	dccp_insert_options(sk, skb);

	skb->h.raw = skb_push(skb, dccp_header_size);

	dh = dccp_hdr(skb);
	memset(dh, 0, dccp_header_size);

	dh->dccph_sport	= inet_sk(sk)->sport;
	dh->dccph_dport	= inet_rsk(req)->rmt_port;
	dh->dccph_doff	= (dccp_header_size + DCCP_SKB_CB(skb)->dccpd_opt_len) / 4;
	dh->dccph_type	= DCCP_PKT_RESPONSE;
	dh->dccph_x	= 1;
	dccp_hdr_set_seq(dh, dccp_rsk(req)->dreq_iss);
	dccp_hdr_set_ack(dccp_hdr_ack_bits(skb), dccp_rsk(req)->dreq_isr);

	dh->dccph_checksum = dccp_v4_checksum(skb, inet_rsk(req)->loc_addr,
					      inet_rsk(req)->rmt_addr);

	DCCP_INC_STATS(DCCP_MIB_OUTSEGS);
	return skb;
}

struct sk_buff *dccp_make_reset(struct sock *sk, struct dst_entry *dst,
				const enum dccp_reset_codes code)
				   
{
	struct dccp_hdr *dh;
	struct dccp_sock *dp = dccp_sk(sk);
	const int dccp_header_size = sizeof(struct dccp_hdr) +
				     sizeof(struct dccp_hdr_ext) +
				     sizeof(struct dccp_hdr_reset);
	struct sk_buff *skb = sock_wmalloc(sk, MAX_HEADER + DCCP_MAX_OPT_LEN +
					       dccp_header_size, 1,
					   GFP_ATOMIC);
	if (skb == NULL)
		return NULL;

	/* Reserve space for headers. */
	skb_reserve(skb, MAX_HEADER + DCCP_MAX_OPT_LEN + dccp_header_size);

	skb->dst = dst_clone(dst);
	skb->csum = 0;

	dccp_inc_seqno(&dp->dccps_gss);

	DCCP_SKB_CB(skb)->dccpd_reset_code = code;
	DCCP_SKB_CB(skb)->dccpd_type	   = DCCP_PKT_RESET;
	DCCP_SKB_CB(skb)->dccpd_seq	   = dp->dccps_gss;
	dccp_insert_options(sk, skb);

	skb->h.raw = skb_push(skb, dccp_header_size);

	dh = dccp_hdr(skb);
	memset(dh, 0, dccp_header_size);

	dh->dccph_sport	= inet_sk(sk)->sport;
	dh->dccph_dport	= inet_sk(sk)->dport;
	dh->dccph_doff	= (dccp_header_size + DCCP_SKB_CB(skb)->dccpd_opt_len) / 4;
	dh->dccph_type	= DCCP_PKT_RESET;
	dh->dccph_x	= 1;
	dccp_hdr_set_seq(dh, dp->dccps_gss);
	dccp_hdr_set_ack(dccp_hdr_ack_bits(skb), dp->dccps_gsr);

	dccp_hdr_reset(skb)->dccph_reset_code = code;

	dh->dccph_checksum = dccp_v4_checksum(skb, inet_sk(sk)->saddr,
					      inet_sk(sk)->daddr);

	DCCP_INC_STATS(DCCP_MIB_OUTSEGS);
	return skb;
}

/*
 * Do all connect socket setups that can be done AF independent.
 */
static inline void dccp_connect_init(struct sock *sk)
{
	struct dst_entry *dst = __sk_dst_get(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	sk->sk_err = 0;
	sock_reset_flag(sk, SOCK_DONE);
	
	dccp_sync_mss(sk, dst_mtu(dst));

	/*
	 * FIXME: set dp->{dccps_swh,dccps_swl}, with
	 * something like dccp_inc_seq
	 */

	icsk->icsk_retransmits = 0;
}

int dccp_connect(struct sock *sk)
{
	struct sk_buff *skb;
	struct inet_connection_sock *icsk = inet_csk(sk);

	dccp_connect_init(sk);

	skb = alloc_skb(MAX_DCCP_HEADER + 15, sk->sk_allocation);
	if (unlikely(skb == NULL))
		return -ENOBUFS;

	/* Reserve space for headers. */
	skb_reserve(skb, MAX_DCCP_HEADER);

	DCCP_SKB_CB(skb)->dccpd_type = DCCP_PKT_REQUEST;
	/* FIXME: set service to something meaningful, coming
	 * from userspace*/
	DCCP_SKB_CB(skb)->dccpd_service = 0;
	skb->csum = 0;
	skb_set_owner_w(skb, sk);

	BUG_TRAP(sk->sk_send_head == NULL);
	sk->sk_send_head = skb;
	dccp_transmit_skb(sk, skb_clone(skb, GFP_KERNEL));
	DCCP_INC_STATS(DCCP_MIB_ACTIVEOPENS);

	/* Timer for repeating the REQUEST until an answer. */
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
				  icsk->icsk_rto, DCCP_RTO_MAX);
	return 0;
}

void dccp_send_ack(struct sock *sk)
{
	/* If we have been reset, we may not send again. */
	if (sk->sk_state != DCCP_CLOSED) {
		struct sk_buff *skb = alloc_skb(MAX_DCCP_HEADER, GFP_ATOMIC);

		if (skb == NULL) {
			inet_csk_schedule_ack(sk);
			inet_csk(sk)->icsk_ack.ato = TCP_ATO_MIN;
			inet_csk_reset_xmit_timer(sk, ICSK_TIME_DACK, TCP_DELACK_MAX, TCP_RTO_MAX);
			return;
		}

		/* Reserve space for headers */
		skb_reserve(skb, MAX_DCCP_HEADER);
		skb->csum = 0;
		DCCP_SKB_CB(skb)->dccpd_type = DCCP_PKT_ACK;
		skb_set_owner_w(skb, sk);
		dccp_transmit_skb(sk, skb);
	}
}

EXPORT_SYMBOL_GPL(dccp_send_ack);

void dccp_send_delayed_ack(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	/*
	 * FIXME: tune this timer. elapsed time fixes the skew, so no problem
	 * with using 2s, and active senders also piggyback the ACK into a
	 * DATAACK packet, so this is really for quiescent senders.
	 */
	unsigned long timeout = jiffies + 2 * HZ;

	/* Use new timeout only if there wasn't a older one earlier. */
	if (icsk->icsk_ack.pending & ICSK_ACK_TIMER) {
		/* If delack timer was blocked or is about to expire,
		 * send ACK now.
		 *
		 * FIXME: check the "about to expire" part
		 */
		if (icsk->icsk_ack.blocked) {
			dccp_send_ack(sk);
			return;
		}

		if (!time_before(timeout, icsk->icsk_ack.timeout))
			timeout = icsk->icsk_ack.timeout;
	}
	icsk->icsk_ack.pending |= ICSK_ACK_SCHED | ICSK_ACK_TIMER;
	icsk->icsk_ack.timeout = timeout;
	sk_reset_timer(sk, &icsk->icsk_delack_timer, timeout);
}

void dccp_send_sync(struct sock *sk, u64 seq)
{
	/*
	 * We are not putting this on the write queue, so
	 * dccp_transmit_skb() will set the ownership to this
	 * sock.
	 */
	struct sk_buff *skb = alloc_skb(MAX_DCCP_HEADER, GFP_ATOMIC);

	if (skb == NULL)
		/* FIXME: how to make sure the sync is sent? */
		return;

	/* Reserve space for headers and prepare control bits. */
	skb_reserve(skb, MAX_DCCP_HEADER);
	skb->csum = 0;
	DCCP_SKB_CB(skb)->dccpd_type = DCCP_PKT_SYNC;
	DCCP_SKB_CB(skb)->dccpd_seq = seq;

	skb_set_owner_w(skb, sk);
	dccp_transmit_skb(sk, skb);
}

/* Send a DCCP_PKT_CLOSE/CLOSEREQ.  The caller locks the socket for us.  This cannot be
 * allowed to fail queueing a DCCP_PKT_CLOSE/CLOSEREQ frame under any circumstances.
 */
void dccp_send_close(struct sock *sk)
{
	struct dccp_sock *dp = dccp_sk(sk);
	struct sk_buff *skb;

	/* Socket is locked, keep trying until memory is available. */
	for (;;) {
		skb = alloc_skb(sk->sk_prot->max_header, GFP_KERNEL);
		if (skb != NULL)
			break;
		yield();
	}

	/* Reserve space for headers and prepare control bits. */
	skb_reserve(skb, sk->sk_prot->max_header);
	skb->csum = 0;
	DCCP_SKB_CB(skb)->dccpd_type = dp->dccps_role == DCCP_ROLE_CLIENT ? DCCP_PKT_CLOSE : DCCP_PKT_CLOSEREQ;

	skb_set_owner_w(skb, sk);
	dccp_transmit_skb(sk, skb);

	ccid_hc_rx_exit(dp->dccps_hc_rx_ccid, sk);
	ccid_hc_tx_exit(dp->dccps_hc_tx_ccid, sk);
}
