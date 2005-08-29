/*
 *  net/dccp/ccids/ccid3.h
 *
 *  Copyright (c) 2005 The University of Waikato, Hamilton, New Zealand.
 *
 *  An implementation of the DCCP protocol
 *
 *  This code has been developed by the University of Waikato WAND
 *  research group. For further information please see http://www.wand.net.nz/
 *  or e-mail Ian McDonald - iam4@cs.waikato.ac.nz
 *
 *  This code also uses code from Lulea University, rereleased as GPL by its
 *  authors:
 *  Copyright (c) 2003 Nils-Erik Mattsson, Joacim Haggmark, Magnus Erixzon
 *
 *  Changes to meet Linux coding standards, to make it meet latest ccid3 draft
 *  and to make it work as a loadable module in the DCCP stack written by
 *  Arnaldo Carvalho de Melo <acme@conectiva.com.br>.
 *
 *  Copyright (c) 2005 Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#ifndef _DCCP_CCID3_H_
#define _DCCP_CCID3_H_

#include <linux/types.h>
#include <linux/list.h>

struct ccid3_options_received {
	u64 ccid3or_seqno:48,
	    ccid3or_loss_intervals_idx:16;
	u16 ccid3or_loss_intervals_len;
	u32 ccid3or_loss_event_rate;
	u32 ccid3or_receive_rate;
};

/** struct ccid3_hc_tx_sock - CCID3 sender half connection congestion control block
 *
  * @ccid3hctx_state - Sender state
  * @ccid3hctx_x - Current sending rate
  * @ccid3hctx_x_recv - Receive rate
  * @ccid3hctx_x_calc - Calculated send (?) rate
  * @ccid3hctx_s - Packet size
  * @ccid3hctx_rtt - Estimate of current round trip time in usecs
  * @@ccid3hctx_p - Current loss event rate (0-1) scaled by 1000000
  * @ccid3hctx_last_win_count - Last window counter sent
  * @ccid3hctx_t_last_win_count - Timestamp of earliest packet with last_win_count value sent
  * @ccid3hctx_no_feedback_timer - Handle to no feedback timer
  * @ccid3hctx_idle - FIXME
  * @ccid3hctx_t_ld - Time last doubled during slow start
  * @ccid3hctx_t_nom - Nominal send time of next packet
  * @ccid3hctx_t_ipi - Interpacket (send) interval
  * @ccid3hctx_delta - Send timer delta
  * @ccid3hctx_hist - Packet history
  */
struct ccid3_hc_tx_sock {
	u32				ccid3hctx_x;
	u32				ccid3hctx_x_recv;
	u32				ccid3hctx_x_calc;
	u16				ccid3hctx_s;
	u32				ccid3hctx_rtt;
	u32				ccid3hctx_p;
  	u8				ccid3hctx_state;
	u8				ccid3hctx_last_win_count;
	u8				ccid3hctx_idle;
	struct timeval			ccid3hctx_t_last_win_count;
	struct timer_list		ccid3hctx_no_feedback_timer;
	struct timeval			ccid3hctx_t_ld;
	struct timeval			ccid3hctx_t_nom;
	u32				ccid3hctx_t_ipi;
	u32				ccid3hctx_delta;
	struct list_head		ccid3hctx_hist;
	struct ccid3_options_received	ccid3hctx_options_received;
};

struct ccid3_loss_interval_hist_entry {
	struct list_head	ccid3lih_node;
	u64			ccid3lih_seqno:48,
				ccid3lih_win_count:4;
	u32			ccid3lih_interval;
};

struct ccid3_hc_rx_sock {
  	u64			ccid3hcrx_seqno_last_counter:48,
				ccid3hcrx_state:8,
				ccid3hcrx_last_counter:4;
	unsigned long		ccid3hcrx_rtt;
  	u32			ccid3hcrx_p;
  	u32			ccid3hcrx_bytes_recv;
  	struct timeval		ccid3hcrx_tstamp_last_feedback;
  	struct timeval		ccid3hcrx_tstamp_last_ack;
	struct list_head	ccid3hcrx_hist;
	struct list_head	ccid3hcrx_loss_interval_hist;
  	u16			ccid3hcrx_s;
  	u32			ccid3hcrx_pinv;
  	u32			ccid3hcrx_elapsed_time;
  	u32			ccid3hcrx_x_recv;
};

#define ccid3_hc_tx_field(s,field) (s->dccps_hc_tx_ccid_private == NULL ? 0 : \
				    ((struct ccid3_hc_tx_sock *)s->dccps_hc_tx_ccid_private)->ccid3hctx_##field)

#define ccid3_hc_rx_field(s,field) (s->dccps_hc_rx_ccid_private == NULL ? 0 : \
				    ((struct ccid3_hc_rx_sock *)s->dccps_hc_rx_ccid_private)->ccid3hcrx_##field)

#endif /* _DCCP_CCID3_H_ */
