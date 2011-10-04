/*
 * Agere Systems Inc.
 * 10/100/1000 Base-T Ethernet Driver for the ET1301 and ET131x series MACs
 *
 * Copyright © 2005 Agere Systems Inc.
 * All rights reserved.
 *   http://www.agere.com
 *
 *------------------------------------------------------------------------------
 *
 * et131x_adapter.h - Header which includes the private adapter structure, along
 *                    with related support structures, macros, definitions, etc.
 *
 *------------------------------------------------------------------------------
 *
 * SOFTWARE LICENSE
 *
 * This software is provided subject to the following terms and conditions,
 * which you should read carefully before using the software.  Using this
 * software indicates your acceptance of these terms and conditions.  If you do
 * not agree with these terms and conditions, do not use the software.
 *
 * Copyright © 2005 Agere Systems Inc.
 * All rights reserved.
 *
 * Redistribution and use in source or binary forms, with or without
 * modifications, are permitted provided that the following conditions are met:
 *
 * . Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following Disclaimer as comments in the code as
 *    well as in the documentation and/or other materials provided with the
 *    distribution.
 *
 * . Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following Disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * . Neither the name of Agere Systems Inc. nor the names of the contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Disclaimer
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, INFRINGEMENT AND THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  ANY
 * USE, MODIFICATION OR DISTRIBUTION OF THIS SOFTWARE IS SOLELY AT THE USERS OWN
 * RISK. IN NO EVENT SHALL AGERE SYSTEMS INC. OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, INCLUDING, BUT NOT LIMITED TO, CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 */

#ifndef __ET131X_ADAPTER_H__
#define __ET131X_ADAPTER_H__

#include "et1310_address_map.h"
#include "et1310_tx.h"
#include "et1310_rx.h"

/*
 * Do not change these values: if changed, then change also in respective
 * TXdma and Rxdma engines
 */
#define NUM_DESC_PER_RING_TX         512    /* TX Do not change these values */
#define NUM_TCB                      64

/*
 * These values are all superseded by registry entries to facilitate tuning.
 * Once the desired performance has been achieved, the optimal registry values
 * should be re-populated to these #defines:
 */
#define NUM_TRAFFIC_CLASSES          1

#define TX_ERROR_PERIOD             1000

#define LO_MARK_PERCENT_FOR_PSR     15
#define LO_MARK_PERCENT_FOR_RX      15

/* RFD (Receive Frame Descriptor) */
struct rfd {
	struct list_head list_node;
	struct sk_buff *skb;
	u32 len;	/* total size of receive frame */
	u16 bufferindex;
	u8 ringindex;
};

/* Flow Control */
#define FLOW_BOTH	0
#define FLOW_TXONLY	1
#define FLOW_RXONLY	2
#define FLOW_NONE	3

/* Struct to define some device statistics */
struct ce_stats {
	/* MIB II variables
	 *
	 * NOTE: atomic_t types are only guaranteed to store 24-bits; if we
	 * MUST have 32, then we'll need another way to perform atomic
	 * operations
	 */
	u32		unicast_pkts_rcvd;
	atomic_t	unicast_pkts_xmtd;
	u32		multicast_pkts_rcvd;
	atomic_t	multicast_pkts_xmtd;
	u32		broadcast_pkts_rcvd;
	atomic_t	broadcast_pkts_xmtd;
	u32		rcvd_pkts_dropped;

	/* Tx Statistics. */
	u32		tx_underflows;

	u32		tx_collisions;
	u32		tx_excessive_collisions;
	u32		tx_first_collisions;
	u32		tx_late_collisions;
	u32		tx_max_pkt_errs;
	u32		tx_deferred;

	/* Rx Statistics. */
	u32		rx_overflows;

	u32		rx_length_errs;
	u32		rx_align_errs;
	u32		rx_crc_errs;
	u32		rx_code_violations;
	u32		rx_other_errs;

	u32		synchronous_iterations;
	u32		interrupt_status;
};

/* The private adapter structure */
struct et131x_adapter {
	struct net_device *netdev;
	struct pci_dev *pdev;
	struct mii_bus *mii_bus;
	struct phy_device *phydev;
	struct work_struct task;

	/* Flags that indicate current state of the adapter */
	u32 flags;

	/* local link state, to determine if a state change has occurred */
	int link;

	/* Configuration  */
	u8 rom_addr[ETH_ALEN];
	u8 addr[ETH_ALEN];
	bool has_eeprom;
	u8 eeprom_data[2];

	/* Spinlocks */
	spinlock_t lock;

	spinlock_t tcb_send_qlock;
	spinlock_t tcb_ready_qlock;
	spinlock_t send_hw_lock;

	spinlock_t rcv_lock;
	spinlock_t rcv_pend_lock;
	spinlock_t fbr_lock;

	spinlock_t phy_lock;

	/* Packet Filter and look ahead size */
	u32 packet_filter;

	/* multicast list */
	u32 multicast_addr_count;
	u8 multicast_list[NIC_MAX_MCAST_LIST][ETH_ALEN];

	/* Pointer to the device's PCI register space */
	struct address_map __iomem *regs;

	/* Registry parameters */
	u8 wanted_flow;		/* Flow we want for 802.3x flow control */
	u32 registry_jumbo_packet;	/* Max supported ethernet packet size */

	/* Derived from the registry: */
	u8 flowcontrol;		/* flow control validated by the far-end */

	/* Minimize init-time */
	struct timer_list error_timer;

	/* variable putting the phy into coma mode when boot up with no cable
	 * plugged in after 5 seconds
	 */
	u8 boot_coma;

	/* Next two used to save power information at power down. This
	 * information will be used during power up to set up parts of Power
	 * Management in JAGCore
	 */
	u16 pdown_speed;
	u8 pdown_duplex;

	/* Tx Memory Variables */
	struct tx_ring tx_ring;

	/* Rx Memory Variables */
	struct rx_ring rx_ring;

	/* Stats */
	struct ce_stats stats;

	struct net_device_stats net_stats;
};

#endif /* __ET131X_ADAPTER_H__ */
