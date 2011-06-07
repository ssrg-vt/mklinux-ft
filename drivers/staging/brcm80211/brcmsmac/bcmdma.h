/*
 * Copyright (c) 2010 Broadcom Corporation
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef	_bcmdma_h_
#define	_bcmdma_h_

#include "wlc_types.h"		/* forward structure declarations */

#ifndef _dma_pub_
#define _dma_pub_
struct dma_pub;
#endif				/* _dma_pub_ */

/* DMA structure:
 *  support two DMA engines: 32 bits address or 64 bit addressing
 *  basic DMA register set is per channel(transmit or receive)
 *  a pair of channels is defined for convenience
 */

/* 32 bits addressing */

typedef volatile struct {	/* diag access */
	u32 fifoaddr;	/* diag address */
	u32 fifodatalow;	/* low 32bits of data */
	u32 fifodatahigh;	/* high 32bits of data */
	u32 pad;		/* reserved */
} dma32diag_t;

/* 64 bits addressing */

/* dma registers per channel(xmt or rcv) */
typedef volatile struct {
	u32 control;		/* enable, et al */
	u32 ptr;		/* last descriptor posted to chip */
	u32 addrlow;		/* descriptor ring base address low 32-bits (8K aligned) */
	u32 addrhigh;	/* descriptor ring base address bits 63:32 (8K aligned) */
	u32 status0;		/* current descriptor, xmt state */
	u32 status1;		/* active descriptor, xmt error */
} dma64regs_t;

/* map/unmap direction */
#define	DMA_TX	1		/* TX direction for DMA */
#define	DMA_RX	2		/* RX direction for DMA */
#define BUS_SWAP32(v)		(v)

/* range param for dma_getnexttxp() and dma_txreclaim */
typedef enum txd_range {
	HNDDMA_RANGE_ALL = 1,
	HNDDMA_RANGE_TRANSMITTED,
	HNDDMA_RANGE_TRANSFERED
} txd_range_t;

/* dma function type */
typedef void (*di_detach_t) (struct dma_pub *dmah);
typedef bool(*di_txreset_t) (struct dma_pub *dmah);
typedef bool(*di_rxreset_t) (struct dma_pub *dmah);
typedef bool(*di_rxidle_t) (struct dma_pub *dmah);
typedef void (*di_txinit_t) (struct dma_pub *dmah);
typedef bool(*di_txenabled_t) (struct dma_pub *dmah);
typedef void (*di_rxinit_t) (struct dma_pub *dmah);
typedef void (*di_txsuspend_t) (struct dma_pub *dmah);
typedef void (*di_txresume_t) (struct dma_pub *dmah);
typedef bool(*di_txsuspended_t) (struct dma_pub *dmah);
typedef bool(*di_txsuspendedidle_t) (struct dma_pub *dmah);
typedef int (*di_txfast_t) (struct dma_pub *dmah, struct sk_buff *p,
			    bool commit);
typedef int (*di_txunframed_t) (struct dma_pub *dmah, void *p, uint len,
				bool commit);
typedef void *(*di_getpos_t) (struct dma_pub *di, bool direction);
typedef void (*di_fifoloopbackenable_t) (struct dma_pub *dmah);
typedef bool(*di_txstopped_t) (struct dma_pub *dmah);
typedef bool(*di_rxstopped_t) (struct dma_pub *dmah);
typedef bool(*di_rxenable_t) (struct dma_pub *dmah);
typedef bool(*di_rxenabled_t) (struct dma_pub *dmah);
typedef void *(*di_rx_t) (struct dma_pub *dmah);
typedef bool(*di_rxfill_t) (struct dma_pub *dmah);
typedef void (*di_txreclaim_t) (struct dma_pub *dmah, txd_range_t range);
typedef void (*di_rxreclaim_t) (struct dma_pub *dmah);
typedef unsigned long (*di_getvar_t) (struct dma_pub *dmah,
				      const char *name);
typedef void *(*di_getnexttxp_t) (struct dma_pub *dmah, txd_range_t range);
typedef void *(*di_getnextrxp_t) (struct dma_pub *dmah, bool forceall);
typedef void *(*di_peeknexttxp_t) (struct dma_pub *dmah);
typedef void *(*di_peeknextrxp_t) (struct dma_pub *dmah);
typedef void (*di_rxparam_get_t) (struct dma_pub *dmah, u16 *rxoffset,
				  u16 *rxbufsize);
typedef void (*di_txblock_t) (struct dma_pub *dmah);
typedef void (*di_txunblock_t) (struct dma_pub *dmah);
typedef uint(*di_txactive_t) (struct dma_pub *dmah);
typedef void (*di_txrotate_t) (struct dma_pub *dmah);
typedef void (*di_counterreset_t) (struct dma_pub *dmah);
typedef uint(*di_ctrlflags_t) (struct dma_pub *dmah, uint mask, uint flags);
typedef char *(*di_dump_t) (struct dma_pub *dmah, struct bcmstrbuf *b,
			    bool dumpring);
typedef char *(*di_dumptx_t) (struct dma_pub *dmah, struct bcmstrbuf *b,
			      bool dumpring);
typedef char *(*di_dumprx_t) (struct dma_pub *dmah, struct bcmstrbuf *b,
			      bool dumpring);
typedef uint(*di_rxactive_t) (struct dma_pub *dmah);
typedef uint(*di_txpending_t) (struct dma_pub *dmah);
typedef uint(*di_txcommitted_t) (struct dma_pub *dmah);

/* dma opsvec */
typedef struct di_fcn_s {
	di_detach_t detach;
	di_txinit_t txinit;
	di_txreset_t txreset;
	di_txenabled_t txenabled;
	di_txsuspend_t txsuspend;
	di_txresume_t txresume;
	di_txsuspended_t txsuspended;
	di_txsuspendedidle_t txsuspendedidle;
	di_txfast_t txfast;
	di_txunframed_t txunframed;
	di_getpos_t getpos;
	di_txstopped_t txstopped;
	di_txreclaim_t txreclaim;
	di_getnexttxp_t getnexttxp;
	di_peeknexttxp_t peeknexttxp;
	di_txblock_t txblock;
	di_txunblock_t txunblock;
	di_txactive_t txactive;
	di_txrotate_t txrotate;

	di_rxinit_t rxinit;
	di_rxreset_t rxreset;
	di_rxidle_t rxidle;
	di_rxstopped_t rxstopped;
	di_rxenable_t rxenable;
	di_rxenabled_t rxenabled;
	di_rx_t rx;
	di_rxfill_t rxfill;
	di_rxreclaim_t rxreclaim;
	di_getnextrxp_t getnextrxp;
	di_peeknextrxp_t peeknextrxp;
	di_rxparam_get_t rxparam_get;

	di_fifoloopbackenable_t fifoloopbackenable;
	di_getvar_t d_getvar;
	di_counterreset_t counterreset;
	di_ctrlflags_t ctrlflags;
	di_dump_t dump;
	di_dumptx_t dumptx;
	di_dumprx_t dumprx;
	di_rxactive_t rxactive;
	di_txpending_t txpending;
	di_txcommitted_t txcommitted;
	uint endnum;
} di_fcn_t;

/*
 * Exported data structure (read-only)
 */
/* export structure */
struct dma_pub {
	const di_fcn_t *di_fn;	/* DMA function pointers */
	uint txavail;		/* # free tx descriptors */
	uint dmactrlflags;	/* dma control flags */

	/* rx error counters */
	uint rxgiants;		/* rx giant frames */
	uint rxnobuf;		/* rx out of dma descriptors */
	/* tx error counters */
	uint txnobuf;		/* tx out of dma descriptors */
};

extern struct dma_pub *dma_attach(char *name, struct si_pub *sih,
			    void *dmaregstx, void *dmaregsrx, uint ntxd,
			    uint nrxd, uint rxbufsize, int rxextheadroom,
			    uint nrxpost, uint rxoffset, uint *msg_level);

extern const di_fcn_t dma64proc;

#define dma_detach(di)			(dma64proc.detach(di))
#define dma_txreset(di)			(dma64proc.txreset(di))
#define dma_rxreset(di)			(dma64proc.rxreset(di))
#define dma_rxidle(di)			(dma64proc.rxidle(di))
#define dma_txinit(di)                  (dma64proc.txinit(di))
#define dma_txenabled(di)               (dma64proc.txenabled(di))
#define dma_rxinit(di)                  (dma64proc.rxinit(di))
#define dma_txsuspend(di)               (dma64proc.txsuspend(di))
#define dma_txresume(di)                (dma64proc.txresume(di))
#define dma_txsuspended(di)             (dma64proc.txsuspended(di))
#define dma_txsuspendedidle(di)         (dma64proc.txsuspendedidle(di))
#define dma_txfast(di, p, commit)	(dma64proc.txfast(di, p, commit))
#define dma_txunframed(di, p, l, commit)(dma64proc.txunframed(di, p, l, commit))
#define dma_getpos(di, dir)		(dma64proc.getpos(di, dir))
#define dma_fifoloopbackenable(di)      (dma64proc.fifoloopbackenable(di))
#define dma_txstopped(di)               (dma64proc.txstopped(di))
#define dma_rxstopped(di)               (dma64proc.rxstopped(di))
#define dma_rxenable(di)                (dma64proc.rxenable(di))
#define dma_rxenabled(di)               (dma64proc.rxenabled(di))
#define dma_rx(di)                      (dma64proc.rx(di))
#define dma_rxfill(di)                  (dma64proc.rxfill(di))
#define dma_txreclaim(di, range)	(dma64proc.txreclaim(di, range))
#define dma_rxreclaim(di)               (dma64proc.rxreclaim(di))
#define dma_getvar(di, name)		(dma64proc.d_getvar(di, name))
#define dma_getnexttxp(di, range)	(dma64proc.getnexttxp(di, range))
#define dma_getnextrxp(di, forceall)    (dma64proc.getnextrxp(di, forceall))
#define dma_peeknexttxp(di)             (dma64proc.peeknexttxp(di))
#define dma_peeknextrxp(di)             (dma64proc.peeknextrxp(di))
#define dma_rxparam_get(di, off, bufs)	(dma64proc.rxparam_get(di, off, bufs))

#define dma_txblock(di)                 (dma64proc.txblock(di))
#define dma_txunblock(di)               (dma64proc.txunblock(di))
#define dma_txactive(di)                (dma64proc.txactive(di))
#define dma_rxactive(di)                (dma64proc.rxactive(di))
#define dma_txrotate(di)                (dma64proc.txrotate(di))
#define dma_counterreset(di)            (dma64proc.counterreset(di))
#define dma_ctrlflags(di, mask, flags)  (dma64proc.ctrlflags((di), (mask), (flags)))
#define dma_txpending(di)		(dma64proc.txpending(di))
#define dma_txcommitted(di)		(dma64proc.txcommitted(di))


/* return addresswidth allowed
 * This needs to be done after SB attach but before dma attach.
 * SB attach provides ability to probe backplane and dma core capabilities
 * This info is needed by DMA_ALLOC_CONSISTENT in dma attach
 */
extern uint dma_addrwidth(struct si_pub *sih, void *dmaregs);
void dma_walk_packets(struct dma_pub *dmah, void (*callback_fnc)
		      (void *pkt, void *arg_a), void *arg_a);

/*
 * DMA(Bug) on some chips seems to declare that the packet is ready, but the
 * packet length is not updated yet (by DMA) on the expected time.
 * Workaround is to hold processor till DMA updates the length, and stay off
 * the bus to allow DMA update the length in buffer
 */
static inline void dma_spin_for_len(uint len, struct sk_buff *head)
{
#if defined(__mips__)
	if (!len) {
		while (!(len = *(u16 *) KSEG1ADDR(head->data)))
			udelay(1);

		*(u16 *) (head->data) = cpu_to_le16((u16) len);
	}
#endif				/* defined(__mips__) */
}

#endif				/* _bcmdma_h_ */
