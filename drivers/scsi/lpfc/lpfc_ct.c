/*******************************************************************
 * This file is part of the Emulex Linux Device Driver for         *
 * Fibre Channel Host Bus Adapters.                                *
 * Copyright (C) 2004-2007 Emulex.  All rights reserved.           *
 * EMULEX and SLI are trademarks of Emulex.                        *
 * www.emulex.com                                                  *
 *                                                                 *
 * This program is free software; you can redistribute it and/or   *
 * modify it under the terms of version 2 of the GNU General       *
 * Public License as published by the Free Software Foundation.    *
 * This program is distributed in the hope that it will be useful. *
 * ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND          *
 * WARRANTIES, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY,  *
 * FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT, ARE      *
 * DISCLAIMED, EXCEPT TO THE EXTENT THAT SUCH DISCLAIMERS ARE HELD *
 * TO BE LEGALLY INVALID.  See the GNU General Public License for  *
 * more details, a copy of which can be found in the file COPYING  *
 * included with this package.                                     *
 *******************************************************************/

/*
 * Fibre Channel SCSI LAN Device Driver CT support
 */

#include <linux/blkdev.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/utsname.h>

#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_transport_fc.h>

#include "lpfc_hw.h"
#include "lpfc_sli.h"
#include "lpfc_disc.h"
#include "lpfc_scsi.h"
#include "lpfc.h"
#include "lpfc_logmsg.h"
#include "lpfc_crtn.h"
#include "lpfc_version.h"

#define HBA_PORTSPEED_UNKNOWN               0	/* Unknown - transceiver
						 * incapable of reporting */
#define HBA_PORTSPEED_1GBIT                 1	/* 1 GBit/sec */
#define HBA_PORTSPEED_2GBIT                 2	/* 2 GBit/sec */
#define HBA_PORTSPEED_4GBIT                 8   /* 4 GBit/sec */
#define HBA_PORTSPEED_8GBIT                16   /* 8 GBit/sec */
#define HBA_PORTSPEED_10GBIT                4	/* 10 GBit/sec */
#define HBA_PORTSPEED_NOT_NEGOTIATED        5	/* Speed not established */

#define FOURBYTES	4


static char *lpfc_release_version = LPFC_DRIVER_VERSION;

/*
 * lpfc_ct_unsol_event
 */
static void
lpfc_ct_unsol_buffer(struct lpfc_hba *phba, struct lpfc_iocbq *piocbq,
		     struct lpfc_dmabuf *mp, uint32_t size)
{
	if (!mp) {
		printk(KERN_ERR "%s (%d): Unsolited CT, no buffer, "
		       "piocbq = %p, status = x%x, mp = %p, size = %d\n",
		       __FUNCTION__, __LINE__,
		       piocbq, piocbq->iocb.ulpStatus, mp, size);
	}

	printk(KERN_ERR "%s (%d): Ignoring unsolicted CT piocbq = %p, "
	       "buffer = %p, size = %d, status = x%x\n",
	       __FUNCTION__, __LINE__,
	       piocbq, mp, size,
	       piocbq->iocb.ulpStatus);
}

static void
lpfc_ct_ignore_hbq_buffer(struct lpfc_hba *phba, struct lpfc_iocbq *piocbq,
			  struct hbq_dmabuf *sp, uint32_t size)
{
	struct lpfc_dmabuf *mp = NULL;

	mp = sp ? &sp->dbuf : NULL;
	if (!mp) {
		printk(KERN_ERR "%s (%d): Unsolited CT, no "
		       "HBQ buffer, piocbq = %p, status = x%x\n",
		       __FUNCTION__, __LINE__,
		       piocbq, piocbq->iocb.ulpStatus);
	} else {
		lpfc_ct_unsol_buffer(phba, piocbq, mp, size);
		printk(KERN_ERR "%s (%d): Ignoring unsolicted CT "
		       "piocbq = %p, buffer = %p, size = %d, "
		       "status = x%x\n",
		       __FUNCTION__, __LINE__,
		       piocbq, mp, size, piocbq->iocb.ulpStatus);
	}
}

void
lpfc_ct_unsol_event(struct lpfc_hba *phba, struct lpfc_sli_ring *pring,
		    struct lpfc_iocbq *piocbq)
{
	struct lpfc_dmabuf *mp = NULL;
	struct hbq_dmabuf  *sp = NULL;
	IOCB_t *icmd = &piocbq->iocb;
	int i;
	struct lpfc_iocbq *iocbq;
	dma_addr_t paddr;
	uint32_t size;

	if ((icmd->ulpStatus == IOSTAT_LOCAL_REJECT) &&
	    ((icmd->un.ulpWord[4] & 0xff) == IOERR_RCV_BUFFER_WAITING)) {
		/* Not enough posted buffers; Try posting more buffers */
		phba->fc_stat.NoRcvBuf++;
		if (phba->sli3_options & LPFC_SLI3_HBQ_ENABLED)
			lpfc_sli_hbqbuf_fill_hbq(phba);
		else
			lpfc_post_buffer(phba, pring, 0, 1);
		return;
	}

	/* If there are no BDEs associated with this IOCB,
	 * there is nothing to do.
	 */
	if (icmd->ulpBdeCount == 0)
		return;

	if (phba->sli3_options & LPFC_SLI3_HBQ_ENABLED) {
		list_for_each_entry(iocbq, &piocbq->list, list) {
			icmd = &iocbq->iocb;
			if (icmd->ulpBdeCount == 0) {
				printk(KERN_ERR "%s (%d): Unsolited CT, no "
				       "BDE, iocbq = %p, status = x%x\n",
				       __FUNCTION__, __LINE__,
				       iocbq, iocbq->iocb.ulpStatus);
				continue;
			}

			size  = icmd->un.cont64[0].tus.f.bdeSize;
			sp = lpfc_sli_hbqbuf_find(phba, icmd->un.ulpWord[3]);
			if (sp)
				phba->hbq_buff_count--;
			lpfc_ct_ignore_hbq_buffer(phba, iocbq, sp, size);
			lpfc_sli_free_hbq(phba, sp);
			if (icmd->ulpBdeCount == 2) {
				sp = lpfc_sli_hbqbuf_find(phba,
							  icmd->un.ulpWord[15]);
				if (sp)
					phba->hbq_buff_count--;
				lpfc_ct_ignore_hbq_buffer(phba, iocbq, sp,
							  size);
				lpfc_sli_free_hbq(phba, sp);
			}

		}
		lpfc_sli_hbqbuf_fill_hbq(phba);
	} else {
		struct lpfc_iocbq  *next;

		list_for_each_entry_safe(iocbq, next, &piocbq->list, list) {
			icmd = &iocbq->iocb;
			if (icmd->ulpBdeCount == 0) {
				printk(KERN_ERR "%s (%d): Unsolited CT, no "
				       "BDE, iocbq = %p, status = x%x\n",
				       __FUNCTION__, __LINE__,
				       iocbq, iocbq->iocb.ulpStatus);
				continue;
			}

			for (i = 0; i < icmd->ulpBdeCount; i++) {
				paddr = getPaddr(icmd->un.cont64[i].addrHigh,
						 icmd->un.cont64[i].addrLow);
				mp = lpfc_sli_ringpostbuf_get(phba, pring,
							      paddr);
				size = icmd->un.cont64[i].tus.f.bdeSize;
				lpfc_ct_unsol_buffer(phba, piocbq, mp, size);
				lpfc_mbuf_free(phba, mp->virt, mp->phys);
				kfree(mp);
			}
			list_del(&iocbq->list);
			lpfc_sli_release_iocbq(phba, iocbq);
		}
	}
}

static void
lpfc_free_ct_rsp(struct lpfc_hba *phba, struct lpfc_dmabuf *mlist)
{
	struct lpfc_dmabuf *mlast, *next_mlast;

	list_for_each_entry_safe(mlast, next_mlast, &mlist->list, list) {
		lpfc_mbuf_free(phba, mlast->virt, mlast->phys);
		list_del(&mlast->list);
		kfree(mlast);
	}
	lpfc_mbuf_free(phba, mlist->virt, mlist->phys);
	kfree(mlist);
	return;
}

static struct lpfc_dmabuf *
lpfc_alloc_ct_rsp(struct lpfc_hba *phba, int cmdcode, struct ulp_bde64 *bpl,
		  uint32_t size, int *entries)
{
	struct lpfc_dmabuf *mlist = NULL;
	struct lpfc_dmabuf *mp;
	int cnt, i = 0;

	/* We get chucks of FCELSSIZE */
	cnt = size > FCELSSIZE ? FCELSSIZE: size;

	while (size) {
		/* Allocate buffer for rsp payload */
		mp = kmalloc(sizeof(struct lpfc_dmabuf), GFP_KERNEL);
		if (!mp) {
			if (mlist)
				lpfc_free_ct_rsp(phba, mlist);
			return NULL;
		}

		INIT_LIST_HEAD(&mp->list);

		if (cmdcode == be16_to_cpu(SLI_CTNS_GID_FT))
			mp->virt = lpfc_mbuf_alloc(phba, MEM_PRI, &(mp->phys));
		else
			mp->virt = lpfc_mbuf_alloc(phba, 0, &(mp->phys));

		if (!mp->virt) {
			kfree(mp);
			if (mlist)
				lpfc_free_ct_rsp(phba, mlist);
			return NULL;
		}

		/* Queue it to a linked list */
		if (!mlist)
			mlist = mp;
		else
			list_add_tail(&mp->list, &mlist->list);

		bpl->tus.f.bdeFlags = BUFF_USE_RCV;
		/* build buffer ptr list for IOCB */
		bpl->addrLow = le32_to_cpu( putPaddrLow(mp->phys) );
		bpl->addrHigh = le32_to_cpu( putPaddrHigh(mp->phys) );
		bpl->tus.f.bdeSize = (uint16_t) cnt;
		bpl->tus.w = le32_to_cpu(bpl->tus.w);
		bpl++;

		i++;
		size -= cnt;
	}

	*entries = i;
	return mlist;
}

static int
lpfc_gen_req(struct lpfc_vport *vport, struct lpfc_dmabuf *bmp,
	     struct lpfc_dmabuf *inp, struct lpfc_dmabuf *outp,
	     void (*cmpl) (struct lpfc_hba *, struct lpfc_iocbq *,
		     struct lpfc_iocbq *),
	     struct lpfc_nodelist *ndlp, uint32_t usr_flg, uint32_t num_entry,
	     uint32_t tmo)
{
	struct lpfc_hba  *phba = vport->phba;
	struct lpfc_sli  *psli = &phba->sli;
	struct lpfc_sli_ring *pring = &psli->ring[LPFC_ELS_RING];
	IOCB_t *icmd;
	struct lpfc_iocbq *geniocb;

	/* Allocate buffer for  command iocb */
	geniocb = lpfc_sli_get_iocbq(phba);

	if (geniocb == NULL)
		return 1;

	icmd = &geniocb->iocb;
	icmd->un.genreq64.bdl.ulpIoTag32 = 0;
	icmd->un.genreq64.bdl.addrHigh = putPaddrHigh(bmp->phys);
	icmd->un.genreq64.bdl.addrLow = putPaddrLow(bmp->phys);
	icmd->un.genreq64.bdl.bdeFlags = BUFF_TYPE_BDL;
	icmd->un.genreq64.bdl.bdeSize = (num_entry * sizeof (struct ulp_bde64));

	if (usr_flg)
		geniocb->context3 = NULL;
	else
		geniocb->context3 = (uint8_t *) bmp;

	/* Save for completion so we can release these resources */
	geniocb->context1 = (uint8_t *) inp;
	geniocb->context2 = (uint8_t *) outp;

	/* Fill in payload, bp points to frame payload */
	icmd->ulpCommand = CMD_GEN_REQUEST64_CR;

	/* Fill in rest of iocb */
	icmd->un.genreq64.w5.hcsw.Fctl = (SI | LA);
	icmd->un.genreq64.w5.hcsw.Dfctl = 0;
	icmd->un.genreq64.w5.hcsw.Rctl = FC_UNSOL_CTL;
	icmd->un.genreq64.w5.hcsw.Type = FC_COMMON_TRANSPORT_ULP;

	if (!tmo) {
		 /* FC spec states we need 3 * ratov for CT requests */
		tmo = (3 * phba->fc_ratov);
	}
	icmd->ulpTimeout = tmo;
	icmd->ulpBdeCount = 1;
	icmd->ulpLe = 1;
	icmd->ulpClass = CLASS3;
	icmd->ulpContext = ndlp->nlp_rpi;

	/* Issue GEN REQ IOCB for NPORT <did> */
	lpfc_printf_log(phba, KERN_INFO, LOG_ELS,
			"%d:0119 Issue GEN REQ IOCB for NPORT x%x "
			"Data: x%x x%x\n", phba->brd_no, icmd->un.ulpWord[5],
			icmd->ulpIoTag, vport->port_state);
	geniocb->iocb_cmpl = cmpl;
	geniocb->drvrTimeout = icmd->ulpTimeout + LPFC_DRVR_TIMEOUT;
	geniocb->vport = vport;
	if (lpfc_sli_issue_iocb(phba, pring, geniocb, 0) == IOCB_ERROR) {
		lpfc_sli_release_iocbq(phba, geniocb);
		return 1;
	}

	return 0;
}

static int
lpfc_ct_cmd(struct lpfc_vport *vport, struct lpfc_dmabuf *inmp,
	    struct lpfc_dmabuf *bmp, struct lpfc_nodelist *ndlp,
	    void (*cmpl) (struct lpfc_hba *, struct lpfc_iocbq *,
			  struct lpfc_iocbq *),
	    uint32_t rsp_size)
{
	struct lpfc_hba  *phba = vport->phba;
	struct ulp_bde64 *bpl = (struct ulp_bde64 *) bmp->virt;
	struct lpfc_dmabuf *outmp;
	int cnt = 0, status;
	int cmdcode = ((struct lpfc_sli_ct_request *) inmp->virt)->
		CommandResponse.bits.CmdRsp;

	bpl++;			/* Skip past ct request */

	/* Put buffer(s) for ct rsp in bpl */
	outmp = lpfc_alloc_ct_rsp(phba, cmdcode, bpl, rsp_size, &cnt);
	if (!outmp)
		return -ENOMEM;

	status = lpfc_gen_req(vport, bmp, inmp, outmp, cmpl, ndlp, 0,
			      cnt+1, 0);
	if (status) {
		lpfc_free_ct_rsp(phba, outmp);
		return -ENOMEM;
	}
	return 0;
}

static int
lpfc_ns_rsp(struct lpfc_vport *vport, struct lpfc_dmabuf *mp, uint32_t Size)
{
	struct Scsi_Host *shost = lpfc_shost_from_vport(vport);
	struct lpfc_hba  *phba = vport->phba;
	struct lpfc_sli_ct_request *Response =
		(struct lpfc_sli_ct_request *) mp->virt;
	struct lpfc_nodelist *ndlp = NULL;
	struct lpfc_dmabuf *mlast, *next_mp;
	uint32_t *ctptr = (uint32_t *) & Response->un.gid.PortType;
	uint32_t Did, CTentry;
	int Cnt;
	struct list_head head;

	lpfc_set_disctmo(vport);


	list_add_tail(&head, &mp->list);
	list_for_each_entry_safe(mp, next_mp, &head, list) {
		mlast = mp;

		Cnt = Size  > FCELSSIZE ? FCELSSIZE : Size;

		Size -= Cnt;

		if (!ctptr) {
			ctptr = (uint32_t *) mlast->virt;
		} else
			Cnt -= 16;	/* subtract length of CT header */

		/* Loop through entire NameServer list of DIDs */
		while (Cnt >= sizeof (uint32_t)) {
			/* Get next DID from NameServer List */
			CTentry = *ctptr++;
			Did = ((be32_to_cpu(CTentry)) & Mask_DID);
			ndlp = NULL;
			/* Check for rscn processing or not */
			if (Did != vport->fc_myDID)
				ndlp = lpfc_setup_disc_node(vport, Did);
			if (ndlp) {
				lpfc_printf_log(phba, KERN_INFO, LOG_DISCOVERY,
						"%d:0238 Process x%x NameServer"
						" Rsp Data: x%x x%x x%x\n",
						phba->brd_no,
						Did, ndlp->nlp_flag,
						vport->fc_flag,
						vport->fc_rscn_id_cnt);
			} else {
				lpfc_printf_log(phba, KERN_INFO, LOG_DISCOVERY,
						"%d:0239 Skip x%x NameServer "
						"Rsp Data: x%x x%x x%x\n",
						phba->brd_no,
						Did, Size, vport->fc_flag,
						vport->fc_rscn_id_cnt);
			}
			if (CTentry & (be32_to_cpu(SLI_CT_LAST_ENTRY)))
				goto nsout1;
			Cnt -= sizeof (uint32_t);
		}
		ctptr = NULL;

	}

nsout1:
	list_del(&head);

	/*
	 * The driver has cycled through all Nports in the RSCN payload.
	 * Complete the handling by cleaning up and marking the
	 * current driver state.
	 */
	if (vport->port_state == LPFC_VPORT_READY) {
		lpfc_els_flush_rscn(vport);
		spin_lock_irq(shost->host_lock);
		vport->fc_flag |= FC_RSCN_MODE; /* we are still in RSCN mode */
		spin_unlock_irq(shost->host_lock);
	}
	return 0;
}




static void
lpfc_cmpl_ct_cmd_gid_ft(struct lpfc_hba *phba, struct lpfc_iocbq *cmdiocb,
			struct lpfc_iocbq *rspiocb)
{
	struct lpfc_vport *vport = cmdiocb->vport;
	IOCB_t *irsp;
	struct lpfc_dmabuf *bmp;
	struct lpfc_dmabuf *inp;
	struct lpfc_dmabuf *outp;
	struct lpfc_nodelist *ndlp;
	struct lpfc_sli_ct_request *CTrsp;
	int rc;

	/* we pass cmdiocb to state machine which needs rspiocb as well */
	cmdiocb->context_un.rsp_iocb = rspiocb;

	inp = (struct lpfc_dmabuf *) cmdiocb->context1;
	outp = (struct lpfc_dmabuf *) cmdiocb->context2;
	bmp = (struct lpfc_dmabuf *) cmdiocb->context3;

	irsp = &rspiocb->iocb;
	if (irsp->ulpStatus) {
		if ((irsp->ulpStatus == IOSTAT_LOCAL_REJECT) &&
			((irsp->un.ulpWord[4] == IOERR_SLI_DOWN) ||
			 (irsp->un.ulpWord[4] == IOERR_SLI_ABORTED)))
			goto out;

		/* Check for retry */
		if (vport->fc_ns_retry < LPFC_MAX_NS_RETRY) {
			vport->fc_ns_retry++;
			/* CT command is being retried */
			ndlp = lpfc_findnode_did(vport, NameServer_DID);
			if (ndlp && ndlp->nlp_state == NLP_STE_UNMAPPED_NODE) {
				rc = lpfc_ns_cmd(vport, ndlp, SLI_CTNS_GID_FT);
				if (rc == 0)
					goto out;
				}
			}
	} else {
		/* Good status, continue checking */
		CTrsp = (struct lpfc_sli_ct_request *) outp->virt;
		if (CTrsp->CommandResponse.bits.CmdRsp ==
		    be16_to_cpu(SLI_CT_RESPONSE_FS_ACC)) {
			lpfc_printf_log(phba, KERN_INFO, LOG_DISCOVERY,
					"%d:0208 NameServer Rsp "
					"Data: x%x\n",
					phba->brd_no,
					vport->fc_flag);
			lpfc_ns_rsp(vport, outp,
				    (uint32_t) (irsp->un.genreq64.bdl.bdeSize));
		} else if (CTrsp->CommandResponse.bits.CmdRsp ==
			   be16_to_cpu(SLI_CT_RESPONSE_FS_RJT)) {
			/* NameServer Rsp Error */
			lpfc_printf_log(phba, KERN_INFO, LOG_DISCOVERY,
					"%d:0240 NameServer Rsp Error "
					"Data: x%x x%x x%x x%x\n",
					phba->brd_no,
					CTrsp->CommandResponse.bits.CmdRsp,
					(uint32_t) CTrsp->ReasonCode,
					(uint32_t) CTrsp->Explanation,
					vport->fc_flag);
		} else {
			/* NameServer Rsp Error */
			lpfc_printf_log(phba,
					KERN_INFO,
					LOG_DISCOVERY,
					"%d:0241 NameServer Rsp Error "
					"Data: x%x x%x x%x x%x\n",
					phba->brd_no,
					CTrsp->CommandResponse.bits.CmdRsp,
					(uint32_t) CTrsp->ReasonCode,
					(uint32_t) CTrsp->Explanation,
					vport->fc_flag);
		}
	}
	/* Link up / RSCN discovery */
	lpfc_disc_start(vport);
out:
	lpfc_free_ct_rsp(phba, outp);
	lpfc_mbuf_free(phba, inp->virt, inp->phys);
	lpfc_mbuf_free(phba, bmp->virt, bmp->phys);
	kfree(inp);
	kfree(bmp);
	lpfc_sli_release_iocbq(phba, cmdiocb);
	return;
}

static void
lpfc_cmpl_ct_cmd_rft_id(struct lpfc_hba *phba, struct lpfc_iocbq *cmdiocb,
			struct lpfc_iocbq *rspiocb)
{
	struct lpfc_dmabuf *bmp;
	struct lpfc_dmabuf *inp;
	struct lpfc_dmabuf *outp;
	IOCB_t *irsp;
	struct lpfc_sli_ct_request *CTrsp;

	/* we pass cmdiocb to state machine which needs rspiocb as well */
	cmdiocb->context_un.rsp_iocb = rspiocb;

	inp = (struct lpfc_dmabuf *) cmdiocb->context1;
	outp = (struct lpfc_dmabuf *) cmdiocb->context2;
	bmp = (struct lpfc_dmabuf *) cmdiocb->context3;
	irsp = &rspiocb->iocb;

	CTrsp = (struct lpfc_sli_ct_request *) outp->virt;

	/* RFT request completes status <ulpStatus> CmdRsp <CmdRsp> */
	lpfc_printf_log(phba, KERN_INFO, LOG_DISCOVERY,
			"%d:0209 RFT request completes ulpStatus x%x "
			"CmdRsp x%x, Context x%x, Tag x%x\n",
			phba->brd_no, irsp->ulpStatus,
			CTrsp->CommandResponse.bits.CmdRsp,
			cmdiocb->iocb.ulpContext, cmdiocb->iocb.ulpIoTag);

	lpfc_free_ct_rsp(phba, outp);
	lpfc_mbuf_free(phba, inp->virt, inp->phys);
	lpfc_mbuf_free(phba, bmp->virt, bmp->phys);
	kfree(inp);
	kfree(bmp);
	lpfc_sli_release_iocbq(phba, cmdiocb);
	return;
}

static void
lpfc_cmpl_ct_cmd_rnn_id(struct lpfc_hba *phba, struct lpfc_iocbq *cmdiocb,
			struct lpfc_iocbq *rspiocb)
{
	lpfc_cmpl_ct_cmd_rft_id(phba, cmdiocb, rspiocb);
	return;
}

static void
lpfc_cmpl_ct_cmd_rsnn_nn(struct lpfc_hba *phba, struct lpfc_iocbq *cmdiocb,
			 struct lpfc_iocbq *rspiocb)
{
	lpfc_cmpl_ct_cmd_rft_id(phba, cmdiocb, rspiocb);
	return;
}

static void
lpfc_cmpl_ct_cmd_rff_id(struct lpfc_hba * phba, struct lpfc_iocbq * cmdiocb,
			 struct lpfc_iocbq * rspiocb)
{
	lpfc_cmpl_ct_cmd_rft_id(phba, cmdiocb, rspiocb);
	return;
}

void
lpfc_get_hba_sym_node_name(struct lpfc_hba *phba, uint8_t *symbp)
{
	char fwrev[16];

	lpfc_decode_firmware_rev(phba, fwrev, 0);

	sprintf(symbp, "Emulex %s FV%s DV%s", phba->ModelName,
		fwrev, lpfc_release_version);
	return;
}

/*
 * lpfc_ns_cmd
 * Description:
 *    Issue Cmd to NameServer
 *       SLI_CTNS_GID_FT
 *       LI_CTNS_RFT_ID
 */
int
lpfc_ns_cmd(struct lpfc_vport *vport, struct lpfc_nodelist * ndlp, int cmdcode)
{
	struct lpfc_hba *phba = vport->phba;
	struct lpfc_dmabuf *mp, *bmp;
	struct lpfc_sli_ct_request *CtReq;
	struct ulp_bde64 *bpl;
	void (*cmpl) (struct lpfc_hba *, struct lpfc_iocbq *,
		      struct lpfc_iocbq *) = NULL;
	uint32_t rsp_size = 1024;

	/* fill in BDEs for command */
	/* Allocate buffer for command payload */
	mp = kmalloc(sizeof (struct lpfc_dmabuf), GFP_KERNEL);
	if (!mp)
		goto ns_cmd_exit;

	INIT_LIST_HEAD(&mp->list);
	mp->virt = lpfc_mbuf_alloc(phba, MEM_PRI, &(mp->phys));
	if (!mp->virt)
		goto ns_cmd_free_mp;

	/* Allocate buffer for Buffer ptr list */
	bmp = kmalloc(sizeof (struct lpfc_dmabuf), GFP_KERNEL);
	if (!bmp)
		goto ns_cmd_free_mpvirt;

	INIT_LIST_HEAD(&bmp->list);
	bmp->virt = lpfc_mbuf_alloc(phba, MEM_PRI, &(bmp->phys));
	if (!bmp->virt)
		goto ns_cmd_free_bmp;

	/* NameServer Req */
	lpfc_printf_log(phba,
			KERN_INFO,
			LOG_DISCOVERY,
			"%d:0236 NameServer Req Data: x%x x%x x%x\n",
			phba->brd_no, cmdcode, vport->fc_flag,
			vport->fc_rscn_id_cnt);

	bpl = (struct ulp_bde64 *) bmp->virt;
	memset(bpl, 0, sizeof(struct ulp_bde64));
	bpl->addrHigh = le32_to_cpu( putPaddrHigh(mp->phys) );
	bpl->addrLow = le32_to_cpu( putPaddrLow(mp->phys) );
	bpl->tus.f.bdeFlags = 0;
	if (cmdcode == SLI_CTNS_GID_FT)
		bpl->tus.f.bdeSize = GID_REQUEST_SZ;
	else if (cmdcode == SLI_CTNS_RFT_ID)
		bpl->tus.f.bdeSize = RFT_REQUEST_SZ;
	else if (cmdcode == SLI_CTNS_RNN_ID)
		bpl->tus.f.bdeSize = RNN_REQUEST_SZ;
	else if (cmdcode == SLI_CTNS_RSNN_NN)
		bpl->tus.f.bdeSize = RSNN_REQUEST_SZ;
	else if (cmdcode == SLI_CTNS_RFF_ID)
		bpl->tus.f.bdeSize = RFF_REQUEST_SZ;
	else
		bpl->tus.f.bdeSize = 0;
	bpl->tus.w = le32_to_cpu(bpl->tus.w);

	CtReq = (struct lpfc_sli_ct_request *) mp->virt;
	memset(CtReq, 0, sizeof (struct lpfc_sli_ct_request));
	CtReq->RevisionId.bits.Revision = SLI_CT_REVISION;
	CtReq->RevisionId.bits.InId = 0;
	CtReq->FsType = SLI_CT_DIRECTORY_SERVICE;
	CtReq->FsSubType = SLI_CT_DIRECTORY_NAME_SERVER;
	CtReq->CommandResponse.bits.Size = 0;
	switch (cmdcode) {
	case SLI_CTNS_GID_FT:
		CtReq->CommandResponse.bits.CmdRsp =
		    be16_to_cpu(SLI_CTNS_GID_FT);
		CtReq->un.gid.Fc4Type = SLI_CTPT_FCP;
		if (vport->port_state < LPFC_VPORT_READY)
			vport->port_state = LPFC_NS_QRY;
		lpfc_set_disctmo(vport);
		cmpl = lpfc_cmpl_ct_cmd_gid_ft;
		rsp_size = FC_MAX_NS_RSP;
		break;

	case SLI_CTNS_RFT_ID:
		CtReq->CommandResponse.bits.CmdRsp =
		    be16_to_cpu(SLI_CTNS_RFT_ID);
		CtReq->un.rft.PortId = be32_to_cpu(vport->fc_myDID);
		CtReq->un.rft.fcpReg = 1;
		cmpl = lpfc_cmpl_ct_cmd_rft_id;
		break;

	case SLI_CTNS_RFF_ID:
		CtReq->CommandResponse.bits.CmdRsp =
			be16_to_cpu(SLI_CTNS_RFF_ID);
		CtReq->un.rff.PortId = be32_to_cpu(vport->fc_myDID);
		CtReq->un.rff.feature_res = 0;
		CtReq->un.rff.feature_tgt = 0;
		CtReq->un.rff.type_code = FC_FCP_DATA;
		CtReq->un.rff.feature_init = 1;
		cmpl = lpfc_cmpl_ct_cmd_rff_id;
		break;

	case SLI_CTNS_RNN_ID:
		CtReq->CommandResponse.bits.CmdRsp =
		    be16_to_cpu(SLI_CTNS_RNN_ID);
		CtReq->un.rnn.PortId = be32_to_cpu(vport->fc_myDID);
		memcpy(CtReq->un.rnn.wwnn,  &vport->fc_nodename,
		       sizeof (struct lpfc_name));
		cmpl = lpfc_cmpl_ct_cmd_rnn_id;
		break;

	case SLI_CTNS_RSNN_NN:
		CtReq->CommandResponse.bits.CmdRsp =
		    be16_to_cpu(SLI_CTNS_RSNN_NN);
		memcpy(CtReq->un.rsnn.wwnn, &vport->fc_nodename,
		       sizeof (struct lpfc_name));
		lpfc_get_hba_sym_node_name(phba, CtReq->un.rsnn.symbname);
		CtReq->un.rsnn.len = strlen(CtReq->un.rsnn.symbname);
		cmpl = lpfc_cmpl_ct_cmd_rsnn_nn;
		break;
	}

	if (!lpfc_ct_cmd(vport, mp, bmp, ndlp, cmpl, rsp_size))
		/* On success, The cmpl function will free the buffers */
		return 0;

	lpfc_mbuf_free(phba, bmp->virt, bmp->phys);
ns_cmd_free_bmp:
	kfree(bmp);
ns_cmd_free_mpvirt:
	lpfc_mbuf_free(phba, mp->virt, mp->phys);
ns_cmd_free_mp:
	kfree(mp);
ns_cmd_exit:
	return 1;
}

static void
lpfc_cmpl_ct_cmd_fdmi(struct lpfc_hba *phba, struct lpfc_iocbq *cmdiocb,
		      struct lpfc_iocbq * rspiocb)
{
	struct lpfc_dmabuf *bmp = cmdiocb->context3;
	struct lpfc_dmabuf *inp = cmdiocb->context1;
	struct lpfc_dmabuf *outp = cmdiocb->context2;
	struct lpfc_sli_ct_request *CTrsp = outp->virt;
	struct lpfc_sli_ct_request *CTcmd = inp->virt;
	struct lpfc_nodelist *ndlp;
	uint16_t fdmi_cmd = CTcmd->CommandResponse.bits.CmdRsp;
	uint16_t fdmi_rsp = CTrsp->CommandResponse.bits.CmdRsp;
	struct lpfc_vport *vport = cmdiocb->vport;

	ndlp = lpfc_findnode_did(vport, FDMI_DID);
	if (fdmi_rsp == be16_to_cpu(SLI_CT_RESPONSE_FS_RJT)) {
		/* FDMI rsp failed */
		lpfc_printf_log(phba, KERN_INFO, LOG_DISCOVERY,
				"%d:0220 FDMI rsp failed Data: x%x\n",
				phba->brd_no, be16_to_cpu(fdmi_cmd));
	}

	switch (be16_to_cpu(fdmi_cmd)) {
	case SLI_MGMT_RHBA:
		lpfc_fdmi_cmd(vport, ndlp, SLI_MGMT_RPA);
		break;

	case SLI_MGMT_RPA:
		break;

	case SLI_MGMT_DHBA:
		lpfc_fdmi_cmd(vport, ndlp, SLI_MGMT_DPRT);
		break;

	case SLI_MGMT_DPRT:
		lpfc_fdmi_cmd(vport, ndlp, SLI_MGMT_RHBA);
		break;
	}

	lpfc_free_ct_rsp(phba, outp);
	lpfc_mbuf_free(phba, inp->virt, inp->phys);
	lpfc_mbuf_free(phba, bmp->virt, bmp->phys);
	kfree(inp);
	kfree(bmp);
	lpfc_sli_release_iocbq(phba, cmdiocb);
	return;
}

int
lpfc_fdmi_cmd(struct lpfc_vport *vport, struct lpfc_nodelist *ndlp, int cmdcode)
{
	struct lpfc_hba *phba = vport->phba;
	struct lpfc_dmabuf *mp, *bmp;
	struct lpfc_sli_ct_request *CtReq;
	struct ulp_bde64 *bpl;
	uint32_t size;
	REG_HBA *rh;
	PORT_ENTRY *pe;
	REG_PORT_ATTRIBUTE *pab;
	ATTRIBUTE_BLOCK *ab;
	ATTRIBUTE_ENTRY *ae;
	void (*cmpl) (struct lpfc_hba *, struct lpfc_iocbq *,
		      struct lpfc_iocbq *);


	/* fill in BDEs for command */
	/* Allocate buffer for command payload */
	mp = kmalloc(sizeof (struct lpfc_dmabuf), GFP_KERNEL);
	if (!mp)
		goto fdmi_cmd_exit;

	mp->virt = lpfc_mbuf_alloc(phba, 0, &(mp->phys));
	if (!mp->virt)
		goto fdmi_cmd_free_mp;

	/* Allocate buffer for Buffer ptr list */
	bmp = kmalloc(sizeof (struct lpfc_dmabuf), GFP_KERNEL);
	if (!bmp)
		goto fdmi_cmd_free_mpvirt;

	bmp->virt = lpfc_mbuf_alloc(phba, 0, &(bmp->phys));
	if (!bmp->virt)
		goto fdmi_cmd_free_bmp;

	INIT_LIST_HEAD(&mp->list);
	INIT_LIST_HEAD(&bmp->list);

	/* FDMI request */
	lpfc_printf_log(phba, KERN_INFO, LOG_DISCOVERY,
		        "%d:0218 FDMI Request Data: x%x x%x x%x\n",
		        phba->brd_no,
			vport->fc_flag, vport->port_state, cmdcode);

	CtReq = (struct lpfc_sli_ct_request *) mp->virt;

	memset(CtReq, 0, sizeof(struct lpfc_sli_ct_request));
	CtReq->RevisionId.bits.Revision = SLI_CT_REVISION;
	CtReq->RevisionId.bits.InId = 0;

	CtReq->FsType = SLI_CT_MANAGEMENT_SERVICE;
	CtReq->FsSubType = SLI_CT_FDMI_Subtypes;
	size = 0;

	switch (cmdcode) {
	case SLI_MGMT_RHBA:
		{
			lpfc_vpd_t *vp = &phba->vpd;
			uint32_t i, j, incr;
			int len;

			CtReq->CommandResponse.bits.CmdRsp =
			    be16_to_cpu(SLI_MGMT_RHBA);
			CtReq->CommandResponse.bits.Size = 0;
			rh = (REG_HBA *) & CtReq->un.PortID;
			memcpy(&rh->hi.PortName, &vport->fc_sparam.portName,
			       sizeof (struct lpfc_name));
			/* One entry (port) per adapter */
			rh->rpl.EntryCnt = be32_to_cpu(1);
			memcpy(&rh->rpl.pe, &vport->fc_sparam.portName,
			       sizeof (struct lpfc_name));

			/* point to the HBA attribute block */
			size = 2 * sizeof (struct lpfc_name) + FOURBYTES;
			ab = (ATTRIBUTE_BLOCK *) ((uint8_t *) rh + size);
			ab->EntryCnt = 0;

			/* Point to the beginning of the first HBA attribute
			   entry */
			/* #1 HBA attribute entry */
			size += FOURBYTES;
			ae = (ATTRIBUTE_ENTRY *) ((uint8_t *) rh + size);
			ae->ad.bits.AttrType = be16_to_cpu(NODE_NAME);
			ae->ad.bits.AttrLen =  be16_to_cpu(FOURBYTES
						+ sizeof (struct lpfc_name));
			memcpy(&ae->un.NodeName, &vport->fc_sparam.nodeName,
			       sizeof (struct lpfc_name));
			ab->EntryCnt++;
			size += FOURBYTES + sizeof (struct lpfc_name);

			/* #2 HBA attribute entry */
			ae = (ATTRIBUTE_ENTRY *) ((uint8_t *) rh + size);
			ae->ad.bits.AttrType = be16_to_cpu(MANUFACTURER);
			strcpy(ae->un.Manufacturer, "Emulex Corporation");
			len = strlen(ae->un.Manufacturer);
			len += (len & 3) ? (4 - (len & 3)) : 4;
			ae->ad.bits.AttrLen = be16_to_cpu(FOURBYTES + len);
			ab->EntryCnt++;
			size += FOURBYTES + len;

			/* #3 HBA attribute entry */
			ae = (ATTRIBUTE_ENTRY *) ((uint8_t *) rh + size);
			ae->ad.bits.AttrType = be16_to_cpu(SERIAL_NUMBER);
			strcpy(ae->un.SerialNumber, phba->SerialNumber);
			len = strlen(ae->un.SerialNumber);
			len += (len & 3) ? (4 - (len & 3)) : 4;
			ae->ad.bits.AttrLen = be16_to_cpu(FOURBYTES + len);
			ab->EntryCnt++;
			size += FOURBYTES + len;

			/* #4 HBA attribute entry */
			ae = (ATTRIBUTE_ENTRY *) ((uint8_t *) rh + size);
			ae->ad.bits.AttrType = be16_to_cpu(MODEL);
			strcpy(ae->un.Model, phba->ModelName);
			len = strlen(ae->un.Model);
			len += (len & 3) ? (4 - (len & 3)) : 4;
			ae->ad.bits.AttrLen = be16_to_cpu(FOURBYTES + len);
			ab->EntryCnt++;
			size += FOURBYTES + len;

			/* #5 HBA attribute entry */
			ae = (ATTRIBUTE_ENTRY *) ((uint8_t *) rh + size);
			ae->ad.bits.AttrType = be16_to_cpu(MODEL_DESCRIPTION);
			strcpy(ae->un.ModelDescription, phba->ModelDesc);
			len = strlen(ae->un.ModelDescription);
			len += (len & 3) ? (4 - (len & 3)) : 4;
			ae->ad.bits.AttrLen = be16_to_cpu(FOURBYTES + len);
			ab->EntryCnt++;
			size += FOURBYTES + len;

			/* #6 HBA attribute entry */
			ae = (ATTRIBUTE_ENTRY *) ((uint8_t *) rh + size);
			ae->ad.bits.AttrType = be16_to_cpu(HARDWARE_VERSION);
			ae->ad.bits.AttrLen = be16_to_cpu(FOURBYTES + 8);
			/* Convert JEDEC ID to ascii for hardware version */
			incr = vp->rev.biuRev;
			for (i = 0; i < 8; i++) {
				j = (incr & 0xf);
				if (j <= 9)
					ae->un.HardwareVersion[7 - i] =
					    (char)((uint8_t) 0x30 +
						   (uint8_t) j);
				else
					ae->un.HardwareVersion[7 - i] =
					    (char)((uint8_t) 0x61 +
						   (uint8_t) (j - 10));
				incr = (incr >> 4);
			}
			ab->EntryCnt++;
			size += FOURBYTES + 8;

			/* #7 HBA attribute entry */
			ae = (ATTRIBUTE_ENTRY *) ((uint8_t *) rh + size);
			ae->ad.bits.AttrType = be16_to_cpu(DRIVER_VERSION);
			strcpy(ae->un.DriverVersion, lpfc_release_version);
			len = strlen(ae->un.DriverVersion);
			len += (len & 3) ? (4 - (len & 3)) : 4;
			ae->ad.bits.AttrLen = be16_to_cpu(FOURBYTES + len);
			ab->EntryCnt++;
			size += FOURBYTES + len;

			/* #8 HBA attribute entry */
			ae = (ATTRIBUTE_ENTRY *) ((uint8_t *) rh + size);
			ae->ad.bits.AttrType = be16_to_cpu(OPTION_ROM_VERSION);
			strcpy(ae->un.OptionROMVersion, phba->OptionROMVersion);
			len = strlen(ae->un.OptionROMVersion);
			len += (len & 3) ? (4 - (len & 3)) : 4;
			ae->ad.bits.AttrLen = be16_to_cpu(FOURBYTES + len);
			ab->EntryCnt++;
			size += FOURBYTES + len;

			/* #9 HBA attribute entry */
			ae = (ATTRIBUTE_ENTRY *) ((uint8_t *) rh + size);
			ae->ad.bits.AttrType = be16_to_cpu(FIRMWARE_VERSION);
			lpfc_decode_firmware_rev(phba, ae->un.FirmwareVersion,
				1);
			len = strlen(ae->un.FirmwareVersion);
			len += (len & 3) ? (4 - (len & 3)) : 4;
			ae->ad.bits.AttrLen = be16_to_cpu(FOURBYTES + len);
			ab->EntryCnt++;
			size += FOURBYTES + len;

			/* #10 HBA attribute entry */
			ae = (ATTRIBUTE_ENTRY *) ((uint8_t *) rh + size);
			ae->ad.bits.AttrType = be16_to_cpu(OS_NAME_VERSION);
			sprintf(ae->un.OsNameVersion, "%s %s %s",
				init_utsname()->sysname,
				init_utsname()->release,
				init_utsname()->version);
			len = strlen(ae->un.OsNameVersion);
			len += (len & 3) ? (4 - (len & 3)) : 4;
			ae->ad.bits.AttrLen = be16_to_cpu(FOURBYTES + len);
			ab->EntryCnt++;
			size += FOURBYTES + len;

			/* #11 HBA attribute entry */
			ae = (ATTRIBUTE_ENTRY *) ((uint8_t *) rh + size);
			ae->ad.bits.AttrType = be16_to_cpu(MAX_CT_PAYLOAD_LEN);
			ae->ad.bits.AttrLen = be16_to_cpu(FOURBYTES + 4);
			ae->un.MaxCTPayloadLen = (65 * 4096);
			ab->EntryCnt++;
			size += FOURBYTES + 4;

			ab->EntryCnt = be32_to_cpu(ab->EntryCnt);
			/* Total size */
			size = GID_REQUEST_SZ - 4 + size;
		}
		break;

	case SLI_MGMT_RPA:
		{
			lpfc_vpd_t *vp;
			struct serv_parm *hsp;
			int len;

			vp = &phba->vpd;

			CtReq->CommandResponse.bits.CmdRsp =
			    be16_to_cpu(SLI_MGMT_RPA);
			CtReq->CommandResponse.bits.Size = 0;
			pab = (REG_PORT_ATTRIBUTE *) & CtReq->un.PortID;
			size = sizeof (struct lpfc_name) + FOURBYTES;
			memcpy((uint8_t *) & pab->PortName,
			       (uint8_t *) & vport->fc_sparam.portName,
			       sizeof (struct lpfc_name));
			pab->ab.EntryCnt = 0;

			/* #1 Port attribute entry */
			ae = (ATTRIBUTE_ENTRY *) ((uint8_t *) pab + size);
			ae->ad.bits.AttrType = be16_to_cpu(SUPPORTED_FC4_TYPES);
			ae->ad.bits.AttrLen = be16_to_cpu(FOURBYTES + 32);
			ae->un.SupportFC4Types[2] = 1;
			ae->un.SupportFC4Types[7] = 1;
			pab->ab.EntryCnt++;
			size += FOURBYTES + 32;

			/* #2 Port attribute entry */
			ae = (ATTRIBUTE_ENTRY *) ((uint8_t *) pab + size);
			ae->ad.bits.AttrType = be16_to_cpu(SUPPORTED_SPEED);
			ae->ad.bits.AttrLen = be16_to_cpu(FOURBYTES + 4);

			ae->un.SupportSpeed = 0;
			if (phba->lmt & LMT_10Gb)
				ae->un.SupportSpeed = HBA_PORTSPEED_10GBIT;
			if (phba->lmt & LMT_8Gb)
				ae->un.SupportSpeed |= HBA_PORTSPEED_8GBIT;
			if (phba->lmt & LMT_4Gb)
				ae->un.SupportSpeed |= HBA_PORTSPEED_4GBIT;
			if (phba->lmt & LMT_2Gb)
				ae->un.SupportSpeed |= HBA_PORTSPEED_2GBIT;
			if (phba->lmt & LMT_1Gb)
				ae->un.SupportSpeed |= HBA_PORTSPEED_1GBIT;

			pab->ab.EntryCnt++;
			size += FOURBYTES + 4;

			/* #3 Port attribute entry */
			ae = (ATTRIBUTE_ENTRY *) ((uint8_t *) pab + size);
			ae->ad.bits.AttrType = be16_to_cpu(PORT_SPEED);
			ae->ad.bits.AttrLen = be16_to_cpu(FOURBYTES + 4);
			switch(phba->fc_linkspeed) {
				case LA_1GHZ_LINK:
					ae->un.PortSpeed = HBA_PORTSPEED_1GBIT;
				break;
				case LA_2GHZ_LINK:
					ae->un.PortSpeed = HBA_PORTSPEED_2GBIT;
				break;
				case LA_4GHZ_LINK:
					ae->un.PortSpeed = HBA_PORTSPEED_4GBIT;
				break;
				case LA_8GHZ_LINK:
					ae->un.PortSpeed = HBA_PORTSPEED_8GBIT;
				break;
				default:
					ae->un.PortSpeed =
						HBA_PORTSPEED_UNKNOWN;
				break;
			}
			pab->ab.EntryCnt++;
			size += FOURBYTES + 4;

			/* #4 Port attribute entry */
			ae = (ATTRIBUTE_ENTRY *) ((uint8_t *) pab + size);
			ae->ad.bits.AttrType = be16_to_cpu(MAX_FRAME_SIZE);
			ae->ad.bits.AttrLen = be16_to_cpu(FOURBYTES + 4);
			hsp = (struct serv_parm *) & vport->fc_sparam;
			ae->un.MaxFrameSize =
			    (((uint32_t) hsp->cmn.
			      bbRcvSizeMsb) << 8) | (uint32_t) hsp->cmn.
			    bbRcvSizeLsb;
			pab->ab.EntryCnt++;
			size += FOURBYTES + 4;

			/* #5 Port attribute entry */
			ae = (ATTRIBUTE_ENTRY *) ((uint8_t *) pab + size);
			ae->ad.bits.AttrType = be16_to_cpu(OS_DEVICE_NAME);
			strcpy((char *)ae->un.OsDeviceName, LPFC_DRIVER_NAME);
			len = strlen((char *)ae->un.OsDeviceName);
			len += (len & 3) ? (4 - (len & 3)) : 4;
			ae->ad.bits.AttrLen = be16_to_cpu(FOURBYTES + len);
			pab->ab.EntryCnt++;
			size += FOURBYTES + len;

			if (phba->cfg_fdmi_on == 2) {
				/* #6 Port attribute entry */
				ae = (ATTRIBUTE_ENTRY *) ((uint8_t *) pab +
							  size);
				ae->ad.bits.AttrType = be16_to_cpu(HOST_NAME);
				sprintf(ae->un.HostName, "%s",
					init_utsname()->nodename);
				len = strlen(ae->un.HostName);
				len += (len & 3) ? (4 - (len & 3)) : 4;
				ae->ad.bits.AttrLen =
				    be16_to_cpu(FOURBYTES + len);
				pab->ab.EntryCnt++;
				size += FOURBYTES + len;
			}

			pab->ab.EntryCnt = be32_to_cpu(pab->ab.EntryCnt);
			/* Total size */
			size = GID_REQUEST_SZ - 4 + size;
		}
		break;

	case SLI_MGMT_DHBA:
		CtReq->CommandResponse.bits.CmdRsp = be16_to_cpu(SLI_MGMT_DHBA);
		CtReq->CommandResponse.bits.Size = 0;
		pe = (PORT_ENTRY *) & CtReq->un.PortID;
		memcpy((uint8_t *) & pe->PortName,
		       (uint8_t *) & vport->fc_sparam.portName,
		       sizeof (struct lpfc_name));
		size = GID_REQUEST_SZ - 4 + sizeof (struct lpfc_name);
		break;

	case SLI_MGMT_DPRT:
		CtReq->CommandResponse.bits.CmdRsp = be16_to_cpu(SLI_MGMT_DPRT);
		CtReq->CommandResponse.bits.Size = 0;
		pe = (PORT_ENTRY *) & CtReq->un.PortID;
		memcpy((uint8_t *) & pe->PortName,
		       (uint8_t *) & vport->fc_sparam.portName,
		       sizeof (struct lpfc_name));
		size = GID_REQUEST_SZ - 4 + sizeof (struct lpfc_name);
		break;
	}

	bpl = (struct ulp_bde64 *) bmp->virt;
	bpl->addrHigh = le32_to_cpu( putPaddrHigh(mp->phys) );
	bpl->addrLow = le32_to_cpu( putPaddrLow(mp->phys) );
	bpl->tus.f.bdeFlags = 0;
	bpl->tus.f.bdeSize = size;
	bpl->tus.w = le32_to_cpu(bpl->tus.w);

	cmpl = lpfc_cmpl_ct_cmd_fdmi;

	if (!lpfc_ct_cmd(vport, mp, bmp, ndlp, cmpl, FC_MAX_NS_RSP))
		return 0;

	lpfc_mbuf_free(phba, bmp->virt, bmp->phys);
fdmi_cmd_free_bmp:
	kfree(bmp);
fdmi_cmd_free_mpvirt:
	lpfc_mbuf_free(phba, mp->virt, mp->phys);
fdmi_cmd_free_mp:
	kfree(mp);
fdmi_cmd_exit:
	/* Issue FDMI request failed */
	lpfc_printf_log(phba, KERN_INFO, LOG_DISCOVERY,
		        "%d:0244 Issue FDMI request failed Data: x%x\n",
		        phba->brd_no, cmdcode);
	return 1;
}

void
lpfc_fdmi_tmo(unsigned long ptr)
{
	struct lpfc_vport *vport = (struct lpfc_vport *)ptr;
	struct lpfc_hba   *phba = vport->phba;
	unsigned long iflag;

	spin_lock_irqsave(&vport->work_port_lock, iflag);
	if (!(vport->work_port_events & WORKER_FDMI_TMO)) {
		vport->work_port_events |= WORKER_FDMI_TMO;
		if (phba->work_wait)
			wake_up(phba->work_wait);
	}
	spin_unlock_irqrestore(&vport->work_port_lock, iflag);
}

void
lpfc_fdmi_timeout_handler(struct lpfc_vport *vport)
{
	struct lpfc_nodelist *ndlp;

	ndlp = lpfc_findnode_did(vport, FDMI_DID);
	if (ndlp) {
		if (init_utsname()->nodename[0] != '\0')
			lpfc_fdmi_cmd(vport, ndlp, SLI_MGMT_DHBA);
		else
			mod_timer(&vport->fc_fdmitmo, jiffies + HZ * 60);
	}
	return;
}

void
lpfc_decode_firmware_rev(struct lpfc_hba *phba, char *fwrevision, int flag)
{
	struct lpfc_sli *psli = &phba->sli;
	lpfc_vpd_t *vp = &phba->vpd;
	uint32_t b1, b2, b3, b4, i, rev;
	char c;
	uint32_t *ptr, str[4];
	uint8_t *fwname;

	if (vp->rev.rBit) {
		if (psli->sli_flag & LPFC_SLI2_ACTIVE)
			rev = vp->rev.sli2FwRev;
		else
			rev = vp->rev.sli1FwRev;

		b1 = (rev & 0x0000f000) >> 12;
		b2 = (rev & 0x00000f00) >> 8;
		b3 = (rev & 0x000000c0) >> 6;
		b4 = (rev & 0x00000030) >> 4;

		switch (b4) {
		case 0:
			c = 'N';
			break;
		case 1:
			c = 'A';
			break;
		case 2:
			c = 'B';
			break;
		default:
			c = 0;
			break;
		}
		b4 = (rev & 0x0000000f);

		if (psli->sli_flag & LPFC_SLI2_ACTIVE)
			fwname = vp->rev.sli2FwName;
		else
			fwname = vp->rev.sli1FwName;

		for (i = 0; i < 16; i++)
			if (fwname[i] == 0x20)
				fwname[i] = 0;

		ptr = (uint32_t*)fwname;

		for (i = 0; i < 3; i++)
			str[i] = be32_to_cpu(*ptr++);

		if (c == 0) {
			if (flag)
				sprintf(fwrevision, "%d.%d%d (%s)",
					b1, b2, b3, (char *)str);
			else
				sprintf(fwrevision, "%d.%d%d", b1,
					b2, b3);
		} else {
			if (flag)
				sprintf(fwrevision, "%d.%d%d%c%d (%s)",
					b1, b2, b3, c,
					b4, (char *)str);
			else
				sprintf(fwrevision, "%d.%d%d%c%d",
					b1, b2, b3, c, b4);
		}
	} else {
		rev = vp->rev.smFwRev;

		b1 = (rev & 0xff000000) >> 24;
		b2 = (rev & 0x00f00000) >> 20;
		b3 = (rev & 0x000f0000) >> 16;
		c  = (rev & 0x0000ff00) >> 8;
		b4 = (rev & 0x000000ff);

		if (flag)
			sprintf(fwrevision, "%d.%d%d%c%d ", b1,
				b2, b3, c, b4);
		else
			sprintf(fwrevision, "%d.%d%d%c%d ", b1,
				b2, b3, c, b4);
	}
	return;
}
