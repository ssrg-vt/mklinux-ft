/*
	Mantis PCI bridge driver

	Copyright (C) 2005, 2006 Manu Abraham (abraham.manu@gmail.com)

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "mantis_common.h"
#include "mantis_hif.h"
#include "mantis_link.h" /* temporary due to physical layer stuff */

static int mantis_hif_data_available(struct mantis_ca *ca)
{
	struct mantis_pci *mantis = ca->ca_priv;
	int rc = 0;

	if (wait_event_interruptible_timeout(ca->hif_data_wq,
					     ca->sbuf_status & MANTIS_SBUF_DATA_AVAIL,
					     msecs_to_jiffies(500)) == -ERESTARTSYS) {

		dprintk(verbose, MANTIS_ERROR, 1, "Adapter(%d) Slot(0): HIF Read wait event timeout !", mantis->num);
		rc = -EREMOTEIO;
	}
	ca->sbuf_status &= ~MANTIS_SBUF_DATA_AVAIL;
	udelay(2);
	return rc;
}

static int mantis_hif_sbuf_opdone_wait(struct mantis_ca *ca)
{
	struct mantis_pci *mantis = ca->ca_priv;
	int rc = 0;

	if (wait_event_interruptible_timeout(ca->hif_opdone_wq,
					     ca->hif_event & MANTIS_SBUF_OPDONE,
					     msecs_to_jiffies(500)) == -ERESTARTSYS) {

		dprintk(verbose, MANTIS_ERROR, 1, "Adapter(%d) Slot(0): Smart buffer operation timeout !", mantis->num);
		rc = -EREMOTEIO;
	}
	ca->hif_event &= ~MANTIS_SBUF_OPDONE;
	udelay(5);
	return rc;
}


int mantis_hif_read_mem(struct mantis_ca *ca, u32 addr)
{
	struct mantis_pci *mantis = ca->ca_priv;
	u32 hif_addr = 0, data, count = 4;

	dprintk(verbose, MANTIS_DEBUG, 1, "Adapter(%d) Slot(0): Request HIF Mem Read", mantis->num);
	hif_addr |=  MANTIS_GPIF_HIFRDWRN;
	hif_addr &= ~MANTIS_GPIF_PCMCIAREG;
	hif_addr &= ~MANTIS_GPIF_PCMCIAIOM;
	hif_addr |=  addr;

	mmwrite(hif_addr | MANTIS_HIF_STATUS, MANTIS_GPIF_BRADDR);
	mmwrite(count, MANTIS_GPIF_BRBYTES);

	udelay(20);

	mmwrite(hif_addr, MANTIS_GPIF_ADDR);
	if (mantis_hif_data_available(ca) != 0) {
		dprintk(verbose, MANTIS_ERROR, 1, "Adapter(%d) Slot(0): GPIF Smart Buffer burst read failed", mantis->num);
		return -EREMOTEIO;
	}
	if (mantis_hif_sbuf_opdone_wait(ca) != 0) {
		dprintk(verbose, MANTIS_ERROR, 1, "Adapter(%d) Slot(0): GPIF Smart Buffer operation failed", mantis->num);
		return -EREMOTEIO;
	}
	data = mmread(MANTIS_GPIF_DIN);

	return (data >> 24) & 0xff;
}

int mantis_hif_write_mem(struct mantis_ca *ca, u32 addr, u8 data)
{
	struct mantis_slot *slot = ca->slot;
	struct mantis_pci *mantis = ca->ca_priv;
	u32 hif_addr = 0;

	dprintk(verbose, MANTIS_DEBUG, 1, "Adapter(%d) Slot(0): Request HIF Mem Write", mantis->num);
	hif_addr &= ~MANTIS_GPIF_HIFRDWRN;
	hif_addr &= ~MANTIS_GPIF_PCMCIAREG;
	hif_addr &= ~MANTIS_GPIF_PCMCIAIOM;
	hif_addr |= addr;

	mmwrite(slot->slave_cfg, MANTIS_GPIF_CFGSLA); /* Slot0 alone for now */

	mmwrite(hif_addr | MANTIS_HIF_STATUS, MANTIS_GPIF_ADDR);
	mmwrite(data, MANTIS_GPIF_DOUT);
	ca->hif_job_queue = MANTIS_HIF_MEMWR;

	if (mantis_hif_sbuf_opdone_wait(ca) != 0) {
		ca->hif_job_queue &= ~MANTIS_HIF_MEMWR;
		dprintk(verbose, MANTIS_ERROR, 1, "Adapter(%d) Slot(0): HIF Smart Buffer operation failed", mantis->num);
		return -EREMOTEIO;
	}
	ca->hif_job_queue &= ~MANTIS_HIF_MEMWR;
	return 0;
}

int mantis_hif_read_iom(struct mantis_ca *ca, u32 addr)
{
	struct mantis_pci *mantis = ca->ca_priv;
	u32 data, hif_addr = 0;

	dprintk(verbose, MANTIS_DEBUG, 1, "Adapter(%d) Slot(0): Request HIF I/O Read", mantis->num);
	hif_addr &= ~MANTIS_GPIF_PCMCIAREG;
	hif_addr |=  MANTIS_GPIF_HIFRDWRN;
	hif_addr |=  MANTIS_GPIF_PCMCIAIOM;
	hif_addr |=  addr;

	mmwrite(hif_addr | MANTIS_HIF_STATUS, MANTIS_GPIF_ADDR);
	ca->hif_job_queue = MANTIS_HIF_IOMRD;

	if (mantis_hif_sbuf_opdone_wait(ca) != 0) {
		ca->hif_job_queue &= ~MANTIS_HIF_IOMRD;
		dprintk(verbose, MANTIS_ERROR, 1, "Adapter(%d) Slot(0): HIF Smart Buffer operation failed", mantis->num);
		return -EREMOTEIO;
	}
	udelay(50);
	ca->hif_job_queue &= ~MANTIS_HIF_IOMRD;
	data = mmread(MANTIS_GPIF_DIN);
	hif_addr |= MANTIS_GPIF_PCMCIAREG;
	mmwrite(hif_addr, MANTIS_GPIF_ADDR);

	return (u8) data;
}

int mantis_hif_write_iom(struct mantis_ca *ca, u32 addr, u8 data)
{
	struct mantis_pci *mantis = ca->ca_priv;
	u32 hif_addr = 0;

	dprintk(verbose, MANTIS_DEBUG, 1, "Adapter(%d) Slot(0): Request HIF I/O Write", mantis->num);
	hif_addr &= ~MANTIS_GPIF_PCMCIAREG;
	hif_addr &= ~MANTIS_GPIF_HIFRDWRN;
	hif_addr |=  MANTIS_GPIF_PCMCIAIOM;
	hif_addr |=  addr;

	mmwrite(hif_addr | MANTIS_HIF_STATUS, MANTIS_GPIF_ADDR);
	mmwrite(data, MANTIS_GPIF_DOUT);

	ca->hif_job_queue = MANTIS_HIF_IOMWR;
	if (mantis_hif_sbuf_opdone_wait(ca) != 0) {
		ca->hif_job_queue &= ~MANTIS_HIF_IOMWR;
		dprintk(verbose, MANTIS_ERROR, 1, "Adapter(%d) Slot(0): HIF Smart Buffer operation failed", mantis->num);
		return -EREMOTEIO;
	}
	udelay(50);
	ca->hif_job_queue &= ~MANTIS_HIF_IOMWR;
	hif_addr |= MANTIS_GPIF_PCMCIAREG;
	mmwrite(hif_addr, MANTIS_GPIF_ADDR);

	return 0;
}

int mantis_hif_init(struct mantis_ca *ca)
{
	struct mantis_slot *slot = ca->slot;
	struct mantis_pci *mantis = ca->ca_priv;
	u32 irqcfg;

	slot[0].slave_cfg = 0x70773028;
	dprintk(verbose, MANTIS_ERROR, 1, "Adapter(%d) Initializing Mantis Host Interface", mantis->num);
	init_waitqueue_head(&ca->hif_data_wq);
	init_waitqueue_head(&ca->hif_opdone_wq);

	irqcfg  = mmread(MANTIS_GPIF_IRQCFG);
	irqcfg |= MANTIS_MASK_BRRDY;
	mmwrite(irqcfg, MANTIS_GPIF_IRQCFG);

	return 0;
}

void mantis_hif_exit(struct mantis_ca *ca)
{
	struct mantis_pci *mantis = ca->ca_priv;
	u32 irqcfg;

	dprintk(verbose, MANTIS_ERROR, 1, "Adapter(%d) Exiting Mantis Host Interface", mantis->num);
	irqcfg = mmread(MANTIS_GPIF_IRQCFG);
	irqcfg &= ~MANTIS_MASK_BRRDY;
	mmwrite(irqcfg, MANTIS_GPIF_IRQCFG);
}
