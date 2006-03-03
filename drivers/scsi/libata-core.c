/*
 *  libata-core.c - helper library for ATA
 *
 *  Maintained by:  Jeff Garzik <jgarzik@pobox.com>
 *    		    Please ALWAYS copy linux-ide@vger.kernel.org
 *		    on emails.
 *
 *  Copyright 2003-2004 Red Hat, Inc.  All rights reserved.
 *  Copyright 2003-2004 Jeff Garzik
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *
 *  libata documentation is available via 'make {ps|pdf}docs',
 *  as Documentation/DocBook/libata.*
 *
 *  Hardware documentation available from http://www.t13.org/ and
 *  http://www.sata-io.org/
 *
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/spinlock.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/completion.h>
#include <linux/suspend.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/scatterlist.h>
#include <scsi/scsi.h>
#include "scsi_priv.h"
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_host.h>
#include <linux/libata.h>
#include <asm/io.h>
#include <asm/semaphore.h>
#include <asm/byteorder.h>

#include "libata.h"

static unsigned int ata_dev_init_params(struct ata_port *ap,
					struct ata_device *dev);
static void ata_set_mode(struct ata_port *ap);
static void ata_dev_set_xfermode(struct ata_port *ap, struct ata_device *dev);
static unsigned int ata_get_mode_mask(const struct ata_port *ap, int shift);
static int fgb(u32 bitmap);
static int ata_choose_xfer_mode(const struct ata_port *ap,
				u8 *xfer_mode_out,
				unsigned int *xfer_shift_out);

static unsigned int ata_unique_id = 1;
static struct workqueue_struct *ata_wq;

int atapi_enabled = 0;
module_param(atapi_enabled, int, 0444);
MODULE_PARM_DESC(atapi_enabled, "Enable discovery of ATAPI devices (0=off, 1=on)");

int libata_fua = 0;
module_param_named(fua, libata_fua, int, 0444);
MODULE_PARM_DESC(fua, "FUA support (0=off, 1=on)");

MODULE_AUTHOR("Jeff Garzik");
MODULE_DESCRIPTION("Library module for ATA devices");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);


/**
 *	ata_tf_to_fis - Convert ATA taskfile to SATA FIS structure
 *	@tf: Taskfile to convert
 *	@fis: Buffer into which data will output
 *	@pmp: Port multiplier port
 *
 *	Converts a standard ATA taskfile to a Serial ATA
 *	FIS structure (Register - Host to Device).
 *
 *	LOCKING:
 *	Inherited from caller.
 */

void ata_tf_to_fis(const struct ata_taskfile *tf, u8 *fis, u8 pmp)
{
	fis[0] = 0x27;	/* Register - Host to Device FIS */
	fis[1] = (pmp & 0xf) | (1 << 7); /* Port multiplier number,
					    bit 7 indicates Command FIS */
	fis[2] = tf->command;
	fis[3] = tf->feature;

	fis[4] = tf->lbal;
	fis[5] = tf->lbam;
	fis[6] = tf->lbah;
	fis[7] = tf->device;

	fis[8] = tf->hob_lbal;
	fis[9] = tf->hob_lbam;
	fis[10] = tf->hob_lbah;
	fis[11] = tf->hob_feature;

	fis[12] = tf->nsect;
	fis[13] = tf->hob_nsect;
	fis[14] = 0;
	fis[15] = tf->ctl;

	fis[16] = 0;
	fis[17] = 0;
	fis[18] = 0;
	fis[19] = 0;
}

/**
 *	ata_tf_from_fis - Convert SATA FIS to ATA taskfile
 *	@fis: Buffer from which data will be input
 *	@tf: Taskfile to output
 *
 *	Converts a serial ATA FIS structure to a standard ATA taskfile.
 *
 *	LOCKING:
 *	Inherited from caller.
 */

void ata_tf_from_fis(const u8 *fis, struct ata_taskfile *tf)
{
	tf->command	= fis[2];	/* status */
	tf->feature	= fis[3];	/* error */

	tf->lbal	= fis[4];
	tf->lbam	= fis[5];
	tf->lbah	= fis[6];
	tf->device	= fis[7];

	tf->hob_lbal	= fis[8];
	tf->hob_lbam	= fis[9];
	tf->hob_lbah	= fis[10];

	tf->nsect	= fis[12];
	tf->hob_nsect	= fis[13];
}

static const u8 ata_rw_cmds[] = {
	/* pio multi */
	ATA_CMD_READ_MULTI,
	ATA_CMD_WRITE_MULTI,
	ATA_CMD_READ_MULTI_EXT,
	ATA_CMD_WRITE_MULTI_EXT,
	0,
	0,
	0,
	ATA_CMD_WRITE_MULTI_FUA_EXT,
	/* pio */
	ATA_CMD_PIO_READ,
	ATA_CMD_PIO_WRITE,
	ATA_CMD_PIO_READ_EXT,
	ATA_CMD_PIO_WRITE_EXT,
	0,
	0,
	0,
	0,
	/* dma */
	ATA_CMD_READ,
	ATA_CMD_WRITE,
	ATA_CMD_READ_EXT,
	ATA_CMD_WRITE_EXT,
	0,
	0,
	0,
	ATA_CMD_WRITE_FUA_EXT
};

/**
 *	ata_rwcmd_protocol - set taskfile r/w commands and protocol
 *	@qc: command to examine and configure
 *
 *	Examine the device configuration and tf->flags to calculate 
 *	the proper read/write commands and protocol to use.
 *
 *	LOCKING:
 *	caller.
 */
int ata_rwcmd_protocol(struct ata_queued_cmd *qc)
{
	struct ata_taskfile *tf = &qc->tf;
	struct ata_device *dev = qc->dev;
	u8 cmd;

	int index, fua, lba48, write;
 
	fua = (tf->flags & ATA_TFLAG_FUA) ? 4 : 0;
	lba48 = (tf->flags & ATA_TFLAG_LBA48) ? 2 : 0;
	write = (tf->flags & ATA_TFLAG_WRITE) ? 1 : 0;

	if (dev->flags & ATA_DFLAG_PIO) {
		tf->protocol = ATA_PROT_PIO;
		index = dev->multi_count ? 0 : 8;
	} else if (lba48 && (qc->ap->flags & ATA_FLAG_PIO_LBA48)) {
		/* Unable to use DMA due to host limitation */
		tf->protocol = ATA_PROT_PIO;
		index = dev->multi_count ? 0 : 8;
	} else {
		tf->protocol = ATA_PROT_DMA;
		index = 16;
	}

	cmd = ata_rw_cmds[index + fua + lba48 + write];
	if (cmd) {
		tf->command = cmd;
		return 0;
	}
	return -1;
}

static const char * const xfer_mode_str[] = {
	"UDMA/16",
	"UDMA/25",
	"UDMA/33",
	"UDMA/44",
	"UDMA/66",
	"UDMA/100",
	"UDMA/133",
	"UDMA7",
	"MWDMA0",
	"MWDMA1",
	"MWDMA2",
	"PIO0",
	"PIO1",
	"PIO2",
	"PIO3",
	"PIO4",
};

/**
 *	ata_udma_string - convert UDMA bit offset to string
 *	@mask: mask of bits supported; only highest bit counts.
 *
 *	Determine string which represents the highest speed
 *	(highest bit in @udma_mask).
 *
 *	LOCKING:
 *	None.
 *
 *	RETURNS:
 *	Constant C string representing highest speed listed in
 *	@udma_mask, or the constant C string "<n/a>".
 */

static const char *ata_mode_string(unsigned int mask)
{
	int i;

	for (i = 7; i >= 0; i--)
		if (mask & (1 << i))
			goto out;
	for (i = ATA_SHIFT_MWDMA + 2; i >= ATA_SHIFT_MWDMA; i--)
		if (mask & (1 << i))
			goto out;
	for (i = ATA_SHIFT_PIO + 4; i >= ATA_SHIFT_PIO; i--)
		if (mask & (1 << i))
			goto out;

	return "<n/a>";

out:
	return xfer_mode_str[i];
}

/**
 *	ata_pio_devchk - PATA device presence detection
 *	@ap: ATA channel to examine
 *	@device: Device to examine (starting at zero)
 *
 *	This technique was originally described in
 *	Hale Landis's ATADRVR (www.ata-atapi.com), and
 *	later found its way into the ATA/ATAPI spec.
 *
 *	Write a pattern to the ATA shadow registers,
 *	and if a device is present, it will respond by
 *	correctly storing and echoing back the
 *	ATA shadow register contents.
 *
 *	LOCKING:
 *	caller.
 */

static unsigned int ata_pio_devchk(struct ata_port *ap,
				   unsigned int device)
{
	struct ata_ioports *ioaddr = &ap->ioaddr;
	u8 nsect, lbal;

	ap->ops->dev_select(ap, device);

	outb(0x55, ioaddr->nsect_addr);
	outb(0xaa, ioaddr->lbal_addr);

	outb(0xaa, ioaddr->nsect_addr);
	outb(0x55, ioaddr->lbal_addr);

	outb(0x55, ioaddr->nsect_addr);
	outb(0xaa, ioaddr->lbal_addr);

	nsect = inb(ioaddr->nsect_addr);
	lbal = inb(ioaddr->lbal_addr);

	if ((nsect == 0x55) && (lbal == 0xaa))
		return 1;	/* we found a device */

	return 0;		/* nothing found */
}

/**
 *	ata_mmio_devchk - PATA device presence detection
 *	@ap: ATA channel to examine
 *	@device: Device to examine (starting at zero)
 *
 *	This technique was originally described in
 *	Hale Landis's ATADRVR (www.ata-atapi.com), and
 *	later found its way into the ATA/ATAPI spec.
 *
 *	Write a pattern to the ATA shadow registers,
 *	and if a device is present, it will respond by
 *	correctly storing and echoing back the
 *	ATA shadow register contents.
 *
 *	LOCKING:
 *	caller.
 */

static unsigned int ata_mmio_devchk(struct ata_port *ap,
				    unsigned int device)
{
	struct ata_ioports *ioaddr = &ap->ioaddr;
	u8 nsect, lbal;

	ap->ops->dev_select(ap, device);

	writeb(0x55, (void __iomem *) ioaddr->nsect_addr);
	writeb(0xaa, (void __iomem *) ioaddr->lbal_addr);

	writeb(0xaa, (void __iomem *) ioaddr->nsect_addr);
	writeb(0x55, (void __iomem *) ioaddr->lbal_addr);

	writeb(0x55, (void __iomem *) ioaddr->nsect_addr);
	writeb(0xaa, (void __iomem *) ioaddr->lbal_addr);

	nsect = readb((void __iomem *) ioaddr->nsect_addr);
	lbal = readb((void __iomem *) ioaddr->lbal_addr);

	if ((nsect == 0x55) && (lbal == 0xaa))
		return 1;	/* we found a device */

	return 0;		/* nothing found */
}

/**
 *	ata_devchk - PATA device presence detection
 *	@ap: ATA channel to examine
 *	@device: Device to examine (starting at zero)
 *
 *	Dispatch ATA device presence detection, depending
 *	on whether we are using PIO or MMIO to talk to the
 *	ATA shadow registers.
 *
 *	LOCKING:
 *	caller.
 */

static unsigned int ata_devchk(struct ata_port *ap,
				    unsigned int device)
{
	if (ap->flags & ATA_FLAG_MMIO)
		return ata_mmio_devchk(ap, device);
	return ata_pio_devchk(ap, device);
}

/**
 *	ata_dev_classify - determine device type based on ATA-spec signature
 *	@tf: ATA taskfile register set for device to be identified
 *
 *	Determine from taskfile register contents whether a device is
 *	ATA or ATAPI, as per "Signature and persistence" section
 *	of ATA/PI spec (volume 1, sect 5.14).
 *
 *	LOCKING:
 *	None.
 *
 *	RETURNS:
 *	Device type, %ATA_DEV_ATA, %ATA_DEV_ATAPI, or %ATA_DEV_UNKNOWN
 *	the event of failure.
 */

unsigned int ata_dev_classify(const struct ata_taskfile *tf)
{
	/* Apple's open source Darwin code hints that some devices only
	 * put a proper signature into the LBA mid/high registers,
	 * So, we only check those.  It's sufficient for uniqueness.
	 */

	if (((tf->lbam == 0) && (tf->lbah == 0)) ||
	    ((tf->lbam == 0x3c) && (tf->lbah == 0xc3))) {
		DPRINTK("found ATA device by sig\n");
		return ATA_DEV_ATA;
	}

	if (((tf->lbam == 0x14) && (tf->lbah == 0xeb)) ||
	    ((tf->lbam == 0x69) && (tf->lbah == 0x96))) {
		DPRINTK("found ATAPI device by sig\n");
		return ATA_DEV_ATAPI;
	}

	DPRINTK("unknown device\n");
	return ATA_DEV_UNKNOWN;
}

/**
 *	ata_dev_try_classify - Parse returned ATA device signature
 *	@ap: ATA channel to examine
 *	@device: Device to examine (starting at zero)
 *	@r_err: Value of error register on completion
 *
 *	After an event -- SRST, E.D.D., or SATA COMRESET -- occurs,
 *	an ATA/ATAPI-defined set of values is placed in the ATA
 *	shadow registers, indicating the results of device detection
 *	and diagnostics.
 *
 *	Select the ATA device, and read the values from the ATA shadow
 *	registers.  Then parse according to the Error register value,
 *	and the spec-defined values examined by ata_dev_classify().
 *
 *	LOCKING:
 *	caller.
 *
 *	RETURNS:
 *	Device type - %ATA_DEV_ATA, %ATA_DEV_ATAPI or %ATA_DEV_NONE.
 */

static unsigned int
ata_dev_try_classify(struct ata_port *ap, unsigned int device, u8 *r_err)
{
	struct ata_taskfile tf;
	unsigned int class;
	u8 err;

	ap->ops->dev_select(ap, device);

	memset(&tf, 0, sizeof(tf));

	ap->ops->tf_read(ap, &tf);
	err = tf.feature;
	if (r_err)
		*r_err = err;

	/* see if device passed diags */
	if (err == 1)
		/* do nothing */ ;
	else if ((device == 0) && (err == 0x81))
		/* do nothing */ ;
	else
		return ATA_DEV_NONE;

	/* determine if device is ATA or ATAPI */
	class = ata_dev_classify(&tf);

	if (class == ATA_DEV_UNKNOWN)
		return ATA_DEV_NONE;
	if ((class == ATA_DEV_ATA) && (ata_chk_status(ap) == 0))
		return ATA_DEV_NONE;
	return class;
}

/**
 *	ata_id_string - Convert IDENTIFY DEVICE page into string
 *	@id: IDENTIFY DEVICE results we will examine
 *	@s: string into which data is output
 *	@ofs: offset into identify device page
 *	@len: length of string to return. must be an even number.
 *
 *	The strings in the IDENTIFY DEVICE page are broken up into
 *	16-bit chunks.  Run through the string, and output each
 *	8-bit chunk linearly, regardless of platform.
 *
 *	LOCKING:
 *	caller.
 */

void ata_id_string(const u16 *id, unsigned char *s,
		   unsigned int ofs, unsigned int len)
{
	unsigned int c;

	while (len > 0) {
		c = id[ofs] >> 8;
		*s = c;
		s++;

		c = id[ofs] & 0xff;
		*s = c;
		s++;

		ofs++;
		len -= 2;
	}
}

/**
 *	ata_id_c_string - Convert IDENTIFY DEVICE page into C string
 *	@id: IDENTIFY DEVICE results we will examine
 *	@s: string into which data is output
 *	@ofs: offset into identify device page
 *	@len: length of string to return. must be an odd number.
 *
 *	This function is identical to ata_id_string except that it
 *	trims trailing spaces and terminates the resulting string with
 *	null.  @len must be actual maximum length (even number) + 1.
 *
 *	LOCKING:
 *	caller.
 */
void ata_id_c_string(const u16 *id, unsigned char *s,
		     unsigned int ofs, unsigned int len)
{
	unsigned char *p;

	WARN_ON(!(len & 1));

	ata_id_string(id, s, ofs, len - 1);

	p = s + strnlen(s, len - 1);
	while (p > s && p[-1] == ' ')
		p--;
	*p = '\0';
}

static u64 ata_id_n_sectors(const u16 *id)
{
	if (ata_id_has_lba(id)) {
		if (ata_id_has_lba48(id))
			return ata_id_u64(id, 100);
		else
			return ata_id_u32(id, 60);
	} else {
		if (ata_id_current_chs_valid(id))
			return ata_id_u32(id, 57);
		else
			return id[1] * id[3] * id[6];
	}
}

/**
 *	ata_noop_dev_select - Select device 0/1 on ATA bus
 *	@ap: ATA channel to manipulate
 *	@device: ATA device (numbered from zero) to select
 *
 *	This function performs no actual function.
 *
 *	May be used as the dev_select() entry in ata_port_operations.
 *
 *	LOCKING:
 *	caller.
 */
void ata_noop_dev_select (struct ata_port *ap, unsigned int device)
{
}


/**
 *	ata_std_dev_select - Select device 0/1 on ATA bus
 *	@ap: ATA channel to manipulate
 *	@device: ATA device (numbered from zero) to select
 *
 *	Use the method defined in the ATA specification to
 *	make either device 0, or device 1, active on the
 *	ATA channel.  Works with both PIO and MMIO.
 *
 *	May be used as the dev_select() entry in ata_port_operations.
 *
 *	LOCKING:
 *	caller.
 */

void ata_std_dev_select (struct ata_port *ap, unsigned int device)
{
	u8 tmp;

	if (device == 0)
		tmp = ATA_DEVICE_OBS;
	else
		tmp = ATA_DEVICE_OBS | ATA_DEV1;

	if (ap->flags & ATA_FLAG_MMIO) {
		writeb(tmp, (void __iomem *) ap->ioaddr.device_addr);
	} else {
		outb(tmp, ap->ioaddr.device_addr);
	}
	ata_pause(ap);		/* needed; also flushes, for mmio */
}

/**
 *	ata_dev_select - Select device 0/1 on ATA bus
 *	@ap: ATA channel to manipulate
 *	@device: ATA device (numbered from zero) to select
 *	@wait: non-zero to wait for Status register BSY bit to clear
 *	@can_sleep: non-zero if context allows sleeping
 *
 *	Use the method defined in the ATA specification to
 *	make either device 0, or device 1, active on the
 *	ATA channel.
 *
 *	This is a high-level version of ata_std_dev_select(),
 *	which additionally provides the services of inserting
 *	the proper pauses and status polling, where needed.
 *
 *	LOCKING:
 *	caller.
 */

void ata_dev_select(struct ata_port *ap, unsigned int device,
			   unsigned int wait, unsigned int can_sleep)
{
	VPRINTK("ENTER, ata%u: device %u, wait %u\n",
		ap->id, device, wait);

	if (wait)
		ata_wait_idle(ap);

	ap->ops->dev_select(ap, device);

	if (wait) {
		if (can_sleep && ap->device[device].class == ATA_DEV_ATAPI)
			msleep(150);
		ata_wait_idle(ap);
	}
}

/**
 *	ata_dump_id - IDENTIFY DEVICE info debugging output
 *	@id: IDENTIFY DEVICE page to dump
 *
 *	Dump selected 16-bit words from the given IDENTIFY DEVICE
 *	page.
 *
 *	LOCKING:
 *	caller.
 */

static inline void ata_dump_id(const u16 *id)
{
	DPRINTK("49==0x%04x  "
		"53==0x%04x  "
		"63==0x%04x  "
		"64==0x%04x  "
		"75==0x%04x  \n",
		id[49],
		id[53],
		id[63],
		id[64],
		id[75]);
	DPRINTK("80==0x%04x  "
		"81==0x%04x  "
		"82==0x%04x  "
		"83==0x%04x  "
		"84==0x%04x  \n",
		id[80],
		id[81],
		id[82],
		id[83],
		id[84]);
	DPRINTK("88==0x%04x  "
		"93==0x%04x\n",
		id[88],
		id[93]);
}

/*
 *	Compute the PIO modes available for this device. This is not as
 *	trivial as it seems if we must consider early devices correctly.
 *
 *	FIXME: pre IDE drive timing (do we care ?). 
 */

static unsigned int ata_pio_modes(const struct ata_device *adev)
{
	u16 modes;

	/* Usual case. Word 53 indicates word 64 is valid */
	if (adev->id[ATA_ID_FIELD_VALID] & (1 << 1)) {
		modes = adev->id[ATA_ID_PIO_MODES] & 0x03;
		modes <<= 3;
		modes |= 0x7;
		return modes;
	}

	/* If word 64 isn't valid then Word 51 high byte holds the PIO timing
	   number for the maximum. Turn it into a mask and return it */
	modes = (2 << ((adev->id[ATA_ID_OLD_PIO_MODES] >> 8) & 0xFF)) - 1 ;
	return modes;
	/* But wait.. there's more. Design your standards by committee and
	   you too can get a free iordy field to process. However its the 
	   speeds not the modes that are supported... Note drivers using the
	   timing API will get this right anyway */
}

static inline void
ata_queue_packet_task(struct ata_port *ap)
{
	if (!(ap->flags & ATA_FLAG_FLUSH_PIO_TASK))
		queue_work(ata_wq, &ap->packet_task);
}

static inline void
ata_queue_pio_task(struct ata_port *ap)
{
	if (!(ap->flags & ATA_FLAG_FLUSH_PIO_TASK))
		queue_work(ata_wq, &ap->pio_task);
}

static inline void
ata_queue_delayed_pio_task(struct ata_port *ap, unsigned long delay)
{
	if (!(ap->flags & ATA_FLAG_FLUSH_PIO_TASK))
		queue_delayed_work(ata_wq, &ap->pio_task, delay);
}

/**
 *	ata_flush_pio_tasks - Flush pio_task and packet_task
 *	@ap: the target ata_port
 *
 *	After this function completes, pio_task and packet_task are
 *	guranteed not to be running or scheduled.
 *
 *	LOCKING:
 *	Kernel thread context (may sleep)
 */

static void ata_flush_pio_tasks(struct ata_port *ap)
{
	int tmp = 0;
	unsigned long flags;

	DPRINTK("ENTER\n");

	spin_lock_irqsave(&ap->host_set->lock, flags);
	ap->flags |= ATA_FLAG_FLUSH_PIO_TASK;
	spin_unlock_irqrestore(&ap->host_set->lock, flags);

	DPRINTK("flush #1\n");
	flush_workqueue(ata_wq);

	/*
	 * At this point, if a task is running, it's guaranteed to see
	 * the FLUSH flag; thus, it will never queue pio tasks again.
	 * Cancel and flush.
	 */
	tmp |= cancel_delayed_work(&ap->pio_task);
	tmp |= cancel_delayed_work(&ap->packet_task);
	if (!tmp) {
		DPRINTK("flush #2\n");
		flush_workqueue(ata_wq);
	}

	spin_lock_irqsave(&ap->host_set->lock, flags);
	ap->flags &= ~ATA_FLAG_FLUSH_PIO_TASK;
	spin_unlock_irqrestore(&ap->host_set->lock, flags);

	DPRINTK("EXIT\n");
}

void ata_qc_complete_internal(struct ata_queued_cmd *qc)
{
	struct completion *waiting = qc->private_data;

	qc->ap->ops->tf_read(qc->ap, &qc->tf);
	complete(waiting);
}

/**
 *	ata_exec_internal - execute libata internal command
 *	@ap: Port to which the command is sent
 *	@dev: Device to which the command is sent
 *	@tf: Taskfile registers for the command and the result
 *	@dma_dir: Data tranfer direction of the command
 *	@buf: Data buffer of the command
 *	@buflen: Length of data buffer
 *
 *	Executes libata internal command with timeout.  @tf contains
 *	command on entry and result on return.  Timeout and error
 *	conditions are reported via return value.  No recovery action
 *	is taken after a command times out.  It's caller's duty to
 *	clean up after timeout.
 *
 *	LOCKING:
 *	None.  Should be called with kernel context, might sleep.
 */

static unsigned
ata_exec_internal(struct ata_port *ap, struct ata_device *dev,
		  struct ata_taskfile *tf,
		  int dma_dir, void *buf, unsigned int buflen)
{
	u8 command = tf->command;
	struct ata_queued_cmd *qc;
	DECLARE_COMPLETION(wait);
	unsigned long flags;
	unsigned int err_mask;

	spin_lock_irqsave(&ap->host_set->lock, flags);

	qc = ata_qc_new_init(ap, dev);
	BUG_ON(qc == NULL);

	qc->tf = *tf;
	qc->dma_dir = dma_dir;
	if (dma_dir != DMA_NONE) {
		ata_sg_init_one(qc, buf, buflen);
		qc->nsect = buflen / ATA_SECT_SIZE;
	}

	qc->private_data = &wait;
	qc->complete_fn = ata_qc_complete_internal;

	qc->err_mask = ata_qc_issue(qc);
	if (qc->err_mask)
		ata_qc_complete(qc);

	spin_unlock_irqrestore(&ap->host_set->lock, flags);

	if (!wait_for_completion_timeout(&wait, ATA_TMOUT_INTERNAL)) {
		spin_lock_irqsave(&ap->host_set->lock, flags);

		/* We're racing with irq here.  If we lose, the
		 * following test prevents us from completing the qc
		 * again.  If completion irq occurs after here but
		 * before the caller cleans up, it will result in a
		 * spurious interrupt.  We can live with that.
		 */
		if (qc->flags & ATA_QCFLAG_ACTIVE) {
			qc->err_mask = AC_ERR_TIMEOUT;
			ata_qc_complete(qc);
			printk(KERN_WARNING "ata%u: qc timeout (cmd 0x%x)\n",
			       ap->id, command);
		}

		spin_unlock_irqrestore(&ap->host_set->lock, flags);
	}

	*tf = qc->tf;
	err_mask = qc->err_mask;

	ata_qc_free(qc);

	return err_mask;
}

/**
 *	ata_pio_need_iordy	-	check if iordy needed
 *	@adev: ATA device
 *
 *	Check if the current speed of the device requires IORDY. Used
 *	by various controllers for chip configuration.
 */

unsigned int ata_pio_need_iordy(const struct ata_device *adev)
{
	int pio;
	int speed = adev->pio_mode - XFER_PIO_0;

	if (speed < 2)
		return 0;
	if (speed > 2)
		return 1;
		
	/* If we have no drive specific rule, then PIO 2 is non IORDY */

	if (adev->id[ATA_ID_FIELD_VALID] & 2) {	/* EIDE */
		pio = adev->id[ATA_ID_EIDE_PIO];
		/* Is the speed faster than the drive allows non IORDY ? */
		if (pio) {
			/* This is cycle times not frequency - watch the logic! */
			if (pio > 240)	/* PIO2 is 240nS per cycle */
				return 1;
			return 0;
		}
	}
	return 0;
}

/**
 *	ata_dev_read_id - Read ID data from the specified device
 *	@ap: port on which target device resides
 *	@dev: target device
 *	@p_class: pointer to class of the target device (may be changed)
 *	@post_reset: is this read ID post-reset?
 *	@p_id: read IDENTIFY page (newly allocated)
 *
 *	Read ID data from the specified device.  ATA_CMD_ID_ATA is
 *	performed on ATA devices and ATA_CMD_ID_ATAPI on ATAPI
 *	devices.  This function also takes care of EDD signature
 *	misreporting (to be removed once EDD support is gone) and
 *	issues ATA_CMD_INIT_DEV_PARAMS for pre-ATA4 drives.
 *
 *	LOCKING:
 *	Kernel thread context (may sleep)
 *
 *	RETURNS:
 *	0 on success, -errno otherwise.
 */
static int ata_dev_read_id(struct ata_port *ap, struct ata_device *dev,
			   unsigned int *p_class, int post_reset, u16 **p_id)
{
	unsigned int class = *p_class;
	unsigned int using_edd;
	struct ata_taskfile tf;
	unsigned int err_mask = 0;
	u16 *id;
	const char *reason;
	int rc;

	DPRINTK("ENTER, host %u, dev %u\n", ap->id, dev->devno);

	if (ap->ops->probe_reset ||
	    ap->flags & (ATA_FLAG_SRST | ATA_FLAG_SATA_RESET))
		using_edd = 0;
	else
		using_edd = 1;

	ata_dev_select(ap, dev->devno, 1, 1); /* select device 0/1 */

	id = kmalloc(sizeof(id[0]) * ATA_ID_WORDS, GFP_KERNEL);
	if (id == NULL) {
		rc = -ENOMEM;
		reason = "out of memory";
		goto err_out;
	}

 retry:
	ata_tf_init(ap, &tf, dev->devno);

	switch (class) {
	case ATA_DEV_ATA:
		tf.command = ATA_CMD_ID_ATA;
		break;
	case ATA_DEV_ATAPI:
		tf.command = ATA_CMD_ID_ATAPI;
		break;
	default:
		rc = -ENODEV;
		reason = "unsupported class";
		goto err_out;
	}

	tf.protocol = ATA_PROT_PIO;

	err_mask = ata_exec_internal(ap, dev, &tf, DMA_FROM_DEVICE,
				     id, sizeof(id[0]) * ATA_ID_WORDS);

	if (err_mask) {
		rc = -EIO;
		reason = "I/O error";

		if (err_mask & ~AC_ERR_DEV)
			goto err_out;

		/*
		 * arg!  EDD works for all test cases, but seems to return
		 * the ATA signature for some ATAPI devices.  Until the
		 * reason for this is found and fixed, we fix up the mess
		 * here.  If IDENTIFY DEVICE returns command aborted
		 * (as ATAPI devices do), then we issue an
		 * IDENTIFY PACKET DEVICE.
		 *
		 * ATA software reset (SRST, the default) does not appear
		 * to have this problem.
		 */
		if ((using_edd) && (class == ATA_DEV_ATA)) {
			u8 err = tf.feature;
			if (err & ATA_ABORTED) {
				class = ATA_DEV_ATAPI;
				goto retry;
			}
		}
		goto err_out;
	}

	swap_buf_le16(id, ATA_ID_WORDS);

	/* print device capabilities */
	printk(KERN_DEBUG "ata%u: dev %u cfg "
	       "49:%04x 82:%04x 83:%04x 84:%04x 85:%04x 86:%04x 87:%04x 88:%04x\n",
	       ap->id, dev->devno,
	       id[49], id[82], id[83], id[84], id[85], id[86], id[87], id[88]);

	/* sanity check */
	if ((class == ATA_DEV_ATA) != ata_id_is_ata(id)) {
		rc = -EINVAL;
		reason = "device reports illegal type";
		goto err_out;
	}

	if (post_reset && class == ATA_DEV_ATA) {
		/*
		 * The exact sequence expected by certain pre-ATA4 drives is:
		 * SRST RESET
		 * IDENTIFY
		 * INITIALIZE DEVICE PARAMETERS
		 * anything else..
		 * Some drives were very specific about that exact sequence.
		 */
		if (ata_id_major_version(id) < 4 || !ata_id_has_lba(id)) {
			err_mask = ata_dev_init_params(ap, dev);
			if (err_mask) {
				rc = -EIO;
				reason = "INIT_DEV_PARAMS failed";
				goto err_out;
			}

			/* current CHS translation info (id[53-58]) might be
			 * changed. reread the identify device info.
			 */
			post_reset = 0;
			goto retry;
		}
	}

	*p_class = class;
	*p_id = id;
	return 0;

 err_out:
	printk(KERN_WARNING "ata%u: dev %u failed to IDENTIFY (%s)\n",
	       ap->id, dev->devno, reason);
	kfree(id);
	return rc;
}

/**
 *	ata_dev_identify - obtain IDENTIFY x DEVICE page
 *	@ap: port on which device we wish to probe resides
 *	@device: device bus address, starting at zero
 *
 *	Following bus reset, we issue the IDENTIFY [PACKET] DEVICE
 *	command, and read back the 512-byte device information page.
 *	The device information page is fed to us via the standard
 *	PIO-IN protocol, but we hand-code it here. (TODO: investigate
 *	using standard PIO-IN paths)
 *
 *	After reading the device information page, we use several
 *	bits of information from it to initialize data structures
 *	that will be used during the lifetime of the ata_device.
 *	Other data from the info page is used to disqualify certain
 *	older ATA devices we do not wish to support.
 *
 *	LOCKING:
 *	Inherited from caller.  Some functions called by this function
 *	obtain the host_set lock.
 */

static void ata_dev_identify(struct ata_port *ap, unsigned int device)
{
	struct ata_device *dev = &ap->device[device];
	unsigned long xfer_modes;
	int i, rc;

	if (!ata_dev_present(dev)) {
		DPRINTK("ENTER/EXIT (host %u, dev %u) -- nodev\n",
			ap->id, device);
		return;
	}

	DPRINTK("ENTER, host %u, dev %u\n", ap->id, device);

	WARN_ON(dev->id != NULL);
	rc = ata_dev_read_id(ap, dev, &dev->class, 1, &dev->id);
	if (rc)
		goto err_out;

	/*
	 * common ATA, ATAPI feature tests
	 */

	/* we require DMA support (bits 8 of word 49) */
	if (!ata_id_has_dma(dev->id)) {
		printk(KERN_DEBUG "ata%u: no dma\n", ap->id);
		goto err_out_nosup;
	}

	/* quick-n-dirty find max transfer mode; for printk only */
	xfer_modes = dev->id[ATA_ID_UDMA_MODES];
	if (!xfer_modes)
		xfer_modes = (dev->id[ATA_ID_MWDMA_MODES]) << ATA_SHIFT_MWDMA;
	if (!xfer_modes)
		xfer_modes = ata_pio_modes(dev);

	ata_dump_id(dev->id);

	/* ATA-specific feature tests */
	if (dev->class == ATA_DEV_ATA) {
		dev->n_sectors = ata_id_n_sectors(dev->id);

		if (ata_id_has_lba(dev->id)) {
			dev->flags |= ATA_DFLAG_LBA;

			if (ata_id_has_lba48(dev->id))
				dev->flags |= ATA_DFLAG_LBA48;

			/* print device info to dmesg */
			printk(KERN_INFO "ata%u: dev %u ATA-%d, max %s, %Lu sectors:%s\n",
			       ap->id, device,
			       ata_id_major_version(dev->id),
			       ata_mode_string(xfer_modes),
			       (unsigned long long)dev->n_sectors,
			       dev->flags & ATA_DFLAG_LBA48 ? " LBA48" : " LBA");
		} else { 
			/* CHS */

			/* Default translation */
			dev->cylinders	= dev->id[1];
			dev->heads	= dev->id[3];
			dev->sectors	= dev->id[6];

			if (ata_id_current_chs_valid(dev->id)) {
				/* Current CHS translation is valid. */
				dev->cylinders = dev->id[54];
				dev->heads     = dev->id[55];
				dev->sectors   = dev->id[56];
			}

			/* print device info to dmesg */
			printk(KERN_INFO "ata%u: dev %u ATA-%d, max %s, %Lu sectors: CHS %d/%d/%d\n",
			       ap->id, device,
			       ata_id_major_version(dev->id),
			       ata_mode_string(xfer_modes),
			       (unsigned long long)dev->n_sectors,
			       (int)dev->cylinders, (int)dev->heads, (int)dev->sectors);

		}

		dev->cdb_len = 16;
	}

	/* ATAPI-specific feature tests */
	else if (dev->class == ATA_DEV_ATAPI) {
		rc = atapi_cdb_len(dev->id);
		if ((rc < 12) || (rc > ATAPI_CDB_LEN)) {
			printk(KERN_WARNING "ata%u: unsupported CDB len\n", ap->id);
			goto err_out_nosup;
		}
		dev->cdb_len = (unsigned int) rc;

		/* print device info to dmesg */
		printk(KERN_INFO "ata%u: dev %u ATAPI, max %s\n",
		       ap->id, device,
		       ata_mode_string(xfer_modes));
	}

	ap->host->max_cmd_len = 0;
	for (i = 0; i < ATA_MAX_DEVICES; i++)
		ap->host->max_cmd_len = max_t(unsigned int,
					      ap->host->max_cmd_len,
					      ap->device[i].cdb_len);

	DPRINTK("EXIT, drv_stat = 0x%x\n", ata_chk_status(ap));
	return;

err_out_nosup:
	printk(KERN_WARNING "ata%u: dev %u not supported, ignoring\n",
	       ap->id, device);
err_out:
	dev->class++;	/* converts ATA_DEV_xxx into ATA_DEV_xxx_UNSUP */
	DPRINTK("EXIT, err\n");
}


static inline u8 ata_dev_knobble(const struct ata_port *ap,
				 struct ata_device *dev)
{
	return ((ap->cbl == ATA_CBL_SATA) && (!ata_id_is_sata(dev->id)));
}

/**
 * ata_dev_config - Run device specific handlers & check for SATA->PATA bridges
 * @ap: Bus
 * @i:  Device
 *
 * LOCKING:
 */

void ata_dev_config(struct ata_port *ap, unsigned int i)
{
	/* limit bridge transfers to udma5, 200 sectors */
	if (ata_dev_knobble(ap, &ap->device[i])) {
		printk(KERN_INFO "ata%u(%u): applying bridge limits\n",
		       ap->id, i);
		ap->udma_mask &= ATA_UDMA5;
		ap->device[i].max_sectors = ATA_MAX_SECTORS;
	}

	if (ap->ops->dev_config)
		ap->ops->dev_config(ap, &ap->device[i]);
}

/**
 *	ata_bus_probe - Reset and probe ATA bus
 *	@ap: Bus to probe
 *
 *	Master ATA bus probing function.  Initiates a hardware-dependent
 *	bus reset, then attempts to identify any devices found on
 *	the bus.
 *
 *	LOCKING:
 *	PCI/etc. bus probe sem.
 *
 *	RETURNS:
 *	Zero on success, non-zero on error.
 */

static int ata_bus_probe(struct ata_port *ap)
{
	unsigned int i, found = 0;

	if (ap->ops->probe_reset) {
		unsigned int classes[ATA_MAX_DEVICES];
		int rc;

		ata_port_probe(ap);

		rc = ap->ops->probe_reset(ap, classes);
		if (rc == 0) {
			for (i = 0; i < ATA_MAX_DEVICES; i++) {
				if (classes[i] == ATA_DEV_UNKNOWN)
					classes[i] = ATA_DEV_NONE;
				ap->device[i].class = classes[i];
			}
		} else {
			printk(KERN_ERR "ata%u: probe reset failed, "
			       "disabling port\n", ap->id);
			ata_port_disable(ap);
		}
	} else
		ap->ops->phy_reset(ap);

	if (ap->flags & ATA_FLAG_PORT_DISABLED)
		goto err_out;

	for (i = 0; i < ATA_MAX_DEVICES; i++) {
		ata_dev_identify(ap, i);
		if (ata_dev_present(&ap->device[i])) {
			found = 1;
			ata_dev_config(ap,i);
		}
	}

	if ((!found) || (ap->flags & ATA_FLAG_PORT_DISABLED))
		goto err_out_disable;

	ata_set_mode(ap);
	if (ap->flags & ATA_FLAG_PORT_DISABLED)
		goto err_out_disable;

	return 0;

err_out_disable:
	ap->ops->port_disable(ap);
err_out:
	return -1;
}

/**
 *	ata_port_probe - Mark port as enabled
 *	@ap: Port for which we indicate enablement
 *
 *	Modify @ap data structure such that the system
 *	thinks that the entire port is enabled.
 *
 *	LOCKING: host_set lock, or some other form of
 *	serialization.
 */

void ata_port_probe(struct ata_port *ap)
{
	ap->flags &= ~ATA_FLAG_PORT_DISABLED;
}

/**
 *	sata_print_link_status - Print SATA link status
 *	@ap: SATA port to printk link status about
 *
 *	This function prints link speed and status of a SATA link.
 *
 *	LOCKING:
 *	None.
 */
static void sata_print_link_status(struct ata_port *ap)
{
	u32 sstatus, tmp;
	const char *speed;

	if (!ap->ops->scr_read)
		return;

	sstatus = scr_read(ap, SCR_STATUS);

	if (sata_dev_present(ap)) {
		tmp = (sstatus >> 4) & 0xf;
		if (tmp & (1 << 0))
			speed = "1.5";
		else if (tmp & (1 << 1))
			speed = "3.0";
		else
			speed = "<unknown>";
		printk(KERN_INFO "ata%u: SATA link up %s Gbps (SStatus %X)\n",
		       ap->id, speed, sstatus);
	} else {
		printk(KERN_INFO "ata%u: SATA link down (SStatus %X)\n",
		       ap->id, sstatus);
	}
}

/**
 *	__sata_phy_reset - Wake/reset a low-level SATA PHY
 *	@ap: SATA port associated with target SATA PHY.
 *
 *	This function issues commands to standard SATA Sxxx
 *	PHY registers, to wake up the phy (and device), and
 *	clear any reset condition.
 *
 *	LOCKING:
 *	PCI/etc. bus probe sem.
 *
 */
void __sata_phy_reset(struct ata_port *ap)
{
	u32 sstatus;
	unsigned long timeout = jiffies + (HZ * 5);

	if (ap->flags & ATA_FLAG_SATA_RESET) {
		/* issue phy wake/reset */
		scr_write_flush(ap, SCR_CONTROL, 0x301);
		/* Couldn't find anything in SATA I/II specs, but
		 * AHCI-1.1 10.4.2 says at least 1 ms. */
		mdelay(1);
	}
	scr_write_flush(ap, SCR_CONTROL, 0x300); /* phy wake/clear reset */

	/* wait for phy to become ready, if necessary */
	do {
		msleep(200);
		sstatus = scr_read(ap, SCR_STATUS);
		if ((sstatus & 0xf) != 1)
			break;
	} while (time_before(jiffies, timeout));

	/* print link status */
	sata_print_link_status(ap);

	/* TODO: phy layer with polling, timeouts, etc. */
	if (sata_dev_present(ap))
		ata_port_probe(ap);
	else
		ata_port_disable(ap);

	if (ap->flags & ATA_FLAG_PORT_DISABLED)
		return;

	if (ata_busy_sleep(ap, ATA_TMOUT_BOOT_QUICK, ATA_TMOUT_BOOT)) {
		ata_port_disable(ap);
		return;
	}

	ap->cbl = ATA_CBL_SATA;
}

/**
 *	sata_phy_reset - Reset SATA bus.
 *	@ap: SATA port associated with target SATA PHY.
 *
 *	This function resets the SATA bus, and then probes
 *	the bus for devices.
 *
 *	LOCKING:
 *	PCI/etc. bus probe sem.
 *
 */
void sata_phy_reset(struct ata_port *ap)
{
	__sata_phy_reset(ap);
	if (ap->flags & ATA_FLAG_PORT_DISABLED)
		return;
	ata_bus_reset(ap);
}

/**
 *	ata_port_disable - Disable port.
 *	@ap: Port to be disabled.
 *
 *	Modify @ap data structure such that the system
 *	thinks that the entire port is disabled, and should
 *	never attempt to probe or communicate with devices
 *	on this port.
 *
 *	LOCKING: host_set lock, or some other form of
 *	serialization.
 */

void ata_port_disable(struct ata_port *ap)
{
	ap->device[0].class = ATA_DEV_NONE;
	ap->device[1].class = ATA_DEV_NONE;
	ap->flags |= ATA_FLAG_PORT_DISABLED;
}

/*
 * This mode timing computation functionality is ported over from
 * drivers/ide/ide-timing.h and was originally written by Vojtech Pavlik
 */
/*
 * PIO 0-5, MWDMA 0-2 and UDMA 0-6 timings (in nanoseconds).
 * These were taken from ATA/ATAPI-6 standard, rev 0a, except
 * for PIO 5, which is a nonstandard extension and UDMA6, which
 * is currently supported only by Maxtor drives. 
 */

static const struct ata_timing ata_timing[] = {

	{ XFER_UDMA_6,     0,   0,   0,   0,   0,   0,   0,  15 },
	{ XFER_UDMA_5,     0,   0,   0,   0,   0,   0,   0,  20 },
	{ XFER_UDMA_4,     0,   0,   0,   0,   0,   0,   0,  30 },
	{ XFER_UDMA_3,     0,   0,   0,   0,   0,   0,   0,  45 },

	{ XFER_UDMA_2,     0,   0,   0,   0,   0,   0,   0,  60 },
	{ XFER_UDMA_1,     0,   0,   0,   0,   0,   0,   0,  80 },
	{ XFER_UDMA_0,     0,   0,   0,   0,   0,   0,   0, 120 },

/*	{ XFER_UDMA_SLOW,  0,   0,   0,   0,   0,   0,   0, 150 }, */
                                          
	{ XFER_MW_DMA_2,  25,   0,   0,   0,  70,  25, 120,   0 },
	{ XFER_MW_DMA_1,  45,   0,   0,   0,  80,  50, 150,   0 },
	{ XFER_MW_DMA_0,  60,   0,   0,   0, 215, 215, 480,   0 },
                                          
	{ XFER_SW_DMA_2,  60,   0,   0,   0, 120, 120, 240,   0 },
	{ XFER_SW_DMA_1,  90,   0,   0,   0, 240, 240, 480,   0 },
	{ XFER_SW_DMA_0, 120,   0,   0,   0, 480, 480, 960,   0 },

/*	{ XFER_PIO_5,     20,  50,  30, 100,  50,  30, 100,   0 }, */
	{ XFER_PIO_4,     25,  70,  25, 120,  70,  25, 120,   0 },
	{ XFER_PIO_3,     30,  80,  70, 180,  80,  70, 180,   0 },

	{ XFER_PIO_2,     30, 290,  40, 330, 100,  90, 240,   0 },
	{ XFER_PIO_1,     50, 290,  93, 383, 125, 100, 383,   0 },
	{ XFER_PIO_0,     70, 290, 240, 600, 165, 150, 600,   0 },

/*	{ XFER_PIO_SLOW, 120, 290, 240, 960, 290, 240, 960,   0 }, */

	{ 0xFF }
};

#define ENOUGH(v,unit)		(((v)-1)/(unit)+1)
#define EZ(v,unit)		((v)?ENOUGH(v,unit):0)

static void ata_timing_quantize(const struct ata_timing *t, struct ata_timing *q, int T, int UT)
{
	q->setup   = EZ(t->setup   * 1000,  T);
	q->act8b   = EZ(t->act8b   * 1000,  T);
	q->rec8b   = EZ(t->rec8b   * 1000,  T);
	q->cyc8b   = EZ(t->cyc8b   * 1000,  T);
	q->active  = EZ(t->active  * 1000,  T);
	q->recover = EZ(t->recover * 1000,  T);
	q->cycle   = EZ(t->cycle   * 1000,  T);
	q->udma    = EZ(t->udma    * 1000, UT);
}

void ata_timing_merge(const struct ata_timing *a, const struct ata_timing *b,
		      struct ata_timing *m, unsigned int what)
{
	if (what & ATA_TIMING_SETUP  ) m->setup   = max(a->setup,   b->setup);
	if (what & ATA_TIMING_ACT8B  ) m->act8b   = max(a->act8b,   b->act8b);
	if (what & ATA_TIMING_REC8B  ) m->rec8b   = max(a->rec8b,   b->rec8b);
	if (what & ATA_TIMING_CYC8B  ) m->cyc8b   = max(a->cyc8b,   b->cyc8b);
	if (what & ATA_TIMING_ACTIVE ) m->active  = max(a->active,  b->active);
	if (what & ATA_TIMING_RECOVER) m->recover = max(a->recover, b->recover);
	if (what & ATA_TIMING_CYCLE  ) m->cycle   = max(a->cycle,   b->cycle);
	if (what & ATA_TIMING_UDMA   ) m->udma    = max(a->udma,    b->udma);
}

static const struct ata_timing* ata_timing_find_mode(unsigned short speed)
{
	const struct ata_timing *t;

	for (t = ata_timing; t->mode != speed; t++)
		if (t->mode == 0xFF)
			return NULL;
	return t; 
}

int ata_timing_compute(struct ata_device *adev, unsigned short speed,
		       struct ata_timing *t, int T, int UT)
{
	const struct ata_timing *s;
	struct ata_timing p;

	/*
	 * Find the mode. 
	 */

	if (!(s = ata_timing_find_mode(speed)))
		return -EINVAL;

	memcpy(t, s, sizeof(*s));

	/*
	 * If the drive is an EIDE drive, it can tell us it needs extended
	 * PIO/MW_DMA cycle timing.
	 */

	if (adev->id[ATA_ID_FIELD_VALID] & 2) {	/* EIDE drive */
		memset(&p, 0, sizeof(p));
		if(speed >= XFER_PIO_0 && speed <= XFER_SW_DMA_0) {
			if (speed <= XFER_PIO_2) p.cycle = p.cyc8b = adev->id[ATA_ID_EIDE_PIO];
					    else p.cycle = p.cyc8b = adev->id[ATA_ID_EIDE_PIO_IORDY];
		} else if(speed >= XFER_MW_DMA_0 && speed <= XFER_MW_DMA_2) {
			p.cycle = adev->id[ATA_ID_EIDE_DMA_MIN];
		}
		ata_timing_merge(&p, t, t, ATA_TIMING_CYCLE | ATA_TIMING_CYC8B);
	}

	/*
	 * Convert the timing to bus clock counts.
	 */

	ata_timing_quantize(t, t, T, UT);

	/*
	 * Even in DMA/UDMA modes we still use PIO access for IDENTIFY,
	 * S.M.A.R.T * and some other commands. We have to ensure that the
	 * DMA cycle timing is slower/equal than the fastest PIO timing.
	 */

	if (speed > XFER_PIO_4) {
		ata_timing_compute(adev, adev->pio_mode, &p, T, UT);
		ata_timing_merge(&p, t, t, ATA_TIMING_ALL);
	}

	/*
	 * Lengthen active & recovery time so that cycle time is correct.
	 */

	if (t->act8b + t->rec8b < t->cyc8b) {
		t->act8b += (t->cyc8b - (t->act8b + t->rec8b)) / 2;
		t->rec8b = t->cyc8b - t->act8b;
	}

	if (t->active + t->recover < t->cycle) {
		t->active += (t->cycle - (t->active + t->recover)) / 2;
		t->recover = t->cycle - t->active;
	}

	return 0;
}

static const struct {
	unsigned int shift;
	u8 base;
} xfer_mode_classes[] = {
	{ ATA_SHIFT_UDMA,	XFER_UDMA_0 },
	{ ATA_SHIFT_MWDMA,	XFER_MW_DMA_0 },
	{ ATA_SHIFT_PIO,	XFER_PIO_0 },
};

static u8 base_from_shift(unsigned int shift)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(xfer_mode_classes); i++)
		if (xfer_mode_classes[i].shift == shift)
			return xfer_mode_classes[i].base;

	return 0xff;
}

static void ata_dev_set_mode(struct ata_port *ap, struct ata_device *dev)
{
	int ofs, idx;
	u8 base;

	if (!ata_dev_present(dev) || (ap->flags & ATA_FLAG_PORT_DISABLED))
		return;

	if (dev->xfer_shift == ATA_SHIFT_PIO)
		dev->flags |= ATA_DFLAG_PIO;

	ata_dev_set_xfermode(ap, dev);

	base = base_from_shift(dev->xfer_shift);
	ofs = dev->xfer_mode - base;
	idx = ofs + dev->xfer_shift;
	WARN_ON(idx >= ARRAY_SIZE(xfer_mode_str));

	DPRINTK("idx=%d xfer_shift=%u, xfer_mode=0x%x, base=0x%x, offset=%d\n",
		idx, dev->xfer_shift, (int)dev->xfer_mode, (int)base, ofs);

	printk(KERN_INFO "ata%u: dev %u configured for %s\n",
		ap->id, dev->devno, xfer_mode_str[idx]);
}

static int ata_host_set_pio(struct ata_port *ap)
{
	unsigned int mask;
	int x, i;
	u8 base, xfer_mode;

	mask = ata_get_mode_mask(ap, ATA_SHIFT_PIO);
	x = fgb(mask);
	if (x < 0) {
		printk(KERN_WARNING "ata%u: no PIO support\n", ap->id);
		return -1;
	}

	base = base_from_shift(ATA_SHIFT_PIO);
	xfer_mode = base + x;

	DPRINTK("base 0x%x xfer_mode 0x%x mask 0x%x x %d\n",
		(int)base, (int)xfer_mode, mask, x);

	for (i = 0; i < ATA_MAX_DEVICES; i++) {
		struct ata_device *dev = &ap->device[i];
		if (ata_dev_present(dev)) {
			dev->pio_mode = xfer_mode;
			dev->xfer_mode = xfer_mode;
			dev->xfer_shift = ATA_SHIFT_PIO;
			if (ap->ops->set_piomode)
				ap->ops->set_piomode(ap, dev);
		}
	}

	return 0;
}

static void ata_host_set_dma(struct ata_port *ap, u8 xfer_mode,
			    unsigned int xfer_shift)
{
	int i;

	for (i = 0; i < ATA_MAX_DEVICES; i++) {
		struct ata_device *dev = &ap->device[i];
		if (ata_dev_present(dev)) {
			dev->dma_mode = xfer_mode;
			dev->xfer_mode = xfer_mode;
			dev->xfer_shift = xfer_shift;
			if (ap->ops->set_dmamode)
				ap->ops->set_dmamode(ap, dev);
		}
	}
}

/**
 *	ata_set_mode - Program timings and issue SET FEATURES - XFER
 *	@ap: port on which timings will be programmed
 *
 *	Set ATA device disk transfer mode (PIO3, UDMA6, etc.).
 *
 *	LOCKING:
 *	PCI/etc. bus probe sem.
 */
static void ata_set_mode(struct ata_port *ap)
{
	unsigned int xfer_shift;
	u8 xfer_mode;
	int rc;

	/* step 1: always set host PIO timings */
	rc = ata_host_set_pio(ap);
	if (rc)
		goto err_out;

	/* step 2: choose the best data xfer mode */
	xfer_mode = xfer_shift = 0;
	rc = ata_choose_xfer_mode(ap, &xfer_mode, &xfer_shift);
	if (rc)
		goto err_out;

	/* step 3: if that xfer mode isn't PIO, set host DMA timings */
	if (xfer_shift != ATA_SHIFT_PIO)
		ata_host_set_dma(ap, xfer_mode, xfer_shift);

	/* step 4: update devices' xfer mode */
	ata_dev_set_mode(ap, &ap->device[0]);
	ata_dev_set_mode(ap, &ap->device[1]);

	if (ap->flags & ATA_FLAG_PORT_DISABLED)
		return;

	if (ap->ops->post_set_mode)
		ap->ops->post_set_mode(ap);

	return;

err_out:
	ata_port_disable(ap);
}

/**
 *	ata_tf_to_host - issue ATA taskfile to host controller
 *	@ap: port to which command is being issued
 *	@tf: ATA taskfile register set
 *
 *	Issues ATA taskfile register set to ATA host controller,
 *	with proper synchronization with interrupt handler and
 *	other threads.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 */

static inline void ata_tf_to_host(struct ata_port *ap,
				  const struct ata_taskfile *tf)
{
	ap->ops->tf_load(ap, tf);
	ap->ops->exec_command(ap, tf);
}

/**
 *	ata_busy_sleep - sleep until BSY clears, or timeout
 *	@ap: port containing status register to be polled
 *	@tmout_pat: impatience timeout
 *	@tmout: overall timeout
 *
 *	Sleep until ATA Status register bit BSY clears,
 *	or a timeout occurs.
 *
 *	LOCKING: None.
 */

unsigned int ata_busy_sleep (struct ata_port *ap,
			     unsigned long tmout_pat, unsigned long tmout)
{
	unsigned long timer_start, timeout;
	u8 status;

	status = ata_busy_wait(ap, ATA_BUSY, 300);
	timer_start = jiffies;
	timeout = timer_start + tmout_pat;
	while ((status & ATA_BUSY) && (time_before(jiffies, timeout))) {
		msleep(50);
		status = ata_busy_wait(ap, ATA_BUSY, 3);
	}

	if (status & ATA_BUSY)
		printk(KERN_WARNING "ata%u is slow to respond, "
		       "please be patient\n", ap->id);

	timeout = timer_start + tmout;
	while ((status & ATA_BUSY) && (time_before(jiffies, timeout))) {
		msleep(50);
		status = ata_chk_status(ap);
	}

	if (status & ATA_BUSY) {
		printk(KERN_ERR "ata%u failed to respond (%lu secs)\n",
		       ap->id, tmout / HZ);
		return 1;
	}

	return 0;
}

static void ata_bus_post_reset(struct ata_port *ap, unsigned int devmask)
{
	struct ata_ioports *ioaddr = &ap->ioaddr;
	unsigned int dev0 = devmask & (1 << 0);
	unsigned int dev1 = devmask & (1 << 1);
	unsigned long timeout;

	/* if device 0 was found in ata_devchk, wait for its
	 * BSY bit to clear
	 */
	if (dev0)
		ata_busy_sleep(ap, ATA_TMOUT_BOOT_QUICK, ATA_TMOUT_BOOT);

	/* if device 1 was found in ata_devchk, wait for
	 * register access, then wait for BSY to clear
	 */
	timeout = jiffies + ATA_TMOUT_BOOT;
	while (dev1) {
		u8 nsect, lbal;

		ap->ops->dev_select(ap, 1);
		if (ap->flags & ATA_FLAG_MMIO) {
			nsect = readb((void __iomem *) ioaddr->nsect_addr);
			lbal = readb((void __iomem *) ioaddr->lbal_addr);
		} else {
			nsect = inb(ioaddr->nsect_addr);
			lbal = inb(ioaddr->lbal_addr);
		}
		if ((nsect == 1) && (lbal == 1))
			break;
		if (time_after(jiffies, timeout)) {
			dev1 = 0;
			break;
		}
		msleep(50);	/* give drive a breather */
	}
	if (dev1)
		ata_busy_sleep(ap, ATA_TMOUT_BOOT_QUICK, ATA_TMOUT_BOOT);

	/* is all this really necessary? */
	ap->ops->dev_select(ap, 0);
	if (dev1)
		ap->ops->dev_select(ap, 1);
	if (dev0)
		ap->ops->dev_select(ap, 0);
}

/**
 *	ata_bus_edd - Issue EXECUTE DEVICE DIAGNOSTIC command.
 *	@ap: Port to reset and probe
 *
 *	Use the EXECUTE DEVICE DIAGNOSTIC command to reset and
 *	probe the bus.  Not often used these days.
 *
 *	LOCKING:
 *	PCI/etc. bus probe sem.
 *	Obtains host_set lock.
 *
 */

static unsigned int ata_bus_edd(struct ata_port *ap)
{
	struct ata_taskfile tf;
	unsigned long flags;

	/* set up execute-device-diag (bus reset) taskfile */
	/* also, take interrupts to a known state (disabled) */
	DPRINTK("execute-device-diag\n");
	ata_tf_init(ap, &tf, 0);
	tf.ctl |= ATA_NIEN;
	tf.command = ATA_CMD_EDD;
	tf.protocol = ATA_PROT_NODATA;

	/* do bus reset */
	spin_lock_irqsave(&ap->host_set->lock, flags);
	ata_tf_to_host(ap, &tf);
	spin_unlock_irqrestore(&ap->host_set->lock, flags);

	/* spec says at least 2ms.  but who knows with those
	 * crazy ATAPI devices...
	 */
	msleep(150);

	return ata_busy_sleep(ap, ATA_TMOUT_BOOT_QUICK, ATA_TMOUT_BOOT);
}

static unsigned int ata_bus_softreset(struct ata_port *ap,
				      unsigned int devmask)
{
	struct ata_ioports *ioaddr = &ap->ioaddr;

	DPRINTK("ata%u: bus reset via SRST\n", ap->id);

	/* software reset.  causes dev0 to be selected */
	if (ap->flags & ATA_FLAG_MMIO) {
		writeb(ap->ctl, (void __iomem *) ioaddr->ctl_addr);
		udelay(20);	/* FIXME: flush */
		writeb(ap->ctl | ATA_SRST, (void __iomem *) ioaddr->ctl_addr);
		udelay(20);	/* FIXME: flush */
		writeb(ap->ctl, (void __iomem *) ioaddr->ctl_addr);
	} else {
		outb(ap->ctl, ioaddr->ctl_addr);
		udelay(10);
		outb(ap->ctl | ATA_SRST, ioaddr->ctl_addr);
		udelay(10);
		outb(ap->ctl, ioaddr->ctl_addr);
	}

	/* spec mandates ">= 2ms" before checking status.
	 * We wait 150ms, because that was the magic delay used for
	 * ATAPI devices in Hale Landis's ATADRVR, for the period of time
	 * between when the ATA command register is written, and then
	 * status is checked.  Because waiting for "a while" before
	 * checking status is fine, post SRST, we perform this magic
	 * delay here as well.
	 */
	msleep(150);

	ata_bus_post_reset(ap, devmask);

	return 0;
}

/**
 *	ata_bus_reset - reset host port and associated ATA channel
 *	@ap: port to reset
 *
 *	This is typically the first time we actually start issuing
 *	commands to the ATA channel.  We wait for BSY to clear, then
 *	issue EXECUTE DEVICE DIAGNOSTIC command, polling for its
 *	result.  Determine what devices, if any, are on the channel
 *	by looking at the device 0/1 error register.  Look at the signature
 *	stored in each device's taskfile registers, to determine if
 *	the device is ATA or ATAPI.
 *
 *	LOCKING:
 *	PCI/etc. bus probe sem.
 *	Obtains host_set lock.
 *
 *	SIDE EFFECTS:
 *	Sets ATA_FLAG_PORT_DISABLED if bus reset fails.
 */

void ata_bus_reset(struct ata_port *ap)
{
	struct ata_ioports *ioaddr = &ap->ioaddr;
	unsigned int slave_possible = ap->flags & ATA_FLAG_SLAVE_POSS;
	u8 err;
	unsigned int dev0, dev1 = 0, rc = 0, devmask = 0;

	DPRINTK("ENTER, host %u, port %u\n", ap->id, ap->port_no);

	/* determine if device 0/1 are present */
	if (ap->flags & ATA_FLAG_SATA_RESET)
		dev0 = 1;
	else {
		dev0 = ata_devchk(ap, 0);
		if (slave_possible)
			dev1 = ata_devchk(ap, 1);
	}

	if (dev0)
		devmask |= (1 << 0);
	if (dev1)
		devmask |= (1 << 1);

	/* select device 0 again */
	ap->ops->dev_select(ap, 0);

	/* issue bus reset */
	if (ap->flags & ATA_FLAG_SRST)
		rc = ata_bus_softreset(ap, devmask);
	else if ((ap->flags & ATA_FLAG_SATA_RESET) == 0) {
		/* set up device control */
		if (ap->flags & ATA_FLAG_MMIO)
			writeb(ap->ctl, (void __iomem *) ioaddr->ctl_addr);
		else
			outb(ap->ctl, ioaddr->ctl_addr);
		rc = ata_bus_edd(ap);
	}

	if (rc)
		goto err_out;

	/*
	 * determine by signature whether we have ATA or ATAPI devices
	 */
	ap->device[0].class = ata_dev_try_classify(ap, 0, &err);
	if ((slave_possible) && (err != 0x81))
		ap->device[1].class = ata_dev_try_classify(ap, 1, &err);

	/* re-enable interrupts */
	if (ap->ioaddr.ctl_addr)	/* FIXME: hack. create a hook instead */
		ata_irq_on(ap);

	/* is double-select really necessary? */
	if (ap->device[1].class != ATA_DEV_NONE)
		ap->ops->dev_select(ap, 1);
	if (ap->device[0].class != ATA_DEV_NONE)
		ap->ops->dev_select(ap, 0);

	/* if no devices were detected, disable this port */
	if ((ap->device[0].class == ATA_DEV_NONE) &&
	    (ap->device[1].class == ATA_DEV_NONE))
		goto err_out;

	if (ap->flags & (ATA_FLAG_SATA_RESET | ATA_FLAG_SRST)) {
		/* set up device control for ATA_FLAG_SATA_RESET */
		if (ap->flags & ATA_FLAG_MMIO)
			writeb(ap->ctl, (void __iomem *) ioaddr->ctl_addr);
		else
			outb(ap->ctl, ioaddr->ctl_addr);
	}

	DPRINTK("EXIT\n");
	return;

err_out:
	printk(KERN_ERR "ata%u: disabling port\n", ap->id);
	ap->ops->port_disable(ap);

	DPRINTK("EXIT\n");
}

static int sata_phy_resume(struct ata_port *ap)
{
	unsigned long timeout = jiffies + (HZ * 5);
	u32 sstatus;

	scr_write_flush(ap, SCR_CONTROL, 0x300);

	/* Wait for phy to become ready, if necessary. */
	do {
		msleep(200);
		sstatus = scr_read(ap, SCR_STATUS);
		if ((sstatus & 0xf) != 1)
			return 0;
	} while (time_before(jiffies, timeout));

	return -1;
}

/**
 *	ata_std_probeinit - initialize probing
 *	@ap: port to be probed
 *
 *	@ap is about to be probed.  Initialize it.  This function is
 *	to be used as standard callback for ata_drive_probe_reset().
 *
 *	NOTE!!! Do not use this function as probeinit if a low level
 *	driver implements only hardreset.  Just pass NULL as probeinit
 *	in that case.  Using this function is probably okay but doing
 *	so makes reset sequence different from the original
 *	->phy_reset implementation and Jeff nervous.  :-P
 */
extern void ata_std_probeinit(struct ata_port *ap)
{
	if (ap->flags & ATA_FLAG_SATA && ap->ops->scr_read) {
		sata_phy_resume(ap);
		if (sata_dev_present(ap))
			ata_busy_sleep(ap, ATA_TMOUT_BOOT_QUICK, ATA_TMOUT_BOOT);
	}
}

/**
 *	ata_std_softreset - reset host port via ATA SRST
 *	@ap: port to reset
 *	@verbose: fail verbosely
 *	@classes: resulting classes of attached devices
 *
 *	Reset host port using ATA SRST.  This function is to be used
 *	as standard callback for ata_drive_*_reset() functions.
 *
 *	LOCKING:
 *	Kernel thread context (may sleep)
 *
 *	RETURNS:
 *	0 on success, -errno otherwise.
 */
int ata_std_softreset(struct ata_port *ap, int verbose, unsigned int *classes)
{
	unsigned int slave_possible = ap->flags & ATA_FLAG_SLAVE_POSS;
	unsigned int devmask = 0, err_mask;
	u8 err;

	DPRINTK("ENTER\n");

	if (ap->ops->scr_read && !sata_dev_present(ap)) {
		classes[0] = ATA_DEV_NONE;
		goto out;
	}

	/* determine if device 0/1 are present */
	if (ata_devchk(ap, 0))
		devmask |= (1 << 0);
	if (slave_possible && ata_devchk(ap, 1))
		devmask |= (1 << 1);

	/* select device 0 again */
	ap->ops->dev_select(ap, 0);

	/* issue bus reset */
	DPRINTK("about to softreset, devmask=%x\n", devmask);
	err_mask = ata_bus_softreset(ap, devmask);
	if (err_mask) {
		if (verbose)
			printk(KERN_ERR "ata%u: SRST failed (err_mask=0x%x)\n",
			       ap->id, err_mask);
		else
			DPRINTK("EXIT, softreset failed (err_mask=0x%x)\n",
				err_mask);
		return -EIO;
	}

	/* determine by signature whether we have ATA or ATAPI devices */
	classes[0] = ata_dev_try_classify(ap, 0, &err);
	if (slave_possible && err != 0x81)
		classes[1] = ata_dev_try_classify(ap, 1, &err);

 out:
	DPRINTK("EXIT, classes[0]=%u [1]=%u\n", classes[0], classes[1]);
	return 0;
}

/**
 *	sata_std_hardreset - reset host port via SATA phy reset
 *	@ap: port to reset
 *	@verbose: fail verbosely
 *	@class: resulting class of attached device
 *
 *	SATA phy-reset host port using DET bits of SControl register.
 *	This function is to be used as standard callback for
 *	ata_drive_*_reset().
 *
 *	LOCKING:
 *	Kernel thread context (may sleep)
 *
 *	RETURNS:
 *	0 on success, -errno otherwise.
 */
int sata_std_hardreset(struct ata_port *ap, int verbose, unsigned int *class)
{
	DPRINTK("ENTER\n");

	/* Issue phy wake/reset */
	scr_write_flush(ap, SCR_CONTROL, 0x301);

	/*
	 * Couldn't find anything in SATA I/II specs, but AHCI-1.1
	 * 10.4.2 says at least 1 ms.
	 */
	msleep(1);

	/* Bring phy back */
	sata_phy_resume(ap);

	/* TODO: phy layer with polling, timeouts, etc. */
	if (!sata_dev_present(ap)) {
		*class = ATA_DEV_NONE;
		DPRINTK("EXIT, link offline\n");
		return 0;
	}

	if (ata_busy_sleep(ap, ATA_TMOUT_BOOT_QUICK, ATA_TMOUT_BOOT)) {
		if (verbose)
			printk(KERN_ERR "ata%u: COMRESET failed "
			       "(device not ready)\n", ap->id);
		else
			DPRINTK("EXIT, device not ready\n");
		return -EIO;
	}

	ap->ops->dev_select(ap, 0);	/* probably unnecessary */

	*class = ata_dev_try_classify(ap, 0, NULL);

	DPRINTK("EXIT, class=%u\n", *class);
	return 0;
}

/**
 *	ata_std_postreset - standard postreset callback
 *	@ap: the target ata_port
 *	@classes: classes of attached devices
 *
 *	This function is invoked after a successful reset.  Note that
 *	the device might have been reset more than once using
 *	different reset methods before postreset is invoked.
 *
 *	This function is to be used as standard callback for
 *	ata_drive_*_reset().
 *
 *	LOCKING:
 *	Kernel thread context (may sleep)
 */
void ata_std_postreset(struct ata_port *ap, unsigned int *classes)
{
	DPRINTK("ENTER\n");

	/* set cable type if it isn't already set */
	if (ap->cbl == ATA_CBL_NONE && ap->flags & ATA_FLAG_SATA)
		ap->cbl = ATA_CBL_SATA;

	/* print link status */
	if (ap->cbl == ATA_CBL_SATA)
		sata_print_link_status(ap);

	/* re-enable interrupts */
	if (ap->ioaddr.ctl_addr)	/* FIXME: hack. create a hook instead */
		ata_irq_on(ap);

	/* is double-select really necessary? */
	if (classes[0] != ATA_DEV_NONE)
		ap->ops->dev_select(ap, 1);
	if (classes[1] != ATA_DEV_NONE)
		ap->ops->dev_select(ap, 0);

	/* bail out if no device is present */
	if (classes[0] == ATA_DEV_NONE && classes[1] == ATA_DEV_NONE) {
		DPRINTK("EXIT, no device\n");
		return;
	}

	/* set up device control */
	if (ap->ioaddr.ctl_addr) {
		if (ap->flags & ATA_FLAG_MMIO)
			writeb(ap->ctl, (void __iomem *) ap->ioaddr.ctl_addr);
		else
			outb(ap->ctl, ap->ioaddr.ctl_addr);
	}

	DPRINTK("EXIT\n");
}

/**
 *	ata_std_probe_reset - standard probe reset method
 *	@ap: prot to perform probe-reset
 *	@classes: resulting classes of attached devices
 *
 *	The stock off-the-shelf ->probe_reset method.
 *
 *	LOCKING:
 *	Kernel thread context (may sleep)
 *
 *	RETURNS:
 *	0 on success, -errno otherwise.
 */
int ata_std_probe_reset(struct ata_port *ap, unsigned int *classes)
{
	ata_reset_fn_t hardreset;

	hardreset = NULL;
	if (ap->flags & ATA_FLAG_SATA && ap->ops->scr_read)
		hardreset = sata_std_hardreset;

	return ata_drive_probe_reset(ap, ata_std_probeinit,
				     ata_std_softreset, hardreset,
				     ata_std_postreset, classes);
}

static int do_probe_reset(struct ata_port *ap, ata_reset_fn_t reset,
			  ata_postreset_fn_t postreset,
			  unsigned int *classes)
{
	int i, rc;

	for (i = 0; i < ATA_MAX_DEVICES; i++)
		classes[i] = ATA_DEV_UNKNOWN;

	rc = reset(ap, 0, classes);
	if (rc)
		return rc;

	/* If any class isn't ATA_DEV_UNKNOWN, consider classification
	 * is complete and convert all ATA_DEV_UNKNOWN to
	 * ATA_DEV_NONE.
	 */
	for (i = 0; i < ATA_MAX_DEVICES; i++)
		if (classes[i] != ATA_DEV_UNKNOWN)
			break;

	if (i < ATA_MAX_DEVICES)
		for (i = 0; i < ATA_MAX_DEVICES; i++)
			if (classes[i] == ATA_DEV_UNKNOWN)
				classes[i] = ATA_DEV_NONE;

	if (postreset)
		postreset(ap, classes);

	return classes[0] != ATA_DEV_UNKNOWN ? 0 : -ENODEV;
}

/**
 *	ata_drive_probe_reset - Perform probe reset with given methods
 *	@ap: port to reset
 *	@probeinit: probeinit method (can be NULL)
 *	@softreset: softreset method (can be NULL)
 *	@hardreset: hardreset method (can be NULL)
 *	@postreset: postreset method (can be NULL)
 *	@classes: resulting classes of attached devices
 *
 *	Reset the specified port and classify attached devices using
 *	given methods.  This function prefers softreset but tries all
 *	possible reset sequences to reset and classify devices.  This
 *	function is intended to be used for constructing ->probe_reset
 *	callback by low level drivers.
 *
 *	Reset methods should follow the following rules.
 *
 *	- Return 0 on sucess, -errno on failure.
 *	- If classification is supported, fill classes[] with
 *	  recognized class codes.
 *	- If classification is not supported, leave classes[] alone.
 *	- If verbose is non-zero, print error message on failure;
 *	  otherwise, shut up.
 *
 *	LOCKING:
 *	Kernel thread context (may sleep)
 *
 *	RETURNS:
 *	0 on success, -EINVAL if no reset method is avaliable, -ENODEV
 *	if classification fails, and any error code from reset
 *	methods.
 */
int ata_drive_probe_reset(struct ata_port *ap, ata_probeinit_fn_t probeinit,
			  ata_reset_fn_t softreset, ata_reset_fn_t hardreset,
			  ata_postreset_fn_t postreset, unsigned int *classes)
{
	int rc = -EINVAL;

	if (probeinit)
		probeinit(ap);

	if (softreset) {
		rc = do_probe_reset(ap, softreset, postreset, classes);
		if (rc == 0)
			return 0;
	}

	if (!hardreset)
		return rc;

	rc = do_probe_reset(ap, hardreset, postreset, classes);
	if (rc == 0 || rc != -ENODEV)
		return rc;

	if (softreset)
		rc = do_probe_reset(ap, softreset, postreset, classes);

	return rc;
}

static void ata_pr_blacklisted(const struct ata_port *ap,
			       const struct ata_device *dev)
{
	printk(KERN_WARNING "ata%u: dev %u is on DMA blacklist, disabling DMA\n",
		ap->id, dev->devno);
}

static const char * const ata_dma_blacklist [] = {
	"WDC AC11000H",
	"WDC AC22100H",
	"WDC AC32500H",
	"WDC AC33100H",
	"WDC AC31600H",
	"WDC AC32100H",
	"WDC AC23200L",
	"Compaq CRD-8241B",
	"CRD-8400B",
	"CRD-8480B",
	"CRD-8482B",
 	"CRD-84",
	"SanDisk SDP3B",
	"SanDisk SDP3B-64",
	"SANYO CD-ROM CRD",
	"HITACHI CDR-8",
	"HITACHI CDR-8335",
	"HITACHI CDR-8435",
	"Toshiba CD-ROM XM-6202B",
	"TOSHIBA CD-ROM XM-1702BC",
	"CD-532E-A",
	"E-IDE CD-ROM CR-840",
	"CD-ROM Drive/F5A",
	"WPI CDD-820",
	"SAMSUNG CD-ROM SC-148C",
	"SAMSUNG CD-ROM SC",
	"SanDisk SDP3B-64",
	"ATAPI CD-ROM DRIVE 40X MAXIMUM",
	"_NEC DV5800A",
};

static int ata_dma_blacklisted(const struct ata_device *dev)
{
	unsigned char model_num[41];
	int i;

	ata_id_c_string(dev->id, model_num, ATA_ID_PROD_OFS, sizeof(model_num));

	for (i = 0; i < ARRAY_SIZE(ata_dma_blacklist); i++)
		if (!strcmp(ata_dma_blacklist[i], model_num))
			return 1;

	return 0;
}

static unsigned int ata_get_mode_mask(const struct ata_port *ap, int shift)
{
	const struct ata_device *master, *slave;
	unsigned int mask;

	master = &ap->device[0];
	slave = &ap->device[1];

	WARN_ON(!ata_dev_present(master) && !ata_dev_present(slave));

	if (shift == ATA_SHIFT_UDMA) {
		mask = ap->udma_mask;
		if (ata_dev_present(master)) {
			mask &= (master->id[ATA_ID_UDMA_MODES] & 0xff);
			if (ata_dma_blacklisted(master)) {
				mask = 0;
				ata_pr_blacklisted(ap, master);
			}
		}
		if (ata_dev_present(slave)) {
			mask &= (slave->id[ATA_ID_UDMA_MODES] & 0xff);
			if (ata_dma_blacklisted(slave)) {
				mask = 0;
				ata_pr_blacklisted(ap, slave);
			}
		}
	}
	else if (shift == ATA_SHIFT_MWDMA) {
		mask = ap->mwdma_mask;
		if (ata_dev_present(master)) {
			mask &= (master->id[ATA_ID_MWDMA_MODES] & 0x07);
			if (ata_dma_blacklisted(master)) {
				mask = 0;
				ata_pr_blacklisted(ap, master);
			}
		}
		if (ata_dev_present(slave)) {
			mask &= (slave->id[ATA_ID_MWDMA_MODES] & 0x07);
			if (ata_dma_blacklisted(slave)) {
				mask = 0;
				ata_pr_blacklisted(ap, slave);
			}
		}
	}
	else if (shift == ATA_SHIFT_PIO) {
		mask = ap->pio_mask;
		if (ata_dev_present(master)) {
			/* spec doesn't return explicit support for
			 * PIO0-2, so we fake it
			 */
			u16 tmp_mode = master->id[ATA_ID_PIO_MODES] & 0x03;
			tmp_mode <<= 3;
			tmp_mode |= 0x7;
			mask &= tmp_mode;
		}
		if (ata_dev_present(slave)) {
			/* spec doesn't return explicit support for
			 * PIO0-2, so we fake it
			 */
			u16 tmp_mode = slave->id[ATA_ID_PIO_MODES] & 0x03;
			tmp_mode <<= 3;
			tmp_mode |= 0x7;
			mask &= tmp_mode;
		}
	}
	else {
		mask = 0xffffffff; /* shut up compiler warning */
		BUG();
	}

	return mask;
}

/* find greatest bit */
static int fgb(u32 bitmap)
{
	unsigned int i;
	int x = -1;

	for (i = 0; i < 32; i++)
		if (bitmap & (1 << i))
			x = i;

	return x;
}

/**
 *	ata_choose_xfer_mode - attempt to find best transfer mode
 *	@ap: Port for which an xfer mode will be selected
 *	@xfer_mode_out: (output) SET FEATURES - XFER MODE code
 *	@xfer_shift_out: (output) bit shift that selects this mode
 *
 *	Based on host and device capabilities, determine the
 *	maximum transfer mode that is amenable to all.
 *
 *	LOCKING:
 *	PCI/etc. bus probe sem.
 *
 *	RETURNS:
 *	Zero on success, negative on error.
 */

static int ata_choose_xfer_mode(const struct ata_port *ap,
				u8 *xfer_mode_out,
				unsigned int *xfer_shift_out)
{
	unsigned int mask, shift;
	int x, i;

	for (i = 0; i < ARRAY_SIZE(xfer_mode_classes); i++) {
		shift = xfer_mode_classes[i].shift;
		mask = ata_get_mode_mask(ap, shift);

		x = fgb(mask);
		if (x >= 0) {
			*xfer_mode_out = xfer_mode_classes[i].base + x;
			*xfer_shift_out = shift;
			return 0;
		}
	}

	return -1;
}

/**
 *	ata_dev_set_xfermode - Issue SET FEATURES - XFER MODE command
 *	@ap: Port associated with device @dev
 *	@dev: Device to which command will be sent
 *
 *	Issue SET FEATURES - XFER MODE command to device @dev
 *	on port @ap.
 *
 *	LOCKING:
 *	PCI/etc. bus probe sem.
 */

static void ata_dev_set_xfermode(struct ata_port *ap, struct ata_device *dev)
{
	struct ata_taskfile tf;

	/* set up set-features taskfile */
	DPRINTK("set features - xfer mode\n");

	ata_tf_init(ap, &tf, dev->devno);
	tf.command = ATA_CMD_SET_FEATURES;
	tf.feature = SETFEATURES_XFER;
	tf.flags |= ATA_TFLAG_ISADDR | ATA_TFLAG_DEVICE;
	tf.protocol = ATA_PROT_NODATA;
	tf.nsect = dev->xfer_mode;

	if (ata_exec_internal(ap, dev, &tf, DMA_NONE, NULL, 0)) {
		printk(KERN_ERR "ata%u: failed to set xfermode, disabled\n",
		       ap->id);
		ata_port_disable(ap);
	}

	DPRINTK("EXIT\n");
}

/**
 *	ata_dev_init_params - Issue INIT DEV PARAMS command
 *	@ap: Port associated with device @dev
 *	@dev: Device to which command will be sent
 *
 *	LOCKING:
 *	Kernel thread context (may sleep)
 *
 *	RETURNS:
 *	0 on success, AC_ERR_* mask otherwise.
 */

static unsigned int ata_dev_init_params(struct ata_port *ap,
					struct ata_device *dev)
{
	struct ata_taskfile tf;
	unsigned int err_mask;
	u16 sectors = dev->id[6];
	u16 heads   = dev->id[3];

	/* Number of sectors per track 1-255. Number of heads 1-16 */
	if (sectors < 1 || sectors > 255 || heads < 1 || heads > 16)
		return 0;

	/* set up init dev params taskfile */
	DPRINTK("init dev params \n");

	ata_tf_init(ap, &tf, dev->devno);
	tf.command = ATA_CMD_INIT_DEV_PARAMS;
	tf.flags |= ATA_TFLAG_ISADDR | ATA_TFLAG_DEVICE;
	tf.protocol = ATA_PROT_NODATA;
	tf.nsect = sectors;
	tf.device |= (heads - 1) & 0x0f; /* max head = num. of heads - 1 */

	err_mask = ata_exec_internal(ap, dev, &tf, DMA_NONE, NULL, 0);

	DPRINTK("EXIT, err_mask=%x\n", err_mask);
	return err_mask;
}

/**
 *	ata_sg_clean - Unmap DMA memory associated with command
 *	@qc: Command containing DMA memory to be released
 *
 *	Unmap all mapped DMA memory associated with this command.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 */

static void ata_sg_clean(struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;
	struct scatterlist *sg = qc->__sg;
	int dir = qc->dma_dir;
	void *pad_buf = NULL;

	WARN_ON(!(qc->flags & ATA_QCFLAG_DMAMAP));
	WARN_ON(sg == NULL);

	if (qc->flags & ATA_QCFLAG_SINGLE)
		WARN_ON(qc->n_elem > 1);

	VPRINTK("unmapping %u sg elements\n", qc->n_elem);

	/* if we padded the buffer out to 32-bit bound, and data
	 * xfer direction is from-device, we must copy from the
	 * pad buffer back into the supplied buffer
	 */
	if (qc->pad_len && !(qc->tf.flags & ATA_TFLAG_WRITE))
		pad_buf = ap->pad + (qc->tag * ATA_DMA_PAD_SZ);

	if (qc->flags & ATA_QCFLAG_SG) {
		if (qc->n_elem)
			dma_unmap_sg(ap->host_set->dev, sg, qc->n_elem, dir);
		/* restore last sg */
		sg[qc->orig_n_elem - 1].length += qc->pad_len;
		if (pad_buf) {
			struct scatterlist *psg = &qc->pad_sgent;
			void *addr = kmap_atomic(psg->page, KM_IRQ0);
			memcpy(addr + psg->offset, pad_buf, qc->pad_len);
			kunmap_atomic(addr, KM_IRQ0);
		}
	} else {
		if (qc->n_elem)
			dma_unmap_single(ap->host_set->dev,
				sg_dma_address(&sg[0]), sg_dma_len(&sg[0]),
				dir);
		/* restore sg */
		sg->length += qc->pad_len;
		if (pad_buf)
			memcpy(qc->buf_virt + sg->length - qc->pad_len,
			       pad_buf, qc->pad_len);
	}

	qc->flags &= ~ATA_QCFLAG_DMAMAP;
	qc->__sg = NULL;
}

/**
 *	ata_fill_sg - Fill PCI IDE PRD table
 *	@qc: Metadata associated with taskfile to be transferred
 *
 *	Fill PCI IDE PRD (scatter-gather) table with segments
 *	associated with the current disk command.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 *
 */
static void ata_fill_sg(struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;
	struct scatterlist *sg;
	unsigned int idx;

	WARN_ON(qc->__sg == NULL);
	WARN_ON(qc->n_elem == 0 && qc->pad_len == 0);

	idx = 0;
	ata_for_each_sg(sg, qc) {
		u32 addr, offset;
		u32 sg_len, len;

		/* determine if physical DMA addr spans 64K boundary.
		 * Note h/w doesn't support 64-bit, so we unconditionally
		 * truncate dma_addr_t to u32.
		 */
		addr = (u32) sg_dma_address(sg);
		sg_len = sg_dma_len(sg);

		while (sg_len) {
			offset = addr & 0xffff;
			len = sg_len;
			if ((offset + sg_len) > 0x10000)
				len = 0x10000 - offset;

			ap->prd[idx].addr = cpu_to_le32(addr);
			ap->prd[idx].flags_len = cpu_to_le32(len & 0xffff);
			VPRINTK("PRD[%u] = (0x%X, 0x%X)\n", idx, addr, len);

			idx++;
			sg_len -= len;
			addr += len;
		}
	}

	if (idx)
		ap->prd[idx - 1].flags_len |= cpu_to_le32(ATA_PRD_EOT);
}
/**
 *	ata_check_atapi_dma - Check whether ATAPI DMA can be supported
 *	@qc: Metadata associated with taskfile to check
 *
 *	Allow low-level driver to filter ATA PACKET commands, returning
 *	a status indicating whether or not it is OK to use DMA for the
 *	supplied PACKET command.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 *
 *	RETURNS: 0 when ATAPI DMA can be used
 *               nonzero otherwise
 */
int ata_check_atapi_dma(struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;
	int rc = 0; /* Assume ATAPI DMA is OK by default */

	if (ap->ops->check_atapi_dma)
		rc = ap->ops->check_atapi_dma(qc);

	return rc;
}
/**
 *	ata_qc_prep - Prepare taskfile for submission
 *	@qc: Metadata associated with taskfile to be prepared
 *
 *	Prepare ATA taskfile for submission.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 */
void ata_qc_prep(struct ata_queued_cmd *qc)
{
	if (!(qc->flags & ATA_QCFLAG_DMAMAP))
		return;

	ata_fill_sg(qc);
}

/**
 *	ata_sg_init_one - Associate command with memory buffer
 *	@qc: Command to be associated
 *	@buf: Memory buffer
 *	@buflen: Length of memory buffer, in bytes.
 *
 *	Initialize the data-related elements of queued_cmd @qc
 *	to point to a single memory buffer, @buf of byte length @buflen.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 */

void ata_sg_init_one(struct ata_queued_cmd *qc, void *buf, unsigned int buflen)
{
	struct scatterlist *sg;

	qc->flags |= ATA_QCFLAG_SINGLE;

	memset(&qc->sgent, 0, sizeof(qc->sgent));
	qc->__sg = &qc->sgent;
	qc->n_elem = 1;
	qc->orig_n_elem = 1;
	qc->buf_virt = buf;

	sg = qc->__sg;
	sg_init_one(sg, buf, buflen);
}

/**
 *	ata_sg_init - Associate command with scatter-gather table.
 *	@qc: Command to be associated
 *	@sg: Scatter-gather table.
 *	@n_elem: Number of elements in s/g table.
 *
 *	Initialize the data-related elements of queued_cmd @qc
 *	to point to a scatter-gather table @sg, containing @n_elem
 *	elements.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 */

void ata_sg_init(struct ata_queued_cmd *qc, struct scatterlist *sg,
		 unsigned int n_elem)
{
	qc->flags |= ATA_QCFLAG_SG;
	qc->__sg = sg;
	qc->n_elem = n_elem;
	qc->orig_n_elem = n_elem;
}

/**
 *	ata_sg_setup_one - DMA-map the memory buffer associated with a command.
 *	@qc: Command with memory buffer to be mapped.
 *
 *	DMA-map the memory buffer associated with queued_cmd @qc.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 *
 *	RETURNS:
 *	Zero on success, negative on error.
 */

static int ata_sg_setup_one(struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;
	int dir = qc->dma_dir;
	struct scatterlist *sg = qc->__sg;
	dma_addr_t dma_address;
	int trim_sg = 0;

	/* we must lengthen transfers to end on a 32-bit boundary */
	qc->pad_len = sg->length & 3;
	if (qc->pad_len) {
		void *pad_buf = ap->pad + (qc->tag * ATA_DMA_PAD_SZ);
		struct scatterlist *psg = &qc->pad_sgent;

		WARN_ON(qc->dev->class != ATA_DEV_ATAPI);

		memset(pad_buf, 0, ATA_DMA_PAD_SZ);

		if (qc->tf.flags & ATA_TFLAG_WRITE)
			memcpy(pad_buf, qc->buf_virt + sg->length - qc->pad_len,
			       qc->pad_len);

		sg_dma_address(psg) = ap->pad_dma + (qc->tag * ATA_DMA_PAD_SZ);
		sg_dma_len(psg) = ATA_DMA_PAD_SZ;
		/* trim sg */
		sg->length -= qc->pad_len;
		if (sg->length == 0)
			trim_sg = 1;

		DPRINTK("padding done, sg->length=%u pad_len=%u\n",
			sg->length, qc->pad_len);
	}

	if (trim_sg) {
		qc->n_elem--;
		goto skip_map;
	}

	dma_address = dma_map_single(ap->host_set->dev, qc->buf_virt,
				     sg->length, dir);
	if (dma_mapping_error(dma_address)) {
		/* restore sg */
		sg->length += qc->pad_len;
		return -1;
	}

	sg_dma_address(sg) = dma_address;
	sg_dma_len(sg) = sg->length;

skip_map:
	DPRINTK("mapped buffer of %d bytes for %s\n", sg_dma_len(sg),
		qc->tf.flags & ATA_TFLAG_WRITE ? "write" : "read");

	return 0;
}

/**
 *	ata_sg_setup - DMA-map the scatter-gather table associated with a command.
 *	@qc: Command with scatter-gather table to be mapped.
 *
 *	DMA-map the scatter-gather table associated with queued_cmd @qc.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 *
 *	RETURNS:
 *	Zero on success, negative on error.
 *
 */

static int ata_sg_setup(struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;
	struct scatterlist *sg = qc->__sg;
	struct scatterlist *lsg = &sg[qc->n_elem - 1];
	int n_elem, pre_n_elem, dir, trim_sg = 0;

	VPRINTK("ENTER, ata%u\n", ap->id);
	WARN_ON(!(qc->flags & ATA_QCFLAG_SG));

	/* we must lengthen transfers to end on a 32-bit boundary */
	qc->pad_len = lsg->length & 3;
	if (qc->pad_len) {
		void *pad_buf = ap->pad + (qc->tag * ATA_DMA_PAD_SZ);
		struct scatterlist *psg = &qc->pad_sgent;
		unsigned int offset;

		WARN_ON(qc->dev->class != ATA_DEV_ATAPI);

		memset(pad_buf, 0, ATA_DMA_PAD_SZ);

		/*
		 * psg->page/offset are used to copy to-be-written
		 * data in this function or read data in ata_sg_clean.
		 */
		offset = lsg->offset + lsg->length - qc->pad_len;
		psg->page = nth_page(lsg->page, offset >> PAGE_SHIFT);
		psg->offset = offset_in_page(offset);

		if (qc->tf.flags & ATA_TFLAG_WRITE) {
			void *addr = kmap_atomic(psg->page, KM_IRQ0);
			memcpy(pad_buf, addr + psg->offset, qc->pad_len);
			kunmap_atomic(addr, KM_IRQ0);
		}

		sg_dma_address(psg) = ap->pad_dma + (qc->tag * ATA_DMA_PAD_SZ);
		sg_dma_len(psg) = ATA_DMA_PAD_SZ;
		/* trim last sg */
		lsg->length -= qc->pad_len;
		if (lsg->length == 0)
			trim_sg = 1;

		DPRINTK("padding done, sg[%d].length=%u pad_len=%u\n",
			qc->n_elem - 1, lsg->length, qc->pad_len);
	}

	pre_n_elem = qc->n_elem;
	if (trim_sg && pre_n_elem)
		pre_n_elem--;

	if (!pre_n_elem) {
		n_elem = 0;
		goto skip_map;
	}

	dir = qc->dma_dir;
	n_elem = dma_map_sg(ap->host_set->dev, sg, pre_n_elem, dir);
	if (n_elem < 1) {
		/* restore last sg */
		lsg->length += qc->pad_len;
		return -1;
	}

	DPRINTK("%d sg elements mapped\n", n_elem);

skip_map:
	qc->n_elem = n_elem;

	return 0;
}

/**
 *	ata_poll_qc_complete - turn irq back on and finish qc
 *	@qc: Command to complete
 *	@err_mask: ATA status register content
 *
 *	LOCKING:
 *	None.  (grabs host lock)
 */

void ata_poll_qc_complete(struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;
	unsigned long flags;

	spin_lock_irqsave(&ap->host_set->lock, flags);
	ap->flags &= ~ATA_FLAG_NOINTR;
	ata_irq_on(ap);
	ata_qc_complete(qc);
	spin_unlock_irqrestore(&ap->host_set->lock, flags);
}

/**
 *	ata_pio_poll - poll using PIO, depending on current state
 *	@ap: the target ata_port
 *
 *	LOCKING:
 *	None.  (executing in kernel thread context)
 *
 *	RETURNS:
 *	timeout value to use
 */

static unsigned long ata_pio_poll(struct ata_port *ap)
{
	struct ata_queued_cmd *qc;
	u8 status;
	unsigned int poll_state = HSM_ST_UNKNOWN;
	unsigned int reg_state = HSM_ST_UNKNOWN;

	qc = ata_qc_from_tag(ap, ap->active_tag);
	WARN_ON(qc == NULL);

	switch (ap->hsm_task_state) {
	case HSM_ST:
	case HSM_ST_POLL:
		poll_state = HSM_ST_POLL;
		reg_state = HSM_ST;
		break;
	case HSM_ST_LAST:
	case HSM_ST_LAST_POLL:
		poll_state = HSM_ST_LAST_POLL;
		reg_state = HSM_ST_LAST;
		break;
	default:
		BUG();
		break;
	}

	status = ata_chk_status(ap);
	if (status & ATA_BUSY) {
		if (time_after(jiffies, ap->pio_task_timeout)) {
			qc->err_mask |= AC_ERR_TIMEOUT;
			ap->hsm_task_state = HSM_ST_TMOUT;
			return 0;
		}
		ap->hsm_task_state = poll_state;
		return ATA_SHORT_PAUSE;
	}

	ap->hsm_task_state = reg_state;
	return 0;
}

/**
 *	ata_pio_complete - check if drive is busy or idle
 *	@ap: the target ata_port
 *
 *	LOCKING:
 *	None.  (executing in kernel thread context)
 *
 *	RETURNS:
 *	Non-zero if qc completed, zero otherwise.
 */

static int ata_pio_complete (struct ata_port *ap)
{
	struct ata_queued_cmd *qc;
	u8 drv_stat;

	/*
	 * This is purely heuristic.  This is a fast path.  Sometimes when
	 * we enter, BSY will be cleared in a chk-status or two.  If not,
	 * the drive is probably seeking or something.  Snooze for a couple
	 * msecs, then chk-status again.  If still busy, fall back to
	 * HSM_ST_POLL state.
	 */
	drv_stat = ata_busy_wait(ap, ATA_BUSY, 10);
	if (drv_stat & ATA_BUSY) {
		msleep(2);
		drv_stat = ata_busy_wait(ap, ATA_BUSY, 10);
		if (drv_stat & ATA_BUSY) {
			ap->hsm_task_state = HSM_ST_LAST_POLL;
			ap->pio_task_timeout = jiffies + ATA_TMOUT_PIO;
			return 0;
		}
	}

	qc = ata_qc_from_tag(ap, ap->active_tag);
	WARN_ON(qc == NULL);

	drv_stat = ata_wait_idle(ap);
	if (!ata_ok(drv_stat)) {
		qc->err_mask |= __ac_err_mask(drv_stat);
		ap->hsm_task_state = HSM_ST_ERR;
		return 0;
	}

	ap->hsm_task_state = HSM_ST_IDLE;

	WARN_ON(qc->err_mask);
	ata_poll_qc_complete(qc);

	/* another command may start at this point */

	return 1;
}


/**
 *	swap_buf_le16 - swap halves of 16-bit words in place
 *	@buf:  Buffer to swap
 *	@buf_words:  Number of 16-bit words in buffer.
 *
 *	Swap halves of 16-bit words if needed to convert from
 *	little-endian byte order to native cpu byte order, or
 *	vice-versa.
 *
 *	LOCKING:
 *	Inherited from caller.
 */
void swap_buf_le16(u16 *buf, unsigned int buf_words)
{
#ifdef __BIG_ENDIAN
	unsigned int i;

	for (i = 0; i < buf_words; i++)
		buf[i] = le16_to_cpu(buf[i]);
#endif /* __BIG_ENDIAN */
}

/**
 *	ata_mmio_data_xfer - Transfer data by MMIO
 *	@ap: port to read/write
 *	@buf: data buffer
 *	@buflen: buffer length
 *	@write_data: read/write
 *
 *	Transfer data from/to the device data register by MMIO.
 *
 *	LOCKING:
 *	Inherited from caller.
 */

static void ata_mmio_data_xfer(struct ata_port *ap, unsigned char *buf,
			       unsigned int buflen, int write_data)
{
	unsigned int i;
	unsigned int words = buflen >> 1;
	u16 *buf16 = (u16 *) buf;
	void __iomem *mmio = (void __iomem *)ap->ioaddr.data_addr;

	/* Transfer multiple of 2 bytes */
	if (write_data) {
		for (i = 0; i < words; i++)
			writew(le16_to_cpu(buf16[i]), mmio);
	} else {
		for (i = 0; i < words; i++)
			buf16[i] = cpu_to_le16(readw(mmio));
	}

	/* Transfer trailing 1 byte, if any. */
	if (unlikely(buflen & 0x01)) {
		u16 align_buf[1] = { 0 };
		unsigned char *trailing_buf = buf + buflen - 1;

		if (write_data) {
			memcpy(align_buf, trailing_buf, 1);
			writew(le16_to_cpu(align_buf[0]), mmio);
		} else {
			align_buf[0] = cpu_to_le16(readw(mmio));
			memcpy(trailing_buf, align_buf, 1);
		}
	}
}

/**
 *	ata_pio_data_xfer - Transfer data by PIO
 *	@ap: port to read/write
 *	@buf: data buffer
 *	@buflen: buffer length
 *	@write_data: read/write
 *
 *	Transfer data from/to the device data register by PIO.
 *
 *	LOCKING:
 *	Inherited from caller.
 */

static void ata_pio_data_xfer(struct ata_port *ap, unsigned char *buf,
			      unsigned int buflen, int write_data)
{
	unsigned int words = buflen >> 1;

	/* Transfer multiple of 2 bytes */
	if (write_data)
		outsw(ap->ioaddr.data_addr, buf, words);
	else
		insw(ap->ioaddr.data_addr, buf, words);

	/* Transfer trailing 1 byte, if any. */
	if (unlikely(buflen & 0x01)) {
		u16 align_buf[1] = { 0 };
		unsigned char *trailing_buf = buf + buflen - 1;

		if (write_data) {
			memcpy(align_buf, trailing_buf, 1);
			outw(le16_to_cpu(align_buf[0]), ap->ioaddr.data_addr);
		} else {
			align_buf[0] = cpu_to_le16(inw(ap->ioaddr.data_addr));
			memcpy(trailing_buf, align_buf, 1);
		}
	}
}

/**
 *	ata_data_xfer - Transfer data from/to the data register.
 *	@ap: port to read/write
 *	@buf: data buffer
 *	@buflen: buffer length
 *	@do_write: read/write
 *
 *	Transfer data from/to the device data register.
 *
 *	LOCKING:
 *	Inherited from caller.
 */

static void ata_data_xfer(struct ata_port *ap, unsigned char *buf,
			  unsigned int buflen, int do_write)
{
	/* Make the crap hardware pay the costs not the good stuff */
	if (unlikely(ap->flags & ATA_FLAG_IRQ_MASK)) {
		unsigned long flags;
		local_irq_save(flags);
		if (ap->flags & ATA_FLAG_MMIO)
			ata_mmio_data_xfer(ap, buf, buflen, do_write);
		else
			ata_pio_data_xfer(ap, buf, buflen, do_write);
		local_irq_restore(flags);
	} else {
		if (ap->flags & ATA_FLAG_MMIO)
			ata_mmio_data_xfer(ap, buf, buflen, do_write);
		else
			ata_pio_data_xfer(ap, buf, buflen, do_write);
	}
}

/**
 *	ata_pio_sector - Transfer ATA_SECT_SIZE (512 bytes) of data.
 *	@qc: Command on going
 *
 *	Transfer ATA_SECT_SIZE of data from/to the ATA device.
 *
 *	LOCKING:
 *	Inherited from caller.
 */

static void ata_pio_sector(struct ata_queued_cmd *qc)
{
	int do_write = (qc->tf.flags & ATA_TFLAG_WRITE);
	struct scatterlist *sg = qc->__sg;
	struct ata_port *ap = qc->ap;
	struct page *page;
	unsigned int offset;
	unsigned char *buf;

	if (qc->cursect == (qc->nsect - 1))
		ap->hsm_task_state = HSM_ST_LAST;

	page = sg[qc->cursg].page;
	offset = sg[qc->cursg].offset + qc->cursg_ofs * ATA_SECT_SIZE;

	/* get the current page and offset */
	page = nth_page(page, (offset >> PAGE_SHIFT));
	offset %= PAGE_SIZE;

	buf = kmap(page) + offset;

	qc->cursect++;
	qc->cursg_ofs++;

	if ((qc->cursg_ofs * ATA_SECT_SIZE) == (&sg[qc->cursg])->length) {
		qc->cursg++;
		qc->cursg_ofs = 0;
	}

	DPRINTK("data %s\n", qc->tf.flags & ATA_TFLAG_WRITE ? "write" : "read");

	/* do the actual data transfer */
	do_write = (qc->tf.flags & ATA_TFLAG_WRITE);
	ata_data_xfer(ap, buf, ATA_SECT_SIZE, do_write);

	kunmap(page);
}

/**
 *	__atapi_pio_bytes - Transfer data from/to the ATAPI device.
 *	@qc: Command on going
 *	@bytes: number of bytes
 *
 *	Transfer Transfer data from/to the ATAPI device.
 *
 *	LOCKING:
 *	Inherited from caller.
 *
 */

static void __atapi_pio_bytes(struct ata_queued_cmd *qc, unsigned int bytes)
{
	int do_write = (qc->tf.flags & ATA_TFLAG_WRITE);
	struct scatterlist *sg = qc->__sg;
	struct ata_port *ap = qc->ap;
	struct page *page;
	unsigned char *buf;
	unsigned int offset, count;

	if (qc->curbytes + bytes >= qc->nbytes)
		ap->hsm_task_state = HSM_ST_LAST;

next_sg:
	if (unlikely(qc->cursg >= qc->n_elem)) {
		/*
		 * The end of qc->sg is reached and the device expects
		 * more data to transfer. In order not to overrun qc->sg
		 * and fulfill length specified in the byte count register,
		 *    - for read case, discard trailing data from the device
		 *    - for write case, padding zero data to the device
		 */
		u16 pad_buf[1] = { 0 };
		unsigned int words = bytes >> 1;
		unsigned int i;

		if (words) /* warning if bytes > 1 */
			printk(KERN_WARNING "ata%u: %u bytes trailing data\n",
			       ap->id, bytes);

		for (i = 0; i < words; i++)
			ata_data_xfer(ap, (unsigned char*)pad_buf, 2, do_write);

		ap->hsm_task_state = HSM_ST_LAST;
		return;
	}

	sg = &qc->__sg[qc->cursg];

	page = sg->page;
	offset = sg->offset + qc->cursg_ofs;

	/* get the current page and offset */
	page = nth_page(page, (offset >> PAGE_SHIFT));
	offset %= PAGE_SIZE;

	/* don't overrun current sg */
	count = min(sg->length - qc->cursg_ofs, bytes);

	/* don't cross page boundaries */
	count = min(count, (unsigned int)PAGE_SIZE - offset);

	buf = kmap(page) + offset;

	bytes -= count;
	qc->curbytes += count;
	qc->cursg_ofs += count;

	if (qc->cursg_ofs == sg->length) {
		qc->cursg++;
		qc->cursg_ofs = 0;
	}

	DPRINTK("data %s\n", qc->tf.flags & ATA_TFLAG_WRITE ? "write" : "read");

	/* do the actual data transfer */
	ata_data_xfer(ap, buf, count, do_write);

	kunmap(page);

	if (bytes)
		goto next_sg;
}

/**
 *	atapi_pio_bytes - Transfer data from/to the ATAPI device.
 *	@qc: Command on going
 *
 *	Transfer Transfer data from/to the ATAPI device.
 *
 *	LOCKING:
 *	Inherited from caller.
 */

static void atapi_pio_bytes(struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;
	struct ata_device *dev = qc->dev;
	unsigned int ireason, bc_lo, bc_hi, bytes;
	int i_write, do_write = (qc->tf.flags & ATA_TFLAG_WRITE) ? 1 : 0;

	ap->ops->tf_read(ap, &qc->tf);
	ireason = qc->tf.nsect;
	bc_lo = qc->tf.lbam;
	bc_hi = qc->tf.lbah;
	bytes = (bc_hi << 8) | bc_lo;

	/* shall be cleared to zero, indicating xfer of data */
	if (ireason & (1 << 0))
		goto err_out;

	/* make sure transfer direction matches expected */
	i_write = ((ireason & (1 << 1)) == 0) ? 1 : 0;
	if (do_write != i_write)
		goto err_out;

	__atapi_pio_bytes(qc, bytes);

	return;

err_out:
	printk(KERN_INFO "ata%u: dev %u: ATAPI check failed\n",
	      ap->id, dev->devno);
	qc->err_mask |= AC_ERR_HSM;
	ap->hsm_task_state = HSM_ST_ERR;
}

/**
 *	ata_pio_block - start PIO on a block
 *	@ap: the target ata_port
 *
 *	LOCKING:
 *	None.  (executing in kernel thread context)
 */

static void ata_pio_block(struct ata_port *ap)
{
	struct ata_queued_cmd *qc;
	u8 status;

	/*
	 * This is purely heuristic.  This is a fast path.
	 * Sometimes when we enter, BSY will be cleared in
	 * a chk-status or two.  If not, the drive is probably seeking
	 * or something.  Snooze for a couple msecs, then
	 * chk-status again.  If still busy, fall back to
	 * HSM_ST_POLL state.
	 */
	status = ata_busy_wait(ap, ATA_BUSY, 5);
	if (status & ATA_BUSY) {
		msleep(2);
		status = ata_busy_wait(ap, ATA_BUSY, 10);
		if (status & ATA_BUSY) {
			ap->hsm_task_state = HSM_ST_POLL;
			ap->pio_task_timeout = jiffies + ATA_TMOUT_PIO;
			return;
		}
	}

	qc = ata_qc_from_tag(ap, ap->active_tag);
	WARN_ON(qc == NULL);

	/* check error */
	if (status & (ATA_ERR | ATA_DF)) {
		qc->err_mask |= AC_ERR_DEV;
		ap->hsm_task_state = HSM_ST_ERR;
		return;
	}

	/* transfer data if any */
	if (is_atapi_taskfile(&qc->tf)) {
		/* DRQ=0 means no more data to transfer */
		if ((status & ATA_DRQ) == 0) {
			ap->hsm_task_state = HSM_ST_LAST;
			return;
		}

		atapi_pio_bytes(qc);
	} else {
		/* handle BSY=0, DRQ=0 as error */
		if ((status & ATA_DRQ) == 0) {
			qc->err_mask |= AC_ERR_HSM;
			ap->hsm_task_state = HSM_ST_ERR;
			return;
		}

		ata_pio_sector(qc);
	}
}

static void ata_pio_error(struct ata_port *ap)
{
	struct ata_queued_cmd *qc;

	qc = ata_qc_from_tag(ap, ap->active_tag);
	WARN_ON(qc == NULL);

	if (qc->tf.command != ATA_CMD_PACKET)
		printk(KERN_WARNING "ata%u: PIO error\n", ap->id);

	/* make sure qc->err_mask is available to 
	 * know what's wrong and recover
	 */
	WARN_ON(qc->err_mask == 0);

	ap->hsm_task_state = HSM_ST_IDLE;

	ata_poll_qc_complete(qc);
}

static void ata_pio_task(void *_data)
{
	struct ata_port *ap = _data;
	unsigned long timeout;
	int qc_completed;

fsm_start:
	timeout = 0;
	qc_completed = 0;

	switch (ap->hsm_task_state) {
	case HSM_ST_IDLE:
		return;

	case HSM_ST:
		ata_pio_block(ap);
		break;

	case HSM_ST_LAST:
		qc_completed = ata_pio_complete(ap);
		break;

	case HSM_ST_POLL:
	case HSM_ST_LAST_POLL:
		timeout = ata_pio_poll(ap);
		break;

	case HSM_ST_TMOUT:
	case HSM_ST_ERR:
		ata_pio_error(ap);
		return;
	}

	if (timeout)
		ata_queue_delayed_pio_task(ap, timeout);
	else if (!qc_completed)
		goto fsm_start;
}

/**
 *	ata_qc_timeout - Handle timeout of queued command
 *	@qc: Command that timed out
 *
 *	Some part of the kernel (currently, only the SCSI layer)
 *	has noticed that the active command on port @ap has not
 *	completed after a specified length of time.  Handle this
 *	condition by disabling DMA (if necessary) and completing
 *	transactions, with error if necessary.
 *
 *	This also handles the case of the "lost interrupt", where
 *	for some reason (possibly hardware bug, possibly driver bug)
 *	an interrupt was not delivered to the driver, even though the
 *	transaction completed successfully.
 *
 *	LOCKING:
 *	Inherited from SCSI layer (none, can sleep)
 */

static void ata_qc_timeout(struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;
	struct ata_host_set *host_set = ap->host_set;
	u8 host_stat = 0, drv_stat;
	unsigned long flags;

	DPRINTK("ENTER\n");

	ata_flush_pio_tasks(ap);
	ap->hsm_task_state = HSM_ST_IDLE;

	spin_lock_irqsave(&host_set->lock, flags);

	switch (qc->tf.protocol) {

	case ATA_PROT_DMA:
	case ATA_PROT_ATAPI_DMA:
		host_stat = ap->ops->bmdma_status(ap);

		/* before we do anything else, clear DMA-Start bit */
		ap->ops->bmdma_stop(qc);

		/* fall through */

	default:
		ata_altstatus(ap);
		drv_stat = ata_chk_status(ap);

		/* ack bmdma irq events */
		ap->ops->irq_clear(ap);

		printk(KERN_ERR "ata%u: command 0x%x timeout, stat 0x%x host_stat 0x%x\n",
		       ap->id, qc->tf.command, drv_stat, host_stat);

		/* complete taskfile transaction */
		qc->err_mask |= ac_err_mask(drv_stat);
		break;
	}

	spin_unlock_irqrestore(&host_set->lock, flags);

	ata_eh_qc_complete(qc);

	DPRINTK("EXIT\n");
}

/**
 *	ata_eng_timeout - Handle timeout of queued command
 *	@ap: Port on which timed-out command is active
 *
 *	Some part of the kernel (currently, only the SCSI layer)
 *	has noticed that the active command on port @ap has not
 *	completed after a specified length of time.  Handle this
 *	condition by disabling DMA (if necessary) and completing
 *	transactions, with error if necessary.
 *
 *	This also handles the case of the "lost interrupt", where
 *	for some reason (possibly hardware bug, possibly driver bug)
 *	an interrupt was not delivered to the driver, even though the
 *	transaction completed successfully.
 *
 *	LOCKING:
 *	Inherited from SCSI layer (none, can sleep)
 */

void ata_eng_timeout(struct ata_port *ap)
{
	DPRINTK("ENTER\n");

	ata_qc_timeout(ata_qc_from_tag(ap, ap->active_tag));

	DPRINTK("EXIT\n");
}

/**
 *	ata_qc_new - Request an available ATA command, for queueing
 *	@ap: Port associated with device @dev
 *	@dev: Device from whom we request an available command structure
 *
 *	LOCKING:
 *	None.
 */

static struct ata_queued_cmd *ata_qc_new(struct ata_port *ap)
{
	struct ata_queued_cmd *qc = NULL;
	unsigned int i;

	for (i = 0; i < ATA_MAX_QUEUE; i++)
		if (!test_and_set_bit(i, &ap->qactive)) {
			qc = ata_qc_from_tag(ap, i);
			break;
		}

	if (qc)
		qc->tag = i;

	return qc;
}

/**
 *	ata_qc_new_init - Request an available ATA command, and initialize it
 *	@ap: Port associated with device @dev
 *	@dev: Device from whom we request an available command structure
 *
 *	LOCKING:
 *	None.
 */

struct ata_queued_cmd *ata_qc_new_init(struct ata_port *ap,
				      struct ata_device *dev)
{
	struct ata_queued_cmd *qc;

	qc = ata_qc_new(ap);
	if (qc) {
		qc->scsicmd = NULL;
		qc->ap = ap;
		qc->dev = dev;

		ata_qc_reinit(qc);
	}

	return qc;
}

/**
 *	ata_qc_free - free unused ata_queued_cmd
 *	@qc: Command to complete
 *
 *	Designed to free unused ata_queued_cmd object
 *	in case something prevents using it.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 */
void ata_qc_free(struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;
	unsigned int tag;

	WARN_ON(qc == NULL);	/* ata_qc_from_tag _might_ return NULL */

	qc->flags = 0;
	tag = qc->tag;
	if (likely(ata_tag_valid(tag))) {
		if (tag == ap->active_tag)
			ap->active_tag = ATA_TAG_POISON;
		qc->tag = ATA_TAG_POISON;
		clear_bit(tag, &ap->qactive);
	}
}

void __ata_qc_complete(struct ata_queued_cmd *qc)
{
	WARN_ON(qc == NULL);	/* ata_qc_from_tag _might_ return NULL */
	WARN_ON(!(qc->flags & ATA_QCFLAG_ACTIVE));

	if (likely(qc->flags & ATA_QCFLAG_DMAMAP))
		ata_sg_clean(qc);

	/* atapi: mark qc as inactive to prevent the interrupt handler
	 * from completing the command twice later, before the error handler
	 * is called. (when rc != 0 and atapi request sense is needed)
	 */
	qc->flags &= ~ATA_QCFLAG_ACTIVE;

	/* call completion callback */
	qc->complete_fn(qc);
}

static inline int ata_should_dma_map(struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;

	switch (qc->tf.protocol) {
	case ATA_PROT_DMA:
	case ATA_PROT_ATAPI_DMA:
		return 1;

	case ATA_PROT_ATAPI:
	case ATA_PROT_PIO:
	case ATA_PROT_PIO_MULT:
		if (ap->flags & ATA_FLAG_PIO_DMA)
			return 1;

		/* fall through */

	default:
		return 0;
	}

	/* never reached */
}

/**
 *	ata_qc_issue - issue taskfile to device
 *	@qc: command to issue to device
 *
 *	Prepare an ATA command to submission to device.
 *	This includes mapping the data into a DMA-able
 *	area, filling in the S/G table, and finally
 *	writing the taskfile to hardware, starting the command.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 *
 *	RETURNS:
 *	Zero on success, AC_ERR_* mask on failure
 */

unsigned int ata_qc_issue(struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;

	if (ata_should_dma_map(qc)) {
		if (qc->flags & ATA_QCFLAG_SG) {
			if (ata_sg_setup(qc))
				goto sg_err;
		} else if (qc->flags & ATA_QCFLAG_SINGLE) {
			if (ata_sg_setup_one(qc))
				goto sg_err;
		}
	} else {
		qc->flags &= ~ATA_QCFLAG_DMAMAP;
	}

	ap->ops->qc_prep(qc);

	qc->ap->active_tag = qc->tag;
	qc->flags |= ATA_QCFLAG_ACTIVE;

	return ap->ops->qc_issue(qc);

sg_err:
	qc->flags &= ~ATA_QCFLAG_DMAMAP;
	return AC_ERR_SYSTEM;
}


/**
 *	ata_qc_issue_prot - issue taskfile to device in proto-dependent manner
 *	@qc: command to issue to device
 *
 *	Using various libata functions and hooks, this function
 *	starts an ATA command.  ATA commands are grouped into
 *	classes called "protocols", and issuing each type of protocol
 *	is slightly different.
 *
 *	May be used as the qc_issue() entry in ata_port_operations.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 *
 *	RETURNS:
 *	Zero on success, AC_ERR_* mask on failure
 */

unsigned int ata_qc_issue_prot(struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;

	ata_dev_select(ap, qc->dev->devno, 1, 0);

	switch (qc->tf.protocol) {
	case ATA_PROT_NODATA:
		ata_tf_to_host(ap, &qc->tf);
		break;

	case ATA_PROT_DMA:
		ap->ops->tf_load(ap, &qc->tf);	 /* load tf registers */
		ap->ops->bmdma_setup(qc);	    /* set up bmdma */
		ap->ops->bmdma_start(qc);	    /* initiate bmdma */
		break;

	case ATA_PROT_PIO: /* load tf registers, initiate polling pio */
		ata_qc_set_polling(qc);
		ata_tf_to_host(ap, &qc->tf);
		ap->hsm_task_state = HSM_ST;
		ata_queue_pio_task(ap);
		break;

	case ATA_PROT_ATAPI:
		ata_qc_set_polling(qc);
		ata_tf_to_host(ap, &qc->tf);
		ata_queue_packet_task(ap);
		break;

	case ATA_PROT_ATAPI_NODATA:
		ap->flags |= ATA_FLAG_NOINTR;
		ata_tf_to_host(ap, &qc->tf);
		ata_queue_packet_task(ap);
		break;

	case ATA_PROT_ATAPI_DMA:
		ap->flags |= ATA_FLAG_NOINTR;
		ap->ops->tf_load(ap, &qc->tf);	 /* load tf registers */
		ap->ops->bmdma_setup(qc);	    /* set up bmdma */
		ata_queue_packet_task(ap);
		break;

	default:
		WARN_ON(1);
		return AC_ERR_SYSTEM;
	}

	return 0;
}

/**
 *	ata_bmdma_setup_mmio - Set up PCI IDE BMDMA transaction
 *	@qc: Info associated with this ATA transaction.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 */

static void ata_bmdma_setup_mmio (struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;
	unsigned int rw = (qc->tf.flags & ATA_TFLAG_WRITE);
	u8 dmactl;
	void __iomem *mmio = (void __iomem *) ap->ioaddr.bmdma_addr;

	/* load PRD table addr. */
	mb();	/* make sure PRD table writes are visible to controller */
	writel(ap->prd_dma, mmio + ATA_DMA_TABLE_OFS);

	/* specify data direction, triple-check start bit is clear */
	dmactl = readb(mmio + ATA_DMA_CMD);
	dmactl &= ~(ATA_DMA_WR | ATA_DMA_START);
	if (!rw)
		dmactl |= ATA_DMA_WR;
	writeb(dmactl, mmio + ATA_DMA_CMD);

	/* issue r/w command */
	ap->ops->exec_command(ap, &qc->tf);
}

/**
 *	ata_bmdma_start_mmio - Start a PCI IDE BMDMA transaction
 *	@qc: Info associated with this ATA transaction.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 */

static void ata_bmdma_start_mmio (struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;
	void __iomem *mmio = (void __iomem *) ap->ioaddr.bmdma_addr;
	u8 dmactl;

	/* start host DMA transaction */
	dmactl = readb(mmio + ATA_DMA_CMD);
	writeb(dmactl | ATA_DMA_START, mmio + ATA_DMA_CMD);

	/* Strictly, one may wish to issue a readb() here, to
	 * flush the mmio write.  However, control also passes
	 * to the hardware at this point, and it will interrupt
	 * us when we are to resume control.  So, in effect,
	 * we don't care when the mmio write flushes.
	 * Further, a read of the DMA status register _immediately_
	 * following the write may not be what certain flaky hardware
	 * is expected, so I think it is best to not add a readb()
	 * without first all the MMIO ATA cards/mobos.
	 * Or maybe I'm just being paranoid.
	 */
}

/**
 *	ata_bmdma_setup_pio - Set up PCI IDE BMDMA transaction (PIO)
 *	@qc: Info associated with this ATA transaction.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 */

static void ata_bmdma_setup_pio (struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;
	unsigned int rw = (qc->tf.flags & ATA_TFLAG_WRITE);
	u8 dmactl;

	/* load PRD table addr. */
	outl(ap->prd_dma, ap->ioaddr.bmdma_addr + ATA_DMA_TABLE_OFS);

	/* specify data direction, triple-check start bit is clear */
	dmactl = inb(ap->ioaddr.bmdma_addr + ATA_DMA_CMD);
	dmactl &= ~(ATA_DMA_WR | ATA_DMA_START);
	if (!rw)
		dmactl |= ATA_DMA_WR;
	outb(dmactl, ap->ioaddr.bmdma_addr + ATA_DMA_CMD);

	/* issue r/w command */
	ap->ops->exec_command(ap, &qc->tf);
}

/**
 *	ata_bmdma_start_pio - Start a PCI IDE BMDMA transaction (PIO)
 *	@qc: Info associated with this ATA transaction.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 */

static void ata_bmdma_start_pio (struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;
	u8 dmactl;

	/* start host DMA transaction */
	dmactl = inb(ap->ioaddr.bmdma_addr + ATA_DMA_CMD);
	outb(dmactl | ATA_DMA_START,
	     ap->ioaddr.bmdma_addr + ATA_DMA_CMD);
}


/**
 *	ata_bmdma_start - Start a PCI IDE BMDMA transaction
 *	@qc: Info associated with this ATA transaction.
 *
 *	Writes the ATA_DMA_START flag to the DMA command register.
 *
 *	May be used as the bmdma_start() entry in ata_port_operations.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 */
void ata_bmdma_start(struct ata_queued_cmd *qc)
{
	if (qc->ap->flags & ATA_FLAG_MMIO)
		ata_bmdma_start_mmio(qc);
	else
		ata_bmdma_start_pio(qc);
}


/**
 *	ata_bmdma_setup - Set up PCI IDE BMDMA transaction
 *	@qc: Info associated with this ATA transaction.
 *
 *	Writes address of PRD table to device's PRD Table Address
 *	register, sets the DMA control register, and calls
 *	ops->exec_command() to start the transfer.
 *
 *	May be used as the bmdma_setup() entry in ata_port_operations.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 */
void ata_bmdma_setup(struct ata_queued_cmd *qc)
{
	if (qc->ap->flags & ATA_FLAG_MMIO)
		ata_bmdma_setup_mmio(qc);
	else
		ata_bmdma_setup_pio(qc);
}


/**
 *	ata_bmdma_irq_clear - Clear PCI IDE BMDMA interrupt.
 *	@ap: Port associated with this ATA transaction.
 *
 *	Clear interrupt and error flags in DMA status register.
 *
 *	May be used as the irq_clear() entry in ata_port_operations.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 */

void ata_bmdma_irq_clear(struct ata_port *ap)
{
    if (ap->flags & ATA_FLAG_MMIO) {
        void __iomem *mmio = ((void __iomem *) ap->ioaddr.bmdma_addr) + ATA_DMA_STATUS;
        writeb(readb(mmio), mmio);
    } else {
        unsigned long addr = ap->ioaddr.bmdma_addr + ATA_DMA_STATUS;
        outb(inb(addr), addr);
    }

}


/**
 *	ata_bmdma_status - Read PCI IDE BMDMA status
 *	@ap: Port associated with this ATA transaction.
 *
 *	Read and return BMDMA status register.
 *
 *	May be used as the bmdma_status() entry in ata_port_operations.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 */

u8 ata_bmdma_status(struct ata_port *ap)
{
	u8 host_stat;
	if (ap->flags & ATA_FLAG_MMIO) {
		void __iomem *mmio = (void __iomem *) ap->ioaddr.bmdma_addr;
		host_stat = readb(mmio + ATA_DMA_STATUS);
	} else
		host_stat = inb(ap->ioaddr.bmdma_addr + ATA_DMA_STATUS);
	return host_stat;
}


/**
 *	ata_bmdma_stop - Stop PCI IDE BMDMA transfer
 *	@qc: Command we are ending DMA for
 *
 *	Clears the ATA_DMA_START flag in the dma control register
 *
 *	May be used as the bmdma_stop() entry in ata_port_operations.
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 */

void ata_bmdma_stop(struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;
	if (ap->flags & ATA_FLAG_MMIO) {
		void __iomem *mmio = (void __iomem *) ap->ioaddr.bmdma_addr;

		/* clear start/stop bit */
		writeb(readb(mmio + ATA_DMA_CMD) & ~ATA_DMA_START,
			mmio + ATA_DMA_CMD);
	} else {
		/* clear start/stop bit */
		outb(inb(ap->ioaddr.bmdma_addr + ATA_DMA_CMD) & ~ATA_DMA_START,
			ap->ioaddr.bmdma_addr + ATA_DMA_CMD);
	}

	/* one-PIO-cycle guaranteed wait, per spec, for HDMA1:0 transition */
	ata_altstatus(ap);        /* dummy read */
}

/**
 *	ata_host_intr - Handle host interrupt for given (port, task)
 *	@ap: Port on which interrupt arrived (possibly...)
 *	@qc: Taskfile currently active in engine
 *
 *	Handle host interrupt for given queued command.  Currently,
 *	only DMA interrupts are handled.  All other commands are
 *	handled via polling with interrupts disabled (nIEN bit).
 *
 *	LOCKING:
 *	spin_lock_irqsave(host_set lock)
 *
 *	RETURNS:
 *	One if interrupt was handled, zero if not (shared irq).
 */

inline unsigned int ata_host_intr (struct ata_port *ap,
				   struct ata_queued_cmd *qc)
{
	u8 status, host_stat;

	switch (qc->tf.protocol) {

	case ATA_PROT_DMA:
	case ATA_PROT_ATAPI_DMA:
	case ATA_PROT_ATAPI:
		/* check status of DMA engine */
		host_stat = ap->ops->bmdma_status(ap);
		VPRINTK("ata%u: host_stat 0x%X\n", ap->id, host_stat);

		/* if it's not our irq... */
		if (!(host_stat & ATA_DMA_INTR))
			goto idle_irq;

		/* before we do anything else, clear DMA-Start bit */
		ap->ops->bmdma_stop(qc);

		/* fall through */

	case ATA_PROT_ATAPI_NODATA:
	case ATA_PROT_NODATA:
		/* check altstatus */
		status = ata_altstatus(ap);
		if (status & ATA_BUSY)
			goto idle_irq;

		/* check main status, clearing INTRQ */
		status = ata_chk_status(ap);
		if (unlikely(status & ATA_BUSY))
			goto idle_irq;
		DPRINTK("ata%u: protocol %d (dev_stat 0x%X)\n",
			ap->id, qc->tf.protocol, status);

		/* ack bmdma irq events */
		ap->ops->irq_clear(ap);

		/* complete taskfile transaction */
		qc->err_mask |= ac_err_mask(status);
		ata_qc_complete(qc);
		break;

	default:
		goto idle_irq;
	}

	return 1;	/* irq handled */

idle_irq:
	ap->stats.idle_irq++;

#ifdef ATA_IRQ_TRAP
	if ((ap->stats.idle_irq % 1000) == 0) {
		handled = 1;
		ata_irq_ack(ap, 0); /* debug trap */
		printk(KERN_WARNING "ata%d: irq trap\n", ap->id);
	}
#endif
	return 0;	/* irq not handled */
}

/**
 *	ata_interrupt - Default ATA host interrupt handler
 *	@irq: irq line (unused)
 *	@dev_instance: pointer to our ata_host_set information structure
 *	@regs: unused
 *
 *	Default interrupt handler for PCI IDE devices.  Calls
 *	ata_host_intr() for each port that is not disabled.
 *
 *	LOCKING:
 *	Obtains host_set lock during operation.
 *
 *	RETURNS:
 *	IRQ_NONE or IRQ_HANDLED.
 */

irqreturn_t ata_interrupt (int irq, void *dev_instance, struct pt_regs *regs)
{
	struct ata_host_set *host_set = dev_instance;
	unsigned int i;
	unsigned int handled = 0;
	unsigned long flags;

	/* TODO: make _irqsave conditional on x86 PCI IDE legacy mode */
	spin_lock_irqsave(&host_set->lock, flags);

	for (i = 0; i < host_set->n_ports; i++) {
		struct ata_port *ap;

		ap = host_set->ports[i];
		if (ap &&
		    !(ap->flags & (ATA_FLAG_PORT_DISABLED | ATA_FLAG_NOINTR))) {
			struct ata_queued_cmd *qc;

			qc = ata_qc_from_tag(ap, ap->active_tag);
			if (qc && (!(qc->tf.ctl & ATA_NIEN)) &&
			    (qc->flags & ATA_QCFLAG_ACTIVE))
				handled |= ata_host_intr(ap, qc);
		}
	}

	spin_unlock_irqrestore(&host_set->lock, flags);

	return IRQ_RETVAL(handled);
}

/**
 *	atapi_packet_task - Write CDB bytes to hardware
 *	@_data: Port to which ATAPI device is attached.
 *
 *	When device has indicated its readiness to accept
 *	a CDB, this function is called.  Send the CDB.
 *	If DMA is to be performed, exit immediately.
 *	Otherwise, we are in polling mode, so poll
 *	status under operation succeeds or fails.
 *
 *	LOCKING:
 *	Kernel thread context (may sleep)
 */

static void atapi_packet_task(void *_data)
{
	struct ata_port *ap = _data;
	struct ata_queued_cmd *qc;
	u8 status;

	qc = ata_qc_from_tag(ap, ap->active_tag);
	WARN_ON(qc == NULL);
	WARN_ON(!(qc->flags & ATA_QCFLAG_ACTIVE));

	/* sleep-wait for BSY to clear */
	DPRINTK("busy wait\n");
	if (ata_busy_sleep(ap, ATA_TMOUT_CDB_QUICK, ATA_TMOUT_CDB)) {
		qc->err_mask |= AC_ERR_TIMEOUT;
		goto err_out;
	}

	/* make sure DRQ is set */
	status = ata_chk_status(ap);
	if ((status & (ATA_BUSY | ATA_DRQ)) != ATA_DRQ) {
		qc->err_mask |= AC_ERR_HSM;
		goto err_out;
	}

	/* send SCSI cdb */
	DPRINTK("send cdb\n");
	WARN_ON(qc->dev->cdb_len < 12);

	if (qc->tf.protocol == ATA_PROT_ATAPI_DMA ||
	    qc->tf.protocol == ATA_PROT_ATAPI_NODATA) {
		unsigned long flags;

		/* Once we're done issuing command and kicking bmdma,
		 * irq handler takes over.  To not lose irq, we need
		 * to clear NOINTR flag before sending cdb, but
		 * interrupt handler shouldn't be invoked before we're
		 * finished.  Hence, the following locking.
		 */
		spin_lock_irqsave(&ap->host_set->lock, flags);
		ap->flags &= ~ATA_FLAG_NOINTR;
		ata_data_xfer(ap, qc->cdb, qc->dev->cdb_len, 1);
		if (qc->tf.protocol == ATA_PROT_ATAPI_DMA)
			ap->ops->bmdma_start(qc);	/* initiate bmdma */
		spin_unlock_irqrestore(&ap->host_set->lock, flags);
	} else {
		ata_data_xfer(ap, qc->cdb, qc->dev->cdb_len, 1);

		/* PIO commands are handled by polling */
		ap->hsm_task_state = HSM_ST;
		ata_queue_pio_task(ap);
	}

	return;

err_out:
	ata_poll_qc_complete(qc);
}


/*
 * Execute a 'simple' command, that only consists of the opcode 'cmd' itself,
 * without filling any other registers
 */
static int ata_do_simple_cmd(struct ata_port *ap, struct ata_device *dev,
			     u8 cmd)
{
	struct ata_taskfile tf;
	int err;

	ata_tf_init(ap, &tf, dev->devno);

	tf.command = cmd;
	tf.flags |= ATA_TFLAG_DEVICE;
	tf.protocol = ATA_PROT_NODATA;

	err = ata_exec_internal(ap, dev, &tf, DMA_NONE, NULL, 0);
	if (err)
		printk(KERN_ERR "%s: ata command failed: %d\n",
				__FUNCTION__, err);

	return err;
}

static int ata_flush_cache(struct ata_port *ap, struct ata_device *dev)
{
	u8 cmd;

	if (!ata_try_flush_cache(dev))
		return 0;

	if (ata_id_has_flush_ext(dev->id))
		cmd = ATA_CMD_FLUSH_EXT;
	else
		cmd = ATA_CMD_FLUSH;

	return ata_do_simple_cmd(ap, dev, cmd);
}

static int ata_standby_drive(struct ata_port *ap, struct ata_device *dev)
{
	return ata_do_simple_cmd(ap, dev, ATA_CMD_STANDBYNOW1);
}

static int ata_start_drive(struct ata_port *ap, struct ata_device *dev)
{
	return ata_do_simple_cmd(ap, dev, ATA_CMD_IDLEIMMEDIATE);
}

/**
 *	ata_device_resume - wakeup a previously suspended devices
 *	@ap: port the device is connected to
 *	@dev: the device to resume
 *
 *	Kick the drive back into action, by sending it an idle immediate
 *	command and making sure its transfer mode matches between drive
 *	and host.
 *
 */
int ata_device_resume(struct ata_port *ap, struct ata_device *dev)
{
	if (ap->flags & ATA_FLAG_SUSPENDED) {
		ap->flags &= ~ATA_FLAG_SUSPENDED;
		ata_set_mode(ap);
	}
	if (!ata_dev_present(dev))
		return 0;
	if (dev->class == ATA_DEV_ATA)
		ata_start_drive(ap, dev);

	return 0;
}

/**
 *	ata_device_suspend - prepare a device for suspend
 *	@ap: port the device is connected to
 *	@dev: the device to suspend
 *
 *	Flush the cache on the drive, if appropriate, then issue a
 *	standbynow command.
 */
int ata_device_suspend(struct ata_port *ap, struct ata_device *dev)
{
	if (!ata_dev_present(dev))
		return 0;
	if (dev->class == ATA_DEV_ATA)
		ata_flush_cache(ap, dev);

	ata_standby_drive(ap, dev);
	ap->flags |= ATA_FLAG_SUSPENDED;
	return 0;
}

/**
 *	ata_port_start - Set port up for dma.
 *	@ap: Port to initialize
 *
 *	Called just after data structures for each port are
 *	initialized.  Allocates space for PRD table.
 *
 *	May be used as the port_start() entry in ata_port_operations.
 *
 *	LOCKING:
 *	Inherited from caller.
 */

int ata_port_start (struct ata_port *ap)
{
	struct device *dev = ap->host_set->dev;
	int rc;

	ap->prd = dma_alloc_coherent(dev, ATA_PRD_TBL_SZ, &ap->prd_dma, GFP_KERNEL);
	if (!ap->prd)
		return -ENOMEM;

	rc = ata_pad_alloc(ap, dev);
	if (rc) {
		dma_free_coherent(dev, ATA_PRD_TBL_SZ, ap->prd, ap->prd_dma);
		return rc;
	}

	DPRINTK("prd alloc, virt %p, dma %llx\n", ap->prd, (unsigned long long) ap->prd_dma);

	return 0;
}


/**
 *	ata_port_stop - Undo ata_port_start()
 *	@ap: Port to shut down
 *
 *	Frees the PRD table.
 *
 *	May be used as the port_stop() entry in ata_port_operations.
 *
 *	LOCKING:
 *	Inherited from caller.
 */

void ata_port_stop (struct ata_port *ap)
{
	struct device *dev = ap->host_set->dev;

	dma_free_coherent(dev, ATA_PRD_TBL_SZ, ap->prd, ap->prd_dma);
	ata_pad_free(ap, dev);
}

void ata_host_stop (struct ata_host_set *host_set)
{
	if (host_set->mmio_base)
		iounmap(host_set->mmio_base);
}


/**
 *	ata_host_remove - Unregister SCSI host structure with upper layers
 *	@ap: Port to unregister
 *	@do_unregister: 1 if we fully unregister, 0 to just stop the port
 *
 *	LOCKING:
 *	Inherited from caller.
 */

static void ata_host_remove(struct ata_port *ap, unsigned int do_unregister)
{
	struct Scsi_Host *sh = ap->host;

	DPRINTK("ENTER\n");

	if (do_unregister)
		scsi_remove_host(sh);

	ap->ops->port_stop(ap);
}

/**
 *	ata_host_init - Initialize an ata_port structure
 *	@ap: Structure to initialize
 *	@host: associated SCSI mid-layer structure
 *	@host_set: Collection of hosts to which @ap belongs
 *	@ent: Probe information provided by low-level driver
 *	@port_no: Port number associated with this ata_port
 *
 *	Initialize a new ata_port structure, and its associated
 *	scsi_host.
 *
 *	LOCKING:
 *	Inherited from caller.
 */

static void ata_host_init(struct ata_port *ap, struct Scsi_Host *host,
			  struct ata_host_set *host_set,
			  const struct ata_probe_ent *ent, unsigned int port_no)
{
	unsigned int i;

	host->max_id = 16;
	host->max_lun = 1;
	host->max_channel = 1;
	host->unique_id = ata_unique_id++;
	host->max_cmd_len = 12;

	ap->flags = ATA_FLAG_PORT_DISABLED;
	ap->id = host->unique_id;
	ap->host = host;
	ap->ctl = ATA_DEVCTL_OBS;
	ap->host_set = host_set;
	ap->port_no = port_no;
	ap->hard_port_no =
		ent->legacy_mode ? ent->hard_port_no : port_no;
	ap->pio_mask = ent->pio_mask;
	ap->mwdma_mask = ent->mwdma_mask;
	ap->udma_mask = ent->udma_mask;
	ap->flags |= ent->host_flags;
	ap->ops = ent->port_ops;
	ap->cbl = ATA_CBL_NONE;
	ap->active_tag = ATA_TAG_POISON;
	ap->last_ctl = 0xFF;

	INIT_WORK(&ap->packet_task, atapi_packet_task, ap);
	INIT_WORK(&ap->pio_task, ata_pio_task, ap);
	INIT_LIST_HEAD(&ap->eh_done_q);

	for (i = 0; i < ATA_MAX_DEVICES; i++)
		ap->device[i].devno = i;

#ifdef ATA_IRQ_TRAP
	ap->stats.unhandled_irq = 1;
	ap->stats.idle_irq = 1;
#endif

	memcpy(&ap->ioaddr, &ent->port[port_no], sizeof(struct ata_ioports));
}

/**
 *	ata_host_add - Attach low-level ATA driver to system
 *	@ent: Information provided by low-level driver
 *	@host_set: Collections of ports to which we add
 *	@port_no: Port number associated with this host
 *
 *	Attach low-level ATA driver to system.
 *
 *	LOCKING:
 *	PCI/etc. bus probe sem.
 *
 *	RETURNS:
 *	New ata_port on success, for NULL on error.
 */

static struct ata_port * ata_host_add(const struct ata_probe_ent *ent,
				      struct ata_host_set *host_set,
				      unsigned int port_no)
{
	struct Scsi_Host *host;
	struct ata_port *ap;
	int rc;

	DPRINTK("ENTER\n");
	host = scsi_host_alloc(ent->sht, sizeof(struct ata_port));
	if (!host)
		return NULL;

	ap = (struct ata_port *) &host->hostdata[0];

	ata_host_init(ap, host, host_set, ent, port_no);

	rc = ap->ops->port_start(ap);
	if (rc)
		goto err_out;

	return ap;

err_out:
	scsi_host_put(host);
	return NULL;
}

/**
 *	ata_device_add - Register hardware device with ATA and SCSI layers
 *	@ent: Probe information describing hardware device to be registered
 *
 *	This function processes the information provided in the probe
 *	information struct @ent, allocates the necessary ATA and SCSI
 *	host information structures, initializes them, and registers
 *	everything with requisite kernel subsystems.
 *
 *	This function requests irqs, probes the ATA bus, and probes
 *	the SCSI bus.
 *
 *	LOCKING:
 *	PCI/etc. bus probe sem.
 *
 *	RETURNS:
 *	Number of ports registered.  Zero on error (no ports registered).
 */

int ata_device_add(const struct ata_probe_ent *ent)
{
	unsigned int count = 0, i;
	struct device *dev = ent->dev;
	struct ata_host_set *host_set;

	DPRINTK("ENTER\n");
	/* alloc a container for our list of ATA ports (buses) */
	host_set = kzalloc(sizeof(struct ata_host_set) +
			   (ent->n_ports * sizeof(void *)), GFP_KERNEL);
	if (!host_set)
		return 0;
	spin_lock_init(&host_set->lock);

	host_set->dev = dev;
	host_set->n_ports = ent->n_ports;
	host_set->irq = ent->irq;
	host_set->mmio_base = ent->mmio_base;
	host_set->private_data = ent->private_data;
	host_set->ops = ent->port_ops;

	/* register each port bound to this device */
	for (i = 0; i < ent->n_ports; i++) {
		struct ata_port *ap;
		unsigned long xfer_mode_mask;

		ap = ata_host_add(ent, host_set, i);
		if (!ap)
			goto err_out;

		host_set->ports[i] = ap;
		xfer_mode_mask =(ap->udma_mask << ATA_SHIFT_UDMA) |
				(ap->mwdma_mask << ATA_SHIFT_MWDMA) |
				(ap->pio_mask << ATA_SHIFT_PIO);

		/* print per-port info to dmesg */
		printk(KERN_INFO "ata%u: %cATA max %s cmd 0x%lX ctl 0x%lX "
				 "bmdma 0x%lX irq %lu\n",
			ap->id,
			ap->flags & ATA_FLAG_SATA ? 'S' : 'P',
			ata_mode_string(xfer_mode_mask),
	       		ap->ioaddr.cmd_addr,
	       		ap->ioaddr.ctl_addr,
	       		ap->ioaddr.bmdma_addr,
	       		ent->irq);

		ata_chk_status(ap);
		host_set->ops->irq_clear(ap);
		count++;
	}

	if (!count)
		goto err_free_ret;

	/* obtain irq, that is shared between channels */
	if (request_irq(ent->irq, ent->port_ops->irq_handler, ent->irq_flags,
			DRV_NAME, host_set))
		goto err_out;

	/* perform each probe synchronously */
	DPRINTK("probe begin\n");
	for (i = 0; i < count; i++) {
		struct ata_port *ap;
		int rc;

		ap = host_set->ports[i];

		DPRINTK("ata%u: bus probe begin\n", ap->id);
		rc = ata_bus_probe(ap);
		DPRINTK("ata%u: bus probe end\n", ap->id);

		if (rc) {
			/* FIXME: do something useful here?
			 * Current libata behavior will
			 * tear down everything when
			 * the module is removed
			 * or the h/w is unplugged.
			 */
		}

		rc = scsi_add_host(ap->host, dev);
		if (rc) {
			printk(KERN_ERR "ata%u: scsi_add_host failed\n",
			       ap->id);
			/* FIXME: do something useful here */
			/* FIXME: handle unconditional calls to
			 * scsi_scan_host and ata_host_remove, below,
			 * at the very least
			 */
		}
	}

	/* probes are done, now scan each port's disk(s) */
	DPRINTK("host probe begin\n");
	for (i = 0; i < count; i++) {
		struct ata_port *ap = host_set->ports[i];

		ata_scsi_scan_host(ap);
	}

	dev_set_drvdata(dev, host_set);

	VPRINTK("EXIT, returning %u\n", ent->n_ports);
	return ent->n_ports; /* success */

err_out:
	for (i = 0; i < count; i++) {
		ata_host_remove(host_set->ports[i], 1);
		scsi_host_put(host_set->ports[i]->host);
	}
err_free_ret:
	kfree(host_set);
	VPRINTK("EXIT, returning 0\n");
	return 0;
}

/**
 *	ata_host_set_remove - PCI layer callback for device removal
 *	@host_set: ATA host set that was removed
 *
 *	Unregister all objects associated with this host set. Free those 
 *	objects.
 *
 *	LOCKING:
 *	Inherited from calling layer (may sleep).
 */

void ata_host_set_remove(struct ata_host_set *host_set)
{
	struct ata_port *ap;
	unsigned int i;

	for (i = 0; i < host_set->n_ports; i++) {
		ap = host_set->ports[i];
		scsi_remove_host(ap->host);
	}

	free_irq(host_set->irq, host_set);

	for (i = 0; i < host_set->n_ports; i++) {
		ap = host_set->ports[i];

		ata_scsi_release(ap->host);

		if ((ap->flags & ATA_FLAG_NO_LEGACY) == 0) {
			struct ata_ioports *ioaddr = &ap->ioaddr;

			if (ioaddr->cmd_addr == 0x1f0)
				release_region(0x1f0, 8);
			else if (ioaddr->cmd_addr == 0x170)
				release_region(0x170, 8);
		}

		scsi_host_put(ap->host);
	}

	if (host_set->ops->host_stop)
		host_set->ops->host_stop(host_set);

	kfree(host_set);
}

/**
 *	ata_scsi_release - SCSI layer callback hook for host unload
 *	@host: libata host to be unloaded
 *
 *	Performs all duties necessary to shut down a libata port...
 *	Kill port kthread, disable port, and release resources.
 *
 *	LOCKING:
 *	Inherited from SCSI layer.
 *
 *	RETURNS:
 *	One.
 */

int ata_scsi_release(struct Scsi_Host *host)
{
	struct ata_port *ap = (struct ata_port *) &host->hostdata[0];
	int i;

	DPRINTK("ENTER\n");

	ap->ops->port_disable(ap);
	ata_host_remove(ap, 0);
	for (i = 0; i < ATA_MAX_DEVICES; i++)
		kfree(ap->device[i].id);

	DPRINTK("EXIT\n");
	return 1;
}

/**
 *	ata_std_ports - initialize ioaddr with standard port offsets.
 *	@ioaddr: IO address structure to be initialized
 *
 *	Utility function which initializes data_addr, error_addr,
 *	feature_addr, nsect_addr, lbal_addr, lbam_addr, lbah_addr,
 *	device_addr, status_addr, and command_addr to standard offsets
 *	relative to cmd_addr.
 *
 *	Does not set ctl_addr, altstatus_addr, bmdma_addr, or scr_addr.
 */

void ata_std_ports(struct ata_ioports *ioaddr)
{
	ioaddr->data_addr = ioaddr->cmd_addr + ATA_REG_DATA;
	ioaddr->error_addr = ioaddr->cmd_addr + ATA_REG_ERR;
	ioaddr->feature_addr = ioaddr->cmd_addr + ATA_REG_FEATURE;
	ioaddr->nsect_addr = ioaddr->cmd_addr + ATA_REG_NSECT;
	ioaddr->lbal_addr = ioaddr->cmd_addr + ATA_REG_LBAL;
	ioaddr->lbam_addr = ioaddr->cmd_addr + ATA_REG_LBAM;
	ioaddr->lbah_addr = ioaddr->cmd_addr + ATA_REG_LBAH;
	ioaddr->device_addr = ioaddr->cmd_addr + ATA_REG_DEVICE;
	ioaddr->status_addr = ioaddr->cmd_addr + ATA_REG_STATUS;
	ioaddr->command_addr = ioaddr->cmd_addr + ATA_REG_CMD;
}


#ifdef CONFIG_PCI

void ata_pci_host_stop (struct ata_host_set *host_set)
{
	struct pci_dev *pdev = to_pci_dev(host_set->dev);

	pci_iounmap(pdev, host_set->mmio_base);
}

/**
 *	ata_pci_remove_one - PCI layer callback for device removal
 *	@pdev: PCI device that was removed
 *
 *	PCI layer indicates to libata via this hook that
 *	hot-unplug or module unload event has occurred.
 *	Handle this by unregistering all objects associated
 *	with this PCI device.  Free those objects.  Then finally
 *	release PCI resources and disable device.
 *
 *	LOCKING:
 *	Inherited from PCI layer (may sleep).
 */

void ata_pci_remove_one (struct pci_dev *pdev)
{
	struct device *dev = pci_dev_to_dev(pdev);
	struct ata_host_set *host_set = dev_get_drvdata(dev);

	ata_host_set_remove(host_set);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	dev_set_drvdata(dev, NULL);
}

/* move to PCI subsystem */
int pci_test_config_bits(struct pci_dev *pdev, const struct pci_bits *bits)
{
	unsigned long tmp = 0;

	switch (bits->width) {
	case 1: {
		u8 tmp8 = 0;
		pci_read_config_byte(pdev, bits->reg, &tmp8);
		tmp = tmp8;
		break;
	}
	case 2: {
		u16 tmp16 = 0;
		pci_read_config_word(pdev, bits->reg, &tmp16);
		tmp = tmp16;
		break;
	}
	case 4: {
		u32 tmp32 = 0;
		pci_read_config_dword(pdev, bits->reg, &tmp32);
		tmp = tmp32;
		break;
	}

	default:
		return -EINVAL;
	}

	tmp &= bits->mask;

	return (tmp == bits->val) ? 1 : 0;
}

int ata_pci_device_suspend(struct pci_dev *pdev, pm_message_t state)
{
	pci_save_state(pdev);
	pci_disable_device(pdev);
	pci_set_power_state(pdev, PCI_D3hot);
	return 0;
}

int ata_pci_device_resume(struct pci_dev *pdev)
{
	pci_set_power_state(pdev, PCI_D0);
	pci_restore_state(pdev);
	pci_enable_device(pdev);
	pci_set_master(pdev);
	return 0;
}
#endif /* CONFIG_PCI */


static int __init ata_init(void)
{
	ata_wq = create_workqueue("ata");
	if (!ata_wq)
		return -ENOMEM;

	printk(KERN_DEBUG "libata version " DRV_VERSION " loaded.\n");
	return 0;
}

static void __exit ata_exit(void)
{
	destroy_workqueue(ata_wq);
}

module_init(ata_init);
module_exit(ata_exit);

static unsigned long ratelimit_time;
static spinlock_t ata_ratelimit_lock = SPIN_LOCK_UNLOCKED;

int ata_ratelimit(void)
{
	int rc;
	unsigned long flags;

	spin_lock_irqsave(&ata_ratelimit_lock, flags);

	if (time_after(jiffies, ratelimit_time)) {
		rc = 1;
		ratelimit_time = jiffies + (HZ/5);
	} else
		rc = 0;

	spin_unlock_irqrestore(&ata_ratelimit_lock, flags);

	return rc;
}

/*
 * libata is essentially a library of internal helper functions for
 * low-level ATA host controller drivers.  As such, the API/ABI is
 * likely to change as new drivers are added and updated.
 * Do not depend on ABI/API stability.
 */

EXPORT_SYMBOL_GPL(ata_std_bios_param);
EXPORT_SYMBOL_GPL(ata_std_ports);
EXPORT_SYMBOL_GPL(ata_device_add);
EXPORT_SYMBOL_GPL(ata_host_set_remove);
EXPORT_SYMBOL_GPL(ata_sg_init);
EXPORT_SYMBOL_GPL(ata_sg_init_one);
EXPORT_SYMBOL_GPL(__ata_qc_complete);
EXPORT_SYMBOL_GPL(ata_qc_issue_prot);
EXPORT_SYMBOL_GPL(ata_eng_timeout);
EXPORT_SYMBOL_GPL(ata_tf_load);
EXPORT_SYMBOL_GPL(ata_tf_read);
EXPORT_SYMBOL_GPL(ata_noop_dev_select);
EXPORT_SYMBOL_GPL(ata_std_dev_select);
EXPORT_SYMBOL_GPL(ata_tf_to_fis);
EXPORT_SYMBOL_GPL(ata_tf_from_fis);
EXPORT_SYMBOL_GPL(ata_check_status);
EXPORT_SYMBOL_GPL(ata_altstatus);
EXPORT_SYMBOL_GPL(ata_exec_command);
EXPORT_SYMBOL_GPL(ata_port_start);
EXPORT_SYMBOL_GPL(ata_port_stop);
EXPORT_SYMBOL_GPL(ata_host_stop);
EXPORT_SYMBOL_GPL(ata_interrupt);
EXPORT_SYMBOL_GPL(ata_qc_prep);
EXPORT_SYMBOL_GPL(ata_bmdma_setup);
EXPORT_SYMBOL_GPL(ata_bmdma_start);
EXPORT_SYMBOL_GPL(ata_bmdma_irq_clear);
EXPORT_SYMBOL_GPL(ata_bmdma_status);
EXPORT_SYMBOL_GPL(ata_bmdma_stop);
EXPORT_SYMBOL_GPL(ata_port_probe);
EXPORT_SYMBOL_GPL(sata_phy_reset);
EXPORT_SYMBOL_GPL(__sata_phy_reset);
EXPORT_SYMBOL_GPL(ata_bus_reset);
EXPORT_SYMBOL_GPL(ata_std_probeinit);
EXPORT_SYMBOL_GPL(ata_std_softreset);
EXPORT_SYMBOL_GPL(sata_std_hardreset);
EXPORT_SYMBOL_GPL(ata_std_postreset);
EXPORT_SYMBOL_GPL(ata_std_probe_reset);
EXPORT_SYMBOL_GPL(ata_drive_probe_reset);
EXPORT_SYMBOL_GPL(ata_port_disable);
EXPORT_SYMBOL_GPL(ata_ratelimit);
EXPORT_SYMBOL_GPL(ata_busy_sleep);
EXPORT_SYMBOL_GPL(ata_scsi_ioctl);
EXPORT_SYMBOL_GPL(ata_scsi_queuecmd);
EXPORT_SYMBOL_GPL(ata_scsi_timed_out);
EXPORT_SYMBOL_GPL(ata_scsi_error);
EXPORT_SYMBOL_GPL(ata_scsi_slave_config);
EXPORT_SYMBOL_GPL(ata_scsi_release);
EXPORT_SYMBOL_GPL(ata_host_intr);
EXPORT_SYMBOL_GPL(ata_dev_classify);
EXPORT_SYMBOL_GPL(ata_id_string);
EXPORT_SYMBOL_GPL(ata_id_c_string);
EXPORT_SYMBOL_GPL(ata_dev_config);
EXPORT_SYMBOL_GPL(ata_scsi_simulate);
EXPORT_SYMBOL_GPL(ata_eh_qc_complete);
EXPORT_SYMBOL_GPL(ata_eh_qc_retry);

EXPORT_SYMBOL_GPL(ata_pio_need_iordy);
EXPORT_SYMBOL_GPL(ata_timing_compute);
EXPORT_SYMBOL_GPL(ata_timing_merge);

#ifdef CONFIG_PCI
EXPORT_SYMBOL_GPL(pci_test_config_bits);
EXPORT_SYMBOL_GPL(ata_pci_host_stop);
EXPORT_SYMBOL_GPL(ata_pci_init_native_mode);
EXPORT_SYMBOL_GPL(ata_pci_init_one);
EXPORT_SYMBOL_GPL(ata_pci_remove_one);
EXPORT_SYMBOL_GPL(ata_pci_device_suspend);
EXPORT_SYMBOL_GPL(ata_pci_device_resume);
#endif /* CONFIG_PCI */

EXPORT_SYMBOL_GPL(ata_device_suspend);
EXPORT_SYMBOL_GPL(ata_device_resume);
EXPORT_SYMBOL_GPL(ata_scsi_device_suspend);
EXPORT_SYMBOL_GPL(ata_scsi_device_resume);
