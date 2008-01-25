/*
 * linux/drivers/ide/ide-taskfile.c	Version 0.38	March 05, 2003
 *
 *  Copyright (C) 2000-2002	Michael Cornwell <cornwell@acm.org>
 *  Copyright (C) 2000-2002	Andre Hedrick <andre@linux-ide.org>
 *  Copyright (C) 2001-2002	Klaus Smolin
 *					IBM Storage Technology Division
 *  Copyright (C) 2003-2004	Bartlomiej Zolnierkiewicz
 *
 *  The big the bad and the ugly.
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/major.h>
#include <linux/errno.h>
#include <linux/genhd.h>
#include <linux/blkpg.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/hdreg.h>
#include <linux/ide.h>
#include <linux/bitops.h>
#include <linux/scatterlist.h>

#include <asm/byteorder.h>
#include <asm/irq.h>
#include <asm/uaccess.h>
#include <asm/io.h>

static void ata_bswap_data (void *buffer, int wcount)
{
	u16 *p = buffer;

	while (wcount--) {
		*p = *p << 8 | *p >> 8; p++;
		*p = *p << 8 | *p >> 8; p++;
	}
}

static void taskfile_input_data(ide_drive_t *drive, void *buffer, u32 wcount)
{
	HWIF(drive)->ata_input_data(drive, buffer, wcount);
	if (drive->bswap)
		ata_bswap_data(buffer, wcount);
}

static void taskfile_output_data(ide_drive_t *drive, void *buffer, u32 wcount)
{
	if (drive->bswap) {
		ata_bswap_data(buffer, wcount);
		HWIF(drive)->ata_output_data(drive, buffer, wcount);
		ata_bswap_data(buffer, wcount);
	} else {
		HWIF(drive)->ata_output_data(drive, buffer, wcount);
	}
}

void ide_tf_load(ide_drive_t *drive, ide_task_t *task)
{
	ide_hwif_t *hwif = drive->hwif;
	struct ide_taskfile *tf = &task->tf;
	u8 HIHI = (task->tf_flags & IDE_TFLAG_LBA48) ? 0xE0 : 0xEF;

	if (task->tf_flags & IDE_TFLAG_FLAGGED)
		HIHI = 0xFF;

#ifdef DEBUG
	printk("%s: tf: feat 0x%02x nsect 0x%02x lbal 0x%02x "
		"lbam 0x%02x lbah 0x%02x dev 0x%02x cmd 0x%02x\n",
		drive->name, tf->feature, tf->nsect, tf->lbal,
		tf->lbam, tf->lbah, tf->device, tf->command);
#endif

	if (IDE_CONTROL_REG)
		hwif->OUTB(drive->ctl, IDE_CONTROL_REG); /* clear nIEN */

	if ((task->tf_flags & IDE_TFLAG_NO_SELECT_MASK) == 0)
		SELECT_MASK(drive, 0);

	if (task->tf_flags & IDE_TFLAG_OUT_DATA)
		hwif->OUTW((tf->hob_data << 8) | tf->data, IDE_DATA_REG);

	if (task->tf_flags & IDE_TFLAG_OUT_HOB_FEATURE)
		hwif->OUTB(tf->hob_feature, IDE_FEATURE_REG);
	if (task->tf_flags & IDE_TFLAG_OUT_HOB_NSECT)
		hwif->OUTB(tf->hob_nsect, IDE_NSECTOR_REG);
	if (task->tf_flags & IDE_TFLAG_OUT_HOB_LBAL)
		hwif->OUTB(tf->hob_lbal, IDE_SECTOR_REG);
	if (task->tf_flags & IDE_TFLAG_OUT_HOB_LBAM)
		hwif->OUTB(tf->hob_lbam, IDE_LCYL_REG);
	if (task->tf_flags & IDE_TFLAG_OUT_HOB_LBAH)
		hwif->OUTB(tf->hob_lbah, IDE_HCYL_REG);

	if (task->tf_flags & IDE_TFLAG_OUT_FEATURE)
		hwif->OUTB(tf->feature, IDE_FEATURE_REG);
	if (task->tf_flags & IDE_TFLAG_OUT_NSECT)
		hwif->OUTB(tf->nsect, IDE_NSECTOR_REG);
	if (task->tf_flags & IDE_TFLAG_OUT_LBAL)
		hwif->OUTB(tf->lbal, IDE_SECTOR_REG);
	if (task->tf_flags & IDE_TFLAG_OUT_LBAM)
		hwif->OUTB(tf->lbam, IDE_LCYL_REG);
	if (task->tf_flags & IDE_TFLAG_OUT_LBAH)
		hwif->OUTB(tf->lbah, IDE_HCYL_REG);

	if (task->tf_flags & IDE_TFLAG_OUT_DEVICE)
		hwif->OUTB((tf->device & HIHI) | drive->select.all, IDE_SELECT_REG);
}

EXPORT_SYMBOL_GPL(ide_tf_load);

int taskfile_lib_get_identify (ide_drive_t *drive, u8 *buf)
{
	ide_task_t args;

	memset(&args, 0, sizeof(ide_task_t));
	args.tf.nsect = 0x01;
	if (drive->media == ide_disk)
		args.tf.command = WIN_IDENTIFY;
	else
		args.tf.command = WIN_PIDENTIFY;
	args.tf_flags = IDE_TFLAG_OUT_TF | IDE_TFLAG_OUT_DEVICE;
	args.command_type = IDE_DRIVE_TASK_IN;
	args.data_phase   = TASKFILE_IN;
	args.handler	  = &task_in_intr;
	return ide_raw_taskfile(drive, &args, buf);
}

static int inline task_dma_ok(ide_task_t *task)
{
	if (task->tf_flags & IDE_TFLAG_FLAGGED)
		return 1;

	switch (task->tf.command) {
		case WIN_WRITEDMA_ONCE:
		case WIN_WRITEDMA:
		case WIN_WRITEDMA_EXT:
		case WIN_READDMA_ONCE:
		case WIN_READDMA:
		case WIN_READDMA_EXT:
		case WIN_IDENTIFY_DMA:
			return 1;
	}

	return 0;
}

ide_startstop_t do_rw_taskfile (ide_drive_t *drive, ide_task_t *task)
{
	ide_hwif_t *hwif	= HWIF(drive);
	struct ide_taskfile *tf = &task->tf;

	ide_tf_load(drive, task);

	if (task->handler != NULL) {
		if (task->prehandler != NULL) {
			hwif->OUTBSYNC(drive, tf->command, IDE_COMMAND_REG);
			ndelay(400);	/* FIXME */
			return task->prehandler(drive, task->rq);
		}
		ide_execute_command(drive, tf->command, task->handler, WAIT_WORSTCASE, NULL);
		return ide_started;
	}

	if (task_dma_ok(task) && drive->using_dma && !hwif->dma_setup(drive)) {
		hwif->dma_exec_cmd(drive, tf->command);
		hwif->dma_start(drive);
		return ide_started;
	}

	return ide_stopped;
}

/*
 * set_multmode_intr() is invoked on completion of a WIN_SETMULT cmd.
 */
ide_startstop_t set_multmode_intr (ide_drive_t *drive)
{
	ide_hwif_t *hwif = HWIF(drive);
	u8 stat;

	if (OK_STAT(stat = hwif->INB(IDE_STATUS_REG),READY_STAT,BAD_STAT)) {
		drive->mult_count = drive->mult_req;
	} else {
		drive->mult_req = drive->mult_count = 0;
		drive->special.b.recalibrate = 1;
		(void) ide_dump_status(drive, "set_multmode", stat);
	}
	return ide_stopped;
}

/*
 * set_geometry_intr() is invoked on completion of a WIN_SPECIFY cmd.
 */
ide_startstop_t set_geometry_intr (ide_drive_t *drive)
{
	ide_hwif_t *hwif = HWIF(drive);
	int retries = 5;
	u8 stat;

	while (((stat = hwif->INB(IDE_STATUS_REG)) & BUSY_STAT) && retries--)
		udelay(10);

	if (OK_STAT(stat, READY_STAT, BAD_STAT))
		return ide_stopped;

	if (stat & (ERR_STAT|DRQ_STAT))
		return ide_error(drive, "set_geometry_intr", stat);

	BUG_ON(HWGROUP(drive)->handler != NULL);
	ide_set_handler(drive, &set_geometry_intr, WAIT_WORSTCASE, NULL);
	return ide_started;
}

/*
 * recal_intr() is invoked on completion of a WIN_RESTORE (recalibrate) cmd.
 */
ide_startstop_t recal_intr (ide_drive_t *drive)
{
	ide_hwif_t *hwif = HWIF(drive);
	u8 stat;

	if (!OK_STAT(stat = hwif->INB(IDE_STATUS_REG), READY_STAT, BAD_STAT))
		return ide_error(drive, "recal_intr", stat);
	return ide_stopped;
}

/*
 * Handler for commands without a data phase
 */
ide_startstop_t task_no_data_intr (ide_drive_t *drive)
{
	ide_task_t *args	= HWGROUP(drive)->rq->special;
	ide_hwif_t *hwif	= HWIF(drive);
	u8 stat;

	local_irq_enable_in_hardirq();
	if (!OK_STAT(stat = hwif->INB(IDE_STATUS_REG),READY_STAT,BAD_STAT)) {
		return ide_error(drive, "task_no_data_intr", stat);
		/* calls ide_end_drive_cmd */
	}
	if (args)
		ide_end_drive_cmd(drive, stat, hwif->INB(IDE_ERROR_REG));

	return ide_stopped;
}

static u8 wait_drive_not_busy(ide_drive_t *drive)
{
	ide_hwif_t *hwif = HWIF(drive);
	int retries;
	u8 stat;

	/*
	 * Last sector was transfered, wait until drive is ready.
	 * This can take up to 10 usec, but we will wait max 1 ms
	 * (drive_cmd_intr() waits that long).
	 */
	for (retries = 0; retries < 100; retries++) {
		if ((stat = hwif->INB(IDE_STATUS_REG)) & BUSY_STAT)
			udelay(10);
		else
			break;
	}

	if (stat & BUSY_STAT)
		printk(KERN_ERR "%s: drive still BUSY!\n", drive->name);

	return stat;
}

static void ide_pio_sector(ide_drive_t *drive, unsigned int write)
{
	ide_hwif_t *hwif = drive->hwif;
	struct scatterlist *sg = hwif->sg_table;
	struct scatterlist *cursg = hwif->cursg;
	struct page *page;
#ifdef CONFIG_HIGHMEM
	unsigned long flags;
#endif
	unsigned int offset;
	u8 *buf;

	cursg = hwif->cursg;
	if (!cursg) {
		cursg = sg;
		hwif->cursg = sg;
	}

	page = sg_page(cursg);
	offset = cursg->offset + hwif->cursg_ofs * SECTOR_SIZE;

	/* get the current page and offset */
	page = nth_page(page, (offset >> PAGE_SHIFT));
	offset %= PAGE_SIZE;

#ifdef CONFIG_HIGHMEM
	local_irq_save(flags);
#endif
	buf = kmap_atomic(page, KM_BIO_SRC_IRQ) + offset;

	hwif->nleft--;
	hwif->cursg_ofs++;

	if ((hwif->cursg_ofs * SECTOR_SIZE) == cursg->length) {
		hwif->cursg = sg_next(hwif->cursg);
		hwif->cursg_ofs = 0;
	}

	/* do the actual data transfer */
	if (write)
		taskfile_output_data(drive, buf, SECTOR_WORDS);
	else
		taskfile_input_data(drive, buf, SECTOR_WORDS);

	kunmap_atomic(buf, KM_BIO_SRC_IRQ);
#ifdef CONFIG_HIGHMEM
	local_irq_restore(flags);
#endif
}

static void ide_pio_multi(ide_drive_t *drive, unsigned int write)
{
	unsigned int nsect;

	nsect = min_t(unsigned int, drive->hwif->nleft, drive->mult_count);
	while (nsect--)
		ide_pio_sector(drive, write);
}

static void ide_pio_datablock(ide_drive_t *drive, struct request *rq,
				     unsigned int write)
{
	if (rq->bio)	/* fs request */
		rq->errors = 0;

	touch_softlockup_watchdog();

	switch (drive->hwif->data_phase) {
	case TASKFILE_MULTI_IN:
	case TASKFILE_MULTI_OUT:
		ide_pio_multi(drive, write);
		break;
	default:
		ide_pio_sector(drive, write);
		break;
	}
}

static ide_startstop_t task_error(ide_drive_t *drive, struct request *rq,
				  const char *s, u8 stat)
{
	if (rq->bio) {
		ide_hwif_t *hwif = drive->hwif;
		int sectors = hwif->nsect - hwif->nleft;

		switch (hwif->data_phase) {
		case TASKFILE_IN:
			if (hwif->nleft)
				break;
			/* fall through */
		case TASKFILE_OUT:
			sectors--;
			break;
		case TASKFILE_MULTI_IN:
			if (hwif->nleft)
				break;
			/* fall through */
		case TASKFILE_MULTI_OUT:
			sectors -= drive->mult_count;
		default:
			break;
		}

		if (sectors > 0) {
			ide_driver_t *drv;

			drv = *(ide_driver_t **)rq->rq_disk->private_data;
			drv->end_request(drive, 1, sectors);
		}
	}
	return ide_error(drive, s, stat);
}

static void task_end_request(ide_drive_t *drive, struct request *rq, u8 stat)
{
	HWIF(drive)->cursg = NULL;

	if (rq->cmd_type == REQ_TYPE_ATA_TASKFILE) {
		ide_task_t *task = rq->special;

		if (task->tf_flags & IDE_TFLAG_FLAGGED) {
			u8 err = drive->hwif->INB(IDE_ERROR_REG);
			ide_end_drive_cmd(drive, stat, err);
			return;
		}
	}

	if (rq->rq_disk) {
		ide_driver_t *drv;

		drv = *(ide_driver_t **)rq->rq_disk->private_data;;
		drv->end_request(drive, 1, rq->hard_nr_sectors);
	} else
		ide_end_request(drive, 1, rq->hard_nr_sectors);
}

/*
 * Handler for command with PIO data-in phase (Read/Read Multiple).
 */
ide_startstop_t task_in_intr (ide_drive_t *drive)
{
	ide_hwif_t *hwif = drive->hwif;
	struct request *rq = HWGROUP(drive)->rq;
	u8 stat = hwif->INB(IDE_STATUS_REG);

	/* new way for dealing with premature shared PCI interrupts */
	if (!OK_STAT(stat, DATA_READY, BAD_R_STAT)) {
		if (stat & (ERR_STAT | DRQ_STAT))
			return task_error(drive, rq, __FUNCTION__, stat);
		/* No data yet, so wait for another IRQ. */
		ide_set_handler(drive, &task_in_intr, WAIT_WORSTCASE, NULL);
		return ide_started;
	}

	ide_pio_datablock(drive, rq, 0);

	/* If it was the last datablock check status and finish transfer. */
	if (!hwif->nleft) {
		stat = wait_drive_not_busy(drive);
		if (!OK_STAT(stat, 0, BAD_R_STAT))
			return task_error(drive, rq, __FUNCTION__, stat);
		task_end_request(drive, rq, stat);
		return ide_stopped;
	}

	/* Still data left to transfer. */
	ide_set_handler(drive, &task_in_intr, WAIT_WORSTCASE, NULL);

	return ide_started;
}
EXPORT_SYMBOL(task_in_intr);

/*
 * Handler for command with PIO data-out phase (Write/Write Multiple).
 */
static ide_startstop_t task_out_intr (ide_drive_t *drive)
{
	ide_hwif_t *hwif = drive->hwif;
	struct request *rq = HWGROUP(drive)->rq;
	u8 stat = hwif->INB(IDE_STATUS_REG);

	if (!OK_STAT(stat, DRIVE_READY, drive->bad_wstat))
		return task_error(drive, rq, __FUNCTION__, stat);

	/* Deal with unexpected ATA data phase. */
	if (((stat & DRQ_STAT) == 0) ^ !hwif->nleft)
		return task_error(drive, rq, __FUNCTION__, stat);

	if (!hwif->nleft) {
		task_end_request(drive, rq, stat);
		return ide_stopped;
	}

	/* Still data left to transfer. */
	ide_pio_datablock(drive, rq, 1);
	ide_set_handler(drive, &task_out_intr, WAIT_WORSTCASE, NULL);

	return ide_started;
}

ide_startstop_t pre_task_out_intr (ide_drive_t *drive, struct request *rq)
{
	ide_startstop_t startstop;

	if (ide_wait_stat(&startstop, drive, DATA_READY,
			  drive->bad_wstat, WAIT_DRQ)) {
		printk(KERN_ERR "%s: no DRQ after issuing %sWRITE%s\n",
				drive->name,
				drive->hwif->data_phase ? "MULT" : "",
				drive->addressing ? "_EXT" : "");
		return startstop;
	}

	if (!drive->unmask)
		local_irq_disable();

	ide_set_handler(drive, &task_out_intr, WAIT_WORSTCASE, NULL);
	ide_pio_datablock(drive, rq, 1);

	return ide_started;
}
EXPORT_SYMBOL(pre_task_out_intr);

static int ide_diag_taskfile(ide_drive_t *drive, ide_task_t *args, unsigned long data_size, u8 *buf)
{
	struct request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ref_count = 1;
	rq.cmd_type = REQ_TYPE_ATA_TASKFILE;
	rq.buffer = buf;

	/*
	 * (ks) We transfer currently only whole sectors.
	 * This is suffient for now.  But, it would be great,
	 * if we would find a solution to transfer any size.
	 * To support special commands like READ LONG.
	 */
	if (args->command_type != IDE_DRIVE_TASK_NO_DATA) {
		if (data_size == 0)
			rq.nr_sectors = (args->tf.hob_nsect << 8) | args->tf.nsect;
		else
			rq.nr_sectors = data_size / SECTOR_SIZE;

		if (!rq.nr_sectors) {
			printk(KERN_ERR "%s: in/out command without data\n",
					drive->name);
			return -EFAULT;
		}

		rq.hard_nr_sectors = rq.nr_sectors;
		rq.hard_cur_sectors = rq.current_nr_sectors = rq.nr_sectors;

		if (args->command_type == IDE_DRIVE_TASK_RAW_WRITE)
			rq.cmd_flags |= REQ_RW;
	}

	rq.special = args;
	args->rq = &rq;
	return ide_do_drive_cmd(drive, &rq, ide_wait);
}

int ide_raw_taskfile (ide_drive_t *drive, ide_task_t *args, u8 *buf)
{
	return ide_diag_taskfile(drive, args, 0, buf);
}

EXPORT_SYMBOL(ide_raw_taskfile);

int ide_no_data_taskfile(ide_drive_t *drive, ide_task_t *task)
{
	task->command_type = IDE_DRIVE_TASK_NO_DATA;
	task->data_phase   = TASKFILE_NO_DATA;
	task->handler      = task_no_data_intr;

	return ide_raw_taskfile(drive, task, NULL);
}
EXPORT_SYMBOL_GPL(ide_no_data_taskfile);

#ifdef CONFIG_IDE_TASK_IOCTL
int ide_taskfile_ioctl (ide_drive_t *drive, unsigned int cmd, unsigned long arg)
{
	ide_task_request_t	*req_task;
	ide_task_t		args;
	u8 *outbuf		= NULL;
	u8 *inbuf		= NULL;
	int err			= 0;
	int tasksize		= sizeof(struct ide_task_request_s);
	unsigned int taskin	= 0;
	unsigned int taskout	= 0;
	u8 io_32bit		= drive->io_32bit;
	char __user *buf = (char __user *)arg;

//	printk("IDE Taskfile ...\n");

	req_task = kzalloc(tasksize, GFP_KERNEL);
	if (req_task == NULL) return -ENOMEM;
	if (copy_from_user(req_task, buf, tasksize)) {
		kfree(req_task);
		return -EFAULT;
	}

	taskout = req_task->out_size;
	taskin  = req_task->in_size;
	
	if (taskin > 65536 || taskout > 65536) {
		err = -EINVAL;
		goto abort;
	}

	if (taskout) {
		int outtotal = tasksize;
		outbuf = kzalloc(taskout, GFP_KERNEL);
		if (outbuf == NULL) {
			err = -ENOMEM;
			goto abort;
		}
		if (copy_from_user(outbuf, buf + outtotal, taskout)) {
			err = -EFAULT;
			goto abort;
		}
	}

	if (taskin) {
		int intotal = tasksize + taskout;
		inbuf = kzalloc(taskin, GFP_KERNEL);
		if (inbuf == NULL) {
			err = -ENOMEM;
			goto abort;
		}
		if (copy_from_user(inbuf, buf + intotal, taskin)) {
			err = -EFAULT;
			goto abort;
		}
	}

	memset(&args, 0, sizeof(ide_task_t));

	memcpy(&args.tf_array[0], req_task->hob_ports, HDIO_DRIVE_HOB_HDR_SIZE - 2);
	memcpy(&args.tf_array[6], req_task->io_ports, HDIO_DRIVE_TASK_HDR_SIZE);
	args.tf_in_flags  = req_task->in_flags;
	args.data_phase   = req_task->data_phase;
	args.command_type = req_task->req_cmd;

	args.tf_flags = IDE_TFLAG_OUT_DEVICE;
	if (drive->addressing == 1)
		args.tf_flags |= IDE_TFLAG_LBA48;

	if (req_task->out_flags.all) {
		args.tf_flags |= IDE_TFLAG_FLAGGED;

		if (req_task->out_flags.b.data)
			args.tf_flags |= IDE_TFLAG_OUT_DATA;

		if (req_task->out_flags.b.nsector_hob)
			args.tf_flags |= IDE_TFLAG_OUT_HOB_NSECT;
		if (req_task->out_flags.b.sector_hob)
			args.tf_flags |= IDE_TFLAG_OUT_HOB_LBAL;
		if (req_task->out_flags.b.lcyl_hob)
			args.tf_flags |= IDE_TFLAG_OUT_HOB_LBAM;
		if (req_task->out_flags.b.hcyl_hob)
			args.tf_flags |= IDE_TFLAG_OUT_HOB_LBAH;

		if (req_task->out_flags.b.error_feature)
			args.tf_flags |= IDE_TFLAG_OUT_FEATURE;
		if (req_task->out_flags.b.nsector)
			args.tf_flags |= IDE_TFLAG_OUT_NSECT;
		if (req_task->out_flags.b.sector)
			args.tf_flags |= IDE_TFLAG_OUT_LBAL;
		if (req_task->out_flags.b.lcyl)
			args.tf_flags |= IDE_TFLAG_OUT_LBAM;
		if (req_task->out_flags.b.hcyl)
			args.tf_flags |= IDE_TFLAG_OUT_LBAH;
	} else {
		args.tf_flags |= IDE_TFLAG_OUT_TF;
		if (args.tf_flags & IDE_TFLAG_LBA48)
			args.tf_flags |= IDE_TFLAG_OUT_HOB;
	}

	drive->io_32bit = 0;
	switch(req_task->data_phase) {
		case TASKFILE_OUT_DMAQ:
		case TASKFILE_OUT_DMA:
			err = ide_diag_taskfile(drive, &args, taskout, outbuf);
			break;
		case TASKFILE_IN_DMAQ:
		case TASKFILE_IN_DMA:
			err = ide_diag_taskfile(drive, &args, taskin, inbuf);
			break;
		case TASKFILE_MULTI_OUT:
			if (!drive->mult_count) {
				/* (hs): give up if multcount is not set */
				printk(KERN_ERR "%s: %s Multimode Write " \
					"multcount is not set\n",
					drive->name, __FUNCTION__);
				err = -EPERM;
				goto abort;
			}
			/* fall through */
		case TASKFILE_OUT:
			args.prehandler = &pre_task_out_intr;
			args.handler = &task_out_intr;
			err = ide_diag_taskfile(drive, &args, taskout, outbuf);
			break;
		case TASKFILE_MULTI_IN:
			if (!drive->mult_count) {
				/* (hs): give up if multcount is not set */
				printk(KERN_ERR "%s: %s Multimode Read failure " \
					"multcount is not set\n",
					drive->name, __FUNCTION__);
				err = -EPERM;
				goto abort;
			}
			/* fall through */
		case TASKFILE_IN:
			args.handler = &task_in_intr;
			err = ide_diag_taskfile(drive, &args, taskin, inbuf);
			break;
		case TASKFILE_NO_DATA:
			args.handler = &task_no_data_intr;
			err = ide_diag_taskfile(drive, &args, 0, NULL);
			break;
		default:
			err = -EFAULT;
			goto abort;
	}

	memcpy(req_task->hob_ports, &args.tf_array[0], HDIO_DRIVE_HOB_HDR_SIZE - 2);
	memcpy(req_task->io_ports, &args.tf_array[6], HDIO_DRIVE_TASK_HDR_SIZE);
	req_task->in_flags  = args.tf_in_flags;

	if (copy_to_user(buf, req_task, tasksize)) {
		err = -EFAULT;
		goto abort;
	}
	if (taskout) {
		int outtotal = tasksize;
		if (copy_to_user(buf + outtotal, outbuf, taskout)) {
			err = -EFAULT;
			goto abort;
		}
	}
	if (taskin) {
		int intotal = tasksize + taskout;
		if (copy_to_user(buf + intotal, inbuf, taskin)) {
			err = -EFAULT;
			goto abort;
		}
	}
abort:
	kfree(req_task);
	kfree(outbuf);
	kfree(inbuf);

//	printk("IDE Taskfile ioctl ended. rc = %i\n", err);

	drive->io_32bit = io_32bit;

	return err;
}
#endif

int ide_wait_cmd (ide_drive_t *drive, u8 cmd, u8 nsect, u8 feature, u8 sectors, u8 *buf)
{
	struct request rq;
	u8 buffer[4];

	if (!buf)
		buf = buffer;
	memset(buf, 0, 4 + SECTOR_WORDS * 4 * sectors);
	ide_init_drive_cmd(&rq);
	rq.buffer = buf;
	*buf++ = cmd;
	*buf++ = nsect;
	*buf++ = feature;
	*buf++ = sectors;
	return ide_do_drive_cmd(drive, &rq, ide_wait);
}

int ide_cmd_ioctl (ide_drive_t *drive, unsigned int cmd, unsigned long arg)
{
	int err = 0;
	u8 args[4], *argbuf = args;
	u8 xfer_rate = 0;
	int argsize = 4;
	ide_task_t tfargs;
	struct ide_taskfile *tf = &tfargs.tf;

	if (NULL == (void *) arg) {
		struct request rq;
		ide_init_drive_cmd(&rq);
		return ide_do_drive_cmd(drive, &rq, ide_wait);
	}

	if (copy_from_user(args, (void __user *)arg, 4))
		return -EFAULT;

	memset(&tfargs, 0, sizeof(ide_task_t));
	tf->feature = args[2];
	tf->nsect   = args[3];
	tf->lbal    = args[1];
	tf->command = args[0];

	if (args[3]) {
		argsize = 4 + (SECTOR_WORDS * 4 * args[3]);
		argbuf = kzalloc(argsize, GFP_KERNEL);
		if (argbuf == NULL)
			return -ENOMEM;
	}
	if (set_transfer(drive, &tfargs)) {
		xfer_rate = args[1];
		if (ide_ata66_check(drive, &tfargs))
			goto abort;
	}

	err = ide_wait_cmd(drive, args[0], args[1], args[2], args[3], argbuf);

	if (!err && xfer_rate) {
		/* active-retuning-calls future */
		ide_set_xfer_rate(drive, xfer_rate);
		ide_driveid_update(drive);
	}
abort:
	if (copy_to_user((void __user *)arg, argbuf, argsize))
		err = -EFAULT;
	if (argsize > 4)
		kfree(argbuf);
	return err;
}

int ide_task_ioctl (ide_drive_t *drive, unsigned int cmd, unsigned long arg)
{
	void __user *p = (void __user *)arg;
	int err = 0;
	u8 args[7];
	ide_task_t task;

	if (copy_from_user(args, p, 7))
		return -EFAULT;

	memset(&task, 0, sizeof(task));
	memcpy(&task.tf_array[7], &args[1], 6);
	task.tf.command = args[0];
	task.tf_flags = IDE_TFLAG_OUT_TF | IDE_TFLAG_OUT_DEVICE;

	err = ide_no_data_taskfile(drive, &task);

	args[0] = task.tf.command;
	memcpy(&args[1], &task.tf_array[7], 6);

	if (copy_to_user(p, args, 7))
		err = -EFAULT;

	return err;
}

/*
 * NOTICE: This is additions from IBM to provide a discrete interface,
 * for selective taskregister access operations.  Nice JOB Klaus!!!
 * Glad to be able to work and co-develop this with you and IBM.
 */
ide_startstop_t flagged_taskfile (ide_drive_t *drive, ide_task_t *task)
{
	if (task->data_phase == TASKFILE_MULTI_IN ||
	    task->data_phase == TASKFILE_MULTI_OUT) {
		if (!drive->mult_count) {
			printk(KERN_ERR "%s: multimode not set!\n", drive->name);
			return ide_stopped;
		}
	}

	/*
	 * (ks) Check taskfile in flags.
	 * If set, then execute as it is defined.
	 * If not set, then define default settings.
	 * The default values are:
	 *	read all taskfile registers (except data)
	 *	read the hob registers (sector, nsector, lcyl, hcyl)
	 */
	if (task->tf_in_flags.all == 0) {
		task->tf_in_flags.all = IDE_TASKFILE_STD_IN_FLAGS;
		if (drive->addressing == 1)
			task->tf_in_flags.all |= (IDE_HOB_STD_IN_FLAGS  << 8);
        }

	return do_rw_taskfile(drive, task);
}
