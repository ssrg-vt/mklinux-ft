/*
 * Copyright 2004 Peter M. Jones <pjones@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public Licens
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-
 *
 */

#include <linux/list.h>
#include <linux/genhd.h>
#include <linux/spinlock.h>
#include <linux/parser.h>
#include <linux/capability.h>
#include <linux/bitops.h>

#include <scsi/scsi.h>
#include <linux/cdrom.h>

int blk_cmd_filter_verify_command(struct blk_scsi_cmd_filter *filter,
				  unsigned char *cmd, mode_t *f_mode)
{
	/* root can do any command. */
	if (capable(CAP_SYS_RAWIO))
		return 0;

	/* if there's no filter set, assume we're filtering everything out */
	if (!filter)
		return -EPERM;

	/* Anybody who can open the device can do a read-safe command */
	if (test_bit(cmd[0], filter->read_ok))
		return 0;

	/* Write-safe commands require a writable open */
	if (test_bit(cmd[0], filter->write_ok) && (*f_mode & FMODE_WRITE))
		return 0;

	return -EPERM;
}
EXPORT_SYMBOL(blk_cmd_filter_verify_command);

int blk_verify_command(struct file *file, unsigned char *cmd)
{
	struct gendisk *disk;
	struct inode *inode;

	if (!file)
		return -EINVAL;

	inode = file->f_dentry->d_inode;
	if (!inode)
		return -EINVAL;

	disk = inode->i_bdev->bd_disk;

	return blk_cmd_filter_verify_command(&disk->cmd_filter,
						 cmd, &file->f_mode);
}
EXPORT_SYMBOL(blk_verify_command);

/* and now, the sysfs stuff */
static ssize_t rcf_cmds_show(struct blk_scsi_cmd_filter *filter, char *page,
			     int rw)
{
	char *npage = page;
	unsigned long *okbits;
	int i;

	if (rw == READ)
		okbits = filter->read_ok;
	else
		okbits = filter->write_ok;

	for (i = 0; i < BLK_SCSI_MAX_CMDS; i++) {
		if (test_bit(i, okbits)) {
			sprintf(npage, "%02x", i);
			npage += 2;
			if (i < BLK_SCSI_MAX_CMDS - 1)
				sprintf(npage++, " ");
		}
	}

	if (npage != page)
		npage += sprintf(npage, "\n");

	return npage - page;
}

static ssize_t rcf_readcmds_show(struct blk_scsi_cmd_filter *filter, char *page)
{
	return rcf_cmds_show(filter, page, READ);
}

static ssize_t rcf_writecmds_show(struct blk_scsi_cmd_filter *filter,
				 char *page)
{
	return rcf_cmds_show(filter, page, WRITE);
}

static ssize_t rcf_cmds_store(struct blk_scsi_cmd_filter *filter,
			      const char *page, size_t count, int rw)
{
	ssize_t ret = 0;
	unsigned long okbits[BLK_SCSI_CMD_PER_LONG], *target_okbits;
	int cmd, status, len;
	substring_t ss;

	memset(&okbits, 0, sizeof(okbits));

	for (len = strlen(page); len > 0; len -= 3) {
		if (len < 2)
			break;
		ss.from = (char *) page + ret;
		ss.to = (char *) page + ret + 2;
		ret += 3;
		status = match_hex(&ss, &cmd);
		/* either of these cases means invalid input, so do nothing. */
		if (status || cmd >= BLK_SCSI_MAX_CMDS)
			return -EINVAL;

		__set_bit(cmd, okbits);
	}

	if (rw == READ)
		target_okbits = filter->read_ok;
	else
		target_okbits = filter->write_ok;

	memmove(target_okbits, okbits, sizeof(okbits));
	return count;
}

static ssize_t rcf_readcmds_store(struct blk_scsi_cmd_filter *filter,
				  const char *page, size_t count)
{
	return rcf_cmds_store(filter, page, count, READ);
}

static ssize_t rcf_writecmds_store(struct blk_scsi_cmd_filter *filter,
				   const char *page, size_t count)
{
	return rcf_cmds_store(filter, page, count, WRITE);
}

struct rcf_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct blk_scsi_cmd_filter *, char *);
	ssize_t (*store)(struct blk_scsi_cmd_filter *, const char *, size_t);
};

static struct rcf_sysfs_entry rcf_readcmds_entry = {
	.attr = { .name = "read_table", .mode = S_IRUGO | S_IWUSR },
	.show = rcf_readcmds_show,
	.store = rcf_readcmds_store,
};

static struct rcf_sysfs_entry rcf_writecmds_entry = {
	.attr = {.name = "write_table", .mode = S_IRUGO | S_IWUSR },
	.show = rcf_writecmds_show,
	.store = rcf_writecmds_store,
};

static struct attribute *default_attrs[] = {
	&rcf_readcmds_entry.attr,
	&rcf_writecmds_entry.attr,
	NULL,
};

#define to_rcf(atr) container_of((atr), struct rcf_sysfs_entry, attr)

static ssize_t
rcf_attr_show(struct kobject *kobj, struct attribute *attr, char *page)
{
	struct rcf_sysfs_entry *entry = to_rcf(attr);
	struct blk_scsi_cmd_filter *filter;

	filter = container_of(kobj, struct blk_scsi_cmd_filter, kobj);
	if (entry->show)
		return entry->show(filter, page);

	return 0;
}

static ssize_t
rcf_attr_store(struct kobject *kobj, struct attribute *attr,
			const char *page, size_t length)
{
	struct rcf_sysfs_entry *entry = to_rcf(attr);
	struct blk_scsi_cmd_filter *filter;

	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;

	if (!entry->store)
		return -EINVAL;

	filter = container_of(kobj, struct blk_scsi_cmd_filter, kobj);
	return entry->store(filter, page, length);
}

static struct sysfs_ops rcf_sysfs_ops = {
	.show = rcf_attr_show,
	.store = rcf_attr_store,
};

static struct kobj_type rcf_ktype = {
	.sysfs_ops = &rcf_sysfs_ops,
	.default_attrs = default_attrs,
};

static void rcf_set_defaults(struct blk_scsi_cmd_filter *filter)
{
	/* Basic read-only commands */
	__set_bit(TEST_UNIT_READY, filter->read_ok);
	__set_bit(REQUEST_SENSE, filter->read_ok);
	__set_bit(READ_6, filter->read_ok);
	__set_bit(READ_10, filter->read_ok);
	__set_bit(READ_12, filter->read_ok);
	__set_bit(READ_16, filter->read_ok);
	__set_bit(READ_BUFFER, filter->read_ok);
	__set_bit(READ_DEFECT_DATA, filter->read_ok);
	__set_bit(READ_LONG, filter->read_ok);
	__set_bit(INQUIRY, filter->read_ok);
	__set_bit(MODE_SENSE, filter->read_ok);
	__set_bit(MODE_SENSE_10, filter->read_ok);
	__set_bit(LOG_SENSE, filter->read_ok);
	__set_bit(START_STOP, filter->read_ok);
	__set_bit(GPCMD_VERIFY_10, filter->read_ok);
	__set_bit(VERIFY_16, filter->read_ok);
	__set_bit(GPCMD_READ_BUFFER_CAPACITY, filter->read_ok);

	/* Audio CD commands */
	__set_bit(GPCMD_PLAY_CD, filter->read_ok);
	__set_bit(GPCMD_PLAY_AUDIO_10, filter->read_ok);
	__set_bit(GPCMD_PLAY_AUDIO_MSF, filter->read_ok);
	__set_bit(GPCMD_PLAY_AUDIO_TI, filter->read_ok);
	__set_bit(GPCMD_PAUSE_RESUME, filter->read_ok);

	/* CD/DVD data reading */
	__set_bit(GPCMD_READ_CD, filter->read_ok);
	__set_bit(GPCMD_READ_CD_MSF, filter->read_ok);
	__set_bit(GPCMD_READ_DISC_INFO, filter->read_ok);
	__set_bit(GPCMD_READ_CDVD_CAPACITY, filter->read_ok);
	__set_bit(GPCMD_READ_DVD_STRUCTURE, filter->read_ok);
	__set_bit(GPCMD_READ_HEADER, filter->read_ok);
	__set_bit(GPCMD_READ_TRACK_RZONE_INFO, filter->read_ok);
	__set_bit(GPCMD_READ_SUBCHANNEL, filter->read_ok);
	__set_bit(GPCMD_READ_TOC_PMA_ATIP, filter->read_ok);
	__set_bit(GPCMD_REPORT_KEY, filter->read_ok);
	__set_bit(GPCMD_SCAN, filter->read_ok);
	__set_bit(GPCMD_GET_CONFIGURATION, filter->read_ok);
	__set_bit(GPCMD_READ_FORMAT_CAPACITIES, filter->read_ok);
	__set_bit(GPCMD_GET_EVENT_STATUS_NOTIFICATION, filter->read_ok);
	__set_bit(GPCMD_GET_PERFORMANCE, filter->read_ok);
	__set_bit(GPCMD_SEEK, filter->read_ok);
	__set_bit(GPCMD_STOP_PLAY_SCAN, filter->read_ok);

	/* Basic writing commands */
	__set_bit(WRITE_6, filter->write_ok);
	__set_bit(WRITE_10, filter->write_ok);
	__set_bit(WRITE_VERIFY, filter->write_ok);
	__set_bit(WRITE_12, filter->write_ok);
	__set_bit(WRITE_VERIFY_12, filter->write_ok);
	__set_bit(WRITE_16, filter->write_ok);
	__set_bit(WRITE_LONG, filter->write_ok);
	__set_bit(WRITE_LONG_2, filter->write_ok);
	__set_bit(ERASE, filter->write_ok);
	__set_bit(GPCMD_MODE_SELECT_10, filter->write_ok);
	__set_bit(MODE_SELECT, filter->write_ok);
	__set_bit(LOG_SELECT, filter->write_ok);
	__set_bit(GPCMD_BLANK, filter->write_ok);
	__set_bit(GPCMD_CLOSE_TRACK, filter->write_ok);
	__set_bit(GPCMD_FLUSH_CACHE, filter->write_ok);
	__set_bit(GPCMD_FORMAT_UNIT, filter->write_ok);
	__set_bit(GPCMD_REPAIR_RZONE_TRACK, filter->write_ok);
	__set_bit(GPCMD_RESERVE_RZONE_TRACK, filter->write_ok);
	__set_bit(GPCMD_SEND_DVD_STRUCTURE, filter->write_ok);
	__set_bit(GPCMD_SEND_EVENT, filter->write_ok);
	__set_bit(GPCMD_SEND_KEY, filter->write_ok);
	__set_bit(GPCMD_SEND_OPC, filter->write_ok);
	__set_bit(GPCMD_SEND_CUE_SHEET, filter->write_ok);
	__set_bit(GPCMD_SET_SPEED, filter->write_ok);
	__set_bit(GPCMD_PREVENT_ALLOW_MEDIUM_REMOVAL, filter->write_ok);
	__set_bit(GPCMD_LOAD_UNLOAD, filter->write_ok);
	__set_bit(GPCMD_SET_STREAMING, filter->write_ok);
}

int blk_register_filter(struct gendisk *disk)
{
	int ret;
	struct blk_scsi_cmd_filter *filter = &disk->cmd_filter;
	struct kobject *parent = kobject_get(disk->holder_dir->parent);

	if (!parent)
		return -ENODEV;

	ret = kobject_init_and_add(&filter->kobj, &rcf_ktype, parent,
				 "%s", "cmd_filter");

	if (ret < 0)
		return ret;

	rcf_set_defaults(filter);
	return 0;
}

void blk_unregister_filter(struct gendisk *disk)
{
	struct blk_scsi_cmd_filter *filter = &disk->cmd_filter;

	kobject_put(&filter->kobj);
	kobject_put(disk->holder_dir->parent);
}

