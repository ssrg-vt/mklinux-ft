/*
 *  linux/fs/9p/vfs_file.c
 *
 * This file contians vfs file ops for 9P2000.
 *
 *  Copyright (C) 2004 by Eric Van Hensbergen <ericvh@gmail.com>
 *  Copyright (C) 2002 by Ron Minnich <rminnich@lanl.gov>
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
 *  along with this program; if not, write to:
 *  Free Software Foundation
 *  51 Franklin Street, Fifth Floor
 *  Boston, MA  02111-1301  USA
 *
 */

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/smp_lock.h>
#include <linux/inet.h>
#include <linux/version.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/idr.h>

#include "debug.h"
#include "v9fs.h"
#include "9p.h"
#include "v9fs_vfs.h"
#include "fid.h"

/**
 * v9fs_file_open - open a file (or directory)
 * @inode: inode to be opened
 * @file: file being opened
 *
 */

int v9fs_file_open(struct inode *inode, struct file *file)
{
	struct v9fs_session_info *v9ses = v9fs_inode2v9ses(inode);
	struct v9fs_fid *v9fid = v9fs_fid_lookup(file->f_dentry, FID_WALK);
	struct v9fs_fid *v9newfid = NULL;
	struct v9fs_fcall *fcall = NULL;
	int open_mode = 0;
	unsigned int iounit = 0;
	int newfid = -1;
	long result = -1;

	dprintk(DEBUG_VFS, "inode: %p file: %p v9fid= %p\n", inode, file,
		v9fid);

	if (!v9fid) {
		struct dentry *dentry = file->f_dentry;
		dprintk(DEBUG_ERROR, "Couldn't resolve fid from dentry\n");

		/* XXX - some duplication from lookup, generalize later */
		/* basically vfs_lookup is too heavy weight */
		v9fid = v9fs_fid_lookup(file->f_dentry, FID_OP);
		if (!v9fid)
			return -EBADF;

		v9fid = v9fs_fid_lookup(dentry->d_parent, FID_WALK);
		if (!v9fid)
			return -EBADF;

		newfid = v9fs_get_idpool(&v9ses->fidpool);
		if (newfid < 0) {
			eprintk(KERN_WARNING, "newfid fails!\n");
			return -ENOSPC;
		}

		result =
		    v9fs_t_walk(v9ses, v9fid->fid, newfid,
				(char *)file->f_dentry->d_name.name, NULL);
		if (result < 0) {
			v9fs_put_idpool(newfid, &v9ses->fidpool);
			dprintk(DEBUG_ERROR, "rewalk didn't work\n");
			return -EBADF;
		}

		v9fid = v9fs_fid_create(dentry);
		if (v9fid == NULL) {
			dprintk(DEBUG_ERROR, "couldn't insert\n");
			return -ENOMEM;
		}
		v9fid->fid = newfid;
	}

	if (v9fid->fidcreate) {
		/* create case */
		newfid = v9fid->fid;
		iounit = v9fid->iounit;
		v9fid->fidcreate = 0;
	} else {
		if (!S_ISDIR(inode->i_mode))
			newfid = v9fid->fid;
		else {
			newfid = v9fs_get_idpool(&v9ses->fidpool);
			if (newfid < 0) {
				eprintk(KERN_WARNING, "allocation failed\n");
				return -ENOSPC;
			}
			/* This would be a somewhat critical clone */
			result =
			    v9fs_t_walk(v9ses, v9fid->fid, newfid, NULL,
					&fcall);
			if (result < 0) {
				dprintk(DEBUG_ERROR, "clone error: %s\n",
					FCALL_ERROR(fcall));
				kfree(fcall);
				return result;
			}

			v9newfid = v9fs_fid_create(file->f_dentry);
			v9newfid->fid = newfid;
			v9newfid->qid = v9fid->qid;
			v9newfid->iounit = v9fid->iounit;
			v9newfid->fidopen = 0;
			v9newfid->fidclunked = 0;
			v9newfid->v9ses = v9ses;
			v9fid = v9newfid;
			kfree(fcall);
		}

		/* TODO: do special things for O_EXCL, O_NOFOLLOW, O_SYNC */
		/* translate open mode appropriately */
		open_mode = file->f_flags & 0x3;

		if (file->f_flags & O_EXCL)
			open_mode |= V9FS_OEXCL;

		if (v9ses->extended) {
			if (file->f_flags & O_TRUNC)
				open_mode |= V9FS_OTRUNC;

			if (file->f_flags & O_APPEND)
				open_mode |= V9FS_OAPPEND;
		}

		result = v9fs_t_open(v9ses, newfid, open_mode, &fcall);
		if (result < 0) {
			dprintk(DEBUG_ERROR,
				"open failed, open_mode 0x%x: %s\n", open_mode,
				FCALL_ERROR(fcall));
			kfree(fcall);
			return result;
		}

		iounit = fcall->params.ropen.iounit;
		kfree(fcall);
	}


	file->private_data = v9fid;

	v9fid->rdir_pos = 0;
	v9fid->rdir_fcall = NULL;
	v9fid->fidopen = 1;
	v9fid->filp = file;
	v9fid->iounit = iounit;

	return 0;
}

/**
 * v9fs_file_lock - lock a file (or directory)
 * @inode: inode to be opened
 * @file: file being opened
 *
 * XXX - this looks like a local only lock, we should extend into 9P
 *       by using open exclusive
 */

static int v9fs_file_lock(struct file *filp, int cmd, struct file_lock *fl)
{
	int res = 0;
	struct inode *inode = filp->f_dentry->d_inode;

	dprintk(DEBUG_VFS, "filp: %p lock: %p\n", filp, fl);

	/* No mandatory locks */
	if ((inode->i_mode & (S_ISGID | S_IXGRP)) == S_ISGID)
		return -ENOLCK;

	if ((IS_SETLK(cmd) || IS_SETLKW(cmd)) && fl->fl_type != F_UNLCK) {
		filemap_fdatawrite(inode->i_mapping);
		filemap_fdatawait(inode->i_mapping);
		invalidate_inode_pages(&inode->i_data);
	}

	return res;
}

/**
 * v9fs_read - read from a file (internal)
 * @filep: file pointer to read
 * @data: data buffer to read data into
 * @count: size of buffer
 * @offset: offset at which to read data
 *
 */

static ssize_t
v9fs_read(struct file *filp, char *buffer, size_t count, loff_t * offset)
{
	struct inode *inode = filp->f_dentry->d_inode;
	struct v9fs_session_info *v9ses = v9fs_inode2v9ses(inode);
	struct v9fs_fid *v9f = filp->private_data;
	struct v9fs_fcall *fcall = NULL;
	int fid = v9f->fid;
	int rsize = 0;
	int result = 0;
	int total = 0;

	dprintk(DEBUG_VFS, "\n");

	rsize = v9ses->maxdata - V9FS_IOHDRSZ;
	if (v9f->iounit != 0 && rsize > v9f->iounit)
		rsize = v9f->iounit;

	do {
		if (count < rsize)
			rsize = count;

		result = v9fs_t_read(v9ses, fid, *offset, rsize, &fcall);

		if (result < 0) {
			printk(KERN_ERR "9P2000: v9fs_t_read returned %d\n",
			       result);

			kfree(fcall);
			return total;
		} else
			*offset += result;

		/* XXX - extra copy */
		memcpy(buffer, fcall->params.rread.data, result);
		count -= result;
		buffer += result;
		total += result;

		kfree(fcall);

		if (result < rsize)
			break;
	} while (count);

	return total;
}

/**
 * v9fs_file_read - read from a file
 * @filep: file pointer to read
 * @data: data buffer to read data into
 * @count: size of buffer
 * @offset: offset at which to read data
 *
 */

static ssize_t
v9fs_file_read(struct file *filp, char __user * data, size_t count,
	       loff_t * offset)
{
	int retval = -1;
	int ret = 0;
	char *buffer;

	buffer = kmalloc(count, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	retval = v9fs_read(filp, buffer, count, offset);
	if (retval > 0) {
		if ((ret = copy_to_user(data, buffer, retval)) != 0) {
			dprintk(DEBUG_ERROR, "Problem copying to user %d\n",
				ret);
			retval = ret;
		}
	}

	kfree(buffer);

	return retval;
}

/**
 * v9fs_write - write to a file
 * @filep: file pointer to write
 * @data: data buffer to write data from
 * @count: size of buffer
 * @offset: offset at which to write data
 *
 */

static ssize_t
v9fs_write(struct file *filp, char *buffer, size_t count, loff_t * offset)
{
	struct inode *inode = filp->f_dentry->d_inode;
	struct v9fs_session_info *v9ses = v9fs_inode2v9ses(inode);
	struct v9fs_fid *v9fid = filp->private_data;
	struct v9fs_fcall *fcall;
	int fid = v9fid->fid;
	int result = -EIO;
	int rsize = 0;
	int total = 0;

	dprintk(DEBUG_VFS, "data %p count %d offset %x\n", buffer, (int)count,
		(int)*offset);
	rsize = v9ses->maxdata - V9FS_IOHDRSZ;
	if (v9fid->iounit != 0 && rsize > v9fid->iounit)
		rsize = v9fid->iounit;

	dump_data(buffer, count);

	do {
		if (count < rsize)
			rsize = count;

		result =
		    v9fs_t_write(v9ses, fid, *offset, rsize, buffer, &fcall);
		if (result < 0) {
			eprintk(KERN_ERR, "error while writing: %s(%d)\n",
				FCALL_ERROR(fcall), result);
			kfree(fcall);
			return result;
		} else
			*offset += result;

		kfree(fcall);

		if (result != rsize) {
			eprintk(KERN_ERR,
				"short write: v9fs_t_write returned %d\n",
				result);
			break;
		}

		count -= result;
		buffer += result;
		total += result;
	} while (count);

	return total;
}

/**
 * v9fs_file_write - write to a file
 * @filep: file pointer to write
 * @data: data buffer to write data from
 * @count: size of buffer
 * @offset: offset at which to write data
 *
 */

static ssize_t
v9fs_file_write(struct file *filp, const char __user * data,
		size_t count, loff_t * offset)
{
	int ret = -1;
	char *buffer;

	buffer = kmalloc(count, GFP_KERNEL);
	if (buffer == NULL)
		return -ENOMEM;

	ret = copy_from_user(buffer, data, count);
	if (ret) {
		dprintk(DEBUG_ERROR, "Problem copying from user\n");
		ret = -EFAULT;
	} else {
		ret = v9fs_write(filp, buffer, count, offset);
	}

	kfree(buffer);

	return ret;
}

struct file_operations v9fs_file_operations = {
	.llseek = generic_file_llseek,
	.read = v9fs_file_read,
	.write = v9fs_file_write,
	.open = v9fs_file_open,
	.release = v9fs_dir_release,
	.lock = v9fs_file_lock,
};
