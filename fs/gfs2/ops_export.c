/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2005 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/buffer_head.h>
#include <linux/gfs2_ondisk.h>
#include <asm/semaphore.h>

#include "gfs2.h"
#include "lm_interface.h"
#include "incore.h"
#include "dir.h"
#include "glock.h"
#include "glops.h"
#include "inode.h"
#include "ops_export.h"
#include "rgrp.h"

static struct dentry *gfs2_decode_fh(struct super_block *sb,
				     __u32 *fh,
				     int fh_len,
				     int fh_type,
				     int (*acceptable)(void *context,
						       struct dentry *dentry),
				     void *context)
{
	struct gfs2_inum this, parent;

	if (fh_type != fh_len)
		return NULL;

	memset(&parent, 0, sizeof(struct gfs2_inum));

	switch (fh_type) {
	case 8:
		parent.no_formal_ino = ((uint64_t)be32_to_cpu(fh[4])) << 32;
		parent.no_formal_ino |= be32_to_cpu(fh[5]);
		parent.no_addr = ((uint64_t)be32_to_cpu(fh[6])) << 32;
		parent.no_addr |= be32_to_cpu(fh[7]);
	case 4:
		this.no_formal_ino = ((uint64_t)be32_to_cpu(fh[0])) << 32;
		this.no_formal_ino |= be32_to_cpu(fh[1]);
		this.no_addr = ((uint64_t)be32_to_cpu(fh[2])) << 32;
		this.no_addr |= be32_to_cpu(fh[3]);
		break;
	default:
		return NULL;
	}

	return gfs2_export_ops.find_exported_dentry(sb, &this, &parent,
						    acceptable, context);
}

static int gfs2_encode_fh(struct dentry *dentry, __u32 *fh, int *len,
			  int connectable)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct gfs2_inode *ip = inode->u.generic_ip;

	if (*len < 4 || (connectable && *len < 8))
		return 255;

	fh[0] = ip->i_num.no_formal_ino >> 32;
	fh[0] = cpu_to_be32(fh[0]);
	fh[1] = ip->i_num.no_formal_ino & 0xFFFFFFFF;
	fh[1] = cpu_to_be32(fh[1]);
	fh[2] = ip->i_num.no_addr >> 32;
	fh[2] = cpu_to_be32(fh[2]);
	fh[3] = ip->i_num.no_addr & 0xFFFFFFFF;
	fh[3] = cpu_to_be32(fh[3]);
	*len = 4;

	if (!connectable || inode == sb->s_root->d_inode)
		return *len;

	spin_lock(&dentry->d_lock);
	inode = dentry->d_parent->d_inode;
	ip = inode->u.generic_ip;
	gfs2_inode_hold(ip);
	spin_unlock(&dentry->d_lock);

	fh[4] = ip->i_num.no_formal_ino >> 32;
	fh[4] = cpu_to_be32(fh[4]);
	fh[5] = ip->i_num.no_formal_ino & 0xFFFFFFFF;
	fh[5] = cpu_to_be32(fh[5]);
	fh[6] = ip->i_num.no_addr >> 32;
	fh[6] = cpu_to_be32(fh[6]);
	fh[7] = ip->i_num.no_addr & 0xFFFFFFFF;
	fh[7] = cpu_to_be32(fh[7]);
	*len = 8;

	gfs2_inode_put(ip);

	return *len;
}

struct get_name_filldir {
	struct gfs2_inum inum;
	char *name;
};

static int get_name_filldir(void *opaque, const char *name, unsigned int length,
			    uint64_t offset, struct gfs2_inum *inum,
			    unsigned int type)
{
	struct get_name_filldir *gnfd = (struct get_name_filldir *)opaque;

	if (!gfs2_inum_equal(inum, &gnfd->inum))
		return 0;

	memcpy(gnfd->name, name, length);
	gnfd->name[length] = 0;

	return 1;
}

static int gfs2_get_name(struct dentry *parent, char *name,
			 struct dentry *child)
{
	struct inode *dir = parent->d_inode;
	struct inode *inode = child->d_inode;
	struct gfs2_inode *dip, *ip;
	struct get_name_filldir gnfd;
	struct gfs2_holder gh;
	uint64_t offset = 0;
	int error;

	if (!dir)
		return -EINVAL;

	if (!S_ISDIR(dir->i_mode) || !inode)
		return -EINVAL;

	dip = dir->u.generic_ip;
	ip = inode->u.generic_ip;

	*name = 0;
	gnfd.inum = ip->i_num;
	gnfd.name = name;

	error = gfs2_glock_nq_init(dip->i_gl, LM_ST_SHARED, 0, &gh);
	if (error)
		return error;

	error = gfs2_dir_read(dip, &offset, &gnfd, get_name_filldir);

	gfs2_glock_dq_uninit(&gh);

	if (!error && !*name)
		error = -ENOENT;

	return error;
}

static struct dentry *gfs2_get_parent(struct dentry *child)
{
	struct qstr dotdot = { .name = "..", .len = 2 };
	struct inode *inode;
	struct dentry *dentry;
	int error;

	error = gfs2_lookupi(child->d_inode, &dotdot, 1, &inode);
	if (error)
		return ERR_PTR(error);

	dentry = d_alloc_anon(inode);
	if (!dentry) {
		iput(inode);
		return ERR_PTR(-ENOMEM);
	}

	return dentry;
}

static struct dentry *gfs2_get_dentry(struct super_block *sb, void *inum_p)
{
	struct gfs2_sbd *sdp = sb->s_fs_info;
	struct gfs2_inum *inum = (struct gfs2_inum *)inum_p;
	struct gfs2_holder i_gh, ri_gh, rgd_gh;
	struct gfs2_rgrpd *rgd;
	struct gfs2_inode *ip;
	struct inode *inode;
	struct dentry *dentry;
	int error;

	/* System files? */

	inode = gfs2_iget(sb, inum);
	if (inode) {
		ip = inode->u.generic_ip;
		if (ip->i_num.no_formal_ino != inum->no_formal_ino) {
			iput(inode);
			return ERR_PTR(-ESTALE);
		}
		goto out_inode;
	}

	error = gfs2_glock_nq_num(sdp,
				  inum->no_addr, &gfs2_inode_glops,
				  LM_ST_SHARED, LM_FLAG_ANY | GL_LOCAL_EXCL,
				  &i_gh);
	if (error)
		return ERR_PTR(error);

	error = gfs2_inode_get(i_gh.gh_gl, inum, NO_CREATE, &ip);
	if (error)
		goto fail;
	if (ip)
		goto out_ip;

	error = gfs2_rindex_hold(sdp, &ri_gh);
	if (error)
		goto fail;

	error = -EINVAL;
	rgd = gfs2_blk2rgrpd(sdp, inum->no_addr);
	if (!rgd)
		goto fail_rindex;

	error = gfs2_glock_nq_init(rgd->rd_gl, LM_ST_SHARED, 0, &rgd_gh);
	if (error)
		goto fail_rindex;

	error = -ESTALE;
	if (gfs2_get_block_type(rgd, inum->no_addr) != GFS2_BLKST_DINODE)
		goto fail_rgd;

	gfs2_glock_dq_uninit(&rgd_gh);
	gfs2_glock_dq_uninit(&ri_gh);

	error = gfs2_inode_get(i_gh.gh_gl, inum, CREATE, &ip);
	if (error)
		goto fail;

	error = gfs2_inode_refresh(ip);
	if (error) {
		gfs2_inode_put(ip);
		goto fail;
	}

 out_ip:
	error = -EIO;
	if (ip->i_di.di_flags & GFS2_DIF_SYSTEM) {
		gfs2_inode_put(ip);
		goto fail;
	}

	gfs2_glock_dq_uninit(&i_gh);

	inode = gfs2_ip2v(ip);
	gfs2_inode_put(ip);

	if (!inode)
		return ERR_PTR(-ENOMEM);

 out_inode:
	dentry = d_alloc_anon(inode);
	if (!dentry) {
		iput(inode);
		return ERR_PTR(-ENOMEM);
	}

	return dentry;

 fail_rgd:
	gfs2_glock_dq_uninit(&rgd_gh);

 fail_rindex:
	gfs2_glock_dq_uninit(&ri_gh);

 fail:
	gfs2_glock_dq_uninit(&i_gh);
	return ERR_PTR(error);
}

struct export_operations gfs2_export_ops = {
	.decode_fh = gfs2_decode_fh,
	.encode_fh = gfs2_encode_fh,
	.get_name = gfs2_get_name,
	.get_parent = gfs2_get_parent,
	.get_dentry = gfs2_get_dentry,
};

