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
#include <asm/semaphore.h>

#include "gfs2.h"
#include <linux/gfs2_ondisk.h>

#define pv(struct, member, fmt) printk(KERN_INFO "  "#member" = "fmt"\n", \
				       struct->member);

/*
 * gfs2_xxx_in - read in an xxx struct
 * first arg: the cpu-order structure
 * buf: the disk-order buffer
 *
 * gfs2_xxx_out - write out an xxx struct
 * first arg: the cpu-order structure
 * buf: the disk-order buffer
 *
 * gfs2_xxx_print - print out an xxx struct
 * first arg: the cpu-order structure
 */

void gfs2_inum_in(struct gfs2_inum *no, char *buf)
{
	struct gfs2_inum *str = (struct gfs2_inum *)buf;

	no->no_formal_ino = be64_to_cpu(str->no_formal_ino);
	no->no_addr = be64_to_cpu(str->no_addr);
}

void gfs2_inum_out(const struct gfs2_inum *no, char *buf)
{
	struct gfs2_inum *str = (struct gfs2_inum *)buf;

	str->no_formal_ino = cpu_to_be64(no->no_formal_ino);
	str->no_addr = cpu_to_be64(no->no_addr);
}

static void gfs2_inum_print(struct gfs2_inum *no)
{
	pv(no, no_formal_ino, "%llu");
	pv(no, no_addr, "%llu");
}

static void gfs2_meta_header_in(struct gfs2_meta_header *mh, char *buf)
{
	struct gfs2_meta_header *str = (struct gfs2_meta_header *)buf;

	mh->mh_magic = be32_to_cpu(str->mh_magic);
	mh->mh_type = be32_to_cpu(str->mh_type);
	mh->mh_format = be32_to_cpu(str->mh_format);
}

static void gfs2_meta_header_out(struct gfs2_meta_header *mh, char *buf)
{
	struct gfs2_meta_header *str = (struct gfs2_meta_header *)buf;

	str->mh_magic = cpu_to_be32(mh->mh_magic);
	str->mh_type = cpu_to_be32(mh->mh_type);
	str->mh_format = cpu_to_be32(mh->mh_format);
}

static void gfs2_meta_header_print(struct gfs2_meta_header *mh)
{
	pv(mh, mh_magic, "0x%.8X");
	pv(mh, mh_type, "%u");
	pv(mh, mh_format, "%u");
}

void gfs2_sb_in(struct gfs2_sb *sb, char *buf)
{
	struct gfs2_sb *str = (struct gfs2_sb *)buf;

	gfs2_meta_header_in(&sb->sb_header, buf);

	sb->sb_fs_format = be32_to_cpu(str->sb_fs_format);
	sb->sb_multihost_format = be32_to_cpu(str->sb_multihost_format);
	sb->sb_bsize = be32_to_cpu(str->sb_bsize);
	sb->sb_bsize_shift = be32_to_cpu(str->sb_bsize_shift);

	gfs2_inum_in(&sb->sb_master_dir, (char *)&str->sb_master_dir);
	gfs2_inum_in(&sb->sb_root_dir, (char *)&str->sb_root_dir);

	memcpy(sb->sb_lockproto, str->sb_lockproto, GFS2_LOCKNAME_LEN);
	memcpy(sb->sb_locktable, str->sb_locktable, GFS2_LOCKNAME_LEN);
}

void gfs2_rindex_in(struct gfs2_rindex *ri, char *buf)
{
	struct gfs2_rindex *str = (struct gfs2_rindex *)buf;

	ri->ri_addr = be64_to_cpu(str->ri_addr);
	ri->ri_length = be32_to_cpu(str->ri_length);
	ri->ri_data0 = be64_to_cpu(str->ri_data0);
	ri->ri_data = be32_to_cpu(str->ri_data);
	ri->ri_bitbytes = be32_to_cpu(str->ri_bitbytes);

}

void gfs2_rindex_print(struct gfs2_rindex *ri)
{
	pv(ri, ri_addr, "%llu");
	pv(ri, ri_length, "%u");

	pv(ri, ri_data0, "%llu");
	pv(ri, ri_data, "%u");

	pv(ri, ri_bitbytes, "%u");
}

void gfs2_rgrp_in(struct gfs2_rgrp *rg, char *buf)
{
	struct gfs2_rgrp *str = (struct gfs2_rgrp *)buf;

	gfs2_meta_header_in(&rg->rg_header, buf);
	rg->rg_flags = be32_to_cpu(str->rg_flags);
	rg->rg_free = be32_to_cpu(str->rg_free);
	rg->rg_dinodes = be32_to_cpu(str->rg_dinodes);
}

void gfs2_rgrp_out(struct gfs2_rgrp *rg, char *buf)
{
	struct gfs2_rgrp *str = (struct gfs2_rgrp *)buf;

	gfs2_meta_header_out(&rg->rg_header, buf);
	str->rg_flags = cpu_to_be32(rg->rg_flags);
	str->rg_free = cpu_to_be32(rg->rg_free);
	str->rg_dinodes = cpu_to_be32(rg->rg_dinodes);

	memset(&str->rg_reserved, 0, sizeof(str->rg_reserved));
}

void gfs2_quota_in(struct gfs2_quota *qu, char *buf)
{
	struct gfs2_quota *str = (struct gfs2_quota *)buf;

	qu->qu_limit = be64_to_cpu(str->qu_limit);
	qu->qu_warn = be64_to_cpu(str->qu_warn);
	qu->qu_value = be64_to_cpu(str->qu_value);
}

void gfs2_dinode_in(struct gfs2_dinode *di, char *buf)
{
	struct gfs2_dinode *str = (struct gfs2_dinode *)buf;

	gfs2_meta_header_in(&di->di_header, buf);
	gfs2_inum_in(&di->di_num, (char *)&str->di_num);

	di->di_mode = be32_to_cpu(str->di_mode);
	di->di_uid = be32_to_cpu(str->di_uid);
	di->di_gid = be32_to_cpu(str->di_gid);
	di->di_nlink = be32_to_cpu(str->di_nlink);
	di->di_size = be64_to_cpu(str->di_size);
	di->di_blocks = be64_to_cpu(str->di_blocks);
	di->di_atime = be64_to_cpu(str->di_atime);
	di->di_mtime = be64_to_cpu(str->di_mtime);
	di->di_ctime = be64_to_cpu(str->di_ctime);
	di->di_major = be32_to_cpu(str->di_major);
	di->di_minor = be32_to_cpu(str->di_minor);

	di->di_goal_meta = be64_to_cpu(str->di_goal_meta);
	di->di_goal_data = be64_to_cpu(str->di_goal_data);

	di->di_flags = be32_to_cpu(str->di_flags);
	di->di_payload_format = be32_to_cpu(str->di_payload_format);
	di->di_height = be16_to_cpu(str->di_height);

	di->di_depth = be16_to_cpu(str->di_depth);
	di->di_entries = be32_to_cpu(str->di_entries);

	di->di_eattr = be64_to_cpu(str->di_eattr);

}

void gfs2_dinode_out(struct gfs2_dinode *di, char *buf)
{
	struct gfs2_dinode *str = (struct gfs2_dinode *)buf;

	gfs2_meta_header_out(&di->di_header, buf);
	gfs2_inum_out(&di->di_num, (char *)&str->di_num);

	str->di_mode = cpu_to_be32(di->di_mode);
	str->di_uid = cpu_to_be32(di->di_uid);
	str->di_gid = cpu_to_be32(di->di_gid);
	str->di_nlink = cpu_to_be32(di->di_nlink);
	str->di_size = cpu_to_be64(di->di_size);
	str->di_blocks = cpu_to_be64(di->di_blocks);
	str->di_atime = cpu_to_be64(di->di_atime);
	str->di_mtime = cpu_to_be64(di->di_mtime);
	str->di_ctime = cpu_to_be64(di->di_ctime);
	str->di_major = cpu_to_be32(di->di_major);
	str->di_minor = cpu_to_be32(di->di_minor);

	str->di_goal_meta = cpu_to_be64(di->di_goal_meta);
	str->di_goal_data = cpu_to_be64(di->di_goal_data);

	str->di_flags = cpu_to_be32(di->di_flags);
	str->di_payload_format = cpu_to_be32(di->di_payload_format);
	str->di_height = cpu_to_be16(di->di_height);

	str->di_depth = cpu_to_be16(di->di_depth);
	str->di_entries = cpu_to_be32(di->di_entries);

	str->di_eattr = cpu_to_be64(di->di_eattr);

}

void gfs2_dinode_print(struct gfs2_dinode *di)
{
	gfs2_meta_header_print(&di->di_header);
	gfs2_inum_print(&di->di_num);

	pv(di, di_mode, "0%o");
	pv(di, di_uid, "%u");
	pv(di, di_gid, "%u");
	pv(di, di_nlink, "%u");
	pv(di, di_size, "%llu");
	pv(di, di_blocks, "%llu");
	pv(di, di_atime, "%lld");
	pv(di, di_mtime, "%lld");
	pv(di, di_ctime, "%lld");
	pv(di, di_major, "%u");
	pv(di, di_minor, "%u");

	pv(di, di_goal_meta, "%llu");
	pv(di, di_goal_data, "%llu");

	pv(di, di_flags, "0x%.8X");
	pv(di, di_payload_format, "%u");
	pv(di, di_height, "%u");

	pv(di, di_depth, "%u");
	pv(di, di_entries, "%u");

	pv(di, di_eattr, "%llu");
}

void gfs2_log_header_in(struct gfs2_log_header *lh, char *buf)
{
	struct gfs2_log_header *str = (struct gfs2_log_header *)buf;

	gfs2_meta_header_in(&lh->lh_header, buf);
	lh->lh_sequence = be64_to_cpu(str->lh_sequence);
	lh->lh_flags = be32_to_cpu(str->lh_flags);
	lh->lh_tail = be32_to_cpu(str->lh_tail);
	lh->lh_blkno = be32_to_cpu(str->lh_blkno);
	lh->lh_hash = be32_to_cpu(str->lh_hash);
}

void gfs2_inum_range_in(struct gfs2_inum_range *ir, char *buf)
{
	struct gfs2_inum_range *str = (struct gfs2_inum_range *)buf;

	ir->ir_start = be64_to_cpu(str->ir_start);
	ir->ir_length = be64_to_cpu(str->ir_length);
}

void gfs2_inum_range_out(struct gfs2_inum_range *ir, char *buf)
{
	struct gfs2_inum_range *str = (struct gfs2_inum_range *)buf;

	str->ir_start = cpu_to_be64(ir->ir_start);
	str->ir_length = cpu_to_be64(ir->ir_length);
}

void gfs2_statfs_change_in(struct gfs2_statfs_change *sc, char *buf)
{
	struct gfs2_statfs_change *str = (struct gfs2_statfs_change *)buf;

	sc->sc_total = be64_to_cpu(str->sc_total);
	sc->sc_free = be64_to_cpu(str->sc_free);
	sc->sc_dinodes = be64_to_cpu(str->sc_dinodes);
}

void gfs2_statfs_change_out(struct gfs2_statfs_change *sc, char *buf)
{
	struct gfs2_statfs_change *str = (struct gfs2_statfs_change *)buf;

	str->sc_total = cpu_to_be64(sc->sc_total);
	str->sc_free = cpu_to_be64(sc->sc_free);
	str->sc_dinodes = cpu_to_be64(sc->sc_dinodes);
}

void gfs2_unlinked_tag_in(struct gfs2_unlinked_tag *ut, char *buf)
{
	struct gfs2_unlinked_tag *str = (struct gfs2_unlinked_tag *)buf;

	gfs2_inum_in(&ut->ut_inum, buf);
	ut->ut_flags = be32_to_cpu(str->ut_flags);
}

void gfs2_unlinked_tag_out(struct gfs2_unlinked_tag *ut, char *buf)
{
	struct gfs2_unlinked_tag *str = (struct gfs2_unlinked_tag *)buf;

	gfs2_inum_out(&ut->ut_inum, buf);
	str->ut_flags = cpu_to_be32(ut->ut_flags);
	str->__pad = 0;
}

void gfs2_quota_change_in(struct gfs2_quota_change *qc, char *buf)
{
	struct gfs2_quota_change *str = (struct gfs2_quota_change *)buf;

	qc->qc_change = be64_to_cpu(str->qc_change);
	qc->qc_flags = be32_to_cpu(str->qc_flags);
	qc->qc_id = be32_to_cpu(str->qc_id);
}

