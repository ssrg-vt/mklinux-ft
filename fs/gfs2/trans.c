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
#include "glock.h"
#include "log.h"
#include "lops.h"
#include "meta_io.h"
#include "trans.h"
#include "util.h"

int gfs2_trans_begin_i(struct gfs2_sbd *sdp, unsigned int blocks,
		       unsigned int revokes, char *file, unsigned int line)
{
	struct gfs2_trans *tr;
	int error;

	if (gfs2_assert_warn(sdp, !current->journal_info) ||
	    gfs2_assert_warn(sdp, blocks || revokes)) {
		fs_warn(sdp, "(%s, %u)\n", file, line);
		return -EINVAL;
	}

	tr = kzalloc(sizeof(struct gfs2_trans), GFP_NOFS);
	if (!tr)
		return -ENOMEM;

	tr->tr_file = file;
	tr->tr_line = line;
	tr->tr_blocks = blocks;
	tr->tr_revokes = revokes;
	tr->tr_reserved = 1;
	if (blocks)
		tr->tr_reserved += 1 + blocks;
	if (revokes)
		tr->tr_reserved += gfs2_struct2blk(sdp, revokes,
						   sizeof(uint64_t));
	INIT_LIST_HEAD(&tr->tr_list_buf);

	gfs2_holder_init(sdp->sd_trans_gl, LM_ST_SHARED,
			 GL_NEVER_RECURSE, &tr->tr_t_gh);

	error = gfs2_glock_nq(&tr->tr_t_gh);
	if (error)
		goto fail_holder_uninit;

	if (!test_bit(SDF_JOURNAL_LIVE, &sdp->sd_flags)) {
		tr->tr_t_gh.gh_flags |= GL_NOCACHE;
		error = -EROFS;
		goto fail_gunlock;
	}

	error = gfs2_log_reserve(sdp, tr->tr_reserved);
	if (error)
		goto fail_gunlock;

	current->journal_info = tr;

	return 0;

 fail_gunlock:
	gfs2_glock_dq(&tr->tr_t_gh);

 fail_holder_uninit:
	gfs2_holder_uninit(&tr->tr_t_gh);
	kfree(tr);

	return error;
}

void gfs2_trans_end(struct gfs2_sbd *sdp)
{
	struct gfs2_trans *tr;

	tr = current->journal_info;
	current->journal_info = NULL;

	if (gfs2_assert_warn(sdp, tr))
		return;

	if (!tr->tr_touched) {
		gfs2_log_release(sdp, tr->tr_reserved);

		gfs2_glock_dq(&tr->tr_t_gh);
		gfs2_holder_uninit(&tr->tr_t_gh);

		kfree(tr);
		return;
	}

	if (gfs2_assert_withdraw(sdp, tr->tr_num_buf <= tr->tr_blocks))
		fs_err(sdp, "tr_num_buf = %u, tr_blocks = %u "
		       "tr_file = %s, tr_line = %u\n",
		       tr->tr_num_buf, tr->tr_blocks,
		       tr->tr_file, tr->tr_line);
	if (gfs2_assert_withdraw(sdp, tr->tr_num_revoke <= tr->tr_revokes))
		fs_err(sdp, "tr_num_revoke = %u, tr_revokes = %u "
		       "tr_file = %s, tr_line = %u\n",
		       tr->tr_num_revoke, tr->tr_revokes,
		       tr->tr_file, tr->tr_line);

	gfs2_log_commit(sdp, tr);

        gfs2_glock_dq(&tr->tr_t_gh);
        gfs2_holder_uninit(&tr->tr_t_gh);

        kfree(tr);

	if (sdp->sd_vfs->s_flags & MS_SYNCHRONOUS)
		gfs2_log_flush(sdp);
}

void gfs2_trans_add_gl(struct gfs2_glock *gl)
{
	lops_add(gl->gl_sbd, &gl->gl_le);
}

/**
 * gfs2_trans_add_bh - Add a to-be-modified buffer to the current transaction
 * @gl: the glock the buffer belongs to
 * @bh: The buffer to add
 * @meta: True in the case of adding metadata
 *
 */

void gfs2_trans_add_bh(struct gfs2_glock *gl, struct buffer_head *bh, int meta)
{
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct gfs2_bufdata *bd;

	bd = bh->b_private;
	if (bd)
		gfs2_assert(sdp, bd->bd_gl == gl);
	else {
		gfs2_attach_bufdata(gl, bh, meta);
		bd = bh->b_private;
	}
	lops_add(sdp, &bd->bd_le);
}

void gfs2_trans_add_revoke(struct gfs2_sbd *sdp, uint64_t blkno)
{
	struct gfs2_revoke *rv = kmalloc(sizeof(struct gfs2_revoke),
					 GFP_NOFS | __GFP_NOFAIL);
	lops_init_le(&rv->rv_le, &gfs2_revoke_lops);
	rv->rv_blkno = blkno;
	lops_add(sdp, &rv->rv_le);
}

void gfs2_trans_add_unrevoke(struct gfs2_sbd *sdp, uint64_t blkno)
{
	struct gfs2_revoke *rv;
	int found = 0;

	gfs2_log_lock(sdp);

	list_for_each_entry(rv, &sdp->sd_log_le_revoke, rv_le.le_list) {
		if (rv->rv_blkno == blkno) {
			list_del(&rv->rv_le.le_list);
			gfs2_assert_withdraw(sdp, sdp->sd_log_num_revoke);
			sdp->sd_log_num_revoke--;
			found = 1;
			break;
		}
	}

	gfs2_log_unlock(sdp);

	if (found) {
		struct gfs2_trans *tr = current->journal_info;
		kfree(rv);
		tr->tr_num_revoke_rm++;
	}
}

void gfs2_trans_add_rg(struct gfs2_rgrpd *rgd)
{
	lops_add(rgd->rd_sbd, &rgd->rd_le);
}

