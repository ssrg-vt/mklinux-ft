/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * extent_map.c
 *
 * Block/Cluster mapping functions
 *
 * Copyright (C) 2004 Oracle.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License, version 2,  as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/types.h>

#define MLOG_MASK_PREFIX ML_EXTENT_MAP
#include <cluster/masklog.h>

#include "ocfs2.h"

#include "alloc.h"
#include "extent_map.h"
#include "inode.h"
#include "super.h"

#include "buffer_head_io.h"

/*
 * Return the 1st index within el which contains an extent start
 * larger than v_cluster.
 */
static int ocfs2_search_for_hole_index(struct ocfs2_extent_list *el,
				       u32 v_cluster)
{
	int i;
	struct ocfs2_extent_rec *rec;

	for(i = 0; i < le16_to_cpu(el->l_next_free_rec); i++) {
		rec = &el->l_recs[i];

		if (v_cluster < le32_to_cpu(rec->e_cpos))
			break;
	}

	return i;
}

/*
 * Figure out the size of a hole which starts at v_cluster within the given
 * extent list.
 *
 * If there is no more allocation past v_cluster, we return the maximum
 * cluster size minus v_cluster.
 *
 * If we have in-inode extents, then el points to the dinode list and
 * eb_bh is NULL. Otherwise, eb_bh should point to the extent block
 * containing el.
 */
static int ocfs2_figure_hole_clusters(struct inode *inode,
				      struct ocfs2_extent_list *el,
				      struct buffer_head *eb_bh,
				      u32 v_cluster,
				      u32 *num_clusters)
{
	int ret, i;
	struct buffer_head *next_eb_bh = NULL;
	struct ocfs2_extent_block *eb, *next_eb;

	i = ocfs2_search_for_hole_index(el, v_cluster);

	if (i == le16_to_cpu(el->l_next_free_rec) && eb_bh) {
		eb = (struct ocfs2_extent_block *)eb_bh->b_data;

		/*
		 * Check the next leaf for any extents.
		 */

		if (le64_to_cpu(eb->h_next_leaf_blk) == 0ULL)
			goto no_more_extents;

		ret = ocfs2_read_block(OCFS2_SB(inode->i_sb),
				       le64_to_cpu(eb->h_next_leaf_blk),
				       &next_eb_bh, OCFS2_BH_CACHED, inode);
		if (ret) {
			mlog_errno(ret);
			goto out;
		}
		next_eb = (struct ocfs2_extent_block *)next_eb_bh->b_data;

		if (!OCFS2_IS_VALID_EXTENT_BLOCK(next_eb)) {
			ret = -EROFS;
			OCFS2_RO_ON_INVALID_EXTENT_BLOCK(inode->i_sb, next_eb);
			goto out;
		}

		el = &next_eb->h_list;

		i = ocfs2_search_for_hole_index(el, v_cluster);
	}

no_more_extents:
	if (i == le16_to_cpu(el->l_next_free_rec)) {
		/*
		 * We're at the end of our existing allocation. Just
		 * return the maximum number of clusters we could
		 * possibly allocate.
		 */
		*num_clusters = UINT_MAX - v_cluster;
	} else {
		*num_clusters = le32_to_cpu(el->l_recs[i].e_cpos) - v_cluster;
	}

	ret = 0;
out:
	brelse(next_eb_bh);
	return ret;
}

/*
 * Return the index of the extent record which contains cluster #v_cluster.
 * -1 is returned if it was not found.
 *
 * Should work fine on interior and exterior nodes.
 */
static int ocfs2_search_extent_list(struct ocfs2_extent_list *el,
				    u32 v_cluster)
{
	int ret = -1;
	int i;
	struct ocfs2_extent_rec *rec;
	u32 rec_end, rec_start, clusters;

	for(i = 0; i < le16_to_cpu(el->l_next_free_rec); i++) {
		rec = &el->l_recs[i];

		rec_start = le32_to_cpu(rec->e_cpos);
		clusters = ocfs2_rec_clusters(el, rec);

		rec_end = rec_start + clusters;

		if (v_cluster >= rec_start && v_cluster < rec_end) {
			ret = i;
			break;
		}
	}

	return ret;
}

int ocfs2_get_clusters(struct inode *inode, u32 v_cluster,
		       u32 *p_cluster, u32 *num_clusters,
		       unsigned int *extent_flags)
{
	int ret, i;
	unsigned int flags = 0;
	struct buffer_head *di_bh = NULL;
	struct buffer_head *eb_bh = NULL;
	struct ocfs2_dinode *di;
	struct ocfs2_extent_block *eb;
	struct ocfs2_extent_list *el;
	struct ocfs2_extent_rec *rec;
	u32 coff;

	ret = ocfs2_read_block(OCFS2_SB(inode->i_sb), OCFS2_I(inode)->ip_blkno,
			       &di_bh, OCFS2_BH_CACHED, inode);
	if (ret) {
		mlog_errno(ret);
		goto out;
	}

	di = (struct ocfs2_dinode *) di_bh->b_data;
	el = &di->id2.i_list;

	if (el->l_tree_depth) {
		ret = ocfs2_find_leaf(inode, el, v_cluster, &eb_bh);
		if (ret) {
			mlog_errno(ret);
			goto out;
		}

		eb = (struct ocfs2_extent_block *) eb_bh->b_data;
		el = &eb->h_list;

		if (el->l_tree_depth) {
			ocfs2_error(inode->i_sb,
				    "Inode %lu has non zero tree depth in "
				    "leaf block %llu\n", inode->i_ino,
				    (unsigned long long)eb_bh->b_blocknr);
			ret = -EROFS;
			goto out;
		}
	}

	i = ocfs2_search_extent_list(el, v_cluster);
	if (i == -1) {
		/*
		 * A hole was found. Return some canned values that
		 * callers can key on. If asked for, num_clusters will
		 * be populated with the size of the hole.
		 */
		*p_cluster = 0;
		if (num_clusters) {
			ret = ocfs2_figure_hole_clusters(inode, el, eb_bh,
							 v_cluster,
							 num_clusters);
			if (ret) {
				mlog_errno(ret);
				goto out;
			}
		}
	} else {
		rec = &el->l_recs[i];

		BUG_ON(v_cluster < le32_to_cpu(rec->e_cpos));

		if (!rec->e_blkno) {
			ocfs2_error(inode->i_sb, "Inode %lu has bad extent "
				    "record (%u, %u, 0)", inode->i_ino,
				    le32_to_cpu(rec->e_cpos),
				    ocfs2_rec_clusters(el, rec));
			ret = -EROFS;
			goto out;
		}

		coff = v_cluster - le32_to_cpu(rec->e_cpos);

		*p_cluster = ocfs2_blocks_to_clusters(inode->i_sb,
						    le64_to_cpu(rec->e_blkno));
		*p_cluster = *p_cluster + coff;

		if (num_clusters)
			*num_clusters = ocfs2_rec_clusters(el, rec) - coff;

		flags = rec->e_flags;
	}

	if (extent_flags)
		*extent_flags = flags;

out:
	brelse(di_bh);
	brelse(eb_bh);
	return ret;
}

/*
 * This expects alloc_sem to be held. The allocation cannot change at
 * all while the map is in the process of being updated.
 */
int ocfs2_extent_map_get_blocks(struct inode *inode, u64 v_blkno, u64 *p_blkno,
				u64 *ret_count, unsigned int *extent_flags)
{
	int ret;
	int bpc = ocfs2_clusters_to_blocks(inode->i_sb, 1);
	u32 cpos, num_clusters, p_cluster;
	u64 boff = 0;

	cpos = ocfs2_blocks_to_clusters(inode->i_sb, v_blkno);

	ret = ocfs2_get_clusters(inode, cpos, &p_cluster, &num_clusters,
				 extent_flags);
	if (ret) {
		mlog_errno(ret);
		goto out;
	}

	/*
	 * p_cluster == 0 indicates a hole.
	 */
	if (p_cluster) {
		boff = ocfs2_clusters_to_blocks(inode->i_sb, p_cluster);
		boff += (v_blkno & (u64)(bpc - 1));
	}

	*p_blkno = boff;

	if (ret_count) {
		*ret_count = ocfs2_clusters_to_blocks(inode->i_sb, num_clusters);
		*ret_count -= v_blkno & (u64)(bpc - 1);
	}

out:
	return ret;
}
