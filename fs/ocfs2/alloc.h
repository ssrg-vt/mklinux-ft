/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * alloc.h
 *
 * Function prototypes
 *
 * Copyright (C) 2002, 2004 Oracle.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
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

#ifndef OCFS2_ALLOC_H
#define OCFS2_ALLOC_H

enum ocfs2_extent_tree_type {
	OCFS2_DINODE_EXTENT = 0,
};

struct ocfs2_alloc_context;
int ocfs2_insert_extent(struct ocfs2_super *osb,
			handle_t *handle,
			struct inode *inode,
			struct buffer_head *root_bh,
			u32 cpos,
			u64 start_blk,
			u32 new_clusters,
			u8 flags,
			struct ocfs2_alloc_context *meta_ac,
			enum ocfs2_extent_tree_type et_type);
enum ocfs2_alloc_restarted {
	RESTART_NONE = 0,
	RESTART_TRANS,
	RESTART_META
};
int ocfs2_add_clusters_in_btree(struct ocfs2_super *osb,
				struct inode *inode,
				u32 *logical_offset,
				u32 clusters_to_add,
				int mark_unwritten,
				struct buffer_head *root_bh,
				struct ocfs2_extent_list *root_el,
				handle_t *handle,
				struct ocfs2_alloc_context *data_ac,
				struct ocfs2_alloc_context *meta_ac,
				enum ocfs2_alloc_restarted *reason_ret,
				enum ocfs2_extent_tree_type type);
struct ocfs2_cached_dealloc_ctxt;
int ocfs2_mark_extent_written(struct inode *inode, struct buffer_head *root_bh,
			      handle_t *handle, u32 cpos, u32 len, u32 phys,
			      struct ocfs2_alloc_context *meta_ac,
			      struct ocfs2_cached_dealloc_ctxt *dealloc,
			      enum ocfs2_extent_tree_type et_type);
int ocfs2_remove_extent(struct inode *inode, struct buffer_head *root_bh,
			u32 cpos, u32 len, handle_t *handle,
			struct ocfs2_alloc_context *meta_ac,
			struct ocfs2_cached_dealloc_ctxt *dealloc,
			enum ocfs2_extent_tree_type et_type);
int ocfs2_num_free_extents(struct ocfs2_super *osb,
			   struct inode *inode,
			   struct buffer_head *root_bh,
			   enum ocfs2_extent_tree_type et_type);

/*
 * how many new metadata chunks would an allocation need at maximum?
 *
 * Please note that the caller must make sure that root_el is the root
 * of extent tree. So for an inode, it should be &fe->id2.i_list. Otherwise
 * the result may be wrong.
 */
static inline int ocfs2_extend_meta_needed(struct ocfs2_extent_list *root_el)
{
	/*
	 * Rather than do all the work of determining how much we need
	 * (involves a ton of reads and locks), just ask for the
	 * maximal limit.  That's a tree depth shift.  So, one block for
	 * level of the tree (current l_tree_depth), one block for the
	 * new tree_depth==0 extent_block, and one block at the new
	 * top-of-the tree.
	 */
	return le16_to_cpu(root_el->l_tree_depth) + 2;
}

void ocfs2_dinode_new_extent_list(struct inode *inode, struct ocfs2_dinode *di);
void ocfs2_set_inode_data_inline(struct inode *inode, struct ocfs2_dinode *di);
int ocfs2_convert_inline_data_to_extents(struct inode *inode,
					 struct buffer_head *di_bh);

int ocfs2_truncate_log_init(struct ocfs2_super *osb);
void ocfs2_truncate_log_shutdown(struct ocfs2_super *osb);
void ocfs2_schedule_truncate_log_flush(struct ocfs2_super *osb,
				       int cancel);
int ocfs2_flush_truncate_log(struct ocfs2_super *osb);
int ocfs2_begin_truncate_log_recovery(struct ocfs2_super *osb,
				      int slot_num,
				      struct ocfs2_dinode **tl_copy);
int ocfs2_complete_truncate_log_recovery(struct ocfs2_super *osb,
					 struct ocfs2_dinode *tl_copy);
int ocfs2_truncate_log_needs_flush(struct ocfs2_super *osb);
int ocfs2_truncate_log_append(struct ocfs2_super *osb,
			      handle_t *handle,
			      u64 start_blk,
			      unsigned int num_clusters);
int __ocfs2_flush_truncate_log(struct ocfs2_super *osb);

/*
 * Process local structure which describes the block unlinks done
 * during an operation. This is populated via
 * ocfs2_cache_block_dealloc().
 *
 * ocfs2_run_deallocs() should be called after the potentially
 * de-allocating routines. No journal handles should be open, and most
 * locks should have been dropped.
 */
struct ocfs2_cached_dealloc_ctxt {
	struct ocfs2_per_slot_free_list		*c_first_suballocator;
};
static inline void ocfs2_init_dealloc_ctxt(struct ocfs2_cached_dealloc_ctxt *c)
{
	c->c_first_suballocator = NULL;
}
int ocfs2_run_deallocs(struct ocfs2_super *osb,
		       struct ocfs2_cached_dealloc_ctxt *ctxt);

struct ocfs2_truncate_context {
	struct ocfs2_cached_dealloc_ctxt tc_dealloc;
	int tc_ext_alloc_locked; /* is it cluster locked? */
	/* these get destroyed once it's passed to ocfs2_commit_truncate. */
	struct buffer_head *tc_last_eb_bh;
};

int ocfs2_zero_range_for_truncate(struct inode *inode, handle_t *handle,
				  u64 range_start, u64 range_end);
int ocfs2_prepare_truncate(struct ocfs2_super *osb,
			   struct inode *inode,
			   struct buffer_head *fe_bh,
			   struct ocfs2_truncate_context **tc);
int ocfs2_commit_truncate(struct ocfs2_super *osb,
			  struct inode *inode,
			  struct buffer_head *fe_bh,
			  struct ocfs2_truncate_context *tc);
int ocfs2_truncate_inline(struct inode *inode, struct buffer_head *di_bh,
			  unsigned int start, unsigned int end, int trunc);

int ocfs2_find_leaf(struct inode *inode, struct ocfs2_extent_list *root_el,
		    u32 cpos, struct buffer_head **leaf_bh);
int ocfs2_search_extent_list(struct ocfs2_extent_list *el, u32 v_cluster);

/*
 * Helper function to look at the # of clusters in an extent record.
 */
static inline unsigned int ocfs2_rec_clusters(struct ocfs2_extent_list *el,
					      struct ocfs2_extent_rec *rec)
{
	/*
	 * Cluster count in extent records is slightly different
	 * between interior nodes and leaf nodes. This is to support
	 * unwritten extents which need a flags field in leaf node
	 * records, thus shrinking the available space for a clusters
	 * field.
	 */
	if (el->l_tree_depth)
		return le32_to_cpu(rec->e_int_clusters);
	else
		return le16_to_cpu(rec->e_leaf_clusters);
}

/*
 * This is only valid for leaf nodes, which are the only ones that can
 * have empty extents anyway.
 */
static inline int ocfs2_is_empty_extent(struct ocfs2_extent_rec *rec)
{
	return !rec->e_leaf_clusters;
}

#endif /* OCFS2_ALLOC_H */
