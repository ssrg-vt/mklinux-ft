/*
 * Copyright (C) 2007 Oracle.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
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

#ifndef __BTRFS_I__
#define __BTRFS_I__

#include "extent_map.h"
#include "extent_io.h"
#include "ordered-data.h"

/* in memory btrfs inode */
struct btrfs_inode {
	struct btrfs_root *root;
	struct btrfs_block_group_cache *block_group;
	struct btrfs_key location;
	struct extent_map_tree extent_tree;
	struct extent_io_tree io_tree;
	struct extent_io_tree io_failure_tree;
	struct mutex csum_mutex;
	struct mutex extent_mutex;
	struct mutex log_mutex;
	struct inode vfs_inode;
	struct btrfs_ordered_inode_tree ordered_tree;

	struct posix_acl *i_acl;
	struct posix_acl *i_default_acl;

	/* for keeping track of orphaned inodes */
	struct list_head i_orphan;

	struct list_head delalloc_inodes;

	/* full 64 bit generation number */
	u64 generation;

	/*
	 * transid of the trans_handle that last modified this inode
	 */
	u64 last_trans;
	/*
	 * transid that last logged this inode
	 */
	u64 logged_trans;

	/* trans that last made a change that should be fully fsync'd */
	u64 log_dirty_trans;
	u64 delalloc_bytes;
	u64 disk_i_size;
	u32 flags;

	/*
	 * if this is a directory then index_cnt is the counter for the index
	 * number for new files that are created
	 */
	u64 index_cnt;
};

static inline struct btrfs_inode *BTRFS_I(struct inode *inode)
{
	return container_of(inode, struct btrfs_inode, vfs_inode);
}

static inline void btrfs_i_size_write(struct inode *inode, u64 size)
{
	inode->i_size = size;
	BTRFS_I(inode)->disk_i_size = size;
}


#endif
