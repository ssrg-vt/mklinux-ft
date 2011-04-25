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

#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>

#include "ctree.h"
#include "disk-io.h"
#include "free-space-cache.h"
#include "inode-map.h"
#include "transaction.h"

static int caching_kthread(void *data)
{
	struct btrfs_root *root = data;
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_free_space_ctl *ctl = root->free_ino_ctl;
	struct btrfs_key key;
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	u64 last = (u64)-1;
	int slot;
	int ret;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	/* Since the commit root is read-only, we can safely skip locking. */
	path->skip_locking = 1;
	path->search_commit_root = 1;
	path->reada = 2;

	key.objectid = BTRFS_FIRST_FREE_OBJECTID;
	key.offset = 0;
	key.type = BTRFS_INODE_ITEM_KEY;
again:
	/* need to make sure the commit_root doesn't disappear */
	mutex_lock(&root->fs_commit_mutex);

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0)
		goto out;

	while (1) {
		smp_mb();
		if (fs_info->closing > 1)
			goto out;

		leaf = path->nodes[0];
		slot = path->slots[0];
		if (path->slots[0] >= btrfs_header_nritems(leaf)) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0)
				goto out;
			else if (ret > 0)
				break;

			if (need_resched() ||
			    btrfs_transaction_in_commit(fs_info)) {
				leaf = path->nodes[0];

				if (btrfs_header_nritems(leaf) == 0) {
					WARN_ON(1);
					break;
				}

				/*
				 * Save the key so we can advances forward
				 * in the next search.
				 */
				btrfs_item_key_to_cpu(leaf, &key, 0);
				btrfs_release_path(root, path);
				root->cache_progress = last;
				mutex_unlock(&root->fs_commit_mutex);
				schedule_timeout(1);
				goto again;
			} else
				continue;
		}

		btrfs_item_key_to_cpu(leaf, &key, slot);

		if (key.type != BTRFS_INODE_ITEM_KEY)
			goto next;

		if (key.objectid >= BTRFS_LAST_FREE_OBJECTID)
			break;

		if (last != (u64)-1 && last + 1 != key.objectid) {
			__btrfs_add_free_space(ctl, last + 1,
					       key.objectid - last - 1);
			wake_up(&root->cache_wait);
		}

		last = key.objectid;
next:
		path->slots[0]++;
	}

	if (last < BTRFS_LAST_FREE_OBJECTID - 1) {
		__btrfs_add_free_space(ctl, last + 1,
				       BTRFS_LAST_FREE_OBJECTID - last - 1);
	}

	spin_lock(&root->cache_lock);
	root->cached = BTRFS_CACHE_FINISHED;
	spin_unlock(&root->cache_lock);

	root->cache_progress = (u64)-1;
	btrfs_unpin_free_ino(root);
out:
	wake_up(&root->cache_wait);
	mutex_unlock(&root->fs_commit_mutex);

	btrfs_free_path(path);

	return ret;
}

static void start_caching(struct btrfs_root *root)
{
	struct task_struct *tsk;

	spin_lock(&root->cache_lock);
	if (root->cached != BTRFS_CACHE_NO) {
		spin_unlock(&root->cache_lock);
		return;
	}

	root->cached = BTRFS_CACHE_STARTED;
	spin_unlock(&root->cache_lock);

	tsk = kthread_run(caching_kthread, root, "btrfs-ino-cache-%llu\n",
			  root->root_key.objectid);
	BUG_ON(IS_ERR(tsk));
}

int btrfs_find_free_ino(struct btrfs_root *root, u64 *objectid)
{
again:
	*objectid = btrfs_find_ino_for_alloc(root);

	if (*objectid != 0)
		return 0;

	start_caching(root);

	wait_event(root->cache_wait,
		   root->cached == BTRFS_CACHE_FINISHED ||
		   root->free_ino_ctl->free_space > 0);

	if (root->cached == BTRFS_CACHE_FINISHED &&
	    root->free_ino_ctl->free_space == 0)
		return -ENOSPC;
	else
		goto again;
}

void btrfs_return_ino(struct btrfs_root *root, u64 objectid)
{
	struct btrfs_free_space_ctl *ctl = root->free_ino_ctl;
	struct btrfs_free_space_ctl *pinned = root->free_ino_pinned;
again:
	if (root->cached == BTRFS_CACHE_FINISHED) {
		__btrfs_add_free_space(ctl, objectid, 1);
	} else {
		/*
		 * If we are in the process of caching free ino chunks,
		 * to avoid adding the same inode number to the free_ino
		 * tree twice due to cross transaction, we'll leave it
		 * in the pinned tree until a transaction is committed
		 * or the caching work is done.
		 */

		mutex_lock(&root->fs_commit_mutex);
		spin_lock(&root->cache_lock);
		if (root->cached == BTRFS_CACHE_FINISHED) {
			spin_unlock(&root->cache_lock);
			mutex_unlock(&root->fs_commit_mutex);
			goto again;
		}
		spin_unlock(&root->cache_lock);

		start_caching(root);

		if (objectid <= root->cache_progress)
			__btrfs_add_free_space(ctl, objectid, 1);
		else
			__btrfs_add_free_space(pinned, objectid, 1);

		mutex_unlock(&root->fs_commit_mutex);
	}
}

/*
 * When a transaction is committed, we'll move those inode numbers which
 * are smaller than root->cache_progress from pinned tree to free_ino tree,
 * and others will just be dropped, because the commit root we were
 * searching has changed.
 *
 * Must be called with root->fs_commit_mutex held
 */
void btrfs_unpin_free_ino(struct btrfs_root *root)
{
	struct btrfs_free_space_ctl *ctl = root->free_ino_ctl;
	struct rb_root *rbroot = &root->free_ino_pinned->free_space_offset;
	struct btrfs_free_space *info;
	struct rb_node *n;
	u64 count;

	while (1) {
		n = rb_first(rbroot);
		if (!n)
			break;

		info = rb_entry(n, struct btrfs_free_space, offset_index);
		BUG_ON(info->bitmap);

		if (info->offset > root->cache_progress)
			goto free;
		else if (info->offset + info->bytes > root->cache_progress)
			count = root->cache_progress - info->offset + 1;
		else
			count = info->bytes;

		__btrfs_add_free_space(ctl, info->offset, count);
free:
		rb_erase(&info->offset_index, rbroot);
		kfree(info);
	}
}

#define INIT_THRESHOLD	(((1024 * 32) / 2) / sizeof(struct btrfs_free_space))
#define INODES_PER_BITMAP (PAGE_CACHE_SIZE * 8)

/*
 * The goal is to keep the memory used by the free_ino tree won't
 * exceed the memory if we use bitmaps only.
 */
static void recalculate_thresholds(struct btrfs_free_space_ctl *ctl)
{
	struct btrfs_free_space *info;
	struct rb_node *n;
	int max_ino;
	int max_bitmaps;

	n = rb_last(&ctl->free_space_offset);
	if (!n) {
		ctl->extents_thresh = INIT_THRESHOLD;
		return;
	}
	info = rb_entry(n, struct btrfs_free_space, offset_index);

	/*
	 * Find the maximum inode number in the filesystem. Note we
	 * ignore the fact that this can be a bitmap, because we are
	 * not doing precise calculation.
	 */
	max_ino = info->bytes - 1;

	max_bitmaps = ALIGN(max_ino, INODES_PER_BITMAP) / INODES_PER_BITMAP;
	if (max_bitmaps <= ctl->total_bitmaps) {
		ctl->extents_thresh = 0;
		return;
	}

	ctl->extents_thresh = (max_bitmaps - ctl->total_bitmaps) *
				PAGE_CACHE_SIZE / sizeof(*info);
}

/*
 * We don't fall back to bitmap, if we are below the extents threshold
 * or this chunk of inode numbers is a big one.
 */
static bool use_bitmap(struct btrfs_free_space_ctl *ctl,
		       struct btrfs_free_space *info)
{
	if (ctl->free_extents < ctl->extents_thresh ||
	    info->bytes > INODES_PER_BITMAP / 10)
		return false;

	return true;
}

static struct btrfs_free_space_op free_ino_op = {
	.recalc_thresholds	= recalculate_thresholds,
	.use_bitmap		= use_bitmap,
};

static void pinned_recalc_thresholds(struct btrfs_free_space_ctl *ctl)
{
}

static bool pinned_use_bitmap(struct btrfs_free_space_ctl *ctl,
			      struct btrfs_free_space *info)
{
	/*
	 * We always use extents for two reasons:
	 *
	 * - The pinned tree is only used during the process of caching
	 *   work.
	 * - Make code simpler. See btrfs_unpin_free_ino().
	 */
	return false;
}

static struct btrfs_free_space_op pinned_free_ino_op = {
	.recalc_thresholds	= pinned_recalc_thresholds,
	.use_bitmap		= pinned_use_bitmap,
};

void btrfs_init_free_ino_ctl(struct btrfs_root *root)
{
	struct btrfs_free_space_ctl *ctl = root->free_ino_ctl;
	struct btrfs_free_space_ctl *pinned = root->free_ino_pinned;

	spin_lock_init(&ctl->tree_lock);
	ctl->unit = 1;
	ctl->start = 0;
	ctl->private = NULL;
	ctl->op = &free_ino_op;

	/*
	 * Initially we allow to use 16K of ram to cache chunks of
	 * inode numbers before we resort to bitmaps. This is somewhat
	 * arbitrary, but it will be adjusted in runtime.
	 */
	ctl->extents_thresh = INIT_THRESHOLD;

	spin_lock_init(&pinned->tree_lock);
	pinned->unit = 1;
	pinned->start = 0;
	pinned->private = NULL;
	pinned->extents_thresh = 0;
	pinned->op = &pinned_free_ino_op;
}

static int btrfs_find_highest_objectid(struct btrfs_root *root, u64 *objectid)
{
	struct btrfs_path *path;
	int ret;
	struct extent_buffer *l;
	struct btrfs_key search_key;
	struct btrfs_key found_key;
	int slot;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	search_key.objectid = BTRFS_LAST_FREE_OBJECTID;
	search_key.type = -1;
	search_key.offset = (u64)-1;
	ret = btrfs_search_slot(NULL, root, &search_key, path, 0, 0);
	if (ret < 0)
		goto error;
	BUG_ON(ret == 0);
	if (path->slots[0] > 0) {
		slot = path->slots[0] - 1;
		l = path->nodes[0];
		btrfs_item_key_to_cpu(l, &found_key, slot);
		*objectid = max_t(u64, found_key.objectid,
				  BTRFS_FIRST_FREE_OBJECTID - 1);
	} else {
		*objectid = BTRFS_FIRST_FREE_OBJECTID - 1;
	}
	ret = 0;
error:
	btrfs_free_path(path);
	return ret;
}

int btrfs_find_free_objectid(struct btrfs_root *root, u64 *objectid)
{
	int ret;
	mutex_lock(&root->objectid_mutex);

	if (unlikely(root->highest_objectid < BTRFS_FIRST_FREE_OBJECTID)) {
		ret = btrfs_find_highest_objectid(root,
						  &root->highest_objectid);
		if (ret)
			goto out;
	}

	if (unlikely(root->highest_objectid >= BTRFS_LAST_FREE_OBJECTID)) {
		ret = -ENOSPC;
		goto out;
	}

	*objectid = ++root->highest_objectid;
	ret = 0;
out:
	mutex_unlock(&root->objectid_mutex);
	return ret;
}
