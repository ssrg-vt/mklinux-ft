/*
 *  linux/fs/pnode.c
 *
 * (C) Copyright IBM Corporation 2005.
 *	Released under GPL v2.
 *	Author : Ram Pai (linuxram@us.ibm.com)
 *
 */
#include <linux/namespace.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include "pnode.h"

/* return the next shared peer mount of @p */
static inline struct vfsmount *next_peer(struct vfsmount *p)
{
	return list_entry(p->mnt_share.next, struct vfsmount, mnt_share);
}

void change_mnt_propagation(struct vfsmount *mnt, int type)
{
	if (type == MS_SHARED) {
		set_mnt_shared(mnt);
	} else {
		list_del_init(&mnt->mnt_share);
		mnt->mnt_flags &= ~MNT_PNODE_MASK;
	}
}

/*
 * get the next mount in the propagation tree.
 * @m: the mount seen last
 * @origin: the original mount from where the tree walk initiated
 */
static struct vfsmount *propagation_next(struct vfsmount *m,
					 struct vfsmount *origin)
{
	m = next_peer(m);
	if (m == origin)
		return NULL;
	return m;
}

/*
 * mount 'source_mnt' under the destination 'dest_mnt' at
 * dentry 'dest_dentry'. And propagate that mount to
 * all the peer and slave mounts of 'dest_mnt'.
 * Link all the new mounts into a propagation tree headed at
 * source_mnt. Also link all the new mounts using ->mnt_list
 * headed at source_mnt's ->mnt_list
 *
 * @dest_mnt: destination mount.
 * @dest_dentry: destination dentry.
 * @source_mnt: source mount.
 * @tree_list : list of heads of trees to be attached.
 */
int propagate_mnt(struct vfsmount *dest_mnt, struct dentry *dest_dentry,
		    struct vfsmount *source_mnt, struct list_head *tree_list)
{
	struct vfsmount *m, *child;
	int ret = 0;
	struct vfsmount *prev_dest_mnt = dest_mnt;
	struct vfsmount *prev_src_mnt  = source_mnt;
	LIST_HEAD(tmp_list);
	LIST_HEAD(umount_list);

	for (m = propagation_next(dest_mnt, dest_mnt); m;
			m = propagation_next(m, dest_mnt)) {
		int type = CL_PROPAGATION;

		if (IS_MNT_NEW(m))
			continue;

		if (IS_MNT_SHARED(m))
			type |= CL_MAKE_SHARED;

		if (!(child = copy_tree(source_mnt, source_mnt->mnt_root,
						type))) {
			ret = -ENOMEM;
			list_splice(tree_list, tmp_list.prev);
			goto out;
		}

		if (is_subdir(dest_dentry, m->mnt_root)) {
			mnt_set_mountpoint(m, dest_dentry, child);
			list_add_tail(&child->mnt_hash, tree_list);
		} else {
			/*
			 * This can happen if the parent mount was bind mounted
			 * on some subdirectory of a shared/slave mount.
			 */
			list_add_tail(&child->mnt_hash, &tmp_list);
		}
		prev_dest_mnt = m;
		prev_src_mnt  = child;
	}
out:
	spin_lock(&vfsmount_lock);
	while (!list_empty(&tmp_list)) {
		child = list_entry(tmp_list.next, struct vfsmount, mnt_hash);
		list_del_init(&child->mnt_hash);
		umount_tree(child, 0, &umount_list);
	}
	spin_unlock(&vfsmount_lock);
	release_mounts(&umount_list);
	return ret;
}

/*
 * return true if the refcount is greater than count
 */
static inline int do_refcount_check(struct vfsmount *mnt, int count)
{
	int mycount = atomic_read(&mnt->mnt_count);
	return (mycount > count);
}

/*
 * check if the mount 'mnt' can be unmounted successfully.
 * @mnt: the mount to be checked for unmount
 * NOTE: unmounting 'mnt' would naturally propagate to all
 * other mounts its parent propagates to.
 * Check if any of these mounts that **do not have submounts**
 * have more references than 'refcnt'. If so return busy.
 */
int propagate_mount_busy(struct vfsmount *mnt, int refcnt)
{
	struct vfsmount *m, *child;
	struct vfsmount *parent = mnt->mnt_parent;
	int ret = 0;

	if (mnt == parent)
		return do_refcount_check(mnt, refcnt);

	/*
	 * quickly check if the current mount can be unmounted.
	 * If not, we don't have to go checking for all other
	 * mounts
	 */
	if (!list_empty(&mnt->mnt_mounts) || do_refcount_check(mnt, refcnt))
		return 1;

	for (m = propagation_next(parent, parent); m;
	     		m = propagation_next(m, parent)) {
		child = __lookup_mnt(m, mnt->mnt_mountpoint, 0);
		if (child && list_empty(&child->mnt_mounts) &&
		    (ret = do_refcount_check(child, 1)))
			break;
	}
	return ret;
}

/*
 * NOTE: unmounting 'mnt' naturally propagates to all other mounts its
 * parent propagates to.
 */
static void __propagate_umount(struct vfsmount *mnt)
{
	struct vfsmount *parent = mnt->mnt_parent;
	struct vfsmount *m;

	BUG_ON(parent == mnt);

	for (m = propagation_next(parent, parent); m;
			m = propagation_next(m, parent)) {

		struct vfsmount *child = __lookup_mnt(m,
					mnt->mnt_mountpoint, 0);
		/*
		 * umount the child only if the child has no
		 * other children
		 */
		if (child && list_empty(&child->mnt_mounts)) {
			list_del(&child->mnt_hash);
			list_add_tail(&child->mnt_hash, &mnt->mnt_hash);
		}
	}
}

/*
 * collect all mounts that receive propagation from the mount in @list,
 * and return these additional mounts in the same list.
 * @list: the list of mounts to be unmounted.
 */
int propagate_umount(struct list_head *list)
{
	struct vfsmount *mnt;

	list_for_each_entry(mnt, list, mnt_hash)
		__propagate_umount(mnt);
	return 0;
}
