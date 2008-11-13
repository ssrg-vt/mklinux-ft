/* Credentials management
 *
 * Copyright (C) 2008 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _LINUX_CRED_H
#define _LINUX_CRED_H

#include <linux/capability.h>
#include <linux/key.h>
#include <asm/atomic.h>

struct user_struct;
struct cred;

/*
 * COW Supplementary groups list
 */
#define NGROUPS_SMALL		32
#define NGROUPS_PER_BLOCK	((unsigned int)(PAGE_SIZE / sizeof(gid_t)))

struct group_info {
	atomic_t	usage;
	int		ngroups;
	int		nblocks;
	gid_t		small_block[NGROUPS_SMALL];
	gid_t		*blocks[0];
};

/**
 * get_group_info - Get a reference to a group info structure
 * @group_info: The group info to reference
 *
 * This must be called with the owning task locked (via task_lock()) when task
 * != current.  The reason being that the vast majority of callers are looking
 * at current->group_info, which can not be changed except by the current task.
 * Changing current->group_info requires the task lock, too.
 */
#define get_group_info(group_info)		\
do {						\
	atomic_inc(&(group_info)->usage);	\
} while (0)

/**
 * put_group_info - Release a reference to a group info structure
 * @group_info: The group info to release
 */
#define put_group_info(group_info)			\
do {							\
	if (atomic_dec_and_test(&(group_info)->usage))	\
		groups_free(group_info);		\
} while (0)

extern struct group_info *groups_alloc(int);
extern void groups_free(struct group_info *);
extern int set_current_groups(struct group_info *);
extern int set_groups(struct cred *, struct group_info *);
extern int groups_search(struct group_info *, gid_t);

/* access the groups "array" with this macro */
#define GROUP_AT(gi, i) \
	((gi)->blocks[(i) / NGROUPS_PER_BLOCK][(i) % NGROUPS_PER_BLOCK])

extern int in_group_p(gid_t);
extern int in_egroup_p(gid_t);

/*
 * The security context of a task
 *
 * The parts of the context break down into two categories:
 *
 *  (1) The objective context of a task.  These parts are used when some other
 *	task is attempting to affect this one.
 *
 *  (2) The subjective context.  These details are used when the task is acting
 *	upon another object, be that a file, a task, a key or whatever.
 *
 * Note that some members of this structure belong to both categories - the
 * LSM security pointer for instance.
 *
 * A task has two security pointers.  task->real_cred points to the objective
 * context that defines that task's actual details.  The objective part of this
 * context is used whenever that task is acted upon.
 *
 * task->cred points to the subjective context that defines the details of how
 * that task is going to act upon another object.  This may be overridden
 * temporarily to point to another security context, but normally points to the
 * same context as task->real_cred.
 */
struct cred {
	atomic_t	usage;
	uid_t		uid;		/* real UID of the task */
	gid_t		gid;		/* real GID of the task */
	uid_t		suid;		/* saved UID of the task */
	gid_t		sgid;		/* saved GID of the task */
	uid_t		euid;		/* effective UID of the task */
	gid_t		egid;		/* effective GID of the task */
	uid_t		fsuid;		/* UID for VFS ops */
	gid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
#ifdef CONFIG_KEYS
	unsigned char	jit_keyring;	/* default keyring to attach requested
					 * keys to */
	struct key	*thread_keyring; /* keyring private to this thread */
	struct key	*request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
	void		*security;	/* subjective LSM security */
#endif
	struct user_struct *user;	/* real user ID subscription */
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	struct rcu_head	rcu;		/* RCU deletion hook */
	spinlock_t	lock;		/* lock for pointer changes */
};

#define get_current_user()	(get_uid(current->cred->user))

#define task_uid(task)		((task)->cred->uid)
#define task_gid(task)		((task)->cred->gid)
#define task_euid(task)		((task)->cred->euid)
#define task_egid(task)		((task)->cred->egid)

#define current_uid()		(current->cred->uid)
#define current_gid()		(current->cred->gid)
#define current_euid()		(current->cred->euid)
#define current_egid()		(current->cred->egid)
#define current_suid()		(current->cred->suid)
#define current_sgid()		(current->cred->sgid)
#define current_fsuid()		(current->cred->fsuid)
#define current_fsgid()		(current->cred->fsgid)
#define current_cap()		(current->cred->cap_effective)

#define current_uid_gid(_uid, _gid)		\
do {						\
	*(_uid) = current->cred->uid;		\
	*(_gid) = current->cred->gid;		\
} while(0)

#define current_euid_egid(_uid, _gid)		\
do {						\
	*(_uid) = current->cred->euid;		\
	*(_gid) = current->cred->egid;		\
} while(0)

#define current_fsuid_fsgid(_uid, _gid)		\
do {						\
	*(_uid) = current->cred->fsuid;		\
	*(_gid) = current->cred->fsgid;		\
} while(0)

#endif /* _LINUX_CRED_H */
