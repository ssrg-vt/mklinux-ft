/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * stackglue.c
 *
 * Code which implements an OCFS2 specific interface to underlying
 * cluster stacks.
 *
 * Copyright (C) 2007 Oracle.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include "cluster/masklog.h"
#include "stackglue.h"

static struct ocfs2_locking_protocol *lproto;

/* These should be identical */
#if (DLM_LOCK_IV != LKM_IVMODE)
# error Lock modes do not match
#endif
#if (DLM_LOCK_NL != LKM_NLMODE)
# error Lock modes do not match
#endif
#if (DLM_LOCK_CR != LKM_CRMODE)
# error Lock modes do not match
#endif
#if (DLM_LOCK_CW != LKM_CWMODE)
# error Lock modes do not match
#endif
#if (DLM_LOCK_PR != LKM_PRMODE)
# error Lock modes do not match
#endif
#if (DLM_LOCK_PW != LKM_PWMODE)
# error Lock modes do not match
#endif
#if (DLM_LOCK_EX != LKM_EXMODE)
# error Lock modes do not match
#endif
static inline int mode_to_o2dlm(int mode)
{
	BUG_ON(mode > LKM_MAXMODE);

	return mode;
}

#define map_flag(_generic, _o2dlm)		\
	if (flags & (_generic)) {		\
		flags &= ~(_generic);		\
		o2dlm_flags |= (_o2dlm);	\
	}
static int flags_to_o2dlm(u32 flags)
{
	int o2dlm_flags = 0;

	map_flag(DLM_LKF_NOQUEUE, LKM_NOQUEUE);
	map_flag(DLM_LKF_CANCEL, LKM_CANCEL);
	map_flag(DLM_LKF_CONVERT, LKM_CONVERT);
	map_flag(DLM_LKF_VALBLK, LKM_VALBLK);
	map_flag(DLM_LKF_IVVALBLK, LKM_INVVALBLK);
	map_flag(DLM_LKF_ORPHAN, LKM_ORPHAN);
	map_flag(DLM_LKF_FORCEUNLOCK, LKM_FORCE);
	map_flag(DLM_LKF_TIMEOUT, LKM_TIMEOUT);
	map_flag(DLM_LKF_LOCAL, LKM_LOCAL);

	/* map_flag() should have cleared every flag passed in */
	BUG_ON(flags != 0);

	return o2dlm_flags;
}
#undef map_flag

/*
 * Map an o2dlm status to standard errno values.
 *
 * o2dlm only uses a handful of these, and returns even fewer to the
 * caller. Still, we try to assign sane values to each error.
 *
 * The following value pairs have special meanings to dlmglue, thus
 * the right hand side needs to stay unique - never duplicate the
 * mapping elsewhere in the table!
 *
 * DLM_NORMAL:		0
 * DLM_NOTQUEUED:	-EAGAIN
 * DLM_CANCELGRANT:	-DLM_ECANCEL
 * DLM_CANCEL:		-DLM_EUNLOCK
 */
/* Keep in sync with dlmapi.h */
static int status_map[] = {
	[DLM_NORMAL]			= 0,		/* Success */
	[DLM_GRANTED]			= -EINVAL,
	[DLM_DENIED]			= -EACCES,
	[DLM_DENIED_NOLOCKS]		= -EACCES,
	[DLM_WORKING]			= -EBUSY,
	[DLM_BLOCKED]			= -EINVAL,
	[DLM_BLOCKED_ORPHAN]		= -EINVAL,
	[DLM_DENIED_GRACE_PERIOD]	= -EACCES,
	[DLM_SYSERR]			= -ENOMEM,	/* It is what it is */
	[DLM_NOSUPPORT]			= -EPROTO,
	[DLM_CANCELGRANT]		= -DLM_ECANCEL, /* Cancel after grant */
	[DLM_IVLOCKID]			= -EINVAL,
	[DLM_SYNC]			= -EINVAL,
	[DLM_BADTYPE]			= -EINVAL,
	[DLM_BADRESOURCE]		= -EINVAL,
	[DLM_MAXHANDLES]		= -ENOMEM,
	[DLM_NOCLINFO]			= -EINVAL,
	[DLM_NOLOCKMGR]			= -EINVAL,
	[DLM_NOPURGED]			= -EINVAL,
	[DLM_BADARGS]			= -EINVAL,
	[DLM_VOID]			= -EINVAL,
	[DLM_NOTQUEUED]			= -EAGAIN,	/* Trylock failed */
	[DLM_IVBUFLEN]			= -EINVAL,
	[DLM_CVTUNGRANT]		= -EPERM,
	[DLM_BADPARAM]			= -EINVAL,
	[DLM_VALNOTVALID]		= -EINVAL,
	[DLM_REJECTED]			= -EPERM,
	[DLM_ABORT]			= -EINVAL,
	[DLM_CANCEL]			= -DLM_EUNLOCK,	/* Successful cancel */
	[DLM_IVRESHANDLE]		= -EINVAL,
	[DLM_DEADLOCK]			= -EDEADLK,
	[DLM_DENIED_NOASTS]		= -EINVAL,
	[DLM_FORWARD]			= -EINVAL,
	[DLM_TIMEOUT]			= -ETIMEDOUT,
	[DLM_IVGROUPID]			= -EINVAL,
	[DLM_VERS_CONFLICT]		= -EOPNOTSUPP,
	[DLM_BAD_DEVICE_PATH]		= -ENOENT,
	[DLM_NO_DEVICE_PERMISSION]	= -EPERM,
	[DLM_NO_CONTROL_DEVICE]		= -ENOENT,
	[DLM_RECOVERING]		= -ENOTCONN,
	[DLM_MIGRATING]			= -ERESTART,
	[DLM_MAXSTATS]			= -EINVAL,
};
static int dlm_status_to_errno(enum dlm_status status)
{
	BUG_ON(status > (sizeof(status_map) / sizeof(status_map[0])));

	return status_map[status];
}

static void o2dlm_lock_ast_wrapper(void *astarg)
{
	BUG_ON(lproto == NULL);

	lproto->lp_lock_ast(astarg);
}

static void o2dlm_blocking_ast_wrapper(void *astarg, int level)
{
	BUG_ON(lproto == NULL);

	lproto->lp_blocking_ast(astarg, level);
}

static void o2dlm_unlock_ast_wrapper(void *astarg, enum dlm_status status)
{
	int error;

	BUG_ON(lproto == NULL);

	/*
	 * XXX: CANCEL values are sketchy.
	 *
	 * Currently we have preserved the o2dlm paradigm.  You can get
	 * unlock_ast() whether the cancel succeded or not.
	 *
	 * First, we're going to pass DLM_EUNLOCK just like fs/dlm does for
	 * successful unlocks.  That is a clean behavior.
	 *
	 * In o2dlm, you can get both the lock_ast() for the lock being
	 * granted and the unlock_ast() for the CANCEL failing.  A
	 * successful cancel sends DLM_NORMAL here.  If the
	 * lock grant happened before the cancel arrived, you get
	 * DLM_CANCELGRANT.  For now, we'll use DLM_ECANCEL to signify
	 * CANCELGRANT - the CANCEL was supposed to happen but didn't.  We
	 * can then use DLM_EUNLOCK to signify a successful CANCEL -
	 * effectively, the CANCEL caused the lock to roll back.
	 *
	 * In the future, we will likely move the o2dlm to send only one
	 * ast - either unlock_ast() for a successful CANCEL or lock_ast()
	 * when the grant succeeds.  At that point, we'll send DLM_ECANCEL
	 * for all cancel results (CANCELGRANT will no longer exist).
	 */
	error = dlm_status_to_errno(status);

	/* Successful unlock is DLM_EUNLOCK */
	if (!error)
		error = -DLM_EUNLOCK;

	lproto->lp_unlock_ast(astarg, error);
}

int ocfs2_dlm_lock(struct dlm_ctxt *dlm,
		   int mode,
		   struct dlm_lockstatus *lksb,
		   u32 flags,
		   void *name,
		   unsigned int namelen,
		   void *astarg)
{
	enum dlm_status status;
	int o2dlm_mode = mode_to_o2dlm(mode);
	int o2dlm_flags = flags_to_o2dlm(flags);
	int ret;

	BUG_ON(lproto == NULL);

	status = dlmlock(dlm, o2dlm_mode, lksb, o2dlm_flags, name, namelen,
		       o2dlm_lock_ast_wrapper, astarg,
		       o2dlm_blocking_ast_wrapper);
	ret = dlm_status_to_errno(status);
	return ret;
}

int ocfs2_dlm_unlock(struct dlm_ctxt *dlm,
		     struct dlm_lockstatus *lksb,
		     u32 flags,
		     void *astarg)
{
	enum dlm_status status;
	int o2dlm_flags = flags_to_o2dlm(flags);
	int ret;

	BUG_ON(lproto == NULL);

	status = dlmunlock(dlm, lksb, o2dlm_flags,
			 o2dlm_unlock_ast_wrapper, astarg);
	ret = dlm_status_to_errno(status);
	return ret;
}


void o2cb_get_stack(struct ocfs2_locking_protocol *proto)
{
	BUG_ON(proto == NULL);

	lproto = proto;
}

void o2cb_put_stack(void)
{
	lproto = NULL;
}
