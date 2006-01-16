/******************************************************************************
*******************************************************************************
**
**  Copyright (C) Sistina Software, Inc.  1997-2003  All rights reserved.
**  Copyright (C) 2004-2005 Red Hat, Inc.  All rights reserved.
**
**  This copyrighted material is made available to anyone wishing to use,
**  modify, copy, or redistribute it subject to the terms and conditions
**  of the GNU General Public License v.2.
**
*******************************************************************************
******************************************************************************/

#include "lock_dlm.h"

static char junk_lvb[GDLM_LVB_SIZE];

static void queue_complete(struct gdlm_lock *lp)
{
	struct gdlm_ls *ls = lp->ls;

	clear_bit(LFL_ACTIVE, &lp->flags);

	spin_lock(&ls->async_lock);
	list_add_tail(&lp->clist, &ls->complete);
	spin_unlock(&ls->async_lock);
	wake_up(&ls->thread_wait);
}

static inline void gdlm_ast(void *astarg)
{
	queue_complete((struct gdlm_lock *) astarg);
}

static inline void gdlm_bast(void *astarg, int mode)
{
	struct gdlm_lock *lp = astarg;
	struct gdlm_ls *ls = lp->ls;

	if (!mode) {
		printk("lock_dlm: bast mode zero %x,%"PRIx64"\n",
			lp->lockname.ln_type, lp->lockname.ln_number);
		return;
	}

	spin_lock(&ls->async_lock);
	if (!lp->bast_mode) {
		list_add_tail(&lp->blist, &ls->blocking);
		lp->bast_mode = mode;
	} else if (lp->bast_mode < mode)
		lp->bast_mode = mode;
	spin_unlock(&ls->async_lock);
	wake_up(&ls->thread_wait);
}

void gdlm_queue_delayed(struct gdlm_lock *lp)
{
	struct gdlm_ls *ls = lp->ls;

	spin_lock(&ls->async_lock);
	list_add_tail(&lp->delay_list, &ls->delayed);
	spin_unlock(&ls->async_lock);
}

/* convert gfs lock-state to dlm lock-mode */

static int16_t make_mode(int16_t lmstate)
{
	switch (lmstate) {
	case LM_ST_UNLOCKED:
		return DLM_LOCK_NL;
	case LM_ST_EXCLUSIVE:
		return DLM_LOCK_EX;
	case LM_ST_DEFERRED:
		return DLM_LOCK_CW;
	case LM_ST_SHARED:
		return DLM_LOCK_PR;
	default:
		GDLM_ASSERT(0, printk("unknown LM state %d\n", lmstate););
	}
}

/* convert dlm lock-mode to gfs lock-state */

int16_t gdlm_make_lmstate(int16_t dlmmode)
{
	switch (dlmmode) {
	case DLM_LOCK_IV:
	case DLM_LOCK_NL:
		return LM_ST_UNLOCKED;
	case DLM_LOCK_EX:
		return LM_ST_EXCLUSIVE;
	case DLM_LOCK_CW:
		return LM_ST_DEFERRED;
	case DLM_LOCK_PR:
		return LM_ST_SHARED;
	default:
		GDLM_ASSERT(0, printk("unknown DLM mode %d\n", dlmmode););
	}
}

/* verify agreement with GFS on the current lock state, NB: DLM_LOCK_NL and
   DLM_LOCK_IV are both considered LM_ST_UNLOCKED by GFS. */

static void check_cur_state(struct gdlm_lock *lp, unsigned int cur_state)
{
	int16_t cur = make_mode(cur_state);
	if (lp->cur != DLM_LOCK_IV)
		GDLM_ASSERT(lp->cur == cur, printk("%d, %d\n", lp->cur, cur););
}

static inline unsigned int make_flags(struct gdlm_lock *lp,
				      unsigned int gfs_flags,
				      int16_t cur, int16_t req)
{
	unsigned int lkf = 0;

	if (gfs_flags & LM_FLAG_TRY)
		lkf |= DLM_LKF_NOQUEUE;

	if (gfs_flags & LM_FLAG_TRY_1CB) {
		lkf |= DLM_LKF_NOQUEUE;
		lkf |= DLM_LKF_NOQUEUEBAST;
	}

	if (gfs_flags & LM_FLAG_PRIORITY) {
		lkf |= DLM_LKF_NOORDER;
		lkf |= DLM_LKF_HEADQUE;
	}

	if (gfs_flags & LM_FLAG_ANY) {
		if (req == DLM_LOCK_PR)
			lkf |= DLM_LKF_ALTCW;
		else if (req == DLM_LOCK_CW)
			lkf |= DLM_LKF_ALTPR;
	}

	if (lp->lksb.sb_lkid != 0) {
		lkf |= DLM_LKF_CONVERT;

		/* Conversion deadlock avoidance by DLM */

		if (!test_bit(LFL_FORCE_PROMOTE, &lp->flags) &&
		    !(lkf & DLM_LKF_NOQUEUE) &&
		    cur > DLM_LOCK_NL && req > DLM_LOCK_NL && cur != req)
			lkf |= DLM_LKF_CONVDEADLK;
	}

	if (lp->lvb)
		lkf |= DLM_LKF_VALBLK;

	return lkf;
}

/* make_strname - convert GFS lock numbers to a string */

static inline void make_strname(struct lm_lockname *lockname,
				struct gdlm_strname *str)
{
	sprintf(str->name, "%8x%16"PRIx64, lockname->ln_type,
		lockname->ln_number);
	str->namelen = GDLM_STRNAME_BYTES;
}

int gdlm_create_lp(struct gdlm_ls *ls, struct lm_lockname *name,
		   struct gdlm_lock **lpp)
{
	struct gdlm_lock *lp;

	lp = kmalloc(sizeof(struct gdlm_lock), GFP_KERNEL);
	if (!lp)
		return -ENOMEM;

	memset(lp, 0, sizeof(struct gdlm_lock));
	lp->lockname = *name;
	lp->ls = ls;
	lp->cur = DLM_LOCK_IV;
	lp->lvb = NULL;
	lp->hold_null = NULL;
	init_completion(&lp->ast_wait);
	INIT_LIST_HEAD(&lp->clist);
	INIT_LIST_HEAD(&lp->blist);
	INIT_LIST_HEAD(&lp->delay_list);

	spin_lock(&ls->async_lock);
	list_add(&lp->all_list, &ls->all_locks);
	ls->all_locks_count++;
	spin_unlock(&ls->async_lock);

	*lpp = lp;
	return 0;
}

void gdlm_delete_lp(struct gdlm_lock *lp)
{
	struct gdlm_ls *ls = lp->ls;

	spin_lock(&ls->async_lock);
	if (!list_empty(&lp->clist))
		list_del_init(&lp->clist);
	if (!list_empty(&lp->blist))
		list_del_init(&lp->blist);
	if (!list_empty(&lp->delay_list))
		list_del_init(&lp->delay_list);
	GDLM_ASSERT(!list_empty(&lp->all_list),);
	list_del_init(&lp->all_list);
	ls->all_locks_count--;
	spin_unlock(&ls->async_lock);

	kfree(lp);
}

int gdlm_get_lock(lm_lockspace_t *lockspace, struct lm_lockname *name,
		  lm_lock_t **lockp)
{
	struct gdlm_lock *lp;
	int error;

	error = gdlm_create_lp((struct gdlm_ls *) lockspace, name, &lp);

	*lockp = (lm_lock_t *) lp;
	return error;
}

void gdlm_put_lock(lm_lock_t *lock)
{
	gdlm_delete_lp((struct gdlm_lock *) lock);
}

void gdlm_do_lock(struct gdlm_lock *lp, struct dlm_range *range)
{
	struct gdlm_ls *ls = lp->ls;
	struct gdlm_strname str;
	int error, bast = 1;

	/*
	 * When recovery is in progress, delay lock requests for submission
	 * once recovery is done.  Requests for recovery (NOEXP) and unlocks
	 * can pass.
	 */

	if (test_bit(DFL_BLOCK_LOCKS, &ls->flags) &&
	    !test_bit(LFL_NOBLOCK, &lp->flags) && lp->req != DLM_LOCK_NL) {
		gdlm_queue_delayed(lp);
		return;
	}

	/*
	 * Submit the actual lock request.
	 */

	if (test_bit(LFL_NOBAST, &lp->flags))
		bast = 0;

	make_strname(&lp->lockname, &str);

	set_bit(LFL_ACTIVE, &lp->flags);

	log_debug("lk %x,%"PRIx64" id %x %d,%d %x", lp->lockname.ln_type,
		  lp->lockname.ln_number, lp->lksb.sb_lkid,
		  lp->cur, lp->req, lp->lkf);

	error = dlm_lock(ls->dlm_lockspace, lp->req, &lp->lksb, lp->lkf,
			 str.name, str.namelen, 0, gdlm_ast, (void *) lp,
			 bast ? gdlm_bast : NULL, range);

	if ((error == -EAGAIN) && (lp->lkf & DLM_LKF_NOQUEUE)) {
		lp->lksb.sb_status = -EAGAIN;
		queue_complete(lp);
		error = 0;
	}

	GDLM_ASSERT(!error,
		   printk("%s: num=%x,%"PRIx64" err=%d cur=%d req=%d lkf=%x\n",
			  ls->fsname, lp->lockname.ln_type,
			  lp->lockname.ln_number, error, lp->cur, lp->req,
			  lp->lkf););
}

void gdlm_do_unlock(struct gdlm_lock *lp)
{
	unsigned int lkf = 0;
	int error;

	set_bit(LFL_DLM_UNLOCK, &lp->flags);
	set_bit(LFL_ACTIVE, &lp->flags);

	if (lp->lvb)
		lkf = DLM_LKF_VALBLK;

	log_debug("un %x,%"PRIx64" %x %d %x", lp->lockname.ln_type,
		  lp->lockname.ln_number, lp->lksb.sb_lkid, lp->cur, lkf);

	error = dlm_unlock(lp->ls->dlm_lockspace, lp->lksb.sb_lkid, lkf,
			   NULL, lp);

	GDLM_ASSERT(!error,
		   printk("%s: error=%d num=%x,%"PRIx64" lkf=%x flags=%lx\n",
			  lp->ls->fsname, error, lp->lockname.ln_type,
			  lp->lockname.ln_number, lkf, lp->flags););
}

unsigned int gdlm_lock(lm_lock_t *lock, unsigned int cur_state,
		       unsigned int req_state, unsigned int flags)
{
	struct gdlm_lock *lp = (struct gdlm_lock *) lock;

	clear_bit(LFL_DLM_CANCEL, &lp->flags);
	if (flags & LM_FLAG_NOEXP)
		set_bit(LFL_NOBLOCK, &lp->flags);

	check_cur_state(lp, cur_state);
	lp->req = make_mode(req_state);
	lp->lkf = make_flags(lp, flags, lp->cur, lp->req);

	gdlm_do_lock(lp, NULL);
	return LM_OUT_ASYNC;
}

unsigned int gdlm_unlock(lm_lock_t *lock, unsigned int cur_state)
{
	struct gdlm_lock *lp = (struct gdlm_lock *) lock;

	clear_bit(LFL_DLM_CANCEL, &lp->flags);
	if (lp->cur == DLM_LOCK_IV)
		return 0;
	gdlm_do_unlock(lp);
	return LM_OUT_ASYNC;
}

void gdlm_cancel(lm_lock_t *lock)
{
	struct gdlm_lock *lp = (struct gdlm_lock *) lock;
	struct gdlm_ls *ls = lp->ls;
	int error, delay_list = 0;

	if (test_bit(LFL_DLM_CANCEL, &lp->flags))
		return;

	log_all("gdlm_cancel %x,%"PRIx64" flags %lx",
		lp->lockname.ln_type, lp->lockname.ln_number, lp->flags);

	spin_lock(&ls->async_lock);
	if (!list_empty(&lp->delay_list)) {
		list_del_init(&lp->delay_list);
		delay_list = 1;
	}
	spin_unlock(&ls->async_lock);

	if (delay_list) {
		set_bit(LFL_CANCEL, &lp->flags);
		set_bit(LFL_ACTIVE, &lp->flags);
		queue_complete(lp);
		return;
	}

	if (!test_bit(LFL_ACTIVE, &lp->flags) ||
	    test_bit(LFL_DLM_UNLOCK, &lp->flags))	{
		log_all("gdlm_cancel skip %x,%"PRIx64" flags %lx",
			lp->lockname.ln_type, lp->lockname.ln_number,
			lp->flags);
		return;
	}

	/* the lock is blocked in the dlm */

	set_bit(LFL_DLM_CANCEL, &lp->flags);
	set_bit(LFL_ACTIVE, &lp->flags);

	error = dlm_unlock(ls->dlm_lockspace, lp->lksb.sb_lkid, DLM_LKF_CANCEL,
			   NULL, lp);

	log_all("gdlm_cancel rv %d %x,%"PRIx64" flags %lx", error,
		lp->lockname.ln_type, lp->lockname.ln_number, lp->flags);

	if (error == -EBUSY)
		clear_bit(LFL_DLM_CANCEL, &lp->flags);
}

int gdlm_add_lvb(struct gdlm_lock *lp)
{
	char *lvb;

	lvb = kmalloc(GDLM_LVB_SIZE, GFP_KERNEL);
	if (!lvb)
		return -ENOMEM;

	memset(lvb, 0, GDLM_LVB_SIZE);

	lp->lksb.sb_lvbptr = lvb;
	lp->lvb = lvb;
	return 0;
}

void gdlm_del_lvb(struct gdlm_lock *lp)
{
	kfree(lp->lvb);
	lp->lvb = NULL;
	lp->lksb.sb_lvbptr = NULL;
}

/* This can do a synchronous dlm request (requiring a lock_dlm thread to get
   the completion) because gfs won't call hold_lvb() during a callback (from
   the context of a lock_dlm thread). */

static int hold_null_lock(struct gdlm_lock *lp)
{
	struct gdlm_lock *lpn = NULL;
	int error;

	if (lp->hold_null) {
		printk("lock_dlm: lvb already held\n");
		return 0;
	}

	error = gdlm_create_lp(lp->ls, &lp->lockname, &lpn);
	if (error)
		goto out;

	lpn->lksb.sb_lvbptr = junk_lvb;
	lpn->lvb = junk_lvb;

	lpn->req = DLM_LOCK_NL;
	lpn->lkf = DLM_LKF_VALBLK | DLM_LKF_EXPEDITE;
	set_bit(LFL_NOBAST, &lpn->flags);
	set_bit(LFL_INLOCK, &lpn->flags);

	init_completion(&lpn->ast_wait);
	gdlm_do_lock(lpn, NULL);
	wait_for_completion(&lpn->ast_wait);
	error = lp->lksb.sb_status;
	if (error) {
		printk("lock_dlm: hold_null_lock dlm error %d\n", error);
		gdlm_delete_lp(lpn);
		lpn = NULL;
	}
 out:
	lp->hold_null = lpn;
	return error;
}

/* This cannot do a synchronous dlm request (requiring a lock_dlm thread to get
   the completion) because gfs may call unhold_lvb() during a callback (from
   the context of a lock_dlm thread) which could cause a deadlock since the
   other lock_dlm thread could be engaged in recovery. */

static void unhold_null_lock(struct gdlm_lock *lp)
{
	struct gdlm_lock *lpn = lp->hold_null;

	GDLM_ASSERT(lpn,);
	lpn->lksb.sb_lvbptr = NULL;
	lpn->lvb = NULL;
	set_bit(LFL_UNLOCK_DELETE, &lpn->flags);
	gdlm_do_unlock(lpn);
	lp->hold_null = NULL;
}

/* Acquire a NL lock because gfs requires the value block to remain
   intact on the resource while the lvb is "held" even if it's holding no locks
   on the resource. */

int gdlm_hold_lvb(lm_lock_t *lock, char **lvbp)
{
	struct gdlm_lock *lp = (struct gdlm_lock *) lock;
	int error;

	error = gdlm_add_lvb(lp);
	if (error)
		return error;

	*lvbp = lp->lvb;

	error = hold_null_lock(lp);
	if (error)
		gdlm_del_lvb(lp);

	return error;
}

void gdlm_unhold_lvb(lm_lock_t *lock, char *lvb)
{
	struct gdlm_lock *lp = (struct gdlm_lock *) lock;

	unhold_null_lock(lp);
	gdlm_del_lvb(lp);
}

void gdlm_sync_lvb(lm_lock_t *lock, char *lvb)
{
	struct gdlm_lock *lp = (struct gdlm_lock *) lock;

	if (lp->cur != DLM_LOCK_EX)
		return;

	init_completion(&lp->ast_wait);
	set_bit(LFL_SYNC_LVB, &lp->flags);

	lp->req = DLM_LOCK_EX;
	lp->lkf = make_flags(lp, 0, lp->cur, lp->req);

	gdlm_do_lock(lp, NULL);
	wait_for_completion(&lp->ast_wait);
}

void gdlm_submit_delayed(struct gdlm_ls *ls)
{
	struct gdlm_lock *lp, *safe;

	spin_lock(&ls->async_lock);
	list_for_each_entry_safe(lp, safe, &ls->delayed, delay_list) {
		list_del_init(&lp->delay_list);
		list_add_tail(&lp->delay_list, &ls->submit);
	}
	spin_unlock(&ls->async_lock);
	wake_up(&ls->thread_wait);
}

int gdlm_release_all_locks(struct gdlm_ls *ls)
{
	struct gdlm_lock *lp, *safe;
	int count = 0;

	spin_lock(&ls->async_lock);
	list_for_each_entry_safe(lp, safe, &ls->all_locks, all_list) {
		list_del_init(&lp->all_list);

		if (lp->lvb && lp->lvb != junk_lvb)
			kfree(lp->lvb);
		kfree(lp);
		count++;
	}
	spin_unlock(&ls->async_lock);

	return count;
}

