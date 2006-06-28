/*
 * RT Mutexes: blocking mutual exclusion locks with PI support
 *
 * started by Ingo Molnar and Thomas Gleixner:
 *
 *  Copyright (C) 2004-2006 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *  Copyright (C) 2006, Timesys Corp., Thomas Gleixner <tglx@timesys.com>
 *
 * This file contains the private data structure and API definitions.
 */

#ifndef __KERNEL_RTMUTEX_COMMON_H
#define __KERNEL_RTMUTEX_COMMON_H

#include <linux/rtmutex.h>

/*
 * This is the control structure for tasks blocked on a rt_mutex,
 * which is allocated on the kernel stack on of the blocked task.
 *
 * @list_entry:		pi node to enqueue into the mutex waiters list
 * @pi_list_entry:	pi node to enqueue into the mutex owner waiters list
 * @task:		task reference to the blocked task
 */
struct rt_mutex_waiter {
	struct plist_node	list_entry;
	struct plist_node	pi_list_entry;
	struct task_struct	*task;
	struct rt_mutex		*lock;
#ifdef CONFIG_DEBUG_RT_MUTEXES
	unsigned long		ip;
	pid_t			deadlock_task_pid;
	struct rt_mutex		*deadlock_lock;
#endif
};

/*
 * Various helpers to access the waiters-plist:
 */
static inline int rt_mutex_has_waiters(struct rt_mutex *lock)
{
	return !plist_head_empty(&lock->wait_list);
}

static inline struct rt_mutex_waiter *
rt_mutex_top_waiter(struct rt_mutex *lock)
{
	struct rt_mutex_waiter *w;

	w = plist_first_entry(&lock->wait_list, struct rt_mutex_waiter,
			       list_entry);
	BUG_ON(w->lock != lock);

	return w;
}

static inline int task_has_pi_waiters(struct task_struct *p)
{
	return !plist_head_empty(&p->pi_waiters);
}

static inline struct rt_mutex_waiter *
task_top_pi_waiter(struct task_struct *p)
{
	return plist_first_entry(&p->pi_waiters, struct rt_mutex_waiter,
				  pi_list_entry);
}

/*
 * lock->owner state tracking:
 */
#define RT_MUTEX_OWNER_PENDING	1UL
#define RT_MUTEX_HAS_WAITERS	2UL
#define RT_MUTEX_OWNER_MASKALL	3UL

static inline struct task_struct *rt_mutex_owner(struct rt_mutex *lock)
{
	return (struct task_struct *)
		((unsigned long)lock->owner & ~RT_MUTEX_OWNER_MASKALL);
}

static inline struct task_struct *rt_mutex_real_owner(struct rt_mutex *lock)
{
 	return (struct task_struct *)
		((unsigned long)lock->owner & ~RT_MUTEX_HAS_WAITERS);
}

static inline unsigned long rt_mutex_owner_pending(struct rt_mutex *lock)
{
	return (unsigned long)lock->owner & RT_MUTEX_OWNER_PENDING;
}

#endif
