/*
 * 
 * popcorn_namespace.h
 * 
 * Author: Marina
 */
 
#ifndef _POPCORN_NAMESPACE_H
#define _POPCORN_NAMESPACE_H

#include <linux/nsproxy.h>
#include <linux/spinlock.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/ft_common_syscall_management.h>
#include <asm/atomic.h>

// If AGGRESSIVE_DET is enabled, for all the blocking system calls,
// only Futex will be skipped
#define AGGRESSIVE_DET 0

struct popcorn_namespace *get_popcorn_ns(struct popcorn_namespace *ns);
struct popcorn_namespace *copy_pop_ns(unsigned long flags, struct popcorn_namespace *ns);
void free_popcorn_ns(struct kref *kref);
void put_pop_ns(struct popcorn_namespace *ns);
int associate_to_popcorn_ns(struct task_struct * tsk, int replication_degree, int type);
int is_popcorn_namespace_active(struct popcorn_namespace* ns);
static inline int update_token(struct popcorn_namespace *ns);
long __det_start(struct task_struct *task);
long __det_end(struct task_struct *task);

struct task_list {
	struct list_head task_list_member;
	struct task_struct *task;
};


struct popcorn_namespace
{
	struct kref kref;
	int activate;
	pid_t root;
	int replication_degree;

	// This one stores all the pids under this namespace, ordered by their creation time
	struct task_list ns_task_list;
	spinlock_t task_list_lock;
	spinlock_t task_tick_lock;
	struct task_list *token;
	int last_tick;
	int task_count;
	/* The queue for storing wake up information from primary */
	struct wake_up_buffer wake_up_buffer;
};

extern struct popcorn_namespace init_pop_ns;

static inline void dump_task_list(struct popcorn_namespace *ns)
{
	struct list_head *iter= NULL;
	struct task_list *objPtr;
	spin_lock(&ns->task_list_lock);
	list_for_each(iter, &ns->ns_task_list.task_list_member) {
		objPtr = list_entry(iter, struct task_list, task_list_member);
		if (ns->token != NULL && objPtr->task == ns->token->task)
			printk("%d(%d)[%d][%d][o] -> ", objPtr->task->pid, atomic_read(&objPtr->task->ft_det_tick), objPtr->task->state, objPtr->task->ft_det_state);
		else
			printk("%d(%d)[%d][%d][x] -> ", objPtr->task->pid, atomic_read(&objPtr->task->ft_det_tick), objPtr->task->state, objPtr->task->ft_det_state);
	}
	printk("\n");
	spin_unlock(&ns->task_list_lock);
}

static inline int is_popcorn(struct task_struct *tsk)
{
	if (tsk->nsproxy && tsk->nsproxy->pop_ns) {
		return is_popcorn_namespace_active(tsk->nsproxy->pop_ns);
	}

	return 0;
}

static inline void init_task_list(struct popcorn_namespace *ns)
{
	INIT_LIST_HEAD(&ns->ns_task_list.task_list_member);
	spin_lock_init(&ns->task_list_lock);
	spin_lock_init(&ns->task_tick_lock);
	ns->token = NULL;
	ns->last_tick = 0;
	ns->task_count = 0;
	sema_init(&(ns->wake_up_buffer.queue_full), MAX_WAKE_UP_BUFFER);
	sema_init(&(ns->wake_up_buffer.queue_empty), 0);
	spin_lock_init(&(ns->wake_up_buffer.enqueue_lock));
	spin_lock_init(&(ns->wake_up_buffer.dequeue_lock));
	memset(&(ns->wake_up_buffer.wake_up_queue), 0, MAX_WAKE_UP_BUFFER * sizeof(struct sleeping_syscall_request *));
}

// Pass the token to the next task in this namespace
static inline void pass_token(struct popcorn_namespace *ns)
{
	do {
		ns->token = container_of(ns->token->task_list_member.next, struct task_list, task_list_member);
	} while (ns->token == NULL || ns->token->task == NULL);
}

static inline int set_token(struct popcorn_namespace *ns, struct task_struct *task)
{
	struct list_head *iter= NULL;
	struct task_list *objPtr;
	unsigned long flags;

	spin_lock_irqsave(&ns->task_list_lock, flags);
	list_for_each(iter, &ns->ns_task_list.task_list_member) {
		objPtr = list_entry(iter, struct task_list, task_list_member);
		if (objPtr->task == task) {
			ns->token = objPtr;
			spin_unlock_irqrestore(&ns->task_list_lock, flags);
			return 1;
		}
	}
	spin_unlock_irqrestore(&ns->task_list_lock, flags);
	return 0;
}

// Whenever a new thread is created, the task should go to ns
static inline int add_task_to_ns(struct popcorn_namespace *ns, struct task_struct *task)
{
	unsigned long flags;
	printk("Add %x, %d to ns\n", task, task->pid);
	struct task_list *new_task = kmalloc(sizeof(struct task_list), GFP_KERNEL);
	if (new_task == NULL)
		return -1;

	atomic_set(&task->ft_det_tick, 0);
	new_task->task = task;
	ns->task_count++;
	spin_lock_irqsave(&ns->task_list_lock, flags);
	list_add_tail(&new_task->task_list_member, &ns->ns_task_list.task_list_member);
	spin_unlock_irqrestore(&ns->task_list_lock, flags);
	return 0;
}

// Whenever a new thread is gone, the task should get deleted
static inline int remove_task_from_ns(struct popcorn_namespace *ns, struct task_struct *task)
{
	struct list_head *iter= NULL;
	struct list_head *n;
	struct task_list *objPtr;
	unsigned long flags;

	spin_lock_irqsave(&ns->task_list_lock, flags);
	list_for_each_safe(iter, n, &ns->ns_task_list.task_list_member) {
		objPtr = list_entry(iter, struct task_list, task_list_member);
		if (objPtr->task == task) {
			list_del(iter);
			kfree(iter);
			update_token(ns);
			ns->task_count--;
			spin_unlock_irqrestore(&ns->task_list_lock, flags);
			//dump_task_list(ns);
			return 0;
		}
	}
	spin_unlock_irqrestore(&ns->task_list_lock, flags);

	return -1;
}

static inline int update_token(struct popcorn_namespace *ns)
{
	struct list_head *iter= NULL;
	struct task_list *objPtr;
	struct task_list *new_token = ns->token;
	int tick_value = 0;
	// TODO: overflow
	int min_value = 999999999;

	list_for_each(iter, &ns->ns_task_list.task_list_member) {
		objPtr = list_entry(iter, struct task_list, task_list_member);
		tick_value = atomic_read(&objPtr->task->ft_det_tick);
		if (min_value >= tick_value) {
#ifdef AGGRESSIVE_DET 
			if(!(objPtr->task->state == TASK_RUNNING ||
				 objPtr->task->state == TASK_WAKING ||
				 objPtr->task->ft_det_state == FT_DET_WAIT_TOKEN) &&
					objPtr->task->current_syscall == 202) { // Skip futex
			} else {
#else
			if(objPtr->task->state == TASK_RUNNING ||
				 objPtr->task->state == TASK_WAKING ||
				 objPtr->task->ft_det_state == FT_DET_WAIT_TOKEN) {
#endif
				new_token = objPtr;
				min_value = tick_value;
			}
		}
	}
	ns->token = new_token;
	if (ns->token != NULL &&
			ns->token->task != NULL) {
		ns->last_tick = atomic_read(&ns->token->task->ft_det_tick);
		if (ns->token->task->state == TASK_INTERRUPTIBLE) {
			wake_up_process(ns->token->task);
		}
	}
	return 0;
}

static inline int update_tick(struct task_struct *task)
{
	unsigned long flags;
	struct popcorn_namespace *ns;

	ns = task->nsproxy->pop_ns;

	//dump_task_list(ns);
	atomic_inc(&task->ft_det_tick);
	spin_lock_irqsave(&ns->task_list_lock, flags);
	update_token(ns);
	spin_unlock_irqrestore(&ns->task_list_lock, flags);
	return 1;
}

static inline void det_wake_up(struct task_struct *task)
{
	unsigned long flags;
	int tick;
	struct popcorn_namespace *ns;

	ns = task->nsproxy->pop_ns;

	spin_lock_irqsave(&ns->task_list_lock, flags);
	if (ns->last_tick > atomic_read(&task->ft_det_tick)) {
		atomic_set(&task->ft_det_tick, ns->last_tick);
		update_token(ns);
		spin_unlock_irqrestore(&ns->task_list_lock, flags);
	} else {
		spin_unlock_irqrestore(&ns->task_list_lock, flags);
	}

	if (task->ft_det_state == FT_DET_ACTIVE) {
		__det_start(task);
	}
	//printk("Waking up %d from %pS with tick %d\n", task->pid, __builtin_return_address(1), task->ft_det_tick);
	//dump_task_list(ns);
}

static inline int have_token(struct task_struct *task)
{
	unsigned long flags;
	struct popcorn_namespace *ns;

	ns = task->nsproxy->pop_ns;

	spin_lock_irqsave(&ns->task_list_lock, flags);
	if (ns->token->task == task) {
		spin_unlock_irqrestore(&ns->task_list_lock, flags);
		return 1;
	} else {
//		update_token(ns);
		spin_unlock_irqrestore(&ns->task_list_lock, flags);
		return 0;
	}
}

#endif /* _POPCORN_NAMESPACE_H */
