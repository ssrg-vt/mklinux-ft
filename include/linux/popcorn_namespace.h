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
#include <linux/delay.h>
#include <linux/ft_common_syscall_management.h>

// If AGGRESSIVE_DET is enabled, for all the blocking system calls,
// only Futex will be skipped
#define AGGRESSIVE_DET 1
#define DETONLY
#define TOKEN_RETRY 20

//#define DET_PROF 1

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
#ifdef DET_PROF
	uint64_t start_cost[64];
	uint64_t tick_cost[64];
	uint64_t end_cost[64];
	spinlock_t tick_cost_lock;
#endif
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
			printk("%d(%d)[%ld][%d]<%ld>[o] -> ", objPtr->task->pid, objPtr->task->ft_det_tick, objPtr->task->state, objPtr->task->ft_det_state, objPtr->task->current_syscall);
		else
			printk("%d(%d)[%ld][%d]<%ld>[x] -> ", objPtr->task->pid, objPtr->task->ft_det_tick, objPtr->task->state, objPtr->task->ft_det_state, objPtr->task->current_syscall);
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
#ifdef DET_PROF
	spin_lock_init(&(ns->tick_cost_lock));
	int i;
	for (i = 0; i < 64; i++) {
		ns->tick_cost[i] = 1;
		ns->start_cost[i] = 1;
		ns->end_cost[i] = 1;
	}
#endif
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
	struct task_list *new_task;
	//printk("Add %x, %d to ns\n", (unsigned long) task, task->pid);
	new_task = kmalloc(sizeof(struct task_list), GFP_KERNEL);
	if (new_task == NULL)
		return -1;

	task->ft_det_tick = 0;
	new_task->task = task;
	spin_lock_irqsave(&ns->task_list_lock, flags);
	mb();
	ns->task_count++;
	list_add_tail(&new_task->task_list_member, &ns->ns_task_list.task_list_member);
	mb();
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
	mb();
	list_for_each_safe(iter, n, &ns->ns_task_list.task_list_member) {
		objPtr = list_entry(iter, struct task_list, task_list_member);
		if (objPtr->task == task) {
			list_del(iter);
			kfree(iter);
			update_token(ns);
			ns->task_count--;
			mb();
			spin_unlock_irqrestore(&ns->task_list_lock, flags);
#ifdef DET_PROF
			printk("tick_count now for %d %llu %llu %llu\n", task->pid % 64, ns->start_cost[task->pid % 64], ns->tick_cost[task->pid % 64], ns->end_cost[task->pid % 64]);
			ns->tick_cost[task->pid % 64] = 1;
			ns->start_cost[task->pid % 64] = 1;
			ns->end_cost[task->pid % 64] = 1;
#endif
			//dump_task_list(ns);
			return 0;
		}
	}
	mb();
	spin_unlock_irqrestore(&ns->task_list_lock, flags);

	return -1;
}

/* Lock should be held before calling this */
static inline int update_token(struct popcorn_namespace *ns)
{
	struct list_head *iter= NULL;
	struct task_list *objPtr;
	struct task_list *new_token = ns->token;
	uint64_t tick_value = 0;
	uint64_t min_value = ~0;

	list_for_each_prev(iter, &ns->ns_task_list.task_list_member) {
		objPtr = list_entry(iter, struct task_list, task_list_member);
		tick_value = objPtr->task->ft_det_tick;
		if (min_value >= tick_value) {
			if(objPtr->task->state == TASK_RUNNING ||
				 objPtr->task->state == TASK_WAKING ||
#ifdef AGGRESSIVE_DET
				 objPtr->task->current_syscall == __NR_read ||
				 objPtr->task->current_syscall == __NR_sendto ||
				 objPtr->task->current_syscall == __NR_sendmsg ||
				 objPtr->task->current_syscall == __NR_close ||
				 objPtr->task->current_syscall == __NR_recvfrom ||
				 objPtr->task->current_syscall == __NR_recvmsg ||
				 objPtr->task->current_syscall == __NR_write ||
				 objPtr->task->current_syscall == __NR_accept ||
				 objPtr->task->current_syscall == __NR_time ||
				 objPtr->task->current_syscall == __NR_poll ||
				 objPtr->task->current_syscall == __NR_epoll_wait ||
				 objPtr->task->current_syscall == __NR_gettimeofday ||
				 objPtr->task->current_syscall == __NR_bind ||
				 objPtr->task->current_syscall == __NR_wait4 ||
				 objPtr->task->current_syscall == __NR_nanosleep ||
				 objPtr->task->current_syscall == __NR_socket ||
#endif
				 objPtr->task->ft_det_state == FT_DET_WAIT_TOKEN) {
				new_token = objPtr;
				min_value = tick_value;
			}
		}
	}
/*	
	 if (ns->token != NULL && ns->token->task != NULL && new_token != NULL && new_token->task != NULL)
	     trace_printk("token from %d to %d\n", ns->token->task->pid, new_token->task->pid);
	 else if ((ns->token == NULL || ns->token->task == NULL) && (new_token != NULL && new_token->task != NULL))
	     trace_printk("token from NULL to %d\n", new_token->task->pid);
	 else if ((ns->token == NULL || ns->token->task == NULL) && (new_token == NULL || new_token->task == NULL))
	     trace_printk("token from NULL to NULL\n");
*/	 
	mb();
	
	ns->token = new_token;
	mb();
	if (ns->token != NULL &&
			ns->token->task != NULL) {
		mb();
		ns->last_tick = ns->token->task->ft_det_tick;
		mb();
		if (ns->token->task->state == TASK_INTERRUPTIBLE &&
				ns->token->task->ft_det_state == FT_DET_WAIT_TOKEN) {
			mb();
			wake_up_process(ns->token->task);
		}
	}
	return 0;
}

static inline int update_tick(struct task_struct *task, long tick)
{
	unsigned long flags;
	struct popcorn_namespace *ns;

	ns = task->nsproxy->pop_ns;

	//dump_task_list(ns);
	spin_lock_irqsave(&ns->task_list_lock, flags);
	mb();
	task->ft_det_tick += tick;
	mb();
	update_token(ns);
	mb();
	spin_unlock_irqrestore(&ns->task_list_lock, flags);
	return 1;
}

static inline void det_wake_up(struct task_struct *task)
{
	unsigned long flags;
	//int tick;
	struct popcorn_namespace *ns;

	ns = task->nsproxy->pop_ns;

	spin_lock_irqsave(&ns->task_list_lock, flags);
	mb();

	if (ns->last_tick > task->ft_det_tick) {
	//	task->ft_det_tick = ns->last_tick;
	}
	mb();
	update_token(ns);
	mb();
	spin_unlock_irqrestore(&ns->task_list_lock, flags);

	if (task->ft_det_state == FT_DET_ACTIVE) {
		__det_start(task);
	}
}

static inline int is_det_active(struct popcorn_namespace *ns, struct task_struct *task);

static inline int have_token(struct task_struct *task)
{
	unsigned long flags;
	int retry = 0;
	struct popcorn_namespace *ns;

	ns = task->nsproxy->pop_ns;

again:
	task->ft_det_state = FT_DET_WAIT_TOKEN;
	mb();
	update_token(ns);
	mb();
	if (ns->token != NULL && ns->token->task == task) {
		if (is_det_active(ns, task)) {
			retry++;
			printk("WARNING: %d task which does not have the token is in state FT_DET_ACTIVE [%d](%d)\n", ns->token->task->pid, task->pid, retry);
			if (retry < TOKEN_RETRY) {
				goto again;
			} else {
				printk("[%d][%d] Critical token error\n", ns->token->task->pid, task->pid);
				return 1;
			}
		}
		return 1;
	} else {
		return 0;
	}
}

// checks whether there is a task different from the task parameter which in state FT_DET_ACTIVE.
// lock must be held to call this function.
static inline int is_det_active(struct popcorn_namespace *ns, struct task_struct *task)
{
	struct list_head *iter= NULL;
	struct task_list *objPtr;
	unsigned long flags;

	list_for_each(iter, &ns->ns_task_list.task_list_member) {
		objPtr = list_entry(iter, struct task_list, task_list_member);
		if (objPtr->task->ft_det_state == FT_DET_ACTIVE) {
			if ((task == NULL || objPtr->task != task) &&
					(objPtr->task->state == TASK_RUNNING)) {
				trace_printk("(%d)[%d]%d holding token while (%d)[%d]%d asking for it\n", objPtr->task->pid, objPtr->task->current_syscall, objPtr->task->state, task->pid, task->current_syscall, task->state);
				// here I give you one moment to figure out the token
				spin_unlock_irqrestore(&ns->task_list_lock, flags);
				mdelay(2);
				spin_lock_irqsave(&ns->task_list_lock, flags);
				return 1;
			}
		}
	}
	return 0;
}


#endif /* _POPCORN_NAMESPACE_H */
