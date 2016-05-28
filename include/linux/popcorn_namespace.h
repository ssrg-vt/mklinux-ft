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
#include <asm/atomic64_64.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/ft_common_syscall_management.h>

// If AGGRESSIVE_DET is enabled, for all the blocking system calls,
// only Futex will be skipped
#define AGGRESSIVE_DET 1
#define DETONLY
#define TOKEN_RETRY 20

// The ultimate lock replication mode
#define LOCK_REPLICATION

//#define DET_PROF 1
//
extern atomic64_t global_msg_cnt;
extern atomic64_t global_sysmsg_cnt;
extern atomic64_t global_tickmsg_cnt;
extern atomic64_t global_syncmsg_cnt;

struct popcorn_namespace *get_popcorn_ns(struct popcorn_namespace *ns);
struct popcorn_namespace *copy_pop_ns(unsigned long flags, struct popcorn_namespace *ns);
void free_popcorn_ns(struct kref *kref);
void put_pop_ns(struct popcorn_namespace *ns);
int associate_to_popcorn_ns(struct task_struct * tsk, int replication_degree, int type);
int is_popcorn_namespace_active(struct popcorn_namespace* ns);
static inline int update_token(struct popcorn_namespace *ns);
long __det_start(struct task_struct *task);
long __det_end(struct task_struct *task);
long __rep_start(struct task_struct *task);
long __rep_end(struct task_struct *task);
int send_rep_turn(struct popcorn_namespace *ns, struct task_struct *task);
int wait_rep_turn(struct popcorn_namespace *ns, struct task_struct *task);
int is_det_sched_disable(struct task_struct *task);
void disable_det_sched(struct task_struct *task);
int remove_task_from_ns(struct popcorn_namespace *ns, struct task_struct *task);
int add_task_to_ns(struct popcorn_namespace *ns, struct task_struct *task);

struct task_list {
	struct list_head task_list_member;
	struct task_struct *task;
	struct ftpid_hash_entry *hash_entry;
};

struct rep_sync_list {
	struct list_head rep_sync_member;
	uint64_t rep_id;
	uint64_t global_rep_id;
	struct ft_pid ft_pid;
};

typedef struct _hashentry {
	struct list_head list;
	spinlock_t spinlock;
	void *obj; //pointer to the object to store
} hashentry_t;

typedef struct _hashtable {
	int size;
	spinlock_t spinlock; //used to lock the whole hash table when adding/removing/looking, not fine grain but effective!
	hashentry_t **table;
} hashtable_t;

struct ftpid_hash_entry {
	struct ft_pid *ft_pid;
	struct popcorn_namespace *ns;
};

struct rep_sync_msg {
	struct pcn_kmsg_hdr header;
	struct ft_pid ft_pid;
	uint64_t rep_id;
	int global_rep_id;
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
	/* The shepherd */
	struct task_struct *shepherd;
	/* Tasks that are waiting for the token. */
	int wait_count;
	uint64_t shepherd_bump;
#ifdef LOCK_REPLICATION
	struct mutex gmtx;
	atomic_t global_rep_id;
	atomic_t queue_len;
	spinlock_t rep_queue_lock;
	spinlock_t rep_queue_lock_tail;
	struct rep_sync_list ns_rep_list;
	// For stats
	atomic64_t rep_msg_cnt;
#endif
#ifdef DET_PROF
	uint64_t start_cost[64];
	uint64_t tick_cost[64];
	uint64_t end_cost[64];
	spinlock_t tick_cost_lock;
#endif
	// For stats
	atomic64_t net_msg_cnt;
	atomic64_t total_msg_cnt;
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
			printk("%d(%d)[%ld][%d]<%ld>[o] -> ", objPtr->task->pid, (int) objPtr->task->ft_det_tick, (long int) objPtr->task->state, objPtr->task->ft_det_state, objPtr->task->current_syscall);
		else
			printk("%d(%d)[%ld][%d]<%ld>[x] -> ", objPtr->task->pid, (int) objPtr->task->ft_det_tick, (long int) objPtr->task->state, objPtr->task->ft_det_state, objPtr->task->current_syscall);
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

static inline void init_rep_list(struct popcorn_namespace *ns)
{
	mutex_init(&ns->gmtx);
	INIT_LIST_HEAD(&ns->ns_rep_list.rep_sync_member);
	spin_lock_init(&ns->rep_queue_lock);
	spin_lock_init(&ns->rep_queue_lock_tail);
	atomic_set(&ns->global_rep_id, 0);
	atomic_set(&ns->queue_len, 0);
	atomic_set(&global_msg_cnt, 0);
	atomic_set(&global_sysmsg_cnt, 0);
	atomic_set(&global_tickmsg_cnt, 0);
	atomic_set(&global_syncmsg_cnt, 0);
}

static inline int enqueue_rep_list(struct popcorn_namespace *ns, uint64_t rep_id, uint64_t global_rep_id, struct ft_pid *ft_pid)
{
	unsigned long flags;
	struct rep_sync_list *new_sync;
	struct list_head *iter= NULL;
	struct task_list *objPtr;

	new_sync = kmalloc(sizeof(struct rep_sync_list), GFP_KERNEL);
	if (new_sync == NULL)
		return -1;

	new_sync->rep_id = rep_id;
	new_sync->global_rep_id = global_rep_id;
	memcpy(&new_sync->ft_pid, ft_pid, sizeof(struct ft_pid));
	spin_lock_irqsave(&ns->rep_queue_lock, flags);
	atomic_inc(&ns->queue_len);
	list_add_tail(&new_sync->rep_sync_member, &ns->ns_rep_list.rep_sync_member);
	spin_unlock_irqrestore(&ns->rep_queue_lock, flags);

	if (atomic_read(&ns->queue_len) <= 1) {
		spin_lock_irqsave(&ns->rep_queue_lock, flags);
		spin_unlock_irqrestore(&ns->rep_queue_lock, flags);
		list_for_each(iter, &ns->ns_task_list.task_list_member) {
			objPtr = list_entry(iter, struct task_list, task_list_member);
			if (are_ft_pid_equals(&new_sync->ft_pid, &objPtr->task->ft_pid)) {
				wake_up_process(objPtr->task);
				return 0;
			}
		}
	}

	return 1;
}

static inline int peek_rep_list(struct popcorn_namespace *ns, uint64_t rep_id, uint64_t global_rep_id, struct ft_pid *ft_pid)
{
	unsigned long flags;
	struct rep_sync_list *sync;

	spin_lock_irqsave(&ns->rep_queue_lock, flags);
	if (list_empty(&ns->ns_rep_list.rep_sync_member)) {
		spin_unlock_irqrestore(&ns->rep_queue_lock, flags);
		return 0;
	}
	mb();
	sync = list_first_entry(&ns->ns_rep_list.rep_sync_member, struct rep_sync_list, rep_sync_member);
	if (sync->rep_id == rep_id &&
			sync->global_rep_id == global_rep_id &&
			are_ft_pid_equals(&sync->ft_pid, ft_pid)) {
		spin_unlock_irqrestore(&ns->rep_queue_lock, flags);
		return 1;
	} else {
		spin_unlock_irqrestore(&ns->rep_queue_lock, flags);
		return 0;
	}
}

static inline int dequeue_rep_list(struct popcorn_namespace *ns)
{
	unsigned long flags;
	struct rep_sync_list *sync;
	int lock_tail = 0;
	int ret;

	spin_lock_irqsave(&ns->rep_queue_lock, flags);
	atomic_dec(&ns->queue_len);
	if (list_empty(&ns->ns_rep_list.rep_sync_member)) {
		ret = 0;
		goto dequeue_out;
	}
	sync = list_first_entry(&ns->ns_rep_list.rep_sync_member, struct rep_sync_list, rep_sync_member);
	list_del(&sync->rep_sync_member);
	kfree(sync);
	ret = 1;
dequeue_out:
	spin_unlock_irqrestore(&ns->rep_queue_lock, flags);
	return ret;
}

static inline void init_task_list(struct popcorn_namespace *ns)
{
	INIT_LIST_HEAD(&ns->ns_task_list.task_list_member);
	spin_lock_init(&ns->task_list_lock);
	spin_lock_init(&ns->task_tick_lock);
	ns->token = NULL;
	ns->last_tick = 0;
	ns->task_count = 0;
	ns->wait_count = 0;
	ns->shepherd = NULL;
	ns->shepherd_bump = 0;
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


/* Lock should be held before calling this */
static inline int update_token(struct popcorn_namespace *ns)
{
	struct list_head *iter= NULL;
	struct task_list *objPtr;
	struct task_list *new_token = ns->token;
	uint64_t tick_value = 0;
	uint64_t min_value = ~0;

	if(is_det_sched_disable(current))
		return 0;

	smp_mb();
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
				 objPtr->task->current_syscall == __NR_writev ||
				 objPtr->task->current_syscall == __NR_readv ||
				 objPtr->task->current_syscall == __NR_preadv ||
				 objPtr->task->current_syscall == __NR_pwritev ||
				 objPtr->task->current_syscall == __NR_pread64 ||
				 objPtr->task->current_syscall == __NR_pwrite64 ||
				 objPtr->task->current_syscall == __NR_accept ||
				 objPtr->task->current_syscall == __NR_accept4 ||
				 objPtr->task->current_syscall == __NR_time ||
				 objPtr->task->current_syscall == __NR_poll ||
				 objPtr->task->current_syscall == __NR_epoll_wait ||
				 objPtr->task->current_syscall == __NR_gettimeofday ||
				 objPtr->task->current_syscall == __NR_bind ||
				 objPtr->task->current_syscall == __NR_nanosleep ||
				 objPtr->task->current_syscall == __NR_socket ||
				 objPtr->task->current_syscall == __NR_popcorn_det_start ||
#endif
				 objPtr->task->ft_det_state == FT_DET_WAIT_TOKEN) {
				new_token = objPtr;
				min_value = tick_value;
			}
		}
	}
	mb();
	/*if (ns->token != NULL && ns->token->task != NULL && new_token != NULL && new_token->task != NULL)
		trace_printk("token from %d[%d]<%d> to %d[%d]<%d>\n", ns->token->task->pid, ns->token->task->ft_det_tick, ns->token->task->id_syscall, new_token->task->pid, new_token->task->ft_det_tick, new_token->task->id_syscall);
	else if ((ns->token == NULL || ns->token->task == NULL) && (new_token != NULL && new_token->task != NULL))
		trace_printk("token from NULL to %d[%d]<%d>\n", new_token->task->pid, new_token->task->ft_det_tick, new_token->task->id_syscall);
	else if ((ns->token == NULL || ns->token->task == NULL) && (new_token == NULL || new_token->task == NULL))
		trace_printk("token from NULL to NULL\n");
	
	mb();*/

	ns->token = new_token;
	if (ns->token != NULL &&
			ns->token->task != NULL) {
		ns->last_tick = ns->token->task->ft_det_tick;
		mb();
		if (ns->token->task->state == TASK_INTERRUPTIBLE &&
				ns->token->task->ft_det_state == FT_DET_WAIT_TOKEN) {
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
	task->ft_det_tick += tick;
	smp_mb();
	update_token(ns);
	spin_unlock_irqrestore(&ns->task_list_lock, flags);
	return 1;
}

static inline void det_wake_up(struct task_struct *task)
{
	unsigned long flags;
	//int tick;
	struct popcorn_namespace *ns;
#ifdef LOCK_REPLICATION
#else
	ns = task->nsproxy->pop_ns;

	spin_lock_irqsave(&ns->task_list_lock, flags);
	update_token(ns);
	spin_unlock_irqrestore(&ns->task_list_lock, flags);

	__det_start(task);
#endif
}

//static inline int is_det_active(struct popcorn_namespace *ns, struct task_struct *task);

static inline int have_token(struct task_struct *task)
{
	struct popcorn_namespace *ns;

	ns = task->nsproxy->pop_ns;

	task->ft_det_state = FT_DET_WAIT_TOKEN;
	update_token(ns);
	if (ns->token != NULL && ns->token->task == task) {
		return 1;
	} else {
		return 0;
	}
}
#endif /* _POPCORN_NAMESPACE_H */
