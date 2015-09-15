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

struct popcorn_namespace *get_popcorn_ns(struct popcorn_namespace *ns);
struct popcorn_namespace *copy_pop_ns(unsigned long flags, struct popcorn_namespace *ns);
void free_popcorn_ns(struct kref *kref);
void put_pop_ns(struct popcorn_namespace *ns);
int associate_to_popcorn_ns(struct task_struct * tsk, int replication_degree);
int is_popcorn_namespace_active(struct popcorn_namespace* ns);

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
	struct task_list *token;
};

extern struct popcorn_namespace init_pop_ns;

static inline void dump_task_list(struct popcorn_namespace *ns)
{
	struct list_head *iter= NULL;
	struct task_list *objPtr;
	spin_lock(&ns->task_list_lock);
	list_for_each(iter, &ns->ns_task_list.task_list_member) {
		objPtr = list_entry(iter, struct task_list, task_list_member);
		printk("%d -> ", objPtr->task->pid);
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
	ns->token == NULL;
}

// Pass the token to the next task in this namespace
static inline void pass_token(struct popcorn_namespace *ns)
{
	spin_lock(&ns->task_list_lock);
	//if (list_is_last(ns->token->task_list_member.prev, &ns->ns_task_list.task_list_member))
	ns->token = container_of(ns->token->task_list_member.next, struct task_list, task_list_member);
	if (ns->token->task == NULL) {
		ns->token = container_of(ns->token->task_list_member.next, struct task_list, task_list_member);
	}
	printk("token is %x, %d\n", ns->token, ns->token->task->pid);
	spin_unlock(&ns->task_list_lock);
}

static inline int set_token(struct popcorn_namespace *ns, struct task_struct *task)
{
	struct list_head *iter= NULL;
	struct task_list *objPtr;
	spin_lock(&ns->task_list_lock);
	list_for_each(iter, &ns->ns_task_list.task_list_member) {
		objPtr = list_entry(iter, struct task_list, task_list_member);
		if (objPtr->task == task) {
			ns->token = objPtr;
			spin_unlock(&ns->task_list_lock);
			return 1;
		}
	}
	spin_unlock(&ns->task_list_lock);
	return 0;
}

// Whenever a new thread is created, the task should go to ns
static inline int add_task_to_ns(struct popcorn_namespace *ns, struct task_struct *task)
{
	printk("Add %x, %d to ns\n", task, task->pid);
	struct task_list *new_task = kmalloc(sizeof(struct task_list), GFP_KERNEL);
	if (new_task == NULL)
		return -1;

	spin_lock(&ns->task_list_lock);
	new_task->task = task;
	list_add_tail(&new_task->task_list_member, &ns->ns_task_list.task_list_member);
	spin_unlock(&ns->task_list_lock);
	dump_task_list(ns);
	return 0;
}

// Whenever a new thread is gone, the task should get deleted
static inline int remove_task_from_ns(struct popcorn_namespace *ns, struct task_struct *task)
{
	struct list_head *iter= NULL;
	struct task_list *objPtr;
	spin_lock(&ns->task_list_lock);
	list_for_each(iter, &ns->ns_task_list.task_list_member) {
		objPtr = list_entry(iter, struct task_list, task_list_member);
		if (objPtr->task == task) {
			if (ns->token == objPtr) {
				spin_unlock(&ns->task_list_lock);
				pass_token(ns);
				spin_lock(&ns->task_list_lock);
			}
			list_del(iter);
			kfree(iter);
			spin_unlock(&ns->task_list_lock);
			return 0;
		}
	}
	spin_unlock(&ns->task_list_lock);

	return -1;
}

#endif /* _POPCORN_NAMESPACE_H */
