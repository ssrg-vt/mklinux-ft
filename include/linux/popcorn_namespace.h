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

struct pid_list {
	struct list_head pid_list_member;
	pid_t pid;
};

struct popcorn_namespace
{
	struct kref kref;
	int activate;
	pid_t root;
	int replication_degree;

	// This one stores all the pids under this namespace, ordered by their creation time
	struct pid_list ns_pid_list;
	spinlock_t pid_list_lock;
	struct pid_list *token;
};

extern struct popcorn_namespace init_pop_ns;

static inline void dump_pid_list(struct popcorn_namespace *ns)
{
	struct list_head *iter= NULL;
	struct pid_list *objPtr;
	spin_lock(&ns->pid_list_lock);
	list_for_each(iter, &ns->ns_pid_list.pid_list_member) {
		objPtr = list_entry(iter, struct pid_list, pid_list_member);
		printk("%d -> ", objPtr->pid);
	}
	printk("\n");
	spin_unlock(&ns->pid_list_lock);
}

static inline int is_popcorn(struct task_struct *tsk)
{
	if (tsk->nsproxy && tsk->nsproxy->pop_ns) {
		return is_popcorn_namespace_active(tsk->nsproxy->pop_ns);
	}

	return 0;
}

static inline void init_pid_list(struct popcorn_namespace *ns)
{
	INIT_LIST_HEAD(&ns->ns_pid_list.pid_list_member);
	spin_lock_init(&ns->pid_list_lock);
}

// Pass the token to the next task in this namespace
static inline void pass_token(struct popcorn_namespace *ns)
{
	spin_lock(&ns->pid_list_lock);
	ns->token = container_of(ns->token->pid_list_member.prev, struct pid_list, pid_list_member);
	printk("token is %d\n", ns->token->pid);
	spin_unlock(&ns->pid_list_lock);
}

static inline int set_token(struct popcorn_namespace *ns, pid_t pid)
{
	struct list_head *iter= NULL;
	struct pid_list *objPtr;
	spin_lock(&ns->pid_list_lock);
	list_for_each(iter, &ns->ns_pid_list.pid_list_member) {
		objPtr = list_entry(iter, struct pid_list, pid_list_member);
		if ((uint64_t) objPtr->pid == (uint64_t) pid) {
			ns->token = objPtr;
			spin_unlock(&ns->pid_list_lock);
			return 1;
		}
	}
	spin_unlock(&ns->pid_list_lock);
	printk("%d is not in ns\n", pid);
	return 0;
}

// Whenever a new thread is created, the pid should go to ns
static inline int add_pid_to_ns(struct popcorn_namespace *ns, pid_t pid)
{
	printk("Add %d to ns\n", pid);
	struct pid_list *new_pid = kmalloc(sizeof(struct pid_list), GFP_KERNEL);
	if (new_pid == NULL)
		return -1;

	spin_lock(&ns->pid_list_lock);
	memcpy(&new_pid->pid, &pid, sizeof(pid_t));
	list_add_tail(&new_pid->pid_list_member, &ns->ns_pid_list.pid_list_member);
	spin_unlock(&ns->pid_list_lock);
	dump_pid_list(ns);
	return 0;
}

// Whenever a new thread is gone, the pid should get deleted
static inline int remove_pid_from_ns(struct popcorn_namespace *ns, pid_t pid)
{
	struct list_head *iter= NULL;
	struct pid_list *objPtr;
	spin_lock(&ns->pid_list_lock);
	list_for_each(iter, &ns->ns_pid_list.pid_list_member) {
		objPtr = list_entry(iter, struct pid_list, pid_list_member);
		if ((uint64_t) objPtr->pid == (uint64_t) pid) {
			if (ns->token == objPtr)
				pass_token(ns);
			list_del(iter);
			kfree(iter);
			spin_unlock(&ns->pid_list_lock);
			return 0;
		}
	}
	spin_unlock(&ns->pid_list_lock);

	return -1;
}

#endif /* _POPCORN_NAMESPACE_H */
