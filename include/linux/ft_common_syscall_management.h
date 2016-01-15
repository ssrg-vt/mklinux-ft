/*
 * ft_common_syscall_management.h
 * Copyright (C) 2015 Yuzhong Wen <wyz2014@vt.edu>
 *
 */

#ifndef FT_COMMON_SYSCALL_MANAGEMENT_H
#define FT_COMMON_SYSCALL_MANAGEMENT_H

#include <linux/ft_replication.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/pcn_kmsg.h>
#include <linux/popcorn_namespace.h>
#include <linux/ft_common_syscall_management.h>
#include <asm/unistd_64.h>

/*
 * Message structure for synchronizing sleeping system calls
 */
struct sleeping_syscall_request {
	struct pcn_kmsg_hdr header;
	struct ft_pid ft_pid;
	int det_process_count;
	int syscall_id;
	uint64_t ticks[0];
};

#define MAX_WAKE_UP_BUFFER 1024
struct wake_up_buffer {
	struct sleeping_syscall_request *wake_up_queue[MAX_WAKE_UP_BUFFER];
	int queue_head;
	int queue_tail;
	spinlock_t enqueue_lock;
	spinlock_t dequeue_lock;
	struct semaphore queue_empty;
	struct semaphore queue_full;
};

static inline void enqueue_wake_up (struct wake_up_buffer *buf, 
		struct sleeping_syscall_request *req) {
	int head;
	down_interruptible(&(buf->queue_full));
	spin_lock(&(buf->enqueue_lock));
	head = buf->queue_head;

	buf->wake_up_queue[head] = req;

	smp_wmb();
	buf->queue_head = (head + 1) & (MAX_WAKE_UP_BUFFER - 1);
	up(&(buf->queue_empty));
	spin_unlock(&(buf->enqueue_lock));
}

static inline struct sleeping_syscall_request *dequeue_wake_up(struct wake_up_buffer *buf) {
	struct sleeping_syscall_request *req;
	int tail;
	down_interruptible(&(buf->queue_empty));
	spin_lock(&(buf->dequeue_lock));
	tail = buf->queue_tail;

	smp_mb();
	req = buf->wake_up_queue[tail];

	smp_mb();
	buf->queue_head = (tail + 1) & (MAX_WAKE_UP_BUFFER - 1);
	up(&(buf->queue_full));
	spin_unlock(&(buf->dequeue_lock));

	return req;
}

static inline struct sleeping_syscall_request *peek_wake_up(struct wake_up_buffer *buf) {
	struct sleeping_syscall_request *req;
	int tail;
	spin_lock(&(buf->dequeue_lock));
	tail = buf->queue_tail;

	smp_mb();
	req = buf->wake_up_queue[tail];
	spin_unlock(&(buf->dequeue_lock));

	return req;
}
void wait_for_wakeup(struct task_struct *task, int syscall_id);
int notify_syscall_wakeup(struct task_struct *task, int syscall_id);

#endif /* !FT_COMMON_SYSCALL_MANAGEMENT_H */
