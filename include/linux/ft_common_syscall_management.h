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
#include <asm/unistd_64.h>

void wait_bump(struct task_struct *task);
void consume_pending_bump(struct task_struct *task);
int send_bump(struct task_struct *task, int id_syscall, uint64_t prev_tick, uint64_t new_tick);

#endif /* !FT_COMMON_SYSCALL_MANAGEMENT_H */
