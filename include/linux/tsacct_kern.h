/*
 * tsacct_kern.h - kernel header for system accounting over taskstats interface
 *
 * Copyright (C) Jay Lan	SGI
 */

#ifndef _LINUX_TSACCT_KERN_H
#define _LINUX_TSACCT_KERN_H

#include <linux/taskstats.h>

#ifdef CONFIG_TASKSTATS
extern void bacct_add_tsk(struct taskstats *stats, struct task_struct *tsk);
#else
static inline void bacct_add_tsk(struct taskstats *stats, struct task_struct *tsk)
{}
#endif /* CONFIG_TASKSTATS */

#endif
