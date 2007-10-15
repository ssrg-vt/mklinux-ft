/*
 * Completely Fair Scheduling (CFS) Class (SCHED_NORMAL/SCHED_BATCH)
 *
 *  Copyright (C) 2007 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *
 *  Interactivity improvements by Mike Galbraith
 *  (C) 2007 Mike Galbraith <efault@gmx.de>
 *
 *  Various enhancements by Dmitry Adamushko.
 *  (C) 2007 Dmitry Adamushko <dmitry.adamushko@gmail.com>
 *
 *  Group scheduling enhancements by Srivatsa Vaddagiri
 *  Copyright IBM Corporation, 2007
 *  Author: Srivatsa Vaddagiri <vatsa@linux.vnet.ibm.com>
 *
 *  Scaled math optimizations by Thomas Gleixner
 *  Copyright (C) 2007, Thomas Gleixner <tglx@linutronix.de>
 *
 *  Adaptive scheduling granularity, math enhancements by Peter Zijlstra
 *  Copyright (C) 2007 Red Hat, Inc., Peter Zijlstra <pzijlstr@redhat.com>
 */

/*
 * Targeted preemption latency for CPU-bound tasks:
 * (default: 20ms, units: nanoseconds)
 *
 * NOTE: this latency value is not the same as the concept of
 * 'timeslice length' - timeslices in CFS are of variable length.
 * (to see the precise effective timeslice length of your workload,
 *  run vmstat and monitor the context-switches field)
 *
 * On SMP systems the value of this is multiplied by the log2 of the
 * number of CPUs. (i.e. factor 2x on 2-way systems, 3x on 4-way
 * systems, 4x on 8-way systems, 5x on 16-way systems, etc.)
 * Targeted preemption latency for CPU-bound tasks:
 */
const_debug unsigned int sysctl_sched_latency = 20000000ULL;

/*
 * After fork, child runs first. (default) If set to 0 then
 * parent will (try to) run first.
 */
const_debug unsigned int sysctl_sched_child_runs_first = 1;

/*
 * Minimal preemption granularity for CPU-bound tasks:
 * (default: 2 msec, units: nanoseconds)
 */
unsigned int sysctl_sched_min_granularity __read_mostly = 2000000ULL;

/*
 * sys_sched_yield() compat mode
 *
 * This option switches the agressive yield implementation of the
 * old scheduler back on.
 */
unsigned int __read_mostly sysctl_sched_compat_yield;

/*
 * SCHED_BATCH wake-up granularity.
 * (default: 25 msec, units: nanoseconds)
 *
 * This option delays the preemption effects of decoupled workloads
 * and reduces their over-scheduling. Synchronous workloads will still
 * have immediate wakeup/sleep latencies.
 */
const_debug unsigned int sysctl_sched_batch_wakeup_granularity = 25000000UL;

/*
 * SCHED_OTHER wake-up granularity.
 * (default: 1 msec, units: nanoseconds)
 *
 * This option delays the preemption effects of decoupled workloads
 * and reduces their over-scheduling. Synchronous workloads will still
 * have immediate wakeup/sleep latencies.
 */
const_debug unsigned int sysctl_sched_wakeup_granularity = 2000000UL;

unsigned int sysctl_sched_runtime_limit __read_mostly;

extern struct sched_class fair_sched_class;

/**************************************************************
 * CFS operations on generic schedulable entities:
 */

#ifdef CONFIG_FAIR_GROUP_SCHED

/* cpu runqueue to which this cfs_rq is attached */
static inline struct rq *rq_of(struct cfs_rq *cfs_rq)
{
	return cfs_rq->rq;
}

/* An entity is a task if it doesn't "own" a runqueue */
#define entity_is_task(se)	(!se->my_q)

#else	/* CONFIG_FAIR_GROUP_SCHED */

static inline struct rq *rq_of(struct cfs_rq *cfs_rq)
{
	return container_of(cfs_rq, struct rq, cfs);
}

#define entity_is_task(se)	1

#endif	/* CONFIG_FAIR_GROUP_SCHED */

static inline struct task_struct *task_of(struct sched_entity *se)
{
	return container_of(se, struct task_struct, se);
}


/**************************************************************
 * Scheduling class tree data structure manipulation methods:
 */

static inline u64
max_vruntime(u64 min_vruntime, u64 vruntime)
{
	if ((vruntime > min_vruntime) ||
	    (min_vruntime > (1ULL << 61) && vruntime < (1ULL << 50)))
		min_vruntime = vruntime;

	return min_vruntime;
}

static inline void
set_leftmost(struct cfs_rq *cfs_rq, struct rb_node *leftmost)
{
	struct sched_entity *se;

	cfs_rq->rb_leftmost = leftmost;
	if (leftmost)
		se = rb_entry(leftmost, struct sched_entity, run_node);
}

static inline s64
entity_key(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	return se->vruntime - cfs_rq->min_vruntime;
}

/*
 * Enqueue an entity into the rb-tree:
 */
static void
__enqueue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	struct rb_node **link = &cfs_rq->tasks_timeline.rb_node;
	struct rb_node *parent = NULL;
	struct sched_entity *entry;
	s64 key = entity_key(cfs_rq, se);
	int leftmost = 1;

	/*
	 * Find the right place in the rbtree:
	 */
	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct sched_entity, run_node);
		/*
		 * We dont care about collisions. Nodes with
		 * the same key stay together.
		 */
		if (key < entity_key(cfs_rq, entry)) {
			link = &parent->rb_left;
		} else {
			link = &parent->rb_right;
			leftmost = 0;
		}
	}

	/*
	 * Maintain a cache of leftmost tree entries (it is frequently
	 * used):
	 */
	if (leftmost)
		set_leftmost(cfs_rq, &se->run_node);

	rb_link_node(&se->run_node, parent, link);
	rb_insert_color(&se->run_node, &cfs_rq->tasks_timeline);
}

static void
__dequeue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	if (cfs_rq->rb_leftmost == &se->run_node)
		set_leftmost(cfs_rq, rb_next(&se->run_node));

	rb_erase(&se->run_node, &cfs_rq->tasks_timeline);
}

static inline struct rb_node *first_fair(struct cfs_rq *cfs_rq)
{
	return cfs_rq->rb_leftmost;
}

static struct sched_entity *__pick_next_entity(struct cfs_rq *cfs_rq)
{
	return rb_entry(first_fair(cfs_rq), struct sched_entity, run_node);
}

static inline struct sched_entity *__pick_last_entity(struct cfs_rq *cfs_rq)
{
	struct rb_node **link = &cfs_rq->tasks_timeline.rb_node;
	struct sched_entity *se = NULL;
	struct rb_node *parent;

	while (*link) {
		parent = *link;
		se = rb_entry(parent, struct sched_entity, run_node);
		link = &parent->rb_right;
	}

	return se;
}

/**************************************************************
 * Scheduling class statistics methods:
 */

static u64 __sched_period(unsigned long nr_running)
{
	u64 period = sysctl_sched_latency;
	unsigned long nr_latency =
		sysctl_sched_latency / sysctl_sched_min_granularity;

	if (unlikely(nr_running > nr_latency)) {
		period *= nr_running;
		do_div(period, nr_latency);
	}

	return period;
}

static u64 sched_slice(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	u64 period = __sched_period(cfs_rq->nr_running);

	period *= se->load.weight;
	do_div(period, cfs_rq->load.weight);

	return period;
}

/*
 * Update the current task's runtime statistics. Skip current tasks that
 * are not in our scheduling class.
 */
static inline void
__update_curr(struct cfs_rq *cfs_rq, struct sched_entity *curr,
	      unsigned long delta_exec)
{
	unsigned long delta_exec_weighted;
	u64 next_vruntime, min_vruntime;

	schedstat_set(curr->exec_max, max((u64)delta_exec, curr->exec_max));

	curr->sum_exec_runtime += delta_exec;
	schedstat_add(cfs_rq, exec_clock, delta_exec);
	delta_exec_weighted = delta_exec;
	if (unlikely(curr->load.weight != NICE_0_LOAD)) {
		delta_exec_weighted = calc_delta_fair(delta_exec_weighted,
							&curr->load);
	}
	curr->vruntime += delta_exec_weighted;

	/*
	 * maintain cfs_rq->min_vruntime to be a monotonic increasing
	 * value tracking the leftmost vruntime in the tree.
	 */
	if (first_fair(cfs_rq)) {
		next_vruntime = __pick_next_entity(cfs_rq)->vruntime;

		/* min_vruntime() := !max_vruntime() */
		min_vruntime = max_vruntime(curr->vruntime, next_vruntime);
		if (min_vruntime == next_vruntime)
			min_vruntime = curr->vruntime;
		else
			min_vruntime = next_vruntime;
	} else
		min_vruntime = curr->vruntime;

	cfs_rq->min_vruntime =
		max_vruntime(cfs_rq->min_vruntime, min_vruntime);
}

static void update_curr(struct cfs_rq *cfs_rq)
{
	struct sched_entity *curr = cfs_rq->curr;
	u64 now = rq_of(cfs_rq)->clock;
	unsigned long delta_exec;

	if (unlikely(!curr))
		return;

	/*
	 * Get the amount of time the current task was running
	 * since the last time we changed load (this cannot
	 * overflow on 32 bits):
	 */
	delta_exec = (unsigned long)(now - curr->exec_start);

	__update_curr(cfs_rq, curr, delta_exec);
	curr->exec_start = now;
}

static inline void
update_stats_wait_start(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	schedstat_set(se->wait_start, rq_of(cfs_rq)->clock);
}

static inline unsigned long
calc_weighted(unsigned long delta, struct sched_entity *se)
{
	unsigned long weight = se->load.weight;

	if (unlikely(weight != NICE_0_LOAD))
		return (u64)delta * se->load.weight >> NICE_0_SHIFT;
	else
		return delta;
}

/*
 * Task is being enqueued - update stats:
 */
static void update_stats_enqueue(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	/*
	 * Are we enqueueing a waiting task? (for current tasks
	 * a dequeue/enqueue event is a NOP)
	 */
	if (se != cfs_rq->curr)
		update_stats_wait_start(cfs_rq, se);
}

static void
update_stats_wait_end(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	schedstat_set(se->wait_max, max(se->wait_max,
			rq_of(cfs_rq)->clock - se->wait_start));
	schedstat_set(se->wait_start, 0);
}

static inline void
update_stats_dequeue(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	update_curr(cfs_rq);
	/*
	 * Mark the end of the wait period if dequeueing a
	 * waiting task:
	 */
	if (se != cfs_rq->curr)
		update_stats_wait_end(cfs_rq, se);
}

/*
 * We are picking a new current task - update its stats:
 */
static inline void
update_stats_curr_start(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	/*
	 * We are starting a new run period:
	 */
	se->exec_start = rq_of(cfs_rq)->clock;
}

/*
 * We are descheduling a task - update its stats:
 */
static inline void
update_stats_curr_end(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	se->exec_start = 0;
}

/**************************************************
 * Scheduling class queueing methods:
 */

static void
account_entity_enqueue(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	update_load_add(&cfs_rq->load, se->load.weight);
	cfs_rq->nr_running++;
	se->on_rq = 1;
}

static void
account_entity_dequeue(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	update_load_sub(&cfs_rq->load, se->load.weight);
	cfs_rq->nr_running--;
	se->on_rq = 0;
}

static void enqueue_sleeper(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
#ifdef CONFIG_SCHEDSTATS
	if (se->sleep_start) {
		u64 delta = rq_of(cfs_rq)->clock - se->sleep_start;

		if ((s64)delta < 0)
			delta = 0;

		if (unlikely(delta > se->sleep_max))
			se->sleep_max = delta;

		se->sleep_start = 0;
		se->sum_sleep_runtime += delta;
	}
	if (se->block_start) {
		u64 delta = rq_of(cfs_rq)->clock - se->block_start;

		if ((s64)delta < 0)
			delta = 0;

		if (unlikely(delta > se->block_max))
			se->block_max = delta;

		se->block_start = 0;
		se->sum_sleep_runtime += delta;

		/*
		 * Blocking time is in units of nanosecs, so shift by 20 to
		 * get a milliseconds-range estimation of the amount of
		 * time that the task spent sleeping:
		 */
		if (unlikely(prof_on == SLEEP_PROFILING)) {
			struct task_struct *tsk = task_of(se);

			profile_hits(SLEEP_PROFILING, (void *)get_wchan(tsk),
				     delta >> 20);
		}
	}
#endif
}

static void
place_entity(struct cfs_rq *cfs_rq, struct sched_entity *se, int initial)
{
	u64 min_runtime, latency;

	min_runtime = cfs_rq->min_vruntime;

	if (sched_feat(USE_TREE_AVG)) {
		struct sched_entity *last = __pick_last_entity(cfs_rq);
		if (last) {
			min_runtime = __pick_next_entity(cfs_rq)->vruntime;
			min_runtime += last->vruntime;
			min_runtime >>= 1;
		}
	} else if (sched_feat(APPROX_AVG))
		min_runtime += sysctl_sched_latency/2;

	if (initial && sched_feat(START_DEBIT))
		min_runtime += sched_slice(cfs_rq, se);

	if (!initial && sched_feat(NEW_FAIR_SLEEPERS)) {
		latency = sysctl_sched_latency;
		if (min_runtime > latency)
			min_runtime -= latency;
		else
			min_runtime = 0;
	}

	se->vruntime = max(se->vruntime, min_runtime);
}

static void
enqueue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se,
		int wakeup, int set_curr)
{
	/*
 	 * In case of the 'current'.
 	 */
	if (unlikely(set_curr)) {
		update_stats_curr_start(cfs_rq, se);
		cfs_rq->curr = se;
		account_entity_enqueue(cfs_rq, se);
		return;
	}

	/*
	 * Update the fair clock.
	 */
	update_curr(cfs_rq);

	if (wakeup) {
		place_entity(cfs_rq, se, 0);
		enqueue_sleeper(cfs_rq, se);
	}

	update_stats_enqueue(cfs_rq, se);
	__enqueue_entity(cfs_rq, se);
	account_entity_enqueue(cfs_rq, se);
}

static void
dequeue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se, int sleep)
{
	update_stats_dequeue(cfs_rq, se);
#ifdef CONFIG_SCHEDSTATS
	if (sleep) {
		if (entity_is_task(se)) {
			struct task_struct *tsk = task_of(se);

			if (tsk->state & TASK_INTERRUPTIBLE)
				se->sleep_start = rq_of(cfs_rq)->clock;
			if (tsk->state & TASK_UNINTERRUPTIBLE)
				se->block_start = rq_of(cfs_rq)->clock;
		}
	}
#endif
	if (likely(se != cfs_rq->curr))
		__dequeue_entity(cfs_rq, se);
	else {
		update_stats_curr_end(cfs_rq, se);
		cfs_rq->curr = NULL;
	}
	account_entity_dequeue(cfs_rq, se);
}

/*
 * Preempt the current task with a newly woken task if needed:
 */
static void
check_preempt_tick(struct cfs_rq *cfs_rq, struct sched_entity *curr)
{
	unsigned long ideal_runtime, delta_exec;

	ideal_runtime = sched_slice(cfs_rq, curr);
	delta_exec = curr->sum_exec_runtime - curr->prev_sum_exec_runtime;
	if (delta_exec > ideal_runtime)
		resched_task(rq_of(cfs_rq)->curr);
}

static inline void
set_next_entity(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	/*
	 * Any task has to be enqueued before it get to execute on
	 * a CPU. So account for the time it spent waiting on the
	 * runqueue.
	 */
	update_stats_wait_end(cfs_rq, se);
	update_stats_curr_start(cfs_rq, se);
	cfs_rq->curr = se;
#ifdef CONFIG_SCHEDSTATS
	/*
	 * Track our maximum slice length, if the CPU's load is at
	 * least twice that of our own weight (i.e. dont track it
	 * when there are only lesser-weight tasks around):
	 */
	if (rq_of(cfs_rq)->load.weight >= 2*se->load.weight) {
		se->slice_max = max(se->slice_max,
			se->sum_exec_runtime - se->prev_sum_exec_runtime);
	}
#endif
	se->prev_sum_exec_runtime = se->sum_exec_runtime;
}

static struct sched_entity *pick_next_entity(struct cfs_rq *cfs_rq)
{
	struct sched_entity *se = __pick_next_entity(cfs_rq);

	/* 'current' is not kept within the tree. */
	if (se)
		__dequeue_entity(cfs_rq, se);

	set_next_entity(cfs_rq, se);

	return se;
}

static void put_prev_entity(struct cfs_rq *cfs_rq, struct sched_entity *prev)
{
	/*
	 * If still on the runqueue then deactivate_task()
	 * was not called and update_curr() has to be done:
	 */
	if (prev->on_rq)
		update_curr(cfs_rq);

	update_stats_curr_end(cfs_rq, prev);

	if (prev->on_rq) {
		update_stats_wait_start(cfs_rq, prev);
		/* Put 'current' back into the tree. */
		__enqueue_entity(cfs_rq, prev);
	}
	cfs_rq->curr = NULL;
}

static void entity_tick(struct cfs_rq *cfs_rq, struct sched_entity *curr)
{
	/*
	 * Update run-time statistics of the 'current'.
	 */
	update_curr(cfs_rq);

	if (cfs_rq->nr_running > 1)
		check_preempt_tick(cfs_rq, curr);
}

/**************************************************
 * CFS operations on tasks:
 */

#ifdef CONFIG_FAIR_GROUP_SCHED

/* Walk up scheduling entities hierarchy */
#define for_each_sched_entity(se) \
		for (; se; se = se->parent)

static inline struct cfs_rq *task_cfs_rq(struct task_struct *p)
{
	return p->se.cfs_rq;
}

/* runqueue on which this entity is (to be) queued */
static inline struct cfs_rq *cfs_rq_of(struct sched_entity *se)
{
	return se->cfs_rq;
}

/* runqueue "owned" by this group */
static inline struct cfs_rq *group_cfs_rq(struct sched_entity *grp)
{
	return grp->my_q;
}

/* Given a group's cfs_rq on one cpu, return its corresponding cfs_rq on
 * another cpu ('this_cpu')
 */
static inline struct cfs_rq *cpu_cfs_rq(struct cfs_rq *cfs_rq, int this_cpu)
{
	return cfs_rq->tg->cfs_rq[this_cpu];
}

/* Iterate thr' all leaf cfs_rq's on a runqueue */
#define for_each_leaf_cfs_rq(rq, cfs_rq) \
	list_for_each_entry(cfs_rq, &rq->leaf_cfs_rq_list, leaf_cfs_rq_list)

/* Do the two (enqueued) tasks belong to the same group ? */
static inline int is_same_group(struct task_struct *curr, struct task_struct *p)
{
	if (curr->se.cfs_rq == p->se.cfs_rq)
		return 1;

	return 0;
}

#else	/* CONFIG_FAIR_GROUP_SCHED */

#define for_each_sched_entity(se) \
		for (; se; se = NULL)

static inline struct cfs_rq *task_cfs_rq(struct task_struct *p)
{
	return &task_rq(p)->cfs;
}

static inline struct cfs_rq *cfs_rq_of(struct sched_entity *se)
{
	struct task_struct *p = task_of(se);
	struct rq *rq = task_rq(p);

	return &rq->cfs;
}

/* runqueue "owned" by this group */
static inline struct cfs_rq *group_cfs_rq(struct sched_entity *grp)
{
	return NULL;
}

static inline struct cfs_rq *cpu_cfs_rq(struct cfs_rq *cfs_rq, int this_cpu)
{
	return &cpu_rq(this_cpu)->cfs;
}

#define for_each_leaf_cfs_rq(rq, cfs_rq) \
		for (cfs_rq = &rq->cfs; cfs_rq; cfs_rq = NULL)

static inline int is_same_group(struct task_struct *curr, struct task_struct *p)
{
	return 1;
}

#endif	/* CONFIG_FAIR_GROUP_SCHED */

/*
 * The enqueue_task method is called before nr_running is
 * increased. Here we update the fair scheduling stats and
 * then put the task into the rbtree:
 */
static void enqueue_task_fair(struct rq *rq, struct task_struct *p, int wakeup)
{
	struct cfs_rq *cfs_rq;
	struct sched_entity *se = &p->se;
	int set_curr = 0;

	/* Are we enqueuing the current task? */
	if (unlikely(task_running(rq, p)))
		set_curr = 1;

	for_each_sched_entity(se) {
		if (se->on_rq)
			break;
		cfs_rq = cfs_rq_of(se);
		enqueue_entity(cfs_rq, se, wakeup, set_curr);
	}
}

/*
 * The dequeue_task method is called before nr_running is
 * decreased. We remove the task from the rbtree and
 * update the fair scheduling stats:
 */
static void dequeue_task_fair(struct rq *rq, struct task_struct *p, int sleep)
{
	struct cfs_rq *cfs_rq;
	struct sched_entity *se = &p->se;

	for_each_sched_entity(se) {
		cfs_rq = cfs_rq_of(se);
		dequeue_entity(cfs_rq, se, sleep);
		/* Don't dequeue parent if it has other entities besides us */
		if (cfs_rq->load.weight)
			break;
	}
}

/*
 * sched_yield() support is very simple - we dequeue and enqueue.
 *
 * If compat_yield is turned on then we requeue to the end of the tree.
 */
static void yield_task_fair(struct rq *rq)
{
	struct cfs_rq *cfs_rq = &rq->cfs;
	struct rb_node **link = &cfs_rq->tasks_timeline.rb_node;
	struct sched_entity *rightmost, *se = &rq->curr->se;
	struct rb_node *parent;

	/*
	 * Are we the only task in the tree?
	 */
	if (unlikely(cfs_rq->nr_running == 1))
		return;

	if (likely(!sysctl_sched_compat_yield)) {
		__update_rq_clock(rq);
		/*
		 * Dequeue and enqueue the task to update its
		 * position within the tree:
		 */
		dequeue_entity(cfs_rq, se, 0);
		enqueue_entity(cfs_rq, se, 0, 1);

		return;
	}
	/*
	 * Find the rightmost entry in the rbtree:
	 */
	do {
		parent = *link;
		link = &parent->rb_right;
	} while (*link);

	rightmost = rb_entry(parent, struct sched_entity, run_node);
	/*
	 * Already in the rightmost position?
	 */
	if (unlikely(rightmost == se))
		return;

	/*
	 * Minimally necessary key value to be last in the tree:
	 */
	se->vruntime = rightmost->vruntime + 1;

	if (cfs_rq->rb_leftmost == &se->run_node)
		cfs_rq->rb_leftmost = rb_next(&se->run_node);
	/*
	 * Relink the task to the rightmost position:
	 */
	rb_erase(&se->run_node, &cfs_rq->tasks_timeline);
	rb_link_node(&se->run_node, parent, link);
	rb_insert_color(&se->run_node, &cfs_rq->tasks_timeline);
}

/*
 * Preempt the current task with a newly woken task if needed:
 */
static void check_preempt_wakeup(struct rq *rq, struct task_struct *p)
{
	struct task_struct *curr = rq->curr;
	struct cfs_rq *cfs_rq = task_cfs_rq(curr);

	if (unlikely(rt_prio(p->prio))) {
		update_rq_clock(rq);
		update_curr(cfs_rq);
		resched_task(curr);
		return;
	}
	if (is_same_group(curr, p)) {
		s64 delta = curr->se.vruntime - p->se.vruntime;

		if (delta > (s64)sysctl_sched_wakeup_granularity)
			resched_task(curr);
	}
}

static struct task_struct *pick_next_task_fair(struct rq *rq)
{
	struct cfs_rq *cfs_rq = &rq->cfs;
	struct sched_entity *se;

	if (unlikely(!cfs_rq->nr_running))
		return NULL;

	do {
		se = pick_next_entity(cfs_rq);
		cfs_rq = group_cfs_rq(se);
	} while (cfs_rq);

	return task_of(se);
}

/*
 * Account for a descheduled task:
 */
static void put_prev_task_fair(struct rq *rq, struct task_struct *prev)
{
	struct sched_entity *se = &prev->se;
	struct cfs_rq *cfs_rq;

	for_each_sched_entity(se) {
		cfs_rq = cfs_rq_of(se);
		put_prev_entity(cfs_rq, se);
	}
}

/**************************************************
 * Fair scheduling class load-balancing methods:
 */

/*
 * Load-balancing iterator. Note: while the runqueue stays locked
 * during the whole iteration, the current task might be
 * dequeued so the iterator has to be dequeue-safe. Here we
 * achieve that by always pre-iterating before returning
 * the current task:
 */
static inline struct task_struct *
__load_balance_iterator(struct cfs_rq *cfs_rq, struct rb_node *curr)
{
	struct task_struct *p;

	if (!curr)
		return NULL;

	p = rb_entry(curr, struct task_struct, se.run_node);
	cfs_rq->rb_load_balance_curr = rb_next(curr);

	return p;
}

static struct task_struct *load_balance_start_fair(void *arg)
{
	struct cfs_rq *cfs_rq = arg;

	return __load_balance_iterator(cfs_rq, first_fair(cfs_rq));
}

static struct task_struct *load_balance_next_fair(void *arg)
{
	struct cfs_rq *cfs_rq = arg;

	return __load_balance_iterator(cfs_rq, cfs_rq->rb_load_balance_curr);
}

#ifdef CONFIG_FAIR_GROUP_SCHED
static int cfs_rq_best_prio(struct cfs_rq *cfs_rq)
{
	struct sched_entity *curr;
	struct task_struct *p;

	if (!cfs_rq->nr_running)
		return MAX_PRIO;

	curr = __pick_next_entity(cfs_rq);
	p = task_of(curr);

	return p->prio;
}
#endif

static unsigned long
load_balance_fair(struct rq *this_rq, int this_cpu, struct rq *busiest,
		  unsigned long max_nr_move, unsigned long max_load_move,
		  struct sched_domain *sd, enum cpu_idle_type idle,
		  int *all_pinned, int *this_best_prio)
{
	struct cfs_rq *busy_cfs_rq;
	unsigned long load_moved, total_nr_moved = 0, nr_moved;
	long rem_load_move = max_load_move;
	struct rq_iterator cfs_rq_iterator;

	cfs_rq_iterator.start = load_balance_start_fair;
	cfs_rq_iterator.next = load_balance_next_fair;

	for_each_leaf_cfs_rq(busiest, busy_cfs_rq) {
#ifdef CONFIG_FAIR_GROUP_SCHED
		struct cfs_rq *this_cfs_rq;
		long imbalance;
		unsigned long maxload;

		this_cfs_rq = cpu_cfs_rq(busy_cfs_rq, this_cpu);

		imbalance = busy_cfs_rq->load.weight - this_cfs_rq->load.weight;
		/* Don't pull if this_cfs_rq has more load than busy_cfs_rq */
		if (imbalance <= 0)
			continue;

		/* Don't pull more than imbalance/2 */
		imbalance /= 2;
		maxload = min(rem_load_move, imbalance);

		*this_best_prio = cfs_rq_best_prio(this_cfs_rq);
#else
# define maxload rem_load_move
#endif
		/* pass busy_cfs_rq argument into
		 * load_balance_[start|next]_fair iterators
		 */
		cfs_rq_iterator.arg = busy_cfs_rq;
		nr_moved = balance_tasks(this_rq, this_cpu, busiest,
				max_nr_move, maxload, sd, idle, all_pinned,
				&load_moved, this_best_prio, &cfs_rq_iterator);

		total_nr_moved += nr_moved;
		max_nr_move -= nr_moved;
		rem_load_move -= load_moved;

		if (max_nr_move <= 0 || rem_load_move <= 0)
			break;
	}

	return max_load_move - rem_load_move;
}

/*
 * scheduler tick hitting a task of our scheduling class:
 */
static void task_tick_fair(struct rq *rq, struct task_struct *curr)
{
	struct cfs_rq *cfs_rq;
	struct sched_entity *se = &curr->se;

	for_each_sched_entity(se) {
		cfs_rq = cfs_rq_of(se);
		entity_tick(cfs_rq, se);
	}
}

#define swap(a,b) do { typeof(a) tmp = (a); (a) = (b); (b) = tmp; } while (0)

/*
 * Share the fairness runtime between parent and child, thus the
 * total amount of pressure for CPU stays equal - new tasks
 * get a chance to run but frequent forkers are not allowed to
 * monopolize the CPU. Note: the parent runqueue is locked,
 * the child is not running yet.
 */
static void task_new_fair(struct rq *rq, struct task_struct *p)
{
	struct cfs_rq *cfs_rq = task_cfs_rq(p);
	struct sched_entity *se = &p->se, *curr = cfs_rq->curr;

	sched_info_queued(p);

	update_curr(cfs_rq);
	place_entity(cfs_rq, se, 1);

	if (sysctl_sched_child_runs_first &&
			curr->vruntime < se->vruntime) {
		/*
 		 * Upon rescheduling, sched_class::put_prev_task() will place
 		 * 'current' within the tree based on its new key value.
 		 */
		swap(curr->vruntime, se->vruntime);
	}

	update_stats_enqueue(cfs_rq, se);
	__enqueue_entity(cfs_rq, se);
	account_entity_enqueue(cfs_rq, se);
	resched_task(rq->curr);
}

/*
 * All the scheduling class methods:
 */
struct sched_class fair_sched_class __read_mostly = {
	.enqueue_task		= enqueue_task_fair,
	.dequeue_task		= dequeue_task_fair,
	.yield_task		= yield_task_fair,

	.check_preempt_curr	= check_preempt_wakeup,

	.pick_next_task		= pick_next_task_fair,
	.put_prev_task		= put_prev_task_fair,

	.load_balance		= load_balance_fair,

	.task_tick		= task_tick_fair,
	.task_new		= task_new_fair,
};

#ifdef CONFIG_SCHED_DEBUG
static void print_cfs_stats(struct seq_file *m, int cpu)
{
	struct cfs_rq *cfs_rq;

	for_each_leaf_cfs_rq(cpu_rq(cpu), cfs_rq)
		print_cfs_rq(m, cpu, cfs_rq);
}
#endif
