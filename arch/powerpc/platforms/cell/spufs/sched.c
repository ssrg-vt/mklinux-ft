/* sched.c - SPU scheduler.
 *
 * Copyright (C) IBM 2005
 * Author: Mark Nutter <mnutter@us.ibm.com>
 *
 * 2006-03-31	NUMA domains added.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#undef DEBUG

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/completion.h>
#include <linux/vmalloc.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/numa.h>
#include <linux/mutex.h>
#include <linux/notifier.h>

#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/spu.h>
#include <asm/spu_csa.h>
#include <asm/spu_priv1.h>
#include "spufs.h"

#define SPU_MIN_TIMESLICE 	(100 * HZ / 1000)

#define SPU_BITMAP_SIZE (((MAX_PRIO+BITS_PER_LONG)/BITS_PER_LONG)+1)
struct spu_prio_array {
	unsigned long bitmap[SPU_BITMAP_SIZE];
	struct list_head runq[MAX_PRIO];
	spinlock_t runq_lock;
	struct list_head active_list[MAX_NUMNODES];
	struct mutex active_mutex[MAX_NUMNODES];
};

static struct spu_prio_array *spu_prio;

static inline int node_allowed(int node)
{
	cpumask_t mask;

	if (!nr_cpus_node(node))
		return 0;
	mask = node_to_cpumask(node);
	if (!cpus_intersects(mask, current->cpus_allowed))
		return 0;
	return 1;
}

/**
 * spu_add_to_active_list - add spu to active list
 * @spu:	spu to add to the active list
 */
static void spu_add_to_active_list(struct spu *spu)
{
	mutex_lock(&spu_prio->active_mutex[spu->node]);
	list_add_tail(&spu->list, &spu_prio->active_list[spu->node]);
	mutex_unlock(&spu_prio->active_mutex[spu->node]);
}

/**
 * spu_remove_from_active_list - remove spu from active list
 * @spu:       spu to remove from the active list
 */
static void spu_remove_from_active_list(struct spu *spu)
{
	int node = spu->node;

	mutex_lock(&spu_prio->active_mutex[node]);
	list_del_init(&spu->list);
	mutex_unlock(&spu_prio->active_mutex[node]);
}

static inline void mm_needs_global_tlbie(struct mm_struct *mm)
{
	int nr = (NR_CPUS > 1) ? NR_CPUS : NR_CPUS + 1;

	/* Global TLBIE broadcast required with SPEs. */
	__cpus_setall(&mm->cpu_vm_mask, nr);
}

static BLOCKING_NOTIFIER_HEAD(spu_switch_notifier);

static void spu_switch_notify(struct spu *spu, struct spu_context *ctx)
{
	blocking_notifier_call_chain(&spu_switch_notifier,
			    ctx ? ctx->object_id : 0, spu);
}

int spu_switch_event_register(struct notifier_block * n)
{
	return blocking_notifier_chain_register(&spu_switch_notifier, n);
}

int spu_switch_event_unregister(struct notifier_block * n)
{
	return blocking_notifier_chain_unregister(&spu_switch_notifier, n);
}

/**
 * spu_bind_context - bind spu context to physical spu
 * @spu:	physical spu to bind to
 * @ctx:	context to bind
 */
static void spu_bind_context(struct spu *spu, struct spu_context *ctx)
{
	pr_debug("%s: pid=%d SPU=%d NODE=%d\n", __FUNCTION__, current->pid,
		 spu->number, spu->node);
	spu->ctx = ctx;
	spu->flags = 0;
	ctx->spu = spu;
	ctx->ops = &spu_hw_ops;
	spu->pid = current->pid;
	spu->mm = ctx->owner;
	mm_needs_global_tlbie(spu->mm);
	spu->ibox_callback = spufs_ibox_callback;
	spu->wbox_callback = spufs_wbox_callback;
	spu->stop_callback = spufs_stop_callback;
	spu->mfc_callback = spufs_mfc_callback;
	spu->dma_callback = spufs_dma_callback;
	mb();
	spu_unmap_mappings(ctx);
	spu_restore(&ctx->csa, spu);
	spu->timestamp = jiffies;
	spu_cpu_affinity_set(spu, raw_smp_processor_id());
	spu_switch_notify(spu, ctx);
	spu_add_to_active_list(spu);
	ctx->state = SPU_STATE_RUNNABLE;
}

/**
 * spu_unbind_context - unbind spu context from physical spu
 * @spu:	physical spu to unbind from
 * @ctx:	context to unbind
 */
static void spu_unbind_context(struct spu *spu, struct spu_context *ctx)
{
	pr_debug("%s: unbind pid=%d SPU=%d NODE=%d\n", __FUNCTION__,
		 spu->pid, spu->number, spu->node);

	spu_remove_from_active_list(spu);
	spu_switch_notify(spu, NULL);
	spu_unmap_mappings(ctx);
	spu_save(&ctx->csa, spu);
	spu->timestamp = jiffies;
	ctx->state = SPU_STATE_SAVED;
	spu->ibox_callback = NULL;
	spu->wbox_callback = NULL;
	spu->stop_callback = NULL;
	spu->mfc_callback = NULL;
	spu->dma_callback = NULL;
	spu->mm = NULL;
	spu->pid = 0;
	ctx->ops = &spu_backing_ops;
	ctx->spu = NULL;
	spu->flags = 0;
	spu->ctx = NULL;
}

/**
 * spu_add_to_rq - add a context to the runqueue
 * @ctx:       context to add
 */
static void spu_add_to_rq(struct spu_context *ctx)
{
	spin_lock(&spu_prio->runq_lock);
	list_add_tail(&ctx->rq, &spu_prio->runq[ctx->prio]);
	set_bit(ctx->prio, spu_prio->bitmap);
	spin_unlock(&spu_prio->runq_lock);
}

/**
 * spu_del_from_rq - remove a context from the runqueue
 * @ctx:       context to remove
 */
static void spu_del_from_rq(struct spu_context *ctx)
{
	spin_lock(&spu_prio->runq_lock);
	list_del_init(&ctx->rq);
	if (list_empty(&spu_prio->runq[ctx->prio]))
		clear_bit(ctx->prio, spu_prio->bitmap);
	spin_unlock(&spu_prio->runq_lock);
}

/**
 * spu_grab_context - remove one context from the runqueue
 * @prio:      priority of the context to be removed
 *
 * This function removes one context from the runqueue for priority @prio.
 * If there is more than one context with the given priority the first
 * task on the runqueue will be taken.
 *
 * Returns the spu_context it just removed.
 *
 * Must be called with spu_prio->runq_lock held.
 */
static struct spu_context *spu_grab_context(int prio)
{
	struct list_head *rq = &spu_prio->runq[prio];

	if (list_empty(rq))
		return NULL;
	return list_entry(rq->next, struct spu_context, rq);
}

static void spu_prio_wait(struct spu_context *ctx)
{
	DEFINE_WAIT(wait);

	set_bit(SPU_SCHED_WAKE, &ctx->sched_flags);
	prepare_to_wait_exclusive(&ctx->stop_wq, &wait, TASK_INTERRUPTIBLE);
	if (!signal_pending(current)) {
		mutex_unlock(&ctx->state_mutex);
		schedule();
		mutex_lock(&ctx->state_mutex);
	}
	__set_current_state(TASK_RUNNING);
	remove_wait_queue(&ctx->stop_wq, &wait);
	clear_bit(SPU_SCHED_WAKE, &ctx->sched_flags);
}

/**
 * spu_reschedule - try to find a runnable context for a spu
 * @spu:       spu available
 *
 * This function is called whenever a spu becomes idle.  It looks for the
 * most suitable runnable spu context and schedules it for execution.
 */
static void spu_reschedule(struct spu *spu)
{
	int best;

	spu_free(spu);

	spin_lock(&spu_prio->runq_lock);
	best = sched_find_first_bit(spu_prio->bitmap);
	if (best < MAX_PRIO) {
		struct spu_context *ctx = spu_grab_context(best);
		if (ctx && test_bit(SPU_SCHED_WAKE, &ctx->sched_flags))
			wake_up(&ctx->stop_wq);
	}
	spin_unlock(&spu_prio->runq_lock);
}

static struct spu *spu_get_idle(struct spu_context *ctx)
{
	struct spu *spu = NULL;
	int node = cpu_to_node(raw_smp_processor_id());
	int n;

	for (n = 0; n < MAX_NUMNODES; n++, node++) {
		node = (node < MAX_NUMNODES) ? node : 0;
		if (!node_allowed(node))
			continue;
		spu = spu_alloc_node(node);
		if (spu)
			break;
	}
	return spu;
}

/* The three externally callable interfaces
 * for the scheduler begin here.
 *
 *	spu_activate	- bind a context to SPU, waiting as needed.
 *	spu_deactivate	- unbind a context from its SPU.
 *	spu_yield	- yield an SPU if others are waiting.
 */

/**
 * spu_activate - find a free spu for a context and execute it
 * @ctx:	spu context to schedule
 * @flags:	flags (currently ignored)
 *
 * Tries to find a free spu to run @ctx.  If no free spu is availble
 * add the context to the runqueue so it gets woken up once an spu
 * is available.
 */
int spu_activate(struct spu_context *ctx, unsigned long flags)
{

	if (ctx->spu)
		return 0;

	do {
		struct spu *spu;

		spu = spu_get_idle(ctx);
		if (spu) {
			spu_bind_context(spu, ctx);
			return 0;
		}

		spu_add_to_rq(ctx);
		if (!(flags & SPU_ACTIVATE_NOWAKE))
			spu_prio_wait(ctx);
		spu_del_from_rq(ctx);
	} while (!signal_pending(current));

	return -ERESTARTSYS;
}

/**
 * spu_deactivate - unbind a context from it's physical spu
 * @ctx:	spu context to unbind
 *
 * Unbind @ctx from the physical spu it is running on and schedule
 * the highest priority context to run on the freed physical spu.
 */
void spu_deactivate(struct spu_context *ctx)
{
	struct spu *spu = ctx->spu;

	if (spu) {
		spu_unbind_context(spu, ctx);
		spu_reschedule(spu);
	}
}

void spu_yield(struct spu_context *ctx)
{
	struct spu *spu;
	int need_yield = 0;

	if (mutex_trylock(&ctx->state_mutex)) {
		if ((spu = ctx->spu) != NULL) {
			int best = sched_find_first_bit(spu_prio->bitmap);
			if (best < MAX_PRIO) {
				pr_debug("%s: yielding SPU %d NODE %d\n",
					 __FUNCTION__, spu->number, spu->node);
				spu_deactivate(ctx);
				need_yield = 1;
			}
		}
		mutex_unlock(&ctx->state_mutex);
	}
	if (unlikely(need_yield))
		yield();
}

int __init spu_sched_init(void)
{
	int i;

	spu_prio = kzalloc(sizeof(struct spu_prio_array), GFP_KERNEL);
	if (!spu_prio) {
		printk(KERN_WARNING "%s: Unable to allocate priority queue.\n",
		       __FUNCTION__);
		return 1;
	}
	for (i = 0; i < MAX_PRIO; i++) {
		INIT_LIST_HEAD(&spu_prio->runq[i]);
		__clear_bit(i, spu_prio->bitmap);
	}
	__set_bit(MAX_PRIO, spu_prio->bitmap);
	for (i = 0; i < MAX_NUMNODES; i++) {
		mutex_init(&spu_prio->active_mutex[i]);
		INIT_LIST_HEAD(&spu_prio->active_list[i]);
	}
	spin_lock_init(&spu_prio->runq_lock);
	return 0;
}

void __exit spu_sched_exit(void)
{
	struct spu *spu, *tmp;
	int node;

	for (node = 0; node < MAX_NUMNODES; node++) {
		mutex_lock(&spu_prio->active_mutex[node]);
		list_for_each_entry_safe(spu, tmp, &spu_prio->active_list[node],
					 list) {
			list_del_init(&spu->list);
			spu_free(spu);
		}
		mutex_unlock(&spu_prio->active_mutex[node]);
	}
	kfree(spu_prio);
}
