/*
 * linux/kernel/irq/handle.c
 *
 * Copyright (C) 1992, 1998-2004 Linus Torvalds, Ingo Molnar
 *
 * This file contains the core interrupt handling code.
 */

#include <linux/irq.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>

#include "internals.h"

/*
 * Linux has a controller-independent interrupt architecture.
 * Every controller has a 'controller-template', that is used
 * by the main code to do the right thing. Each driver-visible
 * interrupt source is transparently wired to the appropriate
 * controller. Thus drivers need not be aware of the
 * interrupt-controller.
 *
 * The code is designed to be easily extended with new/different
 * interrupt controllers, without having to do assembly magic or
 * having to touch the generic code.
 *
 * Controller mappings for all interrupt sources:
 */
struct irq_desc irq_desc[NR_IRQS] __cacheline_aligned = {
	[0 ... NR_IRQS-1] = {
		.status = IRQ_DISABLED,
		.chip = &no_irq_type,
		.depth = 1,
		.lock = SPIN_LOCK_UNLOCKED,
#ifdef CONFIG_SMP
		.affinity = CPU_MASK_ALL
#endif
	}
};

/*
 * What should we do if we get a hw irq event on an illegal vector?
 * Each architecture has to answer this themself.
 */
static void ack_bad(unsigned int irq)
{
	ack_bad_irq(irq);
}

/*
 * NOP functions
 */
static void noop(unsigned int irq)
{
}

static unsigned int noop_ret(unsigned int irq)
{
	return 0;
}

/*
 * Generic no controller implementation
 */
struct hw_interrupt_type no_irq_type = {
	.typename	= "none",
	.startup	= noop_ret,
	.shutdown	= noop,
	.enable		= noop,
	.disable	= noop,
	.ack		= ack_bad,
	.end		= noop,
};

/*
 * Special, empty irq handler:
 */
irqreturn_t no_action(int cpl, void *dev_id, struct pt_regs *regs)
{
	return IRQ_NONE;
}

/**
 * handle_IRQ_event - irq action chain handler
 * @irq:	the interrupt number
 * @regs:	pointer to a register structure
 * @action:	the interrupt action chain for this irq
 *
 * Handles the action chain of an irq event
 */
irqreturn_t handle_IRQ_event(unsigned int irq, struct pt_regs *regs,
			     struct irqaction *action)
{
	irqreturn_t ret, retval = IRQ_NONE;
	unsigned int status = 0;

	if (!(action->flags & SA_INTERRUPT))
		local_irq_enable();

	do {
		ret = action->handler(irq, action->dev_id, regs);
		if (ret == IRQ_HANDLED)
			status |= action->flags;
		retval |= ret;
		action = action->next;
	} while (action);

	if (status & SA_SAMPLE_RANDOM)
		add_interrupt_randomness(irq);
	local_irq_disable();

	return retval;
}

/**
 * __do_IRQ - original all in one highlevel IRQ handler
 * @irq:	the interrupt number
 * @regs:	pointer to a register structure
 *
 * __do_IRQ handles all normal device IRQ's (the special
 * SMP cross-CPU interrupts have their own specific
 * handlers).
 *
 * This is the original x86 implementation which is used for every
 * interrupt type.
 */
fastcall unsigned int __do_IRQ(unsigned int irq, struct pt_regs *regs)
{
	struct irq_desc *desc = irq_desc + irq;
	struct irqaction *action;
	unsigned int status;

	kstat_this_cpu.irqs[irq]++;
	if (CHECK_IRQ_PER_CPU(desc->status)) {
		irqreturn_t action_ret;

		/*
		 * No locking required for CPU-local interrupts:
		 */
		if (desc->chip->ack)
			desc->chip->ack(irq);
		action_ret = handle_IRQ_event(irq, regs, desc->action);
		desc->chip->end(irq);
		return 1;
	}

	spin_lock(&desc->lock);
	if (desc->chip->ack)
		desc->chip->ack(irq);
	/*
	 * REPLAY is when Linux resends an IRQ that was dropped earlier
	 * WAITING is used by probe to mark irqs that are being tested
	 */
	status = desc->status & ~(IRQ_REPLAY | IRQ_WAITING);
	status |= IRQ_PENDING; /* we _want_ to handle it */

	/*
	 * If the IRQ is disabled for whatever reason, we cannot
	 * use the action we have.
	 */
	action = NULL;
	if (likely(!(status & (IRQ_DISABLED | IRQ_INPROGRESS)))) {
		action = desc->action;
		status &= ~IRQ_PENDING; /* we commit to handling */
		status |= IRQ_INPROGRESS; /* we are handling it */
	}
	desc->status = status;

	/*
	 * If there is no IRQ handler or it was disabled, exit early.
	 * Since we set PENDING, if another processor is handling
	 * a different instance of this same irq, the other processor
	 * will take care of it.
	 */
	if (unlikely(!action))
		goto out;

	/*
	 * Edge triggered interrupts need to remember
	 * pending events.
	 * This applies to any hw interrupts that allow a second
	 * instance of the same irq to arrive while we are in do_IRQ
	 * or in the handler. But the code here only handles the _second_
	 * instance of the irq, not the third or fourth. So it is mostly
	 * useful for irq hardware that does not mask cleanly in an
	 * SMP environment.
	 */
	for (;;) {
		irqreturn_t action_ret;

		spin_unlock(&desc->lock);

		action_ret = handle_IRQ_event(irq, regs, action);

		spin_lock(&desc->lock);
		if (!noirqdebug)
			note_interrupt(irq, desc, action_ret, regs);
		if (likely(!(desc->status & IRQ_PENDING)))
			break;
		desc->status &= ~IRQ_PENDING;
	}
	desc->status &= ~IRQ_INPROGRESS;

out:
	/*
	 * The ->end() handler has to deal with interrupts which got
	 * disabled while the handler was running.
	 */
	desc->chip->end(irq);
	spin_unlock(&desc->lock);

	return 1;
}

