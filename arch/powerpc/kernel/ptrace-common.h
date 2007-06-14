/*
 *    Copyright (c) 2002 Stephen Rothwell, IBM Coproration
 *    Copyright (c) 2007 Benjamin Herrenschmidt, IBM Coproration
 *    Extracted from ptrace.c and ptrace32.c
 *
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file README.legal in the main directory of
 * this archive for more details.
 */

#ifndef _POWERPC_PTRACE_COMMON_H
#define _POWERPC_PTRACE_COMMON_H

/*
 * Get contents of register REGNO in task TASK.
 */
static inline unsigned long get_reg(struct task_struct *task, int regno)
{
	unsigned long tmp = 0;

	if (task->thread.regs == NULL)
		return -EIO;

	if (regno == PT_MSR) {
		tmp = ((unsigned long *)task->thread.regs)[PT_MSR];
		return PT_MUNGE_MSR(tmp, task);
	}

	if (regno < (sizeof(struct pt_regs) / sizeof(unsigned long)))
		return ((unsigned long *)task->thread.regs)[regno];

	return -EIO;
}

/*
 * Write contents of register REGNO in task TASK.
 */
static inline int put_reg(struct task_struct *task, int regno,
			  unsigned long data)
{
	if (task->thread.regs == NULL)
		return -EIO;

	if (regno <= PT_MAX_PUT_REG) {
		if (regno == PT_MSR)
			data = (data & MSR_DEBUGCHANGE)
				| (task->thread.regs->msr & ~MSR_DEBUGCHANGE);
		((unsigned long *)task->thread.regs)[regno] = data;
		return 0;
	}
	return -EIO;
}


static inline int get_fpregs(void __user *data,
			     struct task_struct *task,
			     int has_fpscr)
{
	unsigned int count = has_fpscr ? 33 : 32;

	if (copy_to_user(data, task->thread.fpr, count * sizeof(double)))
		return -EFAULT;
	return 0;
}

static inline int set_fpregs(void __user *data,
			     struct task_struct *task,
			     int has_fpscr)
{
	unsigned int count = has_fpscr ? 33 : 32;

	if (copy_from_user(task->thread.fpr, data, count * sizeof(double)))
		return -EFAULT;
	return 0;
}


#ifdef CONFIG_ALTIVEC
/*
 * Get/set all the altivec registers vr0..vr31, vscr, vrsave, in one go.
 * The transfer totals 34 quadword.  Quadwords 0-31 contain the
 * corresponding vector registers.  Quadword 32 contains the vscr as the
 * last word (offset 12) within that quadword.  Quadword 33 contains the
 * vrsave as the first word (offset 0) within the quadword.
 *
 * This definition of the VMX state is compatible with the current PPC32
 * ptrace interface.  This allows signal handling and ptrace to use the
 * same structures.  This also simplifies the implementation of a bi-arch
 * (combined (32- and 64-bit) gdb.
 */

/*
 * Get contents of AltiVec register state in task TASK
 */
static inline int get_vrregs(unsigned long __user *data,
			     struct task_struct *task)
{
	unsigned long regsize;

	/* copy AltiVec registers VR[0] .. VR[31] */
	regsize = 32 * sizeof(vector128);
	if (copy_to_user(data, task->thread.vr, regsize))
		return -EFAULT;
	data += (regsize / sizeof(unsigned long));

	/* copy VSCR */
	regsize = 1 * sizeof(vector128);
	if (copy_to_user(data, &task->thread.vscr, regsize))
		return -EFAULT;
	data += (regsize / sizeof(unsigned long));

	/* copy VRSAVE */
	if (put_user(task->thread.vrsave, (u32 __user *)data))
		return -EFAULT;

	return 0;
}

/*
 * Write contents of AltiVec register state into task TASK.
 */
static inline int set_vrregs(struct task_struct *task,
			     unsigned long __user *data)
{
	unsigned long regsize;

	/* copy AltiVec registers VR[0] .. VR[31] */
	regsize = 32 * sizeof(vector128);
	if (copy_from_user(task->thread.vr, data, regsize))
		return -EFAULT;
	data += (regsize / sizeof(unsigned long));

	/* copy VSCR */
	regsize = 1 * sizeof(vector128);
	if (copy_from_user(&task->thread.vscr, data, regsize))
		return -EFAULT;
	data += (regsize / sizeof(unsigned long));

	/* copy VRSAVE */
	if (get_user(task->thread.vrsave, (u32 __user *)data))
		return -EFAULT;

	return 0;
}
#endif /* CONFIG_ALTIVEC */

static inline void set_single_step(struct task_struct *task)
{
	struct pt_regs *regs = task->thread.regs;

	if (regs != NULL) {
#if defined(CONFIG_40x) || defined(CONFIG_BOOKE)
		task->thread.dbcr0 = DBCR0_IDM | DBCR0_IC;
		regs->msr |= MSR_DE;
#else
		regs->msr |= MSR_SE;
#endif
	}
	set_tsk_thread_flag(task, TIF_SINGLESTEP);
}

static inline void clear_single_step(struct task_struct *task)
{
	struct pt_regs *regs = task->thread.regs;

	if (regs != NULL) {
#if defined(CONFIG_40x) || defined(CONFIG_BOOKE)
		task->thread.dbcr0 = 0;
		regs->msr &= ~MSR_DE;
#else
		regs->msr &= ~MSR_SE;
#endif
	}
	clear_tsk_thread_flag(task, TIF_SINGLESTEP);
}

#endif /* _POWERPC_PTRACE_COMMON_H */
