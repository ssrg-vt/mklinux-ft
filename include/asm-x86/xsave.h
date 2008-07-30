#ifndef __ASM_X86_XSAVE_H
#define __ASM_X86_XSAVE_H

#include <asm/processor.h>
#include <asm/i387.h>

#define XSTATE_FP	0x1
#define XSTATE_SSE	0x2

#define XSTATE_FPSSE	(XSTATE_FP | XSTATE_SSE)

#define FXSAVE_SIZE	512

/*
 * These are the features that the OS can handle currently.
 */
#define XCNTXT_LMASK	(XSTATE_FP | XSTATE_SSE)
#define XCNTXT_HMASK	0x0

#ifdef CONFIG_X86_64
#define REX_PREFIX	"0x48, "
#else
#define REX_PREFIX
#endif

extern unsigned int xstate_size, pcntxt_hmask, pcntxt_lmask;
extern struct xsave_struct *init_xstate_buf;

extern void xsave_cntxt_init(void);
extern void xsave_init(void);
extern int init_fpu(struct task_struct *child);

static inline int xrstor_checking(struct xsave_struct *fx)
{
	int err;

	asm volatile("1: .byte " REX_PREFIX "0x0f,0xae,0x2f\n\t"
		     "2:\n"
		     ".section .fixup,\"ax\"\n"
		     "3:  movl $-1,%[err]\n"
		     "    jmp  2b\n"
		     ".previous\n"
		     _ASM_EXTABLE(1b, 3b)
		     : [err] "=r" (err)
		     : "D" (fx), "m" (*fx), "a" (-1), "d" (-1), "0" (0)
		     : "memory");

	return err;
}

static inline void xsave(struct task_struct *tsk)
{
	/* This, however, we can work around by forcing the compiler to select
	   an addressing mode that doesn't require extended registers. */
	__asm__ __volatile__(".byte " REX_PREFIX "0x0f,0xae,0x27"
			     : : "D" (&(tsk->thread.xstate->xsave)),
				 "a" (-1), "d"(-1) : "memory");
}
#endif
