/*
 *  linux/arch/arm/mm/copypage-v4wt.S
 *
 *  Copyright (C) 1995-1999 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *  This is for CPUs with a writethrough cache and 'flush ID cache' is
 *  the only supported cache operation.
 */
#include <linux/init.h>

#include <asm/page.h>

/*
 * ARMv4 optimised copy_user_page
 *
 * Since we have writethrough caches, we don't have to worry about
 * dirty data in the cache.  However, we do have to ensure that
 * subsequent reads are up to date.
 */
void __attribute__((naked))
v4wt_copy_user_page(void *kto, const void *kfrom, unsigned long vaddr)
{
	asm("\
	stmfd	sp!, {r4, lr}			@ 2\n\
	mov	r2, %0				@ 1\n\
	ldmia	r1!, {r3, r4, ip, lr}		@ 4\n\
1:	stmia	r0!, {r3, r4, ip, lr}		@ 4\n\
	ldmia	r1!, {r3, r4, ip, lr}		@ 4+1\n\
	stmia	r0!, {r3, r4, ip, lr}		@ 4\n\
	ldmia	r1!, {r3, r4, ip, lr}		@ 4\n\
	stmia	r0!, {r3, r4, ip, lr}		@ 4\n\
	ldmia	r1!, {r3, r4, ip, lr}		@ 4\n\
	subs	r2, r2, #1			@ 1\n\
	stmia	r0!, {r3, r4, ip, lr}		@ 4\n\
	ldmneia	r1!, {r3, r4, ip, lr}		@ 4\n\
	bne	1b				@ 1\n\
	mcr	p15, 0, r2, c7, c7, 0		@ flush ID cache\n\
	ldmfd	sp!, {r4, pc}			@ 3"
	:
	: "I" (PAGE_SIZE / 64));
}

/*
 * ARMv4 optimised clear_user_page
 *
 * Same story as above.
 */
void __attribute__((naked))
v4wt_clear_user_page(void *kaddr, unsigned long vaddr)
{
	asm("\
	str	lr, [sp, #-4]!\n\
	mov	r1, %0				@ 1\n\
	mov	r2, #0				@ 1\n\
	mov	r3, #0				@ 1\n\
	mov	ip, #0				@ 1\n\
	mov	lr, #0				@ 1\n\
1:	stmia	r0!, {r2, r3, ip, lr}		@ 4\n\
	stmia	r0!, {r2, r3, ip, lr}		@ 4\n\
	stmia	r0!, {r2, r3, ip, lr}		@ 4\n\
	stmia	r0!, {r2, r3, ip, lr}		@ 4\n\
	subs	r1, r1, #1			@ 1\n\
	bne	1b				@ 1\n\
	mcr	p15, 0, r2, c7, c7, 0		@ flush ID cache\n\
	ldr	pc, [sp], #4"
	:
	: "I" (PAGE_SIZE / 64));
}

struct cpu_user_fns v4wt_user_fns __initdata = {
	.cpu_clear_user_page	= v4wt_clear_user_page,
	.cpu_copy_user_page	= v4wt_copy_user_page,
};
