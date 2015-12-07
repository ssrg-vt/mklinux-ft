/*
 * atomic_x86.c
 *
 *  Created on: Dec 7, 2015
 *      Author: root
 */

#ifndef PCNMSG_ATOMIC_X86_C_
#define PCNMSG_ATOMIC_X86_C_


/*****************************************************************************/
/* ARCH DEP */
/*****************************************************************************/

/* From Wikipedia page "Fetch and add", modified to work for u64 */
static inline unsigned long fetch_and_add(volatile unsigned long * variable,
					  unsigned long value)
{
	asm volatile(
		     "lock; xaddq %%rax, %2;"
		     :"=a" (value)                   //Output
		     : "a" (value), "m" (*variable)  //Input
		     :"memory" );
	return value;
}

static inline int atomic_add_return_sync(int i, atomic_t *v)
{
	return i + xadd_sync(&v->counter, i);
}

static inline int atomic_dec_and_test_sync(atomic_t *v)
{
	unsigned char c;

	asm volatile("lock; decl %0; sete %1"
		     : "+m" (v->counter), "=qm" (c)
		     : : "memory");
	return c != 0;
}

#endif /* PCNMSG_ATOMIC_X86_C_ */
