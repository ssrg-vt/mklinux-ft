/*
 * Copyright (C) 1994 Linus Torvalds
 */

#ifndef __ASM_X86_64_PROCESSOR_H
#define __ASM_X86_64_PROCESSOR_H

#include <asm/segment.h>
#include <asm/page.h>
#include <asm/types.h>
#include <asm/sigcontext.h>
#include <asm/cpufeature.h>
#include <linux/threads.h>
#include <asm/msr.h>
#include <asm/current.h>
#include <asm/system.h>
#include <asm/mmsegment.h>
#include <asm/percpu.h>
#include <linux/personality.h>
#include <linux/cpumask.h>
#include <asm/desc_defs.h>

/*
 *  CPU type and hardware bug flags. Kept separately for each CPU.
 */

struct cpuinfo_x86 {
	__u8	x86;		/* CPU family */
	__u8	x86_vendor;	/* CPU vendor */
	__u8	x86_model;
	__u8	x86_mask;
	int	cpuid_level;	/* Maximum supported CPUID level, -1=no CPUID */
	__u32	x86_capability[NCAPINTS];
	char	x86_vendor_id[16];
	char	x86_model_id[64];
	int 	x86_cache_size;  /* in KB */
	int	x86_clflush_size;
	int	x86_cache_alignment;
	int	x86_tlbsize;	/* number of 4K pages in DTLB/ITLB combined(in pages)*/
        __u8    x86_virt_bits, x86_phys_bits;
	__u8	x86_max_cores;	/* cpuid returned max cores value */
	__u8	x86_coreid_bits; /* cpuid returned core id bits */
        __u32   x86_power; 	
	__u32   extended_cpuid_level;	/* Max extended CPUID function supported */
	unsigned long loops_per_jiffy;
#ifdef CONFIG_SMP
	cpumask_t llc_shared_map;	/* cpus sharing the last level cache */
#endif
	__u8	apicid;
#ifdef CONFIG_SMP
	__u8	booted_cores;	/* number of cores as seen by OS */
	__u8	phys_proc_id;	/* Physical Processor id. */
	__u8	cpu_core_id;	/* Core id. */
	__u8	cpu_index;	/* index into per_cpu list */
#endif
} ____cacheline_aligned;

#define X86_VENDOR_INTEL 0
#define X86_VENDOR_CYRIX 1
#define X86_VENDOR_AMD 2
#define X86_VENDOR_UMC 3
#define X86_VENDOR_NEXGEN 4
#define X86_VENDOR_CENTAUR 5
#define X86_VENDOR_TRANSMETA 7
#define X86_VENDOR_NUM 8
#define X86_VENDOR_UNKNOWN 0xff

#ifdef CONFIG_SMP
DECLARE_PER_CPU(struct cpuinfo_x86, cpu_info);
#define cpu_data(cpu)		per_cpu(cpu_info, cpu)
#define current_cpu_data	cpu_data(smp_processor_id())
#else
#define cpu_data(cpu)		boot_cpu_data
#define current_cpu_data	boot_cpu_data
#endif

extern char ignore_irq13;

extern void identify_cpu(struct cpuinfo_x86 *);

/*
 * User space process size. 47bits minus one guard page.
 */
#define TASK_SIZE64	(0x800000000000UL - 4096)

/* This decides where the kernel will search for a free chunk of vm
 * space during mmap's.
 */
#define IA32_PAGE_OFFSET ((current->personality & ADDR_LIMIT_3GB) ? 0xc0000000 : 0xFFFFe000)

#define TASK_SIZE 		(test_thread_flag(TIF_IA32) ? IA32_PAGE_OFFSET : TASK_SIZE64)
#define TASK_SIZE_OF(child) 	((test_tsk_thread_flag(child, TIF_IA32)) ? IA32_PAGE_OFFSET : TASK_SIZE64)


struct i387_fxsave_struct {
	u16	cwd;
	u16	swd;
	u16	twd;
	u16	fop;
	u64	rip;
	u64	rdp; 
	u32	mxcsr;
	u32	mxcsr_mask;
	u32	st_space[32];	/* 8*16 bytes for each FP-reg = 128 bytes */
	u32	xmm_space[64];	/* 16*16 bytes for each XMM-reg = 256 bytes */
	u32	padding[24];
} __attribute__ ((aligned (16)));

union i387_union {
	struct i387_fxsave_struct	fxsave;
};

extern struct cpuinfo_x86 boot_cpu_data;
/* Save the original ist values for checking stack pointers during debugging */
struct orig_ist {
	unsigned long ist[7];
};
DECLARE_PER_CPU(struct orig_ist, orig_ist);

#ifdef CONFIG_X86_VSMP
#define ARCH_MIN_TASKALIGN	(1 << INTERNODE_CACHE_SHIFT)
#define ARCH_MIN_MMSTRUCT_ALIGN	(1 << INTERNODE_CACHE_SHIFT)
#else
#define ARCH_MIN_TASKALIGN	16
#define ARCH_MIN_MMSTRUCT_ALIGN	0
#endif

#define INIT_THREAD  { \
	.sp0 = (unsigned long)&init_stack + sizeof(init_stack) \
}

#define INIT_TSS  { \
	.x86_tss.sp0 = (unsigned long)&init_stack + sizeof(init_stack) \
}

#define INIT_MMAP \
{ &init_mm, 0, 0, NULL, PAGE_SHARED, VM_READ | VM_WRITE | VM_EXEC, 1, NULL, NULL }

#define start_thread(regs,new_rip,new_rsp) do { \
	asm volatile("movl %0,%%fs; movl %0,%%es; movl %0,%%ds": :"r" (0));	 \
	load_gs_index(0);							\
	(regs)->ip = (new_rip);						 \
	(regs)->sp = (new_rsp);						 \
	write_pda(oldrsp, (new_rsp));						 \
	(regs)->cs = __USER_CS;							 \
	(regs)->ss = __USER_DS;							 \
	(regs)->flags = 0x200;							 \
	set_fs(USER_DS);							 \
} while(0) 

/*
 * Return saved PC of a blocked thread.
 * What is this good for? it will be always the scheduler or ret_from_fork.
 */
#define thread_saved_pc(t) (*(unsigned long *)((t)->thread.sp - 8))

#define task_pt_regs(tsk) ((struct pt_regs *)(tsk)->thread.sp0 - 1)
#define KSTK_ESP(tsk) -1 /* sorry. doesn't work for syscall. */


#if defined(CONFIG_MPSC) || defined(CONFIG_MCORE2)
#define ASM_NOP1 P6_NOP1
#define ASM_NOP2 P6_NOP2
#define ASM_NOP3 P6_NOP3
#define ASM_NOP4 P6_NOP4
#define ASM_NOP5 P6_NOP5
#define ASM_NOP6 P6_NOP6
#define ASM_NOP7 P6_NOP7
#define ASM_NOP8 P6_NOP8
#else
#define ASM_NOP1 K8_NOP1
#define ASM_NOP2 K8_NOP2
#define ASM_NOP3 K8_NOP3
#define ASM_NOP4 K8_NOP4
#define ASM_NOP5 K8_NOP5
#define ASM_NOP6 K8_NOP6
#define ASM_NOP7 K8_NOP7
#define ASM_NOP8 K8_NOP8
#endif

/* Opteron nops */
#define K8_NOP1 ".byte 0x90\n"
#define K8_NOP2	".byte 0x66,0x90\n" 
#define K8_NOP3	".byte 0x66,0x66,0x90\n" 
#define K8_NOP4	".byte 0x66,0x66,0x66,0x90\n" 
#define K8_NOP5	K8_NOP3 K8_NOP2 
#define K8_NOP6	K8_NOP3 K8_NOP3
#define K8_NOP7	K8_NOP4 K8_NOP3
#define K8_NOP8	K8_NOP4 K8_NOP4

/* P6 nops */
/* uses eax dependencies (Intel-recommended choice) */
#define P6_NOP1	".byte 0x90\n"
#define P6_NOP2	".byte 0x66,0x90\n"
#define P6_NOP3	".byte 0x0f,0x1f,0x00\n"
#define P6_NOP4	".byte 0x0f,0x1f,0x40,0\n"
#define P6_NOP5	".byte 0x0f,0x1f,0x44,0x00,0\n"
#define P6_NOP6	".byte 0x66,0x0f,0x1f,0x44,0x00,0\n"
#define P6_NOP7	".byte 0x0f,0x1f,0x80,0,0,0,0\n"
#define P6_NOP8	".byte 0x0f,0x1f,0x84,0x00,0,0,0,0\n"

#define ASM_NOP_MAX 8

static inline void prefetchw(void *x) 
{ 
	alternative_input("prefetcht0 (%1)",
			  "prefetchw (%1)",
			  X86_FEATURE_3DNOW,
			  "r" (x));
} 


#define stack_current() \
({								\
	struct thread_info *ti;					\
	asm("andq %%rsp,%0; ":"=r" (ti) : "0" (CURRENT_MASK));	\
	ti->task;					\
})


#endif /* __ASM_X86_64_PROCESSOR_H */
