#ifndef __ASM_X86_PROCESSOR_H
#define __ASM_X86_PROCESSOR_H

#include <asm/processor-flags.h>

/* Forward declaration, a strange C thing */
struct task_struct;
struct mm_struct;

#include <asm/page.h>
#include <asm/system.h>

static inline void native_cpuid(unsigned int *eax, unsigned int *ebx,
					 unsigned int *ecx, unsigned int *edx)
{
	/* ecx is often an input as well as an output. */
	__asm__("cpuid"
		: "=a" (*eax),
		  "=b" (*ebx),
		  "=c" (*ecx),
		  "=d" (*edx)
		: "0" (*eax), "2" (*ecx));
}

static inline void load_cr3(pgd_t *pgdir)
{
	write_cr3(__pa(pgdir));
}

#ifdef CONFIG_X86_32
# include "processor_32.h"
#else
# include "processor_64.h"
#endif

extern void print_cpu_info(struct cpuinfo_x86 *);
extern void init_scattered_cpuid_features(struct cpuinfo_x86 *c);
extern unsigned int init_intel_cacheinfo(struct cpuinfo_x86 *c);
extern unsigned short num_cache_leaves;

static inline unsigned long native_get_debugreg(int regno)
{
	unsigned long val = 0; 	/* Damn you, gcc! */

	switch (regno) {
	case 0:
		asm("mov %%db0, %0" :"=r" (val)); break;
	case 1:
		asm("mov %%db1, %0" :"=r" (val)); break;
	case 2:
		asm("mov %%db2, %0" :"=r" (val)); break;
	case 3:
		asm("mov %%db3, %0" :"=r" (val)); break;
	case 6:
		asm("mov %%db6, %0" :"=r" (val)); break;
	case 7:
		asm("mov %%db7, %0" :"=r" (val)); break;
	default:
		BUG();
	}
	return val;
}

static inline void native_set_debugreg(int regno, unsigned long value)
{
	switch (regno) {
	case 0:
		asm("mov %0,%%db0"	: /* no output */ :"r" (value));
		break;
	case 1:
		asm("mov %0,%%db1"	: /* no output */ :"r" (value));
		break;
	case 2:
		asm("mov %0,%%db2"	: /* no output */ :"r" (value));
		break;
	case 3:
		asm("mov %0,%%db3"	: /* no output */ :"r" (value));
		break;
	case 6:
		asm("mov %0,%%db6"	: /* no output */ :"r" (value));
		break;
	case 7:
		asm("mov %0,%%db7"	: /* no output */ :"r" (value));
		break;
	default:
		BUG();
	}
}

/*
 * Set IOPL bits in EFLAGS from given mask
 */
static inline void native_set_iopl_mask(unsigned mask)
{
#ifdef CONFIG_X86_32
	unsigned int reg;
	__asm__ __volatile__ ("pushfl;"
			      "popl %0;"
			      "andl %1, %0;"
			      "orl %2, %0;"
			      "pushl %0;"
			      "popfl"
				: "=&r" (reg)
				: "i" (~X86_EFLAGS_IOPL), "r" (mask));
#endif
}


#ifndef CONFIG_PARAVIRT
#define __cpuid native_cpuid
#define paravirt_enabled() 0

/*
 * These special macros can be used to get or set a debugging register
 */
#define get_debugreg(var, register)				\
	(var) = native_get_debugreg(register)
#define set_debugreg(value, register)				\
	native_set_debugreg(register, value)

#define set_iopl_mask native_set_iopl_mask
#endif /* CONFIG_PARAVIRT */

/*
 * Save the cr4 feature set we're using (ie
 * Pentium 4MB enable and PPro Global page
 * enable), so that any CPU's that boot up
 * after us can get the correct flags.
 */
extern unsigned long mmu_cr4_features;

static inline void set_in_cr4(unsigned long mask)
{
	unsigned cr4;
	mmu_cr4_features |= mask;
	cr4 = read_cr4();
	cr4 |= mask;
	write_cr4(cr4);
}

static inline void clear_in_cr4(unsigned long mask)
{
	unsigned cr4;
	mmu_cr4_features &= ~mask;
	cr4 = read_cr4();
	cr4 &= ~mask;
	write_cr4(cr4);
}

struct microcode_header {
	unsigned int hdrver;
	unsigned int rev;
	unsigned int date;
	unsigned int sig;
	unsigned int cksum;
	unsigned int ldrver;
	unsigned int pf;
	unsigned int datasize;
	unsigned int totalsize;
	unsigned int reserved[3];
};

struct microcode {
	struct microcode_header hdr;
	unsigned int bits[0];
};

typedef struct microcode microcode_t;
typedef struct microcode_header microcode_header_t;

/* microcode format is extended from prescott processors */
struct extended_signature {
	unsigned int sig;
	unsigned int pf;
	unsigned int cksum;
};

struct extended_sigtable {
	unsigned int count;
	unsigned int cksum;
	unsigned int reserved[3];
	struct extended_signature sigs[0];
};

/*
 * create a kernel thread without removing it from tasklists
 */
extern int kernel_thread(int (*fn)(void *), void *arg, unsigned long flags);

/* Free all resources held by a thread. */
extern void release_thread(struct task_struct *);

/* Prepare to copy thread state - unlazy all lazy status */
extern void prepare_to_copy(struct task_struct *tsk);

unsigned long get_wchan(struct task_struct *p);

/*
 * Generic CPUID function
 * clear %ecx since some cpus (Cyrix MII) do not set or clear %ecx
 * resulting in stale register contents being returned.
 */
static inline void cpuid(unsigned int op,
			 unsigned int *eax, unsigned int *ebx,
			 unsigned int *ecx, unsigned int *edx)
{
	*eax = op;
	*ecx = 0;
	__cpuid(eax, ebx, ecx, edx);
}

/* Some CPUID calls want 'count' to be placed in ecx */
static inline void cpuid_count(unsigned int op, int count,
			       unsigned int *eax, unsigned int *ebx,
			       unsigned int *ecx, unsigned int *edx)
{
	*eax = op;
	*ecx = count;
	__cpuid(eax, ebx, ecx, edx);
}

/*
 * CPUID functions returning a single datum
 */
static inline unsigned int cpuid_eax(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);
	return eax;
}
static inline unsigned int cpuid_ebx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);
	return ebx;
}
static inline unsigned int cpuid_ecx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);
	return ecx;
}
static inline unsigned int cpuid_edx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);
	return edx;
}

/* REP NOP (PAUSE) is a good thing to insert into busy-wait loops. */
static inline void rep_nop(void)
{
	__asm__ __volatile__("rep;nop": : :"memory");
}

/* Stop speculative execution */
static inline void sync_core(void)
{
	int tmp;
	asm volatile("cpuid" : "=a" (tmp) : "0" (1)
					  : "ebx", "ecx", "edx", "memory");
}

#define cpu_relax()   rep_nop()

static inline void __monitor(const void *eax, unsigned long ecx,
		unsigned long edx)
{
	/* "monitor %eax,%ecx,%edx;" */
	asm volatile(
		".byte 0x0f,0x01,0xc8;"
		: :"a" (eax), "c" (ecx), "d"(edx));
}

static inline void __mwait(unsigned long eax, unsigned long ecx)
{
	/* "mwait %eax,%ecx;" */
	asm volatile(
		".byte 0x0f,0x01,0xc9;"
		: :"a" (eax), "c" (ecx));
}

static inline void __sti_mwait(unsigned long eax, unsigned long ecx)
{
	/* "mwait %eax,%ecx;" */
	asm volatile(
		"sti; .byte 0x0f,0x01,0xc9;"
		: :"a" (eax), "c" (ecx));
}

extern void mwait_idle_with_hints(unsigned long eax, unsigned long ecx);

extern int force_mwait;

extern void select_idle_routine(const struct cpuinfo_x86 *c);

extern unsigned long boot_option_idle_override;

/* Boot loader type from the setup header */
extern int bootloader_type;
#define cache_line_size() (boot_cpu_data.x86_cache_alignment)

#define HAVE_ARCH_PICK_MMAP_LAYOUT 1
#define ARCH_HAS_PREFETCHW
#define ARCH_HAS_SPINLOCK_PREFETCH

#define spin_lock_prefetch(x)	prefetchw(x)
/* This decides where the kernel will search for a free chunk of vm
 * space during mmap's.
 */
#define TASK_UNMAPPED_BASE	(PAGE_ALIGN(TASK_SIZE / 3))

#define KSTK_EIP(task) (task_pt_regs(task)->ip)

#endif
