#ifndef _ASM_X86_APIC_H
#define _ASM_X86_APIC_H

#include <linux/pm.h>
#include <linux/delay.h>
#include <asm/fixmap.h>
#include <asm/apicdef.h>
#include <asm/processor.h>
#include <asm/system.h>
#include <asm/cpufeature.h>
#include <asm/msr.h>

#define ARCH_APICTIMER_STOPS_ON_C3	1

#define Dprintk(x...)

/*
 * Debugging macros
 */
#define APIC_QUIET   0
#define APIC_VERBOSE 1
#define APIC_DEBUG   2

/*
 * Define the default level of output to be very little
 * This can be turned up by using apic=verbose for more
 * information and apic=debug for _lots_ of information.
 * apic_verbosity is defined in apic.c
 */
#define apic_printk(v, s, a...) do {       \
		if ((v) <= apic_verbosity) \
			printk(s, ##a);    \
	} while (0)


extern void generic_apic_probe(void);

#ifdef CONFIG_X86_LOCAL_APIC

extern int apic_verbosity;
extern int local_apic_timer_c2_ok;

extern int ioapic_force;

extern int disable_apic;
/*
 * Basic functions accessing APICs.
 */
#ifdef CONFIG_PARAVIRT
#include <asm/paravirt.h>
#else
#ifndef CONFIG_X86_64
#define apic_write native_apic_mem_write
#define apic_write_atomic native_apic_mem_write_atomic
#define apic_read native_apic_mem_read
#endif
#define setup_boot_clock setup_boot_APIC_clock
#define setup_secondary_clock setup_secondary_APIC_clock
#endif

extern int is_vsmp_box(void);

static inline void native_apic_mem_write(u32 reg, u32 v)
{
	*((volatile u32 *)(APIC_BASE + reg)) = v;
}

static inline void native_apic_mem_write_atomic(u32 reg, u32 v)
{
	(void)xchg((u32 *)(APIC_BASE + reg), v);
}

static inline u32 native_apic_mem_read(u32 reg)
{
	return *((volatile u32 *)(APIC_BASE + reg));
}

static inline void native_apic_msr_write(u32 reg, u32 v)
{
	if (reg == APIC_DFR || reg == APIC_ID || reg == APIC_LDR ||
	    reg == APIC_LVR)
		return;

	wrmsr(APIC_BASE_MSR + (reg >> 4), v, 0);
}

static inline u32 native_apic_msr_read(u32 reg)
{
	u32 low, high;

	if (reg == APIC_DFR)
		return -1;

	rdmsr(APIC_BASE_MSR + (reg >> 4), low, high);
	return low;
}

#ifdef CONFIG_X86_32
extern void apic_wait_icr_idle(void);
extern u32 safe_apic_wait_icr_idle(void);
extern void apic_icr_write(u32 low, u32 id);
#else

struct apic_ops {
	u32 (*read)(u32 reg);
	void (*write)(u32 reg, u32 v);
	void (*write_atomic)(u32 reg, u32 v);
	u64 (*icr_read)(void);
	void (*icr_write)(u32 low, u32 high);
	void (*wait_icr_idle)(void);
	u32 (*safe_wait_icr_idle)(void);
};

extern struct apic_ops *apic_ops;

#define apic_read (apic_ops->read)
#define apic_write (apic_ops->write)
#define apic_write_atomic (apic_ops->write_atomic)
#define apic_icr_read (apic_ops->icr_read)
#define apic_icr_write (apic_ops->icr_write)
#define apic_wait_icr_idle (apic_ops->wait_icr_idle)
#define safe_apic_wait_icr_idle (apic_ops->safe_wait_icr_idle)
#endif

extern int get_physical_broadcast(void);

#ifdef CONFIG_X86_GOOD_APIC
# define FORCE_READ_AROUND_WRITE 0
# define apic_read_around(x)
# define apic_write_around(x, y) apic_write((x), (y))
#else
# define FORCE_READ_AROUND_WRITE 1
# define apic_read_around(x) apic_read(x)
# define apic_write_around(x, y) apic_write_atomic((x), (y))
#endif

static inline void ack_APIC_irq(void)
{
	/*
	 * ack_APIC_irq() actually gets compiled as a single instruction:
	 * - a single rmw on Pentium/82489DX
	 * - a single write on P6+ cores (CONFIG_X86_GOOD_APIC)
	 * ... yummie.
	 */

	/* Docs say use 0 for future compatibility */
#ifdef CONFIG_X86_32
	apic_write_around(APIC_EOI, 0);
#else
	native_apic_mem_write(APIC_EOI, 0);
#endif
}

extern int lapic_get_maxlvt(void);
extern void clear_local_APIC(void);
extern void connect_bsp_APIC(void);
extern void disconnect_bsp_APIC(int virt_wire_setup);
extern void disable_local_APIC(void);
extern void lapic_shutdown(void);
extern int verify_local_APIC(void);
extern void cache_APIC_registers(void);
extern void sync_Arb_IDs(void);
extern void init_bsp_APIC(void);
extern void setup_local_APIC(void);
extern void end_local_APIC_setup(void);
extern void init_apic_mappings(void);
extern void setup_boot_APIC_clock(void);
extern void setup_secondary_APIC_clock(void);
extern int APIC_init_uniprocessor(void);
extern void enable_NMI_through_LVT0(void);

/*
 * On 32bit this is mach-xxx local
 */
#ifdef CONFIG_X86_64
extern void early_init_lapic_mapping(void);
extern int apic_is_clustered_box(void);
#else
static inline int apic_is_clustered_box(void)
{
	return 0;
}
#endif

extern u8 setup_APIC_eilvt_mce(u8 vector, u8 msg_type, u8 mask);
extern u8 setup_APIC_eilvt_ibs(u8 vector, u8 msg_type, u8 mask);


#else /* !CONFIG_X86_LOCAL_APIC */
static inline void lapic_shutdown(void) { }
#define local_apic_timer_c2_ok		1
static inline void init_apic_mappings(void) { }

#endif /* !CONFIG_X86_LOCAL_APIC */

#endif /* __ASM_APIC_H */
