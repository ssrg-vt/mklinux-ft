#ifndef XEN_OPS_H
#define XEN_OPS_H

#include <linux/init.h>

/* These are code, but not functions.  Defined in entry.S */
extern const char xen_hypervisor_callback[];
extern const char xen_failsafe_callback[];

void xen_copy_trap_info(struct trap_info *traps);

DECLARE_PER_CPU(struct vcpu_info *, xen_vcpu);
DECLARE_PER_CPU(unsigned long, xen_cr3);

extern struct start_info *xen_start_info;
extern struct shared_info *HYPERVISOR_shared_info;

char * __init xen_memory_setup(void);
void __init xen_arch_setup(void);
void __init xen_init_IRQ(void);

void xen_setup_timer(int cpu);
void xen_setup_cpu_clockevents(void);
unsigned long xen_cpu_khz(void);
void __init xen_time_init(void);
unsigned long xen_get_wallclock(void);
int xen_set_wallclock(unsigned long time);
unsigned long long xen_sched_clock(void);

void xen_mark_init_mm_pinned(void);

DECLARE_PER_CPU(enum paravirt_lazy_mode, xen_lazy_mode);

static inline unsigned xen_get_lazy_mode(void)
{
	return x86_read_percpu(xen_lazy_mode);
}

void __init xen_fill_possible_map(void);

void __init xen_setup_vcpu_info_placement(void);
void xen_smp_prepare_boot_cpu(void);
void xen_smp_prepare_cpus(unsigned int max_cpus);
int xen_cpu_up(unsigned int cpu);
void xen_smp_cpus_done(unsigned int max_cpus);

void xen_smp_send_stop(void);
void xen_smp_send_reschedule(int cpu);
int xen_smp_call_function (void (*func) (void *info), void *info, int nonatomic,
			   int wait);
int xen_smp_call_function_single(int cpu, void (*func) (void *info), void *info,
				 int nonatomic, int wait);

int xen_smp_call_function_mask(cpumask_t mask, void (*func)(void *),
			       void *info, int wait);

#endif /* XEN_OPS_H */
