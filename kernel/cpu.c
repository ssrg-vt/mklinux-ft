/* CPU control.
 * (C) 2001, 2002, 2003, 2004 Rusty Russell
 *
 * This code is licenced under the GPL.
 */
#include <linux/proc_fs.h>
#include <linux/smp.h>
#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/stop_machine.h>
#include <linux/mutex.h>

/*
 * Represents all cpu's present in the system
 * In systems capable of hotplug, this map could dynamically grow
 * as new cpu's are detected in the system via any platform specific
 * method, such as ACPI for e.g.
 */
cpumask_t cpu_present_map __read_mostly;
EXPORT_SYMBOL(cpu_present_map);

#ifndef CONFIG_SMP

/*
 * Represents all cpu's that are currently online.
 */
cpumask_t cpu_online_map __read_mostly = CPU_MASK_ALL;
EXPORT_SYMBOL(cpu_online_map);

cpumask_t cpu_possible_map __read_mostly = CPU_MASK_ALL;
EXPORT_SYMBOL(cpu_possible_map);

#else /* CONFIG_SMP */

/* Serializes the updates to cpu_online_map, cpu_present_map */
static DEFINE_MUTEX(cpu_add_remove_lock);

static __cpuinitdata RAW_NOTIFIER_HEAD(cpu_chain);

/* If set, cpu_up and cpu_down will return -EBUSY and do nothing.
 * Should always be manipulated under cpu_add_remove_lock
 */
static int cpu_hotplug_disabled;

static struct {
	struct task_struct *active_writer;
	struct mutex lock; /* Synchronizes accesses to refcount, */
	/*
	 * Also blocks the new readers during
	 * an ongoing cpu hotplug operation.
	 */
	int refcount;
} cpu_hotplug;

void __init cpu_hotplug_init(void)
{
	cpu_hotplug.active_writer = NULL;
	mutex_init(&cpu_hotplug.lock);
	cpu_hotplug.refcount = 0;
}

cpumask_t cpu_active_map;

#ifdef CONFIG_HOTPLUG_CPU

void get_online_cpus(void)
{
	might_sleep();
	if (cpu_hotplug.active_writer == current)
		return;
	mutex_lock(&cpu_hotplug.lock);
	cpu_hotplug.refcount++;
	mutex_unlock(&cpu_hotplug.lock);

}
EXPORT_SYMBOL_GPL(get_online_cpus);

void put_online_cpus(void)
{
	if (cpu_hotplug.active_writer == current)
		return;
	mutex_lock(&cpu_hotplug.lock);
	if (!--cpu_hotplug.refcount && unlikely(cpu_hotplug.active_writer))
		wake_up_process(cpu_hotplug.active_writer);
	mutex_unlock(&cpu_hotplug.lock);

}
EXPORT_SYMBOL_GPL(put_online_cpus);

#endif	/* CONFIG_HOTPLUG_CPU */

/*
 * The following two API's must be used when attempting
 * to serialize the updates to cpu_online_map, cpu_present_map.
 */
void cpu_maps_update_begin(void)
{
	mutex_lock(&cpu_add_remove_lock);
}

void cpu_maps_update_done(void)
{
	mutex_unlock(&cpu_add_remove_lock);
}

/*
 * This ensures that the hotplug operation can begin only when the
 * refcount goes to zero.
 *
 * Note that during a cpu-hotplug operation, the new readers, if any,
 * will be blocked by the cpu_hotplug.lock
 *
 * Since cpu_hotplug_begin() is always called after invoking
 * cpu_maps_update_begin(), we can be sure that only one writer is active.
 *
 * Note that theoretically, there is a possibility of a livelock:
 * - Refcount goes to zero, last reader wakes up the sleeping
 *   writer.
 * - Last reader unlocks the cpu_hotplug.lock.
 * - A new reader arrives at this moment, bumps up the refcount.
 * - The writer acquires the cpu_hotplug.lock finds the refcount
 *   non zero and goes to sleep again.
 *
 * However, this is very difficult to achieve in practice since
 * get_online_cpus() not an api which is called all that often.
 *
 */
static void cpu_hotplug_begin(void)
{
	cpu_hotplug.active_writer = current;

	for (;;) {
		mutex_lock(&cpu_hotplug.lock);
		if (likely(!cpu_hotplug.refcount))
			break;
		__set_current_state(TASK_UNINTERRUPTIBLE);
		mutex_unlock(&cpu_hotplug.lock);
		schedule();
	}
}

static void cpu_hotplug_done(void)
{
	cpu_hotplug.active_writer = NULL;
	mutex_unlock(&cpu_hotplug.lock);
}
/* Need to know about CPUs going up/down? */
int __ref register_cpu_notifier(struct notifier_block *nb)
{
	int ret;
	cpu_maps_update_begin();
	ret = raw_notifier_chain_register(&cpu_chain, nb);
	cpu_maps_update_done();
	return ret;
}

#ifdef CONFIG_HOTPLUG_CPU

EXPORT_SYMBOL(register_cpu_notifier);

void __ref unregister_cpu_notifier(struct notifier_block *nb)
{
	cpu_maps_update_begin();
	raw_notifier_chain_unregister(&cpu_chain, nb);
	cpu_maps_update_done();
}
EXPORT_SYMBOL(unregister_cpu_notifier);

static inline void check_for_tasks(int cpu)
{
	struct task_struct *p;

	write_lock_irq(&tasklist_lock);
	for_each_process(p) {
		if (task_cpu(p) == cpu &&
		    (!cputime_eq(p->utime, cputime_zero) ||
		     !cputime_eq(p->stime, cputime_zero)))
			printk(KERN_WARNING "Task %s (pid = %d) is on cpu %d\
				(state = %ld, flags = %x) \n",
				 p->comm, task_pid_nr(p), cpu,
				 p->state, p->flags);
	}
	write_unlock_irq(&tasklist_lock);
}

struct take_cpu_down_param {
	unsigned long mod;
	void *hcpu;
};

/* Take this CPU down. */
static int __ref take_cpu_down(void *_param)
{
	struct take_cpu_down_param *param = _param;
	int err;

	raw_notifier_call_chain(&cpu_chain, CPU_DYING | param->mod,
				param->hcpu);
	/* Ensure this CPU doesn't handle any more interrupts. */
	err = __cpu_disable();
	if (err < 0)
		return err;

	/* Force idle task to run as soon as we yield: it should
	   immediately notice cpu is offline and die quickly. */
	sched_idle_next();
	return 0;
}

/* Requires cpu_add_remove_lock to be held */
static int __ref _cpu_down(unsigned int cpu, int tasks_frozen)
{
	int err, nr_calls = 0;
	struct task_struct *p;
	cpumask_t old_allowed, tmp;
	void *hcpu = (void *)(long)cpu;
	unsigned long mod = tasks_frozen ? CPU_TASKS_FROZEN : 0;
	struct take_cpu_down_param tcd_param = {
		.mod = mod,
		.hcpu = hcpu,
	};

	if (num_online_cpus() == 1)
		return -EBUSY;

	if (!cpu_online(cpu))
		return -EINVAL;

	cpu_hotplug_begin();
	err = __raw_notifier_call_chain(&cpu_chain, CPU_DOWN_PREPARE | mod,
					hcpu, -1, &nr_calls);
	if (err == NOTIFY_BAD) {
		nr_calls--;
		__raw_notifier_call_chain(&cpu_chain, CPU_DOWN_FAILED | mod,
					  hcpu, nr_calls, NULL);
		printk("%s: attempt to take down CPU %u failed\n",
				__func__, cpu);
		err = -EINVAL;
		goto out_release;
	}

	/* Ensure that we are not runnable on dying cpu */
	old_allowed = current->cpus_allowed;
	cpus_setall(tmp);
	cpu_clear(cpu, tmp);
	set_cpus_allowed_ptr(current, &tmp);

	p = __stop_machine_run(take_cpu_down, &tcd_param, cpu);

	if (IS_ERR(p) || cpu_online(cpu)) {
		/* CPU didn't die: tell everyone.  Can't complain. */
		if (raw_notifier_call_chain(&cpu_chain, CPU_DOWN_FAILED | mod,
					    hcpu) == NOTIFY_BAD)
			BUG();

		if (IS_ERR(p)) {
			err = PTR_ERR(p);
			goto out_allowed;
		}
		goto out_thread;
	}

	/* Wait for it to sleep (leaving idle task). */
	while (!idle_cpu(cpu))
		yield();

	/* This actually kills the CPU. */
	__cpu_die(cpu);

	/* CPU is completely dead: tell everyone.  Too late to complain. */
	if (raw_notifier_call_chain(&cpu_chain, CPU_DEAD | mod,
				    hcpu) == NOTIFY_BAD)
		BUG();

	check_for_tasks(cpu);

out_thread:
	err = kthread_stop(p);
out_allowed:
	set_cpus_allowed_ptr(current, &old_allowed);
out_release:
	cpu_hotplug_done();
	if (!err) {
		if (raw_notifier_call_chain(&cpu_chain, CPU_POST_DEAD | mod,
					    hcpu) == NOTIFY_BAD)
			BUG();
	}
	return err;
}

int __ref cpu_down(unsigned int cpu)
{
	int err = 0;

	cpu_maps_update_begin();

	if (cpu_hotplug_disabled) {
		err = -EBUSY;
		goto out;
	}

	cpu_clear(cpu, cpu_active_map);

	/*
	 * Make sure the all cpus did the reschedule and are not
	 * using stale version of the cpu_active_map.
	 * This is not strictly necessary becuase stop_machine()
	 * that we run down the line already provides the required
	 * synchronization. But it's really a side effect and we do not
	 * want to depend on the innards of the stop_machine here.
	 */
	synchronize_sched();

	err = _cpu_down(cpu, 0);

	if (cpu_online(cpu))
		cpu_set(cpu, cpu_active_map);

out:
	cpu_maps_update_done();
	return err;
}
EXPORT_SYMBOL(cpu_down);
#endif /*CONFIG_HOTPLUG_CPU*/

/* Requires cpu_add_remove_lock to be held */
static int __cpuinit _cpu_up(unsigned int cpu, int tasks_frozen)
{
	int ret, nr_calls = 0;
	void *hcpu = (void *)(long)cpu;
	unsigned long mod = tasks_frozen ? CPU_TASKS_FROZEN : 0;

	if (cpu_online(cpu) || !cpu_present(cpu))
		return -EINVAL;

	cpu_hotplug_begin();
	ret = __raw_notifier_call_chain(&cpu_chain, CPU_UP_PREPARE | mod, hcpu,
							-1, &nr_calls);
	if (ret == NOTIFY_BAD) {
		nr_calls--;
		printk("%s: attempt to bring up CPU %u failed\n",
				__func__, cpu);
		ret = -EINVAL;
		goto out_notify;
	}

	/* Arch-specific enabling code. */
	ret = __cpu_up(cpu);
	if (ret != 0)
		goto out_notify;
	BUG_ON(!cpu_online(cpu));

	/* Now call notifier in preparation. */
	raw_notifier_call_chain(&cpu_chain, CPU_ONLINE | mod, hcpu);

out_notify:
	if (ret != 0)
		__raw_notifier_call_chain(&cpu_chain,
				CPU_UP_CANCELED | mod, hcpu, nr_calls, NULL);
	cpu_hotplug_done();

	return ret;
}

int __cpuinit cpu_up(unsigned int cpu)
{
	int err = 0;
	if (!cpu_isset(cpu, cpu_possible_map)) {
		printk(KERN_ERR "can't online cpu %d because it is not "
			"configured as may-hotadd at boot time\n", cpu);
#if defined(CONFIG_IA64) || defined(CONFIG_X86_64) || defined(CONFIG_S390)
		printk(KERN_ERR "please check additional_cpus= boot "
				"parameter\n");
#endif
		return -EINVAL;
	}

	cpu_maps_update_begin();

	if (cpu_hotplug_disabled) {
		err = -EBUSY;
		goto out;
	}

	err = _cpu_up(cpu, 0);

	if (cpu_online(cpu))
		cpu_set(cpu, cpu_active_map);

out:
	cpu_maps_update_done();
	return err;
}

#ifdef CONFIG_PM_SLEEP_SMP
static cpumask_t frozen_cpus;

int disable_nonboot_cpus(void)
{
	int cpu, first_cpu, error = 0;

	cpu_maps_update_begin();
	first_cpu = first_cpu(cpu_online_map);
	/* We take down all of the non-boot CPUs in one shot to avoid races
	 * with the userspace trying to use the CPU hotplug at the same time
	 */
	cpus_clear(frozen_cpus);
	printk("Disabling non-boot CPUs ...\n");
	for_each_online_cpu(cpu) {
		if (cpu == first_cpu)
			continue;
		error = _cpu_down(cpu, 1);
		if (!error) {
			cpu_set(cpu, frozen_cpus);
			printk("CPU%d is down\n", cpu);
		} else {
			printk(KERN_ERR "Error taking CPU%d down: %d\n",
				cpu, error);
			break;
		}
	}
	if (!error) {
		BUG_ON(num_online_cpus() > 1);
		/* Make sure the CPUs won't be enabled by someone else */
		cpu_hotplug_disabled = 1;
	} else {
		printk(KERN_ERR "Non-boot CPUs are not disabled\n");
	}
	cpu_maps_update_done();
	return error;
}

void __ref enable_nonboot_cpus(void)
{
	int cpu, error;

	/* Allow everyone to use the CPU hotplug again */
	cpu_maps_update_begin();
	cpu_hotplug_disabled = 0;
	if (cpus_empty(frozen_cpus))
		goto out;

	printk("Enabling non-boot CPUs ...\n");
	for_each_cpu_mask_nr(cpu, frozen_cpus) {
		error = _cpu_up(cpu, 1);
		if (!error) {
			printk("CPU%d is up\n", cpu);
			continue;
		}
		printk(KERN_WARNING "Error taking CPU%d up: %d\n", cpu, error);
	}
	cpus_clear(frozen_cpus);
out:
	cpu_maps_update_done();
}
#endif /* CONFIG_PM_SLEEP_SMP */

#endif /* CONFIG_SMP */

#ifndef CONFIG_HAVE_CPUMASK_OF_CPU_MAP
/* 64 bits of zeros, for initializers. */
#if BITS_PER_LONG == 32
#define Z64 0, 0
#else
#define Z64 0
#endif

/* Initializer macros. */
#define CMI0(n) { .bits = { 1UL << (n) } }
#define CMI(n, ...) { .bits = { __VA_ARGS__, 1UL << ((n) % BITS_PER_LONG) } }

#define CMI8(n, ...)						\
	CMI((n), __VA_ARGS__), CMI((n)+1, __VA_ARGS__),		\
	CMI((n)+2, __VA_ARGS__), CMI((n)+3, __VA_ARGS__),	\
	CMI((n)+4, __VA_ARGS__), CMI((n)+5, __VA_ARGS__),	\
	CMI((n)+6, __VA_ARGS__), CMI((n)+7, __VA_ARGS__)

#if BITS_PER_LONG == 32
#define CMI64(n, ...)							\
	CMI8((n), __VA_ARGS__), CMI8((n)+8, __VA_ARGS__),		\
	CMI8((n)+16, __VA_ARGS__), CMI8((n)+24, __VA_ARGS__),		\
	CMI8((n)+32, 0, __VA_ARGS__), CMI8((n)+40, 0, __VA_ARGS__),	\
	CMI8((n)+48, 0, __VA_ARGS__), CMI8((n)+56, 0, __VA_ARGS__)
#else
#define CMI64(n, ...)							\
	CMI8((n), __VA_ARGS__), CMI8((n)+8, __VA_ARGS__),		\
	CMI8((n)+16, __VA_ARGS__), CMI8((n)+24, __VA_ARGS__),		\
	CMI8((n)+32, __VA_ARGS__), CMI8((n)+40, __VA_ARGS__),	\
	CMI8((n)+48, __VA_ARGS__), CMI8((n)+56, __VA_ARGS__)
#endif

#define CMI256(n, ...)							\
	CMI64((n), __VA_ARGS__), CMI64((n)+64, Z64, __VA_ARGS__),	\
	CMI64((n)+128, Z64, Z64, __VA_ARGS__),				\
	CMI64((n)+192, Z64, Z64, Z64, __VA_ARGS__)
#define Z256 Z64, Z64, Z64, Z64

#define CMI1024(n, ...)					\
	CMI256((n), __VA_ARGS__),			\
	CMI256((n)+256, Z256, __VA_ARGS__),		\
	CMI256((n)+512, Z256, Z256, __VA_ARGS__),	\
	CMI256((n)+768, Z256, Z256, Z256, __VA_ARGS__)
#define Z1024 Z256, Z256, Z256, Z256

/* We want this statically initialized, just to be safe.  We try not
 * to waste too much space, either. */
static const cpumask_t cpumask_map[] = {
	CMI0(0), CMI0(1), CMI0(2), CMI0(3),
#if NR_CPUS > 4
	CMI0(4), CMI0(5), CMI0(6), CMI0(7),
#endif
#if NR_CPUS > 8
	CMI0(8), CMI0(9), CMI0(10), CMI0(11),
	CMI0(12), CMI0(13), CMI0(14), CMI0(15),
#endif
#if NR_CPUS > 16
	CMI0(16), CMI0(17), CMI0(18), CMI0(19),
	CMI0(20), CMI0(21), CMI0(22), CMI0(23),
	CMI0(24), CMI0(25), CMI0(26), CMI0(27),
	CMI0(28), CMI0(29), CMI0(30), CMI0(31),
#endif
#if NR_CPUS > 32
#if BITS_PER_LONG == 32
	CMI(32, 0), CMI(33, 0), CMI(34, 0), CMI(35, 0),
	CMI(36, 0), CMI(37, 0), CMI(38, 0), CMI(39, 0),
	CMI(40, 0), CMI(41, 0), CMI(42, 0), CMI(43, 0),
	CMI(44, 0), CMI(45, 0), CMI(46, 0), CMI(47, 0),
	CMI(48, 0), CMI(49, 0), CMI(50, 0), CMI(51, 0),
	CMI(52, 0), CMI(53, 0), CMI(54, 0), CMI(55, 0),
	CMI(56, 0), CMI(57, 0), CMI(58, 0), CMI(59, 0),
	CMI(60, 0), CMI(61, 0), CMI(62, 0), CMI(63, 0),
#else
	CMI0(32), CMI0(33), CMI0(34), CMI0(35),
	CMI0(36), CMI0(37), CMI0(38), CMI0(39),
	CMI0(40), CMI0(41), CMI0(42), CMI0(43),
	CMI0(44), CMI0(45), CMI0(46), CMI0(47),
	CMI0(48), CMI0(49), CMI0(50), CMI0(51),
	CMI0(52), CMI0(53), CMI0(54), CMI0(55),
	CMI0(56), CMI0(57), CMI0(58), CMI0(59),
	CMI0(60), CMI0(61), CMI0(62), CMI0(63),
#endif /* BITS_PER_LONG == 64 */
#endif
#if NR_CPUS > 64
	CMI64(64, Z64),
#endif
#if NR_CPUS > 128
	CMI64(128, Z64, Z64), CMI64(192, Z64, Z64, Z64),
#endif
#if NR_CPUS > 256
	CMI256(256, Z256),
#endif
#if NR_CPUS > 512
	CMI256(512, Z256, Z256), CMI256(768, Z256, Z256, Z256),
#endif
#if NR_CPUS > 1024
	CMI1024(1024, Z1024),
#endif
#if NR_CPUS > 2048
	CMI1024(2048, Z1024, Z1024), CMI1024(3072, Z1024, Z1024, Z1024),
#endif
#if NR_CPUS > 4096
#error NR_CPUS too big.  Fix initializers or set CONFIG_HAVE_CPUMASK_OF_CPU_MAP
#endif
};

const cpumask_t *cpumask_of_cpu_map = cpumask_map;
#endif /* !CONFIG_HAVE_CPUMASK_OF_CPU_MAP */
