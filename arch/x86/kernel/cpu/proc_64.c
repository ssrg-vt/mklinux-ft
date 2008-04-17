#include <linux/smp.h>
#include <linux/timex.h>
#include <linux/string.h>
#include <asm/semaphore.h>
#include <linux/seq_file.h>
#include <linux/cpufreq.h>

/*
 *	Get CPU information for use by the procfs.
 */

static int show_cpuinfo(struct seq_file *m, void *v)
{
	struct cpuinfo_x86 *c = v;
	int cpu = 0, i;

#ifdef CONFIG_SMP
	cpu = c->cpu_index;
#endif

	seq_printf(m, "processor\t: %u\n"
		   "vendor_id\t: %s\n"
		   "cpu family\t: %d\n"
		   "model\t\t: %d\n"
		   "model name\t: %s\n",
		   (unsigned)cpu,
		   c->x86_vendor_id[0] ? c->x86_vendor_id : "unknown",
		   c->x86,
		   (int)c->x86_model,
		   c->x86_model_id[0] ? c->x86_model_id : "unknown");

	if (c->x86_mask || c->cpuid_level >= 0)
		seq_printf(m, "stepping\t: %d\n", c->x86_mask);
	else
		seq_printf(m, "stepping\t: unknown\n");

	if (cpu_has(c, X86_FEATURE_TSC)) {
		unsigned int freq = cpufreq_quick_get((unsigned)cpu);

		if (!freq)
			freq = cpu_khz;
		seq_printf(m, "cpu MHz\t\t: %u.%03u\n",
			   freq / 1000, (freq % 1000));
	}

	/* Cache size */
	if (c->x86_cache_size >= 0)
		seq_printf(m, "cache size\t: %d KB\n", c->x86_cache_size);

#ifdef CONFIG_SMP
	if (smp_num_siblings * c->x86_max_cores > 1) {
		seq_printf(m, "physical id\t: %d\n", c->phys_proc_id);
		seq_printf(m, "siblings\t: %d\n",
			       cpus_weight(per_cpu(cpu_core_map, cpu)));
		seq_printf(m, "core id\t\t: %d\n", c->cpu_core_id);
		seq_printf(m, "cpu cores\t: %d\n", c->booted_cores);
	}
#endif

	seq_printf(m,
		   "fpu\t\t: yes\n"
		   "fpu_exception\t: yes\n"
		   "cpuid level\t: %d\n"
		   "wp\t\t: yes\n"
		   "flags\t\t:",
		   c->cpuid_level);

	for (i = 0; i < 32*NCAPINTS; i++)
		if (cpu_has(c, i) && x86_cap_flags[i] != NULL)
			seq_printf(m, " %s", x86_cap_flags[i]);

	seq_printf(m, "\nbogomips\t: %lu.%02lu\n",
		   c->loops_per_jiffy/(500000/HZ),
		   (c->loops_per_jiffy/(5000/HZ)) % 100);

	if (c->x86_tlbsize > 0)
		seq_printf(m, "TLB size\t: %d 4K pages\n", c->x86_tlbsize);
	seq_printf(m, "clflush size\t: %d\n", c->x86_clflush_size);
	seq_printf(m, "cache_alignment\t: %d\n", c->x86_cache_alignment);

	seq_printf(m, "address sizes\t: %u bits physical, %u bits virtual\n",
		   c->x86_phys_bits, c->x86_virt_bits);

	seq_printf(m, "power management:");
	for (i = 0; i < 32; i++) {
		if (c->x86_power & (1 << i)) {
			if (i < ARRAY_SIZE(x86_power_flags) &&
			    x86_power_flags[i])
				seq_printf(m, "%s%s",
					   x86_power_flags[i][0]?" ":"",
					   x86_power_flags[i]);
			else
				seq_printf(m, " [%d]", i);
		}
	}

	seq_printf(m, "\n\n");

	return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	if (*pos == 0)	/* just in case, cpu 0 is not the first */
		*pos = first_cpu(cpu_online_map);
	if ((*pos) < NR_CPUS && cpu_online(*pos))
		return &cpu_data(*pos);
	return NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	*pos = next_cpu(*pos, cpu_online_map);
	return c_start(m, pos);
}

static void c_stop(struct seq_file *m, void *v)
{
}

const struct seq_operations cpuinfo_op = {
	.start = c_start,
	.next =	c_next,
	.stop =	c_stop,
	.show =	show_cpuinfo,
};
