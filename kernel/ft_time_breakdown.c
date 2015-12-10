/* 
 * ft_time_breakdown.c  
 *
 * Author: Marina
 */

#include <linux/ft_time_breakdown.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>

#if FT_BREAKDOWN_TIME
static int home_kernel;

struct time_statistics{
        u64 min;
        u64 max;
        u64 tot;
        u64 count;
	char* name;
};

struct time_statistics breackdown_times[MAX_BREACKDOWNS];

void ft_start_time(u64 *time){
        *time= cpu_clock(home_kernel);
}

void ft_end_time(u64 *time){
        *time= cpu_clock(home_kernel) - *time;
}

void ft_update_time(u64 *time, unsigned int type){
	u64 old;
	
again1:	old= breackdown_times[type].tot;
        if (cmpxchg64(&breackdown_times[type].tot, old, old+*time) != old)
                 goto again1;
again2: old= breackdown_times[type].count;
        if (cmpxchg64(&breackdown_times[type].count, old, old+1) != old)
                 goto again2;
again3: old= breackdown_times[type].min;
	if(old>*time){
        	if (cmpxchg64(&breackdown_times[type].min, old, *time) != old)
                	 goto again3;
	}
again4: old= breackdown_times[type].max;
	if(old<*time){
        	if (cmpxchg64(&breackdown_times[type].max, old, *time) != old)
                	 goto again4;
	}
}

int write_ft_time_breakdown(struct file *file, const char __user *buffer, unsigned long count, void *data)
{
 	long action;
	int i;

        kstrtol_from_user(buffer, count, 0, &action);
	
	if(action==0){
		for(i=0; i<MAX_BREACKDOWNS; i++){
                	breackdown_times[i].min= ~0;
                	breackdown_times[i].max= 0;
                	breackdown_times[i].tot= 0;
                	breackdown_times[i].count= 0;
	        }

	}

	return count;
}

int read_ft_time_breakdown(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	char *p = page;
        int i,len;

	for(i=0; i<MAX_BREACKDOWNS; i++){
        	p += sprintf(p, "%d : min %llu max %llu avg %llu count %llu\n", i, breackdown_times[i].min, breackdown_times[i].max, breackdown_times[i].count? (breackdown_times[i].tot/breackdown_times[i].count) : 0, breackdown_times[i].count);
	}

        len = (p -page) - off;
        if (len < 0)
                len = 0;
        *eof = (len <= count) ? 1 : 0;
        *start = page + off;
        return len;

}

static int __init ft_time_breakdown_init(void){
	int i;
	struct proc_dir_entry *res;

#ifndef SUPPORT_FOR_CLUSTERING
        home_kernel= _cpu;
#else
        home_kernel= cpumask_first(cpu_present_mask);
#endif
	for(i=0; i<MAX_BREACKDOWNS; i++){
		breackdown_times[i].min= ~0;
		breackdown_times[i].max= 0;
		breackdown_times[i].tot= 0;
		breackdown_times[i].count= 0;
	}
	
	res = create_proc_entry("ft_time_breakdown", S_IRUGO, NULL);
        if (!res) {
                printk("%s: create_proc_entry failed (%p)\n", __func__, res);
                return -ENOMEM;
        }
        res->read_proc = read_ft_time_breakdown;
        res->write_proc = write_ft_time_breakdown;

	return 0;
}

late_initcall(ft_time_breakdown_init);

#endif
