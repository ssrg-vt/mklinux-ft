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

asmlinkage long sys_print_current_time(void){
	printk("%s : %u\n", __func__, cpu_clock(home_kernel));
	return 0;
}

void ft_start_time(u64 *time){
        *time= cpu_clock(home_kernel);
	//trace_printk("%pS\n", __builtin_return_address(0));
}

void ft_end_time(u64 *time){
        *time= cpu_clock(home_kernel) - *time;
	//trace_printk("%pS\n", __builtin_return_address(0));
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

extern void init_net_stat(void);

void init_breackdown(void){
	int i;

	for(i=0; i<MAX_BREACKDOWNS; i++){
		breackdown_times[i].min= ~0;
		breackdown_times[i].max= 0;
		breackdown_times[i].tot= 0;
		breackdown_times[i].count= 0;
	}
}

int write_ft_time_breakdown(struct file *file, const char __user *buffer, unsigned long count, void *data)
{
 	long action;

        kstrtol_from_user(buffer, count, 0, &action);
	
	if(action==0){
		init_breackdown();	
		init_net_stat();
	}

	return count;
}

int print_ft_time_breakdown(void){
	int i;

	printk("FT_TIME_HOOK_BEF_NET 0\nFT_TIME_BEF_NET_REP 1\nFT_TIME_HOOK_AFT_NET 2\nFT_TIME_AFT_NET_REP 3\nFT_TIME_HOOK_BEF_TRA 4\nFT_TIME_BEF_TRA_REP 5\nFT_TIME_HOOK_AFT_TRA 6\nFT_TIME_AFT_TRA_REP 7\nFT_TIME_SEND_PACKET_REP 8\nFT_TIME_INJECT_RECV_PACKET 9\nFT_TIME_INJECT_HANDSHACKE_PACKETS\nTOT_TIME_SEND 11\nTOT_TIME_RCV 12\nTOT_TIME_POLL 13\nTOT_TIME_319 14\nTOT_TIME_320 15\nTOT_TIME_ACCEPT 16\nFT_TIME_SEND_SYCALL 17\nFT_TIME_RCV_SYSCALL 18\nFT_TIME_DET_START 19\nFT_TIME_WAIT_BUMP 20\nFT_TIME_SEND_BUMP 21\n\n");

	printk("breakdowns are in nanosecond\n");

	for(i=0; i<MAX_BREACKDOWNS; i++){
                printk("%d : min %llu max %llu avg %llu tot %llu count %llu\n", i, breackdown_times[i].min, breackdown_times[i].max, breackdown_times[i].count? (breackdown_times[i].tot/breackdown_times[i].count) : 0, breackdown_times[i].tot, breackdown_times[i].count);
        }

	return 0;
}

int read_ft_time_breakdown(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	char *p = page;
        int i,len;

	p+= sprintf(p,"FT_TIME_HOOK_BEF_NET 0\nFT_TIME_BEF_NET_REP 1\nFT_TIME_HOOK_AFT_NET 2\nFT_TIME_AFT_NET_REP 3\nFT_TIME_HOOK_BEF_TRA 4\nFT_TIME_BEF_TRA_REP 5\nFT_TIME_HOOK_AFT_TRA 6\nFT_TIME_AFT_TRA_REP 7\nFT_TIME_SEND_PACKET_REP 8\nFT_TIME_INJECT_RECV_PACKET 9\nFT_TIME_INJECT_HANDSHACKE_PACKETS\nTOT_TIME_SEND 11\nTOT_TIME_RCV 12\nTOT_TIME_POLL 13\nTOT_TIME_319 14\nTOT_TIME_320 15\nTOT_TIME_ACCEPT 16\nFT_TIME_SEND_SYCALL 17\nFT_TIME_RCV_SYSCALL 18\nFT_TIME_DET_START 19\nFT_TIME_WAIT_BUMP 20\nFT_TIME_SEND_BUMP 21\n\n");

	p+= sprintf(p,"breakdowns are in nanosecond\n");

	for(i=0; i<MAX_BREACKDOWNS; i++){
        	p += sprintf(p, "%d : min %llu max %llu avg %llu tot %llu count %llu\n", i, breackdown_times[i].min, breackdown_times[i].max, breackdown_times[i].count? (breackdown_times[i].tot/breackdown_times[i].count) : 0, breackdown_times[i].tot, breackdown_times[i].count);
	}

        len = (p -page) - off;
        if (len < 0)
                len = 0;
        *eof = (len <= count) ? 1 : 0;
        *start = page + off;
        return len;

}

static int __init ft_time_breakdown_init(void){
	struct proc_dir_entry *res;

#ifndef SUPPORT_FOR_CLUSTERING
        home_kernel= _cpu;
#else
        home_kernel= cpumask_first(cpu_present_mask);
#endif
	init_breackdown();
	
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
