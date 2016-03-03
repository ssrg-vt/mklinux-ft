 
/*
 * Popcorn Namespaces
 * 
 * Author: Marina
 */

#include <linux/err.h>
#include <linux/proc_fs.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/popcorn_namespace.h>
#include <linux/spinlock.h>
#include <linux/ft_replication.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <asm/atomic.h>
#include <asm/msr.h>
#include <linux/time.h>

//#define DET_PROF 1

static struct kmem_cache *popcorn_ns_cachep;
struct proc_dir_entry *res;
DEFINE_SPINLOCK(ft_lock); 

struct popcorn_namespace init_pop_ns = {
	.kref = {
		.refcount= ATOMIC_INIT(2),
	},
	.activate= 0,
	.root= 0,
	.replication_degree= 0,
};
EXPORT_SYMBOL_GPL(init_pop_ns);

int is_popcorn_namespace_active(struct popcorn_namespace* ns){
	if(ns){
		if(ns!=&init_pop_ns){
			return ns->activate==1;
		}
	}

	return 0;
}

int det_shepherd(void *data);
static struct popcorn_namespace *create_popcorn_namespace(struct popcorn_namespace *parent_ns)
{
	struct popcorn_namespace *ns;
	int err = -ENOMEM;

	ns = kmem_cache_zalloc(popcorn_ns_cachep, GFP_KERNEL);
	if (ns == NULL)
		goto out;

	kref_init(&ns->kref);
	init_task_list(ns);
	//add_task_to_ns(ns, current);
	//set_token(ns, current);
	
	ns->shepherd = kthread_run(det_shepherd, (void *)ns, "shepherd(%d)", current->pid);
	printk("Shepherd created %d\n", ns->shepherd->pid);

        return ns;

out:
        return ERR_PTR(err);
}

struct popcorn_namespace* get_popcorn_ns(struct popcorn_namespace *ns){
	if(ns!= &init_pop_ns)
		kref_get(&ns->kref);
	return ns;
}

struct popcorn_namespace *copy_pop_ns(unsigned long flags, struct popcorn_namespace *old_ns)
{
	if (!(flags & CLONE_NEWPOPCORN)) {
		return get_popcorn_ns(old_ns);
	}
	if (flags & (CLONE_THREAD|CLONE_PARENT)) {
		return ERR_PTR(-EINVAL);
	}
	return create_popcorn_namespace(old_ns);
}

static void destroy_popcorn_namespace(struct popcorn_namespace *ns)
{
	// Also terminate the shepherd
	if (ns->shepherd != NULL) {
		kthread_stop(ns->shepherd);
	}
	kmem_cache_free(popcorn_ns_cachep, ns);
}

void free_popcorn_ns(struct kref *kref)
{
	struct popcorn_namespace *ns;

	ns = container_of(kref, struct popcorn_namespace, kref);

	destroy_popcorn_namespace(ns);

}

void put_pop_ns(struct popcorn_namespace *ns)
{
        if (ns != &init_pop_ns)
                kref_put(&ns->kref, free_popcorn_ns);
}

int read_notify_popcorn_ns(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	char *p = page;
	int len;
	struct popcorn_namespace *ns = current->nsproxy->pop_ns;

	if(ns){
		if(ns==&init_pop_ns){
			p += sprintf(p, "popcorn ns %p is init popcorn => no associated by default\n", ns);
		}
		else{
			if(ns->activate==1){
				p += sprintf(p, "popcorn ns is %p. It is associate root is pid %d and replication degree is %d\n", ns,ns->root,ns->replication_degree);
			}
			else{
				 p += sprintf(p, "popcorn ns is %p. It is not associate\n", ns);
			}
			
		}
	}
	else{
		 p += sprintf(p, "no popcorn ns pointer \n");
	}

  	len = (p -page) - off;
	if (len < 0)
		len = 0;
	*eof = (len <= count) ? 1 : 0;
	*start = page + off;
	return len;
}

int associate_to_popcorn_ns(struct task_struct * tsk, int replication_degree, int type)
{
	struct popcorn_namespace* pop;

	pop= tsk->nsproxy->pop_ns;
	if(!pop){
		printk("%s: no popcorn_ns pointer\n",__func__);
		return -1;
	}
		
	if (tsk->nsproxy->pop_ns == &init_pop_ns) {
                printk("%s: tring to associate init popcorn namespace with popcorn from pid %d. Create new namespace before tring again.\n", __func__,tsk->pid);
                return -1;
        }
	
	if(pop->activate==1){
		printk("%s: tring to associate popcorn namespace from pid %d but already associated by pid %d\n", __func__,tsk->pid,pop->root);
                return -1;
	}

	spin_lock(&ft_lock);
	if(pop->activate==0){
		pop->root= tsk->pid;
		//tsk->replica_type= ROOT_POT_PRIMARY_REPLICA;
		ft_modify_replica_type(tsk, type);
		pop->replication_degree= replication_degree;
		pop->activate=1;
	}
	spin_unlock(&ft_lock);

	printk("%s: associated popcorn namespace %p with root %d and replication_degree %d\n",__func__,pop,pop->root,pop->replication_degree);
	return 0;
}


int write_notify_popcorn_ns(struct file *file, const char __user *buffer, unsigned long count, void *data)
{
	long replication_degree;
	kstrtol_from_user(buffer, count, 0, &replication_degree);

	if(replication_degree > 0 && replication_degree < NR_CPUS){

		get_task_struct(current);

		if((associate_to_popcorn_ns(current, replication_degree, FT_ROOT_POT_PRIMARY_REPLICA))==-1) {
			printk("associate_to_popcorn_ns failed for pid %d\n", current->pid);
		}
		else{
			printk("task pid %d %s associated with popcorn\n",current->pid, current->comm);
		}
		 
		put_task_struct(current);

	}
	else{
		printk("task pid %d requested an invalid replication degree (%ld)\n",current->pid, replication_degree);
	}

	return count;
}

/*
 * This is the shepherd thread, it checks the "stalling state" in the deterministic execution
 * on the primary. The secondary doesn't have this.
 * Each popcorn namespace should have one,
 * and it quits until the namespace perishes.
 */
int det_shepherd(void *data)
{
	struct popcorn_namespace *ns = (struct popcorn_namespace *) data;
	struct task_list *token, *token2;
	uint64_t tick, tick2;
	uint64_t exp = 10;
	uint64_t pre_bump, bump = 0;
	int id_syscall = 0;
	struct task_struct *bump_task;
	unsigned long flags;

	// I spin until the end of this namespace
	while (!kthread_should_stop()) {
		bump = -2;
		if (ns->task_count == 0 ||
				ns->wait_count == 0) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule();
			set_current_state(TASK_RUNNING);
			continue;
		}
		spin_lock_irqsave(&ns->task_list_lock, flags);
		token = ns->token;
		if (token == NULL ||
				token->task == NULL) {
			spin_unlock(&ns->task_list_lock);
			continue;
		}
		tick = token->task->ft_det_tick;
		spin_unlock_irqrestore(&ns->task_list_lock, flags);
		//schedule();
		udelay(20);
		spin_lock_irqsave(&ns->task_list_lock, flags);
		token2 = ns->token;
		if (token2 == NULL ||
				token2->task == NULL) {
			spin_unlock_irqrestore(&ns->task_list_lock, flags);
			continue;
		}
		tick2 = token2->task->ft_det_tick;
		// Which means the token hasn't been changed during the delay,
		// This is considered as a possible "stalling state"
		if (token == token2 && tick2 == tick) {
			mb();
			// ...And it's not waiting for the token
			if (token->task->ft_det_state != FT_DET_WAIT_TOKEN &&
			// ...And it is waiting for an event that we care about
					token->task->state == TASK_INTERRUPTIBLE &&
			// Hey ey ey, we don't care time & gettimeofday on purpose, this
			// is only for external events
					(token->task->current_syscall == __NR_read ||
				 token->task->current_syscall == __NR_sendto ||
				 token->task->current_syscall == __NR_sendmsg ||
				 token->task->current_syscall == __NR_recvfrom ||
				 token->task->current_syscall == __NR_recvmsg ||
				 token->task->current_syscall == __NR_write ||
				 token->task->current_syscall == __NR_accept ||
				 token->task->current_syscall == __NR_accept4 ||
				 token->task->current_syscall == __NR_poll ||
				 token->task->current_syscall == __NR_epoll_wait ||
				 token->task->current_syscall == __NR_socket)) {
				mb();
				if (ns->wait_count != 0 &&
						token->task->bumped == 0) {
					// Boom-sha-ka-la-ka bump the tick la
					ns->shepherd_bump ++;
					bump_task = token->task;
					id_syscall = token->task->id_syscall;
					bump = ns->last_tick + 1;
					pre_bump = token->task->ft_det_tick;
					token->task->ft_det_tick = ns->last_tick + 1;
					update_token(ns);
					spin_unlock_irqrestore(&ns->task_list_lock, flags);
					// Hello from the other side!
					send_bump(bump_task, id_syscall, pre_bump, bump);
					continue;
				}
			}
		}
		spin_unlock_irqrestore(&ns->task_list_lock, flags);
	}
}

#ifdef DET_PROF
__inline__ uint64_t perf_counter(struct timeval *tv)
{
	do_gettimeofday(tv);
}
#endif

int is_det_sched_disable(struct task_struct *task){
	return (task->ft_popcorn && task->ft_popcorn->disable_det_sched==1);
}

void disable_det_sched(struct task_struct *task){
	struct task_list *objPtr;
	struct popcorn_namespace *ns;
	struct list_head *iter= NULL;

	if(task->ft_popcorn && task->ft_popcorn->disable_det_sched==0 && !is_there_any_secondary_replica(task->ft_popcorn)){
		task->ft_popcorn->disable_det_sched= 1;
		
		//wake up all threads after disabling det sched
		ns = task->nsproxy->pop_ns;
        	list_for_each_prev(iter, &ns->ns_task_list.task_list_member) {
                	objPtr = list_entry(iter, struct task_list, task_list_member);
                	wake_up_process(objPtr->task);	
		}
	}
}

long __det_start(struct task_struct *task)
{
	struct popcorn_namespace *ns;
	unsigned long flags= 0;
#ifdef DET_PROF
	uint64_t dtime;
#endif

	if(!is_popcorn(task) || is_det_sched_disable(task)) {
		return 0;
	}

	
	/*cannot avoid to run deterministically after failure. The secondary copy migth be beyond, so the threads still need to det run to consume
	 *exactly the same syscall done by the primary
	if(ft_is_primary_after_secondary_replica(task) 
		&& !is_there_any_secondary_replica(task->ft_popcorn) ){
		return 0;
	}*/
	//trace_printk("det \n");
	ns = task->nsproxy->pop_ns;
#ifdef DET_PROF
	dtime = (uint64_t) ktime_get().tv64;
#endif

	for (;;) {
		set_task_state(task, TASK_INTERRUPTIBLE);
		mb();
		spin_lock_irqsave(&ns->task_list_lock, flags);
		if (have_token(task) || is_det_sched_disable(task)) {
			mb();
			set_task_state(task, TASK_RUNNING);
			spin_unlock_irqrestore(&ns->task_list_lock, flags);
			break;
		} else {
			mb();
			ns->wait_count ++;
			spin_unlock_irqrestore(&ns->task_list_lock, flags);
			// We might get into sleep, time for calling the Cavalry to save the rest of us
			if (ns->shepherd != NULL &&
					ft_is_primary_replica(task)) {
				wake_up_process(ns->shepherd);
			}
		}
		schedule();
		spin_lock_irqsave(&ns->task_list_lock, flags);
		mb();
		ns->wait_count --;
		spin_unlock_irqrestore(&ns->task_list_lock, flags);
		if (ns->shepherd != NULL &&
				ft_is_primary_replica(task)) {
			wake_up_process(ns->shepherd);
		}
	}
	//trace_printk("det f \n");
	// Out of waiting for token, now go active
	spin_lock_irqsave(&ns->task_list_lock, flags);
	task->ft_det_state = FT_DET_ACTIVE;
	spin_unlock_irqrestore(&ns->task_list_lock, flags);
	//trace_printk("has token with %d\n", task->ft_det_tick);
#ifdef DET_PROF
	dtime = (uint64_t) ktime_get().tv64 - dtime;
	spin_lock(&(ns->tick_cost_lock));
	ns->start_cost[task->pid % 64] += dtime;
	spin_unlock(&(ns->tick_cost_lock));
#endif

	return 1;
}

asmlinkage long sys_popcorn_det_start(void)
{
	return __det_start(current);
}

asmlinkage long sys_popcorn_det_tick(long tick)
{
#ifdef DET_PROF
	uint64_t dtime;
	ns = current->nsproxy->pop_ns;
#endif

	if(is_popcorn(current)) {
	//trace_printk("\n");
#ifdef DET_PROF
		dtime = (uint64_t) ktime_get().tv64;
#endif
		update_tick(current, tick);
		//printk("pid %d ticks %d\n", current->pid, current->ft_det_tick);
#ifdef DET_PROF
		dtime = (uint64_t) ktime_get().tv64 - dtime;
		spin_lock(&(ns->tick_cost_lock));
		ns->tick_cost[current->pid % 64] += dtime;
		spin_unlock(&(ns->tick_cost_lock));
#endif
		//trace_printk("f \n");
		return 0;
	}

	return 0;
}

long __det_end(struct task_struct *task)
{
	struct popcorn_namespace *ns;
	unsigned long flags= 0;
#ifdef DET_PROF
	uint64_t dtime;
#endif

	if(!is_popcorn(task)) {
		return 0;
	}
	//trace_printk("\n");

	//trace_printk("end with %d\n", task->ft_det_tick);
#ifdef DET_PROF
	dtime = (uint64_t) ktime_get().tv64;
#endif
	ns = task->nsproxy->pop_ns;

	spin_lock_irqsave(&ns->task_list_lock, flags);
	task->ft_det_state = FT_DET_INACTIVE;
	spin_unlock_irqrestore(&ns->task_list_lock, flags);
	mb();
	update_tick(task, 1);
	//dump_task_list(ns);

#ifdef DET_PROF
	dtime = (uint64_t) ktime_get().tv64 - dtime;
	spin_lock(&(ns->tick_cost_lock));
	ns->end_cost[task->pid % 64] += dtime;
	spin_unlock(&(ns->tick_cost_lock));
#endif
	//trace_printk("f \n");
	return ns->token->task->pid;
}

asmlinkage long sys_popcorn_det_end(void)
{
	return __det_end(current);
}

static int register_popcorn_ns(void)
{
	printk("Inserting popcorn fd in proc\n");

	res = create_proc_entry("popcorn_namespace", S_IRUGO, NULL);
	if (!res) {
		printk("%s: create_proc_entry failed (%p)\n", __func__, res);
		return -ENOMEM;
	}
	res->read_proc = read_notify_popcorn_ns;
	res->write_proc = write_notify_popcorn_ns;
	
	return 0;
}

static __init int popcorn_namespaces_init(void)
{
	printk("Initializing popcorn_namespace\n");
	popcorn_ns_cachep = KMEM_CACHE(popcorn_namespace, SLAB_PANIC);
	if (!popcorn_ns_cachep) {
		printk("%s: popcorn_namespace initialization error.\n", __func__);
		return -ENOMEM;
	}
	
	register_popcorn_ns();
	
	return 0;
}

__initcall(popcorn_namespaces_init);
