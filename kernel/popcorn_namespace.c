 
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
#include <linux/ft_time_breakdown.h>

//#define DET_PROF 1

static struct kmem_cache *popcorn_ns_cachep;
static struct popcorn_namespace *last_ns = NULL;

struct proc_dir_entry *res;
DEFINE_SPINLOCK(ft_lock);

/* Create an hash table with size @size.
 *
 */
static hashtable_t* create_hashtable(int size){
	hashtable_t *ret;
	hashentry_t **table;
	int i;

	if(size<1)
		return ERR_PTR(-EFAULT);

	ret= kmalloc(sizeof(*ret), GFP_KERNEL);
	if(!ret)
		return ERR_PTR(-ENOMEM);

	table= kmalloc(sizeof(*table)*size, GFP_KERNEL);
	if(!table){
		kfree(ret);
		return ERR_PTR(-ENOMEM);
	}

	for(i=0;i<size;i++){
		table[i]= NULL;
	}

	ret->size = size;
	ret->table = table;
	spin_lock_init(&ret->spinlock);

	return ret;
}

typedef int (*hashdata_compare_cb)(const void *, const void *);

static void* hash_add(hashtable_t *hashtable, int key, void* obj,
		hashdata_compare_cb compare) {
	int hashval;
	void* entry= NULL;
	hashentry_t *new, *head, *app;

	new = kmalloc(sizeof(hashentry_t), GFP_ATOMIC);
	if(!new)
			return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&new->list);
	new->obj = obj;

	hashval = key;

	head = hashtable->table[hashval];
	if (head) {
		spin_lock(&head->spinlock);
		list_for_each_entry(app, &head->list, list){
			if (compare(obj, app->obj)) {
				entry = app->obj;
				spin_unlock(&head->spinlock);
				kfree(new);
				return entry;
			}
		}
		spin_unlock(&head->spinlock);
	} else {
		spin_lock(&hashtable->spinlock);
		hashtable->table[hashval] = kmalloc(sizeof(hashentry_t), GFP_ATOMIC);
		if(!hashtable->table[hashval]){
				spin_unlock(&hashtable->spinlock);
				kfree(new);
				return ERR_PTR(-ENOMEM);
		}
		head= hashtable->table[hashval];
		spin_lock_init(&head->spinlock);
		INIT_LIST_HEAD(&head->list);
		spin_unlock(&hashtable->spinlock);
	}

	spin_lock(&head->spinlock);
	list_add(&new->list, &head->list);
	spin_unlock(&head->spinlock);

	return NULL;
}

static void* hash_remove(hashtable_t *hashtable, int key, void *obj,
		hashdata_compare_cb compare) {
	int hashval;
	hashentry_t *head, *app;
	hashentry_t *entry= NULL;

	hashval= key;

	spin_lock(&hashtable->spinlock);
	head= hashtable->table[hashval];
	if(head){
		list_for_each_entry(app, &head->list, list){
			if(compare(app->obj, obj)){
				entry = app;
				list_del(&app->list);
				goto out;
			}
		}
	}
out:
	spin_unlock(&hashtable->spinlock);
	if(entry) {
		obj = entry->obj;
		kfree(entry);
	}

	return obj;
}

#define FTPID_HASH_SIZE 512
static hashtable_t *global_ftpid_hash;

static int compare_ftpid_entry(const void *data1, const void *data2);
static inline int choose_key_for_ftpid(const void *data, int32_t size);

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
	init_rep_list(ns);
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
	u64 time;
#ifdef LOCK_REPLICATION
	return 0;
#endif

	if(!is_popcorn(task) || is_det_sched_disable(task)) {
		return 0;
	}

	ft_start_time(&time);	
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
	ft_end_time(&time);
	ft_update_time(&time, FT_TIME_DET_START);
	return 1;
}

asmlinkage long sys_popcorn_det_start(void)
{
#ifdef LOCK_REPLICATION
	return __rep_start(current);
#else
	return __det_start(current);
#endif
}

asmlinkage long sys_popcorn_det_tick(long tick)
{
	struct popcorn_namespace *ns;
#ifdef DET_PROF
	uint64_t dtime;
#endif

	if(is_popcorn(current)) {
	//trace_printk("\n");
#ifdef LOCK_REPLICATION
		current->ft_det_state = FT_DET_COND_WAIT_HINT;
		return 0;
#endif

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
#ifdef LOCK_REPLICATION
	return 0;
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
#ifdef LOCK_REPLICATION
	return __rep_end(current);
#else
	return __det_end(current);
#endif
}

long __rep_start(struct task_struct *task)
{
	struct popcorn_namespace *ns;
	int wait_cnt = 0;
	if(!is_popcorn(task)) {
		return 0;
	}
	ns = task->nsproxy->pop_ns;
	mutex_lock(&ns->gmtx);
	for (;;) {
		task->ft_det_state = FT_DET_ACTIVE;
		// Let the __rep_end to unlock the mutex, we are serializing the mutex
		// If the lock ever gets into sleeping, it is going to release the mutex
		// right before futex_wait.
		if (ft_is_primary_replica(task)) {
			// Primary simply falls through.
			break;
		} else if (ft_is_secondary_replica(task)) {
			// Secondary must wait until it sees its turn
			// Basically it means that the secondary cannot proceed until the primary
			// successfully acquires the mutex lock (the userspace one).
			if (wait_rep_turn(ns, task)) {
				trace_printk("Peeking sync for rep_id %llu, gid %llu for %d\n", task->rep_id, atomic_read(&ns->global_rep_id),
					choose_key_for_ftpid(&task->ft_pid, FTPID_HASH_SIZE));
				break;
			} else {
				// Keep waiting
				mutex_unlock(&ns->gmtx);
				wait_cnt ++;
				if (wait_cnt < 200) {
					udelay(5);
				} else {
					schedule_timeout(1);
				}
				mutex_lock(&ns->gmtx);
			}
		}
	}

	return 1;
}

long __rep_end(struct task_struct *task)
{
	struct popcorn_namespace *ns;
	if(!is_popcorn(task)) {
		return 0;
	}

	ns = task->nsproxy->pop_ns;
	if (ft_is_primary_replica(task)) {
		send_rep_turn(ns, task);
	}
	atomic_inc(&ns->global_rep_id);
	task->rep_id++;
	task->ft_det_state = FT_DET_INACTIVE;
	mutex_unlock(&ns->gmtx);
}

// Whenever a new thread is created, the task should go to ns
int add_task_to_ns(struct popcorn_namespace *ns, struct task_struct *task)
{
	unsigned long flags;
	struct task_list *new_task;
#ifdef LOCK_REPLICATION
	struct ftpid_hash_entry *new_hash_node;
#endif
	//printk("Add %x, %d to ns\n", (unsigned long) task, task->pid);
	new_task = kmalloc(sizeof(struct task_list), GFP_KERNEL);
	if (new_task == NULL)
		return -1;

#ifdef LOCK_REPLICATION
	task->rep_id = 0;
	new_hash_node = kmalloc(sizeof(struct ftpid_hash_entry), GFP_KERNEL);
	if (new_hash_node == NULL)
		return -1;

	new_hash_node->ft_pid = &task->ft_pid;
	new_hash_node->ns = ns;
	trace_printk("Adding %d to hash\n", choose_key_for_ftpid(&task->ft_pid, FTPID_HASH_SIZE));
	hash_add(global_ftpid_hash,
			choose_key_for_ftpid(&task->ft_pid, FTPID_HASH_SIZE), new_hash_node,
			compare_ftpid_entry);
	new_task->hash_entry = new_hash_node;
#endif

	task->ft_det_tick = 0;
	new_task->task = task;
	if (ns->shepherd != NULL && ns->shepherd->state == TASK_INTERRUPTIBLE &&
		ft_is_primary_replica(task)) {
		wake_up_process(ns->shepherd);
	}
	spin_lock_irqsave(&ns->task_list_lock, flags);
	mb();
	ns->task_count++;
	list_add_tail(&new_task->task_list_member, &ns->ns_task_list.task_list_member);
	spin_unlock_irqrestore(&ns->task_list_lock, flags);
	return 0;
}

// Whenever a new thread is gone, the task should get deleted
int remove_task_from_ns(struct popcorn_namespace *ns, struct task_struct *task)
{
	struct list_head *iter= NULL;
	struct list_head *n;
	struct task_list *objPtr;
	unsigned long flags;

	spin_lock_irqsave(&ns->task_list_lock, flags);
	list_for_each_safe(iter, n, &ns->ns_task_list.task_list_member) {
		objPtr = list_entry(iter, struct task_list, task_list_member);
		if (objPtr->task == task) {
			hash_remove(global_ftpid_hash, choose_key_for_ftpid(&objPtr->task->ft_pid, FTPID_HASH_SIZE),
					objPtr->hash_entry, compare_ftpid_entry);
			list_del(iter);
			kfree(iter);
			update_token(ns);
			ns->task_count--;
			spin_unlock_irqrestore(&ns->task_list_lock, flags);
#ifdef DET_PROF
			printk("tick_count now for %d %llu %llu %llu\n", task->pid % 64, ns->start_cost[task->pid % 64], ns->tick_cost[task->pid % 64], ns->end_cost[task->pid % 64]);
			ns->tick_cost[task->pid % 64] = 1;
			ns->start_cost[task->pid % 64] = 1;
			ns->end_cost[task->pid % 64] = 1;
#endif
			return 0;
		}
	}
	spin_unlock_irqrestore(&ns->task_list_lock, flags);

	return -1;
}


static int compare_ftpid_entry(const void *data1, const void *data2)
{
	struct ftpid_hash_entry *e1, *e2;
	e1 = data1; e2 = data2;

	return (memcmp(e1->ft_pid, e2->ft_pid, sizeof(struct ft_pid)) == 0 ? 1 : 0);
}

/*
 * Hash function to generate key from ftpid
 * @data: the generic data
 * @size: size of the hash table
 */
static inline int choose_key_for_ftpid(const void *data, int32_t size)
{
	struct ft_pid *ft_pid;
	uint32_t hash = 0;
	size_t i;

	ft_pid = (struct ft_pid *) data;
	for (i = 0; i < ft_pid->level; i++) {
		hash += ft_pid->id_array[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += ft_pid->level;
	hash += (hash << 10);
	hash ^= (hash >> 6);

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash % size;
}

struct popcorn_namespace *find_ns_by_ftpid(struct ft_pid *ft_pid)
{
	unsigned int hashval;
	struct ftpid_hash_entry *ftpid_entry;
	struct popcorn_namespace *ret = NULL;
	hashentry_t *head, *entry;
	hashtable_t *hashtable = global_ftpid_hash;
	struct list_head *iter= NULL;
	struct task_list *objPtr;

	// Let's guess ns first!
	ret = last_ns;
	if (ret != NULL) {
		list_for_each(iter, &ret->ns_task_list.task_list_member) {
			objPtr = list_entry(iter, struct task_list, task_list_member);
			if (objPtr->task->ft_pid.ft_pop_id.id == ft_pid->ft_pop_id.id) {
				last_ns = ret;
				return ret;
			}
		}
	}
	ret = NULL;

	hashval = choose_key_for_ftpid(ft_pid, FTPID_HASH_SIZE);

	head = hashtable->table[hashval];
	if(head) {
		spin_lock(&head->spinlock);
		list_for_each_entry(entry, &head->list, list) {
			ftpid_entry = (struct ftpid_hash_entry *) entry->obj;
			if(are_ft_pid_equals(ft_pid, ftpid_entry->ft_pid)){
				ret = ftpid_entry->ns;
				spin_unlock(&head->spinlock);
				last_ns = ret;
				goto out;
			}
		}
		spin_unlock(&head->spinlock);
	}

out:
	return ret;
}

int wait_rep_turn(struct popcorn_namespace *ns, struct task_struct *task)
{
	// Must be called with ns->gmtx
	// It's not waiting actually, just checking if the head of the queue
	// is what we want.
	if (peek_rep_list(ns, task->rep_id, atomic_read(&ns->global_rep_id), &task->ft_pid)) {
		return dequeue_rep_list(ns);
	}

	return 0;
}

int send_rep_turn(struct popcorn_namespace *ns, struct task_struct *task)
{
	// Must be called with ns->gmtx
	struct rep_sync_msg *msg;
	msg = kmalloc(sizeof(struct rep_sync_msg), GFP_KERNEL);
	if (msg == NULL)
		return -ENOMEM;

	msg->header.type = PCN_KMSG_TYPE_FT_REPSYNC_INFO;
	msg->header.prio = PCN_KMSG_PRIO_NORMAL;
	memcpy(&msg->ft_pid, &task->ft_pid, sizeof(struct ft_pid));
	msg->rep_id = task->rep_id;
	msg->global_rep_id = atomic_read(&ns->global_rep_id);
	mb();
	trace_printk("Sending sync for rep_id %llu, gid %d for %d\n", msg->rep_id, msg->global_rep_id,
		choose_key_for_ftpid(&task->ft_pid, FTPID_HASH_SIZE));
    send_to_all_secondary_replicas(task->ft_popcorn, (struct pcn_kmsg_long_message*) msg, sizeof(struct rep_sync_msg));
	kfree(msg);

	return 0;
}

static int handle_repsync_msg(struct pcn_kmsg_message *inc_msg)
{
	struct rep_sync_msg *msg = (struct rep_sync_msg *) inc_msg;
	struct ft_pid *ft_pid = &msg->ft_pid;
	struct popcorn_namespace *ns;

	trace_printk("Got sync for rep_id %llu, gid %llu for %d\n", msg->rep_id, msg->global_rep_id,
		choose_key_for_ftpid(&msg->ft_pid, FTPID_HASH_SIZE));
	if ((ns = find_ns_by_ftpid(ft_pid)) == NULL) {
		trace_printk("Critical error, cannot find corresponding ns\n");
		pcn_kmsg_free_msg(msg);
		return 1;
	}

	enqueue_rep_list(ns, msg->rep_id, msg->global_rep_id, ft_pid);
	pcn_kmsg_free_msg(msg);
	return 0;
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
	global_ftpid_hash = create_hashtable(FTPID_HASH_SIZE);
	pcn_kmsg_register_callback(PCN_KMSG_TYPE_FT_REPSYNC_INFO, handle_repsync_msg);
	return 0;
}

__initcall(popcorn_namespaces_init);
