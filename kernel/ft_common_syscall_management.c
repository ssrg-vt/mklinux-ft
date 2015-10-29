/*
 * ft_common_syscall_management.c
 *
 * Author: Marina
 * 
 */

#include <linux/ft_replication.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/pcn_kmsg.h>
#include <linux/popcorn_namespace.h>
#include <linux/ft_common_syscall_management.h>
#include <asm/unistd_64.h>

/*
 * Below lines are copied from DMP.
 * Remeber to appericiate them if we make this thing working.
 */
/* MOT options */
#define SPECIAL		(0)		/* comment that this syscall is handled specially */
#define P		(0)
#define S		(1<<0)		/* i.e. always serialize */
#define FD		(1<<1)		/* fd must be first arg: uses fd */
#define FILE_READ	(FD|(1<<2))	/* reads  data via fd */
#define FILE_WRITE	(FD|(1<<3))	/* writes data via fd */
#define FDTABLE		(1<<4)		/* modifies fd table */
#define FSINFO_READ	(1<<5)		/* uses     fs info */
#define FSINFO_WRITE	(1<<6)		/* modifies fs info */
#define MM		(1<<7)
/* sleep options */
#define NOSLEEP		(1<<15)

static uint16_t syscall_info_table[__NR_syscall_max] = {
#include <linux/syscallinfo.h>
};

#define FT_CSYSC_VERBOSE 0
#if FT_CSYSC_VERBOSE
#define FTPRINTK(...) printk(__VA_ARGS__)
#else
#define FTPRINTK(...) ;
#endif

typedef struct _list_entry{
        struct list_head list;
        char *string; //key
        void *obj; //pointer to the object to store
} list_entry_t;

typedef struct _hash_table{
        int size;
        spinlock_t spinlock; //used to lock the whole hash table when adding/removing/looking, not fine grain but effective!
        list_entry_t **table;
}hash_table_t;

static inline struct sleeping_syscall_request *alloc_syscall_req (struct task_struct *task, int det_process_count) {
    struct sleeping_syscall_request *req;
    req = (struct sleeping_syscall_request *) kmalloc(sizeof(struct sleeping_syscall_request) +
                sizeof(uint64_t) * (det_process_count + 1), GFP_KERNEL);

    if (!req)
        return NULL;

    req->header.type = PCN_KMSG_TYPE_FT_SYSCALL_WAKE_UP_INFO;
    req->header.prio = PCN_KMSG_PRIO_NORMAL;
    req->ft_pid = task->ft_pid;

    return req;
}

/* Create an hash table with size @size.
 *
 */
static hash_table_t* create_hashtable(int size){
        hash_table_t *ret;
        list_entry_t **table;
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

        ret->size= size;
        ret->table= table;
        spin_lock_init(&ret->spinlock);

        return ret;
}

static unsigned int hash(hash_table_t *hashtable, char *str)
{
    unsigned int hashval;

    /* we start our hash out at 0 */
    hashval = 0;

    /* for each character, we multiply the old hash by 31 and add the current
     * character.  Remember that shifting a number left is equivalent to 
     * multiplying it by 2 raised to the number of places shifted.  So we 
     * are in effect multiplying hashval by 32 and then subtracting hashval.  
     * Why do we do this?  Because shifting and subtraction are much more 
     * efficient operations than multiplication.
     */
    for(; *str != '\0'; str++) hashval = *str + (hashval << 5) - hashval;

    /* we then return the hash value mod the hashtable size so that it will
     * fit into the necessary range
     */
    return hashval % hashtable->size;
}

/* Return the object stored in @hashtable in the entry with key @key  
 * if any, NULL otherwise.
 */
static void* hash_lookup(hash_table_t *hashtable, char *key){
        unsigned int hashval;
        list_entry_t *head, *entry;
        void* obj= NULL;

        hashval= hash(hashtable, key);
        spin_lock(&hashtable->spinlock);

        head= hashtable->table[hashval];
        if(head){
                list_for_each_entry(entry, &head->list, list){
                        if((strcmp(entry->string,key)==0)){
                                obj= entry->obj;
                                goto out;
                        }

                }
        }

out:    spin_unlock(&hashtable->spinlock);
        return obj;
}

/* Add a new object in @hashtable with key @key and object @obj.
 * 
 * If an entry with the same key is already present, the object of that entry 
 * is returned and the one passed as paramenter is NOT inserted ( => remember to free both @key and @obj) 
 *
 * If no entry with the same key are found, NULL is returned and the entry inserted will use both @key and @obj
 * pointers so do not free them while not removed from the hashtable.
 */
static void* hash_add(hash_table_t *hashtable, char *key, void* obj){
        unsigned int hashval;
        void* entry= NULL;
        list_entry_t *new, *head, *app;

        new= kmalloc(sizeof(list_entry_t), GFP_ATOMIC);
        if(!new)
                return ERR_PTR(-ENOMEM);

        INIT_LIST_HEAD(&new->list);
        new->string= key;
        new->obj= obj;

        hashval= hash(hashtable, key);

        spin_lock(&hashtable->spinlock);

        head= hashtable->table[hashval];

        if(head){
                list_for_each_entry(app, &head->list, list){
                        if((strcmp(app->string, key)==0)){
                                entry= app->obj;
                                spin_unlock(&hashtable->spinlock);
                                kfree(new);
                                return entry;
                        }

                }
        }
        else{
                hashtable->table[hashval]= kmalloc(sizeof(list_entry_t), GFP_ATOMIC);
                if(!hashtable->table[hashval]){
                        spin_unlock(&hashtable->spinlock);
                        kfree(new);
                        return ERR_PTR(-ENOMEM);
                }
                head= hashtable->table[hashval];
                INIT_LIST_HEAD(&head->list);
        }

        list_add(&new->list, &head->list);

        spin_unlock(&hashtable->spinlock);

        return NULL;
}

/* Remove an entry from the hash table @hashtable with key @key.
 *
 * If a corresponding entry to @key is found, the object stored by that entry 
 * is returned, NULL otherwise. 
 *
 * NOTE: remember to free @key and the object returned eventually.
 */
static void* hash_remove(hash_table_t *hashtable, char *key){
        unsigned int hashval;
        list_entry_t *head, *app;
        list_entry_t *entry= NULL;
        void *obj= NULL;

        hashval= hash(hashtable, key);

        spin_lock(&hashtable->spinlock);
        head= hashtable->table[hashval];
        if(head){
                list_for_each_entry(app, &head->list, list){
                        if((strcmp(app->string, key)==0)){
                                entry= app;
                                list_del(&app->list);
                                goto out;
                        }

                }
        }
out:
        spin_unlock(&hashtable->spinlock);
        if(entry){
                obj= entry->obj;
                kfree(entry->string);
                kfree(entry);
        }

        return obj;
}

/* syscall_hash is an hash table used to store info about syscalls that need to be synchronized between replicas.
 *
 * The inital idea is that the primary replica performs the syscall and sends meaningfull info for that syscall to the secondary replicas.
 * Those info can be stored in the hash table while the secondary replica reaches the same syscall, or the secondary replica can create an "empty"
 * entry in the hash and sleeps while the primary send the info over.
 * 
 * The key of the hash table should be computed with get_key from ft_pid entries and id_syscall of the thread.
 * The object stored is a void* that can be used differently by each syscall.
 */
hash_table_t* syscall_hash;

/* Remove an entry from the syscall_hash  with key @key.
 *
 * If a corresponding entry to @key is found, the object stored by that entry 
 * is returned, NULL otherwise. 
 *
 * NOTE: remember to free @key and the object returned eventually.
 */
void* ft_syscall_hash_remove(char *key){
	return hash_remove(syscall_hash, key);
}

/* Add a new object in sycall_hash with key @key and object @obj.
 * 
 * If an entry with the same key is already present, the object of that entry 
 * is returned and the one passed as paramenter is NOT inserted ( => remember to free both @key and @obj) 
 *
 * If no entry with the same key are found, NULL is returned and the entry inserted will use both @key and @obj
 * pointers so do not free them while not removed from the hashtable.
 */
void* ft_syscall_hash_add(char *key, void* obj){
	return hash_add(syscall_hash, key, obj);
}

/* Return the object stored in syscall_hash in the entry with key @key  
 * if any, NULL otherwise.
 */
void* ft_syscall_hash_lookup(char *key){
	return hash_lookup(syscall_hash, key);
}

/* Return a string that is the concatenation of ft_pop_id fields, level, id_array and id_syscall.
 * This uniquely identify each syscall for each ft_pid replica.
 *
 */
char* ft_syscall_get_key(struct ft_pop_rep_id* ft_pop_id, int level, int* id_array, int id_syscall){
        char* string;
        const int size= 1024;
        int pos,i;

        string= kmalloc(size, GFP_KERNEL);
        if(!string)
                return NULL;

        pos= snprintf(string, size,"%d%d%d", ft_pop_id->kernel, ft_pop_id->id, level);
        if(pos>=size)
                goto out_clean;

        if(level){
                for(i=0;i<level;i++){
                        pos= pos+ snprintf(&string[pos], size-pos, "%d", id_array[i]);
                        if(pos>=size)
                                goto out_clean;
                }
        }

        pos= snprintf(&string[pos], size-pos,"%d%c", id_syscall,'\0');
        if(pos>=size)
                goto out_clean;

        return string;

out_clean:
        kfree(string);
        printk("%s: buffer size too small\n", __func__);
        return NULL;

}

/* Return a string that is the concatenation of ft_pop_id fields, level, id_array and id_syscall.
 * This uniquely identify each syscall for each ft_pid replica.
 *
 */
char* ft_syscall_get_key_from_ft_pid(struct ft_pid *ft_pid, int id_syscall){
	return ft_syscall_get_key(&ft_pid->ft_pop_id, ft_pid->level, ft_pid->id_array, id_syscall);
}


static struct workqueue_struct *ft_syscall_info_wq;

struct wait_syscall{
        struct task_struct *task;
        int populated;
	void *private;
};

struct send_syscall_work{
        struct work_struct work;
        struct ft_pop_rep *replica_group; //to know secondary replicas to whom send the msg
	struct ft_pid sender; 
	int syscall_id; //syscall id for that ft_pid replica
	unsigned int private_data_size; //size of the private data of the syscall
	char* private;
};

struct syscall_msg{
        struct pcn_kmsg_hdr header;
        /*the following is pid_t linearized*/
        struct ft_pop_rep_id ft_pop_id;
        int level;
	int id_array[MAX_GENERATION_LENGTH]; 

        int syscall_id;
	unsigned int syscall_info_size;
	
	/*this must be the last field of the struct*/
        char data; /*contains syscall_info*/
};

static int create_syscall_msg(struct ft_pop_rep_id* primary_ft_pop_id, int primary_level, int* primary_id_array, int syscall_id, char* syscall_info, unsigned int syscall_info_size, struct syscall_msg** message, int *msg_size){

	struct syscall_msg* msg;
        int size;
	char* variable_data;

        size= sizeof(*msg) + syscall_info_size;
        msg= kmalloc(size, GFP_KERNEL);
        if(!msg)
                return -ENOMEM;

	msg->header.type= PCN_KMSG_TYPE_FT_SYSCALL_INFO;
        msg->header.prio= PCN_KMSG_PRIO_NORMAL;

        msg->ft_pop_id= *primary_ft_pop_id;
        msg->level= primary_level;
	
	if(primary_level)
		memcpy(msg->id_array, primary_id_array, primary_level*sizeof(int));

	msg->syscall_id= syscall_id;
	msg->syscall_info_size= syscall_info_size;

	variable_data= &msg->data;
	
	if(syscall_info_size){
		memcpy(variable_data, syscall_info, syscall_info_size);
	}

        *message= msg;
        *msg_size= size;

        return 0;
}

static void send_syscall_info_to_secondary_replicas(struct ft_pop_rep *replica_group, struct ft_pop_rep_id* primary_ft_pop_id, int primary_level, int* primary_id_array, int syscall_id, char* syscall_info, unsigned int syscall_info_size){
        struct syscall_msg* msg;
        int msg_size;
        int ret;

        ret= create_syscall_msg(primary_ft_pop_id, primary_level, primary_id_array, syscall_id, syscall_info, syscall_info_size, &msg, &msg_size);
        if(ret)
                return;

        send_to_all_secondary_replicas(replica_group, (struct pcn_kmsg_long_message*) msg, msg_size);

        kfree(msg);
}

static void send_syscall_info_to_secondary_replicas_from_work(struct work_struct* work){
        struct send_syscall_work *my_work= (struct send_syscall_work*) work;

        send_syscall_info_to_secondary_replicas(my_work->replica_group, &my_work->sender.ft_pop_id, my_work->sender.level, my_work->sender.id_array, my_work->syscall_id, my_work->private, my_work->private_data_size);

        put_ft_pop_rep(my_work->replica_group);
	
	kfree(my_work->private);
        kfree(my_work);

}

/* Supposed to be called by a primary replica to send syscall info to its secondary replicas.
 * Data sent is stored in @syscall_info and it is of @syscall_info_size bytes.
 * A copy is made so data can be free after the call.
 * The current thread will be used to send the data.
 */
void ft_send_syscall_info(struct ft_pop_rep *replica_group, struct ft_pid *primary_pid, int syscall_id, char* syscall_info, unsigned int syscall_info_size){
	
	send_syscall_info_to_secondary_replicas(replica_group, &primary_pid->ft_pop_id, primary_pid->level, primary_pid->id_array, syscall_id, syscall_info, syscall_info_size);
}

/* As for ft_send_syscall_info, but a worker thread will be used to send the data.
 * Also in this case a copy of the data will be made, so it is possible to free @syscall_info
 * after the call.
 */
void ft_send_syscall_info_from_work(struct ft_pop_rep *replica_group, struct ft_pid *primary_pid, int syscall_id, char* syscall_info, unsigned int syscall_info_size){
	struct send_syscall_work *work;

	FTPRINTK("%s called from pid %s\n", __func__, current->pid);

	work= kmalloc( sizeof(*work), GFP_KERNEL);
	if(!work)
		return;

	get_ft_pop_rep(replica_group);
	work->replica_group= replica_group;

	work->sender= *primary_pid;
	
	/* Do a copy of syscall_info */
	work->private_data_size= syscall_info_size;
	if(syscall_info_size){
		work->private= kmalloc(syscall_info_size, GFP_KERNEL);
		if(!work->private){
			kfree(work);
			return;
		}
		memcpy(work->private, syscall_info, syscall_info_size);
	}
	work->syscall_id= syscall_id;
		
	INIT_WORK( (struct work_struct*)work, send_syscall_info_to_secondary_replicas_from_work);

	queue_work(ft_syscall_info_wq, (struct work_struct*)work);

	FTPRINTK("%s work queued\n", __func__);

	return;
	
}

/* Supposed to be called by primary after secondary replicas to get syscall data sent by the primary replica before failing if any.
 * The data returned is the one identified by the ft_pid of the replica and the syscall_id.
 */
void* ft_get_pending_syscall_info(struct ft_pid *pri_after_sec, int id_syscall){
        struct wait_syscall* present_info= NULL;
        char* key;
        void* ret= NULL;
         
        FTPRINTK("%s called from pid %s\n", __func__, current->pid);
        
        key= ft_syscall_get_key_from_ft_pid(pri_after_sec, id_syscall);
        if(!key)
                return ERR_PTR(-ENOMEM);

	present_info= ft_syscall_hash_remove(key);

	if(present_info){
		ret= present_info->private;
		kfree(present_info);
	}

        kfree(key);
	
	return ret;
}

/* Supposed to be called by secondary replicas to wait for syscall data sent by the primary replica.
 * The data returned is the one identified by the ft_pid of the replica and the syscall_id.
 * It may put the current thread to sleep.
 * NOTE: do not try to put more than one thread to sleep for the same data, it won't work. This is
 * designed to allow only the secondary replica itself to sleep while waiting the data from its primary. 
 */
void* ft_wait_for_syscall_info(struct ft_pid *secondary, int id_syscall){
	struct wait_syscall* wait_info;
        struct wait_syscall* present_info= NULL;
	char* key;
        int free_key= 0;
	void* ret= NULL;

	FTPRINTK("%s called from pid %s\n", __func__, current->pid);

	key= ft_syscall_get_key_from_ft_pid(secondary, id_syscall);
        if(!key)
                return ERR_PTR(-ENOMEM);

        wait_info= kmalloc(sizeof(*wait_info), GFP_ATOMIC);
        if(!wait_info)
                return ERR_PTR(-ENOMEM);

        wait_info->task= current;
        wait_info->populated= 0;
	wait_info->private= NULL;

        if((present_info= ((struct wait_syscall*) ft_syscall_hash_add(key, (void*) wait_info)))){
		FTPRINTK("%s data present, no need to wait\n", __func__);

                kfree(wait_info);
                free_key= 1;
                goto copy;
        }
        else{
		FTPRINTK("%s: pid %d going to wait for data\n", __func__, current->pid);

                present_info= wait_info;
                while(present_info->populated==0){
                        set_current_state(TASK_UNINTERRUPTIBLE);
                        if(present_info->populated==0);
                                schedule();
                        set_current_state(TASK_RUNNING);
                }
		
		FTPRINTK("%s: data arrived for pid %d \n", __func__, current->pid);
        }


copy:   if(present_info->populated != 1){
                printk("%s ERROR, entry present in syscall hash but not populated\n", __func__);
                ret= ERR_PTR(-EFAULT);
		goto out;
        }

	ret= present_info->private;

out:
	ft_syscall_hash_remove(key);
        if(free_key)
                kfree(key);
        kfree(present_info);

        return ret;


}

struct flush_pckt_work{
        struct work_struct work;
        atomic_t* counter;
        struct task_struct *waiting;
};

static void notify_flush_received(struct work_struct* work){
        struct flush_pckt_work *my_work= (struct flush_pckt_work *)work;

        atomic_dec(my_work->counter);
        wake_up_process(my_work->waiting);

        kfree(my_work);
}

static int ft_wake_up_primary_after_secondary(void){
	int ret= 0, i;
	list_entry_t *head, *app;
	struct wait_syscall* wait_info;

	spin_lock(&syscall_hash->spinlock);
        
	for(i=0; i<syscall_hash->size; i++){
		head= syscall_hash->table[i];
		if(head){
			list_for_each_entry(app, &head->list, list){
				if(!app->obj){
					ret= -EFAULT;
					printk("ERROR: %s no obj field\n", __func__);
					goto out;
				}
				wait_info= (struct wait_syscall*) app->obj;
				if(ft_is_primary_after_secondary_replica(wait_info->task)){
					wait_info->populated= 1;
			                wake_up_process(wait_info->task);
				}
			}
		}
	}

out:        
	spin_unlock(&syscall_hash->spinlock);
	return ret;
	
}

static int flush_sys_wq(void){
	struct flush_pckt_work *work;
        atomic_t sys_wq_to_wait= ATOMIC_INIT(0);
        int ret= 0, wake;

        work= kmalloc(sizeof(*work), GFP_ATOMIC);
        if(!work){
                ret= -ENOMEM;
                return ret;
        }

        INIT_WORK( (struct work_struct*)work, notify_flush_received);
        work->counter= &sys_wq_to_wait;
        work->waiting= current;
        //NOTE this because it is a syngle thread wq
        queue_work(ft_syscall_info_wq, (struct work_struct*)work);

        atomic_inc(&sys_wq_to_wait);

        wake= 0;
        while(atomic_read(&sys_wq_to_wait)!=0){
                local_irq_disable();
                preempt_disable();

                __set_current_state(TASK_INTERRUPTIBLE);
                if(atomic_read(&sys_wq_to_wait)==0)
                        wake= 1;

                preempt_enable();
                local_irq_enable();

                if(!wake)
                        schedule();

        }

	return ret;
}

/* Flush any pending syscall info still to be consumed by worker thread
 * and wake up all primary_after_secondary replicas that are waiting for a syscall info.
 * NOTE: this is supposed to be called after update_replica_type_after_failure.
 */
int flush_syscall_info(void){
	int ret;

	ret= flush_sys_wq();
	if(ret)
		return ret;

	ret= ft_wake_up_primary_after_secondary();

	return ret;
}

static int handle_syscall_info_msg(struct pcn_kmsg_message* inc_msg){
        struct syscall_msg* msg = (struct syscall_msg*) inc_msg;
        struct wait_syscall* wait_info;
        struct wait_syscall* present_info= NULL;
        char* key;
	char* private;

	/* retrive variable data length field (syscall_info)*/
	private= &msg->data;

	/* retrive key for this syscall in hash_table*/
        key= ft_syscall_get_key(&msg->ft_pop_id, msg->level, msg->id_array, msg->syscall_id);
        if(!key)
                return -ENOMEM;

	/* create a wait_syscall struct.
	 * if nobody was already waiting for this syscall, this struct will be added
	 * on the hash table, otherwise the private field will be copied on the wait_syscall
	 * present on the hash table and this one will be discarded.
	 */
        wait_info= kmalloc(sizeof(*wait_info), GFP_ATOMIC);
        if(!wait_info)
                return -ENOMEM;
	
	if(msg->syscall_info_size){
		wait_info->private= kmalloc(msg->syscall_info_size, GFP_ATOMIC);
		if(!wait_info->private){
			kfree(wait_info);
			return -ENOMEM;
		}
		memcpy(wait_info->private, private, msg->syscall_info_size);
	}
	else
		wait_info->private= NULL;

        wait_info->task= NULL;
        wait_info->populated= 1;

        if((present_info= ((struct wait_syscall*) ft_syscall_hash_add(key, (void*) wait_info)))){
                present_info->private= wait_info->private;
                present_info->populated= 1;
                wake_up_process(present_info->task);
		kfree(key);
		kfree(wait_info);
        }

        pcn_kmsg_free_msg(msg);

        return 0;

}

/*
 * Upon receving the wake up info, the replica is supposed to queue the request in a FIFO.
 * Whenever a system call is trying to wake up, it checks the queue to see if it has a pending
 * syscall on the head of the queue, otherwise it waits until its turn.
 *
 * This is based on a fact that the replica always gets an event later than the primary.
 */
static int handle_syscall_wake_up_info_msg(struct pcn_kmsg_message* inc_msg)
{
    struct popcorn_namespace *ns = NULL;
    struct sleeping_syscall_request *req;
    struct task_struct *task;

    /* The message will be freed by the dequeuer */
    req = (struct sleeping_syscall_request*) inc_msg;
    printk("Incoming message for synchronizing wake up %d\n", req->ft_pid.ft_pop_id.id);
    for_each_process(task) {
        if (task->ft_pid.ft_pop_id.kernel == req->ft_pid.ft_pop_id.kernel &&
                task->ft_pid.ft_pop_id.id == req->ft_pid.ft_pop_id.id) {
            ns = task->nsproxy->pop_ns;
            break;
        }
    }
    if (ns == NULL) {
        printk("Now we have a problem, the process cannot be found.\n");
        return 1;
    }

    enqueue_wake_up(&(ns->wake_up_buffer), req);

    return 0;
}

/*
 * Whenever a system call is waken up from sleeping, a message is sent to replicas.
 * The sequence of syscalls should be serialized.
 */
int notify_syscall_wakeup(struct task_struct *task, int syscall_id)
{
    struct list_head *iter= NULL;
    struct task_list *objPtr;
    struct popcorn_namespace *ns;
    struct sleeping_syscall_request *req;
    int task_cnt = 0;

    // Only primary gets to send this message
    if (!is_popcorn(task) ||
           !ft_is_primary_replica(task)) {
        return 0;
    }

    ns = task->nsproxy->pop_ns;
    req = alloc_syscall_req(task, ns->task_count);
    if (!req)
        return 0;

    req->syscall_id = syscall_id;
    req->det_process_count = ns->task_count;
    printk("primary notifies wake up on %d of %d\n", task->current_syscall, task->pid);
    spin_lock(&ns->task_list_lock);
    list_for_each(iter, &ns->ns_task_list.task_list_member) {
        objPtr = list_entry(iter, struct task_list, task_list_member);
        smp_mb();
        req->ticks[task_cnt] = atomic_read(&objPtr->task->ft_det_tick);
        task_cnt++;
    }
    spin_unlock(&ns->task_list_lock);

    send_to_all_secondary_replicas(task->ft_popcorn, (struct pcn_kmsg_long_message*) req, sizeof(*req));
    kfree(req);

    return 1;
}

void wait_for_wakeup(struct task_struct *task, int syscall_id)
{
    struct wake_up_buffer *buf;
    struct sleeping_syscall_request *req;

    if (!is_popcorn(task))
        return 0;

    // Only secondary gets to wait
    if (ft_is_primary_replica(task))
        return 0;

    buf = &(task->nsproxy->pop_ns->wake_up_buffer);
    for (;;) {
        req = peek_wake_up(buf);
        if (req != NULL &&
                task->ft_pid.ft_pop_id.kernel == req->ft_pid.ft_pop_id.kernel &&
                task->ft_pid.ft_pop_id.id == req->ft_pid.ft_pop_id.id) {
            printk("secondary wakes up on %d of %d\n", task->current_syscall, task->pid);
            break;
        }
        schedule();
    }

    dequeue_wake_up(buf);
    pcn_kmsg_free_msg(req);
}

long syscall_hook_enter(struct pt_regs *regs)
{
        current->current_syscall = regs->orig_ax;
        // System call number is in orig_ax
        if(ft_is_replicated(current) && (
                    regs->orig_ax != __NR_popcorn_det_start &&
                    regs->orig_ax != __NR_popcorn_det_end &&
                    regs->orig_ax != __NR_popcorn_det_tick &&
                    regs->orig_ax != __NR_futex)) {
                current->id_syscall++;
        }
        return regs->orig_ax;
}

void syscall_hook_exit(struct pt_regs *regs)
{
        // System call number is in ax
        if(ft_is_replicated(current) && (
                    regs->ax != __NR_popcorn_det_start &&
                    regs->ax != __NR_popcorn_det_end &&
                    regs->ax != __NR_popcorn_det_tick)) {
            // We just woke up from a sleeping syscall
            if (!(syscall_info_table[regs->ax] & NOSLEEP)) {
                // Deterministically wake up, basically futex
                // TODO: too ugly
                det_wake_up(current);
                // Skip futex
                if (regs->ax != __NR_futex) {
                    printk("Imma trying to wake %d up with %d\n", current->pid, regs->ax);
	                dump_task_list(current->nsproxy->pop_ns);
				}
            }
        }
        current->current_syscall = -1;
}

static int __init ft_syscall_common_management_init(void) {
	ft_syscall_info_wq= create_singlethread_workqueue("ft_syscall_info_wq");
	pcn_kmsg_register_callback(PCN_KMSG_TYPE_FT_SYSCALL_INFO, handle_syscall_info_msg);
	pcn_kmsg_register_callback(PCN_KMSG_TYPE_FT_SYSCALL_WAKE_UP_INFO, handle_syscall_wake_up_info_msg);
        syscall_hash= create_hashtable(50);
        return 0;
}

late_initcall(ft_syscall_common_management_init);
