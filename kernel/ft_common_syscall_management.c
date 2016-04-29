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
#include <linux/ft_time_breakdown.h>

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

        string= kmalloc(size, GFP_ATOMIC);
        if(!string){
		printk("%s impossible to kmalloc\n", __func__);
                return NULL;
	}

        pos= snprintf(string, size,"%d %d %d", ft_pop_id->kernel, ft_pop_id->id, level);
        if(pos>=size)
                goto out_clean;

        if(level){
                for(i=0;i<level;i++){
                        pos= pos+ snprintf(&string[pos], size-pos, " %d", id_array[i]);
                        if(pos>=size)
                                goto out_clean;
                }
        }

        pos= pos+ snprintf(&string[pos], size-pos," %d%c", id_syscall,'\0');
        if(pos>=size)
                goto out_clean;

        return string;

out_clean:
        kfree(string);
        printk("%s: buffer size too small\n", __func__);
        return NULL;

}

void ft_get_key_from_filter(struct net_filter_info *filter, const char* pre_append, char **key, int *key_size){
	char* string;
        const int size= 1024;
        int pos,i;

        string= kmalloc(size, GFP_ATOMIC);
        if(!string){
                printk("%s impossible to kmalloc\n", __func__);
    		*key= NULL;
	        return;
        }
	
	pos= snprintf(string, size, "%s", pre_append);
	if(pos>=size)
		goto out_clean;

        pos= pos+snprintf(&string[pos], size-pos," %d %d %d", filter->creator.ft_pop_id.kernel, filter->creator.ft_pop_id.id, filter->creator.level);
        if(pos>=size)
                goto out_clean;

        if(filter->creator.level){
                for(i=0;i<filter->creator.level;i++){
                        pos= pos+ snprintf(&string[pos], size-pos, " %d", filter->creator.id_array[i]);
                        if(pos>=size)
                                goto out_clean;
                }
        }
        
	pos= pos+ snprintf(&string[pos], size-pos," %d", filter->id);
        if(pos>=size)
                goto out_clean;
	
	if(filter->type & FT_FILTER_CHILD){
		pos= pos+ snprintf(&string[pos], size-pos," %i %i", ntohs(filter->tcp_param.daddr), ntohs(filter->tcp_param.dport));
        	if(pos>=size)
                	goto out_clean;

	}
	
	pos= pos+ snprintf(&string[pos], size-pos,"%c", '\0');
        if(pos>=size)
                goto out_clean;
	
	*key= string;
	*key_size= size;
        return ;

out_clean:
        kfree(string);
        printk("%s: buffer size too small\n", __func__);
        *key= NULL;
	return;

	
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
	char* extra_key;
	void *private;
};

hash_table_t* tickbump_hash;

/*
 * Message structure for synchronizing bumps
 */
struct tick_bump_msg {
    struct pcn_kmsg_hdr header;
    struct ft_pop_rep_id ft_pop_id;
    int level;
    int id_array[MAX_GENERATION_LENGTH];
    int syscall_id;
    uint64_t prev_tick;
    uint64_t new_tick;
};

struct wait_bump_info {
    struct task_struct *task;
    uint64_t prev_tick;
    uint64_t new_tick;
    int populated;
};

struct send_syscall_work{
        struct work_struct work;
	u64 time;
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
	
	int extra_key_size;

	/*this must be the last field of the struct*/
        char data; /*contains syscall_info + extra_key*/
};

static int create_syscall_msg(struct ft_pop_rep_id* primary_ft_pop_id, int primary_level, int* primary_id_array, int syscall_id, char* syscall_info, unsigned int syscall_info_size, char* extra_key, int extra_key_size, struct syscall_msg** message, int *msg_size){

	struct syscall_msg* msg;
        int size;
	char* variable_data;

        size= sizeof(*msg) + syscall_info_size+ extra_key_size;
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
	msg->extra_key_size= extra_key_size;

	variable_data= &msg->data;

	if(syscall_info_size){
		memcpy(variable_data, syscall_info, syscall_info_size);
	}

	variable_data= &msg->data+syscall_info_size;
	if(extra_key_size){
		memcpy(variable_data, extra_key, extra_key_size);
	}

        *message= msg;
        *msg_size= size;

        return 0;
}

static void send_syscall_info_to_secondary_replicas(struct ft_pop_rep *replica_group, struct ft_pop_rep_id* primary_ft_pop_id, int primary_level, int* primary_id_array, int syscall_id, char* syscall_info, unsigned int syscall_info_size, char* extra_key, unsigned int extra_key_size){
        struct syscall_msg* msg;
        int msg_size;
        int ret;

        ret= create_syscall_msg(primary_ft_pop_id, primary_level, primary_id_array, syscall_id, syscall_info, syscall_info_size, extra_key, extra_key_size, &msg, &msg_size);
        if(ret)
                return;

        send_to_all_secondary_replicas(replica_group, (struct pcn_kmsg_long_message*) msg, msg_size);

        kfree(msg);
}

static void send_syscall_info_to_secondary_replicas_from_work(struct work_struct* work){
        struct send_syscall_work *my_work= (struct send_syscall_work*) work;

        send_syscall_info_to_secondary_replicas(my_work->replica_group, &my_work->sender.ft_pop_id, my_work->sender.level, my_work->sender.id_array, my_work->syscall_id, my_work->private, my_work->private_data_size, NULL, 0);

        put_ft_pop_rep(my_work->replica_group);
	
	kfree(my_work->private);

	//ft_end_time(&my_work->time);
	//ft_update_time(&my_work->time, TIME_SEND_SYCALL);

        kfree(my_work);

}

/* Supposed to be called by a primary replica to send syscall info to its secondary replicas.
 * Data sent is stored in @syscall_info and it is of @syscall_info_size bytes.
 * A copy is made so data can be free after the call.
 * The current thread will be used to send the data.
 */
void ft_send_syscall_info(struct ft_pop_rep *replica_group, struct ft_pid *primary_pid, int syscall_id, char* syscall_info, unsigned int syscall_info_size){
	u64 time;
	char *key;
	
	ft_start_time(&time);
	
	// For debugging
	/*
	key = ft_syscall_get_key_from_ft_pid(primary_pid, syscall_id);
	trace_printk("sending %s in %d\n", key, current->current_syscall);
	kfree(key);
	*/

	send_syscall_info_to_secondary_replicas(replica_group, &primary_pid->ft_pop_id, primary_pid->level, primary_pid->id_array, syscall_id, syscall_info, syscall_info_size, NULL, 0);
	
	ft_end_time(&time);
	ft_update_time(&time, FT_TIME_SEND_SYCALL);
}

/* Supposed to be called by a primary replica to send syscall info to its secondary replicas.
 * Data sent is stored in @syscall_info and it is of @syscall_info_size bytes.
 * A copy is made so data can be free after the call.
 * The current thread will be used to send the data.
 * It can provide and extra key to identify this syscall.
 */
void ft_send_syscall_info_extra_key(struct ft_pop_rep *replica_group, struct ft_pid *primary_pid, int syscall_id, char* syscall_info, unsigned int syscall_info_size, char *extra_key, unsigned int extra_key_size){
        u64 time;

        ft_start_time(&time);

        send_syscall_info_to_secondary_replicas(replica_group, &primary_pid->ft_pop_id, primary_pid->level, primary_pid->id_array, syscall_id, syscall_info, syscall_info_size, extra_key, extra_key_size);

        ft_end_time(&time);
        ft_update_time(&time, FT_TIME_SEND_SYCALL);
}

/* As for ft_send_syscall_info, but a worker thread will be used to send the data.
 * Also in this case a copy of the data will be made, so it is possible to free @syscall_info
 * after the call.
 */
void ft_send_syscall_info_from_work(struct ft_pop_rep *replica_group, struct ft_pid *primary_pid, int syscall_id, char* syscall_info, unsigned int syscall_info_size){
	struct send_syscall_work *work;
	u64 time= 0;

        //ft_start_time(&time);

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
	work->time= time;
	
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
		if(present_info->extra_key)
			kfree(present_info->extra_key);

		kfree(present_info);
	}

        kfree(key);
	
	return ret;
}

/* Supposed to be called by secondary replicas to wait for syscall data sent by the primary replica.
 * The data returned is the one identified by the ft_pid of the replica and the syscall_id.
 * It may put the current thread to sleep.
 * extra_key will be added as info while sleeping, DO NOT free it!
 * NOTE: do not try to put more than one thread to sleep for the same data, it won't work. This is
 * designed to allow only the secondary replica itself to sleep while waiting the data from its primary. 
 */
void* ft_wait_for_syscall_info_extra_key(struct ft_pid *secondary, int id_syscall, char* extra_key){
	struct wait_syscall* wait_info;
        struct wait_syscall* present_info= NULL;
	char* key;
        int free_key= 0;
	void* ret= NULL;
	u64 time;
	
	ft_start_time(&time);

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
	wait_info->extra_key= extra_key;

        if((present_info= ((struct wait_syscall*) ft_syscall_hash_add(key, (void*) wait_info)))){
		FTPRINTK("%s data present, no need to wait\n", __func__);
		
		kfree(extra_key);
                kfree(wait_info);
                free_key= 1;
                goto copy;
        }
        else{
		FTPRINTK("%s: pid %d going to wait for data\n", __func__, current->pid);

                present_info= wait_info;
                while(present_info->populated==0){
                        set_current_state(TASK_INTERRUPTIBLE);
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
	if(present_info->extra_key)
		kfree(present_info->extra_key);
        kfree(present_info);
	
	ft_end_time(&time);
	ft_update_time(&time, FT_TIME_RCV_SYSCALL);

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
	u64 time;
	
	ft_start_time(&time);

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
	wait_info->extra_key= NULL;

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
                        set_current_state(TASK_INTERRUPTIBLE);
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
	if(present_info->extra_key)
		kfree(present_info->extra_key);
        kfree(present_info);
	
	ft_end_time(&time);
	ft_update_time(&time, FT_TIME_RCV_SYSCALL);

        return ret;


}

static int ft_wake_up_primary_after_secondary(void){
	int ret= 0, i;
	list_entry_t *head, *app;
	struct wait_syscall* wait_info;
	int pending_syscalls= 0, woken_up=0;

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
				pending_syscalls++;
				wait_info= (struct wait_syscall*) app->obj;
				if(wait_info->task && ft_is_primary_after_secondary_replica(wait_info->task)){
					woken_up++;
					wait_info->populated= 1;
					wake_up_process(wait_info->task);
				}
			}
		}
	}

	trace_printk("pending syscalls %d of which woken up %d\n", pending_syscalls, woken_up);
	printk("pending syscalls %d of which woken up %d\n", pending_syscalls, woken_up);


out:        
	spin_unlock(&syscall_hash->spinlock);
	return ret;
	
}

static int flush_sys_wq(void){
	drain_workqueue(ft_syscall_info_wq);
	return 0;
}

int ft_are_syscall_extra_key_present(char * key){
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
				if(wait_info->extra_key && (strcmp(wait_info->extra_key, key)==0)){
					ret++;
				}
			}
                }
        }

out:
        spin_unlock(&syscall_hash->spinlock);
	return ret;

}

int ft_check_and_set_syscall_extra_key_sleeping(char * key, int *extra_syscall){
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
				if(wait_info->extra_key && (strcmp(wait_info->extra_key, key)==0)){
					//if wait_info->task is not NULL, a thread is waiting for the syscall
					if(wait_info->task)
						ret++;
				}
			}
                }
        }

out:
	*extra_syscall= ret;
        spin_unlock(&syscall_hash->spinlock);
	return ret;

}

int ft_check_and_set_syscall_extra_key(char * key, int *extra_syscall){
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
				if(wait_info->extra_key && (strcmp(wait_info->extra_key, key)==0)){
					//count the one just sent from the primary
					if(wait_info->task)
						ret++;
				}
			}
                }
        }

out:
	*extra_syscall= ret;
        spin_unlock(&syscall_hash->spinlock);
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

	if(msg->extra_key_size){
		wait_info->extra_key= kmalloc(msg->extra_key_size, GFP_ATOMIC);
		if(!wait_info->extra_key){
			if(wait_info->private)
				kfree(wait_info->private);
                        kfree(wait_info);
                        return -ENOMEM;
                }

		memcpy(wait_info->extra_key, private+ msg->syscall_info_size, msg->extra_key_size);
	}
	else
		wait_info->extra_key= NULL;

        wait_info->task= NULL;
        wait_info->populated= 1;

        if((present_info= ((struct wait_syscall*) ft_syscall_hash_add(key, (void*) wait_info)))){
		if (present_info->task == NULL) {
           		 printk("%s ERROR PRESENT INFO TASK IS NULL %d[%s]\n", __func__, msg->syscall_id, key);
		
		} else {
	                present_info->private= wait_info->private;
        	        present_info->populated= 1;
                	wake_up_process(present_info->task);
		}

		kfree(key);
		if(wait_info->extra_key)
			kfree(wait_info->extra_key);
		kfree(wait_info);
        } 
	

        pcn_kmsg_free_msg(msg);

        return 0;

}

char* tickbump_get_key(struct ft_pop_rep_id* ft_pop_id, int level, int* id_array, int id_syscall, uint64_t oldtick)
{
    char* string;
    const int size = 128;
    int pos,i;

    string = kmalloc(size, GFP_ATOMIC);
    if (!string) {
        printk("%s impossible to kmalloc\n", __func__);
        return NULL;
    }

    pos = snprintf(string, size,"%llu %d %d %d", oldtick, ft_pop_id->kernel, ft_pop_id->id, level);
    if (pos >= size)
        goto out_clean;

    if (level) {
        for(i = 0; i < level; i++) {
            pos = pos + snprintf(&string[pos], size-pos, " %d", id_array[i]);
            if (pos >= size)
                goto out_clean;
        }
    }

    pos = pos + snprintf(&string[pos], size-pos," %d%c", id_syscall,'\0');
    if (pos >= size)
        goto out_clean;

    return string;

out_clean:
    kfree(string);
    printk("%s: buffer size too small\n", __func__);
    return NULL;
}

static int handle_bump_info_msg(struct pcn_kmsg_message* inc_msg)
{
    struct tick_bump_msg *msg = (struct tick_bump_msg *) inc_msg;
    struct wait_bump_info *wait_info;
    struct wait_bump_info *present_info;
    char *key;

    //trace_printk("got msg %d %d %lld\n", msg->level, msg->syscall_id, msg->prev_tick);
    key = tickbump_get_key(&msg->ft_pop_id, msg->level, msg->id_array, msg->syscall_id, msg->prev_tick);
    if (!key)
        return -ENOMEM;

    wait_info = kmalloc(sizeof(struct wait_bump_info), GFP_ATOMIC);
    wait_info->task = NULL;
    wait_info->populated = 1;
    wait_info->prev_tick = msg->prev_tick;
    wait_info->new_tick = msg->new_tick;

    //trace_printk("%s\n", key);
    if ((present_info = (struct wait_bump_info *) hash_add(tickbump_hash, key, (void *) wait_info))) {
        if (present_info->task == NULL) {
            printk("%s ERROR PRESENT INFO TASK IS NULL %d[%s]\n", __func__, msg->syscall_id, key);
        } else {
            present_info->prev_tick = wait_info->prev_tick;
            present_info->new_tick = wait_info->new_tick;
            present_info->populated = 1;
            wake_up_process(present_info->task);
        }

        kfree(key);
        kfree(wait_info);
    }

    pcn_kmsg_free_msg(msg);

    return 0;
}

static uint64_t wait_for_bump_info(struct task_struct *task)
{
    struct wait_bump_info *wait_info;
    struct wait_bump_info *present_info;
    char *key;
    uint64_t ret = -1;
    int free_key= 0;

    key = tickbump_get_key(&task->ft_pid.ft_pop_id, task->ft_pid.level, task->ft_pid.id_array, task->id_syscall, task->ft_det_tick);
    if (!key)
        return -1;
    trace_printk("%d wait bump %s, on %d[%d]<%d>\n", task->pid, key, task->ft_det_tick, task->id_syscall, task->current_syscall);

    wait_info = kmalloc(sizeof(struct wait_bump_info), GFP_ATOMIC);
    wait_info->task = task;
    wait_info->populated = 0;
    wait_info->prev_tick = task->ft_det_tick;
    wait_info->new_tick = 0;

    if ((present_info = ((struct wait_bump_info *) hash_add(tickbump_hash, key, (void *) wait_info)))) {
        kfree(wait_info);
        free_key = 1;
    } else {
        present_info = wait_info;
        while (present_info->populated == 0 &&
               ft_is_secondary_replica(task)) {  // This is needed because during the recovery it might still be spinning on a bump
            if (present_info->populated == 0)
                schedule_timeout_interruptible(1);
        }
    }
    ret = present_info->new_tick;

    hash_remove(tickbump_hash, key);
    if (free_key)
        kfree(key);

    kfree(present_info);
    return ret;
}

static uint64_t get_pending_bump_info(struct task_struct *task)
{
    struct wait_bump_info *present_info;
    char *key;
    uint64_t ret = -1;

    key = tickbump_get_key(&task->ft_pid.ft_pop_id, task->ft_pid.level, task->ft_pid.id_array, task->id_syscall, task->ft_det_tick);
    if (!key)
        return -1;

    present_info = hash_remove(tickbump_hash, key);

    if (present_info) {
        ret = present_info->new_tick;
        kfree(present_info);
    }

    kfree(key);

    return ret;
}

void consume_pending_bump(struct task_struct *task)
{
    uint64_t new_tick;
    struct popcorn_namespace *ns;
    ns = task->nsproxy->pop_ns;

    while ((new_tick = get_pending_bump_info(task)) != -1) {
        spin_lock(&ns->task_list_lock);
        task->ft_det_tick = new_tick;
        update_token(ns);
        spin_unlock(&ns->task_list_lock);
    }
}

#define LOCK_REPLICATION
void wait_bump(struct task_struct *task)
{
    uint64_t new_tick;
    struct popcorn_namespace *ns;
    ns = task->nsproxy->pop_ns;

#ifdef LOCK_REPLICATION
	return 0;
#endif

    u64 time;
    ft_start_time(&time);
    /*
     * Now the thread puts itself into sleep, until it receives a -1 bump on current tick.
     * Because on the secondary every thread handles the bumps by itself, so no shepherd is needed.
     */
    while ((new_tick = wait_for_bump_info(task)) != -1 &&
               ft_is_secondary_replica(task)) { // This is needed because during the recovery it might still be spinning on a bump
        spin_lock(&ns->task_list_lock);
        task->ft_det_tick = new_tick;
        update_token(ns);
        spin_unlock(&ns->task_list_lock);
    }

    ft_end_time(&time);
    ft_update_time(&time, FT_TIME_WAIT_BUMP);
}

int send_bump(struct task_struct *task, int id_syscall, uint64_t prev_tick, uint64_t new_tick)
{
    struct tick_bump_msg *msg;

#ifdef LOCK_REPLICATION
	return 0;
#endif

    u64 time;
    ft_start_time(&time);    
    trace_printk("%d is bumping %d to %d [%d]<%d>\n", task->pid, prev_tick, new_tick, id_syscall, task->current_syscall);
    msg = kmalloc(sizeof(struct tick_bump_msg), GFP_KERNEL);
    if (!msg)
        return -ENOMEM;

    msg->header.type = PCN_KMSG_TYPE_FT_TICKBUMP_INFO;
    msg->header.prio = PCN_KMSG_PRIO_NORMAL;
    memcpy(&(msg->ft_pop_id), &(task->ft_pid.ft_pop_id), sizeof(struct ft_pop_rep_id));
    msg->level = task->ft_pid.level;
    if (msg->level) {
        memcpy(msg->id_array, task->ft_pid.id_array, msg->level * sizeof(int));
    } else {
        memset(msg->id_array, 0, msg->level * sizeof(int));
    }
    msg->syscall_id = id_syscall;
    msg->prev_tick = prev_tick;
    msg->new_tick = new_tick;
    send_to_all_secondary_replicas(task->ft_popcorn, (struct pcn_kmsg_long_message*) msg, sizeof(struct tick_bump_msg));
    kfree(msg);
    //trace_printk("%d done sending bump\n", task->pid);
    ft_end_time(&time);
    ft_update_time(&time, FT_TIME_SEND_BUMP);
    return 0;
}

long syscall_hook_enter(struct pt_regs *regs)
{
        current->current_syscall = regs->orig_ax;
        current->bumped = -1;
        struct popcorn_namespace *ns;

	/*
         * System call number is in orig_ax
         * Only increment the system call counter if we see one of the synchronized system calls.
         *
         * Some socket system calls are handled inside the implementation:
         * __NR_read, __NR_sendto, __NR_sendmsg, __NR_recvfrom, __NR_recvmsg, __NR_write
         * Because we don't want non-socket read & write to be tracked.
         */
/*
 *        if (ft_is_replicated(current))
 *            trace_printk("%d[%d] in syscall %d<%d>\n", current->pid, current->ft_det_tick, regs->orig_ax, current->id_syscall);
 *
 */
	if(ft_is_replicated(current) && (current->current_syscall == 319 || current->current_syscall == 320 || current->current_syscall == __NR_accept || current->current_syscall == __NR_accept4 || current->current_syscall == __NR_poll)){
		ft_start_time(&current->time_stat);
	}
	
        if(ft_is_replicated(current) &&
                // TODO: orgnize those syscalls in a better way, avoid this tidious if conditions
                   (current->current_syscall == __NR_gettimeofday ||
                    current->current_syscall == __NR_epoll_wait ||
                    current->current_syscall == __NR_time ||
                    current->current_syscall == __NR_poll ||
                    current->current_syscall == __NR_accept ||
                    current->current_syscall == __NR_accept4 ||
                    current->current_syscall == __NR_bind ||
                    current->current_syscall == __NR_listen)) {
            ns = current->nsproxy->pop_ns;
            spin_lock(&ns->task_list_lock);
            current->id_syscall++;
            current->bumped = 0;
            spin_unlock(&ns->task_list_lock);
           trace_printk("%s Syscall %d (sycall id %d) on pid %d tic %u\n", __func__, regs->orig_ax, current->id_syscall, current->pid, current->ft_det_tick);
		/*
		 *if (ft_is_secondary_replica(current)) {
		 *        // Wake me up when OSDI ends
		 *        wait_bump(current);
		 *    } else if (ft_is_primary_after_secondary_replica(current)) {
		 *        consume_pending_bump(current);
		 *    }
		 */

		}

        return regs->orig_ax;
}

void syscall_hook_exit(struct pt_regs *regs)
{
        uint64_t bump = 0;
        int id_syscall = 0;
        unsigned long flags;
        // System call number is in ax
        
	if(ft_is_replicated(current) &&
                // TODO: orgnize those syscalls in a better way, avoid this tidious if conditions
                   (current->current_syscall == __NR_gettimeofday ||
                    current->current_syscall == __NR_epoll_wait ||
                    current->current_syscall == __NR_time ||
                    current->current_syscall == __NR_poll ||
                    current->current_syscall == __NR_accept ||
                    current->current_syscall == __NR_accept4 ||
                    current->current_syscall == __NR_bind ||
                    current->current_syscall == __NR_listen)) {
          
	    trace_printk("%s Syscall %d (sycall id %d) on pid %d tic %u\n", __func__, current->current_syscall, current->id_syscall, current->pid, current->ft_det_tick);

		/*
		 *if (ft_is_primary_replica(current)) {
         *        // Wake up the other guy
         *        spin_lock_irqsave(&current->nsproxy->pop_ns->task_list_lock, flags);
         *        bump = current->ft_det_tick;
         *        id_syscall = current->id_syscall;
         *        current->bumped = 1;
         *        spin_unlock_irqrestore(&current->nsproxy->pop_ns->task_list_lock, flags);
         *        send_bump(current, id_syscall, bump, -1);
         *    }
		 */

            /*
             * This means the syscall is wrapped inside a det section, however the syscall may
             * or may not go to sleep:
             * 1. The syscall returns from a sleeping state
             * 2. The syscall didn't get into sleep (Like the read from secondary)
             * Either case, this syscall should go back to wait for its token
             *
             * Alright futex is handled inside the do_futex.
             */
			/*
             *spin_lock_irqsave(&current->nsproxy->pop_ns->task_list_lock, flags);
             *if (current->ft_det_state == FT_DET_SLEEP_SYSCALL ||
             *        current->ft_det_state == FT_DET_ACTIVE) {
             *    spin_unlock_irqrestore(&current->nsproxy->pop_ns->task_list_lock, flags);
             *    det_wake_up(current);
             *} else {
             *    spin_unlock_irqrestore(&current->nsproxy->pop_ns->task_list_lock, flags);
             *}
			 */
        }

	if(ft_is_replicated(current) && (current->current_syscall == 319 || current->current_syscall == 320 || current->current_syscall == __NR_accept || current->current_syscall == __NR_accept4 || current->current_syscall == __NR_poll)){
		
                ft_end_time(&current->time_stat);
		if(current->current_syscall == 319)
			ft_update_time(&current->time_stat, TOT_TIME_319);
		if(current->current_syscall == 320)
			ft_update_time(&current->time_stat, TOT_TIME_320);
		if(current->current_syscall == __NR_accept)
			ft_update_time(&current->time_stat, TOT_TIME_ACCEPT);
		if(current->current_syscall == __NR_poll)
			ft_update_time(&current->time_stat, TOT_TIME_POLL);
        }

	current->current_syscall = -1;
        current->bumped = -1;


}

static int __init ft_syscall_common_management_init(void) {
	ft_syscall_info_wq= create_singlethread_workqueue("ft_syscall_info_wq");
	pcn_kmsg_register_callback(PCN_KMSG_TYPE_FT_SYSCALL_INFO, handle_syscall_info_msg);
	pcn_kmsg_register_callback(PCN_KMSG_TYPE_FT_TICKBUMP_INFO, handle_bump_info_msg);
        syscall_hash= create_hashtable(1009);
        tickbump_hash = create_hashtable(1009);
        return 0;
}

late_initcall(ft_syscall_common_management_init);
