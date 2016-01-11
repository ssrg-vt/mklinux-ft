/* 
 * ft_filter.c
 *
 * Author: Marina
 */

#include <linux/ft_replication.h>
#include <linux/popcorn_namespace.h>
#include <linux/pcn_kmsg.h>
#include <linux/slab.h>
#include <asm/atomic.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <linux/tcp.h>
#include <net/route.h>
#include <net/checksum.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/workqueue.h>
#include <linux/ft_time_breakdown.h>

#define FT_FILTER_VERBOSE 0 
#define FT_FILTER_MINIMAL_VERBOSE 0

#if FT_FILTER_VERBOSE
#define FT_FILTER_MINIMAL_VERBOSE 1
#define FTPRINTK(...) printk(__VA_ARGS__)
#else
#define FTPRINTK(...) ;
#endif

#if FT_FILTER_MINIMAL_VERBOSE
#define FTMPRINTK(...) printk(__VA_ARGS__)
#else
#define FTMPRINTK(...) ;
#endif

struct ft_sk_buff_tcp_list{
         struct ft_sk_buff_list ft_sk_buff_list_common;
         __u32 seq;
         __u32 seq_ack;
         __u16 syn:1;
         __u16 ack:1;
         __u16 fin:1;
};

struct release_filter_msg{
        struct pcn_kmsg_hdr header;
        struct ft_pid creator;
        int filter_id;
        int is_child;
        __be16 dport;
        __be32 daddr;
};

struct rx_copy_msg{
	struct pcn_kmsg_hdr header;
        struct ft_pid creator;
        int filter_id;
	int is_child;
	__be16 dport;
	__be32 daddr;
        long long pckt_id;
	long long local_tx;

	ktime_t tstamp;	
        char cb[48];
	union {
                __wsum          csum;
                struct {
                        __u16   csum_start;
                        __u16   csum_offset;
                };
        };
        __u32 priority;
        kmemcheck_bitfield_begin(flags1);
        __u8 local_df:1,
             cloned:1,
             ip_summed:2,
             nohdr:1,
             nfctinfo:3;
        __u8 pkt_type:3,
             fclone:2,
             ipvs_property:1,
             peeked:1,
             nf_trace:1;
        kmemcheck_bitfield_end(flags1);
        __be16 protocol;
	__u32 rxhash;
	int skb_iif;
#ifdef CONFIG_NET_SCHED
        __u16 tc_index;       /* traffic control index */
#ifdef CONFIG_NET_CLS_ACT
        __u16 tc_verd;        /* traffic control verdict */
#endif
#endif
	kmemcheck_bitfield_begin(flags2);
#ifdef CONFIG_IPV6_NDISC_NODETYPE
        __u8 ndisc_nodetype:2;
#endif
        __u8 ooo_okay:1;
        __u8 l4_rxhash:1;
        kmemcheck_bitfield_end(flags2);
#ifdef CONFIG_NETWORK_SECMARK
        __u32 secmark;
#endif
	union {
                __u32           mark;
                __u32           dropcount;
        };
	__u16 vlan_tci;
	int transport_header_off;
        int network_header_off;
        int mac_header_off;

	int headerlen;
        int datalen;
        int taillen;
	//NOTE: data must be the last field;
	char data;
};

struct tx_notify_msg{
        struct pcn_kmsg_hdr header;
	struct ft_pid creator;
	int filter_id;
	int is_child;
        __be16 dport;
        __be32 daddr;
        long long pckt_id;
	__wsum csum;
};

struct tcp_init_param_msg{
        struct pcn_kmsg_hdr header;
        struct ft_pid creator;
        int filter_id;
	int is_child;
        __be16 dport;
        __be32 daddr;
        int connect_id;
	int accept_id;
	struct tcp_init_param tcp_param;
};

struct tx_notify_work{
        struct work_struct work;
        struct net_filter_info *filter;
	long long pckt_id;
	__wsum csum;
	struct sk_buff* skb;
};

struct rx_copy_work{
        struct delayed_work work;
        struct net_filter_info* filter;
	int count;
	u64 time;
	void* data;
};

struct release_filter_work{
	struct work_struct work;
        struct net_filter_info *filter;
	int count;
        u64 time;
	void* data;
};

struct tcp_param_work{
	struct delayed_work work;
        struct net_filter_info* filter;
	int connect_id;
	int accept_id;
	struct tcp_init_param tcp_param;
};

static struct workqueue_struct *tx_notify_wq;
struct list_head filter_list_head;
DEFINE_SPINLOCK(filter_list_lock);

struct handshake_work{
	struct work_struct work;
	struct list_head list_member;
	struct net_filter_info *filter;
	__be32 source; 
        __be16 port;	
	struct sk_buff *syn;
        long long syn_pckt_id;
        __u32 syn_seq;
	struct sk_buff *ack;
        long long ack_pckt_id;
        __u32 ack_seq;
	int completed;
	u64 time;
};

//number of working queues used to dispatch pckts forwarded by primary replica. NOTE: there will be a special listening queue in addition to PCKT_DISP_POOL_SIZE to just handling handshakes of HAND_DISP_POOL_SIZE threads.
#define PCKT_DISP_POOL_SIZE 32
#define HAND_DISP_POOL_SIZE 8
#define WQ_NAME_PREFIX "ft_wq_"
#define WQ_NAME_SIZE 20
char workqueue_name[(PCKT_DISP_POOL_SIZE+1)][WQ_NAME_SIZE];
static struct workqueue_struct *pckt_dispatcher_pool[(PCKT_DISP_POOL_SIZE+1)];
static spinlock_t pending_handshake_lock;
static struct list_head pending_handshake;
extern const char* get_wq_name(struct workqueue_struct *wq);

DEFINE_SPINLOCK(pckt_dispatcher_pool_lock);
int next_pckt_dispatcher;

struct kmem_cache *stable_buffer_entries;
struct kmem_cache *ft_filters_entries;

static int get_iphdr(struct sk_buff *skb, struct iphdr** ip_header,int *iphdrlen);
static void put_iphdr(struct sk_buff *skb, int iphdrlen);
static __sum16 checksum_tcp_rx(struct sk_buff *skb, int len, struct iphdr *iph, struct tcphdr *tcph);

static int create_pckt_dispatcher_pool(void){
	int i, ret;
	struct workqueue_struct *wq;

	next_pckt_dispatcher= 0;

	for(i=0; i<PCKT_DISP_POOL_SIZE; i++){
		ret= snprintf(workqueue_name[i], WQ_NAME_SIZE, WQ_NAME_PREFIX"_%d", i);
                if(ret==WQ_NAME_SIZE){
                        printk("%s ERROR: name field too small\n", __func__);
                        return -EFAULT;
                }

                wq= create_singlethread_workqueue(workqueue_name[i]);
                if(wq){
			pckt_dispatcher_pool[i]= wq;
		}
		else
			return -EFAULT;
	}
	
	//special queue for listening sockets...
	ret= snprintf(workqueue_name[i], WQ_NAME_SIZE, WQ_NAME_PREFIX"_listen");
	if(ret==WQ_NAME_SIZE){
		printk("%s ERROR: name field too small\n", __func__);
		return -EFAULT;
	}

	wq= alloc_workqueue(workqueue_name[i], WQ_UNBOUND | WQ_MEM_RECLAIM | WQ_HIGHPRI, HAND_DISP_POOL_SIZE);
	if(wq){
		pckt_dispatcher_pool[PCKT_DISP_POOL_SIZE]= wq;
		INIT_LIST_HEAD(&pending_handshake);
		spin_lock_init(&pending_handshake_lock);
	}
	else{
		return -EFAULT;
	}

	
	return 0;
}

static void lock_handshake(void){
	spin_lock_bh(&pending_handshake_lock);
}

static void unlock_handshake(void){
        spin_unlock_bh(&pending_handshake_lock);
}

static void remove_handshake_work(struct handshake_work* work){

        spin_lock_bh(&pending_handshake_lock);
	list_del(&work->list_member);
	spin_unlock_bh(&pending_handshake_lock);

}

static void add_handshake_work(struct handshake_work* new_work){
	struct list_head *head;

	spin_lock_bh(&pending_handshake_lock);
	head= &pending_handshake;
	list_add(&new_work->list_member, head);
	spin_unlock_bh(&pending_handshake_lock);
}

static void add_handshake_work_notlocking(struct handshake_work* new_work){
        struct list_head *head;

        head= &pending_handshake;
        list_add(&new_work->list_member, head);
}

static struct handshake_work* get_handshake_work(__be32 source, __be16 port){
	struct handshake_work* ret= NULL;
	struct list_head *head;
        struct list_head *iter= NULL;
	struct handshake_work* objPtr= NULL;
	
	spin_lock_bh(&pending_handshake_lock);
	head= &pending_handshake;
	if(!list_empty(head)){
		
        	list_for_each(iter, head) {
                	objPtr = list_entry(iter, struct handshake_work, list_member);
                	if(objPtr->source == source && objPtr->port == port){
                        	ret= objPtr;
                        	goto out;
                	}
        	}
	}

out:
	spin_unlock_bh(&pending_handshake_lock);
	return ret;
	
}

static struct handshake_work* get_handshake_work_notlocking(__be32 source, __be16 port){
        struct handshake_work* ret= NULL;
        struct list_head *head;
        struct list_head *iter= NULL;
        struct handshake_work* objPtr= NULL;

        head= &pending_handshake;
        if(!list_empty(head)){

                list_for_each(iter, head) {
                        objPtr = list_entry(iter, struct handshake_work, list_member);
                        if(objPtr->source == source && objPtr->port == port){
                                ret= objPtr;
                                goto out;
                        }
                }
        }

out:
        return ret;

}

static struct workqueue_struct * peak_wq_from_pckt_dispatcher_pool(void){
	struct workqueue_struct *ret;
	
	spin_lock_bh(&pckt_dispatcher_pool_lock);
	
	ret= pckt_dispatcher_pool[next_pckt_dispatcher];
	next_pckt_dispatcher= (next_pckt_dispatcher+1)%PCKT_DISP_POOL_SIZE;
	
	spin_unlock_bh(&pckt_dispatcher_pool_lock);	

	return ret;
}

/* NOTE: filter lock must be already aquired
 */
static void add_ft_buff_entry(struct ft_sk_buff_list* list_head, struct ft_sk_buff_list* entry){
	struct ft_sk_buff_list* next= NULL;
	struct ft_sk_buff_list* prev= NULL;
	struct list_head *iter= NULL;

	list_for_each_prev(iter, &list_head->list_member) {
		prev = list_entry(iter, struct ft_sk_buff_list, list_member);
		if(prev->pckt_id < entry->pckt_id)
			goto out;
		next= prev;
	}

out:
	if(prev == next){
		list_add(&entry->list_member, &list_head->list_member);
		return;
	}

	if(prev && next){
		__list_add(&entry->list_member, &prev->list_member, &next->list_member);
		return;
	}

	
	list_add_tail(&entry->list_member, &list_head->list_member);
	return;
	
}

/* NOTE: filter lock must be already aquired
 */
static struct ft_sk_buff_list* remove_ft_buff_entry(struct ft_sk_buff_list* list_head, long long pckt_id){
        struct ft_sk_buff_list* objPtr= NULL;
	struct list_head *iter= NULL;
	struct ft_sk_buff_list* entry= NULL;

        list_for_each(iter, &list_head->list_member) {
                objPtr = list_entry(iter, struct ft_sk_buff_list, list_member);
                if(objPtr->pckt_id == pckt_id){
			entry= objPtr;
			goto out;
		}
		if(objPtr->pckt_id > pckt_id)
                        goto out;
        }

out:
	if(entry){	
		list_del(&entry->list_member);
	}

	return entry;
}

/* set the delta to add for the incoming stream.
 * to compute the incoming seq.
 */
void set_idelta_seq(struct net_filter_info* filter, __u32 end_seq){
	if(end_seq-filter->in_initial_seq > filter->idelta_seq)
		filter->idelta_seq= end_seq- filter->in_initial_seq;
}

void set_idelta_seq_hard(struct net_filter_info* filter, __u32 end_seq){
        filter->idelta_seq= end_seq- filter->in_initial_seq;
}


void set_odelta_seq(struct net_filter_info* filter, __u32 last_ack){
        filter->odelta_seq= filter->my_initial_out_seq-last_ack;
}

__u32 get_iseq_in(struct net_filter_info* filter, __u32 seq){
	return seq- filter->idelta_seq;
}

__u32 get_oseq_in(struct net_filter_info* filter, __u32 last_ack){
	return last_ack+ filter->odelta_seq;
}

__u32 get_iseq_out(struct net_filter_info* filter, __u32 ack){
        return ack+ filter->idelta_seq;
}

__u32 get_oseq_out(struct net_filter_info* filter, __u32 seq){
        return seq- filter->odelta_seq;
}

struct send_buffer{
        __u32 first_byte_to_consume;
	__u32 last_ack;
        spinlock_t lock;
        struct list_head send_buffer_head;
};

struct send_buffer_entry{
        struct list_head list_entry;
        int to_consume_start;
	unsigned int size;
        char data;
};

/* Creates a send_buffer and store it in *@send_buffer.
 * It initializes fields to default values.
 */
void init_send_buffer(struct send_buffer **send_buffer){
        struct send_buffer *se_buffer;
        se_buffer= kmalloc(sizeof(*se_buffer), GFP_ATOMIC);
        if(se_buffer){
                se_buffer->first_byte_to_consume= 0;
		se_buffer->last_ack= 0;
                spin_lock_init(&se_buffer->lock);
                INIT_LIST_HEAD(&se_buffer->send_buffer_head);
                *send_buffer= se_buffer;
        }
        else{
                *send_buffer= NULL;
        }
}

/* Frees a send buffer.
 */
void free_send_buffer(struct send_buffer *send_buffer){
        struct list_head *item, *n;
        struct list_head *send_buffer_head;
        struct send_buffer_entry *entry;

        if(send_buffer){
                spin_lock_bh(&send_buffer->lock);

                send_buffer_head= &send_buffer->send_buffer_head;
                if(!list_empty(send_buffer_head)){
                        list_for_each_safe(item, n, send_buffer_head){
                                        entry= list_entry(item, struct send_buffer_entry, list_entry);
                                        list_del(item);
                                        kfree(entry);
                        }
                }
                spin_unlock_bh(&send_buffer->lock);

                kfree(send_buffer);
        }
}

/* Set the first_byte_to_consume field of @send_buffer to @value.
 *
 * This is supposed to be called by secondary replicas when the tcp handshake finish
 * to identify the next value that will be stored on the send_buffer.
 *
 * It must be coherent with the value used to remove data from the send_buffer.
 */
void init_first_byte_to_consume_send_buffer(struct send_buffer *send_buffer, __u32 value){
	if(send_buffer){
		send_buffer->first_byte_to_consume= value;
	}
}

/* Return the last_ack field of @send_buffer.
 *
 */
u32 get_last_ack_send_buffer(struct send_buffer *send_buffer){
	return send_buffer->last_ack;
}

/* Adds @size bytes copied from @iov to the @send_buffer. It also computes the csum of the data and stores it in *@csum.  
 *
 * NOTE: if last_ack received is greater than first_byte_to_consume, the first last_ack-first_byte_to_consume bytes of @iov won't be copied
 * in the send_buffer.
 */
int insert_in_send_buffer_and_csum(struct send_buffer *send_buffer, struct iovec *iov, int iovlen, int size, __wsum *csum){
	struct send_buffer_entry *entry;
	struct list_head *send_buffer_head;
	struct list_head *last;
	char* where_to_copy;
	int size_to_remove;
	int i, len, err;
	int ret= -EFAULT;

	if(!send_buffer || !iov || iovlen<=0 || size<0){
		printk("%s wrong parameters send_buffer %p iov %p iovlen %d size %d\n", __func__, send_buffer, iov, iovlen, size);
		return -EFAULT;
	}

	if(size==0){
		return 0;
	}

	/* TODO: do an early check to see if send_buffer->first_byte_to_consume < send_buffer->last_ack
	 * because in that case the data should not be saved in the send_buffer and thus it should be avoided to copy it.	
	 * Why I didn't do it?! because I do know how to compute the checksum without coping the data!!!
	 */

	entry= kmalloc(sizeof(*entry)+size+1, GFP_KERNEL);
	if(!entry){
		printk("ERROR: %s out of memory\n", __func__);
		return -ENOMEM;
	}

	entry->to_consume_start= 0;
	entry->size= size;
	where_to_copy= &entry->data;
	*csum= 0;
	len= 0;

        for(i=0; i< iovlen; i++){
		len+= iov[i].iov_len;
		if(len>size){
			printk("ERROR: %s iov has more bytes (len %d) then size declared (%d) \n", __func__, len, size);
                        goto out;
		}

                *csum= csum_and_copy_from_user(iov[i].iov_base, (void*)where_to_copy, iov[i].iov_len, *csum, &err);
                if(err){
                         printk("ERROR: %s copy_from_user failed\n", __func__);
                         goto out;

                }

		where_to_copy+= iov[i].iov_len;
        }
	where_to_copy[0]='\0';
	FTMPRINTK("%s: data %s size %d\n", __func__, &entry->data, len);

	spin_lock_bh(&send_buffer->lock);
	
	send_buffer_head= &send_buffer->send_buffer_head;

	/* Case acks arrived but the data was not already added to the send buffer.
	 * This case can happen only if send buffer is empty.
	 */
	if(send_buffer->first_byte_to_consume < send_buffer->last_ack){
		if(!list_empty(send_buffer_head)){
			printk("ERROR: %s first_byte_to_consume (%d) < last_ack (%d) but send buffer is not empty\n", __func__, send_buffer->first_byte_to_consume, send_buffer->last_ack);
			ret= -EFAULT;
			goto out_lock;
		}
		
		size_to_remove= send_buffer->last_ack - send_buffer->first_byte_to_consume;
		if(size_to_remove >= size){
			kfree(entry);
			send_buffer->first_byte_to_consume+= size;
		}
		else{
			entry->to_consume_start+= size_to_remove;
			send_buffer->first_byte_to_consume+= size_to_remove;
			list_add(&entry->list_entry, send_buffer_head);
		}
		ret= 0;
                goto out_lock;
	}

	
        if(!list_empty(send_buffer_head)){

		last = send_buffer_head->prev;
		__list_add(&entry->list_entry, last, last->next);

	}
	else{
                list_add(&entry->list_entry, send_buffer_head);
                
        }

	ret= 0;

out_lock:
	spin_unlock_bh(&send_buffer->lock);

out:
	return ret;
	
}

/* Removes all the data stored in the @send_buffer up to @last_ack.
 *
 * NOTE: data stored in the send_buffer are identified by the value of first_byte_to_consume.
 * e.g.: if the send_buffer has N bytes, those bytes are labeled from first_byte_to_consume to first_byte_to_consume+N.
 * 
 * If @last_ack is greater then first_byte_to_consume, @last_byte-first_byte_to_consume bytes will be remove from the
 * stable_buffer and first_byte_to_consume will be updated. If stable_buffer does not have that amount fo bytes, 
 * the next insert_in_send_buffer will not copy the "removed" bytes.
 */
int remove_from_send_buffer(struct send_buffer *send_buffer, __u32 last_ack){
 	struct send_buffer_entry *entry;
        struct list_head *send_buffer_head, *item, *n;
        int data_to_remove, removed= 0;

	spin_lock_bh(&send_buffer->lock);

	/* case not yet initialized, but it should not happen...
	 *
	 */
	if(send_buffer->first_byte_to_consume == 0 ){
		send_buffer->last_ack= last_ack;
		spin_unlock_bh(&send_buffer->lock);
		return 0;
	}

	FTPRINTK("%s last_ack %u send_buffer->last_ack %u send_buffer->first_byte_to_consume %u \n",__func__,last_ack,send_buffer->last_ack,send_buffer->first_byte_to_consume);
	
	if(last_ack > send_buffer->last_ack)
		send_buffer->last_ack= last_ack;

	if(send_buffer->last_ack > send_buffer->first_byte_to_consume){
		
		data_to_remove= send_buffer->last_ack- send_buffer->first_byte_to_consume;
		send_buffer_head= &send_buffer->send_buffer_head;
		
		removed= 0;
		list_for_each_safe(item, n, send_buffer_head){
                        entry= list_entry(item, struct send_buffer_entry, list_entry);	
			if( data_to_remove-removed >=	entry->size- entry->to_consume_start){
				list_del(item);
				removed+= entry->size- entry->to_consume_start;
				kfree(entry);
			}
			else{
				entry->to_consume_start+= data_to_remove-removed;
				removed= data_to_remove;
			}
			
			if(removed==data_to_remove)
				goto out;
		}

out:
		send_buffer->first_byte_to_consume+= removed;
	}	

	spin_unlock_bh(&send_buffer->lock);
	
	FTPRINTK("%s removed %d bytes\n", __func__, removed);
	return removed;
}

/* Checks if @send_buffer is empty.
 *
 */
int send_buffer_empty(struct send_buffer *send_buffer){
	return list_empty(&send_buffer->send_buffer_head);
}

/* Flush of the send buffer:
 * All data that is stored in @send_buffer will be removed and sent over the network through @sock.
 * 
 * NOTE: this is suppose to be called upon failure of the primary and if this replica has been elected new primary.
 * To be called before updating replica type and flush syscall info.
 */
int flush_send_buffer(struct send_buffer *send_buffer, struct sock* sock){
	struct msghdr msg;
	struct kvec iov;
	struct send_buffer_entry *entry;
        struct list_head *send_buffer_head, *item, *n;
	int ret, len, removed;

	spin_lock_bh(&send_buffer->lock);

        /* case not yet initialized, but it should not happen...
         *
         */
        if(send_buffer->first_byte_to_consume == 0 || list_empty(&send_buffer->send_buffer_head)){
                spin_unlock_bh(&send_buffer->lock);
                return 0;
        }

        FTPRINTK("%s last_ack %u send_buffer->last_ack %u send_buffer->first_byte_to_consume %u \n",__func__,last_ack,send_buffer->last_ack,send_buffer->first_byte_to_consume);

        send_buffer_head= &send_buffer->send_buffer_head;

	removed= 0;
        list_for_each_safe(item, n, send_buffer_head){
        	entry= list_entry(item, struct send_buffer_entry, list_entry);
               
		again:
		
		len = entry->size- entry->to_consume_start;
		if (len > INT_MAX)
			len = INT_MAX;

		iov.iov_base = (void*) ( (char*) &entry->data + entry->to_consume_start);
		iov.iov_len = len;
		msg.msg_name = NULL;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_namelen = 0;
		msg.msg_flags = MSG_DONTWAIT;

		/* remove kernel_sendmsg if you don't want to retrasmit the date stored in the send buffer
		 * over the network, but enable the line at the bottom of the function to update
		 * the odelt_seq if you do so.
		 * Why? the data in send buffer might be already sent from the primary. If you assume that you don't
		 * need to retransmit them because the primary sent them AND the client received them, then you have to
		 * update your delta.
		 * But you should not assume that, that's why I am resending everything.
		 */
		ret= kernel_sendmsg(sock->sk_socket, &msg, &iov, 1, len);
		if(ret!=len){
			printk("%s ERROR sock send msg returned %d instead of %d\n", __func__, ret, len);
		}

		entry->to_consume_start+= len;
                removed+= len;

		if(entry->size- entry->to_consume_start == 0){
                	list_del(item);
                        kfree(entry);
		}
                else{
                	goto again;
		}	

        }

        send_buffer->first_byte_to_consume+= removed;

	//sock->ft_filter->odelta_seq+= removed;
        spin_unlock_bh(&send_buffer->lock);
	
	return 0;
}

struct stable_buffer{
	volatile __u32 first_byte_to_consume;
	u32 last_byte;
	spinlock_t lock;
	struct list_head stable_buffer_head;
	struct task_struct *waiting;	
};

struct stable_buffer_entry{
        struct list_head list_entry;
        __u32 start;
        int to_consume_start;
	int to_consume_end;
        struct sk_buff *data;
};

/* Creates a stable_buffer and store it in *@stable_buffer.
 * It initializes fields to default values.
 */
void init_stable_buffer(struct stable_buffer **stable_buffer){
	struct stable_buffer *st_buffer;
	st_buffer= kmalloc(sizeof(*st_buffer), GFP_ATOMIC);
	if(st_buffer){
		st_buffer->first_byte_to_consume= 0;
		st_buffer->last_byte= 0;
		spin_lock_init(&st_buffer->lock);
		INIT_LIST_HEAD(&st_buffer->stable_buffer_head);
		st_buffer->waiting= NULL;
		*stable_buffer= st_buffer;
	}
	else{
		*stable_buffer= NULL;
	}	
}

/* Frees a stable buffer.
 */
void free_stable_buffer(struct stable_buffer *stable_buffer){
	struct list_head *item, *n;
        struct list_head *stable_buffer_head;
	struct stable_buffer_entry *entry;

	if(stable_buffer){
		spin_lock_bh(&stable_buffer->lock);
		
		stable_buffer_head= &stable_buffer->stable_buffer_head;
		if(!list_empty(stable_buffer_head)){
			list_for_each_safe(item, n, stable_buffer_head){
					entry= list_entry(item, struct stable_buffer_entry, list_entry);
					list_del(item);
					kfree_skb(entry->data);
					kmem_cache_free(stable_buffer_entries, entry);
			}
		}
		spin_unlock_bh(&stable_buffer->lock);

		kfree(stable_buffer);
	}
}

/* Set the first_byte_to_consume field of @stable_buffer to @value.
 *
 * This is supposed to be called by secondary replicas when the tcp handshake finish
 * to identify the next value that will be stored on the stable_buffer.
 *
 * It must be coherent with the value used to insert data after in the stable_buffer to check if there are holes.
 */
void init_first_byte_to_consume_stable_buffer(struct stable_buffer *stable_buffer, __u32 value){
        if(stable_buffer){
                stable_buffer->first_byte_to_consume= value;
        }
}

/* Returns the last byte stored (and not trimmed) in @stable_buffer.
 *
 * To be called only after calling trim_stable_buffer on @stable_buffer.
 */
u32 get_last_byte_received_stable_buffer(struct stable_buffer *stable_buffer){ 
	return stable_buffer->last_byte;
}

/* Discards all the data stored in @stable_buffer after the first hole =>
 * stable buffer will have only contiguous data after this call.
 *
 * This function will also set the value of @stable_buffer->last_byte as the id of
 * the last byte that is stored in @stable_buffer after the trim. 
 *  
 * NOTE: this function is supposed to be called upon failure of the primary and only if the
 * current replica is elected new primary.
 */
static int trim_stable_buffer(struct stable_buffer *stable_buffer){
	struct list_head *item, *n;
        struct list_head *stable_buffer_head;
        struct stable_buffer_entry *entry;
	int remove;
        int ret= 0;
	u32 last_byte= 0;
	
	if(!stable_buffer)
		return -EFAULT;

	spin_lock_bh(&stable_buffer->lock);

	if(stable_buffer->waiting != NULL){
		printk("WARNING (my pid %d): %s thread pid %d is waiting for data when trimming stable buffer\n", current->pid, __func__, stable_buffer->waiting->pid);
	}

	stable_buffer_head= &stable_buffer->stable_buffer_head;
	last_byte= stable_buffer->first_byte_to_consume;

	/* check that there is data
	 */
	if(stable_buffer->first_byte_to_consume == 0 || list_empty(stable_buffer_head)){
		ret= 0;
                goto finish;
        }

	/* Find the first hole
	 * and delete from there
	 */
	remove= 0; 
	list_for_each_safe(item, n, stable_buffer_head){
                        entry= list_entry(item, struct stable_buffer_entry, list_entry);
		
			if(remove){
				list_del(item);
                                kfree_skb(entry->data);
                                kmem_cache_free(stable_buffer_entries, entry);
			}	
			else{
				if(last_byte != entry->to_consume_start){
					// Hole!!
					remove= 1;
					printk("%s trimming\n",__func__);
					list_del(item);
                                	kfree_skb(entry->data);
                                	kmem_cache_free(stable_buffer_entries, entry);

				}
				last_byte= entry->to_consume_end+ 1;
			}

			//last_byte= entry->to_consume_end+ 1;
	}	

finish:
	stable_buffer->last_byte= last_byte- 1;
	spin_unlock_bh(&stable_buffer->lock);
	//printk("%s first byte %u last byte %u size %u \n", __func__, stable_buffer->first_byte_to_consume, stable_buffer->last_byte, stable_buffer->last_byte-stable_buffer->first_byte_to_consume);
	return ret;

}

/* Copies the first contiguous bytes from @stable_buffer to iov up to @size bytes.
 * 
 * This function will update first_byte_to_consume of the amount of data copied. 
 *
 * NOTE: To use only after trimming the stable buffer, because it assumes that there are no holes.
 */

int remove_and_copy_from_stable_buffer_no_wait(struct stable_buffer *stable_buffer, struct iovec *iov, int size){
	struct list_head *item, *n;
	struct list_head *stable_buffer_head;
	struct list_head entry_to_copy_head;
        struct stable_buffer_entry *entry, *new_entry;
	int ret= 0, first_byte, len, copied;

	if(!stable_buffer || size<0)
		return -EFAULT;

	spin_lock_bh(&stable_buffer->lock);

	if(stable_buffer->waiting != NULL){
		printk("ERROR (my pid %d): %s thread pid %d is waiting for data\n", current->pid, __func__, stable_buffer->waiting->pid);
		spin_unlock_bh(&stable_buffer->lock);
		return -EFAULT;
	}

	stable_buffer_head= &stable_buffer->stable_buffer_head;
	
	/* check that there is data
	 */
	if(stable_buffer->first_byte_to_consume == 0 || list_empty(stable_buffer_head)){		
		ret= 0;
		goto finish;
	}

	/* Check that there are no holes in the first contiguous bytes.
	 */
	first_byte= stable_buffer->first_byte_to_consume;
	ret= 0; 
	list_for_each(item, stable_buffer_head){
                        entry= list_entry(item, struct stable_buffer_entry, list_entry);
			
			if(first_byte != entry->to_consume_start){
				// Hole!!!
				printk("ERROR %s there are holes in the stable buffer\n", __func__);
				ret= -EFAULT;	
			}

			if( size-ret <= entry->to_consume_end - entry->to_consume_start + 1){
				goto out;
			}
			else{
				ret+= entry->to_consume_end - entry->to_consume_start + 1;
			}

			first_byte= entry->to_consume_end+ 1;
	}	

out:
	ret=0;
	INIT_LIST_HEAD(&entry_to_copy_head);
	list_for_each_safe(item, n, stable_buffer_head){
                        entry= list_entry(item, struct stable_buffer_entry, list_entry);

                        if( size-ret < entry->to_consume_end - entry->to_consume_start +1){
                                len= size-ret;
                        }
                        else{
                                len= entry->to_consume_end - entry->to_consume_start +1;
                        }

                        if(len==entry->to_consume_end - entry->to_consume_start + 1){
				list_del(item);
				list_add_tail(&entry->list_entry, &entry_to_copy_head);

                        }
                        else{
				new_entry= kmem_cache_alloc(stable_buffer_entries, GFP_ATOMIC);
                                if(!new_entry){
					printk("ERROR: %s out of memory\n", __func__);
                                        ret= -ENOMEM;
                                        goto finish;
                                }
                                *new_entry= *entry;
                                skb_get(entry->data);
                                list_add_tail(&new_entry->list_entry, &entry_to_copy_head);
                                entry->to_consume_start += len;

                        }

                        ret+=len;

                        if(ret==size)
                                goto finish;
        }

finish:
	stable_buffer->first_byte_to_consume += ret;
	spin_unlock_bh(&stable_buffer->lock);

	if( ret>0 && !list_empty(&entry_to_copy_head)){
                copied= ret;
                list_for_each_safe(item, n, &entry_to_copy_head){
                        if(copied<=0){
                                printk("ERROR %s no more data to copy\n", __func__);
                        }

                        entry= list_entry(item, struct stable_buffer_entry, list_entry);
                        if(entry->to_consume_end - entry->to_consume_start +1 > copied){
                                len= copied;
                        }
                        else{
                                len= entry->to_consume_end - entry->to_consume_start +1;
                        }

                        skb_copy_datagram_iovec(entry->data, entry->to_consume_start - entry->start, iov, len);

                        copied-= len;
                        list_del(item);
                        kfree_skb(entry->data);
                        kmem_cache_free(stable_buffer_entries, entry);
                }
        }

	FTPRINTK("%s removed %d bytes\n", __func__, ret);
	return ret;

}

/* Copies the first contiguous @size bytes from @stable_buffer to iov.
 * 
 * If @size contiguous bytes are not yet present in @stable_buffer, this function will sleep waiting for them.
 * This function will update first_byte_to_consume of the amount of data copied. 
 *
 * NOTE: only one thread at a time can wait for data on a @stable_buffer, if another thread is found that id waiting for data 
 * on the same @stable_buffer error is returned.
 */
int remove_and_copy_from_stable_buffer(struct stable_buffer *stable_buffer, struct iovec *iov, int size){
	struct list_head *item, *n;
	struct list_head *stable_buffer_head;
	struct list_head entry_to_copy_head;
        struct stable_buffer_entry *entry, *new_entry;
	int ret= 0, first_byte, copied, len;
	unsigned long flags;

	if(!stable_buffer || size<0)
		return -EFAULT;

	spin_lock_bh(&stable_buffer->lock);

	if(stable_buffer->waiting != NULL){
		printk("ERROR (my pid %d): %s thread pid %d is already waiting for data\n", current->pid, __func__, stable_buffer->waiting->pid);
		spin_unlock_bh(&stable_buffer->lock);
		return -EFAULT;
	}

	stable_buffer->waiting= current;
	
	/* I need to retrive a consequent stream of bytes, so if there are holes,
	 * wait for them to be filled.
	 */

again:
	stable_buffer_head= &stable_buffer->stable_buffer_head;
	
	/* 1. check that there is data,
	 * if not, wait for it.
	 */
	while(stable_buffer->first_byte_to_consume == 0 || list_empty(stable_buffer_head)){		
		
                local_irq_save(flags);
		preempt_disable();
	
		__set_current_state(TASK_INTERRUPTIBLE);
		spin_unlock(&stable_buffer->lock);

		preempt_enable();
		local_irq_restore(flags);
		 
		local_bh_enable();

		schedule();

		spin_lock_bh(&stable_buffer->lock);

		stable_buffer_head= &stable_buffer->stable_buffer_head;		
	}

	/* Check that there are no holes in the first @size bytes
	 *
	 */
	first_byte= stable_buffer->first_byte_to_consume;
	ret= 0; 
	list_for_each(item, stable_buffer_head){
                        entry= list_entry(item, struct stable_buffer_entry, list_entry);
			
			if(first_byte != entry->to_consume_start){
				/* Hole!!!
				 * wait for it to be filled.
				 */
               			
                		local_irq_save(flags);
                		preempt_disable();
	
				__set_current_state(TASK_INTERRUPTIBLE);
                		spin_unlock(&stable_buffer->lock);

                		preempt_enable();
				local_irq_restore(flags);

				local_bh_enable();

				schedule();

        		        spin_lock_bh(&stable_buffer->lock);

				goto again;
				
			}

			if( size-ret <= entry->to_consume_end - entry->to_consume_start + 1){
				goto out;
			}
			else{
				ret+= entry->to_consume_end - entry->to_consume_start + 1;
			}

			first_byte= entry->to_consume_end+ 1;
	}	

	if(ret<size) {
		/* not enough data!!
		 * wait for it...
		 */

		local_irq_save(flags);
                preempt_disable();

		__set_current_state(TASK_INTERRUPTIBLE);
		spin_unlock(&stable_buffer->lock);

		preempt_enable();
                local_irq_restore(flags);

		local_bh_enable();
	
		schedule();

		spin_lock_bh(&stable_buffer->lock);

		goto again;

	}

out:
	/* all data is there!!
	 * steal the data for coping it when releasing the spinlock.
	 */
	ret=0;
	INIT_LIST_HEAD(&entry_to_copy_head);
	list_for_each_safe(item, n, stable_buffer_head){
                        entry= list_entry(item, struct stable_buffer_entry, list_entry);

                        if( size-ret < entry->to_consume_end - entry->to_consume_start +1){
                                len= size-ret;
                        }
                        else{
                                len= entry->to_consume_end - entry->to_consume_start +1;
                        }

			
                        if(len==entry->to_consume_end - entry->to_consume_start + 1){
				list_del(item);
				list_add_tail(&entry->list_entry, &entry_to_copy_head);
                        }
                        else{
				new_entry= kmem_cache_alloc(stable_buffer_entries, GFP_ATOMIC);
        			if(!new_entry){
					printk("ERROR: %s out of memory\n", __func__);
                			ret= -ENOMEM;
					goto finish;
				}
				*new_entry= *entry;
				skb_get(entry->data);
				list_add_tail(&new_entry->list_entry, &entry_to_copy_head);
                                entry->to_consume_start += len;
                        }

                        ret+=len;

                        if(ret==size)
                                goto finish;
        }

finish:
	/* Yeeee! finally copy!
         *
         */
	stable_buffer->waiting= NULL;
	stable_buffer->first_byte_to_consume += ret;
	spin_unlock_bh(&stable_buffer->lock);

	if( ret>0 && !list_empty(&entry_to_copy_head)){
		copied= ret;
		list_for_each_safe(item, n, &entry_to_copy_head){
                        if(copied<=0){
				printk("ERROR %s no more data to copy\n", __func__);
			}

			entry= list_entry(item, struct stable_buffer_entry, list_entry);
			if(entry->to_consume_end - entry->to_consume_start +1 > copied){
                                len= copied;
                        }
                        else{
                                len= entry->to_consume_end - entry->to_consume_start +1;
                        }

                        skb_copy_datagram_iovec(entry->data, entry->to_consume_start - entry->start, iov, len);  

			copied-= len;
			list_del(item);
			kfree_skb(entry->data);
                        kmem_cache_free(stable_buffer_entries, entry); 
		}
	}

	FTPRINTK("%s removed %d bytes\n", __func__, ret);
	return ret;
}

/* Inserts bytes from @start to @end (both inclusive) in @stable_buffer.
 * @start and @end must be compatible with the value used to init the fist_byte_to_consume of @stable_buffer.
 * 
 * This function will steal the @skb and saves pointer relative to the current configuration=>
 * do not push/pull from it after calling this function. 
 *
 * NOTE it assumes that tcph has not been pulled from the @skb, but iph has been.
 */
int insert_in_stable_buffer(struct stable_buffer *stable_buffer, struct sk_buff *skb, __u32 start, __u32 end){
	struct list_head *stable_buffer_head;
	struct list_head *prev, *n;
	struct stable_buffer_entry *prev_entry;
	struct stable_buffer_entry *entry;
	int ret= 0;

	if(!stable_buffer || !skb){
		printk("%s stable_buffer %p skb %p\n", __func__, stable_buffer, skb);
		return -EFAULT;
	}

	if(end < start){
		printk("%s start %u end %u\n", __func__, start, end);
		return -EFAULT;
	}

	entry= kmem_cache_alloc(stable_buffer_entries, GFP_ATOMIC);
	if(!entry){
		printk("ERROR: %s out of memory\n", __func__);
		return -ENOMEM;
	}
	
	entry->start= entry->to_consume_start= start;
	entry->to_consume_end= end;
	entry->data= skb;
	__skb_pull(skb, tcp_hdrlen(skb));

	/* try to add element at the end of the list
	 */ 
	spin_lock_bh(&stable_buffer->lock);
	
	/*check if this is a retransmition of already consumed data*/
	if(entry->to_consume_start < stable_buffer->first_byte_to_consume){
		if(entry->to_consume_end < stable_buffer->first_byte_to_consume){
			kfree_skb(entry->data);
                        kmem_cache_free(stable_buffer_entries, entry);
			goto out;
		}
		else{
			entry->to_consume_start= stable_buffer->first_byte_to_consume;
		}
	}

	stable_buffer_head= &stable_buffer->stable_buffer_head;

	if(!list_empty(stable_buffer_head)){
		
		list_for_each_prev_safe(prev, n, stable_buffer_head){
			prev_entry= list_entry(prev, struct stable_buffer_entry, list_entry);
			
			/* prev_entry:	s----e
			 * entry:	        s-----e
			 *
			 */

			if(prev_entry->to_consume_end < entry->to_consume_start){
				 __list_add(&entry->list_entry, prev, prev->next);
				goto out;
			}

			/* prev_entry:  s---------e
                         * entry:         s-----e
                         *
                         */

			if(prev_entry->to_consume_start <= entry->to_consume_start && prev_entry->to_consume_end >= entry->to_consume_end){
				kmem_cache_free(stable_buffer_entries, entry);
				kfree_skb(skb);
				goto out;
			}

			/* prev_entry:  s----e
                         * entry:         s-----e
                         *
                         */

			if(prev_entry->to_consume_start <= entry->to_consume_start && prev_entry->to_consume_end <= entry->to_consume_end){
				entry->to_consume_start= prev_entry->to_consume_end+1;
				if(entry->to_consume_end - entry->to_consume_start < 0){
					kmem_cache_free(stable_buffer_entries, entry);
					kfree_skb(skb);
					goto out;
				}
				else{ 
					__list_add(&entry->list_entry, prev, prev->next);
					goto out;
				}
                        }

			/* prev_entry:        s----e
                         * entry:         s-----e
                         *
                         */

                        if(prev_entry->to_consume_start <= entry->to_consume_end){
				prev_entry->to_consume_start= entry->to_consume_end+1;
				if(prev_entry->to_consume_end - prev_entry->to_consume_start < 0){
					list_del(prev);
					kfree_skb(prev_entry->data);
					kmem_cache_free(stable_buffer_entries, prev_entry);
				}
                                                   
                        }
			

		}

		//if out of the loop I have reached the head
		list_add(&entry->list_entry, stable_buffer_head);
		goto out;
	}
	else{
		list_add(&entry->list_entry, stable_buffer_head);
		goto out;
	}

	kmem_cache_free(stable_buffer_entries, entry);
	ret= -EFAULT;
	printk("%s end of loop\n", __func__);
	__skb_push(skb, tcp_hdrlen(skb));

out:
	if(stable_buffer->waiting)
		wake_up_process(stable_buffer->waiting);

	spin_unlock_bh(&stable_buffer->lock);

	FTPRINTK("%s inserted %d bytes\n", __func__, end-start+1);

	return ret;	
}

static void add_filter(struct net_filter_info* filter){
        if(!filter)
                return;

        spin_lock_bh(&filter_list_lock);
        list_add_tail(&filter->list_member,&filter_list_head);
        spin_unlock_bh(&filter_list_lock);

}

static void remove_filter(struct net_filter_info* filter){
        if(!filter)
                return;

        spin_lock_bh(&filter_list_lock);
        list_del(&filter->list_member);
        spin_unlock_bh(&filter_list_lock);

}

/*for debugging it prints filter information in trace of debug filesystem*/
void print_all_filters(void){
	struct net_filter_info* filter= NULL;
        struct list_head *iter= NULL;
	char * filter_id;

        spin_lock_bh(&filter_list_lock);

        if(!list_empty(&filter_list_head)){
                list_for_each(iter, &filter_list_head) {
                        filter = list_entry(iter, struct net_filter_info, list_member);
			filter_id= print_filter_id(filter);
			trace_printk("%s filter: %s usage: %u sk->state: %u pendig_pckt %u \n",  (filter->type & FT_FILTER_FAKE)?"fake":"", filter_id, filter->kref.refcount, filter->ft_sock?filter->ft_sock->sk_state:0, filter->ft_pending_packets);
                	kfree(filter_id);
		}
        }

	spin_unlock_bh(&filter_list_lock);

}

int ft_is_filter_primary(struct net_filter_info* filter){
        return filter->type & FT_FILTER_PRIMARY_REPLICA;
}

int ft_is_filter_primary_after_secondary(struct net_filter_info* filter){
        return filter->type & FT_FILTER_PRIMARY_AFTER_SECONDARY_REPLICA;
}

int ft_is_filter_secondary(struct net_filter_info* filter){
        return filter->type & FT_FILTER_SECONDARY_REPLICA;
}

static void send_release_filter_message(struct net_filter_info *filter);
static void release_filter(struct kref *kref){
	struct net_filter_info* filter;
#if FT_FILTER_VERBOSE
	char* filter_printed;
#endif
	filter= container_of(kref, struct net_filter_info, kref);
	if (filter){

		if(!(filter->type & FT_FILTER_FAKE)){
			remove_filter(filter);
			if(ft_is_filter_primary(filter)){
				send_release_filter_message(filter);
			}
		}
#if FT_FILTER_VERBOSE
                filter_printed= print_filter_id(filter);
                FTPRINTK("%s: deleting %s filter %s\n", __func__, (filter->type & FT_FILTER_FAKE)?"fake":"", filter_printed);
                if(filter_printed)
                        kfree(filter_printed);
#endif
                char* filter_printed= print_filter_id(filter);
                trace_printk("deleting %s filter %s pckt rcv %lld pckt snt %lld\n", (filter->type & FT_FILTER_FAKE)?"fake":"", filter_printed, filter->local_rx, filter->local_tx);
		if(filter_printed)
                        kfree(filter_printed);

		if(filter->ft_popcorn)
			put_ft_pop_rep(filter->ft_popcorn);
		if(filter->wait_queue)
			kfree(filter->wait_queue);
		if(filter->stable_buffer){
			free_stable_buffer(filter->stable_buffer);
		}
		if(filter->send_buffer){
			free_send_buffer(filter->send_buffer);
		}
		kmem_cache_free(ft_filters_entries, filter);
	}
}

void get_ft_filter(struct net_filter_info* filter){
	kref_get(&filter->kref);
}

/*Note: put_ft_filter may call release_filter that acquires filter_list_lock
 *Never call this function while holding that lock.
 */
void put_ft_filter(struct net_filter_info* filter){
	/*if( __builtin_return_address(1) == sk_free+0x25){
		printk("put daddr %u dport %u from %pS %pS %pS %pS %pS pid %d\n", filter->tcp_param.daddr, ntohs(filter->tcp_param.dport), __builtin_return_address(0), __builtin_return_address(1), __builtin_return_address(2), __builtin_return_address(3), __builtin_return_address(4), current->pid);
		dump_stack();
	}*/
	kref_put(&filter->kref, release_filter);
}

static struct net_filter_info* find_and_get_filter(struct ft_pid *creator, int filter_id, int is_child, __be32 daddr, __be16 dport){

	struct net_filter_info* filter= NULL;
        struct list_head *iter= NULL;
        struct net_filter_info *objPtr= NULL;

        spin_lock_bh(&filter_list_lock);

	if(!list_empty(&filter_list_head)){
		list_for_each(iter, &filter_list_head) {
			objPtr = list_entry(iter, struct net_filter_info, list_member);
			if( are_ft_pid_equals(&objPtr->creator, creator)
				&& objPtr->id == filter_id){
				
				if( !is_child && !(objPtr->type & FT_FILTER_CHILD) ){
					filter= objPtr;
					get_ft_filter(filter);
					goto out;
				}
				
				if( is_child && (objPtr->type & FT_FILTER_CHILD) &&
					daddr == objPtr->tcp_param.daddr &&
					dport == objPtr->tcp_param.dport ){

					filter= objPtr;
					get_ft_filter(filter);
					goto out;
				}

				
			}

		}
	}

out: 	spin_unlock_bh(&filter_list_lock);
	return filter;

}

/* Add struct net_filter_info filter in filter_list_head.
 * If a fake_filter is found with the same id of filter, fake_filter's counters are copied
 * on filter before adding it.
 * Fake_filter is then removed from the list.
 * Returns 1 in case a fake_filter was found while adding @filter, 0 otherwise.
 */
static int add_filter_coping_pending(struct net_filter_info* filter){
	struct net_filter_info* fake_filter= NULL;
        struct list_head *iter= NULL;
        struct net_filter_info *objPtr= NULL;
	int is_child= (filter->type & FT_FILTER_CHILD);
	struct workqueue_struct *filter_wq;
	int ret= 0;
	char *pfake,*pnew;

        spin_lock_bh(&filter_list_lock);

	if(!list_empty(&filter_list_head)){
		list_for_each(iter, &filter_list_head) {
			objPtr = list_entry(iter, struct net_filter_info, list_member);
			if( are_ft_pid_equals(&objPtr->creator, &filter->creator)
				&& objPtr->id == filter->id){

				if( !is_child && !(objPtr->type & FT_FILTER_CHILD) ){
					fake_filter= objPtr;
					goto next;
				}

				if( is_child && (objPtr->type & FT_FILTER_CHILD) &&
					filter->tcp_param.daddr == objPtr->tcp_param.daddr &&
					filter->tcp_param.dport == objPtr->tcp_param.dport ){
					
					fake_filter= objPtr;
					goto next;
				}

			}

		}
	}

next:	if(fake_filter){
		if(!(fake_filter->type & FT_FILTER_FAKE)){
			pfake= print_filter_id(fake_filter);
			pnew= print_filter_id(filter);
			printk("ERROR %s: substituting a real filter %s with new %s\n",__func__, pfake, pnew);
			kfree(pfake);	
			kfree(pnew);
			dump_stack();
			goto out;
		}

		ret= 1;

		if(filter->wait_queue)		
			kfree(filter->wait_queue);

		filter_wq= filter->rx_copy_wq;
		
		free_send_buffer(filter->send_buffer);
		free_stable_buffer(filter->stable_buffer);

		spin_lock_bh(&fake_filter->lock);
		
		filter->local_tx= fake_filter->local_tx;
		filter->primary_tx= fake_filter->primary_tx;
		filter->local_rx= fake_filter->local_rx;
		filter->primary_rx= fake_filter->primary_rx;
	
		filter->primary_connect_id= fake_filter->primary_connect_id;
        	filter->local_connect_id= fake_filter->local_connect_id;
		filter->primary_accept_id= fake_filter->primary_accept_id;
                filter->local_accept_id= fake_filter->local_accept_id;
		
		filter->ft_pending_packets= fake_filter->ft_pending_packets;
		filter->ft_primary_closed= fake_filter->ft_primary_closed;

		filter->tcp_param= fake_filter->tcp_param;
		
		filter->wait_queue= fake_filter->wait_queue;	
		fake_filter->wait_queue= NULL;

		filter->rx_copy_wq= fake_filter->rx_copy_wq;
		fake_filter->rx_copy_wq= NULL;
		
		filter->send_buffer= fake_filter->send_buffer;
		fake_filter->send_buffer= NULL;

		filter->stable_buffer= fake_filter->stable_buffer;
		fake_filter->stable_buffer= NULL;
		
		filter->idelta_seq= fake_filter->idelta_seq;
	        filter->odelta_seq= fake_filter->odelta_seq;

		fake_filter->type &= ~FT_FILTER_ENABLE;

		list_del(&fake_filter->list_member);

		spin_unlock_bh(&fake_filter->lock);

	}

out:	list_add(&filter->list_member,&filter_list_head);
	spin_unlock_bh(&filter_list_lock);
        
	if(fake_filter){
		if(filter->wait_queue)
			wake_up(filter->wait_queue);
		put_ft_filter(fake_filter);
	}

	return ret;

}

/* Adds a struct net_filter_info filter in filter_list_head.
 * If a real_filter is found with the same id of filter, filter is not 
 * inserted in the list and its reference is dropped. 
 */
static void add_filter_with_check(struct net_filter_info* filter){
        struct net_filter_info* real_filter= NULL;
        struct list_head *iter= NULL;
        struct net_filter_info *objPtr= NULL;
	int is_child= (filter->type & FT_FILTER_CHILD);

        spin_lock_bh(&filter_list_lock);

	if(!list_empty(&filter_list_head)){
		list_for_each(iter, &filter_list_head) {
			objPtr = list_entry(iter, struct net_filter_info, list_member);
			if( are_ft_pid_equals(&objPtr->creator, &filter->creator)
				&& objPtr->id == filter->id){

				if( !is_child && !(objPtr->type & FT_FILTER_CHILD) ){
					real_filter= objPtr;
					goto next;
				}

				if( is_child && (objPtr->type & FT_FILTER_CHILD) &&
					filter->tcp_param.daddr == objPtr->tcp_param.daddr &&
					filter->tcp_param.dport == objPtr->tcp_param.dport ){

					real_filter= objPtr;
					goto next;
				}

			}

		}
	}

next:   if(!real_filter){
		list_add(&filter->list_member,&filter_list_head);
	}

	spin_unlock_bh(&filter_list_lock);

	if(real_filter){
		put_ft_filter(filter);
	}
        return ;

}

/* Prints the filter identificative on string.
 *
 * Remember to kfree the returned string eventually.
 */
char* print_filter_id(struct net_filter_info *filter){
        char *string;
	char *creator_printed;
        const int size= 1024*2;
	int rsize,ret, is_child;

        if(!filter)
                return NULL;

	is_child= (filter->type & FT_FILTER_CHILD);
	creator_printed= print_ft_pid(&filter->creator);
	if(!creator_printed)
		return NULL;

        string= kmalloc(size, GFP_NOWAIT | GFP_ATOMIC);
        if(!string)
                return NULL;
	
	memset(string, 0, size);
	
	rsize= size;
        ret= snprintf(string, rsize, "{ creator: %s, id %d", creator_printed, filter->id);
	if (ret>= rsize)
		goto out_clean;
	
	rsize= rsize-ret;
	if(is_child){
		ret= snprintf(&string[ret], rsize, ", daddr: %i, dport: %i}", ntohs(filter->tcp_param.daddr), ntohs(filter->tcp_param.dport));
                if(ret>=rsize)
                        goto out_clean;

	}
	else{
		ret= snprintf(&string[ret], rsize, "}");
		if(ret>=rsize)
			goto out_clean;
	}
	
        kfree(creator_printed);

	return string;

out_clean:
	kfree(creator_printed);
	kfree(string);
	printk("%s: buff size too small\n", __func__);
        return NULL;
}

/* Initialize main fields of a struct net_filter_info. 
 * If primary is set, resourses for stable buffer send buffer and queue are not allocated.
 */
static int init_filter_common(struct net_filter_info* filter, int primary){

	INIT_LIST_HEAD(&filter->list_member);
        atomic_set(&filter->kref.refcount,1);

	//those fields must be set to NULL before calling return err
	filter->ft_popcorn= NULL;
	filter->wait_queue= NULL;
	filter->rx_copy_wq= NULL;
	filter->stable_buffer= NULL;
	filter->send_buffer= NULL;	

	if(!primary){
		filter->wait_queue= kmalloc(sizeof(*filter->wait_queue),GFP_ATOMIC);
        	if(!filter->wait_queue){
            		printk("ERROR: %s out of memory\n", __func__);
			return -ENOMEM;
        	}
		init_waitqueue_head(filter->wait_queue);
	}
	
	INIT_LIST_HEAD(&filter->skbuff_list.list_member);

	memset(&filter->creator, 0, sizeof(filter->creator));
	filter->id= 0;
        filter->ft_sock= NULL;
        filter->ft_req= NULL;
	filter->ft_time_wait= NULL;

        spin_lock_init(&filter->lock);
       
	if(!primary){ 
        	init_stable_buffer(&filter->stable_buffer);
        	init_send_buffer(&filter->send_buffer);
	}

        filter->type= FT_FILTER_DISABLE;

        memset(&filter->tcp_param, 0, sizeof(filter->tcp_param));

        filter->local_tx= 0;
        filter->primary_tx= 0;
        filter->local_rx= 0;
        filter->primary_rx= 0;

        filter->primary_connect_id= 0;
        filter->local_connect_id= 0;

        filter->primary_accept_id= 0;
        filter->local_accept_id= 0;
	
	filter->ft_pending_packets= 0;
	filter->ft_primary_closed= 0;
        filter->deliver_packets= 1;

	filter->idelta_seq= 0;
        filter->odelta_seq= 0;

	return 0;

}

/* Creates a struct net_filter_info* fake_filter and adds it in filter_list_head
 * if a real one does not already exists.
 * 
 * A fake filter is used as "temporary" struct net_filter_info to store primary replica's
 * notifications while the secondary one reaches the create_filter call.
 */
static int create_fake_filter(struct ft_pid *creator, int filter_id, int is_child, __be32 daddr, __be16 dport){
	struct net_filter_info* filter;
	int err;
#if FT_FILTER_VERBOSE
	char* filter_id_printed;
#endif

	filter= kmem_cache_alloc(ft_filters_entries, GFP_ATOMIC);
	if(!filter){
		printk("ERROR: %s out of memory\n", __func__);
		return -ENOMEM;
	}
	err= init_filter_common(filter, 0);
	if(err){
		put_ft_filter(filter);
		return err;
	}

	filter->creator= *creator;
	filter->id= filter_id;

	filter->type= FT_FILTER_ENABLE;
        filter->type|= FT_FILTER_FAKE;

	filter->deliver_packets= 0;

	if(is_child){
                filter->type|= FT_FILTER_CHILD;
                filter->tcp_param.daddr= daddr;
                filter->tcp_param.dport= dport;
        }

#if FT_FILTER_VERBOSE
        filter_id_printed= print_filter_id(filter);
	FTPRINTK("%s: pid %d created new filter %s\n\n", __func__, current->pid, filter_id_printed);
        if(filter_id_printed)
  	      kfree(filter_id_printed);
#endif
	char *filter_id_printed= print_filter_id(filter);
	kfree(filter_id_printed);

	add_filter_with_check(filter);

	return 0;
}

void ft_grown_mini_filter(struct sock* sk, struct request_sock *req){
	if(req->ft_filter){
		get_ft_filter(req->ft_filter);
		spin_lock_bh(&req->ft_filter->lock);
		req->ft_filter->my_initial_out_seq= tcp_sk(sk)->snd_nxt;
		req->ft_filter->in_initial_seq= tcp_sk(sk)->rcv_nxt;

		//printk("init out seq %u init in seq %u \n", req->ft_filter->my_initial_out_seq,req->ft_filter->in_initial_seq);
		req->ft_filter->idelta_seq= 0;
	
		//when handling last ack of handshake ack received has been saved on req->ft_filter->odelta_seq
		req->ft_filter->odelta_seq= req->ft_filter->my_initial_out_seq- req->ft_filter->odelta_seq;

		req->ft_filter->ft_sock= sk;
		req->ft_filter->ft_req= NULL;
		if(sk->ft_filter){
			put_ft_filter(sk->ft_filter);
		}
		sk->ft_filter= req->ft_filter;
		spin_unlock_bh(&req->ft_filter->lock);
	}
}

void ft_activate_grown_filter(struct net_filter_info* filter){
         if(filter){
                 spin_lock_bh(&filter->lock);
                 filter->deliver_packets= 1;
                 spin_unlock_bh(&filter->lock);
         }
}

int ft_create_mini_filter(struct request_sock *req, struct sock *sk, struct sk_buff * skb){
	struct net_filter_info* parent_filter= sk->ft_filter;
        struct net_filter_info* filter;
	int err;
	__be16 dport = tcp_hdr(skb)->source;
        __be32 daddr = ip_hdr(skb)->saddr;
	struct handshake_work* hand_work= NULL;
//#if FT_FILTER_VERBOSE
	char* filter_id_printed;
//#endif

	if(parent_filter){
		filter= kmem_cache_alloc(ft_filters_entries, GFP_ATOMIC);
                if(!filter){
			printk("ERROR: %s out of memory\n", __func__);
                        return -ENOMEM;
		}

		if(parent_filter->type & FT_FILTER_PRIMARY_AFTER_SECONDARY_REPLICA){
			hand_work= get_handshake_work(daddr, dport);
                	if(hand_work && hand_work->completed == 1){
				//the filter will be FT_FILTER_PRIMARY_AFTER_SECONDARY_REPLICA
                		err= init_filter_common(filter, 0);
			}
			else{
				//the filter will be FT_FILTER_PRIMARY_AFTER_PRIMARY_REPLICA
				err= init_filter_common(filter, 1);
			}
		}
		else{
			err= init_filter_common(filter, parent_filter->type & FT_FILTER_PRIMARY_REPLICA);
		}

		if(err){
			put_ft_filter(filter);
			return err;
		}

		filter->creator= parent_filter->creator;
                get_ft_pop_rep(parent_filter->ft_popcorn);
                filter->ft_popcorn= parent_filter->ft_popcorn;
          	filter->ft_req= req;

		filter->type= parent_filter->type | FT_FILTER_CHILD;
                filter->id= parent_filter->id;
		filter->tcp_param.daddr= daddr;
                filter->tcp_param.dport= dport;

		filter->deliver_packets= 0;

		if(filter->type & FT_FILTER_PRIMARY_REPLICA){
			add_filter(filter);
		}
		else{
			if(filter->type & FT_FILTER_SECONDARY_REPLICA){
				add_filter_coping_pending(filter);
				if(parent_filter->type & FT_FILTER_PRIMARY_AFTER_SECONDARY_REPLICA){
                                	filter->type &= ~FT_FILTER_SECONDARY_REPLICA;
	                        	filter->type |= FT_FILTER_PRIMARY_AFTER_SECONDARY_REPLICA;
				}
			}
			else{
				//the listening socket is a PRIMARY_AFTER_SECONDARY=>
				//create the mini-socket as PRIMARY, nothing can be pending

                                if(hand_work && hand_work->completed == 1){
					remove_handshake_work(hand_work);
				}
				else{
	                        	filter->type &= ~FT_FILTER_PRIMARY_AFTER_SECONDARY_REPLICA;
					filter->type |= FT_FILTER_PRIMARY_REPLICA;
				}

				if(add_filter_coping_pending(filter)){
					printk("ERROR %s a filter was found while creating a FT_FILTER_PRIMARY minifilter from a FT_FILTER_PRIMARY_AFTER_SECONDARY_REPLICA\n", __func__);
				}
			}
		}

		req->ft_filter= filter;

//#if FT_FILTER_VERBOSE
                filter_id_printed= print_filter_id(filter);
		FTPRINTK("%s: pid %d created new filter %s\n\n", __func__, current->pid, filter_id_printed);
		if(filter_id_printed)
			kfree(filter_id_printed);		
//#endif

	}
	else{
		req->ft_filter= NULL;
	}

	return 0;
}

void ft_change_to_time_wait_filter(struct sock *sk, struct inet_timewait_sock *tw){
	if(sk->ft_filter){
                        get_ft_filter(sk->ft_filter);
			spin_lock_bh(&sk->ft_filter->lock);
			sk->ft_filter->ft_time_wait= tw;
                        tw->ft_filter= sk->ft_filter;
			spin_unlock_bh(&sk->ft_filter->lock);
	}
}

void ft_deactivate_sk_after_time_wait_filter(struct inet_timewait_sock *tw){
        if(tw->ft_filter){
			spin_lock_bh(&tw->ft_filter->lock);
                        tw->ft_filter->ft_sock= NULL;
			spin_unlock_bh(&tw->ft_filter->lock);
        }
}


/* Create a struct net_filter_info* real_filter and add it in filter_list_head.
 * The filter created will be associated with the struct ft_pop_rep ft_popcorn of task.
 * 
 * Returns 0 in case of success.
 */
int create_filter(struct task_struct *task, struct sock *sk, gfp_t priority){
	struct net_filter_info* filter;
	int err;
#if FT_FILTER_VERBOSE
        char* filter_id_printed;
#endif
	if(in_interrupt()){
		printk("WARNING %s called from interrupt\n", __func__);
		sk->ft_filter= NULL;
		return 0;
	}

	if(ft_is_replicated(task)){

		filter= kmem_cache_alloc(ft_filters_entries, priority);
		if(!filter){
			printk("ERROR: %s out of memory\n", __func__);
			return -ENOMEM;
		}

		err= init_filter_common(filter, ft_is_primary_replica(task)||ft_is_primary_after_secondary_replica(task));
		if(err){
			put_ft_filter(filter);	
			return err;
		}
	
		filter->creator= task->ft_pid;
                get_ft_pop_rep(task->ft_popcorn);
                filter->ft_popcorn= task->ft_popcorn;
                filter->ft_sock= sk;
	
		/* NOTE: target applications are deterministic, so all replicas will do the same actions 
                 * on the same order.
                 * Because of this, all replicas will and up creating this socket, and giving it the same id.
                 */

		filter->id= task->next_id_resources++;

		if(sk->sk_protocol == IPPROTO_UDP){
			filter->deliver_packets= 2;
		}
		else{
			filter->deliver_packets= 1;
		}
			
		if(ft_is_primary_replica(task)){
			filter->type= FT_FILTER_ENABLE;
                        filter->type |= FT_FILTER_PRIMARY_REPLICA;
                        add_filter(filter);
		}
		else{
			if(ft_is_secondary_replica(task)){
				filter->type= FT_FILTER_ENABLE;
                                filter->type |= FT_FILTER_SECONDARY_REPLICA;
                                /*maybe the primary replica alredy sent me some notifications or msg*/
                                add_filter_coping_pending(filter);
				//check that I did not change type while adding the filter.
				if(!ft_is_secondary_replica(task)){
					filter->type &= ~FT_FILTER_SECONDARY_REPLICA;
                                        filter->type |= FT_FILTER_PRIMARY_AFTER_SECONDARY_REPLICA;
				}
			}
			else{

				if(ft_is_primary_after_secondary_replica(task)){
					filter->type= FT_FILTER_ENABLE;
        	                        /*maybe the primary replica alredy sent me some notifications or msg before failing*/
                	                if(add_filter_coping_pending(filter)){
						filter->type |= FT_FILTER_PRIMARY_AFTER_SECONDARY_REPLICA;
					}
					else{
						filter->type |= FT_FILTER_PRIMARY_REPLICA;
					}

				}
				else{
					printk("%s: ERROR replica type not valid (current pid %d tgid %d)\n", __func__, task->pid, task->tgid);
					put_ft_filter(filter);
					return -EFAULT;
				}

			}
		}

		sk->ft_filter= filter;
		char* filter_id_printed= print_filter_id(filter);
		kfree(filter_id_printed);
#if FT_FILTER_VERBOSE
		filter_id_printed= print_filter_id(filter);
        	FTPRINTK("%s: pid %d created new filter %s\n\n", __func__, current->pid, filter_id_printed);

	    	if(filter_id_printed)
                	kfree(filter_id_printed);
#endif
		
	}else{
		sk->ft_filter= NULL;
	}	

	return 0;	
}

struct nf_hook_ops ft_after_network_hook;

/* Compute a checksum of the application data of an skb.
 * For now, it assumes network prot IP and transport TCP/UDP.
 * It uses headers API, so call it only after net and trans stack
 * have been called in tx. 
 * So call it before going to link layer but after network!
 */
static __wsum compute_user_checksum(struct sk_buff* skb){
	unsigned char *app;
	struct iphdr* network_header;
	struct tcphdr *tcp_header= NULL;     // tcp header struct
        struct udphdr *udp_header= NULL;
	unsigned int head_len= 0, size;	
	__wsum res;

        network_header= (struct iphdr *)skb_network_header(skb);
	head_len= ip_hdrlen(skb);
        if(network_header->protocol == IPPROTO_UDP){
		udp_header= udp_hdr(skb);	
		head_len+= sizeof(*udp_header);
        }else{
		tcp_header= tcp_hdr(skb);
		head_len+= tcp_hdrlen(skb);
	}

	size= ntohs(network_header->tot_len)- head_len;
	app= kmalloc(size, GFP_ATOMIC);
	if(!app)
		return 0;

	skb_copy_bits(skb, head_len,(void*) app, size);
	
	res= csum_partial(app, size, 0);
	
	//FTPRINTK("%s len %u head_len %u data len %d len-head_len-data_len %u size %u skb->csum %u seq %u seq_end %u h_seq %u fin %u syn %u csum %u\n", __func__, skb->len, head_len, skb->data_len, skb->len-skb->data_len-head_len, size, skb->csum,TCP_SKB_CB(skb)->seq,TCP_SKB_CB(skb)->end_seq,tcp_hdr(skb)->seq,tcp_hdr(skb)->fin,tcp_hdr(skb)->syn, res);
	
	kfree(app);
		
	return res;
}

static int check_msg(struct ft_sk_buff_list *copy, __wsum msg_csum, struct net_filter_info *filter){
        char* ft_filter_printed;
        int ret= 0;

        /* This is a check on only the application data,
         * not transport/network protol headers.
         */
        if(copy->csum != msg_csum){
                ret= -EFAULT;
		ft_filter_printed= print_filter_id(filter);
                printk("%s ERROR in filter %s: csum of pckt id %lld does not match (%u %u)\n", __func__, ft_filter_printed, copy->pckt_id, copy->csum, msg_csum);
		if(ft_filter_printed)
                        kfree(ft_filter_printed);

        }

        return ret;
}

static unsigned int ft_hook_after_network_layer_secondary_tcp(struct net_filter_info *filter, struct sk_buff *skb){
	long long pckt_id;
#if FT_FILTER_VERBOSE
	char* filter_id_printed;
	char* ft_pid_printed;
#endif

	spin_lock_bh(&filter->lock);

        pckt_id= ++filter->local_tx;
 	
	spin_unlock_bh(&filter->lock);

#if FT_FILTER_VERBOSE
        ft_pid_printed= print_ft_pid(&current->ft_pid);
        filter_id_printed= print_filter_id(filter);
        FTPRINTK("%s: pid %d ft_pid %s tx packet %llu csum %d in filter %s\n", __func__, current->pid, ft_pid_printed, pckt_id, csum, filter_id_printed);
	if(ft_pid_printed)
                kfree(ft_pid_printed);
        if(filter_id_printed)
                kfree(filter_id_printed);
#endif
	FTMPRINTK("%s dropping packt\n", __func__);
	
	kfree_skb(skb);
        return NF_STOLEN;
}

static unsigned int ft_hook_after_network_layer_secondary_udp(struct net_filter_info *filter, struct sk_buff *skb){
	long long pckt_id;
	struct ft_sk_buff_list *buff_entry, *old_buff_entry= NULL;
	int sk_buff_added= 0;
	__wsum csum;	
	char* filter_id_printed;
#if FT_FILTER_VERBOSE
	char* ft_pid_printed;
#endif

	buff_entry= kmalloc(sizeof(*buff_entry),GFP_ATOMIC);
	if(!buff_entry){
		return NF_DROP;
	}
	
	skb_get(skb);
	
	csum= compute_user_checksum(skb);
	buff_entry->csum= csum;

	spin_lock_bh(&filter->lock);
	
	pckt_id= ++filter->local_tx;
	buff_entry->pckt_id= pckt_id;

	if(filter->primary_tx < pckt_id){
		//increment kref of filter to let it active for the handler of tx_notify
		get_ft_filter(filter);
	
		add_ft_buff_entry(&filter->skbuff_list, buff_entry);
		sk_buff_added= 1;
		FTPRINTK("%s: pid %d saved packet %llu \n\n", __func__, current->pid, pckt_id);
	}
	else{
		old_buff_entry= remove_ft_buff_entry(&filter->skbuff_list, pckt_id);
	}
	spin_unlock_bh(&filter->lock);
	
	if(sk_buff_added == 0){
		if(old_buff_entry){
			check_msg(old_buff_entry, csum, filter);
			kfree(old_buff_entry);
		}
		else{
			filter_id_printed= print_filter_id(filter);
			printk("%s ERROR in filter %s: no pack entry id %lld for checking csum \n",__func__, filter_id_printed, pckt_id);
			if(filter_id_printed)
				kfree(filter_id_printed);
		}
		kfree_skb(skb);
		kfree(buff_entry);
	}

	

#if FT_FILTER_VERBOSE
        ft_pid_printed= print_ft_pid(&current->ft_pid);
        filter_id_printed= print_filter_id(filter);
        FTPRINTK("%s: pid %d ft_pid %s tx packet %llu csum %d in filter %s\n", __func__, current->pid, ft_pid_printed, pckt_id, csum, filter_id_printed);
	if(ft_pid_printed)
                kfree(ft_pid_printed);
        if(filter_id_printed)
                kfree(filter_id_printed);
#endif

	wake_up(filter->wait_queue);

	return NF_DROP;

}

/* Stores primary_replica notifications on the proper struct net_filter_info filter.
 * 
 * If a filter is not found, a fake one is temporarily added in the list for storing
 * incoming notifications.
 */
static int handle_tx_notify(struct pcn_kmsg_message* inc_msg){
	struct tx_notify_msg *msg= (struct tx_notify_msg *) inc_msg;
	struct net_filter_info *filter;
	int err;
	struct ft_sk_buff_list *entry= NULL, *new_entry;
	wait_queue_head_t *filter_wait_queue= NULL;
	int removing_fake= 0;
#if FT_FILTER_VERBOSE
        char* ft_filter_printed;
	char* ft_pid_printed;
#endif


again:	filter= find_and_get_filter(&msg->creator, msg->filter_id, msg->is_child, msg->daddr, msg->dport);
	if(filter){
		spin_lock_bh(&filter->lock);

		if(filter->type & FT_FILTER_ENABLE){ 

			if(filter->primary_tx < msg->pckt_id)
				filter->primary_tx= msg->pckt_id;

			filter_wait_queue= filter->wait_queue;
		
			/* see if this pckt id has already been stored.
			 * If not save a new_entry for this msg in skbuff_list. 
			 */	
			entry= remove_ft_buff_entry(&filter->skbuff_list, msg->pckt_id);
			if(!entry){
				FTPRINTK("%s adding packt in list\n", __func__);
				new_entry= kmalloc(sizeof(*new_entry), GFP_ATOMIC);
                        	if(!new_entry){
                                	spin_unlock_bh(&filter->lock);
                                	put_ft_filter(filter);
                                	goto out;
                        	}

                        	new_entry->csum= msg->csum;
                        	new_entry->pckt_id= msg->pckt_id;
                        	new_entry->skbuff= NULL;

				add_ft_buff_entry(&filter->skbuff_list, new_entry);
			}
		}
		else{
			removing_fake= 1;
		}

        	spin_unlock_bh(&filter->lock);
		
		if(removing_fake){
			put_ft_filter(filter);
			removing_fake= 0;
			goto again;
		}
		
		if(entry){
			
			check_msg(entry, msg->csum, filter);	
		
			kfree_skb(entry->skbuff);
                	kfree(entry);
			entry= NULL;
			//who added entry should have got filter for me...
                        put_ft_filter(filter);

		}

		wake_up(filter_wait_queue);
		
		put_ft_filter(filter);
	}
	else{
#if FT_FILTER_VERBOSE
        	ft_pid_printed= print_ft_pid(&msg->creator);
        	FTPRINTK("%s: creating fake filter for ft_pid %s id %d\n\n", __func__, ft_pid_printed, msg->filter_id);
        	if(ft_pid_printed)
                	kfree(ft_pid_printed);
#endif
		
		err= create_fake_filter(&msg->creator, msg->filter_id, msg->is_child, msg->daddr, msg->dport);
		if(!err)
			goto again;
	}
	
out:
	pcn_kmsg_free_msg(msg);
	
	return 0;
}

/* Creates a struct tx_notify_msg message.
 * In case of success 0 is returned and msg and msg_size are properly populated.
 *
 * Remember to kfree the message eventually.
 */
static int create_tx_notify_msg(struct net_filter_info *filter, long long pckt_id, __wsum csum, struct sk_buff* skb, struct tx_notify_msg** msg, int* msg_size){
	struct tx_notify_msg* message;
	
	message= kmalloc(sizeof(*message), GFP_ATOMIC);
	if(!message){
		printk("ERROR: %s out of memory\n", __func__);
		return -ENOMEM;
	}
	message->creator= filter->creator;
	message->filter_id= filter->id;
	message->is_child= filter->type & FT_FILTER_CHILD;
	if(message->is_child){
		message->daddr= filter->tcp_param.daddr;
		message->dport= filter->tcp_param.dport;
	}
		
	message->pckt_id= pckt_id;
	message->csum= csum;
	
	message->header.type= PCN_KMSG_TYPE_FT_TX_NOTIFY;
	message->header.prio= PCN_KMSG_PRIO_NORMAL;

	*msg_size= sizeof(*message);
	*msg= message;

	return 0;
}

static void send_tx_notification(struct work_struct* work){
	struct tx_notify_work *tx_n_work= (struct tx_notify_work*) work;
	struct net_filter_info *filter= tx_n_work->filter;
	struct tx_notify_msg* msg;
	int msg_size;
	int ret;
#if FT_FILTER_VERBOSE
	char *filter_id_printed;
#endif

	if(is_there_any_secondary_replica(filter->ft_popcorn)){
		ret= create_tx_notify_msg(filter, tx_n_work->pckt_id, tx_n_work->csum, tx_n_work->skb, &msg, &msg_size);
		if(ret)
			goto out;

	#if FT_FILTER_VERBOSE
		filter_id_printed= print_filter_id(filter);
		FTPRINTK("%s: reached send of packet %llu in filter %s csum %u \n\n", __func__, tx_n_work->pckt_id, filter_id_printed, tx_n_work->csum);
		if(filter_id_printed)
			kfree(filter_id_printed);

	#endif

		send_to_all_secondary_replicas(filter->ft_popcorn, (struct pcn_kmsg_long_message*) msg, msg_size);
		
		kfree(msg);
	}

out:	kfree_skb(tx_n_work->skb);
	kfree(work);	
	put_ft_filter(filter);
}

static unsigned int ft_hook_after_network_layer_primary_udp(struct net_filter_info *filter, struct sk_buff* skb){
        long long pckt_id;
	unsigned int ret= NF_ACCEPT;
	struct tx_notify_work *work;
#if FT_FILTER_VERBOSE
        char* ft_pid_printed;
        char* filter_id_printed;
#endif

        spin_lock_bh(&filter->lock);

        pckt_id= ++filter->local_tx;

        spin_unlock_bh(&filter->lock);

#if FT_FILTER_VERBOSE
        ft_pid_printed= print_ft_pid(&current->ft_pid);
        filter_id_printed= print_filter_id(filter);
        FTPRINTK("%s: pid %d ft_pid %s reached send of packet %llu in filter %s\n\n", __func__, current->pid, ft_pid_printed, pckt_id, filter_id_printed);
        if(ft_pid_printed)
                kfree(ft_pid_printed);
        if(filter_id_printed)
                kfree(filter_id_printed);

#endif

	if(is_there_any_secondary_replica(filter->ft_popcorn)){
		work= kmalloc(sizeof(*work), GFP_ATOMIC);
		if(!work){
			ret= NF_DROP;
			goto out;
		}

		INIT_WORK( (struct work_struct*)work, send_tx_notification);
		get_ft_filter(filter);
		work->filter= filter;
		work->pckt_id= pckt_id;

		/* compute it here bacause the structure of the skb may change after when pushing 
			* it on the link layer.
		 */ 
		work->csum= compute_user_checksum(skb);
		skb_get(skb);
		work->skb= skb; 

		queue_work(tx_notify_wq, (struct work_struct*)work);
	}

out:        
	return ret;

}

static unsigned int ft_hook_after_network_layer_primary_tcp(struct net_filter_info *filter, struct sk_buff* skb){
    long long pckt_id;
    unsigned int ret= NF_ACCEPT;
    struct iphdr *iph;
#if FT_FILTER_VERBOSE
    char* ft_pid_printed;
    char* filter_id_printed;
#endif

    spin_lock_bh(&filter->lock);

    pckt_id= ++filter->local_tx;

    spin_unlock_bh(&filter->lock);

    /* IP protocol numbers all packt that it sends sequentially from a rand number and saves
     * this value in id.
     * To hide the failure of the primary, set id to 0 always.
     */
    iph = ip_hdr(skb);

    iph->id= 0;
    ip_send_check(iph);

#if FT_FILTER_VERBOSE
    ft_pid_printed= print_ft_pid(&current->ft_pid);
    filter_id_printed= print_filter_id(filter);
    FTPRINTK("%s: pid %d ft_pid %s reached send of packet %llu in filter %s\n\n", __func__, current->pid, ft_pid_printed, pckt_id, filter_id_printed);
    if(ft_pid_printed)
        kfree(ft_pid_printed);
    if(filter_id_printed)
        kfree(filter_id_printed);

#endif

    return ret;

}

unsigned int ft_hook_func_after_network_layer(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {

    struct iphdr *iph;
    unsigned int ret= NF_ACCEPT;
    struct sock *sk;
    struct net_filter_info *filter;
	u64 time, itime;
	
	ft_start_time(&time);

    if(hooknum != NF_INET_POST_ROUTING){
        printk("ERROR: %s has been called at hooknum %d\n", __func__, hooknum);
        goto out;
    }

    /* This is the end of IP tx path, so all the iph and transporth pointers should be
     * already correctly populated.
     */

    iph = ip_hdr(skb);

    if(iph->protocol == IPPROTO_UDP
            || iph->protocol == IPPROTO_TCP){

        /* We are on the tx path, so the socket was already found,
         * if there, it is stored in skb->sk
         */
        sk= skb->sk;
        if(sk){
            if(sk->sk_state==TCP_TIME_WAIT)
                filter= inet_twsk(sk)->ft_filter;
            else
                filter= sk->ft_filter;

            if(filter){
                get_ft_filter(filter);

                if(filter->type & FT_FILTER_SECONDARY_REPLICA){
                    if (iph->protocol == IPPROTO_UDP)
                        ret= ft_hook_after_network_layer_secondary_udp(filter, skb);
                    else
                        ret= ft_hook_after_network_layer_secondary_tcp(filter, skb);
                }
                else{
                    if(filter->type & FT_FILTER_PRIMARY_REPLICA || filter->type & FT_FILTER_PRIMARY_AFTER_SECONDARY_REPLICA){
                        if (iph->protocol == IPPROTO_UDP)
                            ret= ft_hook_after_network_layer_primary_udp(filter, skb);
                        else
                            ret= ft_hook_after_network_layer_primary_tcp(filter, skb);
                    }
                }
                put_ft_filter(filter);
            }
        }
    }
out:
	ft_end_time(&time);
	ft_update_time(&time, FT_TIME_HOOK_AFT_NET);
	return ret; 
}


struct nf_hook_ops ft_before_network_hook;

static void fake_parameters(struct sk_buff *skb, struct net_filter_info *filter){
	struct inet_sock *inet;
	struct inet_request_sock *ireq;
	struct inet_timewait_sock *twsk;
	int res, iphdrlen, datalen, msg_changed;
        struct iphdr *network_header; 
	struct tcphdr *tcp_header= NULL;     // tcp header struct
        struct udphdr *udp_header= NULL;     // udp header struct
	__be16 sport;
	__be32 saddr;

	/* I need to fake the receive of this skbuff from a device.
         * I use dummy net driver for that.
         */
        skb->dev= dev_get_by_name(&init_net, DUMMY_DRIVER);

	/* The local IP or port may be different, 
	 * hack the message with the correct ones.
	 */
	if(filter->ft_sock){
		inet = inet_sk(filter->ft_sock);
		if(!inet){
			printk("%s, ERROR impossible to retrive inet socket\n",__func__);
                        return;
		}
		sport= inet->inet_sport;
                saddr= inet->inet_saddr;
	}
	else{
		if(filter->ft_req){
			ireq= inet_rsk(filter->ft_req);
        	        if(!ireq){
				printk("%s, ERROR impossible to retrive inet_rsk socket\n",__func__);
                	        return;
			}
                        sport= ireq->loc_port;
                        saddr= ireq->loc_addr;
                }
		else{
			if(!filter->ft_time_wait){
				printk("%s, ERROR no sock req or time wait\n",__func__);
                                return;
			}
			twsk= filter->ft_time_wait;
			sport= twsk->tw_sport;
                        saddr= twsk->tw_rcv_saddr;;

		}
		
	}

	res= get_iphdr(skb, &network_header, &iphdrlen);
	if(res){
		return;
	}

	msg_changed= 0;

	/* saddr is the local IP
	 * watch out, saddr=0 means any address so do not change it
	 * in the packet.
	 */
	if(saddr && network_header->daddr != saddr){
		network_header->daddr= saddr;
		msg_changed= 1;
	}

	if (network_header->protocol == IPPROTO_UDP){
		udp_header= (struct udphdr *) ((char*)network_header+ network_header->ihl*4);
		datalen= skb->len - ip_hdrlen(skb);
		
		if(udp_header->dest != sport){
			udp_header->dest= sport;
			msg_changed= 1 ;
		} 
		//inet_iif(skb)
		
		if(msg_changed){
	                 udp_header->check = csum_tcpudp_magic(network_header->saddr, network_header->daddr,
 	                                   datalen, network_header->protocol,
 	                                   csum_partial((char *)udp_header, datalen, 0));
 	                 ip_send_check(network_header);
 	         }

	}
	else{
		if (skb->pkt_type != PACKET_HOST)
			goto out_put;

		if (!pskb_may_pull(skb, sizeof(struct tcphdr)))
			goto out_put;

		tcp_header= tcp_hdr(skb);

		if (tcp_header->doff < sizeof(struct tcphdr) / 4)
			goto out_put;

		if (!pskb_may_pull(skb, tcp_header->doff * 4))
			goto out_put;

		if(tcp_header->dest != sport){     
                        tcp_header->dest= sport; 
                        msg_changed= 1 ;
                }

		if(msg_changed){
			 //tcp_v4_send_check(filter->ft_sock, skb);
                        tcp_header->check = 0;
                        tcp_header->check= checksum_tcp_rx(skb, skb->len, network_header, tcp_header); 
			ip_send_check(network_header);
                }

		//inet_iif(skb)
	}

out_put:	put_iphdr(skb, iphdrlen);
		
}

static struct sk_buff* create_skb_from_rx_copy_msg(struct rx_copy_msg *msg, struct net_filter_info *filter){
	struct sk_buff *skb;

        skb= dev_alloc_skb(msg->datalen+ msg->headerlen+ msg->taillen);
	if(!skb){
		printk("ERROR: %s out of memory\n", __func__);
		return ERR_PTR(-ENOMEM);
	}

	/* Set the data pointer */
	skb_reserve(skb, msg->headerlen);
	/* Set the tail pointer and length */
	skb_put(skb, msg->datalen);	
	
	skb_copy_to_linear_data_offset(skb, -msg->headerlen, &msg->data, msg->headerlen+ msg->datalen);

	/* Code copied from __copy_skb_header 
         *
         */
        skb->tstamp		= msg->tstamp;
        /*new->dev              = old->dev;*/
	skb_set_transport_header(skb,msg->transport_header_off);
	skb_set_network_header(skb,msg->network_header_off);
	skb_set_mac_header(skb,msg->mac_header_off);

        /*skb_dst_copy(new, old);*/

        skb->rxhash             = msg->rxhash;
        skb->ooo_okay           = msg->ooo_okay;
        skb->l4_rxhash          = msg->l4_rxhash;
        /*#ifdef CONFIG_XFRM
        new->sp                 = secpath_get(old->sp);
        #endif*/
        memcpy(skb->cb, msg->cb, sizeof(skb->cb));
        skb->csum               = msg->csum;
        skb->local_df           = msg->local_df;
        skb->pkt_type           = msg->pkt_type;
        skb->ip_summed          = msg->ip_summed;
        /*skb_copy_queue_mapping(new, old);*/
        skb->priority          = msg->priority;
#if defined(CONFIG_IP_VS) || defined(CONFIG_IP_VS_MODULE)
        skb->ipvs_property      = msg->ipvs_property;
#endif
        skb->protocol           = msg->protocol;
        skb->mark               = msg->mark;
        skb->skb_iif            = msg->skb_iif;
        /*__nf_copy(new, old);*/
#if defined(CONFIG_NETFILTER_XT_TARGET_TRACE) || \
    defined(CONFIG_NETFILTER_XT_TARGET_TRACE_MODULE)
        skb->nf_trace           = msg->nf_trace;
#endif
#ifdef CONFIG_NET_SCHED
        skb->tc_index           = msg->tc_index;
#ifdef CONFIG_NET_CLS_ACT
        skb->tc_verd            = msg->tc_verd;
#endif
#endif
        skb->vlan_tci           = msg->vlan_tci;
        skb->secmark 		= msg->secmark;
	
	fake_parameters(skb, filter);
	
	return skb;
}

static int get_handshake_param(struct sk_buff *skb, __be32 *source, __be16 *port, __u32 *syn, __u32 *ack, int *size, __u32 *seq){
	int ret= -EFAULT;
	struct tcphdr *tcp_header;
	struct iphdr *iph;
	
	__skb_pull(skb, ip_hdrlen(skb));
        skb_reset_transport_header(skb);
	
	iph= ip_hdr(skb);
        if (iph->protocol == IPPROTO_UDP){
       		printk("ERROR udp packt in %s\n", __func__);
		goto out;
	}
        else{
        	if (skb->pkt_type != PACKET_HOST)
                         goto out;
		
		if (!pskb_may_pull(skb, sizeof(struct tcphdr)))
                         goto out;

                tcp_header= tcp_hdr(skb);

                if (tcp_header->doff < sizeof(struct tcphdr) / 4)
                	goto out;

                if (!pskb_may_pull(skb, tcp_header->doff * 4))
                	goto out;

                //if (!skb_csum_unnecessary(skb) && tcp_v4_checksum_init(skb))
                //      goto out;

                tcp_header = tcp_hdr(skb);
                iph = ip_hdr(skb);
	
        	*seq= ntohl(tcp_header->seq);
		*size= tcp_header->syn + tcp_header->fin + skb->len - tcp_header->doff * 4;
		*port= tcp_header->source;
		*source= iph->saddr;
		*syn= tcp_header->syn;
		*ack= tcp_header->ack;
		
		ret= 0;
	
 	}

out:
         __skb_push(skb, ip_hdrlen(skb));
         return ret;
 }

static void dispatch_handshake_msg(struct work_struct* work){
	struct handshake_work* my_work= (struct handshake_work*) work;
	int ret;
	struct sk_buff *skb;
//	struct net_filter_info *filter;

	trace_printk("%s ack and syn dispatching: syn seq %u  ack seq %u port %d ip %d\n", __func__, my_work->syn_seq, my_work->ack_seq, ntohs(my_work->port), my_work->source);

	skb= my_work->syn;

	local_bh_disable();
        ret= netif_receive_skb(skb);
        local_bh_enable();
	
	if(ret==NET_RX_DROP){
		printk("WARNING %s packet syn seq %u port %d ip %d was dropped\n", __func__, my_work->syn_seq, ntohs(my_work->port), my_work->source);
	}	

	msleep(1);

	skb= my_work->ack;

	local_bh_disable();
        ret= netif_receive_skb(skb);
        local_bh_enable();

	if(ret==NET_RX_DROP){
                printk("WARNING %s packet ack seq %u port %d ip %d was dropped \n", __func__, my_work->ack_seq, ntohs(my_work->port), my_work->source);
	}  


	/*filter= my_work->filter;
	if(!(filter->type &  FT_FILTER_ENABLE)){
                if(!(filter->type & FT_FILTER_FAKE)){
                        printk("%s: ERROR filter is disable but not fake\n",__func__);
                        goto out;
                }
		struct ft_pid creator= filter->creator;
		int is_child= filter->type & FT_FILTER_CHILD;
		int filter_id= filter->id;
                put_ft_filter(filter);

                filter= find_and_get_filter(&creator, filter_id, is_child , my_work->source, my_work->port);
		if(!filter){
			printk("ERROR %s no filter active after releasing fake port %d\n", __func__, htons(my_work->port));
			goto out;
		}
	}	

	spin_lock_bh(&filter->lock);	
	filter->ft_pending_packets--;
	spin_unlock_bh(&filter->lock);
	put_ft_filter(filter);
	*/

	//ft_end_time(&my_work->time);
	//ft_update_time(&my_work->time,  FT_TIME_INJECT_HANDSHACKE_PACKETS);

out:	kfree(work);

	return;
}

/* Supposed to be called only by primary after secondary listening sockets.
 * Try to match the skb as the last ack of an handshake maybe started while secondary.
 * return what to do with the skb.
 */
static int try_complete_handshake_seq(struct sk_buff *skb, struct net_filter_info *filter){
	__be32 source=0 ;
        __be16 port= 0;
        __u32 syn= 0, ack= 0, seq= 0;
        struct handshake_work *hand_work;
	int size, data_to_trim, ip_tot_len;
	struct tcphdr *tcp_header;
        struct iphdr *iph;

	tcp_header= tcp_hdr(skb);
	iph = ip_hdr(skb);
        port= tcp_header->source;
        source= iph->saddr;

        seq= ntohl(tcp_header->seq);
        syn= tcp_header->syn;
	ack= tcp_header->ack;
 	size= tcp_header->syn+ tcp_header->fin+ skb->len- tcp_header->doff*4;

        hand_work= get_handshake_work(source, port);

	if(hand_work && !hand_work->completed){
         	if(!hand_work->syn || hand_work->ack || syn || !ack){
			printk("ERROR %s hand_work->syn is %p hand_work->ack is %p syn %u ack %u\n", __func__, hand_work->syn, hand_work->ack, syn, ack);
			return NF_DROP;
		}

		if(size>0){
                	/* we have a syn but not the ack
			 * this is the next pckt (the one supposed for the established connection
			 * for what I sow, the other side won't resend a pure ack but this packet if no answers are sent
			 */
			if(seq == hand_work->syn_seq+1){
				ip_tot_len= ntohs(iph->tot_len);
				data_to_trim= size- (tcp_header->syn+ tcp_header->fin);	
				tcp_header->fin= 0;		
				___pskb_trim(skb, skb->len- data_to_trim);
                                tcp_header= tcp_hdr(skb);
                                iph= ip_hdr(skb);
           
				//recompute tcp checksum
                        	tcp_header->check = 0;
                        	tcp_header->check= checksum_tcp_rx(skb, skb->len, iph, tcp_header);
	
				//NOTE: the pckt will be reinjected through ip=> recompute ip header fields too	

				/* Manipulating necessary header fields */
                                iph->tot_len = htons(ip_tot_len - data_to_trim);

                                /* Calculation of IP header checksum */
                                iph->check = 0;
                                ip_send_check(iph);

				goto match;
			}
			else{
				printk("%s dropping seq %u syn seq %u\n", __func__, seq, hand_work->syn_seq);
                		return NF_DROP;
			}
        	}


match:		hand_work->ack= skb;
                hand_work->ack_seq= seq;

		if(hand_work->syn_seq+1 == hand_work->ack_seq){
			hand_work->completed= 1;
			//get_ft_filter(filter);
			//hand_work->filter= filter;			
			//NOTE: if NF_STOLEN is returned, the before_tcp_hook will not push back ip header
			__skb_push(skb, ip_hdrlen(skb));
			INIT_WORK((struct work_struct*) hand_work, dispatch_handshake_msg);
                        queue_work(filter->rx_copy_wq, (struct work_struct *) hand_work);
			return NF_STOLEN;
		}
		else{
			hand_work->ack= NULL;
                	hand_work->ack_seq= 0;
			printk("ERROR %s hand_work->syn_seq is %u hand_work->ack_seq is %u\n", __func__, hand_work->syn_seq, hand_work->ack_seq);
                        return NF_DROP;

		}

	}

	printk("%s no hand_work\n", __func__);

	return NF_ACCEPT;
}

/* 
 *
 */
static void create_handshake_seq(struct rx_copy_work *my_work){
	struct rx_copy_msg *msg= (struct rx_copy_msg *) my_work->data;
	struct net_filter_info *filter= ( struct net_filter_info *) my_work->filter;
	struct sk_buff *skb;
	__be32 source=0 ;
	__be16 port= 0;
	__u32 syn= 0, ack= 0, seq= 0;
	struct handshake_work *hand_work;
	int size;

	if(filter->rx_copy_wq != pckt_dispatcher_pool[PCKT_DISP_POOL_SIZE]){
                printk("ERROR %s called with filter wq %s\n", __func__, get_wq_name(filter->rx_copy_wq));
        }

	skb= create_skb_from_rx_copy_msg(msg, filter);
        if(IS_ERR(skb)){
                printk("ERROR %s impossible to allocate more skb\n", __func__);
        	return;
	}

	if(get_handshake_param(skb, &source, &port, &syn, &ack, &size, &seq)){
		printk("ERROR %s wrong get_handshake_param\n", __func__);
		goto out_no_save;
	}

	if( !(syn||ack) || (syn && ack) || (size>1) || (size==1 && !syn) ){
		printk("WARNING %s syn %d ack %d size %d \n", __func__, syn, ack, size);
		goto out_no_save;
	}

	//printk("%s called ip %d port %d syn %d ack %d \n", __func__,  source, ntohs(port), syn, ack);
	lock_handshake();
	hand_work= get_handshake_work_notlocking(source, port);

	//NOTE not assuming uncorrect sequence of packts (attact cases)
	if(hand_work){
		if(hand_work->syn){
			if(syn){
				if( seq==hand_work->syn_seq ){
					//printk("%s: duplicate syn ip %d port %d\n", __func__, source, ntohs(port));
					goto out_no_save;
				}
				//previous syn older than current
				if( hand_work->syn_pckt_id < msg->pckt_id ){
					if(hand_work->ack)
						printk("WARNING %s substituting syn but ack present for ip %d port %d\n", __func__, source, ntohs(port));
					//substitute with new one
					kfree_skb(hand_work->syn);
					hand_work->syn= skb;
					hand_work->syn_pckt_id= msg->pckt_id;
					hand_work->syn_seq= seq;
					printk("%s: sub syn seq %u pckt id %llu (old syn seq %u pckt id %llu)  port %d ip %d\n", __func__, seq, msg->pckt_id, hand_work->syn_seq, hand_work->syn_pckt_id, ntohs(port), source);
					goto check;
				}
				
				printk("%s discarding syn seq %u pckt id %llu (old syn seq %u pckt id %llu ) port %d ip %d\n", __func__, seq, msg->pckt_id, hand_work->syn_seq, hand_work->syn_pckt_id, ntohs(port), source);
				goto out_no_save;
			}

		}	

		if(hand_work->ack){
			if(ack){
				if( seq==hand_work->ack_seq ){
					printk("%s: duplicate ack ip %d port %d\n", __func__, source, ntohs(port));
					goto out_no_save;
				}

				printk("ERROR %s double ack seq %u pckt id %llu (old ack seq %u pckt id %llu ) port %d ip %d\n", __func__, seq, msg->pckt_id, hand_work->ack_seq, hand_work->ack_pckt_id, ntohs(port), source);
				goto out_no_save;
			}
		}

		if(syn){
			 hand_work->syn= skb;
                         hand_work->syn_pckt_id= msg->pckt_id;
                         hand_work->syn_seq= seq;

		}
		else{
			 hand_work->ack= skb;
                         hand_work->ack_pckt_id= msg->pckt_id;
                         hand_work->ack_seq= seq;
		}
	}	
	else{
		hand_work= kmalloc(sizeof(*hand_work), GFP_ATOMIC);
		if(!hand_work){
			printk("ERROR %s impossible to kmalloc\n", __func__);
			goto out_no_save;
		}

		memset(hand_work, 0, sizeof(*hand_work));
		
		hand_work->source= source;
		hand_work->port= port;

		if(syn){
                         hand_work->syn= skb;
                         hand_work->syn_pckt_id= msg->pckt_id;
                         hand_work->syn_seq= seq;

                }
                else{   
                         hand_work->ack= skb;
                         hand_work->ack_pckt_id= msg->pckt_id;
                         hand_work->ack_seq= seq;
                }
		
		hand_work->time= my_work->time;
		add_handshake_work_notlocking(hand_work);

	}

check:
	unlock_handshake();
	if(hand_work->syn && hand_work->ack){
		if(hand_work->syn_seq+1 == hand_work->ack_seq){
			remove_handshake_work(hand_work);
			
			/*get_ft_filter(filter);
			hand_work->filter= filter;
                	spin_lock_bh(&filter->lock);
                	filter->ft_pending_packets++;
                	spin_unlock_bh(&filter->lock);
			*/

			//INIT_WORK((struct work_struct*) hand_work, dispatch_handshake_msg);
			//queue_work(filter->rx_copy_wq, (struct work_struct *) hand_work);	
			dispatch_handshake_msg((struct work_struct *)hand_work);
		}
		else{
			printk("ERROR %s ack and syn not matching: syn seq %u pckt id %llu ack seq %u pckt id %llu  port %d ip %d\n", __func__, hand_work->syn_seq, hand_work->syn_pckt_id, hand_work->ack_seq, hand_work->ack_pckt_id, ntohs(port), source);

		}
	}
	
	return;
	
out_no_save:
	unlock_handshake();
	kfree_skb(skb);
	return;
}

static void dispatch_release_filter_msg (struct work_struct* work){
        struct release_filter_work *my_work=  (struct release_filter_work*) work;
	struct release_filter_msg *msg= (struct release_filter_msg* ) my_work->data;	
	struct net_filter_info *filter= ( struct net_filter_info *) my_work->filter;
	struct workqueue_struct *rx_copy_wq;

again:	spin_lock_bh(&filter->lock);
	
	if(!(filter->type & FT_FILTER_ENABLE)){
		if(!(filter->type & FT_FILTER_FAKE)){
                        printk("%s: ERROR filter is disable but not fake\n", __func__);
                        goto out_lock;
                }
	
		spin_unlock_bh(&filter->lock);
                put_ft_filter(filter);

		filter= find_and_get_filter(&msg->creator, msg->filter_id, msg->is_child, msg->daddr, msg->dport);
                if(!filter){
                        goto out;
                }
                else
                        goto again;

	}
	
	if(filter->type & FT_FILTER_FAKE || filter->ft_pending_packets > 0){
		//printk("WARNING ft_pending_packets %d port %d\n", filter->ft_pending_packets, ntohs(filter->tcp_param.dport));

		/*wait for pending packets to get dispatched*/
		rx_copy_wq= filter->rx_copy_wq;
		spin_unlock_bh(&filter->lock);

		INIT_WORK(work, dispatch_release_filter_msg);
		my_work->count++;
		my_work->filter= filter;
		
		queue_work(rx_copy_wq, work);
		return;

        }

	if(filter->ft_sock){
		switch(filter->ft_sock->sk_state){
                        case TCP_CLOSE_WAIT:
                        /*The device has received a close request (FIN) from the other device. It must now wait for the application on the local device to acknowledge this request and generate a matching request.*/
                        //printk("WARNING in CLOSE_WAIT port %d\n", ntohs(filter->tcp_param.dport));
                        rx_copy_wq= filter->rx_copy_wq;
                	spin_unlock_bh(&filter->lock);
			INIT_WORK(work, dispatch_release_filter_msg);
	                my_work->count++;
			my_work->filter= filter;
        	        queue_work(rx_copy_wq, work);

			return;

			case TCP_CLOSE:
			goto out_lock;

			default: 
			break;

		}	
		trace_printk("calling tcp_done port %d state %d ft_time_wait %u\n", ntohs(filter->tcp_param.dport), filter->ft_sock->sk_state, filter->ft_time_wait?1:0);
		tcp_done(filter->ft_sock);
		trace_printk("after tcp_done port %d state %d ft_time_wait %u\n", ntohs(filter->tcp_param.dport),filter->ft_sock? filter->ft_sock->sk_state:0, filter->ft_time_wait?1:0);
	}

out_lock: 
	spin_unlock_bh(&filter->lock);
	put_ft_filter(filter);
out:	pcn_kmsg_free_msg(msg);
	kfree(work);

	return;
}

void ft_listen_init(struct sock* sk){
        if(sk->ft_filter){
                if( sk->ft_filter->type & FT_FILTER_SECONDARY_REPLICA || (sk->ft_filter->type & FT_FILTER_PRIMARY_AFTER_SECONDARY_REPLICA )){
                        sk->ft_filter->rx_copy_wq = pckt_dispatcher_pool[PCKT_DISP_POOL_SIZE];
                }
        }
}

struct request_sock *ft_reqsk_queue_find_remove(struct request_sock_queue *queue, __be32 daddr, __be16 dport){
	struct request_sock *prev= NULL;
        struct request_sock *req= queue->rskq_accept_head;
        struct inet_request_sock * inet_req;

        WARN_ON(req == NULL);

        while(req){
                inet_req= (struct inet_request_sock *)req;
                if( inet_req->rmt_addr==daddr && inet_req->rmt_port==dport )
                        break;
                prev= req;
                req= req->dl_next;
        }

        if(!req)
                return NULL;

        if(!prev)
                queue->rskq_accept_head = req->dl_next;
        else
                prev->dl_next= req->dl_next;

        if (queue->rskq_accept_tail == req)
                queue->rskq_accept_tail = prev;

        return req;
}

struct request_sock *ft_reqsk_queue_find(struct request_sock_queue *queue, __be32 daddr, __be16 dport)
{
        struct request_sock *req= queue->rskq_accept_head;
        struct inet_request_sock * inet_req;

        WARN_ON(req == NULL);

        while(req){
                inet_req= (struct inet_request_sock *)req;
                if( inet_req->rmt_addr==daddr && inet_req->rmt_port==dport )
                        break;
                req= req->dl_next;
        }

        return req;
}


static void dispatch_copy_msg(struct work_struct* work){
        struct rx_copy_work *my_work= (struct rx_copy_work *) work;
        struct rx_copy_msg *msg= (struct rx_copy_msg *) my_work->data;
	struct net_filter_info *filter= ( struct net_filter_info *) my_work->filter;
	struct sk_buff *skb;
	char* filter_id_printed;
	unsigned long time_to_wait;
	struct workqueue_struct *rx_copy_wq;

	/*if(filter->tcp_param.daddr==0){
		printk("%s daddr %u dport %u pid %d\n", __func__, filter->tcp_param.daddr, ntohs(filter->tcp_param.dport), current->pid);
		filter_id_printed= print_filter_id(filter);
                printk("filter %s %s\n", (filter->type & FT_FILTER_FAKE)?"fake":"", filter_id_printed);
                if(filter_id_printed)
                        kfree(filter_id_printed);
	}*/

	/*if(my_work->count > 50 && (my_work->count%50)==0){
		filter_id_printed= print_filter_id(filter);
                printk("%s: WARNING work count is %d msg->pckt_id %llu primary rx %llu deliver_pckts %d in %s filter %s\n", __func__, my_work->count,  msg->pckt_id, filter->primary_rx, filter->deliver_packets, (filter->type & FT_FILTER_FAKE)?"fake":"", filter_id_printed);
                if(filter_id_printed)
                	kfree(filter_id_printed);

	}*/

again:	spin_lock_bh(&filter->lock);

	if(filter->type & FT_FILTER_ENABLE){
		
		//collect handshake packets
		if( !(filter->type & FT_FILTER_FAKE) && filter->ft_sock && filter->ft_sock->sk_state==TCP_LISTEN){

			//if not queue for listening socket change queue
			//NOTE: this may cause potential reordering of incoming connections
                        if(filter->rx_copy_wq != pckt_dispatcher_pool[PCKT_DISP_POOL_SIZE]){

                                filter->rx_copy_wq = pckt_dispatcher_pool[PCKT_DISP_POOL_SIZE];
                        	//remove this if counting packts in listening socket
				filter->ft_pending_packets--; 

			       	spin_unlock_bh(&filter->lock);

                                INIT_WORK(work, dispatch_copy_msg);
                                my_work->data= msg;
                                my_work->filter= filter;
                                my_work->count= 0;
                                queue_work(pckt_dispatcher_pool[PCKT_DISP_POOL_SIZE], work);
                                return;
                        }

			spin_unlock_bh(&filter->lock);
			
			create_handshake_seq(my_work);
                

	                //spin_lock_bh(&filter->lock);
        	        //filter->ft_pending_packets--;
                	//spin_unlock_bh(&filter->lock);	

			put_ft_filter(filter);
			pcn_kmsg_free_msg(msg);
        		kfree(work);
		        return;
		}

		//no way too long, you are an error or your real filter was closed before
		if(((filter->type & FT_FILTER_FAKE) && my_work->count > 200) || my_work->count > 300){
			filter_id_printed= print_filter_id(filter);
                	printk("%s: pid %d WARNING dropping msg->pckt_id %llu primary rx %llu deliver_pckts %d in %s filter %s\n", __func__, current->pid, msg->pckt_id, filter->primary_rx, filter->deliver_packets, (filter->type & FT_FILTER_FAKE)?"fake":"", filter_id_printed);
                	if(filter_id_printed)
                        	kfree(filter_id_printed);

			goto out_err;
		}
 
		if(msg->pckt_id != filter->primary_rx+1){

			//requeue it
                        /*INIT_DELAYED_WORK( (struct delayed_work *)work, dispatch_copy_msg);
                        my_work->data= (void*) msg;
                        my_work->filter= filter;
			my_work->count++;
			time_to_wait= ((my_work->count<10)?1:my_work->count/10);
			if(time_to_wait>100)
				time_to_wait= msecs_to_jiffies(1000);
			else 
				time_to_wait= time_to_wait*msecs_to_jiffies(10);

                        queue_delayed_work(filter->rx_copy_wq, (struct delayed_work *)work, time_to_wait);
			*/
			rx_copy_wq= filter->rx_copy_wq;
			spin_unlock_bh(&filter->lock);

			INIT_WORK(work, dispatch_copy_msg);
			my_work->data= (void*) msg;
                        my_work->filter= filter;
                        my_work->count++;
			queue_work( rx_copy_wq, work);
			
			return;
		}
		
		/* Wait to be aligned with the primary replica for the delivery of the packet.
		 * => for tcp means wait to create the same filter
		 * => for udp wait to reach the same number of sent pckts (on a not fake filter).
		 */

#define PR_RX_CP_MSG_SLEEP_COND ((filter->type & FT_FILTER_FAKE) || (filter->deliver_packets==0) || ((filter->deliver_packets==2) && (filter->local_tx < msg->local_tx)))
 
		if(PR_RX_CP_MSG_SLEEP_COND){
           		
			/*INIT_DELAYED_WORK( (struct delayed_work *)work, dispatch_copy_msg);
                        my_work->data= (void*) msg;
                        my_work->filter= filter;
                        my_work->count++;
                        time_to_wait= ((my_work->count<10)?1:my_work->count/10);
                        if(time_to_wait>100)
                                time_to_wait= msecs_to_jiffies(1000);
                        else
                                time_to_wait= time_to_wait*msecs_to_jiffies(10);

                        queue_delayed_work(filter->rx_copy_wq, (struct delayed_work *)work, time_to_wait);
			*/
			rx_copy_wq= filter->rx_copy_wq;
                        spin_unlock_bh(&filter->lock);

			INIT_WORK(work, dispatch_copy_msg);
                        my_work->data= (void*) msg;
                        my_work->filter= filter;
                        my_work->count++;
                        queue_work(rx_copy_wq, work);

			/* If here possibly the listening wq is busy trying to opening connections,
			 * including mine...
			 * flush it to be sure that if there was my pending connection is getting opened...
			 */
			flush_workqueue(pckt_dispatcher_pool[PCKT_DISP_POOL_SIZE]);
			
                        return; 

		}

		filter->primary_rx= msg->pckt_id;
	}
	else{

		if(!(filter->type & FT_FILTER_FAKE)){
			printk("%s: ERROR filter is disable but not fake\n",__func__);
			goto out_err;
		}

		spin_unlock_bh(&filter->lock);
		put_ft_filter(filter);

		filter= find_and_get_filter(&msg->creator, msg->filter_id, msg->is_child, msg->daddr, msg->dport);
		if(!filter){
			printk("%s: ERROR no filter for addr %d port %d pckt id %llu\n", __func__, msg->daddr, ntohs(msg->dport), msg->pckt_id);
			goto out;
		}
		else
			goto again;
	}

	spin_unlock_bh(&filter->lock);

	if(filter->type & FT_FILTER_FAKE){
		printk("%s: ERROR trying to delivery pckt to fake filter\n", __func__);
		put_ft_filter(filter);
		goto out;
	}

	
	skb= create_skb_from_rx_copy_msg(msg, filter);
        if(IS_ERR(skb)){
             	printk("ERROR %s imposible to allocate more skb\n", __func__);
		put_ft_filter(filter);
                goto out;
        }

#if FT_FILTER_VERBOSE
	filter_id_printed= print_filter_id(filter);
	FTPRINTK("%s: pid %d is going to deliver the packet %llu in filter %s\n\n", __func__, current->pid, msg->pckt_id, filter_id_printed);
	if(filter_id_printed)
		kfree(filter_id_printed);
#endif

	/* the network stack rx path is thougth to be executed in softirq
	 * context...
	 */

	local_bh_disable();	
	netif_receive_skb(skb);
	local_bh_enable();

	spin_lock_bh(&filter->lock);
	filter->ft_pending_packets--;
	spin_unlock_bh(&filter->lock);

	put_ft_filter(filter);

out:	pcn_kmsg_free_msg(msg);

	//ft_end_time(&my_work->time);
	//ft_update_time(&my_work->time, FT_TIME_INJECT_RECV_PACKET);

	kfree(work);
	return;
out_err:
	spin_unlock_bh(&filter->lock);
        put_ft_filter(filter);
	goto out;

}

static int handle_rx_copy(struct pcn_kmsg_message* inc_msg){
	struct rx_copy_msg *msg= (struct rx_copy_msg *) inc_msg;
	struct rx_copy_work *work;
	int ret= 0;
	struct net_filter_info* filter;
	struct workqueue_struct *rx_copy_wq;
#if FT_FILTER_VERBOSE
	char* ft_pid_printed;
#endif
	//u64 time;

	//ft_start_time(&time);

again:  filter= find_and_get_filter(&msg->creator, msg->filter_id, msg->is_child, msg->daddr, msg->dport);
        if(filter){
                spin_lock_bh(&filter->lock);
           
		if(filter->ft_primary_closed==1){
			printk("WARNING primary closed is set on port %d\n", filter->tcp_param.dport);
		}
	
		if(!filter->rx_copy_wq){
			filter->rx_copy_wq= peak_wq_from_pckt_dispatcher_pool();
		}

		if(filter->type & FT_FILTER_ENABLE){
			rx_copy_wq= filter->rx_copy_wq;
			if(rx_copy_wq!=pckt_dispatcher_pool[PCKT_DISP_POOL_SIZE])
				filter->ft_pending_packets++;
			spin_unlock_bh(&filter->lock);	
		
			work= kmalloc(sizeof(*work), GFP_ATOMIC);
		        if(!work){
                		printk("ERROR: %s out of memory\n", __func__);
				ret= -ENOMEM;
                		goto out_err;
        		}

        		INIT_WORK( (struct work_struct*)work, dispatch_copy_msg);
        		work->data= inc_msg;
			work->filter= filter;
			work->count= 0;
			//work->time= time;
        		queue_work(rx_copy_wq, (struct work_struct*)work);
			
                }
                else{

			if(!(filter->type & FT_FILTER_FAKE)){
	                	spin_unlock_bh(&filter->lock);
			        printk("%s: ERROR filter is disable but not fake\n",__func__);
				ret= -EFAULT;
				goto out_err;
			}

                        spin_unlock_bh(&filter->lock);
			put_ft_filter(filter);
                        goto again;

                }

        }
        else{
#if FT_FILTER_VERBOSE
                ft_pid_printed= print_ft_pid(&msg->creator);
                FTPRINTK("%s: creating fake filter ft_pid %s id %d child %i\n\n", __func__, ft_pid_printed, msg->filter_id, msg->is_child);
                if(ft_pid_printed)
                        kfree(ft_pid_printed);
#endif

                ret= create_fake_filter(&msg->creator, msg->filter_id, msg->is_child, msg->daddr, msg->dport);
                if(!ret){
                        goto again;
		}
		else{
			printk("ERROR: %s impossible to create fake filter\n", __func__);
			pcn_kmsg_free_msg(msg);
		}
        }

out:
	return ret;
out_err:
	put_ft_filter(filter);
	pcn_kmsg_free_msg(msg);
	goto out;
}

/*
 * For coping skb check net/core/skb.c 
 */
static int create_rx_skb_copy_msg(struct net_filter_info *filter, long long pckt_id, long long local_tx, struct sk_buff *skb, struct rx_copy_msg **msg, int *msg_size){
	struct rx_copy_msg *message;
	int headerlen;
	int head_data_len;
	int message_size;

	headerlen = skb_headroom(skb);
	head_data_len= headerlen + skb->len;
	message_size= head_data_len+ sizeof(*message);

	message= kmalloc(message_size, GFP_ATOMIC);
	if(!message){
		printk("ERROR: %s out of memory\n", __func__);
		return -ENOMEM;
	}
	message->creator= filter->creator;
	message->filter_id= filter->id;
	message->is_child= filter->type & FT_FILTER_CHILD;
        if(message->is_child){
                message->daddr= filter->tcp_param.daddr;
                message->dport= filter->tcp_param.dport;
        }
	message->pckt_id= pckt_id;
	message->local_tx= local_tx;

	message->headerlen= headerlen;
	message->datalen= skb->len;
	message->taillen= skb_end_pointer(skb) - skb_tail_pointer(skb);
	
	//this should copy both header and data
	if (skb_copy_bits(skb, -headerlen, &message->data, head_data_len))
               BUG();

	/* Code copied from __copy_skb_header 
	 *
	 */

	message->tstamp		    = skb->tstamp;
	/*new->dev                  = old->dev;*/
#ifdef NET_SKBUFF_DATA_USES_OFFSET
	message->transport_header_off   = skb->transport_header- (skb->data-skb->head);
        message->network_header_off     = skb->network_header- (skb->data-skb->head);
        message->mac_header_off         = skb->mac_header- (skb->data-skb->head);
#else
	message->transport_header_off   = skb->transport_header- (skb->data);
        message->network_header_off     = skb->network_header- (skb->data);
        message->mac_header_off         = skb->mac_header- (skb->data);

#endif
	//skb_dst_copy(new, old);

        message->rxhash             = skb->rxhash;
        message->ooo_okay           = skb->ooo_okay;
        message->l4_rxhash          = skb->l4_rxhash;
	/*#ifdef CONFIG_XFRM
        new->sp                 = secpath_get(old->sp);
	#endif*/
	memcpy(message->cb, skb->cb, sizeof(message->cb));
	message->csum               = skb->csum;
        message->local_df           = skb->local_df;
        message->pkt_type           = skb->pkt_type;
        message->ip_summed          = skb->ip_summed;
	/*skb_copy_queue_mapping(new, old);*/
	message->priority          = skb->priority;
#if defined(CONFIG_IP_VS) || defined(CONFIG_IP_VS_MODULE)
        message->ipvs_property      = skb->ipvs_property;
#endif
        message->protocol           = skb->protocol;
	message->mark               = skb->mark;
        message->skb_iif            = skb->skb_iif;
        /*__nf_copy(new, old);*/
#if defined(CONFIG_NETFILTER_XT_TARGET_TRACE) || \
    defined(CONFIG_NETFILTER_XT_TARGET_TRACE_MODULE)
        message->nf_trace           = skb->nf_trace;
#endif
#ifdef CONFIG_NET_SCHED
        message->tc_index           = skb->tc_index;
#ifdef CONFIG_NET_CLS_ACT
        message->tc_verd            = skb->tc_verd;
#endif
#endif
        message->vlan_tci           = skb->vlan_tci;
	message->secmark = skb->secmark;


	message->header.type= PCN_KMSG_TYPE_FT_RX_COPY;
        message->header.prio= PCN_KMSG_PRIO_NORMAL;

	*msg= message;		
	*msg_size= message_size;

	return 0;
 
}

static void send_skb_copy(struct net_filter_info *filter, long long pckt_id, long long local_tx, struct sk_buff *skb){
        struct rx_copy_msg* msg;
        int msg_size;
        int ret;

        ret= create_rx_skb_copy_msg(filter, pckt_id, local_tx, skb, &msg, &msg_size);
        if(ret)
                return;

	send_to_all_secondary_replicas(filter->ft_popcorn, (struct pcn_kmsg_long_message*) msg, msg_size);

        kfree(msg);
}

static int handle_release_filter(struct pcn_kmsg_message* inc_msg){
	struct release_filter_msg *msg= (struct release_filter_msg* ) inc_msg;
	int ret= 0;
	struct release_filter_work *work;
	struct net_filter_info *filter;
	struct workqueue_struct *rx_copy_wq;

	filter= find_and_get_filter(&msg->creator, msg->filter_id, msg->is_child, msg->daddr, msg->dport);
        if(filter){
		
                spin_lock_bh(&filter->lock);
           	
		if(!filter->rx_copy_wq){
			printk("ERROR: no rx_copy_wq\n");
			goto out_err;
		}

		filter->ft_primary_closed= 1;
		rx_copy_wq= filter->rx_copy_wq;
		spin_unlock_bh(&filter->lock);	
	
		work= kmalloc(sizeof(*work), GFP_ATOMIC);
		if(!work){
			printk("ERROR: %s out of memory\n", __func__);
			ret= -ENOMEM;
			goto out_err;
		}

		INIT_WORK( (struct work_struct*)work, dispatch_release_filter_msg);
		work->filter= filter;
		work->count= 0;
		work->data= msg;
		queue_work(rx_copy_wq, (struct work_struct*)work);

        }

out:
	return ret;
out_err:
	spin_lock_bh(&filter->lock);
	put_ft_filter(filter);
	pcn_kmsg_free_msg(msg);
	goto out;
}


static int create_release_filter_msg(struct net_filter_info *filter, struct release_filter_msg **msg, int *msg_size){
	struct release_filter_msg *message;
	int message_size;

	message_size= sizeof(*message);

	message= kmalloc(message_size, GFP_ATOMIC);
	if(!message){
		printk("ERROR: %s out of memory\n", __func__);
		return -ENOMEM;
	}
	message->creator= filter->creator;
	message->filter_id= filter->id;
	message->is_child= filter->type & FT_FILTER_CHILD;
        if(message->is_child){
                message->daddr= filter->tcp_param.daddr;
                message->dport= filter->tcp_param.dport;
        }


	message->header.type= PCN_KMSG_TYPE_FT_RELEASE_FILTER;
        message->header.prio= PCN_KMSG_PRIO_NORMAL;

	*msg= message;		
	*msg_size= message_size;

	return 0;
 
}

static void send_release_filter_message(struct net_filter_info *filter){
	struct release_filter_msg* msg;
        int msg_size;
        int ret;

        ret= create_release_filter_msg(filter, &msg, &msg_size);
        if(ret)
                return;

        send_to_all_secondary_replicas(filter->ft_popcorn, (struct pcn_kmsg_long_message*) msg, msg_size);

        kfree(msg);
}

static void update_tcp_init_param(struct net_filter_info *filter, struct tcp_init_param *tcp_param){

        filter->tcp_param= *tcp_param;

}

static int handle_tcp_init_param(struct pcn_kmsg_message* inc_msg){
	struct tcp_init_param_msg* msg= (struct tcp_init_param_msg*) inc_msg;
	struct net_filter_info *filter;
        int err= 0;
        int removing_fake= 0;
#if FT_FILTER_VERBOSE
        char* ft_pid_printed;
#endif

again:  filter= find_and_get_filter(&msg->creator, msg->filter_id, msg->is_child, msg->daddr, msg->dport);
        if(filter){

                spin_lock_bh(&filter->lock);
                if(filter->type & FT_FILTER_ENABLE){
			if(msg->connect_id != -1){
				filter->primary_connect_id++;

			}
			else{
           			filter->primary_accept_id++;
			}
			update_tcp_init_param(filter, &msg->tcp_param);
                }
                else{
                        removing_fake= 1;
                }
                spin_unlock_bh(&filter->lock);

                put_ft_filter(filter);

                if(removing_fake){
                        removing_fake= 0;
                        goto again;
                }
        }
        else{
#if FT_FILTER_VERBOSE
                ft_pid_printed= print_ft_pid(&msg->creator);
                FTPRINTK("%s: creating fake filter for ft_pid %s id %d\n\n", __func__, ft_pid_printed, msg->filter_id);
                if(ft_pid_printed)
                        kfree(ft_pid_printed);
#endif

                err= create_fake_filter(&msg->creator, msg->filter_id, msg->is_child, msg->daddr, msg->dport);
                if(!err)
                        goto again;
        }

        pcn_kmsg_free_msg(msg);
	return err;
}

static int create_tcp_init_param_msg(struct net_filter_info* filter, int connect_id, int accept_id, struct tcp_init_param* tcp_param, struct tcp_init_param_msg** msg, int* msg_leng ){
	struct tcp_init_param_msg* message;

	message= kmalloc(sizeof(*message), GFP_ATOMIC);
	if(!message){
		printk("ERROR: %s out of memory\n", __func__);
		return -ENOMEM;
	}
	message->header.type= PCN_KMSG_TYPE_FT_TCP_INIT_PARAM;
        message->header.prio= PCN_KMSG_PRIO_NORMAL;

	message->is_child= filter->type & FT_FILTER_CHILD;
        message->creator= filter->creator;
        message->filter_id= filter->id;
	message->daddr= filter->tcp_param.daddr;
	message->dport= filter->tcp_param.dport;
        message->connect_id= connect_id;
	message->accept_id= accept_id;
	message->tcp_param= *tcp_param;

	*msg_leng= sizeof(*message);
	*msg= message;

	return 0; 
}

static void send_tcp_init_parameters_from_work(struct work_struct* work){
	struct tcp_param_work* my_work= (struct tcp_param_work*)work;
	struct net_filter_info* filter= my_work->filter;
	struct tcp_init_param_msg* msg;
	int msg_size,ret;

	if(is_there_any_secondary_replica(filter->ft_popcorn)){
		ret= create_tcp_init_param_msg(filter, my_work->connect_id, my_work->accept_id, &my_work->tcp_param, &msg, &msg_size);
		if(ret)
			goto out;
		
		send_to_all_secondary_replicas(filter->ft_popcorn, (struct pcn_kmsg_long_message*) msg, msg_size);
		
		kfree(msg);
	}
out:
	kfree(work);
	put_ft_filter(filter); 
	
}

static void send_tcp_init_param_accept(struct net_filter_info* filter, struct request_sock *req){
	struct tcp_param_work* work;
	int accept;
	struct inet_request_sock *ireq;

	spin_lock_bh(&filter->lock);
        accept= ++filter->local_accept_id;    
        spin_unlock_bh(&filter->lock);
        
        work= kmalloc(sizeof(*work), GFP_ATOMIC);
        if(!work)
                return;

        INIT_WORK( (struct work_struct*)work, send_tcp_init_parameters_from_work);
        work->filter= filter;
        work->connect_id= -1;
	work->accept_id= accept;
	ireq = inet_rsk(req);
	work->tcp_param.saddr= ireq->loc_addr;
        work->tcp_param.sport= ireq->loc_port;
	work->tcp_param.daddr= ireq->rmt_addr;
	work->tcp_param.dport= ireq->rmt_port;
       	work->tcp_param.snt_isn= tcp_rsk(req)->snt_isn; 
        work->tcp_param.snt_synack= tcp_rsk(req)->snt_synack;
	get_ft_filter(filter);

        queue_work(tx_notify_wq, (struct work_struct*)work);

}

static void send_tcp_init_param_connect(struct net_filter_info* filter, struct sock* sk){
	struct inet_sock *inet = inet_sk(sk);
        struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_param_work* work;
	int connect;

	spin_lock_bh(&filter->lock);
	connect= ++filter->local_connect_id;	
	spin_unlock_bh(&filter->lock);
	
	work= kmalloc(sizeof(*work), GFP_ATOMIC);
	if(!work)
		return;

	INIT_WORK( (struct work_struct*)work, send_tcp_init_parameters_from_work);
        work->filter= filter;
	work->accept_id= -1;
	work->connect_id= connect;
        work->tcp_param.write_seq= tp->write_seq;
	work->tcp_param.inet_id= inet->inet_id;
	work->tcp_param.sport= inet->inet_sport;
	work->tcp_param.dport= inet->inet_dport;
	work->tcp_param.daddr= inet->inet_daddr;
	work->tcp_param.saddr= inet->inet_saddr;
	work->tcp_param.rcv_saddr= inet->inet_rcv_saddr;
	
	get_ft_filter(filter);

        queue_work(tx_notify_wq, (struct work_struct*)work);
}

static void send_tcp_init_param(struct net_filter_info* filter, struct sock* sk, struct request_sock *req){
	
	if (req) {
		send_tcp_init_param_accept(filter, req);
		return;
	}

	if (sk){
		send_tcp_init_param_connect(filter, sk);
		return;
	}
}

void ft_change_tcp_init_connect(struct sock* sk){
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	tp->write_seq= inet->inet_daddr + inet->inet_dport;
}

/* Remove randomly generated sequence numbers to align primary/secondary replicas.
 * If replica is PRIMARY, also send init connection information, like real port
 * and address to SECONDARY replicas.
 */
void ft_check_tcp_init_param(struct net_filter_info* filter, struct sock* sk, struct request_sock *req){

	if(filter){
		if(!req)
			ft_change_tcp_init_connect(sk);
	
		if(filter->type & FT_FILTER_PRIMARY_REPLICA){
			if(is_there_any_secondary_replica(filter->ft_popcorn)){
				send_tcp_init_param(filter, sk, req);
			}
		}
	}

}

/* Note: call put_iphdr after using get_iphdr in case 
 * of no errors.
 */
static int get_iphdr(struct sk_buff *skb, struct iphdr** ip_header,int *iphdrlen){
	int res= -EFAULT;
	struct iphdr* network_header= NULL;
	int len;

	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
	skb_reset_mac_len(skb);

	if (skb->pkt_type == PACKET_OTHERHOST)
		goto out;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto out;

	/*if(skb_shared(skb))
		printk("%s: WARNING skb shared\n", __func__);*/

	network_header= ip_hdr(skb);

	if (network_header->ihl < 5 || network_header->version != 4)
		goto out;

	if (!pskb_may_pull(skb, network_header->ihl*4))
		goto out;

	network_header= ip_hdr(skb);

	if (unlikely(ip_fast_csum((u8 *)network_header, network_header->ihl)))
		goto out;

	len = ntohs(network_header->tot_len);
	if (skb->len < len || len < network_header->ihl*4)
		goto out;

	if (pskb_trim_rcsum(skb, len))
		goto out;

	/* Remove any debris in the socket control block */
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
	skb_orphan(skb);

	*iphdrlen= ip_hdrlen(skb);
	__skb_pull(skb, *iphdrlen);
	skb_reset_transport_header(skb);

	*ip_header= ip_hdr(skb);

	res= 0;

out:
	return res;
}

static void put_iphdr(struct sk_buff *skb, int iphdrlen){
	__skb_push(skb, iphdrlen);
}

static unsigned int ft_hook_before_network_layer_primary(struct net_filter_info *filter, struct sk_buff *skb){
        long long pckt_id;
        long long local_tx;
#if FT_FILTER_VERBOSE
        char* filter_id_printed;
#endif
	u64 time;
	
        spin_lock_bh(&filter->lock);
        pckt_id= ++filter->local_rx;
        local_tx= filter->local_tx;

#if FT_FILTER_VERBOSE
        filter_id_printed= print_filter_id(filter);
        FTPRINTK("%s: pid %d broadcasting packet %llu in filter %s\n\n", __func__, current->pid, pckt_id, filter_id_printed);
        if(filter_id_printed)
                kfree(filter_id_printed);
#endif
	if(is_there_any_secondary_replica(filter->ft_popcorn)){
        	//ft_start_time(&time);

		send_skb_copy(filter, pckt_id, local_tx, skb);

		//ft_end_time(&time);
		//ft_update_time(&time, FT_TIME_SEND_PACKET_REP);
	}

        /* Do not know if it is correct to send msgs while holding this lock,
         * but this should prevent deliver out of order of pckts to secondary replicas
         * if the working queues rx_copy_wq are single thread.
         * (assuming that msg layer is FIFO)
         */
        spin_unlock_bh(&filter->lock);

        return NF_ACCEPT;
}

static unsigned int ft_hook_before_network_layer_secondary(struct net_filter_info *filter, struct sk_buff* skb){
        long long pckt_id;
        long long primary_rx;
#if FT_FILTER_VERBOSE
	char* filter_id_printed= NULL;
        char* ft_pid_printed;
#endif

        spin_lock_bh(&filter->lock);
        pckt_id= ++filter->local_rx;
        primary_rx= filter->primary_rx;
        spin_unlock_bh(&filter->lock);

#if FT_FILTER_VERBOSE
        ft_pid_printed= print_ft_pid(&current->ft_pid);
        filter_id_printed= print_filter_id(filter);
        FTPRINTK("%s: pid %d ft_pid %s received pckt %llu in filter %s\n\n", __func__, current->pid, ft_pid_printed, pckt_id, filter_id_printed);
        if(ft_pid_printed)
                kfree(ft_pid_printed);
        if(filter_id_printed){
                kfree(filter_id_printed);
        }
#endif
	return NF_ACCEPT;
}

static int check_correct_filter(struct net_filter_info **filter, struct sock *sk, struct sk_buff *skb){
	struct iphdr *iph;
        struct tcphdr *tcp_header;
	__u32 start,end,size;
	struct net_filter_info *old_filter= NULL;
	struct sock *csk= NULL;
	struct request_sock **prev;
        struct request_sock *req;
	int ret= 0;
	
	iph = ip_hdr(skb);
	if(iph->protocol == IPPROTO_TCP && sk->sk_state == TCP_LISTEN){
	
		skb_pull(skb, ip_hdrlen(skb));
                skb_reset_transport_header(skb);

		tcp_header= tcp_hdr(skb);
                iph = ip_hdr(skb);
		
                start= ntohl(tcp_header->seq);
                end= ntohl(tcp_header->seq)+ tcp_header->syn+ tcp_header->fin+ skb->len- tcp_header->doff*4;
                size= end-start;

		/* Check if the message is meant for the child socket
                 *
                 */
		if(!tcp_header->syn && size){
			bh_lock_sock(sk);
			req = inet_csk_search_req(sk, &prev, tcp_header->source, iph->saddr, iph->daddr);
                	if(req){
				old_filter= *filter;
				get_ft_filter(req->ft_filter);
				*filter= req->ft_filter;
				ret= 1;	
                	}
			else{
				csk = find_tcp_sock(skb, tcp_header);
				if(csk && sk!=csk){
					old_filter= *filter;
	                                get_ft_filter(csk->ft_filter);
                	                *filter= csk->ft_filter;
                                	ret= 1;
				}
				
			}
			bh_unlock_sock(sk);
			if(csk){
				sock_put(csk);
			}
			if(old_filter){
				 put_ft_filter(old_filter);
			}
		}


		__skb_push(skb, ip_hdrlen(skb));
	}

	return ret;
}

unsigned int ft_hook_func_before_network_layer(unsigned int hooknum,
                                 struct sk_buff *skb,
                                 const struct net_device *in,
                                 const struct net_device *out,
                                 int (*okfn)(struct sk_buff *)){

        struct iphdr *iph;
        unsigned int ret= NF_ACCEPT;
        struct udphdr *udp_header;
        struct tcphdr *tcp_header;
        struct sock *sk;
	struct net_filter_info *filter;
	int err, time_wait=0;
	u64 time, itime;

	ft_start_time(&time);

        if(hooknum != NF_INET_PRE_ROUTING){
                printk("ERROR: %s has been called at hooknum %d\n", __func__, hooknum);
                goto out;
        }

	iph = ip_hdr(skb);
	
	if(iph->protocol == IPPROTO_UDP
                        || iph->protocol == IPPROTO_TCP){

			/* skb_dst must be set to corectly retrive the sock struct.
			 * because we are in pre_routing this field migth not be already set up.
			 */
                        if (skb_dst(skb) == NULL) {
                                err = ip_route_input_noref(skb, iph->daddr, iph->saddr, iph->tos, skb->dev);
                                if (unlikely(err)) {
                                        goto out;
                                }
                        }


			/* IP did not finish yet, so transport header is not set...
                         * undo things after!!!
                         */
                        __skb_pull(skb, ip_hdrlen(skb));
                        skb_reset_transport_header(skb);

                        if (iph->protocol == IPPROTO_UDP){
                                udp_header= udp_hdr(skb);
                                sk = udp4_lib_lookup(dev_net(skb_dst(skb)->dev), iph->saddr, udp_header->source,
                                     iph->daddr, udp_header->dest, inet_iif(skb));
                        }
                        else{
                                tcp_header= tcp_hdr(skb);
                                sk = find_tcp_sock(skb, tcp_header);
                        }

			 __skb_push(skb, ip_hdrlen(skb));

			if(sk){
				/* Special case in which the sock struct is discarded and substituted by
				 * a struct inet_timewait_sock.
				 * This happen after closing a socket when the timeout is triggered ( see tcp_time_wait)
				 */
				if(sk->sk_state == TCP_TIME_WAIT){
					filter= inet_twsk(sk)->ft_filter;
					time_wait= 1;
				}
				else{
					filter= sk->ft_filter;
				}

				if(filter){
					//ft_start_time(&itime);

					get_ft_filter(filter);
					check_correct_filter(&filter, sk, skb);
					
					if(filter->type & FT_FILTER_SECONDARY_REPLICA){
                				ret= ft_hook_before_network_layer_secondary(filter, skb);
        				}
					else{
        					if(filter->type & FT_FILTER_PRIMARY_REPLICA || filter->type & FT_FILTER_PRIMARY_AFTER_SECONDARY_REPLICA){
							ret= ft_hook_before_network_layer_primary(filter, skb);
                   				}
					}

					put_ft_filter(filter);
					
					//ft_end_time(&itime);
				        //ft_update_time(&itime, FT_TIME_BEF_NET_REP);

				}

                        	if(time_wait){
					inet_twsk_put(inet_twsk(sk));
				}
				else{
					sock_put(sk);
				}
                        }

	}
out:
	ft_end_time(&time);
	ft_update_time(&time, FT_TIME_HOOK_BEF_NET);
        return ret;
}

/* ARGH... no clues on what to do with the timestemps...
 *
 */
int ft_check_tcp_timestamp(struct sock* sk){
	if(sk->ft_filter){
		if(sk->ft_filter->type & FT_FILTER_SECONDARY_REPLICA){
			return 0;
		}
	}

	return 1;
}

struct nf_hook_ops ft_before_transport_hook;

struct tcp_out_options {
         u8 options;             /* bit field of OPTION_* */
         u8 ws;                  /* window scale, 0 to disable */
         u8 num_sack_blocks;     /* number of SACK blocks to include */
         u8 hash_size;           /* bytes in hash_location */
         u16 mss;                /* 0 to disable */
         __u32 tsval, tsecr;     /* need to include OPTION_TS */
         __u8 *hash_location;    /* temporary pointer, overloaded */
};

/* For value of ip_summed check include/linux/skbuff.h
 *
 */
static __sum16 checksum_tcp_rx(struct sk_buff *skb, int len, struct iphdr *iph, struct tcphdr *tcph){
	__sum16 ret= 0;
	
	/*NOTE tcp_v4_check calls csum_tcpudp_magic for tcp.
	 *csum_tcpudp_magic adds to the checksum provided the saddr and daddr  
	 */
	ret= tcp_v4_check(len, iph->saddr, iph->daddr, csum_partial((char *)tcph, len, 0));
	
	/* this should tell tcp to not check the th->checksum against the one stored in skb->csum
	 * =>as if the hardware already check it.
	 */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	return ret; 
}

static __sum16 checksum_tcp_tx(struct sk_buff *skb, int len, struct iphdr *iph, struct tcphdr *tcph){
	__sum16 ret= 0;
	if ((skb_dst(skb) && skb_dst(skb)->dev) && (!(skb_dst(skb)->dev->features & NETIF_F_V4_CSUM))) {
		//no hw checksum
		skb->ip_summed = CHECKSUM_COMPLETE;
		//_wsum csum = skb_checksum(skb, 0, skb->len - ip_hdrlen(skb), 0);
		//tcp_header->check = csum_tcpudp_magic(iph->saddr,iph->daddr, skb->len - ip_hdrlen(skb), IPPROTO_TCP, csum);

		ret= tcp_v4_check(len, iph->saddr, iph->daddr, csum_partial((char *)tcph, len, 0));
		if (ret == 0)
                        ret = CSUM_MANGLED_0;

	} else {
		/*
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = tcph;
		skb->csum_offset = offsetof(struct tcphdr, check);
		//ret= ~csum_tcpudp_magic(inet->ineinet->inet_daddr, len, IPPROTO_TCP, 0);
		ret= ~tcp_v4_check(len, iph->saddr, iph->daddr, csum_partial((char *)tcph, len, 0));
		*/
		skb->csum_start = skb_transport_header(skb) - skb->head;
        	skb->csum_offset = offsetof(struct tcphdr, check);
        	skb->ip_summed = CHECKSUM_PARTIAL;

		ret= ~csum_tcpudp_magic(iph->saddr, iph->daddr, len, IPPROTO_TCP, 0);

	}

	return ret;
}

void send_ack(struct sock* sk, __u32 seq, __u32 ack_seq, __u32 window){

	 struct sk_buff *skb;
 	 const struct inet_connection_sock *icsk = inet_csk(sk);
         struct inet_sock *inet;
         struct tcp_sock *tp;
         struct tcp_skb_cb *tcb;
         struct tcp_out_options opts;
         unsigned tcp_options_size, tcp_header_size;
         struct tcphdr *th;
	 unsigned int eff_sacks;
	 //s32 win;
         int err;
	 __be32 *ptr;
	 u8 options;

	 /* We are not putting this on the write queue, so
	  * tcp_transmit_skb() will set the ownership to this
	  * sock.
	  */
	 skb = alloc_skb(MAX_TCP_HEADER, GFP_ATOMIC);
         if (skb == NULL) {
                 return;
         }
 
         /* Reserve space for headers and prepare control bits. */
         skb_reserve(skb, MAX_TCP_HEADER);
	 skb->ip_summed = CHECKSUM_PARTIAL;
         skb->csum = 0;
 
         TCP_SKB_CB(skb)->tcp_flags = TCPHDR_ACK;
         TCP_SKB_CB(skb)->sacked = 0;
 
         skb_shinfo(skb)->gso_segs = 1;
         skb_shinfo(skb)->gso_size = 0;
         skb_shinfo(skb)->gso_type = 0;
 
         TCP_SKB_CB(skb)->seq = seq;
         TCP_SKB_CB(skb)->end_seq = seq; 
         /* Send it off, this clears delayed acks for us. */
         TCP_SKB_CB(skb)->when = tcp_time_stamp;

 
         /* If congestion control is doing timestamping, we must
          * take such a timestamp before we potentially clone/copy.
          */
         if (icsk->icsk_ca_ops->flags & TCP_CONG_RTT_STAMP)
                 __net_timestamp(skb);
 
         inet = inet_sk(sk);
         tp = tcp_sk(sk);
         tcb = TCP_SKB_CB(skb);
         memset(&opts, 0, sizeof(opts));
	
	#define OPTION_TS               (1 << 1) 
	tcp_options_size= 0;
	 if (likely(tp->rx_opt.tstamp_ok)) {       
		printk("%s ERROR: timestamp opt should be disable\n",__func__);
		 opts.options |= OPTION_TS;
                 opts.tsval = tcb ? tcb->when : 0;
                 opts.tsecr = tp->rx_opt.ts_recent;
                 tcp_options_size += TCPOLEN_TSTAMP_ALIGNED;
         }
 
         eff_sacks = tp->rx_opt.num_sacks + tp->rx_opt.dsack;
         if (unlikely(eff_sacks)) {
                 const unsigned remaining = MAX_TCP_OPTION_SPACE - tcp_options_size;
                 opts.num_sack_blocks =
                         min_t(unsigned, eff_sacks,
                               (remaining - TCPOLEN_SACK_BASE_ALIGNED) /
                               TCPOLEN_SACK_PERBLOCK);
                 tcp_options_size += TCPOLEN_SACK_BASE_ALIGNED +
                         opts.num_sack_blocks * TCPOLEN_SACK_PERBLOCK;
         } 

         tcp_header_size = tcp_options_size + sizeof(struct tcphdr);
 
         skb->ooo_okay = 1;
 
         skb_push(skb, tcp_header_size);
         skb_reset_transport_header(skb);
         skb_set_owner_w(skb, sk);
 
         /* Build TCP header and checksum it. */
         th = tcp_hdr(skb);
         th->source              = inet->inet_sport;
         th->dest                = inet->inet_dport;
         th->seq                 = htonl(tcb->seq);
         th->ack_seq             = htonl(ack_seq);
         *(((__be16 *)th) + 6)   = htons(((tcp_header_size >> 2) << 12) |
                                         tcb->tcp_flags);
 
	 /*win = htons(min(tp->rcv_wnd, 65535U));
	 if (win < 0)
                 win = 0;

         th->window      = htons((u32)win);*/
	 th->window	 =  htons(window);
	 th->check               = 0;
         th->urg_ptr             = 0;
 
      
	 ptr= (__be32 *)(th + 1);
	 options = opts.options;     /* mungable copy */

         if (likely(OPTION_TS & options)) {
                 *ptr++ = htonl((TCPOPT_NOP << 24) |
                                        (TCPOPT_NOP << 16) |
                                        (TCPOPT_TIMESTAMP << 8) |
                                        TCPOLEN_TIMESTAMP);
                 *ptr++ = htonl(opts.tsval);
                 *ptr++ = htonl(opts.tsecr);
         }
 
         if (unlikely(opts.num_sack_blocks)) {
                 struct tcp_sack_block *sp = tp->rx_opt.dsack ?
                         tp->duplicate_sack : tp->selective_acks;
                 int this_sack;
 
                 *ptr++ = htonl((TCPOPT_NOP  << 24) |
                                (TCPOPT_NOP  << 16) |
                                (TCPOPT_SACK <<  8) |
                                (TCPOLEN_SACK_BASE + (opts.num_sack_blocks *
                                                      TCPOLEN_SACK_PERBLOCK)));
 
                 for (this_sack = 0; this_sack < opts.num_sack_blocks;
                      ++this_sack) {
                         *ptr++ = htonl(sp[this_sack].start_seq);
                         *ptr++ = htonl(sp[this_sack].end_seq);
                 }
 
                 tp->rx_opt.dsack = 0;
         }
        // TCP_ECN_send(sk, skb, tcp_header_size);

 
	 icsk->icsk_af_ops->send_check(sk, skb);

         err = icsk->icsk_af_ops->queue_xmit(skb, &inet->cork.fl);
         if (likely(err <= 0))
                 return;
 
         tcp_enter_cwr(sk, 1);
 
         /*net_xmit_eval(err);*/

}

/*TODO
 * do not use this function, it was a static function in its file.
 * rewrite a new one.
 */
extern void tcp_fin(struct sock *sk);

/* This is the core of the tcp filter hook after that a failure occured and the secondary replica has been elected primary.
 * 
 * It modifies the tcp header of the packets that needs to be delivered to hide th.
 *
 * NOTE: it assumes that the iphdr has been pulled from the skbuff->data.
 */
unsigned int ft_hook_before_tcp_primary_after_secondary(struct sk_buff *skb, struct net_filter_info *filter){
	struct tcphdr *tcp_header;
	struct iphdr *iph;
	struct sock *sk;
	char *filter_id_printed;
	__u32 start,end,size;
	struct request_sock **prev;
        struct request_sock *req;
	int actual_data_size, data_to_keep;

	
	/* The idea is to just let transit all packets but change the seq 
	 * and ack_seq to be aligned with the status on the current socket.
	 * Why? if the connection was established by the primary before failing,
	 * the current socket was left inactive after the handshake while the primary was
	 * dealing with the client. 
	 */
	 
        sk= filter->ft_sock;

	if( filter->ft_time_wait || !sk){
              	if(!filter->ft_time_wait){
			/* This can happen only if it is a minisocket.
			 * But a minisocket should not be select by tcp for delivering pckts....
			 */ 
			filter_id_printed= print_filter_id(filter);
			printk("ERROR in %s, ft_sock is null in filter %s", __func__, filter_id_printed);	
			if(filter_id_printed)
				kfree(filter_id_printed);

			goto out;
		}
		else{
			sk= (struct sock*)filter->ft_time_wait;
		}
        }

	switch (sk->sk_state) {
	
	case TCP_ESTABLISHED:
		{

		/* Code copied from tcp_v4_rcv.
		 * It checks that the pckt is valid.
		 */

		if (skb->pkt_type != PACKET_HOST)
			goto out;
		
		if (!pskb_may_pull(skb, sizeof(struct tcphdr)))
			goto out;
		
		tcp_header= tcp_hdr(skb);
		
		if (tcp_header->doff < sizeof(struct tcphdr) / 4)
			goto out;
	
		if (!pskb_may_pull(skb, tcp_header->doff * 4))
			goto out;
		
		//if (!skb_csum_unnecessary(skb) && tcp_v4_checksum_init(skb))
		//	goto out;
	
		tcp_header = tcp_hdr(skb);
		iph = ip_hdr(skb);
		TCP_SKB_CB(skb)->seq = ntohl(tcp_header->seq);
		TCP_SKB_CB(skb)->end_seq = (TCP_SKB_CB(skb)->seq + tcp_header->syn + tcp_header->fin +
				  skb->len - tcp_header->doff * 4);
	
		TCP_SKB_CB(skb)->ack_seq = ntohl(tcp_header->ack_seq);
		TCP_SKB_CB(skb)->when    = 0;
		TCP_SKB_CB(skb)->ip_dsfield = ipv4_get_dsfield(iph);
		TCP_SKB_CB(skb)->sacked  = 0;

		if (unlikely(iph->ttl < inet_sk(sk)->min_ttl)) {
			goto out;
		}

		if( tcp_header->syn ) {
			goto out;
		}

		//if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
		//	goto out;
		
		nf_reset(skb);

		if (sk_filter(sk, skb))
			goto out;
		
		//NOTE send buffer should have been flushed before changing replicas/filters type.
		if(!send_buffer_empty(filter->send_buffer)){
			printk("%s ERROR send buffer not empty\n",__func__);
		}
		
		/* Let the packet transit 
		 * but change seq/ack_seq
		 */

		start= ntohl(tcp_header->seq);
		end= ntohl(tcp_header->seq)+ tcp_header->syn+ tcp_header->fin+ skb->len- tcp_header->doff*4;
		size= end-start;

		//printk("%s status %d: syn %u ack %u fin %u seq %u end seq %u size %u ack_seq %u port %i\n", __func__, filter->ft_sock->sk_state, tcp_header->syn, tcp_header->ack, tcp_header->fin, start, end, size,ntohl( tcp_header->ack_seq), ntohs(tcp_header->source));
		
		if(TCP_SKB_CB(skb)->seq <= get_last_byte_received_stable_buffer(filter->stable_buffer)){
			//the client is resending data already received

			if( TCP_SKB_CB(skb)->ack_seq > get_last_ack_send_buffer(filter->send_buffer)){
				//printk("%s acking new data: last ack %u ack seq %u", __func__, get_last_ack_send_buffer(filter->send_buffer), TCP_SKB_CB(skb)->ack_seq);
			} 
		
			/*				
				
			//code for sending and ack for the retransmitted data directly from here.
			//it acks just old received data

			if(TCP_SKB_CB(skb)->end_seq > filter->stable_buffer->last_byte+1){
				printk("%s WARINIG: client is retrasmitting old data with new one\n", __func__);
			}

			if(TCP_SKB_CB(skb)->end_seq > filter->stable_buffer->last_byte+1)
				send_ack(sk, TCP_SKB_CB(skb)->ack_seq + filter->idelta_seq, filter->stable_buffer->last_byte + filter->odelta_seq);
			else
				send_ack(sk, TCP_SKB_CB(skb)->ack_seq + filter->idelta_seq, TCP_SKB_CB(skb)->end_seq + filter->odelta_seq);

			*/				
		
			//remove the previous data and let it transit with same ack
			actual_data_size=  TCP_SKB_CB(skb)->end_seq -TCP_SKB_CB(skb)->seq- tcp_header->syn- tcp_header->fin;
			data_to_keep= get_last_byte_received_stable_buffer(filter->stable_buffer)+1 - TCP_SKB_CB(skb)->end_seq;
			if(data_to_keep){
				//Not sure if during retransmission you can send new data within the same pckt...
				printk("ERROR %s new data with old one (dropping)!!! TODO KEEP THE DATA!!\n", __func__);
				return NF_DROP;
			}

			TCP_SKB_CB(skb)->seq= TCP_SKB_CB(skb)->end_seq;
			tcp_header->seq= htonl(TCP_SKB_CB(skb)->seq);
			if(actual_data_size){
				___pskb_trim(skb, skb->len- actual_data_size);
				tcp_header= tcp_hdr(skb);			
				iph= ip_hdr(skb);
			}		
		}

		tcp_header->seq= htonl(get_iseq_in(filter, ntohl(tcp_header->seq)));
		tcp_header->ack_seq= htonl(get_oseq_in(filter, ntohl(tcp_header->ack_seq)));

		//recompute checksum
		tcp_header->check = 0;
		tcp_header->check= checksum_tcp_rx(skb, skb->len, iph, tcp_header);

		start= ntohl(tcp_header->seq);
		end= ntohl(tcp_header->seq)+ tcp_header->syn+ tcp_header->fin+ skb->len- tcp_header->doff*4;
		size= end-start;

		//printk("%s status %d: syn %u ack %u fin %u seq %u end seq %u size %u ack_seq %u port %i\n", __func__, filter->ft_sock->sk_state, tcp_header->syn, tcp_header->ack, tcp_header->fin, start, end, size,ntohl( tcp_header->ack_seq), ntohs(tcp_header->source));

		return NF_ACCEPT;
		
		}

	case TCP_SYN_SENT:
	case TCP_SYN_RECV:
	case TCP_LISTEN:
		{

		/* Let packets transit as they are to open connections.
		 *
		 */

		tcp_header= tcp_hdr(skb);
		iph = ip_hdr(skb);

		start= ntohl(tcp_header->seq);
		end= ntohl(tcp_header->seq)+ tcp_header->syn+ tcp_header->fin+ skb->len- tcp_header->doff*4;
		size= end-start;
	
		req = inet_csk_search_req(sk, &prev, tcp_header->source, iph->saddr, iph->daddr);
		if(req){
			/* ACK received after SYNACK
			 *
			 */
			if( (size-tcp_header->syn) > 0){
				//this msg is not ending the handshake
				printk("ERROR %s received a unexpected packet during handshake, dropping it.\n", __func__);
				goto out;
			}

			if(!tcp_header->syn && tcp_header->ack){	
				/*set first byte to consume in both receive and send buffer*/

				//stable buffer stores data sent by the client with seq number chosen by the client itself.
				//init first_byte_to_consume with the seq chosen by the client.
				init_first_byte_to_consume_stable_buffer(req->ft_filter->stable_buffer, end);
				
				//send buffer stores data sent by the server. The seq number changes between replicas, but the client will always ack the seq 
				//chosen by the primary replica, so init first_byte_to_consume with the seq of the primary. 
				init_first_byte_to_consume_send_buffer(req->ft_filter->send_buffer, ntohl(tcp_header->ack_seq));
				
				//when creating the socket from minisocket will be used to compute the real odelta
				req->ft_filter->odelta_seq= ntohl(tcp_header->ack_seq);

				//NOTE, this  msg is acking the seq sent by the primary replica, change it with the correct ack_seq.
				tcp_header->ack_seq= htonl(tcp_rsk(req)->snt_isn+ 1);
				
				//recompute checksum
				tcp_header->check = 0;
				tcp_header->check= checksum_tcp_rx(skb, skb->len, iph, tcp_header);
			}
		}

		//printk("%s listening skb %p: syn %u ack %u fin %u seq %u end seq %u size %u ack_seq %u port %i \n", __func__, skb, tcp_header->syn, tcp_header->ack, tcp_header->fin, start, end, size,ntohl( tcp_header->ack_seq), ntohs(tcp_header->source));

		if(!req && !tcp_header->syn && tcp_header->ack){
			//could be for pending connection
			return try_complete_handshake_seq(skb, filter);
		}
		
		return NF_ACCEPT;

		}

	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
	case TCP_LAST_ACK:
		{
		
		tcp_header= tcp_hdr(skb); 
		iph = ip_hdr(skb);

		start= ntohl(tcp_header->seq);
		end= ntohl(tcp_header->seq)+ tcp_header->syn+ tcp_header->fin+ skb->len- tcp_header->doff*4;
		size= end-start;

		//printk("%s status %d: syn %u ack %u fin %u seq %u end seq %u size %u ack_seq %u port %i\n", __func__, filter->ft_sock->sk_state, tcp_header->syn, tcp_header->ack, tcp_header->fin, start, end, size,ntohl( tcp_header->ack_seq), ntohs(tcp_header->source)); 
		 
		 /* Let the packet transit to close connections 
		  * but change seq/ack_seq
		  */

		 tcp_header->seq= htonl(get_iseq_in(filter, ntohl(tcp_header->seq))); 
		 tcp_header->ack_seq= htonl(get_oseq_in(filter, ntohl(tcp_header->ack_seq)));
		 
		 //recompute checksum
		 tcp_header->check = 0;
		 tcp_header->check= checksum_tcp_rx(skb, skb->len, iph, tcp_header);

		start= ntohl(tcp_header->seq);
		end= ntohl(tcp_header->seq)+ tcp_header->syn+ tcp_header->fin+ skb->len- tcp_header->doff*4;
		size= end-start;
		//printk("%s status %d: syn %u ack %u fin %u seq %u end seq %u size %u ack_seq %u port %i\n", __func__, filter->ft_sock->sk_state, tcp_header->syn, tcp_header->ack, tcp_header->fin, start, end, size,ntohl( tcp_header->ack_seq), ntohs(tcp_header->source));

		 return NF_ACCEPT;
		}

	case TCP_CLOSE:
	case TCP_TIME_WAIT:
		//printk("%s closed\n",__func__);
		return NF_ACCEPT;
	}	

out:
	return NF_DROP;

}

/* This is the core of the tcp filter hook.
 * 
 * It steals pckts that are not needed to open or close a connection, and it saves them in a stable buffer.
 * 
 * The stable buffer will be used by rcv syscalls to read data delivered to this socket and it will be used in case
 * of the primary failure.
 * 
 * It also checks acks sent to this socket to free items stored by send syscalls in the send buffer.
 *
 * NOTE: it assumes that the iphdr has been pulled from the skbuff->data
 */
unsigned int ft_hook_before_tcp_secondary(struct sk_buff *skb, struct net_filter_info *filter){
	struct tcphdr *tcp_header;
	struct iphdr *iph;
	struct sock *sk;
	char *filter_id_printed;
	__u32 start,end,size;
	unsigned int ret, stolen= 0;
	struct request_sock **prev;
        struct request_sock *req;
	struct sk_buff *new_skb= NULL;


	/* The idea is to just let transit packets needed to establish and close connections.
	 * If a socket is in TCP_LISTEN, it just establishes connections, so let transit everything.
	 *
	 * If status is TCP_ESTABLISHED, steal the packet and save it on the stable buffer.
	 * If status is one of the "closing statuses" let it transit to close the socket.
	 */
        sk= filter->ft_sock;

	if(filter->ft_time_wait || !sk){
                
		if(!filter->ft_time_wait){
			/* This can happen only if it is a minisocket.
			 * But a minisocket should not be select by tcp for delivering pckts....
			 */ 
			filter_id_printed= print_filter_id(filter);
			printk("ERROR in %s, ft_sock is null in filter %s", __func__, filter_id_printed);	
			if(filter_id_printed)
				kfree(filter_id_printed);
			goto out;
		}
		else{
			sk= (struct sock*)filter->ft_time_wait;
		}
        }
	
	switch (sk->sk_state) {
	
	case TCP_ESTABLISHED:
		{
		/* Stop packets. Do not inject them in the tcp state machine,
		 * but save them in stable buffer.
		 */
		
		/* Code copied from tcp_v4_rcv.
		 * It checks that the pckt is valid.
		 */

		if (skb->pkt_type != PACKET_HOST)
			goto out;
		
		if (!pskb_may_pull(skb, sizeof(struct tcphdr)))
			goto out;
		
		tcp_header= tcp_hdr(skb);
		
		if (tcp_header->doff < sizeof(struct tcphdr) / 4)
			goto out;
	
		if (!pskb_may_pull(skb, tcp_header->doff * 4))
			goto out;
		
		//if (!skb_csum_unnecessary(skb) && tcp_v4_checksum_init(skb))
		//	goto out;
	
		tcp_header = tcp_hdr(skb);
		iph = ip_hdr(skb);
		TCP_SKB_CB(skb)->seq = ntohl(tcp_header->seq);
		TCP_SKB_CB(skb)->end_seq = (TCP_SKB_CB(skb)->seq + tcp_header->syn + tcp_header->fin +
				  skb->len - tcp_header->doff * 4);
	
		TCP_SKB_CB(skb)->ack_seq = ntohl(tcp_header->ack_seq);
		TCP_SKB_CB(skb)->when    = 0;
		TCP_SKB_CB(skb)->ip_dsfield = ipv4_get_dsfield(iph);
		TCP_SKB_CB(skb)->sacked  = 0;

		if (unlikely(iph->ttl < inet_sk(sk)->min_ttl)) {
			goto out;
		}

		if( tcp_header->syn ) {
			goto out;
		}
		//if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
		//	goto out;
		
		nf_reset(skb);

		if (sk_filter(sk, skb))
			goto out;
		
		//skb->dev = NULL;

		start= TCP_SKB_CB(skb)->seq;
		end=  TCP_SKB_CB(skb)->end_seq;
		size= end-start;			
		
		/* update deltas */
		set_idelta_seq(filter, end-tcp_header->fin);
		set_odelta_seq(filter, TCP_SKB_CB(skb)->ack_seq);

		/* remove data stored in the send buffer */ 
		//NOTE send buffer has been initialized with primary seq, so it is safe to not apply any delta to the used ack.
		remove_from_send_buffer(filter->send_buffer, TCP_SKB_CB(skb)->ack_seq);
	   
		//printk("%s pckt on status %d: syn %u ack %u fin %u seq %u end seq %u size %u ack_seq %u port %i\n", __func__, filter->ft_sock->sk_state, tcp_header->syn, tcp_header->ack, tcp_header->fin, start, end, size,ntohl( tcp_header->ack_seq), ntohs(tcp_header->source));

		/* save the packet in the stable buffer only if there is actual payload*/
		if(size && !(size==1 && tcp_header->fin) ){

			//printk("%s inserting in stable buffer %d: syn %u ack %u fin %u seq %u end seq %u size %u ack_seq %u port %i\n", __func__, filter->ft_sock->sk_state, tcp_header->syn, tcp_header->ack, tcp_header->fin, start, end, size,ntohl( tcp_header->ack_seq), ntohs(tcp_header->source));

			if(tcp_header->fin){
				//in this case the packet should transit througth the real socket too
				//copy it
				new_skb= skb_copy(skb, GFP_ATOMIC);
				if(!new_skb){
					printk("ERROR: %s impossible to copy skb\n", __func__);
					goto out;
				}
				
				ret= insert_in_stable_buffer(filter->stable_buffer, new_skb, start, end-1-tcp_header->fin); 
			}
			else{

				ret= insert_in_stable_buffer(filter->stable_buffer, skb, start, end-1-tcp_header->fin);	
			}

			//printk("%s saving pckt on stable buffer %d: syn %u ack %u fin %u seq %u end seq %u size %u ack_seq %u port %i\n", __func__, filter->ft_sock->sk_state, tcp_header->syn, tcp_header->ack, tcp_header->fin, start, end, size,ntohl( tcp_header->ack_seq), ntohs(tcp_header->source));

			if(ret){
				printk("ERROR %s impossible to save in stable buffer ret %d\n", __func__, ret);
				goto out;
			}
			else{
				stolen= 1;
			}
		}			

		/*start closing socket if fin is active*/
		if(tcp_header->fin){
			trace_printk("ESTABLISH: fin arrived port %i size %d\n", ntohs(tcp_header->source), size);
			if(size && !(size==1)){
				if(!new_skb){
					printk("ERROR %s pckt should have been saved on stable buffer with fin without copying it\n", __func__);
					skb_get(skb);
				}
				
				//trim pckt
				TCP_SKB_CB(skb)->seq= TCP_SKB_CB(skb)->end_seq-1;
				tcp_header->seq= htonl(TCP_SKB_CB(skb)->seq);
				___pskb_trim(skb, skb->len- size + tcp_header->fin);
				tcp_header= tcp_hdr(skb);
				iph= ip_hdr(skb);
			}

			tcp_header->seq= htonl(get_iseq_in(filter, ntohl(tcp_header->seq)));
			tcp_header->ack_seq= htonl(get_oseq_in(filter, ntohl(tcp_header->ack_seq)));

			//recompute checksum
			tcp_header->check = 0;
			tcp_header->check= checksum_tcp_rx(skb, skb->len, iph, tcp_header);

			trace_printk("status %i fin %d ack %d seq %u ack seq %u tp rcv next %u snd next %u port %i\n", sk->sk_state, tcp_header->fin, tcp_header->ack, ntohl(tcp_header->seq), ntohl(tcp_header->ack_seq), tcp_sk(sk)->rcv_nxt, tcp_sk(sk)->snd_nxt, ntohs(tcp_header->source));

			return NF_ACCEPT;
		}


		if(stolen)
			return NF_STOLEN;
		else
			return NF_DROP;
		
		}

	case TCP_SYN_SENT:
	case TCP_SYN_RECV:
	case TCP_LISTEN:
		{

		/* Let packets transit as they are to open connections.
		 *
		 */

		tcp_header= tcp_hdr(skb);
		iph = ip_hdr(skb);

		start= ntohl(tcp_header->seq);
		end=  ntohl(tcp_header->seq)+ tcp_header->syn+ tcp_header->fin+ skb->len- tcp_header->doff*4;
		size= end-start;
		
		/*printk("%s letting pckt transiting on status %d: syn %u ack %u fin %u seq %u end seq %u size %u ack_seq %u port %i\n", __func__, filter->ft_sock->sk_state, tcp_header->syn, tcp_header->ack, tcp_header->fin, start, end, size,ntohl( tcp_header->ack_seq), ntohs(tcp_header->source));

		if (inet_csk_reqsk_queue_is_full(sk) ) {
			printk("%s inet_csk_reqsk_queue_is_full\n",__func__);
		}
		if (sk_acceptq_is_full(sk)){
			 printk("%s sk_acceptq_is_full\n",__func__);
		}
		if (inet_csk_reqsk_queue_young(sk) > 1){
			 printk("%s inet_csk_reqsk_queue_young\n",__func__);
		}*/


		req = inet_csk_search_req(sk, &prev, tcp_header->source, iph->saddr, iph->daddr);
		if(req){
			/* ACK received after SYNACK
			 *
			 */
			if((size-tcp_header->syn) > 0){
				//this msg is not part of the handshake
				printk("ERROR %s received a unexpected packet during handshake, dropping it.\n", __func__);
				goto out;
			}

			FTMPRINTK("%s letting pckt transiting on status %d: syn %u ack %u fin %u seq %u end seq %u size %u ack_seq %u\n", __func__, filter->ft_sock->sk_state, tcp_header->syn, tcp_header->ack, tcp_header->fin, start, end, size,ntohl( tcp_header->ack_seq));

			/*set first byte to consume in both receive and send buffer*/

			if(!tcp_header->syn && tcp_header->ack){				
				//stable buffer stores data sent by the client with seq number chosen by the client itself.
				//init first_byte_to_consume with the seq chosen by the client.
				init_first_byte_to_consume_stable_buffer(req->ft_filter->stable_buffer, end);
	
				//send buffer stores data sent by the server. The seq number changes between replicas, but the client will always ack the seq 
				//chosen by the primary replica, so init first_byte_to_consume with the seq of the primary. 
				init_first_byte_to_consume_send_buffer(req->ft_filter->send_buffer, ntohl(tcp_header->ack_seq));
			
				//when creating the socket from minisocket will be used to compute the real odelta
				req->ft_filter->odelta_seq= ntohl(tcp_header->ack_seq);

				//NOTE, this  msg is acking the seq sent by the primary replica, change it with the correct ack_seq.
				tcp_header->ack_seq= htonl(tcp_rsk(req)->snt_isn+ 1);
			      
				//recompute checksum
				tcp_header->check = 0;
				tcp_header->check= checksum_tcp_rx(skb, skb->len, iph, tcp_header);
			}
		}
		
		return NF_ACCEPT;

		}

	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
	case TCP_LAST_ACK:
		{
				
		 /* Let the packet transit to close connections 
		  * but change seq/ack_seq
		  * NOTE: stop updating deltas, the connection is active again!			
		  */

		 /* Code copied from tcp_v4_rcv.
		  * It checks that the pckt is valid.
		  */

		if (skb->pkt_type != PACKET_HOST)
			goto out;

		if (!pskb_may_pull(skb, sizeof(struct tcphdr)))
			goto out;

		tcp_header= tcp_hdr(skb);

		if (tcp_header->doff < sizeof(struct tcphdr) / 4)
			goto out;

		if (!pskb_may_pull(skb, tcp_header->doff * 4))
			goto out;

		//if (!skb_csum_unnecessary(skb) && tcp_v4_checksum_init(skb))
		//      goto out;

		tcp_header = tcp_hdr(skb);
		iph = ip_hdr(skb);
		TCP_SKB_CB(skb)->seq = ntohl(tcp_header->seq);
		TCP_SKB_CB(skb)->end_seq = (TCP_SKB_CB(skb)->seq + tcp_header->syn + tcp_header->fin +
				  skb->len - tcp_header->doff * 4);

		TCP_SKB_CB(skb)->ack_seq = ntohl(tcp_header->ack_seq);
		TCP_SKB_CB(skb)->when    = 0;
		TCP_SKB_CB(skb)->ip_dsfield = ipv4_get_dsfield(iph);
		TCP_SKB_CB(skb)->sacked  = 0;

		if (unlikely(iph->ttl < inet_sk(sk)->min_ttl)) {
			goto out;
		}

		if( tcp_header->syn ) {
			goto out;
		}

		//if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
		//      goto out;

		nf_reset(skb);
		
		if (sk_filter(sk, skb))
			goto out;

		//skb->dev = NULL;

		start= TCP_SKB_CB(skb)->seq;
		end=  TCP_SKB_CB(skb)->end_seq;
		size= end-start;

		/* update deltas */
		//set_idelta_seq(filter, end);
		//set_odelta_seq(filter, TCP_SKB_CB(skb)->ack_seq);

		/* remove data stored in the send buffer */
		//NOTE send buffer has been initialized with primary seq, so it is safe to not apply any delta to the used ack.
		remove_from_send_buffer(filter->send_buffer, TCP_SKB_CB(skb)->ack_seq);

		//printk("%s letting pckt transiting on status %d: syn %u ack %u fin %u seq %u end seq %u size %u ack_seq %u port %i\n", __func__, filter->ft_sock->sk_state, tcp_header->syn, tcp_header->ack, tcp_header->fin, start, end, size,ntohl( tcp_header->ack_seq), ntohs(tcp_header->source));

		/* save the packet in the stable buffer only if there is actual payload*/
		if(size && !(size==1 && tcp_header->fin) ){
			
			new_skb= skb_copy(skb, GFP_ATOMIC);
			if(!new_skb){
				printk("ERROR: %s impossible to copy skb\n", __func__);
				goto out;
			}

			ret= insert_in_stable_buffer(filter->stable_buffer, new_skb, start, end-1-tcp_header->fin);
			if(ret){
				printk("ERROR %s impossible to save in stable buffer ret %d\n", __func__, ret);
				goto out;
			}
			else{
				//trim pckt
				TCP_SKB_CB(skb)->seq= TCP_SKB_CB(skb)->end_seq;
				tcp_header->seq= htonl(TCP_SKB_CB(skb)->seq);
				___pskb_trim(skb, skb->len- size + tcp_header->fin);
				tcp_header= tcp_hdr(skb);
				iph= ip_hdr(skb);         	
			}
		}


		// tcp_header->seq= htonl(get_iseq_in(filter, ntohl(tcp_header->seq))); 
	
		/* Brute force approach, why?
		 * Primary and secondary may have a different tcp state machine for closing connection.
		 * so packets forwarded by the primary will not close the connection on the secondary.
		 * Therefore brutally change incoming packet to make the secondary connection close.
		 * NOTE: we could use deltas to compute seq and ack_seq but they migth be shifted according to what that packet 
		 * was acking of the primary => directly use rcv next and snd next to be align with this socket.
		 */	 
		 
		 tcp_header->seq= htonl(tcp_sk(sk)->rcv_nxt);
		 tcp_header->ack_seq= htonl(tcp_sk(sk)->snd_nxt);

		 switch(sk->sk_state){
			case TCP_FIN_WAIT1:
			/*A device in this state is waiting for an ACK for a FIN it has sent, or is waiting for a connection termination request from the other device.*/
			
			case TCP_FIN_WAIT2:
			/*A device in this state has received an ACK for its request to terminate the connection and is now waiting for a matching FIN from the other device.*/

			/*we need a fin packet in these cases, easier if not fin-ack*/
			if(!tcp_header->fin){
				 tcp_header->fin= 1;
			}
			break;

			case TCP_LAST_ACK:
			/*A device that has already received a close request and acknowledged it, has sent its own FIN and is waiting for an ACK to this request.*/

			/*we need an ack without fin*/

			if(tcp_header->fin){
				tcp_header->fin= 0;
                        }
			
			break;

			case TCP_CLOSING:
			/*The device has received a FIN from the other device and sent an ACK for it, but not yet received an ACK for its own FIN message*/
			
			/*we need an ack with fin*/
			if(!tcp_header->fin){
                        	tcp_header->fin= 1;
			}
			break;

			case TCP_CLOSE_WAIT:
			/*The device has received a close request (FIN) from the other device. It must now wait for the application on the local device to acknowledge this request and generate a matching request.*/
			//printk("WARNING in CLOSE_WAIT fin %d port %d\n", tcp_header->fin, ntohs(tcp_header->source));
			break;

		 }

		 //recompute checksum
		 tcp_header->check = 0;
		 tcp_header->check= checksum_tcp_rx(skb, skb->len, iph, tcp_header);

		 trace_printk("fin status %i fin %d ack %d seq %u ack seq %u tp rcv next %u  tp send next %u port %i\n", sk->sk_state, tcp_header->fin, tcp_header->ack, ntohl(tcp_header->seq), ntohl(tcp_header->ack_seq), tcp_sk(sk)->rcv_nxt,  tcp_sk(sk)->snd_nxt, ntohs(tcp_header->source));

		 return NF_ACCEPT;
		}

	case TCP_CLOSE:
	case TCP_TIME_WAIT:
		return NF_DROP;
	}	

out:
	return NF_DROP;
}


unsigned int ft_hook_before_tcp(struct sk_buff *skb, struct net_filter_info *ft_filter){
	unsigned int ret= NF_ACCEPT; 
#if FT_FILTER_VERBOSE
        char *filter_id_printed;
#endif
	u64 time;

        if(ft_filter){
		//ft_start_time(&time);

		get_ft_filter(ft_filter);
                
		if(ft_filter->type & FT_FILTER_SECONDARY_REPLICA){

#if FT_FILTER_VERBOSE
			filter_id_printed= print_filter_id(ft_filter);
                        FTPRINTK("%s: Received tcp pckt in filter %s of secondary replica\n", __func__, filter_id_printed);
			if(filter_id_printed)
                        	kfree(filter_id_printed);
#endif

			ret= ft_hook_before_tcp_secondary(skb, ft_filter);	
			
                }
                else{
                        if(ft_filter->type & FT_FILTER_PRIMARY_REPLICA){
				/* Primary replica does not need to do anything...
				 * Simply let the pckt be delivered to tcp.
				 */
#if FT_FILTER_VERBOSE
				filter_id_printed= print_filter_id(ft_filter);
				FTPRINTK("%s: Received tcp pckt in filter %s of primary replica\n", __func__, filter_id_printed);
				if(filter_id_printed)
                        		kfree(filter_id_printed);
#endif

				struct tcphdr *tcp_header = tcp_hdr(skb);
				if(ft_filter->ft_sock && (ft_filter->ft_sock->sk_state==TCP_FIN_WAIT1 || ft_filter->ft_sock->sk_state==TCP_FIN_WAIT2 || ft_filter->ft_sock->sk_state==TCP_CLOSE_WAIT || ft_filter->ft_sock->sk_state==TCP_CLOSING || ft_filter->ft_sock->sk_state==TCP_LAST_ACK || tcp_header->fin)){
					
					trace_printk("status %d pckt: syn %u ack %u fin %u seq %u end seq %u size %u ack_seq %u port %i\n", ft_filter->ft_sock->sk_state, tcp_header->syn, tcp_header->ack, tcp_header->fin, ntohl(tcp_header->seq), ntohl(tcp_header->seq) + tcp_header->syn + tcp_header->fin + skb->len - tcp_header->doff * 4, tcp_header->syn + tcp_header->fin + skb->len - tcp_header->doff * 4,ntohl( tcp_header->ack_seq), ntohs(tcp_header->source));
				}

				/*struct tcphdr *tcp_header = tcp_hdr(skb);

	                        printk("%s pckt: syn %u ack %u fin %u seq %u end seq %u size %u ack_seq %u port %i\n", __func__, tcp_header->syn, tcp_header->ack, tcp_header->fin, ntohl(tcp_header->seq), ntohl(tcp_header->seq) + tcp_header->syn + tcp_header->fin + skb->len - tcp_header->doff * 4, tcp_header->syn + tcp_header->fin + skb->len - tcp_header->doff * 4,ntohl( tcp_header->ack_seq), ntohs(tcp_header->source));
                        	if(ft_filter->ft_sock && ft_filter->ft_sock->sk_state==TCP_LISTEN){
					if (inet_csk_reqsk_queue_is_full(ft_filter->ft_sock) ) {
						printk("%s inet_csk_reqsk_queue_is_full\n",__func__);
					}
					if (sk_acceptq_is_full(ft_filter->ft_sock)){
						 printk("%s sk_acceptq_is_full\n",__func__);
					}
					if (inet_csk_reqsk_queue_young(ft_filter->ft_sock) > 1){
                                                 printk("%s inet_csk_reqsk_queue_young\n",__func__);
                                        }

				}*/
			}
			else{
				if(ft_filter->type & FT_FILTER_PRIMARY_AFTER_SECONDARY_REPLICA){
#if FT_FILTER_VERBOSE
	                                filter_id_printed= print_filter_id(ft_filter);
        	                        FTPRINTK("%s: Received tcp pckt in filter %s of primary replica\n", __func__, filter_id_printed);
                	                if(filter_id_printed)
                        	                kfree(filter_id_printed);
#endif

					//if the filter is fake, means that the aplication did not create the socket yet,
					//so we cannot deliver packts... 
					//TODO
					//save them???
					if(ft_filter->type & FT_FILTER_FAKE)
						printk("ERROR: %s packet delivered to a fake filter while in primary after secondary\n", __func__);

					ret= ft_hook_before_tcp_primary_after_secondary(skb, ft_filter);
				}
			}
                }

		put_ft_filter(ft_filter);
		
		//ft_end_time(&time);
		//ft_update_time(&time, FT_TIME_BEF_TRA_REP);
        }

        return ret;
}

unsigned int ft_hook_before_udp(struct sk_buff *skb, struct net_filter_info *ft_filter){
	
	char *filter_id_printed;
	unsigned int ret= NF_ACCEPT;
	if(ft_filter){
		filter_id_printed= print_filter_id(ft_filter);
		if(ft_filter->type & FT_FILTER_SECONDARY_REPLICA){
                	printk("%s: Received udp pckt in filter %s of secondary replica\n", __func__, filter_id_printed);
        	}
		else{
        		if(ft_filter->type & FT_FILTER_PRIMARY_REPLICA){
        			printk("%s: Received udp pckt in filter %s of primary replica\n", __func__, filter_id_printed);
			}	
			else
				if(ft_filter->type & FT_FILTER_PRIMARY_AFTER_SECONDARY_REPLICA){
					printk("%s: Received udp pckt in filter %s of primary after secondary replica\n", __func__, filter_id_printed);
					if(ft_filter->type & FT_FILTER_FAKE){
						printk("ERROR: %s packet delivered to a fake filter while in primary after secondary\n", __func__);
						ret= NF_DROP;
					}
				}
		}
		if(filter_id_printed)
                        kfree(filter_id_printed);
	}

	return ret;
}

/* This hook is needed for replicating tcp connections.
 * It works mainly on secondary replicas in which it allows packets to transit
 * in the tcp state machine only to open and close connections. 
 * All other packets are stored in a stable buffer that will be queried in case
 * of the primary failure.
 */
unsigned int ft_hook_func_before_transport_layer(unsigned int hooknum,
                                 struct sk_buff *skb,
                                 const struct net_device *in,
                                 const struct net_device *out,
                                 int (*okfn)(struct sk_buff *)){

	struct iphdr *iph;
	unsigned int ret= NF_ACCEPT;
	struct udphdr *udp_header;
	struct tcphdr *tcp_header;
	struct sock *sk;
	u64 time;

	ft_start_time(&time);
	
	
	if(hooknum != NF_INET_LOCAL_IN){
		printk("ERROR: %s has been called at hooknum %d\n", __func__, hooknum);
		goto out;
	}

	/* I should be in IP, just before calling the transport layer,
	 * so in skb the pointer to ip header should already be set correctly,
	 * but pull is not already been done, so transport header may not point 
	 * to the correct position.
	 */

	iph= ip_hdr(skb);

	/* Replica information, if there, are stored in a field of struct sock;
	 * try to retrive the sock struct to extract ft_filter,
	 * if not possible simply accept the pckt.
	 */
	if(iph->protocol == IPPROTO_UDP
                        || iph->protocol == IPPROTO_TCP){


                        if (skb_dst(skb) == NULL) {
				/* Routing decitions should have already been made.
				 * => this field should be correctly populated.
				 */
                        	printk("ERROR: %s skb_dst is NULL\n", __func__);
				goto out;
			}
			
			/* IP did not finish yet, so transport header is not set...
			 * undo things after!!!
			 */
			__skb_pull(skb, ip_hdrlen(skb));
                        skb_reset_transport_header(skb);
                        
			if (iph->protocol == IPPROTO_UDP){
				udp_header= udp_hdr(skb);
                                sk = udp4_lib_lookup(dev_net(skb_dst(skb)->dev), iph->saddr, udp_header->source,
                                     iph->daddr, udp_header->dest, inet_iif(skb));
                                if(sk){
					ret= ft_hook_before_udp(skb, sk->ft_filter);
					sock_put(sk);
				}
                        }
                        else{
				tcp_header= tcp_hdr(skb);
                                sk = find_tcp_sock(skb, tcp_header);
                                
				if(sk){

					if(sk->sk_state==TCP_TIME_WAIT){
                                		ret= ft_hook_before_tcp(skb, inet_twsk(sk)->ft_filter);
						inet_twsk_put(inet_twsk(sk));
					}
                                	else{
						ret= ft_hook_before_tcp(skb, sk->ft_filter);
	                               		sock_put(sk);
					}
				}

                        }
			
			/*AAA do not undu if it has been stolen! 
			 *It will use tcph, so do not move iph!!
			 */			
			if(ret!=NF_STOLEN)
				__skb_push(skb, ip_hdrlen(skb));

	}

out:
	ft_end_time(&time);
	ft_update_time(&time, FT_TIME_HOOK_BEF_TRA);

	return ret;
}

struct nf_hook_ops ft_after_transport_hook;

unsigned int ft_hook_after_transport_layer_primary_after_secondary(struct net_filter_info *filter, struct sk_buff *skb){
	struct tcphdr *tcp_header;
	struct iphdr *iph;
	struct sock *sk;
	char *filter_id_printed;
	struct handshake_work *hand_work;
	u32 max_ack;

        sk= filter->ft_sock;

	if(filter->ft_time_wait || !sk){
              	if(!filter->ft_time_wait){
			/* This can happen only if it is a minisocket.
			 * But a minisocket should not be select by tcp for delivering pckts....
			 */ 
			filter_id_printed= print_filter_id(filter);
			printk("ERROR in %s, ft_sock is null in filter %s", __func__, filter_id_printed);	
			if(filter_id_printed)
				kfree(filter_id_printed);

			goto out;
		}
		else{
			sk= (struct sock*)filter->ft_time_wait;
		}
        }
      
	switch (sk->sk_state) {
	
	case TCP_ESTABLISHED:
		{
		tcp_header = tcp_hdr(skb);
		iph= ip_hdr(skb);

		FTMPRINTK("%s BEFORE: syn %u ack %u fin %u seq %u ack_seq %u\n", __func__, tcp_header->syn, tcp_header->ack, tcp_header->fin, ntohl(tcp_header->seq), ntohl( tcp_header->ack_seq));

		FTMPRINTK("%s filter->odelta_seq %u filter->idelta_seq %u\n", __func__, filter->odelta_seq, filter->idelta_seq);

		tcp_header->seq= htonl(get_oseq_out(filter, ntohl(tcp_header->seq)));
		max_ack= ((get_iseq_out(filter, ntohl(tcp_header->ack_seq))) > get_last_byte_received_stable_buffer(filter->stable_buffer))? get_iseq_out(filter, ntohl(tcp_header->ack_seq)): get_last_byte_received_stable_buffer(filter->stable_buffer);
		tcp_header->ack_seq= htonl(max_ack);

		/* code for changing outgoing window size.
		if(tcp_header->window== htons(17520)){
			printk("CHANGING\n");
			tcp_header->window= htons(20440);	
		}
		*/	
		
		//recompute checksum
		tcp_header->check = 0;
		tcp_header->check= checksum_tcp_tx(skb, skb->len - ip_hdrlen(skb), iph, tcp_header);

		FTMPRINTK("%s AFTER: syn %u ack %u fin %u seq %u ack_seq %u\n", __func__, tcp_header->syn, tcp_header->ack, tcp_header->fin, ntohl(tcp_header->seq), ntohl( tcp_header->ack_seq));

		return NF_ACCEPT;
		
		}

	case TCP_SYN_SENT:
	case TCP_SYN_RECV:
	case TCP_LISTEN:
		{

		FTMPRINTK("%s in one of listen, What to do?Modify?\n", __func__);
		tcp_header = tcp_hdr(skb);
		iph= ip_hdr(skb);
		
		/* If part of handshake completed by the primary drop answer*/
		if(tcp_header->syn && filter->rx_copy_wq){

			hand_work= get_handshake_work(iph->daddr, tcp_header->dest);
			if(hand_work && hand_work->completed==1){
				kfree_skb(skb);
				return NF_STOLEN;
			}
		}

		return NF_ACCEPT;

		}

	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
	case TCP_LAST_ACK:
		{
		 
		 /* Let the packet transit to close connections 
		  * but change seq/ack_seq
		  */

		tcp_header= tcp_hdr(skb);
		iph= ip_hdr(skb);

		tcp_header->seq= htonl(get_oseq_out(filter, ntohl(tcp_header->seq))); 
		max_ack= ((get_iseq_out(filter, ntohl(tcp_header->ack_seq))) > get_last_byte_received_stable_buffer(filter->stable_buffer))? get_iseq_out(filter, ntohl(tcp_header->ack_seq)): get_last_byte_received_stable_buffer(filter->stable_buffer);
		tcp_header->ack_seq= htonl(max_ack);

		//recompute checksum
		tcp_header->check = 0;
		tcp_header->check= checksum_tcp_tx(skb, skb->len - ip_hdrlen(skb), iph, tcp_header);

		FTMPRINTK("in one of the fin status seq %u ack seq %u tp rcv next %u\n", ntohl(tcp_header->seq), ntohl(tcp_header->ack_seq), tcp_sk(sk)->rcv_nxt);

		return NF_ACCEPT;
		}

	case TCP_CLOSE:
	case TCP_TIME_WAIT:
		return NF_ACCEPT;
	}	

out:	return NF_ACCEPT;

}

unsigned int ft_hook_func_after_transport_layer(unsigned int hooknum,
                                 struct sk_buff *skb,
                                 const struct net_device *in,
                                 const struct net_device *out,
                                 int (*okfn)(struct sk_buff *)){

	struct iphdr *iph;
        unsigned int ret= NF_ACCEPT;
        struct sock *sk;
        struct net_filter_info *filter;
	u64 time, itime;

	ft_start_time(&time);

	if(hooknum != NF_INET_LOCAL_OUT){
                printk("ERROR: %s has been called at hooknum %d\n", __func__, hooknum);
                goto out;
        }

        /* This is the end of IP tx path, so all the iph and transporth pointers should be
         * already correctly populated.
         */

        iph = ip_hdr(skb);

        if(iph->protocol == IPPROTO_TCP){

                        /* We are on the tx path, so the socket was already found,
                         * if there, it is stored in skb->sk
                         */
                        sk= skb->sk;
                        if(sk){
                                if(sk->sk_state== TCP_TIME_WAIT)
					filter= inet_twsk(sk)->ft_filter;
				else
					filter= sk->ft_filter;
                                
				if(filter){
                       			//ft_start_time(&itime);   
              
					get_ft_filter(filter);
			
                                        if(filter->type & FT_FILTER_PRIMARY_AFTER_SECONDARY_REPLICA){
						ret= ft_hook_after_transport_layer_primary_after_secondary(filter, skb);
					}
                                        
                                        put_ft_filter(filter);

					//ft_end_time(&itime);
					//ft_update_time(&itime, FT_TIME_AFT_TRA_REP);
                                }
                        }

        }
out:
	ft_end_time(&time);
	ft_update_time(&time, FT_TIME_HOOK_AFT_TRA);

        return ret;

}

/* NOTE: to be called only after flush filters to be sure that all the 
 * data has been inserted in stable bufferi before trimming.
 *
 */
int trim_stable_buffer_in_filters(void){
	struct list_head *iter= NULL;
        struct net_filter_info *filter= NULL;
        int ret= 0;

	spin_lock_bh(&filter_list_lock);

        if(!list_empty(&filter_list_head)){
                list_for_each(iter, &filter_list_head) {
                        filter = list_entry(iter, struct net_filter_info, list_member);
                        if(filter->type & FT_FILTER_ENABLE){
				//char* filter_print= print_filter_id(filter);
				//printk("%s :",filter_print);
				//kfree(filter_print);
				ret= trim_stable_buffer(filter->stable_buffer);
				if(ret)
                                	goto out;
				set_idelta_seq_hard(filter, get_last_byte_received_stable_buffer(filter->stable_buffer)+1);
                        }

                }
        }

out:
        spin_unlock_bh(&filter_list_lock);
	
	return ret;
}

/* NOTE: to be called only after flush filters to be sure that all the 
 * data has been acknoleged in send buffer before flushing.
 *
 */
int flush_send_buffer_in_filters(void){
        struct list_head *iter= NULL;
        struct net_filter_info *filter= NULL;
        int ret= 0;

        spin_lock_bh(&filter_list_lock);

        if(!list_empty(&filter_list_head)){
                list_for_each(iter, &filter_list_head) {
                        filter = list_entry(iter, struct net_filter_info, list_member);
                        if(filter->type & FT_FILTER_ENABLE){
                             	ret= flush_send_buffer(filter->send_buffer, filter->ft_sock);
				if(ret)
                                	goto out;
                        }

                }
        }

out:
        spin_unlock_bh(&filter_list_lock);

        return ret;
}

int send_zero_window_in_filters(void){
        struct list_head *iter= NULL;
        struct net_filter_info *filter= NULL;
        int ret= 0;

        spin_lock_bh(&filter_list_lock);

        if(!list_empty(&filter_list_head)){
                list_for_each(iter, &filter_list_head) {
                        filter = list_entry(iter, struct net_filter_info, list_member);
                        if(filter->type & FT_FILTER_ENABLE && filter->ft_sock && filter->ft_sock->sk_state!=TCP_LISTEN){
                        	send_ack(filter->ft_sock, tcp_sk(filter->ft_sock)->snd_nxt, tcp_sk(filter->ft_sock)->rcv_nxt, 0);
			}

                }
        }

        spin_unlock_bh(&filter_list_lock);

        return ret;
}

/*Flush the working queues used to deliver pckts in filters.
 *This function might put the current thread to sleep.
 */
int flush_pending_pckt_in_filters(void){
	int i;
	
	for(i=0; i< PCKT_DISP_POOL_SIZE; i++){
		drain_workqueue(pckt_dispatcher_pool[i]);
	}

	return 0;
}

//NOTE:  write_lock(&replica_type_lock) must be held
int update_filter_type_after_failure(void){

	struct list_head *iter= NULL;
        struct net_filter_info *filter= NULL;
        int ret= 0;

        spin_lock_bh(&filter_list_lock);

        if(!list_empty(&filter_list_head)){
                list_for_each(iter, &filter_list_head) {
                        filter = list_entry(iter, struct net_filter_info, list_member);
                        if(filter->type & FT_FILTER_ENABLE){
				if(filter->type & FT_FILTER_SECONDARY_REPLICA){
					filter->type &= ~FT_FILTER_SECONDARY_REPLICA;
					filter->type |= FT_FILTER_PRIMARY_AFTER_SECONDARY_REPLICA;
				}	
				//if(filter->ft_sock && filter->ft_sock->sk_state!=TCP_LISTEN)
				//	send_ack(filter->ft_sock, tcp_sk(filter->ft_sock)->snd_nxt, tcp_sk(filter->ft_sock)->rcv_nxt, min(tcp_sk(filter->ft_sock)->rcv_wnd, 65535U));
			}
		}
	}

	spin_unlock_bh(&filter_list_lock);

	return ret;
}

static int __init ft_filter_init(void){

	if(create_pckt_dispatcher_pool())
		printk("%s ERROR cannot create pckt_dispatcher_pool\n", __func__);

	INIT_LIST_HEAD(&filter_list_head);

	tx_notify_wq= create_singlethread_workqueue("tx_notify_wq");
	
	pcn_kmsg_register_callback(PCN_KMSG_TYPE_FT_TX_NOTIFY, handle_tx_notify);
	pcn_kmsg_register_callback(PCN_KMSG_TYPE_FT_RX_COPY, handle_rx_copy);
	pcn_kmsg_register_callback(PCN_KMSG_TYPE_FT_TCP_INIT_PARAM, handle_tcp_init_param);
	pcn_kmsg_register_callback(PCN_KMSG_TYPE_FT_RELEASE_FILTER, handle_release_filter);

	print_log_buf_info();

	/* Slab cache for stable buffers.
	 * For now it is one for each kernel, but it can be changed and set
	 * one for each socket.
	 */	

	stable_buffer_entries= kmem_cache_create("stable_buffers_cache", sizeof(struct stable_buffer_entry), 0, SLAB_PANIC, NULL);
	if(!stable_buffer_entries)
		printk("%s ERROR cannot create stable buffer cache\n", __func__);

	/* Slab cache for ft filters (struct net_filter_info).
         */

	ft_filters_entries= kmem_cache_create("ft_filters_cache", sizeof(struct net_filter_info), 0, SLAB_PANIC, NULL);
        if(!ft_filters_entries)
                printk("%s ERROR cannot create ft filters cache\n", __func__);

	/* Register netfilter hooks.
	 * ft_before_network_hook-> rx path, in first hook called by IP.
	 * ft_after_network_hook-> tx path, in last hook called by IP.
	 * ft_before_transport_hook-> rx path, in last hook called by IP before delivering to local machine.
	 * ft_after_transport_hook-> tx path, in first hook called by IP before going out from local machine.
	 */
	ft_before_transport_hook.hook= ft_hook_func_before_transport_layer;
	ft_before_transport_hook.pf= PF_INET;
	ft_before_transport_hook.priority= NF_IP_PRI_LAST;
	ft_before_transport_hook.hooknum= NF_INET_LOCAL_IN;
	
	nf_register_hook(&ft_before_transport_hook);

	ft_after_transport_hook.hook= ft_hook_func_after_transport_layer;
        ft_after_transport_hook.pf= PF_INET;
        ft_after_transport_hook.priority= NF_IP_PRI_LAST;
        ft_after_transport_hook.hooknum= NF_INET_LOCAL_OUT;

        nf_register_hook(&ft_after_transport_hook);

	ft_before_network_hook.hook= ft_hook_func_before_network_layer;
        ft_before_network_hook.pf= PF_INET;
        ft_before_network_hook.priority= NF_IP_PRI_LAST;
        ft_before_network_hook.hooknum= NF_INET_PRE_ROUTING;

        nf_register_hook(&ft_before_network_hook);

	ft_after_network_hook.hook= ft_hook_func_after_network_layer;
        ft_after_network_hook.pf= PF_INET;
        ft_after_network_hook.priority= NF_IP_PRI_LAST;
        ft_after_network_hook.hooknum= NF_INET_POST_ROUTING;

        nf_register_hook(&ft_after_network_hook);


	return 0;
}

late_initcall(ft_filter_init);
