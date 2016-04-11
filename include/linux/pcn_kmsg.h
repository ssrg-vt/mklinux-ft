#ifndef __LINUX_PCN_KMSG_H
#define __LINUX_PCN_KMSG_H
/*
 * Header file for Popcorn inter-kernel messaging layer
 *
 * (C) Ben Shelton <beshelto@vt.edu> 2013
 */

#include <linux/list.h>
#include <linux/multikernel.h>
#include <linux/types.h>

/* LOCKING / SYNCHRONIZATION */
#define pcn_cpu_relax() __asm__ ("pause":::"memory")
//#define pcn_barrier() __asm__ __volatile__("":::"memory")
#define pcn_barrier() mb()

/* BOOKKEEPING */

#define POPCORN_MAX_MCAST_CHANNELS 32

struct pcn_kmsg_mcast_wininfo {
	volatile unsigned char lock;
	unsigned char owner_cpu;
	volatile unsigned char is_closing;
	unsigned long mask;
	unsigned int num_members;
	unsigned long phys_addr;
};

// only one allocated by the first kernel?
struct pcn_kmsg_rkinfo {
	long active[POPCORN_MAX_CPUS];
	unsigned long phys_addr[POPCORN_MAX_CPUS];
	struct cpumask _cpumask[POPCORN_MAX_CPUS];
	struct pcn_kmsg_mcast_wininfo mcast_wininfo[POPCORN_MAX_MCAST_CHANNELS];
};

enum pcn_kmsg_wq_ops {
	PCN_KMSG_WQ_OP_MAP_MSG_WIN,
	PCN_KMSG_WQ_OP_UNMAP_MSG_WIN,
	PCN_KMSG_WQ_OP_MAP_MCAST_WIN,
	PCN_KMSG_WQ_OP_UNMAP_MCAST_WIN
};

typedef unsigned long pcn_kmsg_mcast_id;

typedef struct {
	struct work_struct work;
	enum pcn_kmsg_wq_ops op;
	int from_cpu;
	int cpu_to_add;
	pcn_kmsg_mcast_id id_to_join;
} pcn_kmsg_work_t;

/* MESSAGING */

/* Enum for message types.  Modules should add types after
   PCN_KMSG_END. */
enum pcn_kmsg_type {
	PCN_KMSG_TYPE_TEST,
	PCN_KMSG_TYPE_TEST_LONG,
	PCN_KMSG_TYPE_CHECKIN,
	PCN_KMSG_TYPE_KEEPALIVE,
#ifdef PCN_SUPPORT_MULTICAST
	PCN_KMSG_TYPE_MCAST,
#endif /* PCN_SUPPORT_MULTICAST */
    PCN_KMSG_TYPE_PROC_SRV_CLONE_REQUEST,
    PCN_KMSG_TYPE_PROC_SRV_CREATE_PROCESS_PAIRING,
    PCN_KMSG_TYPE_PROC_SRV_EXIT_PROCESS,
    PCN_KMSG_TYPE_PROC_SRV_EXIT_GROUP,
    PCN_KMSG_TYPE_PROC_SRV_EXIT_SHADOW,
    PCN_KMSG_TYPE_PROC_SRV_VMA_TRANSFER,
    PCN_KMSG_TYPE_PROC_SRV_PTE_TRANSFER,
    PCN_KMSG_TYPE_PROC_SRV_MAPPING_REQUEST,
    PCN_KMSG_TYPE_PROC_SRV_MAPPING_RESPONSE,
    PCN_KMSG_TYPE_PROC_SRV_INVALID_DATA,
    PCN_KMSG_TYPE_PROC_SRV_ACK_DATA,
    PCN_KMSG_TYPE_PROC_SRV_THREAD_COUNT_REQUEST,
    PCN_KMSG_TYPE_PROC_SRV_THREAD_COUNT_RESPONSE,
    PCN_KMSG_TYPE_PROC_SRV_THREAD_GROUP_EXITED_NOTIFICATION,
	PCN_KMSG_TYPE_PROC_SRV_MAPPING_RESPONSE_NONPRESENT,
	PCN_KMSG_TYPE_PROC_SRV_MPROTECT_RESPONSE,
	PCN_KMSG_TYPE_PROC_SRV_MPROTECT_REQUEST,
	PCN_KMSG_TYPE_PROC_SRV_MUNMAP_REQUEST,
	PCN_KMSG_TYPE_PROC_SRV_MUNMAP_RESPONSE,
    PCN_KMSG_TYPE_PROC_SRV_BACK_MIGRATION,
    PCN_KMSG_TYPE_PROC_SRV_LAMPORT_BARRIER_REQUEST,
    PCN_KMSG_TYPE_PROC_SRV_LAMPORT_BARRIER_REQUEST_RANGE,
    PCN_KMSG_TYPE_PROC_SRV_LAMPORT_BARRIER_RESPONSE,
    PCN_KMSG_TYPE_PROC_SRV_LAMPORT_BARRIER_RESPONSE_RANGE,
    PCN_KMSG_TYPE_PROC_SRV_LAMPORT_BARRIER_RELEASE,
    PCN_KMSG_TYPE_PROC_SRV_LAMPORT_BARRIER_RELEASE_RANGE,
    PCN_KMSG_TYPE_PROC_SRV_GET_COUNTER_PHYS_REQUEST,
    PCN_KMSG_TYPE_PROC_SRV_GET_COUNTER_PHYS_RESPONSE,
    PCN_KMSG_TYPE_PROC_SRV_STATS_CLEAR,
    PCN_KMSG_TYPE_PROC_SRV_STATS_QUERY,
    PCN_KMSG_TYPE_PROC_SRV_STATS_RESPONSE,
	PCN_KMSG_TYPE_FT_SECONDARY_REPLICA_REQUEST,
	PCN_KMSG_TYPE_FT_SECONDARY_REPLICA_ANSWER,
	PCN_KMSG_TYPE_FT_PRIMARY_REPLICA_ANSWER,
	PCN_KMSG_TYPE_FT_TX_NOTIFY,
	PCN_KMSG_TYPE_FT_RX_COPY,
	PCN_KMSG_TYPE_FT_TCP_INIT_PARAM,
	PCN_KMSG_TYPE_FT_RELEASE_FILTER,
	PCN_KMSG_TYPE_FT_RELEASE_FILTER_PRIMARY,
	PCN_KMSG_TYPE_FT_SYSCALL_INFO,
	PCN_KMSG_TYPE_FT_TICKBUMP_INFO,
	PCN_KMSG_TYPE_FT_REPSYNC_INFO,
	PCN_KMSG_TYPE_FT_UTS_SYNC,
	PCN_KMGS_TYPE_FT_CRASH_KERNEL,
	PCN_KMSG_TYPE_PCN_PERF_START_MESSAGE,
	PCN_KMSG_TYPE_PCN_PERF_END_MESSAGE,
	PCN_KMSG_TYPE_PCN_PERF_CONTEXT_MESSAGE,
	PCN_KMSG_TYPE_PCN_PERF_ENTRY_MESSAGE,
	PCN_KMSG_TYPE_PCN_PERF_END_ACK_MESSAGE,
    PCN_KMSG_TYPE_START_TEST,
    PCN_KMSG_TYPE_REQUEST_TEST,
    PCN_KMSG_TYPE_ANSWER_TEST,
	PCN_KMSG_TYPE_MCAST_CLOSE,
	PCN_KMSG_TYPE_SHMTUN,
PCN_KMSG_TYPE_REMOTE_PROC_CPUINFO_RESPONSE,
PCN_KMSG_TYPE_REMOTE_PROC_CPUINFO_REQUEST,
	PCN_KMSG_TYPE_MAX
};
#define __PCN_KMSG_TYPE_MAX PCN_KMSG_TYPE_MAX
/*#if (__PCN_KMSG_TYPE_MAX > ((1<<8) -1))
 #error "The current messaging layer don't support that many message types"
#endif */

/* Enum for message priority. */
enum pcn_kmsg_prio {
	PCN_KMSG_PRIO_HIGH,
	PCN_KMSG_PRIO_NORMAL
};

#define __READY_SIZE 1
#define LG_SEQNUM_SIZE  (16 - __READY_SIZE)

/* Message header */
struct pcn_kmsg_hdr {
	unsigned int from_cpu	:8; // b0
	
	enum pcn_kmsg_type type	:8; // b1
	
	enum pcn_kmsg_prio prio	:5; // b2
	unsigned int is_lg_msg  :1;
	unsigned int lg_start   :1;
	unsigned int lg_end     :1;

	unsigned long long_number; // b3 .. b10
	
	unsigned int lg_seqnum 	:LG_SEQNUM_SIZE; // b11 .. b12
	unsigned int __ready	:__READY_SIZE;
}__attribute__((packed));
/*#if (((sizeof(struct pcn_kmsg_hdr)*8) - 24 - sizeof(unsigned long) - __READY_SIZE) != LG_SEQNUM_SIZE)
 #error "LG_SEQNUM_SIZE is not correctly sized"
#endif */

//#if ( &((struct pcn_kmsg_hdr*)0)->ready != 12 )
/*#if ( sizeof(struct pcn_kmsg_hdr) != 12 )
 #error "pcn_kmsg_hdr is not 12 bytes"
#endif */

// TODO cache size can be retrieved by the compiler, put it here
// I do not know how it is possible that cache line is 128
//#define CACHE_LINE_SIZE 64
#define CACHE_LINE_SIZE 128
//#define PCN_KMSG_PAYLOAD_SIZE 60
#define PCN_KMSG_PAYLOAD_SIZE (CACHE_LINE_SIZE - sizeof(struct pcn_kmsg_hdr))

#define MAX_CHUNKS ((1 << LG_SEQNUM_SIZE) -1)
#define PCN_KMSG_LONG_PAYLOAD_SIZE (MAX_CHUNKS * PCN_KMSG_PAYLOAD_SIZE)

/* The actual messages.  The expectation is that developers will create their
   own message structs with the payload replaced with their own fields, and then
   cast them to a struct pcn_kmsg_message.  See the checkin message below for
   an example of how to do this. */

/* Struct for the actual messages.  Note that hdr and payload are flipped
   when this actually goes out, so the receiver can poll on the ready bit
   in the header. */
struct pcn_kmsg_message {
	struct pcn_kmsg_hdr hdr;
	unsigned char payload[PCN_KMSG_PAYLOAD_SIZE];
}__attribute__((packed)) __attribute__((aligned(CACHE_LINE_SIZE)));
/*#if (sizeof(struct pcn_kmsg_message) % CACHE_LINE_SIZE != 0)
 #error "pcn_kmsg_message is not a multiple of cacheline size"
#endif */

struct pcn_kmsg_reverse_message {
	unsigned char payload[PCN_KMSG_PAYLOAD_SIZE];
	struct pcn_kmsg_hdr hdr;
	volatile unsigned long last_ticket;
	volatile unsigned char ready;
}__attribute__((packed)) __attribute__((aligned(CACHE_LINE_SIZE)));
/*#if (sizeof(struct pcn_kmsg_reverse_message) % CACHE_LINE_SIZE != 0)
 #error "pcn_kmsg_message is not a multiple of cacheline size"
#endif */

/* Struct for sending long messages (>60 bytes payload) */
struct pcn_kmsg_long_message {
	struct pcn_kmsg_hdr hdr;
	unsigned char payload[PCN_KMSG_LONG_PAYLOAD_SIZE];
}__attribute__((packed));

/* List entry to copy message into and pass around in receiving kernel */
struct pcn_kmsg_container {
	struct list_head list;
	struct pcn_kmsg_message msg;
}__attribute__((packed));


/*****************************************************************************/
/* TYPES OF MESSAGES */
/*****************************************************************************/

/* Message struct for guest kernels to check in with each other. */
struct pcn_kmsg_checkin_message {
	struct pcn_kmsg_hdr hdr;
	unsigned long window_phys_addr;
	unsigned char cpu_to_add;
	struct cpumask _cpumask;
#define CHECKIN_PADDING (sizeof(struct pcn_kmsg_hdr) + sizeof(unsigned long) + sizeof(unsigned char) + sizeof(struct cpumask))
	char pad[(CACHE_LINE_SIZE - CHECKIN_PADDING)];
}__attribute__((packed)) __attribute__((aligned(CACHE_LINE_SIZE)));

struct pcn_kmsg_keepalive_message {
	struct pcn_kmsg_hdr hdr;
	unsigned long sequence_num;
	unsigned char sender ;
#define KEEPALIVE_PADDING (sizeof(struct pcn_kmsg_hdr) + sizeof(unsigned long) + sizeof(unsigned char))
	char pad[(CACHE_LINE_SIZE - KEEPALIVE_PADDING)];
}__attribute__((packed)) __attribute__((aligned(CACHE_LINE_SIZE)));


/* RING BUFFER */

#define RB_SHIFT 13
#define RB_SIZE (1 << RB_SHIFT)
#define RB_MASK ((1 << RB_SHIFT) - 1)
#if (RB_SHIFT > LG_SEQNUM_SIZE)
#warning "there are more buffers than chuncks"
#elif (RB_SHIFT > LG_SEQNUM_SIZE)
#warning "there are more chuncks than buffer"
#endif

/* WINDOW / BUFFERING */

#define PCN_KMSG_RBUF_SIZE (RB_SIZE)

struct pcn_kmsg_window {
	volatile unsigned long head;
	volatile unsigned long tail;
	volatile unsigned char int_enabled;
	volatile struct pcn_kmsg_reverse_message buffer[PCN_KMSG_RBUF_SIZE];
	volatile int second_buffer[PCN_KMSG_RBUF_SIZE];
}__attribute__((packed));

/* Typedef for function pointer to callback functions */
typedef int (*pcn_kmsg_cbftn)(struct pcn_kmsg_message *);

/* FUNCTIONS */

/* SETUP */

/* Register a callback function to handle a new message type.  Intended to
   be called when a kernel module is loaded. */
int pcn_kmsg_register_callback(enum pcn_kmsg_type type, 
			       pcn_kmsg_cbftn callback);

/* Unregister a callback function for a message type.  Intended to
   be called when a kernel module is unloaded. */
int pcn_kmsg_unregister_callback(enum pcn_kmsg_type type);

void pcn_kmsg_exit(void);
/* MESSAGING */

/* Send a message to the specified destination CPU. */
int pcn_kmsg_send(unsigned int dest_cpu, struct pcn_kmsg_message *msg);

/* Send a long message to the specified destination CPU. */
int pcn_kmsg_send_long(unsigned int dest_cpu, 
		       struct pcn_kmsg_long_message *lmsg, 
		       unsigned int payload_size);

int pcn_kmsg_send_long_timeout(unsigned int dest_cpu,
                       struct pcn_kmsg_long_message *lmsg,
                       unsigned int payload_size, long * timeout);
/* Free a received message (called at the end of the callback function) */
inline void pcn_kmsg_free_msg(void *msg);

/* MULTICAST GROUPS */

/* Enum for mcast message type. */
enum pcn_kmsg_mcast_type {
	PCN_KMSG_MCAST_OPEN,
	PCN_KMSG_MCAST_ADD_MEMBERS,
	PCN_KMSG_MCAST_DEL_MEMBERS,
	PCN_KMSG_MCAST_CLOSE,
	PCN_KMSG_MCAST_MAX
};

/* Message struct for guest kernels to check in with each other. */
struct pcn_kmsg_mcast_message {
	struct pcn_kmsg_hdr hdr;
	enum pcn_kmsg_mcast_type type :32; 
	pcn_kmsg_mcast_id id;	
	unsigned long mask;
	unsigned int num_members;
	unsigned long window_phys_addr;
	char pad[28];
}__attribute__((packed)) __attribute__((aligned(CACHE_LINE_SIZE)));

struct pcn_kmsg_mcast_window {
	volatile unsigned long head;
	volatile unsigned long tail;
	atomic_t read_counter[PCN_KMSG_RBUF_SIZE];
	volatile struct pcn_kmsg_reverse_message buffer[PCN_KMSG_RBUF_SIZE];
}__attribute__((packed));

struct pcn_kmsg_mcast_local {
	struct pcn_kmsg_mcast_window * mcastvirt;
	unsigned long local_tail;
};

/* Open a multicast group containing the CPUs specified in the mask. */
int pcn_kmsg_mcast_open(pcn_kmsg_mcast_id *id, unsigned long mask);

/* Add new members to a multicast group. */
int pcn_kmsg_mcast_add_members(pcn_kmsg_mcast_id id, unsigned long mask);

/* Remove existing members from a multicast group. */
int pcn_kmsg_mcast_delete_members(pcn_kmsg_mcast_id id, unsigned long mask);

/* Close a multicast group. */
int pcn_kmsg_mcast_close(pcn_kmsg_mcast_id id);

/* Send a message to the specified multicast group. */
int pcn_kmsg_mcast_send(pcn_kmsg_mcast_id id, struct pcn_kmsg_message *msg);

/* Send a long message to the specified multicast group. */
int pcn_kmsg_mcast_send_long(pcn_kmsg_mcast_id id, 
			     struct pcn_kmsg_long_message *msg,
			     unsigned int payload_size);

#endif /* __LINUX_PCN_KMSG_H */
