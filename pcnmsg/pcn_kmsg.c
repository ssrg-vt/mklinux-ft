/*
 * Inter-kernel messaging support for Popcorn
 *
 * (C) Ben Shelton <beshelto@vt.edu> 2013
 */

#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/smp.h>
#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/multikernel.h>
#include <linux/pcn_kmsg.h>
#include <linux/list.h>
#include <linux/slab.h>

#include <asm/system.h>
#include <asm/apic.h>
#include <asm/hardirq.h>
#include <asm/setup.h>
#include <asm/bootparam.h>
#include <asm/errno.h>
#include <asm/atomic.h>

#define KMSG_VERBOSE 1

#ifdef KMSG_VERBOSE
#define KMSG_PRINTK(fmt, args...) printk("%s: " fmt, __func__, ##args)
#else
#define KMSG_PRINTK(...) ;
#endif


#define MCAST_VERBOSE 1

#ifdef MCAST_VERBOSE
#define MCAST_PRINTK(fmt, args...) printk("%s: " fmt, __func__, ##args)
#else
#define MCAST_PRINTK(...) ;
#endif

#define KMSG_INIT(fmt, args...) printk("KMSG INIT: %s: " fmt, __func__, ##args)

#define KMSG_ERR(fmt, args...) printk("%s: ERROR: " fmt, __func__, ##args)

/* COMMON STATE */

/* table of callback functions for handling each message type */
pcn_kmsg_cbftn callback_table[PCN_KMSG_TYPE_MAX];

/* number of current kernel */
int my_cpu = 0;

/* pointer to table with phys addresses for remote kernels' windows,
 * owned by kernel 0 */
struct pcn_kmsg_rkinfo *rkinfo;

/* table with virtual (mapped) addresses for remote kernels' windows,
   one per kernel */
struct pcn_kmsg_window * rkvirt[POPCORN_MAX_CPUS];

/* Same thing, but for mcast windows */
struct pcn_kmsg_mcast_local mcastlocal[POPCORN_MAX_MCAST_CHANNELS];

/* lists of messages to be processed for each prio */
struct list_head msglist_hiprio, msglist_normprio;

/* array to hold pointers to large messages received */
struct pcn_kmsg_long_message * lg_buf[POPCORN_MAX_CPUS];

/* action for bottom half */
static void pcn_kmsg_action(struct softirq_action *h);

/* workqueue for operations that can sleep */
struct workqueue_struct *kmsg_wq;

/* RING BUFFER */

#define RB_SHIFT 6
#define RB_SIZE (1 << RB_SHIFT)
#define RB_MASK ((1 << RB_SHIFT) - 1)

/* From Wikipedia page "Fetch and add", modified to work for u64 */
static inline unsigned long fetch_and_add(volatile unsigned long * variable, 
					  unsigned long value)
{
	asm volatile( 
		     "lock; xaddq %%rax, %2;"
		     :"=a" (value)                   //Output
		     : "a" (value), "m" (*variable)  //Input
		     :"memory" );
	return value;
}

static inline unsigned long win_inuse(struct pcn_kmsg_window *win) 
{
	return win->head - win->tail;
}

static inline int win_put(struct pcn_kmsg_window *win, 
			  struct pcn_kmsg_message *msg) 
{
	unsigned long ticket;

	/* if the queue is already really long, return EAGAIN */
	if (win_inuse(win) >= RB_SIZE) {
		KMSG_PRINTK("window full, caller should try again...\n");
		return -EAGAIN;
	}

	/* grab ticket */
	ticket = fetch_and_add(&win->head, 1);
	KMSG_PRINTK("ticket = %lu, head = %lu, tail = %lu\n", 
		    ticket, win->head, win->tail);

	/* spin until there's a spot free for me */
	while (win_inuse(win) >= RB_SIZE) {}

	/* insert item */
	memcpy(&win->buffer[ticket & RB_MASK], msg, 
	       sizeof(struct pcn_kmsg_message));

	pcn_barrier();

	/* set completed flag */
	win->buffer[ticket & RB_MASK].hdr.ready = 1;

	return 0;
}

static inline int win_get(struct pcn_kmsg_window *win, 
			  struct pcn_kmsg_message **msg) 
{
	struct pcn_kmsg_message *rcvd;

	if (!win_inuse(win)) {
		KMSG_PRINTK("nothing in buffer, returning...\n");
		return -1;
	}

	KMSG_PRINTK("reached win_get, head %lu, tail %lu\n", 
		    win->head, win->tail);	

	/* spin until entry.ready at end of cache line is set */
	rcvd = &(win->buffer[win->tail & RB_MASK]);
	//KMSG_PRINTK("%s: Ready bit: %u\n", __func__, rcvd->hdr.ready);
	while (!rcvd->hdr.ready) {
		pcn_cpu_relax();
	}

	// barrier here?
	pcn_barrier();

	rcvd->hdr.ready = 0;

	*msg = rcvd;	

	return 0;
}

static inline void win_advance_tail(struct pcn_kmsg_window *win) 
{
	win->tail++;
}

#define MCASTWIN(_id_) (mcastlocal[(_id_)].mcastvirt)
#define LOCAL_TAIL(_id_) (mcastlocal[(_id_)].local_tail)

/* MULTICAST RING BUFFER */
static inline unsigned long mcastwin_inuse(pcn_kmsg_mcast_id id)
{
	return MCASTWIN(id)->head - MCASTWIN(id)->tail;
}

static inline int mcastwin_put(pcn_kmsg_mcast_id id,
			       struct pcn_kmsg_message *msg)
{
	unsigned long ticket;

	MCAST_PRINTK("called for id %lu, msg 0x%p\n", id, msg);

	/* if the queue is already really long, return EAGAIN */
	if (mcastwin_inuse(id) >= RB_SIZE) {
		MCAST_PRINTK("window full, caller should try again...\n");
		return -EAGAIN;
	}

	/* grab ticket */
	ticket = fetch_and_add(&MCASTWIN(id)->head, 1);
	MCAST_PRINTK("ticket = %lu, head = %lu, tail = %lu\n",
		     ticket, MCASTWIN(id)->head, MCASTWIN(id)->tail);

	/* spin until there's a spot free for me */
	while (mcastwin_inuse(id) >= RB_SIZE) {}

	/* insert item */
	memcpy(&MCASTWIN(id)->buffer[ticket & RB_MASK], msg,
	       sizeof(struct pcn_kmsg_message));

	/* set counter to (# in group - self) */
	MCASTWIN(id)->read_counter[ticket & RB_MASK] = 
		rkinfo->mcast_wininfo[id].num_members - 1;

	MCAST_PRINTK("set counter to %d\n", 
		     rkinfo->mcast_wininfo[id].num_members - 1);

	pcn_barrier();

	/* set completed flag */
	MCASTWIN(id)->buffer[ticket & RB_MASK].hdr.ready = 1;

	return 0;
}

static inline int mcastwin_get(pcn_kmsg_mcast_id id,
			       struct pcn_kmsg_message **msg)
{
	struct pcn_kmsg_message *rcvd;

	MCAST_PRINTK("called for id %lu, head %lu, tail %lu, local_tail %lu\n", 
		     id, MCASTWIN(id)->head, MCASTWIN(id)->tail, 
		     LOCAL_TAIL(id));

retry:

	/* if we sent a bunch of messages, it's possible our local_tail
	   has gotten behind the global tail and we need to update it */
	/* TODO -- atomicity concerns here? */
	if (LOCAL_TAIL(id) < MCASTWIN(id)->tail) {
		LOCAL_TAIL(id) = MCASTWIN(id)->tail;
	}

	if (MCASTWIN(id)->head == LOCAL_TAIL(id)) {
		MCAST_PRINTK("nothing in buffer, returning...\n");
		return -1;
	}

	/* spin until entry.ready at end of cache line is set */
	rcvd = &(MCASTWIN(id)->buffer[LOCAL_TAIL(id) & RB_MASK]);
	while (!rcvd->hdr.ready) {
		pcn_cpu_relax();
	}

	// barrier here?
	pcn_barrier();

	/* we can't step on our own messages! */
	if (rcvd->hdr.from_cpu == my_cpu) {
		LOCAL_TAIL(id)++;
		goto retry;
	}

	*msg = rcvd;

	return 0;
}

static inline void mcastwin_advance_tail(pcn_kmsg_mcast_id id)
{
	unsigned long slot = LOCAL_TAIL(id) & RB_MASK;

	MCAST_PRINTK("local tail currently on slot %lu\n", 
		     LOCAL_TAIL(id));

	if (atomic_dec_and_test((atomic_t *) &MCASTWIN(id)->read_counter[slot])) {
		MCAST_PRINTK("we're the last reader to go; ++ global tail\n");
		MCASTWIN(id)->buffer[LOCAL_TAIL(id) & RB_MASK].hdr.ready = 0;
		atomic64_inc((atomic64_t *) &MCASTWIN(id)->tail);
	}

	LOCAL_TAIL(id)++;
}

/* INITIALIZATION */

static int pcn_kmsg_mcast_callback(struct pcn_kmsg_message *message);

static void map_msg_win(pcn_kmsg_work_t *w)
{
	int cpu = w->cpu_to_add;

	if (cpu < 0 || cpu >= POPCORN_MAX_CPUS) {
		KMSG_ERR("invalid CPU %d specified!\n", cpu);
		return;
	}

	rkvirt[cpu] = ioremap_cache(rkinfo->phys_addr[cpu],
				    sizeof(struct pcn_kmsg_window));
	if (rkvirt[cpu]) {
		KMSG_INIT("ioremapped window, virt addr 0x%p\n", 
			  rkvirt[cpu]);
	} else {
		KMSG_ERR("failed to map CPU %d's window at phys addr 0x%lx\n",
			 cpu, rkinfo->phys_addr[cpu]);
	}
}

static void map_mcast_win(pcn_kmsg_work_t *w)
{
	pcn_kmsg_mcast_id id = w->id_to_join;

	/* map window */
	if (id < 0 || id > POPCORN_MAX_MCAST_CHANNELS) {
		KMSG_ERR("%s: invalid mcast channel id %lu specified!\n",
			 __func__, id);
		return;
	}

	MCASTWIN(id) = ioremap_cache(rkinfo->mcast_wininfo[id].phys_addr,
				     sizeof(struct pcn_kmsg_mcast_window));
	if (MCASTWIN(id)) {
		MCAST_PRINTK("ioremapped mcast window, virt addr 0x%p\n",
			     MCASTWIN(id));
	} else {
		KMSG_ERR("Failed to map mcast window %lu at phys addr 0x%lx\n",
			 id, rkinfo->mcast_wininfo[id].phys_addr);
	}
}

/* bottom half for workqueue */
static void process_kmsg_wq_item(struct work_struct * work)
{
	pcn_kmsg_work_t *w = (pcn_kmsg_work_t *) work;

	KMSG_PRINTK("called with op %d\n", w->op);

	switch (w->op) {
		case PCN_KMSG_WQ_OP_MAP_MSG_WIN:
			map_msg_win(w);
			break;

		case PCN_KMSG_WQ_OP_UNMAP_MSG_WIN:
			KMSG_ERR("%s: UNMAP_MSG_WIN not yet implemented!\n",
				 __func__);
			break;

		case PCN_KMSG_WQ_OP_MAP_MCAST_WIN:
			map_mcast_win(w);
			break;

		case PCN_KMSG_WQ_OP_UNMAP_MCAST_WIN:
			KMSG_ERR("UNMAP_MCAST_WIN not yet implemented!\n");
			break;

		default:
			KMSG_ERR("Invalid work queue operation %d\n", w->op);

	}

	kfree(work);
}

static int pcn_kmsg_checkin_callback(struct pcn_kmsg_message *message) 
{
	struct pcn_kmsg_checkin_message *msg = 
		(struct pcn_kmsg_checkin_message *) message;
	int from_cpu = msg->hdr.from_cpu;
	pcn_kmsg_work_t *kmsg_work = NULL;

	KMSG_INIT("From CPU %d, type %d, window phys addr 0x%lx\n", 
		  msg->hdr.from_cpu, msg->hdr.type, 
		  msg->window_phys_addr);

	if (from_cpu >= POPCORN_MAX_CPUS) {
		KMSG_ERR("Invalid source CPU %d\n", msg->hdr.from_cpu);
		return -1;
	}

	if (!msg->window_phys_addr) {
		KMSG_ERR("Window physical address from CPU %d is NULL!\n", 
			 from_cpu);
		return -1;
	}

	/* Note that we're not allowed to ioremap anything from a bottom half,
	   so we'll add it to a workqueue and do it in a kernel thread. */
	kmsg_work = kmalloc(sizeof(pcn_kmsg_work_t), GFP_ATOMIC);
	if (likely(kmsg_work)) {
		INIT_WORK((struct work_struct *) kmsg_work, 
			  process_kmsg_wq_item);
		kmsg_work->op = PCN_KMSG_WQ_OP_MAP_MSG_WIN;
		kmsg_work->from_cpu = msg->hdr.from_cpu;
		kmsg_work->cpu_to_add = msg->cpu_to_add;
		queue_work(kmsg_wq, (struct work_struct *) kmsg_work);
	} else {
		KMSG_ERR("Failed to malloc work structure!\n");
	}

	kfree(message);

	return 0;
}

static int pcn_kmsg_test_callback(struct pcn_kmsg_message *message)
{
	struct pcn_kmsg_long_message *lmsg = 
		(struct pcn_kmsg_long_message *) message;

	printk("Received test long message, payload: %s\n", 
	       (char *) &lmsg->payload);

	return 0;
}

static inline int pcn_kmsg_window_init(struct pcn_kmsg_window *window)
{
	window->head = 0;
	window->tail = 0;
	memset(&window->buffer, 0, 
	       PCN_KMSG_RBUF_SIZE * sizeof(struct pcn_kmsg_message));
	return 0;
}

static inline int pcn_kmsg_mcast_window_init(struct pcn_kmsg_mcast_window *win)
{
	win->head = 0;
	win->tail = 0;
	memset(&win->read_counter, 0, 
	       PCN_KMSG_RBUF_SIZE * sizeof(int));
	memset(&win->buffer, 0,
	       PCN_KMSG_RBUF_SIZE * sizeof(struct pcn_kmsg_message));
	return 0;
}

extern unsigned long orig_boot_params;

static int send_checkin_msg(unsigned int cpu_to_add, unsigned int to_cpu)
{
	int rc;
	struct pcn_kmsg_checkin_message msg;

	msg.hdr.type = PCN_KMSG_TYPE_CHECKIN;
	msg.hdr.prio = PCN_KMSG_PRIO_HIGH;
	msg.window_phys_addr = rkinfo->phys_addr[my_cpu];
	msg.cpu_to_add = cpu_to_add;

	rc = pcn_kmsg_send(to_cpu, (struct pcn_kmsg_message *) &msg);

	if (rc) {
		KMSG_ERR("Failed to send checkin message, rc = %d\n", rc);
		return rc;
	}

	return 0;
}

static int do_checkin(void)
{
	int rc = 0;
	int i;

	for (i = 0; i < POPCORN_MAX_CPUS; i++) {
		if (i == my_cpu) {
			continue;
		}

		if (rkinfo->phys_addr[i]) {
			rkvirt[i] = ioremap_cache(rkinfo->phys_addr[i],
						  sizeof(struct pcn_kmsg_rkinfo));
			if (rkvirt[i]) {
				KMSG_INIT("ioremapped CPU %d's window, virt addr 0x%p\n", 
					  i, rkvirt[i]);
			} else {
				KMSG_ERR("Failed to ioremap CPU %d's window at phys addr 0x%lx\n",
					 i, rkinfo->phys_addr[i]);
				return -1;
			}

			KMSG_INIT("Sending checkin message to kernel %d\n", i);			
			rc = send_checkin_msg(my_cpu, i);
			if (rc) {
				KMSG_ERR("POPCORN: Checkin failed for CPU %d!\n", i);
				return rc;
			}
		}
	}

	return rc;
}

static int __init pcn_kmsg_init(void)
{
	int rc;
	unsigned long win_virt_addr, win_phys_addr, rkinfo_phys_addr;
	struct boot_params * boot_params_va;

	KMSG_INIT("entered\n");

	my_cpu = raw_smp_processor_id();

	/* Initialize list heads */
	INIT_LIST_HEAD(&msglist_hiprio);
	INIT_LIST_HEAD(&msglist_normprio);

	/* Clear out large-message receive buffers */
	memset(&lg_buf, 0, POPCORN_MAX_CPUS * sizeof(unsigned char *));

	/* Clear callback table and register default callback functions */
	KMSG_INIT("Registering initial callbacks...\n");
	memset(&callback_table, 0, PCN_KMSG_TYPE_MAX * sizeof(pcn_kmsg_cbftn));
	rc = pcn_kmsg_register_callback(PCN_KMSG_TYPE_CHECKIN, 
					&pcn_kmsg_checkin_callback);
	if (rc) {
		KMSG_ERR("Failed to register initial kmsg checkin callback!\n");
	}

	rc = pcn_kmsg_register_callback(PCN_KMSG_TYPE_MCAST, 
					&pcn_kmsg_mcast_callback);
	if (rc) {
		KMSG_ERR("Failed to register initial kmsg mcast callback!\n");
	}

	rc = pcn_kmsg_register_callback(PCN_KMSG_TYPE_TEST, 
					&pcn_kmsg_test_callback);
	if (rc) {
		KMSG_ERR("Failed to register initial kmsg test callback!\n");
	}

	/* Register softirq handler */
	KMSG_INIT("Registering softirq handler...\n");
	open_softirq(PCN_KMSG_SOFTIRQ, pcn_kmsg_action);

	/* Initialize work queue */
	KMSG_INIT("Initializing workqueue...\n");
	kmsg_wq = create_workqueue("kmsg_wq");

	/* If we're the master kernel, malloc and map the rkinfo structure and 
	   put its physical address in boot_params; otherwise, get it from the 
	   boot_params and map it */
	if (!mklinux_boot) {
		KMSG_INIT("We're the master; mallocing rkinfo...\n");
		rkinfo = kmalloc(sizeof(struct pcn_kmsg_rkinfo), GFP_KERNEL);

		if (!rkinfo) {
			KMSG_ERR("Failed to malloc rkinfo structure!\n");
			return -1;
		}

		rkinfo_phys_addr = virt_to_phys(rkinfo);

		KMSG_INIT("rkinfo virt addr 0x%p, phys addr 0x%lx\n", 
			  rkinfo, rkinfo_phys_addr);

		memset(rkinfo, 0x0, sizeof(struct pcn_kmsg_rkinfo));

		KMSG_INIT("Setting boot_params...\n");
		/* Otherwise, we need to set the boot_params to show the rest
		   of the kernels where the master kernel's messaging window 
		   is. */
		boot_params_va = (struct boot_params *) 
			(0xffffffff80000000 + orig_boot_params);
		KMSG_INIT("Boot params virt addr: 0x%p\n", boot_params_va);
		boot_params_va->pcn_kmsg_master_window = rkinfo_phys_addr;
	} else {
		KMSG_INIT("Master kernel rkinfo phys addr: 0x%lx\n", 
			  (unsigned long) boot_params.pcn_kmsg_master_window);

		rkinfo_phys_addr = boot_params.pcn_kmsg_master_window;
		rkinfo = ioremap_cache(rkinfo_phys_addr, 
				       sizeof(struct pcn_kmsg_rkinfo));

		if (!rkinfo) {
			KMSG_ERR("Failed to map rkinfo from master kernel!\n");
		}

		KMSG_INIT("rkinfo virt addr: 0x%p\n", rkinfo);
	}

	/* Malloc our own receive buffer and set it up */
	win_virt_addr = __get_free_pages(GFP_KERNEL, 2);
	KMSG_INIT("Allocated 4 pages for my window, virt addr 0x%lx\n", 
		  win_virt_addr);
	rkvirt[my_cpu] = (struct pcn_kmsg_window *) win_virt_addr;
	win_phys_addr = virt_to_phys((void *) win_virt_addr);
	KMSG_INIT("Physical address: 0x%lx\n", win_phys_addr);
	rkinfo->phys_addr[my_cpu] = win_phys_addr;

	rc = pcn_kmsg_window_init(rkvirt[my_cpu]);
	if (rc) {
		KMSG_ERR("Failed to initialize kmsg recv window!\n");
	}

	/* If we're not the master kernel, we need to check in */
	if (mklinux_boot) {
		rc = do_checkin();

		if (rc) { 
			KMSG_ERR("Failed to check in!\n");
			return -1;
		}
	} 

	return 0;
}

subsys_initcall(pcn_kmsg_init);

/* Register a callback function when a kernel module is loaded */
int pcn_kmsg_register_callback(enum pcn_kmsg_type type, pcn_kmsg_cbftn callback)
{
	if (type >= PCN_KMSG_TYPE_MAX) {
		KMSG_ERR("Attempted to register callback with bad type %d\n", 
			 type);
		return -1;
	}

	callback_table[type] = callback;

	return 0;
}

/* Unregister a callback function when a kernel module is unloaded */
int pcn_kmsg_unregister_callback(enum pcn_kmsg_type type)
{
	if (type >= PCN_KMSG_TYPE_MAX) {
		KMSG_ERR("Attempted to register callback with bad type %d\n", 
			 type);
		return -1;
	}

	callback_table[type] = NULL;

	return 0;
}

/* SENDING / MARSHALING */

static int __pcn_kmsg_send(unsigned int dest_cpu, struct pcn_kmsg_message *msg)
{
	int rc;
	struct pcn_kmsg_window *dest_window;

	if (unlikely(dest_cpu >= POPCORN_MAX_CPUS)) {
		KMSG_ERR("Invalid destination CPU %d\n", dest_cpu);
		return -1;
	}

	dest_window = rkvirt[dest_cpu];

	if (unlikely(!rkvirt[dest_cpu])) {
		KMSG_ERR("Dest win for CPU %d not mapped!\n", dest_cpu);
		return -1;
	}

	if (unlikely(!msg)) {
		KMSG_ERR("Passed in a null pointer to msg!\n");
		return -1;
	}

	/* set source CPU */
	msg->hdr.from_cpu = my_cpu;

	/* place message in rbuf */
	rc = win_put(dest_window, msg);		

	if (rc) {
		KMSG_ERR("Failed to place message in destination window -- maybe it's full?\n");
		return -1;
	}

	/* send IPI */
	apic->send_IPI_mask(cpumask_of(dest_cpu), POPCORN_KMSG_VECTOR);

	return 0;
}

int pcn_kmsg_send(unsigned int dest_cpu, struct pcn_kmsg_message *msg)
{
	msg->hdr.is_lg_msg = 0;
	msg->hdr.lg_start = 0;
	msg->hdr.lg_end = 0;
	msg->hdr.lg_seqnum = 0;

	return __pcn_kmsg_send(dest_cpu, msg);
}

int pcn_kmsg_send_long(unsigned int dest_cpu, 
		       struct pcn_kmsg_long_message *lmsg, 
		       unsigned int payload_size)
{
	int i;
	int num_chunks = payload_size / PCN_KMSG_PAYLOAD_SIZE;
	struct pcn_kmsg_message this_chunk;
	//char test_buf[15];

	if (payload_size % PCN_KMSG_PAYLOAD_SIZE) {
		num_chunks++;
	}

	KMSG_PRINTK("Sending large message to CPU %d, type %d, payload size %d bytes, %d chunks\n", 
		    dest_cpu, lmsg->hdr.type, payload_size, num_chunks);

	this_chunk.hdr.type = lmsg->hdr.type;
	this_chunk.hdr.prio = lmsg->hdr.prio;
	this_chunk.hdr.is_lg_msg = 1;

	for (i = 0; i < num_chunks; i++) {
		KMSG_PRINTK("Sending chunk %d\n", i);

		this_chunk.hdr.lg_start = (i == 0) ? 1 : 0;
		this_chunk.hdr.lg_end = (i == num_chunks - 1) ? 1 : 0;
		this_chunk.hdr.lg_seqnum = (i == 0) ? num_chunks : i;

		memcpy(&this_chunk.payload, 
		       ((unsigned char *) &lmsg->payload) + 
		       i * PCN_KMSG_PAYLOAD_SIZE, 
		       PCN_KMSG_PAYLOAD_SIZE);

		__pcn_kmsg_send(dest_cpu, &this_chunk);
	}

	return 0;
}

/* RECEIVING / UNMARSHALING */

static int process_message_list(struct list_head *head) 
{
	int rc, rc_overall = 0;
	struct pcn_kmsg_container *pos = NULL, *n = NULL;
	struct pcn_kmsg_message *msg;

	list_for_each_entry_safe(pos, n, head, list) {
		msg = &pos->msg;

		KMSG_PRINTK("Item in list, type %d,  processing it...\n", 
			    msg->hdr.type);

		list_del(&pos->list);

		if (unlikely(msg->hdr.type >= PCN_KMSG_TYPE_MAX || 
			     !callback_table[msg->hdr.type])) {
			KMSG_ERR("Invalid type %d; continuing!\n", 
				 msg->hdr.type);
			continue;
		}

		rc = callback_table[msg->hdr.type](msg);
		if (!rc_overall) {
			rc_overall = rc;
		}

		/* NOTE: callback function is responsible for freeing memory
		   that was kmalloced! */
	}

	return rc_overall;
}

//void pcn_kmsg_do_tasklet(unsigned long);
//DECLARE_TASKLET(pcn_kmsg_tasklet, pcn_kmsg_do_tasklet, 0);

/* top half */
void smp_popcorn_kmsg_interrupt(struct pt_regs *regs)
{
	ack_APIC_irq();

	KMSG_PRINTK("Reached Popcorn KMSG interrupt handler!\n");

	inc_irq_stat(irq_popcorn_kmsg_count);
	irq_enter();

	/* We do as little work as possible in here (decoupling notification 
	   from messaging) */

	/* schedule bottom half */
	__raise_softirq_irqoff(PCN_KMSG_SOFTIRQ);
	//tasklet_schedule(&pcn_kmsg_tasklet);

	irq_exit();
	return;
}

static int process_large_message(struct pcn_kmsg_message *msg)
{
	int rc = 0;
	int recv_buf_size;

	KMSG_PRINTK("Got a large message fragment, type %u, from_cpu %u, start %u, end %u, seqnum %u!\n",
		    msg->hdr.type, msg->hdr.from_cpu,
		    msg->hdr.lg_start, msg->hdr.lg_end,
		    msg->hdr.lg_seqnum);

	if (msg->hdr.lg_start) {
		KMSG_PRINTK("Processing initial message fragment...\n");

		recv_buf_size = sizeof(struct pcn_kmsg_hdr) + 
			msg->hdr.lg_seqnum * PCN_KMSG_PAYLOAD_SIZE;

		lg_buf[msg->hdr.from_cpu] = kmalloc(recv_buf_size, GFP_ATOMIC);

		if (!lg_buf[msg->hdr.from_cpu]) {
			KMSG_ERR("Unable to kmalloc buffer for incoming message!\n");
			goto out;
		}

		/* copy header first */
		memcpy((unsigned char *)lg_buf[msg->hdr.from_cpu], 
		       &msg->hdr, sizeof(struct pcn_kmsg_hdr));

		/* copy first chunk of message */
		memcpy((unsigned char *)lg_buf[msg->hdr.from_cpu] + 
		       sizeof(struct pcn_kmsg_hdr),
		       &msg->payload, PCN_KMSG_PAYLOAD_SIZE);

		if (msg->hdr.lg_end) {
			KMSG_PRINTK("NOTE: Long message of length 1 received; this isn't efficient!\n");
			rc = callback_table[msg->hdr.type]((struct pcn_kmsg_message *)lg_buf[msg->hdr.from_cpu]);

			if (rc) {
				KMSG_ERR("Large message callback failed!\n");
			}
		}
	} else {

		KMSG_PRINTK("Processing subsequent message fragment...\n");

		memcpy((unsigned char *)lg_buf[msg->hdr.from_cpu] + 
		       sizeof(struct pcn_kmsg_hdr) + 
		       PCN_KMSG_PAYLOAD_SIZE * msg->hdr.lg_seqnum,
		       &msg->payload, PCN_KMSG_PAYLOAD_SIZE);

		if (msg->hdr.lg_end) {
			KMSG_PRINTK("Last fragment in series...\n");

			KMSG_PRINTK("from_cpu %d, type %d, prio %d\n",
				    lg_buf[msg->hdr.from_cpu]->hdr.from_cpu,
				    lg_buf[msg->hdr.from_cpu]->hdr.type,
				    lg_buf[msg->hdr.from_cpu]->hdr.prio);


			rc = callback_table[msg->hdr.type]((struct pcn_kmsg_message *)lg_buf[msg->hdr.from_cpu]);

			if (rc) {
				KMSG_ERR("Large message callback failed!\n");
			}
		}
	}

out:

	win_advance_tail(rkvirt[my_cpu]);

	return rc;
}

static int process_small_message(struct pcn_kmsg_message *msg)
{
	int rc;
	struct pcn_kmsg_container *incoming;

	/* malloc some memory (don't sleep!) */
	incoming = kmalloc(sizeof(struct pcn_kmsg_container), GFP_ATOMIC);
	if (unlikely(!incoming)) {
		KMSG_ERR("Unable to kmalloc buffer for incoming message!\n");
		win_advance_tail(rkvirt[my_cpu]);
		return -1;
	}

	/* memcpy message from rbuf */
	memcpy(&incoming->msg, msg,
	       sizeof(struct pcn_kmsg_message));
	win_advance_tail(rkvirt[my_cpu]);

	KMSG_PRINTK("Received message, type %d, prio %d\n",
		    incoming->msg.hdr.type, incoming->msg.hdr.prio);

	/* add container to appropriate list */
	switch (incoming->msg.hdr.prio) {
		case PCN_KMSG_PRIO_HIGH:
			KMSG_PRINTK("Adding to high-priority list...\n");
			list_add_tail(&(incoming->list),
				      &msglist_hiprio);
			break;

		case PCN_KMSG_PRIO_NORMAL:
			KMSG_PRINTK("Adding to normal-priority list...\n");
			list_add_tail(&(incoming->list),
				      &msglist_normprio);
			break;

		default:
			KMSG_ERR("Priority value %d unknown!\n",
				 incoming->msg.hdr.prio);
	}

	return rc;
}

static void process_mcast_queue(pcn_kmsg_mcast_id id)
{
	struct pcn_kmsg_message *msg;
	while (!mcastwin_get(id, &msg)) {
		MCAST_PRINTK("Got an mcast message!\n");

		/* If the mcast message is a window close, handle it right away;
		   otherwise, put the message in the appropriate queue */
		if (msg->hdr.type == PCN_KMSG_TYPE_MCAST_CLOSE) {

			MCAST_PRINTK("Got mcast close message!\n");
		} else {

		}

		mcastwin_advance_tail(id);
	}

}

/* bottom half */
static void pcn_kmsg_action(struct softirq_action *h)
{
	int rc;
	struct pcn_kmsg_message *msg;
	int i;

	KMSG_PRINTK("called\n");

	/* Get messages out of the buffer first */

	while (!win_get(rkvirt[my_cpu], &msg)) {
		KMSG_PRINTK("got a message!\n");

		/* Special processing for large messages */
		if (msg->hdr.is_lg_msg) {
			KMSG_PRINTK("message is a large message!\n");
			rc = process_large_message(msg);
		} else {
			KMSG_PRINTK("message is a small message!\n");
			rc = process_small_message(msg);
		}

	}

	KMSG_PRINTK("ring buffer empty; checking mcast queues...\n");

	for (i = 0; i < POPCORN_MAX_MCAST_CHANNELS; i++) {
		if (MCASTWIN(i)) {
			KMSG_PRINTK("mcast win %d mapped, processing it\n", i);
			process_mcast_queue(i);
		}
	}

	KMSG_PRINTK("Done checking mcast queues; processing messages\n");

	/* Process high-priority queue first */
	rc = process_message_list(&msglist_hiprio);

	if (list_empty(&msglist_hiprio)) {
		KMSG_PRINTK("High-priority queue is empty!\n");
	}

	/* Then process normal-priority queue */
	rc = process_message_list(&msglist_normprio);

	return;
}

/* Syscall for testing all this stuff */
SYSCALL_DEFINE1(popcorn_test_kmsg, int, cpu)
{
	int rc = 0;
	unsigned long mask = 0xf;
	static pcn_kmsg_mcast_id test_id = -1;
	struct pcn_kmsg_test_message msg;

#if 1
	switch (cpu) {
		case 0:
			/* open */
			printk("%s: open\n", __func__);
			rc = pcn_kmsg_mcast_open(&test_id, mask);
			if (rc) {
				printk("POPCORN: pcn_kmsg_mcast_open returned %d, test_id %lu\n", 
				       rc, test_id);
			}
			break;

		case 1:
			/* send */
			printk("%s: send\n", __func__);
			msg.hdr.type = PCN_KMSG_TYPE_TEST;
			msg.hdr.prio = PCN_KMSG_PRIO_HIGH;

			rc = pcn_kmsg_mcast_send(test_id, 
						 (struct pcn_kmsg_message *) &msg);
			if (rc) {
				printk("%s: failed to send mcast message to group %lu!\n",
				       __func__, test_id);
				return -1;
			}
			break;

		case 2:
			/* close */
			printk("%s: close\n", __func__);

			rc = pcn_kmsg_mcast_close(test_id);

			printk("%s: mcast close returned %d\n", __func__, rc);

			break;

		default:
			printk("%s: invalid option %d\n", __func__, cpu);
			return -1;
	}

#else

	struct pcn_kmsg_long_message lmsg;
	char *str = "This is a very long test message.  Don't be surprised if it gets corrupted; it probably will.  If it does, you're in for a lot more work, and may not get home to see your wife this weekend.  You should knock on wood before running this test.";


	lmsg.hdr.type = PCN_KMSG_TYPE_TEST;
	lmsg.hdr.prio = PCN_KMSG_PRIO_NORMAL;

	strcpy(&lmsg.payload, str); 

	printk("Message to send: %s\n", &lmsg.payload);

	printk("POPCORN: syscall to test kernel messaging, to CPU %d\n", cpu);

	rc = pcn_kmsg_send_long(cpu, &lmsg, strlen(str) + 5);

	if (rc) {
		printk("POPCORN: error: pcn_kmsg_send_long returned %d\n", rc);
	}

#endif

	return rc;
}

/* MULTICAST */

inline void lock_chan(pcn_kmsg_mcast_id id)
{

}

inline void unlock_chan(pcn_kmsg_mcast_id id)
{

}

inline int count_members(unsigned long mask)
{
	int i, count = 0;

	for (i = 0; i < POPCORN_MAX_CPUS; i++) {
		if (mask & (1ULL << i)) {
			count++;
		}
	}

	return count;
}

void print_mcast_map(void)
{
#if MCAST_VERBOSE
	int i;

	printk("ACTIVE MCAST GROUPS:\n");

	for (i = 0; i < POPCORN_MAX_MCAST_CHANNELS; i++) {
		if (rkinfo->mcast_wininfo[i].mask) {
			printk("group %d, mask 0x%lx, num_members %d\n", 
			       i, rkinfo->mcast_wininfo[i].mask, 
			       rkinfo->mcast_wininfo[i].num_members);
		}
	}
	return;
#endif
}

/* Open a multicast group containing the CPUs specified in the mask. */
int pcn_kmsg_mcast_open(pcn_kmsg_mcast_id *id, unsigned long mask)
{
	int rc, i, found_id;
	struct pcn_kmsg_mcast_message msg;
	struct pcn_kmsg_mcast_wininfo *slot;
	struct pcn_kmsg_mcast_window * new_win;

	MCAST_PRINTK("Reached pcn_kmsg_mcast_open, mask 0x%lx\n", mask);

	if (!(mask & (1 << my_cpu))) {
		KMSG_ERR("This CPU is not a member of the mcast group to be created, cpu %d, mask 0x%lx\n",
			 my_cpu, mask);
		return -1;
	}

	/* find first unused channel */
retry:
	found_id = -1;

	for (i = 0; i < POPCORN_MAX_MCAST_CHANNELS; i++) {
		if (!rkinfo->mcast_wininfo[i].num_members) {
			found_id = i;
			break;
		}
	}

	MCAST_PRINTK("Found channel ID %d\n", found_id);

	if (found_id == -1) {
		KMSG_ERR("No free multicast channels!\n");
		return -1;
	}

	/* lock and check if channel is still unused; 
	   otherwise, try again */
	lock_chan(found_id);

	if (rkinfo->mcast_wininfo[i].num_members) {
		unlock_chan(found_id);
		MCAST_PRINTK("Got scooped; trying again...\n");
		goto retry;
	}

	/* set slot info */
	slot = &rkinfo->mcast_wininfo[found_id];
	slot->mask = mask;
	slot->num_members = count_members(mask);
	slot->owner_cpu = my_cpu;

	MCAST_PRINTK("Found %d members\n", slot->num_members);

	/* kmalloc window for slot */
	new_win = kmalloc(sizeof(struct pcn_kmsg_mcast_window), GFP_ATOMIC);

	if (!new_win) {
		KMSG_ERR("Failed to kmalloc mcast buffer!\n");
		goto out;
	}

	/* zero out window */
	memset(new_win, 0x0, sizeof(struct pcn_kmsg_mcast_window));

	MCASTWIN(found_id) = new_win;
	slot->phys_addr = virt_to_phys(new_win);
	MCAST_PRINTK("Malloced mcast receive window %d at phys addr 0x%lx\n",
		     found_id, slot->phys_addr);

	/* send message to each member except self.  Can't use mcast yet because
	   group is not yet established, so unicast to each CPU in mask. */
	msg.hdr.type = PCN_KMSG_TYPE_MCAST;
	msg.hdr.prio = PCN_KMSG_PRIO_HIGH;
	msg.type = PCN_KMSG_MCAST_OPEN;
	msg.id = found_id;
	msg.mask = mask;
	msg.num_members = slot->num_members;

	for (i = 0; i < POPCORN_MAX_CPUS; i++) {
		if ((slot->mask & (1ULL << i)) && 
		    (my_cpu != i)) {
			MCAST_PRINTK("Sending message to CPU %d\n", i);

			rc = pcn_kmsg_send(i, (struct pcn_kmsg_message *) &msg);

			if (rc) {
				KMSG_ERR("Message send failed!\n");
			}
		}
	}

	*id = found_id;

out:
	unlock_chan(found_id);

	return 0;
}

/* Add new members to a multicast group. */
int pcn_kmsg_mcast_add_members(pcn_kmsg_mcast_id id, unsigned long mask)
{
	lock_chan(id);

	KMSG_ERR("Operation not yet supported!\n");

	//rkinfo->mcast_wininfo[id].mask |= mask; 

	/* TODO -- notify new members */

	unlock_chan(id);
	return 0;
}

/* Remove existing members from a multicast group. */
int pcn_kmsg_mcast_delete_members(pcn_kmsg_mcast_id id, unsigned long mask)
{
	lock_chan(id);

	KMSG_ERR("Operation not yet supported!\n");

	//rkinfo->mcast_wininfo[id].mask &= !mask;

	/* TODO -- notify new members */

	unlock_chan(id);

	return 0;
}

inline int pcn_kmsg_mcast_close_notowner(pcn_kmsg_mcast_id id)
{
	MCAST_PRINTK("Closing multicast channel %lu on CPU %d\n", id, my_cpu);

	/* process remaining messages in queue (should there be any?) */

	/* remove queue from list of queues being polled */
	iounmap(MCASTWIN(id));

	MCASTWIN(id) = NULL;

	return 0;
}

/* Close a multicast group. */
int pcn_kmsg_mcast_close(pcn_kmsg_mcast_id id)
{
	int rc;
	struct pcn_kmsg_mcast_message msg;
	struct pcn_kmsg_mcast_wininfo *wi = &rkinfo->mcast_wininfo[id];

	if (wi->owner_cpu != my_cpu) {
		KMSG_ERR("Only creator (cpu %d) can close mcast group %lu!\n",
			 wi->owner_cpu, id);
		return -1;
	}

	lock_chan(id);

	/* set window to close */
	wi->is_closing = 1;

	/* broadcast message to close window globally */
	msg.hdr.type = PCN_KMSG_TYPE_MCAST;
	msg.hdr.prio = PCN_KMSG_PRIO_HIGH;
	msg.type = PCN_KMSG_MCAST_CLOSE;
	msg.id = id;

	rc = pcn_kmsg_mcast_send(id, (struct pcn_kmsg_message *) &msg);
	if (rc) {
		KMSG_ERR("failed to send mcast close message!\n");
		return -1;
	}

	/* wait until global_tail == global_head */
	while (MCASTWIN(id)->tail != MCASTWIN(id)->head) {}

	/* free window and set channel as unused */
	kfree(MCASTWIN(id));
	MCASTWIN(id) = NULL;

	wi->mask = 0;
	wi->num_members = 0;
	wi->is_closing = 0;

	unlock_chan(id);

	return 0;
}

static int __pcn_kmsg_mcast_send(pcn_kmsg_mcast_id id, 
				 struct pcn_kmsg_message *msg)
{
	int i, rc;

	if (!msg) {
		KMSG_ERR("Passed in a null pointer to msg!\n");
		return -1;
	}

	/* set source CPU */
	msg->hdr.from_cpu = my_cpu;

	/* place message in rbuf */
	rc = mcastwin_put(id, msg);

	if (rc) {
		KMSG_ERR("failed to place message in mcast window -- maybe it's full?\n");
		return -1;
	}

	/* send IPI to all in mask but me */

	for (i = 0; i < POPCORN_MAX_CPUS; i++) {
		if (rkinfo->mcast_wininfo[id].mask & (1ULL << i)) {
			if (i != my_cpu) {
				MCAST_PRINTK("sending IPI to CPU %d\n", i);
				apic->send_IPI_mask(cpumask_of(i), 
						    POPCORN_KMSG_VECTOR);
			}
		}
	}

	return 0;
}

#define MCAST_HACK 0

/* Send a message to the specified multicast group. */
int pcn_kmsg_mcast_send(pcn_kmsg_mcast_id id, struct pcn_kmsg_message *msg)
{
#if MCAST_HACK

	int i, rc;

	MCAST_PRINTK("Sending mcast message, id %lu\n", id);

	/* quick hack for testing for now; 
	   loop through mask and send individual messages */
	for (i = 0; i < POPCORN_MAX_CPUS; i++) {
		if (rkinfo->mcast_wininfo[id].mask & (0x1 << i)) {
			rc = pcn_kmsg_send(i, msg);

			if (rc) {
				KMSG_ERR("Batch send failed to CPU %d\n", i);
				return -1;
			}
		}
	}

	return 0;
#else
	int rc;

	MCAST_PRINTK("sending mcast message to group id %lu\n", id);

	msg->hdr.is_lg_msg = 0;
	msg->hdr.lg_start = 0;
	msg->hdr.lg_end = 0;
	msg->hdr.lg_seqnum = 0;

	rc = __pcn_kmsg_mcast_send(id, msg);

	return rc;
#endif
}

/* Send a message to the specified multicast group. */
int pcn_kmsg_mcast_send_long(pcn_kmsg_mcast_id id, 
			     struct pcn_kmsg_long_message *msg, 
			     unsigned int payload_size)
{
#if MCAST_HACK
	int i, rc;

	MCAST_PRINTK("Sending long mcast message, id %lu, size %u\n", 
		     id, payload_size);

	/* quick hack for testing for now; 
	   loop through mask and send individual messages */
	for (i = 0; i < POPCORN_MAX_CPUS; i++) {
		if (rkinfo->mcast_wininfo[id].mask & (0x1 << i)) {
			rc = pcn_kmsg_send_long(i, msg, payload_size);

			if (rc) {
				KMSG_ERR("Batch send failed to CPU %d\n", i);
				return -1;
			}
		}
	}

	return 0;
#else

	KMSG_ERR("long messages not yet supported in mcast!\n");

	return 0;
#endif
}


static int pcn_kmsg_mcast_callback(struct pcn_kmsg_message *message) 
{
	int rc = 0;
	struct pcn_kmsg_mcast_message *msg = 
		(struct pcn_kmsg_mcast_message *) message;
	pcn_kmsg_work_t *kmsg_work;

	MCAST_PRINTK("Received mcast message, type %d\n", msg->type);

	switch (msg->type) {
		case PCN_KMSG_MCAST_OPEN:
			MCAST_PRINTK("Processing mcast open message...\n");

			/* Need to queue work to remap the window in a kernel
			   thread; it can't happen here */
			kmsg_work = kmalloc(sizeof(pcn_kmsg_work_t), GFP_ATOMIC);
			if (kmsg_work) {
				INIT_WORK((struct work_struct *) kmsg_work,
					  process_kmsg_wq_item);
				kmsg_work->op = PCN_KMSG_WQ_OP_MAP_MCAST_WIN;
				kmsg_work->from_cpu = msg->hdr.from_cpu;
				kmsg_work->id_to_join = msg->id;
				queue_work(kmsg_wq, 
					   (struct work_struct *) kmsg_work);
			} else {
				KMSG_ERR("Failed to kmalloc work structure!\n");
			}

			break;

		case PCN_KMSG_MCAST_ADD_MEMBERS:
			KMSG_ERR("Mcast add not yet implemented...\n");
			break;

		case PCN_KMSG_MCAST_DEL_MEMBERS:
			KMSG_ERR("Mcast delete not yet implemented...\n");
			break;

		case PCN_KMSG_MCAST_CLOSE:
			MCAST_PRINTK("Processing mcast close message...\n");
			pcn_kmsg_mcast_close_notowner(msg->id);
			break;

		default:
			KMSG_ERR("Invalid multicast message type %d\n", 
				 msg->type);
			rc = -1;
			goto out;
	}

	print_mcast_map();

out:
	kfree(message);
	return rc;
}



