
#include <asm/system.h>
#include <asm/apic.h>
#include <asm/hardirq.h>
#include <asm/setup.h>
#include <asm/bootparam.h>
#include <asm/errno.h>
#include <asm/atomic.h>

#include <linux/delay.h>
#include <linux/pcn_kmsg.h>

#include "kmsg_core.h"
#include "atomic_x86.h"
#include "ringBuffer.h"

int who_is_writing=-1;

/*****************************************************************************/
/* WINDOWS/BUFFERING */
/*****************************************************************************/

/*static inline unsigned long win_inuse(struct pcn_kmsg_window *win)
{
	return win->head - win->tail;
}
*/
static inline void win_advance_tail(struct pcn_kmsg_window *win)
{
	win->tail++;
}

//static inline
int win_put(struct pcn_kmsg_window *win,
			  struct pcn_kmsg_message *msg,
			  int no_block)
{
	unsigned long ticket;
    	unsigned long long sleep_start;

	/* if we can't block and the queue is already really long,
	   return EAGAIN */
	if (no_block && (win_inuse(win) >= RB_SIZE)) {
		KMSG_PRINTK("window full, caller should try again...\n");
		return -EAGAIN;
	}

	/* grab ticket */ // TODO grab a bunch of tickets instead of just one
	ticket = fetch_and_add(&win->head, 1);
	if(ticket >= ULONG_MAX)
		printk("ERROR threashold ticket reached\n");

	PCN_DEBUG(KERN_ERR "%s: ticket = %lu, head = %lu, tail = %lu\n",
		 __func__, ticket, win->head, win->tail);

	KMSG_PRINTK("%s: ticket = %lu, head = %lu, tail = %lu\n",
			 __func__, ticket, win->head, win->tail);

	who_is_writing= ticket;
	/* spin until there's a spot free for me */
	//while (win_inuse(win) >= RB_SIZE) {}
	//if(ticket>=PCN_KMSG_RBUF_SIZE){
    sleep_start = native_read_tsc();
		while((win->buffer[ticket%PCN_KMSG_RBUF_SIZE].last_ticket != ticket-PCN_KMSG_RBUF_SIZE)) {
			//pcn_cpu_relax();
			//msleep(1);
		}
		while(	win->buffer[ticket%PCN_KMSG_RBUF_SIZE].ready!=0){
			//pcn_cpu_relax();
			//msleep(1);
		}
    total_sleep_win_put += native_read_tsc() - sleep_start;
    sleep_win_put_count++;
	//}
	/* insert item */
	memcpy(&win->buffer[ticket%PCN_KMSG_RBUF_SIZE].payload,
	       &msg->payload, PCN_KMSG_PAYLOAD_SIZE);

	memcpy((void*)&(win->buffer[ticket%PCN_KMSG_RBUF_SIZE].hdr),
	       (void*)&(msg->hdr), sizeof(struct pcn_kmsg_hdr));

	//log_send[log_s_index%LOGLEN]= win->buffer[ticket & RB_MASK].hdr;
	memcpy(&(log_send[log_s_index%LOGLEN]),
		(void*)&(win->buffer[ticket%PCN_KMSG_RBUF_SIZE].hdr),
		sizeof(struct pcn_kmsg_hdr));
	log_s_index++;

	win->second_buffer[ticket%PCN_KMSG_RBUF_SIZE]++;

	/* set completed flag */
	win->buffer[ticket%PCN_KMSG_RBUF_SIZE].ready = 1;
	wmb();
	win->buffer[ticket%PCN_KMSG_RBUF_SIZE].last_ticket = ticket;

	who_is_writing=-1;

msg_put++;

	return 0;
}

//static inline 
int win_get(struct pcn_kmsg_window *win,
			  struct pcn_kmsg_reverse_message **msg)
{
	struct pcn_kmsg_reverse_message *rcvd;
    unsigned long long sleep_start;

	if (!win_inuse(win)) {

		KMSG_PRINTK("nothing in buffer, returning...\n");
		return -1;
	}

	KMSG_PRINTK("reached win_get, head %lu, tail %lu\n",
		    win->head, win->tail);

	/* spin until entry.ready at end of cache line is set */
	rcvd =(struct pcn_kmsg_reverse_message*) &(win->buffer[win->tail % PCN_KMSG_RBUF_SIZE]);
	//KMSG_PRINTK("%s: Ready bit: %u\n", __func__, rcvd->hdr.ready);

    sleep_start = native_read_tsc();
	while (!rcvd->ready) {

		//pcn_cpu_relax();
		//msleep(1);

	}
    total_sleep_win_get += native_read_tsc() - sleep_start;
    sleep_win_get_count++;

	// barrier here?
	pcn_barrier();

	//log_receive[log_r_index%LOGLEN]=rcvd->hdr;
	memcpy(&(log_receive[log_r_index%LOGLEN]),&(rcvd->hdr),sizeof(struct pcn_kmsg_hdr));
	log_r_index++;

	//rcvd->hdr.ready = 0;

	*msg = rcvd;
msg_get++;

	return 0;
}

int win_init (void)
{
	int bug=0;

// TODO move the following in the initialization specific code
//antoniob these are controls that should be done a compile time and are dependent to the low level messaging used ...
	if ( __PCN_KMSG_TYPE_MAX > ((1<<8) -1) ) {
		printk(KERN_ALERT"%s: __PCN_KMSG_TYPE_MAX=%ld too big.\n", // this check goes here because is related to the transport: this transport doesn't support more than this number of messages types
			__func__, (unsigned long) __PCN_KMSG_TYPE_MAX);
		bug++;
	}
	if ( (((sizeof(struct pcn_kmsg_hdr)*8) - 24 - sizeof(unsigned long) - __READY_SIZE) != LG_SEQNUM_SIZE) ) {
		printk(KERN_ALERT"%s: LG_SEQNUM_SIZE=%ld is not correctly sized, should be %ld.\n",
			__func__, (unsigned long) LG_SEQNUM_SIZE,
			(unsigned long)((sizeof(struct pcn_kmsg_hdr)*8) - 24 - sizeof(unsigned long) - __READY_SIZE));
		bug++;
	}
	if ( (sizeof(struct pcn_kmsg_message) % CACHE_LINE_SIZE != 0) ) {
		printk(KERN_ALERT"%s: sizeof(struct pcn_kmsg_message)=%ld is not a multiple of cacheline size.\n",
			__func__, (unsigned long)sizeof(struct pcn_kmsg_message));
		bug++;
	}
        if ( (sizeof(struct pcn_kmsg_reverse_message) % CACHE_LINE_SIZE != 0) ) {
                printk(KERN_ALERT"%s: sizeof(struct pcn_kmsg_reverse_message)=%ld is not a multiple of cacheline size.\n",
                        __func__, (unsigned long)sizeof(struct pcn_kmsg_reverse_message));
                bug++;
        }
	BUG_ON((bug>1));
}
