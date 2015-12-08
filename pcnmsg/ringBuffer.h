/*
 * ringBuffer.h
 *
 *  Created on: Dec 7, 2015
 *      Author: root
 */

#ifndef PCNMSG_RINGBUFFER_H_
#define PCNMSG_RINGBUFFER_H_

int win_init (void);

int win_get(struct pcn_kmsg_window *win,
                          struct pcn_kmsg_reverse_message **msg);


int win_put(struct pcn_kmsg_window *win,
                          struct pcn_kmsg_message *msg,
                          int no_block);

static inline unsigned long win_inuse(struct pcn_kmsg_window *win)
{
        return win->head - win->tail;
}

#endif /* PCNMSG_RINGBUFFER_H_ */
