/*
 * ft_eventpoll.c
 * Copyright (C) 2016 Yuzhong Wen <wyz2014@vt.edu>
 *
 * This is for replicating epoll system calls
 * Currently only consider epoll_wait.
 */

#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/eventpoll.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/poll.h>
#include <asm/uaccess.h>
#include <linux/list.h>
#include <linux/ft_replication.h>

/*
 * Structure for epoll_wait syscall info
 */
struct epoll_wait_info {
	int nr_events;     // Number of events
	struct epoll_event events[0];   // Array of events, it has to be at the end of the struct
} __attribute__((packed));

/*
 * Wait for the epoll info from the other side
 */
int ft_ep_poll_secondary(struct epoll_event __user *events)
{
	int ret=0;
	int i;
	struct epoll_wait_info *epinfo = NULL;

	printk("waiting events for syscall %d\n", current->id_syscall);
	epinfo = (struct epoll_wait_info *) ft_wait_for_syscall_info(&current->ft_pid, current->id_syscall);

	if (!epinfo) {
		return -EFAULT;
	}

	if (epinfo->nr_events > 0) {
		for (i = 0; i < epinfo->nr_events; i++) {
			epinfo->events[i].data -= 3;
		}
		copy_to_user(events, epinfo->events, epinfo->nr_events * sizeof(struct epoll_event));
	} else {
		printk("OOPS %d\n", epinfo->nr_events);
	}

	ret = epinfo->nr_events;
	printk("got %d events\n", ret);
	kfree(epinfo);

	return ret;
}

/*
 * Send the epoll info to the other side
 */
int ft_ep_poll_primary(struct epoll_event __user *events, int nr_events)
{
	struct epoll_wait_info *epinfo = NULL;
	ssize_t epinfo_size;

	if (nr_events > 0) {
		epinfo_size = sizeof(struct epoll_wait_info) + nr_events * sizeof(struct epoll_event);
	} else {
		epinfo_size = sizeof(struct epoll_wait_info);
	}
	epinfo = (struct epoll_wait_info *) kmalloc(epinfo_size, GFP_KERNEL);

	if (!epinfo) {
		printk("epinfo allocation failed!\n");
		return -ENOMEM;
	}

	epinfo->nr_events = nr_events;

	if (nr_events > 0) {
		copy_from_user(epinfo->events, events, nr_events * sizeof(struct epoll_event));
	}
	
	if(is_there_any_secondary_replica(current->ft_popcorn)){
		printk("sending %d events for syscall %d\n", nr_events, current->id_syscall);
		ft_send_syscall_info(current->ft_popcorn, &current->ft_pid, current->id_syscall, (char*) epinfo, epinfo_size);
	}

	kfree(epinfo);

	return 0;
}
