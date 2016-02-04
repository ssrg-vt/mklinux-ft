/*
 * ft_select.c
 * Copyright (C) 2016 Yuzhong Wen <wyz2014@vt.edu>
 *
 * This is for replicating select and poll system calls
 */

#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/poll.h>
#include <asm/uaccess.h>
#include <linux/list.h>
#include <linux/ft_replication.h>
#include <linux/net.h>
#include <net/sock.h>

/*
 * Structure for poll_wait syscall info
 */
struct poll_wait_info {
	int nr_events;     // Number of events
	struct pollfd events[0];   // Array of events, it has to be at the end of the struct
} __attribute__((packed));


/*
 * Structure for select_wait syscall info
 */
struct select_wait_info {
} __attribute__((packed));

/*
 * Send the poll info to the other side
 */
int ft_poll_primary_after(struct pollfd __user *events, int* ret)
{
	struct poll_wait_info *pinfo = NULL;
	ssize_t pinfo_size;
	int nr_events= *ret;

	if(is_there_any_secondary_replica(current->ft_popcorn)){
		if (nr_events > 0) {
			pinfo_size = sizeof(struct poll_wait_info) + nr_events * sizeof(struct pollfd);
		} else {
			pinfo_size = sizeof(struct poll_wait_info);
		}
		pinfo = (struct poll_wait_info *) kmalloc(pinfo_size, GFP_KERNEL);

		if (!pinfo) {
			printk("epinfo allocation failed!\n");
			return -ENOMEM;
		}

		pinfo->nr_events = nr_events;

		if (nr_events > 0) {
			copy_from_user(pinfo->events, events, nr_events * sizeof(struct pollfd));
		}
		
		ft_send_syscall_info(current->ft_popcorn, &current->ft_pid, current->id_syscall, (char*) pinfo, pinfo_size);

		kfree(pinfo);

	}

	return FT_SYSCALL_CONTINUE;
}

static int check_if_read_data_available_from_stable_buffer(struct pollfd __user *events, unsigned int nfds){
	int i;
	struct pollfd pollentry;
	struct socket *sock;
	int err, copied;
	int ret= 0;

	for(i=0; i<nfds ; i++){
		copied= 0;
		copy_from_user(&pollentry, &events[i], sizeof(struct pollfd));
		if(pollentry.fd> 0 && pollentry.events & POLLIN){
			sock= sockfd_lookup(pollentry.fd, &err);
			if (sock) {
				if(sock->sk && sock->sk->ft_filter){
					if(!is_stable_buffer_empty(sock->sk->ft_filter->stable_buffer)){
						ret++;
						trace_printk("stable buffer not empty port %d\n", ntohs(sock->sk->ft_filter->tcp_param.dport));
						copied= POLLIN;
						copy_to_user(&events[i].revents, &copied, sizeof(pollentry.revents));				
						copied= 1;
					}
				}
				sockfd_put(sock);
			}
		}
		if(!copied)
			copy_to_user(&events[i].revents, 0, sizeof(pollentry.revents));
	}

	return ret;
}

/*
 * Wait for the poll info from the other side
 */
int ft_poll_primary_after_secondary_before(struct pollfd __user *events, unsigned int nfds, int* ret)
{
        struct poll_wait_info *pinfo = NULL;
	int stb_data;

	trace_printk("\n");
	
        pinfo = (struct poll_wait_info *) ft_get_pending_syscall_info(&current->ft_pid, current->id_syscall);

        if (!pinfo) {
		//threa migth be data on the stable buffer of the sockets
		stb_data= check_if_read_data_available_from_stable_buffer(events, nfds);
		if(stb_data){
			*ret= stb_data;
			return FT_SYSCALL_DROP;
		}
		return FT_SYSCALL_CONTINUE;
        }

	trace_printk("poll from primary\n");
        if (pinfo->nr_events > 0) {
                copy_to_user(events, pinfo->events, pinfo->nr_events * sizeof(struct pollfd));
        } else {
                printk("OOPS %d\n", pinfo->nr_events);
        }

        *ret = pinfo->nr_events;
        kfree(pinfo);

        return FT_SYSCALL_DROP;

}

/*
 * Wait for the poll info from the other side
 */
int ft_poll_secondary_before(struct pollfd __user *events, unsigned int nfds, int *ret)
{
	struct poll_wait_info *pinfo = NULL;

	pinfo = (struct poll_wait_info *) ft_wait_for_syscall_info(&current->ft_pid, current->id_syscall);

	if (!pinfo) {
		return ft_poll_primary_after_secondary_before(events, nfds, ret);
	}

	if (pinfo->nr_events > 0) {
		copy_to_user(events, pinfo->events, pinfo->nr_events * sizeof(struct pollfd));
	} else {
		printk("OOPS %d\n", pinfo->nr_events);
	}

	*ret = pinfo->nr_events;
	kfree(pinfo);

	return FT_SYSCALL_DROP;

}

int ft_poll_before(struct pollfd __user *events, unsigned int nfds, int *ret){
	if(ft_is_replicated(current)){
		if(ft_is_secondary_replica(current))
                	return ft_poll_secondary_before(events, nfds, ret);
		if(ft_is_primary_after_secondary_replica(current))
			return ft_poll_primary_after_secondary_before(events, nfds, ret);
        }

	return FT_SYSCALL_CONTINUE;
}

int ft_poll_after(struct pollfd __user *events, int *ret){
        if(ft_is_replicated(current)){
                if(ft_is_primary_replica(current) || ft_is_primary_after_secondary_replica(current))
                        return ft_poll_primary_after(events, ret);
        }

        return FT_SYSCALL_CONTINUE;
}

