/*
 * ft_network.c
 *
 * Author: Marina
 */

#include <linux/ft_replication.h>
#include <linux/popcorn_namespace.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <net/inet_sock.h>

#define FT_NET_VERBOSE 0
#define FT_NET_MVERBOSE 0

#if FT_NET_VERBOSE
#define FT_NET_MVERBOSE 1
#define FTPRINTK(...) printk(__VA_ARGS__)
#else
#define FTPRINTK(...) ;
#endif

#if FT_NET_MVERBOSE
#define FTMPRINTK(...) printk(__VA_ARGS__)
#else
#define FTMPRINTK(...) ;
#endif

#define ENABLE_CHECKSUM 1

struct send_fam_info{
	int size;
	__wsum csum;
	int ret;
};

struct rcv_fam_info_before{
        int size;
        int src_addr_size;
	void __user *ubuf;
	void *src_addr;
	int flags;
};

struct rcv_fam_info{
        int size;
	int flags;
        __wsum csum;
        int ret;
	//NOTE this must be the last field;
	char data;
};

struct accept_info{
	int error;
	__be32	daddr;
	__be16	dport;
};

extern int inet_csk_wait_for_connect(struct sock *sk, long timeo);
static int ft_syscall_accept_primary_before(struct request_sock_queue *queue, struct sock *sk,  int flags, int* err, struct sock **newsk){
	int error;
	struct accept_info *sys_info;

 	/* Find already established connection */
        if (reqsk_queue_empty(queue)) {
                long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);
                                
                /* If this is a non blocking socket don't sleep */
                error = -EAGAIN;        
                if (!timeo)     
                        goto out_err;
                                        
                error = inet_csk_wait_for_connect(sk, timeo);
                        
                if (error)
                        goto out_err;
        }
	return FT_SYSCALL_CONTINUE;

out_err:
	if(is_there_any_secondary_replica(current->ft_popcorn)){
                sys_info= kmalloc(sizeof(*sys_info), GFP_ATOMIC);
                if(!sys_info){
                        printk("ERROR %s impossible to malloc\n", __func__);
                        *err= -ENOMEM;
                        return *err;
                }
		
		sys_info->error= error;

                ft_send_syscall_info(current->ft_popcorn, &current->ft_pid, current->id_syscall, (char*) sys_info, sizeof(*sys_info));
                kfree(sys_info);
        }

	return error;      

}

static int __ft_syscall_accept_primary_after(struct request_sock_queue *queue, struct sock *parent, int* err, struct sock **newsk){
	struct sock* ret= reqsk_queue_get_child(queue, parent);
	struct accept_info *sys_info;

	if(is_there_any_secondary_replica(current->ft_popcorn)){
		sys_info= kmalloc(sizeof(*sys_info), GFP_ATOMIC);
		if(!sys_info){
			printk("ERROR %s impossible to malloc\n", __func__);
			*err= -ENOMEM;
			return *err;
		}

		sys_info->error= 0;
		sys_info->daddr= inet_sk(ret)->inet_daddr;
		sys_info->dport= inet_sk(ret)->inet_dport;

		ft_send_syscall_info(current->ft_popcorn, &current->ft_pid, current->id_syscall, (char*) sys_info, sizeof(*sys_info));
		kfree(sys_info);
	}

	//printk("%s sending connection %i %i pid %d \n", __func__, ntohs(inet_sk(ret)->inet_daddr), ntohs(inet_sk(ret)->inet_dport), current->pid);

	*newsk= ret;
	return FT_SYSCALL_CONTINUE;

}

static int __ft_syscall_accept_secondary(struct request_sock_queue *queue, struct sock *parent, int flags, int* err, __be32 addr, __be16 port, struct sock **newsk){
	struct request_sock *req;
        struct sock *child;
	
	req = reqsk_queue_find_remove(queue, addr, port);
	if(!req){
		/* code from  inet_csk_wait_for_connect*/

       		DEFINE_WAIT(wait);

        	for (;;) {
			
			//printk("%s pid %i waiting for a:%i p:%i \n", __func__, current->pid, ntohs(addr), ntohs(port));
			long timeo= MAX_SCHEDULE_TIMEOUT;
                
			prepare_to_wait_exclusive(sk_sleep(parent), &wait,
                                          TASK_INTERRUPTIBLE);
                	release_sock(parent);
                	if (!reqsk_queue_find(queue, addr, port))
                        	timeo = schedule_timeout(timeo);
                	lock_sock(parent);
			
                	*err = 0;
			req= reqsk_queue_find_remove(queue, addr, port);
                	if (req)
                        	break;
                	*err = -EINVAL;
                	if (parent->sk_state != TCP_LISTEN)
                        	break;
                	*err = sock_intr_errno(timeo);
                	if (signal_pending(current))
                        	break;
        	}


        	finish_wait(sk_sleep(parent), &wait);

		if (*err){
			*newsk= NULL;
			printk("ERROR %s error while waiting (err %d)\n", __func__, *err);
                 	return *err;
		}
		else{
			if(!req){
				printk("ERROR %s out from loop but not req pid %d\n", __func__, current->pid);
				*err= -EFAULT;
				*newsk= NULL;
				return *err;
			}
		}
	}

	//trace_printk("received connection %i %i from primary\n",ntohs(addr), ntohs(port));
	/* code from: reqsk_queue_get_child */

	child = req->sk;
        
        WARN_ON(child == NULL);

        sk_acceptq_removed(parent);
        __reqsk_free(req);
        

	*newsk= child;

	return FT_SYSCALL_DROP;
}

static int ft_syscall_accept_primary_after_secondary_before(struct request_sock_queue *queue, struct sock *parent, int flags, int* err, struct sock **newsk){
	struct accept_info *syscall_info_primary;
	__be32 addr;
        __be16 port;

	syscall_info_primary= (struct accept_info *) ft_get_pending_syscall_info(&current->ft_pid, current->id_syscall);
        if(syscall_info_primary){
		if(syscall_info_primary->error){
			*err =syscall_info_primary->error;
			kfree(syscall_info_primary);
			return *err;
		}
			
		addr= syscall_info_primary->daddr;
        	port= syscall_info_primary->dport;

        	kfree(syscall_info_primary);
			
		return __ft_syscall_accept_secondary(queue, parent, flags, err, addr, port, newsk);
	}
	else{
        	disable_det_sched(current);
		return ft_syscall_accept_primary_before(queue, parent, flags, err, newsk);
	}
}

static int ft_syscall_accept_secondary_before(struct request_sock_queue *queue, struct sock *parent, int flags, int* err, struct sock **newsk){
	struct accept_info *syscall_info_primary;
	__be32 addr;
	__be16 port;

	syscall_info_primary= (struct accept_info *) ft_wait_for_syscall_info(&current->ft_pid, current->id_syscall);
        if(!syscall_info_primary){
                //trace_printk(" switching to primary after secondary\n");

                /* I am the new primary replica*/

                return ft_syscall_accept_primary_after_secondary_before(queue, parent, flags, err, newsk);
        }

	if(syscall_info_primary->error){
		*err= syscall_info_primary->error;
		kfree(syscall_info_primary);
		return *err;
	}

	addr= syscall_info_primary->daddr;
	port= syscall_info_primary->dport;
	
	kfree(syscall_info_primary);

	return __ft_syscall_accept_secondary(queue, parent, flags, err, addr, port, newsk);
}

static int ft_syscall_accept_primary_after(struct request_sock_queue *queue, struct sock *parent, int* err,  struct sock **newsk){
	
	return __ft_syscall_accept_primary_after(queue, parent, err, newsk);
}

int ft_syscall_accept_after(struct request_sock_queue *queue, struct sock *parent, int flags, int* err, struct sock **newsk){
	
	if(ft_is_replicated(current)){

		/* Just a check to be sure that the sock that is using is replicated too...
                 *
                 */
                if(!parent->ft_filter){
                        trace_printk("WARNING: current is replicated (pid %d) but sock is not\n", current->pid);
                        return FT_SYSCALL_CONTINUE;
                }

                if( ft_is_primary_replica(current) || ft_is_primary_after_secondary_replica(current)){
			return ft_syscall_accept_primary_after(queue, parent, err, newsk);
		}
		else{
			if( ft_is_secondary_replica(current) ){
				printk("ERROR %s called by secondary replica\n", __func__);
				return -EFAULT;
			}
			else{
				printk("ERROR: %s current (pid %d) is not primary, secondary or primary_after_secondary replica \n", __func__, current->pid);
				return -EFAULT;
			}
		}

        }
        else{
                *newsk= reqsk_queue_get_child(queue, parent);
		return FT_SYSCALL_CONTINUE;
        }


}

int ft_syscall_accept_before(struct request_sock_queue *queue, struct sock *parent, int flags, int* err, struct sock **newsk){
	
	if(ft_is_replicated(current)){

		/* Just a check to be sure that the sock that is using is replicated too...
	         *
        	 */
        	if(!parent->ft_filter){
                	trace_printk("WARNING: current is replicated (pid %d) but sock is not\n", current->pid);
                	return FT_SYSCALL_CONTINUE;
        	}

                if( ft_is_primary_replica(current) ){
			return ft_syscall_accept_primary_before(queue, parent, flags, err, newsk);
		}
		else{
			if( ft_is_secondary_replica(current) ){
				return ft_syscall_accept_secondary_before(queue, parent, flags, err, newsk);
			}
			else{
				if(!ft_is_primary_after_secondary_replica(current)){
					printk("ERROR: %s current (pid %d) is not primary, secondary or primary_after_secondary replica \n", __func__, current->pid);
					return -EFAULT;
				}
				else
					return ft_syscall_accept_primary_after_secondary_before(queue, parent, flags, err, newsk);

			}
		}

        }
        else{
                return FT_SYSCALL_CONTINUE;
        }


}

static int after_syscall_rcv_family_primary_after_secondary(struct kiocb *iocb, struct socket *sock,
                                       struct msghdr *msg, size_t size, int flags, int ret){

        struct rcv_fam_info *syscall_info;
	struct rcv_fam_info_before *store_info; 
	int data_size= 0;
#if ENABLE_CHECKSUM
	char* where_to_copy;
	int err;
#endif
        //trace_printk("syscall_id %d\n", current->id_syscall);
	
	store_info= (struct rcv_fam_info_before*) current->useful;
        if(!store_info){
                /*I still was acting as a secondary replica on the "before" syscall rcv part*/
		return FT_SYSCALL_CONTINUE;
        }
      	else
		current->useful= NULL;

	if(is_there_any_secondary_replica(current->ft_popcorn)){

		/* in case without errors ret is the actual number of bytes copied.
		 * size is the maximum bytes allowed to copy.
		 */
		#if ENABLE_CHECKSUM
		if(ret>0)
			data_size= store_info->size - size + ret;
		else	
			data_size= store_info->size - size;
		#endif

		syscall_info= kmalloc( sizeof(*syscall_info) + data_size+ 1, GFP_KERNEL);
		if(!syscall_info)
			return -ENOMEM;

		syscall_info->size= store_info->size;
		syscall_info->flags= flags;
		syscall_info->ret= ret;

		/* TODO a copy is not needed. It is sent just as a first test.
		 * the data can be retrieved from the secondary from the packet forwarded to the stable buffer.
		 */
		syscall_info->csum= 0;
		#if ENABLE_CHECKSUM
		if(data_size){
				where_to_copy= &syscall_info->data;	
				syscall_info->csum= csum_and_copy_from_user(store_info->ubuf, where_to_copy, data_size, syscall_info->csum, &err);
				if(err){
					printk("ERROR: %s copy_from_user failed\n", __func__);
					goto out;
				}
				where_to_copy[data_size]='\0';
				FTPRINTK("%s: data %s size %d\n", __func__, where_to_copy, data_size);
		}
		#endif
		/*TODO
		 * NOTE: for tcp msg it is not important
		 * but for udp msg the fields  msg_name/msg_namelen should be copied too.
		 */

		/* NOTE: multiple threads could call rcv simultaneusly. On tcp_rcvmsg the socket is locked therefore they are serialized. 
		 * In here the lock already have been released, but the data was copied while holding it.
		 * In secondary replicas, if retriving data from the stable buffer, the same order of access to the stable buffer must be ensured.
		 */
		FTPRINTK("%s pid %d syscall_id %d sending size %d flags %d csum %d ret %d \n", __func__, current->pid, current->id_syscall, syscall_info->size, syscall_info->flags, syscall_info->csum, syscall_info->ret);
		ft_send_syscall_info(current->ft_popcorn, &current->ft_pid, current->id_syscall, (char*) syscall_info, sizeof(*syscall_info));
#if ENABLE_CHECKSUM
	out:
#endif
		kfree(syscall_info);
	}

	kfree(store_info);

	//trace_printk("end\n");
	
        return FT_SYSCALL_CONTINUE;
}

static int after_syscall_rcv_family_primary(struct kiocb *iocb, struct socket *sock,
                                       struct msghdr *msg, size_t size, int flags, int ret){

        struct rcv_fam_info *syscall_info;
	struct rcv_fam_info_before *store_info; 
	int data_size= 0;
	char* where_to_copy;
	int err;

        FTPRINTK("%s started for pid %d syscall_id %d\n", __func__, current->pid, current->id_syscall);
	
	store_info= (struct rcv_fam_info_before*) current->useful;
        if(!store_info){
                printk("ERROR: %s current->useful (pid %d) is NULL\n", __func__, current->pid);
                return -EFAULT;
        }
      	else
		current->useful= NULL;

	if(is_there_any_secondary_replica(current->ft_popcorn)){

		/* in case without errors ret is the actual number of bytes copied.
		 * size is the maximum bytes allowed to copy.
		 */
		#if ENABLE_CHECKSUM
		if(ret>0)
			data_size= ret;
		else	
			data_size= 0;
		#endif

		syscall_info= kmalloc( sizeof(*syscall_info) + data_size+ 1, GFP_KERNEL);
		if(!syscall_info)
			return -ENOMEM;

		syscall_info->size= size;
		syscall_info->flags= flags;
		syscall_info->ret= ret;

		/* TODO a copy is not needed. It is sent just as a first test.
		 * the data can be retrieved from the secondary from the packet forwarded to the stable buffer.
		 */
		syscall_info->csum= 0;
		
		#if ENABLE_CHECKSUM
		if(data_size){
				where_to_copy= &syscall_info->data;	
				syscall_info->csum= csum_and_copy_from_user(store_info->ubuf, where_to_copy, data_size, syscall_info->csum, &err);
				if(err){
					printk("ERROR: %s copy_from_user failed\n", __func__);
					goto out;
				}
				where_to_copy[data_size]='\0';
				FTPRINTK("%s: data %s size %d\n", __func__, where_to_copy, data_size);
		}
		#endif

		/*TODO
		 * NOTE: for tcp msg it is not important
		 * but for udp msg the fields  msg_name/msg_namelen should be copied too.
		 */

		/* NOTE: multiple threads could call rcv simultaneusly. On tcp_rcvmsg the socket is locked therefore they are serialized. 
		 * In here the lock already have been released, but the data was copied while holding it.
		 * In secondary replicas, if retriving data from the stable buffer, the same order of access to the stable buffer must be ensured.
		 */
		FTPRINTK("%s pid %d syscall_id %d sending size %d flags %d csum %d ret %d \n", __func__, current->pid, current->id_syscall, syscall_info->size, syscall_info->flags, syscall_info->csum, syscall_info->ret);
		ft_send_syscall_info(current->ft_popcorn, &current->ft_pid, current->id_syscall, (char*) syscall_info, sizeof(*syscall_info));
out:
		kfree(syscall_info);
	}
	
	kfree(store_info);
	
        return FT_SYSCALL_CONTINUE;
}

static int after_syscall_rcv_family_replicated_sock(struct kiocb *iocb, struct socket *sock,
                                       struct msghdr *msg, size_t size, int flags, int ret){

	/* Just a check to be sure that the sock that is using is replicated too...
         *
         */
        struct sock *sk= sock->sk;
        if(!sk || !sk->ft_filter){
                trace_printk("WARNING: current is replicated (pid %d) but sock is not\n", current->pid);
                return FT_SYSCALL_CONTINUE;
        }

        if(ft_is_primary_replica(current) || ft_is_filter_primary(sock->sk->ft_filter)){
                return after_syscall_rcv_family_primary(iocb, sock, msg, size, flags, ret);
        }
	
	if(ft_is_primary_after_secondary_replica(current)){
		return after_syscall_rcv_family_primary_after_secondary(iocb, sock, msg, size, flags, ret);
	}

        if(ft_is_secondary_replica(current)){
                printk("ERROR: %s current (pid %d) is a secondary replica (it should have stop the syscall of the 'before' part\n", __func__, current->pid);
                return -EFAULT;
        }

        printk("ERROR: %s current (pid %d) is not primary or secondar replica \n", __func__, current->pid);
        return -EFAULT;

}


int ft_after_syscall_rcv_family(struct kiocb *iocb, struct socket *sock,
                                       struct msghdr *msg, size_t size, int flags, int ret){

        if(ft_is_replicated(current)){
                return after_syscall_rcv_family_replicated_sock(iocb, sock, msg, size, flags, ret);
        }

        return FT_SYSCALL_CONTINUE;
}

static int before_syscall_rcv_family_primary(struct kiocb *iocb, struct socket *sock,
                                       struct msghdr *msg, size_t size, int flags, int* ret){

	struct rcv_fam_info_before *store_info;

	//trace_printk("syscall_id %d size %d\n", current->id_syscall, size);

	if(msg->msg_iovlen!=1){
                printk("ERROR %s iovlen is %d\n", __func__, (int) msg->msg_iovlen);
		return -EFAULT;
	}

	store_info= kmalloc(sizeof(*store_info), GFP_KERNEL);
	if(!store_info)
		return -ENOMEM;

	store_info->size= size;
	store_info->flags= flags;
	store_info->ubuf= msg->msg_iov->iov_base;

	store_info->src_addr_size= msg->msg_namelen;
	store_info->src_addr= msg->msg_name;
	
	if(current->useful!=NULL)
                printk("WARNING: %s going to use current->useful of pid %d but it is not NULL\n", __func__, current->pid);

        current->useful= (void*) store_info;

	/*char* filter_print= print_filter_id(sock->sk->ft_filter);
        printk("%s for pid %d in filter %s\n", __func__, current->pid, filter_print);
        if(filter_print)
        	kfree(filter_print);
	*/
        return FT_SYSCALL_CONTINUE;

}

static int before_syscall_rcv_family_primary_after_secondary(struct kiocb *iocb, struct socket *sock,
                                       struct msghdr *msg, size_t size, int flags, int* syscall_ret){
	struct sock *sk;
        struct rcv_fam_info *syscall_info_primary= NULL;
        struct rcv_fam_info_before *store_info;
	int data_size;
        __user char* ubuf;
	char* where_to_copy;
        __wsum my_csum;
        int err, ret= FT_SYSCALL_DROP;

        //trace_printk("syscall_id %d size %d port %d\n", current->id_syscall, (int)size, ntohs(sock->sk->ft_filter->tcp_param.dport));
	
	 /* There migth be pending syscall_info to consume
          *
          */
        syscall_info_primary= (struct rcv_fam_info *) ft_get_pending_syscall_info(&current->ft_pid, current->id_syscall);
        if(syscall_info_primary){
       		//trace_printk("stuff from pri\n");
		/* There is a pending syscall info => the primary consumed the data before sending syscall info to me.
		 * => the data should be compleately stored on the stable buffer
	 	 */
		if(syscall_info_primary->ret > 0)
                	data_size= syscall_info_primary->ret;
        	else
                	data_size= 0;

		if(syscall_info_primary->size != size){
                	printk("ERROR: %s for pid %d size of rcv (syscall id %d) not matching between primary(%d) and secondary(%d)\n", __func__, current->pid, current->id_syscall, syscall_info_primary->size, (int) size);
			ret= -EFAULT;
   			goto out;
	 	}

		if(syscall_info_primary->flags != flags){
                	printk("ERROR: %s for pid %d flags of rcv (syscall id %d) not matching between primary(%d) and secondary(%d)\n", __func__, current->pid, current->id_syscall, syscall_info_primary->flags, flags);
			ret= -EFAULT;
        		goto out;
		}

		my_csum= 0;
        	ubuf= msg->msg_iov->iov_base;
		if(data_size){
			sk= sock->sk;
		        if(!sk || !sk->ft_filter){
                		printk("ERROR: %s sock struct or sk->ft_filter is NULL\n", __func__);
                		ret= -EFAULT;
				goto out;
        		}
		
			err= remove_and_copy_from_stable_buffer_no_wait(sk->ft_filter->stable_buffer, msg->msg_iov, data_size);
			if(err < 0){
				ret= err;
				goto out;
			}
			
			if(err != data_size){
				printk("ERROR: %s asked %d bytes from stable buffere but received %d\n", __func__, data_size, err);
				trace_printk("ERROR: asked %d bytes from stable buffere but received %d port %d\n", data_size, err, ntohs(sk->ft_filter->tcp_param.dport));
				ret= -EFAULT;
				goto out;
			}

			#if ENABLE_CHECKSUM

			char* app= kmalloc(data_size+1, GFP_KERNEL);
			if(!app){
				ret= -ENOMEM;
				goto out;
			}

                        my_csum= csum_and_copy_from_user(ubuf, app, data_size, my_csum, &err);
			if(err){
				printk("ERROR: %s copy_from_user failed\n", __func__);
                        	ret= -EFAULT;
				kfree(app);
			       	goto out;
			}
                       	app[data_size]='\0';
			FTPRINTK("%s: data %s size %d\n", __func__, app, data_size);
			kfree(app);
			
			#endif			 
        	}
	
		/*TODO
	 	 * NOTE: for tcp msg it is not important
	 	 * but for udp msg the fields msg_name/msg_namelen should be copied too.
	 	 */

		if(my_csum != syscall_info_primary->csum){
                	printk("ERROR: %s for pid %d csum of send (syscall id %d) not matching between primary(%d) and secondary(%d)\n", __func__, current->pid, current->id_syscall, syscall_info_primary->csum, my_csum);
        		ret= -EFAULT;
		}
		
out:
        	*syscall_ret= syscall_info_primary->ret;

        	kfree(syscall_info_primary);

        	return ret;

	}
	else{
		/* In this case the primary replica did not sent me anything.
	 	 * Data could be on the stable buffer, or in the tcp level.
		 */

		disable_det_sched(current);

		if(msg->msg_iovlen!=1){
                        printk("ERROR %s iovlen is %d\n", __func__, (int) msg->msg_iovlen);
                        return -EFAULT;
                }

		sk= sock->sk;
		ubuf= msg->msg_iov->iov_base;

		data_size= remove_and_copy_from_stable_buffer_no_wait(sk->ft_filter->stable_buffer, msg->msg_iov, size);
                if(data_size > 0){
			FTMPRINTK("%s copied %d bytes from stable buffer\n", __func__, data_size);

			if(data_size!=size){
				//trace_printk("only %d from stable buffer, asking %d to socket?%d\n", data_size, (int) size-data_size, flags&MSG_WAITALL);
				char* filter_id_printed= print_filter_id(sk->ft_filter);
				FTPRINTK("%s WARNING got only %d bytes in stable buffer (needed %d), asking socket %s next %u\n", __func__, data_size, (int)size, filter_id_printed, tcp_sk(sk)->rcv_nxt );
				kfree(filter_id_printed);
				//msg->msg_iov should be already update with the correct offset
				//call normal tcp_recv with size= size-data_size
				if(flags&MSG_WAITALL){
					ret= sock->ops->recvmsg(iocb, sock, msg, size-data_size, flags);
					if(ret!=size-data_size){
						FTPRINTK("WARNING %s recvmsg returned %d when asked %d\n", __func__, ret, size-data_size );
					}

					
					if(ret>0)
						data_size+= ret;
					else
						data_size= ret;

				}
				
			}
	
			if(is_there_any_secondary_replica(current->ft_popcorn)){			

				if(data_size>0)
					syscall_info_primary= kmalloc( sizeof(*syscall_info_primary) + data_size+ 1, GFP_KERNEL);
				else
					syscall_info_primary= kmalloc( sizeof(*syscall_info_primary), GFP_KERNEL);

				if(!syscall_info_primary)
					return -ENOMEM;

				syscall_info_primary->size= size;
				syscall_info_primary->flags= flags;
				syscall_info_primary->ret= data_size;

				/* TODO a copy is not needed. It is sent just as a first test.
				* the data can be retrieved from the secondary from the packet forwarded to the stable buffer.
				*/
				syscall_info_primary->csum= 0;
			
				#if ENABLE_CHECKSUM
				if(data_size>0){
					where_to_copy= &syscall_info_primary->data;
					syscall_info_primary->csum= csum_and_copy_from_user(ubuf, where_to_copy, data_size, syscall_info_primary->csum, &err);
					if(err){
						printk("ERROR: %s copy_from_user failed\n", __func__);
						goto out2;
					}
					where_to_copy[data_size]='\0';
					FTPRINTK("%s: data %s size %d\n", __func__, where_to_copy, data_size);
				}
				#endif

				/*TODO
				 * NOTE: for tcp msg it is not important
				 * but for udp msg the fields  msg_name/msg_namelen should be copied too.
				 */

				/* NOTE: multiple threads could call rcv simultaneusly. On tcp_rcvmsg the socket is locked therefore they are serialized. 
				 * In here the lock already have been released, but the data was copied while holding it.
				 * In secondary replicas, if retriving data from the stable buffer, the same order of access to the stable buffer must be ensured.
				 */
				FTPRINTK("%s pid %d syscall_id %d sending size %d flags %d csum %d ret %d \n", __func__, current->pid, current->id_syscall, syscall_info_primary->size, syscall_info_primary->flags, syscall_info_primary->csum, syscall_info_primary->ret);
				
				if(data_size>0)
					ft_send_syscall_info(current->ft_popcorn, &current->ft_pid, current->id_syscall, (char*) syscall_info_primary, sizeof(*syscall_info_primary)+ data_size);
				else
					ft_send_syscall_info(current->ft_popcorn, &current->ft_pid, current->id_syscall, (char*) syscall_info_primary, sizeof(*syscall_info_primary));
			out2:
				kfree(syscall_info_primary);
			
			}

			*syscall_ret= data_size;
			return FT_SYSCALL_DROP;

		}
		else{

			store_info= kmalloc(sizeof(*store_info), GFP_KERNEL);
			if(!store_info)
				return -ENOMEM;
		
			store_info->size= size;
			store_info->flags= flags;
			store_info->ubuf= ubuf;

			store_info->src_addr_size= msg->msg_namelen;
			store_info->src_addr= msg->msg_name;

			if(current->useful!=NULL)
				printk("WARNING: %s going to use current->useful of pid %d but it is not NULL\n", __func__, current->pid);

			current->useful= (void*) store_info;
			return FT_SYSCALL_CONTINUE;
			
		}

	}

}

static int before_syscall_rcv_family_secondary(struct kiocb *iocb, struct socket *sock,
                                       struct msghdr *msg, size_t size, int flags, int* syscall_ret){

	struct sock *sk;
        struct rcv_fam_info *syscall_info_primary= NULL;
	int data_size;
	__user char* ubuf;
        __wsum my_csum;
        int err, ret= FT_SYSCALL_DROP;

        //trace_printk("syscall_id %d size %d port %d\n", current->id_syscall, (int) size, ntohs(sock->sk->ft_filter->tcp_param.dport));

        syscall_info_primary= (struct rcv_fam_info *) ft_wait_for_syscall_info(&current->ft_pid, current->id_syscall);
        if(!syscall_info_primary){
                //trace_printk("switching to primary after secondary \n");

		/* I am the new primary replica*/

		return before_syscall_rcv_family_primary_after_secondary(iocb, sock, msg, size, flags, syscall_ret);
        }

        if(syscall_info_primary->ret > 0)
                data_size= syscall_info_primary->ret;
        else
                data_size= 0;

	if(syscall_info_primary->size != size){
                printk("ERROR: %s for pid %d size of rcv (syscall id %d) not matching between primary(%d) and secondary(%d)\n", __func__, current->pid, current->id_syscall, syscall_info_primary->size, (int) size);
		ret= -EFAULT;
   		goto out;
	 }

	if(syscall_info_primary->flags != flags){
                printk("ERROR: %s for pid %d flags of rcv (syscall id %d) not matching between primary(%d) and secondary(%d)\n", __func__, current->pid, current->id_syscall, syscall_info_primary->flags, flags);
		ret= -EFAULT;
        	goto out;
	}

	my_csum= 0;
        ubuf= msg->msg_iov->iov_base;
	if(data_size){
			sk= sock->sk;
		        if(!sk || !sk->ft_filter){
                		printk("ERROR: %s sock struct or sk->ft_filter is NULL\n", __func__);
                		ret= -EFAULT;
				goto out;
        		}
		
			err= remove_and_copy_from_stable_buffer(sk->ft_filter->stable_buffer, msg->msg_iov, data_size);
			if(err < 0){
				ret= err;
				goto out;
			}
			
			if(err != data_size){
				printk("ERROR: %s asked %d bytes from stable buffere but received %d\n", __func__, data_size, err);
				ret= -EFAULT;
				goto out;
			}
			
			#if ENABLE_CHECKSUM

			char* app= kmalloc(data_size+1, GFP_KERNEL);
			if(!app){
				ret= -ENOMEM;
				goto out;
			}
                        my_csum= csum_and_copy_from_user(ubuf, app, data_size, my_csum, &err);
			if(err){
				printk("ERROR: %s copy_from_user failed\n", __func__);
                        	ret= -EFAULT;
				kfree(app);
			       	goto out;
			}
                       	app[data_size]='\0';
			FTPRINTK("%s: data %s size %d\n", __func__, app, data_size);
			kfree(app);

			#endif			
                
        }
	
	/*TODO
	 * NOTE: for tcp msg it is not important
	 * but for udp msg the fields msg_name/msg_namelen should be copied too.
	 */

	if(my_csum != syscall_info_primary->csum){
		char* filter_print= print_filter_id(sock->sk->ft_filter);
                printk("ERROR: %s for pid %d csum of rcv (syscall id %d) not matching between primary(%d) and secondary(%d) for %d bytes in filter %s\n", __func__, current->pid, current->id_syscall, syscall_info_primary->csum, my_csum, data_size, filter_print);
		if(filter_print)
			kfree(filter_print);
        	ret= -EFAULT;
	}
	
	/*
	char* filter_print= print_filter_id(sock->sk->ft_filter);
        printk("%s for pid %d in filter %s\n", __func__, current->pid, filter_print);
        if(filter_print)
        	kfree(filter_print);
	*/
out:
        *syscall_ret= syscall_info_primary->ret;

        kfree(syscall_info_primary);

        return ret;
}

static int before_syscall_rcv_family_replicated_sock(struct kiocb *iocb, struct socket *sock,
                                       struct msghdr *msg, size_t size, int flags, int* ret){

	/* Just a check to be sure that the sock that is using is replicated too...
         *
         */
        struct sock *sk= sock->sk;
        if(!sk || !sk->ft_filter){
                trace_printk("WARNING: current is replicated (pid %d) but sock is not\n", current->pid);
                return FT_SYSCALL_CONTINUE;
        }

        // Increase the syscall count

        if(ft_is_primary_replica(current) || (sock->sk && sock->sk->ft_filter && ft_is_filter_primary(sock->sk->ft_filter))){
                return before_syscall_rcv_family_primary(iocb, sock, msg, size, flags, ret);
        }

        if(ft_is_secondary_replica(current)){
                return before_syscall_rcv_family_secondary(iocb, sock, msg, size, flags, ret);
        }

	if(ft_is_primary_after_secondary_replica(current)){
                return before_syscall_rcv_family_primary_after_secondary(iocb, sock, msg, size, flags, ret);
        }

        printk("ERROR: %s current (pid %d) is not primary or secondary replica \n", __func__, current->pid);
        return -EFAULT;

}


int ft_before_syscall_rcv_family(struct kiocb *iocb, struct socket *sock,
                                       struct msghdr *msg, size_t size, int flags, int* ret){

        if(ft_is_replicated(current)){
		return before_syscall_rcv_family_replicated_sock(iocb, sock, msg, size, flags, ret);
        }

        return FT_SYSCALL_CONTINUE;
}

static int after_syscall_send_family_primary(struct socket* sock, int ret){
	struct send_fam_info *syscall_info;
	char *extra_key= NULL;
	unsigned int size_extra_key;

	FTPRINTK("%s started for pid %d syscall_id %d\n", __func__, current->pid, current->id_syscall);

	syscall_info= (struct send_fam_info*) current->useful;
	if(!syscall_info){
		/*TODO FOR SECONDARY*/
		printk("ERROR: %s current->useful (pid %d) is NULL\n", __func__, current->pid);
                return -EFAULT;
	}
	syscall_info->ret= ret;

	FTPRINTK("%s pid %d syscall_id %d sending size %d csum %d ret %d \n", __func__, current->pid, current->id_syscall, syscall_info->size, syscall_info->csum, syscall_info->ret);

	if(is_there_any_secondary_replica(current->ft_popcorn)){	

		ft_get_key_from_filter(sock->sk->ft_filter,"SEND", &extra_key, &size_extra_key);
		ft_send_syscall_info_extra_key( current->ft_popcorn, &current->ft_pid, current->id_syscall, (char*) syscall_info, sizeof(*syscall_info), extra_key, (extra_key==NULL)?0:size_extra_key);

		if(extra_key)
	                kfree(extra_key);

	}
	
	kfree(syscall_info);
	current->useful= NULL;
	
	return FT_SYSCALL_CONTINUE;
}

static int after_syscall_send_family_replicated_sock(struct socket *sock, int ret){

	 /* Just a check to be sure that the sock that is using is replicated too...
         *
         */
        struct sock *sk= sock->sk;
        if(!sk || !sk->ft_filter){
                trace_printk("WARNING: current is replicated (pid %d) but sock is not\n", current->pid);
                return FT_SYSCALL_CONTINUE;
        }

	if(ft_is_primary_replica(current) || ft_is_filter_primary(sk->ft_filter) || ft_is_primary_after_secondary_replica(current)){
                return after_syscall_send_family_primary(sock, ret);
        }

        if(ft_is_secondary_replica(current)){
                printk("ERROR: %s current (pid %d) is a secondary replica (it should have stop the syscall of the 'before' part\n", __func__, current->pid);
        	return -EFAULT;
        }

	printk("ERROR: %s current (pid %d) is not primary or secondar replica \n", __func__, current->pid);
	return -EFAULT;

}


int ft_after_syscall_send_family(struct socket *sock, int ret){

	if(ft_is_replicated(current)){
		return after_syscall_send_family_replicated_sock(sock, ret);
	}
	
	return FT_SYSCALL_CONTINUE;
}

static int before_syscall_send_family_primary(struct kiocb *iocb, struct socket *sock,
                                       struct msghdr *msg, size_t size);
static int before_syscall_send_family_primary_after_secondary(struct kiocb *iocb, struct socket *sock,
                                       struct msghdr *msg, size_t size, int* ret){
	struct send_fam_info *syscall_info_primary= NULL;
        struct iovec *iov;
        int iovlen, err;
        __wsum my_csum;

check_flush:	lock_send_buffer_to_exclude_flushing(sock->sk->ft_filter->send_buffer);

	if(is_send_buffer_flushing(sock->sk->ft_filter->send_buffer)){
		unlock_send_buffer_to_exclude_flushing(sock->sk->ft_filter->send_buffer);
		msleep(300);
		goto check_flush;
	}	

	//trace_printk("port %d\n", ntohs(sock->sk->ft_filter->tcp_param.dport));
	
	unlock_send_buffer_to_exclude_flushing(sock->sk->ft_filter->send_buffer);

	syscall_info_primary= (struct send_fam_info *) ft_get_pending_syscall_info(&current->ft_pid, current->id_syscall);
        if(syscall_info_primary){
		//trace_printk("data from primary\n");
		if(syscall_info_primary->size != size){
			printk("ERROR: %s for pid %d size of send (syscall id %d) not matching between primary(%d) and secondary(%d)\n", __func__, current->pid, current->id_syscall, syscall_info_primary->size, (int) size);
			goto out;
		}

		my_csum= 0;
        	iovlen = msg->msg_iovlen;
        	iov = msg->msg_iov;

        	err= insert_in_send_buffer_and_csum(sock->sk->ft_filter->send_buffer, iov, iovlen, size, &my_csum);
        	if(err){
                	printk("ERROR %s Impossible to insert in send buffer err %d\n", __func__, err);
                	goto out;
        	}

		if(my_csum != syscall_info_primary->csum){
			printk("ERROR: %s for pid %d csum of send (syscall id %d) not matching between primary(%d) and secondary(%d)\n", __func__, current->pid, current->id_syscall, syscall_info_primary->csum, my_csum);
		}

	out:
		*ret= syscall_info_primary->ret;

		kfree(syscall_info_primary);

		if(is_send_buffer_to_flush(sock->sk->ft_filter->send_buffer)){
			lock_send_buffer_for_flushing(sock->sk->ft_filter->send_buffer);
			if(dec_and_check_pending_send_on_send_buffer(sock->sk->ft_filter->send_buffer)){
        			//trace_printk("flushing send buffer of port %d\n", ntohs(sock->sk->ft_filter->tcp_param.dport));
	                	flush_send_buffer_first_time(sock->sk->ft_filter->send_buffer, sock->sk);
                	}
			unlock_send_buffer_for_flushing(sock->sk->ft_filter->send_buffer);
		}

		return FT_SYSCALL_DROP;

	}
	else{
		disable_det_sched(current);
		//trace_printk("sending new data port %d size %d\n", ntohs(sock->sk->ft_filter->tcp_param.dport), (int) size);
		return before_syscall_send_family_primary(iocb, sock, msg, size);
	}

}

static int before_syscall_send_family_secondary(struct kiocb *iocb, struct socket *sock,
                                       struct msghdr *msg, size_t size, int* ret){

        struct send_fam_info *sycall_info_primary= NULL;
	struct iovec *iov;
	int iovlen, err;
	__wsum my_csum;
	int size_extra_key;
	char* extra_key;

	//trace_printk("syscall_id %d size %d on port %d\n", current->id_syscall, (int) size, ntohs(sock->sk->ft_filter->tcp_param.dport));

	lock_send_buffer_to_exclude_flushing(sock->sk->ft_filter->send_buffer);

	ft_get_key_from_filter(sock->sk->ft_filter,"SEND", &extra_key, &size_extra_key);
	
	sycall_info_primary= (struct send_fam_info *) ft_wait_for_syscall_info_extra_key(&current->ft_pid, current->id_syscall, extra_key);
	if(!sycall_info_primary){
		unlock_send_buffer_to_exclude_flushing(sock->sk->ft_filter->send_buffer);
		if(is_send_buffer_to_flush(sock->sk->ft_filter->send_buffer)){
			lock_send_buffer_for_flushing(sock->sk->ft_filter->send_buffer);
			if(dec_and_check_pending_send_on_send_buffer(sock->sk->ft_filter->send_buffer)){
				//trace_printk("flushing send buffer of port %d\n", ntohs(sock->sk->ft_filter->tcp_param.dport));
				flush_send_buffer_first_time(sock->sk->ft_filter->send_buffer, sock->sk);
			}
			unlock_send_buffer_for_flushing(sock->sk->ft_filter->send_buffer);
		}
		//trace_printk("changing to primary after secondary\n");
		return before_syscall_send_family_primary_after_secondary(iocb, sock, msg, size, ret);
	}

	if(sycall_info_primary->size != size){
		printk("ERROR: %s for pid %d size of send (syscall id %d) not matching between primary(%d) and secondary(%d)\n", __func__, current->pid, current->id_syscall, sycall_info_primary->size, (int) size);
		goto out;
	}
	
	my_csum= 0;
	iovlen = msg->msg_iovlen;
        iov = msg->msg_iov;

	err= insert_in_send_buffer_and_csum(sock->sk->ft_filter->send_buffer, iov, iovlen, size, &my_csum);
	if(err){
		printk("ERROR %s Impossible to insert in send buffer err %d\n", __func__, err);
		goto out;
	}

	if(my_csum != sycall_info_primary->csum){
		printk("ERROR: %s for pid %d csum of send (syscall id %d) not matching between primary(%d) and secondary(%d)\n", __func__, current->pid, current->id_syscall, sycall_info_primary->csum, my_csum);
	}

out:

	unlock_send_buffer_to_exclude_flushing(sock->sk->ft_filter->send_buffer);			
	if(is_send_buffer_to_flush(sock->sk->ft_filter->send_buffer)){
		lock_send_buffer_for_flushing(sock->sk->ft_filter->send_buffer);
		if(dec_and_check_pending_send_on_send_buffer(sock->sk->ft_filter->send_buffer)){
			//trace_printk("flushing send buffer of port %d\n", ntohs(sock->sk->ft_filter->tcp_param.dport));
			flush_send_buffer_first_time(sock->sk->ft_filter->send_buffer, sock->sk);
		}
		unlock_send_buffer_for_flushing(sock->sk->ft_filter->send_buffer);
	}


	*ret= sycall_info_primary->ret;

	kfree(sycall_info_primary);

	return FT_SYSCALL_DROP;
}

static int before_syscall_send_family_primary(struct kiocb *iocb, struct socket *sock,
                                       struct msghdr *msg, size_t size){
	struct send_fam_info *syscall_info;
	struct iovec *iov;
        int iovlen, i, err;

	FTPRINTK("%s started for pid %d syscall_id %d\n", __func__, current->pid, current->id_syscall);

	syscall_info= kmalloc(sizeof(*syscall_info), GFP_KERNEL);
	if(!syscall_info)
		return -ENOMEM;

	//calculate hash
	syscall_info->csum= 0;
        iovlen = msg->msg_iovlen;
        iov = msg->msg_iov;

        /* The data is in user space, so I copy it in kernel and after I perform the checksum.
         * Is it really necessary to copy it?! NOT SURE. HOPEFULLY NOT! 
         */
	#if ENABLE_CHECKSUM

        for(i=0; i< iovlen; i++){
                char* app= kmalloc(iov[i].iov_len +1, GFP_KERNEL);
                syscall_info->csum= csum_and_copy_from_user(iov[i].iov_base, (void*)app, iov[i].iov_len, syscall_info->csum, &err);
        	if(err){
			printk("ERROR: %s copy_from_user failed\n", __func__);
                        kfree(app);
                        goto out;
		}
		app[iov[i].iov_len]='\0';
		FTPRINTK("%s: data %s\n",__func__,app);
	        kfree(app);
        }

	#endif

	syscall_info->size= size;

		
	if(current->useful!=NULL)
		printk("WARNING: %s going to use current->useful of pid %d but it is not NULL\n", __func__, current->pid);

	current->useful= (void*) syscall_info;

out:
	return FT_SYSCALL_CONTINUE;
}

static int before_syscall_send_family_replicated_sock(struct kiocb *iocb, struct socket *sock,
                                       struct msghdr *msg, size_t size, int* ret){

	/* Just a check to be sure that the sock that is using is replicated too...
	 *
	 */
	struct sock *sk= sock->sk;
	if(!sk || !sk->ft_filter){
		trace_printk("WARNING: %s current is replicated (pid %d) but sock is not\n", __func__, current->pid);
		return FT_SYSCALL_CONTINUE;
	}

    	// Increase the syscall count
	if(ft_is_primary_replica(current) || ft_is_filter_primary(sk->ft_filter)){
                return before_syscall_send_family_primary(iocb, sock, msg, size);
        }

        if(ft_is_secondary_replica(current)){
                return before_syscall_send_family_secondary(iocb, sock, msg, size, ret);
        }

	if(ft_is_primary_after_secondary_replica(current)){
                return before_syscall_send_family_primary_after_secondary(iocb, sock, msg, size, ret);
        }

	printk("ERROR: %s current (pid %d) is not primary or secondar replica \n", __func__, current->pid);
	return -EFAULT;

}


int ft_before_syscall_send_family(struct kiocb *iocb, struct socket *sock,
                                       struct msghdr *msg, size_t size, int* ret){

	if(ft_is_replicated(current)){
		return before_syscall_send_family_replicated_sock(iocb, sock, msg, size, ret);
	}
	
	return FT_SYSCALL_CONTINUE;
}

