/*
 * linux/net/sunrpc/xprtsock.c
 *
 * Client-side transport implementation for sockets.
 *
 * TCP callback races fixes (C) 1998 Red Hat Software <alan@redhat.com>
 * TCP send fixes (C) 1998 Red Hat Software <alan@redhat.com>
 * TCP NFS related read + write fixes
 *  (C) 1999 Dave Airlie, University of Limerick, Ireland <airlied@linux.ie>
 *
 * Rewrite of larges part of the code in order to stabilize TCP stuff.
 * Fix behaviour when socket buffer is full.
 *  (C) 1999 Trond Myklebust <trond.myklebust@fys.uio.no>
 */

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/mm.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/sunrpc/clnt.h>
#include <linux/file.h>

#include <net/sock.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <net/tcp.h>

/*
 * Maximum port number to use when requesting a reserved port.
 */
#define XS_MAX_RESVPORT		(800U)

#ifdef RPC_DEBUG
# undef  RPC_DEBUG_DATA
# define RPCDBG_FACILITY	RPCDBG_TRANS
#endif

#ifdef RPC_DEBUG_DATA
static void xs_pktdump(char *msg, u32 *packet, unsigned int count)
{
	u8 *buf = (u8 *) packet;
	int j;

	dprintk("RPC:      %s\n", msg);
	for (j = 0; j < count && j < 128; j += 4) {
		if (!(j & 31)) {
			if (j)
				dprintk("\n");
			dprintk("0x%04x ", j);
		}
		dprintk("%02x%02x%02x%02x ",
			buf[j], buf[j+1], buf[j+2], buf[j+3]);
	}
	dprintk("\n");
}
#else
static inline void xs_pktdump(char *msg, u32 *packet, unsigned int count)
{
	/* NOP */
}
#endif

#define XS_SENDMSG_FLAGS	(MSG_DONTWAIT | MSG_NOSIGNAL)

static inline int xs_send_head(struct socket *sock, struct sockaddr *addr, int addrlen, struct xdr_buf *xdr, unsigned int base, unsigned int len)
{
	struct kvec iov = {
		.iov_base	= xdr->head[0].iov_base + base,
		.iov_len	= len - base,
	};
	struct msghdr msg = {
		.msg_name	= addr,
		.msg_namelen	= addrlen,
		.msg_flags	= XS_SENDMSG_FLAGS,
	};

	if (xdr->len > len)
		msg.msg_flags |= MSG_MORE;

	if (likely(iov.iov_len))
		return kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
	return kernel_sendmsg(sock, &msg, NULL, 0, 0);
}

static int xs_send_tail(struct socket *sock, struct xdr_buf *xdr, unsigned int base, unsigned int len)
{
	struct kvec iov = {
		.iov_base	= xdr->tail[0].iov_base + base,
		.iov_len	= len - base,
	};
	struct msghdr msg = {
		.msg_flags	= XS_SENDMSG_FLAGS,
	};

	return kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
}

/**
 * xs_sendpages - write pages directly to a socket
 * @sock: socket to send on
 * @addr: UDP only -- address of destination
 * @addrlen: UDP only -- length of destination address
 * @xdr: buffer containing this request
 * @base: starting position in the buffer
 *
 */
static int xs_sendpages(struct socket *sock, struct sockaddr *addr, int addrlen, struct xdr_buf *xdr, unsigned int base)
{
	struct page **ppage = xdr->pages;
	unsigned int len, pglen = xdr->page_len;
	int err, ret = 0;
	ssize_t (*sendpage)(struct socket *, struct page *, int, size_t, int);

	len = xdr->head[0].iov_len;
	if (base < len || (addr != NULL && base == 0)) {
		err = xs_send_head(sock, addr, addrlen, xdr, base, len);
		if (ret == 0)
			ret = err;
		else if (err > 0)
			ret += err;
		if (err != (len - base))
			goto out;
		base = 0;
	} else
		base -= len;

	if (unlikely(pglen == 0))
		goto copy_tail;
	if (unlikely(base >= pglen)) {
		base -= pglen;
		goto copy_tail;
	}
	if (base || xdr->page_base) {
		pglen -= base;
		base += xdr->page_base;
		ppage += base >> PAGE_CACHE_SHIFT;
		base &= ~PAGE_CACHE_MASK;
	}

	sendpage = sock->ops->sendpage ? : sock_no_sendpage;
	do {
		int flags = XS_SENDMSG_FLAGS;

		len = PAGE_CACHE_SIZE;
		if (base)
			len -= base;
		if (pglen < len)
			len = pglen;

		if (pglen != len || xdr->tail[0].iov_len != 0)
			flags |= MSG_MORE;

		/* Hmm... We might be dealing with highmem pages */
		if (PageHighMem(*ppage))
			sendpage = sock_no_sendpage;
		err = sendpage(sock, *ppage, base, len, flags);
		if (ret == 0)
			ret = err;
		else if (err > 0)
			ret += err;
		if (err != len)
			goto out;
		base = 0;
		ppage++;
	} while ((pglen -= len) != 0);
copy_tail:
	len = xdr->tail[0].iov_len;
	if (base < len) {
		err = xs_send_tail(sock, xdr, base, len);
		if (ret == 0)
			ret = err;
		else if (err > 0)
			ret += err;
	}
out:
	return ret;
}

/**
 * xs_sendmsg - write an RPC request to a socket
 * @xprt: generic transport
 * @req: the RPC request to write
 *
 */
static int xs_sendmsg(struct rpc_xprt *xprt, struct rpc_rqst *req)
{
	struct socket *sock = xprt->sock;
	struct xdr_buf *xdr = &req->rq_snd_buf;
	struct sockaddr *addr = NULL;
	int addrlen = 0;
	unsigned int skip;
	int result;

	if (!sock)
		return -ENOTCONN;

	xs_pktdump("packet data:",
				req->rq_svec->iov_base,
				req->rq_svec->iov_len);

	/* For UDP, we need to provide an address */
	if (!xprt->stream) {
		addr = (struct sockaddr *) &xprt->addr;
		addrlen = sizeof(xprt->addr);
	}
	/* Don't repeat bytes */
	skip = req->rq_bytes_sent;

	clear_bit(SOCK_ASYNC_NOSPACE, &sock->flags);
	result = xs_sendpages(sock, addr, addrlen, xdr, skip);

	dprintk("RPC:      xs_sendmsg(%d) = %d\n", xdr->len - skip, result);

	if (result >= 0)
		return result;

	switch (result) {
	case -ECONNREFUSED:
		/* When the server has died, an ICMP port unreachable message
		 * prompts ECONNREFUSED. */
	case -EAGAIN:
		break;
	case -ECONNRESET:
	case -ENOTCONN:
	case -EPIPE:
		/* connection broken */
		if (xprt->stream)
			result = -ENOTCONN;
		break;
	default:
		break;
	}
	return result;
}

/**
 * xs_send_request - write an RPC request to a socket
 * @task: address of RPC task that manages the state of an RPC request
 *
 * Return values:
 *      0:  The request has been sent
 * EAGAIN:  The socket was blocked, please call again later to
 *          complete the request
 *  other:  Some other error occured, the request was not sent
 *
 * XXX: In the case of soft timeouts, should we eventually give up
 *      if the socket is not able to make progress?
 */
static int xs_send_request(struct rpc_task *task)
{
	struct rpc_rqst *req = task->tk_rqstp;
	struct rpc_xprt *xprt = req->rq_xprt;
	int status, retry = 0;

	/* set up everything as needed. */
	/* Write the record marker */
	if (xprt->stream) {
		u32 *marker = req->rq_svec[0].iov_base;

		*marker = htonl(0x80000000|(req->rq_slen-sizeof(*marker)));
	}

	/* Continue transmitting the packet/record. We must be careful
	 * to cope with writespace callbacks arriving _after_ we have
	 * called sendmsg().
	 */
	while (1) {
		req->rq_xtime = jiffies;
		status = xs_sendmsg(xprt, req);

		if (status < 0)
			break;

		if (xprt->stream) {
			req->rq_bytes_sent += status;

			/* If we've sent the entire packet, immediately
			 * reset the count of bytes sent. */
			if (req->rq_bytes_sent >= req->rq_slen) {
				req->rq_bytes_sent = 0;
				return 0;
			}
		} else {
			if (status >= req->rq_slen)
				return 0;
			status = -EAGAIN;
			break;
		}

		dprintk("RPC: %4d xmit incomplete (%d left of %d)\n",
				task->tk_pid, req->rq_slen - req->rq_bytes_sent,
				req->rq_slen);

		status = -EAGAIN;
		if (retry++ > 50)
			break;
	}

	if (status == -EAGAIN) {
		if (test_bit(SOCK_ASYNC_NOSPACE, &xprt->sock->flags)) {
			/* Protect against races with xs_write_space */
			spin_lock_bh(&xprt->transport_lock);
			/* Don't race with disconnect */
			if (!xprt_connected(xprt))
				task->tk_status = -ENOTCONN;
			else if (test_bit(SOCK_NOSPACE, &xprt->sock->flags)) {
				task->tk_timeout = req->rq_timeout;
				rpc_sleep_on(&xprt->pending, task, NULL, NULL);
			}
			spin_unlock_bh(&xprt->transport_lock);
			return status;
		}
		/* Keep holding the socket if it is blocked */
		rpc_delay(task, HZ>>4);
	}
	return status;
}

/**
 * xs_close - close a socket
 * @xprt: transport
 *
 */
static void xs_close(struct rpc_xprt *xprt)
{
	struct socket *sock = xprt->sock;
	struct sock *sk = xprt->inet;

	if (!sk)
		return;

	dprintk("RPC:      xs_close xprt %p\n", xprt);

	write_lock_bh(&sk->sk_callback_lock);
	xprt->inet = NULL;
	xprt->sock = NULL;

	sk->sk_user_data = NULL;
	sk->sk_data_ready = xprt->old_data_ready;
	sk->sk_state_change = xprt->old_state_change;
	sk->sk_write_space = xprt->old_write_space;
	write_unlock_bh(&sk->sk_callback_lock);

	sk->sk_no_check = 0;

	sock_release(sock);
}

/**
 * xs_destroy - prepare to shutdown a transport
 * @xprt: doomed transport
 *
 */
static void xs_destroy(struct rpc_xprt *xprt)
{
	dprintk("RPC:      xs_destroy xprt %p\n", xprt);

	cancel_delayed_work(&xprt->sock_connect);
	flush_scheduled_work();

	xprt_disconnect(xprt);
	xs_close(xprt);
	kfree(xprt->slot);
}

static inline struct rpc_xprt *xprt_from_sock(struct sock *sk)
{
	return (struct rpc_xprt *) sk->sk_user_data;
}

/**
 * xs_udp_data_ready - "data ready" callback for UDP sockets
 * @sk: socket with data to read
 * @len: how much data to read
 *
 */
static void xs_udp_data_ready(struct sock *sk, int len)
{
	struct rpc_task *task;
	struct rpc_xprt *xprt;
	struct rpc_rqst *rovr;
	struct sk_buff *skb;
	int err, repsize, copied;
	u32 _xid, *xp;

	read_lock(&sk->sk_callback_lock);
	dprintk("RPC:      xs_udp_data_ready...\n");
	if (!(xprt = xprt_from_sock(sk)))
		goto out;

	if ((skb = skb_recv_datagram(sk, 0, 1, &err)) == NULL)
		goto out;

	if (xprt->shutdown)
		goto dropit;

	repsize = skb->len - sizeof(struct udphdr);
	if (repsize < 4) {
		dprintk("RPC:      impossible RPC reply size %d!\n", repsize);
		goto dropit;
	}

	/* Copy the XID from the skb... */
	xp = skb_header_pointer(skb, sizeof(struct udphdr),
				sizeof(_xid), &_xid);
	if (xp == NULL)
		goto dropit;

	/* Look up and lock the request corresponding to the given XID */
	spin_lock(&xprt->transport_lock);
	rovr = xprt_lookup_rqst(xprt, *xp);
	if (!rovr)
		goto out_unlock;
	task = rovr->rq_task;

	dprintk("RPC: %4d received reply\n", task->tk_pid);

	if ((copied = rovr->rq_private_buf.buflen) > repsize)
		copied = repsize;

	/* Suck it into the iovec, verify checksum if not done by hw. */
	if (csum_partial_copy_to_xdr(&rovr->rq_private_buf, skb))
		goto out_unlock;

	/* Something worked... */
	dst_confirm(skb->dst);

	xprt_complete_rqst(xprt, rovr, copied);

 out_unlock:
	spin_unlock(&xprt->transport_lock);
 dropit:
	skb_free_datagram(sk, skb);
 out:
	read_unlock(&sk->sk_callback_lock);
}

static inline size_t xs_tcp_copy_data(skb_reader_t *desc, void *p, size_t len)
{
	if (len > desc->count)
		len = desc->count;
	if (skb_copy_bits(desc->skb, desc->offset, p, len)) {
		dprintk("RPC:      failed to copy %zu bytes from skb. %zu bytes remain\n",
				len, desc->count);
		return 0;
	}
	desc->offset += len;
	desc->count -= len;
	dprintk("RPC:      copied %zu bytes from skb. %zu bytes remain\n",
			len, desc->count);
	return len;
}

static inline void xs_tcp_read_fraghdr(struct rpc_xprt *xprt, skb_reader_t *desc)
{
	size_t len, used;
	char *p;

	p = ((char *) &xprt->tcp_recm) + xprt->tcp_offset;
	len = sizeof(xprt->tcp_recm) - xprt->tcp_offset;
	used = xs_tcp_copy_data(desc, p, len);
	xprt->tcp_offset += used;
	if (used != len)
		return;
	xprt->tcp_reclen = ntohl(xprt->tcp_recm);
	if (xprt->tcp_reclen & 0x80000000)
		xprt->tcp_flags |= XPRT_LAST_FRAG;
	else
		xprt->tcp_flags &= ~XPRT_LAST_FRAG;
	xprt->tcp_reclen &= 0x7fffffff;
	xprt->tcp_flags &= ~XPRT_COPY_RECM;
	xprt->tcp_offset = 0;
	/* Sanity check of the record length */
	if (xprt->tcp_reclen < 4) {
		dprintk("RPC:      invalid TCP record fragment length\n");
		xprt_disconnect(xprt);
		return;
	}
	dprintk("RPC:      reading TCP record fragment of length %d\n",
			xprt->tcp_reclen);
}

static void xs_tcp_check_recm(struct rpc_xprt *xprt)
{
	dprintk("RPC:      xprt = %p, tcp_copied = %lu, tcp_offset = %u, tcp_reclen = %u, tcp_flags = %lx\n",
			xprt, xprt->tcp_copied, xprt->tcp_offset, xprt->tcp_reclen, xprt->tcp_flags);
	if (xprt->tcp_offset == xprt->tcp_reclen) {
		xprt->tcp_flags |= XPRT_COPY_RECM;
		xprt->tcp_offset = 0;
		if (xprt->tcp_flags & XPRT_LAST_FRAG) {
			xprt->tcp_flags &= ~XPRT_COPY_DATA;
			xprt->tcp_flags |= XPRT_COPY_XID;
			xprt->tcp_copied = 0;
		}
	}
}

static inline void xs_tcp_read_xid(struct rpc_xprt *xprt, skb_reader_t *desc)
{
	size_t len, used;
	char *p;

	len = sizeof(xprt->tcp_xid) - xprt->tcp_offset;
	dprintk("RPC:      reading XID (%Zu bytes)\n", len);
	p = ((char *) &xprt->tcp_xid) + xprt->tcp_offset;
	used = xs_tcp_copy_data(desc, p, len);
	xprt->tcp_offset += used;
	if (used != len)
		return;
	xprt->tcp_flags &= ~XPRT_COPY_XID;
	xprt->tcp_flags |= XPRT_COPY_DATA;
	xprt->tcp_copied = 4;
	dprintk("RPC:      reading reply for XID %08x\n",
						ntohl(xprt->tcp_xid));
	xs_tcp_check_recm(xprt);
}

static inline void xs_tcp_read_request(struct rpc_xprt *xprt, skb_reader_t *desc)
{
	struct rpc_rqst *req;
	struct xdr_buf *rcvbuf;
	size_t len;
	ssize_t r;

	/* Find and lock the request corresponding to this xid */
	spin_lock(&xprt->transport_lock);
	req = xprt_lookup_rqst(xprt, xprt->tcp_xid);
	if (!req) {
		xprt->tcp_flags &= ~XPRT_COPY_DATA;
		dprintk("RPC:      XID %08x request not found!\n",
				ntohl(xprt->tcp_xid));
		spin_unlock(&xprt->transport_lock);
		return;
	}

	rcvbuf = &req->rq_private_buf;
	len = desc->count;
	if (len > xprt->tcp_reclen - xprt->tcp_offset) {
		skb_reader_t my_desc;

		len = xprt->tcp_reclen - xprt->tcp_offset;
		memcpy(&my_desc, desc, sizeof(my_desc));
		my_desc.count = len;
		r = xdr_partial_copy_from_skb(rcvbuf, xprt->tcp_copied,
					  &my_desc, xs_tcp_copy_data);
		desc->count -= r;
		desc->offset += r;
	} else
		r = xdr_partial_copy_from_skb(rcvbuf, xprt->tcp_copied,
					  desc, xs_tcp_copy_data);

	if (r > 0) {
		xprt->tcp_copied += r;
		xprt->tcp_offset += r;
	}
	if (r != len) {
		/* Error when copying to the receive buffer,
		 * usually because we weren't able to allocate
		 * additional buffer pages. All we can do now
		 * is turn off XPRT_COPY_DATA, so the request
		 * will not receive any additional updates,
		 * and time out.
		 * Any remaining data from this record will
		 * be discarded.
		 */
		xprt->tcp_flags &= ~XPRT_COPY_DATA;
		dprintk("RPC:      XID %08x truncated request\n",
				ntohl(xprt->tcp_xid));
		dprintk("RPC:      xprt = %p, tcp_copied = %lu, tcp_offset = %u, tcp_reclen = %u\n",
				xprt, xprt->tcp_copied, xprt->tcp_offset, xprt->tcp_reclen);
		goto out;
	}

	dprintk("RPC:      XID %08x read %Zd bytes\n",
			ntohl(xprt->tcp_xid), r);
	dprintk("RPC:      xprt = %p, tcp_copied = %lu, tcp_offset = %u, tcp_reclen = %u\n",
			xprt, xprt->tcp_copied, xprt->tcp_offset, xprt->tcp_reclen);

	if (xprt->tcp_copied == req->rq_private_buf.buflen)
		xprt->tcp_flags &= ~XPRT_COPY_DATA;
	else if (xprt->tcp_offset == xprt->tcp_reclen) {
		if (xprt->tcp_flags & XPRT_LAST_FRAG)
			xprt->tcp_flags &= ~XPRT_COPY_DATA;
	}

out:
	if (!(xprt->tcp_flags & XPRT_COPY_DATA)) {
		dprintk("RPC: %4d received reply complete\n",
				req->rq_task->tk_pid);
		xprt_complete_rqst(xprt, req, xprt->tcp_copied);
	}
	spin_unlock(&xprt->transport_lock);
	xs_tcp_check_recm(xprt);
}

static inline void xs_tcp_read_discard(struct rpc_xprt *xprt, skb_reader_t *desc)
{
	size_t len;

	len = xprt->tcp_reclen - xprt->tcp_offset;
	if (len > desc->count)
		len = desc->count;
	desc->count -= len;
	desc->offset += len;
	xprt->tcp_offset += len;
	dprintk("RPC:      discarded %Zu bytes\n", len);
	xs_tcp_check_recm(xprt);
}

static int xs_tcp_data_recv(read_descriptor_t *rd_desc, struct sk_buff *skb, unsigned int offset, size_t len)
{
	struct rpc_xprt *xprt = rd_desc->arg.data;
	skb_reader_t desc = {
		.skb	= skb,
		.offset	= offset,
		.count	= len,
		.csum	= 0
	};

	dprintk("RPC:      xs_tcp_data_recv started\n");
	do {
		/* Read in a new fragment marker if necessary */
		/* Can we ever really expect to get completely empty fragments? */
		if (xprt->tcp_flags & XPRT_COPY_RECM) {
			xs_tcp_read_fraghdr(xprt, &desc);
			continue;
		}
		/* Read in the xid if necessary */
		if (xprt->tcp_flags & XPRT_COPY_XID) {
			xs_tcp_read_xid(xprt, &desc);
			continue;
		}
		/* Read in the request data */
		if (xprt->tcp_flags & XPRT_COPY_DATA) {
			xs_tcp_read_request(xprt, &desc);
			continue;
		}
		/* Skip over any trailing bytes on short reads */
		xs_tcp_read_discard(xprt, &desc);
	} while (desc.count);
	dprintk("RPC:      xs_tcp_data_recv done\n");
	return len - desc.count;
}

/**
 * xs_tcp_data_ready - "data ready" callback for TCP sockets
 * @sk: socket with data to read
 * @bytes: how much data to read
 *
 */
static void xs_tcp_data_ready(struct sock *sk, int bytes)
{
	struct rpc_xprt *xprt;
	read_descriptor_t rd_desc;

	read_lock(&sk->sk_callback_lock);
	dprintk("RPC:      xs_tcp_data_ready...\n");
	if (!(xprt = xprt_from_sock(sk)))
		goto out;
	if (xprt->shutdown)
		goto out;

	/* We use rd_desc to pass struct xprt to xs_tcp_data_recv */
	rd_desc.arg.data = xprt;
	rd_desc.count = 65536;
	tcp_read_sock(sk, &rd_desc, xs_tcp_data_recv);
out:
	read_unlock(&sk->sk_callback_lock);
}

/**
 * xs_tcp_state_change - callback to handle TCP socket state changes
 * @sk: socket whose state has changed
 *
 */
static void xs_tcp_state_change(struct sock *sk)
{
	struct rpc_xprt *xprt;

	read_lock(&sk->sk_callback_lock);
	if (!(xprt = xprt_from_sock(sk)))
		goto out;
	dprintk("RPC:      xs_tcp_state_change client %p...\n", xprt);
	dprintk("RPC:      state %x conn %d dead %d zapped %d\n",
				sk->sk_state, xprt_connected(xprt),
				sock_flag(sk, SOCK_DEAD),
				sock_flag(sk, SOCK_ZAPPED));

	switch (sk->sk_state) {
	case TCP_ESTABLISHED:
		spin_lock_bh(&xprt->transport_lock);
		if (!xprt_test_and_set_connected(xprt)) {
			/* Reset TCP record info */
			xprt->tcp_offset = 0;
			xprt->tcp_reclen = 0;
			xprt->tcp_copied = 0;
			xprt->tcp_flags = XPRT_COPY_RECM | XPRT_COPY_XID;
			rpc_wake_up(&xprt->pending);
		}
		spin_unlock_bh(&xprt->transport_lock);
		break;
	case TCP_SYN_SENT:
	case TCP_SYN_RECV:
		break;
	default:
		xprt_disconnect(xprt);
		break;
	}
 out:
	read_unlock(&sk->sk_callback_lock);
}

/**
 * xs_write_space - callback invoked when socket buffer space becomes
 *                         available
 * @sk: socket whose state has changed
 *
 * Called when more output buffer space is available for this socket.
 * We try not to wake our writers until they can make "significant"
 * progress, otherwise we'll waste resources thrashing sock_sendmsg
 * with a bunch of small requests.
 */
static void xs_write_space(struct sock *sk)
{
	struct rpc_xprt *xprt;
	struct socket *sock;

	read_lock(&sk->sk_callback_lock);
	if (!(xprt = xprt_from_sock(sk)) || !(sock = sk->sk_socket))
		goto out;
	if (xprt->shutdown)
		goto out;

	/* Wait until we have enough socket memory */
	if (xprt->stream) {
		/* from net/core/stream.c:sk_stream_write_space */
		if (sk_stream_wspace(sk) < sk_stream_min_wspace(sk))
			goto out;
	} else {
		/* from net/core/sock.c:sock_def_write_space */
		if (!sock_writeable(sk))
			goto out;
	}

	if (!test_and_clear_bit(SOCK_NOSPACE, &sock->flags))
		goto out;

	spin_lock_bh(&xprt->transport_lock);
	if (xprt->snd_task)
		rpc_wake_up_task(xprt->snd_task);
	spin_unlock_bh(&xprt->transport_lock);
out:
	read_unlock(&sk->sk_callback_lock);
}

/**
 * xs_set_buffer_size - set send and receive limits
 * @xprt: generic transport
 *
 * Set socket send and receive limits based on the
 * sndsize and rcvsize fields in the generic transport
 * structure. This applies only to UDP sockets.
 */
static void xs_set_buffer_size(struct rpc_xprt *xprt)
{
	struct sock *sk = xprt->inet;

	if (xprt->stream)
		return;
	if (xprt->rcvsize) {
		sk->sk_userlocks |= SOCK_RCVBUF_LOCK;
		sk->sk_rcvbuf = xprt->rcvsize * xprt->max_reqs *  2;
	}
	if (xprt->sndsize) {
		sk->sk_userlocks |= SOCK_SNDBUF_LOCK;
		sk->sk_sndbuf = xprt->sndsize * xprt->max_reqs * 2;
		sk->sk_write_space(sk);
	}
}

static int xs_bindresvport(struct rpc_xprt *xprt, struct socket *sock)
{
	struct sockaddr_in myaddr = {
		.sin_family = AF_INET,
	};
	int err, port;

	/* Were we already bound to a given port? Try to reuse it */
	port = xprt->port;
	do {
		myaddr.sin_port = htons(port);
		err = sock->ops->bind(sock, (struct sockaddr *) &myaddr,
						sizeof(myaddr));
		if (err == 0) {
			xprt->port = port;
			dprintk("RPC:      xs_bindresvport bound to port %u\n",
					port);
			return 0;
		}
		if (--port == 0)
			port = XS_MAX_RESVPORT;
	} while (err == -EADDRINUSE && port != xprt->port);

	dprintk("RPC:      can't bind to reserved port (%d).\n", -err);
	return err;
}

static struct socket *xs_create(struct rpc_xprt *xprt, int proto, int resvport)
{
	struct socket *sock;
	int type, err;

	dprintk("RPC:      xs_create(%s %d)\n",
			   (proto == IPPROTO_UDP)? "udp" : "tcp", proto);

	type = (proto == IPPROTO_UDP)? SOCK_DGRAM : SOCK_STREAM;

	if ((err = sock_create_kern(PF_INET, type, proto, &sock)) < 0) {
		dprintk("RPC:      can't create socket (%d).\n", -err);
		return NULL;
	}

	/* If the caller has the capability, bind to a reserved port */
	if (resvport && xs_bindresvport(xprt, sock) < 0)
		goto failed;

	return sock;

failed:
	sock_release(sock);
	return NULL;
}

static void xs_bind(struct rpc_xprt *xprt, struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (xprt->inet)
		return;

	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_user_data = xprt;
	xprt->old_data_ready = sk->sk_data_ready;
	xprt->old_state_change = sk->sk_state_change;
	xprt->old_write_space = sk->sk_write_space;
	if (xprt->prot == IPPROTO_UDP) {
		sk->sk_data_ready = xs_udp_data_ready;
		sk->sk_no_check = UDP_CSUM_NORCV;
		xprt_set_connected(xprt);
	} else {
		tcp_sk(sk)->nonagle = 1;	/* disable Nagle's algorithm */
		sk->sk_data_ready = xs_tcp_data_ready;
		sk->sk_state_change = xs_tcp_state_change;
		xprt_clear_connected(xprt);
	}
	sk->sk_write_space = xs_write_space;

	/* Reset to new socket */
	xprt->sock = sock;
	xprt->inet = sk;
	write_unlock_bh(&sk->sk_callback_lock);

	return;
}

/**
 * xs_connect_worker - try to connect a socket to a remote endpoint
 * @args: RPC transport to connect
 *
 * Invoked by a work queue tasklet.
 */
static void xs_connect_worker(void *args)
{
	struct rpc_xprt *xprt = (struct rpc_xprt *)args;
	struct socket *sock = xprt->sock;
	int status = -EIO;

	if (xprt->shutdown || xprt->addr.sin_port == 0)
		goto out;

	dprintk("RPC:      xs_connect_worker xprt %p\n", xprt);

	/*
	 * Start by resetting any existing state
	 */
	xs_close(xprt);
	sock = xs_create(xprt, xprt->prot, xprt->resvport);
	if (sock == NULL) {
		/* couldn't create socket or bind to reserved port;
		 * this is likely a permanent error, so cause an abort */
		goto out;
	}
	xs_bind(xprt, sock);
	xs_set_buffer_size(xprt);

	status = 0;
	if (!xprt->stream)
		goto out;

	/*
	 * Tell the socket layer to start connecting...
	 */
	status = sock->ops->connect(sock, (struct sockaddr *) &xprt->addr,
			sizeof(xprt->addr), O_NONBLOCK);
	dprintk("RPC: %p  connect status %d connected %d sock state %d\n",
			xprt, -status, xprt_connected(xprt), sock->sk->sk_state);
	if (status < 0) {
		switch (status) {
			case -EINPROGRESS:
			case -EALREADY:
				goto out_clear;
		}
	}
out:
	if (status < 0)
		rpc_wake_up_status(&xprt->pending, status);
	else
		rpc_wake_up(&xprt->pending);
out_clear:
	xprt_clear_connecting(xprt);
}

/**
 * xs_connect - connect a socket to a remote endpoint
 * @task: address of RPC task that manages state of connect request
 *
 * TCP: If the remote end dropped the connection, delay reconnecting.
 */
static void xs_connect(struct rpc_task *task)
{
	struct rpc_xprt *xprt = task->tk_xprt;

	if (!xprt_test_and_set_connecting(xprt)) {
		if (xprt->sock != NULL) {
			dprintk("RPC:      xs_connect delayed xprt %p\n", xprt);
			schedule_delayed_work(&xprt->sock_connect,
					RPC_REESTABLISH_TIMEOUT);
		} else {
			dprintk("RPC:      xs_connect scheduled xprt %p\n", xprt);
			schedule_work(&xprt->sock_connect);
			/* flush_scheduled_work can sleep... */
			if (!RPC_IS_ASYNC(task))
				flush_scheduled_work();
		}
	}
}

static struct rpc_xprt_ops xs_ops = {
	.set_buffer_size	= xs_set_buffer_size,
	.connect		= xs_connect,
	.send_request		= xs_send_request,
	.close			= xs_close,
	.destroy		= xs_destroy,
};

extern unsigned int xprt_udp_slot_table_entries;
extern unsigned int xprt_tcp_slot_table_entries;

/**
 * xs_setup_udp - Set up transport to use a UDP socket
 * @xprt: transport to set up
 * @to:   timeout parameters
 *
 */
int xs_setup_udp(struct rpc_xprt *xprt, struct rpc_timeout *to)
{
	size_t slot_table_size;

	dprintk("RPC:      setting up udp-ipv4 transport...\n");

	xprt->max_reqs = xprt_udp_slot_table_entries;
	slot_table_size = xprt->max_reqs * sizeof(xprt->slot[0]);
	xprt->slot = kmalloc(slot_table_size, GFP_KERNEL);
	if (xprt->slot == NULL)
		return -ENOMEM;
	memset(xprt->slot, 0, slot_table_size);

	xprt->prot = IPPROTO_UDP;
	xprt->port = XS_MAX_RESVPORT;
	xprt->stream = 0;
	xprt->nocong = 0;
	xprt->cwnd = RPC_INITCWND;
	xprt->resvport = capable(CAP_NET_BIND_SERVICE) ? 1 : 0;
	/* XXX: header size can vary due to auth type, IPv6, etc. */
	xprt->max_payload = (1U << 16) - (MAX_HEADER << 3);

	INIT_WORK(&xprt->sock_connect, xs_connect_worker, xprt);

	xprt->ops = &xs_ops;

	if (to)
		xprt->timeout = *to;
	else
		xprt_set_timeout(&xprt->timeout, 5, 5 * HZ);

	return 0;
}

/**
 * xs_setup_tcp - Set up transport to use a TCP socket
 * @xprt: transport to set up
 * @to: timeout parameters
 *
 */
int xs_setup_tcp(struct rpc_xprt *xprt, struct rpc_timeout *to)
{
	size_t slot_table_size;

	dprintk("RPC:      setting up tcp-ipv4 transport...\n");

	xprt->max_reqs = xprt_tcp_slot_table_entries;
	slot_table_size = xprt->max_reqs * sizeof(xprt->slot[0]);
	xprt->slot = kmalloc(slot_table_size, GFP_KERNEL);
	if (xprt->slot == NULL)
		return -ENOMEM;
	memset(xprt->slot, 0, slot_table_size);

	xprt->prot = IPPROTO_TCP;
	xprt->port = XS_MAX_RESVPORT;
	xprt->stream = 1;
	xprt->nocong = 1;
	xprt->cwnd = RPC_MAXCWND(xprt);
	xprt->resvport = capable(CAP_NET_BIND_SERVICE) ? 1 : 0;
	xprt->max_payload = (1U << 31) - 1;

	INIT_WORK(&xprt->sock_connect, xs_connect_worker, xprt);

	xprt->ops = &xs_ops;

	if (to)
		xprt->timeout = *to;
	else
		xprt_set_timeout(&xprt->timeout, 2, 60 * HZ);

	return 0;
}
