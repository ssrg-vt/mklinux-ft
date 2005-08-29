/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the BSD Socket
 *		interface as the means of communication with the user level.
 *
 * Authors:	Lotsa people, from code originally in tcp
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _INET_HASHTABLES_H
#define _INET_HASHTABLES_H

#include <linux/ip.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>

/* This is for all connections with a full identity, no wildcards.
 * New scheme, half the table is for TIME_WAIT, the other half is
 * for the rest.  I'll experiment with dynamic table growth later.
 */
struct inet_ehash_bucket {
	rwlock_t	  lock;
	struct hlist_head chain;
} __attribute__((__aligned__(8)));

/* There are a few simple rules, which allow for local port reuse by
 * an application.  In essence:
 *
 *	1) Sockets bound to different interfaces may share a local port.
 *	   Failing that, goto test 2.
 *	2) If all sockets have sk->sk_reuse set, and none of them are in
 *	   TCP_LISTEN state, the port may be shared.
 *	   Failing that, goto test 3.
 *	3) If all sockets are bound to a specific inet_sk(sk)->rcv_saddr local
 *	   address, and none of them are the same, the port may be
 *	   shared.
 *	   Failing this, the port cannot be shared.
 *
 * The interesting point, is test #2.  This is what an FTP server does
 * all day.  To optimize this case we use a specific flag bit defined
 * below.  As we add sockets to a bind bucket list, we perform a
 * check of: (newsk->sk_reuse && (newsk->sk_state != TCP_LISTEN))
 * As long as all sockets added to a bind bucket pass this test,
 * the flag bit will be set.
 * The resulting situation is that tcp_v[46]_verify_bind() can just check
 * for this flag bit, if it is set and the socket trying to bind has
 * sk->sk_reuse set, we don't even have to walk the owners list at all,
 * we return that it is ok to bind this socket to the requested local port.
 *
 * Sounds like a lot of work, but it is worth it.  In a more naive
 * implementation (ie. current FreeBSD etc.) the entire list of ports
 * must be walked for each data port opened by an ftp server.  Needless
 * to say, this does not scale at all.  With a couple thousand FTP
 * users logged onto your box, isn't it nice to know that new data
 * ports are created in O(1) time?  I thought so. ;-)	-DaveM
 */
struct inet_bind_bucket {
	unsigned short		port;
	signed short		fastreuse;
	struct hlist_node	node;
	struct hlist_head	owners;
};

#define inet_bind_bucket_for_each(tb, node, head) \
	hlist_for_each_entry(tb, node, head, node)

struct inet_bind_hashbucket {
	spinlock_t		lock;
	struct hlist_head	chain;
};

/* This is for listening sockets, thus all sockets which possess wildcards. */
#define INET_LHTABLE_SIZE	32	/* Yes, really, this is all you need. */

struct inet_hashinfo {
	/* This is for sockets with full identity only.  Sockets here will
	 * always be without wildcards and will have the following invariant:
	 *
	 *          TCP_ESTABLISHED <= sk->sk_state < TCP_CLOSE
	 *
	 * First half of the table is for sockets not in TIME_WAIT, second half
	 * is for TIME_WAIT sockets only.
	 */
	struct inet_ehash_bucket	*ehash;

	/* Ok, let's try this, I give up, we do need a local binding
	 * TCP hash as well as the others for fast bind/connect.
	 */
	struct inet_bind_hashbucket	*bhash;

	int				bhash_size;
	int				ehash_size;

	/* All sockets in TCP_LISTEN state will be in here.  This is the only
	 * table where wildcard'd TCP sockets can exist.  Hash function here
	 * is just local port number.
	 */
	struct hlist_head		listening_hash[INET_LHTABLE_SIZE];

	/* All the above members are written once at bootup and
	 * never written again _or_ are predominantly read-access.
	 *
	 * Now align to a new cache line as all the following members
	 * are often dirty.
	 */
	rwlock_t			lhash_lock ____cacheline_aligned;
	atomic_t			lhash_users;
	wait_queue_head_t		lhash_wait;
	spinlock_t			portalloc_lock;
};

static inline int inet_ehashfn(const __u32 laddr, const __u16 lport,
			       const __u32 faddr, const __u16 fport,
			       const int ehash_size)
{
	int h = (laddr ^ lport) ^ (faddr ^ fport);
	h ^= h >> 16;
	h ^= h >> 8;
	return h & (ehash_size - 1);
}

static inline int inet_sk_ehashfn(const struct sock *sk, const int ehash_size)
{
	const struct inet_sock *inet = inet_sk(sk);
	const __u32 laddr = inet->rcv_saddr;
	const __u16 lport = inet->num;
	const __u32 faddr = inet->daddr;
	const __u16 fport = inet->dport;

	return inet_ehashfn(laddr, lport, faddr, fport, ehash_size);
}

extern struct inet_bind_bucket *
		    inet_bind_bucket_create(kmem_cache_t *cachep,
					    struct inet_bind_hashbucket *head,
					    const unsigned short snum);
extern void inet_bind_bucket_destroy(kmem_cache_t *cachep,
				     struct inet_bind_bucket *tb);

static inline int inet_bhashfn(const __u16 lport, const int bhash_size)
{
	return lport & (bhash_size - 1);
}

/* These can have wildcards, don't try too hard. */
static inline int inet_lhashfn(const unsigned short num)
{
	return num & (INET_LHTABLE_SIZE - 1);
}

static inline int inet_sk_listen_hashfn(const struct sock *sk)
{
	return inet_lhashfn(inet_sk(sk)->num);
}

#endif /* _INET_HASHTABLES_H */
