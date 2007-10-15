#ifndef __NET_FRAG_H__
#define __NET_FRAG_H__

struct inet_frag_queue {
	struct hlist_node	list;
	struct list_head	lru_list;   /* lru list member */
	spinlock_t		lock;
	atomic_t		refcnt;
	struct timer_list	timer;      /* when will this queue expire? */
	struct sk_buff		*fragments; /* list of received fragments */
	ktime_t			stamp;
	int			len;        /* total length of orig datagram */
	int			meat;
	__u8			last_in;    /* first/last segment arrived? */

#define COMPLETE		4
#define FIRST_IN		2
#define LAST_IN			1
};

#define INETFRAGS_HASHSZ		64

struct inet_frags_ctl {
	int high_thresh;
	int low_thresh;
	int timeout;
	int secret_interval;
};

struct inet_frags {
	struct list_head	lru_list;
	struct hlist_head	hash[INETFRAGS_HASHSZ];
	rwlock_t		lock;
	u32			rnd;
	int			nqueues;
	atomic_t		mem;
	struct timer_list	secret_timer;
	struct inet_frags_ctl	*ctl;
};

void inet_frags_init(struct inet_frags *);
void inet_frags_fini(struct inet_frags *);

void inet_frag_kill(struct inet_frag_queue *q, struct inet_frags *f);

#endif
