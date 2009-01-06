/*
 * linux/fs/lockd/mon.c
 *
 * The kernel statd client.
 *
 * Copyright (C) 1996, Olaf Kirch <okir@monad.swb.de>
 */

#include <linux/types.h>
#include <linux/utsname.h>
#include <linux/kernel.h>
#include <linux/sunrpc/clnt.h>
#include <linux/sunrpc/xprtsock.h>
#include <linux/sunrpc/svc.h>
#include <linux/lockd/lockd.h>
#include <linux/lockd/sm_inter.h>


#define NLMDBG_FACILITY		NLMDBG_MONITOR
#define NSM_PROGRAM		100024
#define NSM_VERSION		1

enum {
	NSMPROC_NULL,
	NSMPROC_STAT,
	NSMPROC_MON,
	NSMPROC_UNMON,
	NSMPROC_UNMON_ALL,
	NSMPROC_SIMU_CRASH,
	NSMPROC_NOTIFY,
};

struct nsm_args {
	__be32			addr;		/* remote address */
	u32			prog;		/* RPC callback info */
	u32			vers;
	u32			proc;

	char			*mon_name;
};

struct nsm_res {
	u32			status;
	u32			state;
};

static struct rpc_clnt *	nsm_create(void);

static struct rpc_program	nsm_program;
static				LIST_HEAD(nsm_handles);
static				DEFINE_SPINLOCK(nsm_lock);

/*
 * Local NSM state
 */
int				nsm_local_state;

static void nsm_display_ipv4_address(const struct sockaddr *sap, char *buf,
				     const size_t len)
{
	const struct sockaddr_in *sin = (struct sockaddr_in *)sap;
	snprintf(buf, len, "%pI4", &sin->sin_addr.s_addr);
}

static void nsm_display_ipv6_address(const struct sockaddr *sap, char *buf,
				     const size_t len)
{
	const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sap;

	if (ipv6_addr_v4mapped(&sin6->sin6_addr))
		snprintf(buf, len, "%pI4", &sin6->sin6_addr.s6_addr32[3]);
	else if (sin6->sin6_scope_id != 0)
		snprintf(buf, len, "%pI6%%%u", &sin6->sin6_addr,
				sin6->sin6_scope_id);
	else
		snprintf(buf, len, "%pI6", &sin6->sin6_addr);
}

static void nsm_display_address(const struct sockaddr *sap,
				char *buf, const size_t len)
{
	switch (sap->sa_family) {
	case AF_INET:
		nsm_display_ipv4_address(sap, buf, len);
		break;
	case AF_INET6:
		nsm_display_ipv6_address(sap, buf, len);
		break;
	default:
		snprintf(buf, len, "unsupported address family");
		break;
	}
}

/*
 * Common procedure for NSMPROC_MON/NSMPROC_UNMON calls
 */
static int
nsm_mon_unmon(struct nsm_handle *nsm, u32 proc, struct nsm_res *res)
{
	struct rpc_clnt	*clnt;
	int		status;
	struct nsm_args args = {
		.addr		= nsm_addr_in(nsm)->sin_addr.s_addr,
		.prog		= NLM_PROGRAM,
		.vers		= 3,
		.proc		= NLMPROC_NSM_NOTIFY,
		.mon_name	= nsm->sm_mon_name,
	};
	struct rpc_message msg = {
		.rpc_argp	= &args,
		.rpc_resp	= res,
	};

	clnt = nsm_create();
	if (IS_ERR(clnt)) {
		status = PTR_ERR(clnt);
		dprintk("lockd: failed to create NSM upcall transport, "
				"status=%d\n", status);
		goto out;
	}

	memset(res, 0, sizeof(*res));

	msg.rpc_proc = &clnt->cl_procinfo[proc];
	status = rpc_call_sync(clnt, &msg, 0);
	if (status < 0)
		dprintk("lockd: NSM upcall RPC failed, status=%d\n",
				status);
	else
		status = 0;
	rpc_shutdown_client(clnt);
 out:
	return status;
}

/**
 * nsm_monitor - Notify a peer in case we reboot
 * @host: pointer to nlm_host of peer to notify
 *
 * If this peer is not already monitored, this function sends an
 * upcall to the local rpc.statd to record the name/address of
 * the peer to notify in case we reboot.
 *
 * Returns zero if the peer is monitored by the local rpc.statd;
 * otherwise a negative errno value is returned.
 */
int nsm_monitor(const struct nlm_host *host)
{
	struct nsm_handle *nsm = host->h_nsmhandle;
	struct nsm_res	res;
	int		status;

	dprintk("lockd: nsm_monitor(%s)\n", nsm->sm_name);

	if (nsm->sm_monitored)
		return 0;

	/*
	 * Choose whether to record the caller_name or IP address of
	 * this peer in the local rpc.statd's database.
	 */
	nsm->sm_mon_name = nsm_use_hostnames ? nsm->sm_name : nsm->sm_addrbuf;

	status = nsm_mon_unmon(nsm, NSMPROC_MON, &res);
	if (res.status != 0)
		status = -EIO;
	if (status < 0)
		printk(KERN_NOTICE "lockd: cannot monitor %s\n", nsm->sm_name);
	else
		nsm->sm_monitored = 1;
	return status;
}

/**
 * nsm_unmonitor - Unregister peer notification
 * @host: pointer to nlm_host of peer to stop monitoring
 *
 * If this peer is monitored, this function sends an upcall to
 * tell the local rpc.statd not to send this peer a notification
 * when we reboot.
 */
void nsm_unmonitor(const struct nlm_host *host)
{
	struct nsm_handle *nsm = host->h_nsmhandle;
	struct nsm_res	res;
	int status;

	if (atomic_read(&nsm->sm_count) == 1
	 && nsm->sm_monitored && !nsm->sm_sticky) {
		dprintk("lockd: nsm_unmonitor(%s)\n", nsm->sm_name);

		status = nsm_mon_unmon(nsm, NSMPROC_UNMON, &res);
		if (res.status != 0)
			status = -EIO;
		if (status < 0)
			printk(KERN_NOTICE "lockd: cannot unmonitor %s\n",
					nsm->sm_name);
		else
			nsm->sm_monitored = 0;
	}
}

/**
 * nsm_find - Find or create a cached nsm_handle
 * @sap: pointer to socket address of handle to find
 * @salen: length of socket address
 * @hostname: pointer to C string containing hostname to find
 * @hostname_len: length of C string
 * @create: one means create new handle if not found in cache
 *
 * Behavior is modulated by the global nsm_use_hostnames variable
 * and by the @create argument.
 *
 * Returns a cached nsm_handle after bumping its ref count, or if
 * @create is set, returns a fresh nsm_handle if a handle that
 * matches @sap and/or @hostname cannot be found in the handle cache.
 * Returns NULL if an error occurs.
 */
struct nsm_handle *nsm_find(const struct sockaddr *sap, const size_t salen,
			    const char *hostname, const size_t hostname_len,
			    const int create)
{
	struct nsm_handle *nsm = NULL;
	struct nsm_handle *pos;

	if (hostname && memchr(hostname, '/', hostname_len) != NULL) {
		if (printk_ratelimit()) {
			printk(KERN_WARNING "Invalid hostname \"%.*s\" "
					    "in NFS lock request\n",
				(int)hostname_len, hostname);
		}
		return NULL;
	}

retry:
	spin_lock(&nsm_lock);
	list_for_each_entry(pos, &nsm_handles, sm_link) {

		if (hostname && nsm_use_hostnames) {
			if (strlen(pos->sm_name) != hostname_len
			 || memcmp(pos->sm_name, hostname, hostname_len))
				continue;
		} else if (!nlm_cmp_addr(nsm_addr(pos), sap))
			continue;
		atomic_inc(&pos->sm_count);
		kfree(nsm);
		nsm = pos;
		dprintk("lockd: found nsm_handle for %s (%s), cnt %d\n",
				pos->sm_name, pos->sm_addrbuf,
				atomic_read(&pos->sm_count));
		goto found;
	}
	if (nsm) {
		list_add(&nsm->sm_link, &nsm_handles);
		dprintk("lockd: created nsm_handle for %s (%s)\n",
				nsm->sm_name, nsm->sm_addrbuf);
		goto found;
	}
	spin_unlock(&nsm_lock);

	if (!create)
		return NULL;

	nsm = kzalloc(sizeof(*nsm) + hostname_len + 1, GFP_KERNEL);
	if (nsm == NULL)
		return NULL;

	memcpy(nsm_addr(nsm), sap, salen);
	nsm->sm_addrlen = salen;
	nsm->sm_name = (char *) (nsm + 1);
	memcpy(nsm->sm_name, hostname, hostname_len);
	nsm->sm_name[hostname_len] = '\0';
	nsm_display_address((struct sockaddr *)&nsm->sm_addr,
				nsm->sm_addrbuf, sizeof(nsm->sm_addrbuf));
	atomic_set(&nsm->sm_count, 1);
	goto retry;

found:
	spin_unlock(&nsm_lock);
	return nsm;
}

/**
 * nsm_release - Release an NSM handle
 * @nsm: pointer to handle to be released
 *
 */
void nsm_release(struct nsm_handle *nsm)
{
	if (!nsm)
		return;
	if (atomic_dec_and_lock(&nsm->sm_count, &nsm_lock)) {
		list_del(&nsm->sm_link);
		spin_unlock(&nsm_lock);
		dprintk("lockd: destroyed nsm_handle for %s (%s)\n",
				nsm->sm_name, nsm->sm_addrbuf);
		kfree(nsm);
	}
}

/*
 * Create NSM client for the local host
 */
static struct rpc_clnt *
nsm_create(void)
{
	struct sockaddr_in	sin = {
		.sin_family	= AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port	= 0,
	};
	struct rpc_create_args args = {
		.protocol	= XPRT_TRANSPORT_UDP,
		.address	= (struct sockaddr *)&sin,
		.addrsize	= sizeof(sin),
		.servername	= "localhost",
		.program	= &nsm_program,
		.version	= NSM_VERSION,
		.authflavor	= RPC_AUTH_NULL,
	};

	return rpc_create(&args);
}

/*
 * XDR functions for NSM.
 *
 * See http://www.opengroup.org/ for details on the Network
 * Status Monitor wire protocol.
 */

static int encode_nsm_string(struct xdr_stream *xdr, const char *string)
{
	const u32 len = strlen(string);
	__be32 *p;

	if (unlikely(len > SM_MAXSTRLEN))
		return -EIO;
	p = xdr_reserve_space(xdr, sizeof(u32) + len);
	if (unlikely(p == NULL))
		return -EIO;
	xdr_encode_opaque(p, string, len);
	return 0;
}

/*
 * "mon_name" specifies the host to be monitored.
 */
static int encode_mon_name(struct xdr_stream *xdr, const struct nsm_args *argp)
{
	return encode_nsm_string(xdr, argp->mon_name);
}

/*
 * The "my_id" argument specifies the hostname and RPC procedure
 * to be called when the status manager receives notification
 * (via the NLMPROC_SM_NOTIFY call) that the state of host "mon_name"
 * has changed.
 */
static int encode_my_id(struct xdr_stream *xdr, const struct nsm_args *argp)
{
	int status;
	__be32 *p;

	status = encode_nsm_string(xdr, utsname()->nodename);
	if (unlikely(status != 0))
		return status;
	p = xdr_reserve_space(xdr, 3 * sizeof(u32));
	if (unlikely(p == NULL))
		return -EIO;
	*p++ = htonl(argp->prog);
	*p++ = htonl(argp->vers);
	*p++ = htonl(argp->proc);
	return 0;
}

/*
 * The "mon_id" argument specifies the non-private arguments
 * of an NSMPROC_MON or NSMPROC_UNMON call.
 */
static int encode_mon_id(struct xdr_stream *xdr, const struct nsm_args *argp)
{
	int status;

	status = encode_mon_name(xdr, argp);
	if (unlikely(status != 0))
		return status;
	return encode_my_id(xdr, argp);
}

/*
 * The "priv" argument may contain private information required
 * by the NSMPROC_MON call. This information will be supplied in the
 * NLMPROC_SM_NOTIFY call.
 *
 * Linux provides the raw IP address of the monitored host,
 * left in network byte order.
 */
static int encode_priv(struct xdr_stream *xdr, const struct nsm_args *argp)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, SM_PRIV_SIZE);
	if (unlikely(p == NULL))
		return -EIO;
	*p++ = argp->addr;
	*p++ = 0;
	*p++ = 0;
	*p++ = 0;
	return 0;
}

static int xdr_enc_mon(struct rpc_rqst *req, __be32 *p,
		       const struct nsm_args *argp)
{
	struct xdr_stream xdr;
	int status;

	xdr_init_encode(&xdr, &req->rq_snd_buf, p);
	status = encode_mon_id(&xdr, argp);
	if (unlikely(status))
		return status;
	return encode_priv(&xdr, argp);
}

static int xdr_enc_unmon(struct rpc_rqst *req, __be32 *p,
			 const struct nsm_args *argp)
{
	struct xdr_stream xdr;

	xdr_init_encode(&xdr, &req->rq_snd_buf, p);
	return encode_mon_id(&xdr, argp);
}

static int xdr_dec_stat_res(struct rpc_rqst *rqstp, __be32 *p,
			    struct nsm_res *resp)
{
	struct xdr_stream xdr;

	xdr_init_decode(&xdr, &rqstp->rq_rcv_buf, p);
	p = xdr_inline_decode(&xdr, 2 * sizeof(u32));
	if (unlikely(p == NULL))
		return -EIO;
	resp->status = ntohl(*p++);
	resp->state = ntohl(*p);

	dprintk("lockd: xdr_dec_stat_res status %d state %d\n",
			resp->status, resp->state);
	return 0;
}

static int xdr_dec_stat(struct rpc_rqst *rqstp, __be32 *p,
			struct nsm_res *resp)
{
	struct xdr_stream xdr;

	xdr_init_decode(&xdr, &rqstp->rq_rcv_buf, p);
	p = xdr_inline_decode(&xdr, sizeof(u32));
	if (unlikely(p == NULL))
		return -EIO;
	resp->state = ntohl(*p);

	dprintk("lockd: xdr_dec_stat state %d\n", resp->state);
	return 0;
}

#define SM_my_name_sz	(1+XDR_QUADLEN(SM_MAXSTRLEN))
#define SM_my_id_sz	(SM_my_name_sz+3)
#define SM_mon_name_sz	(1+XDR_QUADLEN(SM_MAXSTRLEN))
#define SM_mon_id_sz	(SM_mon_name_sz+SM_my_id_sz)
#define SM_priv_sz	(XDR_QUADLEN(SM_PRIV_SIZE))
#define SM_mon_sz	(SM_mon_id_sz+SM_priv_sz)
#define SM_monres_sz	2
#define SM_unmonres_sz	1

static struct rpc_procinfo	nsm_procedures[] = {
[NSMPROC_MON] = {
		.p_proc		= NSMPROC_MON,
		.p_encode	= (kxdrproc_t)xdr_enc_mon,
		.p_decode	= (kxdrproc_t)xdr_dec_stat_res,
		.p_arglen	= SM_mon_sz,
		.p_replen	= SM_monres_sz,
		.p_statidx	= NSMPROC_MON,
		.p_name		= "MONITOR",
	},
[NSMPROC_UNMON] = {
		.p_proc		= NSMPROC_UNMON,
		.p_encode	= (kxdrproc_t)xdr_enc_unmon,
		.p_decode	= (kxdrproc_t)xdr_dec_stat,
		.p_arglen	= SM_mon_id_sz,
		.p_replen	= SM_unmonres_sz,
		.p_statidx	= NSMPROC_UNMON,
		.p_name		= "UNMONITOR",
	},
};

static struct rpc_version	nsm_version1 = {
		.number		= 1,
		.nrprocs	= ARRAY_SIZE(nsm_procedures),
		.procs		= nsm_procedures
};

static struct rpc_version *	nsm_version[] = {
	[1] = &nsm_version1,
};

static struct rpc_stat		nsm_stats;

static struct rpc_program	nsm_program = {
		.name		= "statd",
		.number		= NSM_PROGRAM,
		.nrvers		= ARRAY_SIZE(nsm_version),
		.version	= nsm_version,
		.stats		= &nsm_stats
};
