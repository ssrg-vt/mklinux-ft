/* Helper handling for netfilter. */

/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2006 Netfilter Core Team <coreteam@netfilter.org>
 * (C) 2003,2004 USAGI/WIDE Project <http://www.linux-ipv6.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_extend.h>

static __read_mostly LIST_HEAD(helpers);

struct nf_conntrack_helper *
__nf_ct_helper_find(const struct nf_conntrack_tuple *tuple)
{
	struct nf_conntrack_helper *h;
	struct nf_conntrack_tuple_mask mask = { .src.u.all = htons(0xFFFF) };

	list_for_each_entry(h, &helpers, list) {
		if (nf_ct_tuple_src_mask_cmp(tuple, &h->tuple, &mask))
			return h;
	}
	return NULL;
}

struct nf_conntrack_helper *
nf_ct_helper_find_get( const struct nf_conntrack_tuple *tuple)
{
	struct nf_conntrack_helper *helper;

	/* need nf_conntrack_lock to assure that helper exists until
	 * try_module_get() is called */
	read_lock_bh(&nf_conntrack_lock);

	helper = __nf_ct_helper_find(tuple);
	if (helper) {
		/* need to increase module usage count to assure helper will
		 * not go away while the caller is e.g. busy putting a
		 * conntrack in the hash that uses the helper */
		if (!try_module_get(helper->me))
			helper = NULL;
	}

	read_unlock_bh(&nf_conntrack_lock);

	return helper;
}
EXPORT_SYMBOL_GPL(nf_ct_helper_find_get);

void nf_ct_helper_put(struct nf_conntrack_helper *helper)
{
	module_put(helper->me);
}
EXPORT_SYMBOL_GPL(nf_ct_helper_put);

struct nf_conntrack_helper *
__nf_conntrack_helper_find_byname(const char *name)
{
	struct nf_conntrack_helper *h;

	list_for_each_entry(h, &helpers, list) {
		if (!strcmp(h->name, name))
			return h;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(__nf_conntrack_helper_find_byname);

struct nf_conn_help *nf_ct_helper_ext_add(struct nf_conn *ct, gfp_t gfp)
{
	struct nf_conn_help *help;

	help = nf_ct_ext_add(ct, NF_CT_EXT_HELPER, gfp);
	if (help)
		INIT_HLIST_HEAD(&help->expectations);
	else
		pr_debug("failed to add helper extension area");
	return help;
}
EXPORT_SYMBOL_GPL(nf_ct_helper_ext_add);

static inline int unhelp(struct nf_conntrack_tuple_hash *i,
			 const struct nf_conntrack_helper *me)
{
	struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(i);
	struct nf_conn_help *help = nfct_help(ct);

	if (help && help->helper == me) {
		nf_conntrack_event(IPCT_HELPER, ct);
		rcu_assign_pointer(help->helper, NULL);
	}
	return 0;
}

int nf_conntrack_helper_register(struct nf_conntrack_helper *me)
{
	BUG_ON(me->timeout == 0);

	write_lock_bh(&nf_conntrack_lock);
	list_add(&me->list, &helpers);
	write_unlock_bh(&nf_conntrack_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(nf_conntrack_helper_register);

void nf_conntrack_helper_unregister(struct nf_conntrack_helper *me)
{
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_expect *exp;
	struct hlist_node *n, *next;
	unsigned int i;

	/* Need write lock here, to delete helper. */
	write_lock_bh(&nf_conntrack_lock);
	list_del(&me->list);

	/* Get rid of expectations */
	for (i = 0; i < nf_ct_expect_hsize; i++) {
		hlist_for_each_entry_safe(exp, n, next,
					  &nf_ct_expect_hash[i], hnode) {
			struct nf_conn_help *help = nfct_help(exp->master);
			if ((help->helper == me || exp->helper == me) &&
			    del_timer(&exp->timeout)) {
				nf_ct_unlink_expect(exp);
				nf_ct_expect_put(exp);
			}
		}
	}

	/* Get rid of expecteds, set helpers to NULL. */
	hlist_for_each_entry(h, n, &unconfirmed, hnode)
		unhelp(h, me);
	for (i = 0; i < nf_conntrack_htable_size; i++) {
		hlist_for_each_entry(h, n, &nf_conntrack_hash[i], hnode)
			unhelp(h, me);
	}
	write_unlock_bh(&nf_conntrack_lock);

	/* Someone could be still looking at the helper in a bh. */
	synchronize_net();
}
EXPORT_SYMBOL_GPL(nf_conntrack_helper_unregister);

static struct nf_ct_ext_type helper_extend __read_mostly = {
	.len	= sizeof(struct nf_conn_help),
	.align	= __alignof__(struct nf_conn_help),
	.id	= NF_CT_EXT_HELPER,
};

int nf_conntrack_helper_init()
{
	return nf_ct_extend_register(&helper_extend);
}

void nf_conntrack_helper_fini()
{
	nf_ct_extend_unregister(&helper_extend);
}
