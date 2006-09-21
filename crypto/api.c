/*
 * Scatterlist Cryptographic API.
 *
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * Copyright (c) 2002 David S. Miller (davem@redhat.com)
 * Copyright (c) 2005 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * Portions derived from Cryptoapi, by Alexander Kjeldaas <astor@fast.no>
 * and Nettle, by Niels M�ller.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/param.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "internal.h"

LIST_HEAD(crypto_alg_list);
EXPORT_SYMBOL_GPL(crypto_alg_list);
DECLARE_RWSEM(crypto_alg_sem);
EXPORT_SYMBOL_GPL(crypto_alg_sem);

BLOCKING_NOTIFIER_HEAD(crypto_chain);
EXPORT_SYMBOL_GPL(crypto_chain);

static inline struct crypto_alg *crypto_alg_get(struct crypto_alg *alg)
{
	atomic_inc(&alg->cra_refcnt);
	return alg;
}

static inline void crypto_alg_put(struct crypto_alg *alg)
{
	if (atomic_dec_and_test(&alg->cra_refcnt) && alg->cra_destroy)
		alg->cra_destroy(alg);
}

struct crypto_alg *crypto_mod_get(struct crypto_alg *alg)
{
	return try_module_get(alg->cra_module) ? crypto_alg_get(alg) : NULL;
}
EXPORT_SYMBOL_GPL(crypto_mod_get);

void crypto_mod_put(struct crypto_alg *alg)
{
	crypto_alg_put(alg);
	module_put(alg->cra_module);
}
EXPORT_SYMBOL_GPL(crypto_mod_put);

struct crypto_alg *__crypto_alg_lookup(const char *name)
{
	struct crypto_alg *q, *alg = NULL;
	int best = -2;

	list_for_each_entry(q, &crypto_alg_list, cra_list) {
		int exact, fuzzy;

		exact = !strcmp(q->cra_driver_name, name);
		fuzzy = !strcmp(q->cra_name, name);
		if (!exact && !(fuzzy && q->cra_priority > best))
			continue;

		if (unlikely(!crypto_mod_get(q)))
			continue;

		best = q->cra_priority;
		if (alg)
			crypto_mod_put(alg);
		alg = q;

		if (exact)
			break;
	}

	return alg;
}
EXPORT_SYMBOL_GPL(__crypto_alg_lookup);

static void crypto_larval_destroy(struct crypto_alg *alg)
{
	struct crypto_larval *larval = (void *)alg;

	BUG_ON(!crypto_is_larval(alg));
	if (larval->adult)
		crypto_mod_put(larval->adult);
	kfree(larval);
}

static struct crypto_alg *crypto_larval_alloc(const char *name)
{
	struct crypto_alg *alg;
	struct crypto_larval *larval;

	larval = kzalloc(sizeof(*larval), GFP_KERNEL);
	if (!larval)
		return NULL;

	larval->alg.cra_flags = CRYPTO_ALG_LARVAL;
	larval->alg.cra_priority = -1;
	larval->alg.cra_destroy = crypto_larval_destroy;

	atomic_set(&larval->alg.cra_refcnt, 2);
	strlcpy(larval->alg.cra_name, name, CRYPTO_MAX_ALG_NAME);
	init_completion(&larval->completion);

	down_write(&crypto_alg_sem);
	alg = __crypto_alg_lookup(name);
	if (!alg) {
		alg = &larval->alg;
		list_add(&alg->cra_list, &crypto_alg_list);
	}
	up_write(&crypto_alg_sem);

	if (alg != &larval->alg)
		kfree(larval);

	return alg;
}

static void crypto_larval_kill(struct crypto_alg *alg)
{
	struct crypto_larval *larval = (void *)alg;

	down_write(&crypto_alg_sem);
	list_del(&alg->cra_list);
	up_write(&crypto_alg_sem);
	complete(&larval->completion);
	crypto_alg_put(alg);
}

static struct crypto_alg *crypto_larval_wait(struct crypto_alg *alg)
{
	struct crypto_larval *larval = (void *)alg;

	wait_for_completion_interruptible_timeout(&larval->completion, 60 * HZ);
	alg = larval->adult;
	if (alg && !crypto_mod_get(alg))
		alg = NULL;
	crypto_mod_put(&larval->alg);

	return alg;
}

static struct crypto_alg *crypto_alg_lookup(const char *name)
{
	struct crypto_alg *alg;

	if (!name)
		return NULL;

	down_read(&crypto_alg_sem);
	alg = __crypto_alg_lookup(name);
	up_read(&crypto_alg_sem);

	return alg;
}

/* A far more intelligent version of this is planned.  For now, just
 * try an exact match on the name of the algorithm. */
static struct crypto_alg *crypto_alg_mod_lookup(const char *name)
{
	struct crypto_alg *alg;
	struct crypto_alg *larval;

	alg = try_then_request_module(crypto_alg_lookup(name), name);
	if (alg)
		return crypto_is_larval(alg) ? crypto_larval_wait(alg) : alg;

	larval = crypto_larval_alloc(name);
	if (!larval || !crypto_is_larval(larval))
		return larval;

	if (crypto_notify(CRYPTO_MSG_ALG_REQUEST, larval) == NOTIFY_STOP)
		alg = crypto_larval_wait(larval);
	else {
		crypto_mod_put(larval);
		alg = NULL;
	}
	crypto_larval_kill(larval);
	return alg;
}

static int crypto_init_flags(struct crypto_tfm *tfm, u32 flags)
{
	tfm->crt_flags = flags & CRYPTO_TFM_REQ_MASK;
	flags &= ~CRYPTO_TFM_REQ_MASK;
	
	switch (crypto_tfm_alg_type(tfm)) {
	case CRYPTO_ALG_TYPE_CIPHER:
		return crypto_init_cipher_flags(tfm, flags);
		
	case CRYPTO_ALG_TYPE_DIGEST:
		return crypto_init_digest_flags(tfm, flags);
		
	case CRYPTO_ALG_TYPE_COMPRESS:
		return crypto_init_compress_flags(tfm, flags);
	
	default:
		break;
	}
	
	BUG();
	return -EINVAL;
}

static int crypto_init_ops(struct crypto_tfm *tfm)
{
	switch (crypto_tfm_alg_type(tfm)) {
	case CRYPTO_ALG_TYPE_CIPHER:
		return crypto_init_cipher_ops(tfm);
		
	case CRYPTO_ALG_TYPE_DIGEST:
		return crypto_init_digest_ops(tfm);
		
	case CRYPTO_ALG_TYPE_COMPRESS:
		return crypto_init_compress_ops(tfm);
	
	default:
		break;
	}
	
	BUG();
	return -EINVAL;
}

static void crypto_exit_ops(struct crypto_tfm *tfm)
{
	switch (crypto_tfm_alg_type(tfm)) {
	case CRYPTO_ALG_TYPE_CIPHER:
		crypto_exit_cipher_ops(tfm);
		break;
		
	case CRYPTO_ALG_TYPE_DIGEST:
		crypto_exit_digest_ops(tfm);
		break;
		
	case CRYPTO_ALG_TYPE_COMPRESS:
		crypto_exit_compress_ops(tfm);
		break;
	
	default:
		BUG();
		
	}
}

static unsigned int crypto_ctxsize(struct crypto_alg *alg, int flags)
{
	unsigned int len;

	switch (alg->cra_flags & CRYPTO_ALG_TYPE_MASK) {
	default:
		BUG();

	case CRYPTO_ALG_TYPE_CIPHER:
		len = crypto_cipher_ctxsize(alg, flags);
		break;
		
	case CRYPTO_ALG_TYPE_DIGEST:
		len = crypto_digest_ctxsize(alg, flags);
		break;
		
	case CRYPTO_ALG_TYPE_COMPRESS:
		len = crypto_compress_ctxsize(alg, flags);
		break;
	}

	return len + (alg->cra_alignmask & ~(crypto_tfm_ctx_alignment() - 1));
}

struct crypto_tfm *crypto_alloc_tfm(const char *name, u32 flags)
{
	struct crypto_tfm *tfm = NULL;
	struct crypto_alg *alg;
	unsigned int tfm_size;

	alg = crypto_alg_mod_lookup(name);
	if (alg == NULL)
		goto out;

	tfm_size = sizeof(*tfm) + crypto_ctxsize(alg, flags);
	tfm = kzalloc(tfm_size, GFP_KERNEL);
	if (tfm == NULL)
		goto out_put;

	tfm->__crt_alg = alg;
	
	if (crypto_init_flags(tfm, flags))
		goto out_free_tfm;
		
	if (crypto_init_ops(tfm))
		goto out_free_tfm;

	if (alg->cra_init && alg->cra_init(tfm))
		goto cra_init_failed;

	goto out;

cra_init_failed:
	crypto_exit_ops(tfm);
out_free_tfm:
	kfree(tfm);
	tfm = NULL;
out_put:
	crypto_mod_put(alg);
out:
	return tfm;
}

void crypto_free_tfm(struct crypto_tfm *tfm)
{
	struct crypto_alg *alg;
	int size;

	if (unlikely(!tfm))
		return;

	alg = tfm->__crt_alg;
	size = sizeof(*tfm) + alg->cra_ctxsize;

	if (alg->cra_exit)
		alg->cra_exit(tfm);
	crypto_exit_ops(tfm);
	crypto_mod_put(alg);
	memset(tfm, 0, size);
	kfree(tfm);
}

int crypto_alg_available(const char *name, u32 flags)
{
	int ret = 0;
	struct crypto_alg *alg = crypto_alg_mod_lookup(name);
	
	if (alg) {
		crypto_mod_put(alg);
		ret = 1;
	}
	
	return ret;
}

EXPORT_SYMBOL_GPL(crypto_alloc_tfm);
EXPORT_SYMBOL_GPL(crypto_free_tfm);
EXPORT_SYMBOL_GPL(crypto_alg_available);
