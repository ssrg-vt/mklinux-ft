/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2005 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/buffer_head.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <asm/semaphore.h>

#include "gfs2.h"
#include "bmap.h"
#include "inode.h"
#include "page.h"
#include "trans.h"
#include "ops_address.h"

/**
 * gfs2_pte_inval - Sync and invalidate all PTEs associated with a glock
 * @gl: the glock
 *
 */

void gfs2_pte_inval(struct gfs2_glock *gl)
{
	struct gfs2_inode *ip;
	struct inode *inode;

	ip = get_gl2ip(gl);
	if (!ip || !S_ISREG(ip->i_di.di_mode))
		return;

	if (!test_bit(GIF_PAGED, &ip->i_flags))
		return;

	inode = gfs2_ip2v_lookup(ip);
	if (inode) {
		unmap_shared_mapping_range(inode->i_mapping, 0, 0);
		iput(inode);

		if (test_bit(GIF_SW_PAGED, &ip->i_flags))
			set_bit(GLF_DIRTY, &gl->gl_flags);
	}

	clear_bit(GIF_SW_PAGED, &ip->i_flags);
}

/**
 * gfs2_page_inval - Invalidate all pages associated with a glock
 * @gl: the glock
 *
 */

void gfs2_page_inval(struct gfs2_glock *gl)
{
	struct gfs2_inode *ip;
	struct inode *inode;

	ip = get_gl2ip(gl);
	if (!ip || !S_ISREG(ip->i_di.di_mode))
		return;

	inode = gfs2_ip2v_lookup(ip);
	if (inode) {
		struct address_space *mapping = inode->i_mapping;

		truncate_inode_pages(mapping, 0);
		gfs2_assert_withdraw(ip->i_sbd, !mapping->nrpages);

		iput(inode);
	}

	clear_bit(GIF_PAGED, &ip->i_flags);
}

/**
 * gfs2_page_sync - Sync the data pages (not metadata) associated with a glock
 * @gl: the glock
 * @flags: DIO_START | DIO_WAIT
 *
 * Syncs data (not metadata) for a regular file.
 * No-op for all other types.
 */

void gfs2_page_sync(struct gfs2_glock *gl, int flags)
{
	struct gfs2_inode *ip;
	struct inode *inode;

	ip = get_gl2ip(gl);
	if (!ip || !S_ISREG(ip->i_di.di_mode))
		return;

	inode = gfs2_ip2v_lookup(ip);
	if (inode) {
		struct address_space *mapping = inode->i_mapping;
		int error = 0;

		if (flags & DIO_START)
			filemap_fdatawrite(mapping);
		if (!error && (flags & DIO_WAIT))
			error = filemap_fdatawait(mapping);

		/* Put back any errors cleared by filemap_fdatawait()
		   so they can be caught by someone who can pass them
		   up to user space. */

		if (error == -ENOSPC)
			set_bit(AS_ENOSPC, &mapping->flags);
		else if (error)
			set_bit(AS_EIO, &mapping->flags);

		iput(inode);
	}
}

/**
 * gfs2_unstuffer_page - unstuff a stuffed inode into a block cached by a page
 * @ip: the inode
 * @dibh: the dinode buffer
 * @block: the block number that was allocated
 * @private: any locked page held by the caller process
 *
 * Returns: errno
 */

int gfs2_unstuffer_page(struct gfs2_inode *ip, struct buffer_head *dibh,
			uint64_t block, void *private)
{
	struct gfs2_sbd *sdp = ip->i_sbd;
	struct inode *inode = ip->i_vnode;
	struct page *page = (struct page *)private;
	struct buffer_head *bh;
	int release = 0;

	if (!page || page->index) {
		page = grab_cache_page(inode->i_mapping, 0);
		if (!page)
			return -ENOMEM;
		release = 1;
	}

	if (!PageUptodate(page)) {
		void *kaddr = kmap(page);

		memcpy(kaddr,
		       dibh->b_data + sizeof(struct gfs2_dinode),
		       ip->i_di.di_size);
		memset(kaddr + ip->i_di.di_size,
		       0,
		       PAGE_CACHE_SIZE - ip->i_di.di_size);
		kunmap(page);

		SetPageUptodate(page);
	}

	if (!page_has_buffers(page))
		create_empty_buffers(page, 1 << inode->i_blkbits,
				     (1 << BH_Uptodate));

	bh = page_buffers(page);

	if (!buffer_mapped(bh))
		map_bh(bh, inode->i_sb, block);

	set_buffer_uptodate(bh);
	if (sdp->sd_args.ar_data == GFS2_DATA_ORDERED)
		gfs2_trans_add_databuf(sdp, bh);
	mark_buffer_dirty(bh);

	if (release) {
		unlock_page(page);
		page_cache_release(page);
	}

	return 0;
}

/**
 * gfs2_block_truncate_page - Deal with zeroing out data for truncate
 *
 * This is partly borrowed from ext3.
 */
int gfs2_block_truncate_page(struct address_space *mapping)
{
	struct inode *inode = mapping->host;
	struct gfs2_inode *ip = get_v2ip(inode);
	struct gfs2_sbd *sdp = ip->i_sbd;
	loff_t from = inode->i_size;
	unsigned long index = from >> PAGE_CACHE_SHIFT;
	unsigned offset = from & (PAGE_CACHE_SIZE-1);
	unsigned blocksize, iblock, length, pos;
	struct buffer_head *bh;
	struct page *page;
	void *kaddr;
	int err;

	page = grab_cache_page(mapping, index);
	if (!page)
		return 0;

	blocksize = inode->i_sb->s_blocksize;
	length = blocksize - (offset & (blocksize - 1));
	iblock = index << (PAGE_CACHE_SHIFT - inode->i_sb->s_blocksize_bits);

	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);

	/* Find the buffer that contains "offset" */
	bh = page_buffers(page);
	pos = blocksize;
	while (offset >= pos) {
		bh = bh->b_this_page;
		iblock++;
		pos += blocksize;
	}

	err = 0;

	if (!buffer_mapped(bh)) {
		gfs2_get_block(inode, iblock, bh, 0);
		/* unmapped? It's a hole - nothing to do */
		if (!buffer_mapped(bh))
			goto unlock;
	}

	/* Ok, it's mapped. Make sure it's up-to-date */
	if (PageUptodate(page))
		set_buffer_uptodate(bh);

	if (!buffer_uptodate(bh)) {
		err = -EIO;
		ll_rw_block(READ, 1, &bh);
		wait_on_buffer(bh);
		/* Uhhuh. Read error. Complain and punt. */
		if (!buffer_uptodate(bh))
			goto unlock;
	}

	if (sdp->sd_args.ar_data == GFS2_DATA_ORDERED/* || gfs2_is_jdata(ip)*/)
		gfs2_trans_add_databuf(sdp, bh);

	kaddr = kmap_atomic(page, KM_USER0);
	memset(kaddr + offset, 0, length);
	flush_dcache_page(page);
	kunmap_atomic(kaddr, KM_USER0);

unlock:
	unlock_page(page);
	page_cache_release(page);
	return err;
}

void gfs2_page_add_databufs(struct gfs2_inode *ip, struct page *page,
			    unsigned int from, unsigned int to)
{
	struct buffer_head *head = page_buffers(page);
	unsigned int bsize = head->b_size;
	struct buffer_head *bh;
	unsigned int start, end;

	for (bh = head, start = 0;
	     bh != head || !start;
	     bh = bh->b_this_page, start = end) {
		end = start + bsize;
		if (end <= from || start >= to)
			continue;
		gfs2_trans_add_databuf(ip->i_sbd, bh);
	}
}

