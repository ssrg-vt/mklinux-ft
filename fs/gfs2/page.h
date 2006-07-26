/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef __PAGE_DOT_H__
#define __PAGE_DOT_H__

void gfs2_pte_inval(struct gfs2_glock *gl);
void gfs2_page_inval(struct gfs2_glock *gl);
void gfs2_page_sync(struct gfs2_glock *gl, int flags);

int gfs2_block_truncate_page(struct address_space *mapping);
void gfs2_page_add_databufs(struct gfs2_inode *ip, struct page *page,
			    unsigned int from, unsigned int to);

#endif /* __PAGE_DOT_H__ */
