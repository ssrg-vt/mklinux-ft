/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * dlmdebug.h
 *
 * Copyright (C) 2008 Oracle.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 *
 */

#ifndef DLMDEBUG_H
#define DLMDEBUG_H

#ifdef CONFIG_DEBUG_FS

int dlm_create_debugfs_subroot(struct dlm_ctxt *dlm);
void dlm_destroy_debugfs_subroot(struct dlm_ctxt *dlm);

int dlm_create_debugfs_root(void);
void dlm_destroy_debugfs_root(void);

#else

static int dlm_create_debugfs_subroot(struct dlm_ctxt *dlm)
{
	return 0;
}
static void dlm_destroy_debugfs_subroot(struct dlm_ctxt *dlm)
{
}
static int dlm_create_debugfs_root(void)
{
	return 0;
}
static void dlm_destroy_debugfs_root(void)
{
}

#endif	/* CONFIG_DEBUG_FS */
#endif	/* DLMDEBUG_H */
