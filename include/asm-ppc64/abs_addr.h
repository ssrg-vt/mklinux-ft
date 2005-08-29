#ifndef _ABS_ADDR_H
#define _ABS_ADDR_H

#include <linux/config.h>

/*
 * c 2001 PPC 64 Team, IBM Corp
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <asm/types.h>
#include <asm/page.h>
#include <asm/prom.h>
#include <asm/lmb.h>

#ifdef CONFIG_MSCHUNKS

struct mschunks_map {
        unsigned long num_chunks;
        unsigned long chunk_size;
        unsigned long chunk_shift;
        unsigned long chunk_mask;
        u32 *mapping;
};

extern struct mschunks_map mschunks_map;

/* Chunks are 256 KB */
#define MSCHUNKS_CHUNK_SHIFT	(18)
#define MSCHUNKS_CHUNK_SIZE	(1UL << MSCHUNKS_CHUNK_SHIFT)
#define MSCHUNKS_OFFSET_MASK	(MSCHUNKS_CHUNK_SIZE - 1)

static inline unsigned long chunk_to_addr(unsigned long chunk)
{
	return chunk << MSCHUNKS_CHUNK_SHIFT;
}

static inline unsigned long addr_to_chunk(unsigned long addr)
{
	return addr >> MSCHUNKS_CHUNK_SHIFT;
}

static inline unsigned long phys_to_abs(unsigned long pa)
{
	unsigned long chunk;

	chunk = addr_to_chunk(pa);

	if (chunk < mschunks_map.num_chunks)
		chunk = mschunks_map.mapping[chunk];

	return chunk_to_addr(chunk) + (pa & MSCHUNKS_OFFSET_MASK);
}

static inline unsigned long
physRpn_to_absRpn(unsigned long rpn)
{
	unsigned long pa = rpn << PAGE_SHIFT;
	unsigned long aa = phys_to_abs(pa);
	return (aa >> PAGE_SHIFT);
}

/* A macro so it can take pointers or unsigned long. */
#define abs_to_phys(aa) lmb_abs_to_phys((unsigned long)(aa))

#else  /* !CONFIG_MSCHUNKS */

#define chunk_to_addr(chunk) ((unsigned long)(chunk))
#define addr_to_chunk(addr) (addr)
#define chunk_offset(addr) (0)
#define abs_chunk(pchunk) (pchunk)

#define phys_to_abs(pa) (pa)
#define physRpn_to_absRpn(rpn) (rpn)
#define abs_to_phys(aa) (aa)

#endif /* !CONFIG_MSCHUNKS */

/* Convenience macros */
#define virt_to_abs(va) phys_to_abs(__pa(va))
#define abs_to_virt(aa) __va(abs_to_phys(aa))

#endif /* _ABS_ADDR_H */
