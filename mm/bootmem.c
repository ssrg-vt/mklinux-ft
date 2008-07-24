/*
 *  bootmem - A boot-time physical memory allocator and configurator
 *
 *  Copyright (C) 1999 Ingo Molnar
 *                1999 Kanoj Sarcar, SGI
 *                2008 Johannes Weiner
 *
 * Access to this subsystem has to be serialized externally (which is true
 * for the boot process anyway).
 */
#include <linux/init.h>
#include <linux/pfn.h>
#include <linux/bootmem.h>
#include <linux/module.h>

#include <asm/bug.h>
#include <asm/io.h>
#include <asm/processor.h>

#include "internal.h"

unsigned long max_low_pfn;
unsigned long min_low_pfn;
unsigned long max_pfn;

static LIST_HEAD(bdata_list);
#ifdef CONFIG_CRASH_DUMP
/*
 * If we have booted due to a crash, max_pfn will be a very low value. We need
 * to know the amount of memory that the previous kernel used.
 */
unsigned long saved_max_pfn;
#endif

bootmem_data_t bootmem_node_data[MAX_NUMNODES] __initdata;

static int bootmem_debug;

static int __init bootmem_debug_setup(char *buf)
{
	bootmem_debug = 1;
	return 0;
}
early_param("bootmem_debug", bootmem_debug_setup);

#define bdebug(fmt, args...) ({				\
	if (unlikely(bootmem_debug))			\
		printk(KERN_INFO			\
			"bootmem::%s " fmt,		\
			__FUNCTION__, ## args);		\
})

/*
 * Given an initialised bdata, it returns the size of the boot bitmap
 */
static unsigned long __init get_mapsize(bootmem_data_t *bdata)
{
	unsigned long mapsize;
	unsigned long start = PFN_DOWN(bdata->node_boot_start);
	unsigned long end = bdata->node_low_pfn;

	mapsize = ((end - start) + 7) / 8;
	return ALIGN(mapsize, sizeof(long));
}

/**
 * bootmem_bootmap_pages - calculate bitmap size in pages
 * @pages: number of pages the bitmap has to represent
 */
unsigned long __init bootmem_bootmap_pages(unsigned long pages)
{
	unsigned long mapsize;

	mapsize = (pages+7)/8;
	mapsize = (mapsize + ~PAGE_MASK) & PAGE_MASK;
	mapsize >>= PAGE_SHIFT;

	return mapsize;
}

/*
 * link bdata in order
 */
static void __init link_bootmem(bootmem_data_t *bdata)
{
	bootmem_data_t *ent;

	if (list_empty(&bdata_list)) {
		list_add(&bdata->list, &bdata_list);
		return;
	}
	/* insert in order */
	list_for_each_entry(ent, &bdata_list, list) {
		if (bdata->node_boot_start < ent->node_boot_start) {
			list_add_tail(&bdata->list, &ent->list);
			return;
		}
	}
	list_add_tail(&bdata->list, &bdata_list);
}

/*
 * Called once to set up the allocator itself.
 */
static unsigned long __init init_bootmem_core(bootmem_data_t *bdata,
	unsigned long mapstart, unsigned long start, unsigned long end)
{
	unsigned long mapsize;

	mminit_validate_memmodel_limits(&start, &end);
	bdata->node_bootmem_map = phys_to_virt(PFN_PHYS(mapstart));
	bdata->node_boot_start = PFN_PHYS(start);
	bdata->node_low_pfn = end;
	link_bootmem(bdata);

	/*
	 * Initially all pages are reserved - setup_arch() has to
	 * register free RAM areas explicitly.
	 */
	mapsize = get_mapsize(bdata);
	memset(bdata->node_bootmem_map, 0xff, mapsize);

	bdebug("nid=%td start=%lx map=%lx end=%lx mapsize=%lx\n",
		bdata - bootmem_node_data, start, mapstart, end, mapsize);

	return mapsize;
}

/**
 * init_bootmem_node - register a node as boot memory
 * @pgdat: node to register
 * @freepfn: pfn where the bitmap for this node is to be placed
 * @startpfn: first pfn on the node
 * @endpfn: first pfn after the node
 *
 * Returns the number of bytes needed to hold the bitmap for this node.
 */
unsigned long __init init_bootmem_node(pg_data_t *pgdat, unsigned long freepfn,
				unsigned long startpfn, unsigned long endpfn)
{
	return init_bootmem_core(pgdat->bdata, freepfn, startpfn, endpfn);
}

/**
 * init_bootmem - register boot memory
 * @start: pfn where the bitmap is to be placed
 * @pages: number of available physical pages
 *
 * Returns the number of bytes needed to hold the bitmap.
 */
unsigned long __init init_bootmem(unsigned long start, unsigned long pages)
{
	max_low_pfn = pages;
	min_low_pfn = start;
	return init_bootmem_core(NODE_DATA(0)->bdata, start, 0, pages);
}

static unsigned long __init free_all_bootmem_core(bootmem_data_t *bdata)
{
	struct page *page;
	unsigned long pfn;
	unsigned long i, count;
	unsigned long idx;
	unsigned long *map;
	int gofast = 0;

	BUG_ON(!bdata->node_bootmem_map);

	count = 0;
	/* first extant page of the node */
	pfn = PFN_DOWN(bdata->node_boot_start);
	idx = bdata->node_low_pfn - pfn;
	map = bdata->node_bootmem_map;
	/*
	 * Check if we are aligned to BITS_PER_LONG pages.  If so, we might
	 * be able to free page orders of that size at once.
	 */
	if (!(pfn & (BITS_PER_LONG-1)))
		gofast = 1;

	for (i = 0; i < idx; ) {
		unsigned long v = ~map[i / BITS_PER_LONG];

		if (gofast && v == ~0UL) {
			int order;

			page = pfn_to_page(pfn);
			count += BITS_PER_LONG;
			order = ffs(BITS_PER_LONG) - 1;
			__free_pages_bootmem(page, order);
			i += BITS_PER_LONG;
			page += BITS_PER_LONG;
		} else if (v) {
			unsigned long m;

			page = pfn_to_page(pfn);
			for (m = 1; m && i < idx; m<<=1, page++, i++) {
				if (v & m) {
					count++;
					__free_pages_bootmem(page, 0);
				}
			}
		} else {
			i += BITS_PER_LONG;
		}
		pfn += BITS_PER_LONG;
	}

	/*
	 * Now free the allocator bitmap itself, it's not
	 * needed anymore:
	 */
	page = virt_to_page(bdata->node_bootmem_map);
	idx = (get_mapsize(bdata) + PAGE_SIZE-1) >> PAGE_SHIFT;
	for (i = 0; i < idx; i++, page++)
		__free_pages_bootmem(page, 0);
	count += i;
	bdata->node_bootmem_map = NULL;

	bdebug("nid=%td released=%lx\n", bdata - bootmem_node_data, count);

	return count;
}

/**
 * free_all_bootmem_node - release a node's free pages to the buddy allocator
 * @pgdat: node to be released
 *
 * Returns the number of pages actually released.
 */
unsigned long __init free_all_bootmem_node(pg_data_t *pgdat)
{
	register_page_bootmem_info_node(pgdat);
	return free_all_bootmem_core(pgdat->bdata);
}

/**
 * free_all_bootmem - release free pages to the buddy allocator
 *
 * Returns the number of pages actually released.
 */
unsigned long __init free_all_bootmem(void)
{
	return free_all_bootmem_core(NODE_DATA(0)->bdata);
}

static void __init free_bootmem_core(bootmem_data_t *bdata, unsigned long addr,
				     unsigned long size)
{
	unsigned long sidx, eidx;
	unsigned long i;

	BUG_ON(!size);

	/* out range */
	if (addr + size < bdata->node_boot_start ||
		PFN_DOWN(addr) > bdata->node_low_pfn)
		return;
	/*
	 * round down end of usable mem, partially free pages are
	 * considered reserved.
	 */

	if (addr >= bdata->node_boot_start && addr < bdata->last_success)
		bdata->last_success = addr;

	/*
	 * Round up to index to the range.
	 */
	if (PFN_UP(addr) > PFN_DOWN(bdata->node_boot_start))
		sidx = PFN_UP(addr) - PFN_DOWN(bdata->node_boot_start);
	else
		sidx = 0;

	eidx = PFN_DOWN(addr + size - bdata->node_boot_start);
	if (eidx > bdata->node_low_pfn - PFN_DOWN(bdata->node_boot_start))
		eidx = bdata->node_low_pfn - PFN_DOWN(bdata->node_boot_start);

	bdebug("nid=%td start=%lx end=%lx\n", bdata - bootmem_node_data,
		sidx + PFN_DOWN(bdata->node_boot_start),
		eidx + PFN_DOWN(bdata->node_boot_start));

	for (i = sidx; i < eidx; i++) {
		if (unlikely(!test_and_clear_bit(i, bdata->node_bootmem_map)))
			BUG();
	}
}

/**
 * free_bootmem_node - mark a page range as usable
 * @pgdat: node the range resides on
 * @physaddr: starting address of the range
 * @size: size of the range in bytes
 *
 * Partial pages will be considered reserved and left as they are.
 *
 * Only physical pages that actually reside on @pgdat are marked.
 */
void __init free_bootmem_node(pg_data_t *pgdat, unsigned long physaddr,
			      unsigned long size)
{
	free_bootmem_core(pgdat->bdata, physaddr, size);
}

/**
 * free_bootmem - mark a page range as usable
 * @addr: starting address of the range
 * @size: size of the range in bytes
 *
 * Partial pages will be considered reserved and left as they are.
 *
 * All physical pages within the range are marked, no matter what
 * node they reside on.
 */
void __init free_bootmem(unsigned long addr, unsigned long size)
{
	bootmem_data_t *bdata;
	list_for_each_entry(bdata, &bdata_list, list)
		free_bootmem_core(bdata, addr, size);
}

/*
 * Marks a particular physical memory range as unallocatable. Usable RAM
 * might be used for boot-time allocations - or it might get added
 * to the free page pool later on.
 */
static int __init can_reserve_bootmem_core(bootmem_data_t *bdata,
			unsigned long addr, unsigned long size, int flags)
{
	unsigned long sidx, eidx;
	unsigned long i;

	BUG_ON(!size);

	/* out of range, don't hold other */
	if (addr + size < bdata->node_boot_start ||
		PFN_DOWN(addr) > bdata->node_low_pfn)
		return 0;

	/*
	 * Round up to index to the range.
	 */
	if (addr > bdata->node_boot_start)
		sidx= PFN_DOWN(addr - bdata->node_boot_start);
	else
		sidx = 0;

	eidx = PFN_UP(addr + size - bdata->node_boot_start);
	if (eidx > bdata->node_low_pfn - PFN_DOWN(bdata->node_boot_start))
		eidx = bdata->node_low_pfn - PFN_DOWN(bdata->node_boot_start);

	for (i = sidx; i < eidx; i++) {
		if (test_bit(i, bdata->node_bootmem_map)) {
			if (flags & BOOTMEM_EXCLUSIVE)
				return -EBUSY;
		}
	}

	return 0;

}

static void __init reserve_bootmem_core(bootmem_data_t *bdata,
			unsigned long addr, unsigned long size, int flags)
{
	unsigned long sidx, eidx;
	unsigned long i;

	BUG_ON(!size);

	/* out of range */
	if (addr + size < bdata->node_boot_start ||
		PFN_DOWN(addr) > bdata->node_low_pfn)
		return;

	/*
	 * Round up to index to the range.
	 */
	if (addr > bdata->node_boot_start)
		sidx= PFN_DOWN(addr - bdata->node_boot_start);
	else
		sidx = 0;

	eidx = PFN_UP(addr + size - bdata->node_boot_start);
	if (eidx > bdata->node_low_pfn - PFN_DOWN(bdata->node_boot_start))
		eidx = bdata->node_low_pfn - PFN_DOWN(bdata->node_boot_start);

	bdebug("nid=%td start=%lx end=%lx flags=%x\n",
		bdata - bootmem_node_data,
		sidx + PFN_DOWN(bdata->node_boot_start),
		eidx + PFN_DOWN(bdata->node_boot_start),
		flags);

	for (i = sidx; i < eidx; i++)
		if (test_and_set_bit(i, bdata->node_bootmem_map))
			bdebug("hm, page %lx reserved twice.\n",
				PFN_DOWN(bdata->node_boot_start) + i);
}

/**
 * reserve_bootmem_node - mark a page range as reserved
 * @pgdat: node the range resides on
 * @physaddr: starting address of the range
 * @size: size of the range in bytes
 * @flags: reservation flags (see linux/bootmem.h)
 *
 * Partial pages will be reserved.
 *
 * Only physical pages that actually reside on @pgdat are marked.
 */
int __init reserve_bootmem_node(pg_data_t *pgdat, unsigned long physaddr,
				 unsigned long size, int flags)
{
	int ret;

	ret = can_reserve_bootmem_core(pgdat->bdata, physaddr, size, flags);
	if (ret < 0)
		return -ENOMEM;
	reserve_bootmem_core(pgdat->bdata, physaddr, size, flags);
	return 0;
}

#ifndef CONFIG_HAVE_ARCH_BOOTMEM_NODE
/**
 * reserve_bootmem - mark a page range as usable
 * @addr: starting address of the range
 * @size: size of the range in bytes
 * @flags: reservation flags (see linux/bootmem.h)
 *
 * Partial pages will be reserved.
 *
 * All physical pages within the range are marked, no matter what
 * node they reside on.
 */
int __init reserve_bootmem(unsigned long addr, unsigned long size,
			    int flags)
{
	bootmem_data_t *bdata;
	int ret;

	list_for_each_entry(bdata, &bdata_list, list) {
		ret = can_reserve_bootmem_core(bdata, addr, size, flags);
		if (ret < 0)
			return ret;
	}
	list_for_each_entry(bdata, &bdata_list, list)
		reserve_bootmem_core(bdata, addr, size, flags);

	return 0;
}
#endif /* !CONFIG_HAVE_ARCH_BOOTMEM_NODE */

/*
 * We 'merge' subsequent allocations to save space. We might 'lose'
 * some fraction of a page if allocations cannot be satisfied due to
 * size constraints on boxes where there is physical RAM space
 * fragmentation - in these cases (mostly large memory boxes) this
 * is not a problem.
 *
 * On low memory boxes we get it right in 100% of the cases.
 *
 * alignment has to be a power of 2 value.
 *
 * NOTE:  This function is _not_ reentrant.
 */
static void * __init
alloc_bootmem_core(struct bootmem_data *bdata, unsigned long size,
		unsigned long align, unsigned long goal, unsigned long limit)
{
	unsigned long areasize, preferred;
	unsigned long i, start = 0, incr, eidx, end_pfn;
	void *ret;
	unsigned long node_boot_start;
	void *node_bootmem_map;

	if (!size) {
		printk("alloc_bootmem_core(): zero-sized request\n");
		BUG();
	}
	BUG_ON(align & (align-1));

	/* on nodes without memory - bootmem_map is NULL */
	if (!bdata->node_bootmem_map)
		return NULL;

	bdebug("nid=%td size=%lx [%lu pages] align=%lx goal=%lx limit=%lx\n",
		bdata - bootmem_node_data, size, PAGE_ALIGN(size) >> PAGE_SHIFT,
		align, goal, limit);

	/* bdata->node_boot_start is supposed to be (12+6)bits alignment on x86_64 ? */
	node_boot_start = bdata->node_boot_start;
	node_bootmem_map = bdata->node_bootmem_map;
	if (align) {
		node_boot_start = ALIGN(bdata->node_boot_start, align);
		if (node_boot_start > bdata->node_boot_start)
			node_bootmem_map = (unsigned long *)bdata->node_bootmem_map +
			    PFN_DOWN(node_boot_start - bdata->node_boot_start)/BITS_PER_LONG;
	}

	if (limit && node_boot_start >= limit)
		return NULL;

	end_pfn = bdata->node_low_pfn;
	limit = PFN_DOWN(limit);
	if (limit && end_pfn > limit)
		end_pfn = limit;

	eidx = end_pfn - PFN_DOWN(node_boot_start);

	/*
	 * We try to allocate bootmem pages above 'goal'
	 * first, then we try to allocate lower pages.
	 */
	preferred = 0;
	if (goal && PFN_DOWN(goal) < end_pfn) {
		if (goal > node_boot_start)
			preferred = goal - node_boot_start;

		if (bdata->last_success > node_boot_start &&
			bdata->last_success - node_boot_start >= preferred)
			if (!limit || (limit && limit > bdata->last_success))
				preferred = bdata->last_success - node_boot_start;
	}

	preferred = PFN_DOWN(ALIGN(preferred, align));
	areasize = (size + PAGE_SIZE-1) / PAGE_SIZE;
	incr = align >> PAGE_SHIFT ? : 1;

restart_scan:
	for (i = preferred; i < eidx;) {
		unsigned long j;

		i = find_next_zero_bit(node_bootmem_map, eidx, i);
		i = ALIGN(i, incr);
		if (i >= eidx)
			break;
		if (test_bit(i, node_bootmem_map)) {
			i += incr;
			continue;
		}
		for (j = i + 1; j < i + areasize; ++j) {
			if (j >= eidx)
				goto fail_block;
			if (test_bit(j, node_bootmem_map))
				goto fail_block;
		}
		start = i;
		goto found;
	fail_block:
		i = ALIGN(j, incr);
		if (i == j)
			i += incr;
	}

	if (preferred > 0) {
		preferred = 0;
		goto restart_scan;
	}
	return NULL;

found:
	bdata->last_success = PFN_PHYS(start) + node_boot_start;
	BUG_ON(start >= eidx);

	/*
	 * Is the next page of the previous allocation-end the start
	 * of this allocation's buffer? If yes then we can 'merge'
	 * the previous partial page with this allocation.
	 */
	if (align < PAGE_SIZE &&
	    bdata->last_offset && bdata->last_pos+1 == start) {
		unsigned long offset, remaining_size;
		offset = ALIGN(bdata->last_offset, align);
		BUG_ON(offset > PAGE_SIZE);
		remaining_size = PAGE_SIZE - offset;
		if (size < remaining_size) {
			areasize = 0;
			/* last_pos unchanged */
			bdata->last_offset = offset + size;
			ret = phys_to_virt(bdata->last_pos * PAGE_SIZE +
					   offset + node_boot_start);
		} else {
			remaining_size = size - remaining_size;
			areasize = (remaining_size + PAGE_SIZE-1) / PAGE_SIZE;
			ret = phys_to_virt(bdata->last_pos * PAGE_SIZE +
					   offset + node_boot_start);
			bdata->last_pos = start + areasize - 1;
			bdata->last_offset = remaining_size;
		}
		bdata->last_offset &= ~PAGE_MASK;
	} else {
		bdata->last_pos = start + areasize - 1;
		bdata->last_offset = size & ~PAGE_MASK;
		ret = phys_to_virt(start * PAGE_SIZE + node_boot_start);
	}

	bdebug("nid=%td start=%lx end=%lx\n",
		bdata - bootmem_node_data,
		start + PFN_DOWN(bdata->node_boot_start),
		start + areasize + PFN_DOWN(bdata->node_boot_start));

	/*
	 * Reserve the area now:
	 */
	for (i = start; i < start + areasize; i++)
		if (unlikely(test_and_set_bit(i, node_bootmem_map)))
			BUG();
	memset(ret, 0, size);
	return ret;
}

/**
 * __alloc_bootmem_nopanic - allocate boot memory without panicking
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may happen on any node in the system.
 *
 * Returns NULL on failure.
 */
void * __init __alloc_bootmem_nopanic(unsigned long size, unsigned long align,
				      unsigned long goal)
{
	bootmem_data_t *bdata;
	void *ptr;

	list_for_each_entry(bdata, &bdata_list, list) {
		ptr = alloc_bootmem_core(bdata, size, align, goal, 0);
		if (ptr)
			return ptr;
	}
	return NULL;
}

/**
 * __alloc_bootmem - allocate boot memory
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may happen on any node in the system.
 *
 * The function panics if the request can not be satisfied.
 */
void * __init __alloc_bootmem(unsigned long size, unsigned long align,
			      unsigned long goal)
{
	void *mem = __alloc_bootmem_nopanic(size,align,goal);

	if (mem)
		return mem;
	/*
	 * Whoops, we cannot satisfy the allocation request.
	 */
	printk(KERN_ALERT "bootmem alloc of %lu bytes failed!\n", size);
	panic("Out of memory");
	return NULL;
}

/**
 * __alloc_bootmem_node - allocate boot memory from a specific node
 * @pgdat: node to allocate from
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may fall back to any node in the system if the specified node
 * can not hold the requested memory.
 *
 * The function panics if the request can not be satisfied.
 */
void * __init __alloc_bootmem_node(pg_data_t *pgdat, unsigned long size,
				   unsigned long align, unsigned long goal)
{
	void *ptr;

	ptr = alloc_bootmem_core(pgdat->bdata, size, align, goal, 0);
	if (ptr)
		return ptr;

	return __alloc_bootmem(size, align, goal);
}

#ifdef CONFIG_SPARSEMEM
/**
 * alloc_bootmem_section - allocate boot memory from a specific section
 * @size: size of the request in bytes
 * @section_nr: sparse map section to allocate from
 *
 * Return NULL on failure.
 */
void * __init alloc_bootmem_section(unsigned long size,
				    unsigned long section_nr)
{
	void *ptr;
	unsigned long limit, goal, start_nr, end_nr, pfn;
	struct pglist_data *pgdat;

	pfn = section_nr_to_pfn(section_nr);
	goal = PFN_PHYS(pfn);
	limit = PFN_PHYS(section_nr_to_pfn(section_nr + 1)) - 1;
	pgdat = NODE_DATA(early_pfn_to_nid(pfn));
	ptr = alloc_bootmem_core(pgdat->bdata, size, SMP_CACHE_BYTES, goal,
				limit);

	if (!ptr)
		return NULL;

	start_nr = pfn_to_section_nr(PFN_DOWN(__pa(ptr)));
	end_nr = pfn_to_section_nr(PFN_DOWN(__pa(ptr) + size));
	if (start_nr != section_nr || end_nr != section_nr) {
		printk(KERN_WARNING "alloc_bootmem failed on section %ld.\n",
		       section_nr);
		free_bootmem_core(pgdat->bdata, __pa(ptr), size);
		ptr = NULL;
	}

	return ptr;
}
#endif

void * __init __alloc_bootmem_node_nopanic(pg_data_t *pgdat, unsigned long size,
				   unsigned long align, unsigned long goal)
{
	void *ptr;

	ptr = alloc_bootmem_core(pgdat->bdata, size, align, goal, 0);
	if (ptr)
		return ptr;

	return __alloc_bootmem_nopanic(size, align, goal);
}

#ifndef ARCH_LOW_ADDRESS_LIMIT
#define ARCH_LOW_ADDRESS_LIMIT	0xffffffffUL
#endif

/**
 * __alloc_bootmem_low - allocate low boot memory
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may happen on any node in the system.
 *
 * The function panics if the request can not be satisfied.
 */
void * __init __alloc_bootmem_low(unsigned long size, unsigned long align,
				  unsigned long goal)
{
	bootmem_data_t *bdata;
	void *ptr;

	list_for_each_entry(bdata, &bdata_list, list) {
		ptr = alloc_bootmem_core(bdata, size, align, goal,
					ARCH_LOW_ADDRESS_LIMIT);
		if (ptr)
			return ptr;
	}

	/*
	 * Whoops, we cannot satisfy the allocation request.
	 */
	printk(KERN_ALERT "low bootmem alloc of %lu bytes failed!\n", size);
	panic("Out of low memory");
	return NULL;
}

/**
 * __alloc_bootmem_low_node - allocate low boot memory from a specific node
 * @pgdat: node to allocate from
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may fall back to any node in the system if the specified node
 * can not hold the requested memory.
 *
 * The function panics if the request can not be satisfied.
 */
void * __init __alloc_bootmem_low_node(pg_data_t *pgdat, unsigned long size,
				       unsigned long align, unsigned long goal)
{
	return alloc_bootmem_core(pgdat->bdata, size, align, goal,
				ARCH_LOW_ADDRESS_LIMIT);
}
