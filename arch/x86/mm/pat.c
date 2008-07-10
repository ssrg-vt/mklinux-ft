/*
 * Handle caching attributes in page tables (PAT)
 *
 * Authors: Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>
 *          Suresh B Siddha <suresh.b.siddha@intel.com>
 *
 * Loosely based on earlier PAT patchset from Eric Biederman and Andi Kleen.
 */

#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/fs.h>
#include <linux/bootmem.h>

#include <asm/msr.h>
#include <asm/tlbflush.h>
#include <asm/processor.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/pat.h>
#include <asm/e820.h>
#include <asm/cacheflush.h>
#include <asm/fcntl.h>
#include <asm/mtrr.h>
#include <asm/io.h>

#ifdef CONFIG_X86_PAT
int __read_mostly pat_enabled = 1;

void __cpuinit pat_disable(char *reason)
{
	pat_enabled = 0;
	printk(KERN_INFO "%s\n", reason);
}

static int __init nopat(char *str)
{
	pat_disable("PAT support disabled.");
	return 0;
}
early_param("nopat", nopat);
#endif


static int debug_enable;
static int __init pat_debug_setup(char *str)
{
	debug_enable = 1;
	return 0;
}
__setup("debugpat", pat_debug_setup);

#define dprintk(fmt, arg...) \
	do { if (debug_enable) printk(KERN_INFO fmt, ##arg); } while (0)


static u64 __read_mostly boot_pat_state;

enum {
	PAT_UC = 0,		/* uncached */
	PAT_WC = 1,		/* Write combining */
	PAT_WT = 4,		/* Write Through */
	PAT_WP = 5,		/* Write Protected */
	PAT_WB = 6,		/* Write Back (default) */
	PAT_UC_MINUS = 7,	/* UC, but can be overriden by MTRR */
};

#define PAT(x, y)	((u64)PAT_ ## y << ((x)*8))

void pat_init(void)
{
	u64 pat;

	if (!pat_enabled)
		return;

	/* Paranoia check. */
	if (!cpu_has_pat && boot_pat_state) {
		/*
		 * If this happens we are on a secondary CPU, but
		 * switched to PAT on the boot CPU. We have no way to
		 * undo PAT.
		 */
		printk(KERN_ERR "PAT enabled, "
		       "but not supported by secondary CPU\n");
		BUG();
	}

	/* Set PWT to Write-Combining. All other bits stay the same */
	/*
	 * PTE encoding used in Linux:
	 *      PAT
	 *      |PCD
	 *      ||PWT
	 *      |||
	 *      000 WB		_PAGE_CACHE_WB
	 *      001 WC		_PAGE_CACHE_WC
	 *      010 UC-		_PAGE_CACHE_UC_MINUS
	 *      011 UC		_PAGE_CACHE_UC
	 * PAT bit unused
	 */
	pat = PAT(0, WB) | PAT(1, WC) | PAT(2, UC_MINUS) | PAT(3, UC) |
	      PAT(4, WB) | PAT(5, WC) | PAT(6, UC_MINUS) | PAT(7, UC);

	/* Boot CPU check */
	if (!boot_pat_state)
		rdmsrl(MSR_IA32_CR_PAT, boot_pat_state);

	wrmsrl(MSR_IA32_CR_PAT, pat);
	printk(KERN_INFO "x86 PAT enabled: cpu %d, old 0x%Lx, new 0x%Lx\n",
	       smp_processor_id(), boot_pat_state, pat);
}

#undef PAT

static char *cattr_name(unsigned long flags)
{
	switch (flags & _PAGE_CACHE_MASK) {
	case _PAGE_CACHE_UC:		return "uncached";
	case _PAGE_CACHE_UC_MINUS:	return "uncached-minus";
	case _PAGE_CACHE_WB:		return "write-back";
	case _PAGE_CACHE_WC:		return "write-combining";
	default:			return "broken";
	}
}

/*
 * The global memtype list keeps track of memory type for specific
 * physical memory areas. Conflicting memory types in different
 * mappings can cause CPU cache corruption. To avoid this we keep track.
 *
 * The list is sorted based on starting address and can contain multiple
 * entries for each address (this allows reference counting for overlapping
 * areas). All the aliases have the same cache attributes of course.
 * Zero attributes are represented as holes.
 *
 * Currently the data structure is a list because the number of mappings
 * are expected to be relatively small. If this should be a problem
 * it could be changed to a rbtree or similar.
 *
 * memtype_lock protects the whole list.
 */

struct memtype {
	u64 start;
	u64 end;
	unsigned long type;
	struct list_head nd;
};

static LIST_HEAD(memtype_list);
static DEFINE_SPINLOCK(memtype_lock); 	/* protects memtype list */

/*
 * Does intersection of PAT memory type and MTRR memory type and returns
 * the resulting memory type as PAT understands it.
 * (Type in pat and mtrr will not have same value)
 * The intersection is based on "Effective Memory Type" tables in IA-32
 * SDM vol 3a
 */
static unsigned long pat_x_mtrr_type(u64 start, u64 end, unsigned long req_type)
{
	/*
	 * Look for MTRR hint to get the effective type in case where PAT
	 * request is for WB.
	 */
	if (req_type == _PAGE_CACHE_WB) {
		u8 mtrr_type;

		mtrr_type = mtrr_type_lookup(start, end);
		if (mtrr_type == MTRR_TYPE_UNCACHABLE)
			return _PAGE_CACHE_UC;
		if (mtrr_type == MTRR_TYPE_WRCOMB)
			return _PAGE_CACHE_WC;
	}

	return req_type;
}

static int chk_conflict(struct memtype *new, struct memtype *entry,
			unsigned long *type)
{
	if (new->type != entry->type) {
		if (type) {
			new->type = entry->type;
			*type = entry->type;
		} else
			goto conflict;
	}

	 /* check overlaps with more than one entry in the list */
	list_for_each_entry_continue(entry, &memtype_list, nd) {
		if (new->end <= entry->start)
			break;
		else if (new->type != entry->type)
			goto conflict;
	}
	return 0;

 conflict:
	printk(KERN_INFO "%s:%d conflicting memory types "
	       "%Lx-%Lx %s<->%s\n", current->comm, current->pid, new->start,
	       new->end, cattr_name(new->type), cattr_name(entry->type));
	return -EBUSY;
}

/*
 * req_type typically has one of the:
 * - _PAGE_CACHE_WB
 * - _PAGE_CACHE_WC
 * - _PAGE_CACHE_UC_MINUS
 * - _PAGE_CACHE_UC
 *
 * req_type will have a special case value '-1', when requester want to inherit
 * the memory type from mtrr (if WB), existing PAT, defaulting to UC_MINUS.
 *
 * If new_type is NULL, function will return an error if it cannot reserve the
 * region with req_type. If new_type is non-NULL, function will return
 * available type in new_type in case of no error. In case of any error
 * it will return a negative return value.
 */
int reserve_memtype(u64 start, u64 end, unsigned long req_type,
			unsigned long *new_type)
{
	struct memtype *new, *entry;
	unsigned long actual_type;
	struct list_head *where;
	int err = 0;

 	BUG_ON(start >= end); /* end is exclusive */

	if (!pat_enabled) {
		/* This is identical to page table setting without PAT */
		if (new_type) {
			if (req_type == -1)
				*new_type = _PAGE_CACHE_WB;
			else
				*new_type = req_type & _PAGE_CACHE_MASK;
		}
		return 0;
	}

	/* Low ISA region is always mapped WB in page table. No need to track */
	if (is_ISA_range(start, end - 1)) {
		if (new_type)
			*new_type = _PAGE_CACHE_WB;
		return 0;
	}

	if (req_type == -1) {
		/*
		 * Call mtrr_lookup to get the type hint. This is an
		 * optimization for /dev/mem mmap'ers into WB memory (BIOS
		 * tools and ACPI tools). Use WB request for WB memory and use
		 * UC_MINUS otherwise.
		 */
		u8 mtrr_type = mtrr_type_lookup(start, end);

		if (mtrr_type == MTRR_TYPE_WRBACK)
			actual_type = _PAGE_CACHE_WB;
		else
			actual_type = _PAGE_CACHE_UC_MINUS;
	} else
		actual_type = pat_x_mtrr_type(start, end,
					      req_type & _PAGE_CACHE_MASK);

	new  = kmalloc(sizeof(struct memtype), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	new->start = start;
	new->end = end;
	new->type = actual_type;

	if (new_type)
		*new_type = actual_type;

	spin_lock(&memtype_lock);

	/* Search for existing mapping that overlaps the current range */
	where = NULL;
	list_for_each_entry(entry, &memtype_list, nd) {
		if (end <= entry->start) {
			where = entry->nd.prev;
			break;
		} else if (start <= entry->start) { /* end > entry->start */
			err = chk_conflict(new, entry, new_type);
			if (!err) {
				dprintk("Overlap at 0x%Lx-0x%Lx\n",
					entry->start, entry->end);
				where = entry->nd.prev;
			}
			break;
		} else if (start < entry->end) { /* start > entry->start */
			err = chk_conflict(new, entry, new_type);
			if (!err) {
				dprintk("Overlap at 0x%Lx-0x%Lx\n",
					entry->start, entry->end);
				where = &entry->nd;
			}
			break;
		}
	}

	if (err) {
		printk(KERN_INFO "reserve_memtype failed 0x%Lx-0x%Lx, "
		       "track %s, req %s\n",
		       start, end, cattr_name(new->type), cattr_name(req_type));
		kfree(new);
		spin_unlock(&memtype_lock);
		return err;
	}

	if (where)
		list_add(&new->nd, where);
	else
		list_add_tail(&new->nd, &memtype_list);

	spin_unlock(&memtype_lock);

	dprintk("reserve_memtype added 0x%Lx-0x%Lx, track %s, req %s, ret %s\n",
		start, end, cattr_name(new->type), cattr_name(req_type),
		new_type ? cattr_name(*new_type) : "-");

	return err;
}

int free_memtype(u64 start, u64 end)
{
	struct memtype *entry;
	int err = -EINVAL;

	if (!pat_enabled)
		return 0;

	/* Low ISA region is always mapped WB. No need to track */
	if (is_ISA_range(start, end - 1))
		return 0;

	spin_lock(&memtype_lock);
	list_for_each_entry(entry, &memtype_list, nd) {
		if (entry->start == start && entry->end == end) {
			list_del(&entry->nd);
			kfree(entry);
			err = 0;
			break;
		}
	}
	spin_unlock(&memtype_lock);

	if (err) {
		printk(KERN_INFO "%s:%d freeing invalid memtype %Lx-%Lx\n",
			current->comm, current->pid, start, end);
	}

	dprintk("free_memtype request 0x%Lx-0x%Lx\n", start, end);
	return err;
}


/*
 * /dev/mem mmap interface. The memtype used for mapping varies:
 * - Use UC for mappings with O_SYNC flag
 * - Without O_SYNC flag, if there is any conflict in reserve_memtype,
 *   inherit the memtype from existing mapping.
 * - Else use UC_MINUS memtype (for backward compatibility with existing
 *   X drivers.
 */
pgprot_t phys_mem_access_prot(struct file *file, unsigned long pfn,
				unsigned long size, pgprot_t vma_prot)
{
	return vma_prot;
}

#ifdef CONFIG_NONPROMISC_DEVMEM
/* This check is done in drivers/char/mem.c in case of NONPROMISC_DEVMEM*/
static inline int range_is_allowed(unsigned long pfn, unsigned long size)
{
	return 1;
}
#else
static inline int range_is_allowed(unsigned long pfn, unsigned long size)
{
	u64 from = ((u64)pfn) << PAGE_SHIFT;
	u64 to = from + size;
	u64 cursor = from;

	while (cursor < to) {
		if (!devmem_is_allowed(pfn)) {
			printk(KERN_INFO
		"Program %s tried to access /dev/mem between %Lx->%Lx.\n",
				current->comm, from, to);
			return 0;
		}
		cursor += PAGE_SIZE;
		pfn++;
	}
	return 1;
}
#endif /* CONFIG_NONPROMISC_DEVMEM */

int phys_mem_access_prot_allowed(struct file *file, unsigned long pfn,
				unsigned long size, pgprot_t *vma_prot)
{
	u64 offset = ((u64) pfn) << PAGE_SHIFT;
	unsigned long flags = _PAGE_CACHE_UC_MINUS;
	int retval;

	if (!range_is_allowed(pfn, size))
		return 0;

	if (file->f_flags & O_SYNC) {
		flags = _PAGE_CACHE_UC;
	}

#ifdef CONFIG_X86_32
	/*
	 * On the PPro and successors, the MTRRs are used to set
	 * memory types for physical addresses outside main memory,
	 * so blindly setting UC or PWT on those pages is wrong.
	 * For Pentiums and earlier, the surround logic should disable
	 * caching for the high addresses through the KEN pin, but
	 * we maintain the tradition of paranoia in this code.
	 */
	if (!pat_enabled &&
	    !(boot_cpu_has(X86_FEATURE_MTRR) ||
	      boot_cpu_has(X86_FEATURE_K6_MTRR) ||
	      boot_cpu_has(X86_FEATURE_CYRIX_ARR) ||
	      boot_cpu_has(X86_FEATURE_CENTAUR_MCR)) &&
	    (pfn << PAGE_SHIFT) >= __pa(high_memory)) {
		flags = _PAGE_CACHE_UC;
	}
#endif

	/*
	 * With O_SYNC, we can only take UC mapping. Fail if we cannot.
	 * Without O_SYNC, we want to get
	 * - WB for WB-able memory and no other conflicting mappings
	 * - UC_MINUS for non-WB-able memory with no other conflicting mappings
	 * - Inherit from confliting mappings otherwise
	 */
	if (flags != _PAGE_CACHE_UC_MINUS) {
		retval = reserve_memtype(offset, offset + size, flags, NULL);
	} else {
		retval = reserve_memtype(offset, offset + size, -1, &flags);
	}

	if (retval < 0)
		return 0;

	if (pfn <= max_pfn_mapped &&
	    ioremap_change_attr((unsigned long)__va(offset), size, flags) < 0) {
		free_memtype(offset, offset + size);
		printk(KERN_INFO
		"%s:%d /dev/mem ioremap_change_attr failed %s for %Lx-%Lx\n",
			current->comm, current->pid,
			cattr_name(flags),
			offset, (unsigned long long)(offset + size));
		return 0;
	}

	*vma_prot = __pgprot((pgprot_val(*vma_prot) & ~_PAGE_CACHE_MASK) |
			     flags);
	return 1;
}

void map_devmem(unsigned long pfn, unsigned long size, pgprot_t vma_prot)
{
	u64 addr = (u64)pfn << PAGE_SHIFT;
	unsigned long flags;
	unsigned long want_flags = (pgprot_val(vma_prot) & _PAGE_CACHE_MASK);

	reserve_memtype(addr, addr + size, want_flags, &flags);
	if (flags != want_flags) {
		printk(KERN_INFO
		"%s:%d /dev/mem expected mapping type %s for %Lx-%Lx, got %s\n",
			current->comm, current->pid,
			cattr_name(want_flags),
			addr, (unsigned long long)(addr + size),
			cattr_name(flags));
	}
}

void unmap_devmem(unsigned long pfn, unsigned long size, pgprot_t vma_prot)
{
	u64 addr = (u64)pfn << PAGE_SHIFT;

	free_memtype(addr, addr + size);
}
