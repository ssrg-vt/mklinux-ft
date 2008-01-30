/*
 * Copyright 2002 Andi Kleen, SuSE Labs.
 * Thanks to Ben LaHaise for precious feedback.
 */
#include <linux/highmem.h>
#include <linux/bootmem.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/mm.h>

#include <asm/e820.h>
#include <asm/processor.h>
#include <asm/tlbflush.h>
#include <asm/sections.h>
#include <asm/uaccess.h>
#include <asm/pgalloc.h>

static inline int
within(unsigned long addr, unsigned long start, unsigned long end)
{
	return addr >= start && addr < end;
}

/*
 * Flushing functions
 */
void clflush_cache_range(void *addr, int size)
{
	int i;

	for (i = 0; i < size; i += boot_cpu_data.x86_clflush_size)
		clflush(addr+i);
}

static void flush_kernel_map(void *arg)
{
	/*
	 * Flush all to work around Errata in early athlons regarding
	 * large page flushing.
	 */
	__flush_tlb_all();

	if (boot_cpu_data.x86_model >= 4)
		wbinvd();
}

static void global_flush_tlb(void)
{
	BUG_ON(irqs_disabled());

	on_each_cpu(flush_kernel_map, NULL, 1, 1);
}

/*
 * Certain areas of memory on x86 require very specific protection flags,
 * for example the BIOS area or kernel text. Callers don't always get this
 * right (again, ioremap() on BIOS memory is not uncommon) so this function
 * checks and fixes these known static required protection bits.
 */
static inline pgprot_t static_protections(pgprot_t prot, unsigned long address)
{
	pgprot_t forbidden = __pgprot(0);

	/*
	 * The BIOS area between 640k and 1Mb needs to be executable for
	 * PCI BIOS based config access (CONFIG_PCI_GOBIOS) support.
	 */
	if (within(__pa(address), BIOS_BEGIN, BIOS_END))
		pgprot_val(forbidden) |= _PAGE_NX;

	/*
	 * The kernel text needs to be executable for obvious reasons
	 * Does not cover __inittext since that is gone later on
	 */
	if (within(address, (unsigned long)_text, (unsigned long)_etext))
		pgprot_val(forbidden) |= _PAGE_NX;

#ifdef CONFIG_DEBUG_RODATA
	/* The .rodata section needs to be read-only */
	if (within(address, (unsigned long)__start_rodata,
				(unsigned long)__end_rodata))
		pgprot_val(forbidden) |= _PAGE_RW;
#endif

	prot = __pgprot(pgprot_val(prot) & ~pgprot_val(forbidden));

	return prot;
}

pte_t *lookup_address(unsigned long address, int *level)
{
	pgd_t *pgd = pgd_offset_k(address);
	pud_t *pud;
	pmd_t *pmd;

	*level = PG_LEVEL_NONE;

	if (pgd_none(*pgd))
		return NULL;
	pud = pud_offset(pgd, address);
	if (pud_none(*pud))
		return NULL;
	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd))
		return NULL;

	*level = PG_LEVEL_2M;
	if (pmd_large(*pmd))
		return (pte_t *)pmd;

	*level = PG_LEVEL_4K;
	return pte_offset_kernel(pmd, address);
}

static void __set_pmd_pte(pte_t *kpte, unsigned long address, pte_t pte)
{
	/* change init_mm */
	set_pte_atomic(kpte, pte);
#ifdef CONFIG_X86_32
	if (!SHARED_KERNEL_PMD) {
		struct page *page;

		for (page = pgd_list; page; page = (struct page *)page->index) {
			pgd_t *pgd;
			pud_t *pud;
			pmd_t *pmd;

			pgd = (pgd_t *)page_address(page) + pgd_index(address);
			pud = pud_offset(pgd, address);
			pmd = pmd_offset(pud, address);
			set_pte_atomic((pte_t *)pmd, pte);
		}
	}
#endif
}

static int split_large_page(pte_t *kpte, unsigned long address)
{
	pgprot_t ref_prot = pte_pgprot(pte_clrhuge(*kpte));
	gfp_t gfp_flags = GFP_KERNEL;
	unsigned long flags;
	unsigned long addr;
	pte_t *pbase, *tmp;
	struct page *base;
	int i, level;

#ifdef CONFIG_DEBUG_PAGEALLOC
	gfp_flags = GFP_ATOMIC;
#endif
	base = alloc_pages(gfp_flags, 0);
	if (!base)
		return -ENOMEM;

	spin_lock_irqsave(&pgd_lock, flags);
	/*
	 * Check for races, another CPU might have split this page
	 * up for us already:
	 */
	tmp = lookup_address(address, &level);
	if (tmp != kpte) {
		WARN_ON_ONCE(1);
		goto out_unlock;
	}

	address = __pa(address);
	addr = address & LARGE_PAGE_MASK;
	pbase = (pte_t *)page_address(base);
#ifdef CONFIG_X86_32
	paravirt_alloc_pt(&init_mm, page_to_pfn(base));
#endif

	for (i = 0; i < PTRS_PER_PTE; i++, addr += PAGE_SIZE)
		set_pte(&pbase[i], pfn_pte(addr >> PAGE_SHIFT, ref_prot));

	/*
	 * Install the new, split up pagetable. Important detail here:
	 *
	 * On Intel the NX bit of all levels must be cleared to make a
	 * page executable. See section 4.13.2 of Intel 64 and IA-32
	 * Architectures Software Developer's Manual).
	 */
	ref_prot = pte_pgprot(pte_mkexec(pte_clrhuge(*kpte)));
	__set_pmd_pte(kpte, address, mk_pte(base, ref_prot));
	base = NULL;

out_unlock:
	spin_unlock_irqrestore(&pgd_lock, flags);

	if (base)
		__free_pages(base, 0);

	return 0;
}

static int
__change_page_attr(unsigned long address, unsigned long pfn, pgprot_t prot)
{
	struct page *kpte_page;
	int level, err = 0;
	pte_t *kpte;

#ifdef CONFIG_X86_32
	BUG_ON(pfn > max_low_pfn);
#endif

repeat:
	kpte = lookup_address(address, &level);
	if (!kpte)
		return -EINVAL;

	kpte_page = virt_to_page(kpte);
	BUG_ON(PageLRU(kpte_page));
	BUG_ON(PageCompound(kpte_page));

	prot = static_protections(prot, address);

	if (level == PG_LEVEL_4K) {
		WARN_ON_ONCE(pgprot_val(prot) & _PAGE_PSE);
		set_pte_atomic(kpte, pfn_pte(pfn, canon_pgprot(prot)));
	} else {
		/* Clear the PSE bit for the 4k level pages ! */
		pgprot_val(prot) = pgprot_val(prot) & ~_PAGE_PSE;

		err = split_large_page(kpte, address);
		if (!err)
			goto repeat;
	}
	return err;
}

/**
 * change_page_attr_addr - Change page table attributes in linear mapping
 * @address: Virtual address in linear mapping.
 * @prot:    New page table attribute (PAGE_*)
 *
 * Change page attributes of a page in the direct mapping. This is a variant
 * of change_page_attr() that also works on memory holes that do not have
 * mem_map entry (pfn_valid() is false).
 *
 * See change_page_attr() documentation for more details.
 *
 * Modules and drivers should use the set_memory_* APIs instead.
 */

static int change_page_attr_addr(unsigned long address, pgprot_t prot)
{
	int err = 0, kernel_map = 0;
	unsigned long pfn = __pa(address) >> PAGE_SHIFT;

#ifdef CONFIG_X86_64
	if (address >= __START_KERNEL_map &&
			address < __START_KERNEL_map + KERNEL_TEXT_SIZE) {

		address = (unsigned long)__va(__pa(address));
		kernel_map = 1;
	}
#endif

	if (!kernel_map || pte_present(pfn_pte(0, prot))) {
		err = __change_page_attr(address, pfn, prot);
		if (err)
			return err;
	}

#ifdef CONFIG_X86_64
	/*
	 * Handle kernel mapping too which aliases part of
	 * lowmem:
	 */
	if (__pa(address) < KERNEL_TEXT_SIZE) {
		unsigned long addr2;
		pgprot_t prot2;

		addr2 = __START_KERNEL_map + __pa(address);
		/* Make sure the kernel mappings stay executable */
		prot2 = pte_pgprot(pte_mkexec(pfn_pte(0, prot)));
		err = __change_page_attr(addr2, pfn, prot2);
	}
#endif

	return err;
}

/**
 * change_page_attr_set - Change page table attributes in the linear mapping.
 * @addr: Virtual address in linear mapping.
 * @numpages: Number of pages to change
 * @prot: Protection/caching type bits to set (PAGE_*)
 *
 * Returns 0 on success, otherwise a negated errno.
 *
 * This should be used when a page is mapped with a different caching policy
 * than write-back somewhere - some CPUs do not like it when mappings with
 * different caching policies exist. This changes the page attributes of the
 * in kernel linear mapping too.
 *
 * The caller needs to ensure that there are no conflicting mappings elsewhere
 * (e.g. in user space) * This function only deals with the kernel linear map.
 *
 * This function is different from change_page_attr() in that only selected bits
 * are impacted, all other bits remain as is.
 */
static int change_page_attr_set(unsigned long addr, int numpages,
								pgprot_t prot)
{
	pgprot_t current_prot;
	int level;
	pte_t *pte;
	int i, ret;

	for (i = 0; i < numpages ; i++) {

		pte = lookup_address(addr, &level);
		if (pte)
			current_prot = pte_pgprot(*pte);
		else
			pgprot_val(current_prot) = 0;

		pgprot_val(prot) = pgprot_val(current_prot) | pgprot_val(prot);

		ret = change_page_attr_addr(addr, prot);
		if (ret)
			return ret;
		addr += PAGE_SIZE;
	}
	return 0;
}

/**
 * change_page_attr_clear - Change page table attributes in the linear mapping.
 * @addr: Virtual address in linear mapping.
 * @numpages: Number of pages to change
 * @prot: Protection/caching type bits to clear (PAGE_*)
 *
 * Returns 0 on success, otherwise a negated errno.
 *
 * This should be used when a page is mapped with a different caching policy
 * than write-back somewhere - some CPUs do not like it when mappings with
 * different caching policies exist. This changes the page attributes of the
 * in kernel linear mapping too.
 *
 * The caller needs to ensure that there are no conflicting mappings elsewhere
 * (e.g. in user space) * This function only deals with the kernel linear map.
 *
 * This function is different from change_page_attr() in that only selected bits
 * are impacted, all other bits remain as is.
 */
static int change_page_attr_clear(unsigned long addr, int numpages,
								pgprot_t prot)
{
	pgprot_t current_prot;
	int level;
	pte_t *pte;
	int i, ret;

	for (i = 0; i < numpages; i++) {
		pte = lookup_address(addr, &level);
		if (pte)
			current_prot = pte_pgprot(*pte);
		else
			pgprot_val(current_prot) = 0;

		pgprot_val(prot) =
				pgprot_val(current_prot) & ~pgprot_val(prot);

		ret = change_page_attr_addr(addr, prot);
		if (ret)
			return ret;
		addr += PAGE_SIZE;
	}
	return 0;
}

int set_memory_uc(unsigned long addr, int numpages)
{
	int err;

	err = change_page_attr_set(addr, numpages,
				__pgprot(_PAGE_PCD | _PAGE_PWT));
	global_flush_tlb();
	return err;
}
EXPORT_SYMBOL(set_memory_uc);

int set_memory_wb(unsigned long addr, int numpages)
{
	int err;

	err = change_page_attr_clear(addr, numpages,
				__pgprot(_PAGE_PCD | _PAGE_PWT));
	global_flush_tlb();
	return err;
}
EXPORT_SYMBOL(set_memory_wb);

int set_memory_x(unsigned long addr, int numpages)
{
	int err;

	err = change_page_attr_clear(addr, numpages,
				__pgprot(_PAGE_NX));
	global_flush_tlb();
	return err;
}
EXPORT_SYMBOL(set_memory_x);

int set_memory_nx(unsigned long addr, int numpages)
{
	int err;

	err = change_page_attr_set(addr, numpages,
				__pgprot(_PAGE_NX));
	global_flush_tlb();
	return err;
}
EXPORT_SYMBOL(set_memory_nx);

int set_memory_ro(unsigned long addr, int numpages)
{
	int err;

	err = change_page_attr_clear(addr, numpages,
				__pgprot(_PAGE_RW));
	global_flush_tlb();
	return err;
}

int set_memory_rw(unsigned long addr, int numpages)
{
	int err;

	err = change_page_attr_set(addr, numpages,
				__pgprot(_PAGE_RW));
	global_flush_tlb();
	return err;
}

int set_memory_np(unsigned long addr, int numpages)
{
	int err;

	err = change_page_attr_clear(addr, numpages,
				__pgprot(_PAGE_PRESENT));
	global_flush_tlb();
	return err;
}

int set_pages_uc(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_uc(addr, numpages);
}
EXPORT_SYMBOL(set_pages_uc);

int set_pages_wb(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_wb(addr, numpages);
}
EXPORT_SYMBOL(set_pages_wb);

int set_pages_x(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_x(addr, numpages);
}
EXPORT_SYMBOL(set_pages_x);

int set_pages_nx(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_nx(addr, numpages);
}
EXPORT_SYMBOL(set_pages_nx);

int set_pages_ro(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_ro(addr, numpages);
}

int set_pages_rw(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_rw(addr, numpages);
}


#ifdef CONFIG_DEBUG_PAGEALLOC

static int __set_pages_p(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);
	return change_page_attr_set(addr, numpages,
				__pgprot(_PAGE_PRESENT | _PAGE_RW));
}

static int __set_pages_np(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);
	return change_page_attr_clear(addr, numpages, __pgprot(_PAGE_PRESENT));
}

void kernel_map_pages(struct page *page, int numpages, int enable)
{
	if (PageHighMem(page))
		return;
	if (!enable) {
		debug_check_no_locks_freed(page_address(page),
					   numpages * PAGE_SIZE);
	}

	/*
	 * If page allocator is not up yet then do not call c_p_a():
	 */
	if (!debug_pagealloc_enabled)
		return;

	/*
	 * The return value is ignored - the calls cannot fail,
	 * large pages are disabled at boot time:
	 */
	if (enable)
		__set_pages_p(page, numpages);
	else
		__set_pages_np(page, numpages);

	/*
	 * We should perform an IPI and flush all tlbs,
	 * but that can deadlock->flush only current cpu:
	 */
	__flush_tlb_all();
}
#endif

/*
 * The testcases use internal knowledge of the implementation that shouldn't
 * be exposed to the rest of the kernel. Include these directly here.
 */
#ifdef CONFIG_CPA_DEBUG
#include "pageattr-test.c"
#endif
