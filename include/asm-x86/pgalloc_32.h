#ifndef _I386_PGALLOC_H
#define _I386_PGALLOC_H

#include <linux/threads.h>
#include <linux/mm.h>		/* for struct page */
#include <asm/tlb.h>
#include <asm-generic/tlb.h>

#ifdef CONFIG_PARAVIRT
#include <asm/paravirt.h>
#else
#define paravirt_alloc_pt(mm, pfn) do { } while (0)
#define paravirt_alloc_pd(mm, pfn) do { } while (0)
#define paravirt_alloc_pd_clone(pfn, clonepfn, start, count) do { } while (0)
#define paravirt_release_pt(pfn) do { } while (0)
#define paravirt_release_pd(pfn) do { } while (0)
#endif

static inline void pmd_populate_kernel(struct mm_struct *mm,
				       pmd_t *pmd, pte_t *pte)
{
	paravirt_alloc_pt(mm, __pa(pte) >> PAGE_SHIFT);
	set_pmd(pmd, __pmd(__pa(pte) | _PAGE_TABLE));
}

static inline void pmd_populate(struct mm_struct *mm, pmd_t *pmd, struct page *pte)
{
	unsigned long pfn = page_to_pfn(pte);

	paravirt_alloc_pt(mm, pfn);
	set_pmd(pmd, __pmd(((pteval_t)pfn << PAGE_SHIFT) | _PAGE_TABLE));
}

/*
 * Allocate and free page tables.
 */
extern pgd_t *pgd_alloc(struct mm_struct *);
extern void pgd_free(pgd_t *pgd);

extern pte_t *pte_alloc_one_kernel(struct mm_struct *, unsigned long);
extern struct page *pte_alloc_one(struct mm_struct *, unsigned long);

static inline void pte_free_kernel(pte_t *pte)
{
	free_page((unsigned long)pte);
}

static inline void pte_free(struct page *pte)
{
	__free_page(pte);
}


static inline void __pte_free_tlb(struct mmu_gather *tlb, struct page *pte)
{
	paravirt_release_pt(page_to_pfn(pte));
	tlb_remove_page(tlb, pte);
}

#ifdef CONFIG_X86_PAE
/*
 * In the PAE case we free the pmds as part of the pgd.
 */
static inline pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	return (pmd_t *)get_zeroed_page(GFP_KERNEL|__GFP_REPEAT);
}

static inline void pmd_free(pmd_t *pmd)
{
	BUG_ON((unsigned long)pmd & (PAGE_SIZE-1));
	free_page((unsigned long)pmd);
}

static inline void __pmd_free_tlb(struct mmu_gather *tlb, pmd_t *pmd)
{
	paravirt_release_pd(__pa(pmd) >> PAGE_SHIFT);
	tlb_remove_page(tlb, virt_to_page(pmd));
}

static inline void pud_populate(struct mm_struct *mm, pud_t *pudp, pmd_t *pmd)
{
	paravirt_alloc_pd(mm, __pa(pmd) >> PAGE_SHIFT);

	/* Note: almost everything apart from _PAGE_PRESENT is
	   reserved at the pmd (PDPT) level. */
	set_pud(pudp, __pud(__pa(pmd) | _PAGE_PRESENT));

	/*
	 * Pentium-II erratum A13: in PAE mode we explicitly have to flush
	 * the TLB via cr3 if the top-level pgd is changed...
	 */
	if (mm == current->active_mm)
		write_cr3(read_cr3());
}
#endif	/* CONFIG_X86_PAE */

#endif /* _I386_PGALLOC_H */
