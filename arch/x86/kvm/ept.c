/*-
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include "bhyve_linux_defs.h"

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/smp.h>

#include "ept.h"

#define	EPT_PWL4(cap)			((cap) & (1UL << 6))
#define	EPT_MEMORY_TYPE_WB(cap)		((cap) & (1UL << 14))
#define	EPT_PDE_SUPERPAGE(cap)		((cap) & (1UL << 16))	/* 2MB pages */
#define	EPT_PDPTE_SUPERPAGE(cap)	((cap) & (1UL << 17))	/* 1GB pages */
#define	INVVPID_SUPPORTED(cap)		((cap) & (1UL << 32))
#define	INVEPT_SUPPORTED(cap)		((cap) & (1UL << 20))

#define	INVVPID_ALL_TYPES_MASK		0xF0000000000UL
#define	INVVPID_ALL_TYPES_SUPPORTED(cap)	\
	(((cap) & INVVPID_ALL_TYPES_MASK) == INVVPID_ALL_TYPES_MASK)

#define	INVEPT_ALL_TYPES_MASK		0x6000000UL
#define	INVEPT_ALL_TYPES_SUPPORTED(cap)		\
	(((cap) & INVEPT_ALL_TYPES_MASK) == INVEPT_ALL_TYPES_MASK)

#define	EPT_PG_RD			(1 << 0)
#define	EPT_PG_WR			(1 << 1)
#define	EPT_PG_EX			(1 << 2)
#define	EPT_PG_MEMORY_TYPE(x)		((x) << 3)
#define	EPT_PG_IGNORE_PAT		(1 << 6)
#define	EPT_PG_SUPERPAGE		(1 << 7)

#define	EPT_ADDR_MASK			((uint64_t)-1 << 12)

#define EPT_REGION_BASE_ADDRESS         (2 * 1024UL * 1024 * 1024)
#define EPT_REGION_SIZE                 (16 * 1024UL * 1024)

#define PHYS_TO_DMAP(_addr_)            (ept_mapped_addr + (_addr_) - 0x80000000)

static uint64_t page_sizes_mask;

static void *ept_mapped_addr = 0;

/* Set aside a region in memory for the extended page tables */
uint64_t ept_malloc(void)
{
	static int last_page_reserved = 1;
	uint64_t addr_to_allocate;
	
	addr_to_allocate = EPT_REGION_BASE_ADDRESS + (last_page_reserved * (1 << 12));

	if (addr_to_allocate >= (EPT_REGION_BASE_ADDRESS + EPT_REGION_SIZE)) {
		printk("Attempted to allocate an address beyond the EPT region!\n");
	}

	printk("Allocated EPT page 0x%lp\n", last_page_reserved);

	last_page_reserved++;

	return addr_to_allocate;
}

int
ept_init(void)
{
	int page_shift;
	uint64_t cap;

	cap = native_read_msr(MSR_IA32_VMX_EPT_VPID_CAP);

	/* We need to map the extended page table region in physical memory into our address space */
	ept_mapped_addr = ioremap_cache(EPT_REGION_BASE_ADDRESS, EPT_REGION_SIZE);

	printk("Mapped EPT region at physical address 0x%lx to virtual address 0x%lx\n",
		EPT_REGION_BASE_ADDRESS, ept_mapped_addr);

	memset(ept_mapped_addr, 0x0, EPT_REGION_SIZE);

	printk("Memset EPT region to all zeros\n");

	/*
	 * Verify that:
	 * - page walk length is 4 steps
	 * - extended page tables can be laid out in write-back memory
	 * - invvpid instruction with all possible types is supported
	 * - invept instruction with all possible types is supported
	 */
	if (!EPT_PWL4(cap) ||
	    !EPT_MEMORY_TYPE_WB(cap) ||
	    !INVVPID_SUPPORTED(cap) ||
	    !INVVPID_ALL_TYPES_SUPPORTED(cap) ||
	    !INVEPT_SUPPORTED(cap) ||
	    !INVEPT_ALL_TYPES_SUPPORTED(cap))
		return (EINVAL);

	/* Set bits in 'page_sizes_mask' for each valid page size */
	page_shift = PAGE_SHIFT;
	page_sizes_mask = 1UL << page_shift;		/* 4KB page */

	page_shift += 9;
	if (EPT_PDE_SUPERPAGE(cap))
		page_sizes_mask |= 1UL << page_shift;	/* 2MB superpage */

	page_shift += 9;
	if (EPT_PDPTE_SUPERPAGE(cap))
		page_sizes_mask |= 1UL << page_shift;	/* 1GB superpage */

	return (0);
}


static size_t
ept_create_mapping(uint64_t *ptp, phys_addr_t gpa, phys_addr_t hpa, size_t length,
		   int attr, unsigned long prot, bool spok)
{
	int spshift, ptpshift, ptpindex, nlevels;

	ptp = (void *) PHYS_TO_DMAP((uint64_t) ptp);

	/*
	 * Compute the size of the mapping that we can accomodate.
	 *
	 * This is based on three factors:
	 * - super page sizes supported by the processor
	 * - alignment of the region starting at 'gpa' and 'hpa'
	 * - length of the region 'len'
	 */
	spshift = PAGE_SHIFT;
	if (spok)
		spshift += (EPT_PWLEVELS - 1) * 9;
	while (spshift >= PAGE_SHIFT) {
		uint64_t spsize = 1UL << spshift;
		if ((page_sizes_mask & spsize) != 0 &&
		    (gpa & (spsize - 1)) == 0 &&
		    (hpa & (spsize - 1)) == 0 &&
		    length >= spsize) {
			break;
		}
		spshift -= 9;
	}

	if (spshift < PAGE_SHIFT) {
		panic("Invalid spshift for gpa 0x%016lx, hpa 0x%016lx, "
		      "length 0x%016lx, page_sizes_mask 0x%016lx",
		      gpa, hpa, length, page_sizes_mask);
	}

	//printk("spshift is 0x%x\n");

	nlevels = EPT_PWLEVELS;
	while (--nlevels >= 0) {
		ptpshift = PAGE_SHIFT + nlevels * 9;
		ptpindex = (gpa >> ptpshift) & 0x1FF;

		//printk("ptpshift 0x%x, ptpindex 0x%x\n", ptpshift, ptpindex);

		/* We have reached the leaf mapping */
		if (spshift >= ptpshift)
			//printk("Reached the leaf mapping!\n");
			break;

		/*
		 * We are working on a non-leaf page table page.
		 *
		 * Create the next level page table page if necessary and point
		 * to it from the current page table.
		 */

		//printk("Working on a non-leaf page table page\n");

		if (ptp[ptpindex] == 0) {

			//printk("Pagetable pointer is zero; allocating new page and setting the pointer\n");

			void *nlp = ept_malloc();

			//printk("New physical pointer is 0x%lx\n", nlp);

			// ept_malloc already returns a physical address...
			//ptp[ptpindex] = virt_to_phys(nlp);
			ptp[ptpindex] = nlp;
			ptp[ptpindex] |= EPT_PG_RD | EPT_PG_WR | EPT_PG_EX;
		}

		/* Work our way down to the next level page table page */
		ptp = (uint64_t *) PHYS_TO_DMAP(ptp[ptpindex] & EPT_ADDR_MASK);
	}

	if ((gpa & ((1UL << ptpshift) - 1)) != 0) {
		panic("ept_create_mapping: gpa 0x%016lx and ptpshift %d "
		      "mismatch\n", gpa, ptpshift);
	}

	/* Do the mapping */
	ptp[ptpindex] = hpa;

	/* Apply the access controls */
	/*
	if (prot & PROT_READ)
		ptp[ptpindex] |= EPT_PG_RD;
	if (prot & PROT_WRITE)
		ptp[ptpindex] |= EPT_PG_WR;
	if (prot & PROT_EXEC)
		ptp[ptpindex] |= EPT_PG_EX;
	*/
	ptp[ptpindex] |= (EPT_PG_RD | EPT_PG_WR | EPT_PG_EX);

	/*
	 * XXX should we enforce this memory type by setting the ignore PAT
	 * bit to 1.
	 */
	ptp[ptpindex] |= EPT_PG_MEMORY_TYPE(attr);

	if (nlevels > 0)
		ptp[ptpindex] |= EPT_PG_SUPERPAGE;

	return (1UL << ptpshift);
}

static void
ept_free_pt_entry(pt_entry_t pte)
{
	if (pte == 0)
		return;

	/* sanity check */
	if ((pte & EPT_PG_SUPERPAGE) != 0)
		panic("ept_free_pt_entry: pte cannot have superpage bit");

	return;
}

static void
ept_free_pd_entry(pd_entry_t pde)
{
	pt_entry_t	*pt;
	int		i;

	if (pde == 0)
		return;

	if ((pde & EPT_PG_SUPERPAGE) == 0) {
		pt = (pt_entry_t *)PHYS_TO_DMAP(pde & EPT_ADDR_MASK);
		for (i = 0; i < NPTEPG; i++)
			ept_free_pt_entry(pt[i]);
		//free(pt, M_VMX);	/* free the page table page */
	}
}

static void
ept_free_pdp_entry(pdp_entry_t pdpe)
{
	pd_entry_t 	*pd;
	int		 i;

	if (pdpe == 0)
		return;

	if ((pdpe & EPT_PG_SUPERPAGE) == 0) {
		pd = (pd_entry_t *)PHYS_TO_DMAP(pdpe & EPT_ADDR_MASK);
		for (i = 0; i < NPDEPG; i++)
			ept_free_pd_entry(pd[i]);
		//free(pd, M_VMX);	/* free the page directory page */
	}
}

static void
ept_free_pml4_entry(pml4_entry_t pml4e)
{
	pdp_entry_t	*pdp;
	int		i;

	if (pml4e == 0)
		return;

	if ((pml4e & EPT_PG_SUPERPAGE) == 0) {
		pdp = (pdp_entry_t *)PHYS_TO_DMAP(pml4e & EPT_ADDR_MASK);
		for (i = 0; i < NPDPEPG; i++)
			ept_free_pdp_entry(pdp[i]);
		//free(pdp, M_VMX);	/* free the page directory ptr page */
	}
}

#if 0
void
ept_vmcleanup(struct vmx *vmx)
{
	int 		 i;

	for (i = 0; i < NPML4EPG; i++)
		ept_free_pml4_entry(vmx->pml4ept[i]);
}
#endif

int
ept_vmmmap(void *eptp, phys_addr_t gpa, phys_addr_t hpa, size_t len,
	   int attr, int prot, bool spok)
{
	size_t n;

	printk("Called ept_vmmmap, eptp 0x%lp, gpa 0x%lx, hpa 0x%lx, len 0x%lx\n",
		eptp, gpa, hpa, len);

	while (len > 0) {
		//printk("ept_vmmmap: len is 0x%lx\n", len);

		n = ept_create_mapping(eptp, gpa, hpa, len, attr,
				       prot, spok);
		len -= n;
		gpa += n;
		hpa += n;
	}

	return (0);
}
#if 0
static void
invept_single_context(void *arg)
{
	struct invept_desc desc = *(struct invept_desc *)arg;

	invept(INVEPT_TYPE_SINGLE_CONTEXT, desc);
}

void
ept_invalidate_mappings(u_long pml4ept)
{
	struct invept_desc invept_desc = { 0 };

	invept_desc.eptp = EPTP(pml4ept);

	smp_rendezvous(NULL, invept_single_context, NULL, &invept_desc);
}
#endif

