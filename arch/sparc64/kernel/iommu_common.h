/* $Id: iommu_common.h,v 1.5 2001/12/11 09:41:01 davem Exp $
 * iommu_common.h: UltraSparc SBUS/PCI common iommu declarations.
 *
 * Copyright (C) 1999 David S. Miller (davem@redhat.com)
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/device.h>

#include <asm/iommu.h>
#include <asm/scatterlist.h>

/*
 * These give mapping size of each iommu pte/tlb.
 */
#define IO_PAGE_SHIFT			13
#define IO_PAGE_SIZE			(1UL << IO_PAGE_SHIFT)
#define IO_PAGE_MASK			(~(IO_PAGE_SIZE-1))
#define IO_PAGE_ALIGN(addr)		(((addr)+IO_PAGE_SIZE-1)&IO_PAGE_MASK)

#define IO_TSB_ENTRIES			(128*1024)
#define IO_TSB_SIZE			(IO_TSB_ENTRIES * 8)

/*
 * This is the hardwired shift in the iotlb tag/data parts.
 */
#define IOMMU_PAGE_SHIFT		13

#define SG_ENT_PHYS_ADDRESS(SG)	(__pa(sg_virt((SG))))

static inline unsigned long iommu_num_pages(unsigned long vaddr,
					    unsigned long slen)
{
	unsigned long npages;

	npages = IO_PAGE_ALIGN(vaddr + slen) - (vaddr & IO_PAGE_MASK);
	npages >>= IO_PAGE_SHIFT;

	return npages;
}

static inline unsigned long calc_npages(struct scatterlist *sglist, int nelems)
{
	unsigned long i, npages = 0;
	struct scatterlist *sg;

	for_each_sg(sglist, sg, nelems, i) {
		unsigned long paddr = SG_ENT_PHYS_ADDRESS(sg);
		npages += iommu_num_pages(paddr, sg->length);
	}

	return npages;
}
