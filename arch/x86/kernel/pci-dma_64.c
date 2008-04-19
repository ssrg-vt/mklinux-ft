/*
 * Dynamic DMA mapping support.
 */

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/dmar.h>
#include <linux/bootmem.h>
#include <asm/proto.h>
#include <asm/io.h>
#include <asm/gart.h>
#include <asm/calgary.h>

dma_addr_t bad_dma_address __read_mostly;
EXPORT_SYMBOL(bad_dma_address);

/* Dummy device used for NULL arguments (normally ISA). Better would
   be probably a smaller DMA mask, but this is bug-to-bug compatible
   to i386. */
struct device fallback_dev = {
	.bus_id = "fallback device",
	.coherent_dma_mask = DMA_32BIT_MASK,
	.dma_mask = &fallback_dev.coherent_dma_mask,
};

/* Allocate DMA memory on node near device */
noinline static void *
dma_alloc_pages(struct device *dev, gfp_t gfp, unsigned order)
{
	struct page *page;
	int node;

	node = dev_to_node(dev);

	page = alloc_pages_node(node, gfp, order);
	return page ? page_address(page) : NULL;
}

/*
 * Allocate memory for a coherent mapping.
 */
void *
dma_alloc_coherent(struct device *dev, size_t size, dma_addr_t *dma_handle,
		   gfp_t gfp)
{
	void *memory;
	unsigned long dma_mask = 0;
	u64 bus;

	if (!dev)
		dev = &fallback_dev;
	dma_mask = dev->coherent_dma_mask;
	if (dma_mask == 0)
		dma_mask = DMA_32BIT_MASK;

	/* Device not DMA able */
	if (dev->dma_mask == NULL)
		return NULL;

	/* Don't invoke OOM killer */
	gfp |= __GFP_NORETRY;

	/* Kludge to make it bug-to-bug compatible with i386. i386
	   uses the normal dma_mask for alloc_coherent. */
	dma_mask &= *dev->dma_mask;

	/* Why <=? Even when the mask is smaller than 4GB it is often
	   larger than 16MB and in this case we have a chance of
	   finding fitting memory in the next higher zone first. If
	   not retry with true GFP_DMA. -AK */
	if (dma_mask <= DMA_32BIT_MASK)
		gfp |= GFP_DMA32;

 again:
	memory = dma_alloc_pages(dev, gfp, get_order(size));
	if (memory == NULL)
		return NULL;

	{
		int high, mmu;
		bus = virt_to_bus(memory);
	        high = (bus + size) >= dma_mask;
		mmu = high;
		if (force_iommu && !(gfp & GFP_DMA))
			mmu = 1;
		else if (high) {
			free_pages((unsigned long)memory,
				   get_order(size));

			/* Don't use the 16MB ZONE_DMA unless absolutely
			   needed. It's better to use remapping first. */
			if (dma_mask < DMA_32BIT_MASK && !(gfp & GFP_DMA)) {
				gfp = (gfp & ~GFP_DMA32) | GFP_DMA;
				goto again;
			}

			/* Let low level make its own zone decisions */
			gfp &= ~(GFP_DMA32|GFP_DMA);

			if (dma_ops->alloc_coherent)
				return dma_ops->alloc_coherent(dev, size,
							   dma_handle, gfp);
			return NULL;
		}

		memset(memory, 0, size);
		if (!mmu) {
			*dma_handle = virt_to_bus(memory);
			return memory;
		}
	}

	if (dma_ops->alloc_coherent) {
		free_pages((unsigned long)memory, get_order(size));
		gfp &= ~(GFP_DMA|GFP_DMA32);
		return dma_ops->alloc_coherent(dev, size, dma_handle, gfp);
	}

	if (dma_ops->map_simple) {
		*dma_handle = dma_ops->map_simple(dev, virt_to_phys(memory),
					      size,
					      PCI_DMA_BIDIRECTIONAL);
		if (*dma_handle != bad_dma_address)
			return memory;
	}

	if (panic_on_overflow)
		panic("dma_alloc_coherent: IOMMU overflow by %lu bytes\n",size);
	free_pages((unsigned long)memory, get_order(size));
	return NULL;
}
EXPORT_SYMBOL(dma_alloc_coherent);

/*
 * Unmap coherent memory.
 * The caller must ensure that the device has finished accessing the mapping.
 */
void dma_free_coherent(struct device *dev, size_t size,
			 void *vaddr, dma_addr_t bus)
{
	WARN_ON(irqs_disabled());	/* for portability */
	if (dma_ops->unmap_single)
		dma_ops->unmap_single(dev, bus, size, 0);
	free_pages((unsigned long)vaddr, get_order(size));
}
EXPORT_SYMBOL(dma_free_coherent);
