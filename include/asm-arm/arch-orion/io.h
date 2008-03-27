/*
 * include/asm-arm/arch-orion/io.h
 *
 * Tzachi Perelstein <tzachi@marvell.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef __ASM_ARCH_IO_H
#define __ASM_ARCH_IO_H

#include "orion.h"

#define IO_SPACE_LIMIT		0xffffffff
#define IO_SPACE_REMAP		ORION_PCI_SYS_IO_BASE

static inline void __iomem *
__arch_ioremap(unsigned long paddr, size_t size, unsigned int mtype)
{
	void __iomem *retval;

	if (mtype == MT_DEVICE && size && paddr >= ORION_REGS_PHYS_BASE &&
	    paddr + size <= ORION_REGS_PHYS_BASE + ORION_REGS_SIZE) {
		retval = (void __iomem *)ORION_REGS_VIRT_BASE +
				(paddr - ORION_REGS_PHYS_BASE);
	} else {
		retval = __arm_ioremap(paddr, size, mtype);
	}

	return retval;
}

static inline void
__arch_iounmap(void __iomem *addr)
{
	if (addr < (void __iomem *)ORION_REGS_VIRT_BASE ||
	    addr >= (void __iomem *)(ORION_REGS_VIRT_BASE + ORION_REGS_SIZE))
		__iounmap(addr);
}

static inline void __iomem *__io(unsigned long addr)
{
	return (void __iomem *)addr;
}

#define __arch_ioremap(p, s, m)	__arch_ioremap(p, s, m)
#define __arch_iounmap(a)	__arch_iounmap(a)
#define __io(a)			__io(a)
#define __mem_pci(a)		(a)


/*****************************************************************************
 * Helpers to access Orion registers
 ****************************************************************************/
#define orion_read(r)		__raw_readl(r)
#define orion_write(r, val)	__raw_writel(val, r)

/*
 * These are not preempt-safe.  Locks, if needed, must be taken
 * care of by the caller.
 */
#define orion_setbits(r, mask)	orion_write((r), orion_read(r) | (mask))
#define orion_clrbits(r, mask)	orion_write((r), orion_read(r) & ~(mask))


#endif
