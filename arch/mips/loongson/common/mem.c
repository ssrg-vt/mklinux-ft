/*
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/mm.h>

#include <asm/bootinfo.h>

#include <loongson.h>
#include <mem.h>
#include <pci.h>

void __init prom_init_memory(void)
{
    add_memory_region(0x0, (memsize << 20), BOOT_MEM_RAM);

    add_memory_region(memsize << 20, LOONGSON_PCI_MEM_START - (memsize <<
			    20), BOOT_MEM_RESERVED);
#ifdef CONFIG_64BIT
#ifdef CONFIG_CPU_LOONGSON2F
	{
		int bit;

		bit = fls(memsize + highmemsize);
		if (bit != ffs(memsize + highmemsize))
			bit += 20;
		else
			bit = bit + 20 - 1;

		/* set cpu window3 to map CPU to DDR: 2G -> 2G */
		LOONGSON_ADDRWIN_CPUTODDR(ADDRWIN_WIN3, 0x80000000ul,
					  0x80000000ul, (1 << bit));
		mmiowb();
	}
#endif				/* CONFIG_CPU_LOONGSON2F */

	if (highmemsize > 0)
		add_memory_region(LOONGSON_HIGHMEM_START,
				  highmemsize << 20, BOOT_MEM_RAM);

	add_memory_region(LOONGSON_PCI_MEM_END + 1, LOONGSON_HIGHMEM_START -
			  LOONGSON_PCI_MEM_END - 1, BOOT_MEM_RESERVED);

#endif				/* CONFIG_64BIT */
}

/* override of arch/mips/mm/cache.c: __uncached_access */
int __uncached_access(struct file *file, unsigned long addr)
{
	if (file->f_flags & O_DSYNC)
		return 1;

	return addr >= __pa(high_memory) ||
		((addr >= LOONGSON_MMIO_MEM_START) &&
		 (addr < LOONGSON_MMIO_MEM_END));
}
