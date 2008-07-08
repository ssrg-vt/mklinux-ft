/*
 * structures and definitions for the int 15, ax=e820 memory map
 * scheme.
 *
 * In a nutshell, arch/i386/boot/setup.S populates a scratch table
 * in the empty_zero_block that contains a list of usable address/size
 * duples.   In arch/i386/kernel/setup.c, this information is
 * transferred into the e820map, and in arch/i386/mm/init.c, that
 * new information is used to mark pages reserved or not.
 *
 */
#ifndef __E820_HEADER
#define __E820_HEADER

#include <linux/ioport.h>

#define HIGH_MEMORY	(1024*1024)

#ifndef __ASSEMBLY__

extern void setup_memory_map(void);

extern void init_iomem_resources(struct resource *code_resource,
				 struct resource *data_resource,
				 struct resource *bss_resource);

#endif/*!__ASSEMBLY__*/
#endif/*__E820_HEADER*/
