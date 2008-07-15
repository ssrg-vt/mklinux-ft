/*
 * linux/include/asm-mips/txx9/generic.h
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */
#ifndef __ASM_TXX9_GENERIC_H
#define __ASM_TXX9_GENERIC_H

#include <linux/init.h>
#include <linux/ioport.h>	/* for struct resource */

extern struct resource txx9_ce_res[];
extern char txx9_pcode_str[8];
void txx9_reg_res_init(unsigned int pcode, unsigned long base,
		       unsigned long size);

extern unsigned int txx9_master_clock;
extern unsigned int txx9_cpu_clock;
extern unsigned int txx9_gbus_clock;

struct pci_dev;
struct txx9_board_vec {
	unsigned long type;
	const char *system;
	void (*prom_init)(void);
	void (*mem_setup)(void);
	void (*irq_setup)(void);
	void (*time_init)(void);
	void (*arch_init)(void);
	void (*device_init)(void);
#ifdef CONFIG_PCI
	int (*pci_map_irq)(const struct pci_dev *dev, u8 slot, u8 pin);
#endif
};
extern struct txx9_board_vec *txx9_board_vec;
extern int (*txx9_irq_dispatch)(int pending);
void prom_init_cmdline(void);

#endif /* __ASM_TXX9_GENERIC_H */
