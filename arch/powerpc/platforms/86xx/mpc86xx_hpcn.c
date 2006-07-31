/*
 * MPC86xx HPCN board specific routines
 *
 * Recode: ZHANG WEI <wei.zhang@freescale.com>
 * Initial author: Xianghua Xiao <x.xiao@freescale.com>
 *
 * Copyright 2006 Freescale Semiconductor Inc.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/kdev_t.h>
#include <linux/delay.h>
#include <linux/seq_file.h>
#include <linux/root_dev.h>

#include <asm/system.h>
#include <asm/time.h>
#include <asm/machdep.h>
#include <asm/pci-bridge.h>
#include <asm/mpc86xx.h>
#include <asm/prom.h>
#include <mm/mmu_decl.h>
#include <asm/udbg.h>
#include <asm/i8259.h>

#include <asm/mpic.h>

#include <sysdev/fsl_soc.h>

#include "mpc86xx.h"
#include "mpc8641_hpcn.h"

#ifndef CONFIG_PCI
unsigned long isa_io_base = 0;
unsigned long isa_mem_base = 0;
unsigned long pci_dram_offset = 0;
#endif


/*
 * Internal interrupts are all Level Sensitive, and Positive Polarity
 */

static u_char mpc86xx_hpcn_openpic_initsenses[] __initdata = {
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal  0: Reserved */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal  1: MCM */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal  2: DDR DRAM */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal  3: LBIU */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal  4: DMA 0 */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal  5: DMA 1 */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal  6: DMA 2 */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal  7: DMA 3 */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal  8: PCIE1 */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal  9: PCIE2 */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 10: Reserved */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 11: Reserved */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 12: DUART2 */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 13: TSEC 1 Transmit */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 14: TSEC 1 Receive */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 15: TSEC 3 transmit */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 16: TSEC 3 receive */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 17: TSEC 3 error */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 18: TSEC 1 Receive/Transmit Error */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 19: TSEC 2 Transmit */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 20: TSEC 2 Receive */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 21: TSEC 4 transmit */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 22: TSEC 4 receive */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 23: TSEC 4 error */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 24: TSEC 2 Receive/Transmit Error */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 25: Unused */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 26: DUART1 */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 27: I2C */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 28: Performance Monitor */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 29: Unused */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 30: Unused */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 31: Unused */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 32: SRIO error/write-port unit */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 33: SRIO outbound doorbell */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 34: SRIO inbound doorbell */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 35: Unused */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 36: Unused */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 37: SRIO outbound message unit 1 */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 38: SRIO inbound message unit 1 */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 39: SRIO outbound message unit 2 */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 40: SRIO inbound message unit 2 */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 41: Unused */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 42: Unused */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 43: Unused */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 44: Unused */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 45: Unused */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 46: Unused */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* Internal 47: Unused */
	0x0,						/* External  0: */
	0x0,						/* External  1: */
	0x0,						/* External  2: */
	0x0,						/* External  3: */
	0x0,						/* External  4: */
	0x0,						/* External  5: */
	0x0,						/* External  6: */
	0x0,						/* External  7: */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_NEGATIVE),	/* External  8: Pixis FPGA */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_POSITIVE),	/* External  9: ULI 8259 INTR Cascade */
	(IRQ_SENSE_LEVEL | IRQ_POLARITY_NEGATIVE),	/* External 10: Quad ETH PHY */
	0x0,						/* External 11: */
	0x0,
	0x0,
	0x0,
	0x0,
};


void __init
mpc86xx_hpcn_init_irq(void)
{
	struct mpic *mpic1;
	phys_addr_t openpic_paddr;

	/* Determine the Physical Address of the OpenPIC regs */
	openpic_paddr = get_immrbase() + MPC86xx_OPENPIC_OFFSET;

	/* Alloc mpic structure and per isu has 16 INT entries. */
	mpic1 = mpic_alloc(openpic_paddr,
			MPIC_PRIMARY | MPIC_WANTS_RESET | MPIC_BIG_ENDIAN,
			16, MPC86xx_OPENPIC_IRQ_OFFSET, 0, 250,
			mpc86xx_hpcn_openpic_initsenses,
			sizeof(mpc86xx_hpcn_openpic_initsenses),
			" MPIC     ");
	BUG_ON(mpic1 == NULL);

	/* 48 Internal Interrupts */
	mpic_assign_isu(mpic1, 0, openpic_paddr + 0x10200);
	mpic_assign_isu(mpic1, 1, openpic_paddr + 0x10400);
	mpic_assign_isu(mpic1, 2, openpic_paddr + 0x10600);

	/* 16 External interrupts */
	mpic_assign_isu(mpic1, 3, openpic_paddr + 0x10000);

	mpic_init(mpic1);

#ifdef CONFIG_PCI
	mpic_setup_cascade(MPC86xx_IRQ_EXT9, i8259_irq_cascade, NULL);
	i8259_init(0, I8259_OFFSET);
#endif
}



#ifdef CONFIG_PCI
/*
 * interrupt routing
 */

int
mpc86xx_map_irq(struct pci_dev *dev, unsigned char idsel, unsigned char pin)
{
	static char pci_irq_table[][4] = {
		/*
		 *      PCI IDSEL/INTPIN->INTLINE
		 *       A      B      C      D
		 */
		{PIRQA, PIRQB, PIRQC, PIRQD},   /* IDSEL 17 -- PCI Slot 1 */
		{PIRQB, PIRQC, PIRQD, PIRQA},	/* IDSEL 18 -- PCI Slot 2 */
		{0, 0, 0, 0},			/* IDSEL 19 */
		{0, 0, 0, 0},			/* IDSEL 20 */
		{0, 0, 0, 0},			/* IDSEL 21 */
		{0, 0, 0, 0},			/* IDSEL 22 */
		{0, 0, 0, 0},			/* IDSEL 23 */
		{0, 0, 0, 0},			/* IDSEL 24 */
		{0, 0, 0, 0},			/* IDSEL 25 */
		{PIRQD, PIRQA, PIRQB, PIRQC},	/* IDSEL 26 -- PCI Bridge*/
		{PIRQC, 0, 0, 0},		/* IDSEL 27 -- LAN */
		{PIRQE, PIRQF, PIRQH, PIRQ7},	/* IDSEL 28 -- USB 1.1 */
		{PIRQE, PIRQF, PIRQG, 0},	/* IDSEL 29 -- Audio & Modem */
		{PIRQH, 0, 0, 0},		/* IDSEL 30 -- LPC & PMU*/
		{PIRQD, 0, 0, 0},		/* IDSEL 31 -- ATA */
	};

	const long min_idsel = 17, max_idsel = 31, irqs_per_slot = 4;
	return PCI_IRQ_TABLE_LOOKUP + I8259_OFFSET;
}

static void __devinit quirk_ali1575(struct pci_dev *dev)
{
	unsigned short temp;

	/*
	 * ALI1575 interrupts route table setup:
	 *
	 * IRQ pin   IRQ#
	 * PIRQA ---- 3
	 * PIRQB ---- 4
	 * PIRQC ---- 5
	 * PIRQD ---- 6
	 * PIRQE ---- 9
	 * PIRQF ---- 10
	 * PIRQG ---- 11
	 * PIRQH ---- 12
	 *
	 * interrupts for PCI slot0 -- PIRQA / PIRQB / PIRQC / PIRQD
	 *                PCI slot1 -- PIRQB / PIRQC / PIRQD / PIRQA
	 */
	pci_write_config_dword(dev, 0x48, 0xb9317542);

	/* USB 1.1 OHCI controller 1, interrupt: PIRQE */
	pci_write_config_byte(dev, 0x86, 0x0c);

	/* USB 1.1 OHCI controller 2, interrupt: PIRQF */
	pci_write_config_byte(dev, 0x87, 0x0d);

	/* USB 1.1 OHCI controller 3, interrupt: PIRQH */
	pci_write_config_byte(dev, 0x88, 0x0f);

	/* USB 2.0 controller, interrupt: PIRQ7 */
	pci_write_config_byte(dev, 0x74, 0x06);

	/* Audio controller, interrupt: PIRQE */
	pci_write_config_byte(dev, 0x8a, 0x0c);

	/* Modem controller, interrupt: PIRQF */
	pci_write_config_byte(dev, 0x8b, 0x0d);

	/* HD audio controller, interrupt: PIRQG */
	pci_write_config_byte(dev, 0x8c, 0x0e);

	/* Serial ATA interrupt: PIRQD */
	pci_write_config_byte(dev, 0x8d, 0x0b);

	/* SMB interrupt: PIRQH */
	pci_write_config_byte(dev, 0x8e, 0x0f);

	/* PMU ACPI SCI interrupt: PIRQH */
	pci_write_config_byte(dev, 0x8f, 0x0f);

	/* Primary PATA IDE IRQ: 14
	 * Secondary PATA IDE IRQ: 15
	 */
	pci_write_config_byte(dev, 0x44, 0x3d);
	pci_write_config_byte(dev, 0x75, 0x0f);

	/* Set IRQ14 and IRQ15 to legacy IRQs */
	pci_read_config_word(dev, 0x46, &temp);
	temp |= 0xc000;
	pci_write_config_word(dev, 0x46, temp);

	/* Set i8259 interrupt trigger
	 * IRQ 3:  Level
	 * IRQ 4:  Level
	 * IRQ 5:  Level
	 * IRQ 6:  Level
	 * IRQ 7:  Level
	 * IRQ 9:  Level
	 * IRQ 10: Level
	 * IRQ 11: Level
	 * IRQ 12: Level
	 * IRQ 14: Edge
	 * IRQ 15: Edge
	 */
	outb(0xfa, 0x4d0);
	outb(0x1e, 0x4d1);
}

static void __devinit quirk_uli5288(struct pci_dev *dev)
{
	unsigned char c;

	pci_read_config_byte(dev,0x83,&c);
	c |= 0x80;
	pci_write_config_byte(dev, 0x83, c);

	pci_write_config_byte(dev, 0x09, 0x01);
	pci_write_config_byte(dev, 0x0a, 0x06);

	pci_read_config_byte(dev,0x83,&c);
	c &= 0x7f;
	pci_write_config_byte(dev, 0x83, c);

	pci_read_config_byte(dev,0x84,&c);
	c |= 0x01;
	pci_write_config_byte(dev, 0x84, c);
}

static void __devinit quirk_uli5229(struct pci_dev *dev)
{
	unsigned short temp;
	pci_write_config_word(dev, 0x04, 0x0405);
	pci_read_config_word(dev, 0x4a, &temp);
	temp |= 0x1000;
	pci_write_config_word(dev, 0x4a, temp);
}

static void __devinit early_uli5249(struct pci_dev *dev)
{
	unsigned char temp;
	pci_write_config_word(dev, 0x04, 0x0007);
	pci_read_config_byte(dev, 0x7c, &temp);
	pci_write_config_byte(dev, 0x7c, 0x80);
	pci_write_config_byte(dev, 0x09, 0x01);
	pci_write_config_byte(dev, 0x7c, temp);
	dev->class |= 0x1;
}

DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_AL, 0x1575, quirk_ali1575);
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_AL, 0x5288, quirk_uli5288);
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_AL, 0x5229, quirk_uli5229);
DECLARE_PCI_FIXUP_EARLY(PCI_VENDOR_ID_AL, 0x5249, early_uli5249);
#endif /* CONFIG_PCI */


static void __init
mpc86xx_hpcn_setup_arch(void)
{
	struct device_node *np;

	if (ppc_md.progress)
		ppc_md.progress("mpc86xx_hpcn_setup_arch()", 0);

	np = of_find_node_by_type(NULL, "cpu");
	if (np != 0) {
		const unsigned int *fp;

		fp = get_property(np, "clock-frequency", NULL);
		if (fp != 0)
			loops_per_jiffy = *fp / HZ;
		else
			loops_per_jiffy = 50000000 / HZ;
		of_node_put(np);
	}

#ifdef CONFIG_PCI
	for (np = NULL; (np = of_find_node_by_type(np, "pci")) != NULL;)
		add_bridge(np);

	ppc_md.pci_swizzle = common_swizzle;
	ppc_md.pci_map_irq = mpc86xx_map_irq;
	ppc_md.pci_exclude_device = mpc86xx_exclude_device;
#endif

	printk("MPC86xx HPCN board from Freescale Semiconductor\n");

#ifdef  CONFIG_ROOT_NFS
	ROOT_DEV = Root_NFS;
#else
	ROOT_DEV = Root_HDA1;
#endif

#ifdef CONFIG_SMP
	mpc86xx_smp_init();
#endif
}


void
mpc86xx_hpcn_show_cpuinfo(struct seq_file *m)
{
	struct device_node *root;
	uint memsize = total_memory;
	const char *model = "";
	uint svid = mfspr(SPRN_SVR);

	seq_printf(m, "Vendor\t\t: Freescale Semiconductor\n");

	root = of_find_node_by_path("/");
	if (root)
		model = get_property(root, "model", NULL);
	seq_printf(m, "Machine\t\t: %s\n", model);
	of_node_put(root);

	seq_printf(m, "SVR\t\t: 0x%x\n", svid);
	seq_printf(m, "Memory\t\t: %d MB\n", memsize / (1024 * 1024));
}


/*
 * Called very early, device-tree isn't unflattened
 */
static int __init mpc86xx_hpcn_probe(void)
{
	unsigned long root = of_get_flat_dt_root();

	if (of_flat_dt_is_compatible(root, "mpc86xx"))
		return 1;	/* Looks good */

	return 0;
}


void
mpc86xx_restart(char *cmd)
{
	void __iomem *rstcr;

	rstcr = ioremap(get_immrbase() + MPC86XX_RSTCR_OFFSET, 0x100);

	local_irq_disable();

	/* Assert reset request to Reset Control Register */
	out_be32(rstcr, 0x2);

	/* not reached */
}


long __init
mpc86xx_time_init(void)
{
	unsigned int temp;

	/* Set the time base to zero */
	mtspr(SPRN_TBWL, 0);
	mtspr(SPRN_TBWU, 0);

	temp = mfspr(SPRN_HID0);
	temp |= HID0_TBEN;
	mtspr(SPRN_HID0, temp);
	asm volatile("isync");

	return 0;
}


define_machine(mpc86xx_hpcn) {
	.name			= "MPC86xx HPCN",
	.probe			= mpc86xx_hpcn_probe,
	.setup_arch		= mpc86xx_hpcn_setup_arch,
	.init_IRQ		= mpc86xx_hpcn_init_irq,
	.show_cpuinfo		= mpc86xx_hpcn_show_cpuinfo,
	.get_irq		= mpic_get_irq,
	.restart		= mpc86xx_restart,
	.time_init		= mpc86xx_time_init,
	.calibrate_decr		= generic_calibrate_decr,
	.progress		= udbg_progress,
};
