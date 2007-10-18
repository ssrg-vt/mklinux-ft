/*
 *  linux/drivers/ide/pci/generic.c	Version 0.11	December 30, 2002
 *
 *  Copyright (C) 2001-2002	Andre Hedrick <andre@linux-ide.org>
 *  Portions (C) Copyright 2002  Red Hat Inc <alan@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * For the avoidance of doubt the "preferred form" of this code is one which
 * is in an open non patent encumbered format. Where cryptographic key signing
 * forms part of the process of creating an executable the information
 * including keys needed to generate an equivalently functional executable
 * are deemed to be part of the source code.
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/ioport.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/pci.h>
#include <linux/ide.h>
#include <linux/init.h>

#include <asm/io.h>

static int ide_generic_all;		/* Set to claim all devices */

/*
 * the module_param_named() was added for the modular case
 * the __setup() is left as compatibility for existing setups
 */
#ifndef MODULE
static int __init ide_generic_all_on(char *unused)
{
	ide_generic_all = 1;
	printk(KERN_INFO "IDE generic will claim all unknown PCI IDE storage controllers.\n");
	return 1;
}
__setup("all-generic-ide", ide_generic_all_on);
#endif
module_param_named(all_generic_ide, ide_generic_all, bool, 0444);
MODULE_PARM_DESC(all_generic_ide, "IDE generic will claim all unknown PCI IDE storage controllers.");

static void __devinit init_hwif_generic (ide_hwif_t *hwif)
{
	switch(hwif->pci_dev->device) {
		case PCI_DEVICE_ID_UMC_UM8673F:
		case PCI_DEVICE_ID_UMC_UM8886A:
		case PCI_DEVICE_ID_UMC_UM8886BF:
			hwif->irq = hwif->channel ? 15 : 14;
			break;
		default:
			break;
	}

	if (!(hwif->dma_base))
		return;

	hwif->ultra_mask = 0x7f;
	hwif->mwdma_mask = 0x07;
	hwif->swdma_mask = 0x07;
}

#define DECLARE_GENERIC_PCI_DEV(name_str, dma_setting) \
	{ \
		.name		= name_str, \
		.init_hwif	= init_hwif_generic, \
		.autodma	= dma_setting, \
		.host_flags	= IDE_HFLAG_TRUST_BIOS_FOR_DMA | \
				  IDE_HFLAG_BOOTABLE, \
	}

static ide_pci_device_t generic_chipsets[] __devinitdata = {
	/*  0 */ DECLARE_GENERIC_PCI_DEV("Unknown",		AUTODMA),

	{	/* 1 */
		.name		= "NS87410",
		.init_hwif	= init_hwif_generic,
		.autodma	= AUTODMA,
		.enablebits	= {{0x43,0x08,0x08}, {0x47,0x08,0x08}},
		.host_flags	= IDE_HFLAG_TRUST_BIOS_FOR_DMA |
				  IDE_HFLAG_BOOTABLE,
	},

	/*  2 */ DECLARE_GENERIC_PCI_DEV("SAMURAI",		AUTODMA),
	/*  3 */ DECLARE_GENERIC_PCI_DEV("HT6565",		AUTODMA),
	/*  4 */ DECLARE_GENERIC_PCI_DEV("UM8673F",		NODMA),
	/*  5 */ DECLARE_GENERIC_PCI_DEV("UM8886A",		NODMA),
	/*  6 */ DECLARE_GENERIC_PCI_DEV("UM8886BF",		NODMA),
	/*  7 */ DECLARE_GENERIC_PCI_DEV("HINT_IDE",		AUTODMA),
	/*  8 */ DECLARE_GENERIC_PCI_DEV("VIA_IDE",		NOAUTODMA),
	/*  9 */ DECLARE_GENERIC_PCI_DEV("OPTI621V",		NOAUTODMA),

	{	/* 10 */
		.name		= "VIA8237SATA",
		.init_hwif	= init_hwif_generic,
		.autodma	= AUTODMA,
		.host_flags	= IDE_HFLAG_TRUST_BIOS_FOR_DMA |
				  IDE_HFLAG_OFF_BOARD,
	},

	/* 11 */ DECLARE_GENERIC_PCI_DEV("Piccolo0102",		NOAUTODMA),
	/* 12 */ DECLARE_GENERIC_PCI_DEV("Piccolo0103",		NOAUTODMA),
	/* 13 */ DECLARE_GENERIC_PCI_DEV("Piccolo0105",		NOAUTODMA),

	{	/* 14 */
		.name		= "Revolution",
		.init_hwif	= init_hwif_generic,
		.autodma	= AUTODMA,
		.host_flags	= IDE_HFLAG_TRUST_BIOS_FOR_DMA |
				  IDE_HFLAG_OFF_BOARD,
	}
};

/**
 *	generic_init_one	-	called when a PIIX is found
 *	@dev: the generic device
 *	@id: the matching pci id
 *
 *	Called when the PCI registration layer (or the IDE initialization)
 *	finds a device matching our IDE device tables.
 */
 
static int __devinit generic_init_one(struct pci_dev *dev, const struct pci_device_id *id)
{
	ide_pci_device_t *d = &generic_chipsets[id->driver_data];
	int ret = -ENODEV;

	/* Don't use the generic entry unless instructed to do so */
	if (id->driver_data == 0 && ide_generic_all == 0)
			goto out;

	switch (dev->vendor) {
	case PCI_VENDOR_ID_UMC:
		if (dev->device == PCI_DEVICE_ID_UMC_UM8886A &&
				!(PCI_FUNC(dev->devfn) & 1))
			goto out; /* UM8886A/BF pair */
		break;
	case PCI_VENDOR_ID_OPTI:
		if (dev->device == PCI_DEVICE_ID_OPTI_82C558 &&
				!(PCI_FUNC(dev->devfn) & 1))
			goto out;
		break;
	case PCI_VENDOR_ID_JMICRON:
		if (dev->device != PCI_DEVICE_ID_JMICRON_JMB368 &&
				PCI_FUNC(dev->devfn) != 1)
			goto out;
		break;
	case PCI_VENDOR_ID_NS:
		if (dev->device == PCI_DEVICE_ID_NS_87410 &&
				(dev->class >> 8) != PCI_CLASS_STORAGE_IDE)
			goto out;
		break;
	}

	if (dev->vendor != PCI_VENDOR_ID_JMICRON) {
		u16 command;
		pci_read_config_word(dev, PCI_COMMAND, &command);
		if (!(command & PCI_COMMAND_IO)) {
			printk(KERN_INFO "Skipping disabled %s IDE "
					"controller.\n", d->name);
			goto out;
		}
	}
	ret = ide_setup_pci_device(dev, d);
out:
	return ret;
}

static const struct pci_device_id generic_pci_tbl[] = {
	{ PCI_VDEVICE(NS,	PCI_DEVICE_ID_NS_87410),		 1 },
	{ PCI_VDEVICE(PCTECH,	PCI_DEVICE_ID_PCTECH_SAMURAI_IDE),	 2 },
	{ PCI_VDEVICE(HOLTEK,	PCI_DEVICE_ID_HOLTEK_6565),		 3 },
	{ PCI_VDEVICE(UMC,	PCI_DEVICE_ID_UMC_UM8673F),		 4 },
	{ PCI_VDEVICE(UMC,	PCI_DEVICE_ID_UMC_UM8886A),		 5 },
	{ PCI_VDEVICE(UMC,	PCI_DEVICE_ID_UMC_UM8886BF),		 6 },
	{ PCI_VDEVICE(HINT,	PCI_DEVICE_ID_HINT_VXPROII_IDE),	 7 },
	{ PCI_VDEVICE(VIA,	PCI_DEVICE_ID_VIA_82C561),		 8 },
	{ PCI_VDEVICE(OPTI,	PCI_DEVICE_ID_OPTI_82C558),		 9 },
#ifdef CONFIG_BLK_DEV_IDE_SATA
	{ PCI_VDEVICE(VIA,	PCI_DEVICE_ID_VIA_8237_SATA),		10 },
#endif
	{ PCI_VDEVICE(TOSHIBA,	PCI_DEVICE_ID_TOSHIBA_PICCOLO),		11 },
	{ PCI_VDEVICE(TOSHIBA,	PCI_DEVICE_ID_TOSHIBA_PICCOLO_1),	12 },
	{ PCI_VDEVICE(TOSHIBA,	PCI_DEVICE_ID_TOSHIBA_PICCOLO_2),	13 },
	{ PCI_VDEVICE(NETCELL,	PCI_DEVICE_ID_REVOLUTION),		14 },
	/*
	 * Must come last.  If you add entries adjust
	 * this table and generic_chipsets[] appropriately.
	 */
	{ PCI_ANY_ID, PCI_ANY_ID, PCI_ANY_ID, PCI_ANY_ID, PCI_CLASS_STORAGE_IDE << 8, 0xFFFFFF00UL, 0 },
	{ 0, },
};
MODULE_DEVICE_TABLE(pci, generic_pci_tbl);

static struct pci_driver driver = {
	.name		= "PCI_IDE",
	.id_table	= generic_pci_tbl,
	.probe		= generic_init_one,
};

static int __init generic_ide_init(void)
{
	return ide_pci_register_driver(&driver);
}

module_init(generic_ide_init);

MODULE_AUTHOR("Andre Hedrick");
MODULE_DESCRIPTION("PCI driver module for generic PCI IDE");
MODULE_LICENSE("GPL");
