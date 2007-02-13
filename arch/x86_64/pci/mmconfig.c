/*
 * mmconfig.c - Low-level direct PCI config space access via MMCONFIG
 *
 * This is an 64bit optimized version that always keeps the full mmconfig
 * space mapped. This allows lockless config space operation.
 */

#include <linux/pci.h>
#include <linux/init.h>
#include <linux/acpi.h>
#include <linux/bitmap.h>
#include <asm/e820.h>

#include "pci.h"

/* aperture is up to 256MB but BIOS may reserve less */
#define MMCONFIG_APER_MIN	(2 * 1024*1024)
#define MMCONFIG_APER_MAX	(256 * 1024*1024)

/* Verify the first 16 busses. We assume that systems with more busses
   get MCFG right. */
#define PCI_MMCFG_MAX_CHECK_BUS 16

/* Static virtual mapping of the MMCONFIG aperture */
struct mmcfg_virt {
	struct acpi_mcfg_allocation *cfg;
	char __iomem *virt;
};
static struct mmcfg_virt *pci_mmcfg_virt;

static inline int mcfg_broken(void)
{
	struct acpi_mcfg_allocation *cfg = &pci_mmcfg_config[0];

	/* Handle more broken MCFG tables on Asus etc.
	   They only contain a single entry for bus 0-0. Assume
 	   this applies to all busses. */
	if (pci_mmcfg_config_num == 1 &&
	    cfg->pci_segment_group_number == 0 &&
	    (cfg->start_bus_number | cfg->end_bus_number) == 0)
		return 1;
	return 0;
}

static void __iomem *mcfg_ioremap(struct acpi_mcfg_allocation *cfg)
{
	void __iomem *addr;
	u32 size;

	if (mcfg_broken())
		size = 256 << 20;
	else
		size = (cfg->end_bus_number + 1) << 20;

	addr = ioremap_nocache(cfg->base_address, size);
	if (addr) {
		printk(KERN_INFO "PCI: Using MMCONFIG at %x - %x\n",
		       cfg->base_address,
		       cfg->base_address + size - 1);
	}
	return addr;
}

static char __iomem *get_virt(unsigned int seg, unsigned bus)
{
	int cfg_num = -1;
	struct acpi_mcfg_allocation *cfg;

	while (1) {
		++cfg_num;
		if (cfg_num >= pci_mmcfg_config_num)
			break;
		cfg = pci_mmcfg_virt[cfg_num].cfg;
		if (cfg->pci_segment != seg)
			continue;
		if ((cfg->start_bus_number <= bus) &&
		    (cfg->end_bus_number >= bus))
			return pci_mmcfg_virt[cfg_num].virt;
	}

	if (mcfg_broken())
		return pci_mmcfg_virt[0].virt;

	/* Fall back to type 0 */
	return NULL;
}

static char __iomem *pci_dev_base(unsigned int seg, unsigned int bus, unsigned int devfn)
{
	char __iomem *addr;
	if (seg == 0 && bus < PCI_MMCFG_MAX_CHECK_BUS &&
		test_bit(32*bus + PCI_SLOT(devfn), pci_mmcfg_fallback_slots))
		return NULL;
	addr = get_virt(seg, bus);
	if (!addr)
		return NULL;
 	return addr + ((bus << 20) | (devfn << 12));
}

static int pci_mmcfg_read(unsigned int seg, unsigned int bus,
			  unsigned int devfn, int reg, int len, u32 *value)
{
	char __iomem *addr;

	/* Why do we have this when nobody checks it. How about a BUG()!? -AK */
	if (unlikely((bus > 255) || (devfn > 255) || (reg > 4095))) {
		*value = -1;
		return -EINVAL;
	}

	addr = pci_dev_base(seg, bus, devfn);
	if (!addr)
		return pci_conf1_read(seg,bus,devfn,reg,len,value);

	switch (len) {
	case 1:
		*value = readb(addr + reg);
		break;
	case 2:
		*value = readw(addr + reg);
		break;
	case 4:
		*value = readl(addr + reg);
		break;
	}

	return 0;
}

static int pci_mmcfg_write(unsigned int seg, unsigned int bus,
			   unsigned int devfn, int reg, int len, u32 value)
{
	char __iomem *addr;

	/* Why do we have this when nobody checks it. How about a BUG()!? -AK */
	if (unlikely((bus > 255) || (devfn > 255) || (reg > 4095)))
		return -EINVAL;

	addr = pci_dev_base(seg, bus, devfn);
	if (!addr)
		return pci_conf1_write(seg,bus,devfn,reg,len,value);

	switch (len) {
	case 1:
		writeb(value, addr + reg);
		break;
	case 2:
		writew(value, addr + reg);
		break;
	case 4:
		writel(value, addr + reg);
		break;
	}

	return 0;
}

static struct pci_raw_ops pci_mmcfg = {
	.read =		pci_mmcfg_read,
	.write =	pci_mmcfg_write,
};

int __init pci_mmcfg_arch_init(void)
{
	int i;
	pci_mmcfg_virt = kmalloc(sizeof(*pci_mmcfg_virt) *
				 pci_mmcfg_config_num, GFP_KERNEL);
	if (pci_mmcfg_virt == NULL) {
		printk(KERN_ERR "PCI: Can not allocate memory for mmconfig structures\n");
		return 0;
	}

	for (i = 0; i < pci_mmcfg_config_num; ++i) {
		pci_mmcfg_virt[i].cfg = &pci_mmcfg_config[i];
		pci_mmcfg_virt[i].virt = mcfg_ioremap(&pci_mmcfg_config[i]);
		if (!pci_mmcfg_virt[i].virt) {
			printk(KERN_ERR "PCI: Cannot map mmconfig aperture for "
					"segment %d\n",
				pci_mmcfg_config[i].pci_segment);
			return 0;
		}
	}
	raw_pci_ops = &pci_mmcfg;
	return 1;
}
