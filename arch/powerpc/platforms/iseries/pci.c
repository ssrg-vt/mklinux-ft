/*
 * Copyright (C) 2001 Allan Trautman, IBM Corporation
 *
 * iSeries specific routines for PCI.
 *
 * Based on code from pci.c and iSeries_pci.c 32bit
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/prom.h>
#include <asm/machdep.h>
#include <asm/pci-bridge.h>
#include <asm/iommu.h>
#include <asm/abs_addr.h>
#include <asm/firmware.h>

#include <asm/iseries/hv_call_xm.h>
#include <asm/iseries/mf.h>
#include <asm/iseries/iommu.h>

#include <asm/ppc-pci.h>

#include "irq.h"
#include "pci.h"
#include "call_pci.h"

#define PCI_RETRY_MAX	3
static int limit_pci_retries = 1;	/* Set Retry Error on. */

/*
 * Table defines
 * Each Entry size is 4 MB * 1024 Entries = 4GB I/O address space.
 */
#define IOMM_TABLE_MAX_ENTRIES	1024
#define IOMM_TABLE_ENTRY_SIZE	0x0000000000400000UL
#define BASE_IO_MEMORY		0xE000000000000000UL

static unsigned long max_io_memory = BASE_IO_MEMORY;
static long current_iomm_table_entry;

/*
 * Lookup Tables.
 */
static struct device_node *iomm_table[IOMM_TABLE_MAX_ENTRIES];
static u8 iobar_table[IOMM_TABLE_MAX_ENTRIES];

static const char pci_io_text[] = "iSeries PCI I/O";
static DEFINE_SPINLOCK(iomm_table_lock);

/*
 * Generate a Direct Select Address for the Hypervisor
 */
static inline u64 iseries_ds_addr(struct device_node *node)
{
	struct pci_dn *pdn = PCI_DN(node);

	return ((u64)pdn->busno << 48) + ((u64)pdn->bussubno << 40)
			+ ((u64)0x10 << 32);
}

/*
 * iomm_table_allocate_entry
 *
 * Adds pci_dev entry in address translation table
 *
 * - Allocates the number of entries required in table base on BAR
 *   size.
 * - Allocates starting at BASE_IO_MEMORY and increases.
 * - The size is round up to be a multiple of entry size.
 * - CurrentIndex is incremented to keep track of the last entry.
 * - Builds the resource entry for allocated BARs.
 */
static void __init iomm_table_allocate_entry(struct pci_dev *dev, int bar_num)
{
	struct resource *bar_res = &dev->resource[bar_num];
	long bar_size = pci_resource_len(dev, bar_num);

	/*
	 * No space to allocate, quick exit, skip Allocation.
	 */
	if (bar_size == 0)
		return;
	/*
	 * Set Resource values.
	 */
	spin_lock(&iomm_table_lock);
	bar_res->name = pci_io_text;
	bar_res->start = BASE_IO_MEMORY +
		IOMM_TABLE_ENTRY_SIZE * current_iomm_table_entry;
	bar_res->end = bar_res->start + bar_size - 1;
	/*
	 * Allocate the number of table entries needed for BAR.
	 */
	while (bar_size > 0 ) {
		iomm_table[current_iomm_table_entry] = dev->sysdata;
		iobar_table[current_iomm_table_entry] = bar_num;
		bar_size -= IOMM_TABLE_ENTRY_SIZE;
		++current_iomm_table_entry;
	}
	max_io_memory = BASE_IO_MEMORY +
		IOMM_TABLE_ENTRY_SIZE * current_iomm_table_entry;
	spin_unlock(&iomm_table_lock);
}

/*
 * allocate_device_bars
 *
 * - Allocates ALL pci_dev BAR's and updates the resources with the
 *   BAR value.  BARS with zero length will have the resources
 *   The HvCallPci_getBarParms is used to get the size of the BAR
 *   space.  It calls iomm_table_allocate_entry to allocate
 *   each entry.
 * - Loops through The Bar resources(0 - 5) including the ROM
 *   is resource(6).
 */
static void __init allocate_device_bars(struct pci_dev *dev)
{
	int bar_num;

	for (bar_num = 0; bar_num <= PCI_ROM_RESOURCE; ++bar_num)
		iomm_table_allocate_entry(dev, bar_num);
}

/*
 * Log error information to system console.
 * Filter out the device not there errors.
 * PCI: EADs Connect Failed 0x18.58.10 Rc: 0x00xx
 * PCI: Read Vendor Failed 0x18.58.10 Rc: 0x00xx
 * PCI: Connect Bus Unit Failed 0x18.58.10 Rc: 0x00xx
 */
static void pci_log_error(char *error, int bus, int subbus,
		int agent, int hv_res)
{
	if (hv_res == 0x0302)
		return;
	printk(KERN_ERR "PCI: %s Failed: 0x%02X.%02X.%02X Rc: 0x%04X",
	       error, bus, subbus, agent, hv_res);
}

/*
 * Look down the chain to find the matching Device Device
 */
static struct device_node *find_device_node(int bus, int devfn)
{
	struct device_node *node;

	for (node = NULL; (node = of_find_all_nodes(node)); ) {
		struct pci_dn *pdn = PCI_DN(node);

		if (pdn && (bus == pdn->busno) && (devfn == pdn->devfn))
			return node;
	}
	return NULL;
}

/*
 * iSeries_pci_final_fixup(void)
 */
void __init iSeries_pci_final_fixup(void)
{
	struct pci_dev *pdev = NULL;
	struct device_node *node;
	int num_dev = 0;

	/* Fix up at the device node and pci_dev relationship */
	mf_display_src(0xC9000100);

	printk("pcibios_final_fixup\n");
	for_each_pci_dev(pdev) {
		const u32 *agent;
		const u32 *sub_bus;
		unsigned char bus = pdev->bus->number;

		node = find_device_node(bus, pdev->devfn);
		printk("pci dev %p (%x.%x), node %p\n", pdev, bus,
			pdev->devfn, node);
		if (!node) {
			printk("PCI: Device Tree not found for 0x%016lX\n",
					(unsigned long)pdev);
			continue;
		}

		agent = of_get_property(node, "linux,agent-id", NULL);
		sub_bus = of_get_property(node, "linux,subbus", NULL);
		if (agent && sub_bus) {
			u8 irq = iSeries_allocate_IRQ(bus, 0, *sub_bus);
			int err;

			err = HvCallXm_connectBusUnit(bus, *sub_bus,
					*agent, irq);
			if (err)
				pci_log_error("Connect Bus Unit",
					bus, *sub_bus, *agent, err);
			else {
				err = HvCallPci_configStore8(bus, *sub_bus,
					*agent, PCI_INTERRUPT_LINE, irq);
				if (err)
					pci_log_error("PciCfgStore Irq Failed!",
						bus, *sub_bus, *agent, err);
				else
					pdev->irq = irq;
			}
		}

		num_dev++;
		pdev->sysdata = node;
		PCI_DN(node)->pcidev = pdev;
		allocate_device_bars(pdev);
		iSeries_Device_Information(pdev, num_dev, bus, *sub_bus);
		iommu_devnode_init_iSeries(pdev, node);
	}
	iSeries_activate_IRQs();
	mf_display_src(0xC9000200);
}

/*
 * Config space read and write functions.
 * For now at least, we look for the device node for the bus and devfn
 * that we are asked to access.  It may be possible to translate the devfn
 * to a subbus and deviceid more directly.
 */
static u64 hv_cfg_read_func[4]  = {
	HvCallPciConfigLoad8, HvCallPciConfigLoad16,
	HvCallPciConfigLoad32, HvCallPciConfigLoad32
};

static u64 hv_cfg_write_func[4] = {
	HvCallPciConfigStore8, HvCallPciConfigStore16,
	HvCallPciConfigStore32, HvCallPciConfigStore32
};

/*
 * Read PCI config space
 */
static int iSeries_pci_read_config(struct pci_bus *bus, unsigned int devfn,
		int offset, int size, u32 *val)
{
	struct device_node *node = find_device_node(bus->number, devfn);
	u64 fn;
	struct HvCallPci_LoadReturn ret;

	if (node == NULL)
		return PCIBIOS_DEVICE_NOT_FOUND;
	if (offset > 255) {
		*val = ~0;
		return PCIBIOS_BAD_REGISTER_NUMBER;
	}

	fn = hv_cfg_read_func[(size - 1) & 3];
	HvCall3Ret16(fn, &ret, iseries_ds_addr(node), offset, 0);

	if (ret.rc != 0) {
		*val = ~0;
		return PCIBIOS_DEVICE_NOT_FOUND;	/* or something */
	}

	*val = ret.value;
	return 0;
}

/*
 * Write PCI config space
 */

static int iSeries_pci_write_config(struct pci_bus *bus, unsigned int devfn,
		int offset, int size, u32 val)
{
	struct device_node *node = find_device_node(bus->number, devfn);
	u64 fn;
	u64 ret;

	if (node == NULL)
		return PCIBIOS_DEVICE_NOT_FOUND;
	if (offset > 255)
		return PCIBIOS_BAD_REGISTER_NUMBER;

	fn = hv_cfg_write_func[(size - 1) & 3];
	ret = HvCall4(fn, iseries_ds_addr(node), offset, val, 0);

	if (ret != 0)
		return PCIBIOS_DEVICE_NOT_FOUND;

	return 0;
}

static struct pci_ops iSeries_pci_ops = {
	.read = iSeries_pci_read_config,
	.write = iSeries_pci_write_config
};

/*
 * Check Return Code
 * -> On Failure, print and log information.
 *    Increment Retry Count, if exceeds max, panic partition.
 *
 * PCI: Device 23.90 ReadL I/O Error( 0): 0x1234
 * PCI: Device 23.90 ReadL Retry( 1)
 * PCI: Device 23.90 ReadL Retry Successful(1)
 */
static int check_return_code(char *type, struct device_node *dn,
		int *retry, u64 ret)
{
	if (ret != 0)  {
		struct pci_dn *pdn = PCI_DN(dn);

		(*retry)++;
		printk("PCI: %s: Device 0x%04X:%02X  I/O Error(%2d): 0x%04X\n",
				type, pdn->busno, pdn->devfn,
				*retry, (int)ret);
		/*
		 * Bump the retry and check for retry count exceeded.
		 * If, Exceeded, panic the system.
		 */
		if (((*retry) > PCI_RETRY_MAX) &&
				(limit_pci_retries > 0)) {
			mf_display_src(0xB6000103);
			panic_timeout = 0;
			panic("PCI: Hardware I/O Error, SRC B6000103, "
					"Automatic Reboot Disabled.\n");
		}
		return -1;	/* Retry Try */
	}
	return 0;
}

/*
 * Translate the I/O Address into a device node, bar, and bar offset.
 * Note: Make sure the passed variable end up on the stack to avoid
 * the exposure of being device global.
 */
static inline struct device_node *xlate_iomm_address(
		const volatile void __iomem *addr,
		u64 *dsaptr, u64 *bar_offset, const char *func)
{
	unsigned long orig_addr;
	unsigned long base_addr;
	unsigned long ind;
	struct device_node *dn;

	orig_addr = (unsigned long __force)addr;
	if ((orig_addr < BASE_IO_MEMORY) || (orig_addr >= max_io_memory)) {
		static unsigned long last_jiffies;
		static int num_printed;

		if ((jiffies - last_jiffies) > 60 * HZ) {
			last_jiffies = jiffies;
			num_printed = 0;
		}
		if (num_printed++ < 10)
			printk(KERN_ERR
				"iSeries_%s: invalid access at IO address %p\n",
				func, addr);
		return NULL;
	}
	base_addr = orig_addr - BASE_IO_MEMORY;
	ind = base_addr / IOMM_TABLE_ENTRY_SIZE;
	dn = iomm_table[ind];

	if (dn != NULL) {
		int barnum = iobar_table[ind];
		*dsaptr = iseries_ds_addr(dn) | (barnum << 24);
		*bar_offset = base_addr % IOMM_TABLE_ENTRY_SIZE;
	} else
		panic("PCI: Invalid PCI IO address detected!\n");
	return dn;
}

/*
 * Read MM I/O Instructions for the iSeries
 * On MM I/O error, all ones are returned and iSeries_pci_IoError is cal
 * else, data is returned in Big Endian format.
 */
static u8 iseries_readb(const volatile void __iomem *addr)
{
	u64 bar_offset;
	u64 dsa;
	int retry = 0;
	struct HvCallPci_LoadReturn ret;
	struct device_node *dn =
		xlate_iomm_address(addr, &dsa, &bar_offset, "read_byte");

	if (dn == NULL)
		return 0xff;
	do {
		HvCall3Ret16(HvCallPciBarLoad8, &ret, dsa, bar_offset, 0);
	} while (check_return_code("RDB", dn, &retry, ret.rc) != 0);

	return ret.value;
}

static u16 iseries_readw_be(const volatile void __iomem *addr)
{
	u64 bar_offset;
	u64 dsa;
	int retry = 0;
	struct HvCallPci_LoadReturn ret;
	struct device_node *dn =
		xlate_iomm_address(addr, &dsa, &bar_offset, "read_word");

	if (dn == NULL)
		return 0xffff;
	do {
		HvCall3Ret16(HvCallPciBarLoad16, &ret, dsa,
				bar_offset, 0);
	} while (check_return_code("RDW", dn, &retry, ret.rc) != 0);

	return ret.value;
}

static u32 iseries_readl_be(const volatile void __iomem *addr)
{
	u64 bar_offset;
	u64 dsa;
	int retry = 0;
	struct HvCallPci_LoadReturn ret;
	struct device_node *dn =
		xlate_iomm_address(addr, &dsa, &bar_offset, "read_long");

	if (dn == NULL)
		return 0xffffffff;
	do {
		HvCall3Ret16(HvCallPciBarLoad32, &ret, dsa,
				bar_offset, 0);
	} while (check_return_code("RDL", dn, &retry, ret.rc) != 0);

	return ret.value;
}

/*
 * Write MM I/O Instructions for the iSeries
 *
 */
static void iseries_writeb(u8 data, volatile void __iomem *addr)
{
	u64 bar_offset;
	u64 dsa;
	int retry = 0;
	u64 rc;
	struct device_node *dn =
		xlate_iomm_address(addr, &dsa, &bar_offset, "write_byte");

	if (dn == NULL)
		return;
	do {
		rc = HvCall4(HvCallPciBarStore8, dsa, bar_offset, data, 0);
	} while (check_return_code("WWB", dn, &retry, rc) != 0);
}

static void iseries_writew_be(u16 data, volatile void __iomem *addr)
{
	u64 bar_offset;
	u64 dsa;
	int retry = 0;
	u64 rc;
	struct device_node *dn =
		xlate_iomm_address(addr, &dsa, &bar_offset, "write_word");

	if (dn == NULL)
		return;
	do {
		rc = HvCall4(HvCallPciBarStore16, dsa, bar_offset, data, 0);
	} while (check_return_code("WWW", dn, &retry, rc) != 0);
}

static void iseries_writel_be(u32 data, volatile void __iomem *addr)
{
	u64 bar_offset;
	u64 dsa;
	int retry = 0;
	u64 rc;
	struct device_node *dn =
		xlate_iomm_address(addr, &dsa, &bar_offset, "write_long");

	if (dn == NULL)
		return;
	do {
		rc = HvCall4(HvCallPciBarStore32, dsa, bar_offset, data, 0);
	} while (check_return_code("WWL", dn, &retry, rc) != 0);
}

static u16 iseries_readw(const volatile void __iomem *addr)
{
	return le16_to_cpu(iseries_readw_be(addr));
}

static u32 iseries_readl(const volatile void __iomem *addr)
{
	return le32_to_cpu(iseries_readl_be(addr));
}

static void iseries_writew(u16 data, volatile void __iomem *addr)
{
	iseries_writew_be(cpu_to_le16(data), addr);
}

static void iseries_writel(u32 data, volatile void __iomem *addr)
{
	iseries_writel(cpu_to_le32(data), addr);
}

static void iseries_readsb(const volatile void __iomem *addr, void *buf,
			   unsigned long count)
{
	u8 *dst = buf;
	while(count-- > 0)
		*(dst++) = iseries_readb(addr);
}

static void iseries_readsw(const volatile void __iomem *addr, void *buf,
			   unsigned long count)
{
	u16 *dst = buf;
	while(count-- > 0)
		*(dst++) = iseries_readw_be(addr);
}

static void iseries_readsl(const volatile void __iomem *addr, void *buf,
			   unsigned long count)
{
	u32 *dst = buf;
	while(count-- > 0)
		*(dst++) = iseries_readl_be(addr);
}

static void iseries_writesb(volatile void __iomem *addr, const void *buf,
			    unsigned long count)
{
	const u8 *src = buf;
	while(count-- > 0)
		iseries_writeb(*(src++), addr);
}

static void iseries_writesw(volatile void __iomem *addr, const void *buf,
			    unsigned long count)
{
	const u16 *src = buf;
	while(count-- > 0)
		iseries_writew_be(*(src++), addr);
}

static void iseries_writesl(volatile void __iomem *addr, const void *buf,
			    unsigned long count)
{
	const u32 *src = buf;
	while(count-- > 0)
		iseries_writel_be(*(src++), addr);
}

static void iseries_memset_io(volatile void __iomem *addr, int c,
			      unsigned long n)
{
	volatile char __iomem *d = addr;

	while (n-- > 0)
		iseries_writeb(c, d++);
}

static void iseries_memcpy_fromio(void *dest, const volatile void __iomem *src,
				  unsigned long n)
{
	char *d = dest;
	const volatile char __iomem *s = src;

	while (n-- > 0)
		*d++ = iseries_readb(s++);
}

static void iseries_memcpy_toio(volatile void __iomem *dest, const void *src,
				unsigned long n)
{
	const char *s = src;
	volatile char __iomem *d = dest;

	while (n-- > 0)
		iseries_writeb(*s++, d++);
}

/* We only set MMIO ops. The default PIO ops will be default
 * to the MMIO ops + pci_io_base which is 0 on iSeries as
 * expected so both should work.
 *
 * Note that we don't implement the readq/writeq versions as
 * I don't know of an HV call for doing so. Thus, the default
 * operation will be used instead, which will fault a the value
 * return by iSeries for MMIO addresses always hits a non mapped
 * area. This is as good as the BUG() we used to have there.
 */
static struct ppc_pci_io __initdata iseries_pci_io = {
	.readb = iseries_readb,
	.readw = iseries_readw,
	.readl = iseries_readl,
	.readw_be = iseries_readw_be,
	.readl_be = iseries_readl_be,
	.writeb = iseries_writeb,
	.writew = iseries_writew,
	.writel = iseries_writel,
	.writew_be = iseries_writew_be,
	.writel_be = iseries_writel_be,
	.readsb = iseries_readsb,
	.readsw = iseries_readsw,
	.readsl = iseries_readsl,
	.writesb = iseries_writesb,
	.writesw = iseries_writesw,
	.writesl = iseries_writesl,
	.memset_io = iseries_memset_io,
	.memcpy_fromio = iseries_memcpy_fromio,
	.memcpy_toio = iseries_memcpy_toio,
};

/*
 * iSeries_pcibios_init
 *
 * Description:
 *   This function checks for all possible system PCI host bridges that connect
 *   PCI buses.  The system hypervisor is queried as to the guest partition
 *   ownership status.  A pci_controller is built for any bus which is partially
 *   owned or fully owned by this guest partition.
 */
void __init iSeries_pcibios_init(void)
{
	struct pci_controller *phb;
	struct device_node *root = of_find_node_by_path("/");
	struct device_node *node = NULL;

	/* Install IO hooks */
	ppc_pci_io = iseries_pci_io;

	pci_probe_only = 1;

	/* iSeries has no IO space in the common sense, it needs to set
	 * the IO base to 0
	 */
	pci_io_base = 0;

	if (root == NULL) {
		printk(KERN_CRIT "iSeries_pcibios_init: can't find root "
				"of device tree\n");
		return;
	}
	while ((node = of_get_next_child(root, node)) != NULL) {
		HvBusNumber bus;
		const u32 *busp;

		if ((node->type == NULL) || (strcmp(node->type, "pci") != 0))
			continue;

		busp = of_get_property(node, "bus-range", NULL);
		if (busp == NULL)
			continue;
		bus = *busp;
		printk("bus %d appears to exist\n", bus);
		phb = pcibios_alloc_controller(node);
		if (phb == NULL)
			continue;

		phb->pci_mem_offset = bus;
		phb->first_busno = bus;
		phb->last_busno = bus;
		phb->ops = &iSeries_pci_ops;
	}

	of_node_put(root);

	pci_devs_phb_init();
}

