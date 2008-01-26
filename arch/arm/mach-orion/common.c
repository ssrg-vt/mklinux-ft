/*
 * arch/arm/mach-orion/common.c
 *
 * Core functions for Marvell Orion System On Chip
 *
 * Maintainer: Tzachi Perelstein <tzachi@marvell.com>
 *
 * This file is licensed under  the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/serial_8250.h>
#include <asm/page.h>
#include <asm/timex.h>
#include <asm/mach/map.h>
#include <asm/arch/orion.h>
#include "common.h"

/*****************************************************************************
 * I/O Address Mapping
 ****************************************************************************/
static struct map_desc orion_io_desc[] __initdata = {
	{
		.virtual	= ORION_REGS_BASE,
		.pfn		= __phys_to_pfn(ORION_REGS_BASE),
		.length		= ORION_REGS_SIZE,
		.type		= MT_DEVICE
	},
	{
		.virtual	= ORION_PCIE_IO_BASE,
		.pfn		= __phys_to_pfn(ORION_PCIE_IO_BASE),
		.length		= ORION_PCIE_IO_SIZE,
		.type		= MT_DEVICE
	},
	{
		.virtual	= ORION_PCI_IO_BASE,
		.pfn		= __phys_to_pfn(ORION_PCI_IO_BASE),
		.length		= ORION_PCI_IO_SIZE,
		.type		= MT_DEVICE
	},
	{
		.virtual	= ORION_PCIE_WA_BASE,
		.pfn		= __phys_to_pfn(ORION_PCIE_WA_BASE),
		.length		= ORION_PCIE_WA_SIZE,
		.type		= MT_DEVICE
	},
};

void __init orion_map_io(void)
{
	iotable_init(orion_io_desc, ARRAY_SIZE(orion_io_desc));
}

/*****************************************************************************
 * UART
 ****************************************************************************/

static struct resource orion_uart_resources[] = {
	{
		.start		= UART0_BASE,
		.end		= UART0_BASE + 0xff,
		.flags		= IORESOURCE_MEM,
	},
	{
		.start		= IRQ_ORION_UART0,
		.end		= IRQ_ORION_UART0,
		.flags		= IORESOURCE_IRQ,
	},
	{
		.start		= UART1_BASE,
		.end		= UART1_BASE + 0xff,
		.flags		= IORESOURCE_MEM,
	},
	{
		.start		= IRQ_ORION_UART1,
		.end		= IRQ_ORION_UART1,
		.flags		= IORESOURCE_IRQ,
	},
};

static struct plat_serial8250_port orion_uart_data[] = {
	{
		.mapbase	= UART0_BASE,
		.membase	= (char *)UART0_BASE,
		.irq		= IRQ_ORION_UART0,
		.flags		= UPF_SKIP_TEST | UPF_BOOT_AUTOCONF,
		.iotype		= UPIO_MEM,
		.regshift	= 2,
		.uartclk	= ORION_TCLK,
	},
	{
		.mapbase	= UART1_BASE,
		.membase	= (char *)UART1_BASE,
		.irq		= IRQ_ORION_UART1,
		.flags		= UPF_SKIP_TEST | UPF_BOOT_AUTOCONF,
		.iotype		= UPIO_MEM,
		.regshift	= 2,
		.uartclk	= ORION_TCLK,
	},
	{ },
};

static struct platform_device orion_uart = {
	.name			= "serial8250",
	.id			= PLAT8250_DEV_PLATFORM,
	.dev			= {
		.platform_data	= orion_uart_data,
	},
	.resource		= orion_uart_resources,
	.num_resources		= ARRAY_SIZE(orion_uart_resources),
};

/*******************************************************************************
 * USB Controller - 2 interfaces
 ******************************************************************************/

static struct resource orion_ehci0_resources[] = {
	{
		.start	= ORION_USB0_REG_BASE,
		.end	= ORION_USB0_REG_BASE + SZ_4K,
		.flags	= IORESOURCE_MEM,
	},
	{
		.start	= IRQ_ORION_USB0_CTRL,
		.end	= IRQ_ORION_USB0_CTRL,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct resource orion_ehci1_resources[] = {
	{
		.start	= ORION_USB1_REG_BASE,
		.end	= ORION_USB1_REG_BASE + SZ_4K,
		.flags	= IORESOURCE_MEM,
	},
	{
		.start	= IRQ_ORION_USB1_CTRL,
		.end	= IRQ_ORION_USB1_CTRL,
		.flags	= IORESOURCE_IRQ,
	},
};

static u64 ehci_dmamask = 0xffffffffUL;

static struct platform_device orion_ehci0 = {
	.name		= "orion-ehci",
	.id		= 0,
	.dev		= {
		.dma_mask		= &ehci_dmamask,
		.coherent_dma_mask	= 0xffffffff,
	},
	.resource	= orion_ehci0_resources,
	.num_resources	= ARRAY_SIZE(orion_ehci0_resources),
};

static struct platform_device orion_ehci1 = {
	.name		= "orion-ehci",
	.id		= 1,
	.dev		= {
		.dma_mask		= &ehci_dmamask,
		.coherent_dma_mask	= 0xffffffff,
	},
	.resource	= orion_ehci1_resources,
	.num_resources	= ARRAY_SIZE(orion_ehci1_resources),
};

/*****************************************************************************
 * General
 ****************************************************************************/

/*
 * Identify device ID and rev from PCIE configuration header space '0'.
 */
static void orion_id(u32 *dev, u32 *rev, char **dev_name)
{
	orion_pcie_id(dev, rev);

	if (*dev == MV88F5281_DEV_ID) {
		if (*rev == MV88F5281_REV_D2) {
			*dev_name = "MV88F5281-D2";
		} else if (*rev == MV88F5281_REV_D1) {
			*dev_name = "MV88F5281-D1";
		} else {
			*dev_name = "MV88F5281-Rev-Unsupported";
		}
	} else if (*dev == MV88F5182_DEV_ID) {
		if (*rev == MV88F5182_REV_A2) {
			*dev_name = "MV88F5182-A2";
		} else {
			*dev_name = "MV88F5182-Rev-Unsupported";
		}
	} else {
		*dev_name = "Device-Unknown";
	}
}

void __init orion_init(void)
{
	char *dev_name;
	u32 dev, rev;

	orion_id(&dev, &rev, &dev_name);
	printk(KERN_INFO "Orion ID: %s. TCLK=%d.\n", dev_name, ORION_TCLK);

	/*
	 * Setup Orion address map
	 */
	orion_setup_cpu_wins();
	orion_setup_usb_wins();
	orion_setup_eth_wins();
	orion_setup_pci_wins();
	orion_setup_pcie_wins();
	if (dev == MV88F5182_DEV_ID)
		orion_setup_sata_wins();

	/*
	 * REgister devices
	 */
	platform_device_register(&orion_uart);
	platform_device_register(&orion_ehci0);
	if (dev == MV88F5182_DEV_ID)
		platform_device_register(&orion_ehci1);
}
