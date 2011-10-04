/*
 * Agere Systems Inc.
 * 10/100/1000 Base-T Ethernet Driver for the ET1310 and ET131x series MACs
 *
 * Copyright © 2005 Agere Systems Inc.
 * All rights reserved.
 *   http://www.agere.com
 *
 *------------------------------------------------------------------------------
 *
 * et131x_initpci.c - Routines and data used to register the driver with the
 *                    PCI (and PCI Express) subsystem, as well as basic driver
 *                    init and startup.
 *
 *------------------------------------------------------------------------------
 *
 * SOFTWARE LICENSE
 *
 * This software is provided subject to the following terms and conditions,
 * which you should read carefully before using the software.  Using this
 * software indicates your acceptance of these terms and conditions.  If you do
 * not agree with these terms and conditions, do not use the software.
 *
 * Copyright © 2005 Agere Systems Inc.
 * All rights reserved.
 *
 * Redistribution and use in source or binary forms, with or without
 * modifications, are permitted provided that the following conditions are met:
 *
 * . Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following Disclaimer as comments in the code as
 *    well as in the documentation and/or other materials provided with the
 *    distribution.
 *
 * . Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following Disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * . Neither the name of Agere Systems Inc. nor the names of the contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Disclaimer
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, INFRINGEMENT AND THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  ANY
 * USE, MODIFICATION OR DISTRIBUTION OF THIS SOFTWARE IS SOLELY AT THE USERS OWN
 * RISK. IN NO EVENT SHALL AGERE SYSTEMS INC. OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, INCLUDING, BUT NOT LIMITED TO, CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 */

#include "et131x_version.h"
#include "et131x_defs.h"

#include <linux/pci.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>

#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/in.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/bitops.h>
#include <asm/system.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/phy.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/ioport.h>
#include <linux/random.h>

#include "et1310_phy.h"

#include "et131x_adapter.h"

#include "et1310_address_map.h"
#include "et1310_tx.h"
#include "et1310_rx.h"
#include "et131x.h"

#define INTERNAL_MEM_SIZE       0x400	/* 1024 of internal memory */
#define INTERNAL_MEM_RX_OFFSET  0x1FF	/* 50%   Tx, 50%   Rx */

/**
 * et131x_hwaddr_init - set up the MAC Address on the ET1310
 * @adapter: pointer to our private adapter structure
 */
void et131x_hwaddr_init(struct et131x_adapter *adapter)
{
	/* If have our default mac from init and no mac address from
	 * EEPROM then we need to generate the last octet and set it on the
	 * device
	 */
	if (adapter->rom_addr[0] == 0x00 &&
	    adapter->rom_addr[1] == 0x00 &&
	    adapter->rom_addr[2] == 0x00 &&
	    adapter->rom_addr[3] == 0x00 &&
	    adapter->rom_addr[4] == 0x00 &&
	    adapter->rom_addr[5] == 0x00) {
		/*
		 * We need to randomly generate the last octet so we
		 * decrease our chances of setting the mac address to
		 * same as another one of our cards in the system
		 */
		get_random_bytes(&adapter->addr[5], 1);
		/*
		 * We have the default value in the register we are
		 * working with so we need to copy the current
		 * address into the permanent address
		 */
		memcpy(adapter->rom_addr,
			adapter->addr, ETH_ALEN);
	} else {
		/* We do not have an override address, so set the
		 * current address to the permanent address and add
		 * it to the device
		 */
		memcpy(adapter->addr,
		       adapter->rom_addr, ETH_ALEN);
	}
}

/**
 * et131x_pci_init	 - initial PCI setup
 * @adapter: pointer to our private adapter structure
 * @pdev: our PCI device
 *
 * Perform the initial setup of PCI registers and if possible initialise
 * the MAC address. At this point the I/O registers have yet to be mapped
 */
static int et131x_pci_init(struct et131x_adapter *adapter,
						struct pci_dev *pdev)
{
	int i;
	u8 max_payload;
	u8 read_size_reg;

	if (et131x_init_eeprom(adapter) < 0)
		return -EIO;

	/* Let's set up the PORT LOGIC Register.  First we need to know what
	 * the max_payload_size is
	 */
	if (pci_read_config_byte(pdev, ET1310_PCI_MAX_PYLD, &max_payload)) {
		dev_err(&pdev->dev,
		    "Could not read PCI config space for Max Payload Size\n");
		return -EIO;
	}

	/* Program the Ack/Nak latency and replay timers */
	max_payload &= 0x07;	/* Only the lower 3 bits are valid */

	if (max_payload < 2) {
		static const u16 acknak[2] = { 0x76, 0xD0 };
		static const u16 replay[2] = { 0x1E0, 0x2ED };

		if (pci_write_config_word(pdev, ET1310_PCI_ACK_NACK,
					       acknak[max_payload])) {
			dev_err(&pdev->dev,
			  "Could not write PCI config space for ACK/NAK\n");
			return -EIO;
		}
		if (pci_write_config_word(pdev, ET1310_PCI_REPLAY,
					       replay[max_payload])) {
			dev_err(&pdev->dev,
			  "Could not write PCI config space for Replay Timer\n");
			return -EIO;
		}
	}

	/* l0s and l1 latency timers.  We are using default values.
	 * Representing 001 for L0s and 010 for L1
	 */
	if (pci_write_config_byte(pdev, ET1310_PCI_L0L1LATENCY, 0x11)) {
		dev_err(&pdev->dev,
		  "Could not write PCI config space for Latency Timers\n");
		return -EIO;
	}

	/* Change the max read size to 2k */
	if (pci_read_config_byte(pdev, 0x51, &read_size_reg)) {
		dev_err(&pdev->dev,
			"Could not read PCI config space for Max read size\n");
		return -EIO;
	}

	read_size_reg &= 0x8f;
	read_size_reg |= 0x40;

	if (pci_write_config_byte(pdev, 0x51, read_size_reg)) {
		dev_err(&pdev->dev,
		      "Could not write PCI config space for Max read size\n");
		return -EIO;
	}

	/* Get MAC address from config space if an eeprom exists, otherwise
	 * the MAC address there will not be valid
	 */
	if (!adapter->has_eeprom) {
		et131x_hwaddr_init(adapter);
		return 0;
	}

	for (i = 0; i < ETH_ALEN; i++) {
		if (pci_read_config_byte(pdev, ET1310_PCI_MAC_ADDRESS + i,
					adapter->rom_addr + i)) {
			dev_err(&pdev->dev, "Could not read PCI config space for MAC address\n");
			return -EIO;
		}
	}
	memcpy(adapter->addr, adapter->rom_addr, ETH_ALEN);
	return 0;
}

/**
 * et131x_error_timer_handler
 * @data: timer-specific variable; here a pointer to our adapter structure
 *
 * The routine called when the error timer expires, to track the number of
 * recurring errors.
 */
void et131x_error_timer_handler(unsigned long data)
{
	struct et131x_adapter *adapter = (struct et131x_adapter *) data;

	if (!et1310_in_phy_coma(adapter))
		et1310_update_macstat_host_counters(adapter);
	else
		dev_err(&adapter->pdev->dev, "No interrupts, in PHY coma\n");

	if (!(adapter->bmsr & BMSR_LSTATUS) &&
	    adapter->boot_coma < 11) {
		adapter->boot_coma++;
	}

	if (adapter->boot_coma == 10) {
		if (!(adapter->bmsr & BMSR_LSTATUS)) {
			if (!et1310_in_phy_coma(adapter)) {
				/* NOTE - This was originally a 'sync with
				 *  interrupt'. How to do that under Linux?
				 */
				et131x_enable_interrupts(adapter);
				et1310_enable_phy_coma(adapter);
			}
		}
	}

	/* This is a periodic timer, so reschedule */
	mod_timer(&adapter->error_timer, jiffies +
					  TX_ERROR_PERIOD * HZ / 1000);
}

/**
 * et131x_configure_global_regs	-	configure JAGCore global regs
 * @adapter: pointer to our adapter structure
 *
 * Used to configure the global registers on the JAGCore
 */
void et131x_configure_global_regs(struct et131x_adapter *adapter)
{
	struct global_regs __iomem *regs = &adapter->regs->global;

	writel(0, &regs->rxq_start_addr);
	writel(INTERNAL_MEM_SIZE - 1, &regs->txq_end_addr);

	if (adapter->registry_jumbo_packet < 2048) {
		/* Tx / RxDMA and Tx/Rx MAC interfaces have a 1k word
		 * block of RAM that the driver can split between Tx
		 * and Rx as it desires.  Our default is to split it
		 * 50/50:
		 */
		writel(PARM_RX_MEM_END_DEF, &regs->rxq_end_addr);
		writel(PARM_RX_MEM_END_DEF + 1, &regs->txq_start_addr);
	} else if (adapter->registry_jumbo_packet < 8192) {
		/* For jumbo packets > 2k but < 8k, split 50-50. */
		writel(INTERNAL_MEM_RX_OFFSET, &regs->rxq_end_addr);
		writel(INTERNAL_MEM_RX_OFFSET + 1, &regs->txq_start_addr);
	} else {
		/* 9216 is the only packet size greater than 8k that
		 * is available. The Tx buffer has to be big enough
		 * for one whole packet on the Tx side. We'll make
		 * the Tx 9408, and give the rest to Rx
		 */
		writel(0x01b3, &regs->rxq_end_addr);
		writel(0x01b4, &regs->txq_start_addr);
	}

	/* Initialize the loopback register. Disable all loopbacks. */
	writel(0, &regs->loopback);

	/* MSI Register */
	writel(0, &regs->msi_config);

	/* By default, disable the watchdog timer.  It will be enabled when
	 * a packet is queued.
	 */
	writel(0, &regs->watchdog_timer);
}

/**
 * et131x_adapter_setup - Set the adapter up as per cassini+ documentation
 * @adapter: pointer to our private adapter structure
 *
 * Returns 0 on success, errno on failure (as defined in errno.h)
 */
void et131x_adapter_setup(struct et131x_adapter *adapter)
{
	/* Configure the JAGCore */
	et131x_configure_global_regs(adapter);

	et1310_config_mac_regs1(adapter);

	/* Configure the MMC registers */
	/* All we need to do is initialize the Memory Control Register */
	writel(ET_MMC_ENABLE, &adapter->regs->mmc.mmc_ctrl);

	et1310_config_rxmac_regs(adapter);
	et1310_config_txmac_regs(adapter);

	et131x_config_rx_dma_regs(adapter);
	et131x_config_tx_dma_regs(adapter);

	et1310_config_macstat_regs(adapter);

	et1310_phy_power_down(adapter, 0);
	et131x_xcvr_init(adapter);
}

/**
 * et131x_soft_reset - Issue a soft reset to the hardware, complete for ET1310
 * @adapter: pointer to our private adapter structure
 */
void et131x_soft_reset(struct et131x_adapter *adapter)
{
	/* Disable MAC Core */
	writel(0xc00f0000, &adapter->regs->mac.cfg1);

	/* Set everything to a reset value */
	writel(0x7F, &adapter->regs->global.sw_reset);
	writel(0x000f0000, &adapter->regs->mac.cfg1);
	writel(0x00000000, &adapter->regs->mac.cfg1);
}

/**
 * et131x_align_allocated_memory - Align allocated memory on a given boundary
 * @adapter: pointer to our adapter structure
 * @phys_addr: pointer to Physical address
 * @offset: pointer to the offset variable
 * @mask: correct mask
 */
void et131x_align_allocated_memory(struct et131x_adapter *adapter,
				   uint64_t *phys_addr,
				   uint64_t *offset, uint64_t mask)
{
	uint64_t new_addr;

	*offset = 0;

	new_addr = *phys_addr & ~mask;

	if (new_addr != *phys_addr) {
		/* Move to next aligned block */
		new_addr += mask + 1;
		/* Return offset for adjusting virt addr */
		*offset = new_addr - *phys_addr;
		/* Return new physical address */
		*phys_addr = new_addr;
	}
}

/**
 * et131x_adapter_memory_alloc
 * @adapter: pointer to our private adapter structure
 *
 * Returns 0 on success, errno on failure (as defined in errno.h).
 *
 * Allocate all the memory blocks for send, receive and others.
 */
int et131x_adapter_memory_alloc(struct et131x_adapter *adapter)
{
	int status;

	/* Allocate memory for the Tx Ring */
	status = et131x_tx_dma_memory_alloc(adapter);
	if (status != 0) {
		dev_err(&adapter->pdev->dev,
			  "et131x_tx_dma_memory_alloc FAILED\n");
		return status;
	}
	/* Receive buffer memory allocation */
	status = et131x_rx_dma_memory_alloc(adapter);
	if (status != 0) {
		dev_err(&adapter->pdev->dev,
			  "et131x_rx_dma_memory_alloc FAILED\n");
		et131x_tx_dma_memory_free(adapter);
		return status;
	}

	/* Init receive data structures */
	status = et131x_init_recv(adapter);
	if (status != 0) {
		dev_err(&adapter->pdev->dev,
			"et131x_init_recv FAILED\n");
		et131x_tx_dma_memory_free(adapter);
		et131x_rx_dma_memory_free(adapter);
	}
	return status;
}

/**
 * et131x_adapter_memory_free - Free all memory allocated for use by Tx & Rx
 * @adapter: pointer to our private adapter structure
 */
void et131x_adapter_memory_free(struct et131x_adapter *adapter)
{
	/* Free DMA memory */
	et131x_tx_dma_memory_free(adapter);
	et131x_rx_dma_memory_free(adapter);
}

static void et131x_adjust_link(struct net_device *netdev)
{
	struct et131x_adapter *adapter = netdev_priv(netdev);
	struct  phy_device *phydev = adapter->phydev;

	if (netif_carrier_ok(netdev)) {
		adapter->boot_coma = 20;

		if (phydev && phydev->speed == SPEED_10) {
			/*
			 * NOTE - Is there a way to query this without
			 * TruePHY?
			 * && TRU_QueryCoreType(adapter->hTruePhy, 0)==
			 * EMI_TRUEPHY_A13O) {
			 */
			u16 register18;

			et131x_mii_read(adapter, PHY_MPHY_CONTROL_REG,
					 &register18);
			et131x_mii_write(adapter, PHY_MPHY_CONTROL_REG,
					 register18 | 0x4);
			et131x_mii_write(adapter, PHY_INDEX_REG,
					 register18 | 0x8402);
			et131x_mii_write(adapter, PHY_DATA_REG,
					 register18 | 511);
			et131x_mii_write(adapter, PHY_MPHY_CONTROL_REG,
					 register18);
		}

		et1310_config_flow_control(adapter);

		if (phydev && phydev->speed == SPEED_1000 &&
				adapter->registry_jumbo_packet > 2048) {
			u16 reg;

			et131x_mii_read(adapter, PHY_CONFIG, &reg);
			reg &= ~ET_PHY_CONFIG_TX_FIFO_DEPTH;
			reg |= ET_PHY_CONFIG_FIFO_DEPTH_32;
			et131x_mii_write(adapter, PHY_CONFIG, reg);
		}

		et131x_set_rx_dma_timer(adapter);
		et1310_config_mac_regs2(adapter);
	}

	if (phydev->link != adapter->link) {
		/*
		 * Check to see if we are in coma mode and if
		 * so, disable it because we will not be able
		 * to read PHY values until we are out.
		 */
		if (et1310_in_phy_coma(adapter))
			et1310_disable_phy_coma(adapter);

		if (phydev->link) {
			adapter->boot_coma = 20;
		} else {
			dev_warn(&adapter->pdev->dev,
			    "Link down - cable problem ?\n");

			if (phydev && phydev->speed == SPEED_10) {
				/* NOTE - Is there a way to query this without
				 * TruePHY?
				 * && TRU_QueryCoreType(adapter->hTruePhy, 0) ==
				 * EMI_TRUEPHY_A13O)
				 */
				u16 register18;

				et131x_mii_read(adapter, PHY_MPHY_CONTROL_REG,
						 &register18);
				et131x_mii_write(adapter, PHY_MPHY_CONTROL_REG,
						 register18 | 0x4);
				et131x_mii_write(adapter, PHY_INDEX_REG,
						 register18 | 0x8402);
				et131x_mii_write(adapter, PHY_DATA_REG,
						 register18 | 511);
				et131x_mii_write(adapter, PHY_MPHY_CONTROL_REG,
						 register18);
			}

			/* Free the packets being actively sent & stopped */
			et131x_free_busy_send_packets(adapter);

			/* Re-initialize the send structures */
			et131x_init_send(adapter);

			/* Reset the RFD list and re-start RU */
			et131x_reset_recv(adapter);

			/*
			 * Bring the device back to the state it was during
			 * init prior to autonegotiation being complete. This
			 * way, when we get the auto-neg complete interrupt,
			 * we can complete init by calling config_mac_regs2.
			 */
			et131x_soft_reset(adapter);

			/* Setup ET1310 as per the documentation */
			et131x_adapter_setup(adapter);

			/* perform reset of tx/rx */
			et131x_disable_txrx(netdev);
			et131x_enable_txrx(netdev);
		}

		adapter->link = phydev->link;

		phy_print_status(phydev);
	}
}

int et131x_mii_probe(struct net_device *netdev)
{
	struct et131x_adapter *adapter = netdev_priv(netdev);
	struct  phy_device *phydev = NULL;

	phydev = phy_find_first(adapter->mii_bus);
	if (!phydev) {
		dev_err(&adapter->pdev->dev, "no PHY found\n");
		return -ENODEV;
	}

	phydev = phy_connect(netdev, dev_name(&phydev->dev),
			&et131x_adjust_link, 0, PHY_INTERFACE_MODE_MII);

	if (IS_ERR(phydev)) {
		dev_err(&adapter->pdev->dev, "Could not attach to PHY\n");
		return PTR_ERR(phydev);
	}

	phydev->supported &= (SUPPORTED_10baseT_Half
				| SUPPORTED_10baseT_Full
				| SUPPORTED_100baseT_Half
				| SUPPORTED_100baseT_Full
				| SUPPORTED_Autoneg
				| SUPPORTED_MII
				| SUPPORTED_TP);

	if (adapter->pdev->device != ET131X_PCI_DEVICE_ID_FAST)
		phydev->supported |= SUPPORTED_1000baseT_Full;

	phydev->advertising = phydev->supported;
	adapter->phydev = phydev;

	dev_info(&adapter->pdev->dev, "attached PHY driver [%s] "
		 "(mii_bus:phy_addr=%s)\n",
		 phydev->drv->name, dev_name(&phydev->dev));

	return 0;
}

/**
 * et131x_adapter_init
 * @adapter: pointer to the private adapter struct
 * @pdev: pointer to the PCI device
 *
 * Initialize the data structures for the et131x_adapter object and link
 * them together with the platform provided device structures.
 */
static struct et131x_adapter *et131x_adapter_init(struct net_device *netdev,
		struct pci_dev *pdev)
{
	static const u8 default_mac[] = { 0x00, 0x05, 0x3d, 0x00, 0x02, 0x00 };

	struct et131x_adapter *adapter;

	/* Allocate private adapter struct and copy in relevant information */
	adapter = netdev_priv(netdev);
	adapter->pdev = pci_dev_get(pdev);
	adapter->netdev = netdev;

	/* Do the same for the netdev struct */
	netdev->irq = pdev->irq;
	netdev->base_addr = pci_resource_start(pdev, 0);

	/* Initialize spinlocks here */
	spin_lock_init(&adapter->lock);
	spin_lock_init(&adapter->tcb_send_qlock);
	spin_lock_init(&adapter->tcb_ready_qlock);
	spin_lock_init(&adapter->send_hw_lock);
	spin_lock_init(&adapter->rcv_lock);
	spin_lock_init(&adapter->rcv_pend_lock);
	spin_lock_init(&adapter->fbr_lock);
	spin_lock_init(&adapter->phy_lock);

	adapter->registry_jumbo_packet = 1514;	/* 1514-9216 */

	/* Set the MAC address to a default */
	memcpy(adapter->addr, default_mac, ETH_ALEN);

	return adapter;
}

/**
 * et131x_pci_setup - Perform device initialization
 * @pdev: a pointer to the device's pci_dev structure
 * @ent: this device's entry in the pci_device_id table
 *
 * Returns 0 on success, errno on failure (as defined in errno.h)
 *
 * Registered in the pci_driver structure, this function is called when the
 * PCI subsystem finds a new PCI device which matches the information
 * contained in the pci_device_id table. This routine is the equivalent to
 * a device insertion routine.
 */
static int __devinit et131x_pci_setup(struct pci_dev *pdev,
			       const struct pci_device_id *ent)
{
	int result;
	int pm_cap;
	struct net_device *netdev;
	struct et131x_adapter *adapter;
	int ii;

	result = pci_enable_device(pdev);
	if (result) {
		dev_err(&pdev->dev, "pci_enable_device() failed\n");
		goto err_out;
	}

	/* Perform some basic PCI checks */
	if (!(pci_resource_flags(pdev, 0) & IORESOURCE_MEM)) {
		dev_err(&pdev->dev, "Can't find PCI device's base address\n");
		goto err_disable;
	}

	if (pci_request_regions(pdev, DRIVER_NAME)) {
		dev_err(&pdev->dev, "Can't get PCI resources\n");
		goto err_disable;
	}

	pci_set_master(pdev);

	/* Query PCI for Power Mgmt Capabilities
	 *
	 * NOTE: Now reading PowerMgmt in another location; is this still
	 * needed?
	 */
	pm_cap = pci_find_capability(pdev, PCI_CAP_ID_PM);
	if (!pm_cap) {
		dev_err(&pdev->dev,
			  "Cannot find Power Management capabilities\n");
		result = -EIO;
		goto err_release_res;
	}

	/* Check the DMA addressing support of this device */
	if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(64))) {
		result = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));
		if (result) {
			dev_err(&pdev->dev,
			  "Unable to obtain 64 bit DMA for consistent allocations\n");
			goto err_release_res;
		}
	} else if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(32))) {
		result = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
		if (result) {
			dev_err(&pdev->dev,
			  "Unable to obtain 32 bit DMA for consistent allocations\n");
			goto err_release_res;
		}
	} else {
		dev_err(&pdev->dev, "No usable DMA addressing method\n");
		result = -EIO;
		goto err_release_res;
	}

	/* Allocate netdev and private adapter structs */
	netdev = et131x_device_alloc();
	if (!netdev) {
		dev_err(&pdev->dev, "Couldn't alloc netdev struct\n");
		result = -ENOMEM;
		goto err_release_res;
	}

	SET_NETDEV_DEV(netdev, &pdev->dev);
	et131x_set_ethtool_ops(netdev);

	adapter = et131x_adapter_init(netdev, pdev);

	/* Initialise the PCI setup for the device */
	et131x_pci_init(adapter, pdev);

	/* Map the bus-relative registers to system virtual memory */
	adapter->regs = pci_ioremap_bar(pdev, 0);
	if (!adapter->regs) {
		dev_err(&pdev->dev, "Cannot map device registers\n");
		result = -ENOMEM;
		goto err_free_dev;
	}

	/* If Phy COMA mode was enabled when we went down, disable it here. */
	writel(ET_PMCSR_INIT,  &adapter->regs->global.pm_csr);

	/* Issue a global reset to the et1310 */
	et131x_soft_reset(adapter);

	/* Disable all interrupts (paranoid) */
	et131x_disable_interrupts(adapter);

	/* Allocate DMA memory */
	result = et131x_adapter_memory_alloc(adapter);
	if (result) {
		dev_err(&pdev->dev, "Could not alloc adapater memory (DMA)\n");
		goto err_iounmap;
	}

	/* Init send data structures */
	et131x_init_send(adapter);

	/* Set up the task structure for the ISR's deferred handler */
	INIT_WORK(&adapter->task, et131x_isr_handler);

	/* Copy address into the net_device struct */
	memcpy(netdev->dev_addr, adapter->addr, ETH_ALEN);

	adapter->error_timer.expires = jiffies + TX_ERROR_PERIOD * HZ / 1000;
	adapter->error_timer.function = et131x_error_timer_handler;
	adapter->error_timer.data = (unsigned long)adapter;

	/* Init variable for counting how long we do not have link status */
	adapter->boot_coma = 0;
	et1310_disable_phy_coma(adapter);

	/* Setup the mii_bus struct */
	adapter->mii_bus = mdiobus_alloc();
	if (!adapter->mii_bus) {
		dev_err(&pdev->dev, "Alloc of mii_bus struct failed\n");
		goto err_mem_free;
	}

	adapter->mii_bus->name = "et131x_eth_mii";
	snprintf(adapter->mii_bus->id, MII_BUS_ID_SIZE, "%x",
		(adapter->pdev->bus->number << 8) | adapter->pdev->devfn);
	adapter->mii_bus->priv = netdev;
	adapter->mii_bus->read = et131x_mdio_read;
	adapter->mii_bus->write = et131x_mdio_write;
	adapter->mii_bus->reset = et131x_mdio_reset;
	adapter->mii_bus->irq = kmalloc(sizeof(int)*PHY_MAX_ADDR, GFP_KERNEL);
	if (!adapter->mii_bus->irq) {
		dev_err(&pdev->dev, "mii_bus irq allocation failed\n");
		goto err_mdio_free;
	}

	for (ii = 0; ii < PHY_MAX_ADDR; ii++)
		adapter->mii_bus->irq[ii] = PHY_POLL;

	if (mdiobus_register(adapter->mii_bus)) {
		dev_err(&pdev->dev, "failed to register MII bus\n");
		mdiobus_free(adapter->mii_bus);
		goto err_mdio_free_irq;
	}

	if (et131x_mii_probe(netdev)) {
		dev_err(&pdev->dev, "failed to probe MII bus\n");
		goto err_mdio_unregister;
	}

	/* Setup et1310 as per the documentation */
	et131x_adapter_setup(adapter);

	/* Create a timer to count errors received by the NIC */
	init_timer(&adapter->error_timer);

	/* We can enable interrupts now
	 *
	 *  NOTE - Because registration of interrupt handler is done in the
	 *         device's open(), defer enabling device interrupts to that
	 *         point
	 */

	/* Register the net_device struct with the Linux network layer */
	result = register_netdev(netdev);
	if (result != 0) {
		dev_err(&pdev->dev, "register_netdev() failed\n");
		goto err_mdio_unregister;
	}

	/* Register the net_device struct with the PCI subsystem. Save a copy
	 * of the PCI config space for this device now that the device has
	 * been initialized, just in case it needs to be quickly restored.
	 */
	pci_set_drvdata(pdev, netdev);
	pci_save_state(adapter->pdev);

	return result;

err_mdio_unregister:
	mdiobus_unregister(adapter->mii_bus);
err_mdio_free_irq:
	kfree(adapter->mii_bus->irq);
err_mdio_free:
	mdiobus_free(adapter->mii_bus);
err_mem_free:
	et131x_adapter_memory_free(adapter);
err_iounmap:
	iounmap(adapter->regs);
err_free_dev:
	pci_dev_put(pdev);
	free_netdev(netdev);
err_release_res:
	pci_release_regions(pdev);
err_disable:
	pci_disable_device(pdev);
err_out:
	return result;
}

/**
 * et131x_pci_remove
 * @pdev: a pointer to the device's pci_dev structure
 *
 * Registered in the pci_driver structure, this function is called when the
 * PCI subsystem detects that a PCI device which matches the information
 * contained in the pci_device_id table has been removed.
 */
static void __devexit et131x_pci_remove(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct et131x_adapter *adapter = netdev_priv(netdev);

	unregister_netdev(netdev);
	mdiobus_unregister(adapter->mii_bus);
	kfree(adapter->mii_bus->irq);
	mdiobus_free(adapter->mii_bus);

	et131x_adapter_memory_free(adapter);
	iounmap(adapter->regs);
	pci_dev_put(pdev);

	free_netdev(netdev);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
}

static struct pci_device_id et131x_pci_table[] __devinitdata = {
	{ET131X_PCI_VENDOR_ID, ET131X_PCI_DEVICE_ID_GIG, PCI_ANY_ID,
	 PCI_ANY_ID, 0, 0, 0UL},
	{ET131X_PCI_VENDOR_ID, ET131X_PCI_DEVICE_ID_FAST, PCI_ANY_ID,
	 PCI_ANY_ID, 0, 0, 0UL},
	{0,}
};

MODULE_DEVICE_TABLE(pci, et131x_pci_table);

static struct pci_driver et131x_driver = {
	.name		= DRIVER_NAME,
	.id_table	= et131x_pci_table,
	.probe		= et131x_pci_setup,
	.remove		= __devexit_p(et131x_pci_remove),
	.suspend	= NULL,		/* et131x_pci_suspend */
	.resume		= NULL,		/* et131x_pci_resume */
};

/**
 * et131x_init_module - The "main" entry point called on driver initialization
 *
 * Returns 0 on success, errno on failure (as defined in errno.h)
 */
static int __init et131x_init_module(void)
{
	return pci_register_driver(&et131x_driver);
}

/**
 * et131x_cleanup_module - The entry point called on driver cleanup
 */
static void __exit et131x_cleanup_module(void)
{
	pci_unregister_driver(&et131x_driver);
}

module_init(et131x_init_module);
module_exit(et131x_cleanup_module);

/* Modinfo parameters (filled out using defines from et131x_version.h) */
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_INFO);
MODULE_LICENSE(DRIVER_LICENSE);
