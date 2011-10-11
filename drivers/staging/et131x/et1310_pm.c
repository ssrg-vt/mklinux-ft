/*
 * Agere Systems Inc.
 * 10/100/1000 Base-T Ethernet Driver for the ET1301 and ET131x series MACs
 *
 * Copyright © 2005 Agere Systems Inc.
 * All rights reserved.
 *   http://www.agere.com
 *
 * Copyright (c) 2011 Mark Einon <mark.einon@gmail.com>
 *
 *------------------------------------------------------------------------------
 *
 * et1310_pm.c - All power management related code (not completely implemented)
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

#include "et131x_defs.h"

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
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/ioport.h>

#include "et1310_phy.h"
#include "et1310_rx.h"
#include "et131x_adapter.h"
#include "et131x.h"

/**
 * et1310_in_phy_coma - check if the device is in phy coma
 * @adapter: pointer to our adapter structure
 *
 * Returns 0 if the device is not in phy coma, 1 if it is in phy coma
 */
int et1310_in_phy_coma(struct et131x_adapter *adapter)
{
	u32 pmcsr;

	pmcsr = readl(&adapter->regs->global.pm_csr);

	return ET_PM_PHY_SW_COMA & pmcsr ? 1 : 0;
}

/**
 * et1310_enable_phy_coma - called when network cable is unplugged
 * @adapter: pointer to our adapter structure
 *
 * driver receive an phy status change interrupt while in D0 and check that
 * phy_status is down.
 *
 *          -- gate off JAGCore;
 *          -- set gigE PHY in Coma mode
 *          -- wake on phy_interrupt; Perform software reset JAGCore,
 *             re-initialize jagcore and gigE PHY
 *
 *      Add D0-ASPM-PhyLinkDown Support:
 *          -- while in D0, when there is a phy_interrupt indicating phy link
 *             down status, call the MPSetPhyComa routine to enter this active
 *             state power saving mode
 *          -- while in D0-ASPM-PhyLinkDown mode, when there is a phy_interrupt
 *       indicating linkup status, call the MPDisablePhyComa routine to
 *             restore JAGCore and gigE PHY
 */
void et1310_enable_phy_coma(struct et131x_adapter *adapter)
{
	unsigned long flags;
	u32 pmcsr;

	pmcsr = readl(&adapter->regs->global.pm_csr);

	/* Save the GbE PHY speed and duplex modes. Need to restore this
	 * when cable is plugged back in
	 */
	/*
	 * TODO - when PM is re-enabled, check if we need to
	 * perform a similar task as this -
	 * adapter->pdown_speed = adapter->ai_force_speed;
	 * adapter->pdown_duplex = adapter->ai_force_duplex;
	 */

	/* Stop sending packets. */
	spin_lock_irqsave(&adapter->send_hw_lock, flags);
	adapter->flags |= fMP_ADAPTER_LOWER_POWER;
	spin_unlock_irqrestore(&adapter->send_hw_lock, flags);

	/* Wait for outstanding Receive packets */

	et131x_disable_txrx(adapter->netdev);

	/* Gate off JAGCore 3 clock domains */
	pmcsr &= ~ET_PMCSR_INIT;
	writel(pmcsr, &adapter->regs->global.pm_csr);

	/* Program gigE PHY in to Coma mode */
	pmcsr |= ET_PM_PHY_SW_COMA;
	writel(pmcsr, &adapter->regs->global.pm_csr);
}

/**
 * et1310_disable_phy_coma - Disable the Phy Coma Mode
 * @adapter: pointer to our adapter structure
 */
void et1310_disable_phy_coma(struct et131x_adapter *adapter)
{
	u32 pmcsr;

	pmcsr = readl(&adapter->regs->global.pm_csr);

	/* Disable phy_sw_coma register and re-enable JAGCore clocks */
	pmcsr |= ET_PMCSR_INIT;
	pmcsr &= ~ET_PM_PHY_SW_COMA;
	writel(pmcsr, &adapter->regs->global.pm_csr);

	/* Restore the GbE PHY speed and duplex modes;
	 * Reset JAGCore; re-configure and initialize JAGCore and gigE PHY
	 */
	/* TODO - when PM is re-enabled, check if we need to
	 * perform a similar task as this -
	 * adapter->ai_force_speed = adapter->pdown_speed;
	 * adapter->ai_force_duplex = adapter->pdown_duplex;
	 */

	/* Re-initialize the send structures */
	et131x_init_send(adapter);

	/* Reset the RFD list and re-start RU  */
	et131x_reset_recv(adapter);

	/* Bring the device back to the state it was during init prior to
	 * autonegotiation being complete.  This way, when we get the auto-neg
	 * complete interrupt, we can complete init by calling ConfigMacREGS2.
	 */
	et131x_soft_reset(adapter);

	/* setup et1310 as per the documentation ?? */
	et131x_adapter_setup(adapter);

	/* Allow Tx to restart */
	adapter->flags &= ~fMP_ADAPTER_LOWER_POWER;

	et131x_enable_txrx(adapter->netdev);
}

