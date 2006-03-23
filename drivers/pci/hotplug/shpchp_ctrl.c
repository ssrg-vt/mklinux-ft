/*
 * Standard Hot Plug Controller Driver
 *
 * Copyright (C) 1995,2001 Compaq Computer Corporation
 * Copyright (C) 2001 Greg Kroah-Hartman (greg@kroah.com)
 * Copyright (C) 2001 IBM Corp.
 * Copyright (C) 2003-2004 Intel Corporation
 *
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 * NON INFRINGEMENT.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Send feedback to <greg@kroah.com>, <kristen.c.accardi@intel.com>
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/smp_lock.h>
#include <linux/pci.h>
#include <linux/workqueue.h>
#include "../pci.h"
#include "shpchp.h"

static void interrupt_event_handler(void *data);

static int queue_interrupt_event(struct slot *p_slot, u32 event_type)
{
	struct event_info *info;

	info = kmalloc(sizeof(*info), GFP_ATOMIC);
	if (!info)
		return -ENOMEM;

	info->event_type = event_type;
	info->p_slot = p_slot;
	INIT_WORK(&info->work, interrupt_event_handler, info);

	queue_work(shpchp_wq, &info->work);

	return 0;
}

u8 shpchp_handle_attention_button(u8 hp_slot, void *inst_id)
{
	struct controller *ctrl = (struct controller *) inst_id;
	struct slot *p_slot;
	u32 event_type;

	/* Attention Button Change */
	dbg("shpchp:  Attention button interrupt received.\n");
	
	p_slot = shpchp_find_slot(ctrl, hp_slot + ctrl->slot_device_offset);
	p_slot->hpc_ops->get_adapter_status(p_slot, &(p_slot->presence_save));

	/*
	 *  Button pressed - See if need to TAKE ACTION!!!
	 */
	info("Button pressed on Slot(%d)\n", ctrl->first_slot + hp_slot);
	event_type = INT_BUTTON_PRESS;

	if ((p_slot->state == BLINKINGON_STATE)
	    || (p_slot->state == BLINKINGOFF_STATE)) {
		/* Cancel if we are still blinking; this means that we press the
		 * attention again before the 5 sec. limit expires to cancel hot-add
		 * or hot-remove
		 */
		event_type = INT_BUTTON_CANCEL;
		info("Button cancel on Slot(%d)\n", ctrl->first_slot + hp_slot);
	} else if ((p_slot->state == POWERON_STATE)
		   || (p_slot->state == POWEROFF_STATE)) {
		/* Ignore if the slot is on power-on or power-off state; this 
		 * means that the previous attention button action to hot-add or
		 * hot-remove is undergoing
		 */
		event_type = INT_BUTTON_IGNORE;
		info("Button ignore on Slot(%d)\n", ctrl->first_slot + hp_slot);
	}

	queue_interrupt_event(p_slot, event_type);

	return 0;

}

u8 shpchp_handle_switch_change(u8 hp_slot, void *inst_id)
{
	struct controller *ctrl = (struct controller *) inst_id;
	struct slot *p_slot;
	u8 getstatus;
	u32 event_type;

	/* Switch Change */
	dbg("shpchp:  Switch interrupt received.\n");

	p_slot = shpchp_find_slot(ctrl, hp_slot + ctrl->slot_device_offset);
	p_slot->hpc_ops->get_adapter_status(p_slot, &(p_slot->presence_save));
	p_slot->hpc_ops->get_latch_status(p_slot, &getstatus);
	dbg("%s: Card present %x Power status %x\n", __FUNCTION__,
		p_slot->presence_save, p_slot->pwr_save);

	if (getstatus) {
		/*
		 * Switch opened
		 */
		info("Latch open on Slot(%d)\n", ctrl->first_slot + hp_slot);
		event_type = INT_SWITCH_OPEN;
		if (p_slot->pwr_save && p_slot->presence_save) {
			event_type = INT_POWER_FAULT;
			err("Surprise Removal of card\n");
		}
	} else {
		/*
		 *  Switch closed
		 */
		info("Latch close on Slot(%d)\n", ctrl->first_slot + hp_slot);
		event_type = INT_SWITCH_CLOSE;
	}

	queue_interrupt_event(p_slot, event_type);

	return 1;
}

u8 shpchp_handle_presence_change(u8 hp_slot, void *inst_id)
{
	struct controller *ctrl = (struct controller *) inst_id;
	struct slot *p_slot;
	u32 event_type;

	/* Presence Change */
	dbg("shpchp:  Presence/Notify input change.\n");

	p_slot = shpchp_find_slot(ctrl, hp_slot + ctrl->slot_device_offset);

	/* 
	 * Save the presence state
	 */
	p_slot->hpc_ops->get_adapter_status(p_slot, &(p_slot->presence_save));
	if (p_slot->presence_save) {
		/*
		 * Card Present
		 */
		info("Card present on Slot(%d)\n", ctrl->first_slot + hp_slot);
		event_type = INT_PRESENCE_ON;
	} else {
		/*
		 * Not Present
		 */
		info("Card not present on Slot(%d)\n", ctrl->first_slot + hp_slot);
		event_type = INT_PRESENCE_OFF;
	}

	queue_interrupt_event(p_slot, event_type);

	return 1;
}

u8 shpchp_handle_power_fault(u8 hp_slot, void *inst_id)
{
	struct controller *ctrl = (struct controller *) inst_id;
	struct slot *p_slot;
	u32 event_type;

	/* Power fault */
	dbg("shpchp:  Power fault interrupt received.\n");

	p_slot = shpchp_find_slot(ctrl, hp_slot + ctrl->slot_device_offset);

	if ( !(p_slot->hpc_ops->query_power_fault(p_slot))) {
		/*
		 * Power fault Cleared
		 */
		info("Power fault cleared on Slot(%d)\n", ctrl->first_slot + hp_slot);
		p_slot->status = 0x00;
		event_type = INT_POWER_FAULT_CLEAR;
	} else {
		/*
		 *   Power fault
		 */
		info("Power fault on Slot(%d)\n", ctrl->first_slot + hp_slot);
		event_type = INT_POWER_FAULT;
		/* set power fault status for this board */
		p_slot->status = 0xFF;
		info("power fault bit %x set\n", hp_slot);
	}

	queue_interrupt_event(p_slot, event_type);

	return 1;
}

/* The following routines constitute the bulk of the 
   hotplug controller logic
 */
static int change_bus_speed(struct controller *ctrl, struct slot *p_slot,
		enum pci_bus_speed speed)
{ 
	int rc = 0;

	dbg("%s: change to speed %d\n", __FUNCTION__, speed);
	if ((rc = p_slot->hpc_ops->set_bus_speed_mode(p_slot, speed))) {
		err("%s: Issue of set bus speed mode command failed\n", __FUNCTION__);
		return WRONG_BUS_FREQUENCY;
	}
	return rc;
}

static int fix_bus_speed(struct controller *ctrl, struct slot *pslot,
		u8 flag, enum pci_bus_speed asp, enum pci_bus_speed bsp,
		enum pci_bus_speed msp)
{ 
	int rc = 0;
	
	if (flag != 0) { /* Other slots on the same bus are occupied */
		if ( asp < bsp ) {
			err("%s: speed of bus %x and adapter %x mismatch\n", __FUNCTION__, bsp, asp);
			return WRONG_BUS_FREQUENCY;
		}
	} else {
		/* Other slots on the same bus are empty */
		if (msp == bsp) {
		/* if adapter_speed >= bus_speed, do nothing */
			if (asp < bsp) {
				/* 
				* Try to lower bus speed to accommodate the adapter if other slots 
				* on the same controller are empty
				*/
				if ((rc = change_bus_speed(ctrl, pslot, asp)))
					return rc;
			} 
		} else {
			if (asp < msp) {
				if ((rc = change_bus_speed(ctrl, pslot, asp)))
					return rc;
			} else {
				if ((rc = change_bus_speed(ctrl, pslot, msp)))
					return rc;
			}
		}
	}
	return rc;
}

/**
 * board_added - Called after a board has been added to the system.
 *
 * Turns power on for the board
 * Configures board
 *
 */
static int board_added(struct slot *p_slot)
{
	u8 hp_slot;
	u8 slots_not_empty = 0;
	int rc = 0;
	enum pci_bus_speed adapter_speed, bus_speed, max_bus_speed;
	u8 pi, mode;
	struct controller *ctrl = p_slot->ctrl;

	hp_slot = p_slot->device - ctrl->slot_device_offset;

	dbg("%s: p_slot->device, slot_offset, hp_slot = %d, %d ,%d\n",
			__FUNCTION__, p_slot->device,
			ctrl->slot_device_offset, hp_slot);

	/* Power on slot without connecting to bus */
	rc = p_slot->hpc_ops->power_on_slot(p_slot);
	if (rc) {
		err("%s: Failed to power on slot\n", __FUNCTION__);
		return -1;
	}
	
	if ((ctrl->pci_dev->vendor == 0x8086) && (ctrl->pci_dev->device == 0x0332)) {
		if (slots_not_empty)
			return WRONG_BUS_FREQUENCY;
		
		if ((rc = p_slot->hpc_ops->set_bus_speed_mode(p_slot, PCI_SPEED_33MHz))) {
			err("%s: Issue of set bus speed mode command failed\n", __FUNCTION__);
			return WRONG_BUS_FREQUENCY;
		}
		
		/* turn on board, blink green LED, turn off Amber LED */
		if ((rc = p_slot->hpc_ops->slot_enable(p_slot))) {
			err("%s: Issue of Slot Enable command failed\n", __FUNCTION__);
			return rc;
		}
	}
 
	rc = p_slot->hpc_ops->get_adapter_speed(p_slot, &adapter_speed);
	/* 0 = PCI 33Mhz, 1 = PCI 66 Mhz, 2 = PCI-X 66 PA, 4 = PCI-X 66 ECC, */
	/* 5 = PCI-X 133 PA, 7 = PCI-X 133 ECC,  0xa = PCI-X 133 Mhz 266, */
	/* 0xd = PCI-X 133 Mhz 533 */
	/* This encoding is different from the one used in cur_bus_speed & */
	/* max_bus_speed */

	if (rc  || adapter_speed == PCI_SPEED_UNKNOWN) {
		err("%s: Can't get adapter speed or bus mode mismatch\n", __FUNCTION__);
		return WRONG_BUS_FREQUENCY;
	}

	rc = p_slot->hpc_ops->get_cur_bus_speed(p_slot, &bus_speed);
	if (rc || bus_speed == PCI_SPEED_UNKNOWN) {
		err("%s: Can't get bus operation speed\n", __FUNCTION__);
		return WRONG_BUS_FREQUENCY;
	}

	rc = p_slot->hpc_ops->get_max_bus_speed(p_slot, &max_bus_speed);
	if (rc || max_bus_speed == PCI_SPEED_UNKNOWN) {
		err("%s: Can't get max bus operation speed\n", __FUNCTION__);
		max_bus_speed = bus_speed;
	}

	if ((rc  = p_slot->hpc_ops->get_prog_int(p_slot, &pi))) {
		err("%s: Can't get controller programming interface, set it to 1\n", __FUNCTION__);
		pi = 1;
	}

	/* Check if there are other slots or devices on the same bus */
	if (!list_empty(&ctrl->pci_dev->subordinate->devices))
		slots_not_empty = 1;

	dbg("%s: slots_not_empty %d, pi %d\n", __FUNCTION__, 
		slots_not_empty, pi);
	dbg("adapter_speed %d, bus_speed %d, max_bus_speed %d\n", 
		adapter_speed, bus_speed, max_bus_speed);

	if (pi == 2) {
		dbg("%s: In PI = %d\n", __FUNCTION__, pi);
		if ((rc = p_slot->hpc_ops->get_mode1_ECC_cap(p_slot, &mode))) {
			err("%s: Can't get Mode1_ECC, set mode to 0\n", __FUNCTION__);
			mode = 0;
		}

		switch (adapter_speed) {
		case PCI_SPEED_133MHz_PCIX_533:
		case PCI_SPEED_133MHz_PCIX_266:
			if ((bus_speed != adapter_speed) &&
			   ((rc = fix_bus_speed(ctrl, p_slot, slots_not_empty, adapter_speed, bus_speed, max_bus_speed)))) 
				return rc;
			break;	
		case PCI_SPEED_133MHz_PCIX_ECC:
		case PCI_SPEED_133MHz_PCIX:
			if (mode) { /* Bus - Mode 1 ECC */
				if ((bus_speed != 0x7) &&
				   ((rc = fix_bus_speed(ctrl, p_slot, slots_not_empty, adapter_speed, bus_speed, max_bus_speed)))) 
					return rc;
			} else {
				if ((bus_speed != 0x4) &&
				   ((rc = fix_bus_speed(ctrl, p_slot, slots_not_empty, adapter_speed, bus_speed, max_bus_speed)))) 
					return rc;
			}
			break;
		case PCI_SPEED_66MHz_PCIX_ECC:
		case PCI_SPEED_66MHz_PCIX:
			if (mode) { /* Bus - Mode 1 ECC */
				if ((bus_speed != 0x5) &&
				   ((rc = fix_bus_speed(ctrl, p_slot, slots_not_empty, adapter_speed, bus_speed, max_bus_speed)))) 
					return rc;
			} else {
				if ((bus_speed != 0x2) &&
				   ((rc = fix_bus_speed(ctrl, p_slot, slots_not_empty, adapter_speed, bus_speed, max_bus_speed)))) 
					return rc;
			}
			break;
		case PCI_SPEED_66MHz:
			if ((bus_speed != 0x1) &&
			   ((rc = fix_bus_speed(ctrl, p_slot, slots_not_empty, adapter_speed, bus_speed, max_bus_speed)))) 
				return rc;
			break;	
		case PCI_SPEED_33MHz:
			if (bus_speed > 0x0) {
				if (slots_not_empty == 0) {
					if ((rc = change_bus_speed(ctrl, p_slot, adapter_speed)))
						return rc;
				} else {
					err("%s: speed of bus %x and adapter %x mismatch\n", __FUNCTION__, bus_speed, adapter_speed);
					return WRONG_BUS_FREQUENCY;
				}
			}
			break;
		default:
			err("%s: speed of bus %x and adapter %x mismatch\n", __FUNCTION__, bus_speed, adapter_speed);
			return WRONG_BUS_FREQUENCY;
		}
	} else {
		/* If adpater_speed == bus_speed, nothing to do here */
		dbg("%s: In PI = %d\n", __FUNCTION__, pi);
		if ((adapter_speed != bus_speed) &&
		   ((rc = fix_bus_speed(ctrl, p_slot, slots_not_empty, adapter_speed, bus_speed, max_bus_speed))))
				return rc;
	}

	/* turn on board, blink green LED, turn off Amber LED */
	if ((rc = p_slot->hpc_ops->slot_enable(p_slot))) {
		err("%s: Issue of Slot Enable command failed\n", __FUNCTION__);
		return rc;
	}

	/* Wait for ~1 second */
	msleep(1000);

	dbg("%s: slot status = %x\n", __FUNCTION__, p_slot->status);
	/* Check for a power fault */
	if (p_slot->status == 0xFF) {
		/* power fault occurred, but it was benign */
		dbg("%s: power fault\n", __FUNCTION__);
		rc = POWER_FAILURE;
		p_slot->status = 0;
		goto err_exit;
	}

	if (shpchp_configure_device(p_slot)) {
		err("Cannot add device at 0x%x:0x%x\n", p_slot->bus,
				p_slot->device);
		goto err_exit;
	}

	p_slot->status = 0;
	p_slot->is_a_board = 0x01;
	p_slot->pwr_save = 1;

	p_slot->hpc_ops->green_led_on(p_slot);

	return 0;

err_exit:
	/* turn off slot, turn on Amber LED, turn off Green LED */
	rc = p_slot->hpc_ops->slot_disable(p_slot);
	if (rc) {
		err("%s: Issue of Slot Disable command failed\n", __FUNCTION__);
		return rc;
	}

	return(rc);
}


/**
 * remove_board - Turns off slot and LED's
 *
 */
static int remove_board(struct slot *p_slot)
{
	struct controller *ctrl = p_slot->ctrl;
	u8 hp_slot;
	int rc;

	if (shpchp_unconfigure_device(p_slot))
		return(1);

	hp_slot = p_slot->device - ctrl->slot_device_offset;
	p_slot = shpchp_find_slot(ctrl, hp_slot + ctrl->slot_device_offset);

	dbg("In %s, hp_slot = %d\n", __FUNCTION__, hp_slot);

	/* Change status to shutdown */
	if (p_slot->is_a_board)
		p_slot->status = 0x01;

	/* turn off slot, turn on Amber LED, turn off Green LED */
	rc = p_slot->hpc_ops->slot_disable(p_slot);
	if (rc) {
		err("%s: Issue of Slot Disable command failed\n", __FUNCTION__);
		return rc;
	}
	
	rc = p_slot->hpc_ops->set_attention_status(p_slot, 0);
	if (rc) {
		err("%s: Issue of Set Attention command failed\n", __FUNCTION__);
		return rc;
	}

	p_slot->pwr_save = 0;
	p_slot->is_a_board = 0;

	return 0;
}


/**
 * shpchp_pushbutton_thread
 *
 * Scheduled procedure to handle blocking stuff for the pushbuttons
 * Handles all pending events and exits.
 *
 */
void shpchp_pushbutton_thread(void *data)
{
	struct slot *p_slot = data;
	u8 getstatus;

	p_slot->hpc_ops->get_power_status(p_slot, &getstatus);
	if (getstatus) {
		p_slot->state = POWEROFF_STATE;
		shpchp_disable_slot(p_slot);
		p_slot->state = STATIC_STATE;
	} else {
		p_slot->state = POWERON_STATE;
		if (shpchp_enable_slot(p_slot))
			p_slot->hpc_ops->green_led_off(p_slot);
		p_slot->state = STATIC_STATE;
	}
}

static int update_slot_info (struct slot *slot)
{
	struct hotplug_slot_info *info;
	int result;

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	slot->hpc_ops->get_power_status(slot, &(info->power_status));
	slot->hpc_ops->get_attention_status(slot, &(info->attention_status));
	slot->hpc_ops->get_latch_status(slot, &(info->latch_status));
	slot->hpc_ops->get_adapter_status(slot, &(info->adapter_status));

	result = pci_hp_change_slot_info(slot->hotplug_slot, info);
	kfree (info);
	return result;
}

static void interrupt_event_handler(void *data)
{
	struct event_info *info = data;
	struct slot *p_slot = info->p_slot;
	u8 getstatus;

	switch (info->event_type) {
	case INT_BUTTON_CANCEL:
		dbg("%s: button cancel\n", __FUNCTION__);
		cancel_delayed_work(&p_slot->work);
		switch (p_slot->state) {
		case BLINKINGOFF_STATE:
			p_slot->hpc_ops->green_led_on(p_slot);
			p_slot->hpc_ops->set_attention_status(p_slot, 0);
			break;
		case BLINKINGON_STATE:
			p_slot->hpc_ops->green_led_off(p_slot);
			p_slot->hpc_ops->set_attention_status(p_slot, 0);
			break;
		default:
			warn("Not a valid state\n");
			return;
		}
		info(msg_button_cancel, p_slot->number);
		p_slot->state = STATIC_STATE;
		break;
	case INT_BUTTON_PRESS:
		dbg("%s: Button pressed\n", __FUNCTION__);
		p_slot->hpc_ops->get_power_status(p_slot, &getstatus);
		if (getstatus) {
			p_slot->state = BLINKINGOFF_STATE;
			info(msg_button_off, p_slot->number);
		} else {
			p_slot->state = BLINKINGON_STATE;
			info(msg_button_on, p_slot->number);
		}
		/* blink green LED and turn off amber */
		p_slot->hpc_ops->green_led_blink(p_slot);
		p_slot->hpc_ops->set_attention_status(p_slot, 0);

		queue_delayed_work(shpchp_wq, &p_slot->work, 5*HZ);
		break;
	case INT_POWER_FAULT:
		dbg("%s: power fault\n", __FUNCTION__);
		p_slot->hpc_ops->set_attention_status(p_slot, 1);
		p_slot->hpc_ops->green_led_off(p_slot);
		break;
	default:
		update_slot_info(p_slot);
		break;
	}

	kfree(info);
}


int shpchp_enable_slot (struct slot *p_slot)
{
	u8 getstatus = 0;
	int rc, retval = -ENODEV;

	/* Check to see if (latch closed, card present, power off) */
	mutex_lock(&p_slot->ctrl->crit_sect);
	rc = p_slot->hpc_ops->get_adapter_status(p_slot, &getstatus);
	if (rc || !getstatus) {
		info("%s: no adapter on slot(%x)\n", __FUNCTION__, p_slot->number);
		goto out;
	}
	rc = p_slot->hpc_ops->get_latch_status(p_slot, &getstatus);
	if (rc || getstatus) {
		info("%s: latch open on slot(%x)\n", __FUNCTION__, p_slot->number);
		goto out;
	}
	rc = p_slot->hpc_ops->get_power_status(p_slot, &getstatus);
	if (rc || getstatus) {
		info("%s: already enabled on slot(%x)\n", __FUNCTION__, p_slot->number);
		goto out;
	}

	p_slot->is_a_board = 1;

	/* We have to save the presence info for these slots */
	p_slot->hpc_ops->get_adapter_status(p_slot, &(p_slot->presence_save));
	p_slot->hpc_ops->get_power_status(p_slot, &(p_slot->pwr_save));
	dbg("%s: p_slot->pwr_save %x\n", __FUNCTION__, p_slot->pwr_save);
	p_slot->hpc_ops->get_latch_status(p_slot, &getstatus);

	if(((p_slot->ctrl->pci_dev->vendor == PCI_VENDOR_ID_AMD) ||
	    (p_slot->ctrl->pci_dev->device == PCI_DEVICE_ID_AMD_POGO_7458))
	     && p_slot->ctrl->num_slots == 1) {
		/* handle amd pogo errata; this must be done before enable  */
		amd_pogo_errata_save_misc_reg(p_slot);
		retval = board_added(p_slot);
		/* handle amd pogo errata; this must be done after enable  */
		amd_pogo_errata_restore_misc_reg(p_slot);
	} else
		retval = board_added(p_slot);

	if (retval) {
		p_slot->hpc_ops->get_adapter_status(p_slot,
				&(p_slot->presence_save));
		p_slot->hpc_ops->get_latch_status(p_slot, &getstatus);
	}

	update_slot_info(p_slot);
 out:
	mutex_unlock(&p_slot->ctrl->crit_sect);
	return retval;
}


int shpchp_disable_slot (struct slot *p_slot)
{
	u8 getstatus = 0;
	int rc, retval = -ENODEV;

	if (!p_slot->ctrl)
		return -ENODEV;

	/* Check to see if (latch closed, card present, power on) */
	mutex_lock(&p_slot->ctrl->crit_sect);

	rc = p_slot->hpc_ops->get_adapter_status(p_slot, &getstatus);
	if (rc || !getstatus) {
		info("%s: no adapter on slot(%x)\n", __FUNCTION__, p_slot->number);
		goto out;
	}
	rc = p_slot->hpc_ops->get_latch_status(p_slot, &getstatus);
	if (rc || getstatus) {
		info("%s: latch open on slot(%x)\n", __FUNCTION__, p_slot->number);
		goto out;
	}
	rc = p_slot->hpc_ops->get_power_status(p_slot, &getstatus);
	if (rc || !getstatus) {
		info("%s: already disabled slot(%x)\n", __FUNCTION__, p_slot->number);
		goto out;
	}

	retval = remove_board(p_slot);
	update_slot_info(p_slot);
 out:
	mutex_unlock(&p_slot->ctrl->crit_sect);
	return retval;
}

