/*
 *
 *  $Id$
 *
 *  Copyright (C) 2005 Mike Isely <isely@pobox.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#ifndef __PVRUSB2_DEVATTR_H
#define __PVRUSB2_DEVATTR_H

#include <linux/mod_devicetable.h>

/*

  This header defines structures used to describe attributes of a device.

*/


struct pvr2_string_table {
	const char **lst;
	unsigned int cnt;
};


/* This describes a particular hardware type (except for the USB device ID
   which must live in a separate structure due to environmental
   constraints).  See the top of pvrusb2-hdw.c for where this is
   instantiated. */
struct pvr2_device_desc {
	/* Single line text description of hardware */
	const char *description;

	/* Single token identifier for hardware */
	const char *shortname;

	/* List of additional client modules we need to load */
	struct pvr2_string_table client_modules;

	/* List of FX2 firmware file names we should search; if empty then
	   FX2 firmware check / load is skipped and we assume the device
	   was initialized from internal ROM. */
	struct pvr2_string_table fx2_firmware;

	/* If set, we don't bother trying to load cx23416 firmware. */
	char flag_skip_cx23416_firmware;

	/* Device does not require a powerup command to be issued. */
	char flag_no_powerup;

	/* Device has a cx25840 - this enables special additional logic to
	   handle it. */
	char flag_has_cx25840;

	/* Device has a wm8775 - this enables special additional logic to
	   ensure that it is found. */
	char flag_has_wm8775;
};

extern const struct pvr2_device_desc pvr2_device_descriptions[];
extern struct usb_device_id pvr2_device_table[];
extern const unsigned int pvr2_device_count;

#endif /* __PVRUSB2_HDW_INTERNAL_H */

/*
  Stuff for Emacs to see, in order to encourage consistent editing style:
  *** Local Variables: ***
  *** mode: c ***
  *** fill-column: 75 ***
  *** tab-width: 8 ***
  *** c-basic-offset: 8 ***
  *** End: ***
  */
