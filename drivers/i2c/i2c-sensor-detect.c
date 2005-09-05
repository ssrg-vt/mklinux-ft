/*
    i2c-sensor-detect.c - Part of lm_sensors, Linux kernel modules for hardware
            		  monitoring
    Copyright (c) 1998 - 2001 Frodo Looijaard <frodol@dds.nl> and
    Mark D. Studebaker <mdsxyz123@yahoo.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/i2c.h>
#include <linux/i2c-sensor.h>

static unsigned short empty[] = {I2C_CLIENT_END};

/* Won't work for 10-bit addresses! */
int i2c_detect(struct i2c_adapter *adapter,
	       struct i2c_address_data *address_data,
	       int (*found_proc) (struct i2c_adapter *, int, int))
{
	int addr, i, found, j, err;
	int adapter_id = i2c_adapter_id(adapter);
	unsigned short *normal_i2c;
	unsigned short *probe;
	unsigned short *ignore;

	/* Forget it if we can't probe using SMBUS_QUICK */
	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_QUICK))
		return -1;
	
	/* Use default "empty" list if the adapter doesn't specify any */
	normal_i2c = probe = ignore = empty;
	if (address_data->normal_i2c)
		normal_i2c = address_data->normal_i2c;
	if (address_data->probe)
		probe = address_data->probe;
	if (address_data->ignore)
		ignore = address_data->ignore;

	for (addr = 0x00; addr <= 0x7f; addr++) {
		if (i2c_check_addr(adapter, addr))
			continue;

		/* If it is in one of the force entries, we don't do any
		   detection at all */
		found = 0;
		for (i = 0; address_data->forces[i]; i++) {
			for (j = 0; !found && (address_data->forces[i][j] != I2C_CLIENT_END); j += 2) {
				if ( ((adapter_id == address_data->forces[i][j]) ||
				      (address_data->forces[i][j] == ANY_I2C_BUS)) &&
				      (addr == address_data->forces[i][j + 1]) ) {
					dev_dbg(&adapter->dev, "found force parameter for adapter %d, addr %04x\n", adapter_id, addr);
					if ((err = found_proc(adapter, addr, i)))
						return err;
					found = 1;
				}
			}
		}
		if (found)
			continue;

		/* If this address is in one of the ignores, we can forget about it
		   right now */
		for (i = 0; !found && (ignore[i] != I2C_CLIENT_END); i += 2) {
			if ( ((adapter_id == ignore[i]) ||
			      (ignore[i] == ANY_I2C_BUS)) &&
			      (addr == ignore[i + 1])) {
				dev_dbg(&adapter->dev, "found ignore parameter for adapter %d, addr %04x\n", adapter_id, addr);
				found = 1;
			}
		}
		if (found)
			continue;

		/* Now, we will do a detection, but only if it is in the normal or 
		   probe entries */
		for (i = 0; !found && (normal_i2c[i] != I2C_CLIENT_END); i += 1) {
			if (addr == normal_i2c[i]) {
				found = 1;
				dev_dbg(&adapter->dev, "found normal i2c entry for adapter %d, addr %02x\n", adapter_id, addr);
			}
		}

		for (i = 0;
		     !found && (probe[i] != I2C_CLIENT_END);
		     i += 2) {
			if (((adapter_id == probe[i]) ||
			     (probe[i] == ANY_I2C_BUS))
			    && (addr == probe[i + 1])) {
				dev_dbg(&adapter->dev, "found probe parameter for adapter %d, addr %04x\n", adapter_id, addr);
				found = 1;
			}
		}
		if (!found)
			continue;

		/* OK, so we really should examine this address. First check
		   whether there is some client here at all! */
		if (i2c_smbus_xfer(adapter, addr, 0, 0, 0, I2C_SMBUS_QUICK, NULL) >= 0)
			if ((err = found_proc(adapter, addr, -1)))
				return err;
	}
	return 0;
}

EXPORT_SYMBOL(i2c_detect);

MODULE_AUTHOR("Frodo Looijaard <frodol@dds.nl>, "
	      "Rudolf Marek <r.marek@sh.cvut.cz>");

MODULE_DESCRIPTION("i2c-sensor driver");
MODULE_LICENSE("GPL");
