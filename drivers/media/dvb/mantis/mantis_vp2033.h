/*
	Mantis VP-2033 driver

	Copyright (C) 2005, 2006 Manu Abraham (abraham.manu@gmail.com)

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

#ifndef __MANTIS_VP2033_H
#define __MANTIS_VP2033_H

#include "dvb_frontend.h"
#include "mantis_common.h"
#include "tda1002x.h"

#define MANTIS_VP_2033_DVB_C	0x0008

extern struct tda1002x_config philips_cu1216_config;
extern struct mantis_hwconfig vp2033_mantis_config;

extern int philips_cu1216_tuner_set(struct dvb_frontend *fe, struct dvb_frontend_parameters *params);

extern u8 read_pwm(struct mantis_pci *mantis);

#endif // __MANTIS_VP2033_H
