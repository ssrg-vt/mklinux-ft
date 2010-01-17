/*
	Mantis VP-1033 driver

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

#include "mantis_common.h"
#include "mantis_vp1033.h"

u8 lgtdqcs001f_inittab[] = {
	0x01, 0x15,
	0x02, 0x00,
	0x03, 0x00,
	0x04, 0x2a,
	0x05, 0x85,
	0x06, 0x02,
	0x07, 0x00,
	0x08, 0x00,
	0x0c, 0x01,
	0x0d, 0x81,
	0x0e, 0x44,
	0x0f, 0x94,
	0x10, 0x3c,
	0x11, 0x84,
	0x12, 0xb9,
	0x13, 0xb5,
	0x14, 0x4f,
	0x15, 0xc9,
	0x16, 0x80,
	0x17, 0x36,
	0x18, 0xfb,
	0x19, 0xcf,
	0x1a, 0xbc,
	0x1c, 0x2b,
	0x1d, 0x27,
	0x1e, 0x00,
	0x1f, 0x0b,
	0x20, 0xa1,
	0x21, 0x60,
	0x22, 0x00,
	0x23, 0x00,
	0x28, 0x00,
	0x29, 0x28,
	0x2a, 0x14,
	0x2b, 0x0f,
	0x2c, 0x09,
	0x2d, 0x05,
	0x31, 0x1f,
	0x32, 0x19,
	0x33, 0xfc,
	0x34, 0x13,
	0xff, 0xff,
};

struct stv0299_config lgtdqcs001f_config = {
	.demod_address		= 0x68,
	.inittab		= lgtdqcs001f_inittab,
	.mclk			= 88000000UL,
//	.invert = 0,
	.invert			= 1,
//	.enhanced_tuning = 0,
	.skip_reinit		= 0,
	.lock_output		= STV0229_LOCKOUTPUT_0,
	.volt13_op0_op1		= STV0299_VOLT13_OP0,
	.min_delay_ms		= 100,
	.set_symbol_rate	= lgtdqcs001f_set_symbol_rate,
//	.pll_set		= lgtdqcs001f_pll_set,
};

int lgtdqcs001f_tuner_set(struct dvb_frontend *fe,
			  struct dvb_frontend_parameters *params)
{
	u8 buf[4];
	u32 div;

	struct mantis_pci *mantis = fe->dvb->priv;

	struct i2c_msg msg = {
		.addr = 0x61,
		.flags = 0,
		.buf = buf,
		.len = sizeof (buf)
	};
	div = params->frequency / 250;

	buf[0] = (div >> 8) & 0x7f;
	buf[1] =  div & 0xff;
	buf[2] =  0x83;
	buf[3] =  0xc0;

	if (params->frequency < 1531000)
		buf[3] |= 0x04;
	else
		buf[3] &= ~0x04;
	if (i2c_transfer(&mantis->adapter, &msg, 1) < 0) {
		dprintk(verbose, MANTIS_ERROR, 1, "Write: I2C Transfer failed");
		return -EIO;
	}
	msleep_interruptible(100);

	return 0;
}

int lgtdqcs001f_set_symbol_rate(struct dvb_frontend *fe,
				u32 srate, u32 ratio)
{
	u8 aclk = 0;
	u8 bclk = 0;

	if (srate < 1500000) {
		aclk = 0xb7;
		bclk = 0x47;
	} else if (srate < 3000000) {
		aclk = 0xb7;
		bclk = 0x4b;
	} else if (srate < 7000000) {
		aclk = 0xb7;
		bclk = 0x4f;
	} else if (srate < 14000000) {
		aclk = 0xb7;
		bclk = 0x53;
	} else if (srate < 30000000) {
		aclk = 0xb6;
		bclk = 0x53;
	} else if (srate < 45000000) {
		aclk = 0xb4;
		bclk = 0x51;
	}
	stv0299_writereg (fe, 0x13, aclk);
	stv0299_writereg (fe, 0x14, bclk);

	stv0299_writereg (fe, 0x1f, (ratio >> 16) & 0xff);
	stv0299_writereg (fe, 0x20, (ratio >>  8) & 0xff);
	stv0299_writereg (fe, 0x21, (ratio      ) & 0xf0);

	return 0;
}
