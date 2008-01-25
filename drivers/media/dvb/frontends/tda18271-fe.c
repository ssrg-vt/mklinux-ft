/*
    tda18271-fe.c - driver for the Philips / NXP TDA18271 silicon tuner

    Copyright (C) 2007 Michael Krufky (mkrufky@linuxtv.org)

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

#include <linux/delay.h>
#include <linux/videodev2.h>
#include "tda18271-priv.h"

int tda18271_debug;
module_param_named(debug, tda18271_debug, int, 0644);
MODULE_PARM_DESC(debug, "set debug level (info=1, map=2, reg=4 (or-able))");

/*---------------------------------------------------------------------*/

static int tda18271_i2c_gate_ctrl(struct dvb_frontend *fe, int enable)
{
	struct tda18271_priv *priv = fe->tuner_priv;
	enum tda18271_i2c_gate gate;
	int ret = 0;

	switch (priv->gate) {
	case TDA18271_GATE_DIGITAL:
	case TDA18271_GATE_ANALOG:
		gate = priv->gate;
		break;
	case TDA18271_GATE_AUTO:
	default:
		switch (priv->mode) {
		case TDA18271_DIGITAL:
			gate = TDA18271_GATE_DIGITAL;
			break;
		case TDA18271_ANALOG:
		default:
			gate = TDA18271_GATE_ANALOG;
			break;
		}
	}

	switch (gate) {
	case TDA18271_GATE_ANALOG:
		if (fe->ops.analog_ops.i2c_gate_ctrl)
			ret = fe->ops.analog_ops.i2c_gate_ctrl(fe, enable);
		break;
	case TDA18271_GATE_DIGITAL:
		if (fe->ops.i2c_gate_ctrl)
			ret = fe->ops.i2c_gate_ctrl(fe, enable);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
};

/*---------------------------------------------------------------------*/

static void tda18271_dump_regs(struct dvb_frontend *fe)
{
	struct tda18271_priv *priv = fe->tuner_priv;
	unsigned char *regs = priv->tda18271_regs;

	tda_reg("=== TDA18271 REG DUMP ===\n");
	tda_reg("ID_BYTE            = 0x%02x\n", 0xff & regs[R_ID]);
	tda_reg("THERMO_BYTE        = 0x%02x\n", 0xff & regs[R_TM]);
	tda_reg("POWER_LEVEL_BYTE   = 0x%02x\n", 0xff & regs[R_PL]);
	tda_reg("EASY_PROG_BYTE_1   = 0x%02x\n", 0xff & regs[R_EP1]);
	tda_reg("EASY_PROG_BYTE_2   = 0x%02x\n", 0xff & regs[R_EP2]);
	tda_reg("EASY_PROG_BYTE_3   = 0x%02x\n", 0xff & regs[R_EP3]);
	tda_reg("EASY_PROG_BYTE_4   = 0x%02x\n", 0xff & regs[R_EP4]);
	tda_reg("EASY_PROG_BYTE_5   = 0x%02x\n", 0xff & regs[R_EP5]);
	tda_reg("CAL_POST_DIV_BYTE  = 0x%02x\n", 0xff & regs[R_CPD]);
	tda_reg("CAL_DIV_BYTE_1     = 0x%02x\n", 0xff & regs[R_CD1]);
	tda_reg("CAL_DIV_BYTE_2     = 0x%02x\n", 0xff & regs[R_CD2]);
	tda_reg("CAL_DIV_BYTE_3     = 0x%02x\n", 0xff & regs[R_CD3]);
	tda_reg("MAIN_POST_DIV_BYTE = 0x%02x\n", 0xff & regs[R_MPD]);
	tda_reg("MAIN_DIV_BYTE_1    = 0x%02x\n", 0xff & regs[R_MD1]);
	tda_reg("MAIN_DIV_BYTE_2    = 0x%02x\n", 0xff & regs[R_MD2]);
	tda_reg("MAIN_DIV_BYTE_3    = 0x%02x\n", 0xff & regs[R_MD3]);
}

static void tda18271_read_regs(struct dvb_frontend *fe)
{
	struct tda18271_priv *priv = fe->tuner_priv;
	unsigned char *regs = priv->tda18271_regs;
	unsigned char buf = 0x00;
	int ret;
	struct i2c_msg msg[] = {
		{ .addr = priv->i2c_addr, .flags = 0,
		  .buf = &buf, .len = 1 },
		{ .addr = priv->i2c_addr, .flags = I2C_M_RD,
		  .buf = regs, .len = 16 }
	};

	tda18271_i2c_gate_ctrl(fe, 1);

	/* read all registers */
	ret = i2c_transfer(priv->i2c_adap, msg, 2);

	tda18271_i2c_gate_ctrl(fe, 0);

	if (ret != 2)
		tda_err("ERROR: i2c_transfer returned: %d\n", ret);

	if (tda18271_debug & DBG_REG)
		tda18271_dump_regs(fe);
}

static void tda18271_write_regs(struct dvb_frontend *fe, int idx, int len)
{
	struct tda18271_priv *priv = fe->tuner_priv;
	unsigned char *regs = priv->tda18271_regs;
	unsigned char buf[TDA18271_NUM_REGS+1];
	struct i2c_msg msg = { .addr = priv->i2c_addr, .flags = 0,
			       .buf = buf, .len = len+1 };
	int i, ret;

	BUG_ON((len == 0) || (idx+len > sizeof(buf)));

	buf[0] = idx;
	for (i = 1; i <= len; i++) {
		buf[i] = regs[idx-1+i];
	}

	tda18271_i2c_gate_ctrl(fe, 1);

	/* write registers */
	ret = i2c_transfer(priv->i2c_adap, &msg, 1);

	tda18271_i2c_gate_ctrl(fe, 0);

	if (ret != 1)
		tda_err("ERROR: i2c_transfer returned: %d\n", ret);
}

/*---------------------------------------------------------------------*/

static int tda18271_init_regs(struct dvb_frontend *fe)
{
	struct tda18271_priv *priv = fe->tuner_priv;
	unsigned char *regs = priv->tda18271_regs;

	tda_dbg("initializing registers for device @ %d-%04x\n",
		i2c_adapter_id(priv->i2c_adap), priv->i2c_addr);

	/* initialize registers */
	regs[R_ID]   = 0x83;
	regs[R_TM]   = 0x08;
	regs[R_PL]   = 0x80;
	regs[R_EP1]  = 0xc6;
	regs[R_EP2]  = 0xdf;
	regs[R_EP3]  = 0x16;
	regs[R_EP4]  = 0x60;
	regs[R_EP5]  = 0x80;
	regs[R_CPD]  = 0x80;
	regs[R_CD1]  = 0x00;
	regs[R_CD2]  = 0x00;
	regs[R_CD3]  = 0x00;
	regs[R_MPD]  = 0x00;
	regs[R_MD1]  = 0x00;
	regs[R_MD2]  = 0x00;
	regs[R_MD3]  = 0x00;
	regs[R_EB1]  = 0xff;
	regs[R_EB2]  = 0x01;
	regs[R_EB3]  = 0x84;
	regs[R_EB4]  = 0x41;
	regs[R_EB5]  = 0x01;
	regs[R_EB6]  = 0x84;
	regs[R_EB7]  = 0x40;
	regs[R_EB8]  = 0x07;
	regs[R_EB9]  = 0x00;
	regs[R_EB10] = 0x00;
	regs[R_EB11] = 0x96;
	regs[R_EB12] = 0x0f;
	regs[R_EB13] = 0xc1;
	regs[R_EB14] = 0x00;
	regs[R_EB15] = 0x8f;
	regs[R_EB16] = 0x00;
	regs[R_EB17] = 0x00;
	regs[R_EB18] = 0x00;
	regs[R_EB19] = 0x00;
	regs[R_EB20] = 0x20;
	regs[R_EB21] = 0x33;
	regs[R_EB22] = 0x48;
	regs[R_EB23] = 0xb0;

	tda18271_write_regs(fe, 0x00, TDA18271_NUM_REGS);
	/* setup AGC1 & AGC2 */
	regs[R_EB17] = 0x00;
	tda18271_write_regs(fe, R_EB17, 1);
	regs[R_EB17] = 0x03;
	tda18271_write_regs(fe, R_EB17, 1);
	regs[R_EB17] = 0x43;
	tda18271_write_regs(fe, R_EB17, 1);
	regs[R_EB17] = 0x4c;
	tda18271_write_regs(fe, R_EB17, 1);

	regs[R_EB20] = 0xa0;
	tda18271_write_regs(fe, R_EB20, 1);
	regs[R_EB20] = 0xa7;
	tda18271_write_regs(fe, R_EB20, 1);
	regs[R_EB20] = 0xe7;
	tda18271_write_regs(fe, R_EB20, 1);
	regs[R_EB20] = 0xec;
	tda18271_write_regs(fe, R_EB20, 1);

	/* image rejection calibration */

	/* low-band */
	regs[R_EP3] = 0x1f;
	regs[R_EP4] = 0x66;
	regs[R_EP5] = 0x81;
	regs[R_CPD] = 0xcc;
	regs[R_CD1] = 0x6c;
	regs[R_CD2] = 0x00;
	regs[R_CD3] = 0x00;
	regs[R_MPD] = 0xcd;
	regs[R_MD1] = 0x77;
	regs[R_MD2] = 0x08;
	regs[R_MD3] = 0x00;

	tda18271_write_regs(fe, R_EP3, 11);
	msleep(5); /* pll locking */

	regs[R_EP1] = 0xc6;
	tda18271_write_regs(fe, R_EP1, 1);
	msleep(5); /* wanted low measurement */

	regs[R_EP3] = 0x1f;
	regs[R_EP4] = 0x66;
	regs[R_EP5] = 0x85;
	regs[R_CPD] = 0xcb;
	regs[R_CD1] = 0x66;
	regs[R_CD2] = 0x70;
	regs[R_CD3] = 0x00;

	tda18271_write_regs(fe, R_EP3, 7);
	msleep(5); /* pll locking */

	regs[R_EP2] = 0xdf;
	tda18271_write_regs(fe, R_EP2, 1);
	msleep(30); /* image low optimization completion */

	/* mid-band */
	regs[R_EP3] = 0x1f;
	regs[R_EP4] = 0x66;
	regs[R_EP5] = 0x82;
	regs[R_CPD] = 0xa8;
	regs[R_CD1] = 0x66;
	regs[R_CD2] = 0x00;
	regs[R_CD3] = 0x00;
	regs[R_MPD] = 0xa9;
	regs[R_MD1] = 0x73;
	regs[R_MD2] = 0x1a;
	regs[R_MD3] = 0x00;

	tda18271_write_regs(fe, R_EP3, 11);
	msleep(5); /* pll locking */

	regs[R_EP1] = 0xc6;
	tda18271_write_regs(fe, R_EP1, 1);
	msleep(5); /* wanted mid measurement */

	regs[R_EP3] = 0x1f;
	regs[R_EP4] = 0x66;
	regs[R_EP5] = 0x86;
	regs[R_CPD] = 0xa8;
	regs[R_CD1] = 0x66;
	regs[R_CD2] = 0xa0;
	regs[R_CD3] = 0x00;

	tda18271_write_regs(fe, R_EP3, 7);
	msleep(5); /* pll locking */

	regs[R_EP2] = 0xdf;
	tda18271_write_regs(fe, R_EP2, 1);
	msleep(30); /* image mid optimization completion */

	/* high-band */
	regs[R_EP3] = 0x1f;
	regs[R_EP4] = 0x66;
	regs[R_EP5] = 0x83;
	regs[R_CPD] = 0x98;
	regs[R_CD1] = 0x65;
	regs[R_CD2] = 0x00;
	regs[R_CD3] = 0x00;
	regs[R_MPD] = 0x99;
	regs[R_MD1] = 0x71;
	regs[R_MD2] = 0xcd;
	regs[R_MD3] = 0x00;

	tda18271_write_regs(fe, R_EP3, 11);
	msleep(5); /* pll locking */

	regs[R_EP1] = 0xc6;
	tda18271_write_regs(fe, R_EP1, 1);
	msleep(5); /* wanted high measurement */

	regs[R_EP3] = 0x1f;
	regs[R_EP4] = 0x66;
	regs[R_EP5] = 0x87;
	regs[R_CPD] = 0x98;
	regs[R_CD1] = 0x65;
	regs[R_CD2] = 0x50;
	regs[R_CD3] = 0x00;

	tda18271_write_regs(fe, R_EP3, 7);
	msleep(5); /* pll locking */

	regs[R_EP2] = 0xdf;

	tda18271_write_regs(fe, R_EP2, 1);
	msleep(30); /* image high optimization completion */

	regs[R_EP4] = 0x64;
	tda18271_write_regs(fe, R_EP4, 1);

	regs[R_EP1] = 0xc6;
	tda18271_write_regs(fe, R_EP1, 1);

	return 0;
}

static int tda18271_init(struct dvb_frontend *fe)
{
	struct tda18271_priv *priv = fe->tuner_priv;
	unsigned char *regs = priv->tda18271_regs;

	tda18271_read_regs(fe);

	/* test IR_CAL_OK to see if we need init */
	if ((regs[R_EP1] & 0x08) == 0)
		tda18271_init_regs(fe);

	return 0;
}

static int tda18271_calc_main_pll(struct dvb_frontend *fe, u32 freq)
{
	/* Sets Main Post-Divider & Divider bytes, but does not write them */
	struct tda18271_priv *priv = fe->tuner_priv;
	unsigned char *regs = priv->tda18271_regs;
	u8 d, pd;
	u32 div;

	int ret = tda18271_lookup_pll_map(MAIN_PLL, &freq, &pd, &d);
	if (ret < 0)
		goto fail;

	regs[R_MPD]   = (0x77 & pd);

	switch (priv->mode) {
	case TDA18271_ANALOG:
		regs[R_MPD]  &= ~0x08;
		break;
	case TDA18271_DIGITAL:
		regs[R_MPD]  |=  0x08;
		break;
	}

	div =  ((d * (freq / 1000)) << 7) / 125;

	regs[R_MD1]   = 0x7f & (div >> 16);
	regs[R_MD2]   = 0xff & (div >> 8);
	regs[R_MD3]   = 0xff & div;
fail:
	return ret;
}

static int tda18271_calc_cal_pll(struct dvb_frontend *fe, u32 freq)
{
	/* Sets Cal Post-Divider & Divider bytes, but does not write them */
	struct tda18271_priv *priv = fe->tuner_priv;
	unsigned char *regs = priv->tda18271_regs;
	u8 d, pd;
	u32 div;

	int ret = tda18271_lookup_pll_map(CAL_PLL, &freq, &pd, &d);
	if (ret < 0)
		goto fail;

	regs[R_CPD]   = pd;

	div =  ((d * (freq / 1000)) << 7) / 125;

	regs[R_CD1]   = 0x7f & (div >> 16);
	regs[R_CD2]   = 0xff & (div >> 8);
	regs[R_CD3]   = 0xff & div;
fail:
	return ret;
}

static int tda18271_calc_bp_filter(struct dvb_frontend *fe, u32 *freq)
{
	/* Sets BP filter bits, but does not write them */
	struct tda18271_priv *priv = fe->tuner_priv;
	unsigned char *regs = priv->tda18271_regs;
	u8 val;

	int ret = tda18271_lookup_map(BP_FILTER, freq, &val);
	if (ret < 0)
		goto fail;

	regs[R_EP1]  &= ~0x07; /* clear bp filter bits */
	regs[R_EP1]  |= (0x07 & val);
fail:
	return ret;
}

static int tda18271_calc_km(struct dvb_frontend *fe, u32 *freq)
{
	/* Sets K & M bits, but does not write them */
	struct tda18271_priv *priv = fe->tuner_priv;
	unsigned char *regs = priv->tda18271_regs;
	u8 val;

	int ret = tda18271_lookup_map(RF_CAL_KMCO, freq, &val);
	if (ret < 0)
		goto fail;

	regs[R_EB13] &= ~0x7c; /* clear k & m bits */
	regs[R_EB13] |= (0x7c & val);
fail:
	return ret;
}

static int tda18271_calc_rf_band(struct dvb_frontend *fe, u32 *freq)
{
	/* Sets RF Band bits, but does not write them */
	struct tda18271_priv *priv = fe->tuner_priv;
	unsigned char *regs = priv->tda18271_regs;
	u8 val;

	int ret = tda18271_lookup_map(RF_BAND, freq, &val);
	if (ret < 0)
		goto fail;

	regs[R_EP2]  &= ~0xe0; /* clear rf band bits */
	regs[R_EP2]  |= (0xe0 & (val << 5));
fail:
	return ret;
}

static int tda18271_calc_gain_taper(struct dvb_frontend *fe, u32 *freq)
{
	/* Sets Gain Taper bits, but does not write them */
	struct tda18271_priv *priv = fe->tuner_priv;
	unsigned char *regs = priv->tda18271_regs;
	u8 val;

	int ret = tda18271_lookup_map(GAIN_TAPER, freq, &val);
	if (ret < 0)
		goto fail;

	regs[R_EP2]  &= ~0x1f; /* clear gain taper bits */
	regs[R_EP2]  |= (0x1f & val);
fail:
	return ret;
}

static int tda18271_calc_ir_measure(struct dvb_frontend *fe, u32 *freq)
{
	/* Sets IR Meas bits, but does not write them */
	struct tda18271_priv *priv = fe->tuner_priv;
	unsigned char *regs = priv->tda18271_regs;
	u8 val;

	int ret = tda18271_lookup_map(IR_MEASURE, freq, &val);
	if (ret < 0)
		goto fail;

	regs[R_EP5] &= ~0x07;
	regs[R_EP5] |= (0x07 & val);
fail:
	return ret;
}

static int tda18271_calc_rf_cal(struct dvb_frontend *fe, u32 *freq)
{
	/* Sets RF Cal bits, but does not write them */
	struct tda18271_priv *priv = fe->tuner_priv;
	unsigned char *regs = priv->tda18271_regs;
	u8 val;

	int ret = tda18271_lookup_map(RF_CAL, freq, &val);
	if (ret < 0)
		goto fail;

	/* VHF_Low band only */
	if (0 == val) {
		ret = -ERANGE;
		goto fail;
	}
	regs[R_EB14] = val;
fail:
	return ret;
}

static int tda18271_tune(struct dvb_frontend *fe,
			 u32 ifc, u32 freq, u32 bw, u8 std)
{
	struct tda18271_priv *priv = fe->tuner_priv;
	unsigned char *regs = priv->tda18271_regs;
	u32 N = 0;

	tda18271_init(fe);

	tda_dbg("freq = %d, ifc = %d\n", freq, ifc);

	/* RF tracking filter calibration */

	/* calculate BP_Filter */
	tda18271_calc_bp_filter(fe, &freq);
	tda18271_write_regs(fe, R_EP1, 1);

	regs[R_EB4]  &= 0x07;
	regs[R_EB4]  |= 0x60;
	tda18271_write_regs(fe, R_EB4, 1);

	regs[R_EB7]   = 0x60;
	tda18271_write_regs(fe, R_EB7, 1);

	regs[R_EB14]  = 0x00;
	tda18271_write_regs(fe, R_EB14, 1);

	regs[R_EB20]  = 0xcc;
	tda18271_write_regs(fe, R_EB20, 1);

	/* set CAL mode to RF tracking filter calibration */
	regs[R_EP4]  |= 0x03;

	/* calculate CAL PLL */

	switch (priv->mode) {
	case TDA18271_ANALOG:
		N = freq - 1250000;
		break;
	case TDA18271_DIGITAL:
		N = freq + bw / 2;
		break;
	}

	tda18271_calc_cal_pll(fe, N);

	/* calculate MAIN PLL */

	switch (priv->mode) {
	case TDA18271_ANALOG:
		N = freq - 250000;
		break;
	case TDA18271_DIGITAL:
		N = freq + bw / 2 + 1000000;
		break;
	}

	tda18271_calc_main_pll(fe, N);

	tda18271_write_regs(fe, R_EP3, 11);
	msleep(5); /* RF tracking filter calibration initialization */

	/* search for K,M,CO for RF Calibration */
	tda18271_calc_km(fe, &freq);
	tda18271_write_regs(fe, R_EB13, 1);

	/* search for RF_BAND */
	tda18271_calc_rf_band(fe, &freq);

	/* search for Gain_Taper */
	tda18271_calc_gain_taper(fe, &freq);

	tda18271_write_regs(fe, R_EP2, 1);
	tda18271_write_regs(fe, R_EP1, 1);
	tda18271_write_regs(fe, R_EP2, 1);
	tda18271_write_regs(fe, R_EP1, 1);

	regs[R_EB4]  &= 0x07;
	regs[R_EB4]  |= 0x40;
	tda18271_write_regs(fe, R_EB4, 1);

	regs[R_EB7]   = 0x40;
	tda18271_write_regs(fe, R_EB7, 1);
	msleep(10);

	regs[R_EB20]  = 0xec;
	tda18271_write_regs(fe, R_EB20, 1);
	msleep(60); /* RF tracking filter calibration completion */

	regs[R_EP4]  &= ~0x03; /* set cal mode to normal */
	tda18271_write_regs(fe, R_EP4, 1);

	tda18271_write_regs(fe, R_EP1, 1);

	/* RF tracking filter correction for VHF_Low band */
	if (0 == tda18271_calc_rf_cal(fe, &freq))
		tda18271_write_regs(fe, R_EB14, 1);

	/* Channel Configuration */

	switch (priv->mode) {
	case TDA18271_ANALOG:
		regs[R_EB22]  = 0x2c;
		break;
	case TDA18271_DIGITAL:
		regs[R_EB22]  = 0x37;
		break;
	}
	tda18271_write_regs(fe, R_EB22, 1);

	regs[R_EP1]  |= 0x40; /* set dis power level on */

	/* set standard */
	regs[R_EP3]  &= ~0x1f; /* clear std bits */

	/* see table 22 */
	regs[R_EP3]  |= std;

	regs[R_EP4]  &= ~0x03; /* set cal mode to normal */

	regs[R_EP4]  &= ~0x1c; /* clear if level bits */
	switch (priv->mode) {
	case TDA18271_ANALOG:
		regs[R_MPD]  &= ~0x80; /* IF notch = 0 */
		break;
	case TDA18271_DIGITAL:
		regs[R_EP4]  |= 0x04;
		regs[R_MPD]  |= 0x80;
		break;
	}

	regs[R_EP4]  &= ~0x80; /* turn this bit on only for fm */

	/* image rejection validity */
	tda18271_calc_ir_measure(fe, &freq);

	/* calculate MAIN PLL */
	N = freq + ifc;

	tda18271_calc_main_pll(fe, N);

	tda18271_write_regs(fe, R_TM, 15);
	msleep(5);

	return 0;
}

/* ------------------------------------------------------------------ */

static int tda18271_set_params(struct dvb_frontend *fe,
			       struct dvb_frontend_parameters *params)
{
	struct tda18271_priv *priv = fe->tuner_priv;
	u8 std;
	u32 bw, sgIF = 0;

	u32 freq = params->frequency;

	priv->mode = TDA18271_DIGITAL;

	/* see table 22 */
	if (fe->ops.info.type == FE_ATSC) {
		switch (params->u.vsb.modulation) {
		case VSB_8:
		case VSB_16:
			std = 0x1b; /* device-specific (spec says 0x1c) */
			sgIF = 5380000;
			break;
		case QAM_64:
		case QAM_256:
			std = 0x18; /* device-specific (spec says 0x1d) */
			sgIF = 4000000;
			break;
		default:
			tda_warn("modulation not set!\n");
			return -EINVAL;
		}
#if 0
		/* userspace request is already center adjusted */
		freq += 1750000; /* Adjust to center (+1.75MHZ) */
#endif
		bw = 6000000;
	} else if (fe->ops.info.type == FE_OFDM) {
		switch (params->u.ofdm.bandwidth) {
		case BANDWIDTH_6_MHZ:
			std = 0x1b; /* device-specific (spec says 0x1c) */
			bw = 6000000;
			sgIF = 3300000;
			break;
		case BANDWIDTH_7_MHZ:
			std = 0x19; /* device-specific (spec says 0x1d) */
			bw = 7000000;
			sgIF = 3800000;
			break;
		case BANDWIDTH_8_MHZ:
			std = 0x1a; /* device-specific (spec says 0x1e) */
			bw = 8000000;
			sgIF = 4300000;
			break;
		default:
			tda_warn("bandwidth not set!\n");
			return -EINVAL;
		}
	} else {
		tda_warn("modulation type not supported!\n");
		return -EINVAL;
	}

	return tda18271_tune(fe, sgIF, freq, bw, std);
}

static int tda18271_set_analog_params(struct dvb_frontend *fe,
				      struct analog_parameters *params)
{
	struct tda18271_priv *priv = fe->tuner_priv;
	u8 std;
	unsigned int sgIF;
	char *mode;

	priv->mode = TDA18271_ANALOG;

	/* see table 22 */
	if (params->std & V4L2_STD_MN) {
		std = 0x0d;
		sgIF =  92;
		mode = "MN";
	} else if (params->std & V4L2_STD_B) {
		std = 0x0e;
		sgIF =  108;
		mode = "B";
	} else if (params->std & V4L2_STD_GH) {
		std = 0x0f;
		sgIF =  124;
		mode = "GH";
	} else if (params->std & V4L2_STD_PAL_I) {
		std = 0x0f;
		sgIF =  124;
		mode = "I";
	} else if (params->std & V4L2_STD_DK) {
		std = 0x0f;
		sgIF =  124;
		mode = "DK";
	} else if (params->std & V4L2_STD_SECAM_L) {
		std = 0x0f;
		sgIF =  124;
		mode = "L";
	} else if (params->std & V4L2_STD_SECAM_LC) {
		std = 0x0f;
		sgIF =  20;
		mode = "LC";
	} else {
		std = 0x0f;
		sgIF =  124;
		mode = "xx";
	}

	if (params->mode == V4L2_TUNER_RADIO)
		sgIF =  88; /* if frequency is 5.5 MHz */

	tda_dbg("setting tda18271 to system %s\n", mode);

	return tda18271_tune(fe, sgIF * 62500, params->frequency * 62500,
			     0, std);
}

static int tda18271_release(struct dvb_frontend *fe)
{
	kfree(fe->tuner_priv);
	fe->tuner_priv = NULL;
	return 0;
}

static int tda18271_get_frequency(struct dvb_frontend *fe, u32 *frequency)
{
	struct tda18271_priv *priv = fe->tuner_priv;
	*frequency = priv->frequency;
	return 0;
}

static int tda18271_get_bandwidth(struct dvb_frontend *fe, u32 *bandwidth)
{
	struct tda18271_priv *priv = fe->tuner_priv;
	*bandwidth = priv->bandwidth;
	return 0;
}

static int tda18271_get_id(struct dvb_frontend *fe)
{
	struct tda18271_priv *priv = fe->tuner_priv;
	unsigned char *regs = priv->tda18271_regs;
	char *name;
	int ret = 0;

	tda18271_read_regs(fe);

	switch (regs[R_ID] & 0x7f) {
	case 3:
		name = "TDA18271HD/C1";
		break;
	case 4:
		name = "TDA18271HD/C2";
		ret = -EPROTONOSUPPORT;
		break;
	default:
		name = "Unknown device";
		ret = -EINVAL;
		break;
	}

	tda_info("%s detected @ %d-%04x%s\n", name,
		 i2c_adapter_id(priv->i2c_adap), priv->i2c_addr,
		 (0 == ret) ? "" : ", device not supported.");

	return ret;
}

static struct dvb_tuner_ops tda18271_tuner_ops = {
	.info = {
		.name = "NXP TDA18271HD",
		.frequency_min  =  45000000,
		.frequency_max  = 864000000,
		.frequency_step =     62500
	},
	.init              = tda18271_init,
	.set_params        = tda18271_set_params,
	.set_analog_params = tda18271_set_analog_params,
	.release           = tda18271_release,
	.get_frequency     = tda18271_get_frequency,
	.get_bandwidth     = tda18271_get_bandwidth,
};

struct dvb_frontend *tda18271_attach(struct dvb_frontend *fe, u8 addr,
				     struct i2c_adapter *i2c,
				     enum tda18271_i2c_gate gate)
{
	struct tda18271_priv *priv = NULL;

	priv = kzalloc(sizeof(struct tda18271_priv), GFP_KERNEL);
	if (priv == NULL)
		return NULL;

	priv->i2c_addr = addr;
	priv->i2c_adap = i2c;
	priv->gate = gate;

	fe->tuner_priv = priv;

	if (tda18271_get_id(fe) < 0)
		goto fail;

	memcpy(&fe->ops.tuner_ops, &tda18271_tuner_ops,
	       sizeof(struct dvb_tuner_ops));

	tda18271_init_regs(fe);

	return fe;
fail:
	tda18271_release(fe);
	return NULL;
}
EXPORT_SYMBOL_GPL(tda18271_attach);
MODULE_DESCRIPTION("NXP TDA18271HD analog / digital tuner driver");
MODULE_AUTHOR("Michael Krufky <mkrufky@linuxtv.org>");
MODULE_LICENSE("GPL");

/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-basic-offset: 8
 * End:
 */
