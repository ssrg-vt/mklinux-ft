/*
 * Etoms Et61x151 GPL Linux driver by Michel Xhaard (09/09/2004)
 *
 * V4L2 by Jean-Francois Moine <http://moinejf.free.fr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#define MODULE_NAME "etoms"

#include "gspca.h"

#define DRIVER_VERSION_NUMBER	KERNEL_VERSION(2, 1, 0)
static const char version[] = "2.1.0";

MODULE_AUTHOR("Michel Xhaard <mxhaard@users.sourceforge.net>");
MODULE_DESCRIPTION("Etoms USB Camera Driver");
MODULE_LICENSE("GPL");

/* specific webcam descriptor */
struct sd {
	struct gspca_dev gspca_dev;	/* !! must be the first item */

	unsigned char brightness;
	unsigned char contrast;
	unsigned char colors;
	unsigned char autogain;

	char sensor;
#define SENSOR_PAS106 0
#define SENSOR_TAS5130CXX 1
	signed char ag_cnt;
#define AG_CNT_START 13
};

/* V4L2 controls supported by the driver */
static int sd_setbrightness(struct gspca_dev *gspca_dev, __s32 val);
static int sd_getbrightness(struct gspca_dev *gspca_dev, __s32 *val);
static int sd_setcontrast(struct gspca_dev *gspca_dev, __s32 val);
static int sd_getcontrast(struct gspca_dev *gspca_dev, __s32 *val);
static int sd_setcolors(struct gspca_dev *gspca_dev, __s32 val);
static int sd_getcolors(struct gspca_dev *gspca_dev, __s32 *val);
static int sd_setautogain(struct gspca_dev *gspca_dev, __s32 val);
static int sd_getautogain(struct gspca_dev *gspca_dev, __s32 *val);

static struct ctrl sd_ctrls[] = {
#define SD_BRIGHTNESS 0
	{
	 {
	  .id = V4L2_CID_BRIGHTNESS,
	  .type = V4L2_CTRL_TYPE_INTEGER,
	  .name = "Brightness",
	  .minimum = 1,
	  .maximum = 127,
	  .step = 1,
	  .default_value = 63,
	  },
	 .set = sd_setbrightness,
	 .get = sd_getbrightness,
	 },
#define SD_CONTRAST 1
	{
	 {
	  .id = V4L2_CID_CONTRAST,
	  .type = V4L2_CTRL_TYPE_INTEGER,
	  .name = "Contrast",
	  .minimum = 0,
	  .maximum = 255,
	  .step = 1,
	  .default_value = 127,
	  },
	 .set = sd_setcontrast,
	 .get = sd_getcontrast,
	 },
#define SD_COLOR 2
	{
	 {
	  .id = V4L2_CID_SATURATION,
	  .type = V4L2_CTRL_TYPE_INTEGER,
	  .name = "Color",
	  .minimum = 0,
	  .maximum = 15,
	  .step = 1,
	  .default_value = 7,
	  },
	 .set = sd_setcolors,
	 .get = sd_getcolors,
	 },
#define SD_AUTOGAIN 3
	{
	 {
	  .id = V4L2_CID_AUTOGAIN,
	  .type = V4L2_CTRL_TYPE_BOOLEAN,
	  .name = "Auto Gain",
	  .minimum = 0,
	  .maximum = 1,
	  .step = 1,
	  .default_value = 1,
	  },
	 .set = sd_setautogain,
	 .get = sd_getautogain,
	 },
};

static struct cam_mode vga_mode[] = {
	{V4L2_PIX_FMT_SBGGR8, 320, 240, 1},
/*	{V4L2_PIX_FMT_SBGGR8, 640, 480, 0}, */
};

static struct cam_mode sif_mode[] = {
	{V4L2_PIX_FMT_SBGGR8, 176, 144, 1},
	{V4L2_PIX_FMT_SBGGR8, 352, 288, 0},
};

#define ETOMS_ALT_SIZE_1000   12

#define ET_GPIO_DIR_CTRL 0x04	/* Control IO bit[0..5] (0 in  1 out) */
#define ET_GPIO_OUT 0x05	/* Only IO data */
#define ET_GPIO_IN 0x06		/* Read Only IO data */
#define ET_RESET_ALL 0x03
#define ET_ClCK 0x01
#define ET_CTRL 0x02		/* enable i2c OutClck Powerdown mode */

#define ET_COMP 0x12		/* Compression register */
#define ET_MAXQt 0x13
#define ET_MINQt 0x14
#define ET_COMP_VAL0 0x02
#define ET_COMP_VAL1 0x03

#define ET_REG1d 0x1d
#define ET_REG1e 0x1e
#define ET_REG1f 0x1f
#define ET_REG20 0x20
#define ET_REG21 0x21
#define ET_REG22 0x22
#define ET_REG23 0x23
#define ET_REG24 0x24
#define ET_REG25 0x25
/* base registers for luma calculation */
#define ET_LUMA_CENTER 0x39

#define ET_G_RED 0x4d
#define ET_G_GREEN1 0x4e
#define ET_G_BLUE 0x4f
#define ET_G_GREEN2 0x50
#define ET_G_GR_H 0x51
#define ET_G_GB_H 0x52

#define ET_O_RED 0x34
#define ET_O_GREEN1 0x35
#define ET_O_BLUE 0x36
#define ET_O_GREEN2 0x37

#define ET_SYNCHRO 0x68
#define ET_STARTX 0x69
#define ET_STARTY 0x6a
#define ET_WIDTH_LOW 0x6b
#define ET_HEIGTH_LOW 0x6c
#define ET_W_H_HEIGTH 0x6d

#define ET_REG6e 0x6e		/* OBW */
#define ET_REG6f 0x6f		/* OBW */
#define ET_REG70 0x70		/* OBW_AWB */
#define ET_REG71 0x71		/* OBW_AWB */
#define ET_REG72 0x72		/* OBW_AWB */
#define ET_REG73 0x73		/* Clkdelay ns */
#define ET_REG74 0x74		/* test pattern */
#define ET_REG75 0x75		/* test pattern */

#define ET_I2C_CLK 0x8c
#define ET_PXL_CLK 0x60

#define ET_I2C_BASE 0x89
#define ET_I2C_COUNT 0x8a
#define ET_I2C_PREFETCH 0x8b
#define ET_I2C_REG 0x88
#define ET_I2C_DATA7 0x87
#define ET_I2C_DATA6 0x86
#define ET_I2C_DATA5 0x85
#define ET_I2C_DATA4 0x84
#define ET_I2C_DATA3 0x83
#define ET_I2C_DATA2 0x82
#define ET_I2C_DATA1 0x81
#define ET_I2C_DATA0 0x80

#define PAS106_REG2 0x02	/* pxlClk = systemClk/(reg2) */
#define PAS106_REG3 0x03	/* line/frame H [11..4] */
#define PAS106_REG4 0x04	/* line/frame L [3..0] */
#define PAS106_REG5 0x05	/* exposure time line offset(default 5) */
#define PAS106_REG6 0x06	/* exposure time pixel offset(default 6) */
#define PAS106_REG7 0x07	/* signbit Dac (default 0) */
#define PAS106_REG9 0x09
#define PAS106_REG0e 0x0e	/* global gain [4..0](default 0x0e) */
#define PAS106_REG13 0x13	/* end i2c write */

static __u8 GainRGBG[] = { 0x80, 0x80, 0x80, 0x80, 0x00, 0x00 };

static __u8 I2c2[] = { 0x08, 0x08, 0x08, 0x08, 0x0d };

static __u8 I2c3[] = { 0x12, 0x05 };

static __u8 I2c4[] = { 0x41, 0x08 };

static void Et_RegRead(struct usb_device *dev,
		       __u16 index, __u8 *buffer, int len)
{
	usb_control_msg(dev,
			usb_rcvctrlpipe(dev, 0),
			0,
			USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_INTERFACE,
			0, index, buffer, len, 500);
}

static void Et_RegWrite(struct usb_device *dev,
			__u16 index, __u8 *buffer, __u16 len)
{
	usb_control_msg(dev,
			usb_sndctrlpipe(dev, 0),
			0,
			USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_INTERFACE,
			0, index, buffer, len, 500);
}

static int Et_i2cwrite(struct usb_device *dev, __u8 reg, __u8 *buffer,
		       __u16 length, __u8 mode)
{
/* buffer should be [D0..D7] */
	int i, j;
	__u8 base = 0x40;	/* sensor base for the pas106 */
	__u8 ptchcount = 0;

	ptchcount = (((length & 0x07) << 4) | (mode & 0x03));
/* set the base address */
	Et_RegWrite(dev, ET_I2C_BASE, &base, 1);
/* set count and prefetch */
	Et_RegWrite(dev, ET_I2C_COUNT, &ptchcount, 1);
/* set the register base */
	Et_RegWrite(dev, ET_I2C_REG, &reg, 1);
	j = length - 1;
	for (i = 0; i < length; i++) {
		Et_RegWrite(dev, (ET_I2C_DATA0 + j), &buffer[j], 1);
		j--;
	}
	return 0;
}

static int Et_i2cread(struct usb_device *dev, __u8 reg, __u8 *buffer,
		      __u16 length, __u8 mode)
{
/* buffer should be [D0..D7] */
	int i, j;
	__u8 base = 0x40;	/* sensor base for the pas106 */
	__u8 ptchcount;
	__u8 prefetch = 0x02;

	ptchcount = (((length & 0x07) << 4) | (mode & 0x03));
/* set the base address */
	Et_RegWrite(dev, ET_I2C_BASE, &base, 1);
/* set count and prefetch */
	Et_RegWrite(dev, ET_I2C_COUNT, &ptchcount, 1);
/* set the register base */
	Et_RegWrite(dev, ET_I2C_REG, &reg, 1);
	Et_RegWrite(dev, ET_I2C_PREFETCH, &prefetch, 1);
	prefetch = 0x00;
	Et_RegWrite(dev, ET_I2C_PREFETCH, &prefetch, 1);
	j = length - 1;
	for (i = 0; i < length; i++) {
		Et_RegRead(dev, (ET_I2C_DATA0 + j), &buffer[j], 1);
		j--;
	}
	return 0;
}

static int Et_WaitStatus(struct usb_device *dev)
{
	__u8 bytereceived;
	int retry = 10;

	while (retry--) {
		Et_RegRead(dev, ET_ClCK, &bytereceived, 1);
		if (bytereceived != 0)
			return 1;
	}
	return 0;
}

static int Et_videoOff(struct usb_device *dev)
{
	int err;
	__u8 stopvideo = 0;

	Et_RegWrite(dev, ET_GPIO_OUT, &stopvideo, 1);
	err = Et_WaitStatus(dev);
	if (!err)
		PDEBUG(D_ERR, "timeout Et_waitStatus VideoON");
	return err;
}

static int Et_videoOn(struct usb_device *dev)
{
	int err;
	__u8 startvideo = 0x10;	/* set Bit5 */

	Et_RegWrite(dev, ET_GPIO_OUT, &startvideo, 1);
	err = Et_WaitStatus(dev);
	if (!err)
		PDEBUG(D_ERR, "timeout Et_waitStatus VideoOFF");
	return err;
}

static void Et_init2(struct gspca_dev *gspca_dev)
{
	struct usb_device *dev = gspca_dev->dev;
	__u8 value = 0x00;
	__u8 received = 0x00;
	__u8 FormLine[] = { 0x84, 0x03, 0x14, 0xf4, 0x01, 0x05 };

	PDEBUG(D_STREAM, "Open Init2 ET");
	value = 0x2f;
	Et_RegWrite(dev, ET_GPIO_DIR_CTRL, &value, 1);
	value = 0x10;
	Et_RegWrite(dev, ET_GPIO_OUT, &value, 1);
	Et_RegRead(dev, ET_GPIO_IN, &received, 1);
	value = 0x14;		/* 0x14 // 0x16 enabled pattern */
	Et_RegWrite(dev, ET_ClCK, &value, 1);
	value = 0x1b;
	Et_RegWrite(dev, ET_CTRL, &value, 1);

	/*  compression et subsampling */
	if (gspca_dev->cam.cam_mode[(int) gspca_dev->curr_mode].mode)
		value = ET_COMP_VAL1;	/* 320 */
	else
		value = ET_COMP_VAL0;	/* 640 */
	Et_RegWrite(dev, ET_COMP, &value, 1);
	value = 0x1f;
	Et_RegWrite(dev, ET_MAXQt, &value, 1);
	value = 0x04;
	Et_RegWrite(dev, ET_MINQt, &value, 1);
	/* undocumented registers */
	value = 0xff;
	Et_RegWrite(dev, ET_REG1d, &value, 1);
	value = 0xff;
	Et_RegWrite(dev, ET_REG1e, &value, 1);
	value = 0xff;
	Et_RegWrite(dev, ET_REG1f, &value, 1);
	value = 0x35;
	Et_RegWrite(dev, ET_REG20, &value, 1);
	value = 0x01;
	Et_RegWrite(dev, ET_REG21, &value, 1);
	value = 0x00;
	Et_RegWrite(dev, ET_REG22, &value, 1);
	value = 0xff;
	Et_RegWrite(dev, ET_REG23, &value, 1);
	value = 0xff;
	Et_RegWrite(dev, ET_REG24, &value, 1);
	value = 0x0f;
	Et_RegWrite(dev, ET_REG25, &value, 1);
	/* colors setting */
	value = 0x11;
	Et_RegWrite(dev, 0x30, &value, 1);	/* 0x30 */
	value = 0x40;
	Et_RegWrite(dev, 0x31, &value, 1);
	value = 0x00;
	Et_RegWrite(dev, 0x32, &value, 1);
	value = 0x00;
	Et_RegWrite(dev, ET_O_RED, &value, 1);	/* 0x34 */
	value = 0x00;
	Et_RegWrite(dev, ET_O_GREEN1, &value, 1);
	value = 0x00;
	Et_RegWrite(dev, ET_O_BLUE, &value, 1);
	value = 0x00;
	Et_RegWrite(dev, ET_O_GREEN2, &value, 1);
	/*************/
	value = 0x80;
	Et_RegWrite(dev, ET_G_RED, &value, 1);	/* 0x4d */
	value = 0x80;
	Et_RegWrite(dev, ET_G_GREEN1, &value, 1);
	value = 0x80;
	Et_RegWrite(dev, ET_G_BLUE, &value, 1);
	value = 0x80;
	Et_RegWrite(dev, ET_G_GREEN2, &value, 1);
	value = 0x00;
	Et_RegWrite(dev, ET_G_GR_H, &value, 1);
	value = 0x00;
	Et_RegWrite(dev, ET_G_GB_H, &value, 1);	/* 0x52 */
	/* Window control registers */

	value = 0x80;		/* use cmc_out */
	Et_RegWrite(dev, 0x61, &value, 1);

	value = 0x02;
	Et_RegWrite(dev, 0x62, &value, 1);
	value = 0x03;
	Et_RegWrite(dev, 0x63, &value, 1);
	value = 0x14;
	Et_RegWrite(dev, 0x64, &value, 1);
	value = 0x0e;
	Et_RegWrite(dev, 0x65, &value, 1);
	value = 0x02;
	Et_RegWrite(dev, 0x66, &value, 1);
	value = 0x02;
	Et_RegWrite(dev, 0x67, &value, 1);

	/**************************************/
	value = 0x8f;
	Et_RegWrite(dev, ET_SYNCHRO, &value, 1);	/* 0x68 */
	value = 0x69;		/* 0x6a //0x69 */
	Et_RegWrite(dev, ET_STARTX, &value, 1);
	value = 0x0d;		/* 0x0d //0x0c */
	Et_RegWrite(dev, ET_STARTY, &value, 1);
	value = 0x80;
	Et_RegWrite(dev, ET_WIDTH_LOW, &value, 1);
	value = 0xe0;
	Et_RegWrite(dev, ET_HEIGTH_LOW, &value, 1);
	value = 0x60;
	Et_RegWrite(dev, ET_W_H_HEIGTH, &value, 1);	/* 6d */
	value = 0x86;
	Et_RegWrite(dev, ET_REG6e, &value, 1);
	value = 0x01;
	Et_RegWrite(dev, ET_REG6f, &value, 1);
	value = 0x26;
	Et_RegWrite(dev, ET_REG70, &value, 1);
	value = 0x7a;
	Et_RegWrite(dev, ET_REG71, &value, 1);
	value = 0x01;
	Et_RegWrite(dev, ET_REG72, &value, 1);
	/* Clock Pattern registers ***************** */
	value = 0x00;
	Et_RegWrite(dev, ET_REG73, &value, 1);
	value = 0x18;		/* 0x28 */
	Et_RegWrite(dev, ET_REG74, &value, 1);
	value = 0x0f;		/* 0x01 */
	Et_RegWrite(dev, ET_REG75, &value, 1);
	/**********************************************/
	value = 0x20;
	Et_RegWrite(dev, 0x8a, &value, 1);
	value = 0x0f;
	Et_RegWrite(dev, 0x8d, &value, 1);
	value = 0x08;
	Et_RegWrite(dev, 0x8e, &value, 1);
	/**************************************/
	value = 0x08;
	Et_RegWrite(dev, 0x03, &value, 1);
	value = 0x03;
	Et_RegWrite(dev, ET_PXL_CLK, &value, 1);
	value = 0xff;
	Et_RegWrite(dev, 0x81, &value, 1);
	value = 0x00;
	Et_RegWrite(dev, 0x80, &value, 1);
	value = 0xff;
	Et_RegWrite(dev, 0x81, &value, 1);
	value = 0x20;
	Et_RegWrite(dev, 0x80, &value, 1);
	value = 0x01;
	Et_RegWrite(dev, 0x03, &value, 1);
	value = 0x00;
	Et_RegWrite(dev, 0x03, &value, 1);
	value = 0x08;
	Et_RegWrite(dev, 0x03, &value, 1);
	/********************************************/

	/* Et_RegRead(dev,0x0,ET_I2C_BASE,&received,1);
					 always 0x40 as the pas106 ??? */
	/* set the sensor */
	if (gspca_dev->cam.cam_mode[(int) gspca_dev->curr_mode].mode) {
		value = 0x04;	/* 320 */
		Et_RegWrite(dev, ET_PXL_CLK, &value, 1);
		/* now set by fifo the FormatLine setting */
		Et_RegWrite(dev, 0x62, FormLine, 6);
	} else {		/* 640 */
		/* setting PixelClock
		   0x03 mean 24/(3+1) = 6 Mhz
		   0x05 -> 24/(5+1) = 4 Mhz
		   0x0b -> 24/(11+1) = 2 Mhz
		   0x17 -> 24/(23+1) = 1 Mhz
		 */
		value = 0x1e;	/* 0x17 */
		Et_RegWrite(dev, ET_PXL_CLK, &value, 1);
		/* now set by fifo the FormatLine setting */
		Et_RegWrite(dev, 0x62, FormLine, 6);
	}

	/* set exposure times [ 0..0x78] 0->longvalue 0x78->shortvalue */
	value = 0x47;		/* 0x47; */
	Et_RegWrite(dev, 0x81, &value, 1);
	value = 0x40;		/* 0x40; */
	Et_RegWrite(dev, 0x80, &value, 1);
	/* Pedro change */
	/* Brightness change Brith+ decrease value */
	/* Brigth- increase value */
	/* original value = 0x70; */
	value = 0x30;		/* 0x20; */
	Et_RegWrite(dev, 0x81, &value, 1);	/* set brightness */
	value = 0x20;		/* 0x20; */
	Et_RegWrite(dev, 0x80, &value, 1);
}

static void setcolors(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *) gspca_dev;
	struct usb_device *dev = gspca_dev->dev;
	static __u8 I2cc[] = { 0x05, 0x02, 0x02, 0x05, 0x0d };
	__u8 i2cflags = 0x01;
	/* __u8 green = 0; */
	__u8 colors = sd->colors;

	I2cc[3] = colors;	/* red */
	I2cc[0] = 15 - colors;	/* blue */
	/* green = 15 - ((((7*I2cc[0]) >> 2 ) + I2cc[3]) >> 1); */
	/* I2cc[1] = I2cc[2] = green; */
	if (sd->sensor == SENSOR_PAS106) {
		Et_i2cwrite(dev, PAS106_REG13, &i2cflags, 1, 3);
		Et_i2cwrite(dev, PAS106_REG9, I2cc, sizeof(I2cc), 1);
	}
/*	PDEBUG(D_CONF , "Etoms red %d blue %d green %d",
		I2cc[3], I2cc[0], green); */
}

static void getcolors(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *) gspca_dev;
	/* __u8 valblue = 0; */
	__u8 valred;

	if (sd->sensor == SENSOR_PAS106) {
		/* Et_i2cread(gspca_dev->dev,PAS106_REG9,&valblue,1,1); */
		Et_i2cread(gspca_dev->dev, PAS106_REG9 + 3, &valred, 1, 1);
		sd->colors = valred & 0x0f;
	}
}

static void Et_init1(struct gspca_dev *gspca_dev)
{
	struct usb_device *dev = gspca_dev->dev;
	__u8 value = 0x00;
	__u8 received = 0x00;
/*	__u8 I2c0 [] ={0x0a,0x12,0x05,0x22,0xac,0x00,0x01,0x00}; */
	__u8 I2c0[] = { 0x0a, 0x12, 0x05, 0x6d, 0xcd, 0x00, 0x01, 0x00 };
						/* try 1/120 0x6d 0xcd 0x40 */
/*	__u8 I2c0 [] ={0x0a,0x12,0x05,0xfe,0xfe,0xc0,0x01,0x00};
						 * 1/60000 hmm ?? */

	PDEBUG(D_STREAM, "Open Init1 ET");
	value = 7;
	Et_RegWrite(dev, ET_GPIO_DIR_CTRL, &value, 1);
	Et_RegRead(dev, ET_GPIO_IN, &received, 1);
	value = 1;
	Et_RegWrite(dev, ET_RESET_ALL, &value, 1);
	value = 0;
	Et_RegWrite(dev, ET_RESET_ALL, &value, 1);
	value = 0x10;
	Et_RegWrite(dev, ET_ClCK, &value, 1);
	value = 0x19;
	Et_RegWrite(dev, ET_CTRL, &value, 1);
	/*   compression et subsampling */
	if (gspca_dev->cam.cam_mode[(int) gspca_dev->curr_mode].mode)
		value = ET_COMP_VAL1;
	else
		value = ET_COMP_VAL0;

	PDEBUG(D_STREAM, "Open mode %d Compression %d",
	       gspca_dev->cam.cam_mode[(int) gspca_dev->curr_mode].mode,
	       value);
	Et_RegWrite(dev, ET_COMP, &value, 1);
	value = 0x1d;
	Et_RegWrite(dev, ET_MAXQt, &value, 1);
	value = 0x02;
	Et_RegWrite(dev, ET_MINQt, &value, 1);
	/* undocumented registers */
	value = 0xff;
	Et_RegWrite(dev, ET_REG1d, &value, 1);
	value = 0xff;
	Et_RegWrite(dev, ET_REG1e, &value, 1);
	value = 0xff;
	Et_RegWrite(dev, ET_REG1f, &value, 1);
	value = 0x35;
	Et_RegWrite(dev, ET_REG20, &value, 1);
	value = 0x01;
	Et_RegWrite(dev, ET_REG21, &value, 1);
	value = 0x00;
	Et_RegWrite(dev, ET_REG22, &value, 1);
	value = 0xf7;
	Et_RegWrite(dev, ET_REG23, &value, 1);
	value = 0xff;
	Et_RegWrite(dev, ET_REG24, &value, 1);
	value = 0x07;
	Et_RegWrite(dev, ET_REG25, &value, 1);
	/* colors setting */
	value = 0x80;
	Et_RegWrite(dev, ET_G_RED, &value, 1);
	value = 0x80;
	Et_RegWrite(dev, ET_G_GREEN1, &value, 1);
	value = 0x80;
	Et_RegWrite(dev, ET_G_BLUE, &value, 1);
	value = 0x80;
	Et_RegWrite(dev, ET_G_GREEN2, &value, 1);
	value = 0x00;
	Et_RegWrite(dev, ET_G_GR_H, &value, 1);
	value = 0x00;
	Et_RegWrite(dev, ET_G_GB_H, &value, 1);
	/* Window control registers */
	value = 0xf0;
	Et_RegWrite(dev, ET_SYNCHRO, &value, 1);
	value = 0x56;		/* 0x56 */
	Et_RegWrite(dev, ET_STARTX, &value, 1);
	value = 0x05;		/* 0x04 */
	Et_RegWrite(dev, ET_STARTY, &value, 1);
	value = 0x60;
	Et_RegWrite(dev, ET_WIDTH_LOW, &value, 1);
	value = 0x20;
	Et_RegWrite(dev, ET_HEIGTH_LOW, &value, 1);
	value = 0x50;
	Et_RegWrite(dev, ET_W_H_HEIGTH, &value, 1);
	value = 0x86;
	Et_RegWrite(dev, ET_REG6e, &value, 1);
	value = 0x01;
	Et_RegWrite(dev, ET_REG6f, &value, 1);
	value = 0x86;
	Et_RegWrite(dev, ET_REG70, &value, 1);
	value = 0x14;
	Et_RegWrite(dev, ET_REG71, &value, 1);
	value = 0x00;
	Et_RegWrite(dev, ET_REG72, &value, 1);
	/* Clock Pattern registers */
	value = 0x00;
	Et_RegWrite(dev, ET_REG73, &value, 1);
	value = 0x00;
	Et_RegWrite(dev, ET_REG74, &value, 1);
	value = 0x0a;
	Et_RegWrite(dev, ET_REG75, &value, 1);
	value = 0x04;
	Et_RegWrite(dev, ET_I2C_CLK, &value, 1);
	value = 0x01;
	Et_RegWrite(dev, ET_PXL_CLK, &value, 1);
	/* set the sensor */
	if (gspca_dev->cam.cam_mode[(int) gspca_dev->curr_mode].mode) {
		I2c0[0] = 0x06;
		Et_i2cwrite(dev, PAS106_REG2, I2c0, sizeof(I2c0), 1);
		Et_i2cwrite(dev, PAS106_REG9, I2c2, sizeof(I2c2), 1);
		value = 0x06;
		Et_i2cwrite(dev, PAS106_REG2, &value, 1, 1);
		Et_i2cwrite(dev, PAS106_REG3, I2c3, sizeof(I2c3), 1);
		/* value = 0x1f; */
		value = 0x04;
		Et_i2cwrite(dev, PAS106_REG0e, &value, 1, 1);
	} else {
		I2c0[0] = 0x0a;

		Et_i2cwrite(dev, PAS106_REG2, I2c0, sizeof(I2c0), 1);
		Et_i2cwrite(dev, PAS106_REG9, I2c2, sizeof(I2c2), 1);
		value = 0x0a;

		Et_i2cwrite(dev, PAS106_REG2, &value, 1, 1);
		Et_i2cwrite(dev, PAS106_REG3, I2c3, sizeof(I2c3), 1);
		value = 0x04;
		/* value = 0x10; */
		Et_i2cwrite(dev, PAS106_REG0e, &value, 1, 1);
		/* bit 2 enable bit 1:2 select 0 1 2 3
		   value = 0x07;                                * curve 0 *
		   Et_i2cwrite(dev,PAS106_REG0f,&value,1,1);
		 */
	}

/*	value = 0x01; */
/*	value = 0x22; */
/*	Et_i2cwrite(dev, PAS106_REG5, &value, 1, 1); */
	/* magnetude and sign bit for DAC */
	Et_i2cwrite(dev, PAS106_REG7, I2c4, sizeof I2c4, 1);
	/* now set by fifo the whole colors setting */
	Et_RegWrite(dev, ET_G_RED, GainRGBG, 6);
	getcolors(gspca_dev);
	setcolors(gspca_dev);
}

/* this function is called at probe time */
static int sd_config(struct gspca_dev *gspca_dev,
		     const struct usb_device_id *id)
{
	struct sd *sd = (struct sd *) gspca_dev;
	struct cam *cam;
	__u16 vendor;
	__u16 product;

	vendor = id->idVendor;
	product = id->idProduct;
/*	switch (vendor) { */
/*	case 0x102c:		* Etoms */
		switch (product) {
		case 0x6151:
			sd->sensor = SENSOR_PAS106;	/* Etoms61x151 */
			break;
		case 0x6251:
			sd->sensor = SENSOR_TAS5130CXX;	/* Etoms61x251 */
			break;
/*		} */
/*		break; */
	}
	cam = &gspca_dev->cam;
	cam->dev_name = (char *) id->driver_info;
	cam->epaddr = 1;
	if (sd->sensor == SENSOR_PAS106) {
		cam->cam_mode = sif_mode;
		cam->nmodes = sizeof sif_mode / sizeof sif_mode[0];
	} else {
		cam->cam_mode = vga_mode;
		cam->nmodes = sizeof vga_mode / sizeof vga_mode[0];
	}
	sd->brightness = sd_ctrls[SD_BRIGHTNESS].qctrl.default_value;
	sd->contrast = sd_ctrls[SD_CONTRAST].qctrl.default_value;
	sd->colors = sd_ctrls[SD_COLOR].qctrl.default_value;
	sd->autogain = sd_ctrls[SD_AUTOGAIN].qctrl.default_value;
	return 0;
}

/* this function is called at open time */
static int sd_open(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *) gspca_dev;
	struct usb_device *dev = gspca_dev->dev;
	int err;
	__u8 value;

	PDEBUG(D_STREAM, "Initialize ET1");
	if (sd->sensor == SENSOR_PAS106)
		Et_init1(gspca_dev);
	else
		Et_init2(gspca_dev);
	value = 0x08;
	Et_RegWrite(dev, ET_RESET_ALL, &value, 1);
	err = Et_videoOff(dev);
	PDEBUG(D_STREAM, "Et_Init_VideoOff %d", err);
	return 0;
}

/* -- start the camera -- */
static void sd_start(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *) gspca_dev;
	struct usb_device *dev = gspca_dev->dev;
	int err;
	__u8 value;

	if (sd->sensor == SENSOR_PAS106)
		Et_init1(gspca_dev);
	else
		Et_init2(gspca_dev);

	value = 0x08;
	Et_RegWrite(dev, ET_RESET_ALL, &value, 1);
	err = Et_videoOn(dev);
	PDEBUG(D_STREAM, "Et_VideoOn %d", err);
}

static void sd_stopN(struct gspca_dev *gspca_dev)
{
	int err;

	err = Et_videoOff(gspca_dev->dev);
	PDEBUG(D_STREAM, "Et_VideoOff %d", err);

}

static void sd_stop0(struct gspca_dev *gspca_dev)
{
}

static void sd_close(struct gspca_dev *gspca_dev)
{
}

static void setbrightness(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *) gspca_dev;
	int i;
	__u8 brightness = sd->brightness;

	for (i = 0; i < 4; i++)
		Et_RegWrite(gspca_dev->dev, (ET_O_RED + i), &brightness, 1);
}

static void getbrightness(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *) gspca_dev;
	int i;
	int brightness = 0;
	__u8 value = 0;

	for (i = 0; i < 4; i++) {
		Et_RegRead(gspca_dev->dev, (ET_O_RED + i), &value, 1);
		brightness += value;
	}
	sd->brightness = brightness >> 3;
}

static void setcontrast(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *) gspca_dev;
	__u8 RGBG[] = { 0x80, 0x80, 0x80, 0x80, 0x00, 0x00 };
	__u8 contrast = sd->contrast;

	memset(RGBG, contrast, sizeof RGBG - 2);
	Et_RegWrite(gspca_dev->dev, ET_G_RED, RGBG, 6);
}

static void getcontrast(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *) gspca_dev;
	int i;
	int contrast = 0;
	__u8 value = 0;

	for (i = 0; i < 4; i++) {
		Et_RegRead(gspca_dev->dev, (ET_G_RED + i), &value, 1);
		contrast += value;
	}
	sd->contrast = contrast >> 2;
}

static __u8 Et_getgainG(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *) gspca_dev;
	__u8 value = 0;

	if (sd->sensor == SENSOR_PAS106) {
		Et_i2cread(gspca_dev->dev, PAS106_REG0e, &value, 1, 1);
		PDEBUG(D_CONF, "Etoms gain G %d", value);
		return value;
	}
	return 0x1f;
}

static void Et_setgainG(struct gspca_dev *gspca_dev, __u8 gain)
{
	struct sd *sd = (struct sd *) gspca_dev;
	struct usb_device *dev = gspca_dev->dev;
	__u8 i2cflags = 0x01;

	if (sd->sensor == SENSOR_PAS106) {
		Et_i2cwrite(dev, PAS106_REG13, &i2cflags, 1, 3);
		Et_i2cwrite(dev, PAS106_REG0e, &gain, 1, 1);
	}
}

#define BLIMIT(bright) \
	(__u8)((bright > 0x1f)?0x1f:((bright < 4)?3:bright))
#define LIMIT(color) \
	(unsigned char)((color > 0xff)?0xff:((color < 0)?0:color))

static void setautogain(struct gspca_dev *gspca_dev)
{
	struct usb_device *dev = gspca_dev->dev;
	__u8 GRBG[] = { 0, 0, 0, 0 };
	__u8 luma = 0;
	__u8 luma_mean = 128;
	__u8 luma_delta = 20;
	__u8 spring = 4;
	int Gbright = 0;
	__u8 r, g, b;

	Gbright = Et_getgainG(gspca_dev);
	Et_RegRead(dev, ET_LUMA_CENTER, GRBG, 4);
	g = (GRBG[0] + GRBG[3]) >> 1;
	r = GRBG[1];
	b = GRBG[2];
	r = ((r << 8) - (r << 4) - (r << 3)) >> 10;
	b = ((b << 7) >> 10);
	g = ((g << 9) + (g << 7) + (g << 5)) >> 10;
	luma = LIMIT(r + g + b);
	PDEBUG(D_FRAM, "Etoms luma G %d", luma);
	if (luma < luma_mean - luma_delta || luma > luma_mean + luma_delta) {
		Gbright += (luma_mean - luma) >> spring;
		Gbright = BLIMIT(Gbright);
		PDEBUG(D_FRAM, "Etoms Gbright %d", Gbright);
		Et_setgainG(gspca_dev, (__u8) Gbright);
	}
}

#undef BLIMIT
#undef LIMIT

static void sd_pkt_scan(struct gspca_dev *gspca_dev,
			struct gspca_frame *frame,	/* target */
			unsigned char *data,		/* isoc packet */
			int len)			/* iso packet length */
{
	struct sd *sd;
	int seqframe;

	seqframe = data[0] & 0x3f;
	len = (int) (((data[0] & 0xc0) << 2) | data[1]);
	if (seqframe == 0x3f) {
		PDEBUG(D_FRAM,
		       "header packet found datalength %d !!", len);
		PDEBUG(D_FRAM, "G %d R %d G %d B %d",
		       data[2], data[3], data[4], data[5]);
		data += 30;
		/* don't change datalength as the chips provided it */
		frame = gspca_frame_add(gspca_dev, LAST_PACKET, frame,
					data, 0);
		gspca_frame_add(gspca_dev, FIRST_PACKET, frame, data, len);
		sd = (struct sd *) gspca_dev;
		if (sd->ag_cnt >= 0) {
			if (--sd->ag_cnt < 0) {
				sd->ag_cnt = AG_CNT_START;
				setautogain(gspca_dev);
			}
		}
		return;
	}
	if (len) {
		data += 8;
		gspca_frame_add(gspca_dev, INTER_PACKET, frame, data, len);
	} else {			/* Drop Packet */
		gspca_dev->last_packet_type = DISCARD_PACKET;
	}
}

static int sd_setbrightness(struct gspca_dev *gspca_dev, __s32 val)
{
	struct sd *sd = (struct sd *) gspca_dev;

	sd->brightness = val;
	if (gspca_dev->streaming)
		setbrightness(gspca_dev);
	return 0;
}

static int sd_getbrightness(struct gspca_dev *gspca_dev, __s32 *val)
{
	struct sd *sd = (struct sd *) gspca_dev;

	getbrightness(gspca_dev);
	*val = sd->brightness;
	return 0;
}

static int sd_setcontrast(struct gspca_dev *gspca_dev, __s32 val)
{
	struct sd *sd = (struct sd *) gspca_dev;

	sd->contrast = val;
	if (gspca_dev->streaming)
		setcontrast(gspca_dev);
	return 0;
}

static int sd_getcontrast(struct gspca_dev *gspca_dev, __s32 *val)
{
	struct sd *sd = (struct sd *) gspca_dev;

	getcontrast(gspca_dev);
	*val = sd->contrast;
	return 0;
}

static int sd_setcolors(struct gspca_dev *gspca_dev, __s32 val)
{
	struct sd *sd = (struct sd *) gspca_dev;

	sd->colors = val;
	if (gspca_dev->streaming)
		setcolors(gspca_dev);
	return 0;
}

static int sd_getcolors(struct gspca_dev *gspca_dev, __s32 *val)
{
	struct sd *sd = (struct sd *) gspca_dev;

	getcolors(gspca_dev);
	*val = sd->colors;
	return 0;
}

static int sd_setautogain(struct gspca_dev *gspca_dev, __s32 val)
{
	struct sd *sd = (struct sd *) gspca_dev;

	sd->autogain = val;
	if (val)
		sd->ag_cnt = AG_CNT_START;
	else
		sd->ag_cnt = -1;
	return 0;
}

static int sd_getautogain(struct gspca_dev *gspca_dev, __s32 *val)
{
	struct sd *sd = (struct sd *) gspca_dev;

	*val = sd->autogain;
	return 0;
}

/* sub-driver description */
static struct sd_desc sd_desc = {
	.name = MODULE_NAME,
	.ctrls = sd_ctrls,
	.nctrls = ARRAY_SIZE(sd_ctrls),
	.config = sd_config,
	.open = sd_open,
	.start = sd_start,
	.stopN = sd_stopN,
	.stop0 = sd_stop0,
	.close = sd_close,
	.pkt_scan = sd_pkt_scan,
};

/* -- module initialisation -- */
#define DVNM(name) .driver_info = (kernel_ulong_t) name
static __devinitdata struct usb_device_id device_table[] = {
	{USB_DEVICE(0x102c, 0x6151), DVNM("Qcam Sangha CIF")},
	{USB_DEVICE(0x102c, 0x6251), DVNM("Qcam xxxxxx VGA")},
	{}
};

MODULE_DEVICE_TABLE(usb, device_table);

/* -- device connect -- */
static int sd_probe(struct usb_interface *intf,
		    const struct usb_device_id *id)
{
	return gspca_dev_probe(intf, id, &sd_desc, sizeof(struct sd),
			       THIS_MODULE);
}

static struct usb_driver sd_driver = {
	.name = MODULE_NAME,
	.id_table = device_table,
	.probe = sd_probe,
	.disconnect = gspca_disconnect,
};

/* -- module insert / remove -- */
static int __init sd_mod_init(void)
{
	if (usb_register(&sd_driver) < 0)
		return -1;
	PDEBUG(D_PROBE, "v%s registered", version);
	return 0;
}

static void __exit sd_mod_exit(void)
{
	usb_deregister(&sd_driver);
	PDEBUG(D_PROBE, "deregistered");
}

module_init(sd_mod_init);
module_exit(sd_mod_exit);
