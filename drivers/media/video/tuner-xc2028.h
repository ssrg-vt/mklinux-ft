/* tuner-xc2028
 *
 * Copyright (c) 2007 Mauro Carvalho Chehab (mchehab@infradead.org)
 * This code is placed under the terms of the GNU General Public License v2
 */

#ifndef __TUNER_XC2028_H__
#define __TUNER_XC2028_H__

#include "dvb_frontend.h"

#define XC2028_DEFAULT_FIRMWARE "xc3028-v27.fw"

struct xc2028_ctrl {
	char			*fname;
	int			max_len;
	unsigned int		scode_table;
	unsigned int		mts   :1;
	unsigned int		d2633 :1;
	unsigned int		input1:1;
};

struct xc2028_config {
	struct i2c_adapter *i2c_adap;
	u8 		   i2c_addr;
	void               *video_dev;
	struct xc2028_ctrl *ctrl;
	int                (*callback) (void *dev, int command, int arg);
};

/* xc2028 commands for callback */
#define XC2028_TUNER_RESET	0
#define XC2028_RESET_CLK	1

#if defined(CONFIG_TUNER_XC2028) || (defined(CONFIG_TUNER_XC2028_MODULE) && defined(MODULE))
void *xc2028_attach(struct dvb_frontend *fe, struct xc2028_config *cfg);
#else
void *xc2028_attach(struct dvb_frontend *fe,
				struct xc2028_config *cfg)
{
	printk(KERN_INFO "%s: not probed - driver disabled by Kconfig\n",
	       __FUNCTION__);
	return -EINVAL;
}
#endif

#endif /* __TUNER_XC2028_H__ */
