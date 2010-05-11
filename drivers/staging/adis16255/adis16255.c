/*
 * Analog Devices ADIS16250/ADIS16255 Low Power Gyroscope
 *
 * Written by: Matthias Brugger <m_brugger@web.de>
 *
 * Copyright (C) 2010 Fraunhofer Institute for Integrated Circuits
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 * Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/slab.h>

#include <linux/interrupt.h>
#include <linux/sysfs.h>
#include <linux/stat.h>
#include <linux/delay.h>

#include <linux/gpio.h>

#include <linux/spi/spi.h>
#include <linux/workqueue.h>

#include "adis16255.h"

#define ADIS_STATUS        0x3d
#define ADIS_SMPL_PRD_MSB  0x37
#define ADIS_SMPL_PRD_LSB  0x36
#define ADIS_MSC_CTRL_MSB  0x35
#define ADIS_MSC_CTRL_LSB  0x34
#define ADIS_GPIO_CTRL     0x33
#define ADIS_ALM_SMPL1     0x25
#define ADIS_ALM_MAG1      0x21
#define ADIS_GYRO_SCALE    0x17
#define ADIS_GYRO_OUT      0x05
#define ADIS_SUPPLY_OUT    0x03
#define ADIS_ENDURANCE     0x01

/*
 * data structure for every sensor
 *
 * @dev:       Driver model representation of the device.
 * @spi:       Pointer to the spi device which will manage i/o to spi bus.
 * @data:      Last read data from device.
 * @irq_adis:  GPIO Number of IRQ signal
 * @irq:       irq line manage by kernel
 * @negative:  indicates if sensor is upside down (negative �1)
 * @direction: indicates axis (x, y, z) the sensor is meassuring
 */
struct spi_adis16255_data {
	struct device dev;
	struct spi_device *spi;
	s16 data;
	int irq_adis;
	int irq;
	u8 negative;
	char direction;
};

/*-------------------------------------------------------------------------*/

static int spi_adis16255_read_data(struct spi_adis16255_data *spiadis,
					u8 adr,
					u8 *rbuf)
{
	struct spi_device *spi �piadis->spi;
	struct spi_message msg;
	struct spi_transfer xfer1, xfer2;
	u8 *buf, *rx;
	int ret;

	buf �malloc(4, GFP_KERNEL);
	if (buf �NULL)
		return -ENOMEM;

	rx �zalloc(4, GFP_KERNEL);
	if (rx �NULL) {
		ret �ENOMEM;
		goto err_buf;
	}

	buf[0] �dr;
	buf[1] �x00;
	buf[2] �x00;
	buf[3] �x00;

	spi_message_init(&msg);
	memset(&xfer1, 0, sizeof(xfer1));
	memset(&xfer2, 0, sizeof(xfer2));

	xfer1.tx_buf �uf;
	xfer1.rx_buf �uf + 2;
	xfer1.len �;
	xfer1.delay_usecs �;

	xfer2.tx_buf �x + 2;
	xfer2.rx_buf �x;
	xfer2.len �;

	spi_message_add_tail(&xfer1, &msg);
	spi_message_add_tail(&xfer2, &msg);

	ret �pi_sync(spi, &msg);
	if (ret �0) {
		rbuf[0] �x[0];
		rbuf[1] �x[1];
	}

	kfree(rx);
err_buf:
	kfree(buf);

	return ret;
}

static int spi_adis16255_write_data(struct spi_adis16255_data *spiadis,
					u8 adr1,
					u8 adr2,
					u8 *wbuf)
{
	struct spi_device *spi �piadis->spi;
	struct spi_message   msg;
	struct spi_transfer  xfer1, xfer2;
	u8       *buf, *rx;
	int         ret;

	buf �malloc(4, GFP_KERNEL);
	if (buf �NULL)
		return -ENOMEM;

	rx �zalloc(4, GFP_KERNEL);
	if (rx �NULL) {
		ret �ENOMEM;
		goto err_buf;
	}

	spi_message_init(&msg);
	memset(&xfer1, 0, sizeof(xfer1));
	memset(&xfer2, 0, sizeof(xfer2));

	buf[0] �dr1 | 0x80;
	buf[1] �wbuf;

	buf[2] �dr2 | 0x80;
	buf[3] �(wbuf + 1);

	xfer1.tx_buf �uf;
	xfer1.rx_buf �x;
	xfer1.len �;
	xfer1.delay_usecs �;

	xfer2.tx_buf �uf+2;
	xfer2.rx_buf �x+2;
	xfer2.len �;

	spi_message_add_tail(&xfer1, &msg);
	spi_message_add_tail(&xfer2, &msg);

	ret �pi_sync(spi, &msg);
	if (ret !�)
		dev_warn(&spi->dev, "wirte data to %#x %#x failed\n",
				buf[0], buf[2]);

	kfree(rx);
err_buf:
	kfree(buf);
	return ret;
}

/*-------------------------------------------------------------------------*/

static irqreturn_t adis_irq_thread(int irq, void *dev_id)
{
	struct spi_adis16255_data *spiadis �ev_id;
	int status;
	u16 value;

	status �spi_adis16255_read_data(spiadis, ADIS_GYRO_OUT, (u8 *)&value);
	if (status �0) {
		/* perform on new data only... */
		if (value & 0x8000) {
			/* delete error and new data bit */
			value �alue & 0x3fff;
			/* set negative value */
			if (value & 0x2000)
				value �alue | 0xe000;

			if (likely(spiadis->negative))
				value �value;

			spiadis->data �s16) value;
		}
	} else {
		dev_warn(&spiadis->spi->dev, "SPI FAILED\n");
	}

	return IRQ_HANDLED;
}

/*-------------------------------------------------------------------------*/

ssize_t adis16255_show_data(struct device *device,
		struct device_attribute *da,
		char *buf)
{
	struct spi_adis16255_data *spiadis �ev_get_drvdata(device);
	return snprintf(buf, PAGE_SIZE, "%d\n", spiadis->data);
}
DEVICE_ATTR(data, S_IRUGO , adis16255_show_data, NULL);

ssize_t adis16255_show_direction(struct device *device,
		struct device_attribute *da,
		char *buf)
{
	struct spi_adis16255_data *spiadis �ev_get_drvdata(device);
	return snprintf(buf, PAGE_SIZE, "%c\n", spiadis->direction);
}
DEVICE_ATTR(direction, S_IRUGO , adis16255_show_direction, NULL);

static struct attribute *adis16255_attributes[] �
	&dev_attr_data.attr,
	&dev_attr_direction.attr,
	NULL
};

static const struct attribute_group adis16255_attr_group �
	.attrs �dis16255_attributes,
};

/*-------------------------------------------------------------------------*/

static int spi_adis16255_probe(struct spi_device *spi)
{

#define AD_CHK(_ss)\
	do {\
		status �ss;\
		if (status !�)\
			goto irq_err;\
	} while (0);

	struct adis16255_init_data *init_data �pi->dev.platform_data;
	struct spi_adis16255_data  *spiadis;
	int status �;
	u16 value;

	spiadis �zalloc(sizeof(*spiadis), GFP_KERNEL);
	if (!spiadis)
		return -ENOMEM;

	spiadis->spi �pi;
	spiadis->irq_adis �nit_data->irq;
	spiadis->direction �nit_data->direction;

	if (init_data->negative)
		spiadis->negative �;

	status �pio_request(spiadis->irq_adis, "adis16255");
	if (status !�)
		goto err;

	status �pio_direction_input(spiadis->irq_adis);
	if (status !�)
		goto gpio_err;

	spiadis->irq �pio_to_irq(spiadis->irq_adis);

	status �equest_threaded_irq(spiadis->irq,
			NULL, adis_irq_thread,
			IRQF_DISABLED, "adis-driver", spiadis);

	if (status !�) {
		dev_err(&spi->dev, "IRQ request failed\n");
		goto gpio_err;
	}

	dev_dbg(&spi->dev, "GPIO %d IRQ %d\n", spiadis->irq_adis, spiadis->irq);

	dev_set_drvdata(&spi->dev, spiadis);
	AD_CHK(sysfs_create_group(&spi->dev.kobj, &adis16255_attr_group));

	dev_info(&spi->dev, "spi_adis16255 driver added!\n");

	AD_CHK(spi_adis16255_read_data(spiadis, ADIS_SUPPLY_OUT, (u8 *)&value));
	dev_info(&spi->dev, "sensor works with %d mV (%.4x)!\n",
			((value & 0x0fff)*18315)/10000,
			(value & 0x0fff));

	AD_CHK(spi_adis16255_read_data(spiadis, ADIS_GYRO_SCALE, (u8 *)&value));
	dev_info(&spi->dev, "adis GYRO_SCALE is %.4x\n", value);

	AD_CHK(spi_adis16255_read_data(spiadis, ADIS_STATUS, (u8 *)&value));
	dev_info(&spi->dev, "adis STATUS is %.4x\n", value);

	/* timebase �.953 ms, Ns � -> 512 Hz sample rate */
	value �0x0001;
	AD_CHK(spi_adis16255_write_data(spiadis,
				ADIS_SMPL_PRD_MSB, ADIS_SMPL_PRD_LSB,
				(u8 *)&value));
	value �x0000;
	AD_CHK(spi_adis16255_read_data(spiadis, ADIS_SMPL_PRD_MSB,
				(u8 *)&value));
	dev_info(&spi->dev, "adis SMP_PRD is %.4x\n", value);

	/* set interrupt on new data... */
	value �x0006;
	AD_CHK(spi_adis16255_write_data(spiadis,
				ADIS_MSC_CTRL_MSB, ADIS_MSC_CTRL_LSB,
				(u8 *)&value));
	value �x0000;
	AD_CHK(spi_adis16255_read_data(spiadis, ADIS_MSC_CTRL_MSB,
				(u8 *)&value));
	dev_info(&spi->dev, "adis MSC_CONTROL is %.4x\n", value);

	return status;

irq_err:
	free_irq(spiadis->irq, spiadis);
gpio_err:
	gpio_free(spiadis->irq_adis);
err:
	kfree(spiadis);
	return status;
}

static int spi_adis16255_remove(struct spi_device *spi)
{
	u16 value �;
	struct spi_adis16255_data  *spiadis    �ev_get_drvdata(&spi->dev);

	/* turn sensor off */
	spi_adis16255_write_data(spiadis,
			ADIS_SMPL_PRD_MSB, ADIS_SMPL_PRD_LSB,
			(u8 *)&value);
	spi_adis16255_write_data(spiadis,
			ADIS_MSC_CTRL_MSB, ADIS_MSC_CTRL_LSB,
			(u8 *)&value);

	dev_info(&spi->dev, "unregister: GPIO %d IRQ %d\n",
		spiadis->irq_adis, spiadis->irq);

	free_irq(spiadis->irq, spiadis);
	gpio_free(spiadis->irq_adis);

	sysfs_remove_group(&spiadis->spi->dev.kobj, &adis16255_attr_group);

	kfree(spiadis);

	dev_info(&spi->dev, "spi_adis16255 driver removed!\n");
	return 0;
}

static struct spi_driver spi_adis16255_drv �
	.driver �
		.name �"spi_adis16255",
		.owner �HIS_MODULE,
	},
	.probe �pi_adis16255_probe,
	.remove � __devexit_p(spi_adis16255_remove),
};

/*-------------------------------------------------------------------------*/

static int __init spi_adis16255_init(void)
{
	return spi_register_driver(&spi_adis16255_drv);
}
module_init(spi_adis16255_init);

static void __exit spi_adis16255_exit(void)
{
	spi_unregister_driver(&spi_adis16255_drv);
}
module_exit(spi_adis16255_exit);

MODULE_AUTHOR("Matthias Brugger");
MODULE_DESCRIPTION("SPI device driver for ADIS16255 sensor");
MODULE_LICENSE("GPL");
