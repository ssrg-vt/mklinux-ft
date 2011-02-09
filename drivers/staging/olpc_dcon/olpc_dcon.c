/*
 * Mainly by David Woodhouse, somewhat modified by Jordan Crouse
 *
 * Copyright © 2006-2007  Red Hat, Inc.
 * Copyright © 2006-2007  Advanced Micro Devices, Inc.
 * Copyright © 2009       VIA Technology, Inc.
 * Copyright (c) 2010  Andres Salomon <dilinger@queued.net>
 *
 * This program is free software.  You can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */


#include <linux/kernel.h>
#include <linux/fb.h>
#include <linux/console.h>
#include <linux/i2c.h>
#include <linux/platform_device.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/backlight.h>
#include <linux/device.h>
#include <linux/notifier.h>
#include <linux/uaccess.h>
#include <linux/ctype.h>
#include <linux/reboot.h>
#include <asm/tsc.h>
#include <asm/olpc.h>

#include "olpc_dcon.h"

/* Module definitions */

static int resumeline = 898;
module_param(resumeline, int, 0444);

static int noinit;
module_param(noinit, int, 0444);

/* Default off since it doesn't work on DCON ASIC in B-test OLPC board */
static int useaa = 1;
module_param(useaa, int, 0444);

struct dcon_platform_data {
	int (*init)(void);
	void (*bus_stabilize_wiggle)(void);
	void (*set_dconload)(int);
	u8 (*read_status)(void);
};

static struct dcon_platform_data *pdata;

struct dcon_priv {
	struct i2c_client *client;

	struct work_struct switch_source;
	struct notifier_block reboot_nb;

	/* Shadow register for the DCON_REG_MODE register */
	u8 disp_mode;

	/* Current output type; true == mono, false == color */
	bool mono:1;
	bool asleep:1;
};

/* I2C structures */

static struct i2c_driver dcon_driver;

/* Platform devices */
static struct platform_device *dcon_device;

/* Backlight device */
static struct backlight_device *dcon_bl_dev;

static struct fb_info *fbinfo;

/* set this to 1 while controlling fb blank state from this driver */
static int ignore_fb_events = 0;

/* Current source, initialized at probe time */
static int dcon_source;

/* Desired source */
static int dcon_pending;

/* Variables used during switches */
static int dcon_switched;
static struct timespec dcon_irq_time;
static struct timespec dcon_load_time;

static DECLARE_WAIT_QUEUE_HEAD(dcon_wait_queue);

static unsigned short normal_i2c[] = { 0x0d, I2C_CLIENT_END };

static s32 dcon_write(struct dcon_priv *dcon, u8 reg, u16 val)
{
	return i2c_smbus_write_word_data(dcon->client, reg, val);
}

static s32 dcon_read(struct dcon_priv *dcon, u8 reg)
{
	return i2c_smbus_read_word_data(dcon->client, reg);
}

/* The current backlight value - this saves us some smbus traffic */
static int bl_val = -1;

/* ===== API functions - these are called by a variety of users ==== */

static int dcon_hw_init(struct dcon_priv *dcon, int is_init)
{
	struct i2c_client *client = dcon->client;
	uint16_t ver;
	int rc = 0;

	ver = i2c_smbus_read_word_data(client, DCON_REG_ID);
	if ((ver >> 8) != 0xDC) {
		printk(KERN_ERR "olpc-dcon:  DCON ID not 0xDCxx: 0x%04x "
				"instead.\n", ver);
		rc = -ENXIO;
		goto err;
	}

	if (is_init) {
		printk(KERN_INFO "olpc-dcon:  Discovered DCON version %x\n",
				ver & 0xFF);
		rc = pdata->init();
		if (rc != 0) {
			printk(KERN_ERR "olpc-dcon:  Unable to init.\n");
			goto err;
		}
	}

	if (ver < 0xdc02 && !noinit) {
		/* Initialize the DCON registers */

		/* Start with work-arounds for DCON ASIC */
		i2c_smbus_write_word_data(client, 0x4b, 0x00cc);
		i2c_smbus_write_word_data(client, 0x4b, 0x00cc);
		i2c_smbus_write_word_data(client, 0x4b, 0x00cc);
		i2c_smbus_write_word_data(client, 0x0b, 0x007a);
		i2c_smbus_write_word_data(client, 0x36, 0x025c);
		i2c_smbus_write_word_data(client, 0x37, 0x025e);

		/* Initialise SDRAM */

		i2c_smbus_write_word_data(client, 0x3b, 0x002b);
		i2c_smbus_write_word_data(client, 0x41, 0x0101);
		i2c_smbus_write_word_data(client, 0x42, 0x0101);
	} else if (!noinit) {
		/* SDRAM setup/hold time */
		i2c_smbus_write_word_data(client, 0x3a, 0xc040);
		i2c_smbus_write_word_data(client, 0x41, 0x0000);
		i2c_smbus_write_word_data(client, 0x41, 0x0101);
		i2c_smbus_write_word_data(client, 0x42, 0x0101);
	}

	/* Colour swizzle, AA, no passthrough, backlight */
	if (is_init) {
		dcon->disp_mode = MODE_PASSTHRU | MODE_BL_ENABLE |
				MODE_CSWIZZLE;
		if (useaa)
			dcon->disp_mode |= MODE_COL_AA;
	}
	i2c_smbus_write_word_data(client, DCON_REG_MODE, dcon->disp_mode);


	/* Set the scanline to interrupt on during resume */
	i2c_smbus_write_word_data(client, DCON_REG_SCAN_INT, resumeline);

err:
	return rc;
}

/*
 * The smbus doesn't always come back due to what is believed to be
 * hardware (power rail) bugs.  For older models where this is known to
 * occur, our solution is to attempt to wait for the bus to stabilize;
 * if it doesn't happen, cut power to the dcon, repower it, and wait
 * for the bus to stabilize.  Rinse, repeat until we have a working
 * smbus.  For newer models, we simply BUG(); we want to know if this
 * still happens despite the power fixes that have been made!
 */
static int dcon_bus_stabilize(struct dcon_priv *dcon, int is_powered_down)
{
	unsigned long timeout;
	int x;

power_up:
	if (is_powered_down) {
		x = 1;
		x = olpc_ec_cmd(0x26, (unsigned char *) &x, 1, NULL, 0);
		if (x) {
			printk(KERN_WARNING "olpc-dcon:  unable to force dcon "
					"to power up: %d!\n", x);
			return x;
		}
		msleep(10); /* we'll be conservative */
	}

	pdata->bus_stabilize_wiggle();

	for (x = -1, timeout = 50; timeout && x < 0; timeout--) {
		msleep(1);
		x = dcon_read(dcon, DCON_REG_ID);
	}
	if (x < 0) {
		printk(KERN_ERR "olpc-dcon:  unable to stabilize dcon's "
				"smbus, reasserting power and praying.\n");
		BUG_ON(olpc_board_at_least(olpc_board(0xc2)));
		x = 0;
		olpc_ec_cmd(0x26, (unsigned char *) &x, 1, NULL, 0);
		msleep(100);
		is_powered_down = 1;
		goto power_up;	/* argh, stupid hardware.. */
	}

	if (is_powered_down)
		return dcon_hw_init(dcon, 0);
	return 0;
}

static int dcon_get_backlight(struct dcon_priv *dcon)
{
	if (!dcon || !dcon->client)
		return 0;

	if (bl_val == -1)
		bl_val = dcon_read(dcon, DCON_REG_BRIGHT) & 0x0F;

	return bl_val;
}


static void dcon_set_backlight_hw(struct dcon_priv *dcon, int level)
{
	bl_val = level & 0x0F;
	dcon_write(dcon, DCON_REG_BRIGHT, bl_val);

	/* Purposely turn off the backlight when we go to level 0 */
	if (bl_val == 0) {
		dcon->disp_mode &= ~MODE_BL_ENABLE;
		dcon_write(dcon, DCON_REG_MODE, dcon->disp_mode);
	} else if (!(dcon->disp_mode & MODE_BL_ENABLE)) {
		dcon->disp_mode |= MODE_BL_ENABLE;
		dcon_write(dcon, DCON_REG_MODE, dcon->disp_mode);
	}
}

static void dcon_set_backlight(struct dcon_priv *dcon, int level)
{
	if (!dcon || !dcon->client)
		return;

	if (bl_val == (level & 0x0F))
		return;

	dcon_set_backlight_hw(dcon, level);
}

/* Set the output type to either color or mono */
static int dcon_set_mono_mode(struct dcon_priv *dcon, bool enable_mono)
{
	if (dcon->mono == enable_mono)
		return 0;

	dcon->mono = enable_mono;

	if (enable_mono) {
		dcon->disp_mode &= ~(MODE_CSWIZZLE | MODE_COL_AA);
		dcon->disp_mode |= MODE_MONO_LUMA;
	} else {
		dcon->disp_mode &= ~(MODE_MONO_LUMA);
		dcon->disp_mode |= MODE_CSWIZZLE;
		if (useaa)
			dcon->disp_mode |= MODE_COL_AA;
	}

	dcon_write(dcon, DCON_REG_MODE, dcon->disp_mode);
	return 0;
}

/* For now, this will be really stupid - we need to address how
 * DCONLOAD works in a sleep and account for it accordingly
 */

static void dcon_sleep(struct dcon_priv *dcon, bool sleep)
{
	int x;

	/* Turn off the backlight and put the DCON to sleep */

	if (dcon->asleep == sleep)
		return;

	if (!olpc_board_at_least(olpc_board(0xc2)))
		return;

	if (sleep) {
		x = 0;
		x = olpc_ec_cmd(0x26, (unsigned char *) &x, 1, NULL, 0);
		if (x)
			printk(KERN_WARNING "olpc-dcon:  unable to force dcon "
					"to power down: %d!\n", x);
		else
			dcon->asleep = sleep;
	} else {
		/* Only re-enable the backlight if the backlight value is set */
		if (bl_val != 0)
			dcon->disp_mode |= MODE_BL_ENABLE;
		x = dcon_bus_stabilize(dcon, 1);
		if (x)
			printk(KERN_WARNING "olpc-dcon:  unable to reinit dcon"
					" hardware: %d!\n", x);
		else
			dcon->asleep = sleep;

		/* Restore backlight */
		dcon_set_backlight_hw(dcon, bl_val);
	}

	/* We should turn off some stuff in the framebuffer - but what? */
}

/* the DCON seems to get confused if we change DCONLOAD too
 * frequently -- i.e., approximately faster than frame time.
 * normally we don't change it this fast, so in general we won't
 * delay here.
 */
void dcon_load_holdoff(void)
{
	struct timespec delta_t, now;
	while (1) {
		getnstimeofday(&now);
		delta_t = timespec_sub(now, dcon_load_time);
		if (delta_t.tv_sec != 0 ||
			delta_t.tv_nsec > NSEC_PER_MSEC * 20) {
			break;
		}
		mdelay(4);
	}
}
/* Set the source of the display (CPU or DCON) */

static void dcon_source_switch(struct work_struct *work)
{
	struct dcon_priv *dcon = container_of(work, struct dcon_priv,
			switch_source);
	DECLARE_WAITQUEUE(wait, current);
	int source = dcon_pending;

	if (dcon_source == source)
		return;

	dcon_load_holdoff();

	dcon_switched = 0;

	switch (source) {
	case DCON_SOURCE_CPU:
		printk("dcon_source_switch to CPU\n");
		/* Enable the scanline interrupt bit */
		if (dcon_write(dcon, DCON_REG_MODE,
				dcon->disp_mode | MODE_SCAN_INT))
			printk(KERN_ERR
			       "olpc-dcon:  couldn't enable scanline interrupt!\n");
		else {
			/* Wait up to one second for the scanline interrupt */
			wait_event_timeout(dcon_wait_queue,
					   dcon_switched == 1, HZ);
		}

		if (!dcon_switched)
			printk(KERN_ERR "olpc-dcon:  Timeout entering CPU mode; expect a screen glitch.\n");

		/* Turn off the scanline interrupt */
		if (dcon_write(dcon, DCON_REG_MODE, dcon->disp_mode))
			printk(KERN_ERR "olpc-dcon:  couldn't disable scanline interrupt!\n");

		/*
		 * Ideally we'd like to disable interrupts here so that the
		 * fb unblanking and DCON turn on happen at a known time value;
		 * however, we can't do that right now with fb_blank
		 * messing with semaphores.
		 *
		 * For now, we just hope..
		 */
		console_lock();
		ignore_fb_events = 1;
		if (fb_blank(fbinfo, FB_BLANK_UNBLANK)) {
			ignore_fb_events = 0;
			console_unlock();
			printk(KERN_ERR "olpc-dcon:  Failed to enter CPU mode\n");
			dcon_pending = DCON_SOURCE_DCON;
			return;
		}
		ignore_fb_events = 0;
		console_unlock();

		/* And turn off the DCON */
		pdata->set_dconload(1);
		getnstimeofday(&dcon_load_time);

		printk(KERN_INFO "olpc-dcon: The CPU has control\n");
		break;
	case DCON_SOURCE_DCON:
	{
		int t;
		struct timespec delta_t;

		printk(KERN_INFO "dcon_source_switch to DCON\n");

		add_wait_queue(&dcon_wait_queue, &wait);
		set_current_state(TASK_UNINTERRUPTIBLE);

		/* Clear DCONLOAD - this implies that the DCON is in control */
		pdata->set_dconload(0);
		getnstimeofday(&dcon_load_time);

		t = schedule_timeout(HZ/2);
		remove_wait_queue(&dcon_wait_queue, &wait);
		set_current_state(TASK_RUNNING);

		if (!dcon_switched) {
			printk(KERN_ERR "olpc-dcon: Timeout entering DCON mode; expect a screen glitch.\n");
		} else {
			/* sometimes the DCON doesn't follow its own rules,
			 * and doesn't wait for two vsync pulses before
			 * ack'ing the frame load with an IRQ.  the result
			 * is that the display shows the *previously*
			 * loaded frame.  we can detect this by looking at
			 * the time between asserting DCONLOAD and the IRQ --
			 * if it's less than 20msec, then the DCON couldn't
			 * have seen two VSYNC pulses.  in that case we
			 * deassert and reassert, and hope for the best.
			 * see http://dev.laptop.org/ticket/9664
			 */
			delta_t = timespec_sub(dcon_irq_time, dcon_load_time);
			if (dcon_switched && delta_t.tv_sec == 0 &&
					delta_t.tv_nsec < NSEC_PER_MSEC * 20) {
				printk(KERN_ERR "olpc-dcon: missed loading, retrying\n");
				pdata->set_dconload(1);
				mdelay(41);
				pdata->set_dconload(0);
				getnstimeofday(&dcon_load_time);
				mdelay(41);
			}
		}

		console_lock();
		ignore_fb_events = 1;
		if (fb_blank(fbinfo, FB_BLANK_POWERDOWN))
			printk(KERN_ERR "olpc-dcon:  couldn't blank fb!\n");
		ignore_fb_events = 0;
		console_unlock();

		printk(KERN_INFO "olpc-dcon: The DCON has control\n");
		break;
	}
	default:
		BUG();
	}

	dcon_source = source;
}

static void dcon_set_source(struct dcon_priv *dcon, int arg)
{
	if (dcon_pending == arg)
		return;

	dcon_pending = arg;

	if ((dcon_source != arg) && !work_pending(&dcon->switch_source))
		schedule_work(&dcon->switch_source);
}

static void dcon_set_source_sync(struct dcon_priv *dcon, int arg)
{
	dcon_set_source(dcon, arg);
	flush_scheduled_work();
}

static int dconbl_set(struct backlight_device *dev)
{
	struct dcon_priv *dcon = bl_get_data(dev);
	int level = dev->props.brightness;

	if (dev->props.power != FB_BLANK_UNBLANK)
		level = 0;

	dcon_set_backlight(dcon, level);
	return 0;
}

static int dconbl_get(struct backlight_device *dev)
{
	struct dcon_priv *dcon = bl_get_data(dev);
	return dcon_get_backlight(dcon);
}

static ssize_t dcon_mode_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct dcon_priv *dcon = dev_get_drvdata(dev);
	return sprintf(buf, "%4.4X\n", dcon->disp_mode);
}

static ssize_t dcon_sleep_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{

	struct dcon_priv *dcon = dev_get_drvdata(dev);
	return sprintf(buf, "%d\n", dcon->asleep ? 1 : 0);
}

static ssize_t dcon_freeze_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", dcon_source == DCON_SOURCE_DCON ? 1 : 0);
}

static ssize_t dcon_mono_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct dcon_priv *dcon = dev_get_drvdata(dev);
	return sprintf(buf, "%d\n", dcon->mono ? 1 : 0);
}

static ssize_t dcon_resumeline_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", resumeline);
}

static int _strtoul(const char *buf, int len, unsigned int *val)
{

	char *endp;
	unsigned int output = simple_strtoul(buf, &endp, 0);
	int size = endp - buf;

	if (*endp && isspace(*endp))
		size++;

	if (size != len)
		return -EINVAL;

	*val = output;
	return 0;
}

static ssize_t dcon_mono_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	int enable_mono;
	int rc = -EINVAL;

	if (_strtoul(buf, count, &enable_mono))
		return -EINVAL;

	dcon_set_mono_mode(dev_get_drvdata(dev), enable_mono ? 1 : 0);
	rc = count;

	return rc;
}

static ssize_t dcon_freeze_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct dcon_priv *dcon = dev_get_drvdata(dev);
	int output;

	if (_strtoul(buf, count, &output))
		return -EINVAL;

	printk(KERN_INFO "dcon_freeze_store: %d\n", output);

	switch (output) {
	case 0:
		dcon_set_source(dcon, DCON_SOURCE_CPU);
		break;
	case 1:
		dcon_set_source_sync(dcon, DCON_SOURCE_DCON);
		break;
	case 2:  /* normally unused */
		dcon_set_source(dcon, DCON_SOURCE_DCON);
		break;
	default:
		return -EINVAL;
	}

	return count;
}

static ssize_t dcon_resumeline_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	int rl;
	int rc = -EINVAL;

	if (_strtoul(buf, count, &rl))
		return rc;

	resumeline = rl;
	dcon_write(dev_get_drvdata(dev), DCON_REG_SCAN_INT, resumeline);
	rc = count;

	return rc;
}

static ssize_t dcon_sleep_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	int output;

	if (_strtoul(buf, count, &output))
		return -EINVAL;

	dcon_sleep(dev_get_drvdata(dev), output ? true : false);
	return count;
}

static struct device_attribute dcon_device_files[] = {
	__ATTR(mode, 0444, dcon_mode_show, NULL),
	__ATTR(sleep, 0644, dcon_sleep_show, dcon_sleep_store),
	__ATTR(freeze, 0644, dcon_freeze_show, dcon_freeze_store),
	__ATTR(monochrome, 0644, dcon_mono_show, dcon_mono_store),
	__ATTR(resumeline, 0644, dcon_resumeline_show, dcon_resumeline_store),
};

static const struct backlight_ops dcon_bl_ops = {
	.get_brightness = dconbl_get,
	.update_status = dconbl_set
};


static int dcon_reboot_notify(struct notifier_block *nb,
			      unsigned long foo, void *bar)
{
	struct dcon_priv *dcon = container_of(nb, struct dcon_priv, reboot_nb);

	if (!dcon || !dcon->client)
		return 0;

	/* Turn off the DCON. Entirely. */
	dcon_write(dcon, DCON_REG_MODE, 0x39);
	dcon_write(dcon, DCON_REG_MODE, 0x32);
	return 0;
}

static int unfreeze_on_panic(struct notifier_block *nb,
			     unsigned long e, void *p)
{
	pdata->set_dconload(1);
	return NOTIFY_DONE;
}

static struct notifier_block dcon_panic_nb = {
	.notifier_call = unfreeze_on_panic,
};

/*
 * When the framebuffer sleeps due to external sources (e.g. user idle), power
 * down the DCON as well.  Power it back up when the fb comes back to life.
 */
static int fb_notifier_callback(struct notifier_block *self,
				unsigned long event, void *data)
{
	struct fb_event *evdata = data;
	struct backlight_device *bl = container_of(self,
			struct backlight_device, fb_notif);
	struct dcon_priv *dcon = bl_get_data(bl);
	int *blank = (int *) evdata->data;
	if (((event != FB_EVENT_BLANK) && (event != FB_EVENT_CONBLANK)) ||
			ignore_fb_events)
		return 0;
	dcon_sleep(dcon, *blank ? true : false);
	return 0;
}

static struct notifier_block fb_nb = {
	.notifier_call = fb_notifier_callback,
};

static int dcon_detect(struct i2c_client *client, struct i2c_board_info *info)
{
	strlcpy(info->type, "olpc_dcon", I2C_NAME_SIZE);

	return 0;
}

static int dcon_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	struct dcon_priv *dcon;
	int rc, i, j;

	dcon = kzalloc(sizeof(*dcon), GFP_KERNEL);
	if (!dcon)
		return -ENOMEM;

	dcon->client = client;
	INIT_WORK(&dcon->switch_source, dcon_source_switch);
	dcon->reboot_nb.notifier_call = dcon_reboot_notify;
	dcon->reboot_nb.priority = -1;

	i2c_set_clientdata(client, dcon);

	if (num_registered_fb >= 1)
		fbinfo = registered_fb[0];

	rc = dcon_hw_init(dcon, 1);
	if (rc)
		goto einit;

	/* Add the DCON device */

	dcon_device = platform_device_alloc("dcon", -1);

	if (dcon_device == NULL) {
		printk(KERN_ERR "dcon:  Unable to create the DCON device\n");
		rc = -ENOMEM;
		goto eirq;
	}
	rc = platform_device_add(dcon_device);
	platform_set_drvdata(dcon_device, dcon);

	if (rc) {
		printk(KERN_ERR "dcon:  Unable to add the DCON device\n");
		goto edev;
	}

	for (i = 0; i < ARRAY_SIZE(dcon_device_files); i++) {
		rc = device_create_file(&dcon_device->dev,
					&dcon_device_files[i]);
		if (rc) {
			dev_err(&dcon_device->dev, "Cannot create sysfs file\n");
			goto ecreate;
		}
	}

	/* Add the backlight device for the DCON */
	dcon_bl_dev = backlight_device_register("dcon-bl", &dcon_device->dev,
		dcon, &dcon_bl_ops, NULL);

	if (IS_ERR(dcon_bl_dev)) {
		printk(KERN_ERR "Cannot register the backlight device (%ld)\n",
		       PTR_ERR(dcon_bl_dev));
		dcon_bl_dev = NULL;
	} else {
		dcon_bl_dev->props.max_brightness = 15;
		dcon_bl_dev->props.power = FB_BLANK_UNBLANK;
		dcon_bl_dev->props.brightness = dcon_get_backlight(dcon);

		backlight_update_status(dcon_bl_dev);
	}

	register_reboot_notifier(&dcon->reboot_nb);
	atomic_notifier_chain_register(&panic_notifier_list, &dcon_panic_nb);
	fb_register_client(&fb_nb);

	return 0;

 ecreate:
	for (j = 0; j < i; j++)
		device_remove_file(&dcon_device->dev, &dcon_device_files[j]);
 edev:
	platform_device_unregister(dcon_device);
	dcon_device = NULL;
 eirq:
	free_irq(DCON_IRQ, &dcon_driver);
 einit:
	i2c_set_clientdata(client, NULL);
	kfree(dcon);
	return rc;
}

static int dcon_remove(struct i2c_client *client)
{
	struct dcon_priv *dcon = i2c_get_clientdata(client);

	i2c_set_clientdata(client, NULL);

	fb_unregister_client(&fb_nb);
	unregister_reboot_notifier(&dcon->reboot_nb);
	atomic_notifier_chain_unregister(&panic_notifier_list, &dcon_panic_nb);

	free_irq(DCON_IRQ, &dcon_driver);

	if (dcon_bl_dev != NULL)
		backlight_device_unregister(dcon_bl_dev);

	if (dcon_device != NULL)
		platform_device_unregister(dcon_device);
	cancel_work_sync(&dcon->switch_source);

	kfree(dcon);

	return 0;
}

#ifdef CONFIG_PM
static int dcon_suspend(struct i2c_client *client, pm_message_t state)
{
	struct dcon_priv *dcon = i2c_get_clientdata(client);

	if (!dcon->asleep) {
		/* Set up the DCON to have the source */
		dcon_set_source_sync(dcon, DCON_SOURCE_DCON);
	}

	return 0;
}

static int dcon_resume(struct i2c_client *client)
{
	struct dcon_priv *dcon = i2c_get_clientdata(client);

	if (!dcon->asleep) {
		dcon_bus_stabilize(dcon, 0);
		dcon_set_source(dcon, DCON_SOURCE_CPU);
	}

	return 0;
}

#endif


static irqreturn_t dcon_interrupt(int irq, void *id)
{
	int status = pdata->read_status();

	if (status == -1)
		return IRQ_NONE;

	switch (status & 3) {
	case 3:
		printk(KERN_DEBUG "olpc-dcon: DCONLOAD_MISSED interrupt\n");
		break;

	case 2:	/* switch to DCON mode */
	case 1: /* switch to CPU mode */
		dcon_switched = 1;
		getnstimeofday(&dcon_irq_time);
		wake_up(&dcon_wait_queue);
		break;

	case 0:
		/* workaround resume case:  the DCON (on 1.5) doesn't
		 * ever assert status 0x01 when switching to CPU mode
		 * during resume.  this is because DCONLOAD is de-asserted
		 * _immediately_ upon exiting S3, so the actual release
		 * of the DCON happened long before this point.
		 * see http://dev.laptop.org/ticket/9869
		 */
		if (dcon_source != dcon_pending && !dcon_switched) {
			dcon_switched = 1;
			getnstimeofday(&dcon_irq_time);
			wake_up(&dcon_wait_queue);
			printk(KERN_DEBUG "olpc-dcon: switching w/ status 0/0\n");
		} else {
			printk(KERN_DEBUG "olpc-dcon: scanline interrupt w/CPU\n");
		}
	}

	return IRQ_HANDLED;
}

static const struct i2c_device_id dcon_idtable[] = {
	{ "olpc_dcon",  0 },
	{ }
};

MODULE_DEVICE_TABLE(i2c, dcon_idtable);

static struct i2c_driver dcon_driver = {
	.driver = {
		.name	= "olpc_dcon",
	},
	.class = I2C_CLASS_DDC | I2C_CLASS_HWMON,
	.id_table = dcon_idtable,
	.probe = dcon_probe,
	.remove = __devexit_p(dcon_remove),
	.detect = dcon_detect,
	.address_list = normal_i2c,
#ifdef CONFIG_PM
	.suspend = dcon_suspend,
	.resume = dcon_resume,
#endif
};

#include "olpc_dcon_xo_1.c"

static int __init olpc_dcon_init(void)
{
	pdata = &dcon_pdata_xo_1;

	return i2c_add_driver(&dcon_driver);
}

static void __exit olpc_dcon_exit(void)
{
	i2c_del_driver(&dcon_driver);
}

module_init(olpc_dcon_init);
module_exit(olpc_dcon_exit);

MODULE_LICENSE("GPL");
