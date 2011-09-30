/*
 * NVEC: NVIDIA compliant embedded controller interface
 *
 * Copyright (C) 2011 The AC100 Kernel Team <ac100@lists.lauchpad.net>
 *
 * Authors:  Pierre-Hugues Husson <phhusson@free.fr>
 *           Ilya Petrov <ilya.muromec@gmail.com>
 *           Marc Dietrich <marvin24@gmx.de>
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 */

/* #define DEBUG */

#include <asm/irq.h>

#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/slab.h>
#include <linux/gpio.h>
#include <linux/serio.h>
#include <linux/delay.h>
#include <linux/input.h>
#include <linux/workqueue.h>
#include <linux/clk.h>

#include <linux/semaphore.h>
#include <linux/list.h>
#include <linux/notifier.h>
#include <linux/platform_device.h>
#include <linux/mfd/core.h>

#include <mach/iomap.h>
#include <mach/clk.h>

#include "nvec.h"

static const unsigned char EC_DISABLE_EVENT_REPORTING[3] = "\x04\x00\x00";
static const unsigned char EC_ENABLE_EVENT_REPORTING[3]  = "\x04\x00\x01";
static const unsigned char EC_GET_FIRMWARE_VERSION[2]    = "\x07\x15";

static struct nvec_chip *nvec_power_handle;

static struct mfd_cell nvec_devices[] = {
	{
		.name = "nvec-kbd",
		.id = 1,
	},
	{
		.name = "nvec-mouse",
		.id = 1,
	},
	{
		.name = "nvec-power",
		.id = 1,
	},
	{
		.name = "nvec-power",
		.id = 2,
	},
	{
		.name = "nvec-leds",
		.id = 1,
	},
};

int nvec_register_notifier(struct nvec_chip *nvec, struct notifier_block *nb,
			   unsigned int events)
{
	return atomic_notifier_chain_register(&nvec->notifier_list, nb);
}
EXPORT_SYMBOL_GPL(nvec_register_notifier);

static int nvec_status_notifier(struct notifier_block *nb,
				unsigned long event_type, void *data)
{
	unsigned char *msg = (unsigned char *)data;

	if (event_type != NVEC_CNTL)
		return NOTIFY_DONE;

	printk(KERN_WARNING "unhandled msg type %ld\n", event_type);
	print_hex_dump(KERN_WARNING, "payload: ", DUMP_PREFIX_NONE, 16, 1,
		msg, msg[1] + 2, true);

	return NOTIFY_OK;
}

static struct nvec_msg *nvec_msg_alloc(struct nvec_chip *nvec)
{
	int i;

	for (i = 0; i < NVEC_POOL_SIZE; i++) {
		if (atomic_xchg(&nvec->msg_pool[i].used, 1) == 0) {
			dev_vdbg(nvec->dev, "INFO: Allocate %i\n", i);
			return &nvec->msg_pool[i];
		}
	}

	dev_err(nvec->dev, "could not allocate buffer\n");

	return NULL;
}

static void nvec_msg_free(struct nvec_chip *nvec, struct nvec_msg *msg)
{
	dev_vdbg(nvec->dev, "INFO: Free %ti\n", msg - nvec->msg_pool);
	atomic_set(&msg->used, 0);
}

static void nvec_gpio_set_value(struct nvec_chip *nvec, int value)
{
	dev_dbg(nvec->dev, "GPIO changed from %u to %u\n",
		gpio_get_value(nvec->gpio), value);
	gpio_set_value(nvec->gpio, value);
}

void nvec_write_async(struct nvec_chip *nvec, const unsigned char *data,
			short size)
{
	struct nvec_msg *msg = kzalloc(sizeof(struct nvec_msg), GFP_NOWAIT);

	msg->data = kzalloc(size, GFP_NOWAIT);
	msg->data[0] = size;
	memcpy(msg->data + 1, data, size);
	msg->size = size + 1;
	msg->pos = 0;
	INIT_LIST_HEAD(&msg->node);

	list_add_tail(&msg->node, &nvec->tx_data);

	gpio_set_value(nvec->gpio, 0);
}
EXPORT_SYMBOL(nvec_write_async);

static void nvec_request_master(struct work_struct *work)
{
	struct nvec_chip *nvec = container_of(work, struct nvec_chip, tx_work);

	if (!list_empty(&nvec->tx_data))
		gpio_set_value(nvec->gpio, 0);
}

static int parse_msg(struct nvec_chip *nvec, struct nvec_msg *msg)
{
	if ((msg->data[0] & 1 << 7) == 0 && msg->data[3]) {
		dev_err(nvec->dev, "ec responded %02x %02x %02x %02x\n",
			msg->data[0], msg->data[1], msg->data[2], msg->data[3]);
		return -EINVAL;
	}

	if ((msg->data[0] >> 7) == 1 && (msg->data[0] & 0x0f) == 5)
		print_hex_dump(KERN_WARNING, "ec system event ",
				DUMP_PREFIX_NONE, 16, 1, msg->data,
				msg->data[1] + 2, true);

	atomic_notifier_call_chain(&nvec->notifier_list, msg->data[0] & 0x8f,
				   msg->data);

	return 0;
}

static struct nvec_msg *nvec_write_sync(struct nvec_chip *nvec,
					const unsigned char *data, short size)
{
	down(&nvec->sync_write_mutex);

	nvec->sync_write_pending = (data[1] << 8) + data[0];
	nvec_write_async(nvec, data, size);

	dev_dbg(nvec->dev, "nvec_sync_write: 0x%04x\n",
		nvec->sync_write_pending);
	wait_for_completion(&nvec->sync_write);
	dev_dbg(nvec->dev, "nvec_sync_write: pong!\n");

	up(&nvec->sync_write_mutex);

	return nvec->last_sync_msg;
}

/* RX worker */
static void nvec_dispatch(struct work_struct *work)
{
	struct nvec_chip *nvec = container_of(work, struct nvec_chip, rx_work);
	struct nvec_msg *msg;

	while (!list_empty(&nvec->rx_data)) {
		msg = list_first_entry(&nvec->rx_data, struct nvec_msg, node);
		list_del_init(&msg->node);

		if (nvec->sync_write_pending ==
		    (msg->data[2] << 8) + msg->data[0]) {
			dev_dbg(nvec->dev, "sync write completed!\n");
			nvec->sync_write_pending = 0;
			nvec->last_sync_msg = msg;
			complete(&nvec->sync_write);
		} else {
			parse_msg(nvec, msg);
			if ((!msg) || (!msg->data))
				dev_warn(nvec->dev,
					"attempt access zero pointer\n");
			else {
				kfree(msg->data);
				kfree(msg);
			}
		}
	}
}

static irqreturn_t nvec_interrupt(int irq, void *dev)
{
	unsigned long status;
	unsigned long received;
	unsigned char to_send;
	struct nvec_msg *msg;
	struct nvec_chip *nvec = (struct nvec_chip *)dev;
	void __iomem *base = nvec->base;

	status = readl(base + I2C_SL_STATUS);

	if (!(status & I2C_SL_IRQ)) {
		dev_warn(nvec->dev, "nvec Spurious IRQ\n");
		goto handled;
	}
	if (status & END_TRANS && !(status & RCVD)) {
		nvec->state = NVEC_WAIT;
		if (nvec->rx->size > 1) {
			list_add_tail(&nvec->rx->node, &nvec->rx_data);
			schedule_work(&nvec->rx_work);
		} else {
			kfree(nvec->rx->data);
			kfree(nvec->rx);
		}
		return IRQ_HANDLED;
	} else if (status & RNW) {
		if (status & RCVD)
			udelay(3);

		if (status & RCVD)
			nvec->state = NVEC_WRITE;

		if (list_empty(&nvec->tx_data)) {
			dev_err(nvec->dev, "nvec empty tx - sending no-op\n");
			to_send = 0x8a;
			nvec_write_async(nvec, "\x07\x02", 2);
		} else {
			msg =
			    list_first_entry(&nvec->tx_data, struct nvec_msg,
					     node);
			if (msg->pos < msg->size) {
				to_send = msg->data[msg->pos];
				msg->pos++;
			} else {
				dev_err(nvec->dev, "nvec crap! %d\n",
					msg->size);
				to_send = 0x01;
			}

			if (msg->pos >= msg->size) {
				list_del_init(&msg->node);
				kfree(msg->data);
				kfree(msg);
				schedule_work(&nvec->tx_work);
				nvec->state = NVEC_WAIT;
			}
		}
		writel(to_send, base + I2C_SL_RCVD);

		gpio_set_value(nvec->gpio, 1);

		dev_dbg(nvec->dev, "nvec sent %x\n", to_send);

		goto handled;
	} else {
		received = readl(base + I2C_SL_RCVD);

		if (status & RCVD) {
			writel(0, base + I2C_SL_RCVD);
			goto handled;
		}

		if (nvec->state == NVEC_WAIT) {
			nvec->state = NVEC_READ;
			msg = kzalloc(sizeof(struct nvec_msg), GFP_NOWAIT);
			msg->data = kzalloc(32, GFP_NOWAIT);
			INIT_LIST_HEAD(&msg->node);
			nvec->rx = msg;
		} else
			msg = nvec->rx;

		BUG_ON(msg->pos > 32);

		msg->data[msg->pos] = received;
		msg->pos++;
		msg->size = msg->pos;
		dev_dbg(nvec->dev, "Got %02lx from Master (pos: %d)!\n",
			received, msg->pos);
	}
handled:
	return IRQ_HANDLED;
}

static void tegra_init_i2c_slave(struct nvec_chip *nvec)
{
	u32 val;

	clk_enable(nvec->i2c_clk);

	tegra_periph_reset_assert(nvec->i2c_clk);
	udelay(2);
	tegra_periph_reset_deassert(nvec->i2c_clk);

	val = I2C_CNFG_NEW_MASTER_SFM | I2C_CNFG_PACKET_MODE_EN |
	    (0x2 << I2C_CNFG_DEBOUNCE_CNT_SHIFT);
	writel(val, nvec->base + I2C_CNFG);

	clk_set_rate(nvec->i2c_clk, 8 * 80000);

	writel(I2C_SL_NEWL, nvec->base + I2C_SL_CNFG);
	writel(0x1E, nvec->base + I2C_SL_DELAY_COUNT);

	writel(nvec->i2c_addr>>1, nvec->base + I2C_SL_ADDR1);
	writel(0, nvec->base + I2C_SL_ADDR2);

	enable_irq(nvec->irq);

	clk_disable(nvec->i2c_clk);
}

static void nvec_disable_i2c_slave(struct nvec_chip *nvec)
{
	disable_irq(nvec->irq);
	writel(I2C_SL_NEWL | I2C_SL_NACK, nvec->base + I2C_SL_CNFG);
	clk_disable(nvec->i2c_clk);
}

static void nvec_power_off(void)
{
	nvec_write_async(nvec_power_handle, EC_DISABLE_EVENT_REPORTING, 3);
	nvec_write_async(nvec_power_handle, "\x04\x01", 2);
}

static int __devinit tegra_nvec_probe(struct platform_device *pdev)
{
	int err, ret;
	struct clk *i2c_clk;
	struct nvec_platform_data *pdata = pdev->dev.platform_data;
	struct nvec_chip *nvec;
	struct nvec_msg *msg;
	struct resource *res;
	struct resource *iomem;
	void __iomem *base;

	nvec = kzalloc(sizeof(struct nvec_chip), GFP_KERNEL);
	if (nvec == NULL) {
		dev_err(&pdev->dev, "failed to reserve memory\n");
		return -ENOMEM;
	}
	platform_set_drvdata(pdev, nvec);
	nvec->dev = &pdev->dev;
	nvec->gpio = pdata->gpio;
	nvec->i2c_addr = pdata->i2c_addr;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "no mem resource?\n");
		return -ENODEV;
	}

	iomem = request_mem_region(res->start, resource_size(res), pdev->name);
	if (!iomem) {
		dev_err(&pdev->dev, "I2C region already claimed\n");
		return -EBUSY;
	}

	base = ioremap(iomem->start, resource_size(iomem));
	if (!base) {
		dev_err(&pdev->dev, "Can't ioremap I2C region\n");
		return -ENOMEM;
	}

	res = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
	if (!res) {
		dev_err(&pdev->dev, "no irq resource?\n");
		ret = -ENODEV;
		goto err_iounmap;
	}

	i2c_clk = clk_get_sys("tegra-i2c.2", NULL);
	if (IS_ERR(i2c_clk)) {
		dev_err(nvec->dev, "failed to get controller clock\n");
		goto err_iounmap;
	}

	nvec->base = base;
	nvec->irq = res->start;
	nvec->i2c_clk = i2c_clk;

	/* Set the gpio to low when we've got something to say */
	err = gpio_request(nvec->gpio, "nvec gpio");
	if (err < 0)
		dev_err(nvec->dev, "couldn't request gpio\n");

	ATOMIC_INIT_NOTIFIER_HEAD(&nvec->notifier_list);

	init_completion(&nvec->sync_write);
	sema_init(&nvec->sync_write_mutex, 1);
	INIT_LIST_HEAD(&nvec->tx_data);
	INIT_LIST_HEAD(&nvec->rx_data);
	INIT_WORK(&nvec->rx_work, nvec_dispatch);
	INIT_WORK(&nvec->tx_work, nvec_request_master);

	err = request_irq(nvec->irq, nvec_interrupt, 0, "nvec", nvec);
	if (err) {
		dev_err(nvec->dev, "couldn't request irq\n");
		goto failed;
	}
	disable_irq(nvec->irq);

	tegra_init_i2c_slave(nvec);

	clk_enable(i2c_clk);

	gpio_direction_output(nvec->gpio, 1);
	gpio_set_value(nvec->gpio, 1);

	/* enable event reporting */
	nvec_write_async(nvec, EC_ENABLE_EVENT_REPORTING,
			 sizeof(EC_ENABLE_EVENT_REPORTING));

	nvec->nvec_status_notifier.notifier_call = nvec_status_notifier;
	nvec_register_notifier(nvec, &nvec->nvec_status_notifier, 0);

	nvec_power_handle = nvec;
	pm_power_off = nvec_power_off;

	/* Get Firmware Version */
	msg = nvec_write_sync(nvec, EC_GET_FIRMWARE_VERSION,
			      sizeof(EC_GET_FIRMWARE_VERSION));

	dev_warn(nvec->dev, "ec firmware version %02x.%02x.%02x / %02x\n",
		 msg->data[4], msg->data[5], msg->data[6], msg->data[7]);

	kfree(msg->data);
	kfree(msg);

	ret = mfd_add_devices(nvec->dev, -1, nvec_devices,
			      ARRAY_SIZE(nvec_devices), base, 0);
	if (ret)
		dev_err(nvec->dev, "error adding subdevices\n");

	/* unmute speakers? */
	nvec_write_async(nvec, "\x0d\x10\x59\x95", 4);

	/* enable lid switch event */
	nvec_write_async(nvec, "\x01\x01\x01\x00\x00\x02\x00", 7);

	/* enable power button event */
	nvec_write_async(nvec, "\x01\x01\x01\x00\x00\x80\x00", 7);

	return 0;

err_iounmap:
	iounmap(base);
failed:
	kfree(nvec);
	return -ENOMEM;
}

static int __devexit tegra_nvec_remove(struct platform_device *pdev)
{
	struct nvec_chip *nvec = platform_get_drvdata(pdev);

	nvec_write_async(nvec, EC_DISABLE_EVENT_REPORTING, 3);
	mfd_remove_devices(nvec->dev);
	free_irq(nvec->irq, &nvec_interrupt);
	iounmap(nvec->base);
	gpio_free(nvec->gpio);
	kfree(nvec);

	return 0;
}

#ifdef CONFIG_PM

static int tegra_nvec_suspend(struct platform_device *pdev, pm_message_t state)
{
	struct nvec_chip *nvec = platform_get_drvdata(pdev);

	dev_dbg(nvec->dev, "suspending\n");
	nvec_write_async(nvec, EC_DISABLE_EVENT_REPORTING, 3);
	nvec_write_async(nvec, "\x04\x02", 2);
	nvec_disable_i2c_slave(nvec);

	return 0;
}

static int tegra_nvec_resume(struct platform_device *pdev)
{
	struct nvec_chip *nvec = platform_get_drvdata(pdev);

	dev_dbg(nvec->dev, "resuming\n");
	tegra_init_i2c_slave(nvec);
	nvec_write_async(nvec, EC_ENABLE_EVENT_REPORTING, 3);

	return 0;
}

#else
#define tegra_nvec_suspend NULL
#define tegra_nvec_resume NULL
#endif

static struct platform_driver nvec_device_driver = {
	.probe   = tegra_nvec_probe,
	.remove  = __devexit_p(tegra_nvec_remove),
	.suspend = tegra_nvec_suspend,
	.resume  = tegra_nvec_resume,
	.driver  = {
		.name = "nvec",
		.owner = THIS_MODULE,
	}
};

static int __init tegra_nvec_init(void)
{
	return platform_driver_register(&nvec_device_driver);
}

module_init(tegra_nvec_init);

MODULE_ALIAS("platform:nvec");
MODULE_DESCRIPTION("NVIDIA compliant embedded controller interface");
MODULE_AUTHOR("Marc Dietrich <marvin24@gmx.de>");
MODULE_LICENSE("GPL");
