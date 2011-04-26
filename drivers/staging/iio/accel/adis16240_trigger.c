#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/mutex.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/list.h>
#include <linux/spi/spi.h>

#include "../iio.h"
#include "../sysfs.h"
#include "../trigger.h"
#include "adis16240.h"

/**
 * adis16240_data_rdy_trig_poll() the event handler for the data rdy trig
 **/
static irqreturn_t adis16240_data_rdy_trig_poll(int irq, void *trig)
{
	disable_irq_nosync(irq);
	iio_trigger_poll(trig, iio_get_time_ns());
	return IRQ_HANDLED;
}

static IIO_TRIGGER_NAME_ATTR;

static struct attribute *adis16240_trigger_attrs[] = {
	&dev_attr_name.attr,
	NULL,
};

static const struct attribute_group adis16240_trigger_attr_group = {
	.attrs = adis16240_trigger_attrs,
};

/**
 * adis16240_data_rdy_trigger_set_state() set datardy interrupt state
 **/
static int adis16240_data_rdy_trigger_set_state(struct iio_trigger *trig,
						bool state)
{
	struct adis16240_state *st = trig->private_data;
	struct iio_dev *indio_dev = st->indio_dev;

	dev_dbg(&indio_dev->dev, "%s (%d)\n", __func__, state);
	return adis16240_set_irq(&st->indio_dev->dev, state);
}

/**
 * adis16240_trig_try_reen() try renabling irq for data rdy trigger
 * @trig:	the datardy trigger
 **/
static int adis16240_trig_try_reen(struct iio_trigger *trig)
{
	struct adis16240_state *st = trig->private_data;
	enable_irq(st->us->irq);
	return 0;
}

int adis16240_probe_trigger(struct iio_dev *indio_dev)
{
	int ret;
	struct adis16240_state *st = indio_dev->dev_data;

	st->trig = iio_allocate_trigger();
	if (st->trig == NULL) {
		ret = -ENOMEM;
		goto error_ret;
	}
	ret = request_irq(st->us->irq,
			  adis16240_data_rdy_trig_poll,
			  IRQF_TRIGGER_RISING,
			  "adis16240",
			  st->trig);
	if (ret)
		goto error_free_trig;

	st->trig->name = kasprintf(GFP_KERNEL,
				   "adis16240-dev%d",
				   indio_dev->id);
	if (!st->trig->name) {
		ret = -ENOMEM;
		goto error_free_irq;
	}
	st->trig->dev.parent = &st->us->dev;
	st->trig->owner = THIS_MODULE;
	st->trig->private_data = st;
	st->trig->set_trigger_state = &adis16240_data_rdy_trigger_set_state;
	st->trig->try_reenable = &adis16240_trig_try_reen;
	st->trig->control_attrs = &adis16240_trigger_attr_group;
	ret = iio_trigger_register(st->trig);

	/* select default trigger */
	indio_dev->trig = st->trig;
	if (ret)
		goto error_free_trig_name;

	return 0;

error_free_trig_name:
	kfree(st->trig->name);
error_free_irq:
	free_irq(st->us->irq, st->trig);
error_free_trig:
	iio_free_trigger(st->trig);
error_ret:
	return ret;
}

void adis16240_remove_trigger(struct iio_dev *indio_dev)
{
	struct adis16240_state *state = indio_dev->dev_data;

	iio_trigger_unregister(state->trig);
	kfree(state->trig->name);
	free_irq(state->us->irq, state->trig);
	iio_free_trigger(state->trig);
}
