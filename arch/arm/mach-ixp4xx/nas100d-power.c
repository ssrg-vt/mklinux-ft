/*
 * arch/arm/mach-ixp4xx/nas100d-power.c
 *
 * NAS 100d Power/Reset driver
 *
 * Copyright (C) 2005 Tower Technologies
 *
 * based on nas100d-io.c
 *  Copyright (C) 2004 Karen Spearel
 *
 * Author: Alessandro Zummo <a.zummo@towertech.it>
 * Maintainers: http://www.nslu2-linux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/reboot.h>
#include <linux/jiffies.h>
#include <linux/timer.h>

#include <asm/gpio.h>
#include <asm/mach-types.h>

/* This is used to make sure the power-button pusher is serious.  The button
 * must be held until the value of this counter reaches zero.
 */
static int power_button_countdown;

/* Must hold the button down for at least this many counts to be processed */
#define PBUTTON_HOLDDOWN_COUNT 4 /* 2 secs */

static void nas100d_power_handler(unsigned long data);
static DEFINE_TIMER(nas100d_power_timer, nas100d_power_handler, 0, 0);

static void nas100d_power_handler(unsigned long data)
{
	/* This routine is called twice per second to check the
	 * state of the power button.
	 */

	if (gpio_get_value(NAS100D_PB_GPIO)) {

		/* IO Pin is 1 (button pushed) */
		if (power_button_countdown > 0)
			power_button_countdown--;

	} else {

		/* Done on button release, to allow for auto-power-on mods. */
		if (power_button_countdown == 0) {
			/* Signal init to do the ctrlaltdel action,
			 * this will bypass init if it hasn't started
			 * and do a kernel_restart.
			 */
			ctrl_alt_del();

			/* Change the state of the power LED to "blink" */
			gpio_line_set(NAS100D_LED_PWR_GPIO, IXP4XX_GPIO_LOW);
		} else {
			power_button_countdown = PBUTTON_HOLDDOWN_COUNT;
		}
	}

	mod_timer(&nas100d_power_timer, jiffies + msecs_to_jiffies(500));
}

static irqreturn_t nas100d_reset_handler(int irq, void *dev_id)
{
	/* This is the paper-clip reset, it shuts the machine down directly. */
	machine_power_off();

	return IRQ_HANDLED;
}

static int __init nas100d_power_init(void)
{
	if (!(machine_is_nas100d()))
		return 0;

	set_irq_type(gpio_to_irq(NAS100D_RB_GPIO), IRQT_LOW);

	if (request_irq(gpio_to_irq(NAS100D_RB_GPIO), &nas100d_reset_handler,
		IRQF_DISABLED, "NAS100D reset button", NULL) < 0) {

		printk(KERN_DEBUG "Reset Button IRQ %d not available\n",
			gpio_to_irq(NAS100D_RB_GPIO));

		return -EIO;
	}

	/* The power button on the Iomega NAS100d is on GPIO 14, but
	 * it cannot handle interrupts on that GPIO line.  So we'll
	 * have to poll it with a kernel timer.
	 */

	/* Make sure that the power button GPIO is set up as an input */
	gpio_line_config(NAS100D_PB_GPIO, IXP4XX_GPIO_IN);

	/* Set the initial value for the power button IRQ handler */
	power_button_countdown = PBUTTON_HOLDDOWN_COUNT;

	mod_timer(&nas100d_power_timer, jiffies + msecs_to_jiffies(500));

	return 0;
}

static void __exit nas100d_power_exit(void)
{
	if (!(machine_is_nas100d()))
		return;

	del_timer_sync(&nas100d_power_timer);

	free_irq(gpio_to_irq(NAS100D_RB_GPIO), NULL);
}

module_init(nas100d_power_init);
module_exit(nas100d_power_exit);

MODULE_AUTHOR("Alessandro Zummo <a.zummo@towertech.it>");
MODULE_DESCRIPTION("NAS100D Power/Reset driver");
MODULE_LICENSE("GPL");
