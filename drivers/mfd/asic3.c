/*
 * driver/mfd/asic3.c
 *
 * Compaq ASIC3 support.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Copyright 2001 Compaq Computer Corporation.
 * Copyright 2004-2005 Phil Blundell
 * Copyright 2007-2008 OpenedHand Ltd.
 *
 * Authors: Phil Blundell <pb@handhelds.org>,
 *	    Samuel Ortiz <sameo@openedhand.com>
 *
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/irq.h>
#include <linux/gpio.h>
#include <linux/io.h>
#include <linux/spinlock.h>
#include <linux/platform_device.h>

#include <linux/mfd/asic3.h>

struct asic3 {
	void __iomem *mapping;
	unsigned int bus_shift;
	unsigned int irq_nr;
	unsigned int irq_base;
	spinlock_t lock;
	u16 irq_bothedge[4];
	struct gpio_chip gpio;
	struct device *dev;
};

static int asic3_gpio_get(struct gpio_chip *chip, unsigned offset);

static inline void asic3_write_register(struct asic3 *asic,
				 unsigned int reg, u32 value)
{
	iowrite16(value, asic->mapping +
		  (reg >> asic->bus_shift));
}

static inline u32 asic3_read_register(struct asic3 *asic,
			       unsigned int reg)
{
	return ioread16(asic->mapping +
			(reg >> asic->bus_shift));
}

/* IRQs */
#define MAX_ASIC_ISR_LOOPS    20
#define ASIC3_GPIO_Base_INCR \
	(ASIC3_GPIO_B_Base - ASIC3_GPIO_A_Base)

static void asic3_irq_flip_edge(struct asic3 *asic,
				u32 base, int bit)
{
	u16 edge;
	unsigned long flags;

	spin_lock_irqsave(&asic->lock, flags);
	edge = asic3_read_register(asic,
				   base + ASIC3_GPIO_EdgeTrigger);
	edge ^= bit;
	asic3_write_register(asic,
			     base + ASIC3_GPIO_EdgeTrigger, edge);
	spin_unlock_irqrestore(&asic->lock, flags);
}

static void asic3_irq_demux(unsigned int irq, struct irq_desc *desc)
{
	int iter, i;
	unsigned long flags;
	struct asic3 *asic;

	desc->chip->ack(irq);

	asic = desc->handler_data;

	for (iter = 0 ; iter < MAX_ASIC_ISR_LOOPS; iter++) {
		u32 status;
		int bank;

		spin_lock_irqsave(&asic->lock, flags);
		status = asic3_read_register(asic,
					     ASIC3_OFFSET(INTR, PIntStat));
		spin_unlock_irqrestore(&asic->lock, flags);

		/* Check all ten register bits */
		if ((status & 0x3ff) == 0)
			break;

		/* Handle GPIO IRQs */
		for (bank = 0; bank < ASIC3_NUM_GPIO_BANKS; bank++) {
			if (status & (1 << bank)) {
				unsigned long base, istat;

				base = ASIC3_GPIO_A_Base
				       + bank * ASIC3_GPIO_Base_INCR;

				spin_lock_irqsave(&asic->lock, flags);
				istat = asic3_read_register(asic,
							    base +
							    ASIC3_GPIO_IntStatus);
				/* Clearing IntStatus */
				asic3_write_register(asic,
						     base +
						     ASIC3_GPIO_IntStatus, 0);
				spin_unlock_irqrestore(&asic->lock, flags);

				for (i = 0; i < ASIC3_GPIOS_PER_BANK; i++) {
					int bit = (1 << i);
					unsigned int irqnr;

					if (!(istat & bit))
						continue;

					irqnr = asic->irq_base +
						(ASIC3_GPIOS_PER_BANK * bank)
						+ i;
					desc = irq_desc + irqnr;
					desc->handle_irq(irqnr, desc);
					if (asic->irq_bothedge[bank] & bit)
						asic3_irq_flip_edge(asic, base,
								    bit);
				}
			}
		}

		/* Handle remaining IRQs in the status register */
		for (i = ASIC3_NUM_GPIOS; i < ASIC3_NR_IRQS; i++) {
			/* They start at bit 4 and go up */
			if (status & (1 << (i - ASIC3_NUM_GPIOS + 4))) {
				desc = irq_desc +  + i;
				desc->handle_irq(asic->irq_base + i,
						 desc);
			}
		}
	}

	if (iter >= MAX_ASIC_ISR_LOOPS)
		printk(KERN_ERR "%s: interrupt processing overrun\n",
		       __func__);
}

static inline int asic3_irq_to_bank(struct asic3 *asic, int irq)
{
	int n;

	n = (irq - asic->irq_base) >> 4;

	return (n * (ASIC3_GPIO_B_Base - ASIC3_GPIO_A_Base));
}

static inline int asic3_irq_to_index(struct asic3 *asic, int irq)
{
	return (irq - asic->irq_base) & 0xf;
}

static void asic3_mask_gpio_irq(unsigned int irq)
{
	struct asic3 *asic = get_irq_chip_data(irq);
	u32 val, bank, index;
	unsigned long flags;

	bank = asic3_irq_to_bank(asic, irq);
	index = asic3_irq_to_index(asic, irq);

	spin_lock_irqsave(&asic->lock, flags);
	val = asic3_read_register(asic, bank + ASIC3_GPIO_Mask);
	val |= 1 << index;
	asic3_write_register(asic, bank + ASIC3_GPIO_Mask, val);
	spin_unlock_irqrestore(&asic->lock, flags);
}

static void asic3_mask_irq(unsigned int irq)
{
	struct asic3 *asic = get_irq_chip_data(irq);
	int regval;
	unsigned long flags;

	spin_lock_irqsave(&asic->lock, flags);
	regval = asic3_read_register(asic,
				     ASIC3_INTR_Base +
				     ASIC3_INTR_IntMask);

	regval &= ~(ASIC3_INTMASK_MASK0 <<
		    (irq - (asic->irq_base + ASIC3_NUM_GPIOS)));

	asic3_write_register(asic,
			     ASIC3_INTR_Base +
			     ASIC3_INTR_IntMask,
			     regval);
	spin_unlock_irqrestore(&asic->lock, flags);
}

static void asic3_unmask_gpio_irq(unsigned int irq)
{
	struct asic3 *asic = get_irq_chip_data(irq);
	u32 val, bank, index;
	unsigned long flags;

	bank = asic3_irq_to_bank(asic, irq);
	index = asic3_irq_to_index(asic, irq);

	spin_lock_irqsave(&asic->lock, flags);
	val = asic3_read_register(asic, bank + ASIC3_GPIO_Mask);
	val &= ~(1 << index);
	asic3_write_register(asic, bank + ASIC3_GPIO_Mask, val);
	spin_unlock_irqrestore(&asic->lock, flags);
}

static void asic3_unmask_irq(unsigned int irq)
{
	struct asic3 *asic = get_irq_chip_data(irq);
	int regval;
	unsigned long flags;

	spin_lock_irqsave(&asic->lock, flags);
	regval = asic3_read_register(asic,
				     ASIC3_INTR_Base +
				     ASIC3_INTR_IntMask);

	regval |= (ASIC3_INTMASK_MASK0 <<
		   (irq - (asic->irq_base + ASIC3_NUM_GPIOS)));

	asic3_write_register(asic,
			     ASIC3_INTR_Base +
			     ASIC3_INTR_IntMask,
			     regval);
	spin_unlock_irqrestore(&asic->lock, flags);
}

static int asic3_gpio_irq_type(unsigned int irq, unsigned int type)
{
	struct asic3 *asic = get_irq_chip_data(irq);
	u32 bank, index;
	u16 trigger, level, edge, bit;
	unsigned long flags;

	bank = asic3_irq_to_bank(asic, irq);
	index = asic3_irq_to_index(asic, irq);
	bit = 1<<index;

	spin_lock_irqsave(&asic->lock, flags);
	level = asic3_read_register(asic,
				    bank + ASIC3_GPIO_LevelTrigger);
	edge = asic3_read_register(asic,
				   bank + ASIC3_GPIO_EdgeTrigger);
	trigger = asic3_read_register(asic,
				      bank + ASIC3_GPIO_TriggerType);
	asic->irq_bothedge[(irq - asic->irq_base) >> 4] &= ~bit;

	if (type == IRQT_RISING) {
		trigger |= bit;
		edge |= bit;
	} else if (type == IRQT_FALLING) {
		trigger |= bit;
		edge &= ~bit;
	} else if (type == IRQT_BOTHEDGE) {
		trigger |= bit;
		if (asic3_gpio_get(&asic->gpio, irq - asic->irq_base))
			edge &= ~bit;
		else
			edge |= bit;
		asic->irq_bothedge[(irq - asic->irq_base) >> 4] |= bit;
	} else if (type == IRQT_LOW) {
		trigger &= ~bit;
		level &= ~bit;
	} else if (type == IRQT_HIGH) {
		trigger &= ~bit;
		level |= bit;
	} else {
		/*
		 * if type == IRQT_NOEDGE, we should mask interrupts, but
		 * be careful to not unmask them if mask was also called.
		 * Probably need internal state for mask.
		 */
		printk(KERN_NOTICE "asic3: irq type not changed.\n");
	}
	asic3_write_register(asic, bank + ASIC3_GPIO_LevelTrigger,
			     level);
	asic3_write_register(asic, bank + ASIC3_GPIO_EdgeTrigger,
			     edge);
	asic3_write_register(asic, bank + ASIC3_GPIO_TriggerType,
			     trigger);
	spin_unlock_irqrestore(&asic->lock, flags);
	return 0;
}

static struct irq_chip asic3_gpio_irq_chip = {
	.name		= "ASIC3-GPIO",
	.ack		= asic3_mask_gpio_irq,
	.mask		= asic3_mask_gpio_irq,
	.unmask		= asic3_unmask_gpio_irq,
	.set_type	= asic3_gpio_irq_type,
};

static struct irq_chip asic3_irq_chip = {
	.name		= "ASIC3",
	.ack		= asic3_mask_irq,
	.mask		= asic3_mask_irq,
	.unmask		= asic3_unmask_irq,
};

static int asic3_irq_probe(struct platform_device *pdev)
{
	struct asic3 *asic = platform_get_drvdata(pdev);
	unsigned long clksel = 0;
	unsigned int irq, irq_base;

	asic->irq_nr = platform_get_irq(pdev, 0);
	if (asic->irq_nr < 0)
		return asic->irq_nr;

	/* turn on clock to IRQ controller */
	clksel |= CLOCK_SEL_CX;
	asic3_write_register(asic, ASIC3_OFFSET(CLOCK, SEL),
			     clksel);

	irq_base = asic->irq_base;

	for (irq = irq_base; irq < irq_base + ASIC3_NR_IRQS; irq++) {
		if (irq < asic->irq_base + ASIC3_NUM_GPIOS)
			set_irq_chip(irq, &asic3_gpio_irq_chip);
		else
			set_irq_chip(irq, &asic3_irq_chip);

		set_irq_chip_data(irq, asic);
		set_irq_handler(irq, handle_level_irq);
		set_irq_flags(irq, IRQF_VALID | IRQF_PROBE);
	}

	asic3_write_register(asic, ASIC3_OFFSET(INTR, IntMask),
			     ASIC3_INTMASK_GINTMASK);

	set_irq_chained_handler(asic->irq_nr, asic3_irq_demux);
	set_irq_type(asic->irq_nr, IRQT_RISING);
	set_irq_data(asic->irq_nr, asic);

	return 0;
}

static void asic3_irq_remove(struct platform_device *pdev)
{
	struct asic3 *asic = platform_get_drvdata(pdev);
	unsigned int irq, irq_base;

	irq_base = asic->irq_base;

	for (irq = irq_base; irq < irq_base + ASIC3_NR_IRQS; irq++) {
		set_irq_flags(irq, 0);
		set_irq_handler(irq, NULL);
		set_irq_chip(irq, NULL);
		set_irq_chip_data(irq, NULL);
	}
	set_irq_chained_handler(asic->irq_nr, NULL);
}

/* GPIOs */
static int asic3_gpio_direction(struct gpio_chip *chip,
				unsigned offset, int out)
{
	u32 mask = ASIC3_GPIO_TO_MASK(offset), out_reg;
	unsigned int gpio_base;
	unsigned long flags;
	struct asic3 *asic;

	asic = container_of(chip, struct asic3, gpio);
	gpio_base = ASIC3_GPIO_TO_BASE(offset);

	if (gpio_base > ASIC3_GPIO_D_Base) {
		printk(KERN_ERR "Invalid base (0x%x) for gpio %d\n",
		       gpio_base, offset);
		return -EINVAL;
	}

	spin_lock_irqsave(&asic->lock, flags);

	out_reg = asic3_read_register(asic, gpio_base + ASIC3_GPIO_Direction);

	/* Input is 0, Output is 1 */
	if (out)
		out_reg |= mask;
	else
		out_reg &= ~mask;

	asic3_write_register(asic, gpio_base + ASIC3_GPIO_Direction, out_reg);

	spin_unlock_irqrestore(&asic->lock, flags);

	return 0;

}

static int asic3_gpio_direction_input(struct gpio_chip *chip,
				      unsigned offset)
{
	return asic3_gpio_direction(chip, offset, 0);
}

static int asic3_gpio_direction_output(struct gpio_chip *chip,
				       unsigned offset, int value)
{
	return asic3_gpio_direction(chip, offset, 1);
}

static int asic3_gpio_get(struct gpio_chip *chip,
			  unsigned offset)
{
	unsigned int gpio_base;
	u32 mask = ASIC3_GPIO_TO_MASK(offset);
	struct asic3 *asic;

	asic = container_of(chip, struct asic3, gpio);
	gpio_base = ASIC3_GPIO_TO_BASE(offset);

	if (gpio_base > ASIC3_GPIO_D_Base) {
		printk(KERN_ERR "Invalid base (0x%x) for gpio %d\n",
		       gpio_base, offset);
		return -EINVAL;
	}

	return asic3_read_register(asic, gpio_base + ASIC3_GPIO_Status) & mask;
}

static void asic3_gpio_set(struct gpio_chip *chip,
			   unsigned offset, int value)
{
	u32 mask, out_reg;
	unsigned int gpio_base;
	unsigned long flags;
	struct asic3 *asic;

	asic = container_of(chip, struct asic3, gpio);
	gpio_base = ASIC3_GPIO_TO_BASE(offset);

	if (gpio_base > ASIC3_GPIO_D_Base) {
		printk(KERN_ERR "Invalid base (0x%x) for gpio %d\n",
		       gpio_base, offset);
		return;
	}

	mask = ASIC3_GPIO_TO_MASK(offset);

	spin_lock_irqsave(&asic->lock, flags);

	out_reg = asic3_read_register(asic, gpio_base + ASIC3_GPIO_Out);

	if (value)
		out_reg |= mask;
	else
		out_reg &= ~mask;

	asic3_write_register(asic, gpio_base + ASIC3_GPIO_Out, out_reg);

	spin_unlock_irqrestore(&asic->lock, flags);

	return;
}

static inline u32 asic3_get_gpio(struct asic3 *asic, unsigned int base,
				 unsigned int function)
{
	return asic3_read_register(asic, base + function);
}

static void asic3_set_gpio(struct asic3 *asic, unsigned int base,
			   unsigned int function, u32 bits, u32 val)
{
	unsigned long flags;

	spin_lock_irqsave(&asic->lock, flags);
	val |= (asic3_read_register(asic, base + function) & ~bits);

	asic3_write_register(asic, base + function, val);
	spin_unlock_irqrestore(&asic->lock, flags);
}

#define asic3_set_gpio_a(asic, fn, bits, val) \
	asic3_set_gpio(asic, ASIC3_GPIO_A_Base, ASIC3_GPIO_##fn, bits, val)
#define asic3_set_gpio_b(asic, fn, bits, val) \
	asic3_set_gpio(asic, ASIC3_GPIO_B_Base, ASIC3_GPIO_##fn, bits, val)
#define asic3_set_gpio_c(asic, fn, bits, val) \
	asic3_set_gpio(asic, ASIC3_GPIO_C_Base, ASIC3_GPIO_##fn, bits, val)
#define asic3_set_gpio_d(asic, fn, bits, val) \
	asic3_set_gpio(asic, ASIC3_GPIO_D_Base, ASIC3_GPIO_##fn, bits, val)

#define asic3_set_gpio_banks(asic, fn, bits, pdata, field) 		  \
	do {								  \
	     asic3_set_gpio_a((asic), fn, (bits), (pdata)->gpio_a.field); \
	     asic3_set_gpio_b((asic), fn, (bits), (pdata)->gpio_b.field); \
	     asic3_set_gpio_c((asic), fn, (bits), (pdata)->gpio_c.field); \
	     asic3_set_gpio_d((asic), fn, (bits), (pdata)->gpio_d.field); \
	} while (0)


static int asic3_gpio_probe(struct platform_device *pdev)
{
	struct asic3_platform_data *pdata = pdev->dev.platform_data;
	struct asic3 *asic = platform_get_drvdata(pdev);

	asic3_write_register(asic, ASIC3_GPIO_OFFSET(A, Mask), 0xffff);
	asic3_write_register(asic, ASIC3_GPIO_OFFSET(B, Mask), 0xffff);
	asic3_write_register(asic, ASIC3_GPIO_OFFSET(C, Mask), 0xffff);
	asic3_write_register(asic, ASIC3_GPIO_OFFSET(D, Mask), 0xffff);

	asic3_set_gpio_a(asic, SleepMask, 0xffff, 0xffff);
	asic3_set_gpio_b(asic, SleepMask, 0xffff, 0xffff);
	asic3_set_gpio_c(asic, SleepMask, 0xffff, 0xffff);
	asic3_set_gpio_d(asic, SleepMask, 0xffff, 0xffff);

	if (pdata) {
		asic3_set_gpio_banks(asic, Out, 0xffff, pdata, init);
		asic3_set_gpio_banks(asic, Direction, 0xffff, pdata, dir);
		asic3_set_gpio_banks(asic, SleepMask, 0xffff, pdata,
				     sleep_mask);
		asic3_set_gpio_banks(asic, SleepOut, 0xffff, pdata, sleep_out);
		asic3_set_gpio_banks(asic, BattFaultOut, 0xffff, pdata,
				     batt_fault_out);
		asic3_set_gpio_banks(asic, SleepConf, 0xffff, pdata,
				     sleep_conf);
		asic3_set_gpio_banks(asic, AltFunction, 0xffff, pdata,
				     alt_function);
	}

	return gpiochip_add(&asic->gpio);
}

static int asic3_gpio_remove(struct platform_device *pdev)
{
	struct asic3 *asic = platform_get_drvdata(pdev);

	return gpiochip_remove(&asic->gpio);
}


/* Core */
static int asic3_probe(struct platform_device *pdev)
{
	struct asic3_platform_data *pdata = pdev->dev.platform_data;
	struct asic3 *asic;
	struct resource *mem;
	unsigned long clksel;
	int ret = 0;

	asic = kzalloc(sizeof(struct asic3), GFP_KERNEL);
	if (asic == NULL) {
		printk(KERN_ERR "kzalloc failed\n");
		return -ENOMEM;
	}

	spin_lock_init(&asic->lock);
	platform_set_drvdata(pdev, asic);
	asic->dev = &pdev->dev;

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!mem) {
		ret = -ENOMEM;
		printk(KERN_ERR "asic3: no MEM resource\n");
		goto out_free;
	}


	asic->mapping = ioremap(mem->start, PAGE_SIZE);
	if (!asic->mapping) {
		ret = -ENOMEM;
		printk(KERN_ERR "asic3: couldn't ioremap\n");
		goto out_free;
	}

	asic->irq_base = pdata->irq_base;

	if (pdata && pdata->bus_shift)
		asic->bus_shift = 2 - pdata->bus_shift;
	else
		asic->bus_shift = 0;

	clksel = 0;
	asic3_write_register(asic, ASIC3_OFFSET(CLOCK, SEL), clksel);

	ret = asic3_irq_probe(pdev);
	if (ret < 0) {
		printk(KERN_ERR "asic3: couldn't probe IRQs\n");
		goto out_unmap;
	}

	asic->gpio.base = pdata->gpio_base;
	asic->gpio.ngpio = ASIC3_NUM_GPIOS;
	asic->gpio.get = asic3_gpio_get;
	asic->gpio.set = asic3_gpio_set;
	asic->gpio.direction_input = asic3_gpio_direction_input;
	asic->gpio.direction_output = asic3_gpio_direction_output;

	ret = asic3_gpio_probe(pdev);
	if (ret < 0) {
		printk(KERN_ERR "GPIO probe failed\n");
		goto out_irq;
	}

	if (pdata->children) {
		int i;
		for (i = 0; i < pdata->n_children; i++) {
			pdata->children[i]->dev.parent = &pdev->dev;
			platform_device_register(pdata->children[i]);
		}
	}

	printk(KERN_INFO "ASIC3 Core driver\n");

	return 0;

 out_irq:
	asic3_irq_remove(pdev);

 out_unmap:
	iounmap(asic->mapping);

 out_free:
	kfree(asic);

	return ret;
}

static int asic3_remove(struct platform_device *pdev)
{
	int ret;
	struct asic3 *asic = platform_get_drvdata(pdev);

	ret = asic3_gpio_remove(pdev);
	if (ret < 0)
		return ret;
	asic3_irq_remove(pdev);

	asic3_write_register(asic, ASIC3_OFFSET(CLOCK, SEL), 0);

	iounmap(asic->mapping);

	kfree(asic);

	return 0;
}

static void asic3_shutdown(struct platform_device *pdev)
{
}

static struct platform_driver asic3_device_driver = {
	.driver		= {
		.name	= "asic3",
	},
	.probe		= asic3_probe,
	.remove		= __devexit_p(asic3_remove),
	.shutdown	= asic3_shutdown,
};

static int __init asic3_init(void)
{
	int retval = 0;
	retval = platform_driver_register(&asic3_device_driver);
	return retval;
}

subsys_initcall(asic3_init);
