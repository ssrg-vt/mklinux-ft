/*
 *  include/linux/mmc/sdio_func.h
 *
 *  Copyright 2007 Pierre Ossman
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

#ifndef MMC_SDIO_FUNC_H
#define MMC_SDIO_FUNC_H

struct mmc_card;

/*
 * SDIO function devices
 */
struct sdio_func {
	struct mmc_card		*card;		/* the card this device belongs to */
	struct device		dev;		/* the device */
	unsigned int		num;		/* function number */
	unsigned int		state;		/* function state */
#define SDIO_STATE_PRESENT	(1<<0)		/* present in sysfs */
};

#define sdio_func_present(f)	((f)->state & SDIO_STATE_PRESENT)

#define sdio_func_set_present(f) ((f)->state |= SDIO_STATE_PRESENT)

#define sdio_func_id(f)		((f)->dev.bus_id)

#define sdio_get_drvdata(f)	dev_get_drvdata(&(f)->dev)
#define sdio_set_drvdata(f,d)	dev_set_drvdata(&(f)->dev, d)

/*
 * SDIO function device driver
 */
struct sdio_driver {
	char *name;

	int (*probe)(struct sdio_func *);
	void (*remove)(struct sdio_func *);

	struct device_driver drv;
};

extern int sdio_register_driver(struct sdio_driver *);
extern void sdio_unregister_driver(struct sdio_driver *);

#endif

