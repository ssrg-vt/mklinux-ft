/*
 * Copyright (C) 2009 Lemote Inc.
 * Author: Wu Zhangjin, wuzj@lemote.com
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/bootmem.h>

#include <loongson.h>

void __init prom_init(void)
{
	/* init base address of io space */
	set_io_port_base((unsigned long)
		ioremap(LOONGSON_PCIIO_BASE, LOONGSON_PCIIO_SIZE));

	prom_init_cmdline();
	prom_init_env();
	prom_init_memory();

	/*init the uart base address */
#if defined(CONFIG_EARLY_PRINTK) || defined(CONFIG_SERIAL_8250)
	prom_init_uart_base();
#endif
}

void __init prom_free_prom_memory(void)
{
}
