/*
 *  linux/drivers/net/netconsole.c
 *
 *  Copyright (C) 2001  Ingo Molnar <mingo@redhat.com>
 *
 *  This file contains the implementation of an IRQ-safe, crash-safe
 *  kernel console implementation that outputs kernel messages to the
 *  network.
 *
 * Modification history:
 *
 * 2001-09-17    started by Ingo Molnar.
 * 2003-08-11    2.6 port by Matt Mackall
 *               simplified options
 *               generic card hooks
 *               works non-modular
 * 2003-09-07    rewritten with netpoll api
 */

/****************************************************************
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2, or (at your option)
 *      any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 ****************************************************************/

#include <linux/mm.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/console.h>
#include <linux/moduleparam.h>
#include <linux/string.h>
#include <linux/netpoll.h>

MODULE_AUTHOR("Maintainer: Matt Mackall <mpm@selenic.com>");
MODULE_DESCRIPTION("Console driver for network interfaces");
MODULE_LICENSE("GPL");

#define MAX_PARAM_LENGTH	256
#define MAX_PRINT_CHUNK		1000

static char config[MAX_PARAM_LENGTH];
module_param_string(netconsole, config, MAX_PARAM_LENGTH, 0);
MODULE_PARM_DESC(netconsole, " netconsole=[src-port]@[src-ip]/[dev],[tgt-port]@<tgt-ip>/[tgt-macaddr]\n");

#ifndef	MODULE
static int __init option_setup(char *opt)
{
	strlcpy(config, opt, MAX_PARAM_LENGTH);
	return 1;
}
__setup("netconsole=", option_setup);
#endif	/* MODULE */

/**
 * struct netconsole_target - Represents a configured netconsole target.
 * @np:		The netpoll structure for this target.
 */
struct netconsole_target {
	struct netpoll		np;
};

static struct netconsole_target default_target = {
	.np		= {
		.name		= "netconsole",
		.dev_name	= "eth0",
		.local_port	= 6665,
		.remote_port	= 6666,
		.remote_mac	= {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

/* Handle network interface device notifications */
static int netconsole_netdev_event(struct notifier_block *this,
				   unsigned long event,
				   void *ptr)
{
	struct net_device *dev = ptr;
	struct netconsole_target *nt = &default_target;

	if (nt->np.dev == dev) {
		switch (event) {
		case NETDEV_CHANGEADDR:
			memcpy(nt->np.local_mac, dev->dev_addr, ETH_ALEN);
			break;

		case NETDEV_CHANGENAME:
			strlcpy(nt->np.dev_name, dev->name, IFNAMSIZ);
			break;
		}
	}

	return NOTIFY_DONE;
}

static struct notifier_block netconsole_netdev_notifier = {
	.notifier_call  = netconsole_netdev_event,
};

static void write_msg(struct console *con, const char *msg, unsigned int len)
{
	int frag, left;
	unsigned long flags;
	struct netconsole_target *nt = &default_target;

	if (netif_running(nt->np.dev)) {
		local_irq_save(flags);
		for (left = len; left;) {
			frag = min(left, MAX_PRINT_CHUNK);
			netpoll_send_udp(&nt->np, msg, frag);
			msg += frag;
			left -= frag;
		}
		local_irq_restore(flags);
	}
}

static struct console netconsole = {
	.name	= "netcon",
	.flags	= CON_ENABLED | CON_PRINTBUFFER,
	.write	= write_msg,
};

static int __init init_netconsole(void)
{
	int err = 0;
	struct netconsole_target *nt = &default_target;

	if (!strnlen(config, MAX_PARAM_LENGTH)) {
		printk(KERN_INFO "netconsole: not configured, aborting\n");
		goto out;
	}

	err = netpoll_parse_options(&nt->np, config);
	if (err)
		goto out;

	err = netpoll_setup(&nt->np);
	if (err)
		goto out;

	err = register_netdevice_notifier(&netconsole_netdev_notifier);
	if (err)
		goto out;

	register_console(&netconsole);
	printk(KERN_INFO "netconsole: network logging started\n");

out:
	return err;
}

static void __exit cleanup_netconsole(void)
{
	struct netconsole_target *nt = &default_target;

	unregister_console(&netconsole);
	unregister_netdevice_notifier(&netconsole_netdev_notifier);
	netpoll_cleanup(&nt->np);
}

module_init(init_netconsole);
module_exit(cleanup_netconsole);
