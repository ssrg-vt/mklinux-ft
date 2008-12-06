/*
 * Procedures for creating, accessing and interpreting the device tree.
 *
 * Paul Mackerras	August 1996.
 * Copyright (C) 1996-2005 Paul Mackerras.
 * 
 *  Adapted for 64bit PowerPC by Dave Engebretsen and Peter Bergner.
 *    {engebret|bergner}@us.ibm.com 
 *
 *  Adapted for sparc64 by David S. Miller davem@davemloft.net
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/lmb.h>
#include <linux/of_device.h>

#include <asm/prom.h>
#include <asm/oplib.h>
#include <asm/irq.h>
#include <asm/asi.h>
#include <asm/upa.h>
#include <asm/smp.h>

#include "prom.h"

static unsigned int prom_early_allocated __initdata;

void * __init prom_early_alloc(unsigned long size)
{
	unsigned long paddr = lmb_alloc(size, SMP_CACHE_BYTES);
	void *ret;

	if (!paddr) {
		prom_printf("prom_early_alloc(%lu) failed\n");
		prom_halt();
	}

	ret = __va(paddr);
	memset(ret, 0, size);
	prom_early_allocated += size;

	return ret;
}

static int is_root_node(const struct device_node *dp)
{
	if (!dp)
		return 0;

	return (dp->parent == NULL);
}

/* The following routines deal with the black magic of fully naming a
 * node.
 *
 * Certain well known named nodes are just the simple name string.
 *
 * Actual devices have an address specifier appended to the base name
 * string, like this "foo@addr".  The "addr" can be in any number of
 * formats, and the platform plus the type of the node determine the
 * format and how it is constructed.
 *
 * For children of the ROOT node, the naming convention is fixed and
 * determined by whether this is a sun4u or sun4v system.
 *
 * For children of other nodes, it is bus type specific.  So
 * we walk up the tree until we discover a "device_type" property
 * we recognize and we go from there.
 *
 * As an example, the boot device on my workstation has a full path:
 *
 *	/pci@1e,600000/ide@d/disk@0,0:c
 */
static void __init sun4v_path_component(struct device_node *dp, char *tmp_buf)
{
	struct linux_prom64_registers *regs;
	struct property *rprop;
	u32 high_bits, low_bits, type;

	rprop = of_find_property(dp, "reg", NULL);
	if (!rprop)
		return;

	regs = rprop->value;
	if (!is_root_node(dp->parent)) {
		sprintf(tmp_buf, "%s@%x,%x",
			dp->name,
			(unsigned int) (regs->phys_addr >> 32UL),
			(unsigned int) (regs->phys_addr & 0xffffffffUL));
		return;
	}

	type = regs->phys_addr >> 60UL;
	high_bits = (regs->phys_addr >> 32UL) & 0x0fffffffUL;
	low_bits = (regs->phys_addr & 0xffffffffUL);

	if (type == 0 || type == 8) {
		const char *prefix = (type == 0) ? "m" : "i";

		if (low_bits)
			sprintf(tmp_buf, "%s@%s%x,%x",
				dp->name, prefix,
				high_bits, low_bits);
		else
			sprintf(tmp_buf, "%s@%s%x",
				dp->name,
				prefix,
				high_bits);
	} else if (type == 12) {
		sprintf(tmp_buf, "%s@%x",
			dp->name, high_bits);
	}
}

static void __init sun4u_path_component(struct device_node *dp, char *tmp_buf)
{
	struct linux_prom64_registers *regs;
	struct property *prop;

	prop = of_find_property(dp, "reg", NULL);
	if (!prop)
		return;

	regs = prop->value;
	if (!is_root_node(dp->parent)) {
		sprintf(tmp_buf, "%s@%x,%x",
			dp->name,
			(unsigned int) (regs->phys_addr >> 32UL),
			(unsigned int) (regs->phys_addr & 0xffffffffUL));
		return;
	}

	prop = of_find_property(dp, "upa-portid", NULL);
	if (!prop)
		prop = of_find_property(dp, "portid", NULL);
	if (prop) {
		unsigned long mask = 0xffffffffUL;

		if (tlb_type >= cheetah)
			mask = 0x7fffff;

		sprintf(tmp_buf, "%s@%x,%x",
			dp->name,
			*(u32 *)prop->value,
			(unsigned int) (regs->phys_addr & mask));
	}
}

/* "name@slot,offset"  */
static void __init sbus_path_component(struct device_node *dp, char *tmp_buf)
{
	struct linux_prom_registers *regs;
	struct property *prop;

	prop = of_find_property(dp, "reg", NULL);
	if (!prop)
		return;

	regs = prop->value;
	sprintf(tmp_buf, "%s@%x,%x",
		dp->name,
		regs->which_io,
		regs->phys_addr);
}

/* "name@devnum[,func]" */
static void __init pci_path_component(struct device_node *dp, char *tmp_buf)
{
	struct linux_prom_pci_registers *regs;
	struct property *prop;
	unsigned int devfn;

	prop = of_find_property(dp, "reg", NULL);
	if (!prop)
		return;

	regs = prop->value;
	devfn = (regs->phys_hi >> 8) & 0xff;
	if (devfn & 0x07) {
		sprintf(tmp_buf, "%s@%x,%x",
			dp->name,
			devfn >> 3,
			devfn & 0x07);
	} else {
		sprintf(tmp_buf, "%s@%x",
			dp->name,
			devfn >> 3);
	}
}

/* "name@UPA_PORTID,offset" */
static void __init upa_path_component(struct device_node *dp, char *tmp_buf)
{
	struct linux_prom64_registers *regs;
	struct property *prop;

	prop = of_find_property(dp, "reg", NULL);
	if (!prop)
		return;

	regs = prop->value;

	prop = of_find_property(dp, "upa-portid", NULL);
	if (!prop)
		return;

	sprintf(tmp_buf, "%s@%x,%x",
		dp->name,
		*(u32 *) prop->value,
		(unsigned int) (regs->phys_addr & 0xffffffffUL));
}

/* "name@reg" */
static void __init vdev_path_component(struct device_node *dp, char *tmp_buf)
{
	struct property *prop;
	u32 *regs;

	prop = of_find_property(dp, "reg", NULL);
	if (!prop)
		return;

	regs = prop->value;

	sprintf(tmp_buf, "%s@%x", dp->name, *regs);
}

/* "name@addrhi,addrlo" */
static void __init ebus_path_component(struct device_node *dp, char *tmp_buf)
{
	struct linux_prom64_registers *regs;
	struct property *prop;

	prop = of_find_property(dp, "reg", NULL);
	if (!prop)
		return;

	regs = prop->value;

	sprintf(tmp_buf, "%s@%x,%x",
		dp->name,
		(unsigned int) (regs->phys_addr >> 32UL),
		(unsigned int) (regs->phys_addr & 0xffffffffUL));
}

/* "name@bus,addr" */
static void __init i2c_path_component(struct device_node *dp, char *tmp_buf)
{
	struct property *prop;
	u32 *regs;

	prop = of_find_property(dp, "reg", NULL);
	if (!prop)
		return;

	regs = prop->value;

	/* This actually isn't right... should look at the #address-cells
	 * property of the i2c bus node etc. etc.
	 */
	sprintf(tmp_buf, "%s@%x,%x",
		dp->name, regs[0], regs[1]);
}

/* "name@reg0[,reg1]" */
static void __init usb_path_component(struct device_node *dp, char *tmp_buf)
{
	struct property *prop;
	u32 *regs;

	prop = of_find_property(dp, "reg", NULL);
	if (!prop)
		return;

	regs = prop->value;

	if (prop->length == sizeof(u32) || regs[1] == 1) {
		sprintf(tmp_buf, "%s@%x",
			dp->name, regs[0]);
	} else {
		sprintf(tmp_buf, "%s@%x,%x",
			dp->name, regs[0], regs[1]);
	}
}

/* "name@reg0reg1[,reg2reg3]" */
static void __init ieee1394_path_component(struct device_node *dp, char *tmp_buf)
{
	struct property *prop;
	u32 *regs;

	prop = of_find_property(dp, "reg", NULL);
	if (!prop)
		return;

	regs = prop->value;

	if (regs[2] || regs[3]) {
		sprintf(tmp_buf, "%s@%08x%08x,%04x%08x",
			dp->name, regs[0], regs[1], regs[2], regs[3]);
	} else {
		sprintf(tmp_buf, "%s@%08x%08x",
			dp->name, regs[0], regs[1]);
	}
}

static void __init __build_path_component(struct device_node *dp, char *tmp_buf)
{
	struct device_node *parent = dp->parent;

	if (parent != NULL) {
		if (!strcmp(parent->type, "pci") ||
		    !strcmp(parent->type, "pciex")) {
			pci_path_component(dp, tmp_buf);
			return;
		}
		if (!strcmp(parent->type, "sbus")) {
			sbus_path_component(dp, tmp_buf);
			return;
		}
		if (!strcmp(parent->type, "upa")) {
			upa_path_component(dp, tmp_buf);
			return;
		}
		if (!strcmp(parent->type, "ebus")) {
			ebus_path_component(dp, tmp_buf);
			return;
		}
		if (!strcmp(parent->name, "usb") ||
		    !strcmp(parent->name, "hub")) {
			usb_path_component(dp, tmp_buf);
			return;
		}
		if (!strcmp(parent->type, "i2c")) {
			i2c_path_component(dp, tmp_buf);
			return;
		}
		if (!strcmp(parent->type, "firewire")) {
			ieee1394_path_component(dp, tmp_buf);
			return;
		}
		if (!strcmp(parent->type, "virtual-devices")) {
			vdev_path_component(dp, tmp_buf);
			return;
		}
		/* "isa" is handled with platform naming */
	}

	/* Use platform naming convention.  */
	if (tlb_type == hypervisor) {
		sun4v_path_component(dp, tmp_buf);
		return;
	} else {
		sun4u_path_component(dp, tmp_buf);
	}
}

static char * __init build_path_component(struct device_node *dp)
{
	char tmp_buf[64], *n;

	tmp_buf[0] = '\0';
	__build_path_component(dp, tmp_buf);
	if (tmp_buf[0] == '\0')
		strcpy(tmp_buf, dp->name);

	n = prom_early_alloc(strlen(tmp_buf) + 1);
	strcpy(n, tmp_buf);

	return n;
}

static char * __init build_full_name(struct device_node *dp)
{
	int len, ourlen, plen;
	char *n;

	plen = strlen(dp->parent->full_name);
	ourlen = strlen(dp->path_component_name);
	len = ourlen + plen + 2;

	n = prom_early_alloc(len);
	strcpy(n, dp->parent->full_name);
	if (!is_root_node(dp->parent)) {
		strcpy(n + plen, "/");
		plen++;
	}
	strcpy(n + plen, dp->path_component_name);

	return n;
}

static char * __init get_one_property(phandle node, const char *name)
{
	char *buf = "<NULL>";
	int len;

	len = prom_getproplen(node, name);
	if (len > 0) {
		buf = prom_early_alloc(len);
		prom_getproperty(node, name, buf, len);
	}

	return buf;
}

static struct device_node * __init create_node(phandle node, struct device_node *parent)
{
	struct device_node *dp;

	if (!node)
		return NULL;

	dp = prom_early_alloc(sizeof(*dp));
	dp->unique_id = prom_unique_id++;
	dp->parent = parent;

	kref_init(&dp->kref);

	dp->name = get_one_property(node, "name");
	dp->type = get_one_property(node, "device_type");
	dp->node = node;

	dp->properties = build_prop_list(node);

	irq_trans_init(dp);

	return dp;
}

static struct device_node * __init build_tree(struct device_node *parent, phandle node, struct device_node ***nextp)
{
	struct device_node *ret = NULL, *prev_sibling = NULL;
	struct device_node *dp;

	while (1) {
		dp = create_node(node, parent);
		if (!dp)
			break;

		if (prev_sibling)
			prev_sibling->sibling = dp;

		if (!ret)
			ret = dp;
		prev_sibling = dp;

		*(*nextp) = dp;
		*nextp = &dp->allnext;

		dp->path_component_name = build_path_component(dp);
		dp->full_name = build_full_name(dp);

		dp->child = build_tree(dp, prom_getchild(node), nextp);

		node = prom_getsibling(node);
	}

	return ret;
}

static const char *get_mid_prop(void)
{
	return (tlb_type == spitfire ? "upa-portid" : "portid");
}

struct device_node *of_find_node_by_cpuid(int cpuid)
{
	struct device_node *dp;
	const char *mid_prop = get_mid_prop();

	for_each_node_by_type(dp, "cpu") {
		int id = of_getintprop_default(dp, mid_prop, -1);
		const char *this_mid_prop = mid_prop;

		if (id < 0) {
			this_mid_prop = "cpuid";
			id = of_getintprop_default(dp, this_mid_prop, -1);
		}

		if (id < 0) {
			prom_printf("OF: Serious problem, cpu lacks "
				    "%s property", this_mid_prop);
			prom_halt();
		}
		if (cpuid == id)
			return dp;
	}
	return NULL;
}

static void __init of_fill_in_cpu_data(void)
{
	struct device_node *dp;
	const char *mid_prop = get_mid_prop();

	ncpus_probed = 0;
	for_each_node_by_type(dp, "cpu") {
		int cpuid = of_getintprop_default(dp, mid_prop, -1);
		const char *this_mid_prop = mid_prop;
		struct device_node *portid_parent;
		int portid = -1;

		portid_parent = NULL;
		if (cpuid < 0) {
			this_mid_prop = "cpuid";
			cpuid = of_getintprop_default(dp, this_mid_prop, -1);
			if (cpuid >= 0) {
				int limit = 2;

				portid_parent = dp;
				while (limit--) {
					portid_parent = portid_parent->parent;
					if (!portid_parent)
						break;
					portid = of_getintprop_default(portid_parent,
								       "portid", -1);
					if (portid >= 0)
						break;
				}
			}
		}

		if (cpuid < 0) {
			prom_printf("OF: Serious problem, cpu lacks "
				    "%s property", this_mid_prop);
			prom_halt();
		}

		ncpus_probed++;

#ifdef CONFIG_SMP
		if (cpuid >= NR_CPUS) {
			printk(KERN_WARNING "Ignoring CPU %d which is "
			       ">= NR_CPUS (%d)\n",
			       cpuid, NR_CPUS);
			continue;
		}
#else
		/* On uniprocessor we only want the values for the
		 * real physical cpu the kernel booted onto, however
		 * cpu_data() only has one entry at index 0.
		 */
		if (cpuid != real_hard_smp_processor_id())
			continue;
		cpuid = 0;
#endif

		cpu_data(cpuid).clock_tick =
			of_getintprop_default(dp, "clock-frequency", 0);

		if (portid_parent) {
			cpu_data(cpuid).dcache_size =
				of_getintprop_default(dp, "l1-dcache-size",
						      16 * 1024);
			cpu_data(cpuid).dcache_line_size =
				of_getintprop_default(dp, "l1-dcache-line-size",
						      32);
			cpu_data(cpuid).icache_size =
				of_getintprop_default(dp, "l1-icache-size",
						      8 * 1024);
			cpu_data(cpuid).icache_line_size =
				of_getintprop_default(dp, "l1-icache-line-size",
						      32);
			cpu_data(cpuid).ecache_size =
				of_getintprop_default(dp, "l2-cache-size", 0);
			cpu_data(cpuid).ecache_line_size =
				of_getintprop_default(dp, "l2-cache-line-size", 0);
			if (!cpu_data(cpuid).ecache_size ||
			    !cpu_data(cpuid).ecache_line_size) {
				cpu_data(cpuid).ecache_size =
					of_getintprop_default(portid_parent,
							      "l2-cache-size",
							      (4 * 1024 * 1024));
				cpu_data(cpuid).ecache_line_size =
					of_getintprop_default(portid_parent,
							      "l2-cache-line-size", 64);
			}

			cpu_data(cpuid).core_id = portid + 1;
			cpu_data(cpuid).proc_id = portid;
#ifdef CONFIG_SMP
			sparc64_multi_core = 1;
#endif
		} else {
			cpu_data(cpuid).dcache_size =
				of_getintprop_default(dp, "dcache-size", 16 * 1024);
			cpu_data(cpuid).dcache_line_size =
				of_getintprop_default(dp, "dcache-line-size", 32);

			cpu_data(cpuid).icache_size =
				of_getintprop_default(dp, "icache-size", 16 * 1024);
			cpu_data(cpuid).icache_line_size =
				of_getintprop_default(dp, "icache-line-size", 32);

			cpu_data(cpuid).ecache_size =
				of_getintprop_default(dp, "ecache-size",
						      (4 * 1024 * 1024));
			cpu_data(cpuid).ecache_line_size =
				of_getintprop_default(dp, "ecache-line-size", 64);

			cpu_data(cpuid).core_id = 0;
			cpu_data(cpuid).proc_id = -1;
		}

#ifdef CONFIG_SMP
		cpu_set(cpuid, cpu_present_map);
		cpu_set(cpuid, cpu_possible_map);
#endif
	}

	smp_fill_in_sib_core_maps();
}

struct device_node *of_console_device;
EXPORT_SYMBOL(of_console_device);

char *of_console_path;
EXPORT_SYMBOL(of_console_path);

char *of_console_options;
EXPORT_SYMBOL(of_console_options);

static void __init of_console_init(void)
{
	char *msg = "OF stdout device is: %s\n";
	struct device_node *dp;
	const char *type;
	phandle node;

	of_console_path = prom_early_alloc(256);
	if (prom_ihandle2path(prom_stdout, of_console_path, 256) < 0) {
		prom_printf("Cannot obtain path of stdout.\n");
		prom_halt();
	}
	of_console_options = strrchr(of_console_path, ':');
	if (of_console_options) {
		of_console_options++;
		if (*of_console_options == '\0')
			of_console_options = NULL;
	}

	node = prom_inst2pkg(prom_stdout);
	if (!node) {
		prom_printf("Cannot resolve stdout node from "
			    "instance %08x.\n", prom_stdout);
		prom_halt();
	}

	dp = of_find_node_by_phandle(node);
	type = of_get_property(dp, "device_type", NULL);
	if (!type) {
		prom_printf("Console stdout lacks device_type property.\n");
		prom_halt();
	}

	if (strcmp(type, "display") && strcmp(type, "serial")) {
		prom_printf("Console device_type is neither display "
			    "nor serial.\n");
		prom_halt();
	}

	of_console_device = dp;

	printk(msg, of_console_path);
}

void __init prom_build_devicetree(void)
{
	struct device_node **nextp;

	allnodes = create_node(prom_root_node, NULL);
	allnodes->path_component_name = "";
	allnodes->full_name = "/";

	nextp = &allnodes->allnext;
	allnodes->child = build_tree(allnodes,
				     prom_getchild(allnodes->node),
				     &nextp);
	of_console_init();

	printk("PROM: Built device tree with %u bytes of memory.\n",
	       prom_early_allocated);

	if (tlb_type != hypervisor)
		of_fill_in_cpu_data();
}
