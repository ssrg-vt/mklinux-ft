/*
 * support.c - standard functions for the use of pnp protocol drivers
 *
 * Copyright 2003 Adam Belay <ambx1@neo.rr.com>
 */

#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/pnp.h>
#include "base.h"

/**
 * pnp_is_active - Determines if a device is active based on its current
 *	resources
 * @dev: pointer to the desired PnP device
 */
int pnp_is_active(struct pnp_dev *dev)
{
	/*
	 * I don't think this is very reliable because pnp_disable_dev()
	 * only clears out auto-assigned resources.
	 */
	if (!pnp_port_start(dev, 0) && pnp_port_len(dev, 0) <= 1 &&
	    !pnp_mem_start(dev, 0) && pnp_mem_len(dev, 0) <= 1 &&
	    pnp_irq(dev, 0) == -1 && pnp_dma(dev, 0) == -1)
		return 0;
	else
		return 1;
}

EXPORT_SYMBOL(pnp_is_active);

/*
 * Functionally similar to acpi_ex_eisa_id_to_string(), but that's
 * buried in the ACPI CA, and we can't depend on it being present.
 */
void pnp_eisa_id_to_string(u32 id, char *str)
{
	id = be32_to_cpu(id);

	/*
	 * According to the specs, the first three characters are five-bit
	 * compressed ASCII, and the left-over high order bit should be zero.
	 * However, the Linux ISAPNP code historically used six bits for the
	 * first character, and there seem to be IDs that depend on that,
	 * e.g., "nEC8241" in the Linux 8250_pnp serial driver and the
	 * FreeBSD sys/pc98/cbus/sio_cbus.c driver.
	 */
	str[0] = 'A' + ((id >> 26) & 0x3f) - 1;
	str[1] = 'A' + ((id >> 21) & 0x1f) - 1;
	str[2] = 'A' + ((id >> 16) & 0x1f) - 1;
	str[3] = hex_asc_hi(id >> 8);
	str[4] = hex_asc_lo(id >> 8);
	str[5] = hex_asc_hi(id);
	str[6] = hex_asc_lo(id);
	str[7] = '\0';
}

char *pnp_resource_type_name(struct resource *res)
{
	switch (pnp_resource_type(res)) {
	case IORESOURCE_IO:
		return "io";
	case IORESOURCE_MEM:
		return "mem";
	case IORESOURCE_IRQ:
		return "irq";
	case IORESOURCE_DMA:
		return "dma";
	}
	return NULL;
}

void dbg_pnp_show_resources(struct pnp_dev *dev, char *desc)
{
#ifdef DEBUG
	char buf[128];
	int len = 0;
	struct pnp_resource *pnp_res;
	struct resource *res;

	dev_dbg(&dev->dev, "current resources: %s\n", desc);
	list_for_each_entry(pnp_res, &dev->resources, list) {
		res = &pnp_res->res;

		len += snprintf(buf + len, sizeof(buf) - len, "  %-3s ",
				pnp_resource_type_name(res));

		if (res->flags & IORESOURCE_DISABLED) {
			dev_dbg(&dev->dev, "%sdisabled\n", buf);
			continue;
		}

		switch (pnp_resource_type(res)) {
		case IORESOURCE_IO:
		case IORESOURCE_MEM:
			len += snprintf(buf + len, sizeof(buf) - len,
					"%#llx-%#llx flags %#lx",
					(unsigned long long) res->start,
					(unsigned long long) res->end,
					res->flags);
			break;
		case IORESOURCE_IRQ:
		case IORESOURCE_DMA:
			len += snprintf(buf + len, sizeof(buf) - len,
					"%lld flags %#lx",
					(unsigned long long) res->start,
					res->flags);
			break;
		}
		dev_dbg(&dev->dev, "%s\n", buf);
	}
#endif
}
