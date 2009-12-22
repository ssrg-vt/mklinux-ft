/*
 * arch/ia64/kernel/acpi-processor.c
 *
 * Copyright (C) 2005 Intel Corporation
 * 	Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>
 * 	- Added _PDC for platforms with Intel CPUs
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/acpi.h>

#include <acpi/processor.h>
#include <asm/acpi.h>

static void init_intel_pdc(struct acpi_processor *pr)
{
	u32 *buf = (u32 *)pr->pdc->pointer->buffer.pointer;

	buf[0] = ACPI_PDC_REVISION_ID;
	buf[1] = 1;
	buf[2] = ACPI_PDC_EST_CAPABILITY_SMP;
	/*
	 * The default of PDC_SMP_T_SWCOORD bit is set for IA64 cpu so
	 * that OSPM is capable of native ACPI throttling software
	 * coordination using BIOS supplied _TSD info.
	 */
	buf[2] |= ACPI_PDC_SMP_T_SWCOORD;

	return;
}

/* Initialize _PDC data based on the CPU vendor */
void arch_acpi_processor_init_pdc(struct acpi_processor *pr)
{
	init_intel_pdc(pr);
	return;
}

EXPORT_SYMBOL(arch_acpi_processor_init_pdc);

void arch_acpi_processor_cleanup_pdc(struct acpi_processor *pr)
{
	if (pr->pdc) {
		kfree(pr->pdc->pointer->buffer.pointer);
		kfree(pr->pdc->pointer);
		kfree(pr->pdc);
		pr->pdc = NULL;
	}
}

EXPORT_SYMBOL(arch_acpi_processor_cleanup_pdc);
