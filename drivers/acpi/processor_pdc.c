/*
 * Copyright (C) 2005 Intel Corporation
 * Copyright (C) 2009 Hewlett-Packard Development Company, L.P.
 *
 *	Alex Chiang <achiang@hp.com>
 *	- Unified x86/ia64 implementations
 *	Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>
 *	- Added _PDC for platforms with Intel CPUs
 */
#include <linux/dmi.h>

#include <acpi/acpi_drivers.h>
#include <acpi/processor.h>

#include "internal.h"

#define PREFIX			"ACPI: "
#define _COMPONENT		ACPI_PROCESSOR_COMPONENT
ACPI_MODULE_NAME("processor_pdc");

static int set_no_mwait(const struct dmi_system_id *id)
{
	printk(KERN_NOTICE PREFIX "%s detected - "
		"disabling mwait for CPU C-states\n", id->ident);
	idle_nomwait = 1;
	return 0;
}

static struct dmi_system_id __cpuinitdata processor_idle_dmi_table[] = {
	{
	set_no_mwait, "IFL91 board", {
	DMI_MATCH(DMI_BIOS_VENDOR, "COMPAL"),
	DMI_MATCH(DMI_SYS_VENDOR, "ZEPTO"),
	DMI_MATCH(DMI_PRODUCT_VERSION, "3215W"),
	DMI_MATCH(DMI_BOARD_NAME, "IFL91") }, NULL},
	{
	set_no_mwait, "Extensa 5220", {
	DMI_MATCH(DMI_BIOS_VENDOR, "Phoenix Technologies LTD"),
	DMI_MATCH(DMI_SYS_VENDOR, "Acer"),
	DMI_MATCH(DMI_PRODUCT_VERSION, "0100"),
	DMI_MATCH(DMI_BOARD_NAME, "Columbia") }, NULL},
	{},
};

static void acpi_set_pdc_bits(u32 *buf)
{
	buf[0] = ACPI_PDC_REVISION_ID;
	buf[1] = 1;

	/* Enable coordination with firmware's _TSD info */
	buf[2] = ACPI_PDC_SMP_T_SWCOORD;

	/* Twiddle arch-specific bits needed for _PDC */
	arch_acpi_set_pdc_bits(buf);
}

static void acpi_processor_init_pdc(struct acpi_processor *pr)
{
	struct acpi_object_list *obj_list;
	union acpi_object *obj;
	u32 *buf;

	pr->pdc = NULL;

	/* allocate and initialize pdc. It will be used later. */
	obj_list = kmalloc(sizeof(struct acpi_object_list), GFP_KERNEL);
	if (!obj_list) {
		printk(KERN_ERR "Memory allocation error\n");
		return;
	}

	obj = kmalloc(sizeof(union acpi_object), GFP_KERNEL);
	if (!obj) {
		printk(KERN_ERR "Memory allocation error\n");
		kfree(obj_list);
		return;
	}

	buf = kmalloc(12, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "Memory allocation error\n");
		kfree(obj);
		kfree(obj_list);
		return;
	}

	acpi_set_pdc_bits(buf);

	obj->type = ACPI_TYPE_BUFFER;
	obj->buffer.length = 12;
	obj->buffer.pointer = (u8 *) buf;
	obj_list->count = 1;
	obj_list->pointer = obj;
	pr->pdc = obj_list;

	return;
}

/*
 * _PDC is required for a BIOS-OS handshake for most of the newer
 * ACPI processor features.
 */
static int acpi_processor_eval_pdc(struct acpi_processor *pr)
{
	struct acpi_object_list *pdc_in = pr->pdc;
	acpi_status status = AE_OK;

	if (!pdc_in)
		return status;
	if (idle_nomwait) {
		/*
		 * If mwait is disabled for CPU C-states, the C2C3_FFH access
		 * mode will be disabled in the parameter of _PDC object.
		 * Of course C1_FFH access mode will also be disabled.
		 */
		union acpi_object *obj;
		u32 *buffer = NULL;

		obj = pdc_in->pointer;
		buffer = (u32 *)(obj->buffer.pointer);
		buffer[2] &= ~(ACPI_PDC_C_C2C3_FFH | ACPI_PDC_C_C1_FFH);

	}
	status = acpi_evaluate_object(pr->handle, "_PDC", pdc_in, NULL);

	if (ACPI_FAILURE(status))
		ACPI_DEBUG_PRINT((ACPI_DB_INFO,
		    "Could not evaluate _PDC, using legacy perf. control.\n"));

	return status;
}

static void acpi_processor_cleanup_pdc(struct acpi_processor *pr)
{
	if (pr->pdc) {
		kfree(pr->pdc->pointer->buffer.pointer);
		kfree(pr->pdc->pointer);
		kfree(pr->pdc);
		pr->pdc = NULL;
	}
}

void acpi_processor_set_pdc(struct acpi_processor *pr)
{
	if (arch_has_acpi_pdc() == false)
		return;

	acpi_processor_init_pdc(pr);
	acpi_processor_eval_pdc(pr);
	acpi_processor_cleanup_pdc(pr);
}
EXPORT_SYMBOL_GPL(acpi_processor_set_pdc);

static acpi_status
early_init_pdc(acpi_handle handle, u32 lvl, void *context, void **rv)
{
	struct acpi_processor pr;

	pr.handle = handle;

	/* x86 implementation looks at pr.id to determine some
	 * CPU capabilites. We can just hard code to 0 since we're
	 * assuming the CPUs in the system are homogenous and all
	 * have the same capabilities.
	 */
	pr.id = 0;

	acpi_processor_set_pdc(&pr);

	return AE_OK;
}

void acpi_early_processor_set_pdc(void)
{
	/*
	 * Check whether the system is DMI table. If yes, OSPM
	 * should not use mwait for CPU-states.
	 */
	dmi_check_system(processor_idle_dmi_table);

	acpi_walk_namespace(ACPI_TYPE_PROCESSOR, ACPI_ROOT_OBJECT,
			    ACPI_UINT32_MAX,
			    early_init_pdc, NULL, NULL, NULL);
}
