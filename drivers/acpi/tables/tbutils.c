/******************************************************************************
 *
 * Module Name: tbutils   - table utilities
 *
 *****************************************************************************/

/*
 * Copyright (C) 2000 - 2006, R. Byron Moore
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    substantially similar to the "NO WARRANTY" disclaimer below
 *    ("Disclaimer") and any redistribution must be conditioned upon
 *    including a substantially similar Disclaimer requirement for further
 *    binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 */

#include <acpi/acpi.h>
#include <acpi/actables.h>

#define _COMPONENT          ACPI_TABLES
ACPI_MODULE_NAME("tbutils")

/* Local prototypes */
static void acpi_tb_parse_fadt(acpi_native_uint table_index, u8 flags);

static void acpi_tb_convert_fadt(void);

static void
acpi_tb_install_table(acpi_physical_address address,
		      u8 flags, char *signature, acpi_native_uint table_index);

static void inline
acpi_tb_init_generic_address(struct acpi_generic_address *new_gas_struct,
			     u8 bit_width, u64 address);

/* Table used for conversion of FADT to common format */

typedef struct acpi_fadt_conversion {
	u8 target;
	u8 source;
	u8 length;

} acpi_fadt_conversion;

static struct acpi_fadt_conversion fadt_conversion_table[] = {
	{ACPI_FADT_OFFSET(xpm1a_event_block),
	 ACPI_FADT_OFFSET(pm1a_event_block),
	 ACPI_FADT_OFFSET(pm1_event_length)},
	{ACPI_FADT_OFFSET(xpm1b_event_block),
	 ACPI_FADT_OFFSET(pm1b_event_block),
	 ACPI_FADT_OFFSET(pm1_event_length)},
	{ACPI_FADT_OFFSET(xpm1a_control_block),
	 ACPI_FADT_OFFSET(pm1a_control_block),
	 ACPI_FADT_OFFSET(pm1_control_length)},
	{ACPI_FADT_OFFSET(xpm1b_control_block),
	 ACPI_FADT_OFFSET(pm1b_control_block),
	 ACPI_FADT_OFFSET(pm1_control_length)},
	{ACPI_FADT_OFFSET(xpm2_control_block),
	 ACPI_FADT_OFFSET(pm2_control_block),
	 ACPI_FADT_OFFSET(pm2_control_length)},
	{ACPI_FADT_OFFSET(xpm_timer_block), ACPI_FADT_OFFSET(pm_timer_block),
	 ACPI_FADT_OFFSET(pm_timer_length)},
	{ACPI_FADT_OFFSET(xgpe0_block), ACPI_FADT_OFFSET(gpe0_block),
	 ACPI_FADT_OFFSET(gpe0_block_length)},
	{ACPI_FADT_OFFSET(xgpe1_block), ACPI_FADT_OFFSET(gpe1_block),
	 ACPI_FADT_OFFSET(gpe1_block_length)}
};

#define ACPI_FADT_CONVERSION_ENTRIES        (sizeof (fadt_conversion_table) / sizeof (struct acpi_fadt_conversion))

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_print_table_header
 *
 * PARAMETERS:  Address             - Table physical address
 *              Header              - Table header
 *
 * RETURN:      None
 *
 * DESCRIPTION: Print an ACPI table header. Special cases for FACS and RSDP.
 *
 ******************************************************************************/

void
acpi_tb_print_table_header(acpi_physical_address address,
			   struct acpi_table_header *header)
{

	if (ACPI_COMPARE_NAME(header->signature, ACPI_SIG_FACS)) {

		/* FACS only has signature and length fields of common table header */

		ACPI_INFO((AE_INFO, "%4.4s @ 0x%p/0x%04X",
			   header->signature, ACPI_CAST_PTR(void, address),
			   header->length));
	} else if (ACPI_COMPARE_NAME(header->signature, ACPI_SIG_RSDP)) {

		/* RSDP has no common fields */

		ACPI_INFO((AE_INFO, "RSDP @ 0x%p/0x%04X (v%3.3d %6.6s)",
			   ACPI_CAST_PTR(void, address),
			   (((struct acpi_table_rsdp *)header)->revision > 0) ?
			   ((struct acpi_table_rsdp *)header)->length : 20,
			   ((struct acpi_table_rsdp *)header)->revision,
			   ((struct acpi_table_rsdp *)header)->oem_id));
	} else {
		/* Standard ACPI table with full common header */

		ACPI_INFO((AE_INFO,
			   "%4.4s @ 0x%p/0x%04X (v%3.3d %6.6s %8.8s 0x%08X %4.4s 0x%08X)",
			   header->signature, ACPI_CAST_PTR(void, address),
			   header->length, header->revision, header->oem_id,
			   header->oem_table_id, header->oem_revision,
			   header->asl_compiler_id,
			   header->asl_compiler_revision));
	}
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_init_generic_address
 *
 * PARAMETERS:  new_gas_struct      - GAS struct to be initialized
 *              bit_width           - Width of this register
 *              Address             - Address of the register
 *
 * RETURN:      None
 *
 * DESCRIPTION: Initialize a GAS structure.
 *
 ******************************************************************************/

static void inline
acpi_tb_init_generic_address(struct acpi_generic_address *new_gas_struct,
			     u8 bit_width, u64 address)
{

	ACPI_MOVE_64_TO_64(&new_gas_struct->address, &address);
	new_gas_struct->space_id = ACPI_ADR_SPACE_SYSTEM_IO;
	new_gas_struct->bit_width = bit_width;
	new_gas_struct->bit_offset = 0;
	new_gas_struct->access_width = 0;
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_validate_checksum
 *
 * PARAMETERS:  Table               - ACPI table to verify
 *              Length              - Length of entire table
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Verifies that the table checksums to zero. Optionally returns
 *              exception on bad checksum.
 *
 ******************************************************************************/

acpi_status acpi_tb_verify_checksum(struct acpi_table_header *table, u32 length)
{
	u8 checksum;

	/* Compute the checksum on the table */

	checksum = acpi_tb_checksum(ACPI_CAST_PTR(u8, table), length);

	/* Checksum ok? (should be zero) */

	if (checksum) {
		ACPI_WARNING((AE_INFO,
			      "Incorrect checksum in table [%4.4s] -  %2.2X, should be %2.2X",
			      table->signature, table->checksum,
			      (u8) (table->checksum - checksum)));

#if (ACPI_CHECKSUM_ABORT)

		return (AE_BAD_CHECKSUM);
#endif
	}

	return (AE_OK);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_checksum
 *
 * PARAMETERS:  Buffer          - Pointer to memory region to be checked
 *              Length          - Length of this memory region
 *
 * RETURN:      Checksum (u8)
 *
 * DESCRIPTION: Calculates circular checksum of memory region.
 *
 ******************************************************************************/

u8 acpi_tb_checksum(u8 * buffer, acpi_native_uint length)
{
	u8 sum = 0;
	u8 *end = buffer + length;

	while (buffer < end) {
		sum = (u8) (sum + *(buffer++));
	}

	return sum;
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_convert_fadt
 *
 * PARAMETERS:  None, uses acpi_gbl_FADT
 *
 * RETURN:      None
 *
 * DESCRIPTION: Converts all versions of the FADT to a common internal format.
 *
 * NOTE:        acpi_gbl_FADT must be of size (struct acpi_table_fadt), and must contain
 *              a copy of the actual FADT.
 *
 * ACPICA will use the "X" fields of the FADT for all addresses.
 *
 * "X" fields are optional extensions to the original V1.0 fields. Even if
 * they are present in the structure, they can be optionally not used by
 * setting them to zero. Therefore, we must selectively expand V1.0 fields
 * if the corresponding X field is zero.
 *
 * For ACPI 1.0 FADTs, all address fields are expanded to the corresponding
 * "X" fields.
 *
 * For ACPI 2.0 FADTs, any "X" fields that are NULL are filled in by
 * expanding the corresponding ACPI 1.0 field.
 *
 ******************************************************************************/

static void acpi_tb_convert_fadt(void)
{
	u8 pm1_register_length;
	struct acpi_generic_address *target;
	acpi_native_uint i;

	/* Expand the FACS and DSDT addresses as necessary */

	if (!acpi_gbl_FADT.Xfacs) {
		acpi_gbl_FADT.Xfacs = (u64) acpi_gbl_FADT.facs;
	}

	if (!acpi_gbl_FADT.Xdsdt) {
		acpi_gbl_FADT.Xdsdt = (u64) acpi_gbl_FADT.dsdt;
	}

	/*
	 * Expand the V1.0 addresses to the "X" generic address structs,
	 * as necessary.
	 */
	for (i = 0; i < ACPI_FADT_CONVERSION_ENTRIES; i++) {
		target =
		    ACPI_ADD_PTR(struct acpi_generic_address, &acpi_gbl_FADT,
				 fadt_conversion_table[i].target);

		/* Expand only if the X target is null */

		if (!target->address) {
			acpi_tb_init_generic_address(target,
						     *ACPI_ADD_PTR(u8,
								   &acpi_gbl_FADT,
								   fadt_conversion_table
								   [i].length),
						     *ACPI_ADD_PTR(u32,
								   &acpi_gbl_FADT,
								   fadt_conversion_table
								   [i].source));
		}
	}

	/*
	 * Calculate separate GAS structs for the PM1 Enable registers.
	 * These addresses do not appear (directly) in the FADT, so it is
	 * useful to calculate them once, here.
	 *
	 * The PM event blocks are split into two register blocks, first is the
	 * PM Status Register block, followed immediately by the PM Enable Register
	 * block. Each is of length (pm1_event_length/2)
	 */
	pm1_register_length = (u8) ACPI_DIV_2(acpi_gbl_FADT.pm1_event_length);

	/* PM1A is required */

	acpi_tb_init_generic_address(&acpi_gbl_xpm1a_enable,
				     pm1_register_length,
				     (acpi_gbl_FADT.xpm1a_event_block.address +
				      pm1_register_length));

	/* PM1B is optional; leave null if not present */

	if (acpi_gbl_FADT.xpm1b_event_block.address) {
		acpi_tb_init_generic_address(&acpi_gbl_xpm1b_enable,
					     pm1_register_length,
					     (acpi_gbl_FADT.xpm1b_event_block.
					      address + pm1_register_length));
	}

	/* Global FADT is the new common V2.0 FADT  */

	acpi_gbl_FADT.header.length = sizeof(struct acpi_table_fadt);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_install_table
 *
 * PARAMETERS:  Address                 - Physical address of DSDT or FACS
 *              Flags                   - Flags
 *              Signature               - Table signature, NULL if no need to
 *                                        match
 *              table_index             - Index into root table array
 *
 * RETURN:      None
 *
 * DESCRIPTION: Install an ACPI table into the global data structure.
 *
 ******************************************************************************/

static void
acpi_tb_install_table(acpi_physical_address address,
		      u8 flags, char *signature, acpi_native_uint table_index)
{
	struct acpi_table_header *table;

	if (!address) {
		ACPI_ERROR((AE_INFO,
			    "Null physical address for ACPI table [%s]",
			    signature));
		return;
	}

	/* Map just the table header */

	table = acpi_os_map_memory(address, sizeof(struct acpi_table_header));
	if (!table) {
		return;
	}

	/* If a particular signature is expected, signature must match */

	if (signature && !ACPI_COMPARE_NAME(table->signature, signature)) {
		ACPI_ERROR((AE_INFO,
			    "Invalid signature 0x%X for ACPI table [%s]",
			    *ACPI_CAST_PTR(u32, table->signature), signature));
		goto unmap_and_exit;
	}

	/* Initialize the table entry */

	acpi_gbl_root_table_list.tables[table_index].address = address;
	acpi_gbl_root_table_list.tables[table_index].length = table->length;
	acpi_gbl_root_table_list.tables[table_index].flags = flags;

	ACPI_MOVE_32_TO_32(&
			   (acpi_gbl_root_table_list.tables[table_index].
			    signature), table->signature);

	acpi_tb_print_table_header(address, table);

	if (table_index == ACPI_TABLE_INDEX_DSDT) {

		/* Global integer width is based upon revision of the DSDT */

		acpi_ut_set_integer_width(table->revision);
	}

      unmap_and_exit:
	acpi_os_unmap_memory(table, sizeof(struct acpi_table_header));
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_parse_fadt
 *
 * PARAMETERS:  table_index         - Index for the FADT
 *              Flags               - Flags
 *
 * RETURN:      None
 *
 * DESCRIPTION: Initialize the FADT, DSDT and FACS tables
 *              (FADT contains the addresses of the DSDT and FACS)
 *
 ******************************************************************************/

static void acpi_tb_parse_fadt(acpi_native_uint table_index, u8 flags)
{
	u32 length;
	struct acpi_table_header *table;

	/*
	 * Special case for the FADT because of multiple versions and the fact
	 * that it contains pointers to both the DSDT and FACS tables.
	 *
	 * Get a local copy of the FADT and convert it to a common format
	 * Map entire FADT, assumed to be smaller than one page.
	 */
	length = acpi_gbl_root_table_list.tables[table_index].length;

	table =
	    acpi_os_map_memory(acpi_gbl_root_table_list.tables[table_index].
			       address, length);
	if (!table) {
		return;
	}

	/*
	 * Validate the FADT checksum before we copy the table. Ignore
	 * checksum error as we want to try to get the DSDT and FACS.
	 */
	(void)acpi_tb_verify_checksum(table, length);

	/* Copy the entire FADT locally */

	ACPI_MEMSET(&acpi_gbl_FADT, sizeof(struct acpi_table_fadt), 0);

	ACPI_MEMCPY(&acpi_gbl_FADT, table,
		    ACPI_MIN(length, sizeof(struct acpi_table_fadt)));
	acpi_os_unmap_memory(table, length);

	/* Convert local FADT to the common internal format */

	acpi_tb_convert_fadt();

	/* Extract the DSDT and FACS tables from the FADT */

	acpi_tb_install_table((acpi_physical_address) acpi_gbl_FADT.Xdsdt,
			      flags, ACPI_SIG_DSDT, ACPI_TABLE_INDEX_DSDT);

	acpi_tb_install_table((acpi_physical_address) acpi_gbl_FADT.Xfacs,
			      flags, ACPI_SIG_FACS, ACPI_TABLE_INDEX_FACS);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_parse_root_table
 *
 * PARAMETERS:  Rsdp                    - Pointer to the RSDP
 *              Flags                   - Flags
 *
 * RETURN:      Status
 *
 * DESCRIPTION: This function is called to parse the Root System Description
 *              Table (RSDT or XSDT)
 *
 * NOTE:        Tables are mapped (not copied) for efficiency. The FACS must
 *              be mapped and cannot be copied because it contains the actual
 *              memory location of the ACPI Global Lock.
 *
 ******************************************************************************/

acpi_status
acpi_tb_parse_root_table(acpi_physical_address rsdp_address, u8 flags)
{
	struct acpi_table_rsdp *rsdp;
	acpi_native_uint table_entry_size;
	acpi_native_uint i;
	u32 table_count;
	struct acpi_table_header *table;
	acpi_physical_address address;
	u32 length;
	u8 *table_entry;
	acpi_status status;

	ACPI_FUNCTION_TRACE(tb_parse_root_table);

	/*
	 * Map the entire RSDP and extract the address of the RSDT or XSDT
	 */
	rsdp = acpi_os_map_memory(rsdp_address, sizeof(struct acpi_table_rsdp));
	if (!rsdp) {
		return_ACPI_STATUS(AE_NO_MEMORY);
	}

	acpi_tb_print_table_header(rsdp_address,
				   ACPI_CAST_PTR(struct acpi_table_header,
						 rsdp));

	/* Differentiate between RSDT and XSDT root tables */

	if (rsdp->revision > 1 && rsdp->xsdt_physical_address) {
		/*
		 * Root table is an XSDT (64-bit physical addresses). We must use the
		 * XSDT if the revision is > 1 and the XSDT pointer is present, as per
		 * the ACPI specification.
		 */
		address = (acpi_physical_address) rsdp->xsdt_physical_address;
		table_entry_size = sizeof(u64);
	} else {
		/* Root table is an RSDT (32-bit physical addresses) */

		address = (acpi_physical_address) rsdp->rsdt_physical_address;
		table_entry_size = sizeof(u32);
	}

	/*
	 * It is not possible to map more than one entry in some environments,
	 * so unmap the RSDP here before mapping other tables
	 */
	acpi_os_unmap_memory(rsdp, sizeof(struct acpi_table_rsdp));

	/* Map the RSDT/XSDT table header to get the full table length */

	table = acpi_os_map_memory(address, sizeof(struct acpi_table_header));
	if (!table) {
		return_ACPI_STATUS(AE_NO_MEMORY);
	}

	acpi_tb_print_table_header(address, table);

	/* Get the length of the full table, verify length and map entire table */

	length = table->length;
	acpi_os_unmap_memory(table, sizeof(struct acpi_table_header));

	if (length < sizeof(struct acpi_table_header)) {
		ACPI_ERROR((AE_INFO, "Invalid length 0x%X in RSDT/XSDT",
			    length));
		return_ACPI_STATUS(AE_INVALID_TABLE_LENGTH);
	}

	table = acpi_os_map_memory(address, length);
	if (!table) {
		return_ACPI_STATUS(AE_NO_MEMORY);
	}

	/* Validate the root table checksum */

	status = acpi_tb_verify_checksum(table, length);
	if (ACPI_FAILURE(status)) {
		acpi_os_unmap_memory(table, length);
		return_ACPI_STATUS(status);
	}

	/* Calculate the number of tables described in the root table */

	table_count =
	    (table->length -
	     sizeof(struct acpi_table_header)) / table_entry_size;

	/*
	 * First two entries in the table array are reserved for the DSDT and FACS,
	 * which are not actually present in the RSDT/XSDT - they come from the FADT
	 */
	table_entry =
	    ACPI_CAST_PTR(u8, table) + sizeof(struct acpi_table_header);
	acpi_gbl_root_table_list.count = 2;

	/*
	 * Initialize the root table array from the RSDT/XSDT
	 */
	for (i = 0; i < table_count; i++) {
		if (acpi_gbl_root_table_list.count >=
		    acpi_gbl_root_table_list.size) {

			/* There is no more room in the root table array, attempt resize */

			status = acpi_tb_resize_root_table_list();
			if (ACPI_FAILURE(status)) {
				ACPI_WARNING((AE_INFO,
					      "Truncating %u table entries!",
					      (unsigned)
					      (acpi_gbl_root_table_list.size -
					       acpi_gbl_root_table_list.
					       count)));
				break;
			}
		}

		/*
		 * Get the table physical address (32-bit for RSDT, 64-bit for XSDT)
		 */
		if ((table_entry_size == sizeof(u32)) ||
		    (sizeof(acpi_physical_address) == sizeof(u32))) {
			/*
			 * 32-bit platform, RSDT: Move 32-bit to 32-bit
			 * 32-bit platform, XSDT: Truncate 64-bit to 32-bit
			 * 64-bit platform, RSDT: Expand 32-bit to 64-bit
			 *
			 * Note: Addresses are 32-bit aligned in both RSDT and XSDT
			 */
			acpi_gbl_root_table_list.
			    tables[acpi_gbl_root_table_list.count].address =
			    (acpi_physical_address) (*ACPI_CAST_PTR
						     (u32, table_entry));
		} else {
			/*
			 * 64-bit platform, XSDT: Move 64-bit to 64-bit
			 *
			 * Note: 64-bit addresses are only 32-bit aligned in the XSDT
			 */
			ACPI_MOVE_64_TO_64(&acpi_gbl_root_table_list.
					   tables[acpi_gbl_root_table_list.
						  count].address, table_entry);
		}

		table_entry += table_entry_size;
		acpi_gbl_root_table_list.count++;
	}

	/*
	 * It is not possible to map more than one entry in some environments,
	 * so unmap the root table here before mapping other tables
	 */
	acpi_os_unmap_memory(table, length);

	/*
	 * Complete the initialization of the root table array by examining
	 * the header of each table
	 */
	for (i = 2; i < acpi_gbl_root_table_list.count; i++) {
		acpi_tb_install_table(acpi_gbl_root_table_list.tables[i].
				      address, flags, NULL, i);

		/* Special case for FADT - get the DSDT and FACS */

		if (ACPI_COMPARE_NAME
		    (&acpi_gbl_root_table_list.tables[i].signature,
		     ACPI_SIG_FADT)) {
			acpi_tb_parse_fadt(i, flags);
		}
	}

	return_ACPI_STATUS(AE_OK);
}

/******************************************************************************
 *
 * FUNCTION:    acpi_tb_map
 *
 * PARAMETERS:  Address             - Address to be mapped
 *              Length              - Length to be mapped
 *              Flags               - Logical or physical addressing mode
 *
 * RETURN:      Pointer to mapped region
 *
 * DESCRIPTION: Maps memory according to flag
 *
 *****************************************************************************/

void *acpi_tb_map(acpi_physical_address address, u32 length, u32 flags)
{

	if (flags == ACPI_TABLE_ORIGIN_MAPPED) {
		return (acpi_os_map_memory(address, length));
	} else {
		return (ACPI_CAST_PTR(void, address));
	}
}

/******************************************************************************
 *
 * FUNCTION:    acpi_tb_unmap
 *
 * PARAMETERS:  Pointer             - To mapped region
 *              Length              - Length to be unmapped
 *              Flags               - Logical or physical addressing mode
 *
 * RETURN:      None
 *
 * DESCRIPTION: Unmaps memory according to flag
 *
 *****************************************************************************/

void acpi_tb_unmap(void *pointer, u32 length, u32 flags)
{

	if (flags == ACPI_TABLE_ORIGIN_MAPPED) {
		acpi_os_unmap_memory(pointer, length);
	}
}
