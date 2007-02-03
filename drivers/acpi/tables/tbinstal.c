/******************************************************************************
 *
 * Module Name: tbinstal - ACPI table installation and removal
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
#include <acpi/acnamesp.h>
#include <acpi/actables.h>

#define _COMPONENT          ACPI_TABLES
ACPI_MODULE_NAME("tbinstal")

/******************************************************************************
 *
 * FUNCTION:    acpi_tb_verify_table
 *
 * PARAMETERS:  table_desc          - table
 *
 * RETURN:      Status
 *
 * DESCRIPTION: this function is called to verify and map table
 *
 *****************************************************************************/
acpi_status acpi_tb_verify_table(struct acpi_table_desc *table_desc)
{
	u8 checksum;

	ACPI_FUNCTION_TRACE(tb_verify_table);

	/* Map the table if necessary */

	if (!table_desc->pointer) {
		table_desc->pointer =
		    acpi_tb_map(table_desc->address, table_desc->length,
				table_desc->flags & ACPI_TABLE_ORIGIN_MASK);
		if (!table_desc->pointer) {
			return_ACPI_STATUS(AE_NO_MEMORY);
		}
	}

	/* FACS is the odd table, has no standard ACPI header and no checksum */

	if (ACPI_COMPARE_NAME(&(table_desc->signature), ACPI_SIG_FACS)) {
		return_ACPI_STATUS(AE_OK);
	}

	/* Always calculate checksum, ignore bad checksum if requested */

	checksum = acpi_tb_checksum(ACPI_CAST_PTR(void, table_desc->pointer),
				    table_desc->length);

#if (ACPI_CHECKSUM_ABORT)

	if (checksum) {
		return_ACPI_STATUS(AE_BAD_CHECKSUM);
	}
#endif

	return_ACPI_STATUS(AE_OK);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_add_table
 *
 * PARAMETERS:  Table               - Pointer to the table header
 *              table_index         - Where the table index is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: This function is called to add the ACPI table
 *
 ******************************************************************************/

acpi_status
acpi_tb_add_table(struct acpi_table_header *table,
		  acpi_native_uint * table_index)
{
	acpi_native_uint i;
	acpi_native_uint length;
	acpi_status status = AE_OK;

	ACPI_FUNCTION_TRACE(tb_add_table);

	(void)acpi_ut_acquire_mutex(ACPI_MTX_TABLES);

	/* Check if table is already registered */

	for (i = 0; i < acpi_gbl_root_table_list.count; ++i) {
		if (!acpi_gbl_root_table_list.tables[i].pointer) {
			status =
			    acpi_tb_verify_table(&acpi_gbl_root_table_list.
						 tables[i]);
			if (ACPI_FAILURE(status)
			    || !acpi_gbl_root_table_list.tables[i].pointer) {
				continue;
			}
		}

		length = ACPI_MIN(table->length,
				  acpi_gbl_root_table_list.tables[i].pointer->
				  length);
		if (ACPI_MEMCMP
		    (table, acpi_gbl_root_table_list.tables[i].pointer,
		     length)) {
			continue;
		}

		/* Table is already registered */

		ACPI_FREE(table);
		*table_index = i;
		goto release;
	}

	/*
	 * Add the table to the global table list
	 */
	status = acpi_tb_store_table(ACPI_TO_INTEGER(table),
				     table, table->length,
				     ACPI_TABLE_ORIGIN_ALLOCATED, table_index);
	if (ACPI_FAILURE(status)) {
		goto release;
	}

	acpi_tb_print_table_header(0, table);

      release:
	(void)acpi_ut_release_mutex(ACPI_MTX_TABLES);
	return_ACPI_STATUS(status);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_resize_root_table_list
 *
 * PARAMETERS:  None
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Expand the size of global table array
 *
 ******************************************************************************/

acpi_status acpi_tb_resize_root_table_list(void)
{
	struct acpi_table_desc *tables;

	ACPI_FUNCTION_TRACE(tb_resize_root_table_list);

	/* allow_resize flag is a parameter to acpi_initialize_tables */

	if (!(acpi_gbl_root_table_list.flags & ACPI_TABLE_FLAGS_ALLOW_RESIZE)) {
		ACPI_ERROR((AE_INFO,
			    "Resize of Root Table Array is not allowed"));
		return_ACPI_STATUS(AE_SUPPORT);
	}

	/* Increase the Table Array size */

	tables = ACPI_ALLOCATE_ZEROED((acpi_gbl_root_table_list.size +
				       ACPI_ROOT_TABLE_SIZE_INCREMENT)
				      * sizeof(struct acpi_table_desc));
	if (!tables) {
		ACPI_ERROR((AE_INFO,
			    "Could not allocate new root table array"));
		return_ACPI_STATUS(AE_NO_MEMORY);
	}

	/* Copy and free the previous table array */

	if (acpi_gbl_root_table_list.tables) {
		ACPI_MEMCPY(tables, acpi_gbl_root_table_list.tables,
			    acpi_gbl_root_table_list.size *
			    sizeof(struct acpi_table_desc));

		if (acpi_gbl_root_table_list.flags & ACPI_TABLE_ORIGIN_MASK ==
		    ACPI_TABLE_ORIGIN_ALLOCATED) {
			ACPI_FREE(acpi_gbl_root_table_list.tables);
		}
	}

	acpi_gbl_root_table_list.tables = tables;
	acpi_gbl_root_table_list.size += ACPI_ROOT_TABLE_SIZE_INCREMENT;
	acpi_gbl_root_table_list.flags = (u8) (ACPI_TABLE_ORIGIN_ALLOCATED |
					       (acpi_gbl_root_table_list.
						flags &
						~ACPI_TABLE_ORIGIN_MASK));

	return_ACPI_STATUS(AE_OK);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_store_table
 *
 * PARAMETERS:  Address             - Table address
 *              Table               - Table header
 *              Length              - Table length
 *              Flags               - flags
 *
 * RETURN:      Status and table index.
 *
 * DESCRIPTION: Add an ACPI table to the global table list
 *
 ******************************************************************************/

acpi_status
acpi_tb_store_table(acpi_physical_address address,
		    struct acpi_table_header *table,
		    u32 length, u8 flags, acpi_native_uint * table_index)
{
	acpi_status status = AE_OK;

	/* Ensure that there is room for the table in the Root Table List */

	if (acpi_gbl_root_table_list.count >= acpi_gbl_root_table_list.size) {
		status = acpi_tb_resize_root_table_list();
		if (ACPI_FAILURE(status)) {
			return (status);
		}
	}

	/* Initialize added table */

	acpi_gbl_root_table_list.tables[acpi_gbl_root_table_list.count].
	    address = address;
	acpi_gbl_root_table_list.tables[acpi_gbl_root_table_list.count].
	    pointer = table;
	acpi_gbl_root_table_list.tables[acpi_gbl_root_table_list.count].length =
	    length;
	acpi_gbl_root_table_list.tables[acpi_gbl_root_table_list.count].
	    owner_id = 0;
	acpi_gbl_root_table_list.tables[acpi_gbl_root_table_list.count].flags =
	    flags;

	ACPI_MOVE_32_TO_32(&
			   (acpi_gbl_root_table_list.
			    tables[acpi_gbl_root_table_list.count].signature),
			   table->signature);

	*table_index = acpi_gbl_root_table_list.count;
	acpi_gbl_root_table_list.count++;
	return (status);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_delete_table
 *
 * PARAMETERS:  table_index         - Table index
 *
 * RETURN:      None
 *
 * DESCRIPTION: Delete one internal ACPI table
 *
 ******************************************************************************/

void acpi_tb_delete_table(acpi_native_uint table_index)
{
	struct acpi_table_desc *table_desc;

	/* table_index assumed valid */

	table_desc = &acpi_gbl_root_table_list.tables[table_index];

	/* Table must be mapped or allocated */

	if (!table_desc->pointer) {
		return;
	}

	if (table_desc->flags & ACPI_TABLE_ORIGIN_MAPPED) {
		acpi_tb_unmap(table_desc->pointer, table_desc->length,
			      table_desc->flags & ACPI_TABLE_ORIGIN_MASK);
	} else if (table_desc->flags & ACPI_TABLE_ORIGIN_ALLOCATED) {
		ACPI_FREE(table_desc->pointer);
	}

	table_desc->pointer = NULL;
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_terminate
 *
 * PARAMETERS:  None
 *
 * RETURN:      None
 *
 * DESCRIPTION: Delete all internal ACPI tables
 *
 ******************************************************************************/

void acpi_tb_terminate(void)
{
	acpi_native_uint i;

	ACPI_FUNCTION_TRACE(tb_terminate);

	(void)acpi_ut_acquire_mutex(ACPI_MTX_TABLES);

	/* Delete the individual tables */

	for (i = 0; i < acpi_gbl_root_table_list.count; ++i) {
		acpi_tb_delete_table(i);
	}

	/*
	 * Delete the root table array if allocated locally. Array cannot be
	 * mapped, so we don't need to check for that flag.
	 */
	if ((acpi_gbl_root_table_list.flags & ACPI_TABLE_ORIGIN_MASK) ==
	    ACPI_TABLE_ORIGIN_ALLOCATED) {
		ACPI_FREE(acpi_gbl_root_table_list.tables);
	}

	acpi_gbl_root_table_list.tables = NULL;
	acpi_gbl_root_table_list.flags = 0;
	acpi_gbl_root_table_list.count = 0;

	ACPI_DEBUG_PRINT((ACPI_DB_INFO, "ACPI Tables freed\n"));
	(void)acpi_ut_release_mutex(ACPI_MTX_TABLES);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_delete_namespace_by_owner
 *
 * PARAMETERS:  table_index         - Table index
 *
 * RETURN:      None
 *
 * DESCRIPTION: Delete all namespace objects created when this table was loaded.
 *
 ******************************************************************************/

void acpi_tb_delete_namespace_by_owner(acpi_native_uint table_index)
{
	acpi_owner_id owner_id;

	(void)acpi_ut_acquire_mutex(ACPI_MTX_TABLES);
	if (table_index < acpi_gbl_root_table_list.count) {
		owner_id =
		    acpi_gbl_root_table_list.tables[table_index].owner_id;
	} else {
		(void)acpi_ut_release_mutex(ACPI_MTX_TABLES);
		return;
	}

	(void)acpi_ut_release_mutex(ACPI_MTX_TABLES);
	acpi_ns_delete_namespace_by_owner(owner_id);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_allocate_owner_id
 *
 * PARAMETERS:  table_index         - Table index
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Allocates owner_id in table_desc
 *
 ******************************************************************************/

acpi_status acpi_tb_allocate_owner_id(acpi_native_uint table_index)
{
	acpi_status status = AE_BAD_PARAMETER;

	ACPI_FUNCTION_TRACE(tb_allocate_owner_id);

	(void)acpi_ut_acquire_mutex(ACPI_MTX_TABLES);
	if (table_index < acpi_gbl_root_table_list.count) {
		status = acpi_ut_allocate_owner_id
		    (&(acpi_gbl_root_table_list.tables[table_index].owner_id));
	}

	(void)acpi_ut_release_mutex(ACPI_MTX_TABLES);
	return_ACPI_STATUS(status);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_release_owner_id
 *
 * PARAMETERS:  table_index         - Table index
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Releases owner_id in table_desc
 *
 ******************************************************************************/

acpi_status acpi_tb_release_owner_id(acpi_native_uint table_index)
{
	acpi_status status = AE_BAD_PARAMETER;

	ACPI_FUNCTION_TRACE(tb_release_owner_id);

	(void)acpi_ut_acquire_mutex(ACPI_MTX_TABLES);
	if (table_index < acpi_gbl_root_table_list.count) {
		acpi_ut_release_owner_id(&
					 (acpi_gbl_root_table_list.
					  tables[table_index].owner_id));
		status = AE_OK;
	}

	(void)acpi_ut_release_mutex(ACPI_MTX_TABLES);
	return_ACPI_STATUS(status);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_get_owner_id
 *
 * PARAMETERS:  table_index         - Table index
 *              owner_id            - Where the table owner_id is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: returns owner_id for the ACPI table
 *
 ******************************************************************************/

acpi_status
acpi_tb_get_owner_id(acpi_native_uint table_index, acpi_owner_id * owner_id)
{
	acpi_status status = AE_BAD_PARAMETER;

	ACPI_FUNCTION_TRACE(tb_get_owner_id);

	(void)acpi_ut_acquire_mutex(ACPI_MTX_TABLES);
	if (table_index < acpi_gbl_root_table_list.count) {
		*owner_id =
		    acpi_gbl_root_table_list.tables[table_index].owner_id;
		status = AE_OK;
	}

	(void)acpi_ut_release_mutex(ACPI_MTX_TABLES);
	return_ACPI_STATUS(status);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_is_table_loaded
 *
 * PARAMETERS:  table_index         - Table index
 *
 * RETURN:      Table Loaded Flag
 *
 ******************************************************************************/

u8 acpi_tb_is_table_loaded(acpi_native_uint table_index)
{
	u8 is_loaded = FALSE;

	(void)acpi_ut_acquire_mutex(ACPI_MTX_TABLES);
	if (table_index < acpi_gbl_root_table_list.count) {
		is_loaded = (u8)
		    (acpi_gbl_root_table_list.tables[table_index].
		     flags & ACPI_TABLE_FLAGS_LOADED);
	}

	(void)acpi_ut_release_mutex(ACPI_MTX_TABLES);
	return (is_loaded);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_set_table_loaded_flag
 *
 * PARAMETERS:  table_index         - Table index
 *              is_loaded           - TRUE if table is loaded, FALSE otherwise
 *
 * RETURN:      None
 *
 * DESCRIPTION: Sets the table loaded flag to either TRUE or FALSE.
 *
 ******************************************************************************/

void acpi_tb_set_table_loaded_flag(acpi_native_uint table_index, u8 is_loaded)
{

	(void)acpi_ut_acquire_mutex(ACPI_MTX_TABLES);
	if (table_index < acpi_gbl_root_table_list.count) {
		if (is_loaded) {
			acpi_gbl_root_table_list.tables[table_index].flags |=
			    ACPI_TABLE_FLAGS_LOADED;
		} else {
			acpi_gbl_root_table_list.tables[table_index].flags &=
			    ~ACPI_TABLE_FLAGS_LOADED;
		}
	}

	(void)acpi_ut_release_mutex(ACPI_MTX_TABLES);
}
