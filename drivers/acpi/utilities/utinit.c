/******************************************************************************
 *
 * Module Name: utinit - Common ACPI subsystem initialization
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
#include <acpi/acevents.h>
#include <acpi/actables.h>

#define _COMPONENT          ACPI_UTILITIES
ACPI_MODULE_NAME("utinit")

/* Local prototypes */
static void acpi_ut_fadt_register_error(char *register_name, u32 value);

static void acpi_ut_terminate(void);

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_fadt_register_error
 *
 * PARAMETERS:  register_name           - Pointer to string identifying register
 *              Value                   - Actual register contents value
 *
 * RETURN:      None
 *
 * DESCRIPTION: Display failure message
 *
 ******************************************************************************/

static void acpi_ut_fadt_register_error(char *register_name, u32 value)
{

	ACPI_WARNING((AE_INFO, "Invalid FADT value %s = %X",
		      register_name, value));
}

/******************************************************************************
 *
 * FUNCTION:    acpi_ut_validate_fadt
 *
 * PARAMETERS:  None
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Validate various ACPI registers in the FADT
 *
 ******************************************************************************/

acpi_status acpi_ut_validate_fadt(void)
{

	/*
	 * Verify Fixed ACPI Description Table fields,
	 * but don't abort on any problems, just display error
	 */
	if (acpi_gbl_FADT.pm1_event_length < 4) {
		acpi_ut_fadt_register_error("Pm1EventLength",
					    (u32) acpi_gbl_FADT.
					    pm1_event_length);
	}

	if (acpi_gbl_FADT.pm_timer_length < 4) {
		acpi_ut_fadt_register_error("PmTimerLength",
					    (u32) acpi_gbl_FADT.
					    pm_timer_length);
	}

	if (!acpi_gbl_FADT.pm1_control_length) {
		acpi_ut_fadt_register_error("Pm1ControlLength", 0);
	}

	if (!acpi_gbl_FADT.xpm1a_event_block.address) {
		acpi_ut_fadt_register_error("XPm1aEventBlock.Address", 0);
	}

	if (!acpi_gbl_FADT.xpm1a_control_block.address) {
		acpi_ut_fadt_register_error("XPm1aControlBlock.Address", 0);
	}

	if (!acpi_gbl_FADT.xpm_timer_block.address) {
		acpi_ut_fadt_register_error("XPmTimerBlock.Address", 0);
	}

	if ((acpi_gbl_FADT.xpm2_control_block.address &&
	     !acpi_gbl_FADT.pm2_control_length)) {
		acpi_ut_fadt_register_error("Pm2ControlLength",
					    (u32) acpi_gbl_FADT.
					    pm2_control_length);
	}

	/* Length of GPE blocks must be a multiple of 2 */

	if (acpi_gbl_FADT.xgpe0_block.address &&
	    (acpi_gbl_FADT.gpe0_block_length & 1)) {
		acpi_ut_fadt_register_error("Gpe0BlockLength",
					    (u32) acpi_gbl_FADT.
					    gpe0_block_length);
	}

	if (acpi_gbl_FADT.xgpe1_block.address &&
	    (acpi_gbl_FADT.gpe1_block_length & 1)) {
		acpi_ut_fadt_register_error("Gpe1BlockLength",
					    (u32) acpi_gbl_FADT.
					    gpe1_block_length);
	}

	return (AE_OK);
}

/******************************************************************************
 *
 * FUNCTION:    acpi_ut_terminate
 *
 * PARAMETERS:  none
 *
 * RETURN:      none
 *
 * DESCRIPTION: Free global memory
 *
 ******************************************************************************/

static void acpi_ut_terminate(void)
{
	struct acpi_gpe_block_info *gpe_block;
	struct acpi_gpe_block_info *next_gpe_block;
	struct acpi_gpe_xrupt_info *gpe_xrupt_info;
	struct acpi_gpe_xrupt_info *next_gpe_xrupt_info;

	ACPI_FUNCTION_TRACE(ut_terminate);

	/* Free global GPE blocks and related info structures */

	gpe_xrupt_info = acpi_gbl_gpe_xrupt_list_head;
	while (gpe_xrupt_info) {
		gpe_block = gpe_xrupt_info->gpe_block_list_head;
		while (gpe_block) {
			next_gpe_block = gpe_block->next;
			ACPI_FREE(gpe_block->event_info);
			ACPI_FREE(gpe_block->register_info);
			ACPI_FREE(gpe_block);

			gpe_block = next_gpe_block;
		}
		next_gpe_xrupt_info = gpe_xrupt_info->next;
		ACPI_FREE(gpe_xrupt_info);
		gpe_xrupt_info = next_gpe_xrupt_info;
	}

	return_VOID;
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_subsystem_shutdown
 *
 * PARAMETERS:  none
 *
 * RETURN:      none
 *
 * DESCRIPTION: Shutdown the various subsystems.  Don't delete the mutex
 *              objects here -- because the AML debugger may be still running.
 *
 ******************************************************************************/

void acpi_ut_subsystem_shutdown(void)
{

	ACPI_FUNCTION_TRACE(ut_subsystem_shutdown);

	/* Just exit if subsystem is already shutdown */

	if (acpi_gbl_shutdown) {
		ACPI_ERROR((AE_INFO, "ACPI Subsystem is already terminated"));
		return_VOID;
	}

	/* Subsystem appears active, go ahead and shut it down */

	acpi_gbl_shutdown = TRUE;
	acpi_gbl_startup_flags = 0;
	ACPI_DEBUG_PRINT((ACPI_DB_INFO, "Shutting down ACPI Subsystem\n"));

	/* Close the acpi_event Handling */

	acpi_ev_terminate();

	/* Close the Namespace */

	acpi_ns_terminate();

	/* Delete the ACPI tables */

	acpi_tb_terminate();

	/* Close the globals */

	acpi_ut_terminate();

	/* Purge the local caches */

	(void)acpi_ut_delete_caches();
	return_VOID;
}
