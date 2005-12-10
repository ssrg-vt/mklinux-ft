/*******************************************************************************
 *
 * Module Name: rslist - Linked list utilities
 *
 ******************************************************************************/

/*
 * Copyright (C) 2000 - 2005, R. Byron Moore
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
#include <acpi/acresrc.h>

#define _COMPONENT          ACPI_RESOURCES
ACPI_MODULE_NAME("rslist")

/* Local prototypes */
static struct acpi_rsconvert_info *acpi_rs_get_conversion_info(u8
							       resource_type);

static acpi_status acpi_rs_validate_resource_length(union aml_resource *aml);

/*******************************************************************************
 *
 * FUNCTION:    acpi_rs_validate_resource_length
 *
 * PARAMETERS:  Aml                 - Pointer to the AML resource descriptor
 *
 * RETURN:      Status - AE_OK if the resource length appears valid
 *
 * DESCRIPTION: Validate the resource_length. Fixed-length descriptors must
 *              have the exact length; variable-length descriptors must be
 *              at least as long as the minimum. Certain Small descriptors
 *              can vary in size by at most one byte.
 *
 ******************************************************************************/

static acpi_status acpi_rs_validate_resource_length(union aml_resource *aml)
{
	struct acpi_resource_info *resource_info;
	u16 minimum_aml_resource_length;
	u16 resource_length;

	ACPI_FUNCTION_ENTRY();

	/* Get the size and type info about this resource descriptor */

	resource_info =
	    acpi_rs_get_resource_info(aml->small_header.descriptor_type);
	if (!resource_info) {
		return (AE_AML_INVALID_RESOURCE_TYPE);
	}

	resource_length = acpi_ut_get_resource_length(aml);
	minimum_aml_resource_length =
	    resource_info->minimum_aml_resource_length;

	/* Validate based upon the type of resource, fixed length or variable */

	if (resource_info->length_type == ACPI_FIXED_LENGTH) {
		/* Fixed length resource, length must match exactly */

		if (resource_length != minimum_aml_resource_length) {
			return (AE_AML_BAD_RESOURCE_LENGTH);
		}
	} else if (resource_info->length_type == ACPI_VARIABLE_LENGTH) {
		/* Variable length resource, must be at least the minimum */

		if (resource_length < minimum_aml_resource_length) {
			return (AE_AML_BAD_RESOURCE_LENGTH);
		}
	} else {
		/* Small variable length resource, allowed to be (Min) or (Min-1) */

		if ((resource_length > minimum_aml_resource_length) ||
		    (resource_length < (minimum_aml_resource_length - 1))) {
			return (AE_AML_BAD_RESOURCE_LENGTH);
		}
	}

	return (AE_OK);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_rs_get_conversion_info
 *
 * PARAMETERS:  resource_type       - Byte 0 of a resource descriptor
 *
 * RETURN:      Pointer to the resource conversion info table
 *
 * DESCRIPTION: Get the conversion table associated with this resource type
 *
 ******************************************************************************/

static struct acpi_rsconvert_info *acpi_rs_get_conversion_info(u8 resource_type)
{
	ACPI_FUNCTION_ENTRY();

	/* Determine if this is a small or large resource */

	if (resource_type & ACPI_RESOURCE_NAME_LARGE) {
		/* Large Resource Type -- bits 6:0 contain the name */

		if (resource_type > ACPI_RESOURCE_NAME_LARGE_MAX) {
			return (NULL);
		}

		return (acpi_gbl_lg_get_resource_dispatch[(resource_type &
							   ACPI_RESOURCE_NAME_LARGE_MASK)]);
	} else {
		/* Small Resource Type -- bits 6:3 contain the name */

		return (acpi_gbl_sm_get_resource_dispatch[((resource_type &
							    ACPI_RESOURCE_NAME_SMALL_MASK)
							   >> 3)]);
	}
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_rs_convert_aml_to_resources
 *
 * PARAMETERS:  aml_buffer          - Pointer to the resource byte stream
 *              aml_buffer_length   - Length of aml_buffer
 *              output_buffer       - Pointer to the buffer that will
 *                                    contain the output structures
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Takes the resource byte stream and parses it, creating a
 *              linked list of resources in the caller's output buffer
 *
 ******************************************************************************/

acpi_status
acpi_rs_convert_aml_to_resources(u8 * aml_buffer,
				 u32 aml_buffer_length, u8 * output_buffer)
{
	u8 *buffer = output_buffer;
	acpi_status status;
	acpi_size bytes_parsed = 0;
	struct acpi_resource *resource;
	acpi_rsdesc_size descriptor_length;
	struct acpi_rsconvert_info *info;

	ACPI_FUNCTION_TRACE("rs_convert_aml_to_resources");

	/* Loop until end-of-buffer or an end_tag is found */

	while (bytes_parsed < aml_buffer_length) {
		/* Get the conversion table associated with this Descriptor Type */

		info = acpi_rs_get_conversion_info(*aml_buffer);
		if (!info) {
			/* No table indicates an invalid resource type */

			return_ACPI_STATUS(AE_AML_INVALID_RESOURCE_TYPE);
		}

		descriptor_length = acpi_ut_get_descriptor_length(aml_buffer);

		/*
		 * Perform limited validation of the resource length, based upon
		 * what we know about the resource type
		 */
		status =
		    acpi_rs_validate_resource_length(ACPI_CAST_PTR
						     (union aml_resource,
						      aml_buffer));
		if (ACPI_FAILURE(status)) {
			return_ACPI_STATUS(status);
		}

		/* Convert the AML byte stream resource to a local resource struct */

		status =
		    acpi_rs_convert_aml_to_resource(ACPI_CAST_PTR
						    (struct acpi_resource,
						     buffer),
						    ACPI_CAST_PTR(union
								  aml_resource,
								  aml_buffer),
						    info);
		if (ACPI_FAILURE(status)) {
			ACPI_REPORT_ERROR(("Could not convert AML resource (type %X) to resource, %s\n", *aml_buffer, acpi_format_exception(status)));
			return_ACPI_STATUS(status);
		}

		/* Set the aligned length of the new resource descriptor */

		resource = ACPI_CAST_PTR(struct acpi_resource, buffer);
		resource->length =
		    (u32) ACPI_ALIGN_RESOURCE_SIZE(resource->length);

		/* Normal exit on completion of an end_tag resource descriptor */

		if (acpi_ut_get_resource_type(aml_buffer) ==
		    ACPI_RESOURCE_NAME_END_TAG) {
			return_ACPI_STATUS(AE_OK);
		}

		/* Update counter and point to the next input resource */

		bytes_parsed += descriptor_length;
		aml_buffer += descriptor_length;

		/* Point to the next structure in the output buffer */

		buffer += resource->length;
	}

	/* Completed buffer, but did not find an end_tag resource descriptor */

	return_ACPI_STATUS(AE_AML_NO_RESOURCE_END_TAG);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_rs_convert_resources_to_aml
 *
 * PARAMETERS:  Resource            - Pointer to the resource linked list
 *              aml_size_needed     - Calculated size of the byte stream
 *                                    needed from calling acpi_rs_get_aml_length()
 *                                    The size of the output_buffer is
 *                                    guaranteed to be >= aml_size_needed
 *              output_buffer       - Pointer to the buffer that will
 *                                    contain the byte stream
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Takes the resource linked list and parses it, creating a
 *              byte stream of resources in the caller's output buffer
 *
 ******************************************************************************/

acpi_status
acpi_rs_convert_resources_to_aml(struct acpi_resource *resource,
				 acpi_size aml_size_needed, u8 * output_buffer)
{
	u8 *aml_buffer = output_buffer;
	u8 *end_aml_buffer = output_buffer + aml_size_needed;
	acpi_status status;

	ACPI_FUNCTION_TRACE("rs_convert_resources_to_aml");

	/* Walk the resource descriptor list, convert each descriptor */

	while (aml_buffer < end_aml_buffer) {
		/* Validate the Resource Type */

		if (resource->type > ACPI_RESOURCE_TYPE_MAX) {
			ACPI_DEBUG_PRINT((ACPI_DB_ERROR,
					  "Invalid descriptor type (%X) in resource list\n",
					  resource->type));
			return_ACPI_STATUS(AE_BAD_DATA);
		}

		/* Perform the conversion */

		status = acpi_rs_convert_resource_to_aml(resource,
							 ACPI_CAST_PTR(union
								       aml_resource,
								       aml_buffer),
							 acpi_gbl_set_resource_dispatch
							 [resource->type]);
		if (ACPI_FAILURE(status)) {
			ACPI_REPORT_ERROR(("Could not convert resource (type %X) to AML, %s\n", resource->type, acpi_format_exception(status)));
			return_ACPI_STATUS(status);
		}

		/* Perform final sanity check on the new AML resource descriptor */

		status =
		    acpi_rs_validate_resource_length(ACPI_CAST_PTR
						     (union aml_resource,
						      aml_buffer));
		if (ACPI_FAILURE(status)) {
			return_ACPI_STATUS(status);
		}

		/* Check for end-of-list, normal exit */

		if (resource->type == ACPI_RESOURCE_TYPE_END_TAG) {
			/* An End Tag indicates the end of the input Resource Template */

			return_ACPI_STATUS(AE_OK);
		}

		/*
		 * Extract the total length of the new descriptor and set the
		 * aml_buffer to point to the next (output) resource descriptor
		 */
		aml_buffer += acpi_ut_get_descriptor_length(aml_buffer);

		/* Point to the next input resource descriptor */

		resource =
		    ACPI_PTR_ADD(struct acpi_resource, resource,
				 resource->length);

		/* Check for end-of-list, normal exit */

	}

	/* Completed buffer, but did not find an end_tag resource descriptor */

	return_ACPI_STATUS(AE_AML_NO_RESOURCE_END_TAG);
}
