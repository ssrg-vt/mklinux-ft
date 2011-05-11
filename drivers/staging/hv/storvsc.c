/*
 * Copyright (c) 2009, Microsoft Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 * Authors:
 *   Haiyang Zhang <haiyangz@microsoft.com>
 *   Hank Janssen  <hjanssen@microsoft.com>
 *
 * 4/3/2011: K. Y. Srinivasan - Significant restructuring and cleanup.
 */
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include "hv_api.h"
#include "logging.h"
#include "storvsc_api.h"
#include "vmbus_packet_format.h"
#include "vstorage.h"
#include "channel.h"


static inline struct storvsc_device *alloc_stor_device(struct hv_device *device)
{
	struct storvsc_device *stor_device;

	stor_device = kzalloc(sizeof(struct storvsc_device), GFP_KERNEL);
	if (!stor_device)
		return NULL;

	/* Set to 2 to allow both inbound and outbound traffics */
	/* (ie get_stor_device() and must_get_stor_device()) to proceed. */
	atomic_cmpxchg(&stor_device->ref_count, 0, 2);

	stor_device->device = device;
	device->ext = stor_device;

	return stor_device;
}

static inline void free_stor_device(struct storvsc_device *device)
{
	kfree(device);
}

/* Get the stordevice object iff exists and its refcount > 0 */
static inline struct storvsc_device *must_get_stor_device(
					struct hv_device *device)
{
	struct storvsc_device *stor_device;

	stor_device = (struct storvsc_device *)device->ext;
	if (stor_device && atomic_read(&stor_device->ref_count))
		atomic_inc(&stor_device->ref_count);
	else
		stor_device = NULL;

	return stor_device;
}

/* Drop ref count to 1 to effectively disable get_stor_device() */
static inline struct storvsc_device *release_stor_device(
					struct hv_device *device)
{
	struct storvsc_device *stor_device;

	stor_device = (struct storvsc_device *)device->ext;

	/* Busy wait until the ref drop to 2, then set it to 1 */
	while (atomic_cmpxchg(&stor_device->ref_count, 2, 1) != 2)
		udelay(100);

	return stor_device;
}

/* Drop ref count to 0. No one can use stor_device object. */
static inline struct storvsc_device *final_release_stor_device(
			struct hv_device *device)
{
	struct storvsc_device *stor_device;

	stor_device = (struct storvsc_device *)device->ext;

	/* Busy wait until the ref drop to 1, then set it to 0 */
	while (atomic_cmpxchg(&stor_device->ref_count, 1, 0) != 1)
		udelay(100);

	device->ext = NULL;
	return stor_device;
}

static int stor_vsc_channel_init(struct hv_device *device)
{
	struct storvsc_device *stor_device;
	struct hv_storvsc_request *request;
	struct vstor_packet *vstor_packet;
	int ret, t;

	stor_device = get_stor_device(device);
	if (!stor_device) {
		DPRINT_ERR(STORVSC, "unable to get stor device..."
			   "device being destroyed?");
		return -1;
	}

	request = &stor_device->init_request;
	vstor_packet = &request->vstor_packet;

	/*
	 * Now, initiate the vsc/vsp initialization protocol on the open
	 * channel
	 */
	memset(request, 0, sizeof(struct hv_storvsc_request));
	init_completion(&request->wait_event);
	vstor_packet->operation = VSTOR_OPERATION_BEGIN_INITIALIZATION;
	vstor_packet->flags = REQUEST_COMPLETION_FLAG;

	DPRINT_INFO(STORVSC, "BEGIN_INITIALIZATION_OPERATION...");

	ret = vmbus_sendpacket(device->channel, vstor_packet,
			       sizeof(struct vstor_packet),
			       (unsigned long)request,
			       VM_PKT_DATA_INBAND,
			       VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	if (ret != 0) {
		DPRINT_ERR(STORVSC,
			   "unable to send BEGIN_INITIALIZATION_OPERATION");
		goto cleanup;
	}

	t = wait_for_completion_timeout(&request->wait_event, HZ);
	if (t == 0) {
		ret = -ETIMEDOUT;
		goto cleanup;
	}

	if (vstor_packet->operation != VSTOR_OPERATION_COMPLETE_IO ||
	    vstor_packet->status != 0) {
		DPRINT_ERR(STORVSC, "BEGIN_INITIALIZATION_OPERATION failed "
			   "(op %d status 0x%x)",
			   vstor_packet->operation, vstor_packet->status);
		goto cleanup;
	}

	DPRINT_INFO(STORVSC, "QUERY_PROTOCOL_VERSION_OPERATION...");

	/* reuse the packet for version range supported */
	memset(vstor_packet, 0, sizeof(struct vstor_packet));
	vstor_packet->operation = VSTOR_OPERATION_QUERY_PROTOCOL_VERSION;
	vstor_packet->flags = REQUEST_COMPLETION_FLAG;

	vstor_packet->version.major_minor = VMSTOR_PROTOCOL_VERSION_CURRENT;
	FILL_VMSTOR_REVISION(vstor_packet->version.revision);

	ret = vmbus_sendpacket(device->channel, vstor_packet,
			       sizeof(struct vstor_packet),
			       (unsigned long)request,
			       VM_PKT_DATA_INBAND,
			       VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	if (ret != 0) {
		DPRINT_ERR(STORVSC,
			   "unable to send BEGIN_INITIALIZATION_OPERATION");
		goto cleanup;
	}

	t = wait_for_completion_timeout(&request->wait_event, HZ);
	if (t == 0) {
		ret = -ETIMEDOUT;
		goto cleanup;
	}

	/* TODO: Check returned version */
	if (vstor_packet->operation != VSTOR_OPERATION_COMPLETE_IO ||
	    vstor_packet->status != 0) {
		DPRINT_ERR(STORVSC, "QUERY_PROTOCOL_VERSION_OPERATION failed "
			   "(op %d status 0x%x)",
			   vstor_packet->operation, vstor_packet->status);
		goto cleanup;
	}

	/* Query channel properties */
	DPRINT_INFO(STORVSC, "QUERY_PROPERTIES_OPERATION...");

	memset(vstor_packet, 0, sizeof(struct vstor_packet));
	vstor_packet->operation = VSTOR_OPERATION_QUERY_PROPERTIES;
	vstor_packet->flags = REQUEST_COMPLETION_FLAG;
	vstor_packet->storage_channel_properties.port_number =
					stor_device->port_number;

	ret = vmbus_sendpacket(device->channel, vstor_packet,
			       sizeof(struct vstor_packet),
			       (unsigned long)request,
			       VM_PKT_DATA_INBAND,
			       VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	if (ret != 0) {
		DPRINT_ERR(STORVSC,
			   "unable to send QUERY_PROPERTIES_OPERATION");
		goto cleanup;
	}

	t = wait_for_completion_timeout(&request->wait_event, HZ);
	if (t == 0) {
		ret = -ETIMEDOUT;
		goto cleanup;
	}

	/* TODO: Check returned version */
	if (vstor_packet->operation != VSTOR_OPERATION_COMPLETE_IO ||
	    vstor_packet->status != 0) {
		DPRINT_ERR(STORVSC, "QUERY_PROPERTIES_OPERATION failed "
			   "(op %d status 0x%x)",
			   vstor_packet->operation, vstor_packet->status);
		goto cleanup;
	}

	stor_device->path_id = vstor_packet->storage_channel_properties.path_id;
	stor_device->target_id
		= vstor_packet->storage_channel_properties.target_id;

	DPRINT_DBG(STORVSC, "channel flag 0x%x, max xfer len 0x%x",
		   vstor_packet->storage_channel_properties.flags,
		   vstor_packet->storage_channel_properties.max_transfer_bytes);

	DPRINT_INFO(STORVSC, "END_INITIALIZATION_OPERATION...");

	memset(vstor_packet, 0, sizeof(struct vstor_packet));
	vstor_packet->operation = VSTOR_OPERATION_END_INITIALIZATION;
	vstor_packet->flags = REQUEST_COMPLETION_FLAG;

	ret = vmbus_sendpacket(device->channel, vstor_packet,
			       sizeof(struct vstor_packet),
			       (unsigned long)request,
			       VM_PKT_DATA_INBAND,
			       VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	if (ret != 0) {
		DPRINT_ERR(STORVSC,
			   "unable to send END_INITIALIZATION_OPERATION");
		goto cleanup;
	}

	t = wait_for_completion_timeout(&request->wait_event, HZ);
	if (t == 0) {
		ret = -ETIMEDOUT;
		goto cleanup;
	}

	if (vstor_packet->operation != VSTOR_OPERATION_COMPLETE_IO ||
	    vstor_packet->status != 0) {
		DPRINT_ERR(STORVSC, "END_INITIALIZATION_OPERATION failed "
			   "(op %d status 0x%x)",
			   vstor_packet->operation, vstor_packet->status);
		goto cleanup;
	}

	DPRINT_INFO(STORVSC, "**** storage channel up and running!! ****");

cleanup:
	put_stor_device(device);
	return ret;
}

static void stor_vsc_on_io_completion(struct hv_device *device,
				  struct vstor_packet *vstor_packet,
				  struct hv_storvsc_request *request)
{
	struct storvsc_device *stor_device;
	struct vstor_packet *stor_pkt;

	stor_device = must_get_stor_device(device);
	if (!stor_device) {
		DPRINT_ERR(STORVSC, "unable to get stor device..."
			   "device being destroyed?");
		return;
	}

	DPRINT_DBG(STORVSC, "IO_COMPLETE_OPERATION - request %p "
		   "completed bytes xfer %u", request,
		   vstor_packet->vm_srb.data_transfer_length);

	stor_pkt = &request->vstor_packet;


	/* Copy over the status...etc */
	stor_pkt->vm_srb.scsi_status = vstor_packet->vm_srb.scsi_status;
	stor_pkt->vm_srb.srb_status = vstor_packet->vm_srb.srb_status;
	stor_pkt->vm_srb.sense_info_length =
	vstor_packet->vm_srb.sense_info_length;

	if (vstor_packet->vm_srb.scsi_status != 0 ||
		vstor_packet->vm_srb.srb_status != 1) {
		DPRINT_WARN(STORVSC,
			    "cmd 0x%x scsi status 0x%x srb status 0x%x\n",
			    stor_pkt->vm_srb.cdb[0],
			    vstor_packet->vm_srb.scsi_status,
			    vstor_packet->vm_srb.srb_status);
	}

	if ((vstor_packet->vm_srb.scsi_status & 0xFF) == 0x02) {
		/* CHECK_CONDITION */
		if (vstor_packet->vm_srb.srb_status & 0x80) {
			/* autosense data available */
			DPRINT_WARN(STORVSC, "storvsc pkt %p autosense data "
				    "valid - len %d\n", request,
				    vstor_packet->vm_srb.sense_info_length);

			memcpy(request->sense_buffer,
			       vstor_packet->vm_srb.sense_data,
			       vstor_packet->vm_srb.sense_info_length);

		}
	}

	stor_pkt->vm_srb.data_transfer_length =
	vstor_packet->vm_srb.data_transfer_length;

	request->on_io_completion(request);

	atomic_dec(&stor_device->num_outstanding_req);

	put_stor_device(device);
}

static void stor_vsc_on_receive(struct hv_device *device,
			     struct vstor_packet *vstor_packet,
			     struct hv_storvsc_request *request)
{
	switch (vstor_packet->operation) {
	case VSTOR_OPERATION_COMPLETE_IO:
		DPRINT_DBG(STORVSC, "IO_COMPLETE_OPERATION");
		stor_vsc_on_io_completion(device, vstor_packet, request);
		break;
	case VSTOR_OPERATION_REMOVE_DEVICE:
		DPRINT_INFO(STORVSC, "REMOVE_DEVICE_OPERATION");
		/* TODO: */
		break;

	default:
		DPRINT_INFO(STORVSC, "Unknown operation received - %d",
			    vstor_packet->operation);
		break;
	}
}

static void stor_vsc_on_channel_callback(void *context)
{
	struct hv_device *device = (struct hv_device *)context;
	struct storvsc_device *stor_device;
	u32 bytes_recvd;
	u64 request_id;
	unsigned char packet[ALIGN(sizeof(struct vstor_packet), 8)];
	struct hv_storvsc_request *request;
	int ret;


	stor_device = must_get_stor_device(device);
	if (!stor_device) {
		DPRINT_ERR(STORVSC, "unable to get stor device..."
			   "device being destroyed?");
		return;
	}

	do {
		ret = vmbus_recvpacket(device->channel, packet,
				       ALIGN(sizeof(struct vstor_packet), 8),
				       &bytes_recvd, &request_id);
		if (ret == 0 && bytes_recvd > 0) {
			DPRINT_DBG(STORVSC, "receive %d bytes - tid %llx",
				   bytes_recvd, request_id);


			request = (struct hv_storvsc_request *)
					(unsigned long)request_id;

			if ((request == &stor_device->init_request) ||
			    (request == &stor_device->reset_request)) {

				memcpy(&request->vstor_packet, packet,
				       sizeof(struct vstor_packet));
				complete(&request->wait_event);
			} else {
				stor_vsc_on_receive(device,
						(struct vstor_packet *)packet,
						request);
			}
		} else {
			break;
		}
	} while (1);

	put_stor_device(device);
	return;
}

static int stor_vsc_connect_to_vsp(struct hv_device *device)
{
	struct vmstorage_channel_properties props;
	struct storvsc_driver *stor_driver;
	int ret;

	stor_driver = drv_to_stordrv(device->device.driver);
	memset(&props, 0, sizeof(struct vmstorage_channel_properties));

	/* Open the channel */
	ret = vmbus_open(device->channel,
			 stor_driver->ring_buffer_size,
			 stor_driver->ring_buffer_size,
			 (void *)&props,
			 sizeof(struct vmstorage_channel_properties),
			 stor_vsc_on_channel_callback, device);

	DPRINT_DBG(STORVSC, "storage props: path id %d, tgt id %d, max xfer %d",
		   props.path_id, props.target_id, props.max_transfer_bytes);

	if (ret != 0) {
		DPRINT_ERR(STORVSC, "unable to open channel: %d", ret);
		return -1;
	}

	ret = stor_vsc_channel_init(device);

	return ret;
}

/*
 * stor_vsc_on_device_add - Callback when the device belonging to this driver
 * is added
 */
int storvsc_dev_add(struct hv_device *device,
					void *additional_info)
{
	struct storvsc_device *stor_device;
	struct storvsc_device_info *device_info;
	int ret = 0;

	device_info = (struct storvsc_device_info *)additional_info;
	stor_device = alloc_stor_device(device);
	if (!stor_device) {
		ret = -1;
		goto cleanup;
	}

	/* Save the channel properties to our storvsc channel */

	/* FIXME: */
	/*
	 * If we support more than 1 scsi channel, we need to set the
	 * port number here to the scsi channel but how do we get the
	 * scsi channel prior to the bus scan
	 */

	stor_device->port_number = device_info->port_number;
	/* Send it back up */
	ret = stor_vsc_connect_to_vsp(device);

	device_info->path_id = stor_device->path_id;
	device_info->target_id = stor_device->target_id;

	DPRINT_DBG(STORVSC, "assigned port %u, path %u target %u\n",
		   stor_device->port_number, stor_device->path_id,
		   stor_device->target_id);

cleanup:
	return ret;
}

/*
 * stor_vsc_on_device_remove - Callback when the our device is being removed
 */
int stor_vsc_on_device_remove(struct hv_device *device)
{
	struct storvsc_device *stor_device;

	DPRINT_INFO(STORVSC, "disabling storage device (%p)...",
		    device->ext);

	stor_device = release_stor_device(device);

	/*
	 * At this point, all outbound traffic should be disable. We
	 * only allow inbound traffic (responses) to proceed so that
	 * outstanding requests can be completed.
	 */
	while (atomic_read(&stor_device->num_outstanding_req)) {
		DPRINT_INFO(STORVSC, "waiting for %d requests to complete...",
			    atomic_read(&stor_device->num_outstanding_req));
		udelay(100);
	}

	DPRINT_INFO(STORVSC, "removing storage device (%p)...",
		    device->ext);

	stor_device = final_release_stor_device(device);

	DPRINT_INFO(STORVSC, "storage device (%p) safe to remove", stor_device);

	/* Close the channel */
	vmbus_close(device->channel);

	free_stor_device(stor_device);
	return 0;
}

/*
 * stor_vsc_on_io_request - Callback to initiate an I/O request
 */
int stor_vsc_on_io_request(struct hv_device *device,
			      struct hv_storvsc_request *request)
{
	struct storvsc_device *stor_device;
	struct vstor_packet *vstor_packet;
	int ret = 0;

	vstor_packet = &request->vstor_packet;
	stor_device = get_stor_device(device);

	DPRINT_DBG(STORVSC, "enter - Device %p, DeviceExt %p, Request %p, "
		   , device, stor_device, request);

	DPRINT_DBG(STORVSC, "req %p len %d",
		   request, request->data_buffer.len);

	if (!stor_device) {
		DPRINT_ERR(STORVSC, "unable to get stor device..."
			   "device being destroyed?");
		return -2;
	}


	request->device  = device;


	vstor_packet->flags |= REQUEST_COMPLETION_FLAG;

	vstor_packet->vm_srb.length = sizeof(struct vmscsi_request);


	vstor_packet->vm_srb.sense_info_length = SENSE_BUFFER_SIZE;


	vstor_packet->vm_srb.data_transfer_length =
	request->data_buffer.len;

	vstor_packet->operation = VSTOR_OPERATION_EXECUTE_SRB;

	DPRINT_DBG(STORVSC, "srb - len %d port %d, path %d, target %d, "
		   "lun %d senselen %d cdblen %d",
		   vstor_packet->vm_srb.length,
		   vstor_packet->vm_srb.port_number,
		   vstor_packet->vm_srb.path_id,
		   vstor_packet->vm_srb.target_id,
		   vstor_packet->vm_srb.lun,
		   vstor_packet->vm_srb.sense_info_length,
		   vstor_packet->vm_srb.cdb_length);

	if (request->data_buffer.len) {
		ret = vmbus_sendpacket_multipagebuffer(device->channel,
				&request->data_buffer,
				vstor_packet,
				sizeof(struct vstor_packet),
				(unsigned long)request);
	} else {
		ret = vmbus_sendpacket(device->channel, vstor_packet,
				       sizeof(struct vstor_packet),
				       (unsigned long)request,
				       VM_PKT_DATA_INBAND,
				       VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	}

	if (ret != 0) {
		DPRINT_DBG(STORVSC, "Unable to send packet %p ret %d",
			   vstor_packet, ret);
	}

	atomic_inc(&stor_device->num_outstanding_req);

	put_stor_device(device);
	return ret;
}

/*
 * The channel properties uniquely specify how the device is to be
 * presented to the guest. Map this information for use by the block
 * driver. For Linux guests on Hyper-V, we emulate a scsi HBA in the guest
 * (storvsc_drv) and so scsi devices in the guest  are handled by
 * native upper level Linux drivers. Consequently, Hyper-V
 * block driver, while being a generic block driver, presently does not
 * deal with anything other than devices that would need to be presented
 * to the guest as an IDE disk.
 *
 * This function maps the channel properties as embedded in the input
 * parameter device_info onto information necessary to register the
 * corresponding block device.
 *
 * Currently, there is no way to stop the emulation of the block device
 * on the host side. And so, to prevent the native IDE drivers in Linux
 * from taking over these devices (to be managedby Hyper-V block
 * driver), we will take over if need be the major of the IDE controllers.
 *
 */

int stor_vsc_get_major_info(struct storvsc_device_info *device_info,
			    struct storvsc_major_info *major_info)
{
	static bool ide0_registered;
	static bool ide1_registered;

	/*
	 * For now we only support IDE disks.
	 */
	major_info->devname = "ide";
	major_info->diskname = "hd";

	if (device_info->path_id) {
		major_info->major = 22;
		if (!ide1_registered) {
			major_info->do_register = true;
			ide1_registered = true;
		} else
			major_info->do_register = false;

		if (device_info->target_id)
			major_info->index = 3;
		else
			major_info->index = 2;

		return 0;
	} else {
		major_info->major = 3;
		if (!ide0_registered) {
			major_info->do_register = true;
			ide0_registered = true;
		} else
			major_info->do_register = false;

		if (device_info->target_id)
			major_info->index = 1;
		else
			major_info->index = 0;

		return 0;
	}

	return -ENODEV;
}

/*
 * stor_vsc_on_cleanup - Perform any cleanup when the driver is removed
 */
void stor_vsc_on_cleanup(struct hv_driver *driver)
{
}

