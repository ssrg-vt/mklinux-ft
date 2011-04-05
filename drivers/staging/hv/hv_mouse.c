/*
 *  Copyright (c) 2009, Citrix Systems, Inc.
 *  Copyright (c) 2010, Microsoft Corporation.
 *  Copyright (c) 2011, Novell Inc.
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms and conditions of the GNU General Public License,
 *  version 2, as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 *  more details.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/input.h>
#include <linux/hid.h>
#include <linux/hiddev.h>
#include <linux/pci.h>
#include <linux/dmi.h>

#include "hv_api.h"
#include "logging.h"
#include "version_info.h"
#include "vmbus.h"
#include "vmbus_api.h"
#include "channel.h"
#include "vmbus_packet_format.h"


/*
 * Data types
 */
struct hv_input_dev_info {
	unsigned short vendor;
	unsigned short product;
	unsigned short version;
	char name[128];
};

/* Represents the input vsc driver */
/* FIXME - can be removed entirely */
struct mousevsc_drv_obj {
	struct hv_driver base;
};


/* The maximum size of a synthetic input message. */
#define SYNTHHID_MAX_INPUT_REPORT_SIZE 16

/*
 * Current version
 *
 * History:
 * Beta, RC < 2008/1/22        1,0
 * RC > 2008/1/22              2,0
 */
#define SYNTHHID_INPUT_VERSION_MAJOR	2
#define SYNTHHID_INPUT_VERSION_MINOR	0
#define SYNTHHID_INPUT_VERSION		(SYNTHHID_INPUT_VERSION_MINOR | \
					 (SYNTHHID_INPUT_VERSION_MAJOR << 16))


#pragma pack(push,1)
/*
 * Message types in the synthetic input protocol
 */
enum synthhid_msg_type {
	SynthHidProtocolRequest,
	SynthHidProtocolResponse,
	SynthHidInitialDeviceInfo,
	SynthHidInitialDeviceInfoAck,
	SynthHidInputReport,
	SynthHidMax
};

/*
 * Basic message structures.
 */
struct synthhid_msg_hdr {
	enum synthhid_msg_type type;
	u32 size;
};

struct synthhid_msg {
	struct synthhid_msg_hdr header;
	char data[1]; /* Enclosed message */
};

union synthhid_version {
	struct {
		u16 minor_version;
		u16 major_version;
	};
	u32 version;
};

/*
 * Protocol messages
 */
struct synthhid_protocol_request {
	struct synthhid_msg_hdr header;
	union synthhid_version version_requested;
};

struct synthhid_protocol_response {
	struct synthhid_msg_hdr header;
	union synthhid_version version_requested;
	unsigned char approved;
};

struct synthhid_device_info {
	struct synthhid_msg_hdr header;
	struct hv_input_dev_info hid_dev_info;
	struct hid_descriptor hid_descriptor;
};

struct synthhid_device_info_ack {
	struct synthhid_msg_hdr header;
	unsigned char reserved;
};

struct synthhid_input_report {
	struct synthhid_msg_hdr header;
	char buffer[1];
};

#pragma pack(pop)

#define INPUTVSC_SEND_RING_BUFFER_SIZE		10*PAGE_SIZE
#define INPUTVSC_RECV_RING_BUFFER_SIZE		10*PAGE_SIZE

#define NBITS(x) (((x)/BITS_PER_LONG)+1)

enum pipe_prot_msg_type {
	PipeMessageInvalid = 0,
	PipeMessageData,
	PipeMessageMaximum
};


struct pipe_prt_msg {
	enum pipe_prot_msg_type type;
	u32 size;
	char data[1];
};

/*
 * Data types
 */
struct  mousevsc_prt_msg {
	enum pipe_prot_msg_type type;
	u32 size;
	union {
		struct synthhid_protocol_request request;
		struct synthhid_protocol_response response;
		struct synthhid_device_info_ack ack;
	};
};

/*
 * Represents an mousevsc device
 */
struct mousevsc_dev {
	struct hv_device	*device;
	/* 0 indicates the device is being destroyed */
	atomic_t		ref_count;
	int			num_outstanding_req;
	unsigned char		init_complete;
	struct mousevsc_prt_msg	protocol_req;
	struct mousevsc_prt_msg	protocol_resp;
	/* Synchronize the request/response if needed */
	wait_queue_head_t	protocol_wait_event;
	wait_queue_head_t	dev_info_wait_event;
	int			protocol_wait_condition;
	int			device_wait_condition;
	int			dev_info_status;

	struct hid_descriptor	*hid_desc;
	unsigned char		*report_desc;
	u32			report_desc_size;
	struct hv_input_dev_info hid_dev_info;
};


static const char *driver_name = "mousevsc";

/* {CFA8B69E-5B4A-4cc0-B98B-8BA1A1F3F95A} */
static const struct hv_guid mouse_guid = {
	.data = {0x9E, 0xB6, 0xA8, 0xCF, 0x4A, 0x5B, 0xc0, 0x4c,
		 0xB9, 0x8B, 0x8B, 0xA1, 0xA1, 0xF3, 0xF9, 0x5A}
};

static void deviceinfo_callback(struct hv_device *dev, struct hv_input_dev_info *info);
static void inputreport_callback(struct hv_device *dev, void *packet, u32 len);
static void reportdesc_callback(struct hv_device *dev, void *packet, u32 len);

static struct mousevsc_dev *alloc_input_device(struct hv_device *device)
{
	struct mousevsc_dev *inputDevice;

	inputDevice = kzalloc(sizeof(struct mousevsc_dev), GFP_KERNEL);

	if (!inputDevice)
		return NULL;

	/*
	 * Set to 2 to allow both inbound and outbound traffics
	 * (ie get_input_device() and must_get_input_device()) to proceed.
	 */
	atomic_cmpxchg(&inputDevice->ref_count, 0, 2);

	inputDevice->device = device;
	device->ext = inputDevice;

	return inputDevice;
}

static void free_input_device(struct mousevsc_dev *device)
{
	WARN_ON(atomic_read(&device->ref_count) == 0);
	kfree(device);
}

/*
 * Get the inputdevice object if exists and its refcount > 1
 */
static struct mousevsc_dev *get_input_device(struct hv_device *device)
{
	struct mousevsc_dev *inputDevice;

	inputDevice = (struct mousevsc_dev *)device->ext;

/*
 *	FIXME
 *	This sure isn't a valid thing to print for debugging, no matter
 *	what the intention is...
 *
 *	printk(KERN_ERR "-------------------------> REFCOUNT = %d",
 *	       inputDevice->ref_count);
 */

	if (inputDevice && atomic_read(&inputDevice->ref_count) > 1)
		atomic_inc(&inputDevice->ref_count);
	else
		inputDevice = NULL;

	return inputDevice;
}

/*
 * Get the inputdevice object iff exists and its refcount > 0
 */
static struct mousevsc_dev *must_get_input_device(struct hv_device *device)
{
	struct mousevsc_dev *inputDevice;

	inputDevice = (struct mousevsc_dev *)device->ext;

	if (inputDevice && atomic_read(&inputDevice->ref_count))
		atomic_inc(&inputDevice->ref_count);
	else
		inputDevice = NULL;

	return inputDevice;
}

static void put_input_device(struct hv_device *device)
{
	struct mousevsc_dev *inputDevice;

	inputDevice = (struct mousevsc_dev *)device->ext;

	atomic_dec(&inputDevice->ref_count);
}

/*
 * Drop ref count to 1 to effectively disable get_input_device()
 */
static struct mousevsc_dev *release_input_device(struct hv_device *device)
{
	struct mousevsc_dev *inputDevice;

	inputDevice = (struct mousevsc_dev *)device->ext;

	/* Busy wait until the ref drop to 2, then set it to 1  */
	while (atomic_cmpxchg(&inputDevice->ref_count, 2, 1) != 2)
		udelay(100);

	return inputDevice;
}

/*
 * Drop ref count to 0. No one can use input_device object.
 */
static struct mousevsc_dev *final_release_input_device(struct hv_device *device)
{
	struct mousevsc_dev *inputDevice;

	inputDevice = (struct mousevsc_dev *)device->ext;

	/* Busy wait until the ref drop to 1, then set it to 0  */
	while (atomic_cmpxchg(&inputDevice->ref_count, 1, 0) != 1)
		udelay(100);

	device->ext = NULL;
	return inputDevice;
}

static void mousevsc_on_send_completion(struct hv_device *device,
					struct vmpacket_descriptor *packet)
{
	struct mousevsc_dev *inputDevice;
	void *request;

	inputDevice = must_get_input_device(device);
	if (!inputDevice) {
		pr_err("unable to get input device...device being destroyed?");
		return;
	}

	request = (void *)(unsigned long)packet->trans_id;

	if (request == &inputDevice->protocol_req) {
		/* FIXME */
		/* Shouldn't we be doing something here? */
	}

	put_input_device(device);
}

static void mousevsc_on_receive_device_info(struct mousevsc_dev *input_device,
				struct synthhid_device_info *device_info)
{
	int ret = 0;
	struct hid_descriptor *desc;
	struct mousevsc_prt_msg ack;

	/* Assume success for now */
	input_device->dev_info_status = 0;

	/* Save the device attr */
	memcpy(&input_device->hid_dev_info, &device_info->hid_dev_info,
		sizeof(struct hv_input_dev_info));

	/* Save the hid desc */
	desc = &device_info->hid_descriptor;
	WARN_ON(desc->bLength > 0);

	input_device->hid_desc = kzalloc(desc->bLength, GFP_KERNEL);

	if (!input_device->hid_desc) {
		pr_err("unable to allocate hid descriptor - size %d", desc->bLength);
		goto Cleanup;
	}

	memcpy(input_device->hid_desc, desc, desc->bLength);

	/* Save the report desc */
	input_device->report_desc_size = desc->desc[0].wDescriptorLength;
	input_device->report_desc = kzalloc(input_device->report_desc_size,
					  GFP_KERNEL);

	if (!input_device->report_desc) {
		pr_err("unable to allocate report descriptor - size %d",
			   input_device->report_desc_size);
		goto Cleanup;
	}

	memcpy(input_device->report_desc,
	       ((unsigned char *)desc) + desc->bLength,
	       desc->desc[0].wDescriptorLength);

	/* Send the ack */
	memset(&ack, sizeof(struct mousevsc_prt_msg), 0);

	ack.type = PipeMessageData;
	ack.size = sizeof(struct synthhid_device_info_ack);

	ack.ack.header.type = SynthHidInitialDeviceInfoAck;
	ack.ack.header.size = 1;
	ack.ack.reserved = 0;

	ret = vmbus_sendpacket(input_device->device->channel,
			&ack,
			sizeof(struct pipe_prt_msg) - sizeof(unsigned char) +
			sizeof(struct synthhid_device_info_ack),
			(unsigned long)&ack,
			VM_PKT_DATA_INBAND,
			VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	if (ret != 0) {
		pr_err("unable to send synthhid device info ack - ret %d",
			   ret);
		goto Cleanup;
	}

	input_device->device_wait_condition = 1;
	wake_up(&input_device->dev_info_wait_event);

	return;

Cleanup:
	kfree(input_device->hid_desc);
	input_device->hid_desc = NULL;

	kfree(input_device->report_desc);
	input_device->report_desc = NULL;

	input_device->dev_info_status = -1;
	input_device->device_wait_condition = 1;
	wake_up(&input_device->dev_info_wait_event);
}

static void mousevsc_on_receive_input_report(struct mousevsc_dev *input_device,
				struct synthhid_input_report *input_report)
{
	struct mousevsc_drv_obj *inputDriver;

	if (!input_device->init_complete) {
		pr_info("Initialization incomplete...ignoring input_report msg");
		return;
	}

	inputDriver = (struct mousevsc_drv_obj *)input_device->device->drv;

	inputreport_callback(input_device->device,
			     input_report->buffer,
			     input_report->header.size);
}

static void mousevsc_on_receive(struct hv_device *device,
				struct vmpacket_descriptor *packet)
{
	struct pipe_prt_msg *pipeMsg;
	struct synthhid_msg *hidMsg;
	struct mousevsc_dev *inputDevice;

	inputDevice = must_get_input_device(device);
	if (!inputDevice) {
		pr_err("unable to get input device...device being destroyed?");
		return;
	}

	pipeMsg = (struct pipe_prt_msg *)((unsigned long)packet +
						(packet->offset8 << 3));

	if (pipeMsg->type != PipeMessageData) {
		pr_err("unknown pipe msg type - type %d len %d",
			   pipeMsg->type, pipeMsg->size);
		put_input_device(device);
		return ;
	}

	hidMsg = (struct synthhid_msg *)&pipeMsg->data[0];

	switch (hidMsg->header.type) {
	case SynthHidProtocolResponse:
		memcpy(&inputDevice->protocol_resp, pipeMsg,
		       pipeMsg->size + sizeof(struct pipe_prt_msg) -
		       sizeof(unsigned char));
		inputDevice->protocol_wait_condition = 1;
		wake_up(&inputDevice->protocol_wait_event);
		break;

	case SynthHidInitialDeviceInfo:
		WARN_ON(pipeMsg->size >= sizeof(struct hv_input_dev_info));

		/*
		 * Parse out the device info into device attr,
		 * hid desc and report desc
		 */
		mousevsc_on_receive_device_info(inputDevice,
					    (struct synthhid_device_info *)&pipeMsg->data[0]);
		break;
	case SynthHidInputReport:
		mousevsc_on_receive_input_report(inputDevice,
					     (struct synthhid_input_report *)&pipeMsg->data[0]);

		break;
	default:
		pr_err("unsupported hid msg type - type %d len %d",
		       hidMsg->header.type, hidMsg->header.size);
		break;
	}

	put_input_device(device);
}

static void mousevsc_on_channel_callback(void *context)
{
	const int packetSize = 0x100;
	int ret = 0;
	struct hv_device *device = (struct hv_device *)context;
	struct mousevsc_dev *inputDevice;

	u32 bytesRecvd;
	u64 requestId;
	unsigned char packet[packetSize];
	struct vmpacket_descriptor *desc;
	unsigned char	*buffer = packet;
	int	bufferlen = packetSize;

	inputDevice = must_get_input_device(device);

	if (!inputDevice) {
		pr_err("unable to get input device...device being destroyed?");
		return;
	}

	do {
		ret = vmbus_recvpacket_raw(device->channel, buffer, bufferlen, &bytesRecvd, &requestId);

		if (ret == 0) {
			if (bytesRecvd > 0) {
				desc = (struct vmpacket_descriptor *)buffer;

				switch (desc->type) {
					case VM_PKT_COMP:
						mousevsc_on_send_completion(
							device, desc);
						break;

					case VM_PKT_DATA_INBAND:
						mousevsc_on_receive(
							device, desc);
						break;

					default:
						pr_err("unhandled packet type %d, tid %llx len %d\n",
							   desc->type,
							   requestId,
							   bytesRecvd);
						break;
				}

				/* reset */
				if (bufferlen > packetSize) {
					kfree(buffer);

					buffer = packet;
					bufferlen = packetSize;
				}
			} else {
				/*
				 * pr_debug("nothing else to read...");
				 * reset
				 */
				if (bufferlen > packetSize) {
					kfree(buffer);

					buffer = packet;
					bufferlen = packetSize;
				}
				break;
			}
		} else if (ret == -2) {
			/* Handle large packet */
			bufferlen = bytesRecvd;
			buffer = kzalloc(bytesRecvd, GFP_KERNEL);

			if (buffer == NULL) {
				buffer = packet;
				bufferlen = packetSize;

				/* Try again next time around */
				pr_err("unable to allocate buffer of size %d!",
				       bytesRecvd);
				break;
			}
		}
	} while (1);

	put_input_device(device);

	return;
}

static int mousevsc_connect_to_vsp(struct hv_device *device)
{
	int ret = 0;
	struct mousevsc_dev *inputDevice;
	struct mousevsc_prt_msg *request;
	struct mousevsc_prt_msg *response;

	inputDevice = get_input_device(device);

	if (!inputDevice) {
		pr_err("unable to get input device...device being destroyed?");
		return -1;
	}

	init_waitqueue_head(&inputDevice->protocol_wait_event);
	init_waitqueue_head(&inputDevice->dev_info_wait_event);

	request = &inputDevice->protocol_req;

	/*
	 * Now, initiate the vsc/vsp initialization protocol on the open channel
	 */
	memset(request, sizeof(struct mousevsc_prt_msg), 0);

	request->type = PipeMessageData;
	request->size = sizeof(struct synthhid_protocol_request);

	request->request.header.type = SynthHidProtocolRequest;
	request->request.header.size = sizeof(unsigned long);
	request->request.version_requested.version = SYNTHHID_INPUT_VERSION;

	pr_info("synthhid protocol request...");

	ret = vmbus_sendpacket(device->channel, request,
					sizeof(struct pipe_prt_msg) -
					sizeof(unsigned char) +
					sizeof(struct synthhid_protocol_request),
					(unsigned long)request,
					VM_PKT_DATA_INBAND,
					VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	if (ret != 0) {
		pr_err("unable to send synthhid protocol request.");
		goto Cleanup;
	}

	inputDevice->protocol_wait_condition = 0;
	wait_event_timeout(inputDevice->protocol_wait_event,
		inputDevice->protocol_wait_condition, msecs_to_jiffies(1000));
	if (inputDevice->protocol_wait_condition == 0) {
		ret = -ETIMEDOUT;
		goto Cleanup;
	}

	response = &inputDevice->protocol_resp;

	if (!response->response.approved) {
		pr_err("synthhid protocol request failed (version %d)",
		       SYNTHHID_INPUT_VERSION);
		ret = -1;
		goto Cleanup;
	}

	inputDevice->device_wait_condition = 0;
	wait_event_timeout(inputDevice->dev_info_wait_event,
		inputDevice->device_wait_condition, msecs_to_jiffies(1000));
	if (inputDevice->device_wait_condition == 0) {
		ret = -ETIMEDOUT;
		goto Cleanup;
	}

	/*
	 * We should have gotten the device attr, hid desc and report
	 * desc at this point
	 */
	if (!inputDevice->dev_info_status)
		pr_info("**** input channel up and running!! ****");
	else
		ret = -1;

Cleanup:
	put_input_device(device);

	return ret;
}

static int mousevsc_on_device_add(struct hv_device *device,
					void *additional_info)
{
	int ret = 0;
	struct mousevsc_dev *inputDevice;
	struct mousevsc_drv_obj *inputDriver;
	struct hv_input_dev_info dev_info;

	inputDevice = alloc_input_device(device);

	if (!inputDevice) {
		ret = -1;
		goto Cleanup;
	}

	inputDevice->init_complete = false;

	/* Open the channel */
	ret = vmbus_open(device->channel,
		INPUTVSC_SEND_RING_BUFFER_SIZE,
		INPUTVSC_RECV_RING_BUFFER_SIZE,
		NULL,
		0,
		mousevsc_on_channel_callback,
		device
		);

	if (ret != 0) {
		pr_err("unable to open channel: %d", ret);
		free_input_device(inputDevice);
		return -1;
	}

	pr_info("InputVsc channel open: %d", ret);

	ret = mousevsc_connect_to_vsp(device);

	if (ret != 0) {
		pr_err("unable to connect channel: %d", ret);

		vmbus_close(device->channel);
		free_input_device(inputDevice);
		return ret;
	}

	inputDriver = (struct mousevsc_drv_obj *)inputDevice->device->drv;

	dev_info.vendor = inputDevice->hid_dev_info.vendor;
	dev_info.product = inputDevice->hid_dev_info.product;
	dev_info.version = inputDevice->hid_dev_info.version;
	strcpy(dev_info.name, "Microsoft Vmbus HID-compliant Mouse");

	/* Send the device info back up */
	deviceinfo_callback(device, &dev_info);

	/* Send the report desc back up */
	/* workaround SA-167 */
	if (inputDevice->report_desc[14] == 0x25)
		inputDevice->report_desc[14] = 0x29;

	reportdesc_callback(device, inputDevice->report_desc,
			    inputDevice->report_desc_size);

	inputDevice->init_complete = true;

Cleanup:
	return ret;
}

static int mousevsc_on_device_remove(struct hv_device *device)
{
	struct mousevsc_dev *inputDevice;
	int ret = 0;

	pr_info("disabling input device (%p)...",
		    device->ext);

	inputDevice = release_input_device(device);


	/*
	 * At this point, all outbound traffic should be disable. We only
	 * allow inbound traffic (responses) to proceed
	 *
	 * so that outstanding requests can be completed.
	 */
	while (inputDevice->num_outstanding_req) {
		pr_info("waiting for %d requests to complete...",
			inputDevice->num_outstanding_req);

		udelay(100);
	}

	pr_info("removing input device (%p)...", device->ext);

	inputDevice = final_release_input_device(device);

	pr_info("input device (%p) safe to remove", inputDevice);

	/* Close the channel */
	vmbus_close(device->channel);

	free_input_device(inputDevice);

	return ret;
}

static void mousevsc_on_cleanup(struct hv_driver *drv)
{
}

/*
 * Data types
 */
struct input_device_context {
	struct hv_device	*device_ctx;
	struct hid_device	*hid_device;
	struct hv_input_dev_info device_info;
	int			connected;
};


static struct  mousevsc_drv_obj g_mousevsc_drv;

static void deviceinfo_callback(struct hv_device *dev, struct hv_input_dev_info *info)
{
	struct input_device_context *input_device_ctx =
		dev_get_drvdata(&dev->device);

	memcpy(&input_device_ctx->device_info, info,
	       sizeof(struct hv_input_dev_info));

	DPRINT_INFO(INPUTVSC_DRV, "%s", __func__);
}

static void inputreport_callback(struct hv_device *dev, void *packet, u32 len)
{
	int ret = 0;

	struct input_device_context *input_dev_ctx =
		dev_get_drvdata(&dev->device);

	ret = hid_input_report(input_dev_ctx->hid_device,
			      HID_INPUT_REPORT, packet, len, 1);

	DPRINT_DBG(INPUTVSC_DRV, "hid_input_report (ret %d)", ret);
}

static int mousevsc_hid_open(struct hid_device *hid)
{
	return 0;
}

static void mousevsc_hid_close(struct hid_device *hid)
{
}

static int mousevsc_probe(struct device *device)
{
	int ret = 0;

	struct hv_driver *drv =
		drv_to_hv_drv(device->driver);
	struct mousevsc_drv_obj *mousevsc_drv_obj = drv->priv;

	struct hv_device *device_obj = device_to_hv_device(device);
	struct input_device_context *input_dev_ctx;

	input_dev_ctx = kmalloc(sizeof(struct input_device_context),
				GFP_KERNEL);

	dev_set_drvdata(device, input_dev_ctx);

	/* Call to the vsc driver to add the device */
	ret = mousevsc_drv_obj->base.dev_add(device_obj, NULL);

	if (ret != 0) {
		DPRINT_ERR(INPUTVSC_DRV, "unable to add input vsc device");

		return -1;
	}

	return 0;
}

static int mousevsc_remove(struct device *device)
{
	int ret = 0;

	struct hv_driver *drv =
		drv_to_hv_drv(device->driver);
	struct mousevsc_drv_obj *mousevsc_drv_obj = drv->priv;

	struct hv_device *device_obj = device_to_hv_device(device);
	struct input_device_context *input_dev_ctx;

	input_dev_ctx = kmalloc(sizeof(struct input_device_context),
				GFP_KERNEL);

	dev_set_drvdata(device, input_dev_ctx);

	if (input_dev_ctx->connected) {
		hidinput_disconnect(input_dev_ctx->hid_device);
		input_dev_ctx->connected = 0;
	}

	if (!mousevsc_drv_obj->base.dev_rm)
		return -1;

	/*
	 * Call to the vsc driver to let it know that the device
	 * is being removed
	 */
	ret = mousevsc_drv_obj->base.dev_rm(device_obj);

	if (ret != 0) {
		DPRINT_ERR(INPUTVSC_DRV,
			   "unable to remove vsc device (ret %d)", ret);
	}

	kfree(input_dev_ctx);

	return ret;
}

static void reportdesc_callback(struct hv_device *dev, void *packet, u32 len)
{
	struct input_device_context *input_device_ctx =
		dev_get_drvdata(&dev->device);
	struct hid_device *hid_dev;

	/* hid_debug = -1; */
	hid_dev = kmalloc(sizeof(struct hid_device), GFP_KERNEL);

	if (hid_parse_report(hid_dev, packet, len)) {
		DPRINT_INFO(INPUTVSC_DRV, "Unable to call hd_parse_report");
		return;
	}

	if (hid_dev) {
		DPRINT_INFO(INPUTVSC_DRV, "hid_device created");

		hid_dev->ll_driver->open  = mousevsc_hid_open;
		hid_dev->ll_driver->close = mousevsc_hid_close;

		hid_dev->bus = BUS_VIRTUAL;
		hid_dev->vendor = input_device_ctx->device_info.vendor;
		hid_dev->product = input_device_ctx->device_info.product;
		hid_dev->version = input_device_ctx->device_info.version;
		hid_dev->dev = dev->device;

		sprintf(hid_dev->name, "%s",
			input_device_ctx->device_info.name);

		/*
		 * HJ Do we want to call it with a 0
		 */
		if (!hidinput_connect(hid_dev, 0)) {
			hid_dev->claimed |= HID_CLAIMED_INPUT;

			input_device_ctx->connected = 1;

			DPRINT_INFO(INPUTVSC_DRV,
				     "HID device claimed by input\n");
		}

		if (!hid_dev->claimed) {
			DPRINT_ERR(INPUTVSC_DRV,
				    "HID device not claimed by "
				    "input or hiddev\n");
		}

		input_device_ctx->hid_device = hid_dev;
	}

	kfree(hid_dev);
}

static int mousevsc_drv_exit_cb(struct device *dev, void *data)
{
	struct device **curr = (struct device **)data;
	*curr = dev;

	return 1;
}

static void mousevsc_drv_exit(void)
{
	struct mousevsc_drv_obj *mousevsc_drv_obj = &g_mousevsc_drv;
	struct hv_driver *drv = &g_mousevsc_drv.base;
	int ret;

	struct device *current_dev = NULL;

	while (1) {
		current_dev = NULL;

		/* Get the device */
		ret = driver_for_each_device(&drv->driver, NULL,
					     (void *)&current_dev,
					     mousevsc_drv_exit_cb);
		if (ret)
			printk(KERN_ERR "Can't find mouse device!\n");

		if (current_dev == NULL)
			break;

		/* Initiate removal from the top-down */
		device_unregister(current_dev);
	}

	if (mousevsc_drv_obj->base.cleanup)
		mousevsc_drv_obj->base.cleanup(&mousevsc_drv_obj->base);

	vmbus_child_driver_unregister(&drv->driver);

	return;
}

static int mouse_vsc_initialize(struct hv_driver *driver)
{
	struct mousevsc_drv_obj *inputDriver =
		(struct mousevsc_drv_obj *)driver;
	int ret = 0;

	driver->name = driver_name;
	memcpy(&driver->dev_type, &mouse_guid,
	       sizeof(struct hv_guid));

	/* Setup the dispatch table */
	inputDriver->base.dev_add = mousevsc_on_device_add;
	inputDriver->base.dev_rm = mousevsc_on_device_remove;
	inputDriver->base.cleanup = mousevsc_on_cleanup;

	return ret;
}


static int __init mousevsc_init(void)
{
	struct mousevsc_drv_obj *input_drv_obj = &g_mousevsc_drv;
	struct hv_driver *drv = &g_mousevsc_drv.base;

	DPRINT_INFO(INPUTVSC_DRV, "Hyper-V Mouse driver initializing.");

	/* Callback to client driver to complete the initialization */
	mouse_vsc_initialize(&input_drv_obj->base);

	drv->driver.name = input_drv_obj->base.name;
	drv->priv = input_drv_obj;

	drv->driver.probe = mousevsc_probe;
	drv->driver.remove = mousevsc_remove;

	/* The driver belongs to vmbus */
	vmbus_child_driver_register(&drv->driver);

	return 0;
}

static void __exit mousevsc_exit(void)
{
	mousevsc_drv_exit();
}

/*
 * We don't want to automatically load this driver just yet, it's quite
 * broken.  It's safe if you want to load it yourself manually, but
 * don't inflict it on unsuspecting users, that's just mean.
 */
#if 0

/*
 * We use a PCI table to determine if we should autoload this driver  This is
 * needed by distro tools to determine if the hyperv drivers should be
 * installed and/or configured.  We don't do anything else with the table, but
 * it needs to be present.
 */
const static struct pci_device_id microsoft_hv_pci_table[] = {
	{ PCI_DEVICE(0x1414, 0x5353) },	/* VGA compatible controller */
	{ 0 }
};
MODULE_DEVICE_TABLE(pci, microsoft_hv_pci_table);
#endif

MODULE_LICENSE("GPL");
MODULE_VERSION(HV_DRV_VERSION);
module_init(mousevsc_init);
module_exit(mousevsc_exit);

