/*
 * drivers/usb/driver.c - most of the driver model stuff for usb
 *
 * (C) Copyright 2005 Greg Kroah-Hartman <gregkh@suse.de>
 *
 * based on drivers/usb/usb.c which had the following copyrights:
 *	(C) Copyright Linus Torvalds 1999
 *	(C) Copyright Johannes Erdfelt 1999-2001
 *	(C) Copyright Andreas Gal 1999
 *	(C) Copyright Gregory P. Smith 1999
 *	(C) Copyright Deti Fliegl 1999 (new USB architecture)
 *	(C) Copyright Randy Dunlap 2000
 *	(C) Copyright David Brownell 2000-2004
 *	(C) Copyright Yggdrasil Computing, Inc. 2000
 *		(usb_device_id matching changes by Adam J. Richter)
 *	(C) Copyright Greg Kroah-Hartman 2002-2003
 *
 * NOTE! This is not actually a driver at all, rather this is
 * just a collection of helper routines that implement the
 * matching, probing, releasing, suspending and resuming for
 * real drivers.
 *
 */

#include <linux/device.h>
#include <linux/usb.h>
#include "hcd.h"
#include "usb.h"

static int usb_match_one_id(struct usb_interface *interface,
			    const struct usb_device_id *id);

struct usb_dynid {
	struct list_head node;
	struct usb_device_id id;
};

#ifdef CONFIG_HOTPLUG

/*
 * Adds a new dynamic USBdevice ID to this driver,
 * and cause the driver to probe for all devices again.
 */
static ssize_t store_new_id(struct device_driver *driver,
			    const char *buf, size_t count)
{
	struct usb_driver *usb_drv = to_usb_driver(driver);
	struct usb_dynid *dynid;
	u32 idVendor = 0;
	u32 idProduct = 0;
	int fields = 0;

	fields = sscanf(buf, "%x %x", &idVendor, &idProduct);
	if (fields < 2)
		return -EINVAL;

	dynid = kzalloc(sizeof(*dynid), GFP_KERNEL);
	if (!dynid)
		return -ENOMEM;

	INIT_LIST_HEAD(&dynid->node);
	dynid->id.idVendor = idVendor;
	dynid->id.idProduct = idProduct;
	dynid->id.match_flags = USB_DEVICE_ID_MATCH_DEVICE;

	spin_lock(&usb_drv->dynids.lock);
	list_add_tail(&usb_drv->dynids.list, &dynid->node);
	spin_unlock(&usb_drv->dynids.lock);

	if (get_driver(driver)) {
		driver_attach(driver);
		put_driver(driver);
	}

	return count;
}
static DRIVER_ATTR(new_id, S_IWUSR, NULL, store_new_id);

static int usb_create_newid_file(struct usb_driver *usb_drv)
{
	int error = 0;

	if (usb_drv->no_dynamic_id)
		goto exit;

	if (usb_drv->probe != NULL)
		error = sysfs_create_file(&usb_drv->driver.kobj,
					  &driver_attr_new_id.attr);
exit:
	return error;
}

static void usb_remove_newid_file(struct usb_driver *usb_drv)
{
	if (usb_drv->no_dynamic_id)
		return;

	if (usb_drv->probe != NULL)
		sysfs_remove_file(&usb_drv->driver.kobj,
				  &driver_attr_new_id.attr);
}

static void usb_free_dynids(struct usb_driver *usb_drv)
{
	struct usb_dynid *dynid, *n;

	spin_lock(&usb_drv->dynids.lock);
	list_for_each_entry_safe(dynid, n, &usb_drv->dynids.list, node) {
		list_del(&dynid->node);
		kfree(dynid);
	}
	spin_unlock(&usb_drv->dynids.lock);
}
#else
static inline int usb_create_newid_file(struct usb_driver *usb_drv)
{
	return 0;
}

static void usb_remove_newid_file(struct usb_driver *usb_drv)
{
}

static inline void usb_free_dynids(struct usb_driver *usb_drv)
{
}
#endif

static const struct usb_device_id *usb_match_dynamic_id(struct usb_interface *intf,
							struct usb_driver *drv)
{
	struct usb_dynid *dynid;

	spin_lock(&drv->dynids.lock);
	list_for_each_entry(dynid, &drv->dynids.list, node) {
		if (usb_match_one_id(intf, &dynid->id)) {
			spin_unlock(&drv->dynids.lock);
			return &dynid->id;
		}
	}
	spin_unlock(&drv->dynids.lock);
	return NULL;
}


/* called from driver core with usb_bus_type.subsys writelock */
static int usb_probe_interface(struct device *dev)
{
	struct usb_interface * intf = to_usb_interface(dev);
	struct usb_driver * driver = to_usb_driver(dev->driver);
	const struct usb_device_id *id;
	int error = -ENODEV;

	dev_dbg(dev, "%s\n", __FUNCTION__);

	if (!driver->probe)
		return error;
	/* FIXME we'd much prefer to just resume it ... */
	if (interface_to_usbdev(intf)->state == USB_STATE_SUSPENDED)
		return -EHOSTUNREACH;

	id = usb_match_id(intf, driver->id_table);
	if (!id)
		id = usb_match_dynamic_id(intf, driver);
	if (id) {
		dev_dbg(dev, "%s - got id\n", __FUNCTION__);

		/* Interface "power state" doesn't correspond to any hardware
		 * state whatsoever.  We use it to record when it's bound to
		 * a driver that may start I/0:  it's not frozen/quiesced.
		 */
		mark_active(intf);
		intf->condition = USB_INTERFACE_BINDING;
		error = driver->probe(intf, id);
		if (error) {
			mark_quiesced(intf);
			intf->condition = USB_INTERFACE_UNBOUND;
		} else
			intf->condition = USB_INTERFACE_BOUND;
	}

	return error;
}

/* called from driver core with usb_bus_type.subsys writelock */
static int usb_unbind_interface(struct device *dev)
{
	struct usb_interface *intf = to_usb_interface(dev);
	struct usb_driver *driver = to_usb_driver(intf->dev.driver);

	intf->condition = USB_INTERFACE_UNBINDING;

	/* release all urbs for this interface */
	usb_disable_interface(interface_to_usbdev(intf), intf);

	if (driver && driver->disconnect)
		driver->disconnect(intf);

	/* reset other interface state */
	usb_set_interface(interface_to_usbdev(intf),
			intf->altsetting[0].desc.bInterfaceNumber,
			0);
	usb_set_intfdata(intf, NULL);
	intf->condition = USB_INTERFACE_UNBOUND;
	mark_quiesced(intf);

	return 0;
}

/**
 * usb_driver_claim_interface - bind a driver to an interface
 * @driver: the driver to be bound
 * @iface: the interface to which it will be bound; must be in the
 *	usb device's active configuration
 * @priv: driver data associated with that interface
 *
 * This is used by usb device drivers that need to claim more than one
 * interface on a device when probing (audio and acm are current examples).
 * No device driver should directly modify internal usb_interface or
 * usb_device structure members.
 *
 * Few drivers should need to use this routine, since the most natural
 * way to bind to an interface is to return the private data from
 * the driver's probe() method.
 *
 * Callers must own the device lock and the driver model's usb_bus_type.subsys
 * writelock.  So driver probe() entries don't need extra locking,
 * but other call contexts may need to explicitly claim those locks.
 */
int usb_driver_claim_interface(struct usb_driver *driver,
				struct usb_interface *iface, void* priv)
{
	struct device *dev = &iface->dev;

	if (dev->driver)
		return -EBUSY;

	dev->driver = &driver->driver;
	usb_set_intfdata(iface, priv);
	iface->condition = USB_INTERFACE_BOUND;
	mark_active(iface);

	/* if interface was already added, bind now; else let
	 * the future device_add() bind it, bypassing probe()
	 */
	if (device_is_registered(dev))
		device_bind_driver(dev);

	return 0;
}
EXPORT_SYMBOL(usb_driver_claim_interface);

/**
 * usb_driver_release_interface - unbind a driver from an interface
 * @driver: the driver to be unbound
 * @iface: the interface from which it will be unbound
 *
 * This can be used by drivers to release an interface without waiting
 * for their disconnect() methods to be called.  In typical cases this
 * also causes the driver disconnect() method to be called.
 *
 * This call is synchronous, and may not be used in an interrupt context.
 * Callers must own the device lock and the driver model's usb_bus_type.subsys
 * writelock.  So driver disconnect() entries don't need extra locking,
 * but other call contexts may need to explicitly claim those locks.
 */
void usb_driver_release_interface(struct usb_driver *driver,
					struct usb_interface *iface)
{
	struct device *dev = &iface->dev;

	/* this should never happen, don't release something that's not ours */
	if (!dev->driver || dev->driver != &driver->driver)
		return;

	/* don't release from within disconnect() */
	if (iface->condition != USB_INTERFACE_BOUND)
		return;

	/* don't release if the interface hasn't been added yet */
	if (device_is_registered(dev)) {
		iface->condition = USB_INTERFACE_UNBINDING;
		device_release_driver(dev);
	}

	dev->driver = NULL;
	usb_set_intfdata(iface, NULL);
	iface->condition = USB_INTERFACE_UNBOUND;
	mark_quiesced(iface);
}
EXPORT_SYMBOL(usb_driver_release_interface);

/* returns 0 if no match, 1 if match */
static int usb_match_one_id(struct usb_interface *interface,
			    const struct usb_device_id *id)
{
	struct usb_host_interface *intf;
	struct usb_device *dev;

	/* proc_connectinfo in devio.c may call us with id == NULL. */
	if (id == NULL)
		return 0;

	intf = interface->cur_altsetting;
	dev = interface_to_usbdev(interface);

	if ((id->match_flags & USB_DEVICE_ID_MATCH_VENDOR) &&
	    id->idVendor != le16_to_cpu(dev->descriptor.idVendor))
		return 0;

	if ((id->match_flags & USB_DEVICE_ID_MATCH_PRODUCT) &&
	    id->idProduct != le16_to_cpu(dev->descriptor.idProduct))
		return 0;

	/* No need to test id->bcdDevice_lo != 0, since 0 is never
	   greater than any unsigned number. */
	if ((id->match_flags & USB_DEVICE_ID_MATCH_DEV_LO) &&
	    (id->bcdDevice_lo > le16_to_cpu(dev->descriptor.bcdDevice)))
		return 0;

	if ((id->match_flags & USB_DEVICE_ID_MATCH_DEV_HI) &&
	    (id->bcdDevice_hi < le16_to_cpu(dev->descriptor.bcdDevice)))
		return 0;

	if ((id->match_flags & USB_DEVICE_ID_MATCH_DEV_CLASS) &&
	    (id->bDeviceClass != dev->descriptor.bDeviceClass))
		return 0;

	if ((id->match_flags & USB_DEVICE_ID_MATCH_DEV_SUBCLASS) &&
	    (id->bDeviceSubClass!= dev->descriptor.bDeviceSubClass))
		return 0;

	if ((id->match_flags & USB_DEVICE_ID_MATCH_DEV_PROTOCOL) &&
	    (id->bDeviceProtocol != dev->descriptor.bDeviceProtocol))
		return 0;

	if ((id->match_flags & USB_DEVICE_ID_MATCH_INT_CLASS) &&
	    (id->bInterfaceClass != intf->desc.bInterfaceClass))
		return 0;

	if ((id->match_flags & USB_DEVICE_ID_MATCH_INT_SUBCLASS) &&
	    (id->bInterfaceSubClass != intf->desc.bInterfaceSubClass))
		return 0;

	if ((id->match_flags & USB_DEVICE_ID_MATCH_INT_PROTOCOL) &&
	    (id->bInterfaceProtocol != intf->desc.bInterfaceProtocol))
		return 0;

	return 1;
}
/**
 * usb_match_id - find first usb_device_id matching device or interface
 * @interface: the interface of interest
 * @id: array of usb_device_id structures, terminated by zero entry
 *
 * usb_match_id searches an array of usb_device_id's and returns
 * the first one matching the device or interface, or null.
 * This is used when binding (or rebinding) a driver to an interface.
 * Most USB device drivers will use this indirectly, through the usb core,
 * but some layered driver frameworks use it directly.
 * These device tables are exported with MODULE_DEVICE_TABLE, through
 * modutils, to support the driver loading functionality of USB hotplugging.
 *
 * What Matches:
 *
 * The "match_flags" element in a usb_device_id controls which
 * members are used.  If the corresponding bit is set, the
 * value in the device_id must match its corresponding member
 * in the device or interface descriptor, or else the device_id
 * does not match.
 *
 * "driver_info" is normally used only by device drivers,
 * but you can create a wildcard "matches anything" usb_device_id
 * as a driver's "modules.usbmap" entry if you provide an id with
 * only a nonzero "driver_info" field.  If you do this, the USB device
 * driver's probe() routine should use additional intelligence to
 * decide whether to bind to the specified interface.
 *
 * What Makes Good usb_device_id Tables:
 *
 * The match algorithm is very simple, so that intelligence in
 * driver selection must come from smart driver id records.
 * Unless you have good reasons to use another selection policy,
 * provide match elements only in related groups, and order match
 * specifiers from specific to general.  Use the macros provided
 * for that purpose if you can.
 *
 * The most specific match specifiers use device descriptor
 * data.  These are commonly used with product-specific matches;
 * the USB_DEVICE macro lets you provide vendor and product IDs,
 * and you can also match against ranges of product revisions.
 * These are widely used for devices with application or vendor
 * specific bDeviceClass values.
 *
 * Matches based on device class/subclass/protocol specifications
 * are slightly more general; use the USB_DEVICE_INFO macro, or
 * its siblings.  These are used with single-function devices
 * where bDeviceClass doesn't specify that each interface has
 * its own class.
 *
 * Matches based on interface class/subclass/protocol are the
 * most general; they let drivers bind to any interface on a
 * multiple-function device.  Use the USB_INTERFACE_INFO
 * macro, or its siblings, to match class-per-interface style
 * devices (as recorded in bDeviceClass).
 *
 * Within those groups, remember that not all combinations are
 * meaningful.  For example, don't give a product version range
 * without vendor and product IDs; or specify a protocol without
 * its associated class and subclass.
 */
const struct usb_device_id *usb_match_id(struct usb_interface *interface,
					 const struct usb_device_id *id)
{
	/* proc_connectinfo in devio.c may call us with id == NULL. */
	if (id == NULL)
		return NULL;

	/* It is important to check that id->driver_info is nonzero,
	   since an entry that is all zeroes except for a nonzero
	   id->driver_info is the way to create an entry that
	   indicates that the driver want to examine every
	   device and interface. */
	for (; id->idVendor || id->bDeviceClass || id->bInterfaceClass ||
	       id->driver_info; id++) {
		if (usb_match_one_id(interface, id))
			return id;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL_FUTURE(usb_match_id);

int usb_device_match(struct device *dev, struct device_driver *drv)
{
	struct usb_interface *intf;
	struct usb_driver *usb_drv;
	const struct usb_device_id *id;

	/* check for generic driver, which we don't match any device with */
	if (drv == &usb_generic_driver)
		return 0;

	intf = to_usb_interface(dev);
	usb_drv = to_usb_driver(drv);

	id = usb_match_id(intf, usb_drv->id_table);
	if (id)
		return 1;

	id = usb_match_dynamic_id(intf, usb_drv);
	if (id)
		return 1;
	return 0;
}

#ifdef	CONFIG_HOTPLUG

/*
 * This sends an uevent to userspace, typically helping to load driver
 * or other modules, configure the device, and more.  Drivers can provide
 * a MODULE_DEVICE_TABLE to help with module loading subtasks.
 *
 * We're called either from khubd (the typical case) or from root hub
 * (init, kapmd, modprobe, rmmod, etc), but the agents need to handle
 * delays in event delivery.  Use sysfs (and DEVPATH) to make sure the
 * device (and this configuration!) are still present.
 */
static int usb_uevent(struct device *dev, char **envp, int num_envp,
		      char *buffer, int buffer_size)
{
	struct usb_interface *intf;
	struct usb_device *usb_dev;
	struct usb_host_interface *alt;
	int i = 0;
	int length = 0;

	if (!dev)
		return -ENODEV;

	/* driver is often null here; dev_dbg() would oops */
	pr_debug ("usb %s: uevent\n", dev->bus_id);

	/* Must check driver_data here, as on remove driver is always NULL */
	if ((dev->driver == &usb_generic_driver) ||
	    (dev->driver_data == &usb_generic_driver_data))
		return 0;

	intf = to_usb_interface(dev);
	usb_dev = interface_to_usbdev (intf);
	alt = intf->cur_altsetting;

	if (usb_dev->devnum < 0) {
		pr_debug ("usb %s: already deleted?\n", dev->bus_id);
		return -ENODEV;
	}
	if (!usb_dev->bus) {
		pr_debug ("usb %s: bus removed?\n", dev->bus_id);
		return -ENODEV;
	}

#ifdef	CONFIG_USB_DEVICEFS
	/* If this is available, userspace programs can directly read
	 * all the device descriptors we don't tell them about.  Or
	 * even act as usermode drivers.
	 *
	 * FIXME reduce hardwired intelligence here
	 */
	if (add_uevent_var(envp, num_envp, &i,
			   buffer, buffer_size, &length,
			   "DEVICE=/proc/bus/usb/%03d/%03d",
			   usb_dev->bus->busnum, usb_dev->devnum))
		return -ENOMEM;
#endif

	/* per-device configurations are common */
	if (add_uevent_var(envp, num_envp, &i,
			   buffer, buffer_size, &length,
			   "PRODUCT=%x/%x/%x",
			   le16_to_cpu(usb_dev->descriptor.idVendor),
			   le16_to_cpu(usb_dev->descriptor.idProduct),
			   le16_to_cpu(usb_dev->descriptor.bcdDevice)))
		return -ENOMEM;

	/* class-based driver binding models */
	if (add_uevent_var(envp, num_envp, &i,
			   buffer, buffer_size, &length,
			   "TYPE=%d/%d/%d",
			   usb_dev->descriptor.bDeviceClass,
			   usb_dev->descriptor.bDeviceSubClass,
			   usb_dev->descriptor.bDeviceProtocol))
		return -ENOMEM;

	if (add_uevent_var(envp, num_envp, &i,
			   buffer, buffer_size, &length,
			   "INTERFACE=%d/%d/%d",
			   alt->desc.bInterfaceClass,
			   alt->desc.bInterfaceSubClass,
			   alt->desc.bInterfaceProtocol))
		return -ENOMEM;

	if (add_uevent_var(envp, num_envp, &i,
			   buffer, buffer_size, &length,
			   "MODALIAS=usb:v%04Xp%04Xd%04Xdc%02Xdsc%02Xdp%02Xic%02Xisc%02Xip%02X",
			   le16_to_cpu(usb_dev->descriptor.idVendor),
			   le16_to_cpu(usb_dev->descriptor.idProduct),
			   le16_to_cpu(usb_dev->descriptor.bcdDevice),
			   usb_dev->descriptor.bDeviceClass,
			   usb_dev->descriptor.bDeviceSubClass,
			   usb_dev->descriptor.bDeviceProtocol,
			   alt->desc.bInterfaceClass,
			   alt->desc.bInterfaceSubClass,
			   alt->desc.bInterfaceProtocol))
		return -ENOMEM;

	envp[i] = NULL;

	return 0;
}

#else

static int usb_uevent(struct device *dev, char **envp,
			int num_envp, char *buffer, int buffer_size)
{
	return -ENODEV;
}

#endif	/* CONFIG_HOTPLUG */

/**
 * usb_register_driver - register a USB driver
 * @new_driver: USB operations for the driver
 * @owner: module owner of this driver.
 *
 * Registers a USB driver with the USB core.  The list of unattached
 * interfaces will be rescanned whenever a new driver is added, allowing
 * the new driver to attach to any recognized devices.
 * Returns a negative error code on failure and 0 on success.
 *
 * NOTE: if you want your driver to use the USB major number, you must call
 * usb_register_dev() to enable that functionality.  This function no longer
 * takes care of that.
 */
int usb_register_driver(struct usb_driver *new_driver, struct module *owner)
{
	int retval = 0;

	if (usb_disabled())
		return -ENODEV;

	new_driver->driver.name = (char *)new_driver->name;
	new_driver->driver.bus = &usb_bus_type;
	new_driver->driver.probe = usb_probe_interface;
	new_driver->driver.remove = usb_unbind_interface;
	new_driver->driver.owner = owner;
	spin_lock_init(&new_driver->dynids.lock);
	INIT_LIST_HEAD(&new_driver->dynids.list);

	retval = driver_register(&new_driver->driver);

	if (!retval) {
		pr_info("%s: registered new driver %s\n",
			usbcore_name, new_driver->name);
		usbfs_update_special();
		usb_create_newid_file(new_driver);
	} else {
		printk(KERN_ERR "%s: error %d registering driver %s\n",
			usbcore_name, retval, new_driver->name);
	}

	return retval;
}
EXPORT_SYMBOL_GPL_FUTURE(usb_register_driver);

/**
 * usb_deregister - unregister a USB driver
 * @driver: USB operations of the driver to unregister
 * Context: must be able to sleep
 *
 * Unlinks the specified driver from the internal USB driver list.
 *
 * NOTE: If you called usb_register_dev(), you still need to call
 * usb_deregister_dev() to clean up your driver's allocated minor numbers,
 * this * call will no longer do it for you.
 */
void usb_deregister(struct usb_driver *driver)
{
	pr_info("%s: deregistering driver %s\n", usbcore_name, driver->name);

	usb_remove_newid_file(driver);
	usb_free_dynids(driver);
	driver_unregister(&driver->driver);

	usbfs_update_special();
}
EXPORT_SYMBOL_GPL_FUTURE(usb_deregister);

#ifdef CONFIG_PM

static int verify_suspended(struct device *dev, void *unused)
{
	if (dev->driver == NULL)
		return 0;
	return (dev->power.power_state.event == PM_EVENT_ON) ? -EBUSY : 0;
}

static int usb_generic_suspend(struct device *dev, pm_message_t message)
{
	struct usb_interface	*intf;
	struct usb_driver	*driver;
	int			status;

	/* USB devices enter SUSPEND state through their hubs, but can be
	 * marked for FREEZE as soon as their children are already idled.
	 * But those semantics are useless, so we equate the two (sigh).
	 */
	if (dev->driver == &usb_generic_driver) {
		if (dev->power.power_state.event == message.event)
			return 0;
		/* we need to rule out bogus requests through sysfs */
		status = device_for_each_child(dev, NULL, verify_suspended);
		if (status)
			return status;
 		return usb_port_suspend(to_usb_device(dev));
	}

	if ((dev->driver == NULL) ||
	    (dev->driver_data == &usb_generic_driver_data))
		return 0;

	intf = to_usb_interface(dev);
	driver = to_usb_driver(dev->driver);

	/* with no hardware, USB interfaces only use FREEZE and ON states */
	if (!is_active(intf))
		return 0;

	if (driver->suspend && driver->resume) {
		status = driver->suspend(intf, message);
		if (status)
			dev_err(dev, "%s error %d\n", "suspend", status);
		else
			mark_quiesced(intf);
	} else {
		// FIXME else if there's no suspend method, disconnect...
		dev_warn(dev, "no suspend for driver %s?\n", driver->name);
		mark_quiesced(intf);
		status = 0;
	}
	return status;
}

static int usb_generic_resume(struct device *dev)
{
	struct usb_interface	*intf;
	struct usb_driver	*driver;
	struct usb_device	*udev;
	int			status;

	if (dev->power.power_state.event == PM_EVENT_ON)
		return 0;

	/* mark things as "on" immediately, no matter what errors crop up */
	dev->power.power_state.event = PM_EVENT_ON;

	/* devices resume through their hubs */
	if (dev->driver == &usb_generic_driver) {
		udev = to_usb_device(dev);
		if (udev->state == USB_STATE_NOTATTACHED)
			return 0;
		return usb_port_resume(udev);
	}

	if ((dev->driver == NULL) ||
	    (dev->driver_data == &usb_generic_driver_data)) {
		dev->power.power_state.event = PM_EVENT_FREEZE;
		return 0;
	}

	intf = to_usb_interface(dev);
	driver = to_usb_driver(dev->driver);

	udev = interface_to_usbdev(intf);
	if (udev->state == USB_STATE_NOTATTACHED)
		return 0;

	/* if driver was suspended, it has a resume method;
	 * however, sysfs can wrongly mark things as suspended
	 * (on the "no suspend method" FIXME path above)
	 */
	if (driver->resume) {
		status = driver->resume(intf);
		if (status) {
			dev_err(dev, "%s error %d\n", "resume", status);
			mark_quiesced(intf);
		}
	} else
		dev_warn(dev, "no resume for driver %s?\n", driver->name);
	return 0;
}

#endif /* CONFIG_PM */

struct bus_type usb_bus_type = {
	.name =		"usb",
	.match =	usb_device_match,
	.uevent =	usb_uevent,
#ifdef CONFIG_PM
	.suspend =	usb_generic_suspend,
	.resume =	usb_generic_resume,
#endif
};
