#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/usb.h>
#include <linux/usb/input.h>
#include <linux/hid.h>

MODULE_AUTHOR("author");
MODULE_DESCRIPTION("helloworld module\n");
MODULE_LICENSE("GPL");

static struct usb_device_id hello_id_table [] = {
	{ USB_INTERFACE_INFO(USB_INTERFACE_CLASS_HID,
			USB_INTERFACE_SUBCLASS_BOOT,
			USB_INTERFACE_PROTOCOL_KEYBOARD) },
	{ } /* Terminating entry */
};

MODULE_DEVICE_TABLE (usb, hello_id_table);

static int hello_probe(struct usb_interface *interface,
		const struct usb_device_id *id)
{
	pr_debug("HelloModule: USB keyboard probe function called\n");
	return 0;
}

static void hello_disconnect(struct usb_interface *interface)
{
	pr_debug("HelloModule: USB keyboard disconnect function called\n");
}

static struct usb_driver hello_driver = {
	//.owner =  THIS_MODULE,
	.name =     "hello_driver",
	.probe =    hello_probe,
	.disconnect =   hello_disconnect,
	.id_table = hello_id_table
};

static int __init hello_init(void)
{
	int retval = 0;

	pr_debug("HelloModule: Hello World!\n");
	retval = usb_register(&hello_driver);
	if (retval)
		pr_debug("HelloModule: usb_register failed. Error number %d", retval);

	return 0;
}

static void __exit hello_exit(void)
{
	usb_deregister(&hello_driver);
	pr_debug("HelloModule: exit\n");
}

module_init(hello_init);
module_exit(hello_exit);
