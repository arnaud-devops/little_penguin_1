#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arnaud Astruc <aastruc@student.42.fr>");
MODULE_DESCRIPTION("fortytwo misc device driver");

#define LOGIN "aastruc\n"

static char login[] = LOGIN;
static int login_length = sizeof LOGIN;

static ssize_t ft_read(struct file *file, char __user *buf,
		size_t nbytes, loff_t *ppos)
{
	return simple_read_from_buffer(buf, nbytes, ppos, login,
			login_length);
}

static ssize_t ft_write(struct file *file, const char __user *buf,
		size_t nbytes, loff_t *ppos)
{
	char str[login_length];
	ssize_t retval;

	memset(str, 0, login_length);
	if (login_length - 1 != nbytes)
		return -EINVAL;
	retval = simple_write_to_buffer(str, nbytes, ppos, buf, nbytes);
	if (strcmp(login, str) == 0)
		return retval;
	else
		return -EINVAL;
}

const struct file_operations ft_fops = {
	.owner = THIS_MODULE,
	.read = ft_read,
	.write = ft_write,
};

static struct miscdevice fortytwo = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "fortytwo",
	.fops = &ft_fops,
};

static int __init fortytwo_init(void)
{
	int error;

	error = misc_register(&fortytwo);
	if (error)
	{
		pr_err("can't misc_register\n");
		return error;
	}
	pr_info("misc_register done\n");
	return 0;
}

static void __exit fortytwo_cleanup(void)
{
	misc_deregister(&fortytwo);
	pr_info("misc_deregister done\n");
}

module_init(fortytwo_init);
module_exit(fortytwo_cleanup);
