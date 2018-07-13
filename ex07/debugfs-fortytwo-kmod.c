#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/debugfs.h>
#include <linux/mutex.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arnaud Astruc <aastruc@student.42.fr>");
MODULE_DESCRIPTION("debugfs module");

#define ROOT_DEBUGFS "fortytwo"
#define ID_FILE "id"
#define JIFFIES_FILE "jiffies"
#define FOO_FILE "foo"

#define LOGIN "aastruc\n"

static struct dentry *root;

static DEFINE_MUTEX(foo_lock);
static char foo_buf[PAGE_SIZE];

static char login[] = LOGIN;
static int login_length = sizeof(LOGIN);

static ssize_t id_read(struct file *file, char __user *buf,
		size_t nbytes, loff_t *ppos)
{
	return simple_read_from_buffer(buf, nbytes, ppos, login,
			login_length);
}

static ssize_t id_write(struct file *file, const char __user *buf,
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

static const struct file_operations id_fops = {
	.owner = THIS_MODULE,
	.read = id_read,
	.write = id_write,
};

static ssize_t jif_read(struct file *file, char __user *buf,
		size_t nbytes, loff_t *ppos)
{
	char jif_buf[20];

	memset(jif_buf, 0, 20);
	snprintf(jif_buf, 20, "%llu\n", get_jiffies_64());
	return simple_read_from_buffer(buf, nbytes, ppos, jif_buf,
			strlen(jif_buf));
}

static const struct file_operations jif_fops = {
	.owner = THIS_MODULE,
	.read = jif_read,
};

static ssize_t foo_read(struct file *file, char __user *buf,
		size_t nbytes, loff_t *ppos)
{
	int ret;

	mutex_lock(&foo_lock);
	ret = simple_read_from_buffer(buf, nbytes, ppos, foo_buf,
			strlen(foo_buf));
	mutex_unlock(&foo_lock);
	return ret;
}

static ssize_t foo_write(struct file *file, const char __user *buf,
		size_t nbytes, loff_t *ppos)
{
	int ret;
	int len;
	char *tmp = foo_buf;
	char *foo = foo_buf;

	if (file->f_flags & O_APPEND) {
		while (*foo != 0)
			foo++;
		len = foo - tmp;
		mutex_lock(&foo_lock);
		*ppos = + len;
		ret = simple_write_to_buffer(foo_buf, PAGE_SIZE, ppos, buf,
				nbytes);
		mutex_unlock(&foo_lock);
	} else {
		memset(foo_buf, 0, PAGE_SIZE);
		mutex_lock(&foo_lock);
		*ppos = 0;
		ret = simple_write_to_buffer(foo_buf, PAGE_SIZE, ppos, buf,
				nbytes);
		mutex_unlock(&foo_lock);
	}
	return ret;
}

static const struct file_operations foo_fops = {
	.owner = THIS_MODULE,
	.read = foo_read,
	.write = foo_write,
};

static int __init fortytwo_init(void)
{
	memset(foo_buf, 0, PAGE_SIZE);
	root = debugfs_create_dir(ROOT_DEBUGFS, NULL);
	if (!root)
		return -ENOMEM;
	debugfs_create_file(ID_FILE, 0666, root, NULL, &id_fops);
	debugfs_create_file(JIFFIES_FILE, 0444, root, NULL, &jif_fops);
	debugfs_create_file(FOO_FILE, 0644, root, NULL, &foo_fops);
	return 0;
}

static void __exit fortytwo_cleanup(void)
{
	debugfs_remove_recursive(root);
}

module_init(fortytwo_init);
module_exit(fortytwo_cleanup);
