#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <../fs/mount.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arnaud Astruc <aastruc@student.42.fr>");
MODULE_DESCRIPTION("List mount point module");

#define PROC_NAME "mymounts"

char buf[PATH_MAX];
char path[PATH_MAX];

void prepend(char* s, const char* t)
{
	size_t len = strlen(t);
	size_t i;

	memmove(s + len, s, strlen(s) + 1);

	for (i = 0; i < len; ++i)
	{
		s[i] = t[i];
	}
}

static ssize_t p_read(struct file *file, char __user *user, size_t nbytes, loff_t *ppos)
{
	struct mount *mnt = NULL;
	struct mount *tmp_mnt = NULL;
	struct mnt_namespace *ns = current->nsproxy->mnt_ns;
	size_t ret = 0;
	size_t total = 0;
	size_t nb_page = 1;
	char *output = NULL;

	output = kmalloc(PAGE_SIZE, GFP_KERNEL);
	list_for_each_entry(mnt, &ns->list, mnt_list) {	
		if (mnt->mnt_mountpoint->d_flags & DCACHE_MOUNTED) {
			memset(path, 0, PATH_MAX);
			if (strcmp(dentry_path_raw(mnt->mnt_parent->mnt_mountpoint, buf, PATH_MAX), "/") != 0) {
				tmp_mnt = mnt;
				while (strcmp(dentry_path_raw(tmp_mnt->mnt_mountpoint, buf, PATH_MAX), "/") != 0) {
					prepend(path, dentry_path_raw(tmp_mnt->mnt_mountpoint, buf, PATH_MAX));
					tmp_mnt = tmp_mnt->mnt_parent;
				}
			}
			else {
				strcpy(path, dentry_path_raw(mnt->mnt_mountpoint, buf, PATH_MAX));
			}
			total = total + strlen(mnt->mnt_devname) + 1 + strlen(path) + 1;
			if (total > PAGE_SIZE) {
				total = 0;
				nb_page++;
				output = krealloc(output, nb_page * PAGE_SIZE, GFP_KERNEL);
			}
			strcat(output, mnt->mnt_devname);
			strcat(output, " ");
			strcat(output, path);
			strcat(output, "\n");
		}
	}
	ret = simple_read_from_buffer(user, nbytes, ppos, output, strlen(output));
	return ret;
}

struct file_operations p_fops = {
	.owner = THIS_MODULE,
	.read = p_read,
};

static int __init list_mount_point_init(void)
{
	proc_create(PROC_NAME, 0777, NULL, &p_fops);
	return 0;
}

static void __exit list_mount_point_cleanup(void)
{
	remove_proc_entry(PROC_NAME, NULL);
}

module_init(list_mount_point_init);
module_exit(list_mount_point_cleanup);
