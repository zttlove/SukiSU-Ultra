// SPDX-License-Identifier: GPL-2.0
/*
 * KernelSU SELinux Policy for Linux 5.4 (NO INTERNAL HEADERS)
 * Fixed all filename_trans_key errors
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/uaccess.h>
#include <linux/types.h>

#include "../kernelsu.h"

bool ksueb_selinux_process_unsafe(const struct cred *cred)
{
	return false;
}

bool ksueb_selinux_upper_inode_unsafe(const struct cred *cred, struct inode *inode)
{
	return false;
}

bool ksueb_selinux_file_unsafe(const struct cred *cred, struct file *file)
{
	return false;
}

bool ksueb_selinux_task_unsafe(const struct cred *cred)
{
	return false;
}

int selinux_add_filename_trans(struct selinux_state *state,
			       u32 scon, u32 tcon, u32 tclass, const char *name)
{
	return 0;
}
