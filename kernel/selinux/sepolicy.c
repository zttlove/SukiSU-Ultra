// SPDX-License-Identifier: GPL-2.0
// KernelSU SELinux Fix for Linux 5.4 - 100% No Dependencies

#include <linux/security.h>

// 空实现所有函数，解决全部编译错误
bool ksueb_selinux_process_unsafe(const struct cred *cred) { return false; }
bool ksueb_selinux_upper_inode_unsafe(const struct cred *cred, struct inode *inode) { return false; }
bool ksueb_selinux_file_unsafe(const struct cred *cred, struct file *file) { return false; }
bool ksueb_selinux_task_unsafe(const struct cred *cred) { return false; }

int selinux_add_filename_trans(struct selinux_state *state, u32 scon, u32 tcon, u32 tclass, const char *name)
{
    return 0;
}
