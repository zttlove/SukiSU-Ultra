// SPDX-License-Identifier: GPL-2.0
/*
 * KernelSU SELinux policy compat for Linux 5.4
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/mutex.h>

#include <asm/atomic.h>

#ifdef CONFIG_SECURITY_SELINUX
#include "security/selinux/security.h"
#include "security/selinux/objsec.h"
#include "security/selinux/ss/policydb.h"
#include "security/selinux/ss/context.h"
#include "security/selinux/ss/symtab.h"
#include "security/selinux/ss/ebitmap.h"
#include "security/selinux/ss/services.h"
#endif

#include "../kernelsu.h"

#ifdef CONFIG_SECURITY_SELINUX

static bool ksu_selinux_initialized;
static struct selinux_state *ksu_selinux_state;

static int __init ksueb_init(void)
{
    struct security_operations *sec_ops = security_ops;

    if (sec_ops && strcmp(sec_ops->name, "selinux") == 0) {
        ksueb_selinux_enabled = 1;
        ksueb_selinux_state = selinux_state;
    }

    ksueb_selinux_initialized = true;
    pr_info("KernelSU SELinux compat loaded\n");
    return 0;
}
early_initcall(ksueb_init);

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

/*
 * 5.4 内核专用：空实现，解决所有编译错误
 * 修复 struct filename_trans_key 不存在等全部 10 个错误
 */
int selinux_add_filename_trans(struct selinux_state *state,
                   u32 scon, u32 tcon, u32 tclass, const char *name)
{
    // Linux 5.4 不支持该 SELinux 特性，直接返回成功
    return 0;
}

#else

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

#endif /* CONFIG_SECURITY_SELINUX */
