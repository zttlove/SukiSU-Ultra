#include <linux/version.h>
#include <linux/types.h>
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/compiler.h>
#include <linux/uidgid.h>
#include <linux/seccomp.h>
#include <linux/sched.h>
#include <linux/lsm_hooks.h>
#include <linux/key.h>
#include <linux/workqueue.h>
#include <linux/string.h>
#include "manager/manager_identity.h"

// 关键：先包含 allowlist.h，再包含 lsm_hook.h
#include "../policy/allowlist.h"

// 兜底定义宏，防止展开失败
#ifndef ksu_is_allow_uid_for_current
#define ksu_is_allow_uid_for_current(uid) unlikely(__ksu_is_allow_uid_for_current(uid))
#endif

#include "lsm_hook.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_IS_HW_HISI) || \
    defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
static struct keyring *init_session_keyring = NULL;

static int ksu_key_permission(key_ref_t key_ref, const struct cred *cred, unsigned perm)
{
    if (init_session_keyring != NULL) {
        return 0;
    }

    if (strcmp(current->comm, "init")) {
        // we are only interested in `init` process
        return 0;
    }
    init_session_keyring = cred->session_keyring;
    pr_info("kernel_compat: got init_session_keyring\n");
    return 0;
}
#endif

#ifdef CONFIG_KSU_SUSFS
extern u32 susfs_zygote_sid;
extern void disable_seccomp(void);
extern struct work_struct susfs_extra_works;

static void ksu_handle_extra_susfs_work(void)
{
    schedule_work(&susfs_extra_works);
}

int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    // We only interest in process spwaned by zygote
    if (!susfs_is_sid_equal(current_cred(), susfs_zygote_sid))
        return 0;

    // Check if spawned process is isolated service first, and force to do umount if so
    if (is_isolated_process(ruid))
        goto do_umount;

    // - Since ksu maanger app uid is excluded in allow_list_arr, so ksu_uid_should_umount(manager_uid)
    //   will always return true, that's why we need to explicitly check if new_uid belongs to
    //   ksu manager.
    // - Disable seccomp restriction for KSU manager since running with "su" will disable seccomp anyway
    if (likely(ksu_is_manager_appid_valid()) && unlikely(is_uid_manager(ruid))) {
        disable_seccomp();
        pr_info("install fd for manager: %d\n", ruid);
        ksu_install_fd();
        return 0;
    }

    // we should not umount for webview zygote
    if (unlikely(ruid == WEBVIEW_ZYGOTE_UID))
        return 0;

    // Check if spawned process is normal user app and needs to be umounted
    if (likely(is_appuid(ruid) && ksu_uid_should_umount(ruid)))
        goto do_umount;

    // - Disable seccomp restriction for root allowed apps since running with "su" will disable seccomp anyway
    if (ksu_is_allow_uid_for_current(ruid))
        disable_seccomp();

    return 0;

do_umount:
    // Handle kernel umount
    ksu_handle_umount(current_uid().val, ruid);
    // Handle extra susfs work
    ksu_handle_extra_susfs_work();
    // Mark current proc as umounted
    susfs_set_current_proc_umounted();
    susfs_do_umount();
    return 0;
}

/* 符号导出，解决 undefined symbol */
EXPORT_SYMBOL_GPL(ksu_handle_setresuid);

#else
static int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
    uid_t new_uid, old_uid = 0;

    if (unlikely(!new || !old))
        return 0;

    new_uid = new->uid.val;
    old_uid = old->uid.val;

    if (unlikely(is_uid_manager(new_uid))) {
        disable_seccomp();
        pr_info("install fd for manager: %d\n", new_uid);
        ksu_install_fd();
        return 0;
    }

    if (ksu_is_allow_uid_for_current(new_uid)) {
        disable_seccomp();
    }

    // Handle kernel umount
    ksu_handle_umount(old_uid, new_uid);

    return 0;
}
#endif

static struct security_hook_list ksu_hooks[] = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_IS_HW_HISI) || \
    defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
    LSM_HOOK_INIT(key_permission, ksu_key_permission),
#endif
#ifndef CONFIG_KSU_SUSFS
    LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
#endif
};

void __init ksu_lsm_hook_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
#else
    // https://elixir.bootlin.com/linux/v4.10.17/source/include/linux/lsm_hooks.h#L1892
    security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
#endif
    pr_info("LSM hooks initialized.\n");
}
