#ifndef __KSU_H_LSM_HOOK
#define __KSU_H_LSM_HOOK

#include <linux/types.h>
#include <linux/cred.h>
#include <linux/uidgid.h>

// 公共函数声明
void __init ksu_lsm_hook_init(void);

void disable_seccomp(void);

// KSU 内部工具函数
bool is_uid_manager(uid_t uid);
bool ksu_is_allow_uid_for_current(uid_t uid);
void ksu_install_fd(void);
void ksu_handle_umount(uid_t old_uid, uid_t new_uid);
bool ksu_is_manager_appid_valid(void);
bool is_appuid(uid_t uid);
bool ksu_uid_should_umount(uid_t uid);
bool is_isolated_process(uid_t uid);

// SUSFS 相关声明与宏
#ifdef CONFIG_KSU_SUSFS
#include <linux/security.h>
#define WEBVIEW_ZYGOTE_UID 1032

bool susfs_is_sid_equal(const struct cred *cred, u32 sid);
void susfs_do_umount(void);
void susfs_set_current_proc_umounted(void);
#endif

#endif
