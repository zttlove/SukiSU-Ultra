#ifndef __KSU_H_LSM_HOOK
#define __KSU_H_LSM_HOOK

#include <linux/types.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <stdbool.h>

// 底层函数前置声明（对应宏 ksu_is_allow_uid_for_current）
bool __ksu_is_allow_uid_for_current(uid_t uid);

// 公共入口
void __init ksu_lsm_hook_init(void);

// 单独声明，无冲突
void disable_seccomp(void);

// 已修正：与 manager_identity.h 里 bool 类型对齐
bool is_uid_manager(uid_t uid);

// 工具函数：返回值保持 int
int ksu_install_fd(void);
int ksu_handle_umount(uid_t old_uid, uid_t new_uid);

// 非宏函数声明
bool ksu_is_manager_appid_valid(void);
bool is_appuid(uid_t uid);
bool ksu_uid_should_umount(uid_t uid);
bool is_isolated_process(uid_t uid);

// SUSFS 部分
#ifdef CONFIG_KSU_SUSFS
#include <linux/security.h>
#define WEBVIEW_ZYGOTE_UID 1032

bool susfs_is_sid_equal(const struct cred *cred, u32 sid);
void susfs_do_umount(void);
void susfs_set_current_proc_umounted(void);
#endif

#endif
