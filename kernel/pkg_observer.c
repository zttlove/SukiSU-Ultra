// SPDX-License-Identifier: GPL-2.0
/*
 * KernelSU package observer
 */

#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/sched.h>
#include <linux/types.h>

// 屏蔽所有 throne_tracker 相关（解决头文件错误）
// #include "manager/throne_tracker.h"

// 兼容旧内核 fsnotify 结构体
static const struct fsnotify_ops ksu_fsnotify_ops = {
	.handle_event = NULL,
};

// 屏蔽不兼容的回调函数
#if 0
static int ksu_handle_inode_event(struct fsnotify_mark *mark, u32 mask,
				       struct inode *inode, struct inode *dir,
				       const struct qstr *dname, u32 cookie)
{
	return 0;
}
#endif

static struct fsnotify_group *ksu_pkg_group;

int ksu_pkg_observer_init(void)
{
	struct fsnotify_group *g;

	g = fsnotify_alloc_group(&ksu_fsnotify_ops);
	if (IS_ERR(g))
		return PTR_ERR(g);

	ksu_pkg_group = g;
	return 0;
}

void ksu_pkg_observer_exit(void)
{
	if (ksu_pkg_group)
		fsnotify_destroy_group(ksu_pkg_group);
}
