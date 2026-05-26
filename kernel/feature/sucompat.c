#include <linux/compiler_types.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/sched/task_stack.h>
#include <linux/static_key.h>
#include <linux/string.h>
#include <linux/susfs_def.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <asm/current.h>

#include "feature/adb_root.h"
#include "feature/sucompat.h"
#include "klog.h" // IWYU pragma: keep
#include "policy/allowlist.h"
#include "policy/app_profile.h"
#include "policy/feature.h"
#include "runtime/ksud.h"
#include "selinux/selinux.h"
#include "tiny_sulog.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

static const char sh_path[] = SH_PATH;
static const char su_path[] = SU_PATH;
static const char ksud_path[] = KSUD_PATH;

DEFINE_STATIC_KEY_TRUE(ksu_su_compat_enabled);

static int su_compat_feature_get(u64 *value)
{
	*value = static_key_enabled(&ksu_su_compat_enabled) ? 1 : 0;
	return 0;
}

static int su_compat_feature_set(u64 value)
{
	bool enable = value != 0;

	if (enable)
		static_branch_enable(&ksu_su_compat_enabled);
	else
		static_branch_disable(&ksu_su_compat_enabled);

	pr_info("su_compat: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler su_compat_handler = {
	.feature_id = KSU_FEATURE_SU_COMPAT,
	.name = "su_compat",
	.get_handler = su_compat_feature_get,
	.set_handler = su_compat_feature_set,
};

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *sh_user_path(void)
{
	return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
	const char __user *native;

#ifdef CONFIG_COMPAT
	if (unlikely(argv.is_compat)) {
		compat_uptr_t compat;

		if (get_user(compat, argv.ptr.compat + nr))
			return ERR_PTR(-EFAULT);

		return compat_ptr(compat);
	}
#endif

	if (get_user(native, argv.ptr.native + nr))
		return ERR_PTR(-EFAULT);

	return native;
}

/*
 * Return 0 when no further sucompat checks are needed, non-zero to continue.
 */
int ksu_handle_execveat_init(struct filename *filename,
				     struct user_arg_ptr *argv_user,
				     struct user_arg_ptr *envp_user)
{
	int ret;

	if (!filename || IS_ERR(filename))
		return 0;

	if (current->pid == 1 || !is_init(current_cred()))
		return -EINVAL;

	if (unlikely(strcmp(filename->name, KSUD_PATH) == 0)) {
		const char __user *argv0 = argv_user ? get_user_arg_ptr(*argv_user, 0) : NULL;

		pr_info("hook_manager: escape to root for init executing ksud: %d\n",
			current->pid);
		ret = escape_to_root_for_init();
		if (ret) {
			pr_err("escape_to_root_for_init() failed: %d\n", ret);
			return ret;
		}

		if (!argv0 || IS_ERR(argv0))
			return -EFAULT;

		write_sulog('x');
		return 0;
	}

	if (likely(!strstr(filename->name, "/app_process") &&
		   !strstr(filename->name, "/adbd")) &&
	    !susfs_is_current_proc_umounted()) {
		pr_info("susfs: mark no sucompat checks for pid: '%d', exec: '%s'\n",
			current->pid, filename->name);
		susfs_set_current_proc_umounted();
		return 0;
	}

	if (!envp_user)
		return -EINVAL;

#ifdef CONFIG_COMPAT
	if (unlikely(envp_user->is_compat))
		ret = ksu_adb_root_handle_execve(filename->name,
						 (void __user ***)&envp_user->ptr.compat);
	else
		ret = ksu_adb_root_handle_execve(filename->name,
						 (void __user ***)&envp_user->ptr.native);
#else
	ret = ksu_adb_root_handle_execve(filename->name,
					 (void __user ***)&envp_user->ptr.native);
#endif
	if (ret)
		pr_err("adb root failed: %d\n", ret);

	return ret;
}

int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *argv_user, void *envp_user,
				 int *__never_use_flags)
{
	struct filename *filename;
	int ret;

	if (unlikely(!filename_ptr))
		return 0;

	filename = *filename_ptr;
	if (IS_ERR(filename) || !filename)
		return 0;

	ret = ksu_handle_execveat_init(filename, (struct user_arg_ptr *)argv_user,
					 (struct user_arg_ptr *)envp_user);
	if (!ret)
		return 0;

	if (!ksu_is_allow_uid_for_current(current_uid().val))
		return 0;

	if (likely(memcmp(filename->name, su_path, sizeof(su_path))))
		return 0;

	pr_info("ksu_handle_execveat_sucompat: su found\n");
	write_sulog('x');
	memcpy((void *)filename->name, ksud_path, sizeof(ksud_path));

	ret = escape_with_root_profile();
	if (ret)
		pr_err("escape_with_root_profile() failed: %d\n", ret);

	return 0;
}

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
			void *envp, int *flags)
{
	ksu_handle_execveat_ksud(fd, filename_ptr, argv, envp, flags);
	return ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp, flags);
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
			 int *mode, int *__unused_flags)
{
	char path[sizeof(su_path) + 1] = { 0 };

	if (unlikely(!filename_user))
		return 0;

	strncpy_from_user(path, *filename_user, sizeof(path));
	if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
		write_sulog('a');
		pr_info("ksu_handle_faccessat: su->sh!\n");
		*filename_user = sh_user_path();
	}

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0) && defined(CONFIG_KSU_SUSFS)
int ksu_handle_stat(int *dfd, struct filename **filename, int *flags)
{
	if (unlikely(!filename || IS_ERR(*filename) || !(*filename)->name))
		return 0;

	if (likely(memcmp((*filename)->name, su_path, sizeof(su_path))))
		return 0;

	write_sulog('s');
	pr_info("ksu_handle_stat: su->sh!\n");
	memcpy((void *)(*filename)->name, sh_path, sizeof(sh_path));
	return 0;
}
#else
int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	char path[sizeof(su_path) + 1] = { 0 };

	if (unlikely(!filename_user))
		return 0;

	strncpy_from_user(path, *filename_user, sizeof(path));
	if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
		write_sulog('s');
		pr_info("ksu_handle_stat: su->sh!\n");
		*filename_user = sh_user_path();
	}

	return 0;
}
#endif

void __init ksu_sucompat_init(void)
{
	if (ksu_register_feature_handler(&su_compat_handler))
		pr_err("Failed to register su_compat feature handler\n");
}

void __exit ksu_sucompat_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
