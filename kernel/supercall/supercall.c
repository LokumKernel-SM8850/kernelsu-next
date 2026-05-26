#include <linux/anon_inodes.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/utsname.h> // utsname() and uts_sem

#include "uapi/supercall.h"
#include "supercall/internal.h"
#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"

#include "tiny_sulog.h"

uint32_t ksuver_override = 0;

struct ksu_install_fd_tw {
    struct callback_head cb;
    int __user *outp;
};

static int anon_ksu_release(struct inode *inode, struct file *filp)
{
    pr_info("ksu fd released\n");
    return 0;
}

static long anon_ksu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    return ksu_supercall_handle_ioctl(cmd, (void __user *)arg);
}

static const struct file_operations anon_ksu_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = anon_ksu_ioctl,
    .compat_ioctl = anon_ksu_ioctl,
    .release = anon_ksu_release,
};

int ksu_install_fd(void)
{
    struct file *filp;
    int fd;

    fd = get_unused_fd_flags(O_CLOEXEC);
    if (fd < 0) {
        pr_err("ksu_install_fd: failed to get unused fd\n");
        return fd;
    }

    filp = anon_inode_getfile("[ksu_driver]", &anon_ksu_fops, NULL, O_RDWR | O_CLOEXEC);
    if (IS_ERR(filp)) {
        pr_err("ksu_install_fd: failed to create anon inode file\n");
        put_unused_fd(fd);
        return PTR_ERR(filp);
    }

    fd_install(fd, filp);
    pr_info("ksu fd installed: %d for pid %d\n", fd, current->pid);
    return fd;
}

static void ksu_install_fd_tw_func(struct callback_head *cb)
{
    struct ksu_install_fd_tw *tw = container_of(cb, struct ksu_install_fd_tw, cb);
    int fd = ksu_install_fd();

    pr_info("[%d] install ksu fd: %d\n", current->pid, fd);
    if (copy_to_user(tw->outp, &fd, sizeof(fd))) {
        pr_err("install ksu fd reply err\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
        close_fd(fd);
#else
        ksys_close(fd);
#endif
    }

    kfree(tw);
}

int ksu_supercall_reboot_handler(int magic2, unsigned int cmd, void __user **arg)
{
	void __user *uarg = arg ? *arg : NULL;
	unsigned long reply = (unsigned long)uarg;

	if (magic2 == KSU_INSTALL_MAGIC2) {
		struct ksu_install_fd_tw *tw;

		tw = kzalloc(sizeof(*tw), GFP_KERNEL);
		if (!tw)
			return 0;

		tw->outp = (int __user *)uarg;
		tw->cb.func = ksu_install_fd_tw_func;

		if (task_work_add(current, &tw->cb, TWA_RESUME)) {
			kfree(tw);
			pr_warn("install fd add task_work failed\n");
		}

		return 0;
	}

	if (magic2 == CHANGE_MANAGER_UID) {
		if (current_uid().val != 0)
			return 0;

		pr_info("sys_reboot: ksu_set_manager_appid to: %d\n", cmd);
		ksu_set_manager_appid(cmd);

		if (cmd == ksu_get_manager_appid() && uarg) {
			if (copy_to_user(uarg, &reply, sizeof(reply)))
				pr_info("sys_reboot: reply fail\n");
		}
		return 0;
	}

	if (magic2 == GET_SULOG_DUMP_V2) {
		if (current_uid().val != 0)
			return 0;

		if (send_sulog_dump(uarg))
			return 0;

		if (copy_to_user(uarg, &reply, sizeof(reply)))
			return 0;
		return 0;
	}

	if (magic2 == CHANGE_KSUVER) {
		if (current_uid().val != 0)
			return 0;

		pr_info("sys_reboot: ksu_change_ksuver to: %d\n", cmd);
		ksuver_override = cmd;
		if (copy_to_user(uarg, &reply, sizeof(reply)))
			return 0;
		return 0;
	}

	if (magic2 == CHANGE_SPOOF_UNAME) {
		char release_buf[65];
		char version_buf[65];
		static char original_release_buf[65] = { 0 };
		static char original_version_buf[65] = { 0 };
		void __user **ppptr = (void __user **)uarg;
		uint64_t u_pptr = 0;
		uint64_t u_ptr = 0;
		struct new_utsname *u;

		if (current_uid().val != 0)
			return 0;

		if (copy_from_user(&u_pptr, ppptr, sizeof(u_pptr)))
			return 0;
		if (copy_from_user(&u_ptr, (void __user *)u_pptr, sizeof(u_ptr)))
			return 0;
		if (strncpy_from_user(release_buf, (char __user *)u_ptr,
				      sizeof(release_buf)) < 0)
			return 0;
		release_buf[sizeof(release_buf) - 1] = '\0';
		if (strncpy_from_user(version_buf,
				      (char __user *)(u_ptr + strlen(release_buf) + 1),
				      sizeof(version_buf)) < 0)
			return 0;
		version_buf[sizeof(version_buf) - 1] = '\0';

		if (original_release_buf[0] == '\0') {
			struct new_utsname *u_curr = utsname();

			strscpy(original_release_buf, u_curr->release,
			       sizeof(original_release_buf));
			strscpy(original_version_buf, u_curr->version,
			       sizeof(original_version_buf));
		}

		if (!strcmp(release_buf, "default") || !strcmp(version_buf, "default")) {
			memcpy(release_buf, original_release_buf, sizeof(release_buf));
			memcpy(version_buf, original_version_buf, sizeof(version_buf));
		}

		pr_info("sys_reboot: spoofing kernel to: %s - %s\n",
			release_buf, version_buf);
		u = utsname();
		down_write(&uts_sem);
		strscpy(u->release, release_buf, sizeof(u->release));
		strscpy(u->version, version_buf, sizeof(u->version));
		up_write(&uts_sem);

		if (copy_to_user(uarg, &reply, sizeof(reply)))
			return 0;
		return 0;
	}

	return -EINVAL;
}


void __init ksu_supercalls_init(void)
{
	ksu_supercall_dump_commands();
	sulog_init_heap();
}

void __exit ksu_supercalls_exit(void)
{
	ksu_supercall_cleanup_state();
}
