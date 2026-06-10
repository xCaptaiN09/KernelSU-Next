#include <linux/anon_inodes.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/utsname.h> // utsname() and uts_sem
#ifdef CONFIG_KSU_SUSFS
#include <linux/namei.h>
#include <linux/susfs.h>
#include "objsec.h"
#endif // #ifdef CONFIG_KSU_SUSFS

#include "uapi/supercall.h"
#include "supercall/internal.h"
#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"

#include "tiny_sulog.h"

#ifdef CONFIG_KPM
#include "kpm/kpm.h"
#endif

#define CMD_ENABLE_KPM 100

uint32_t ksuver_override = 0;

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

	// Get unused fd
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("ksu_install_fd: failed to get unused fd\n");
		return fd;
	}

	// Create anonymous inode file
	filp = anon_inode_getfile("[ksu_driver]", &anon_ksu_fops, NULL, O_RDWR | O_CLOEXEC);
	if (IS_ERR(filp)) {
		pr_err("ksu_install_fd: failed to create anon inode file\n");
		put_unused_fd(fd);
		return PTR_ERR(filp);
	}

	// Install fd
	fd_install(fd, filp);

	pr_info("ksu fd installed: %d for pid %d\n", fd, current->pid);

	return fd;
}

#ifdef CONFIG_KSU_SUSFS
static void ksu_prctl_reply(unsigned long arg5, int error)
{
	if (arg5 && copy_to_user((void __user *)arg5, &error, sizeof(error)))
		pr_err("prctl reply error: %d\n", error);
}

static int ksu_handle_susfs_prctl(unsigned long cmd, unsigned long arg3,
				  unsigned long arg5)
{
	int error = -EOPNOTSUPP;

	switch (cmd) {
	case CMD_SUSFS_SHOW_VERSION:
		error = copy_to_user((void __user *)arg3, SUSFS_VERSION,
				     strlen(SUSFS_VERSION) + 1) ?
				-EFAULT : 0;
		break;
	case CMD_SUSFS_SHOW_ENABLED_FEATURES: {
		u64 enabled_features = 0;
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
		enabled_features |= (1ULL << 0);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
		enabled_features |= (1ULL << 1);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
		enabled_features |= (1ULL << 2);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
		enabled_features |= (1ULL << 3);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
		enabled_features |= (1ULL << 4);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_OVERLAYFS
		enabled_features |= (1ULL << 5);
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
		enabled_features |= (1ULL << 6);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
		enabled_features |= (1ULL << 7);
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
		enabled_features |= (1ULL << 8);
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
		enabled_features |= (1ULL << 9);
#endif
#ifdef CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
		enabled_features |= (1ULL << 10);
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
		enabled_features |= (1ULL << 11);
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
		enabled_features |= (1ULL << 12);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_SU
		enabled_features |= (1ULL << 13);
#endif
#ifdef CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT
		enabled_features |= (1ULL << 14);
#endif
		error = copy_to_user((void __user *)arg3, &enabled_features,
				     sizeof(enabled_features)) ?
				-EFAULT : 0;
		break;
	}
	case CMD_SUSFS_SHOW_VARIANT:
		error = copy_to_user((void __user *)arg3, SUSFS_VARIANT,
				     strlen(SUSFS_VARIANT) + 1) ?
				-EFAULT : 0;
		break;
	case CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE:
#ifdef CONFIG_KSU_SUSFS_SUS_SU
	{
		int mode = susfs_get_sus_su_working_mode();
		error = copy_to_user((void __user *)arg3, &mode, sizeof(mode)) ?
				-EFAULT : 0;
		break;
	}
#else
		error = -EOPNOTSUPP;
		break;
#endif
	case CMD_SUSFS_IS_SUS_SU_READY:
#ifdef CONFIG_KSU_SUSFS_SUS_SU
	{
		bool ready = true;
		error = copy_to_user((void __user *)arg3, &ready,
				     sizeof(ready)) ?
				-EFAULT : 0;
		break;
	}
#else
		error = -EOPNOTSUPP;
		break;
#endif
	case CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS:
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
		susfs_try_umount(current_uid().val);
		error = 0;
#endif
		break;
	default:
		error = susfs_handle_ioctl((unsigned int)cmd, arg3) ?
				0 : -EOPNOTSUPP;
		break;
	}

	ksu_prctl_reply(arg5, error);
	return 0;
}
#endif

int ksu_handle_prctl(int option, unsigned long arg2, unsigned long arg3,
		     unsigned long arg4, unsigned long arg5)
{
#ifdef CONFIG_KSU_SUSFS
	if (option >= CMD_SUSFS_ADD_SUS_PATH && option <= CMD_SUSFS_SUS_SU) {
		if (current_uid().val != 0 && !is_manager())
			return -EPERM;
		return ksu_handle_susfs_prctl(option, arg2, arg4);
	}
#endif

	if (option != KSU_INSTALL_MAGIC1)
		return -ENOSYS;

	if (current_uid().val != 0 && !is_manager())
		return -EPERM;

#ifdef CONFIG_KPM
	if (arg2 == CMD_ENABLE_KPM) {
		bool enabled = IS_ENABLED(CONFIG_KPM);
		if (copy_to_user((void __user *)arg3, &enabled, sizeof(enabled)))
			return -EFAULT;
		return 0;
	}

	if (sukisu_is_kpm_control_code(arg2))
		return sukisu_handle_kpm(arg2, arg3, arg4, arg5);
#endif

#ifdef CONFIG_KSU_SUSFS
	if (arg2 >= CMD_SUSFS_ADD_SUS_PATH && arg2 <= CMD_SUSFS_SUS_SU)
		return ksu_handle_susfs_prctl(arg2, arg3, arg5);
#endif

	return -ENOSYS;
}

int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd,
			  void __user **arg)
{
	if (magic1 != KSU_INSTALL_MAGIC1)
		return 0;

#ifdef CONFIG_KSU_DEBUG
	pr_info("sys_reboot: intercepted call! magic: 0x%x id: %d\n", magic1,
		magic2);
#endif

	// Check if this is a request to install KSU fd
	if (magic2 == KSU_INSTALL_MAGIC2) {
		int fd = ksu_install_fd();
		// downstream: dereference all arg usage!
		if (copy_to_user((void __user *)*arg, &fd, sizeof(fd))) {
			pr_err("install ksu fd reply err\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
		close_fd(fd);
#else
		__close_fd(current->files, fd);
#endif
		}
		return 0;
	}

	// extensions 
	u64 reply = (u64)*arg;

	if (magic2 == CHANGE_MANAGER_UID) {
		// only root is allowed for this command
		if (current_uid().val != 0)
			return 0;

		pr_info("sys_reboot: ksu_set_manager_appid to: %d\n", cmd);
		ksu_set_manager_appid(cmd);

		if (cmd == ksu_get_manager_appid()) {
			if (copy_to_user((void __user *)*arg, &reply, sizeof(reply)))
				pr_info("sys_reboot: reply fail\n");
		}

		return 0;
	}
	
	if (magic2 == GET_SULOG_DUMP_V2) {
		// only root is allowed for this command
		if (current_uid().val != 0)
			return 0;

		int ret = send_sulog_dump(*arg);
		if (ret)
			return 0;

		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply) ))
			return 0;
	}

	if (magic2 == CHANGE_KSUVER) {
		// only root is allowed for this command
		if (current_uid().val != 0)
			return 0;

		pr_info("sys_reboot: ksu_change_ksuver to: %d\n", cmd);
		ksuver_override = cmd;

		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply) ))
			return 0;
	}

	// WARNING!!! triple ptr zone! ***
	// https://wiki.c2.com/?ThreeStarProgrammer
	if (magic2 == CHANGE_SPOOF_UNAME) {
		// only root is allowed for this command 
		if (current_uid().val != 0)
			return 0;

		char release_buf[65];
		char version_buf[65];
		static char original_release_buf[65] = {0};
		static char original_version_buf[65] = {0};

		// basically void * void __user * void __user *arg
		void ***ppptr = (uintptr_t)arg;

		// user pointer storage
		// init this as zero so this works on 32-on-64 compat (LE)
		uint64_t u_pptr = 0;
		uint64_t u_ptr = 0;

		pr_info("sys_reboot: ppptr: 0x%lx \n", ppptr);

		// arg here is ***, dereference to pull out **
		if (copy_from_user(&u_pptr, (void __user *)*ppptr, sizeof(u_pptr)))
			return 0;

		pr_info("sys_reboot: u_pptr: 0x%lx \n", u_pptr);

		// now we got the __user **
		// we cannot dereference this as this is __user
		// we just do another copy_from_user to get it
		if (copy_from_user(&u_ptr, (void __user *)u_pptr, sizeof(u_ptr)))
			return 0;

		pr_info("sys_reboot: u_ptr: 0x%lx \n", u_ptr);

		// for release
		if (strncpy_from_user(release_buf, (char __user *)u_ptr, sizeof(release_buf)) < 0)
			return 0;
		release_buf[sizeof(release_buf) - 1] = '\0'; 

		// for version
		if (strncpy_from_user(version_buf, (char __user *)(u_ptr + strlen(release_buf) + 1), sizeof(version_buf)) < 0)
			return 0;
		version_buf[sizeof(version_buf) - 1] = '\0'; 

		if (original_release_buf[0] == '\0') {
			struct new_utsname *u_curr = utsname();
			// we save current version as the original before modifying
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
			strscpy(original_release_buf, u_curr->release, sizeof(original_release_buf));
			strscpy(original_version_buf, u_curr->version, sizeof(original_version_buf));
#else
			strlcpy(original_release_buf, u_curr->release, sizeof(original_release_buf));
			strlcpy(original_version_buf, u_curr->version, sizeof(original_version_buf));
#endif
			pr_info("sys_reboot: original uname saved: %s %s\n", original_release_buf, original_version_buf);
		}

		// so user can reset
		if (!strcmp(release_buf, "default") || !strcmp(version_buf, "default") ) {
			memcpy(release_buf, original_release_buf, sizeof(release_buf));
			memcpy(version_buf, original_version_buf, sizeof(version_buf));
		}

		pr_info("sys_reboot: spoofing kernel to: %s - %s\n", release_buf, version_buf);

		struct new_utsname *u = utsname();

		down_write(&uts_sem);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
		strscpy(u->release, release_buf, sizeof(u->release));
		strscpy(u->version, version_buf, sizeof(u->version));
#else
		strlcpy(u->release, release_buf, sizeof(u->release));
		strlcpy(u->version, version_buf, sizeof(u->version));
#endif
		up_write(&uts_sem);

		// we write our confirmation on **
		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply)))
			return 0;
	}

	return 0;
}

#ifdef KSU_KPROBES_HOOK
static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int magic1 = (int)PT_REGS_PARM1(real_regs);
	int magic2 = (int)PT_REGS_PARM2(real_regs);
	unsigned int cmd = (unsigned int)PT_REGS_PARM3(real_regs);
	unsigned long arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);
	unsigned long reply = (unsigned long)arg4;

	return ksu_handle_sys_reboot(magic1, magic2, cmd, (void __user **)&arg4);
}

static struct kprobe reboot_kp = {
	.symbol_name = REBOOT_SYMBOL,
	.pre_handler = reboot_handler_pre,
};
#endif

void __init ksu_supercalls_init(void)
{
	int i;

	ksu_supercall_dump_commands();

#ifdef KSU_KPROBES_HOOK
	int rc = register_kprobe(&reboot_kp);
	if (rc) {
		pr_err("reboot kprobe failed: %d\n", rc);
	} else {
		pr_info("reboot kprobe registered successfully\n");
	}
#endif

	sulog_init_heap(); // grab heap memory
}

void __exit ksu_supercalls_exit(void){
	struct mount_entry *entry, *tmp;

#ifdef KSU_KPROBES_HOOK
	unregister_kprobe(&reboot_kp);
#endif

	ksu_supercall_cleanup_state();
}
