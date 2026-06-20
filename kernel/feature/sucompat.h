#ifndef __KSU_H_SUCOMPAT
#define __KSU_H_SUCOMPAT
#include <linux/types.h>

extern bool ksu_su_compat_enabled;

void ksu_sucompat_init(void);
void ksu_sucompat_exit(void);

// Handler functions exported for hook_manager
int vnd_handle_faccessat(int *dfd, const char __user **filename_user,
				int *mode, int *__unused_flags);
int vnd_handle_stat(int *dfd, const char __user **filename_user, int *flags);
long vnd_handle_execve_sucompat(const char __user **filename_user, int orig_nr, const struct pt_regs *regs);

#endif