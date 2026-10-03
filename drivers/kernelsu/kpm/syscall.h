/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __SUKISU_KPM_SYSCALL_H
#define __SUKISU_KPM_SYSCALL_H

#include <linux/types.h>
#include <linux/uaccess.h>

#define KPM_SYSCALL_TABLE_SIZE 460

struct kpm_syscall_name {
	const char *name;
	unsigned long addr;
};

extern struct kpm_syscall_name syscall_name_table[KPM_SYSCALL_TABLE_SIZE];
extern struct kpm_syscall_name compat_syscall_name_table[KPM_SYSCALL_TABLE_SIZE];
extern int has_syscall_wrapper;
extern int has_config_compat;
extern unsigned long *kpm_native_sys_call_table;
extern unsigned long *kpm_native_compat_sys_call_table;

const char __user *get_user_arg_ptr(void *a0, void *a1, int nr);
int set_user_arg_ptr(void *a0, void *a1, int nr, unsigned long value);
long raw_syscall0(long nr);
long raw_syscall1(long nr, long arg0);
long raw_syscall2(long nr, long arg0, long arg1);
long raw_syscall3(long nr, long arg0, long arg1, long arg2);
long raw_syscall4(long nr, long arg0, long arg1, long arg2, long arg3);
long raw_syscall5(long nr, long arg0, long arg1, long arg2, long arg3,
		  long arg4);
long raw_syscall6(long nr, long arg0, long arg1, long arg2, long arg3,
		  long arg4, long arg5);
unsigned long syscalln_name_addr(int nr, int is_compat);
unsigned long syscalln_addr(int nr, int is_compat);
int fp_wrap_syscalln(int nr, int narg, int is_compat, void *before,
		     void *after, void *udata);
void fp_unwrap_syscalln(int nr, int is_compat, void *before, void *after);
int inline_wrap_syscalln(int nr, int narg, int is_compat, void *before,
			 void *after, void *udata);
void inline_unwrap_syscalln(int nr, int is_compat, void *before, void *after);
int hook_syscalln(int nr, int narg, void *before, void *after, void *udata);
void unhook_syscalln(int nr, void *before, void *after);
int hook_compat_syscalln(int nr, int narg, void *before, void *after,
			 void *udata);
void unhook_compat_syscalln(int nr, void *before, void *after);

#endif
