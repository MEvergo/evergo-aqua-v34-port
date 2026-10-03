// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/compat.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <asm/ptrace.h>
#include <asm/syscall.h>
#include <asm/unistd.h>

#include "hook_abi.h"
#include "kpm_internal.h"
#include "syscall.h"
#include "../infra/symbol_resolver.h"

#define KPM_SYSCALL_NAME_LEN KSYM_NAME_LEN

#ifdef CONFIG_COMPAT
extern void * const compat_sys_call_table[];
#endif

struct kpm_syscall_name syscall_name_table[KPM_SYSCALL_TABLE_SIZE];
struct kpm_syscall_name compat_syscall_name_table[KPM_SYSCALL_TABLE_SIZE];
int has_syscall_wrapper;
int has_config_compat;
unsigned long *kpm_native_sys_call_table =
	(unsigned long *)sys_call_table;
#ifdef CONFIG_COMPAT
unsigned long *kpm_native_compat_sys_call_table =
	(unsigned long *)compat_sys_call_table;
#else
unsigned long *kpm_native_compat_sys_call_table;
#endif

static char syscall_names[KPM_SYSCALL_TABLE_SIZE][KPM_SYSCALL_NAME_LEN];
static char compat_syscall_names[KPM_SYSCALL_TABLE_SIZE][KPM_SYSCALL_NAME_LEN];
static int kpm_syscall_initialized;

static void kpm_syscall_names_init(struct kpm_syscall_name *names,
				   char storage[][KPM_SYSCALL_NAME_LEN],
				   unsigned long *table,
				   unsigned int count)
{
	unsigned int i;

	for (i = 0; i < KPM_SYSCALL_TABLE_SIZE; i++) {
		unsigned long address;
		unsigned long symbol_size;
		unsigned long offset;
		char *module_name = NULL;
		char symbol[KPM_SYSCALL_NAME_LEN];
		const char *name;
		size_t name_len;

		names[i].name = NULL;
		names[i].addr = 0;
		storage[i][0] = '\0';
		if (i >= count || !table)
			continue;
		address = table[i];
		names[i].addr = address;
		if (!address)
			continue;
		name = kallsyms_lookup(address, &symbol_size, &offset,
				       &module_name, symbol);
		if (!name)
			continue;
		if (!strncmp(name, "__arm64_", sizeof("__arm64_") - 1))
			name += sizeof("__arm64_") - 1;
		name_len = strlen(name);
		if (name_len > sizeof(".cfi_jt") - 1 &&
		    !strcmp(name + name_len - (sizeof(".cfi_jt") - 1),
			    ".cfi_jt"))
			name_len -= sizeof(".cfi_jt") - 1;
		else if (name_len > sizeof(".cfi") - 1 &&
			 !strcmp(name + name_len - (sizeof(".cfi") - 1), ".cfi"))
			name_len -= sizeof(".cfi") - 1;
		if (name_len >= sizeof(storage[i]))
			name_len = sizeof(storage[i]) - 1;
		memcpy(storage[i], name, name_len);
		storage[i][name_len] = '\0';
		names[i].name = storage[i];
	}
}
static int __init kpm_syscall_init(void)
{
	unsigned int native_count = min_t(unsigned int, __NR_syscalls,
					 KPM_SYSCALL_TABLE_SIZE);
	unsigned int compat_count = 0;

#ifdef CONFIG_COMPAT
	compat_count = min_t(unsigned int, __NR_compat_syscalls,
			     KPM_SYSCALL_TABLE_SIZE);
#endif
	kpm_syscall_names_init(syscall_name_table, syscall_names,
			       kpm_native_sys_call_table, native_count);
	kpm_syscall_names_init(compat_syscall_name_table,
			       compat_syscall_names,
			       kpm_native_compat_sys_call_table,
			       compat_count);
	has_config_compat = IS_ENABLED(CONFIG_COMPAT) &&
		!!kpm_native_compat_sys_call_table;
	has_syscall_wrapper =
		!!find_kernel_symbol_exact("__arm64_sys_openat") ||
		!!find_kernel_symbol_exact("__arm64_compat_sys_openat");
	WRITE_ONCE(kpm_syscall_initialized, 1);
	return 0;
}
core_initcall(kpm_syscall_init);

static bool kpm_syscall_number_valid(int nr, int is_compat)
{
	if (nr < 0 || nr >= KPM_SYSCALL_TABLE_SIZE)
		return false;
	if (is_compat) {
#ifdef CONFIG_COMPAT
		return has_config_compat && nr < __NR_compat_syscalls;
#else
		return false;
#endif
	}
	return nr < __NR_syscalls;
}

unsigned long syscalln_name_addr(int nr, int is_compat)
{
	struct kpm_syscall_name *table;
	const char *prefixes[] = { "__arm64_", "" };
	const char *suffixes[] = { ".cfi_jt", ".cfi", "" };
	char symbol[KPM_SYSCALL_NAME_LEN + 32];
	unsigned long address;
	unsigned int i;
	unsigned int j;

	if (!READ_ONCE(kpm_syscall_initialized) ||
	    !kpm_syscall_number_valid(nr, is_compat))
		return 0;
	table = is_compat ? compat_syscall_name_table : syscall_name_table;
	address = READ_ONCE(table[nr].addr);
	if (address)
		return address;
	if (!table[nr].name)
		return 0;
	for (i = 0; i < ARRAY_SIZE(prefixes); i++) {
		for (j = 0; j < ARRAY_SIZE(suffixes); j++) {
			snprintf(symbol, sizeof(symbol), "%s%s%s", prefixes[i],
				 table[nr].name, suffixes[j]);
			address = find_kernel_symbol_exact(symbol);
			if (address)
				goto found;
		}
	}
	return 0;
found:
	WRITE_ONCE(table[nr].addr, address);
	return address;
}

unsigned long syscalln_addr(int nr, int is_compat)
{
	unsigned long *table;

	if (!READ_ONCE(kpm_syscall_initialized) ||
	    !kpm_syscall_number_valid(nr, is_compat))
		return 0;
	table = is_compat ? kpm_native_compat_sys_call_table :
		kpm_native_sys_call_table;
	if (table)
		return READ_ONCE(table[nr]);
	return syscalln_name_addr(nr, is_compat);
}

const char __user *get_user_arg_ptr(void *a0, void *a1, int nr)
{
	const void __user *array;
	unsigned long address;
	unsigned long value;
	unsigned int size;
	u32 compat_value;

	if (nr < 0)
		return ERR_PTR(-EINVAL);
	if (has_config_compat) {
		array = (const void __user *)a1;
		size = a0 ? sizeof(compat_value) : sizeof(value);
	} else {
		array = (const void __user *)a0;
		size = sizeof(value);
	}
	if (!array)
		return ERR_PTR(-EFAULT);
	address = (unsigned long)array + (unsigned long)nr * size;
	if (size == sizeof(compat_value)) {
		if (copy_from_user(&compat_value, (const void __user *)address,
				   sizeof(compat_value)))
			return ERR_PTR(-EFAULT);
		value = compat_value;
	} else if (copy_from_user(&value, (const void __user *)address,
				  sizeof(value))) {
		return ERR_PTR(-EFAULT);
	}
	return (const char __user *)value;
}

int set_user_arg_ptr(void *a0, void *a1, int nr, unsigned long value)
{
	void __user *array;
	unsigned long address;
	unsigned int size;
	u32 compat_value;

	if (nr < 0)
		return -EINVAL;
	if (has_config_compat) {
		array = (void __user *)a1;
		size = a0 ? sizeof(compat_value) : sizeof(value);
	} else {
		array = (void __user *)a0;
		size = sizeof(value);
	}
	if (!array)
		return -EFAULT;
	address = (unsigned long)array + (unsigned long)nr * size;
	if (size == sizeof(compat_value)) {
		compat_value = (u32)value;
		return copy_to_user((void __user *)address, &compat_value,
				    sizeof(compat_value));
	}
	return copy_to_user((void __user *)address, &value, sizeof(value));
}

static long kpm_raw_syscall(long nr, unsigned int nargs, long arg0,
			    long arg1, long arg2, long arg3, long arg4,
			    long arg5)
{
	struct pt_regs regs;
	unsigned long address;

	if (nr < 0 || nr >= __NR_syscalls)
		return -ENOSYS;
	address = syscalln_addr((int)nr, 0);
	if (!address)
		return -ENOSYS;
	if (has_syscall_wrapper) {
		memset(&regs, 0, sizeof(regs));
		regs.syscallno = nr;
		regs.regs[8] = nr;
		regs.regs[0] = arg0;
		regs.regs[1] = arg1;
		regs.regs[2] = arg2;
		regs.regs[3] = arg3;
		regs.regs[4] = arg4;
		regs.regs[5] = arg5;
		return ((long (*)(const struct pt_regs *))address)(&regs);
	}
	switch (nargs) {
	case 0:
		return ((long (*)(void))address)();
	case 1:
		return ((long (*)(long))address)(arg0);
	case 2:
		return ((long (*)(long, long))address)(arg0, arg1);
	case 3:
		return ((long (*)(long, long, long))address)(arg0, arg1, arg2);
	case 4:
		return ((long (*)(long, long, long, long))address)(
			arg0, arg1, arg2, arg3);
	case 5:
		return ((long (*)(long, long, long, long, long))address)(
			arg0, arg1, arg2, arg3, arg4);
	default:
		return ((long (*)(long, long, long, long, long, long))address)(
			arg0, arg1, arg2, arg3, arg4, arg5);
	}
}

long raw_syscall0(long nr)
{
	return kpm_raw_syscall(nr, 0, 0, 0, 0, 0, 0, 0);
}

long raw_syscall1(long nr, long arg0)
{
	return kpm_raw_syscall(nr, 1, arg0, 0, 0, 0, 0, 0);
}

long raw_syscall2(long nr, long arg0, long arg1)
{
	return kpm_raw_syscall(nr, 2, arg0, arg1, 0, 0, 0, 0);
}

long raw_syscall3(long nr, long arg0, long arg1, long arg2)
{
	return kpm_raw_syscall(nr, 3, arg0, arg1, arg2, 0, 0, 0);
}

long raw_syscall4(long nr, long arg0, long arg1, long arg2, long arg3)
{
	return kpm_raw_syscall(nr, 4, arg0, arg1, arg2, arg3, 0, 0);
}

long raw_syscall5(long nr, long arg0, long arg1, long arg2, long arg3,
		  long arg4)
{
	return kpm_raw_syscall(nr, 5, arg0, arg1, arg2, arg3, arg4, 0);
}

long raw_syscall6(long nr, long arg0, long arg1, long arg2, long arg3,
		  long arg4, long arg5)
{
	return kpm_raw_syscall(nr, 6, arg0, arg1, arg2, arg3, arg4, arg5);
}

int fp_wrap_syscalln(int nr, int narg, int is_compat, void *before,
		     void *after, void *udata)
{
	unsigned long *table;

	if (!kpm_syscall_number_valid(nr, is_compat) || narg < 0 || narg > 6)
		return KPM_HOOK_BAD_ADDRESS;
	table = is_compat ? kpm_native_compat_sys_call_table :
		kpm_native_sys_call_table;
	if (!table)
		return KPM_HOOK_BAD_ADDRESS;
	if (has_syscall_wrapper)
		narg = 1;
	return fp_hook_wrap((void *)&table[nr], narg, before, after, udata);
}

void fp_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
	unsigned long *table;

	if (!kpm_syscall_number_valid(nr, is_compat))
		return;
	table = is_compat ? kpm_native_compat_sys_call_table :
		kpm_native_sys_call_table;
	if (table)
		fp_hook_unwrap((void *)&table[nr], before, after);
}

int inline_wrap_syscalln(int nr, int narg, int is_compat, void *before,
			 void *after, void *udata)
{
	unsigned long address;

	if (!kpm_syscall_number_valid(nr, is_compat) || narg < 0 || narg > 6)
		return KPM_HOOK_BAD_ADDRESS;
	address = syscalln_name_addr(nr, is_compat);
	if (!address)
		return KPM_HOOK_BAD_ADDRESS;
	if (has_syscall_wrapper)
		narg = 1;
	return hook_wrap((void *)address, narg, before, after, udata);
}

void inline_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
	unsigned long address;

	if (!kpm_syscall_number_valid(nr, is_compat))
		return;
	address = syscalln_name_addr(nr, is_compat);
	if (address)
		hook_unwrap_remove((void *)address, before, after, 1);
}

int hook_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
	if (kpm_native_sys_call_table)
		return fp_wrap_syscalln(nr, narg, 0, before, after, udata);
	return inline_wrap_syscalln(nr, narg, 0, before, after, udata);
}

void unhook_syscalln(int nr, void *before, void *after)
{
	if (kpm_native_sys_call_table)
		fp_unwrap_syscalln(nr, 0, before, after);
	else
		inline_unwrap_syscalln(nr, 0, before, after);
}

int hook_compat_syscalln(int nr, int narg, void *before, void *after,
			 void *udata)
{
	if (kpm_native_compat_sys_call_table)
		return fp_wrap_syscalln(nr, narg, 1, before, after, udata);
	return inline_wrap_syscalln(nr, narg, 1, before, after, udata);
}

void unhook_compat_syscalln(int nr, void *before, void *after)
{
	if (kpm_native_compat_sys_call_table)
		fp_unwrap_syscalln(nr, 1, before, after);
	else
		inline_unwrap_syscalln(nr, 1, before, after);
}
