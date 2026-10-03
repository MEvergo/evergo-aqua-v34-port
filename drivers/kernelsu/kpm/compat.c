/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/errno.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/thread_info.h>
#include <linux/uaccess.h>
#include <asm/sections.h>

#include "../hook/patch_memory.h"
#include "../infra/symbol_resolver.h"
#include "compact.h"
#include "abi_symbols.h"
#include "kpm_internal.h"
#include "hook_abi.h"
#include "syscall.h"

struct kpm_api_symbol {
	const char *name;
	unsigned long address;
};

struct kpm_patch_update {
	struct kpm_owned_patch *record;
	bool new_record;
	u32 expected;
	u32 target;
};

static const unsigned int kpm_native_kpver = KPM_NATIVE_ABI_VERSION;
static const unsigned int kpm_native_kver = LINUX_VERSION_CODE;
static LIST_HEAD(kpm_all_patches);
static DEFINE_MUTEX(kpm_patch_lock);
struct kpm_task_struct_offset {
	s16 pid_offset;
	s16 tgid_offset;
	s16 thread_pid_offset;
	s16 ptracer_cred_offset;
	s16 real_cred_offset;
	s16 cred_offset;
	s16 comm_offset;
	s16 fs_offset;
	s16 files_offset;
	s16 loginuid_offset;
	s16 sessionid_offset;
	s16 seccomp_offset;
	s16 security_offset;
	s16 stack_offset;
	s16 tasks_offset;
	s16 mm_offset;
	s16 active_mm_offset;
};

struct kpm_mm_struct_offset {
	s16 mmap_base_offset;
	s16 task_size_offset;
	s16 pgd_offset;
	s16 map_count_offset;
	s16 total_vm_offset;
	s16 locked_vm_offset;
	s16 pinned_vm_offset;
	s16 data_vm_offset;
	s16 exec_vm_offset;
	s16 stack_vm_offset;
	s16 start_code_offset;
	s16 end_code_offset;
	s16 start_data_offset;
	s16 end_data_offset;
	s16 start_brk_offset;
	s16 brk_offset;
	s16 start_stack_offset;
	s16 arg_start_offset;
	s16 arg_end_offset;
	s16 env_start_offset;
	s16 env_end_offset;
};

static struct kpm_task_struct_offset kpm_task_offsets = {
	.pid_offset = offsetof(struct task_struct, pid),
	.tgid_offset = offsetof(struct task_struct, tgid),
	.thread_pid_offset = offsetof(struct task_struct, thread_pid),
	.ptracer_cred_offset = offsetof(struct task_struct, ptracer_cred),
	.real_cred_offset = offsetof(struct task_struct, real_cred),
	.cred_offset = offsetof(struct task_struct, cred),
	.comm_offset = offsetof(struct task_struct, comm),
	.fs_offset = offsetof(struct task_struct, fs),
	.files_offset = offsetof(struct task_struct, files),
	.loginuid_offset = -1,
	.sessionid_offset = -1,
	.seccomp_offset = offsetof(struct task_struct, seccomp),
	.security_offset = -1,
	.stack_offset = offsetof(struct task_struct, stack),
	.tasks_offset = offsetof(struct task_struct, tasks),
	.mm_offset = offsetof(struct task_struct, mm),
	.active_mm_offset = offsetof(struct task_struct, active_mm),
};

static struct kpm_mm_struct_offset kpm_mm_offsets = {
	.mmap_base_offset = offsetof(struct mm_struct, mmap_base),
	.task_size_offset = offsetof(struct mm_struct, task_size),
	.pgd_offset = offsetof(struct mm_struct, pgd),
	.map_count_offset = offsetof(struct mm_struct, map_count),
	.total_vm_offset = offsetof(struct mm_struct, total_vm),
	.locked_vm_offset = offsetof(struct mm_struct, locked_vm),
	.pinned_vm_offset = offsetof(struct mm_struct, pinned_vm),
	.data_vm_offset = offsetof(struct mm_struct, data_vm),
	.exec_vm_offset = offsetof(struct mm_struct, exec_vm),
	.stack_vm_offset = offsetof(struct mm_struct, stack_vm),
	.start_code_offset = offsetof(struct mm_struct, start_code),
	.end_code_offset = offsetof(struct mm_struct, end_code),
	.start_data_offset = offsetof(struct mm_struct, start_data),
	.end_data_offset = offsetof(struct mm_struct, end_data),
	.start_brk_offset = offsetof(struct mm_struct, start_brk),
	.brk_offset = offsetof(struct mm_struct, brk),
	.start_stack_offset = offsetof(struct mm_struct, start_stack),
	.arg_start_offset = offsetof(struct mm_struct, arg_start),
	.arg_end_offset = offsetof(struct mm_struct, arg_end),
	.env_start_offset = offsetof(struct mm_struct, env_start),
	.env_end_offset = offsetof(struct mm_struct, env_end),
};

static int kpm_thread_size = THREAD_SIZE;
static int kpm_thread_info_in_task = IS_ENABLED(CONFIG_THREAD_INFO_IN_TASK);
static int kpm_sp_el0_is_current = 1;
static int kpm_sp_el0_is_thread_info;
static int kpm_task_in_thread_info_offset = -1;
static int kpm_stack_in_task_offset =
	offsetof(struct task_struct, stack);
/* KernelPatch defines stack_end_offset as the stack top offset. */
static int kpm_stack_end_offset = THREAD_SIZE;

static u64 *kpm_pgtable_entry(u64 pgd_address, u64 virtual_address)
{
	pgd_t *pgd = (pgd_t *)pgd_address + pgd_index(virtual_address);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return NULL;
	p4d = p4d_offset(pgd, virtual_address);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return NULL;
	pud = pud_offset(p4d, virtual_address);
	if (pud_none(*pud) || pud_bad(*pud))
		return NULL;
	if (pud_sect(*pud))
		return (u64 *)pud;
	pmd = pmd_offset(pud, virtual_address);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return NULL;
	if (pmd_sect(*pmd))
		return (u64 *)pmd;
	pte = pte_offset_kernel(pmd, virtual_address);
	return pte ? (u64 *)pte : NULL;
}

static struct pt_regs *kpm_task_pt_reg(struct task_struct *task)
{
	unsigned long stack = (unsigned long)task_stack_page(task);

	return (struct pt_regs *)(THREAD_SIZE + stack - sizeof(struct pt_regs));
}

static int kpm_compat_hotpatch_nosync(void *address, u32 value)
{
	void *addresses[1] = { address };
	u32 values[1] = { value };

	return kpm_compat_hotpatch(addresses, values, 1);
}
static int kpm_compat_copy_to_user(void __user *to, const void *from, int len)
{
	if (len < 0)
		return 0;
	return copy_to_user(to, from, len) ? 0 : len;
}

static long kpm_compat_strncpy_from_user(char *destination,
					 const char __user *source,
					 long count)
{
	long copied;

	if (count <= 0)
		return -EINVAL;
	copied = strncpy_from_user(destination, source, count);
	if (copied >= count) {
		destination[count - 1] = '\0';
		return count;
	}
	return copied > 0 ? copied + 1 : copied;
}

static uid_t kpm_compat_current_uid(void)
{
	/* Match KernelPatch's UID ABI by mapping through current_user_ns(). */
	return from_kuid(current_user_ns(), current_uid());
}


static const struct kpm_api_symbol kpm_api_symbols[] = {
	{ "hotpatch", (unsigned long)kpm_compat_hotpatch },
	{ "hotpatch_nosync", (unsigned long)kpm_compat_hotpatch_nosync },
	{ "kpver", (unsigned long)&kpm_native_kpver },
	{ "kver", (unsigned long)&kpm_native_kver },
	{ "compat_copy_to_user", (unsigned long)kpm_compat_copy_to_user },
	{ "compat_strncpy_from_user",
	  (unsigned long)kpm_compat_strncpy_from_user },
	{ "current_uid", (unsigned long)kpm_compat_current_uid },
	{ "thread_size", (unsigned long)&kpm_thread_size },
	{ "thread_info_in_task",
	  (unsigned long)&kpm_thread_info_in_task },
	{ "sp_el0_is_current", (unsigned long)&kpm_sp_el0_is_current },
	{ "sp_el0_is_thread_info",
	  (unsigned long)&kpm_sp_el0_is_thread_info },
	{ "task_in_thread_info_offset",
	  (unsigned long)&kpm_task_in_thread_info_offset },
	{ "task_struct_offset", (unsigned long)&kpm_task_offsets },
	{ "pgtable_entry", (unsigned long)kpm_pgtable_entry },
	{ "mm_struct_offset", (unsigned long)&kpm_mm_offsets },
	{ "has_config_compat", (unsigned long)&has_config_compat },
	{ "has_syscall_wrapper", (unsigned long)&has_syscall_wrapper },
	{ "sys_call_table", (unsigned long)&kpm_native_sys_call_table },
	{ "compat_sys_call_table",
	  (unsigned long)&kpm_native_compat_sys_call_table },
	{ "syscall_name_table", (unsigned long)syscall_name_table },
	{ "compat_syscall_name_table",
	  (unsigned long)compat_syscall_name_table },
	{ "hook", (unsigned long)hook },
	{ "unhook", (unsigned long)unhook },
	{ "hook_prepare", (unsigned long)hook_prepare },
	{ "hook_install", (unsigned long)hook_install },
	{ "hook_uninstall", (unsigned long)hook_uninstall },
	{ "hook_wrap", (unsigned long)hook_wrap },
	{ "hook_unwrap_remove", (unsigned long)hook_unwrap_remove },
	{ "hook_chain_add", (unsigned long)hook_chain_add },
	{ "hook_chain_remove", (unsigned long)hook_chain_remove },
	{ "fp_hook", (unsigned long)fp_hook },
	{ "fp_unhook", (unsigned long)fp_unhook },
	{ "fp_hook_wrap", (unsigned long)fp_hook_wrap },
	{ "fp_hook_unwrap", (unsigned long)fp_hook_unwrap },
	{ "branch_relative", (unsigned long)branch_relative },
	{ "branch_absolute", (unsigned long)branch_absolute },
	{ "branch_from_to", (unsigned long)branch_from_to },
	{ "ret_absolute", (unsigned long)ret_absolute },
	{ "branch_func_addr", (unsigned long)branch_func_addr },
	{ "get_user_arg_ptr", (unsigned long)get_user_arg_ptr },
	{ "set_user_arg_ptr", (unsigned long)set_user_arg_ptr },
	{ "raw_syscall0", (unsigned long)raw_syscall0 },
	{ "raw_syscall1", (unsigned long)raw_syscall1 },
	{ "raw_syscall2", (unsigned long)raw_syscall2 },
	{ "raw_syscall3", (unsigned long)raw_syscall3 },
	{ "raw_syscall4", (unsigned long)raw_syscall4 },
	{ "raw_syscall5", (unsigned long)raw_syscall5 },
	{ "raw_syscall6", (unsigned long)raw_syscall6 },
	{ "syscalln_name_addr", (unsigned long)syscalln_name_addr },
	{ "syscalln_addr", (unsigned long)syscalln_addr },
	{ "fp_wrap_syscalln", (unsigned long)fp_wrap_syscalln },
	{ "fp_unwrap_syscalln", (unsigned long)fp_unwrap_syscalln },
	{ "inline_wrap_syscalln", (unsigned long)inline_wrap_syscalln },
	{ "inline_unwrap_syscalln", (unsigned long)inline_unwrap_syscalln },
	{ "hook_syscalln", (unsigned long)hook_syscalln },
	{ "unhook_syscalln", (unsigned long)unhook_syscalln },
	{ "hook_compat_syscalln", (unsigned long)hook_compat_syscalln },
	{ "unhook_compat_syscalln", (unsigned long)unhook_compat_syscalln },
	{ "stack_in_task_offset", (unsigned long)&kpm_stack_in_task_offset },
	{ "stack_end_offset", (unsigned long)&kpm_stack_end_offset },
	{ "_task_pt_reg", (unsigned long)kpm_task_pt_reg },
};
static int kpm_unsupported_symbol(const char *name)
{
	return !strcmp(name, "get_ap_mod_exclude") ||
	       !strcmp(name, "set_ap_mod_exclude");
}


static unsigned long kpm_resolve_function_slot(const char *name)
{
	const char *kernel_symbol;
	unsigned long *slot;
	unsigned long address;

	slot = kpm_abi_find_function_slot(name, &kernel_symbol);
	if (!slot)
		return 0;
	address = READ_ONCE(*slot);
	if (!address) {
		address = find_kernel_symbol_exact(kernel_symbol);
		if (!address)
			return 0;
		WRITE_ONCE(*slot, address);
	}
	return (unsigned long)slot;
}

unsigned long kpm_compat_resolve(const char *name)
{
	size_t i;
	unsigned long address;

	if (!name || !name[0])
		return 0;
	for (i = 0; i < ARRAY_SIZE(kpm_api_symbols); i++) {
		if (!strcmp(name, kpm_api_symbols[i].name))
			return kpm_api_symbols[i].address;
	}
	if (kpm_unsupported_symbol(name))
		return 0;
	address = kpm_resolve_function_slot(name);
	if (address)
		return address;
	address = sukisu_compact_find_symbol(name);
	if (address)
		return address;
	return find_kernel_symbol_exact(name);
}

static struct kpm_owned_patch *kpm_find_patch_locked(void *address)
{
	struct kpm_owned_patch *patch;

	list_for_each_entry(patch, &kpm_all_patches, all_node) {
		if (patch->address == address)
			return patch;
	}
	return NULL;
}

static int kpm_valid_patch_address(void *address)
{
	unsigned long start = (unsigned long)_stext;
	unsigned long end = (unsigned long)_etext;
	unsigned long value = (unsigned long)address;

	if (!address || (value & (sizeof(u32) - 1)) ||
	    end < sizeof(u32) || value < start ||
	    value > end - sizeof(u32) ||
	    init_section_intersects(address, sizeof(u32)) ||
	    !is_kernel_text(value) ||
	    !is_kernel_text(value + sizeof(u32) - 1))
		return -EINVAL;
	return 0;
}

static void kpm_link_patch(struct kpm_module *owner,
			   struct kpm_owned_patch *patch)
{
	patch->owner = owner;
	list_add_tail(&patch->module_node, &owner->owned_patches);
	list_add_tail(&patch->all_node, &kpm_all_patches);
}

int kpm_compat_hotpatch(void **addresses, u32 *values, int count)
{
	struct kpm_module *owner = kpm_current_module();
	struct ksu_patch_text_op ops[KPM_MAX_HOTPATCHES];
	struct kpm_patch_update updates[KPM_MAX_HOTPATCHES];
	int i;
	int changed = 0;
	int error = 0;

	if (!owner)
		return -EPERM;
	if (READ_ONCE(owner->state) != KPM_MODULE_LOADING &&
	    READ_ONCE(owner->state) != KPM_MODULE_LIVE)
		return -EBUSY;
	if (!addresses || !values || count <= 0 ||
	    count > KPM_MAX_HOTPATCHES)
		return -EINVAL;
	memset(updates, 0, sizeof(updates));
	mutex_lock(&kpm_patch_lock);
	for (i = 0; i < count; i++) {
		struct kpm_owned_patch *patch;
		u32 current_value;
		int j;

		error = kpm_valid_patch_address(addresses[i]);
		if (error)
			goto out_free;
		for (j = 0; j < i; j++) {
			if (addresses[j] == addresses[i]) {
				error = -EINVAL;
				goto out_free;
			}
		}
		patch = kpm_find_patch_locked(addresses[i]);
		if (patch && patch->owner != owner) {
			error = -EBUSY;
			goto out_free;
		}
		current_value = READ_ONCE(*(u32 *)addresses[i]);
		if (patch && current_value != patch->installed) {
			error = -EBUSY;
			goto out_free;
		}
		if (!patch) {
			patch = kzalloc(sizeof(*patch), GFP_KERNEL);
			if (!patch) {
				error = -ENOMEM;
				goto out_free;
			}
			INIT_LIST_HEAD(&patch->module_node);
			INIT_LIST_HEAD(&patch->all_node);
			patch->address = addresses[i];
			patch->original = current_value;
			updates[i].new_record = true;
		}
		updates[i].record = patch;
		updates[i].expected = current_value;
		updates[i].target = values[i];
		ops[i].dst = addresses[i];
		ops[i].src = &updates[i].target;
		ops[i].expected = &updates[i].expected;
		ops[i].len = sizeof(u32);
	}

	error = ksu_patch_text_batch(ops, count);
	if (!error) {
		for (i = 0; i < count; i++) {
			struct kpm_owned_patch *patch = updates[i].record;

			if (updates[i].new_record)
				kpm_link_patch(owner, patch);
			patch->installed = updates[i].target;
		}
		WRITE_ONCE(owner->ever_patched, true);
		goto out_unlock;
	}
	if (error == -EUCLEAN) {
		for (i = 0; i < count; i++) {
			struct kpm_owned_patch *patch = updates[i].record;
			u32 current_value = READ_ONCE(*(u32 *)addresses[i]);

			if (current_value == updates[i].expected)
				continue;
			changed = 1;
			if (updates[i].new_record)
				kpm_link_patch(owner, patch);
			patch->installed = current_value;
			updates[i].new_record = false;
		}
		if (changed)
			WRITE_ONCE(owner->ever_patched, true);
		error = -EIO;
	}
out_free:
	for (i = 0; i < count; i++) {
		if (updates[i].new_record)
			kfree(updates[i].record);
	}
out_unlock:
	mutex_unlock(&kpm_patch_lock);
	return error;
}

