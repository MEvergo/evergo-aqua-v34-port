/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "../include/uapi/supercall.h"

#include "kpm.h"
#include "kpm_internal.h"

static int kpm_copy_user_string(char *buffer, size_t size, u64 user_address,
				int optional)
{
	long copied;

	if (!user_address) {
		if (!optional)
			return -EFAULT;
		buffer[0] = '\0';
		return 0;
	}
	copied = strncpy_from_user(buffer,
				   (const char __user *)(unsigned long)user_address,
				   size);
	if (copied < 0)
		return copied;
	if ((size_t)copied >= size)
		return -ENAMETOOLONG;
	if (!optional && !copied)
		return -EINVAL;
	return 0;
}

static int kpm_load_from_user(u64 path_address, u64 args_address)
{
	char *path;
	char args[KPM_ARGS_LEN];
	int error;

	if (!path_address)
		return -EFAULT;
	path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	error = kpm_copy_user_string(path, PATH_MAX, path_address, 0);
	if (!error)
		error = kpm_copy_user_string(args, sizeof(args), args_address, 1);
	if (!error)
		error = kpm_load_path(path, args);
	kfree(path);
	return error;
}

static int kpm_unload_from_user(u64 name_address)
{
	char name[KPM_NAME_LEN];
	int error;

	error = kpm_copy_user_string(name, sizeof(name), name_address, 0);
	if (error)
		return error;
	return kpm_unload(name);
}

static int kpm_info_to_user(u64 name_address, u64 buffer_address)
{
	char name[KPM_NAME_LEN];
	char buffer[KPM_INFO_BUF_LEN];
	size_t written;
	int error;

	if (!buffer_address)
		return -EFAULT;
	error = kpm_copy_user_string(name, sizeof(name), name_address, 0);
	if (error)
		return error;
	error = kpm_info(name, buffer, sizeof(buffer), &written);
	if (error)
		return error;
	if (copy_to_user((void __user *)(unsigned long)buffer_address, buffer,
			 written + 1))
		return -EFAULT;
	return 0;
}

static int kpm_list_to_user(u64 buffer_address, u64 requested_size)
{
	char buffer[KPM_LIST_BUF_LEN];
	size_t size;
	size_t written;
	int error;

	if (!buffer_address || !requested_size ||
	    requested_size > sizeof(buffer))
		return -EINVAL;
	size = requested_size;
	error = kpm_list(buffer, size, &written);
	if (error)
		return error;
	if (copy_to_user((void __user *)(unsigned long)buffer_address, buffer,
			 written + 1))
		return -EFAULT;
	return (int)written;
}

static int kpm_control_from_user(u64 name_address, u64 args_address)
{
	char name[KPM_NAME_LEN];
	char args[KPM_ARGS_LEN];
	int error;

	error = kpm_copy_user_string(name, sizeof(name), name_address, 0);
	if (error)
		return error;
	error = kpm_copy_user_string(args, sizeof(args), args_address, 1);
	if (error)
		return error;
	return kpm_control(name, args);
}
static int kpm_control_ex_from_user(u64 command_address)
{
	struct ksu_kpm_control_ex_cmd command;
	char name[KPM_NAME_LEN];
	char args[KPM_ARGS_LEN];
	int error;

	if (!command_address ||
	    copy_from_user(&command, (void __user *)(unsigned long)command_address,
			   sizeof(command)))
		return -EFAULT;
	if (command.reserved || command.outlen > INT_MAX ||
	    (command.outlen && !command.out_msg))
		return -EINVAL;
	error = kpm_copy_user_string(name, sizeof(name), command.name, 0);
	if (error)
		return error;
	error = kpm_copy_user_string(args, sizeof(args), command.args, 1);
	if (error)
		return error;
	return kpm_control_ex(name, args,
		(char __user *)(unsigned long)command.out_msg,
		command.outlen);
}

static int kpm_control1_from_user(u64 command_address)
{
	struct ksu_kpm_control1_cmd command;
	char name[KPM_NAME_LEN];
	int error;

	if (!command_address ||
	    copy_from_user(&command, (void __user *)(unsigned long)command_address,
			   sizeof(command)))
		return -EFAULT;
	error = kpm_copy_user_string(name, sizeof(name), command.name, 0);
	if (error)
		return error;
	return kpm_control1(name, (void *)(unsigned long)command.arg1,
			    (void *)(unsigned long)command.arg2,
			    (void *)(unsigned long)command.arg3);
}

static int kpm_version_to_user(u64 buffer_address, u64 requested_size)
{
	char buffer[KPM_INFO_BUF_LEN];
	size_t size;
	size_t written;
	int error;

	if (!buffer_address || !requested_size)
		return -EINVAL;
	size = (size_t)min_t(u64, requested_size, sizeof(buffer));
	error = kpm_version(buffer, size, &written);
	if (error)
		return error;
	if (copy_to_user((void __user *)(unsigned long)buffer_address, buffer,
			 written + 1))
		return -EFAULT;
	return 0;
}

static int kpm_dispatch(int operation, u64 arg1, u64 arg2)
{
	if (operation == SUKISU_KPM_LOAD)
		return kpm_load_from_user(arg1, arg2);
	if (operation == SUKISU_KPM_UNLOAD)
		return kpm_unload_from_user(arg1);
	if (operation == SUKISU_KPM_NUM)
		return kpm_num();
	if (operation == SUKISU_KPM_LIST)
		return kpm_list_to_user(arg1, arg2);
	if (operation == SUKISU_KPM_INFO)
		return kpm_info_to_user(arg1, arg2);
	if (operation == SUKISU_KPM_CONTROL_EX)
		return kpm_control_ex_from_user(arg1);
	if (operation == SUKISU_KPM_CONTROL1)
		return kpm_control1_from_user(arg1);
	if (operation == SUKISU_KPM_CONTROL)
		return kpm_control_from_user(arg1, arg2);
	if (operation == SUKISU_KPM_VERSION)
		return kpm_version_to_user(arg1, arg2);
	return -EINVAL;
}

int do_kpm(void __user *arg)
{
	struct ksu_kpm_cmd command;
	int __user *operation_pointer;
	int __user *result_pointer;
	int operation;
	int result;

	if (!arg || copy_from_user(&command, arg, sizeof(command)))
		return -EFAULT;
	if (!command.control_code || !command.result_code)
		return -EFAULT;
	operation_pointer = (int __user *)(unsigned long)command.control_code;
	result_pointer = (int __user *)(unsigned long)command.result_code;
	if (get_user(operation, operation_pointer) ||
	    put_user(0, result_pointer))
		return -EFAULT;

	result = kpm_dispatch(operation, command.arg1, command.arg2);
	if (put_user(result, result_pointer))
		return -EFAULT;
	return 0;
}
