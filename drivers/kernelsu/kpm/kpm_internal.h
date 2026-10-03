/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __SUKISU_KPM_INTERNAL_H
#define __SUKISU_KPM_INTERNAL_H

#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include "kpm_elf.h"

#define KPM_NAME_LEN 32
#define KPM_VERSION_LEN 32
#define KPM_LICENSE_LEN 32
#define KPM_AUTHOR_LEN 32
#define KPM_DESCRIPTION_LEN 512
#define KPM_ARGS_LEN 1024
#define KPM_INFO_BUF_LEN 256
#define KPM_LIST_BUF_LEN 1024
#define KPM_MAX_ELF_SIZE (32UL * 1024 * 1024)
#define KPM_MAX_IMAGE_SIZE (32UL * 1024 * 1024)
#define KPM_MAX_HOTPATCHES 64

/* This identifies the in-vmlinux adapter, not a KernelPatch release. */
#define KPM_NATIVE_ABI_VERSION 1

struct kpm_module;

typedef long (*kpm_initcall_t)(const char *args, const char *event,
			       void *reserved);
typedef long (*kpm_exitcall_t)(void *reserved);
typedef long (*kpm_ctl0call_t)(const char *ctl_args,
			       char __user *out_msg, int outlen);
typedef long (*kpm_ctl1call_t)(void *arg1, void *arg2, void *arg3);

enum kpm_module_state {
	KPM_MODULE_LOADING,
	KPM_MODULE_LIVE,
	KPM_MODULE_UNLOADING,
	KPM_MODULE_FAILED,
};

struct kpm_owned_patch {
	struct list_head module_node;
	struct list_head all_node;
	struct kpm_module *owner;
	void *address;
	u32 original;
	u32 installed;
};

struct kpm_module {
	struct list_head node;
	struct list_head owned_patches;
	struct mutex control_lock;
	atomic_t active_calls;
	wait_queue_head_t active_wait;
	enum kpm_module_state state;
	bool init_succeeded;
	bool init_failed;
	bool exit_called;
	bool exit_failed;
	bool ever_patched; /* Patched code may still be executing this image. */
	char name[KPM_NAME_LEN];
	char version[KPM_VERSION_LEN];
	char license[KPM_LICENSE_LEN];
	char author[KPM_AUTHOR_LEN];
	char description[KPM_DESCRIPTION_LEN];
	char args[KPM_ARGS_LEN];
	void *image;
	size_t image_size;
	size_t text_size;
	size_t ro_offset;
	size_t ro_size;
	size_t data_offset;
	size_t data_size;
	int text_pages;
	int total_pages;
	kpm_initcall_t init;
	kpm_exitcall_t exit;
	kpm_ctl0call_t ctl0;
	kpm_ctl1call_t ctl1;
};

int kpm_load_path(const char *path, const char *args);
int kpm_unload(const char *name);
int kpm_num(void);
int kpm_list(char *buffer, size_t size, size_t *written);
int kpm_info(const char *name, char *buffer, size_t size, size_t *written);
int kpm_control(const char *name, const char *args);
int kpm_version(char *buffer, size_t size, size_t *written);
int kpm_control_ex(const char *name, const char *args,
		   char __user *out_msg, int outlen);
int kpm_control1(const char *name, void *arg1, void *arg2, void *arg3);
bool kpm_module_try_get_rcu(struct kpm_module *module);
void kpm_module_put(struct kpm_module *module);
void kpm_hook_remove_owner(struct kpm_module *module);

unsigned long kpm_compat_resolve(const char *name);
struct kpm_module *kpm_current_module(void);
int kpm_compat_hotpatch(void **addresses, u32 *values, int count);

#endif
