/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "abi_symbols.h"

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

struct kpm_function_slot {
	const char *name;
	const char *kernel_symbol;
	unsigned long address;
};

static struct kpm_function_slot kpm_function_slots[] = {
	{ "printk", "printk", 0 },
	{ "kallsyms_lookup_name", "kallsyms_lookup_name", 0 },
	{ "kallsyms_on_each_symbol", "kallsyms_on_each_symbol", 0 },
	{ "kf_sprintf", "sprintf", 0 },
	{ "kf_snprintf", "snprintf", 0 },
	{ "kf_vsnprintf", "vsnprintf", 0 },
	{ "kf_strcpy", "strcpy", 0 },
	{ "kf_strncpy", "strncpy", 0 },
	{ "kf_strncat", "strncat", 0 },
	{ "kf_strcmp", "strcmp", 0 },
	{ "kf_strncmp", "strncmp", 0 },
	{ "kf_strlen", "strlen", 0 },
	{ "kf_strnlen", "strnlen", 0 },
	{ "kf_strchr", "strchr", 0 },
	{ "kf_strrchr", "strrchr", 0 },
	{ "kf_strstr", "strstr", 0 },
	{ "kf_memset", "memset", 0 },
	{ "kf_memcpy", "memcpy", 0 },
	{ "kf_memmove", "memmove", 0 },
	{ "kf_memcmp", "memcmp", 0 },
	{ "kf_kstrdup", "kstrdup", 0 },
	{ "kf_kmemdup", "kmemdup", 0 },
	{ "kf_kasprintf", "kasprintf", 0 },
	{ "kf_memchr", "memchr", 0 },
	{ "kf_strcat", "strcat", 0 },
};

unsigned long *kpm_abi_find_function_slot(const char *name,
					 const char **kernel_symbol)
{
	size_t index;

	if (!name || !kernel_symbol)
		return NULL;
	for (index = 0;
	     index < sizeof(kpm_function_slots) / sizeof(kpm_function_slots[0]);
	     index++) {
		if (!strcmp(name, kpm_function_slots[index].name)) {
			*kernel_symbol = kpm_function_slots[index].kernel_symbol;
			return &kpm_function_slots[index].address;
		}
	}
	return NULL;
}
