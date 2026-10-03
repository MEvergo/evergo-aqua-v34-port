/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __SUKISU_KPM_ARM64_RELOC_H
#define __SUKISU_KPM_ARM64_RELOC_H

#ifdef __KERNEL__
#include <linux/elf.h>
#include <linux/types.h>
typedef u32 kpm_arm64_word_t;
typedef unsigned long kpm_arm64_addr_t;
typedef long kpm_arm64_addend_t;
#else
#include <elf.h>
#include <stddef.h>
#include <stdint.h>
typedef uint32_t kpm_arm64_word_t;
typedef uintptr_t kpm_arm64_addr_t;
typedef int64_t kpm_arm64_addend_t;
#endif

struct kpm_arm64_plt_pool {
	kpm_arm64_word_t *words;
	kpm_arm64_addr_t address;
	size_t capacity;
	size_t used;
};

int kpm_arm64_apply_rela(void *place, kpm_arm64_addr_t place_address,
			 unsigned int type, kpm_arm64_addr_t symbol_address,
			 kpm_arm64_addend_t addend,
			 struct kpm_arm64_plt_pool *plt);

#endif
