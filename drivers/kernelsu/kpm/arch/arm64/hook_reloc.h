/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __SUKISU_KPM_ARM64_HOOK_RELOC_H
#define __SUKISU_KPM_ARM64_HOOK_RELOC_H

#ifdef __KERNEL__
#include <linux/stddef.h>
#include <linux/types.h>
typedef u32 kpm_hook_insn_t;
typedef u64 kpm_hook_addr_t;
#else
#include <stddef.h>
#include <stdint.h>
typedef uint32_t kpm_hook_insn_t;
typedef uint64_t kpm_hook_addr_t;
#endif

#define KPM_ARM64_HOOK_PATCH_WORDS 4
#define KPM_ARM64_HOOK_RELOC_MAX_WORDS 36

int kpm_arm64_relocate_hook(
	const kpm_hook_insn_t *source, kpm_hook_addr_t source_address,
	unsigned int source_words, kpm_hook_insn_t *relocated,
	kpm_hook_addr_t relocated_address, size_t relocated_capacity_words,
	size_t *relocated_words);

#endif
