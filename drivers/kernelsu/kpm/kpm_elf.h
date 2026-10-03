/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __SUKISU_KPM_ELF_H
#define __SUKISU_KPM_ELF_H

#ifdef __KERNEL__
#include <linux/elf.h>
#include <linux/types.h>
typedef u32 kpm_elf_u32;
#else
#include <elf.h>
#include <stddef.h>
#include <stdint.h>
typedef uint32_t kpm_elf_u32;
#endif

struct kpm_elf_view {
	const unsigned char *image;
	size_t image_size;
	const Elf64_Ehdr *ehdr;
	const Elf64_Shdr *sections;
	const char *section_names;
	size_t section_names_size;
	const char *strings;
	size_t strings_size;
	const Elf64_Sym *symbols;
	size_t symbol_count;
	kpm_elf_u32 section_info;
	kpm_elf_u32 section_init;
	kpm_elf_u32 section_exit;
	kpm_elf_u32 section_ctl0;
	kpm_elf_u32 section_ctl1;
	kpm_elf_u32 section_event;
	kpm_elf_u32 section_symtab;
	kpm_elf_u32 section_strtab;
};

#define KPM_ELF_NO_OFFSET ((size_t)-1)
/* SHF_TLS is not exposed by the kernel's linux/elf.h. */
#define KPM_SHF_TLS 0x400
/* SHN_XINDEX is likewise missing from the kernel's linux/elf.h. */
#define KPM_SHN_XINDEX 0xffff
int kpm_elf_materialize(const struct kpm_elf_view *view,
		       const size_t *section_offsets, size_t image_size,
		       void *destination);
int kpm_elf_parse(const void *image, size_t image_size,
		  struct kpm_elf_view *view);

#endif
