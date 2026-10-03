/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "kpm_elf.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

#define KPM_ELF_MAX_SECTIONS 4096

static int kpm_elf_range_valid(size_t image_size, Elf64_Off offset,
			       Elf64_Xword size)
{
	if (offset > image_size || size > image_size - (size_t)offset)
		return 0;
	return 1;
}

static int kpm_elf_get_string(const char *table, size_t table_size,
			      Elf64_Word offset, const char **string)
{
	if (offset >= table_size ||
	    !memchr(table + offset, '\0', table_size - offset))
		return -ENOEXEC;

	*string = table + offset;
	return 0;
}

static int kpm_elf_valid_string_table(const char *table, size_t table_size)
{
	if (!table_size || table[0] != '\0' || table[table_size - 1] != '\0')
		return 0;
	return 1;
}

static int kpm_elf_set_kpm_section(struct kpm_elf_view *view,
				   const char *name, unsigned int index,
				   const Elf64_Shdr *section)
{
	kpm_elf_u32 *slot = NULL;

	if (strcmp(name, ".kpm.info") == 0)
		slot = &view->section_info;
	else if (strcmp(name, ".kpm.init") == 0)
		slot = &view->section_init;
	else if (strcmp(name, ".kpm.exit") == 0)
		slot = &view->section_exit;
	else if (strcmp(name, ".kpm.ctl0") == 0)
		slot = &view->section_ctl0;
	else if (strcmp(name, ".kpm.ctl1") == 0)
		slot = &view->section_ctl1;
	else if (strcmp(name, ".kpm.event") == 0)
		slot = &view->section_event;

	if (!slot)
		return 0;
	if (*slot || section->sh_type != SHT_PROGBITS ||
	    !(section->sh_flags & SHF_ALLOC))
		return -ENOEXEC;
	if (strcmp(name, ".kpm.info") == 0) {
		if (!section->sh_size ||
		    (section->sh_flags & SHF_EXECINSTR) ||
		    view->image[section->sh_offset + section->sh_size - 1] != '\0')
			return -ENOEXEC;
	} else if (section->sh_size != sizeof(Elf64_Addr) ||
		   section->sh_addralign < __alignof__(Elf64_Addr) ||
		   (section->sh_flags & SHF_EXECINSTR)) {
		return -ENOEXEC;
	}

	*slot = index;
	return 0;
}

int kpm_elf_parse(const void *image, size_t image_size,
		  struct kpm_elf_view *view)
{
	const unsigned char *bytes = image;
	const Elf64_Ehdr *ehdr;
	const Elf64_Shdr *sections;
	const Elf64_Shdr *shstr_section;
	const Elf64_Shdr *str_section;
	const Elf64_Shdr *sym_section;
	const Elf64_Sym *symbols;
	const char *section_names;
	const char *strings;
	struct kpm_elf_view parsed;
	size_t section_table_size;
	unsigned int section_index;
	unsigned int symbol_index;
	unsigned int rela_index;
	int error;

	if (!image || !view || image_size < sizeof(*ehdr))
		return -ENOEXEC;

	ehdr = (const Elf64_Ehdr *)bytes;
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) ||
	    ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
	    ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
	    ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
	    ehdr->e_type != ET_REL || ehdr->e_machine != EM_AARCH64 ||
	    ehdr->e_version != EV_CURRENT ||
	    ehdr->e_ehsize != sizeof(Elf64_Ehdr) ||
	    ehdr->e_phoff || ehdr->e_phnum || ehdr->e_shentsize != sizeof(Elf64_Shdr) ||
	    !ehdr->e_shnum || ehdr->e_shnum > KPM_ELF_MAX_SECTIONS ||
	    ehdr->e_shstrndx == KPM_SHN_XINDEX ||
	    ehdr->e_shstrndx >= ehdr->e_shnum ||
	    ehdr->e_shoff % __alignof__(Elf64_Shdr))
		return -ENOEXEC;

	section_table_size = (size_t)ehdr->e_shnum * sizeof(Elf64_Shdr);
	if (!kpm_elf_range_valid(image_size, ehdr->e_shoff,
				 section_table_size))
		return -ENOEXEC;

	sections = (const Elf64_Shdr *)(bytes + ehdr->e_shoff);
	if (sections[0].sh_type != SHT_NULL)
		return -ENOEXEC;
	shstr_section = &sections[ehdr->e_shstrndx];
	if (shstr_section->sh_type != SHT_STRTAB ||
	    !kpm_elf_range_valid(image_size, shstr_section->sh_offset,
				 shstr_section->sh_size))
		return -ENOEXEC;
	section_names = (const char *)bytes + shstr_section->sh_offset;
	if (!kpm_elf_valid_string_table(section_names,
					shstr_section->sh_size))
		return -ENOEXEC;

	memset(&parsed, 0, sizeof(parsed));
	parsed.image = bytes;
	parsed.image_size = image_size;
	parsed.ehdr = ehdr;
	parsed.sections = sections;
	parsed.section_names = section_names;
	parsed.section_names_size = shstr_section->sh_size;
	parsed.section_symtab = 0;
	parsed.section_strtab = 0;
	str_section = NULL;
	sym_section = NULL;

	for (section_index = 1; section_index < ehdr->e_shnum;
	     section_index++) {
		const Elf64_Shdr *section = &sections[section_index];
		const char *name;

		error = kpm_elf_get_string(section_names,
					   shstr_section->sh_size,
					   section->sh_name, &name);
		if (error)
			return error;
		if (section->sh_addralign &&
		    (section->sh_addralign & (section->sh_addralign - 1)))
			return -ENOEXEC;
		if (section->sh_type != SHT_NOBITS &&
		    !kpm_elf_range_valid(image_size, section->sh_offset,
					 section->sh_size))
			return -ENOEXEC;
		if (section->sh_type == SHT_REL)
			return -ENOEXEC;

		if (section->sh_type == SHT_SYMTAB) {
			if (sym_section ||
			    section->sh_entsize != sizeof(Elf64_Sym) ||
			    section->sh_addralign < __alignof__(Elf64_Sym) ||
			    section->sh_offset % __alignof__(Elf64_Sym) ||
			    !section->sh_size ||
			    section->sh_size % sizeof(Elf64_Sym) ||
			    section->sh_link >= ehdr->e_shnum)
				return -ENOEXEC;
			sym_section = section;
			parsed.section_symtab = section_index;
			str_section = &sections[section->sh_link];
			parsed.section_strtab = section->sh_link;
			if (str_section->sh_type != SHT_STRTAB ||
			    !kpm_elf_range_valid(image_size, str_section->sh_offset,
						 str_section->sh_size))
				return -ENOEXEC;
		}

		error = kpm_elf_set_kpm_section(&parsed, name, section_index,
						section);
		if (error)
			return error;
	}

	if (!sym_section || !str_section || !parsed.section_info ||
	    !parsed.section_init || !parsed.section_exit ||
	    !kpm_elf_valid_string_table(
		(const char *)bytes + str_section->sh_offset,
		str_section->sh_size))
		return -ENOEXEC;

	strings = (const char *)bytes + str_section->sh_offset;
	symbols = (const Elf64_Sym *)(bytes + sym_section->sh_offset);
	parsed.strings = strings;
	parsed.strings_size = str_section->sh_size;
	parsed.symbols = symbols;
	parsed.symbol_count = sym_section->sh_size / sizeof(Elf64_Sym);
	if (sym_section->sh_info > parsed.symbol_count)
		return -ENOEXEC;

	for (symbol_index = 0; symbol_index < parsed.symbol_count;
	     symbol_index++) {
		const Elf64_Sym *symbol = &symbols[symbol_index];
		const char *symbol_name;

		error = kpm_elf_get_string(strings, str_section->sh_size,
					   symbol->st_name, &symbol_name);
		if (error || symbol->st_shndx == KPM_SHN_XINDEX)
			return -ENOEXEC;
		if (symbol->st_shndx != SHN_UNDEF &&
		    symbol->st_shndx != SHN_ABS &&
		    (symbol->st_shndx >= SHN_LORESERVE ||
		     symbol->st_shndx >= ehdr->e_shnum))
			return -ENOEXEC;
	}

	for (rela_index = 1; rela_index < ehdr->e_shnum; rela_index++) {
		const Elf64_Shdr *rela = &sections[rela_index];
		const Elf64_Shdr *target;
		const Elf64_Rela *relocations;
		size_t relocation_count;
		size_t i;

		if (rela->sh_type != SHT_RELA)
			continue;
		if (rela->sh_entsize != sizeof(Elf64_Rela) ||
		    rela->sh_offset % __alignof__(Elf64_Rela) ||
		    rela->sh_addralign < __alignof__(Elf64_Rela) ||
		    rela->sh_size % sizeof(Elf64_Rela) ||
		    rela->sh_link != parsed.section_symtab ||
		    !rela->sh_info || rela->sh_info >= ehdr->e_shnum)
			return -ENOEXEC;
		target = &sections[rela->sh_info];
		relocations = (const Elf64_Rela *)(bytes + rela->sh_offset);
		relocation_count = rela->sh_size / sizeof(Elf64_Rela);
		for (i = 0; i < relocation_count; i++) {
			if (ELF64_R_SYM(relocations[i].r_info) >=
			    parsed.symbol_count)
				return -ENOEXEC;
			if (relocations[i].r_offset >= target->sh_size &&
			    target->sh_size)
				return -ENOEXEC;
		}
	}

	*view = parsed;
	return 0;
}

int kpm_elf_materialize(const struct kpm_elf_view *view,
			const size_t *section_offsets, size_t image_size,
			void *destination)
{
	unsigned int index;

	if (!view || !view->ehdr || !view->sections || !view->image ||
	    !section_offsets || !image_size || !destination)
		return -EINVAL;
	for (index = 1; index < view->ehdr->e_shnum; index++) {
		const Elf64_Shdr *section = &view->sections[index];
		size_t offset = section_offsets[index];

		if (!(section->sh_flags & SHF_ALLOC) || !section->sh_size)
			continue;
		if (section->sh_type != SHT_PROGBITS &&
		    section->sh_type != SHT_NOBITS)
			return -ENOEXEC;
		if (offset == KPM_ELF_NO_OFFSET || offset > image_size ||
		    section->sh_size > image_size - offset)
			return -ENOEXEC;
		if (section->sh_type == SHT_PROGBITS &&
		    (section->sh_offset > view->image_size ||
		     section->sh_size > view->image_size - section->sh_offset))
			return -ENOEXEC;
	}

	memset(destination, 0, image_size);
	for (index = 1; index < view->ehdr->e_shnum; index++) {
		const Elf64_Shdr *section = &view->sections[index];

		if (!(section->sh_flags & SHF_ALLOC) ||
		    section->sh_type != SHT_PROGBITS || !section->sh_size)
			continue;
		memcpy((char *)destination + section_offsets[index],
		       view->image + section->sh_offset, section->sh_size);
	}
	return 0;
}
