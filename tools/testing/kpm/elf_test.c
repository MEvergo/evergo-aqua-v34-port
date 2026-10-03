#include <elf.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../../drivers/kernelsu/kpm/kpm_elf.h"

#define FIXTURE_SIZE 4096
#define SECTION_COUNT 11

struct fixture {
	unsigned char data[FIXTURE_SIZE];
	size_t size;
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *sections;
};

static const char section_names[] =
	"\0.shstrtab\0.strtab\0.symtab\0.kpm.info\0.text\0.kpm.init\0"
	".kpm.exit\0.rela.kpm.init\0.rela.kpm.exit\0.bss\0";
static const char symbol_names[] = "\0kpm_init_handler\0kpm_exit_handler\0";
static const char kpm_info[] =
	"name=native-hello\0version=1.0\0license=GPL v2\0"
	"author=test\0description=parser fixture\0";

static size_t align_up(size_t value, size_t alignment)
{
	return (value + alignment - 1) & ~(alignment - 1);
}

static size_t append(struct fixture *fixture, const void *data, size_t size,
		     size_t alignment)
{
	size_t offset = align_up(fixture->size, alignment);

	if (offset + size > sizeof(fixture->data))
		return 0;
	memcpy(fixture->data + offset, data, size);
	fixture->size = offset + size;
	return offset;
}

static void misalign_section_data(struct fixture *fixture, size_t offset)
{
	size_t old_shoff = fixture->ehdr->e_shoff;
	size_t table_size = fixture->ehdr->e_shnum * sizeof(Elf64_Shdr);
	unsigned int i;

	memmove(fixture->data + old_shoff + 8, fixture->data + old_shoff,
		table_size);
	memmove(fixture->data + offset + 1, fixture->data + offset,
		old_shoff - offset);
	fixture->size += 8;
	fixture->ehdr->e_shoff = old_shoff + 8;
	fixture->sections = (Elf64_Shdr *)(fixture->data +
					   fixture->ehdr->e_shoff);
	for (i = 1; i < fixture->ehdr->e_shnum; i++) {
		if (fixture->sections[i].sh_type != SHT_NOBITS &&
		    fixture->sections[i].sh_offset >= offset)
			fixture->sections[i].sh_offset++;
	}
}

static size_t find_string(const char *table, size_t table_size,
			  const char *name)
{
	size_t offset;

	for (offset = 0; offset < table_size; offset++) {
		if (!strcmp(table + offset, name))
			return offset;
	}
	return 0;
}

static void set_section(struct fixture *fixture, Elf64_Shdr *sections,
			unsigned int index, const char *name, uint32_t type,
			uint64_t flags, uint64_t alignment, const void *data,
			size_t size, uint32_t link, uint32_t info,
			uint64_t entsize)
{
	Elf64_Shdr *section = &sections[index];

	section->sh_name = find_string(section_names, sizeof(section_names), name);
	section->sh_type = type;
	section->sh_flags = flags;
	section->sh_addralign = alignment;
	section->sh_size = size;
	section->sh_link = link;
	section->sh_info = info;
	section->sh_entsize = entsize;
	if (type != SHT_NOBITS)
		section->sh_offset = append(fixture, data, size,
					    alignment ? alignment : 1);
}

static int build_fixture(struct fixture *fixture)
{
	static const uint32_t text[] = { 0xd503201f };
	static const uint64_t callback_slot;
	Elf64_Shdr sections[SECTION_COUNT] = { 0 };
	Elf64_Sym symbols[3] = { 0 };
	Elf64_Rela init_rela = { 0 };
	Elf64_Rela exit_rela = { 0 };
	uint64_t shoff;

	memset(fixture, 0, sizeof(*fixture));
	fixture->size = sizeof(Elf64_Ehdr);
	fixture->ehdr = (Elf64_Ehdr *)fixture->data;

	symbols[1].st_name = find_string(symbol_names, sizeof(symbol_names),
					 "kpm_init_handler");
	symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
	symbols[1].st_shndx = 5;
	symbols[1].st_size = sizeof(text);
	symbols[2].st_name = find_string(symbol_names, sizeof(symbol_names),
					 "kpm_exit_handler");
	symbols[2].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
	symbols[2].st_shndx = 5;
	symbols[2].st_size = sizeof(text);
	init_rela.r_info = ELF64_R_INFO(1, R_AARCH64_ABS64);
	exit_rela.r_info = ELF64_R_INFO(2, R_AARCH64_ABS64);

	set_section(fixture, sections, 1, ".shstrtab", SHT_STRTAB, 0, 1,
		    section_names, sizeof(section_names), 0, 0, 0);
	set_section(fixture, sections, 2, ".strtab", SHT_STRTAB, 0, 1,
		    symbol_names, sizeof(symbol_names), 0, 0, 0);
	set_section(fixture, sections, 3, ".symtab", SHT_SYMTAB, 0, 8,
		    symbols, sizeof(symbols), 2, 1, sizeof(Elf64_Sym));
	set_section(fixture, sections, 4, ".kpm.info", SHT_PROGBITS,
		    SHF_ALLOC, 1, kpm_info, sizeof(kpm_info), 0, 0, 0);
	set_section(fixture, sections, 5, ".text", SHT_PROGBITS,
		    SHF_ALLOC | SHF_EXECINSTR, 4, text, sizeof(text), 0, 0, 0);
	set_section(fixture, sections, 6, ".kpm.init", SHT_PROGBITS,
		    SHF_ALLOC | SHF_WRITE, 8, &callback_slot,
		    sizeof(callback_slot), 0, 0, 8);
	set_section(fixture, sections, 7, ".kpm.exit", SHT_PROGBITS,
		    SHF_ALLOC | SHF_WRITE, 8, &callback_slot,
		    sizeof(callback_slot), 0, 0, 8);
	set_section(fixture, sections, 8, ".rela.kpm.init", SHT_RELA, 0, 8,
		    &init_rela, sizeof(init_rela), 3, 6, sizeof(Elf64_Rela));
	set_section(fixture, sections, 9, ".rela.kpm.exit", SHT_RELA, 0, 8,
		    &exit_rela, sizeof(exit_rela), 3, 7, sizeof(Elf64_Rela));
	set_section(fixture, sections, 10, ".bss", SHT_NOBITS,
		    SHF_ALLOC | SHF_WRITE, 16, NULL, 32, 0, 0, 0);

	shoff = append(fixture, sections, sizeof(sections), 8);
	if (!shoff)
		return -1;
	fixture->sections = (Elf64_Shdr *)(fixture->data + shoff);
	fixture->size = (size_t)shoff + sizeof(sections);
	memset(fixture->ehdr, 0, sizeof(*fixture->ehdr));
	memcpy(fixture->ehdr->e_ident, ELFMAG, SELFMAG);
	fixture->ehdr->e_ident[EI_CLASS] = ELFCLASS64;
	fixture->ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	fixture->ehdr->e_ident[EI_VERSION] = EV_CURRENT;
	fixture->ehdr->e_type = ET_REL;
	fixture->ehdr->e_machine = EM_AARCH64;
	fixture->ehdr->e_version = EV_CURRENT;
	fixture->ehdr->e_ehsize = sizeof(Elf64_Ehdr);
	fixture->ehdr->e_shoff = shoff;
	fixture->ehdr->e_shentsize = sizeof(Elf64_Shdr);
	fixture->ehdr->e_shnum = SECTION_COUNT;
	fixture->ehdr->e_shstrndx = 1;
	return 0;
}

static int expect_rejected(struct fixture *fixture, const char *case_name)
{
	struct kpm_elf_view view;
	int error = kpm_elf_parse(fixture->data, fixture->size, &view);

	if (!error) {
		fprintf(stderr, "FAIL: accepted malformed ELF (%s)\n", case_name);
		return -1;
	}
	return 0;
}

int main(void)
{
	struct fixture fixture;
	struct kpm_elf_view view;
	Elf64_Sym *symbols;
	Elf64_Half saved_symbol_section;
	size_t section_offsets[SECTION_COUNT];
	unsigned char materialized[256];
	size_t i;
	uint64_t saved;

	if (build_fixture(&fixture)) {
		fprintf(stderr, "FAIL: fixture construction\n");
		return 1;
	}
	if (kpm_elf_parse(fixture.data, fixture.size, &view)) {
		fprintf(stderr, "FAIL: rejected valid AArch64 KPM ELF\n");
		return 1;
	}
	if (view.section_info != 4 || view.section_init != 6 ||
	    view.section_exit != 7 || view.section_symtab != 3 ||
	    view.section_strtab != 2) {
		fprintf(stderr, "FAIL: parsed section indexes are incorrect\n");
		return 1;
	}
	if (fixture.sections[6].sh_flags & SHF_EXECINSTR) {
		fprintf(stderr, "FAIL: callback pointer section fixture is executable\n");
		return 1;
	}
	for (i = 0; i < SECTION_COUNT; i++)
		section_offsets[i] = KPM_ELF_NO_OFFSET;
	section_offsets[4] = 0;
	section_offsets[5] = 128;
	section_offsets[6] = 160;
	section_offsets[7] = 168;
	section_offsets[10] = 192;
	memset(materialized, 0xa5, sizeof(materialized));
	if (kpm_elf_materialize(&view, section_offsets, sizeof(materialized),
			       materialized)) {
		fprintf(stderr, "FAIL: materializing valid ELF sections\n");
		return 1;
	}
	if (memcmp(materialized, fixture.data + fixture.sections[4].sh_offset,
		    fixture.sections[4].sh_size) ||
	    memcmp(materialized + 128,
		   fixture.data + fixture.sections[5].sh_offset,
		   fixture.sections[5].sh_size)) {
		fprintf(stderr, "FAIL: PROGBITS sections were not copied\n");
		return 1;
	}
	for (i = sizeof(kpm_info); i < 128; i++) {
		if (materialized[i]) {
			fprintf(stderr, "FAIL: section alignment gap was not zero\n");
			return 1;
		}
	}
	for (i = 132; i < 160; i++) {
		if (materialized[i]) {
			fprintf(stderr, "FAIL: callback alignment gap was not zero\n");
			return 1;
		}
	}
	for (i = 176; i < 192; i++) {
		if (materialized[i]) {
			fprintf(stderr, "FAIL: BSS alignment gap was not zero\n");
			return 1;
		}
	}
	for (i = 224; i < sizeof(materialized); i++) {
		if (materialized[i]) {
			fprintf(stderr, "FAIL: image tail was not zero\n");
			return 1;
		}
	}
	for (i = 192; i < 224; i++) {
		if (materialized[i]) {
			fprintf(stderr, "FAIL: SHT_NOBITS storage was not zero\n");
			return 1;
		}
	}
	section_offsets[5] = (size_t)-1;
	memset(materialized, 0xa5, sizeof(materialized));
	if (kpm_elf_materialize(&view, section_offsets,
				sizeof(materialized), materialized) != -ENOEXEC) {
		fprintf(stderr, "FAIL: invalid materialization offset accepted\n");
		return 1;
	}
	for (i = 0; i < sizeof(materialized); i++) {
		if (materialized[i] != 0xa5) {
			fprintf(stderr, "FAIL: invalid layout modified destination\n");
			return 1;
		}
	}
	section_offsets[5] = 128;
	section_offsets[10] = (size_t)-1;
	memset(materialized, 0xa5, sizeof(materialized));
	if (kpm_elf_materialize(&view, section_offsets,
				sizeof(materialized), materialized) != -ENOEXEC ||
	    materialized[0] != 0xa5) {
		fprintf(stderr, "FAIL: invalid BSS layout was accepted or copied\n");
		return 1;
	}
	section_offsets[10] = 192;

	saved = fixture.ehdr->e_type;
	fixture.ehdr->e_type = ET_DYN;
	if (expect_rejected(&fixture, "ET_DYN"))
		return 1;
	fixture.ehdr->e_type = saved;

	saved = fixture.ehdr->e_machine;
	fixture.ehdr->e_machine = EM_X86_64;
	if (expect_rejected(&fixture, "wrong architecture"))
		return 1;
	fixture.ehdr->e_machine = saved;
	saved = fixture.sections[7].sh_name;
	fixture.sections[7].sh_name =
		find_string(section_names, sizeof(section_names), ".text");
	if (expect_rejected(&fixture, "missing .kpm.exit"))
		return 1;
	fixture.sections[7].sh_name = saved;

	saved = fixture.sections[5].sh_name;
	fixture.sections[5].sh_name =
		find_string(section_names, sizeof(section_names), ".kpm.info");
	if (expect_rejected(&fixture, "duplicate .kpm.info"))
		return 1;
	fixture.sections[5].sh_name = saved;

	saved = fixture.sections[8].sh_type;
	fixture.sections[8].sh_type = SHT_REL;
	if (expect_rejected(&fixture, "SHT_REL"))
		return 1;
	fixture.sections[8].sh_type = saved;

	saved = fixture.ehdr->e_shoff;
	fixture.ehdr->e_shoff = fixture.size - sizeof(Elf64_Shdr);
	if (expect_rejected(&fixture, "truncated section table"))
		return 1;
	fixture.ehdr->e_shoff = saved;

	saved = fixture.sections[8].sh_info;
	fixture.sections[8].sh_info = UINT32_MAX;
	if (expect_rejected(&fixture, "invalid relocation target"))
		return 1;
	fixture.sections[8].sh_info = saved;

	symbols = (Elf64_Sym *)(fixture.data +
				fixture.sections[3].sh_offset);
	saved_symbol_section = symbols[1].st_shndx;
	symbols[1].st_shndx = SECTION_COUNT + 1;
	if (expect_rejected(&fixture, "invalid symbol section index"))
		return 1;

	symbols[1].st_shndx = saved_symbol_section;
	saved = fixture.sections[5].sh_flags;
	fixture.sections[5].sh_flags &= ~SHF_ALLOC;
	{
		Elf64_Word saved_target = fixture.sections[8].sh_info;

		fixture.sections[8].sh_info = 5;
		if (kpm_elf_parse(fixture.data, fixture.size, &view)) {
			fprintf(stderr,
				"FAIL: rejected relocation against non-alloc debug section\n");
			return 1;
		}
		fixture.sections[8].sh_info = saved_target;
	}
	fixture.sections[5].sh_flags = saved;

	saved = fixture.sections[2].sh_addralign;
	fixture.sections[2].sh_addralign = 0;
	if (kpm_elf_parse(fixture.data, fixture.size, &view)) {
		fprintf(stderr, "FAIL: rejected zero section alignment\n");
		return 1;
	}
	fixture.sections[2].sh_addralign = saved;


	saved = fixture.sections[4].sh_name;
	fixture.sections[4].sh_name = UINT32_MAX;
	if (expect_rejected(&fixture, "invalid section name offset"))
		return 1;
	fixture.sections[4].sh_name = saved;
	misalign_section_data(&fixture, fixture.sections[3].sh_offset);
	if (expect_rejected(&fixture, "misaligned symbol table"))
		return 1;

	puts("ELF parser tests passed");
	return 0;
}
