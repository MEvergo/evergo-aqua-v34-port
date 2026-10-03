/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "reloc.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

enum kpm_reloc_math {
	KPM_RELOC_ABS,
	KPM_RELOC_PREL,
	KPM_RELOC_PAGE,
};

enum kpm_movw_mode {
	KPM_MOVW_UABS,
	KPM_MOVW_SABS,
	KPM_MOVW_PREL,
	KPM_MOVW_PREL_NC,
};

enum kpm_imm_field {
	KPM_IMM_14,
	KPM_IMM_19,
	KPM_IMM_26,
	KPM_IMM_ADR21,
	KPM_IMM_12,
};

static int kpm_add_addend(kpm_arm64_addr_t symbol,
			  kpm_arm64_addend_t addend,
			  kpm_arm64_addr_t *value)
{
	kpm_arm64_addr_t magnitude;

	if (addend < 0) {
		magnitude = (kpm_arm64_addr_t)(-(addend + 1)) + 1;
		if (symbol < magnitude)
			return -ERANGE;
		*value = symbol - magnitude;
	} else {
		magnitude = (kpm_arm64_addr_t)addend;
		if (symbol > ~(kpm_arm64_addr_t)0 - magnitude)
			return -ERANGE;
		*value = symbol + magnitude;
	}
	return 0;
}

static int kpm_fits_signed(long value, unsigned int bits)
{
	long minimum = -((long)1 << (bits - 1));
	long maximum = ((long)1 << (bits - 1)) - 1;

	return value >= minimum && value <= maximum;
}

static unsigned int kpm_load_word(const void *place)
{
	unsigned int word;

	memcpy(&word, place, sizeof(word));
	return word;
}

static void kpm_store_word(void *place, unsigned int word)
{
	memcpy(place, &word, sizeof(word));
}

static int kpm_instruction_place_aligned(
	const void *place, kpm_arm64_addr_t place_address)
{
	return !(((unsigned long)place | place_address) & 3);
}

static int kpm_apply_data_rela(void *place, kpm_arm64_addr_t place_address,
			       kpm_arm64_addr_t value, unsigned int type)
{
	unsigned long long wide;
	unsigned int word;
	unsigned short half;
	long delta;

	switch (type) {
	case R_AARCH64_ABS64:
		wide = value;
		memcpy(place, &wide, sizeof(wide));
		return 0;
	case R_AARCH64_PREL64:
		wide = value - place_address;
		memcpy(place, &wide, sizeof(wide));
		return 0;
	case R_AARCH64_ABS32:
		if (value > 0xffffffffUL)
			return -ERANGE;
		word = value;
		memcpy(place, &word, sizeof(word));
		return 0;
	case R_AARCH64_PREL32:
		delta = (long)(value - place_address);
		if (!kpm_fits_signed(delta, 32))
			return -ERANGE;
		word = (unsigned int)delta;
		memcpy(place, &word, sizeof(word));
		return 0;
	case R_AARCH64_ABS16:
		if (value > 0xffffUL)
			return -ERANGE;
		half = value;
		memcpy(place, &half, sizeof(half));
		return 0;
	case R_AARCH64_PREL16:
		delta = (long)(value - place_address);
		if (!kpm_fits_signed(delta, 16))
			return -ERANGE;
		half = (unsigned short)delta;
		memcpy(place, &half, sizeof(half));
		return 0;
	default:
		return -ENOEXEC;
	}
}

static int kpm_movw_config(unsigned int type, unsigned int *shift,
			   enum kpm_movw_mode *mode, int *check_overflow)
{
	*check_overflow = 1;
	switch (type) {
	case R_AARCH64_MOVW_UABS_G0:
		*shift = 0;
		*mode = KPM_MOVW_UABS;
		break;
	case R_AARCH64_MOVW_UABS_G0_NC:
		*shift = 0;
		*mode = KPM_MOVW_UABS;
		*check_overflow = 0;
		break;
	case R_AARCH64_MOVW_UABS_G1:
		*shift = 16;
		*mode = KPM_MOVW_UABS;
		break;
	case R_AARCH64_MOVW_UABS_G1_NC:
		*shift = 16;
		*mode = KPM_MOVW_UABS;
		*check_overflow = 0;
		break;
	case R_AARCH64_MOVW_UABS_G2:
		*shift = 32;
		*mode = KPM_MOVW_UABS;
		break;
	case R_AARCH64_MOVW_UABS_G2_NC:
		*shift = 32;
		*mode = KPM_MOVW_UABS;
		*check_overflow = 0;
		break;
	case R_AARCH64_MOVW_UABS_G3:
		*shift = 48;
		*mode = KPM_MOVW_UABS;
		*check_overflow = 0;
		break;
	case R_AARCH64_MOVW_SABS_G0:
		*shift = 0;
		*mode = KPM_MOVW_SABS;
		break;
	case R_AARCH64_MOVW_SABS_G1:
		*shift = 16;
		*mode = KPM_MOVW_SABS;
		break;
	case R_AARCH64_MOVW_SABS_G2:
		*shift = 32;
		*mode = KPM_MOVW_SABS;
		break;
	case R_AARCH64_MOVW_PREL_G0:
		*shift = 0;
		*mode = KPM_MOVW_PREL;
		break;
	case R_AARCH64_MOVW_PREL_G0_NC:
		*shift = 0;
		*mode = KPM_MOVW_PREL_NC;
		*check_overflow = 0;
		break;
	case R_AARCH64_MOVW_PREL_G1:
		*shift = 16;
		*mode = KPM_MOVW_PREL;
		break;
	case R_AARCH64_MOVW_PREL_G1_NC:
		*shift = 16;
		*mode = KPM_MOVW_PREL_NC;
		*check_overflow = 0;
		break;
	case R_AARCH64_MOVW_PREL_G2:
		*shift = 32;
		*mode = KPM_MOVW_PREL;
		break;
	case R_AARCH64_MOVW_PREL_G2_NC:
		*shift = 32;
		*mode = KPM_MOVW_PREL_NC;
		*check_overflow = 0;
		break;
	case R_AARCH64_MOVW_PREL_G3:
		*shift = 48;
		*mode = KPM_MOVW_PREL;
		*check_overflow = 0;
		break;
	default:
		return -ENOEXEC;
	}
	return 0;
}

static int kpm_apply_movw_rela(void *place,
			       kpm_arm64_addr_t place_address,
			       kpm_arm64_addr_t value, unsigned int type)
{
	enum kpm_movw_mode mode;
	unsigned int shift;
	unsigned int instruction;
	unsigned int opcode;
	unsigned int immediate;
	long signed_value;
	long shifted;
	int check_overflow;
	int error;

	error = kpm_movw_config(type, &shift, &mode, &check_overflow);
	if (error)
		return error;
	if (!kpm_instruction_place_aligned(place, place_address))
		return -EINVAL;

	instruction = kpm_load_word(place);
	if ((instruction & 0x1f800000) != 0x12800000 ||
	    ((instruction >> 21) & 3) != shift / 16)
		return -ENOEXEC;
	opcode = (instruction >> 29) & 3;
	if (mode == KPM_MOVW_UABS && opcode != 2 && opcode != 3)
		return -ENOEXEC;
	if (mode == KPM_MOVW_PREL_NC && opcode != 3)
		return -ENOEXEC;

	if (mode == KPM_MOVW_UABS) {
		if (check_overflow && (value >> (shift + 16)))
			return -ERANGE;
		immediate = (unsigned int)(value >> shift) & 0xffff;
	} else {
		if (mode == KPM_MOVW_SABS)
			signed_value = (long)value;
		else
			signed_value = (long)(value - place_address);
		shifted = signed_value >> shift;
		immediate = (unsigned int)shifted & 0xffff;
		if (mode != KPM_MOVW_PREL_NC) {
			if (check_overflow &&
			    (shifted >> 16) != (shifted < 0 ? -1 : 0))
				return -ERANGE;
			instruction &= ~(3U << 29);
			if (shifted < 0) {
				opcode = 0;
				immediate = (~immediate) & 0xffff;
			} else {
				opcode = 2;
			}
		}
	}

	instruction &= ~((3U << 29) | (0xffffU << 5));
	instruction |= (opcode << 29) | (immediate << 5);
	kpm_store_word(place, instruction);
	return 0;
}

static int kpm_branch_delta(kpm_arm64_addr_t target,
			    kpm_arm64_addr_t place_address,
			    unsigned int bits, unsigned int *immediate)
{
	long delta;
	long scaled;

	if ((target | place_address) & 3)
		return -ERANGE;
	delta = (long)(target - place_address);
	scaled = delta >> 2;
	if (!kpm_fits_signed(scaled, bits))
		return -ERANGE;
	*immediate = (unsigned int)scaled & ((1U << bits) - 1);
	return 0;
}

static int kpm_build_plt(struct kpm_arm64_plt_pool *plt,
			 kpm_arm64_addr_t target,
			 kpm_arm64_addr_t *entry_address,
			 unsigned int words[5])
{
	size_t word_offset;
	size_t byte_offset;

	if (!plt || !plt->words || plt->used >= plt->capacity ||
	    (plt->address & 3) || plt->used > (size_t)-1 / 5)
		return -ERANGE;
	word_offset = plt->used * 5;
	if (word_offset > (size_t)-1 / sizeof(*plt->words))
		return -ERANGE;
	byte_offset = word_offset * sizeof(*plt->words);
	if (plt->address > ~(kpm_arm64_addr_t)0 - byte_offset)
		return -ERANGE;
	*entry_address = plt->address + byte_offset;

	words[0] = 0xd2800010 | ((unsigned int)(target & 0xffff) << 5);
	words[1] = 0xf2a00010 |
		((unsigned int)((target >> 16) & 0xffff) << 5);
	words[2] = 0xf2c00010 |
		((unsigned int)((target >> 32) & 0xffff) << 5);
	words[3] = 0xf2e00010 |
		((unsigned int)((target >> 48) & 0xffff) << 5);
	words[4] = 0xd61f0200;
	return 0;
}

static int kpm_validate_branch_instruction(unsigned int instruction,
					   unsigned int type)
{
	if (type == R_AARCH64_CALL26)
		return (instruction & 0xfc000000) == 0x94000000 ? 0 : -ENOEXEC;
	return (instruction & 0xfc000000) == 0x14000000 ? 0 : -ENOEXEC;
}

static int kpm_apply_branch_rela(void *place,
				 kpm_arm64_addr_t place_address,
				 kpm_arm64_addr_t target,
				 unsigned int type,
				 struct kpm_arm64_plt_pool *plt)
{
	unsigned int instruction;
	unsigned int immediate;
	unsigned int plt_words[5];
	kpm_arm64_addr_t branch_target = target;
	kpm_arm64_addr_t plt_address;
	int use_plt = 0;
	int error;

	if (!kpm_instruction_place_aligned(place, place_address))
		return -EINVAL;
	instruction = kpm_load_word(place);

	error = kpm_validate_branch_instruction(instruction, type);
	if (error)
		return error;
	if ((target | place_address) & 3)
		return -ERANGE;
	error = kpm_branch_delta(branch_target, place_address, 26, &immediate);
	if (error == -ERANGE) {
		error = kpm_build_plt(plt, target, &plt_address, plt_words);
		if (error)
			return error;
		branch_target = plt_address;
		error = kpm_branch_delta(branch_target, place_address, 26,
					 &immediate);
		if (error)
			return error;
		use_plt = 1;
	} else if (error) {
		return error;
	}

	instruction = (instruction & ~0x03ffffffU) | immediate;
	if (use_plt) {
		memcpy(plt->words + plt->used * 5, plt_words,
		       sizeof(plt_words));
		plt->used++;
	}
	kpm_store_word(place, instruction);
	return 0;
}

static int kpm_validate_imm_instruction(unsigned int instruction,
					unsigned int type)
{
	if (type == R_AARCH64_ADR_PREL_LO21)
		return (instruction & 0x9f000000) == 0x10000000 ? 0 : -ENOEXEC;
	if (type == R_AARCH64_ADR_PREL_PG_HI21 ||
	    type == R_AARCH64_ADR_PREL_PG_HI21_NC)
		return (instruction & 0x9f000000) == 0x90000000 ? 0 : -ENOEXEC;
	if (type == R_AARCH64_LD_PREL_LO19)
		return (instruction & 0x3b000000) == 0x18000000 ? 0 : -ENOEXEC;
	if (type == R_AARCH64_CONDBR19) {
		if ((instruction & 0xff000010) == 0x54000000 ||
		    (instruction & 0x7e000000) == 0x34000000)
			return 0;
		return -ENOEXEC;
	}
	if (type == R_AARCH64_TSTBR14)
		return (instruction & 0x7e000000) == 0x36000000 ? 0 : -ENOEXEC;
	if (type == R_AARCH64_ADD_ABS_LO12_NC)
		return (instruction & 0x7f400000) == 0x11000000 ? 0 : -ENOEXEC;
	if (type == R_AARCH64_LDST8_ABS_LO12_NC ||
	    type == R_AARCH64_LDST16_ABS_LO12_NC ||
	    type == R_AARCH64_LDST32_ABS_LO12_NC ||
	    type == R_AARCH64_LDST64_ABS_LO12_NC ||
	    type == R_AARCH64_LDST128_ABS_LO12_NC)
		return (instruction & 0x3b000000) == 0x39000000 ? 0 : -ENOEXEC;
	return 0;
}

static int kpm_apply_pcrel_imm(void *place,
			       kpm_arm64_addr_t place_address,
			       kpm_arm64_addr_t target, unsigned int type,
			       enum kpm_imm_field field, unsigned int lsb,
			       unsigned int bits, int check_overflow)
{
	unsigned int instruction;
	unsigned int immediate;
	long delta;
	long scaled;
	int error;

	if (!kpm_instruction_place_aligned(place, place_address))
		return -EINVAL;
	instruction = kpm_load_word(place);

	error = kpm_validate_imm_instruction(instruction, type);
	if (error)
		return error;
	delta = (long)(target - place_address);
	if (lsb && ((unsigned long)delta & ((1UL << lsb) - 1)))
		return -ERANGE;
	scaled = delta >> lsb;
	if (check_overflow && !kpm_fits_signed(scaled, bits))
		return -ERANGE;
	immediate = (unsigned int)scaled & ((1U << bits) - 1);

	switch (field) {
	case KPM_IMM_14:
		instruction = (instruction & ~(0x3fffU << 5)) |
			(immediate << 5);
		break;
	case KPM_IMM_19:
		instruction = (instruction & ~(0x7ffffU << 5)) |
			(immediate << 5);
		break;
	case KPM_IMM_26:
		instruction = (instruction & ~0x03ffffffU) | immediate;
		break;
	case KPM_IMM_ADR21:
		instruction &= ~((3U << 29) | (0x7ffffU << 5));
		instruction |= ((immediate & 3) << 29) |
			(((immediate >> 2) & 0x7ffff) << 5);
		break;
	case KPM_IMM_12:
		instruction = (instruction & ~(0xfffU << 10)) |
			(immediate << 10);
		break;
	}
	kpm_store_word(place, instruction);
	return 0;
}

static int kpm_apply_low12(void *place,
			   kpm_arm64_addr_t place_address,
			   kpm_arm64_addr_t value, unsigned int type,
			   unsigned int scale)
{
	unsigned int instruction;
	unsigned int immediate;
	unsigned int bits = 12 - scale;

	if (!kpm_instruction_place_aligned(place, place_address))
		return -EINVAL;
	instruction = kpm_load_word(place);

	if (kpm_validate_imm_instruction(instruction, type))
		return -ENOEXEC;
	if (scale && (value & (((kpm_arm64_addr_t)1 << scale) - 1)))
		return -ERANGE;
	immediate = (unsigned int)(value >> scale) & ((1U << bits) - 1);
	instruction = (instruction & ~(0xfffU << 10)) | (immediate << 10);
	kpm_store_word(place, instruction);
	return 0;
}

static int kpm_apply_page_rela(void *place,
			       kpm_arm64_addr_t place_address,
			       kpm_arm64_addr_t value, unsigned int type)
{
	kpm_arm64_addr_t target_page = value & ~((kpm_arm64_addr_t)0xfff);
	kpm_arm64_addr_t place_page = place_address &
		~((kpm_arm64_addr_t)0xfff);
	long page_delta = (long)(target_page - place_page);

	return kpm_apply_pcrel_imm(place, place_address,
				   place_address + page_delta, type,
				   KPM_IMM_ADR21, 12, 21,
				   type == R_AARCH64_ADR_PREL_PG_HI21);
}

int kpm_arm64_apply_rela(void *place, kpm_arm64_addr_t place_address,
			 unsigned int type, kpm_arm64_addr_t symbol_address,
			 kpm_arm64_addend_t addend,
			 struct kpm_arm64_plt_pool *plt)
{
	kpm_arm64_addr_t value;
	unsigned int scale;
	int error;

	if (type == R_AARCH64_NONE)
		return 0;
	if (!place)
		return -EINVAL;
	error = kpm_add_addend(symbol_address, addend, &value);
	if (error)
		return error;

	switch (type) {
	case R_AARCH64_ABS64:
	case R_AARCH64_PREL64:
	case R_AARCH64_ABS32:
	case R_AARCH64_PREL32:
	case R_AARCH64_ABS16:
	case R_AARCH64_PREL16:
		return kpm_apply_data_rela(place, place_address, value, type);
	case R_AARCH64_MOVW_UABS_G0:
	case R_AARCH64_MOVW_UABS_G0_NC:
	case R_AARCH64_MOVW_UABS_G1:
	case R_AARCH64_MOVW_UABS_G1_NC:
	case R_AARCH64_MOVW_UABS_G2:
	case R_AARCH64_MOVW_UABS_G2_NC:
	case R_AARCH64_MOVW_UABS_G3:
	case R_AARCH64_MOVW_SABS_G0:
	case R_AARCH64_MOVW_SABS_G1:
	case R_AARCH64_MOVW_SABS_G2:
	case R_AARCH64_MOVW_PREL_G0:
	case R_AARCH64_MOVW_PREL_G0_NC:
	case R_AARCH64_MOVW_PREL_G1:
	case R_AARCH64_MOVW_PREL_G1_NC:
	case R_AARCH64_MOVW_PREL_G2:
	case R_AARCH64_MOVW_PREL_G2_NC:
	case R_AARCH64_MOVW_PREL_G3:
		return kpm_apply_movw_rela(place, place_address, value, type);
	case R_AARCH64_ADR_PREL_PG_HI21:
	case R_AARCH64_ADR_PREL_PG_HI21_NC:
		return kpm_apply_page_rela(place, place_address, value, type);
	case R_AARCH64_ADD_ABS_LO12_NC:
		return kpm_apply_low12(place, place_address, value, type, 0);
	case R_AARCH64_LDST8_ABS_LO12_NC:
		scale = 0;
		break;
	case R_AARCH64_LDST16_ABS_LO12_NC:
		scale = 1;
		break;
	case R_AARCH64_LDST32_ABS_LO12_NC:
		scale = 2;
		break;
	case R_AARCH64_LDST64_ABS_LO12_NC:
		scale = 3;
		break;
	case R_AARCH64_LDST128_ABS_LO12_NC:
		scale = 4;
		break;
	case R_AARCH64_LD_PREL_LO19:
		return kpm_apply_pcrel_imm(place, place_address, value, type,
					   KPM_IMM_19, 2, 19, 1);
	case R_AARCH64_ADR_PREL_LO21:
		return kpm_apply_pcrel_imm(place, place_address, value, type,
					   KPM_IMM_ADR21, 0, 21, 1);
	case R_AARCH64_TSTBR14:
		return kpm_apply_pcrel_imm(place, place_address, value, type,
					   KPM_IMM_14, 2, 14, 1);
	case R_AARCH64_CONDBR19:
		return kpm_apply_pcrel_imm(place, place_address, value, type,
					   KPM_IMM_19, 2, 19, 1);
	case R_AARCH64_CALL26:
	case R_AARCH64_JUMP26:
		return kpm_apply_branch_rela(place, place_address, value, type,
					     plt);
	default:
		return -ENOEXEC;
	}

	error = kpm_apply_low12(place, place_address, value, type, scale);
	return error;
}
