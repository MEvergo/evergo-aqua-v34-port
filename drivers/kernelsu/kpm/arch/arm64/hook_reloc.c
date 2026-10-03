/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * ARM64 inline-hook prologue relocation, adapted from KernelPatch's
 * hook.c instruction rewriting strategy for the native KPM adapter.
 */
#include "hook_reloc.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
typedef s64 kpm_hook_saddr_t;
#else
#include <errno.h>
#include <string.h>
typedef int64_t kpm_hook_saddr_t;
#endif

enum kpm_hook_insn_type {
	KPM_HOOK_OTHER,
	KPM_HOOK_B,
	KPM_HOOK_BL,
	KPM_HOOK_BCOND,
	KPM_HOOK_ADR,
	KPM_HOOK_ADRP,
	KPM_HOOK_LDR32,
	KPM_HOOK_LDR64,
	KPM_HOOK_LDRSW,
	KPM_HOOK_PRFM,
	KPM_HOOK_LDR_SIMD32,
	KPM_HOOK_LDR_SIMD64,
	KPM_HOOK_LDR_SIMD128,
	KPM_HOOK_CBZ,
	KPM_HOOK_CBNZ,
	KPM_HOOK_TBZ,
	KPM_HOOK_TBNZ,
};

static enum kpm_hook_insn_type kpm_hook_classify(kpm_hook_insn_t insn)
{
	if ((insn & 0xfc000000) == 0x14000000)
		return KPM_HOOK_B;
	if ((insn & 0xfc000000) == 0x94000000)
		return KPM_HOOK_BL;
	if ((insn & 0xff000010) == 0x54000000)
		return KPM_HOOK_BCOND;
	if ((insn & 0x9f000000) == 0x10000000)
		return KPM_HOOK_ADR;
	if ((insn & 0x9f000000) == 0x90000000)
		return KPM_HOOK_ADRP;
	if ((insn & 0xff000000) == 0x18000000)
		return KPM_HOOK_LDR32;
	if ((insn & 0xff000000) == 0x58000000)
		return KPM_HOOK_LDR64;
	if ((insn & 0xff000000) == 0x98000000)
		return KPM_HOOK_LDRSW;
	if ((insn & 0xff000000) == 0xd8000000)
		return KPM_HOOK_PRFM;
	if ((insn & 0xff000000) == 0x1c000000)
		return KPM_HOOK_LDR_SIMD32;
	if ((insn & 0xff000000) == 0x5c000000)
		return KPM_HOOK_LDR_SIMD64;
	if ((insn & 0xff000000) == 0x9c000000)
		return KPM_HOOK_LDR_SIMD128;
	if ((insn & 0x7f000000) == 0x34000000)
		return KPM_HOOK_CBZ;
	if ((insn & 0x7f000000) == 0x35000000)
		return KPM_HOOK_CBNZ;
	if ((insn & 0x7f000000) == 0x36000000)
		return KPM_HOOK_TBZ;
	if ((insn & 0x7f000000) == 0x37000000)
		return KPM_HOOK_TBNZ;
	return KPM_HOOK_OTHER;
}

static size_t kpm_hook_relocated_length(enum kpm_hook_insn_type type)
{
	switch (type) {
	case KPM_HOOK_B:
		return 4;
	case KPM_HOOK_BL:
		return 8;
	case KPM_HOOK_BCOND:
	case KPM_HOOK_CBZ:
	case KPM_HOOK_CBNZ:
	case KPM_HOOK_TBZ:
	case KPM_HOOK_TBNZ:
		return 6;
	case KPM_HOOK_ADR:
	case KPM_HOOK_ADRP:
		return 4;
	case KPM_HOOK_LDR32:
	case KPM_HOOK_LDR64:
	case KPM_HOOK_LDRSW:
	case KPM_HOOK_PRFM:
	case KPM_HOOK_LDR_SIMD32:
	case KPM_HOOK_LDR_SIMD64:
	case KPM_HOOK_LDR_SIMD128:
		return 6;
	case KPM_HOOK_OTHER:
	default:
		return 2;
	}
}

static kpm_hook_saddr_t kpm_hook_sign_extend(kpm_hook_addr_t value,
						     unsigned int bits)
{
	kpm_hook_addr_t sign = (kpm_hook_addr_t)1 << (bits - 1);

	return (kpm_hook_saddr_t)((value ^ sign) - sign);
}

static int kpm_hook_add_signed(kpm_hook_addr_t base,
			       kpm_hook_saddr_t offset,
			       kpm_hook_addr_t *result)
{
	kpm_hook_addr_t magnitude;

	if (offset < 0) {
		magnitude = (kpm_hook_addr_t)(-(offset + 1)) + 1;
		if (base < magnitude)
			return -ERANGE;
		*result = base - magnitude;
		return 0;
	}
	magnitude = (kpm_hook_addr_t)offset;
	if (base > ~(kpm_hook_addr_t)0 - magnitude)
		return -ERANGE;
	*result = base + magnitude;
	return 0;
}

static int kpm_hook_branch_target(kpm_hook_insn_t insn,
				  kpm_hook_addr_t pc,
				  enum kpm_hook_insn_type type,
				  kpm_hook_addr_t *target)
{
	kpm_hook_addr_t immediate;
	unsigned int bits;

	switch (type) {
	case KPM_HOOK_B:
	case KPM_HOOK_BL:
		immediate = (insn & 0x03ffffffU) << 2;
		bits = 28;
		break;
	case KPM_HOOK_BCOND:
	case KPM_HOOK_CBZ:
	case KPM_HOOK_CBNZ:
		immediate = ((insn >> 5) & 0x7ffffU) << 2;
		bits = 21;
		break;
	case KPM_HOOK_TBZ:
	case KPM_HOOK_TBNZ:
		immediate = ((insn >> 5) & 0x3fffU) << 2;
		bits = 16;
		break;
	default:
		return -EINVAL;
	}
	return kpm_hook_add_signed(pc,
				   kpm_hook_sign_extend(immediate, bits),
				   target);
}

static int kpm_hook_address_in_range(kpm_hook_addr_t address,
				     kpm_hook_addr_t start,
				     kpm_hook_addr_t end)
{
	return address >= start && address < end;
}

static int kpm_hook_relocate_internal_target(
	kpm_hook_addr_t target, kpm_hook_addr_t source_address,
	kpm_hook_addr_t source_end, kpm_hook_addr_t relocated_address,
	const size_t *offsets, unsigned int source_words,
	kpm_hook_addr_t *relocated_target)
{
	kpm_hook_addr_t displacement;
	unsigned int index;

	if (!kpm_hook_address_in_range(target, source_address, source_end)) {
		*relocated_target = target;
		return 0;
	}
	displacement = target - source_address;
	if ((displacement & 3) || displacement / 4 >= source_words)
		return -EOPNOTSUPP;
	index = displacement / 4;
	if (relocated_address > ~(kpm_hook_addr_t)0 - offsets[index] * 4)
		return -ERANGE;
	*relocated_target = relocated_address + offsets[index] * 4;
	return 0;
}

static int kpm_hook_append(kpm_hook_insn_t *buffer, size_t capacity,
			   size_t *used, kpm_hook_insn_t insn)
{
	if (*used >= capacity)
		return -ENOSPC;
	buffer[(*used)++] = insn;
	return 0;
}

static int kpm_hook_append_u64(kpm_hook_insn_t *buffer, size_t capacity,
			       size_t *used, kpm_hook_addr_t value)
{
	int error;

	error = kpm_hook_append(buffer, capacity, used, (kpm_hook_insn_t)value);
	if (error)
		return error;
	return kpm_hook_append(buffer, capacity, used,
			       (kpm_hook_insn_t)(value >> 32));
}

static int kpm_hook_append_absolute_branch(kpm_hook_insn_t *buffer,
					   size_t capacity, size_t *used,
					   kpm_hook_addr_t target)
{
	int error;

	error = kpm_hook_append(buffer, capacity, used, 0x58000051);
	if (error)
		return error;
	error = kpm_hook_append(buffer, capacity, used, 0xd61f0220);
	if (error)
		return error;
	return kpm_hook_append_u64(buffer, capacity, used, target);
}

static int kpm_hook_relocate_one(
	kpm_hook_insn_t insn, kpm_hook_addr_t source_pc,
	kpm_hook_addr_t source_address, kpm_hook_addr_t source_end,
	kpm_hook_addr_t relocated_address, const size_t *offsets,
	unsigned int source_words, kpm_hook_insn_t *buffer, size_t capacity,
	size_t *used)
{
	enum kpm_hook_insn_type type = kpm_hook_classify(insn);
	kpm_hook_addr_t target;
	kpm_hook_addr_t relocated_target;
	kpm_hook_addr_t immediate;
	kpm_hook_addr_t page_start;
	kpm_hook_addr_t page_end;
	kpm_hook_saddr_t offset;
	kpm_hook_insn_t rewritten;
	unsigned int reg;
	int error;

	if (type == KPM_HOOK_B || type == KPM_HOOK_BL ||
	    type == KPM_HOOK_BCOND || type == KPM_HOOK_CBZ ||
	    type == KPM_HOOK_CBNZ || type == KPM_HOOK_TBZ ||
	    type == KPM_HOOK_TBNZ) {
		error = kpm_hook_branch_target(insn, source_pc, type, &target);
		if (error)
			return error;
		error = kpm_hook_relocate_internal_target(
			target, source_address, source_end, relocated_address,
			offsets, source_words, &relocated_target);
		if (error)
			return error;
		if (type == KPM_HOOK_B)
			return kpm_hook_append_absolute_branch(
				buffer, capacity, used, relocated_target);
		if (type == KPM_HOOK_BL) {
			static const kpm_hook_insn_t call_sequence[] = {
				0x58000051, /* LDR X17, #8 */
				0x14000003, /* B #12 */
				0, 0,        /* target literal */
				0x1000001e,  /* ADR X30, . */
				0x910043de,  /* ADD X30, X30, #16 */
				0xd65f0220,  /* RET X17 */
				0xd503201f,  /* NOP */
			};
			size_t i;

			for (i = 0; i < 2; i++) {
				error = kpm_hook_append(buffer, capacity, used,
						       call_sequence[i]);
				if (error)
					return error;
			}
			error = kpm_hook_append_u64(buffer, capacity, used,
						    relocated_target);
			if (error)
				return error;
			for (i = 4; i < sizeof(call_sequence) /
					      sizeof(call_sequence[0]); i++) {
				error = kpm_hook_append(buffer, capacity, used,
						       call_sequence[i]);
				if (error)
					return error;
			}
			return 0;
		}
		if (type == KPM_HOOK_BCOND)
			rewritten = (insn & 0xff00001fU) | 0x40;
		else if (type == KPM_HOOK_TBZ || type == KPM_HOOK_TBNZ)
			rewritten = (insn & 0xfff8001fU) | 0x40;
		else
			rewritten = (insn & 0xff00001fU) | 0x40;
		error = kpm_hook_append(buffer, capacity, used, rewritten);
		if (error)
			return error;
		error = kpm_hook_append(buffer, capacity, used, 0x14000005);
		if (error)
			return error;
		return kpm_hook_append_absolute_branch(buffer, capacity, used,
						       relocated_target);
	}

	if (type == KPM_HOOK_ADR || type == KPM_HOOK_ADRP) {
		kpm_hook_addr_t immlo = (insn >> 29) & 3;
		kpm_hook_addr_t immhi = (insn >> 5) & 0x7ffff;
		unsigned int destination = insn & 0x1f;

		if (type == KPM_HOOK_ADR) {
			immediate = (immhi << 2) | immlo;
			offset = kpm_hook_sign_extend(immediate, 21);
			error = kpm_hook_add_signed(source_pc, offset, &target);
			if (error)
				return error;
			if (kpm_hook_address_in_range(target, source_address,
						      source_end))
				return -EOPNOTSUPP;
		} else {
			immediate = (immhi << 14) | (immlo << 12);
			offset = kpm_hook_sign_extend(immediate, 33);
			page_start = source_pc & ~(kpm_hook_addr_t)0xfff;
			error = kpm_hook_add_signed(page_start, offset, &target);
			if (error)
				return error;
			target &= ~(kpm_hook_addr_t)0xfff;
			page_start = target;
			if (page_start > ~(kpm_hook_addr_t)0 - 4096)
				return -ERANGE;
			page_end = page_start + 4096;
			if (page_start < source_end && source_address < page_end)
				return -EOPNOTSUPP;
		}
		error = kpm_hook_append(buffer, capacity, used,
					       0x58000040U | destination);
		if (error)
			return error;
		error = kpm_hook_append(buffer, capacity, used, 0x14000003);
		if (error)
			return error;
		return kpm_hook_append_u64(buffer, capacity, used, target);
	}

	if (type == KPM_HOOK_LDR32 || type == KPM_HOOK_LDR64 ||
	    type == KPM_HOOK_LDRSW || type == KPM_HOOK_PRFM ||
	    type == KPM_HOOK_LDR_SIMD32 || type == KPM_HOOK_LDR_SIMD64 ||
	    type == KPM_HOOK_LDR_SIMD128) {
		immediate = ((insn >> 5) & 0x7ffffU) << 2;
		offset = kpm_hook_sign_extend(immediate, 21);
		error = kpm_hook_add_signed(source_pc, offset, &target);
		if (error)
			return error;
		if (kpm_hook_address_in_range(target, source_address,
					      source_end) && type != KPM_HOOK_PRFM)
			return -EOPNOTSUPP;
		error = kpm_hook_relocate_internal_target(
			target, source_address, source_end, relocated_address,
			offsets, source_words, &relocated_target);
		if (error)
			return error;
		reg = insn & 0x1f;
		error = kpm_hook_append(buffer, capacity, used, 0x58000091);
		if (error)
			return error;
		switch (type) {
		case KPM_HOOK_LDR32:
			rewritten = 0xb9400220U | reg;
			break;
		case KPM_HOOK_LDR64:
			rewritten = 0xf9400220U | reg;
			break;
		case KPM_HOOK_LDRSW:
			rewritten = 0xb9800220U | reg;
			break;
		case KPM_HOOK_PRFM:
			rewritten = 0xf9800220U | reg;
			break;
		case KPM_HOOK_LDR_SIMD32:
			rewritten = 0xbd400220U | reg;
			break;
		case KPM_HOOK_LDR_SIMD64:
			rewritten = 0xfd400220U | reg;
			break;
		case KPM_HOOK_LDR_SIMD128:
			rewritten = 0x3dc00220U | reg;
			break;
		default:
			return -EOPNOTSUPP;
		}
		error = kpm_hook_append(buffer, capacity, used, rewritten);
		if (error)
			return error;
		error = kpm_hook_append(buffer, capacity, used, 0x14000004);
		if (error)
			return error;
		error = kpm_hook_append(buffer, capacity, used, 0xd503201f);
		if (error)
			return error;
		return kpm_hook_append_u64(buffer, capacity, used,
					   relocated_target);
	}

	error = kpm_hook_append(buffer, capacity, used, insn);
	if (error)
		return error;
	return kpm_hook_append(buffer, capacity, used, 0xd503201f);
}

int kpm_arm64_relocate_hook(
	const kpm_hook_insn_t *source, kpm_hook_addr_t source_address,
	unsigned int source_words, kpm_hook_insn_t *relocated,
	kpm_hook_addr_t relocated_address, size_t relocated_capacity_words,
	size_t *relocated_words)
{
	kpm_hook_insn_t output[KPM_ARM64_HOOK_RELOC_MAX_WORDS];
	size_t offsets[KPM_ARM64_HOOK_PATCH_WORDS];
	kpm_hook_addr_t source_end;
	size_t used = 0;
	unsigned int i;
	int error;

	if (!source || !relocated || !relocated_words ||
	    source_words != KPM_ARM64_HOOK_PATCH_WORDS ||
	    (source_address & 3) || (relocated_address & 3))
		return -EINVAL;
	if (source_address > ~(kpm_hook_addr_t)0 -
				KPM_ARM64_HOOK_PATCH_WORDS * sizeof(*source))
		return -ERANGE;
	source_end = source_address +
		KPM_ARM64_HOOK_PATCH_WORDS * sizeof(*source);
	offsets[0] = 0;
	for (i = 1; i < source_words; i++) {
		size_t length = kpm_hook_relocated_length(
			kpm_hook_classify(source[i - 1]));

		if (offsets[i - 1] > KPM_ARM64_HOOK_RELOC_MAX_WORDS - length)
			return -E2BIG;
		offsets[i] = offsets[i - 1] + length;
	}

	for (i = 0; i < source_words; i++) {
		kpm_hook_addr_t source_pc = source_address + i * sizeof(*source);

		if (relocated_address > ~(kpm_hook_addr_t)0 - offsets[i] * 4)
			return -ERANGE;
		error = kpm_hook_relocate_one(
			source[i], source_pc, source_address, source_end,
			relocated_address, offsets, source_words, output,
			KPM_ARM64_HOOK_RELOC_MAX_WORDS, &used);
		if (error)
			return error;
		if (used != offsets[i] +
			    kpm_hook_relocated_length(
				    kpm_hook_classify(source[i])))
			return -ENOEXEC;
	}
	error = kpm_hook_append_absolute_branch(
		output, KPM_ARM64_HOOK_RELOC_MAX_WORDS, &used, source_end);
	if (error)
		return error;
	if (used > relocated_capacity_words)
		return -ENOSPC;
	memcpy(relocated, output, used * sizeof(*relocated));
	*relocated_words = used;
	return 0;
}
