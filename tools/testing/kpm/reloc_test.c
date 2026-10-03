#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../../drivers/kernelsu/kpm/arch/arm64/reloc.h"

static int expect_result(int result, int expected, const char *name)
{
	if (result != expected) {
		fprintf(stderr, "FAIL: %s returned %d, expected %d\n", name,
			result, expected);
		return -1;
	}
	return 0;
}

static int test_data_relocations(void)
{
	uint64_t abs64 = 0;
	int32_t prel32 = 0;
	uint32_t abs32 = 0x12345678;

	if (expect_result(kpm_arm64_apply_rela(&abs64, 0x1000,
						 R_AARCH64_ABS64,
						 0xffff000000001000ULL,
						 0x24, NULL),
			 0, "ABS64"))
		return -1;
	if (abs64 != 0xffff000000001024ULL) {
		fprintf(stderr, "FAIL: ABS64 value mismatch\n");
		return -1;
	}
	if (expect_result(kpm_arm64_apply_rela(&prel32, 0x2000,
						 R_AARCH64_PREL32, 0x1ffc, 0,
						 NULL),
			 0, "PREL32"))
		return -1;
	if (prel32 != -4) {
		fprintf(stderr, "FAIL: PREL32 signed result mismatch\n");
		return -1;
	}
	if (expect_result(kpm_arm64_apply_rela(&abs32, 0x3000,
						 R_AARCH64_ABS32, 0x100000000ULL,
						 0, NULL),
			 -ERANGE, "ABS32 overflow"))
		return -1;
	if (abs32 != 0x12345678) {
		fprintf(stderr, "FAIL: ABS32 overflow partially modified place\n");
		return -1;
	}
	return 0;
}

static int test_branch_relocations(void)
{
	uint32_t bl = 0x94000000;
	uint32_t b = 0x14000000;
	uint32_t wrong = 0x14000000;
	uint32_t far = 0x94000000;
	uint32_t bad_plt = 0x94000000;
	uint32_t plt_words[5] = { 0 };
	struct kpm_arm64_plt_pool pool = {
		.words = plt_words,
		.address = 0x100100,
		.capacity = 1,
	};
	uint64_t reconstructed;
	int error;

	error = kpm_arm64_apply_rela(&bl, 0x100000, R_AARCH64_CALL26,
				     0x100100, 0, NULL);
	if (expect_result(error, 0, "CALL26 forward"))
		return -1;
	if (bl != 0x94000040) {
		fprintf(stderr, "FAIL: CALL26 immediate mismatch\n");
		return -1;
	}

	error = kpm_arm64_apply_rela(&b, 0x100000, R_AARCH64_JUMP26,
				     0xfff00, 0, NULL);
	if (expect_result(error, 0, "JUMP26 backward"))
		return -1;
	if (b != (0x14000000 | ((uint32_t)-64 & 0x03ffffff))) {
		fprintf(stderr, "FAIL: negative JUMP26 immediate mismatch\n");
		return -1;
	}

	error = kpm_arm64_apply_rela(&wrong, 0x100000, R_AARCH64_CALL26,
				     0x100100, 0, NULL);
	if (expect_result(error, -ENOEXEC, "CALL26 opcode validation"))
		return -1;
	if (wrong != 0x14000000) {
		fprintf(stderr, "FAIL: bad CALL26 opcode was modified\n");
		return -1;
	}

	error = kpm_arm64_apply_rela(&far, 0x100000, R_AARCH64_CALL26,
				     0x20000000, 0, &pool);
	if (expect_result(error, 0, "CALL26 veneer"))
		return -1;
	if (pool.used != 1 || far != 0x94000040) {
		fprintf(stderr, "FAIL: CALL26 veneer was not linked\n");
		return -1;
	}
	reconstructed = (uint64_t)((plt_words[0] >> 5) & 0xffff);
	reconstructed |= (uint64_t)((plt_words[1] >> 5) & 0xffff) << 16;
	reconstructed |= (uint64_t)((plt_words[2] >> 5) & 0xffff) << 32;
	reconstructed |= (uint64_t)((plt_words[3] >> 5) & 0xffff) << 48;
	if ((plt_words[0] & 0xffe0001f) != 0xd2800010 ||
	    (plt_words[1] & 0xffe0001f) != 0xf2a00010 ||
	    (plt_words[2] & 0xffe0001f) != 0xf2c00010 ||
	    (plt_words[3] & 0xffe0001f) != 0xf2e00010 ||
	    plt_words[4] != 0xd61f0200 || reconstructed != 0x20000000) {
		fprintf(stderr, "FAIL: PLT veneer instruction sequence is invalid\n");
		return -1;
	}

	pool.address = 0x90000000;
	pool.used = 0;
	error = kpm_arm64_apply_rela(&bad_plt, 0x100000,
				     R_AARCH64_CALL26, 0x20000000, 0, &pool);
	if (expect_result(error, -ERANGE, "out-of-range veneer"))
		return -1;
	if (pool.used || bad_plt != 0x94000000) {
		fprintf(stderr, "FAIL: failed veneer allocation changed state\n");
		return -1;
	}
	return 0;
}

static int test_immediate_relocations(void)
{
	uint32_t adrp = 0x90000000;
	uint32_t add = 0x91000000;
	uint32_t cbnz = 0x35000000;
	uint32_t tbnz = 0x37000000;
	uint32_t movz = 0xd2800010;
	uint32_t far_adrp = 0x90000000;
	uint32_t shifted_add = 0x91400000;
	uint32_t saved_shifted_add = shifted_add;
	uint32_t sub = 0xd1000000;
	uint32_t adds = 0xb1000000;
	uint32_t saved_sub = sub;
	uint32_t saved_adds = adds;
	uint32_t unaligned = 0x94000000;
	uint32_t unknown = 0xd503201f;
	uint8_t unaligned_place[8] = { 0 };
	uint32_t adrp_instruction = 0x90000000;
	uint32_t misaligned_address_adrp = 0x90000000;
	uint32_t misaligned_address_add = 0x91000000;

	memcpy(unaligned_place + 1, &adrp_instruction,
	       sizeof(adrp_instruction));
	if (expect_result(kpm_arm64_apply_rela(
				  unaligned_place + 1, 0x1001,
				  R_AARCH64_ADR_PREL_PG_HI21, 0x3000, 0,
				  NULL),
			  -EINVAL, "unaligned ADRP place"))
		return -1;
	if (memcmp(unaligned_place + 1, &adrp_instruction,
		   sizeof(adrp_instruction))) {
		fprintf(stderr, "FAIL: unaligned ADRP modified instruction\n");
		return -1;
	}
	if (expect_result(kpm_arm64_apply_rela(
				  &misaligned_address_adrp, 0x1001,
				  R_AARCH64_ADR_PREL_PG_HI21, 0x3000, 0,
				  NULL),
			  -EINVAL, "unaligned ADRP address"))
		return -1;
	if (misaligned_address_adrp != 0x90000000) {
		fprintf(stderr, "FAIL: unaligned ADRP address modified instruction\n");
		return -1;
	}
	if (expect_result(kpm_arm64_apply_rela(
				  &misaligned_address_add, 0x2001,
				  R_AARCH64_ADD_ABS_LO12_NC, 0x1234, 0, NULL),
			  -EINVAL, "unaligned ADD address"))
		return -1;
	if (misaligned_address_add != 0x91000000) {
		fprintf(stderr, "FAIL: unaligned ADD address modified instruction\n");
		return -1;
	}

	if (expect_result(kpm_arm64_apply_rela(&adrp, 0x1000,
						 R_AARCH64_ADR_PREL_PG_HI21,
						 0x3000, 0, NULL),
			 0, "ADRP page relocation"))
		return -1;
	if (adrp != 0xd0000000) {
		fprintf(stderr, "FAIL: ADRP immediate mismatch: %#x\n", adrp);
		return -1;
	}
	if (expect_result(kpm_arm64_apply_rela(
				  &far_adrp, 0x1000,
				  R_AARCH64_ADR_PREL_PG_HI21, 0x100002000ULL,
				  0, NULL),
			  -ERANGE, "ADRP page delta overflow"))
		return -1;
	if (far_adrp != 0x90000000) {
		fprintf(stderr, "FAIL: overflowing ADRP was modified\n");
		return -1;
	}
	if (expect_result(kpm_arm64_apply_rela(&add, 0x4000,
						 R_AARCH64_ADD_ABS_LO12_NC,
						 0x5234, 0, NULL),
			 0, "ADD low-12 relocation"))
		return -1;
	if (add != (0x91000000 | (0x234 << 10))) {
		fprintf(stderr, "FAIL: ADD low-12 immediate mismatch\n");
		return -1;
	}
	if (expect_result(kpm_arm64_apply_rela(&cbnz, 0x7000,
						 R_AARCH64_CONDBR19, 0x7100, 0,
						 NULL),
			 0, "CBNZ CONDBR19"))
		return -1;
	if (cbnz != (0x35000000 | (64 << 5))) {
		fprintf(stderr, "FAIL: CBNZ immediate mismatch\n");
		return -1;
	}
	if (expect_result(kpm_arm64_apply_rela(&tbnz, 0x7000,
						 R_AARCH64_TSTBR14, 0x6f00, 0,
						 NULL),
			 0, "TBNZ TSTBR14"))
		return -1;
	if (tbnz != (0x37000000 | (((uint32_t)-64 & 0x3fff) << 5))) {
		fprintf(stderr, "FAIL: TBNZ immediate mismatch\n");
		return -1;
	}
	if (expect_result(kpm_arm64_apply_rela(&movz, 0x8000,
						 R_AARCH64_MOVW_UABS_G0,
						 0x1234, 0, NULL),
			 0, "MOVW UABS G0"))
		return -1;
	if (movz != (0xd2800010 | (0x1234 << 5))) {
		fprintf(stderr, "FAIL: MOVW immediate mismatch\n");
		return -1;
	}
	if (expect_result(kpm_arm64_apply_rela(&shifted_add, 0x9000,
						 R_AARCH64_ADD_ABS_LO12_NC,
						 0x1234, 0, NULL),
			 -ENOEXEC, "shifted ADD low-12"))
		return -1;
	if (shifted_add != saved_shifted_add) {
		fprintf(stderr, "FAIL: invalid shifted ADD was modified\n");
		return -1;
	}
	if (expect_result(kpm_arm64_apply_rela(&sub, 0x9000,
						 R_AARCH64_ADD_ABS_LO12_NC,
						 0x1234, 0, NULL),
			 -ENOEXEC, "SUB low-12 opcode"))
		return -1;
	if (sub != saved_sub) {
		fprintf(stderr, "FAIL: invalid SUB was modified\n");
		return -1;
	}
	if (expect_result(kpm_arm64_apply_rela(&adds, 0x9000,
						 R_AARCH64_ADD_ABS_LO12_NC,
						 0x1234, 0, NULL),
			 -ENOEXEC, "ADDS low-12 opcode"))
		return -1;
	if (adds != saved_adds) {
		fprintf(stderr, "FAIL: invalid ADDS was modified\n");
		return -1;
	}

	if (expect_result(kpm_arm64_apply_rela(&unaligned, 0x5000,
						 R_AARCH64_CALL26, 0x5002, 0,
						 NULL),
			 -ERANGE, "unaligned branch"))
		return -1;
	if (unaligned != 0x94000000) {
		fprintf(stderr, "FAIL: unaligned branch modified instruction\n");
		return -1;
	}
	if (expect_result(kpm_arm64_apply_rela(&unknown, 0x6000, 0xffff,
						 0x6000, 0, NULL),
			 -ENOEXEC, "unknown relocation"))
		return -1;
	if (unknown != 0xd503201f) {
		fprintf(stderr, "FAIL: unknown relocation modified instruction\n");
		return -1;
	}
	return 0;
}

int main(void)
{
	if (test_data_relocations() || test_branch_relocations() ||
	    test_immediate_relocations())
		return 1;
	puts("ARM64 relocation tests passed");
	return 0;
}
