#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include "../../../drivers/kernelsu/kpm/arch/arm64/hook_reloc.h"

static int expect(int actual, int expected, const char *name)
{
	if (actual != expected) {
		fprintf(stderr, "FAIL: %s returned %d, expected %d\n", name,
			actual, expected);
		return -1;
	}
	return 0;
}

static int test_copied_prologue_and_return_branch(void)
{
	const uint32_t source[4] = {
		0xa9bf7bfd, 0x910003fd, 0xd503201f, 0xd503201f,
	};
	uint32_t relocated[KPM_ARM64_HOOK_RELOC_MAX_WORDS] = { 0 };
	size_t words = 0;
	int error;

	error = kpm_arm64_relocate_hook(source, 0xffff000000100000ULL, 4,
					relocated, 0xffff800000200000ULL,
					sizeof(relocated) / sizeof(relocated[0]),
					&words);
	if (expect(error, 0, "copy prologue"))
		return -1;
	if (words != 12 || relocated[0] != source[0] ||
	    relocated[1] != 0xd503201f || relocated[2] != source[1] ||
	    relocated[3] != 0xd503201f || relocated[8] != 0x58000051 ||
	    relocated[9] != 0xd61f0220 ||
	    relocated[10] != 0x00100010 || relocated[11] != 0xffff0000) {
		fprintf(stderr, "FAIL: copied prologue or return branch is malformed\n");
		return -1;
	}
	return 0;
}

static int test_internal_branch_target_is_relocated(void)
{
	const uint32_t source[4] = {
		0x14000001, 0xd503201f, 0xd503201f, 0xd503201f,
	};
	uint32_t relocated[KPM_ARM64_HOOK_RELOC_MAX_WORDS] = { 0 };
	size_t words = 0;
	int error;

	error = kpm_arm64_relocate_hook(source, 0x1000, 4, relocated,
					0x2000, sizeof(relocated) /
						sizeof(relocated[0]), &words);
	if (expect(error, 0, "internal B relocation"))
		return -1;
	if (words != 14 || relocated[0] != 0x58000051 ||
	    relocated[1] != 0xd61f0220 || relocated[2] != 0x2010 ||
	    relocated[3] != 0) {
		fprintf(stderr, "FAIL: B into displaced prologue did not target its relocated instruction\n");
		return -1;
	}
	return 0;
}

static int test_unsupported_literal_into_displaced_prologue(void)
{
	const uint32_t source[4] = {
		0x58000020, 0xd503201f, 0xd503201f, 0xd503201f,
	};
	uint32_t relocated[KPM_ARM64_HOOK_RELOC_MAX_WORDS];
	size_t words = 99;
	int error;

	relocated[0] = 0xa5a5a5a5;
	error = kpm_arm64_relocate_hook(source, 0x1000, 4, relocated,
					0x2000, sizeof(relocated) /
						sizeof(relocated[0]), &words);
	if (expect(error, -EOPNOTSUPP,
		   "literal into displaced prologue"))
		return -1;
	if (relocated[0] != 0xa5a5a5a5 || words != 99) {
		fprintf(stderr, "FAIL: rejected relocation modified caller output\n");
		return -1;
	}
	return 0;
}

int main(void)
{
	if (test_copied_prologue_and_return_branch() ||
	    test_internal_branch_target_is_relocated() ||
	    test_unsupported_literal_into_displaced_prologue())
		return 1;
	puts("ARM64 hook relocation contract tests passed");
	return 0;
}
