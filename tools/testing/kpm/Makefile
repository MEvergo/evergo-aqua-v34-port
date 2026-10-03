CC ?= cc
CFLAGS ?= -O2 -g
TEST_CFLAGS := -std=gnu11 -Wall -Wextra -Werror
TEST_BIN ?= /tmp/native-kpm-elf-test
KPM_DIR := ../../../drivers/kernelsu/kpm
RELOC_TEST_BIN ?= /tmp/native-kpm-reloc-test
COMPAT_TEST_BIN ?= /tmp/native-kpm-compat-test

HOOK_RELOC_TEST_BIN ?= /tmp/native-kpm-hook-reloc-test
.PHONY: test elf-test reloc-test hook-reloc-test compat-test

test: elf-test reloc-test hook-reloc-test compat-test

elf-test:
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -DKPM_HOST_TEST -o $(TEST_BIN) elf_test.c $(KPM_DIR)/elf.c
	$(TEST_BIN)

reloc-test:
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -DKPM_HOST_TEST -o $(RELOC_TEST_BIN) reloc_test.c $(KPM_DIR)/arch/arm64/reloc.c
	$(RELOC_TEST_BIN)
hook-reloc-test:
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -DKPM_HOST_TEST -o $(HOOK_RELOC_TEST_BIN) hook_reloc_test.c $(KPM_DIR)/arch/arm64/hook_reloc.c
	$(HOOK_RELOC_TEST_BIN)


compat-test:
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -o $(COMPAT_TEST_BIN) compat_test.c $(KPM_DIR)/abi_symbols.c $(KPM_DIR)/compact_lookup.c
	$(COMPAT_TEST_BIN)

clean:
	rm -f $(TEST_BIN) $(RELOC_TEST_BIN) $(COMPAT_TEST_BIN) \
		$(HOOK_RELOC_TEST_BIN)
