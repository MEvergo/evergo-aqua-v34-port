/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "../../../drivers/kernelsu/kpm/abi_symbols.h"
#include "../../../drivers/kernelsu/kpm/compact.h"

static unsigned long compact_fallback(const char *name)
{
	return !strcmp(name, "do_trace") ? 0xbeefUL : 0;
}

unsigned long *kpm_abi_find_function_slot(const char *name,
					 const char **kernel_symbol);

int main(void)
{
	const struct compact_address_symbol compact_table[] = {
		{ "is_su_allow_uid", 0x1111UL },
	};
	const char *kernel_symbol = NULL;
	unsigned long *slot;

	assert(sukisu_compact_lookup_symbol(
		       "is_su_allow_uid", compact_table, 1,
		       compact_fallback) == 0x1111UL);
	assert(sukisu_compact_lookup_symbol(
		       "do_trace", compact_table, 1,
		       compact_fallback) == 0xbeefUL);
	assert(!sukisu_compact_lookup_symbol(
		       "missing", compact_table, 1,
		       compact_fallback));
	assert(!sukisu_compact_lookup_symbol(
		       NULL, compact_table, 1, compact_fallback));

	slot = kpm_abi_find_function_slot("kf_memcpy", &kernel_symbol);
	assert(slot);
	assert(kernel_symbol && !strcmp(kernel_symbol, "memcpy"));
	*slot = 0x12345678UL;
	assert(kpm_abi_find_function_slot("kf_memcpy", &kernel_symbol) == slot);
	assert(*slot == 0x12345678UL);
	slot = kpm_abi_find_function_slot("kallsyms_lookup_name",
					  &kernel_symbol);
	assert(slot);
	assert(kernel_symbol &&
	       !strcmp(kernel_symbol, "kallsyms_lookup_name"));
	*slot = 0x87654321UL;
	assert(kpm_abi_find_function_slot("kallsyms_lookup_name",
					  &kernel_symbol) == slot);
	assert(*slot == 0x87654321UL);
	slot = kpm_abi_find_function_slot("kallsyms_on_each_symbol",
					  &kernel_symbol);
	assert(slot && kernel_symbol &&
	       !strcmp(kernel_symbol, "kallsyms_on_each_symbol"));
	slot = kpm_abi_find_function_slot("kf_strncat", &kernel_symbol);
	assert(slot && kernel_symbol && !strcmp(kernel_symbol, "strncat"));
	assert(!kpm_abi_find_function_slot("kf_not_an_api", &kernel_symbol));
	assert(!kpm_abi_find_function_slot("memcpy", &kernel_symbol));

	puts("KPM compatibility symbol tests passed");
	return 0;
}

