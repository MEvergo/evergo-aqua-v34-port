/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "compact.h"

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

unsigned long sukisu_compact_lookup_symbol(
	const char *name, const struct compact_address_symbol *symbols,
	size_t count, sukisu_compact_fallback_t fallback)
{
	size_t index;

	if (!name || (count && !symbols))
		return 0;
	for (index = 0; index < count; index++) {
		if (!strcmp(name, symbols[index].name))
			return symbols[index].address;
	}
	return fallback ? fallback(name) : 0;
}
