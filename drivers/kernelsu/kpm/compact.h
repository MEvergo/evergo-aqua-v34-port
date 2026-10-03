/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __SUKISU_KPM_COMPACT_H
#define __SUKISU_KPM_COMPACT_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#endif

struct compact_address_symbol {
	const char *name;
	unsigned long address;
};

typedef unsigned long (*sukisu_compact_fallback_t)(const char *name);

unsigned long sukisu_compact_lookup_symbol(
	const char *name, const struct compact_address_symbol *symbols,
	size_t count, sukisu_compact_fallback_t fallback);
unsigned long sukisu_compact_find_symbol(const char *name);

#endif
