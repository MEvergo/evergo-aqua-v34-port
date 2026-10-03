/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/types.h>

#include "../manager/manager_identity.h"
#include "../policy/allowlist.h"
#include "compact.h"
#include "../infra/symbol_resolver.h"

static int sukisu_is_su_allow_uid(uid_t uid)
{
	return ksu_is_allow_uid_for_current(uid) ? 1 : 0;
}

static int sukisu_is_uid_should_umount(uid_t uid)
{
	return ksu_uid_should_umount(uid) ? 1 : 0;
}

static int sukisu_is_current_uid_manager(void)
{
	return is_manager();
}

static uid_t sukisu_get_manager_uid(void)
{
	return ksu_get_manager_appid();
}

static void sukisu_set_manager_uid(uid_t uid, int force)
{
	if (force || !ksu_is_manager_appid_valid())
		ksu_set_manager_appid(uid);
}


static const struct compact_address_symbol address_symbols[] = {
	{ "kallsyms_lookup_name", (unsigned long)kallsyms_lookup_name },
	{ "compact_find_symbol",
	  (unsigned long)sukisu_compact_find_symbol },
	{ "is_run_in_sukisu_ultra", 1 },
	{ "is_su_allow_uid", (unsigned long)sukisu_is_su_allow_uid },
	{ "is_uid_should_umount", (unsigned long)sukisu_is_uid_should_umount },
	{ "is_current_uid_manager",
	  (unsigned long)sukisu_is_current_uid_manager },
	{ "get_manager_uid", (unsigned long)sukisu_get_manager_uid },
	{ "sukisu_set_manager_uid", (unsigned long)sukisu_set_manager_uid },
};

unsigned long sukisu_compact_find_symbol(const char *name)
{
	return sukisu_compact_lookup_symbol(
		name, address_symbols, ARRAY_SIZE(address_symbols),
		find_kernel_symbol_exact);
}
EXPORT_SYMBOL(sukisu_compact_find_symbol);
