/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __SUKISU_KPM_ABI_SYMBOLS_H
#define __SUKISU_KPM_ABI_SYMBOLS_H

unsigned long *kpm_abi_find_function_slot(const char *name,
					 const char **kernel_symbol);

#endif
