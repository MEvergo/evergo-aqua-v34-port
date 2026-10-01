# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2019 MediaTek Inc.
#
# Connsys FEM (Front-End-Module) driver, built into vmlinux.
#
# Provenance (all files GPL-2.0, see NOTICE):
#   source:  https://github.com/rufnx-prjkt/mtk_module_connectivity
#   commit:  855b454743600e5cd0650daa7713b29a6f079a16  ("Update README.md")
#   path:    connfem/
#   license: GPL-2.0 (SPDX headers on every file + connfem/NOTICE)
#
# This is the same implementation as the stock /vendor/lib/modules/connfem.ko
# shipped with the evergo ROM: identical of_match_table strings, identical
# exported API set, and an identical connfem_is_internal() body. The only
# change is module_init/module_exit -> device_initcall for in-tree build.
#
# CONFIG_MTK_COMBO_CONNFEM is defined in the parent connectivity/Kconfig.
#

ccflags-y += -Wall
ccflags-y += -D CONNFEM_TEST_ENABLED=0
ccflags-y += -I$(src)/include

obj-$(CONFIG_MTK_COMBO_CONNFEM) += connfem.o

connfem-y += connfem_module.o
connfem-y += connfem_api.o
connfem-y += connfem_container.o
connfem-y += connfem_dt_parser.o
connfem-y += connfem_epaelna.o
connfem-y += connfem_subsys_bt.o
connfem-y += connfem_subsys_wifi.o

# connfem_is_internal() is resolved by the __weak default in connfem_module.c,
# which returns false (customer load). This matches the stock vendor connfem.ko
# shipped with the evergo ROM: its connfem_is_internal() compiles to `mov w0, wzr`.
# Do NOT link connfem_internal.o: it returns true and would select the
# 'epa_elna_mtk' node name, diverging from the vendor behaviour.
