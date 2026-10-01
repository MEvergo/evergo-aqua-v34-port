#
# Copyright (C) 2017 MediaTek Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

FPSGO_TOP = $(srctree)/drivers/misc/mediatek/performance/fpsgo_v3
FBT_TOP = $(FPSGO_TOP)/fbt
COMP_TOP = $(FPSGO_TOP)/composer
MTK_TOP = $(srctree)/drivers/misc/mediatek
BASE_TOP = $(FPSGO_TOP)/base
FSTB_TOP = $(FPSGO_TOP)/fstb
EARA_TOP = $(FPSGO_TOP)/eara_job

ccflags-y += -DNR_FREQ_CPU=16

ifeq ($(CONFIG_MACH_MT6893),y)
obj-y += platform/mt6893/fbt_cpu_platform.o
else ifeq ($(CONFIG_MACH_MT6877),y)
obj-y += platform/mt6877/fbt_cpu_platform.o
else
obj-y += platform/$(MTK_PLATFORM)/fbt_cpu_platform.o
endif

ifeq ($(CONFIG_MACH_MT6893),y)
CONFIG_FPSGO_THERMAL_SUPPORT := y
ccflags-y += -DCONFIG_FPSGO_THERMAL_SUPPORT
else
CONFIG_FPSGO_THERMAL_SUPPORT := n
endif

obj-y += \
	src/fbt_cpu.o \
	src/xgf.o \
	src/mini_top.o \
	src/uboost.o \

obj-$(CONFIG_FPSGO_THERMAL_SUPPORT) += src/thermal_aware.o
ifeq ($(CONFIG_MTK_FPSGO_XGF3_BUILTIN),y)
# Clang 11 bitcode cannot join Clang 22 unified LTO; generate PIC ELF under O=.
xgf_vendor_input := $(objtree)/xgf_v3_ko_arm64_cfi.vendor.o
xgf_vendor_sha256 := bdd036932fb255c63f224020413f78d015e0751887dba0e752334da0cefcd480
ifneq ($(firstword $(shell sha256sum $(xgf_vendor_input) 2>/dev/null)),$(xgf_vendor_sha256))
$(error Missing or mismatched private XGF3 bitcode: $(xgf_vendor_input))
endif

obj-y += src/xgf_v3_ko_arm64_cfi.o src/xgf_vendor_init.o

quiet_cmd_xgf_vendor_codegen = XGF3    $@
      cmd_xgf_vendor_codegen = $(CC) --target=aarch64-linux-gnu \
	-x ir -c -fno-lto -fPIC -fno-sanitize=cfi $(xgf_vendor_input) -o $@

$(obj)/src/xgf_v3_ko_arm64_cfi.o: $(xgf_vendor_input) FORCE
	$(call if_changed,xgf_vendor_codegen)
endif


ccflags-y += \
	-I$(srctree)/include/ \
	-I$(MTK_TOP)/include/ \
	-I$(FPSGO_TOP)/base/include/ \
	-I$(COMP_TOP)/include/ \
	-I$(FBT_TOP)/include/ \
	-I$(BASE_TOP)/include/ \
	-I$(MTK_TOP)/base/power/include/ \
	-I$(MTK_TOP)/base/power/$(MTK_PLATFORM)/ \
	-I$(FSTB_TOP)/ \
	-I$(EARA_TOP)/include/ \
	-I$(srctree)/kernel/ \
	-I$(MTK_TOP)/thermal/$(MTK_PLATFORM)/inc/ \
	-I$(MTK_TOP)/thermal/$(MTK_PLATFORM)/inc/mach \
	-I$(MTK_TOP)/include/mt-plat \
	-I$(MTK_TOP)/include/mt-plat/$(MTK_PLATFORM)/include/mach
