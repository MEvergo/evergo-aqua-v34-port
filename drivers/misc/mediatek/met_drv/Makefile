ifeq ($(ARCH), arm)
ccflags-y += -DCONFIG_MET_ARM_32BIT
endif	# ifeq ($(ARCH), arm)

obj-y += met_api.o

ifeq ($(PATCHLEVEL),)
$(error VERSION is not defined)
endif

ifeq ($(PATCHLEVEL),)
$(error PATCHLEVEL is not defined)
endif

CONFIG_KERVER_VERSION := $(VERSION).$(PATCHLEVEL)

#CONFIG_MTK_MET_BUILT_IN := y
ifeq ($(CONFIG_MTK_MET_BUILT_IN),y)
ccflags-y += -DMTK_MET_BUILT_IN
MTK_PLATFORM := $(subst ",,$(CONFIG_MTK_PLATFORM))
MTK_FAMILY_PLATFORM := $(MTK_PLATFORM)
# The device is MT6833 even though CONFIG_MTK_PLATFORM names the mt6853
# driver family. Mirror the vendor MET Makefile: the mach symbol selects the
# MET platform directory, otherwise MET_PLF_DIR would silently miss and MET
# would degrade to a stub core (no real sampler/EMI/GPU/tinysys features).
ifeq ($(CONFIG_MACH_MT6833),y)
    MTK_PLATFORM := mt6833
endif
ifeq ($(CONFIG_MACH_MT6893),y)
    MTK_PLATFORM := mt6893
endif
ifeq ($(CONFIG_MACH_MT6877),y)
    MTK_PLATFORM := mt6877
endif
ifeq ($(CONFIG_MACH_MT6781),y)
    MTK_PLATFORM := mt6781
endif
# Vendor MET_CORE lives in-tree so the built-in broker (met_api.o) and the
# real driver core link into the same vmlinux; the upstream out-of-tree
# vendor/mediatek path is not present in this kernel tree.
MET_ROOT_DIR := $(srctree)/$(src)/met_core
MET_COMMON_DIR := $(wildcard $(MET_ROOT_DIR)/common)
MET_PLF_DIR := $(wildcard $(MET_ROOT_DIR)/$(MTK_PLATFORM))

# mt-plat/met_drv.h in the kernel shares the MET_DRV include guard with the
# donor met_core/common/met_drv.h. When the kernel mt-plat/ directory is
# earlier on the search path (as in a full Image build), metk_emi_bm.h and
# friends resolve "met_drv.h" to the kernel copy, whose guard then hides the
# donor's MET_TRACE/MET_PRINTK definitions. Prepend the met_core directories
# to LINUXINCLUDE so the vendor header always wins inside this subtree.
LINUXINCLUDE := -I$(MET_COMMON_DIR) -I$(MET_PLF_DIR) $(LINUXINCLUDE)

ifeq ($(CONFIG_FTRACE),y)
    ifeq ($(CONFIG_TRACING),y)
        FTRACE_READY := y
    endif
endif

$(info ******** Start to built in met_drv for $(MTK_PLATFORM) ********)
ifneq ($(MET_PLF_DIR),)
    ifeq ($(FTRACE_READY),y)
        # Prefix met-y objects with the in-tree met_core/ layout so they are
        # resolved relative to this directory (kbuild $(obj)).
        MET_CORE := met_core/common
        include $(MET_COMMON_DIR)/Kbuild
    else
        $(error CONFIG_MTK_MET_BUILT_IN needs CONFIG_FTRACE=y and CONFIG_TRACING=y for $(MTK_PLATFORM))
    endif
else
    $(error CONFIG_MTK_MET_BUILT_IN set but no met_core/$(MTK_PLATFORM) platform directory; refusing default-stub fallback)
endif

endif