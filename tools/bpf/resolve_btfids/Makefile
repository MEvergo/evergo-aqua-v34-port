# SPDX-License-Identifier: GPL-2.0-only
include ../../scripts/Makefile.include
include ../../scripts/Makefile.arch

srctree := $(abspath $(CURDIR)/../../../)

ifeq ($(V),1)
  Q =
  msg =
else
  Q = @
  ifeq ($(silent),1)
    msg =
  else
    msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
  endif
  MAKEFLAGS=--no-print-directory
endif

# always use the host compiler
AR       = $(if $(HOSTAR),$(HOSTAR),ar)
CC       = $(HOSTCC)
LD       = $(if $(HOSTLD),$(HOSTLD),ld)
ARCH     = $(HOSTARCH)
RM      ?= rm

OUTPUT ?= $(srctree)/tools/bpf/resolve_btfids/

SUBCMD_SRC := $(srctree)/tools/lib/subcmd/

SUBCMDOBJ  := $(OUTPUT)/libsubcmd/libsubcmd.a

BINARY     := $(OUTPUT)/resolve_btfids
BINARY_IN  := $(BINARY)-in.o

all: $(BINARY)

$(OUTPUT) $(OUTPUT)/libsubcmd:
	$(call msg,MKDIR,,$@)
	$(Q)mkdir -p $(@)

$(SUBCMDOBJ): fixdep FORCE | $(OUTPUT)/libsubcmd
	$(Q)$(MAKE) -C $(SUBCMD_SRC) OUTPUT=$(abspath $(dir $@))/ $(abspath $@)


PKG_CONFIG ?= pkg-config
LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null)
LIBBPF_INCLUDEDIR := $(shell $(PKG_CONFIG) --variable=includedir libbpf 2>/dev/null)
ifeq ($(strip $(LIBBPF_LIBS)),)
$(error libbpf development files are required (pkg-config libbpf))
endif

CFLAGS := -g \
          -I$(LIBBPF_INCLUDEDIR)/bpf \
          -I$(LIBBPF_INCLUDEDIR) \
          -I$(srctree)/tools/include \
          -I$(SUBCMD_SRC) \
          $(LIBBPF_CFLAGS)

LIBS = $(LIBBPF_LIBS) -lelf -lz

export srctree OUTPUT CFLAGS Q
include $(srctree)/tools/build/Makefile.include

$(BINARY_IN): fixdep FORCE | $(OUTPUT)
	$(Q)$(MAKE) $(build)=resolve_btfids

$(BINARY): $(SUBCMDOBJ) $(BINARY_IN)
	$(call msg,LINK,$@)
	$(Q)$(CC) $(BINARY_IN) $(LDFLAGS) -o $@ $(SUBCMDOBJ) $(LIBS)

clean_objects := $(wildcard $(OUTPUT)/*.o                \
                            $(OUTPUT)/.*.o.cmd           \
                            $(OUTPUT)/.*.o.d             \
                            $(OUTPUT)/libsubcmd          \
                            $(OUTPUT)/resolve_btfids)

ifneq ($(clean_objects),)
clean: fixdep-clean
	$(call msg,CLEAN,$(BINARY))
	$(Q)$(RM) -rf $(clean_objects)
else
clean:
endif

tags:
	$(call msg,GEN,,tags)
	$(Q)ctags -R . $(SUBCMD_SRC)

FORCE:

.PHONY: all FORCE clean tags
