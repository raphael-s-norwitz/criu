PLUGIN_NAME := rdma_mlx5_vfmig_plugin
PLUGIN_SOBJ := rdma_mlx5_vfmig_plugin.so

DEPS_RDMA_MLX5_VFMIG := $(PLUGIN_SOBJ)

#
# Where to find <linux/mlx5_vfmig.h>. Defaults to the vendored copy
# under uapi/. Override with e.g.
#   make MLX5_VFMIG_UAPI_INCLUDE=/opt/builds/linux/include/uapi
# when iterating on the kernel UAPI in parallel; the override directory
# must contain linux/mlx5_vfmig.h directly under it (i.e. the same
# layout as the kernel's include/uapi/).
#
MLX5_VFMIG_UAPI_INCLUDE ?= $(CURDIR)/uapi

#
# Heads-up at build time if the system header disagrees with the
# vendored copy. Strictly informational -- the plugin still compiles
# against $(MLX5_VFMIG_UAPI_INCLUDE) so the developer's choice wins,
# but drift is at least loud. Skipped if the user is already overriding
# the include path (we have no opinion on a kernel-tree header vs.
# system header in that case).
#
ifeq ($(MLX5_VFMIG_UAPI_INCLUDE),$(CURDIR)/uapi)
ifneq ($(wildcard /usr/include/linux/mlx5_vfmig.h),)
ifneq ($(shell cmp -s /usr/include/linux/mlx5_vfmig.h $(CURDIR)/uapi/linux/mlx5_vfmig.h && echo same),same)
$(warning rdma_mlx5_vfmig_plugin: vendored uapi/linux/mlx5_vfmig.h \
differs from system /usr/include/linux/mlx5_vfmig.h. Plugin will be \
built against the vendored copy. Pass MLX5_VFMIG_UAPI_INCLUDE=<dir> \
to override.)
endif
endif
endif

PLUGIN_INCLUDE	:= -iquote../../../include
PLUGIN_INCLUDE	+= -iquote../../../criu/include
PLUGIN_INCLUDE	+= -iquote../../../criu/arch/$(ARCH)/include/
PLUGIN_INCLUDE	+= -iquote../../../
PLUGIN_INCLUDE	+= -isystem $(MLX5_VFMIG_UAPI_INCLUDE)

COMPEL := ../../../compel/compel-host

PLUGIN_CFLAGS := -g -Wall -Werror -shared -nostartfiles -fPIC

#
# Plugin source list. Single-pass compile (one $(CC) invocation over
# every .c) preserves -Werror's whole-program reach and keeps the rule
# trivial. Add new modules here as the plugin is built up.
#
PLUGIN_SRCS := rdma_mlx5_vfmig_plugin.c
PLUGIN_SRCS += vfmig_pci.c

__nmk_dir ?= ../../../scripts/nmk/scripts/
include $(__nmk_dir)msg.mk

all: $(DEPS_RDMA_MLX5_VFMIG)

rdma_mlx5_vfmig_plugin.so: $(PLUGIN_SRCS)
	$(call msg-gen, $@)
	$(Q) $(CC) $(PLUGIN_CFLAGS) $(DEFINES) $(shell $(COMPEL) includes) $^ -o $@ $(PLUGIN_INCLUDE) $(PLUGIN_LDFLAGS)

clean:
	$(call msg-clean, $@)
	$(Q) $(RM) $(PLUGIN_SOBJ)
.PHONY: clean

mrproper: clean

install:
	$(Q) mkdir -p $(DESTDIR)$(PLUGINDIR)
	$(E) "  INSTALL " $(PLUGIN_NAME)
	$(Q) install -m 755 $(PLUGIN_SOBJ) $(DESTDIR)$(PLUGINDIR)
.PHONY: install

uninstall:
	$(E) " UNINSTALL" $(PLUGIN_NAME)
	$(Q) $(RM) $(DESTDIR)$(PLUGINDIR)/$(PLUGIN_SOBJ)
.PHONY: uninstall
