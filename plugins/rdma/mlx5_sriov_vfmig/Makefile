PLUGIN_NAME := rdma_mlx5_vfmig_plugin
PLUGIN_SOBJ := rdma_mlx5_vfmig_plugin.so

DEPS_RDMA_MLX5_VFMIG := $(PLUGIN_SOBJ)

PLUGIN_INCLUDE	:= -iquote../../../include
PLUGIN_INCLUDE	+= -iquote../../../criu/include
PLUGIN_INCLUDE	+= -iquote../../../criu/arch/$(ARCH)/include/
PLUGIN_INCLUDE	+= -iquote../../../

COMPEL := ../../../compel/compel-host

PLUGIN_CFLAGS := -g -Wall -Werror -shared -nostartfiles -fPIC

#
# Plugin source list. Single-pass compile (one $(CC) invocation over
# every .c) preserves -Werror's whole-program reach and keeps the rule
# trivial. Add new modules here as the plugin is built up.
#
PLUGIN_SRCS := rdma_mlx5_vfmig_plugin.c

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
