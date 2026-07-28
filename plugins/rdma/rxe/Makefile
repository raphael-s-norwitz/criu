PLUGIN_NAME := rdma_rxe_plugin
PLUGIN_SOBJ := rdma_rxe_plugin.so

DEPS_RDMA_RXE := $(PLUGIN_SOBJ)

PLUGIN_INCLUDE	:= -iquote../../../include
PLUGIN_INCLUDE	+= -iquote../../../criu/include
PLUGIN_INCLUDE	+= -iquote../../../criu/arch/$(ARCH)/include/
PLUGIN_INCLUDE	+= -iquote../../../

COMPEL := ../../../compel/compel-host

PLUGIN_CFLAGS := -g -Wall -Werror -shared -nostartfiles -fPIC

__nmk_dir ?= ../../../scripts/nmk/scripts/
include $(__nmk_dir)msg.mk

all: $(DEPS_RDMA_RXE)

rdma_rxe_plugin.so: rdma_rxe_plugin.c
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
