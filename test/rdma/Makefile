# INTERNAL VALIDATION ONLY -- drop before upstream PR.

CFLAGS  ?= -Wall -Wextra -O2 -g
LDLIBS  := -libverbs

PLUGIN_CFLAGS := -g -Wall -Werror -shared -nostartfiles -fPIC
PLUGIN_INCLUDE := -iquote ../../include
PLUGIN_INCLUDE += -iquote ../../criu/include
PLUGIN_INCLUDE += -iquote ../../

all: uverbs_ctx_holder rdma_rxe_test_exclusive_plugin.so

uverbs_ctx_holder: uverbs_ctx_holder.c

# Test-only plugin that mirrors the rxe claim hook but declares the
# device EXCLUSIVE, so we can drive the cross-tree exclusivity hard-
# fail path without needing real exclusive-by-construction hardware.
rdma_rxe_test_exclusive_plugin.so: test_exclusive_rxe_plugin.c
	$(CC) $(PLUGIN_CFLAGS) $(PLUGIN_INCLUDE) $< -o $@

clean:
	$(RM) uverbs_ctx_holder rdma_rxe_test_exclusive_plugin.so

.PHONY: all clean
