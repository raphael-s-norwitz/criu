# INTERNAL VALIDATION ONLY -- drop before upstream PR.

CFLAGS  ?= -Wall -Wextra -O2 -g
LDLIBS  := -libverbs

all: uverbs_ctx_holder

uverbs_ctx_holder: uverbs_ctx_holder.c

clean:
	$(RM) uverbs_ctx_holder

.PHONY: all clean
