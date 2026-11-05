# INTERNAL VALIDATION ONLY -- drop before upstream PR.

CFLAGS  ?= -Wall -Wextra -O2 -g

all: uverbs_ctx_holder vfmig_barrier_peer qp_gid_holder

uverbs_ctx_holder: LDLIBS := -libverbs
uverbs_ctx_holder: uverbs_ctx_holder.c

# Self-loop RC QP over an IPv4 RoCEv2 GID, for run_vfmig_qp_traffic_cr.sh.
qp_gid_holder: LDLIBS := -libverbs
qp_gid_holder: qp_gid_holder.c

# Standalone barrier peer stand-in (wire-only; no libibverbs).
vfmig_barrier_peer: vfmig_barrier_peer.c

clean:
	$(RM) uverbs_ctx_holder vfmig_barrier_peer qp_gid_holder

.PHONY: all clean
