#ifndef __CR_RDMA_NETLINK_H__
#define __CR_RDMA_NETLINK_H__

/*
 * Thin wrapper around the kernel's RDMA netlink interface
 * (RDMA_NL_NLDEV / NETLINK_RDMA), used by criu/rdma to enumerate live
 * ibv_contexts on the host without freezing or otherwise touching the
 * target.
 *
 * Today this only exposes one operation -- iterate every live RDMA
 * context across every pid. That's what the dump-coverage pre-flight
 * needs (does the snapshot tree hold any context that no loaded plugin
 * can claim?) and what the cross-tree exclusivity check needs (do
 * non-snapshot-tree pids hold contexts on devices our plugins consider
 * exclusive?).
 *
 * Long term this layer is also where hw-agnostic per-resource
 * attribute dumps will live: PD/MR/CQ/QP enumeration, port query,
 * device caps. Those land as additional rdma_nl_for_each_* iterators
 * sharing the same socket open/close machinery.
 */

#include <stdint.h>
#include <sys/types.h>

/*
 * Per-context entry returned to the iterator callback. Stays
 * pid-namespace-naive for now: pid is the kernel-side pid the netlink
 * dump emits, which equals the host pid we get out of pstree's
 * pid->real -- callers need to be careful when criu eventually grows
 * pidns-aware RDMA support, but we have no such users yet.
 */
struct rdma_nl_ctx_info {
	pid_t pid;
	uint32_t ctxn;
	uint32_t dev_index; /* kernel ibdev index from RDMA_NLDEV_ATTR_DEV_INDEX */
	char ibdev[64];	    /* RDMA_NLDEV_ATTR_DEV_NAME */
};

/*
 * Iterator return value semantics:
 *   0      -> continue iterating
 *   != 0   -> stop iterating, propagate this value as
 *             rdma_nl_for_each_context() return
 *
 * Returning a positive value lets callers signal "early-exit success"
 * (e.g. "found what I was looking for") without colliding with
 * negative-errno failure conventions.
 */
typedef int (*rdma_nl_ctx_cb_t)(const struct rdma_nl_ctx_info *info, void *arg);

/*
 * Walk every live RDMA context on the host. Returns 0 if all contexts
 * were enumerated without the callback reporting a stop, the callback's
 * non-zero value if it stopped iteration early, or a negative errno on
 * netlink-layer failures (socket open, send/recv, parse).
 *
 * Cheap by netlink standards but not zero-cost: opens NETLINK_RDMA,
 * issues an NLM_F_DUMP, parses every reply. Caller should not loop
 * this on a hot path; cache the results if you need to query
 * repeatedly.
 */
int rdma_nl_for_each_context(rdma_nl_ctx_cb_t cb, void *arg);

#endif /* __CR_RDMA_NETLINK_H__ */
