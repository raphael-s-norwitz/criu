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

/*
 * Per-resource enumeration. Used by R3 (per-uobject restore)
 * dump-side discovery in criu/rdma/uobj_dump.c -- walk the uobjects
 * on a given ibdev and surface the hw-agnostic attrs the kernel emits
 * via NLDEV today.
 *
 * v0 scopes this to PD only (the T1.1 milestone); CQ/QP/MR/SRQ arms
 * land in their own milestones as the enum and the per-type leaf union
 * grow (append-only, so the e->pd.* access pattern below stays stable).
 *
 * Each per-resource walker takes a single ibdev (named by dev_index,
 * the same kernel-side index returned by rdma_nl_for_each_context).
 * The kernel's RES_*_GET dumps require a per-device argument (no
 * host-wide variant exists), so callers that want every device must
 * enumerate ibdev indices first -- use rdma_nl_for_each_context to
 * harvest them, or rdma_nl_for_each_ibdev for the bare list.
 *
 * Field availability for PD tracks the kernel's fill_res_pd_entry:
 *   pd.usecnt; restrack_id (RES_PDN), ctxn (RES_CTXN), pid (RES_PID)
 *   always set for user PDs.
 *
 * Per-uobject ufile_handle (the per-ufile obj->id user code holds in
 * its restored memory) is emitted by the kernel for every
 * user-created resource as of upstream commit 0601c496b413 (K8a,
 * design/uobject_restore.md 7.5.1). On older kernels the attribute is
 * absent and has_ufile_handle stays false; on newer kernels we read
 * RDMA_NLDEV_ATTR_RES_HANDLE -- the join key the R3 dump path needs to
 * install the restored uobject at the same handle user code cached.
 * Build-time probe FEATURE_TEST_RDMA_NLDEV_ATTR_RES_HANDLE in
 * scripts/feature-tests.mak gates the symbol availability for the
 * compat shim in netlink.c; runtime presence is independent and is
 * reported by has_ufile_handle.
 *
 * The "has_*" booleans gate fields the kernel makes conditional; the
 * caller must check them before reading the matching value.
 *
 * Iterator return semantics match rdma_nl_for_each_context.
 */
enum rdma_nl_res_type {
	RDMA_NL_RES_PD,
};

struct rdma_nl_res_entry {
	enum rdma_nl_res_type type;
	uint32_t dev_index;
	char ibdev[64];

	/*
	 * Kernel-side identity. has_* semantics reflect what the
	 * kernel's fill_res_<type>_entry currently emits; NLDEV is
	 * stable enough that we treat absence as "feature not emitted
	 * yet" rather than as protocol uncertainty.
	 */
	bool has_restrack_id;
	uint32_t restrack_id; /* PDN */
	bool has_ctxn;
	uint32_t ctxn;
	bool has_pid;
	pid_t pid; /* RES_PID */
	bool has_ufile_handle;
	uint32_t ufile_handle; /* ib_uobject->id; needs K8a kernel */

	/* Per-type leaves -- read after switch on `type`. */
	union {
		struct {
			uint64_t usecnt;
		} pd;
	};
};

typedef int (*rdma_nl_res_cb_t)(const struct rdma_nl_res_entry *e, void *arg);

int rdma_nl_for_each_resource(uint32_t dev_index, const char *ibdev, enum rdma_nl_res_type type, rdma_nl_res_cb_t cb,
			      void *arg);

/*
 * Bare ibdev enumeration. Convenience wrapper that emits one
 * (dev_index, ibdev) per host ibdev. Same NLDEV CMD_GET dump as
 * rdma_nl_for_each_context's first phase, exposed standalone so
 * callers that don't need ucontext info don't pay for the per-device
 * CTX_GET that follows.
 */
typedef int (*rdma_nl_ibdev_cb_t)(uint32_t dev_index, const char *ibdev, void *arg);
int rdma_nl_for_each_ibdev(rdma_nl_ibdev_cb_t cb, void *arg);

#endif /* __CR_RDMA_NETLINK_H__ */
