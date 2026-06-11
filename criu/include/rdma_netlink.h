#ifndef __CR_RDMA_NETLINK_H__
#define __CR_RDMA_NETLINK_H__

/*
 * Thin wrapper around the kernel's RDMA netlink interface
 * (RDMA_NL_NLDEV / NETLINK_RDMA), used by criu/rdma.c to enumerate
 * live ibv_contexts on the host without freezing or otherwise
 * touching the target.
 *
 * Today this only exposes one operation -- iterate every live RDMA
 * context across every pid. That's what the dump-coverage pre-flight
 * needs (does the snapshot tree hold any context that no loaded
 * plugin can claim?) and, in a follow-up commit, what the cross-tree
 * exclusivity check needs (do non-snapshot-tree pids hold contexts
 * on devices our plugins consider exclusive?).
 *
 * Long term this layer is also where hw-agnostic per-resource
 * attribute dumps will live: PD/MR/CQ/QP enumeration, port query,
 * device caps. Those will land as additional rdma_nl_for_each_*
 * iterators sharing the same socket open/close machinery.
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
	uint32_t dev_index;	/* kernel ibdev index from RDMA_NLDEV_ATTR_DEV_INDEX */
	char ibdev[64];		/* RDMA_NLDEV_ATTR_DEV_NAME */
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
typedef int (*rdma_nl_ctx_cb_t)(const struct rdma_nl_ctx_info *info,
				void *arg);

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
 * dump-side discovery in criu/rdma.c -- walk every PD/CQ/QP/MR/SRQ
 * on a given ibdev, surface the hw-agnostic attrs the kernel emits
 * via NLDEV today.
 *
 * Each per-resource walker takes a single ibdev (named by
 * dev_index, the same kernel-side index returned by
 * rdma_nl_for_each_context). The kernel's RES_*_GET dumps require
 * a per-device argument (no host-wide variant exists), so callers
 * that want every device must enumerate ibdev indices first --
 * use rdma_nl_for_each_context to harvest them, or rdma_nl_for_
 * each_ibdev for the bare list.
 *
 * Field availability per resource type tracks the kernel's
 * fill_res_<type>_entry coverage as of v6.x:
 *
 *   PD   pd.usecnt; restrack_id, ctxn always set.
 *   CQ   cq.cqe, cq.usecnt; restrack_id, ctxn always set.
 *   QP   qp.lqpn, qp.{has_rqpn?, has_rq_psn?, has_sq_psn?,
 *        qp_type, qp_state, port}; pdn always set, restrack_id
 *        and ctxn currently absent (kernel doesn't emit RES_QPN
 *        as restrack id, doesn't emit RES_CTXN -- per K1 doc).
 *   MR   mr.{mrlen, has_lkey?, has_rkey?, has_iova?}; pdn,
 *        restrack_id always set; ctxn absent until K1.
 *   SRQ  srq.{srq_type, has_cqn?}; pdn, restrack_id always set;
 *        ctxn absent until K1.
 *
 * Per-uobject ufile_handle (the per-ufile obj->id user code holds in
 * its restored memory) is emitted by the kernel for every
 * user-created resource as of upstream commit 0601c496b413 (K8a,
 * design/uobject_restore.md §7.5.1). On older kernels the attribute
 * is absent and `has_ufile_handle` stays false; on newer kernels we
 * read RDMA_NLDEV_ATTR_RES_HANDLE -- the join key the R3 dump path
 * needs to map a parent restrack_id (e.g. QP's parent_pdn) onto the
 * caller-specified target_handle K3 RESTORE_<TYPE> methods install
 * at. Build-time probe FEATURE_TEST_RDMA_NLDEV_ATTR_RES_HANDLE in
 * scripts/feature-tests.mak gates the symbol availability for the
 * compat shim in rdma_netlink.c; runtime presence is independent and
 * is reported by has_ufile_handle.
 *
 * The "has_*" booleans gate fields the kernel makes conditional on
 * QP type / CAP_NET_ADMIN / etc. Callers must check them before
 * reading the matching value.
 *
 * Iterator return semantics match rdma_nl_for_each_context.
 */
enum rdma_nl_res_type {
	RDMA_NL_RES_PD,
	RDMA_NL_RES_CQ,
	RDMA_NL_RES_QP,
	RDMA_NL_RES_MR,
	RDMA_NL_RES_SRQ,
};

struct rdma_nl_res_entry {
	enum rdma_nl_res_type	type;
	uint32_t		dev_index;
	char			ibdev[64];

	/* Kernel-side identity. has_*_id semantics reflect what the
	 * kernel's fill_res_<type>_entry currently emits; NLDEV is
	 * stable enough that we treat absence as "feature not
	 * emitted yet" (cleanup K1 etc.) rather than as protocol
	 * uncertainty. */
	bool			has_restrack_id;
	uint32_t		restrack_id;	/* PDN/CQN/MRN/SRQN; QP absent */
	bool			has_ctxn;
	uint32_t		ctxn;		/* PD/CQ direct; others wait on K1 */
	bool			has_pdn;
	uint32_t		pdn;		/* QP/MR/SRQ; PD/CQ n/a */
	bool			has_pid;
	pid_t			pid;		/* RES_PID */
	bool			has_ufile_handle;
	uint32_t		ufile_handle;	/* ib_uobject->id; needs K8a kernel */

	/*
	 * The PD's mlx5 FW identity (mpd->pdn / mpd->uid) used to be
	 * carried here, decoded from "fw_pdn" / "fw_uid" named driver
	 * TLVs under RDMA_NLDEV_ATTR_DRIVER. The kernel removed those
	 * TLVs from fill_res_pd_entry; CRIU now learns the FW pdn per-
	 * PD-handle via the mlx5 plugin's MLX5_IB_METHOD_VFMIG_QUERY_PD
	 * verb (dump-side CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_PD), the same
	 * per-handle QUERY plane used for cqn (QUERY_CQ) and qpn
	 * (QUERY_QP). No NLDEV-derived FW PD fields remain.
	 */

	/* Per-type leaves -- read after switch on `type`. */
	union {
		struct {
			uint64_t usecnt;
		} pd;
		struct {
			uint32_t cqe;
			uint64_t usecnt;
		} cq;
		struct {
			uint32_t lqpn;
			bool has_rqpn;
			uint32_t rqpn;
			bool has_rq_psn;
			uint32_t rq_psn;
			bool has_sq_psn;
			uint32_t sq_psn;
			uint8_t qp_type;
			uint8_t qp_state;
			bool has_port;
			uint32_t port;
			/*
			 * SEND_CQN / RECV_CQN are the parent CQs' restrack
			 * ids -- the join key R3 turns into SEND_CQ /
			 * RECV_CQ xref edges. They are NOT emitted by
			 * fill_res_qp_entry today: the kernel surfaces
			 * dest_qp_num / lqpn / pdn / psns / port but not
			 * the per-QP CQ binding. UVERBS_METHOD_RESTORE_QP
			 * needs both as MANDATORY IDR(UVERBS_OBJECT_CQ)
			 * attrs and the dispatcher rejects with -ENOENT
			 * before the driver runs, so without these fields
			 * the QP restore path can't be wired.
			 *
			 * Pending kernel ask: extend fill_res_qp_entry to
			 * emit RDMA_NLDEV_ATTR_RES_SEND_CQN /
			 * RDMA_NLDEV_ATTR_RES_RECV_CQN (mirrors the
			 * existing fill_res_srq_entry RES_CQN emission).
			 * Until landed, has_send_cqn / has_recv_cqn stay
			 * false and the dump-side QP walker emits R3UT_QP
			 * entries with no SEND_CQ / RECV_CQ xrefs -- which
			 * the master-side master/PIE seam refuses with a
			 * clear "needs RES_{SEND,RECV}_CQN" diagnostic.
			 */
			bool has_send_cqn;
			uint32_t send_cqn;
			bool has_recv_cqn;
			uint32_t recv_cqn;
		} qp;
		struct {
			uint64_t mrlen;
			bool has_iova;
			uint64_t iova;
			bool has_lkey;
			uint32_t lkey;
			bool has_rkey;
			uint32_t rkey;
		} mr;
		struct {
			uint8_t srq_type;
			bool has_cqn;
			uint32_t cqn;
		} srq;
	};
};

typedef int (*rdma_nl_res_cb_t)(const struct rdma_nl_res_entry *e,
				void *arg);

int rdma_nl_for_each_resource(uint32_t dev_index, const char *ibdev,
			      enum rdma_nl_res_type type,
			      rdma_nl_res_cb_t cb, void *arg);

/*
 * Bare ibdev enumeration. Convenience wrapper that emits one
 * (dev_index, ibdev) per host ibdev. Same NLDEV CMD_GET dump as
 * rdma_nl_for_each_context's first phase, exposed standalone so
 * callers that don't need ucontext info don't pay for the
 * per-device CTX_GET that follows.
 */
typedef int (*rdma_nl_ibdev_cb_t)(uint32_t dev_index, const char *ibdev,
				  void *arg);
int rdma_nl_for_each_ibdev(rdma_nl_ibdev_cb_t cb, void *arg);

#endif /* __CR_RDMA_NETLINK_H__ */
