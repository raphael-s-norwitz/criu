/*
 * R3 restore-side: per-uobject DAG collect + per-ufile dispatch.
 *
 * Public surface (declared in criu/include/rdma.h):
 *
 *   rdma_collect_uobj_dag()             read+group+verify pass on
 *                                       rdma_uobj.img, called once
 *                                       early in restore.
 *   rdma_restore_uobj_dag_for_ufile()   per-cdev-fd dispatcher; called
 *                                       from uverbsfd_open() after the
 *                                       claiming plugin hands back an
 *                                       open cdev fd carrying a
 *                                       restore-mode ucontext.
 *
 * File-private state:
 *
 *   rdma_uobj_groups   per-ufile groups built by rdma_collect_uobj_dag()
 *                      and read by rdma_restore_uobj_dag_for_ufile().
 *                      Lives for the rest of the restore (freed at
 *                      process exit by design -- no release entry).
 *
 * v0 scope (rxe PD + MR + CQ + QP): collect + group, then a dependency-
 * ordered per-ufile walk. Roots first -- PDs then CQs (RESTORE_PD /
 * RESTORE_CQ, synchronous on cmd_fd) -- then MRs, then QPs. An MR
 * carries no ctxn and references its parent PD by the source restrack
 * id, so the walk resolves that edge to the parent's destination handle
 * through the per-ufile (type, restrack_id) -> ufile_handle map the PD
 * and CQ passes build. The RESTORE_MR ioctl itself is deferred to the
 * pie restorer (it must run in the target's restored address space so
 * the MR's user_addr pages are pinnable); this file prepares each MR
 * here -- resolves its parent handle and queues a fully-populated
 * record -- and rdma_prepare_rdma_mrs() later bursts the queue into the
 * pie restorer's RM_PRIVATE args, where restore_rdma_mr issues the ioctl
 * post-VMA. A CQ carries driver-private ring state whose UHW the owning
 * plugin reshapes (RESTORE_UOBJ_CQ_UHW_PACK); the verb runs master-side
 * because rxe registers a kernel-ring mmap slot the pie's VMA pass then
 * maps. A QP binds its parent PD and both CQs (resolved through the map)
 * and likewise carries driver-private wire state the plugin reshapes
 * (RESTORE_UOBJ_QP_UHW_PACK); it too runs master-side so the SQ/RQ ring
 * slots exist before the VMA pass. The SRQ arm follows in its milestone.
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <rdma/rdma_user_ioctl_cmds.h>
#include <rdma/ib_user_ioctl_cmds.h>

#include "common/compiler.h"
#include "common/list.h"
#include "criu-plugin.h"
#include "image.h"
#include "log.h"
#include "protobuf.h"
#include "rdma.h"
#include "restorer.h"
#include "rst-malloc.h"
#include "xmalloc.h"

#include "images/rdma_uobj.pb-c.h"

/*
 * High-fd floor for the per-MR cdev dups handed to the pie restorer:
 * above the user-fd range CRIU's per-task file restorer reinstalls into
 * and below service_fd_base. The pie closes each after its RESTORE_MR.
 */
#define RDMA_PIE_CMD_FD_MIN (1 << 14)

#undef LOG_PREFIX
#define LOG_PREFIX "rdma: "

/*
 * UAPI lag shim for UVERBS_OBJECT_RESTORE / UVERBS_METHOD_RESTORE_PD /
 * UVERBS_ATTR_RESTORE_PD_HANDLE.
 *
 * Upstream kernel include/uapi/rdma/ib_user_ioctl_cmds.h carries
 *   UVERBS_OBJECT_RESTORE         = 18
 *   UVERBS_METHOD_RESTORE_PD      = 0    (within OBJECT_RESTORE)
 *   UVERBS_ATTR_RESTORE_PD_HANDLE = 0    (within METHOD_RESTORE_PD)
 *
 * The kernel matches by integer at wire time, never by enumerator
 * name, so a stable numeric copy here is enough to talk to a kernel
 * that has the support; a too-old kernel returns -EOPNOTSUPP for the
 * unknown object_id, which is the already-handled "kernel too old"
 * signal. Drop the shim once the build's minimum rdma-core ships these
 * symbols.
 */
#ifndef UVERBS_OBJECT_RESTORE
#define UVERBS_OBJECT_RESTORE 18
#endif
#ifndef UVERBS_METHOD_RESTORE_PD
#define UVERBS_METHOD_RESTORE_PD 0
#endif
#ifndef UVERBS_ATTR_RESTORE_PD_HANDLE
#define UVERBS_ATTR_RESTORE_PD_HANDLE 0
#endif

/*
 * UAPI lag shim for UVERBS_METHOD_RESTORE_CQ and its attributes
 * (enum uverbs_methods_restore / uverbs_attrs_restore_cq in the kernel's
 * include/uapi/rdma/ib_user_ioctl_cmds.h). Same numeric-copy rationale
 * as the RESTORE_PD block above: the kernel matches by integer, so this
 * is enough to drive a kernel that has the support; a too-old kernel
 * returns -EOPNOTSUPP for the unknown method. The COMP_CHANNEL / EVENT_FD
 * attrs are intentionally omitted -- v0 rejects CC-bound CQs at dump time
 * (see dump_uverbsfile_cc_precheck) and lets the kernel default the async
 * file, so core never emits them.
 */
#ifndef UVERBS_METHOD_RESTORE_CQ
#define UVERBS_METHOD_RESTORE_CQ 2
#endif
#ifndef UVERBS_ATTR_RESTORE_CQ_HANDLE
#define UVERBS_ATTR_RESTORE_CQ_HANDLE 0
#endif
#ifndef UVERBS_ATTR_RESTORE_CQ_CQE
#define UVERBS_ATTR_RESTORE_CQ_CQE 1
#endif
#ifndef UVERBS_ATTR_RESTORE_CQ_USER_HANDLE
#define UVERBS_ATTR_RESTORE_CQ_USER_HANDLE 2
#endif
#ifndef UVERBS_ATTR_RESTORE_CQ_COMP_VECTOR
#define UVERBS_ATTR_RESTORE_CQ_COMP_VECTOR 3
#endif
#ifndef UVERBS_ATTR_RESTORE_CQ_FLAGS
#define UVERBS_ATTR_RESTORE_CQ_FLAGS 4
#endif
#ifndef UVERBS_ATTR_RESTORE_CQ_RESP_CQE
#define UVERBS_ATTR_RESTORE_CQ_RESP_CQE 7
#endif

/*
 * UAPI lag shim for UVERBS_METHOD_RESTORE_QP and its attributes
 * (enum uverbs_methods_restore / uverbs_attrs_restore_qp in the kernel's
 * include/uapi/rdma/ib_user_ioctl_cmds.h). Same numeric-copy rationale
 * as the RESTORE_PD / RESTORE_CQ blocks above: the kernel matches by
 * integer, so a stable numeric copy is enough to drive a kernel that has
 * the support; a too-old kernel returns -EOPNOTSUPP for the unknown
 * method. The SRQ / CREATE_FLAGS / EVENT_FD attrs are intentionally
 * omitted -- v0 restores plain RC/UD/UC QPs with no SRQ, no vendor
 * create_flags (rxe rejects them), and lets the kernel default the async
 * file, so core never emits them.
 */
#ifndef UVERBS_METHOD_RESTORE_QP
#define UVERBS_METHOD_RESTORE_QP 3
#endif
#ifndef UVERBS_ATTR_RESTORE_QP_HANDLE
#define UVERBS_ATTR_RESTORE_QP_HANDLE 0
#endif
#ifndef UVERBS_ATTR_RESTORE_QP_PD_HANDLE
#define UVERBS_ATTR_RESTORE_QP_PD_HANDLE 1
#endif
#ifndef UVERBS_ATTR_RESTORE_QP_SEND_CQ_HANDLE
#define UVERBS_ATTR_RESTORE_QP_SEND_CQ_HANDLE 2
#endif
#ifndef UVERBS_ATTR_RESTORE_QP_RECV_CQ_HANDLE
#define UVERBS_ATTR_RESTORE_QP_RECV_CQ_HANDLE 3
#endif
#ifndef UVERBS_ATTR_RESTORE_QP_TYPE
#define UVERBS_ATTR_RESTORE_QP_TYPE 5
#endif
#ifndef UVERBS_ATTR_RESTORE_QP_STATE
#define UVERBS_ATTR_RESTORE_QP_STATE 6
#endif
#ifndef UVERBS_ATTR_RESTORE_QP_USER_HANDLE
#define UVERBS_ATTR_RESTORE_QP_USER_HANDLE 7
#endif
#ifndef UVERBS_ATTR_RESTORE_QP_CAP
#define UVERBS_ATTR_RESTORE_QP_CAP 8
#endif
#ifndef UVERBS_ATTR_RESTORE_QP_RESP_QPN
#define UVERBS_ATTR_RESTORE_QP_RESP_QPN 11
#endif

/*
 * UAPI lag shim for struct ib_uverbs_qp_cap (kernel
 * include/uapi/rdma/ib_user_ioctl_verbs.h), the PTR_IN payload of
 * UVERBS_ATTR_RESTORE_QP_CAP. A byte-identical local mirror avoids a
 * hard build dependency on a very recent rdma-core; the kernel matches
 * the 20-byte struct by size/offset at wire time, never by name. Drop
 * once the build's minimum rdma-core ships it.
 */
struct ib_uverbs_qp_cap_local {
	uint32_t max_send_wr;
	uint32_t max_recv_wr;
	uint32_t max_send_sge;
	uint32_t max_recv_sge;
	uint32_t max_inline_data;
};
_Static_assert(sizeof(struct ib_uverbs_qp_cap_local) == 20, "ib_uverbs_qp_cap_local must be 20 bytes (kernel UAPI)");

struct uobj_collected {
	RdmaUobjEntry *e;
	struct list_head link; /* link in uobj_ufile_group.entries */
};

struct uobj_ufile_group {
	uint32_t ufile_id;
	uint32_t hw_driver_id; /* taken from first entry; verified equal */
	struct list_head entries;
	int n_pd;
	int n_other;
	int n_total;
	struct list_head link;
};

/*
 * Built by rdma_collect_uobj_dag() (early in restore, before file
 * restore) and consumed by rdma_restore_uobj_dag_for_ufile() (per cdev
 * fd, from uverbsfd_open()). Lives for the rest of the restore; freed
 * at process exit, so there is deliberately no release entry point.
 */
static LIST_HEAD(rdma_uobj_groups);

static struct uobj_ufile_group *rdma_uobj_group_lookup(uint32_t ufile_id)
{
	struct uobj_ufile_group *g;

	list_for_each_entry(g, &rdma_uobj_groups, link)
		if (g->ufile_id == ufile_id)
			return g;
	return NULL;
}

static struct uobj_ufile_group *rdma_uobj_group_get_or_add(uint32_t ufile_id)
{
	struct uobj_ufile_group *g = rdma_uobj_group_lookup(ufile_id);

	if (g)
		return g;
	g = xzalloc(sizeof(*g));
	if (!g)
		return NULL;
	g->ufile_id = ufile_id;
	INIT_LIST_HEAD(&g->entries);
	INIT_LIST_HEAD(&g->link);
	list_add_tail(&g->link, &rdma_uobj_groups);
	return g;
}

static int uobj_group_add_entry(struct uobj_ufile_group *g, RdmaUobjEntry *e)
{
	struct uobj_collected *c = xzalloc(sizeof(*c));

	if (!c)
		return -1;
	c->e = e;
	INIT_LIST_HEAD(&c->link);
	list_add_tail(&c->link, &g->entries);

	if (g->n_total == 0) {
		g->hw_driver_id = e->hw_driver_id;
	} else if (g->hw_driver_id != e->hw_driver_id) {
		pr_err("uobj DAG: ufile_id=%#x mixes hw_driver_id %u and %u; image inconsistent\n", g->ufile_id,
		       g->hw_driver_id, e->hw_driver_id);
		return -1;
	}

	g->n_total++;
	switch (e->type) {
	case R3_UOBJ_TYPE__R3UT_PD:
		g->n_pd++;
		break;
	default:
		g->n_other++;
		break;
	}
	return 0;
}

int rdma_collect_uobj_dag(void)
{
	struct cr_img *img;
	struct uobj_ufile_group *g;
	int ret = -1;

	img = open_image(CR_FD_RDMA_UOBJ, O_RSTR);
	if (!img)
		return -1;
	if (empty_image(img)) {
		/* No RDMA uobjects captured at dump time. */
		close_image(img);
		return 0;
	}

	while (1) {
		RdmaUobjEntry *e = NULL;
		int r = pb_read_one_eof(img, &e, PB_RDMA_UOBJ);

		if (r < 0)
			goto out;
		if (r == 0)
			break;

		g = rdma_uobj_group_get_or_add(e->ufile_id);
		if (!g) {
			rdma_uobj_entry__free_unpacked(e, NULL);
			goto out;
		}
		if (uobj_group_add_entry(g, e)) {
			rdma_uobj_entry__free_unpacked(e, NULL);
			goto out;
		}
		/* The group keeps @e alive for the rest of the restore. */
	}

	list_for_each_entry(g, &rdma_uobj_groups, link)
		pr_info("uobj DAG: ufile_id=%#x driver=%u uobjs=%d (pd=%d other=%d)\n", g->ufile_id, g->hw_driver_id,
			g->n_total, g->n_pd, g->n_other);

	ret = 0;
out:
	close_image(img);
	return ret;
}

/*
 * Per-ufile handle map: (uobj type, source restrack_id) -> the
 * destination ufile_handle the uobject was reinstalled at. Restore
 * installs each uobject at the ufile_handle the dump recorded (source
 * handle == destination handle), and children resolve their xref edges
 * -- v0: an MR's parent PD -- to the parent's handle through this map.
 * PD has no incoming edges but is a target, so the PD pass writes it
 * and the MR pass reads it.
 */
struct uobj_handle_map_entry {
	R3UobjType type;
	uint32_t restrack_id;
	uint32_t ufile_handle;
};

struct uobj_handle_map {
	struct uobj_handle_map_entry *e;
	size_t n;
	size_t cap;
};

static int handle_map_add(struct uobj_handle_map *m, R3UobjType type, uint32_t restrack_id, uint32_t ufile_handle)
{
	if (m->n == m->cap) {
		size_t newcap = m->cap ? m->cap * 2 : 16;
		void *p = xrealloc(m->e, newcap * sizeof(*m->e));

		if (!p)
			return -1;
		m->e = p;
		m->cap = newcap;
	}
	m->e[m->n].type = type;
	m->e[m->n].restrack_id = restrack_id;
	m->e[m->n].ufile_handle = ufile_handle;
	m->n++;
	return 0;
}

static bool handle_map_lookup(const struct uobj_handle_map *m, R3UobjType type, uint32_t restrack_id, uint32_t *out)
{
	for (size_t i = 0; i < m->n; i++) {
		if (m->e[i].type == type && m->e[i].restrack_id == restrack_id) {
			*out = m->e[i].ufile_handle;
			return true;
		}
	}
	return false;
}

/*
 * Issue UVERBS_METHOD_RESTORE_PD on @cmd_fd, asking the kernel to mint
 * a PD uobject at the ufile handle the dump captured (e->ufile_handle).
 *
 * Core owns only the driver-agnostic attribute: the target handle,
 * which rides inline in the attr's data field (uverbs treats a PTR_IN
 * whose len <= sizeof(data) as an immediate). The driver-private half
 * -- mlx5: the source FW pdn the kernel adopts into a fresh mlx5_ib_pd
 * without ALLOC_PD -- is opaque here; the owning plugin reshapes its
 * per-PD plugin_blob into UHW_IN (and declares any UHW_OUT the kernel's
 * udata requires, optionally with a verify template) via
 * CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_PD_UHW_PACK, dispatched by
 * @criu_driver.
 *
 * rxe carries no per-PD FW state: its plugin registers no UHW-pack
 * hook, the dispatch yields an empty @uhw, and this issues a UHW-less
 * RESTORE_PD -- the handle is the only input.
 *
 * Returns 0 on success, -errno on ioctl failure (a too-old kernel
 * returns -EOPNOTSUPP for the unknown UVERBS_OBJECT_RESTORE), or the
 * negative errno the UHW_PACK dispatch / verify reported.
 */
static int rdma_send_restore_pd(int cmd_fd, uint32_t criu_driver, uint32_t kernel_driver_id, const RdmaUobjEntry *e)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[3];
	} cmd = {};
	struct rdma_uhw_spec uhw = {};
	void *uhw_out_actual = NULL;
	unsigned int n = 0;
	int rc;

	rc = rdma_dispatch_restore_pd_uhw_pack(criu_driver, e, &uhw);
	if (rc)
		return rc; /* dispatch already logged */

	if (uhw.out_len) {
		uhw_out_actual = malloc(uhw.out_len);
		if (!uhw_out_actual) {
			rc = -ENOMEM;
			goto out_free_uhw;
		}
		memset(uhw_out_actual, 0, uhw.out_len);
	}

	cmd.hdr.object_id = UVERBS_OBJECT_RESTORE;
	cmd.hdr.method_id = UVERBS_METHOD_RESTORE_PD;
	cmd.hdr.driver_id = kernel_driver_id;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_PD_HANDLE;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = e->ufile_handle;
	n++;

	if (uhw.out_len) {
		cmd.attrs[n].attr_id = UVERBS_ATTR_UHW_OUT;
		cmd.attrs[n].len = (uint16_t)uhw.out_len;
		cmd.attrs[n].flags = 0;
		cmd.attrs[n].data = (uintptr_t)uhw_out_actual;
		n++;
	}
	if (uhw.in_len) {
		cmd.attrs[n].attr_id = UVERBS_ATTR_UHW_IN;
		cmd.attrs[n].len = (uint16_t)uhw.in_len;
		cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
		cmd.attrs[n].data = (uintptr_t)uhw.in_buf;
		n++;
	}

	cmd.hdr.num_attrs = n;
	cmd.hdr.length = sizeof(cmd.hdr) + n * sizeof(cmd.attrs[0]);

	if (ioctl(cmd_fd, RDMA_VERBS_IOCTL, &cmd) < 0) {
		rc = -errno;
		goto out_free_uhw;
	}

	if (uhw.verify_len > 0 && uhw.verify_len <= uhw.out_len &&
	    memcmp(uhw_out_actual, uhw.out_buf, uhw.verify_len) != 0) {
		pr_err("uobj DAG: RESTORE_PD handle=%u UHW_OUT byte-template mismatch (verify_len=%zu)\n",
		       e->ufile_handle, uhw.verify_len);
		rc = -EPROTO;
		goto out_free_uhw;
	}
	rc = 0;

out_free_uhw:
	free(uhw_out_actual);
	free(uhw.in_buf);
	free(uhw.out_buf);
	return rc;
}

/*
 * Restore one PD: reinstall an ib_uobject at the ufile_handle the dump
 * captured, then record (PD, restrack_id) -> handle so MRs can resolve
 * their parent-PD xref through the map.
 */
static int uobj_restore_pd(int cmd_fd, uint32_t kernel_driver_id, const RdmaUobjEntry *e, struct uobj_handle_map *m)
{
	int rc;

	if (!e->has_ufile_handle) {
		pr_err("uobj DAG: PD entry (restrack_id=%u) has no ufile_handle; cannot restore (dump ran on a "
		       "pre-K8a kernel)\n",
		       e->has_restrack_id ? e->restrack_id : 0);
		return -1;
	}
	if (!e->has_restrack_id) {
		pr_err("uobj DAG: PD entry (handle=%u) has no restrack_id; MR xrefs could not resolve it\n",
		       e->ufile_handle);
		return -1;
	}

	rc = rdma_send_restore_pd(cmd_fd, e->hw_driver_id, kernel_driver_id, e);
	if (rc) {
		pr_err("uobj DAG: RESTORE_PD handle=%u on cmd_fd=%d driver=%u failed: %d (%s)\n", e->ufile_handle,
		       cmd_fd, kernel_driver_id, rc, strerror(rc < 0 ? -rc : rc));
		return -1;
	}
	pr_debug("uobj DAG: RESTORE_PD handle=%u ok (cmd_fd=%d driver=%u)\n", e->ufile_handle, cmd_fd, kernel_driver_id);

	return handle_map_add(m, R3_UOBJ_TYPE__R3UT_PD, e->restrack_id, e->ufile_handle);
}

/*
 * Issue UVERBS_METHOD_RESTORE_CQ on @cmd_fd from CRIU master, minting a
 * CQ uobject at the caller-chosen ufile handle.
 *
 * Core owns only the driver-agnostic attributes: the target handle, the
 * requested cqe count and comp_vector (from the R3UT_CQ image entry, the
 * hw-agnostic fields the dump-side plugin filled), an optional flags
 * word, a user_handle, and the mandatory RESP_CQE sink. The driver-
 * private half -- rxe: the ring mmap vm_pgoff, the producer/consumer
 * cursors and the unreaped-CQE image -- is opaque here; the owning
 * plugin reshapes its per-CQ plugin_blob into UHW_IN (and declares the
 * UHW_OUT size the kernel's udata requires, optionally with a verify
 * template) via CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_CQ_UHW_PACK, dispatched
 * by @criu_driver.
 *
 * This is the "ring lives in kernel pages, exposed via vm_pgoff" camp
 * (rxe): the verb MUST run here, before the pie's user-VMA pass mmaps
 * the cdev at that vm_pgoff (rxe_restore_cq registers the pending mmap
 * slot; mmapping it before the slot exists -EINVALs). rxe pins no user
 * pages, so master's mm is fine. Drivers that pin the ring from
 * current->mm (mlx5) will instead defer to the pie in a later milestone.
 *
 * user_handle is 0 in v0: the source cq_context cookie is not captured
 * (QUERY_CQ/NLDEV don't expose it) and matters only for comp_channel /
 * async-event delivery, neither of which v0 restores. ibv_poll_cq does
 * not consult it.
 *
 * Returns 0 on success, -errno on ioctl failure (a too-old kernel
 * returns -EOPNOTSUPP for the unknown UVERBS_OBJECT_RESTORE), or the
 * negative errno the UHW_PACK dispatch / verify reported.
 */
static int rdma_send_restore_cq(int cmd_fd, uint32_t criu_driver, uint32_t kernel_driver_id, const RdmaUobjEntry *e)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[7];
	} cmd = {};
	struct rdma_uhw_spec uhw = {};
	const RdmaCqAttrs *attrs = e->cq;
	uint32_t cqe = 0, comp_vector = 0, flags = 0, resp_cqe = 0;
	uint64_t user_handle = 0;
	void *uhw_out_actual = NULL;
	unsigned int n = 0;
	int rc;

	if (attrs) {
		if (attrs->has_cqe_count)
			cqe = attrs->cqe_count;
		if (attrs->has_comp_vector)
			comp_vector = attrs->comp_vector;
		if (attrs->has_flags)
			flags = attrs->flags;
	}

	rc = rdma_dispatch_restore_cq_uhw_pack(criu_driver, e, &uhw);
	if (rc)
		return rc; /* dispatch already logged */

	if (uhw.out_len) {
		uhw_out_actual = malloc(uhw.out_len);
		if (!uhw_out_actual) {
			rc = -ENOMEM;
			goto out_free_uhw;
		}
		memset(uhw_out_actual, 0, uhw.out_len);
	}

	cmd.hdr.object_id = UVERBS_OBJECT_RESTORE;
	cmd.hdr.method_id = UVERBS_METHOD_RESTORE_CQ;
	cmd.hdr.driver_id = kernel_driver_id;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_CQ_HANDLE;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = e->ufile_handle;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_CQ_CQE;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = cqe;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_CQ_USER_HANDLE;
	cmd.attrs[n].len = sizeof(uint64_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = user_handle;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_CQ_COMP_VECTOR;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = comp_vector;
	n++;

	if (flags) {
		cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_CQ_FLAGS;
		cmd.attrs[n].len = sizeof(uint32_t);
		cmd.attrs[n].flags = 0;
		cmd.attrs[n].data = flags;
		n++;
	}

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_CQ_RESP_CQE;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&resp_cqe;
	n++;

	if (uhw.out_len) {
		cmd.attrs[n].attr_id = UVERBS_ATTR_UHW_OUT;
		cmd.attrs[n].len = (uint16_t)uhw.out_len;
		cmd.attrs[n].flags = 0;
		cmd.attrs[n].data = (uintptr_t)uhw_out_actual;
		n++;
	}
	if (uhw.in_len) {
		cmd.attrs[n].attr_id = UVERBS_ATTR_UHW_IN;
		cmd.attrs[n].len = (uint16_t)uhw.in_len;
		cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
		cmd.attrs[n].data = (uintptr_t)uhw.in_buf;
		n++;
	}

	cmd.hdr.num_attrs = n;
	cmd.hdr.length = sizeof(cmd.hdr) + n * sizeof(cmd.attrs[0]);

	if (ioctl(cmd_fd, RDMA_VERBS_IOCTL, &cmd) < 0) {
		rc = -errno;
		goto out_free_uhw;
	}

	if (uhw.verify_len > 0 && uhw.verify_len <= uhw.out_len &&
	    memcmp(uhw_out_actual, uhw.out_buf, uhw.verify_len) != 0) {
		pr_err("uobj DAG: RESTORE_CQ handle=%u UHW_OUT byte-template mismatch (verify_len=%zu); kernel did not "
		       "echo the requested ring offset\n",
		       e->ufile_handle, uhw.verify_len);
		rc = -EPROTO;
		goto out_free_uhw;
	}
	rc = 0;

out_free_uhw:
	free(uhw_out_actual);
	free(uhw.in_buf);
	free(uhw.out_buf);
	return rc;
}

/*
 * Restore one CQ: reinstall an ib_uobject at the ufile_handle the dump
 * captured, synchronously on the cmd_fd (master side, before the pie's
 * VMA pass -- see rdma_send_restore_cq). The CQ is a DAG root in v0 (no
 * incoming xrefs), so unlike the MR path it needs no parent resolution.
 * It is, however, an xref *target*: a QP binds its send/recv completion
 * queues by the source CQ restrack id (RES_SEND_CQN / RES_RECV_CQN), so
 * record (CQ, restrack_id) -> handle here for the QP pass to resolve
 * those edges against, exactly as the PD pass does for MR parents.
 */
static int uobj_restore_cq(int cmd_fd, uint32_t kernel_driver_id, const RdmaUobjEntry *e, struct uobj_handle_map *m)
{
	int rc;

	if (!e->has_ufile_handle) {
		pr_err("uobj DAG: CQ entry (restrack_id=%u) has no ufile_handle; cannot restore (dump ran on a "
		       "pre-K8a kernel)\n",
		       e->has_restrack_id ? e->restrack_id : 0);
		return -1;
	}
	if (!e->has_restrack_id) {
		pr_err("uobj DAG: CQ entry (handle=%u) has no restrack_id; QP send/recv-CQ xrefs could not resolve "
		       "it\n",
		       e->ufile_handle);
		return -1;
	}

	rc = rdma_send_restore_cq(cmd_fd, e->hw_driver_id, kernel_driver_id, e);
	if (rc) {
		pr_err("uobj DAG: RESTORE_CQ handle=%u on cmd_fd=%d driver=%u failed: %d (%s)\n", e->ufile_handle,
		       cmd_fd, kernel_driver_id, rc, strerror(rc < 0 ? -rc : rc));
		return -1;
	}
	pr_debug("uobj DAG: RESTORE_CQ handle=%u ok (cmd_fd=%d driver=%u)\n", e->ufile_handle, cmd_fd, kernel_driver_id);

	return handle_map_add(m, R3_UOBJ_TYPE__R3UT_CQ, e->restrack_id, e->ufile_handle);
}

/*
 * Issue UVERBS_METHOD_RESTORE_QP on @cmd_fd from CRIU master, minting a
 * QP uobject at the caller-chosen ufile handle.
 *
 * Core owns the driver-agnostic attributes: the target handle; the
 * parent PD and the send/recv CQ as IDR references (already restored,
 * their destination handles resolved by the caller through the xref
 * map); the captured qp_type / qp_state; the async-event user_handle;
 * and the create-time cap (max_send_wr/... the standard QUERY_QP verb
 * surfaced at dump). The driver-private half -- rxe: the full
 * rxe_restore_qp_req wire state (AV, PSNs, cursors, transport knobs, and
 * the SQ/RQ ring mmap vm_pgoffs) -- is opaque here; the owning plugin
 * reshapes its per-QP plugin_blob into UHW_IN (and declares the UHW_OUT
 * size, optionally with an echo template) via
 * CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_QP_UHW_PACK, dispatched by
 * @criu_driver.
 *
 * Like RESTORE_CQ this runs master-side, before the pie's user-VMA pass:
 * rxe_restore_qp registers the SQ/RQ ring pending-mmap slots at the
 * source vm_pgoffs, which the generic UPDATE_VMA_MAP hook then maps onto
 * the restored cdev. The IDR refs (PD/CQs) ride as handle-in-data attrs
 * with len 0; the target handle, qp_type/qp_state (u64 consts) and
 * user_handle ride inline; the cap struct and RESP_QPN sink ride by
 * pointer.
 *
 * The kernel installs the QP at the source qpn (rxe qpns are wire-
 * visible) and echoes it in RESP_QPN; we verify it matches the captured
 * qp_num and fail-fast on divergence (a collision or cross-arch move
 * that would silently break the peer's in-flight addressing).
 *
 * Returns 0 on success, -errno on ioctl failure (a too-old kernel
 * returns -EOPNOTSUPP for the unknown UVERBS_OBJECT_RESTORE / method), or
 * the negative errno the UHW_PACK dispatch / verify reported.
 */
static int rdma_send_restore_qp(int cmd_fd, uint32_t criu_driver, uint32_t kernel_driver_id, const RdmaUobjEntry *e,
				uint32_t pd_handle, uint32_t send_cq_handle, uint32_t recv_cq_handle)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[11];
	} cmd = {};
	struct rdma_uhw_spec uhw = {};
	const RdmaQpAttrs *attrs = e->qp;
	const RdmaQpCap *qcap;
	struct ib_uverbs_qp_cap_local cap = {};
	uint64_t qp_type, qp_state, user_handle = 0;
	uint32_t resp_qpn = 0;
	void *uhw_out_actual = NULL;
	unsigned int n = 0;
	int rc;

	if (!attrs || !attrs->has_qp_type || !attrs->has_state || !attrs->cap) {
		pr_err("uobj DAG: QP handle=%u missing RESTORE_QP fields (have qp=%d type=%d state=%d cap=%d); image "
		       "dumped against a kernel without the QP cap/identity capture\n",
		       e->ufile_handle, !!attrs, attrs ? attrs->has_qp_type : 0, attrs ? attrs->has_state : 0,
		       attrs ? (attrs->cap != NULL) : 0);
		return -EINVAL;
	}
	qcap = attrs->cap;
	if (!qcap->has_max_send_wr || !qcap->has_max_recv_wr || !qcap->has_max_send_sge || !qcap->has_max_recv_sge ||
	    !qcap->has_max_inline_data) {
		pr_err("uobj DAG: QP handle=%u cap missing fields (swr=%d rwr=%d ssge=%d rsge=%d inl=%d)\n",
		       e->ufile_handle, qcap->has_max_send_wr, qcap->has_max_recv_wr, qcap->has_max_send_sge,
		       qcap->has_max_recv_sge, qcap->has_max_inline_data);
		return -EINVAL;
	}
	qp_type = attrs->qp_type;
	qp_state = attrs->state;
	if (attrs->has_user_handle)
		user_handle = attrs->user_handle;
	cap.max_send_wr = qcap->max_send_wr;
	cap.max_recv_wr = qcap->max_recv_wr;
	cap.max_send_sge = qcap->max_send_sge;
	cap.max_recv_sge = qcap->max_recv_sge;
	cap.max_inline_data = qcap->max_inline_data;

	rc = rdma_dispatch_restore_qp_uhw_pack(criu_driver, e, &uhw);
	if (rc)
		return rc; /* dispatch already logged */

	if (uhw.out_len) {
		uhw_out_actual = malloc(uhw.out_len);
		if (!uhw_out_actual) {
			rc = -ENOMEM;
			goto out_free_uhw;
		}
		memset(uhw_out_actual, 0, uhw.out_len);
	}

	cmd.hdr.object_id = UVERBS_OBJECT_RESTORE;
	cmd.hdr.method_id = UVERBS_METHOD_RESTORE_QP;
	cmd.hdr.driver_id = kernel_driver_id;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_QP_HANDLE;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = e->ufile_handle;
	n++;

	/* IDR references: object id rides in data, len 0. */
	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_QP_PD_HANDLE;
	cmd.attrs[n].len = 0;
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = pd_handle;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_QP_SEND_CQ_HANDLE;
	cmd.attrs[n].len = 0;
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = send_cq_handle;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_QP_RECV_CQ_HANDLE;
	cmd.attrs[n].len = 0;
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = recv_cq_handle;
	n++;

	/* Enum consts ride inline as u64 (kernel uverbs_get_const). */
	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_QP_TYPE;
	cmd.attrs[n].len = sizeof(uint64_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = qp_type;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_QP_STATE;
	cmd.attrs[n].len = sizeof(uint64_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = qp_state;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_QP_USER_HANDLE;
	cmd.attrs[n].len = sizeof(uint64_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = user_handle;
	n++;

	/* cap is 20 bytes (> inline threshold): ride by pointer. */
	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_QP_CAP;
	cmd.attrs[n].len = sizeof(cap);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&cap;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_QP_RESP_QPN;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&resp_qpn;
	n++;

	if (uhw.out_len) {
		cmd.attrs[n].attr_id = UVERBS_ATTR_UHW_OUT;
		cmd.attrs[n].len = (uint16_t)uhw.out_len;
		cmd.attrs[n].flags = 0;
		cmd.attrs[n].data = (uintptr_t)uhw_out_actual;
		n++;
	}
	if (uhw.in_len) {
		cmd.attrs[n].attr_id = UVERBS_ATTR_UHW_IN;
		cmd.attrs[n].len = (uint16_t)uhw.in_len;
		cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
		cmd.attrs[n].data = (uintptr_t)uhw.in_buf;
		n++;
	}

	cmd.hdr.num_attrs = n;
	cmd.hdr.length = sizeof(cmd.hdr) + n * sizeof(cmd.attrs[0]);

	if (ioctl(cmd_fd, RDMA_VERBS_IOCTL, &cmd) < 0) {
		rc = -errno;
		goto out_free_uhw;
	}

	if (uhw.verify_len > 0 && uhw.verify_len <= uhw.out_len &&
	    memcmp(uhw_out_actual, uhw.out_buf, uhw.verify_len) != 0) {
		pr_err("uobj DAG: RESTORE_QP handle=%u UHW_OUT byte-template mismatch (verify_len=%zu); kernel did not "
		       "echo the requested ring offset\n",
		       e->ufile_handle, uhw.verify_len);
		rc = -EPROTO;
		goto out_free_uhw;
	}

	if (attrs->has_qp_num && resp_qpn != attrs->qp_num) {
		pr_err("uobj DAG: RESTORE_QP handle=%u installed qpn=%u != captured qpn=%u; the source qpn could not "
		       "be reinstated (collision / cross-arch move)\n",
		       e->ufile_handle, resp_qpn, attrs->qp_num);
		rc = -EADDRNOTAVAIL;
		goto out_free_uhw;
	}
	rc = 0;

out_free_uhw:
	free(uhw_out_actual);
	free(uhw.in_buf);
	free(uhw.out_buf);
	return rc;
}

/*
 * Restore one QP: resolve its parent-PD / send-CQ / recv-CQ xrefs to the
 * destination handles those uobjects were reinstalled at (through the
 * per-ufile handle map the PD and CQ passes populated), then reinstall
 * the QP at the ufile_handle the dump captured. Synchronous on cmd_fd
 * (master side) like RESTORE_CQ -- see rdma_send_restore_qp.
 */
static int uobj_restore_qp(int cmd_fd, uint32_t kernel_driver_id, const RdmaUobjEntry *e,
			   const struct uobj_handle_map *m)
{
	uint32_t pd_handle = 0, send_cq_handle = 0, recv_cq_handle = 0;
	bool have_pd = false, have_scq = false, have_rcq = false;
	int rc;

	if (!e->has_ufile_handle) {
		pr_err("uobj DAG: QP entry (restrack_id=%u) has no ufile_handle; cannot restore (dump ran on a "
		       "pre-K8a kernel)\n",
		       e->has_restrack_id ? e->restrack_id : 0);
		return -1;
	}

	for (size_t k = 0; k < e->n_xref; k++) {
		const RdmaUobjXref *xr = e->xref[k];

		switch (xr->role) {
		case R3_XREF_ROLE__R3XR_PARENT_PD:
			if (xr->target_type != R3_UOBJ_TYPE__R3UT_PD) {
				pr_err("uobj DAG: QP handle=%u parent xref has non-PD target_type %u\n",
				       e->ufile_handle, xr->target_type);
				return -1;
			}
			if (!handle_map_lookup(m, R3_UOBJ_TYPE__R3UT_PD, xr->target_restrack_id, &pd_handle)) {
				pr_err("uobj DAG: QP handle=%u parent PD (restrack_id=%u) not restored / "
				       "unresolvable\n",
				       e->ufile_handle, xr->target_restrack_id);
				return -1;
			}
			have_pd = true;
			break;
		case R3_XREF_ROLE__R3XR_SEND_CQ:
		case R3_XREF_ROLE__R3XR_RECV_CQ:
			if (xr->target_type != R3_UOBJ_TYPE__R3UT_CQ) {
				pr_err("uobj DAG: QP handle=%u %s xref has non-CQ target_type %u\n", e->ufile_handle,
				       xr->role == R3_XREF_ROLE__R3XR_SEND_CQ ? "send-CQ" : "recv-CQ",
				       xr->target_type);
				return -1;
			}
			if (!handle_map_lookup(m, R3_UOBJ_TYPE__R3UT_CQ, xr->target_restrack_id,
					       xr->role == R3_XREF_ROLE__R3XR_SEND_CQ ? &send_cq_handle :
											&recv_cq_handle)) {
				pr_err("uobj DAG: QP handle=%u %s (restrack_id=%u) not restored / unresolvable\n",
				       e->ufile_handle,
				       xr->role == R3_XREF_ROLE__R3XR_SEND_CQ ? "send-CQ" : "recv-CQ",
				       xr->target_restrack_id);
				return -1;
			}
			if (xr->role == R3_XREF_ROLE__R3XR_SEND_CQ)
				have_scq = true;
			else
				have_rcq = true;
			break;
		default:
			break;
		}
	}

	if (!have_pd || !have_scq || !have_rcq) {
		pr_err("uobj DAG: QP handle=%u missing an xref (parent_pd=%d send_cq=%d recv_cq=%d)\n",
		       e->ufile_handle, have_pd, have_scq, have_rcq);
		return -1;
	}

	rc = rdma_send_restore_qp(cmd_fd, e->hw_driver_id, kernel_driver_id, e, pd_handle, send_cq_handle,
				  recv_cq_handle);
	if (rc) {
		pr_err("uobj DAG: RESTORE_QP handle=%u on cmd_fd=%d driver=%u failed: %d (%s)\n", e->ufile_handle,
		       cmd_fd, kernel_driver_id, rc, strerror(rc < 0 ? -rc : rc));
		return -1;
	}
	pr_debug("uobj DAG: RESTORE_QP handle=%u ok (cmd_fd=%d driver=%u pd=%u scq=%u rcq=%u)\n", e->ufile_handle,
		 cmd_fd, kernel_driver_id, pd_handle, send_cq_handle, recv_cq_handle);
	return 0;
}

/*
 * CQs resolved in Phase A (the per-ufile dispatch) but issued in the pie
 * restorer -- the pie-deferred camp (mlx5), whose RESTORE_CQ pins the
 * source CQE-ring / doorbell pages via pin_user_pages_fast against
 * current->mm, so the verb must run after the pie blob has mmap'd the
 * VMAs at their original VAs (issuing it master-side returns -EFAULT).
 * The master-side camp (rxe) never queues here -- see uobj_restore_cq
 * and CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_CQ_NEEDS_PIE. Each record owns a
 * high-fd dup of the ucontext cdev; the pie closes it after the ioctl.
 */
struct rdma_pending_cq {
	uint32_t ufile_id;
	uint32_t kernel_driver_id;
	uint32_t target_handle;
	uint32_t cqe;
	uint32_t comp_vector;
	uint32_t flags;
	int cmd_fd_dup;
	uint32_t uhw_in_len; /* 0 -> UHW-less RESTORE_CQ */
	uint8_t uhw_in_buf[RST_RDMA_CQ_UHW_IN_MAX];
	struct list_head link;
};

static LIST_HEAD(rdma_pending_cqs);

/*
 * Pie-deferred CQ prepare (mlx5): validate the R3UT_CQ entry, pack its
 * driver-private UHW_IN master-side while the owning plugin is still
 * loaded, dup the ucontext cdev to a high fd for the pie, and queue the
 * record; rdma_prepare_rdma_cqs() later drains it into the restorer
 * args. Unlike uobj_prepare_mr a CQ has no parent to resolve, but it IS
 * an xref target (a QP binds its send/recv CQs by restrack id), so we
 * still record (CQ, restrack_id) -> handle in the map here for the QP
 * pass -- exactly as the master-side uobj_restore_cq does.
 */
static int uobj_prepare_cq(int cmd_fd, uint32_t ufile_id, uint32_t kernel_driver_id, const RdmaUobjEntry *e,
			   struct uobj_handle_map *m)
{
	const RdmaCqAttrs *attrs = e->cq;
	uint8_t uhw_in_buf[RST_RDMA_CQ_UHW_IN_MAX];
	uint32_t uhw_in_len = 0;
	uint32_t cqe = 0, comp_vector = 0, flags = 0;
	struct rdma_pending_cq *p;
	int dup_fd;

	if (!e->has_ufile_handle) {
		pr_err("uobj DAG: CQ entry (restrack_id=%u) has no ufile_handle; cannot restore\n",
		       e->has_restrack_id ? e->restrack_id : 0);
		return -1;
	}
	if (!e->has_restrack_id) {
		pr_err("uobj DAG: CQ entry (handle=%u) has no restrack_id; QP send/recv-CQ xrefs could not resolve "
		       "it\n",
		       e->ufile_handle);
		return -1;
	}

	if (attrs) {
		if (attrs->has_cqe_count)
			cqe = attrs->cqe_count;
		if (attrs->has_comp_vector)
			comp_vector = attrs->comp_vector;
		if (attrs->has_flags)
			flags = attrs->flags;
	}

	/*
	 * Reshape the driver-private UHW_IN here, master-side, while the
	 * owning plugin is still loaded: the RESTORE_CQ ioctl runs later in
	 * the pie (post-VMA, no plugins), so the packed bytes ride inline in
	 * the queued record. mlx5 packs a struct mlx5_ib_restore_cq_req from
	 * its per-CQ plugin_blob.
	 */
	{
		struct rdma_uhw_spec uhw = {};
		int rc = rdma_dispatch_restore_cq_uhw_pack(e->hw_driver_id, e, &uhw);

		if (rc) {
			pr_err("uobj DAG: CQ handle=%u UHW pack failed: %d (%s)\n", e->ufile_handle, rc,
			       strerror(rc < 0 ? -rc : rc));
			free(uhw.in_buf);
			free(uhw.out_buf);
			return -1;
		}
		if (uhw.out_len) {
			pr_err("uobj DAG: CQ handle=%u plugin requested UHW_OUT (%zu bytes); the pie RESTORE_CQ "
			       "path carries UHW_IN only\n",
			       e->ufile_handle, uhw.out_len);
			free(uhw.in_buf);
			free(uhw.out_buf);
			return -1;
		}
		if (uhw.in_len > sizeof(uhw_in_buf)) {
			pr_err("uobj DAG: CQ handle=%u UHW_IN too large (%zu > %zu)\n", e->ufile_handle, uhw.in_len,
			       sizeof(uhw_in_buf));
			free(uhw.in_buf);
			return -1;
		}
		if (uhw.in_len)
			memcpy(uhw_in_buf, uhw.in_buf, uhw.in_len);
		uhw_in_len = (uint32_t)uhw.in_len;
		free(uhw.in_buf);
	}

	dup_fd = fcntl(cmd_fd, F_DUPFD_CLOEXEC, RDMA_PIE_CMD_FD_MIN);
	if (dup_fd < 0) {
		pr_err("uobj DAG: CQ handle=%u: F_DUPFD_CLOEXEC of cdev fd for pie failed: %m\n", e->ufile_handle);
		return -1;
	}

	p = xzalloc(sizeof(*p));
	if (!p) {
		close(dup_fd);
		return -1;
	}
	p->ufile_id = ufile_id;
	p->kernel_driver_id = kernel_driver_id;
	p->target_handle = e->ufile_handle;
	p->cqe = cqe;
	p->comp_vector = comp_vector;
	p->flags = flags;
	p->cmd_fd_dup = dup_fd;
	p->uhw_in_len = uhw_in_len;
	if (uhw_in_len)
		memcpy(p->uhw_in_buf, uhw_in_buf, uhw_in_len);
	INIT_LIST_HEAD(&p->link);
	list_add_tail(&p->link, &rdma_pending_cqs);

	pr_info("uobj DAG: CQ handle=%u queued for pie: cqe=%u comp_vector=%u flags=%#x uhw_in=%u\n", e->ufile_handle,
		cqe, comp_vector, flags, uhw_in_len);

	return handle_map_add(m, R3_UOBJ_TYPE__R3UT_CQ, e->restrack_id, e->ufile_handle);
}

/*
 * MRs resolved in Phase A (the per-ufile dispatch) but issued in the
 * pie restorer. The RESTORE_MR ioctl must run in the target's restored
 * address space -- rxe pins the MR's user_addr pages via
 * pin_user_pages_fast against current->mm, and those pages are not laid
 * out until the pie blob mmaps the VMAs at sigreturn_restore time -- so
 * the dispatch queues a fully-resolved record here and
 * rdma_prepare_rdma_mrs() drains it into the restorer args later.
 * Each record owns a high-fd dup of the ucontext cdev; the pie closes
 * it after the ioctl.
 */
struct rdma_pending_mr {
	uint32_t ufile_id;
	uint32_t kernel_driver_id;
	uint32_t target_handle;
	uint32_t parent_pd_handle;
	uint64_t addr;
	uint64_t length;
	uint64_t iova;
	uint32_t access_flags;
	uint32_t lkey;
	uint32_t rkey;
	int cmd_fd_dup;
	uint32_t uhw_in_len; /* 0 -> UHW-less RESTORE_MR (rxe) */
	uint8_t uhw_in_buf[RST_RDMA_MR_UHW_IN_MAX];
	struct list_head link;
};

static LIST_HEAD(rdma_pending_mrs);

/*
 * Resolve an MR's parent PD to the destination handle it was restored
 * at (via the R3XR_PARENT_PD xref), validate the full RESTORE_MR field
 * set, dup the ucontext cdev to a high fd for the pie, and queue the
 * record. The ioctl itself is deferred to the pie (see struct
 * rdma_pending_mr).
 */
static int uobj_prepare_mr(int cmd_fd, uint32_t ufile_id, uint32_t kernel_driver_id, const RdmaUobjEntry *e,
			   const struct uobj_handle_map *m)
{
	uint32_t parent_pd_handle = 0;
	bool have_parent = false;
	const RdmaMrAttrs *attrs = e->mr;
	uint8_t uhw_in_buf[RST_RDMA_MR_UHW_IN_MAX];
	uint32_t uhw_in_len = 0;
	struct rdma_pending_mr *p;
	int dup_fd;

	if (!e->has_ufile_handle) {
		pr_err("uobj DAG: MR entry (restrack_id=%u) has no ufile_handle; cannot restore\n",
		       e->has_restrack_id ? e->restrack_id : 0);
		return -1;
	}
	if (!attrs || !attrs->has_virt_addr || !attrs->has_length || !attrs->has_iova || !attrs->has_access_flags ||
	    !attrs->has_lkey || !attrs->has_rkey) {
		pr_err("uobj DAG: MR handle=%u missing RESTORE_MR fields (have va=%d len=%d iova=%d access=%d lkey=%d "
		       "rkey=%d); image dumped against a kernel without QUERY_MR user_addr/access_flags\n",
		       e->ufile_handle, attrs ? attrs->has_virt_addr : 0, attrs ? attrs->has_length : 0,
		       attrs ? attrs->has_iova : 0, attrs ? attrs->has_access_flags : 0, attrs ? attrs->has_lkey : 0,
		       attrs ? attrs->has_rkey : 0);
		return -1;
	}

	for (size_t k = 0; k < e->n_xref; k++) {
		const RdmaUobjXref *xr = e->xref[k];

		if (xr->role != R3_XREF_ROLE__R3XR_PARENT_PD)
			continue;
		if (xr->target_type != R3_UOBJ_TYPE__R3UT_PD) {
			pr_err("uobj DAG: MR handle=%u parent xref has non-PD target_type %u\n", e->ufile_handle,
			       xr->target_type);
			return -1;
		}
		if (!handle_map_lookup(m, R3_UOBJ_TYPE__R3UT_PD, xr->target_restrack_id, &parent_pd_handle)) {
			pr_err("uobj DAG: MR handle=%u parent PD (restrack_id=%u) not restored / unresolvable\n",
			       e->ufile_handle, xr->target_restrack_id);
			return -1;
		}
		have_parent = true;
		break;
	}
	if (!have_parent) {
		pr_err("uobj DAG: MR handle=%u has no R3XR_PARENT_PD xref\n", e->ufile_handle);
		return -1;
	}

	/*
	 * Reshape the driver-private UHW_IN here, master-side, while the
	 * owning plugin is still loaded: the RESTORE_MR ioctl runs later in
	 * the pie (post-VMA, no plugins), so the packed bytes ride inline
	 * in the queued record. mlx5 packs a struct mlx5_ib_restore_mr_req
	 * (mkey_index == lkey >> 8); rxe registers no hook and yields an
	 * empty UHW, leaving core to issue a UHW-less RESTORE_MR.
	 */
	{
		struct rdma_uhw_spec uhw = {};
		int rc = rdma_dispatch_restore_mr_uhw_pack(e->hw_driver_id, e, &uhw);

		if (rc) {
			pr_err("uobj DAG: MR handle=%u UHW pack failed: %d (%s)\n", e->ufile_handle, rc,
			       strerror(rc < 0 ? -rc : rc));
			free(uhw.in_buf);
			free(uhw.out_buf);
			return -1;
		}
		if (uhw.out_len) {
			pr_err("uobj DAG: MR handle=%u plugin requested UHW_OUT (%zu bytes); the pie RESTORE_MR "
			       "path carries UHW_IN only\n",
			       e->ufile_handle, uhw.out_len);
			free(uhw.in_buf);
			free(uhw.out_buf);
			return -1;
		}
		if (uhw.in_len > sizeof(uhw_in_buf)) {
			pr_err("uobj DAG: MR handle=%u UHW_IN too large (%zu > %zu)\n", e->ufile_handle, uhw.in_len,
			       sizeof(uhw_in_buf));
			free(uhw.in_buf);
			return -1;
		}
		if (uhw.in_len)
			memcpy(uhw_in_buf, uhw.in_buf, uhw.in_len);
		uhw_in_len = (uint32_t)uhw.in_len;
		free(uhw.in_buf);
	}

	/*
	 * Per-MR dup so each record owns its transit fd and the pie can
	 * close them independently. cmd_fd is the plugin-opened ucontext
	 * cdev; the dup rides above the user-fd reuse range.
	 */
	dup_fd = fcntl(cmd_fd, F_DUPFD_CLOEXEC, RDMA_PIE_CMD_FD_MIN);
	if (dup_fd < 0) {
		pr_err("uobj DAG: MR handle=%u: F_DUPFD_CLOEXEC of cdev fd for pie failed: %m\n", e->ufile_handle);
		return -1;
	}

	p = xzalloc(sizeof(*p));
	if (!p) {
		close(dup_fd);
		return -1;
	}
	p->ufile_id = ufile_id;
	p->kernel_driver_id = kernel_driver_id;
	p->target_handle = e->ufile_handle;
	p->parent_pd_handle = parent_pd_handle;
	p->addr = attrs->virt_addr;
	p->length = attrs->length;
	p->iova = attrs->iova;
	p->access_flags = attrs->access_flags;
	p->lkey = attrs->lkey;
	p->rkey = attrs->rkey;
	p->cmd_fd_dup = dup_fd;
	p->uhw_in_len = uhw_in_len;
	if (uhw_in_len)
		memcpy(p->uhw_in_buf, uhw_in_buf, uhw_in_len);
	INIT_LIST_HEAD(&p->link);
	list_add_tail(&p->link, &rdma_pending_mrs);

	pr_info("uobj DAG: MR handle=%u queued for pie: parent_pd_handle=%u va=%#" PRIx64 " len=%" PRIu64
		" access=%#x lkey=%#x rkey=%#x iova=%#" PRIx64 " uhw_in=%u\n",
		e->ufile_handle, parent_pd_handle, (uint64_t)attrs->virt_addr, (uint64_t)attrs->length,
		attrs->access_flags, attrs->lkey, attrs->rkey, (uint64_t)attrs->iova, uhw_in_len);
	return 0;
}

int rdma_restore_uobj_dag_for_ufile(int cmd_fd, uint32_t ufile_id, uint32_t kernel_driver_id)
{
	struct uobj_ufile_group *g = rdma_uobj_group_lookup(ufile_id);
	struct uobj_handle_map map = {};
	struct uobj_collected *c;
	int ret = 0;

	if (!g) {
		/* Bare context: no uobjects captured for this ufile. */
		return 0;
	}

	pr_info("uobj DAG: restoring ufile_id=%#x (%d uobjs: pd=%d other=%d) on cmd_fd=%d\n", ufile_id, g->n_total,
		g->n_pd, g->n_other, cmd_fd);

	/*
	 * Dependency order: PDs first (xref targets, no incoming edges),
	 * then CQs (also roots, but QP xref targets), then the uobjects
	 * that reference them -- MRs (-> parent PD) and QPs (-> parent PD
	 * + send/recv CQ). A type-ranked three-pass walk (PD; CQ; MR+QP)
	 * is a sufficient topo-sort for these edge kinds; a general Kahn
	 * walk lands if/when intra-class edges do.
	 */
	list_for_each_entry(c, &g->entries, link) {
		if (c->e->type != R3_UOBJ_TYPE__R3UT_PD)
			continue;
		ret = uobj_restore_pd(cmd_fd, kernel_driver_id, c->e, &map);
		if (ret)
			goto out;
	}

	list_for_each_entry(c, &g->entries, link) {
		switch (c->e->type) {
		case R3_UOBJ_TYPE__R3UT_PD:
			break; /* restored in the first pass */
		case R3_UOBJ_TYPE__R3UT_CQ: {
			/*
			 * CQ is a root like PD (no incoming xrefs in v0), but
			 * splits by driver on WHERE the RESTORE_CQ verb runs:
			 * the master-side camp (rxe, needs_pie=0) issues it
			 * here so it precedes the pie's VMA mmap of the
			 * kernel-page ring; the pie-deferred camp (mlx5,
			 * needs_pie>0) queues it via uobj_prepare_cq so the
			 * verb runs after the pie lays out the source ring /
			 * doorbell VMAs its pin_user_pages_fast needs. Both
			 * paths record (CQ, restrack_id) -> handle for the QP
			 * pass. Order vs the MR queueing below is immaterial:
			 * MR only depends on PD.
			 */
			int pie = rdma_dispatch_restore_cq_needs_pie(c->e->hw_driver_id);

			if (pie < 0)
				ret = -1;
			else if (pie > 0)
				ret = uobj_prepare_cq(cmd_fd, ufile_id, kernel_driver_id, c->e, &map);
			else
				ret = uobj_restore_cq(cmd_fd, kernel_driver_id, c->e, &map);
			break;
		}
		case R3_UOBJ_TYPE__R3UT_MR:
			ret = uobj_prepare_mr(cmd_fd, ufile_id, kernel_driver_id, c->e, &map);
			break;
		case R3_UOBJ_TYPE__R3UT_QP:
			/*
			 * Deferred to the third pass: a QP binds its parent
			 * PD and both CQs, so every PD and CQ handle must be
			 * in the map first (a QP entry can precede its CQs in
			 * the image order).
			 */
			break;
		default:
			pr_err("uobj DAG: ufile_id=%#x has unsupported uobj type %d\n", ufile_id, c->e->type);
			ret = -1;
			break;
		}
		if (ret)
			goto out;
	}

	/*
	 * Third pass: QPs. By now every PD (pass 1) and CQ (pass 2) has
	 * been reinstalled and recorded in the map, so the QP's
	 * parent-PD / send-CQ / recv-CQ edges all resolve. Like CQs, QPs
	 * restore synchronously here on cmd_fd (master side) so the SQ/RQ
	 * ring pending-mmap slots exist before the pie's VMA pass.
	 */
	list_for_each_entry(c, &g->entries, link) {
		if (c->e->type != R3_UOBJ_TYPE__R3UT_QP)
			continue;
		ret = uobj_restore_qp(cmd_fd, kernel_driver_id, c->e, &map);
		if (ret)
			goto out;
	}

out:
	xfree(map.e);
	return ret;
}

int rdma_prepare_rdma_mrs(struct task_restore_args *ta)
{
	struct rdma_pending_mr *p, *n;

	/*
	 * Anchor ta->rdma_mrs at the current RM_PRIVATE cursor before
	 * knowing whether anything lands here, so the pool cursor stays
	 * consistent across the whole prepare_* sequence on the no-MR path.
	 */
	ta->rdma_mrs = (struct rst_rdma_mr *)rst_mem_align_cpos(RM_PRIVATE);
	ta->rdma_mrs_n = 0;

	list_for_each_entry_safe(p, n, &rdma_pending_mrs, link) {
		struct rst_rdma_mr *r = rst_mem_alloc(sizeof(*r), RM_PRIVATE);

		if (!r) {
			pr_err("uobj DAG: rst_mem_alloc(RM_PRIVATE) for MR handle=%u failed\n", p->target_handle);
			close(p->cmd_fd_dup);
			return -1;
		}
		r->cmd_fd = p->cmd_fd_dup;
		r->ufile_id = p->ufile_id;
		r->kernel_driver_id = p->kernel_driver_id;
		r->target_handle = p->target_handle;
		r->parent_pd_handle = p->parent_pd_handle;
		r->addr = p->addr;
		r->length = p->length;
		r->iova = p->iova;
		r->access_flags = p->access_flags;
		r->lkey_hint = p->lkey;
		r->rkey_hint = p->rkey;
		r->uhw_in_len = p->uhw_in_len;
		if (p->uhw_in_len)
			memcpy(r->uhw_in_buf, p->uhw_in_buf, p->uhw_in_len);
		ta->rdma_mrs_n++;

		list_del(&p->link);
		xfree(p);
	}

	if (ta->rdma_mrs_n)
		pr_info("uobj DAG: staged %u MR(s) for pie RESTORE_MR\n", ta->rdma_mrs_n);
	return 0;
}
