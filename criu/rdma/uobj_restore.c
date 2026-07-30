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
 * v0 scope (rxe PD + MR): collect + group, then a dependency-ordered
 * per-ufile walk -- PDs first (RESTORE_PD, synchronous on cmd_fd),
 * then MRs. An MR carries no ctxn and references its parent PD by the
 * source restrack id, so the walk resolves that edge to the parent's
 * destination handle through the per-ufile (type, restrack_id) ->
 * ufile_handle map the PD pass builds. The RESTORE_MR ioctl itself is
 * deferred to the pie restorer (it must run in the target's restored
 * address space so the MR's user_addr pages are pinnable); this file
 * prepares each MR here -- resolves its parent handle and queues a
 * fully-populated record -- and rdma_prepare_rdma_mrs() later bursts
 * the queue into the pie restorer's RM_PRIVATE args, where
 * restore_rdma_mr issues the ioctl post-VMA. CQ/QP/SRQ arms follow in
 * their milestones.
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <rdma/rdma_user_ioctl_cmds.h>
#include <rdma/ib_user_ioctl_cmds.h>

#include "common/config.h"
#include "common/compiler.h"
#include "common/list.h"
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
 *   UVERBS_OBJECT_RESTORE         = 20
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
#ifndef CONFIG_HAS_UVERBS_OBJECT_RESTORE
#define UVERBS_OBJECT_RESTORE 20
#endif
#ifndef UVERBS_METHOD_RESTORE_PD
#define UVERBS_METHOD_RESTORE_PD 0
#endif
#ifndef UVERBS_ATTR_RESTORE_PD_HANDLE
#define UVERBS_ATTR_RESTORE_PD_HANDLE 0
#endif

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
 * a PD uobject at the caller-chosen ufile handle @target_handle.
 *
 * rxe (v0): the handle is the only input. rxe's kernel-side
 * restore_pd handler reads no driver-private UHW -- a PD carries no FW
 * state -- so no plugin blob is packed. (mlx5 will add a UHW_IN
 * carrying the source FW pdn via its own plugin hook in a later
 * milestone; core stays driver-agnostic.)
 *
 * The handle rides inline in the attr's data field: uverbs treats a
 * PTR_IN whose len <= sizeof(data) as an immediate.
 *
 * Returns 0 on success or -errno on ioctl failure (a too-old kernel
 * returns -EOPNOTSUPP for the unknown UVERBS_OBJECT_RESTORE).
 */
static int rdma_send_restore_pd(int cmd_fd, uint32_t kernel_driver_id, uint32_t target_handle)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[1];
	} cmd = {};

	cmd.hdr.object_id = UVERBS_OBJECT_RESTORE;
	cmd.hdr.method_id = UVERBS_METHOD_RESTORE_PD;
	cmd.hdr.driver_id = kernel_driver_id;
	cmd.hdr.num_attrs = 1;
	cmd.hdr.length = sizeof(cmd.hdr) + sizeof(cmd.attrs);

	cmd.attrs[0].attr_id = UVERBS_ATTR_RESTORE_PD_HANDLE;
	cmd.attrs[0].len = sizeof(uint32_t);
	cmd.attrs[0].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[0].data = target_handle;

	return ioctl(cmd_fd, RDMA_VERBS_IOCTL, &cmd) < 0 ? -errno : 0;
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

	rc = rdma_send_restore_pd(cmd_fd, kernel_driver_id, e->ufile_handle);
	if (rc) {
		pr_err("uobj DAG: RESTORE_PD handle=%u on cmd_fd=%d driver=%u failed: %d (%s)\n", e->ufile_handle,
		       cmd_fd, kernel_driver_id, rc, strerror(rc < 0 ? -rc : rc));
		return -1;
	}
	pr_debug("uobj DAG: RESTORE_PD handle=%u ok (cmd_fd=%d driver=%u)\n", e->ufile_handle, cmd_fd, kernel_driver_id);

	return handle_map_add(m, R3_UOBJ_TYPE__R3UT_PD, e->restrack_id, e->ufile_handle);
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
	INIT_LIST_HEAD(&p->link);
	list_add_tail(&p->link, &rdma_pending_mrs);

	pr_info("uobj DAG: MR handle=%u queued for pie: parent_pd_handle=%u va=%#" PRIx64 " len=%" PRIu64
		" access=%#x lkey=%#x rkey=%#x iova=%#" PRIx64 "\n",
		e->ufile_handle, parent_pd_handle, (uint64_t)attrs->virt_addr, (uint64_t)attrs->length,
		attrs->access_flags, attrs->lkey, attrs->rkey, (uint64_t)attrs->iova);
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
	 * then the uobjects that reference them. v0 has a single edge kind
	 * (MR -> parent PD), so a type-ranked two-pass walk is a sufficient
	 * topo-sort; a general Kahn walk lands if/when intra-class edges do.
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
		case R3_UOBJ_TYPE__R3UT_MR:
			ret = uobj_prepare_mr(cmd_fd, ufile_id, kernel_driver_id, c->e, &map);
			break;
		default:
			pr_err("uobj DAG: ufile_id=%#x has unsupported uobj type %d\n", ufile_id, c->e->type);
			ret = -1;
			break;
		}
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
		ta->rdma_mrs_n++;

		list_del(&p->link);
		xfree(p);
	}

	if (ta->rdma_mrs_n)
		pr_info("uobj DAG: staged %u MR(s) for pie RESTORE_MR\n", ta->rdma_mrs_n);
	return 0;
}
