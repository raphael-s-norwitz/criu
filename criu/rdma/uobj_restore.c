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
 * v0 scope (rxe PD): collect + group + verify + a PD-entry walk that
 * builds the per-ufile kernel-handle map. The actual
 * UVERBS_METHOD_RESTORE_PD verb lands in the next commit; until then
 * the walk is a no-op replay, so a bare-context (no-PD) dump restores
 * exactly as before. CQ/QP/MR/SRQ arms follow in their milestones.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "common/compiler.h"
#include "common/list.h"
#include "image.h"
#include "log.h"
#include "protobuf.h"
#include "rdma.h"
#include "xmalloc.h"

#include "images/rdma_uobj.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "rdma: "

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
 * Per-ufile kernel-handle map. Restore installs each uobject at the
 * ufile_handle the dump recorded; as later uobject types (CQ/QP/...)
 * come online they resolve their xref edges (parent PD, send/recv CQ)
 * through this map. PD has no incoming edges, so v0 only writes it.
 */
struct uobj_handle_map {
	uint32_t *handles;
	size_t n;
	size_t cap;
};

static int handle_map_add(struct uobj_handle_map *m, uint32_t handle)
{
	if (m->n == m->cap) {
		size_t newcap = m->cap ? m->cap * 2 : 16;
		void *p = xrealloc(m->handles, newcap * sizeof(*m->handles));

		if (!p)
			return -1;
		m->handles = p;
		m->cap = newcap;
	}
	m->handles[m->n++] = handle;
	return 0;
}

/*
 * Restore one PD. v0 stub: the UVERBS_METHOD_RESTORE_PD verb lands in
 * the next commit. For now we validate the entry carries the handle
 * restore needs and record it, so the dispatch scaffolding (and the
 * handle map) is exercised without touching the kernel.
 */
static int uobj_restore_pd(int cmd_fd, uint32_t kernel_driver_id, const RdmaUobjEntry *e, struct uobj_handle_map *m)
{
	if (!e->has_ufile_handle) {
		pr_err("uobj DAG: PD entry (restrack_id=%u) has no ufile_handle; cannot restore (dump ran on a "
		       "pre-K8a kernel)\n",
		       e->has_restrack_id ? e->restrack_id : 0);
		return -1;
	}

	pr_debug("uobj DAG: would RESTORE_PD handle=%u on cmd_fd=%d driver=%u (verb not wired yet)\n", e->ufile_handle,
		 cmd_fd, kernel_driver_id);

	return handle_map_add(m, e->ufile_handle);
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

	pr_info("uobj DAG: restoring ufile_id=%#x (%d uobjs) on cmd_fd=%d\n", ufile_id, g->n_total, cmd_fd);

	list_for_each_entry(c, &g->entries, link) {
		switch (c->e->type) {
		case R3_UOBJ_TYPE__R3UT_PD:
			ret = uobj_restore_pd(cmd_fd, kernel_driver_id, c->e, &map);
			break;
		default:
			pr_err("uobj DAG: ufile_id=%#x has unsupported uobj type %d; only PD is restorable in v0\n",
			       ufile_id, c->e->type);
			ret = -1;
			break;
		}
		if (ret)
			break;
	}

	xfree(map.handles);
	return ret;
}
