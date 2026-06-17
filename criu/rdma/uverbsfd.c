/*
 * uverbs cdev fd dump/restore + plugin-claim arbitration.
 *
 * Owns the dump-side write path for /dev/infiniband/uverbsN cdev
 * fds and their implicitly-created async-event evfds:
 *
 *   dump_uverbsfile()                 fdtype.dump for FD_TYPES__UVERBSFD
 *   dump_async_eventfile()            fdtype.dump for FD_TYPES__UVERBSASYNCFD
 *   uverbsfd_open()                   file_desc.open for FD_TYPES__UVERBSFD
 *   uverbsasyncevfd_open()            file_desc.open for FD_TYPES__UVERBSASYNCFD
 *   collect_one_uverbsfd()            collect_image_info.collect (uverbsfd)
 *   collect_one_uverbsasyncevfd()     collect_image_info.collect (uverbsasyncevfd)
 *
 * Plus the plugin-arbitration / dispatch helpers shared with the
 * pre-suspend coverage path:
 *
 *   rdma_arbitrate_plugin_claim()     declared in rdma.h
 *   rdma_dispatch_dump_uverbs_context() declared in rdma.h
 *   rdma_dispatch_open_uverbs_cdev()  declared in rdma.h
 *   uverbsfd_validate_claim()         file-private
 *
 * Static state owned by this file:
 *
 *   ctxn_uverbsfd_id_map[]            ctxn -> uvfe_id, written by
 *                                     collect_one_uverbsfd, read by
 *                                     uverbsasyncevfd_open.
 *   rdma_dumped_ufiles                LIST_HEAD; struct definition is
 *                                     in criu/include/rdma/internal.h
 *                                     since rdma_dump_uobj_dag
 *                                     reads from it.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include <dlfcn.h>

#include <rdma/rdma_user_ioctl_cmds.h>
#include <rdma/ib_user_ioctl_cmds.h>
#include <rdma/ib_user_ioctl_verbs.h>
#include <rdma/ib_user_verbs.h>

#include "common/compiler.h"
#include "common/list.h"
#include "criu-plugin.h"
#include "fdinfo.h"
#include "files.h"
#include "files-reg.h"
#include "image.h"
#include "imgset.h"
#include "int.h"
#include "log.h"
#include "plugin.h"
#include "protobuf.h"
#include "rdma.h"
#include "rdma/internal.h"
#include "xmalloc.h"

#include "images/fdinfo.pb-c.h"
#include "images/uverbsfd.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "rdma: "

/* FIXME: Probably not a real max */
#define MAX_PROCESS_CONTEXTS 4096

/* FIXME: Probably replace with linked list or hasmap/xarray. */
static u32 ctxn_uverbsfd_id_map[MAX_PROCESS_CONTEXTS];

/*
 * struct rdma_dumped_ufile and the rdma_dumped_ufiles list head
 * are declared in criu/include/rdma/internal.h; this file owns the
 * storage so the consumer in criu/rdma/rdma.c (rdma_dump_uobj_dag)
 * can read it via the extern.
 */
LIST_HEAD(rdma_dumped_ufiles);

static int rdma_record_dumped_ufile(pid_t pid, const char *ibdev,
				    uint32_t kernel_driver_id,
				    uint32_t criu_driver,
				    plugin_desc_t *plugin,
				    uint32_t uvfe_id,
				    bool has_ctxn, uint32_t ctxn,
				    int holder_uctx_fd)
{
	struct rdma_dumped_ufile *r;

	r = xzalloc(sizeof(*r));
	if (!r) {
		if (holder_uctx_fd >= 0)
			close(holder_uctx_fd);
		return -1;
	}
	r->pid = pid;
	r->ctxn = ctxn;
	r->has_ctxn = has_ctxn;
	r->uvfe_id = uvfe_id;
	r->criu_driver = criu_driver;
	r->kernel_driver_id = kernel_driver_id;
	r->holder_uctx_fd = holder_uctx_fd;
	r->plugin = plugin;
	snprintf(r->ibdev, sizeof(r->ibdev), "%.*s",
		 (int)(sizeof(r->ibdev) - 1), ibdev);
	list_add_tail(&r->link, &rdma_dumped_ufiles);
	return 0;
}

bool is_async_eventfd(char *link)
{
	return is_anon_link_type(link, "[infinibandevent]");
}

static int dump_async_eventfile(int lfd, u32 id, const struct fd_parms *p)
{
	UverbsAsyncEvFileEntry uvae = UVERBS_ASYNC_EV_FILE_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;
	struct cr_img *img;

	uvae.id = id;

	/*
	 * Like eventfd: anon_inode has no path; do not call dump_one_reg_file()
	 * (fill_fdlink → anon_inode:… breaks mount lookup in files-reg.c).
	 */
	if (parse_fdinfo_pid(p->pid, p->fd, FD_TYPES__UVERBSASYNCFD, &uvae))
		return -1;

	pr_info("Dumping infinibandevent anon_inode %d with id %#x", lfd, id);
	if (uvae.has_ctxn)
		pr_info(" ctxn %u", uvae.ctxn);
	pr_info("\n");

	fe.type = FD_TYPES__UVERBSASYNCFD;
	fe.id = uvae.id;
	fe.uvaefd = &uvae;

	img = img_from_set(glob_imgset, CR_FD_FILES);
	return pb_write_one(img, &fe, PB_FILE);
}

const struct fdtype_ops uverbs_async_eventfd_dump_ops = {
	.type = FD_TYPES__UVERBSASYNCFD,
	.dump = dump_async_eventfile,
};

struct uverbsasyncevfd_file_info {
	UverbsAsyncEvFileEntry *uvaefe;
	struct file_desc d;
};

/*
 * Forward-declared here so uverbsasyncevfd_open() can container_of() back to
 * the parent uverbs cdev's file_info to fish out its driver_id. The struct's
 * full definition lives further down with the other uverbsfd plumbing.
 */
struct uverbsfd_file_info {
	UverbsFileEntry *uvfe;
	struct file_desc d;
};

static int
ib_uverbs_alloc_async_event_fd_ioctl(int cmd_fd, uint32_t driver_id,
				     int *async_fd_out)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[1];
	} buf;

	memset(&buf, 0, sizeof(buf));

	buf.hdr.object_id = UVERBS_OBJECT_ASYNC_EVENT;
	buf.hdr.method_id = UVERBS_METHOD_ASYNC_EVENT_ALLOC;
	buf.hdr.driver_id = driver_id;
	buf.hdr.reserved1 = 0;
	buf.hdr.reserved2 = 0;
	buf.hdr.num_attrs = 1;

	buf.attrs[0].attr_id = UVERBS_ATTR_ASYNC_EVENT_ALLOC_FD_HANDLE;
	buf.attrs[0].len = 0;
	buf.attrs[0].flags = UVERBS_ATTR_F_MANDATORY;
	buf.attrs[0].data = 0;
	buf.hdr.length = sizeof(buf.hdr) + sizeof(buf.attrs[0]);

	if (ioctl(cmd_fd, RDMA_VERBS_IOCTL, &buf.hdr) != 0)
		return -errno;

	*async_fd_out = (int)buf.attrs[0].data;
	return 0;
}

static int uverbsasyncevfd_open(struct file_desc *d, int *new_fd)
{
	struct uverbsasyncevfd_file_info *ui;
	struct uverbsfd_file_info *cmd_ui;
	struct file_desc *cmd_fd_desc;
	int async_fd = -1, cmd_fd, ret;
	uint32_t driver_id;
	u32 cmd_fd_id;

	ui = container_of(d, struct uverbsasyncevfd_file_info, d);

	cmd_fd_id = ctxn_uverbsfd_id_map[ui->uvaefe->ctxn];
	if (!cmd_fd_id) {
		pr_info("No chr device set for async fd id %#x ctxn %u, retrying\n",
			ui->uvaefe->id,
			ui->uvaefe->has_ctxn ? ui->uvaefe->ctxn : 0);
		return 1;
	}

	cmd_fd_desc = find_file_desc_raw(FD_TYPES__UVERBSFD, cmd_fd_id);
	if (!cmd_fd_desc) {
		pr_info("No cmd_fd found for async ev fd id %#x ctxn %u\n",
			ui->uvaefe->id,
			ui->uvaefe->has_ctxn ? ui->uvaefe->ctxn : 0);
		return -1;
	}

	/*
	 * driver_id is owned by the parent uverbs cdev's file_info; we
	 * intentionally do not duplicate it on the async-ev entry. The
	 * ctxn -> cmd_fd indirection above is the canonical lookup.
	 */
	cmd_ui = container_of(cmd_fd_desc, struct uverbsfd_file_info, d);
	if (!cmd_ui->uvfe->has_driver_id) {
		pr_err("Parent uverbsfd id %#x has no driver_id; image too "
		       "old or produced by criu without RDMA driver detection.\n",
		       cmd_fd_id);
		return -1;
	}
	driver_id = cmd_ui->uvfe->driver_id;
	cmd_fd = file_master(cmd_fd_desc)->fe->fd;

	ret = ib_uverbs_alloc_async_event_fd_ioctl(cmd_fd, driver_id,
						   &async_fd);
	if (ret) {
		pr_info("asyncevfd alloc failed %s (%d) - cmd_fd %d driver=%u id %#x ctxn %u\n",
			strerror(-ret), ret, cmd_fd, driver_id, ui->uvaefe->id,
			ui->uvaefe->has_ctxn ? ui->uvaefe->ctxn : 0);
		return -1;
	}

	pr_info("Opened uverbs async ev fd id %#x ctxn %u with cmd_fd %d driver=%u\n",
		ui->uvaefe->id, ui->uvaefe->has_ctxn ? ui->uvaefe->ctxn : 0,
		cmd_fd, driver_id);

	*new_fd = async_fd;
	return 0;
}

static struct file_desc_ops uverbs_async_eventfile_desc_ops = {
	.type = FD_TYPES__UVERBSASYNCFD,
	.open = uverbsasyncevfd_open,
};

static int collect_one_uverbsasyncevfd(void *o, ProtobufCMessage *base,
				       struct cr_img *i)
{
	struct uverbsasyncevfd_file_info *ui = o;

	ui->uvaefe = pb_msg(base, UverbsAsyncEvFileEntry);
	file_desc_add(&ui->d, ui->uvaefe->id, &uverbs_async_eventfile_desc_ops);

	pr_info("Collected uverbsasyncevfd ctxn %d\n", ui->uvaefe->ctxn);

	return 0;
}

struct collect_image_info uverbsasyncevfd_cinfo = {
	.fd_type = CR_FD_UVERBSAE_FILE,
	.pb_type = PB_UVERBS_ASYNC_EV_FILE,
	.priv_size = sizeof(struct uverbsasyncevfd_file_info),
	.collect = collect_one_uverbsasyncevfd,
};

/*
 * Walk every plugin that registered the RDMA_CLAIM_UVERBS_CONTEXT
 * hook and ask each one whether it claims the given uverbs context.
 *
 * Arbitration policy is exactly-one-claim:
 *   - 0 plugins claim   -> RCD_UNKNOWN return, treated by caller as
 *                          "no CRIU support for this device, fail
 *                          dump (or fail restore -- same iterator
 *                          runs in both directions)".
 *   - 1 plugin claims   -> return that plugin's RdmaCriuDriver value;
 *                          *claimer_name (if non-NULL) is set to the
 *                          plugin's name for diagnostics.
 *   - 2+ plugins claim  -> -EEXIST. The operator's plugin set is
 *                          inconsistent (e.g. two plugins both think
 *                          they own mlx5_core SAVE/LOAD) and we'd
 *                          rather fail loudly than pick arbitrarily.
 *   - any plugin fn returns < 0 -> propagated as a hard error
 *                          (probe failure is distinct from "decline").
 *
 * Iterates the plugin list in registration order; that order is not
 * stable across runs, hence no implicit "first wins" semantics.
 */
int rdma_arbitrate_plugin_claim(const char *ibdev,
				uint32_t kernel_driver_id,
				const char **claimer_name)
{
	plugin_desc_t *this;
	int winner = RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	const char *winner_name = NULL;

	list_for_each_entry(this,
		&cr_plugin_ctl.hook_chain[CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT],
		link[CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT]) {
		CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT_t *fn =
			this->d->hooks[CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT];
		int r = fn(ibdev, kernel_driver_id);

		if (r < 0) {
			pr_err("plugin '%s' claim() probe failed for ibdev=%s "
			       "kdrv=%u: %d\n",
			       this->d->name, ibdev, kernel_driver_id, r);
			return r;
		}
		if (r == RDMA_CRIU_DRIVER__RCD_UNKNOWN)
			continue;
		if (winner != RDMA_CRIU_DRIVER__RCD_UNKNOWN) {
			pr_err("RDMA plugin claim conflict on ibdev=%s: "
			       "'%s' (rcd=%d) and '%s' (rcd=%d) both claim. "
			       "Operator's plugin set is inconsistent.\n",
			       ibdev, winner_name, winner,
			       this->d->name, r);
			return -EEXIST;
		}
		winner = r;
		winner_name = this->d->name;
	}

	if (claimer_name)
		*claimer_name = winner_name;
	return winner;
}

static int dump_uverbsfile_cc_precheck(int lfd, uint32_t driver_id,
				       const char *ibdev, uint32_t ctxn);

static int dump_uverbsfile(int lfd, u32 id, const struct fd_parms *p)
{
	UverbsFileEntry uve = UVERBS_FILE_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;
	struct cr_img *img;
	const char *claimer = NULL;
	plugin_desc_t *plugin = NULL;
	char ibdev[64];
	char driver[64];
	int rcd, ret = -1;

	uve.id = id;

	if (parse_fdinfo_pid(p->pid, p->fd, FD_TYPES__UVERBSFD, &uve))
		return -1;

	if (dump_one_reg_file(lfd, id, p))
		return -1;

	/*
	 * Resolve the cdev to its ibdev and backing kernel driver. Both go
	 * into the image so restore can pick the right RDMA_DRIVER_* without
	 * inferring it (and so future per-provider plugins can claim the
	 * context by driver name).
	 */
	if (rdma_ibdev_from_chrdev(major(p->stat.st_rdev),
				   minor(p->stat.st_rdev),
				   ibdev, sizeof(ibdev))) {
		pr_err("Can't resolve ibdev for uverbs cdev %u:%u\n",
		       major(p->stat.st_rdev), minor(p->stat.st_rdev));
		goto out;
	}
	if (rdma_driver_name_from_ibdev(ibdev, driver, sizeof(driver))) {
		pr_err("Can't resolve kernel driver for ibdev '%s'\n", ibdev);
		goto out;
	}

	uve.ib_dev = xstrdup(ibdev);
	uve.driver_name = xstrdup(driver);
	if (!uve.ib_dev || !uve.driver_name)
		goto out;

	uve.driver_id = rdma_driver_name_to_id(driver);
	uve.has_driver_id = true;
	if (uve.driver_id == RDMA_DRIVER_UNKNOWN) {
		pr_err("Unknown RDMA driver '%s' for ibdev '%s' (uverbs cdev %u:%u). "
		       "Add a mapping to rdma_driver_name_to_id() in criu/rdma.c.\n",
		       driver, ibdev,
		       major(p->stat.st_rdev), minor(p->stat.st_rdev));
		goto out;
	}

	/*
	 * Decide which CRIU plugin owns this context. Even if the kernel
	 * driver is one we recognise, we still need a plugin loaded that
	 * actually knows how to dump+restore it -- otherwise the image
	 * we're about to write would be unrestorable on this very host,
	 * never mind another one. Hard fail: better than silently
	 * producing dead images.
	 */
	rcd = rdma_arbitrate_plugin_claim(ibdev, uve.driver_id, &claimer);
	if (rcd < 0) {
		pr_err("dump_uverbsfile: plugin arbitration failed for "
		       "ibdev=%s driver=%s: %d\n",
		       ibdev, driver, rcd);
		goto out;
	}
	if (rcd == RDMA_CRIU_DRIVER__RCD_UNKNOWN) {
		pr_err("dump_uverbsfile: no RDMA CRIU plugin claims "
		       "ibdev=%s driver=%s (RDMA_DRIVER id=%u). Refusing "
		       "to checkpoint a context that no plugin can "
		       "restore. Load the appropriate plugin via "
		       "CRIU_LIBS_DIR or install it into "
		       "/usr/lib/criu/.\n",
		       ibdev, driver, uve.driver_id);
		goto out;
	}
	uve.criu_driver = rcd;
	uve.has_criu_driver = true;

	pr_info("Dumping uverbs char device %d with id %#x ibdev=%s driver=%s "
		"id=%u claimed by plugin '%s' rcd=%d",
		lfd, id, ibdev, driver, uve.driver_id, claimer, rcd);
	if (uve.has_ctxn)
		pr_info(" ctxn %u", uve.ctxn);
	pr_info("\n");

	/*
	 * Resolve the cached plugin pointer once for this ufile.
	 * CLAIM arbitration just succeeded against this very
	 * criu_driver, so a miss here means the operator's plugin
	 * set is inconsistent (claim hook lives in plugin A,
	 * provided-driver symbol lives in plugin B) -- hard fail
	 * rather than re-walk per uobject.
	 *
	 * The cached pointer flows in two directions: synchronously
	 * into rdma_dispatch_dump_uverbs_context() below (so the
	 * dispatcher doesn't redo the lookup), and onto the
	 * struct rdma_dumped_ufile recorded a few lines down (so
	 * every per-uobject dump dispatcher in the post-walk
	 * picks it up via uf->plugin without another walk).
	 */
	{
		const char *first_name = NULL, *second_name = NULL;
		bool ambiguous = false;

		plugin = rdma_find_plugin_by_provided_driver(uve.criu_driver,
							     &ambiguous,
							     &first_name,
							     &second_name);
		if (ambiguous) {
			pr_err("dump_uverbsfile: multiple plugins declare "
			       "cr_rdma_provided_driver=%u ('%s' and '%s'); "
			       "operator's plugin set is inconsistent.\n",
			       uve.criu_driver, first_name, second_name);
			goto out;
		}
		if (!plugin) {
			pr_err("dump_uverbsfile: no loaded RDMA plugin "
			       "exports cr_rdma_provided_driver=%u for "
			       "ibdev=%s -- CLAIM arbitration just named "
			       "this driver, so the plugin list changed "
			       "mid-dump or the winning plugin is missing "
			       "its CR_PLUGIN_DECLARE_RDMA_PROVIDED_DRIVER "
			       "declaration.\n",
			       uve.criu_driver, ibdev);
			goto out;
		}
	}

	/*
	 * Per-context dump-side state capture (e.g. mlx5
	 * SAVE_VHCA_STATE). Optional: rxe and other plugins that have
	 * no per-context firmware state to persist do not register
	 * the hook and the dispatcher returns 0 without doing
	 * anything. Run after CLAIM (so we know the winning plugin)
	 * but before pb_write_one (so a hook failure aborts the dump
	 * before any uverbsfd record is committed -- the restore
	 * would have nothing to read otherwise). uve.ctxn is the
	 * join key the plugin's restore-side counterpart will use to
	 * find this capture again.
	 */
	if (rdma_dispatch_dump_uverbs_context(plugin, ibdev, uve.driver_id,
					      uve.has_ctxn ? uve.ctxn : 0,
					      lfd, p->pid)) {
		pr_err("dump_uverbsfile: per-context dump hook failed for "
		       "ibdev=%s ctxn=%u; aborting dump\n",
		       ibdev, uve.has_ctxn ? uve.ctxn : 0);
		goto out;
	}

	/*
	 * v0 pre-S8 limitation: any CC-attached CQ would dump fine
	 * but fail at restore time. Refuse the dump now if the source
	 * has any live comp_channel uobjects. Best-effort -- ioctl
	 * failure downgrades to a warn (see helper).
	 */
	if (dump_uverbsfile_cc_precheck(lfd, uve.driver_id, ibdev,
					uve.has_ctxn ? uve.ctxn : 0))
		goto out;

	fe.type = FD_TYPES__UVERBSFD;
	fe.id = uve.id;
	fe.uvfd = &uve;

	/*
	 * Record this ufile for the post-dump R3 per-uobject DAG
	 * walk. Done before pb_write_one so a record-side OOM aborts
	 * the dump with the same atomicity guarantee as a write
	 * failure -- partial uverbs records on disk without a
	 * matching DAG entry would be confusing on inspection.
	 *
	 * Dup @lfd into a long-lived O_CLOEXEC fd before the record;
	 * the dup shares the holder's struct file (and therefore
	 * its ib_ucontext IDR) so rdma_dump_uobj_dag's per-MR
	 * QUERY_MR walk can resolve handles in the right ucontext
	 * scope. -1 means dup failed -- not fatal; the MR walk
	 * gracefully falls back to NLDEV-only field capture, which
	 * means user_addr / access_flags will be absent from the
	 * image and downstream RESTORE_MR may fail. We log so this
	 * is visible if it ever fires in practice.
	 */
	{
		int duped = fcntl(lfd, F_DUPFD_CLOEXEC, 0);
		if (duped < 0) {
			pr_warn("dump_uverbsfile: F_DUPFD_CLOEXEC of "
				"holder uverbsfd (pid=%d uvfe=%#x) failed: "
				"%s -- post-dump QUERY_MR walk will run "
				"without user_addr/access_flags coverage\n",
				p->pid, uve.id, strerror(errno));
		}
		if (rdma_record_dumped_ufile(p->pid, ibdev, uve.driver_id,
					     uve.criu_driver, plugin,
					     uve.id,
					     uve.has_ctxn, uve.ctxn,
					     duped)) {
			pr_err("dump_uverbsfile: failed to record ufile id=%#x "
			       "for post-dump uobj DAG walk\n", uve.id);
			goto out;
		}
	}

	img = img_from_set(glob_imgset, CR_FD_FILES);
	ret = pb_write_one(img, &fe, PB_FILE);
out:
	xfree(uve.ib_dev);
	xfree(uve.driver_name);
	return ret;
}

const struct fdtype_ops uverbs_dump_ops = {
	.type = FD_TYPES__UVERBSFD,
	.dump = dump_uverbsfile,
};

/* struct uverbsfd_file_info is forward-declared near uverbsasyncevfd_open() */

/*
 * Public-API entry point: see criu_ib_uverbs_get_context() doc in
 * criu/include/criu-plugin.h. Plugins (rxe, mlx5_vfmig) call this
 * from their RDMA_OPEN_UVERBS_CDEV hook (or, for mlx5, from the
 * eager init(RESTORE)) so the fd they hand back to CRIU already
 * has a kernel ucontext on it; uverbsfd_open() therefore no longer
 * issues GET_CONTEXT itself (issuing it twice on the same struct
 * file is rejected by the kernel).
 */
int criu_ib_uverbs_get_context(int cmd_fd, uint32_t driver_id)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[2];
	} buf;

	memset(&buf, 0, sizeof(buf));

	buf.hdr.object_id = UVERBS_OBJECT_DEVICE;
	buf.hdr.method_id = UVERBS_METHOD_GET_CONTEXT;
	buf.hdr.driver_id = driver_id;
	buf.hdr.reserved1 = 0;
	buf.hdr.reserved2 = 0;

	buf.hdr.num_attrs = 0;
	buf.hdr.length = sizeof(buf.hdr);

	if (ioctl(cmd_fd, RDMA_VERBS_IOCTL, &buf.hdr) != 0)
		return -errno;

	return 0;
}

/*
 * Source a QP's hw-agnostic cap + state from the standard QUERY_QP
 * verb. See the contract in criu/include/rdma/internal.h.
 *
 * QUERY_QP has no ioctl-namespace method (unlike GET_CONTEXT /
 * INFO_HANDLES, which is why the rest of this file uses
 * RDMA_VERBS_IOCTL); it is a legacy write() command. The legacy
 * framing (drivers/infiniband/core/uverbs_main.c::ib_uverbs_write +
 * verify_hdr) is: total write length == hdr.in_words * 4 (hdr
 * included), the response buffer is reachable via the @response u64
 * at the head of the command body, and hdr.out_words * 4 must cover
 * sizeof(resp). attr_mask is left 0: the cap we need rides in
 * ib_query_qp's init_attr, which every provider fills regardless of
 * mask (rxe_qp_to_init / mlx5_ib_query_qp), as does attr->qp_state.
 */
int rdma_uverbs_query_qp(int cmd_fd, uint32_t qp_handle,
			 struct rdma_std_qp_attrs *out)
{
	struct {
		struct ib_uverbs_cmd_hdr  hdr;
		struct ib_uverbs_query_qp cmd;
	} req = {};
	struct ib_uverbs_query_qp_resp resp = {};
	ssize_t n;

	BUILD_BUG_ON(sizeof(req) % 4 != 0);
	BUILD_BUG_ON(sizeof(resp) % 4 != 0);

	req.hdr.command = IB_USER_VERBS_CMD_QUERY_QP;
	req.hdr.in_words = sizeof(req) / 4;
	req.hdr.out_words = sizeof(resp) / 4;
	req.cmd.response = (uintptr_t)&resp;
	req.cmd.qp_handle = qp_handle;
	req.cmd.attr_mask = 0;

	n = write(cmd_fd, &req, sizeof(req));
	if (n != (ssize_t)sizeof(req))
		return n < 0 ? -errno : -EIO;

	out->max_send_wr = resp.max_send_wr;
	out->max_recv_wr = resp.max_recv_wr;
	out->max_send_sge = resp.max_send_sge;
	out->max_recv_sge = resp.max_recv_sge;
	out->max_inline_data = resp.max_inline_data;
	out->qp_state = resp.qp_state;
	return 0;
}

/*
 * Restore-time counterpart of dump_uverbsfile()'s arbitration step.
 *
 * Re-runs the per-plugin claim() probe against the restoring host's
 * loaded plugin set and confirms that the plugin which would claim
 * this ibdev right now matches the one recorded in the image. This
 * catches three classes of operator misconfiguration:
 *
 *   (a) image carries criu_driver=RCD_X but the destination has no
 *       plugin loaded that returns RCD_X for this ibdev -- e.g.
 *       missed installing rdma_rxe_plugin.so on the destination;
 *
 *   (b) destination has a *different* plugin claiming this ibdev
 *       than the source did -- e.g. mlx5_core context dumped under
 *       mlx5_sriov_vfmig but destination only has the future
 *       fw-assisted-replay plugin loaded;
 *
 *   (c) destination's plugin set has the same ibdev but a stale
 *       host-side gate (e.g. SET_TRACKED was never run on the
 *       destination VF), so the plugin declines.
 *
 * In all three cases the restore must abort here, before the
 * plugin opens a fresh cdev fd and calls criu_ib_uverbs_get_context
 * on it -- that ioctl would happily succeed against any uverbs
 * cdev for which the kernel module is loaded, but no per-resource
 * restore code would subsequently know how to populate the
 * resulting ucontext.
 */
static int uverbsfd_validate_claim(const UverbsFileEntry *uvfe)
{
	const char *claimer = NULL;
	int rcd;

	if (!uvfe->has_criu_driver) {
		pr_err("uverbsfd id %#x has no criu_driver in image; image "
		       "predates plugin-claim arbitration. Re-dump with "
		       "current criu.\n",
		       uvfe->id);
		return -1;
	}

	rcd = rdma_arbitrate_plugin_claim(uvfe->ib_dev ?: "?",
					  uvfe->driver_id, &claimer);
	if (rcd < 0) {
		pr_err("uverbsfd id %#x: arbitration failed at restore: %d\n",
		       uvfe->id, rcd);
		return -1;
	}
	if (rcd == RDMA_CRIU_DRIVER__RCD_UNKNOWN) {
		pr_err("uverbsfd id %#x: no RDMA plugin on this host "
		       "claims ibdev=%s driver=%s. Image was dumped with "
		       "criu_driver=%d; install the matching plugin "
		       "before restoring.\n",
		       uvfe->id, uvfe->ib_dev ?: "?",
		       uvfe->driver_name ?: "?",
		       (int)uvfe->criu_driver);
		return -1;
	}
	if ((int)uvfe->criu_driver != rcd) {
		pr_err("uverbsfd id %#x: image was dumped under "
		       "criu_driver=%d but plugin '%s' (rcd=%d) claims "
		       "ibdev=%s on this host. Refusing to silently swap "
		       "plugins between dump and restore.\n",
		       uvfe->id, (int)uvfe->criu_driver, claimer, rcd,
		       uvfe->ib_dev ?: "?");
		return -1;
	}

	pr_info("uverbsfd id %#x: restore claim OK (plugin '%s' rcd=%d "
		"ibdev=%s)\n",
		uvfe->id, claimer, rcd, uvfe->ib_dev ?: "?");
	return 0;
}

/*
 * Walk the loaded plugin list and dispatch the OPEN_UVERBS_CDEV
 * hook to the single plugin whose cr_rdma_provided_driver constant
 * matches uvfe->criu_driver. Mirrors rdma_plugin_sharing_policy_by_
 * name() in shape: name-keyed walk over cr_plugin_ctl.head, dlsym
 * the well-known per-plugin constant from the dlhandle, compare,
 * dispatch.
 *
 * Why dispatch by image-recorded criu_driver rather than by plugin
 * registration order:
 *   The hook chain
 *   cr_plugin_ctl.hook_chain[CR_PLUGIN_HOOK__RDMA_OPEN_UVERBS_CDEV]
 *   contains every plugin that registered the hook -- i.e. all of
 *   them, in unspecified order. A blind list_for_each that called
 *   the first plugin would happily hand an mlx5 cdev to the rxe
 *   plugin (or vice versa) on a host where both .so files are
 *   loaded. Keying by criu_driver is the same arbitration
 *   guarantee CLAIM enforces at dump-time, replayed on the open
 *   side: exactly one plugin matches, and that plugin owns the
 *   open.
 *
 * Failure modes:
 *   - No plugin exports cr_rdma_provided_driver matching
 *     uvfe->criu_driver: hard fail. Image was dumped against a
 *     plugin that isn't present on this host -- the restore-time
 *     CLAIM validation in uverbsfd_validate_claim() should have
 *     caught this already, but defending in depth is cheap.
 *   - Multiple plugins match: hard fail with a diagnostic.
 *     Operator's plugin set is inconsistent (two .so files both
 *     declare the same provided-driver), and we cannot know which
 *     one the image was dumped against. Same posture as the
 *     dump-time exactly-one-claims policy.
 *   - The matching plugin's hook returns -1: propagate -1; the
 *     plugin is responsible for its own pr_err.
 */
/*
 * Generic per-plugin name lookup: walk the loaded plugin list and
 * return the (single) plugin whose dlhandle exposes a
 * cr_rdma_provided_driver constant equal to @criu_driver. Returns
 * NULL on miss. Returns NULL with *ambiguous=true if more than one
 * plugin matches (caller decides whether to treat that as a hard
 * error). Used by both the dump-side and restore-side dispatchers
 * so the matching policy stays in one place.
 *
 * Cross-file callers (e.g. criu/rdma/uobj_restore.c) use this via
 * the declaration in criu/include/rdma/internal.h to resolve their
 * per-ufile plugin once at the top of the per-ufile restore loop,
 * mirroring the dump-side caching on struct rdma_dumped_ufile.
 */
plugin_desc_t *rdma_find_plugin_by_provided_driver(uint32_t criu_driver,
						   bool *ambiguous,
						   const char **first_name,
						   const char **second_name)
{
	plugin_desc_t *this;
	plugin_desc_t *winner = NULL;

	if (ambiguous)
		*ambiguous = false;
	if (first_name)
		*first_name = NULL;
	if (second_name)
		*second_name = NULL;

	list_for_each_entry(this, &cr_plugin_ctl.head, list) {
		const int *p;

		if (!this->d || !this->dlhandle)
			continue;
		p = (const int *)dlsym(this->dlhandle,
				       CR_PLUGIN_RDMA_PROVIDED_DRIVER_SYM);
		if (!p)
			continue;
		if ((uint32_t)*p != criu_driver)
			continue;

		if (winner) {
			if (ambiguous)
				*ambiguous = true;
			if (second_name)
				*second_name = this->d->name;
			return NULL;
		}
		winner = this;
		if (first_name)
			*first_name = this->d->name;
	}
	return winner;
}

/*
 * Dump-side dispatcher. Calls @plugin's
 * CR_PLUGIN_HOOK__RDMA_DUMP_UVERBS_CONTEXT iff the plugin
 * registered the hook.
 *
 * @plugin is the pointer the caller cached at CLAIM time (see
 * dump_uverbsfile()). The plugin-walk + ambiguity check + missing-
 * provider-symbol diagnostics live at the cache site, not here --
 * by the time we reach this dispatcher, the cache has already
 * enforced exactly-one-plugin uniqueness.
 *
 * Optional hook semantics: rxe takes the no-op path -- it has no
 * firmware blob to capture beyond what the generic UverbsFileEntry
 * already records, so it doesn't bother registering the hook.
 */
int rdma_dispatch_dump_uverbs_context(plugin_desc_t *plugin,
				      const char *ibdev,
				      uint32_t kernel_driver_id,
				      uint32_t ctxn,
				      int lfd, pid_t pid)
{
	CR_PLUGIN_HOOK__RDMA_DUMP_UVERBS_CONTEXT_t *fn;

	if (!plugin->d->hooks[CR_PLUGIN_HOOK__RDMA_DUMP_UVERBS_CONTEXT]) {
		pr_debug("dump_uverbs_context: plugin '%s' (ibdev=%s) does "
			 "not register the hook; skipping.\n",
			 plugin->d->name, ibdev);
		return 0;
	}

	fn = plugin->d->hooks[CR_PLUGIN_HOOK__RDMA_DUMP_UVERBS_CONTEXT];
	pr_debug("dump_uverbs_context: dispatching to plugin '%s' "
		 "(ibdev=%s ctxn=%u pid=%d)\n",
		 plugin->d->name, ibdev, ctxn, (int)pid);
	return fn(ibdev, kernel_driver_id, ctxn, lfd, pid);
}

/*
 * Pre-S8 comp-channel pre-check. v0 RDMA-class plugins do not yet
 * support comp_channel save/restore (kernel UVERBS_METHOD_RESTORE_CQ
 * declares COMP_CHANNEL UA_OPTIONAL but hard-rejects with
 * -EOPNOTSUPP if any caller actually supplies one -- see kernel
 * include/uapi/rdma/ib_user_ioctl_cmds.h). A source CQ bound to a
 * comp_channel would dump cleanly and only surface as a failure at
 * restore time. Bail at dump time instead so the operator sees a
 * crisp diagnostic next to the dumpee, not a cryptic -EOPNOTSUPP
 * after the dump has already been moved off-host.
 *
 * Fires UVERBS_METHOD_INFO_HANDLES on UVERBS_OBJECT_DEVICE asking
 * for UVERBS_OBJECT_COMP_CHANNEL handles. Best-effort: any ioctl
 * failure (older kernel, missing INFO_HANDLES support, transient
 * EBUSY etc.) downgrades to a warn-and-continue. The kernel needs
 * a non-empty HANDLES_LIST out buffer (see uverbs_std_types_device.c
 * UVERBS_METHOD_INFO_HANDLES handler), so we pass a tiny one even
 * though we only inspect the TOTAL_HANDLES out.
 */
#define RDMA_CC_PRECHECK_HANDLES_BUF 16
static int dump_uverbsfile_cc_precheck(int lfd, uint32_t driver_id,
				       const char *ibdev, uint32_t ctxn)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr      attrs[3];
	} cmd = {};
	uint32_t total = 0;
	uint32_t handles[RDMA_CC_PRECHECK_HANDLES_BUF];

	cmd.hdr.object_id = UVERBS_OBJECT_DEVICE;
	cmd.hdr.method_id = UVERBS_METHOD_INFO_HANDLES;
	/* The dispatcher validates @driver_id against the per-
	 * ucontext rdma_driver_id (uverbs_ioctl.c::ib_uverbs_run_
	 * method): a mismatch returns -EINVAL. Pass the kernel-
	 * side driver id we received from CLAIM arbitration. */
	cmd.hdr.driver_id = driver_id;

	/* INFO_OBJECT_ID is UVERBS_ATTR_CONST_IN, which the kernel
	 * declares with sizeof(u64) min/max len -- see
	 * include/rdma/uverbs_ioctl.h::UVERBS_ATTR_CONST_IN. The
	 * uverbs ioctl parser checks uattr->len == sizeof(u64) and
	 * then takes the inline-attr fast path because
	 * uverbs_attr_ptr_is_inline returns true (len <=
	 * sizeof(attr->ptr_attr.data) == 8). The value -- here
	 * UVERBS_OBJECT_COMP_CHANNEL from enum
	 * uverbs_default_objects -- rides verbatim in attr.data. */
	cmd.attrs[0].attr_id = UVERBS_ATTR_INFO_OBJECT_ID;
	cmd.attrs[0].len = sizeof(uint64_t);
	cmd.attrs[0].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[0].data = UVERBS_OBJECT_COMP_CHANNEL;

	cmd.attrs[1].attr_id = UVERBS_ATTR_INFO_TOTAL_HANDLES;
	cmd.attrs[1].len = sizeof(total);
	cmd.attrs[1].flags = 0;
	cmd.attrs[1].data = (uintptr_t)&total;

	cmd.attrs[2].attr_id = UVERBS_ATTR_INFO_HANDLES_LIST;
	cmd.attrs[2].len = sizeof(handles);
	cmd.attrs[2].flags = 0;
	cmd.attrs[2].data = (uintptr_t)handles;

	cmd.hdr.num_attrs = 3;
	cmd.hdr.length = sizeof(cmd.hdr) + 3 * sizeof(cmd.attrs[0]);

	if (ioctl(lfd, RDMA_VERBS_IOCTL, &cmd) < 0) {
		pr_warn("dump_uverbsfile: INFO_HANDLES(COMP_CHANNEL) on "
			"ibdev=%s ctxn=%u failed: %s. Skipping CC "
			"pre-check; CQs bound to a comp_channel (if any) "
			"will surface as -EOPNOTSUPP at restore time.\n",
			ibdev, ctxn, strerror(errno));
		return 0;
	}

	if (total > 0) {
		pr_err("dump_uverbsfile: ibdev=%s ctxn=%u has %u live "
		       "UVERBS_OBJECT_COMP_CHANNEL uobject(s); v0 RDMA-"
		       "class plugins do not yet support comp_channel "
		       "save/restore. The dump would record per-CQ "
		       "state without the CC binding, and "
		       "UVERBS_METHOD_RESTORE_CQ on the destination "
		       "would reject any CC-attached CQ with "
		       "-EOPNOTSUPP. Aborting the dump now to surface "
		       "the limitation explicitly. Track the kernel "
		       "S8 RESTORE_COMP_CHANNEL work in "
		       "tools/testing/mlx5_vfmig/design/uobject_restore.md "
		       "?S8.\n", ibdev, ctxn, total);
		return -1;
	}

	pr_debug("dump_uverbsfile: CC pre-check ok for ibdev=%s ctxn=%u "
		 "(no live UVERBS_OBJECT_COMP_CHANNEL uobjects)\n",
		 ibdev, ctxn);
	return 0;
}

/*
 * Per-CQ dump dispatcher. Calls @plugin's
 * CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_CQ if registered.
 *
 * @plugin is the pointer cached on struct rdma_dumped_ufile.plugin
 * at CLAIM time (the caller in uobj_dump.c::uobj_cq_cb passes
 * @uf->plugin). The dispatcher does NOT re-walk the plugin list
 * per CQ; CLAIM has already enforced exactly-one-plugin uniqueness
 * and the result has been cached.
 *
 * @cq_attrs is owned by the caller and pre-populated with NLDEV-
 * derived fields (cqe_count). The plugin appends its driver-
 * private fields (the entry-level plugin_blob carrying e.g. the
 * mlx5 32B mlx5_ib_restore_cq_req, plus comp_vector + flags on the
 * per-class proto) and returns 0. Plugin-side -ENXIO is treated as
 * a per-uobject skip and surfaces as a successful dispatch with
 * @cq_attrs left as the caller staged it (kernel CQs land here
 * when the IDR walker mis-routes -- the kernel QUERY_CQ handler
 * also returns -ENXIO in that case, so the shape is uniform).
 *
 * Optional hook: a plugin that doesn't register the hook is a
 * no-op success (a future driver whose per-CQ state lives entirely
 * in NLDEV-derived core fields would take this path).
 */
int rdma_dispatch_dump_uobj_cq(plugin_desc_t *plugin,
			       const char *ibdev,
			       uint32_t kernel_driver_id,
			       int lfd, uint32_t ufile_handle,
			       pid_t pid,
			       RdmaCqAttrs *cq_attrs,
			       ProtobufCBinaryData *plugin_blob)
{
	CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_CQ_t *fn;
	int rc;

	if (!plugin->d->hooks[CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_CQ]) {
		pr_debug("dump_uobj_cq: plugin '%s' (ibdev=%s) does not "
			 "register the hook; skipping. ufile_handle=%u "
			 "will be dumped with NLDEV-only RdmaCqAttrs.\n",
			 plugin->d->name, ibdev, ufile_handle);
		return 0;
	}

	fn = plugin->d->hooks[CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_CQ];
	pr_debug("dump_uobj_cq: dispatching to plugin '%s' "
		 "(ibdev=%s ufile_handle=%u pid=%d)\n",
		 plugin->d->name, ibdev, ufile_handle, (int)pid);
	rc = fn(ibdev, kernel_driver_id, lfd, ufile_handle, pid, cq_attrs,
		plugin_blob);
	if (rc == -ENXIO) {
		pr_warn("dump_uobj_cq: plugin '%s' rejected CQ "
			"ufile_handle=%u on ibdev=%s with -ENXIO "
			"(kernel-mode CQ or no source userspace state); "
			"per-uobject driver-private fields will be absent\n",
			plugin->d->name, ufile_handle, ibdev);
		return 0;
	}
	return rc;
}

/*
 * Per-QP dump dispatcher. Mirror of rdma_dispatch_dump_uobj_cq
 * applied to UVERBS_METHOD_RESTORE_QP's discovery-side counterpart.
 *
 * @qp_attrs is owned by the caller and pre-populated with the
 * NLDEV-derived subset (qp_type, state, qp_num, dest_qp_num, sq_psn,
 * rq_psn, port_num) plus the cap tuple, which the caller sources
 * from the standard QUERY_QP verb (not from this plugin). The plugin
 * appends user_handle and create_flags (neither emitted by NLDEV nor
 * by the standard verb) and packs its driver-private 64B per-QP
 * payload into @plugin_blob (mlx5: byte-equal to struct
 * mlx5_ib_restore_qp_req captured via MLX5_IB_METHOD_VFMIG_QUERY_QP).
 *
 * Plugin -ENXIO is the per-uobject skip signal (kernel-mode QP
 * routed here by mistake -- mlx5_ib's QUERY_QP handler returns
 * -ENXIO when base->ubuffer.umem == NULL); demoted to a successful
 * dispatch with whatever NLDEV-derived bits the caller already
 * staged. Restore-side guards on absent driver-private fields and
 * surfaces a clear "image needs a re-dump on a kernel that has
 * QUERY_QP" diagnostic.
 *
 * Optional hook: a plugin that doesn't register the hook is a no-op
 * success (rxe pre-S6a takes this path until RXE_METHOD_VFMIG_QUERY_QP
 * lands).
 */
int rdma_dispatch_dump_uobj_qp(plugin_desc_t *plugin,
			       const char *ibdev,
			       uint32_t kernel_driver_id,
			       int lfd, uint32_t ufile_handle,
			       pid_t pid,
			       RdmaQpAttrs *qp_attrs,
			       ProtobufCBinaryData *plugin_blob)
{
	CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_QP_t *fn;
	int rc;

	if (!plugin->d->hooks[CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_QP]) {
		pr_debug("dump_uobj_qp: plugin '%s' (ibdev=%s) does not "
			 "register the hook; skipping. ufile_handle=%u "
			 "will be dumped with NLDEV-only RdmaQpAttrs.\n",
			 plugin->d->name, ibdev, ufile_handle);
		return 0;
	}

	fn = plugin->d->hooks[CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_QP];
	pr_debug("dump_uobj_qp: dispatching to plugin '%s' "
		 "(ibdev=%s ufile_handle=%u pid=%d)\n",
		 plugin->d->name, ibdev, ufile_handle, (int)pid);
	rc = fn(ibdev, kernel_driver_id, lfd, ufile_handle, pid, qp_attrs,
		plugin_blob);
	if (rc == -ENXIO) {
		pr_warn("dump_uobj_qp: plugin '%s' rejected QP "
			"ufile_handle=%u on ibdev=%s with -ENXIO "
			"(kernel-mode QP or no source userspace state); "
			"per-uobject driver-private fields will be absent\n",
			plugin->d->name, ufile_handle, ibdev);
		return 0;
	}
	return rc;
}

/*
 * Per-PD dump dispatcher. Mirror of rdma_dispatch_dump_uobj_cq /
 * _qp applied to UVERBS_METHOD_RESTORE_PD's discovery-side
 * counterpart.
 *
 * @pd_attrs is owned by the caller. v0 PD carries no NLDEV-derived
 * or plugin-owned hw-agnostic fields (PD allocation is access-flag-
 * less in IB verbs), so the plugin normally leaves it untouched and
 * packs its driver-private payload (mlx5: struct mlx5_ib_restore_pd_req
 * carrying the FW pdn captured via MLX5_IB_METHOD_VFMIG_QUERY_PD) into
 * @plugin_blob.
 *
 * Plugin -ENXIO is the per-uobject skip signal (kernel-internal PD
 * routed here by mistake); demoted to a successful dispatch with the
 * plugin_blob left empty. Optional hook: a plugin that doesn't
 * register the hook is a no-op success (rxe -- rxe_restore_pd reads
 * no UHW).
 */
int rdma_dispatch_dump_uobj_pd(plugin_desc_t *plugin,
			       const char *ibdev,
			       uint32_t kernel_driver_id,
			       int lfd, uint32_t ufile_handle,
			       pid_t pid,
			       RdmaPdAttrs *pd_attrs,
			       ProtobufCBinaryData *plugin_blob)
{
	CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_PD_t *fn;
	int rc;

	if (!plugin->d->hooks[CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_PD]) {
		pr_debug("dump_uobj_pd: plugin '%s' (ibdev=%s) does not "
			 "register the hook; skipping. ufile_handle=%u "
			 "will be dumped with no plugin_blob.\n",
			 plugin->d->name, ibdev, ufile_handle);
		return 0;
	}

	fn = plugin->d->hooks[CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_PD];
	pr_debug("dump_uobj_pd: dispatching to plugin '%s' "
		 "(ibdev=%s ufile_handle=%u pid=%d)\n",
		 plugin->d->name, ibdev, ufile_handle, (int)pid);
	rc = fn(ibdev, kernel_driver_id, lfd, ufile_handle, pid, pd_attrs,
		plugin_blob);
	if (rc == -ENXIO) {
		pr_warn("dump_uobj_pd: plugin '%s' rejected PD "
			"ufile_handle=%u on ibdev=%s with -ENXIO "
			"(kernel-mode PD or no source FW state); "
			"per-uobject driver-private fields will be absent\n",
			plugin->d->name, ufile_handle, ibdev);
		return 0;
	}
	return rc;
}

int rdma_dispatch_open_uverbs_cdev(const UverbsFileEntry *uvfe)
{
	plugin_desc_t *this;
	plugin_desc_t *winner = NULL;
	const char *winner_name = NULL;
	CR_PLUGIN_HOOK__RDMA_OPEN_UVERBS_CDEV_t *fn;

	if (!uvfe->has_criu_driver) {
		pr_err("uverbsfd id %#x: no criu_driver in image; cannot "
		       "dispatch OPEN_UVERBS_CDEV. Image too old.\n",
		       uvfe->id);
		return -1;
	}

	list_for_each_entry(this, &cr_plugin_ctl.head, list) {
		const int *p;

		if (!this->d || !this->dlhandle)
			continue;
		if (!this->d->hooks[CR_PLUGIN_HOOK__RDMA_OPEN_UVERBS_CDEV])
			continue;
		p = (const int *)dlsym(this->dlhandle,
				       CR_PLUGIN_RDMA_PROVIDED_DRIVER_SYM);
		if (!p)
			continue;
		if ((uint32_t)*p != uvfe->criu_driver)
			continue;

		if (winner) {
			pr_err("uverbsfd id %#x: multiple plugins declare "
			       "cr_rdma_provided_driver=%d ('%s' and '%s'); "
			       "operator's plugin set is inconsistent.\n",
			       uvfe->id, (int)uvfe->criu_driver,
			       winner_name, this->d->name);
			return -1;
		}
		winner = this;
		winner_name = this->d->name;
	}

	if (!winner) {
		pr_err("uverbsfd id %#x: no loaded RDMA plugin exports "
		       "cr_rdma_provided_driver=%d for ibdev=%s. Restore "
		       "cannot proceed without a plugin to open the "
		       "destination cdev.\n",
		       uvfe->id, (int)uvfe->criu_driver,
		       uvfe->ib_dev ?: "?");
		return -1;
	}

	fn = winner->d->hooks[CR_PLUGIN_HOOK__RDMA_OPEN_UVERBS_CDEV];
	pr_debug("uverbsfd id %#x: dispatching OPEN_UVERBS_CDEV to "
		 "plugin '%s' (criu_driver=%d ibdev=%s)\n",
		 uvfe->id, winner_name, (int)uvfe->criu_driver,
		 uvfe->ib_dev ?: "?");
	return fn(uvfe);
}

static int uverbsfd_open(struct file_desc *d, int *new_fd)
{
	struct uverbsfd_file_info *ui;
	uint32_t driver_id;
	int fd;

	ui = container_of(d, struct uverbsfd_file_info, d);

	/*
	 * driver_id is mandatory in the image as of the rxe-hardcoding
	 * removal. Older images without the field cannot be restored
	 * (we explicitly chose not to carry backwards compatibility for
	 * the in-flight rdma path).
	 */
	if (!ui->uvfe->has_driver_id) {
		pr_err("uverbsfd id %#x has no driver_id; image too old or "
		       "produced by criu without RDMA driver detection. "
		       "Re-dump with current criu.\n", ui->uvfe->id);
		return -1;
	}
	driver_id = ui->uvfe->driver_id;

	/*
	 * Confirm a plugin on this host claims the context before we
	 * try the kernel ioctls. The actual per-plugin restore work
	 * (PD/MR/CQ/QP recreate, mlx5 LOAD_VHCA_STATE, ...) lands in
	 * later commits; this commit just gates the generic
	 * GET_CONTEXT path on plugin coverage so an unsupported image
	 * fails fast and loudly here rather than partially restoring
	 * into an unusable context.
	 */
	if (uverbsfd_validate_claim(ui->uvfe))
		return -1;

	pr_info("Opening uverbsfd id %#x ibdev=%s driver=%s(%u) ctxn %u\n",
		ui->uvfe->id,
		ui->uvfe->ib_dev ?: "?",
		ui->uvfe->driver_name ?: "?",
		driver_id,
		ui->uvfe->has_ctxn ? ui->uvfe->ctxn : 0);

	/*
	 * Resolve the destination cdev via the claiming plugin rather
	 * than open_reg_by_id(). The image's reg_file_entry carries
	 * the source's cdev path (e.g. "/dev/infiniband/uverbs5"); on
	 * the destination the same ibdev name may live at a different
	 * minor (cross-host migration, post-reboot probe order, rdma
	 * link churn, mlx5 SR-IOV VF re-creation). The plugin walks
	 * /sys/class/infiniband/<ibdev>/dev to find the *current*
	 * minor, and for non-trivial providers (mlx5 vfmig) drives
	 * the per-context restore dance before opening. The
	 * source-recorded reg_file_entry is intentionally left in the
	 * image -- it's a useful diagnostic for `crit decode` and
	 * costs little, but nothing on the restore side opens it.
	 *
	 * Contract: the plugin returns a fd that already has a kernel
	 * ucontext established on it (i.e. the plugin has already
	 * issued criu_ib_uverbs_get_context, or has dup()ed a fd it
	 * eagerly armed in init(RESTORE)). This is uniform across
	 * plugins -- rxe issues GET_CONTEXT inline in its hook, mlx5
	 * vfmig issues it in init(RESTORE) on the cached cdev fds and
	 * hands back dup()s. That avoids the kernel's
	 * "one-ucontext-per-struct-file" rule from biting us if
	 * uverbsfd_open() also tried to issue GET_CONTEXT after the
	 * plugin already had.
	 *
	 * @driver_id is preserved here for the future rdma_image and
	 * for diagnostics; it is no longer used as a GET_CONTEXT
	 * argument by this function.
	 */
	fd = rdma_dispatch_open_uverbs_cdev(ui->uvfe);
	if (fd < 0)
		return -1;

	/*
	 * R3 per-uobject restore. Plugin gave us an open cdev with
	 * a restore-mode ucontext on it; replay every uobject the
	 * dump captured under this ufile by issuing the matching
	 * RESTORE_<TYPE> verb per entry. PD only at S2; CQ/QP/MR/
	 * SRQ/AH come online as the kernel side gains the per-class
	 * driver callbacks (see design/uobject_restore.md). No-op
	 * when the dump produced no rdma-uobj.img coverage for this
	 * ufile_id (treated as best-effort -- the empty ucontext
	 * matches the pre-R3 baseline behavior).
	 *
	 * @driver_id (the kernel's RDMA_DRIVER_* enum value, not the
	 * CRIU per-plugin RdmaCriuDriver enum that the per-uobj DAG
	 * group caches under hw_driver_id) is what the kernel's
	 * UVERBS_OBJECT_RESTORE dispatcher matches in the ioctl
	 * header.
	 */
	if (rdma_restore_uobj_dag_for_ufile(fd, ui->uvfe->id, driver_id)) {
		close(fd);
		return -1;
	}

	ctxn_uverbsfd_id_map[ui->uvfe->ctxn] = ui->uvfe->id;

	*new_fd = fd;
	return 0;
}

static struct file_desc_ops uverbs_desc_ops = {
	.type = FD_TYPES__UVERBSFD,
	.open = uverbsfd_open,
};

static int collect_one_uverbsfd(void *o, ProtobufCMessage *base, struct cr_img *i)
{
	struct uverbsfd_file_info *ui = o;

	ui->uvfe = pb_msg(base, UverbsFileEntry);
	file_desc_add(&ui->d, ui->uvfe->id, &uverbs_desc_ops);

	pr_info("Collected uverbsfd ctxn %d\n", ui->uvfe->ctxn);

	return 0;
}

struct collect_image_info uverbsfd_cinfo = {
	.fd_type = CR_FD_UVERBS_FILE,
	.pb_type = PB_UVERBS_FILE,
	.priv_size = sizeof(struct uverbsfd_file_info),
	.collect = collect_one_uverbsfd,
};
