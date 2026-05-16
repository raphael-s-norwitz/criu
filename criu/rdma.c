#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <rdma/rdma_user_ioctl_cmds.h>
#include <rdma/ib_user_ioctl_cmds.h>
#include <rdma/ib_user_ioctl_verbs.h>

#include "common/compiler.h"
#include "common/list.h"
#include "imgset.h"
#include "image.h"
#include "files.h"
#include "files-reg.h"
#include "int.h"
#include "log.h"
#include "plugin.h"
#include "protobuf.h"
#include "pstree.h"
#include "rdma.h"
#include "rdma_netlink.h"
#include "fdinfo.h"
#include "xmalloc.h"

#include "images/fdinfo.pb-c.h"
#include "images/rdma_criu.pb-c.h"
#include "images/rdma_uobj.pb-c.h"
#include "images/uverbsfd.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "rdma: "

/* FIXME: Probably not a real max */
#define MAX_PROCESS_CONTEXTS 4096

/* FIXME: Probably replace with linked list or hasmap/xarray. */
static u32 ctxn_uverbsfd_id_map[MAX_PROCESS_CONTEXTS];

/*
 * Dump-side R3 (per-uobject DAG) state.
 *
 * dump_uverbsfile() records every uverbs context it commits to the
 * image into rdma_dumped_ufiles, and rdma_dump_uobj_dag() (called
 * once after every pstree task has been dumped) consumes the list
 * to drive the per-ibdev NLDEV walks that build rdma_uobj.img.
 *
 * The list is single-threaded by construction (cr-dump.c walks the
 * pstree sequentially), grows monotonically during dump, and is
 * never freed -- the dump process exits shortly after image close.
 */
struct rdma_dumped_ufile {
	pid_t pid;
	uint32_t ctxn;
	bool has_ctxn;
	uint32_t uvfe_id;
	uint32_t criu_driver;
	uint32_t kernel_driver_id;
	uint32_t dev_index;	/* filled lazily in rdma_dump_uobj_dag */
	bool has_dev_index;
	char ibdev[64];
	/*
	 * Long-lived dup of the holder's uverbs cdev fd, captured in
	 * dump_uverbsfile() and consumed by rdma_dump_uobj_dag()'s
	 * per-MR QUERY_MR walk. Sharing the holder's struct file is
	 * load-bearing: QUERY_MR resolves @handle through the per-
	 * ucontext IDR, so the issuing fd MUST point at the same
	 * ib_ucontext as the source. -1 means "not stashed" (the
	 * dup failed, or this ufile pre-dates the stash logic), and
	 * MR walks gracefully fall back to the NLDEV-only field set.
	 *
	 * Closed in rdma_dump_uobj_dag()'s cleanup path. The dup is
	 * O_CLOEXEC so a criu fork-after-dump can't leak the FW-side
	 * ucontext reference.
	 */
	int holder_uctx_fd;
	struct list_head link;
};
static LIST_HEAD(rdma_dumped_ufiles);

static int rdma_record_dumped_ufile(pid_t pid, const char *ibdev,
				    uint32_t kernel_driver_id,
				    uint32_t criu_driver,
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
	snprintf(r->ibdev, sizeof(r->ibdev), "%.*s",
		 (int)(sizeof(r->ibdev) - 1), ibdev);
	list_add_tail(&r->link, &rdma_dumped_ufiles);
	return 0;
}

/*
 * Read the entirety of a sysfs file into the caller's buffer, NUL-terminate,
 * and trim a single trailing newline if present. Returns 0 on success, -1
 * on any error. The caller-provided buffer must have room for the data plus
 * a NUL byte.
 */
static int read_sysfs_file(const char *path, char *buf, size_t buflen)
{
	int fd, n;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, buflen - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	if (n > 0 && buf[n - 1] == '\n')
		buf[n - 1] = '\0';
	return 0;
}

/*
 * Resolve the chrdev (major,minor) backing a uverbs cdev fd to its ibdev
 * name (e.g. "rxe0", "mlx5_0") via /sys/dev/char/<maj>:<min>/ibdev. Works
 * uniformly across PCI-backed and software-defined providers because the
 * "ibdev" attribute is exposed by the kernel ib_uverbs class for every
 * uverbs cdev. Result is written to @out (NUL-terminated). Returns 0 on
 * success.
 */
static int rdma_ibdev_from_chrdev(unsigned int maj, unsigned int min,
				  char *out, size_t outsz)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/sys/dev/char/%u:%u/ibdev", maj, min);
	if (read_sysfs_file(path, out, outsz) < 0) {
		pr_perror("Can't read %s", path);
		return -1;
	}
	if (out[0] == '\0') {
		pr_err("Empty ibdev name from %s\n", path);
		return -1;
	}
	return 0;
}

/*
 * Resolve an ibdev name to its backing kernel-module driver name (e.g.
 * "mlx5_core", "rxe"). Strategy:
 *   1. PCI-backed devices expose /sys/class/infiniband/<name>/device/driver
 *      as a symlink whose basename is the driver module. This covers
 *      mlx5/mlx4/bnxt_re/qedr/irdma/etc.
 *   2. Software-defined providers (rxe, siw) have no PCI parent and no
 *      such symlink. Fall back to a name-prefix mapping for the small set
 *      of providers we explicitly support.
 *
 * Returns 0 on success with the driver name written to @out. Returns -1 if
 * neither lookup yields a driver name -- callers should treat that as
 * "unknown provider, fail dump."
 */
int rdma_driver_name_from_ibdev(const char *ibdev,
				       char *out, size_t outsz)
{
	char path[PATH_MAX];
	char target[PATH_MAX];
	const char *base;
	ssize_t n;

	snprintf(path, sizeof(path),
		 "/sys/class/infiniband/%s/device/driver", ibdev);
	n = readlink(path, target, sizeof(target) - 1);
	if (n > 0) {
		const char *src;

		target[n] = '\0';
		base = strrchr(target, '/');
		src = base ? base + 1 : target;
		/* width-bounded format so -Wformat-truncation is happy */
		snprintf(out, outsz, "%.*s", (int)(outsz - 1), src);
		return 0;
	}

	if (!strncmp(ibdev, "rxe", 3)) {
		snprintf(out, outsz, "rxe");
		return 0;
	}
	if (!strncmp(ibdev, "siw", 3)) {
		snprintf(out, outsz, "siw");
		return 0;
	}

	return -1;
}

/*
 * Map a kernel-module driver name to the matching RDMA_DRIVER_* enum value
 * the kernel UAPI uses. Returns RDMA_DRIVER_UNKNOWN for unrecognized names;
 * dump_uverbsfile() treats that as a hard error so a checkpoint is never
 * written that the restoring criu would have no provider for.
 *
 * When adding a new entry here, also extend rdma_driver_name_from_ibdev()
 * if the new provider needs the name-prefix fallback (i.e. it is software-
 * defined and has no PCI parent in sysfs).
 */
uint32_t rdma_driver_name_to_id(const char *name)
{
	static const struct {
		const char *name;
		uint32_t id;
	} map[] = {
		{ "rxe",         RDMA_DRIVER_RXE },
		{ "siw",         RDMA_DRIVER_SIW },
		{ "mlx5_core",   RDMA_DRIVER_MLX5 },
		{ "mlx4_core",   RDMA_DRIVER_MLX4 },
		{ "bnxt_re",     RDMA_DRIVER_BNXT_RE },
		{ "qedr",        RDMA_DRIVER_QEDR },
		{ "irdma",       RDMA_DRIVER_IRDMA },
		{ "i40iw",       RDMA_DRIVER_I40IW },
		{ "hns_roce",    RDMA_DRIVER_HNS },
		{ "ocrdma",      RDMA_DRIVER_OCRDMA },
		{ "vmw_pvrdma",  RDMA_DRIVER_VMW_PVRDMA },
		{ "iw_cxgb4",    RDMA_DRIVER_CXGB4 },
		{ "iw_cxgb3",    RDMA_DRIVER_CXGB3 },
		{ "ib_mthca",    RDMA_DRIVER_MTHCA },
		{ "iw_nes",      RDMA_DRIVER_NES },
		{ "usnic_verbs", RDMA_DRIVER_USNIC },
		{ "efa",         RDMA_DRIVER_EFA },
		{ "hfi1",        RDMA_DRIVER_HFI1 },
		{ "qib",         RDMA_DRIVER_QIB },
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(map); i++)
		if (!strcmp(name, map[i].name))
			return map[i].id;
	return RDMA_DRIVER_UNKNOWN;
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

static int dump_uverbsfile(int lfd, u32 id, const struct fd_parms *p)
{
	UverbsFileEntry uve = UVERBS_FILE_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;
	struct cr_img *img;
	const char *claimer = NULL;
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
	if (rdma_dispatch_dump_uverbs_context(ibdev, uve.driver_id,
					      uve.criu_driver,
					      uve.has_ctxn ? uve.ctxn : 0,
					      lfd, p->pid)) {
		pr_err("dump_uverbsfile: per-context dump hook failed for "
		       "ibdev=%s ctxn=%u; aborting dump\n",
		       ibdev, uve.has_ctxn ? uve.ctxn : 0);
		goto out;
	}

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
					     uve.criu_driver, uve.id,
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
 */
static plugin_desc_t *rdma_find_plugin_by_provided_driver(uint32_t criu_driver,
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
 * Dump-side dispatcher. Mirrors rdma_dispatch_open_uverbs_cdev but
 * for the dump-time DUMP_UVERBS_CONTEXT hook:
 *
 *   - Match by image's just-arbitrated criu_driver against each
 *     plugin's cr_rdma_provided_driver symbol (same matching policy
 *     CLAIM/OPEN use).
 *   - If the matching plugin doesn't register
 *     CR_PLUGIN_HOOK__RDMA_DUMP_UVERBS_CONTEXT, the hook is treated
 *     as optional: this is a successful no-op. rxe takes this path
 *     -- it has no firmware blob to capture beyond what the generic
 *     UverbsFileEntry already records, so it doesn't bother
 *     registering the hook.
 *   - If multiple plugins match, hard fail. Operator's plugin set
 *     is inconsistent and we do not pick arbitrarily, same posture
 *     as CLAIM and OPEN.
 *   - If no plugin matches the recorded criu_driver at all, hard
 *     fail. This shouldn't happen in practice -- CLAIM
 *     arbitration just succeeded against this very criu_driver --
 *     but defending in depth is cheap and the alternative
 *     (silently skip) would let an mis-staged plugin set produce
 *     incomplete images.
 */
int rdma_dispatch_dump_uverbs_context(const char *ibdev,
				      uint32_t kernel_driver_id,
				      uint32_t criu_driver,
				      uint32_t ctxn,
				      int lfd, pid_t pid)
{
	plugin_desc_t *winner;
	const char *first_name = NULL, *second_name = NULL;
	bool ambiguous = false;
	CR_PLUGIN_HOOK__RDMA_DUMP_UVERBS_CONTEXT_t *fn;

	winner = rdma_find_plugin_by_provided_driver(criu_driver, &ambiguous,
						     &first_name, &second_name);
	if (ambiguous) {
		pr_err("dump_uverbs_context: multiple plugins declare "
		       "cr_rdma_provided_driver=%u ('%s' and '%s'); "
		       "operator's plugin set is inconsistent.\n",
		       criu_driver, first_name, second_name);
		return -1;
	}
	if (!winner) {
		pr_err("dump_uverbs_context: no loaded RDMA plugin exports "
		       "cr_rdma_provided_driver=%u for ibdev=%s -- CLAIM "
		       "arbitration just named this driver, so the plugin "
		       "list changed mid-dump or the winning plugin is "
		       "missing its CR_PLUGIN_DECLARE_RDMA_PROVIDED_DRIVER "
		       "declaration.\n",
		       criu_driver, ibdev);
		return -1;
	}

	if (!winner->d->hooks[CR_PLUGIN_HOOK__RDMA_DUMP_UVERBS_CONTEXT]) {
		pr_debug("dump_uverbs_context: plugin '%s' (criu_driver=%u "
			 "ibdev=%s) does not register the hook; skipping.\n",
			 winner->d->name, criu_driver, ibdev);
		return 0;
	}

	fn = winner->d->hooks[CR_PLUGIN_HOOK__RDMA_DUMP_UVERBS_CONTEXT];
	pr_debug("dump_uverbs_context: dispatching to plugin '%s' "
		 "(criu_driver=%u ibdev=%s ctxn=%u pid=%d)\n",
		 winner->d->name, criu_driver, ibdev, ctxn, (int)pid);
	return fn(ibdev, kernel_driver_id, ctxn, lfd, pid);
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

/*
 * Pre-suspend RDMA dump-coverage check.
 *
 * The shape of the work:
 *
 *   1. Build a flat array of host pids in the snapshot tree from
 *      pstree (already populated by collect_pstree(), which is the
 *      caller's responsibility). This is the membership oracle for
 *      "is this context held by the snapshot tree?" -- the cross-
 *      tree exclusivity check (next commit) will use the same
 *      membership oracle to look at the *outside* set instead.
 *
 *   2. Issue a single RDMA netlink dump
 *      (rdma_nl_for_each_context()) and run our cb on every context
 *      the kernel reports.
 *
 *   3. For every context the cb sees that's held by a tree pid,
 *      resolve ibdev -> driver name -> RDMA_DRIVER_* enum and run
 *      the same exactly-one-claim arbitration the per-fd dump path
 *      runs. First failure wins: cb returns 1 with the failure
 *      details stashed in the walk context, the iterator stops
 *      iterating, and the caller surfaces a single actionable
 *      pr_err().
 *
 * Why fail closed on netlink errors: the only alternative would be
 * "skip the pre-flight, let dump_uverbsfile() discover the same
 * problem fd-by-fd", which is exactly the user-visible failure mode
 * this pre-flight exists to avoid. If RDMA netlink is unavailable
 * (kernel built without CONFIG_INFINIBAND, NETLINK_RDMA module not
 * loaded) but no pid in the tree holds an RDMA fd, we accept the
 * netlink error as best-effort -- but the typical case is "kernel
 * supports it" and the typical failure is a real kernel-side
 * problem worth surfacing.
 */
struct dump_cov_ctx {
	const pid_t *tree_pids;
	size_t n_tree_pids;
	/* On failure: filled in by the cb, read by the caller. */
	pid_t fail_pid;
	uint32_t fail_ctxn;
	char fail_ibdev[64];
	int fail_reason;	/* 0 = no plugin claims, < 0 = arb error */
};

static bool pid_in_tree(const pid_t *pids, size_t n, pid_t pid)
{
	size_t i;
	for (i = 0; i < n; i++)
		if (pids[i] == pid)
			return true;
	return false;
}

static int dump_cov_cb(const struct rdma_nl_ctx_info *info, void *arg)
{
	struct dump_cov_ctx *cov = arg;
	const char *claimer = NULL;
	char driver[64];
	uint32_t kdrv;
	int rcd;

	if (!pid_in_tree(cov->tree_pids, cov->n_tree_pids, info->pid)) {
		pr_debug("ctx pid=%d ibdev=%s ctxn=%u outside snapshot tree, "
			 "skipping (handled by cross-tree exclusivity)\n",
			 info->pid, info->ibdev, info->ctxn);
		return 0;
	}

	if (rdma_driver_name_from_ibdev(info->ibdev, driver, sizeof(driver))) {
		pr_err("pre-suspend coverage: pid %d holds context on "
		       "ibdev=%s but kernel driver cannot be resolved from "
		       "sysfs. Refusing to dump.\n",
		       info->pid, info->ibdev);
		cov->fail_pid = info->pid;
		cov->fail_ctxn = info->ctxn;
		snprintf(cov->fail_ibdev, sizeof(cov->fail_ibdev),
			 "%.*s", (int)(sizeof(cov->fail_ibdev) - 1),
			 info->ibdev);
		cov->fail_reason = -1;
		return 1;
	}

	kdrv = rdma_driver_name_to_id(driver);
	rcd = rdma_arbitrate_plugin_claim(info->ibdev, kdrv, &claimer);
	if (rcd < 0) {
		cov->fail_pid = info->pid;
		cov->fail_ctxn = info->ctxn;
		snprintf(cov->fail_ibdev, sizeof(cov->fail_ibdev),
			 "%.*s", (int)(sizeof(cov->fail_ibdev) - 1),
			 info->ibdev);
		cov->fail_reason = rcd;
		return 1;
	}
	if (rcd == 0) {
		cov->fail_pid = info->pid;
		cov->fail_ctxn = info->ctxn;
		snprintf(cov->fail_ibdev, sizeof(cov->fail_ibdev),
			 "%.*s", (int)(sizeof(cov->fail_ibdev) - 1),
			 info->ibdev);
		cov->fail_reason = 0;
		return 1;
	}

	pr_debug("pre-suspend coverage OK: pid=%d ibdev=%s ctxn=%u "
		 "claimed by plugin '%s' rcd=%d\n",
		 info->pid, info->ibdev, info->ctxn, claimer, rcd);
	return 0;
}

int rdma_check_dump_coverage(struct pstree_item *root)
{
	struct dump_cov_ctx cov = { 0 };
	struct pstree_item *item;
	pid_t *pids;
	size_t n = 0, cap = 0;
	int ret;

	if (!root)
		return 0;

	for_each_pstree_item(item)
		cap++;

	if (cap == 0)
		return 0;

	pids = xmalloc(cap * sizeof(pid_t));
	if (!pids)
		return -1;

	for_each_pstree_item(item)
		pids[n++] = item->pid->real;

	cov.tree_pids = pids;
	cov.n_tree_pids = n;

	pr_debug("pre-suspend RDMA coverage check: enumerating live "
		 "contexts for snapshot tree of %zu pid(s)\n", n);
	ret = rdma_nl_for_each_context(dump_cov_cb, &cov);
	xfree(pids);

	if (ret < 0) {
		pr_err("pre-suspend RDMA coverage check failed at netlink "
		       "layer (%d). Failing closed: an unsupported context "
		       "in the tree would otherwise surface as a mid-dump "
		       "error. If you're certain the snapshot tree holds "
		       "no RDMA contexts, this can be debugged by running "
		       "'rdma resource show context' and confirming the "
		       "subsystem is loaded.\n",
		       ret);
		return -1;
	}
	if (ret == 0)
		return 0;

	/* Iterator stopped early: cov has the failure details. */
	if (cov.fail_reason == 0) {
		pr_err("pre-suspend RDMA coverage: pid %d holds a context "
		       "on ibdev=%s ctxn=%u that no loaded RDMA plugin "
		       "claims. Refusing to dump a tree that no plugin "
		       "could restore. Load the appropriate plugin via "
		       "CRIU_LIBS_DIR or install it into /usr/lib/criu/.\n",
		       cov.fail_pid, cov.fail_ibdev, cov.fail_ctxn);
	} else {
		pr_err("pre-suspend RDMA coverage: pid %d ibdev=%s ctxn=%u "
		       "arbitration error %d (plugin probe failure or "
		       "claim conflict; check earlier log lines).\n",
		       cov.fail_pid, cov.fail_ibdev, cov.fail_ctxn,
		       cov.fail_reason);
	}
	return -1;
}

/*
 * Cross-tree RDMA exclusivity check.
 *
 * The shape of the work:
 *
 *   1. One netlink pass collects every (pid, ibdev) tuple on the
 *      host. We materialise all tuples up front rather than try to
 *      do the analysis incrementally inside the iterator callback;
 *      the analysis is "for ibdev D, is there an in-tree pid AND
 *      an out-of-tree pid?", which is a join, not a stream filter.
 *
 *   2. Group tuples by ibdev. For each ibdev where any tree pid
 *      holds a context, look at the non-tree pids on the same
 *      ibdev (if any). For each such ibdev, ask the claiming
 *      plugin's exclusivity policy via dlsym of
 *      CR_PLUGIN_RDMA_SHARING_POLICY_SYM ("cr_rdma_sharing_policy"
 *      const int) on the plugin's dlhandle.
 *
 *   3. If the plugin is EXCLUSIVE (or doesn't declare a policy --
 *      safe default), fail with an actionable error naming both
 *      the in-tree and out-of-tree pids and pointing the operator
 *      at the offending non-snapshot process they need to deal
 *      with first.
 *
 *   4. There is a small TOCTOU window between this check and the
 *      eventual restore (or even between this check and SIGSTOP):
 *      a non-tree process could open a fresh context after we
 *      look. A future "freeze the RDMA subsystem to new uverbs
 *      opens" locking API will close that window; for now we
 *      document and accept it -- the same window already exists
 *      for the per-fd dump path's sysfs probes, so the
 *      cross-tree check isn't introducing a new class of race,
 *      just inheriting an existing one.
 */

#define CROSS_TREE_TUPLE_CAP 256
struct cross_tree_tuple {
	pid_t pid;
	char ibdev[64];
};

struct cross_tree_collect_ctx {
	const pid_t *tree_pids;
	size_t n_tree_pids;
	struct cross_tree_tuple *tuples;
	size_t n_tuples;
	size_t cap;
	int oom;
};

static int cross_tree_collect_cb(const struct rdma_nl_ctx_info *info,
				 void *arg)
{
	struct cross_tree_collect_ctx *cc = arg;
	struct cross_tree_tuple *t;

	if (cc->n_tuples >= cc->cap) {
		size_t newcap = cc->cap ? cc->cap * 2 : CROSS_TREE_TUPLE_CAP;
		struct cross_tree_tuple *nt;

		nt = xrealloc(cc->tuples,
			      newcap * sizeof(struct cross_tree_tuple));
		if (!nt) {
			cc->oom = 1;
			return -ENOMEM;
		}
		cc->tuples = nt;
		cc->cap = newcap;
	}

	t = &cc->tuples[cc->n_tuples++];
	t->pid = info->pid;
	snprintf(t->ibdev, sizeof(t->ibdev), "%.*s",
		 (int)(sizeof(t->ibdev) - 1), info->ibdev);
	return 0;
}

/*
 * Look up the per-plugin RDMA sharing policy by walking the loaded
 * plugin list, matching by name (the arbitration helper already gave
 * us the claimer's name, and that's the most stable identity we have
 * across both the hook chain and the dlhandle list).
 *
 * Returns CR_RDMA_SHARING_EXCLUSIVE if:
 *   - The plugin can't be located (shouldn't happen post-arbitration)
 *   - The plugin doesn't export the symbol
 *   - The symbol's value is not a recognised enum value
 *
 * That's deliberate: every "I don't know" path should fail closed.
 */
static int rdma_plugin_sharing_policy_by_name(const char *plugin_name)
{
	plugin_desc_t *this;

	if (!plugin_name)
		return CR_RDMA_SHARING_EXCLUSIVE;

	list_for_each_entry(this, &cr_plugin_ctl.head, list) {
		const int *p;

		if (!this->d || !this->d->name)
			continue;
		if (strcmp(this->d->name, plugin_name) != 0)
			continue;
		if (!this->dlhandle)
			return CR_RDMA_SHARING_EXCLUSIVE;
		p = (const int *)dlsym(this->dlhandle,
				       CR_PLUGIN_RDMA_SHARING_POLICY_SYM);
		if (!p) {
			pr_debug("plugin '%s' does not export %s; "
				 "defaulting to EXCLUSIVE\n",
				 plugin_name,
				 CR_PLUGIN_RDMA_SHARING_POLICY_SYM);
			return CR_RDMA_SHARING_EXCLUSIVE;
		}
		if (*p != CR_RDMA_SHARING_SHAREABLE &&
		    *p != CR_RDMA_SHARING_EXCLUSIVE) {
			pr_warn("plugin '%s' %s = %d is not a recognised "
				"enum value; defaulting to EXCLUSIVE\n",
				plugin_name,
				CR_PLUGIN_RDMA_SHARING_POLICY_SYM, *p);
			return CR_RDMA_SHARING_EXCLUSIVE;
		}
		return *p;
	}
	pr_debug("plugin '%s' not found in loaded list; defaulting "
		 "to EXCLUSIVE\n", plugin_name);
	return CR_RDMA_SHARING_EXCLUSIVE;
}

static bool tuple_pid_in_tree(const struct cross_tree_collect_ctx *cc,
			      pid_t pid)
{
	size_t i;
	for (i = 0; i < cc->n_tree_pids; i++)
		if (cc->tree_pids[i] == pid)
			return true;
	return false;
}

int rdma_check_cross_tree_exclusivity(struct pstree_item *root)
{
	struct cross_tree_collect_ctx cc = { 0 };
	struct pstree_item *item;
	pid_t *pids;
	size_t n = 0, cap = 0;
	int ret;
	size_t i, j;

	if (!root)
		return 0;

	for_each_pstree_item(item)
		cap++;

	if (cap == 0)
		return 0;

	pids = xmalloc(cap * sizeof(pid_t));
	if (!pids)
		return -1;

	for_each_pstree_item(item)
		pids[n++] = item->pid->real;

	cc.tree_pids = pids;
	cc.n_tree_pids = n;

	ret = rdma_nl_for_each_context(cross_tree_collect_cb, &cc);
	if (ret < 0 || cc.oom) {
		pr_err("cross-tree RDMA exclusivity check failed at "
		       "netlink layer (%d). Failing closed.\n", ret);
		xfree(pids);
		xfree(cc.tuples);
		return -1;
	}

	pr_debug("cross-tree exclusivity: %zu (pid, ibdev) tuple(s) on host, "
		 "%zu pid(s) in snapshot tree\n", cc.n_tuples, n);

	/*
	 * O(N^2) over collected tuples. Real systems have a handful of
	 * ibdevs and at most low hundreds of contexts; not worth a
	 * proper hashmap until we see this in a profile.
	 */
	ret = 0;
	for (i = 0; i < cc.n_tuples && ret == 0; i++) {
		struct cross_tree_tuple *ti = &cc.tuples[i];
		const char *claimer = NULL;
		uint32_t kdrv;
		char driver[64];
		int policy;
		int rcd;

		if (!tuple_pid_in_tree(&cc, ti->pid))
			continue;

		for (j = 0; j < cc.n_tuples; j++) {
			struct cross_tree_tuple *tj = &cc.tuples[j];

			if (i == j)
				continue;
			if (strcmp(ti->ibdev, tj->ibdev) != 0)
				continue;
			if (tuple_pid_in_tree(&cc, tj->pid))
				continue;

			/*
			 * (ti->pid in tree) holds a context on ibdev,
			 * (tj->pid not in tree) also holds a context on
			 * the same ibdev. Ask the claiming plugin if
			 * that's a problem.
			 */
			if (rdma_driver_name_from_ibdev(ti->ibdev, driver,
							sizeof(driver))) {
				pr_err("cross-tree exclusivity: cannot "
				       "resolve driver for ibdev=%s\n",
				       ti->ibdev);
				ret = -1;
				break;
			}
			kdrv = rdma_driver_name_to_id(driver);
			rcd = rdma_arbitrate_plugin_claim(ti->ibdev, kdrv,
							  &claimer);
			if (rcd < 0 || rcd == 0) {
				/*
				 * Coverage check should have rejected this
				 * already. Treat as a hard failure -- if we
				 * got here something racy happened.
				 */
				pr_err("cross-tree exclusivity: ibdev=%s "
				       "lost its claim between coverage and "
				       "exclusivity checks (rcd=%d)\n",
				       ti->ibdev, rcd);
				ret = -1;
				break;
			}

			policy = rdma_plugin_sharing_policy_by_name(claimer);
			if (policy == CR_RDMA_SHARING_SHAREABLE) {
				pr_debug("cross-tree exclusivity: ibdev=%s "
					 "shared between in-tree pid %d and "
					 "out-of-tree pid %d, but plugin "
					 "'%s' is SHAREABLE -- OK\n",
					 ti->ibdev, ti->pid, tj->pid,
					 claimer);
				continue;
			}

			pr_err("cross-tree RDMA exclusivity: in-tree pid %d "
			       "and out-of-tree pid %d both hold contexts on "
			       "ibdev=%s, and the claiming plugin '%s' marks "
			       "this device EXCLUSIVE. Snapshotting and "
			       "restoring would destroy pid %d's context. "
			       "Either include pid %d in the snapshot, stop "
			       "it before dumping, or switch the device's "
			       "claiming plugin to a sharing-aware one.\n",
			       ti->pid, tj->pid, ti->ibdev, claimer,
			       tj->pid, tj->pid);
			ret = -1;
			break;
		}
	}

	xfree(pids);
	xfree(cc.tuples);
	return ret;
}

/*
 * R3 dump-side: walk the per-ucontext uobject DAG.
 *
 * Runs once at end-of-dump, after every pstree task has been
 * dump_one_task'd (so dump_uverbsfile() has populated the
 * rdma_dumped_ufiles list with every ufile we just committed to
 * the image). For each in-tree ucontext, asks NLDEV to enumerate
 * its PD/CQ/QP/MR/SRQ uobjects and emits one rdma_uobj_entry per
 * uobject into rdma_uobj.img.
 *
 * S1.b scope: discovery + image emission only. No restore action.
 * Coverage:
 *   * AH                  deferred to S5 (needs K2 LIST_UOBJS).
 *   * comp-channel-fd /
 *     async-event-fd      deferred to S1.c follow-up (NLDEV does
 *                         not enumerate file-typed uobjects;
 *                         discovery is via fdinfo).
 *   * Plugin blob         empty in S1.b; first non-empty blob
 *                         lands at S3 (mlx5 PD restore).
 *
 * Field provenance per resource type is documented inline in
 * images/rdma_uobj.proto. Briefly: PD/CQ have direct CTXN; QP/MR/
 * SRQ get their owning ucontext via PDN-join (the K1 cleanup
 * collapses this to a one-hop filter but isn't required for v0).
 *
 * Failure policy:
 *   * Netlink failure on any per-resource walk -> hard fail.
 *     We've already accepted the cost of pre-suspend coverage's
 *     netlink dump; failing closed here is consistent.
 *   * Image open / write failure -> hard fail.
 *   * An NLDEV uobj whose pdn doesn't map to any in-tree PD ->
 *     silently dropped (kernel resource, or a userspace resource
 *     belonging to a non-snapshot-tree ucontext sharing the
 *     ibdev; coverage check has already proven any in-tree
 *     ucontext is claimable).
 *   * An NLDEV uobj whose direct ctxn doesn't map to any in-tree
 *     ufile -> silently dropped (same reason as above).
 */

/* Per-ibdev book-keeping built up during a uobj DAG dump. */
struct uobj_ibdev {
	char ibdev[64];
	uint32_t dev_index;
	bool has_dev_index;

	/* In-tree ufiles using this ibdev. */
	struct rdma_dumped_ufile **ufiles;
	size_t n_ufiles;

	/* PD inventory: pdn -> ufile (built from PD walk, then read by
	 * the QP/MR/SRQ walks for the PDN-join). */
	struct {
		uint32_t pdn;
		struct rdma_dumped_ufile *uf;
	} *pdn_map;
	size_t n_pdn;
	size_t pdn_cap;

	struct list_head link;
};

/* Cross-walk state shared by the per-resource callbacks. */
struct uobj_walk_ctx {
	struct uobj_ibdev *ib;
	struct cr_img *img;
	int n_emitted;
	int n_dropped;
	int err;
};

static struct uobj_ibdev *uobj_ibdev_find(struct list_head *head,
					  const char *ibdev)
{
	struct uobj_ibdev *ib;

	list_for_each_entry(ib, head, link)
		if (strcmp(ib->ibdev, ibdev) == 0)
			return ib;
	return NULL;
}

static struct uobj_ibdev *uobj_ibdev_get_or_add(struct list_head *head,
						const char *ibdev)
{
	struct uobj_ibdev *ib = uobj_ibdev_find(head, ibdev);

	if (ib)
		return ib;
	ib = xzalloc(sizeof(*ib));
	if (!ib)
		return NULL;
	snprintf(ib->ibdev, sizeof(ib->ibdev), "%.*s",
		 (int)(sizeof(ib->ibdev) - 1), ibdev);
	INIT_LIST_HEAD(&ib->link);
	list_add_tail(&ib->link, head);
	return ib;
}

/* Look up an in-tree ufile on this ibdev by ctxn. */
static struct rdma_dumped_ufile *uobj_ibdev_ufile_by_ctxn(
		const struct uobj_ibdev *ib, uint32_t ctxn)
{
	for (size_t i = 0; i < ib->n_ufiles; i++) {
		struct rdma_dumped_ufile *u = ib->ufiles[i];

		if (u->has_ctxn && u->ctxn == ctxn)
			return u;
	}
	return NULL;
}

static int uobj_ibdev_pdn_add(struct uobj_ibdev *ib, uint32_t pdn,
			      struct rdma_dumped_ufile *uf)
{
	if (ib->n_pdn == ib->pdn_cap) {
		size_t newcap = ib->pdn_cap ? ib->pdn_cap * 2 : 16;
		void *p = xrealloc(ib->pdn_map,
				   newcap * sizeof(*ib->pdn_map));
		if (!p)
			return -1;
		ib->pdn_map = p;
		ib->pdn_cap = newcap;
	}
	ib->pdn_map[ib->n_pdn].pdn = pdn;
	ib->pdn_map[ib->n_pdn].uf = uf;
	ib->n_pdn++;
	return 0;
}

static struct rdma_dumped_ufile *uobj_ibdev_pdn_lookup(
		const struct uobj_ibdev *ib, uint32_t pdn)
{
	for (size_t i = 0; i < ib->n_pdn; i++)
		if (ib->pdn_map[i].pdn == pdn)
			return ib->pdn_map[i].uf;
	return NULL;
}

/*
 * Common emission step: build an RdmaUobjEntry skeleton (ufile_id,
 * hw_driver_id, type, restrack_id, ufile_handle) populated from the
 * join result, leave per-class attrs and xrefs to the caller.
 *
 * ufile_handle is the per-ufile ib_uobject->id NLDEV emits via
 * RDMA_NLDEV_ATTR_RES_HANDLE on kernels carrying upstream commit
 * 0601c496b413 (K8a). On older kernels the flag stays unset and the
 * field is omitted from the image; the restore-side install uses
 * INFO_HANDLES fallbacks (none plumbed yet, see
 * design/uobject_restore.md §7.5.1 -- once the new attr is the
 * minimum, drop the conditional and require it).
 */
static void uobj_entry_init_common(RdmaUobjEntry *e,
				   const struct rdma_dumped_ufile *uf,
				   R3UobjType type,
				   bool has_restrack_id, uint32_t restrack_id,
				   bool has_ufile_handle, uint32_t ufile_handle)
{
	rdma_uobj_entry__init(e);
	e->ufile_id = uf->uvfe_id;
	e->hw_driver_id = uf->criu_driver;
	e->type = type;
	if (has_restrack_id) {
		e->has_restrack_id = true;
		e->restrack_id = restrack_id;
	}
	if (has_ufile_handle) {
		e->has_ufile_handle = true;
		e->ufile_handle = ufile_handle;
	}
}

static int uobj_emit(struct uobj_walk_ctx *w, RdmaUobjEntry *e)
{
	if (pb_write_one(w->img, e, PB_RDMA_UOBJ) < 0) {
		pr_err("rdma_dump_uobj_dag: pb_write_one(rdma_uobj.img) "
		       "failed for ufile_id=%#x type=%u\n",
		       e->ufile_id, e->type);
		return -1;
	}
	w->n_emitted++;
	return 0;
}

/* PD callback: direct CTXN, populate the ibdev's pdn_map for later
 * QP/MR/SRQ joins. */
static int uobj_pd_cb(const struct rdma_nl_res_entry *e, void *arg)
{
	struct uobj_walk_ctx *w = arg;
	struct rdma_dumped_ufile *uf;
	RdmaUobjEntry pe;
	RdmaPdAttrs attrs;

	if (!e->has_ctxn || !e->has_restrack_id) {
		w->n_dropped++;
		return 0;
	}
	uf = uobj_ibdev_ufile_by_ctxn(w->ib, e->ctxn);
	if (!uf) {
		w->n_dropped++;
		return 0;
	}
	if (uobj_ibdev_pdn_add(w->ib, e->restrack_id, uf) < 0) {
		w->err = -1;
		return -1;
	}

	uobj_entry_init_common(&pe, uf, R3_UOBJ_TYPE__R3UT_PD,
			       e->has_restrack_id, e->restrack_id,
			       e->has_ufile_handle, e->ufile_handle);
	rdma_pd_attrs__init(&attrs);
	pe.pd = &attrs;

	/*
	 * mlx5-private FW identity. fw_pdn is the value RESTORE_PD's
	 * UHW (mlx5_ib_restore_pd_req.pdn) must ship -- rdma_send_
	 * restore_pd reads pe.fw_pdn at restore. fw_uid is recorded
	 * for image-inspection symmetry and is sourced from the
	 * same TLV; the per-ufile aggregate is captured separately
	 * by the mlx5 plugin's DUMP_UVERBS_CONTEXT hook (which does
	 * its own NLDEV PD walk). Absent on rxe and on pre-
	 * d4acb54ebd3d kernels; restore-side guards that and fails
	 * the dump as un-restorable on a re-dump-required diagnostic.
	 */
	if (e->has_fw_pdn) {
		pe.has_fw_pdn = true;
		pe.fw_pdn = e->fw_pdn;
	}
	if (e->has_fw_uid) {
		pe.has_fw_uid = true;
		pe.fw_uid = e->fw_uid;
	}
	return uobj_emit(w, &pe) < 0 ? (w->err = -1) : 0;
}

/* CQ callback: direct CTXN. */
static int uobj_cq_cb(const struct rdma_nl_res_entry *e, void *arg)
{
	struct uobj_walk_ctx *w = arg;
	struct rdma_dumped_ufile *uf;
	RdmaUobjEntry pe;
	RdmaCqAttrs attrs;

	if (!e->has_ctxn) {
		w->n_dropped++;
		return 0;
	}
	uf = uobj_ibdev_ufile_by_ctxn(w->ib, e->ctxn);
	if (!uf) {
		w->n_dropped++;
		return 0;
	}

	uobj_entry_init_common(&pe, uf, R3_UOBJ_TYPE__R3UT_CQ,
			       e->has_restrack_id, e->restrack_id,
			       e->has_ufile_handle, e->ufile_handle);
	rdma_cq_attrs__init(&attrs);
	attrs.has_cqe_count = true;
	attrs.cqe_count = e->cq.cqe;
	pe.cq = &attrs;
	return uobj_emit(w, &pe) < 0 ? (w->err = -1) : 0;
}

/*
 * Build a single PARENT_PD xref edge as a one-element repeated
 * field. Helper because QP/MR/SRQ all need exactly this shape.
 */
static void uobj_attach_parent_pd(RdmaUobjEntry *pe, RdmaUobjXref *xref,
				  RdmaUobjXref **xref_arr, uint32_t pdn)
{
	rdma_uobj_xref__init(xref);
	xref->role = R3_XREF_ROLE__R3XR_PARENT_PD;
	xref->target_type = R3_UOBJ_TYPE__R3UT_PD;
	xref->target_restrack_id = pdn;

	xref_arr[0] = xref;
	pe->n_xref = 1;
	pe->xref = xref_arr;
}

/* QP callback: PDN-join, NLDEV-derived qp identity hints. */
static int uobj_qp_cb(const struct rdma_nl_res_entry *e, void *arg)
{
	struct uobj_walk_ctx *w = arg;
	struct rdma_dumped_ufile *uf;
	RdmaUobjEntry pe;
	RdmaQpAttrs attrs;
	RdmaUobjXref xref;
	RdmaUobjXref *xref_arr[1];

	if (!e->has_pdn) {
		w->n_dropped++;
		return 0;
	}
	uf = uobj_ibdev_pdn_lookup(w->ib, e->pdn);
	if (!uf) {
		w->n_dropped++;
		return 0;
	}

	uobj_entry_init_common(&pe, uf, R3_UOBJ_TYPE__R3UT_QP,
			       e->has_restrack_id, e->restrack_id,
			       e->has_ufile_handle, e->ufile_handle);
	rdma_qp_attrs__init(&attrs);
	attrs.has_qp_type = true;
	attrs.qp_type = e->qp.qp_type;
	attrs.has_state = true;
	attrs.state = e->qp.qp_state;
	attrs.has_qp_num = true;
	attrs.qp_num = e->qp.lqpn;
	if (e->qp.has_rqpn) {
		attrs.has_dest_qp_num = true;
		attrs.dest_qp_num = e->qp.rqpn;
	}
	if (e->qp.has_sq_psn) {
		attrs.has_sq_psn = true;
		attrs.sq_psn = e->qp.sq_psn;
	}
	if (e->qp.has_rq_psn) {
		attrs.has_rq_psn = true;
		attrs.rq_psn = e->qp.rq_psn;
	}
	if (e->qp.has_port) {
		attrs.has_port_num = true;
		attrs.port_num = e->qp.port;
	}
	pe.qp = &attrs;

	uobj_attach_parent_pd(&pe, &xref, xref_arr, e->pdn);
	return uobj_emit(w, &pe) < 0 ? (w->err = -1) : 0;
}

/*
 * UAPI lag shim for UVERBS_OBJECT_MR / UVERBS_METHOD_QUERY_MR /
 * UVERBS_ATTR_QUERY_MR_*. Used by the dump-side R3 walk
 * (uobj_mr_cb below) to harvest each MR's wire identity + shape +
 * registration provenance from the kernel.
 *
 * Upstream kernel: include/uapi/rdma/ib_user_ioctl_cmds.h carries
 *   UVERBS_OBJECT_MR                       = 7
 *   UVERBS_METHOD_QUERY_MR                 = 3   (within OBJECT_MR)
 *   UVERBS_ATTR_QUERY_MR_HANDLE            = 0
 *   UVERBS_ATTR_QUERY_MR_RESP_LKEY         = 1
 *   UVERBS_ATTR_QUERY_MR_RESP_RKEY         = 2
 *   UVERBS_ATTR_QUERY_MR_RESP_LENGTH       = 3
 *   UVERBS_ATTR_QUERY_MR_RESP_IOVA         = 4
 *   UVERBS_ATTR_QUERY_MR_RESP_USER_ADDR    = 5  (kernel 35fb92467f68)
 *   UVERBS_ATTR_QUERY_MR_RESP_ACCESS_FLAGS = 6  (kernel 35fb92467f68)
 *
 * Wire-format note: the OBJECT_MR / METHOD_QUERY_MR / four legacy
 * attr ids have been stable upstream since 6c01e6b218ae ("IB/uverbs:
 * Expose UAPI to query MR"). The two USER_ADDR / ACCESS_FLAGS attrs
 * are CRIU-driven additions (35fb92467f68 "RDMA/uverbs: surface
 * user_addr + access_flags via QUERY_MR"); a pre-35fb92 kernel
 * that doesn't recognise these attr_ids will reject the ioctl
 * outright (uverbs treats unknown attr ids as schema mismatch),
 * which uobj_mr_cb surfaces as a fallback to NLDEV-only field
 * capture.
 *
 * Drop the shim once the build's minimum rdma-core ships these
 * symbols upstream.
 */
#ifndef UVERBS_OBJECT_MR
#define UVERBS_OBJECT_MR			7
#endif
#ifndef UVERBS_METHOD_QUERY_MR
#define UVERBS_METHOD_QUERY_MR			3
#endif
#ifndef UVERBS_ATTR_QUERY_MR_HANDLE
#define UVERBS_ATTR_QUERY_MR_HANDLE		0
#endif
#ifndef UVERBS_ATTR_QUERY_MR_RESP_LKEY
#define UVERBS_ATTR_QUERY_MR_RESP_LKEY		1
#endif
#ifndef UVERBS_ATTR_QUERY_MR_RESP_RKEY
#define UVERBS_ATTR_QUERY_MR_RESP_RKEY		2
#endif
#ifndef UVERBS_ATTR_QUERY_MR_RESP_LENGTH
#define UVERBS_ATTR_QUERY_MR_RESP_LENGTH	3
#endif
#ifndef UVERBS_ATTR_QUERY_MR_RESP_IOVA
#define UVERBS_ATTR_QUERY_MR_RESP_IOVA		4
#endif
#ifndef UVERBS_ATTR_QUERY_MR_RESP_USER_ADDR
#define UVERBS_ATTR_QUERY_MR_RESP_USER_ADDR	5
#endif
#ifndef UVERBS_ATTR_QUERY_MR_RESP_ACCESS_FLAGS
#define UVERBS_ATTR_QUERY_MR_RESP_ACCESS_FLAGS	6
#endif

/*
 * Six-OUT reply payload for rdma_send_query_mr. has_<field> is
 * set on a successful ioctl: all six attrs are MANDATORY-from-
 * userspace in our request, so a current kernel writes them all
 * or the ioctl rejects entirely (no partial-write outcome).
 */
struct rdma_query_mr_resp {
	uint32_t lkey;
	uint32_t rkey;
	uint64_t length;
	uint64_t iova;
	uint64_t user_addr;
	uint32_t access_flags;
	bool has_lkey;
	bool has_rkey;
	bool has_length;
	bool has_iova;
	bool has_user_addr;
	bool has_access_flags;
};

/*
 * Issue UVERBS_METHOD_QUERY_MR on @cmd_fd against the holder's
 * ucontext for MR ufile-handle @handle. Used by the dump-side R3
 * walk to harvest the MR's wire identity (lkey, rkey), shape
 * (length, iova), and registration provenance (user VA,
 * access_flags) so the destination's RESTORE_MR can replay them
 * verbatim.
 *
 * @cmd_fd MUST be a dup of the holder's uverbs cdev fd so that
 * the handle resolves in the right ucontext IDR. The per-IDR
 * access check ('this MR belongs to that ucontext') is what pins
 * down the security boundary -- see the commit message of
 * 35fb92467f68 for the rationale, including why this is strictly
 * tighter than NLDEV's CAP_NET_ADMIN gate.
 *
 * Returns 0 on success (with @resp populated); -errno on ioctl
 * failure. -EPROTONOSUPPORT or -EOPNOTSUPP from a kernel that
 * lacks the user_addr/access_flags attrs is the caller's signal
 * to fall back to NLDEV-only field capture.
 */
static int rdma_send_query_mr(int cmd_fd, uint32_t driver_id,
			      uint32_t handle,
			      struct rdma_query_mr_resp *resp)
{
	struct {
		struct ib_uverbs_ioctl_hdr	hdr;
		struct ib_uverbs_attr		attrs[7];
	} cmd = {};
	unsigned int n = 0;

	memset(resp, 0, sizeof(*resp));

	cmd.hdr.object_id = UVERBS_OBJECT_MR;
	cmd.hdr.method_id = UVERBS_METHOD_QUERY_MR;
	/*
	 * QUERY_MR is a generic core uverb (no driver-id-keyed
	 * dispatch on the kernel's UAPI side), but the ioctl
	 * dispatcher still validates @driver_id against the per-
	 * ucontext rdma_driver_id (uverbs_ioctl.c::ib_uverbs_run_
	 * method): a mismatch returns -EINVAL. Pass the destination
	 * ibdev's kernel driver id (RDMA_DRIVER_RXE / _MLX5 / ...)
	 * so the validation succeeds.
	 */
	cmd.hdr.driver_id = driver_id;

	/* HANDLE: IDR(MR_OBJECT) -- attr->data carries the per-ufile handle. */
	cmd.attrs[n].attr_id = UVERBS_ATTR_QUERY_MR_HANDLE;
	cmd.attrs[n].len = 0;
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = handle;
	n++;

	/* Four legacy mandatory OUT attrs (since kernel 6c01e6b218ae). */
	cmd.attrs[n].attr_id = UVERBS_ATTR_QUERY_MR_RESP_LKEY;
	cmd.attrs[n].len = sizeof(resp->lkey);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&resp->lkey;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_QUERY_MR_RESP_RKEY;
	cmd.attrs[n].len = sizeof(resp->rkey);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&resp->rkey;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_QUERY_MR_RESP_LENGTH;
	cmd.attrs[n].len = sizeof(resp->length);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&resp->length;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_QUERY_MR_RESP_IOVA;
	cmd.attrs[n].len = sizeof(resp->iova);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&resp->iova;
	n++;

	/*
	 * Two CRIU-additions (kernel 35fb92467f68). Sent as
	 * F_MANDATORY-from-userspace so uverbs_copy_to actually
	 * writes them on a current kernel. On a pre-35fb92 kernel
	 * the ioctl rejects with -EPROTONOSUPPORT and uobj_mr_cb
	 * falls back to NLDEV-only emission.
	 */
	cmd.attrs[n].attr_id = UVERBS_ATTR_QUERY_MR_RESP_USER_ADDR;
	cmd.attrs[n].len = sizeof(resp->user_addr);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&resp->user_addr;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_QUERY_MR_RESP_ACCESS_FLAGS;
	cmd.attrs[n].len = sizeof(resp->access_flags);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&resp->access_flags;
	n++;

	cmd.hdr.num_attrs = n;
	cmd.hdr.length = sizeof(cmd.hdr) + n * sizeof(cmd.attrs[0]);

	if (ioctl(cmd_fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;

	resp->has_lkey = true;
	resp->has_rkey = true;
	resp->has_length = true;
	resp->has_iova = true;
	resp->has_user_addr = true;
	resp->has_access_flags = true;
	return 0;
}

/*
 * MR callback: PDN-join + per-MR QUERY_MR ioctl on the holder's
 * stashed uverbsfd to harvest the full RESTORE_MR feed (lkey/rkey
 * identity, shape (length, iova), and registration provenance
 * (user_addr, access_flags)).
 *
 * QUERY_MR is the canonical source of all five fields on a current
 * kernel (35fb92467f68 + 6c01e6b218ae). NLDEV's RES_MR_GET supplies
 * the same lkey/rkey/length/iova subset gated by CAP_NET_ADMIN, but
 * not user_addr or access_flags -- those live on the new
 * core-owned struct ib_mr fields and are exposed exclusively
 * through the per-ucontext-IDR-gated uverbs ioctl path. Using
 * QUERY_MR for the entire field set (rather than NLDEV for some +
 * QUERY_MR for the rest) keeps a single source of truth and avoids
 * NLDEV-vs-uverbs skew when the MR was just rereg'd or when the
 * dump straddles a state transition.
 *
 * Ufile-handle source: NLDEV K8a (RDMA_NLDEV_ATTR_RES_HANDLE),
 * which is the same per-ufile id userspace and the kernel's QUERY_
 * MR IDR resolver agree on. Without K8a we cannot issue QUERY_MR
 * (no handle to feed it), so the entry is skipped.
 *
 * Fallback: if QUERY_MR fails (kernel pre-35fb92467f68, or the
 * stashed fd dup wasn't captured), we still emit the entry with
 * NLDEV-only fields. Restore-side rdma_send_restore_mr will then
 * fail loudly on the missing user_addr/access_flags rather than
 * silently registering the MR with sentinel values.
 */
static int uobj_mr_cb(const struct rdma_nl_res_entry *e, void *arg)
{
	struct uobj_walk_ctx *w = arg;
	struct rdma_dumped_ufile *uf;
	RdmaUobjEntry pe;
	RdmaMrAttrs attrs;
	RdmaUobjXref xref;
	RdmaUobjXref *xref_arr[1];
	struct rdma_query_mr_resp qresp = {};
	bool query_ok = false;

	if (!e->has_pdn) {
		w->n_dropped++;
		return 0;
	}
	uf = uobj_ibdev_pdn_lookup(w->ib, e->pdn);
	if (!uf) {
		w->n_dropped++;
		return 0;
	}

	uobj_entry_init_common(&pe, uf, R3_UOBJ_TYPE__R3UT_MR,
			       e->has_restrack_id, e->restrack_id,
			       e->has_ufile_handle, e->ufile_handle);
	rdma_mr_attrs__init(&attrs);

	/*
	 * Try QUERY_MR first when both the per-MR ufile_handle (K8a)
	 * and the per-ufile holder fd dup are present. On a current
	 * kernel this populates all five hw-agnostic fields plus the
	 * new user_addr / access_flags pair in a single ioctl.
	 */
	if (e->has_ufile_handle && uf->holder_uctx_fd >= 0) {
		int rc = rdma_send_query_mr(uf->holder_uctx_fd,
					    uf->kernel_driver_id,
					    e->ufile_handle, &qresp);
		if (rc) {
			pr_warn("uobj DAG: QUERY_MR(handle=%u) on "
				"ibdev=%s ufile_id=%#x failed: %d (%s) "
				"-- falling back to NLDEV-only fields, "
				"user_addr/access_flags will be absent "
				"and RESTORE_MR will refuse this entry "
				"(kernel needs 35fb92467f68 'RDMA/uverbs: "
				"surface user_addr + access_flags via "
				"QUERY_MR')\n",
				e->ufile_handle, uf->ibdev, uf->uvfe_id,
				rc, strerror(-rc));
		} else {
			query_ok = true;
		}
	} else if (!e->has_ufile_handle) {
		pr_debug("uobj DAG: MR pdn=%u on ibdev=%s has no "
			 "ufile_handle (kernel pre-K8a / RES_HANDLE not "
			 "emitted); skipping QUERY_MR, NLDEV-only "
			 "emission\n", e->pdn, uf->ibdev);
	} else {
		pr_warn("uobj DAG: MR pdn=%u on ibdev=%s ufile_id=%#x "
			"has no holder_uctx_fd dup; QUERY_MR skipped\n",
			e->pdn, uf->ibdev, uf->uvfe_id);
	}

	if (query_ok) {
		/* QUERY_MR is the canonical feed when available. */
		attrs.has_lkey = true;
		attrs.lkey = qresp.lkey;
		attrs.has_rkey = true;
		attrs.rkey = qresp.rkey;
		attrs.has_length = true;
		attrs.length = qresp.length;
		attrs.has_iova = true;
		attrs.iova = qresp.iova;
		attrs.has_virt_addr = true;
		attrs.virt_addr = qresp.user_addr;
		attrs.has_access_flags = true;
		attrs.access_flags = qresp.access_flags;
	} else {
		/*
		 * NLDEV-only fallback. lkey/rkey require CAP_NET_ADMIN
		 * upstream; CRIU runs as root, so they're populated in
		 * practice. virt_addr / access_flags stay unset --
		 * restore-side will refuse such an entry with a clear
		 * "needs QUERY_MR re-dump" message.
		 */
		attrs.has_length = true;
		attrs.length = e->mr.mrlen;
		if (e->mr.has_lkey) {
			attrs.has_lkey = true;
			attrs.lkey = e->mr.lkey;
		}
		if (e->mr.has_rkey) {
			attrs.has_rkey = true;
			attrs.rkey = e->mr.rkey;
		}
		if (e->mr.has_iova) {
			attrs.has_iova = true;
			attrs.iova = e->mr.iova;
		}
	}

	pe.mr = &attrs;

	uobj_attach_parent_pd(&pe, &xref, xref_arr, e->pdn);
	return uobj_emit(w, &pe) < 0 ? (w->err = -1) : 0;
}

/*
 * SRQ callback: PDN-join, plus an optional CQN xref for XRC SRQs
 * (the only SRQ flavour where the kernel emits RES_CQN today, per
 * fill_res_srq_entry's ib_srq_has_cq() gate). The CQN xref's
 * target_restrack_id is the CQ's restrack id, which the CQ walk
 * has already emitted for any in-tree CQ -- a restore-side reader
 * can join on it.
 */
static int uobj_srq_cb(const struct rdma_nl_res_entry *e, void *arg)
{
	struct uobj_walk_ctx *w = arg;
	struct rdma_dumped_ufile *uf;
	RdmaUobjEntry pe;
	RdmaSrqAttrs attrs;
	RdmaUobjXref xrefs[2];
	RdmaUobjXref *xref_arr[2];
	int n = 0;

	if (!e->has_pdn) {
		w->n_dropped++;
		return 0;
	}
	uf = uobj_ibdev_pdn_lookup(w->ib, e->pdn);
	if (!uf) {
		w->n_dropped++;
		return 0;
	}

	uobj_entry_init_common(&pe, uf, R3_UOBJ_TYPE__R3UT_SRQ,
			       e->has_restrack_id, e->restrack_id,
			       e->has_ufile_handle, e->ufile_handle);
	rdma_srq_attrs__init(&attrs);
	attrs.has_srq_type = true;
	attrs.srq_type = e->srq.srq_type;
	pe.srq = &attrs;

	rdma_uobj_xref__init(&xrefs[n]);
	xrefs[n].role = R3_XREF_ROLE__R3XR_PARENT_PD;
	xrefs[n].target_type = R3_UOBJ_TYPE__R3UT_PD;
	xrefs[n].target_restrack_id = e->pdn;
	xref_arr[n] = &xrefs[n];
	n++;

	if (e->srq.has_cqn) {
		rdma_uobj_xref__init(&xrefs[n]);
		/*
		 * Reuse SEND_CQ as the SRQ-CQ binding role. SRQ has
		 * exactly one CQ when it has any (XRC), so a dedicated
		 * R3XR_SRQ_CQ enumerant would carry no information
		 * SEND_CQ doesn't already carry; keeping the role set
		 * tight avoids adding values whose only purpose is
		 * shape-of-edge documentation.
		 */
		xrefs[n].role = R3_XREF_ROLE__R3XR_SEND_CQ;
		xrefs[n].target_type = R3_UOBJ_TYPE__R3UT_CQ;
		xrefs[n].target_restrack_id = e->srq.cqn;
		xref_arr[n] = &xrefs[n];
		n++;
	}

	pe.n_xref = n;
	pe.xref = xref_arr;
	return uobj_emit(w, &pe) < 0 ? (w->err = -1) : 0;
}

/*
 * dev_index resolver. We have ibdev names from dump_uverbsfile but
 * NLDEV per-resource walks need dev_index. Run a one-shot ibdev
 * enumeration and patch the dev_index into matching entries on the
 * per-ibdev list.
 */
struct devidx_resolver {
	struct list_head *ibdevs;
};

static int devidx_resolver_cb(uint32_t dev_index, const char *ibdev,
			      void *arg)
{
	struct devidx_resolver *r = arg;
	struct uobj_ibdev *ib = uobj_ibdev_find(r->ibdevs, ibdev);

	if (ib) {
		ib->dev_index = dev_index;
		ib->has_dev_index = true;
	}
	return 0;
}

int rdma_dump_uobj_dag(void)
{
	struct rdma_dumped_ufile *uf;
	struct uobj_ibdev *ib, *ib_next;
	LIST_HEAD(ibdevs);
	struct cr_img *img = NULL;
	int ret = -1;

	if (list_empty(&rdma_dumped_ufiles)) {
		pr_debug("uobj DAG: no in-tree uverbs contexts dumped, "
			 "skipping per-uobject discovery\n");
		return 0;
	}

	/*
	 * 1. Group dumped ufiles by ibdev. Each per-ibdev bucket
	 * carries the in-tree ufile list + (later) a pdn_map built
	 * from the PD walk.
	 */
	list_for_each_entry(uf, &rdma_dumped_ufiles, link) {
		void *p;
		ib = uobj_ibdev_get_or_add(&ibdevs, uf->ibdev);
		if (!ib)
			goto out;
		p = xrealloc(ib->ufiles,
			     (ib->n_ufiles + 1) * sizeof(*ib->ufiles));
		if (!p)
			goto out;
		ib->ufiles = p;
		ib->ufiles[ib->n_ufiles++] = uf;
	}

	/*
	 * 2. Resolve dev_index per ibdev (NLDEV per-resource walks
	 * need dev_index, not name).
	 */
	{
		struct devidx_resolver r = { .ibdevs = &ibdevs };
		if (rdma_nl_for_each_ibdev(devidx_resolver_cb, &r) < 0) {
			pr_err("uobj DAG: ibdev enumeration failed\n");
			goto out;
		}
	}

	/*
	 * 3. Open the image. Only do so once we know we have at
	 * least one ibdev to walk -- skipping the open-then-close
	 * dance saves an empty rdma_uobj.img landing on disk for
	 * dump trees with zero RDMA contexts (already guarded by
	 * the list_empty check, but defence in depth).
	 */
	img = open_image_at(AT_FDCWD, CR_FD_RDMA_UOBJ, O_DUMP);
	if (!img) {
		pr_err("uobj DAG: open_image(rdma-uobj, O_DUMP) failed\n");
		goto out;
	}

	/*
	 * 4. Per-ibdev: PD first (populates pdn_map), then CQ
	 * (direct ctxn), then QP/MR/SRQ (PDN-join through the just-
	 * built pdn_map). Order matters only for the PDN-join
	 * dependency; CQ could equally well run before or after PD.
	 */
	list_for_each_entry(ib, &ibdevs, link) {
		struct uobj_walk_ctx w = { .ib = ib, .img = img };
		static const struct {
			enum rdma_nl_res_type t;
			rdma_nl_res_cb_t cb;
			const char *name;
		} stages[] = {
			{ RDMA_NL_RES_PD,  uobj_pd_cb,  "pd"  },
			{ RDMA_NL_RES_CQ,  uobj_cq_cb,  "cq"  },
			{ RDMA_NL_RES_QP,  uobj_qp_cb,  "qp"  },
			{ RDMA_NL_RES_MR,  uobj_mr_cb,  "mr"  },
			{ RDMA_NL_RES_SRQ, uobj_srq_cb, "srq" },
		};

		if (!ib->has_dev_index) {
			pr_err("uobj DAG: ibdev '%s' had no dev_index "
			       "(disappeared between dump and uobj walk?); "
			       "aborting\n", ib->ibdev);
			goto out;
		}

		for (size_t i = 0; i < ARRAY_SIZE(stages); i++) {
			int r = rdma_nl_for_each_resource(ib->dev_index,
							  ib->ibdev,
							  stages[i].t,
							  stages[i].cb, &w);
			if (r < 0 || w.err) {
				pr_err("uobj DAG: %s walk failed on ibdev "
				       "'%s' (idx=%u): r=%d err=%d\n",
				       stages[i].name, ib->ibdev,
				       ib->dev_index, r, w.err);
				goto out;
			}
		}

		pr_info("uobj DAG: ibdev=%s emitted=%d dropped=%d "
			"(in-tree-ufiles=%zu pdn-map=%zu)\n",
			ib->ibdev, w.n_emitted, w.n_dropped,
			ib->n_ufiles, ib->n_pdn);
	}

	ret = 0;
out:
	if (img)
		close_image(img);
	list_for_each_entry_safe(ib, ib_next, &ibdevs, link) {
		list_del(&ib->link);
		xfree(ib->ufiles);
		xfree(ib->pdn_map);
		xfree(ib);
	}
	/*
	 * Drop the holder uverbsfd dups stashed by dump_uverbsfile. The
	 * walk above is the only consumer; from this point on the holder
	 * is being killed and the ucontext is gone anyway. Skipping
	 * close() here would just leak fds into criu's own image-write
	 * phase, which makes file-leak detectors angry on long-running
	 * dumps.
	 */
	{
		struct rdma_dumped_ufile *uf2;
		list_for_each_entry(uf2, &rdma_dumped_ufiles, link) {
			if (uf2->holder_uctx_fd >= 0) {
				close(uf2->holder_uctx_fd);
				uf2->holder_uctx_fd = -1;
			}
		}
	}
	return ret;
}

/*
 * R3 restore-side: read+verify pass on rdma-uobj.img.
 *
 * S1.c. Validates that what dump_uobj_dag wrote is internally
 * consistent: every xref edge resolves within its ufile group, and
 * (ufile_id, type, restrack_id) tuples are unique. No restore
 * action; per-uobject restore handlers land incrementally in S2+.
 */
struct uobj_collected {
	RdmaUobjEntry *e;
	struct list_head link;	/* link in uobj_ufile_group.entries */
};

struct uobj_ufile_group {
	uint32_t ufile_id;
	uint32_t hw_driver_id;	/* taken from first entry; verified equal */
	struct list_head entries;
	int n_pd, n_cq, n_qp, n_mr, n_srq, n_ah, n_cc, n_aef, n_other;
	int n_xref_total;
	int n_xref_resolved;
	int n_with_handle;	/* entries with has_ufile_handle set */
	int n_total;		/* total entries in this group */
	struct list_head link;
};

/*
 * The DAG built by rdma_collect_uobj_dag() (early in restore, before
 * file restore) and consumed by rdma_restore_uobj_dag_for_ufile()
 * (per cdev fd, called from uverbsfd_open() after the plugin hands
 * back the open fd). Lives for the rest of the restore; free is at
 * process exit so we deliberately don't have a release entry point.
 *
 * Local LIST_HEAD() inside rdma_collect_uobj_dag() would have been
 * nicer but the consumer phase is in a different translation unit's
 * call chain.
 */
static LIST_HEAD(rdma_uobj_groups);

static struct uobj_ufile_group *
rdma_uobj_group_lookup(uint32_t ufile_id)
{
	struct uobj_ufile_group *g;

	list_for_each_entry(g, &rdma_uobj_groups, link)
		if (g->ufile_id == ufile_id)
			return g;
	return NULL;
}

static struct uobj_ufile_group *uobj_ufile_group_get_or_add(
		struct list_head *head, uint32_t ufile_id, uint32_t hw_driver_id)
{
	struct uobj_ufile_group *g;

	list_for_each_entry(g, head, link)
		if (g->ufile_id == ufile_id) {
			if (g->hw_driver_id != hw_driver_id) {
				pr_err("uobj DAG: ufile_id=%#x has entries "
				       "claiming both hw_driver=%u and "
				       "hw_driver=%u; image is inconsistent\n",
				       ufile_id, g->hw_driver_id, hw_driver_id);
				return NULL;
			}
			return g;
		}
	g = xzalloc(sizeof(*g));
	if (!g)
		return NULL;
	g->ufile_id = ufile_id;
	g->hw_driver_id = hw_driver_id;
	INIT_LIST_HEAD(&g->entries);
	INIT_LIST_HEAD(&g->link);
	list_add_tail(&g->link, head);
	return g;
}

static void uobj_ufile_group_count(struct uobj_ufile_group *g,
				   R3UobjType type)
{
	switch (type) {
	case R3_UOBJ_TYPE__R3UT_PD:	g->n_pd++;	break;
	case R3_UOBJ_TYPE__R3UT_CQ:	g->n_cq++;	break;
	case R3_UOBJ_TYPE__R3UT_QP:	g->n_qp++;	break;
	case R3_UOBJ_TYPE__R3UT_MR:	g->n_mr++;	break;
	case R3_UOBJ_TYPE__R3UT_SRQ:	g->n_srq++;	break;
	case R3_UOBJ_TYPE__R3UT_AH:	g->n_ah++;	break;
	case R3_UOBJ_TYPE__R3UT_COMP_CHANNEL_FILE:
					g->n_cc++;	break;
	case R3_UOBJ_TYPE__R3UT_ASYNC_EVENT_FILE:
					g->n_aef++;	break;
	default:			g->n_other++;	break;
	}
}

/*
 * Find an entry by (type, restrack_id) within @g. Used to resolve
 * xref edges. Returns the entry pointer, or NULL if not found or
 * if the candidate has no restrack_id (matches against
 * has_restrack_id false should not resolve).
 */
static const RdmaUobjEntry *uobj_ufile_group_find(
		const struct uobj_ufile_group *g,
		R3UobjType target_type, uint32_t target_restrack_id)
{
	struct uobj_collected *c;

	list_for_each_entry(c, &g->entries, link) {
		const RdmaUobjEntry *e = c->e;

		if (!e->has_restrack_id)
			continue;
		if (e->type != target_type)
			continue;
		if (e->restrack_id != target_restrack_id)
			continue;
		return e;
	}
	return NULL;
}

/*
 * Per-group dedup check: (type, restrack_id) must be unique. So
 * must ufile_handle within the same ufile (it's the kernel's
 * ufile->uobjects xarray index -- unique by construction across
 * every uobject class). Returns -1 on duplicate. O(n^2) but
 * uobject counts per ufile are O(10s), not O(thousands), so the
 * simple sweep beats setting up a hash for the size we actually
 * see.
 */
static int uobj_ufile_group_check_unique(const struct uobj_ufile_group *g)
{
	struct uobj_collected *ci, *cj;

	list_for_each_entry(ci, &g->entries, link) {
		const RdmaUobjEntry *ei = ci->e;

		for (cj = list_entry(ci->link.next, struct uobj_collected, link);
		     &cj->link != &g->entries;
		     cj = list_entry(cj->link.next, struct uobj_collected, link)) {
			const RdmaUobjEntry *ej = cj->e;

			if (ei->has_restrack_id && ej->has_restrack_id &&
			    ei->type == ej->type &&
			    ei->restrack_id == ej->restrack_id) {
				pr_err("uobj DAG: ufile_id=%#x has duplicate "
				       "(type=%u, restrack_id=%u) entries; "
				       "image is inconsistent\n",
				       g->ufile_id, ei->type, ei->restrack_id);
				return -1;
			}
			/*
			 * ufile_handle uniqueness is cross-type within one
			 * ufile because the kernel's ufile->uobjects xarray
			 * is keyed by ib_uobject->id only (the type isn't
			 * part of the key). A duplicate here means the
			 * dump-side join logic merged two NLDEV walks
			 * incorrectly, the kernel emitted a stale id, or
			 * the image was hand-edited. Bail.
			 */
			if (ei->has_ufile_handle && ej->has_ufile_handle &&
			    ei->ufile_handle == ej->ufile_handle) {
				pr_err("uobj DAG: ufile_id=%#x has duplicate "
				       "ufile_handle=%u across types %u and %u; "
				       "image is inconsistent (ufile->uobjects "
				       "ids are unique per ufile by construction)"
				       "\n",
				       g->ufile_id, ei->ufile_handle,
				       ei->type, ej->type);
				return -1;
			}
		}
	}
	return 0;
}

static int uobj_ufile_group_check_xrefs(struct uobj_ufile_group *g)
{
	struct uobj_collected *c;

	list_for_each_entry(c, &g->entries, link) {
		const RdmaUobjEntry *e = c->e;

		for (size_t k = 0; k < e->n_xref; k++) {
			const RdmaUobjXref *xr = e->xref[k];

			g->n_xref_total++;
			if (uobj_ufile_group_find(g, xr->target_type,
						  xr->target_restrack_id)) {
				g->n_xref_resolved++;
				continue;
			}
			pr_err("uobj DAG: ufile_id=%#x entry "
			       "(type=%u, restrack_id=%s%u) has unresolvable "
			       "xref role=%u target_type=%u "
			       "target_restrack_id=%u\n",
			       g->ufile_id, e->type,
			       e->has_restrack_id ? "" : "?",
			       e->has_restrack_id ? e->restrack_id : 0,
			       xr->role, xr->target_type,
			       xr->target_restrack_id);
			return -1;
		}
	}
	return 0;
}

/*
 * UAPI lag shim for UVERBS_OBJECT_RESTORE / UVERBS_METHOD_RESTORE_PD /
 * UVERBS_ATTR_RESTORE_PD_HANDLE.
 *
 * Upstream kernel: include/uapi/rdma/ib_user_ioctl_cmds.h carries
 *   UVERBS_OBJECT_RESTORE       = 18
 *   UVERBS_METHOD_RESTORE_PD    = 0    (within OBJECT_RESTORE)
 *   UVERBS_ATTR_RESTORE_PD_HANDLE = 0  (within METHOD_RESTORE_PD)
 *
 * At wire time the kernel matches by integer, never by enumerator
 * name, so a stable numeric copy here is sufficient to talk to a
 * kernel that has the support, and a fresh-enough kernel is the
 * gate on the operation succeeding (it'll return -EOPNOTSUPP if
 * the dispatch table doesn't know the object_id, which is the
 * already-handled "kernel too old" signal).
 *
 * The mlx5_vfmig plugin uses the same self-contained-numeric pattern
 * for its own per-driver verbs (MLX5_IB_OBJECT_VFMIG_LOCAL etc).
 *
 * Drop the shim once the build's minimum rdma-core ships these
 * symbols upstream.
 */
#ifndef UVERBS_OBJECT_RESTORE
#define UVERBS_OBJECT_RESTORE			18
#endif
#ifndef UVERBS_METHOD_RESTORE_PD
#define UVERBS_METHOD_RESTORE_PD		0
#endif
#ifndef UVERBS_ATTR_RESTORE_PD_HANDLE
#define UVERBS_ATTR_RESTORE_PD_HANDLE		0
#endif

/*
 * UHW is the generic driver-private blob attribute. attr_id 4096
 * (== UVERBS_ID_DRIVER_NS = 1 << UVERBS_ID_NS_SHIFT) is the kernel's
 * namespace boundary that splits core attrs from driver attrs.
 * Defined in include/uapi/rdma/ib_user_ioctl_cmds.h alongside
 * UVERBS_ATTR_UHW_OUT for the response side; we only emit input
 * UHW so we don't need the OUT id.
 */
#ifndef UVERBS_ATTR_UHW_IN
#define UVERBS_ATTR_UHW_IN			((uint16_t)4096)
#endif

/*
 * UAPI lag shim for include/uapi/rdma/mlx5-abi.h's
 * struct mlx5_ib_restore_pd_req. Driver-private UHW payload for
 * UVERBS_METHOD_RESTORE_PD on mlx5; carries the source's FW pdn so
 * mlx5_ib_restore_pd can adopt it into a fresh kernel-side mlx5_ib_pd
 * via "Model A" (no destination FW round-trip; the source pdn is
 * already reserved in firmware after LOAD_VHCA_STATE). The
 * (independent) ufile target handle still travels in the core
 * UVERBS_ATTR_RESTORE_PD_HANDLE attribute.
 *
 * Layout details that matter for wire correctness:
 *   - sizeof > sizeof(u64) is intentional. The uverbs UHW dispatch
 *     path treats len <= sizeof(u64) as INLINE (stuffs attr->data
 *     into a kernel staging slot and rewrites udata->inbuf to a
 *     kernel pointer), which on x86_64 with masked-user-access
 *     support breaks ib_copy_from_udata's copy_from_user. Sizing
 *     above the threshold (12 + 8 = 24 with __aligned_u64 padding;
 *     here 16 with explicit __aligned_u64) takes the ptr path and
 *     ib_copy_from_udata works as expected. We pass by pointer in
 *     attr->data, matching what pd_restore_probe_mlx5_vfmig does.
 *   - reserved/reserved2 must be zero on send. Kernel-side
 *     mlx5_ib_restore_pd validates this for forward-compat
 *     (returns -EINVAL otherwise).
 *
 * Keep this in sync with struct mlx5_ib_restore_pd_req in
 * include/uapi/rdma/mlx5-abi.h. Drop once host rdma-core ships the
 * struct upstream.
 */
struct mlx5_ib_restore_pd_req_local {
	uint32_t	pdn;		/* source FW pdn to adopt */
	uint32_t	reserved;	/* must be 0 */
	uint64_t	reserved2;	/* must be 0; pads above the
					 * 8-byte inline-UHW threshold */
};

/*
 * Issue UVERBS_METHOD_RESTORE_PD on @cmd_fd, asking the kernel to
 * mint a PD uobject at the caller-chosen ufile handle
 * @target_handle.
 *
 * Per-driver UHW shape:
 *   - rxe: no UHW. rxe_restore_pd is a pure kernel-side wrapper;
 *     the only thing it cares about is the ufile target handle.
 *   - mlx5: UHW carries struct mlx5_ib_restore_pd_req with
 *     {pdn = source FW pdn, reserved = 0, reserved2 = 0}. The
 *     source pdn comes from the rdma-uobj.img PD entry's fw_pdn
 *     field, which the dump side sourced from the named
 *     "fw_pdn" driver TLV that mlx5_ib's fill_res_pd_entry
 *     emits under RDMA_NLDEV_ATTR_DRIVER (kernel
 *     d4acb54ebd3d). Earlier CRIUs shipped the entry's
 *     restrack_id here -- restrack_id is NLDEV's
 *     RDMA_NLDEV_ATTR_RES_PDN, *not* mpd->pdn; the two values
 *     coincide on freshly-booted hosts but diverge as the
 *     restrack idr wraps. Sending restrack_id where mpd->pdn
 *     was expected was the silent-correctness bug fixed in
 *     d4acb54ebd3d.
 *
 * @has_src_pdn / @src_pdn carry the source FW pdn captured at dump
 * time. They are mandatory for RDMA_DRIVER_MLX5 (the verb is
 * meaningless without an adoption target) and ignored for any
 * driver whose restore_pd doesn't read UHW.
 *
 * Returns 0 on success, -errno on ioctl failure or -EINVAL if a
 * required input is missing for the chosen driver.
 *
 * Wire-format references:
 *   tools/testing/mlx5_vfmig/uobject_restore/pd_restore/
 *     pd_restore_probe_rxe.c::do_restore_pd        (rxe shape)
 *     pd_restore_probe_mlx5_vfmig.c::do_restore_pd (mlx5 shape, UHW)
 */
static int rdma_send_restore_pd(int cmd_fd, uint32_t driver_id,
				uint32_t target_handle,
				bool has_src_pdn, uint32_t src_pdn)
{
	struct {
		struct ib_uverbs_ioctl_hdr	hdr;
		struct ib_uverbs_attr		attrs[2];
	} cmd = {};
	struct mlx5_ib_restore_pd_req_local mlx5_uhw = {};
	unsigned int n = 0;

	cmd.hdr.object_id = UVERBS_OBJECT_RESTORE;
	cmd.hdr.method_id = UVERBS_METHOD_RESTORE_PD;
	cmd.hdr.driver_id = driver_id;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_PD_HANDLE;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = target_handle;
	n++;

	if (driver_id == RDMA_DRIVER_MLX5) {
		if (!has_src_pdn) {
			pr_err("RESTORE_PD on driver_id=%u (mlx5) requires "
			       "the source FW pdn (mpd->pdn) from rdma-"
			       "uobj.img, but the PD entry has no fw_pdn. "
			       "The image was dumped against a kernel "
			       "that pre-dates d4acb54ebd3d (RDMA/mlx5: "
			       "fix CRIU PD restore by exposing FW pdn): "
			       "re-dump against a current kernel and "
			       "restore against the new image. Note that "
			       "RES_PDN (== restrack_id) is NOT the FW "
			       "pdn -- the two only coincided on freshly-"
			       "booted hosts before this fix.\n",
			       driver_id);
			return -EINVAL;
		}
		mlx5_uhw.pdn = src_pdn;
		/* reserved/reserved2 already zero from designated init */
		cmd.attrs[n].attr_id = UVERBS_ATTR_UHW_IN;
		cmd.attrs[n].len = sizeof(mlx5_uhw);
		cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
		cmd.attrs[n].data = (uintptr_t)&mlx5_uhw;
		n++;
	}

	cmd.hdr.num_attrs = n;
	cmd.hdr.length = sizeof(cmd.hdr) + n * sizeof(cmd.attrs[0]);

	if (ioctl(cmd_fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;
	return 0;
}

/*
 * UAPI lag shim for UVERBS_METHOD_RESTORE_MR + its ten attrs
 * (kernel uverbs_attrs_restore_mr in include/uapi/rdma/
 * ib_user_ioctl_cmds.h). UVERBS_OBJECT_RESTORE / UHW are already
 * shimmed above for RESTORE_PD; share those.
 *
 * Wire-format note: RESTORE_MR sits inside UVERBS_OBJECT_RESTORE
 * (== 18) because it's a generic core operation (not a per-driver
 * uobject-class verb). UVERBS_METHOD_RESTORE_MR is method 1 within
 * that object (RESTORE_PD is method 0). The attr ids are 0..9 in
 * the order declared in the kernel's uverbs_attrs_restore_mr.
 *
 * Drop the shim once the build's minimum rdma-core ships these
 * symbols upstream.
 */
#ifndef UVERBS_METHOD_RESTORE_MR
#define UVERBS_METHOD_RESTORE_MR		1
#endif
#ifndef UVERBS_ATTR_RESTORE_MR_HANDLE
#define UVERBS_ATTR_RESTORE_MR_HANDLE		0
#endif
#ifndef UVERBS_ATTR_RESTORE_MR_PD_HANDLE
#define UVERBS_ATTR_RESTORE_MR_PD_HANDLE	1
#endif
#ifndef UVERBS_ATTR_RESTORE_MR_ADDR
#define UVERBS_ATTR_RESTORE_MR_ADDR		2
#endif
#ifndef UVERBS_ATTR_RESTORE_MR_LENGTH
#define UVERBS_ATTR_RESTORE_MR_LENGTH		3
#endif
#ifndef UVERBS_ATTR_RESTORE_MR_IOVA
#define UVERBS_ATTR_RESTORE_MR_IOVA		4
#endif
#ifndef UVERBS_ATTR_RESTORE_MR_ACCESS_FLAGS
#define UVERBS_ATTR_RESTORE_MR_ACCESS_FLAGS	5
#endif
#ifndef UVERBS_ATTR_RESTORE_MR_LKEY_HINT
#define UVERBS_ATTR_RESTORE_MR_LKEY_HINT	6
#endif
#ifndef UVERBS_ATTR_RESTORE_MR_RKEY_HINT
#define UVERBS_ATTR_RESTORE_MR_RKEY_HINT	7
#endif
#ifndef UVERBS_ATTR_RESTORE_MR_RESP_LKEY
#define UVERBS_ATTR_RESTORE_MR_RESP_LKEY	8
#endif
#ifndef UVERBS_ATTR_RESTORE_MR_RESP_RKEY
#define UVERBS_ATTR_RESTORE_MR_RESP_RKEY	9
#endif

/*
 * Issue UVERBS_METHOD_RESTORE_MR on @cmd_fd, asking the kernel to
 * mint an MR uobject at the caller-chosen ufile slot
 * @target_handle, attached to the parent PD whose ufile slot is
 * @parent_pd_handle, with shape and access flags taken from the
 * source's QUERY_MR snapshot.
 *
 * @lkey_hint / @rkey_hint are the source's wire-visible identity.
 * The kernel writes the actually-installed lkey/rkey into the
 * caller-owned @resp_lkey / @resp_rkey OUT slots:
 *   - rxe (kernel f422e6ba6bdc): hints are honoured verbatim via
 *     __rxe_add_to_pool_at_index(); RESP_LKEY/_RKEY equal the
 *     hints byte-for-byte. The verb returns -EBUSY if the rxe
 *     pool slot is already occupied.
 *   - mlx5: see future S4b. The S4a CRIU build only emits the
 *     core (no UHW) attrs and so produces an MR usable on rxe;
 *     mlx5 will need a UHW similar to RESTORE_PD's
 *     mlx5_ib_restore_mr_req carrying the FW mkey index.
 *
 * @parent_pd_handle is the PD's destination-side ufile slot. With
 * Model A handle preservation that equals the source's PD ufile
 * slot, so the dump-side PD entry's ufile_handle can be looked up
 * directly through the per-ufile handle map without a translation
 * step.
 *
 * The wire shape (no UHW) intentionally mirrors mr_restore_probe_
 * rxe.c::do_restore_mr in tools/testing/mlx5_vfmig/uobject_restore.
 *
 * Returns 0 on success (with @resp_lkey / @resp_rkey populated);
 * -errno on ioctl failure.
 */
static int rdma_send_restore_mr(int cmd_fd, uint32_t driver_id,
				uint32_t target_handle,
				uint32_t parent_pd_handle,
				uint64_t addr, uint64_t length,
				uint64_t iova, uint32_t access_flags,
				uint32_t lkey_hint, uint32_t rkey_hint,
				uint32_t *resp_lkey, uint32_t *resp_rkey)
{
	struct {
		struct ib_uverbs_ioctl_hdr	hdr;
		struct ib_uverbs_attr		attrs[10];
	} cmd = {};
	unsigned int n = 0;

	cmd.hdr.object_id = UVERBS_OBJECT_RESTORE;
	cmd.hdr.method_id = UVERBS_METHOD_RESTORE_MR;
	cmd.hdr.driver_id = driver_id;

	/*
	 * Wire-format note for PTR_IN / FLAGS_IN attrs whose declared
	 * size is <= sizeof(u64): the kernel takes the inline path
	 * (uverbs_attr_ptr_is_inline()) and reads attr->ptr_attr.data
	 * AS THE VALUE -- not as a pointer to it. We follow the
	 * convention used by RESTORE_PD's HANDLE attr above:
	 *   for PTR_IN(u32): data = value (low 32 bits), len = 4
	 *   for PTR_IN(u64): data = value, len = 8
	 *   for FLAGS_IN:    data = value, len = 4 (or 8)
	 *   for IDR input:   data = handle value, len = 0
	 *   for PTR_OUT:     data = (uintptr_t)&buffer, len = sizeof
	 *                    (output ALWAYS uses a userspace pointer
	 *                     via copy_to_user)
	 * Passing `data = (uintptr_t)&local_var` for PTR_IN <= 8 was
	 * a bug that surfaces as -EINVAL from FLAGS_IN bitmask checks
	 * (the kernel sees the pointer's value as the flags) and
	 * wildly-wrong addr/length on the driver side.
	 */

	/* HANDLE: PTR_IN(u32) -- inline. */
	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_HANDLE;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = target_handle;
	n++;

	/* PD_HANDLE: IDR(OBJECT_PD) input -- attr->data carries the handle. */
	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_PD_HANDLE;
	cmd.attrs[n].len = 0;
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = parent_pd_handle;
	n++;

	/* ADDR / LENGTH / IOVA: PTR_IN(u64) -- inline. */
	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_ADDR;
	cmd.attrs[n].len = sizeof(uint64_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = addr;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_LENGTH;
	cmd.attrs[n].len = sizeof(uint64_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = length;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_IOVA;
	cmd.attrs[n].len = sizeof(uint64_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = iova;
	n++;

	/* ACCESS_FLAGS: FLAGS_IN(u32) -- inline. */
	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_ACCESS_FLAGS;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = access_flags;
	n++;

	/* LKEY_HINT / RKEY_HINT: PTR_IN(u32) -- inline. */
	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_LKEY_HINT;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = lkey_hint;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_RKEY_HINT;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = rkey_hint;
	n++;

	/* RESP_LKEY / RESP_RKEY: PTR_OUT(u32) -- pointer to user buffer. */
	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_RESP_LKEY;
	cmd.attrs[n].len = sizeof(*resp_lkey);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)resp_lkey;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_RESP_RKEY;
	cmd.attrs[n].len = sizeof(*resp_rkey);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)resp_rkey;
	n++;

	cmd.hdr.num_attrs = n;
	cmd.hdr.length = sizeof(cmd.hdr) + n * sizeof(cmd.attrs[0]);

	if (ioctl(cmd_fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;
	return 0;
}

/*
 * Per-ufile handle map entry. Built up as we restore each uobject
 * in topological order; consumed by children that need to resolve
 * a parent xref ((target_type, target_restrack_id)) to the
 * parent's destination-side ufile_handle.
 *
 * Model A (handle preservation) means the destination handle
 * always equals the source's recorded ufile_handle, so
 * "destination handle" == "source's RdmaUobjEntry.ufile_handle"
 * and the map is really just a (type, restrack_id) -> uint32_t
 * table populated from each successfully-installed parent's image
 * entry. Doing the lookup the long way (via this map) keeps the
 * design symmetric with future drivers that may not preserve
 * handles -- the lookup interface stays the same; only the way we
 * populate the map changes.
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

static int uobj_handle_map_add(struct uobj_handle_map *m,
			       R3UobjType type, uint32_t restrack_id,
			       uint32_t ufile_handle)
{
	if (m->n == m->cap) {
		size_t newcap = m->cap ? m->cap * 2 : 8;
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

static bool uobj_handle_map_lookup(const struct uobj_handle_map *m,
				   R3UobjType type, uint32_t restrack_id,
				   uint32_t *ufile_handle)
{
	for (size_t i = 0; i < m->n; i++) {
		if (m->e[i].type == type &&
		    m->e[i].restrack_id == restrack_id) {
			*ufile_handle = m->e[i].ufile_handle;
			return true;
		}
	}
	return false;
}

/*
 * Look up the @role-typed parent reference on @e and return its
 * destination-side ufile_handle via @out. Returns false if the xref
 * is missing, the target's restrack_id was missing, or the target
 * hasn't been added to the map yet (i.e. wasn't restored in an
 * earlier topo pass).
 */
static bool uobj_resolve_parent(const RdmaUobjEntry *e,
				R3XrefRole role,
				const struct uobj_handle_map *m,
				uint32_t *out)
{
	for (size_t i = 0; i < e->n_xref; i++) {
		const RdmaUobjXref *xr = e->xref[i];

		if (xr->role != role)
			continue;
		if (uobj_handle_map_lookup(m, xr->target_type,
					   xr->target_restrack_id, out))
			return true;
		return false;
	}
	return false;
}

/*
 * Phase-B pending list: per-ufile restore state stashed by
 * rdma_restore_uobj_dag_for_ufile() (Phase A, pre-VMA) and consumed
 * by rdma_restore_uobj_dag_post_vma() (Phase B, post-VMA).
 *
 * Why split: verbs that pin user pages
 * (UVERBS_METHOD_RESTORE_MR -> pin_user_pages_fast(user_addr, ...))
 * need the restored task's user VMAs to already be mapped, but
 * uverbsfd_open() runs during prepare_fds() which is BEFORE
 * open_vmas(). Phase A handles VA-independent verbs (PD today;
 * CQ/QP/SRQ/AH later, none of which pin user pages) inline,
 * stashes the rest, and Phase B runs once after open_vmas() in
 * the same restored task.
 *
 * Held state per pending ufile:
 *   cmd_fd_dup       O_CLOEXEC dup of the plugin's open cdev fd.
 *                    Phase A's @cmd_fd is a transient passed-in
 *                    parameter; Phase B needs its own long-lived
 *                    handle on the same struct file because the
 *                    kernel ucontext IDR resolves through it.
 *                    Closed by Phase B at end-of-walk.
 *   ufile_id /
 *   kernel_driver_id Pass-through inputs to RESTORE_<TYPE>.
 *   g                The DAG group from rdma_uobj_group_lookup --
 *                    avoids a re-lookup; unchanged across phases.
 *   handle_map       Built up in Phase A (one entry per PD
 *                    successfully RESTORE_PD'd), consumed in
 *                    Phase B (every R3UT_MR's PARENT_PD xref is
 *                    resolved through it). Owned by this struct,
 *                    freed at end-of-Phase-B.
 */
struct uobj_pending_post_vma {
	int cmd_fd_dup;
	uint32_t ufile_id;
	uint32_t kernel_driver_id;
	struct uobj_ufile_group *g;
	struct uobj_handle_map handle_map;
	struct list_head link;
};
static LIST_HEAD(rdma_pending_post_vma);

static int rdma_pending_post_vma_add(int cmd_fd_dup, uint32_t ufile_id,
				     uint32_t kernel_driver_id,
				     struct uobj_ufile_group *g,
				     struct uobj_handle_map *handle_map)
{
	struct uobj_pending_post_vma *p;

	p = xzalloc(sizeof(*p));
	if (!p) {
		close(cmd_fd_dup);
		xfree(handle_map->e);
		return -1;
	}
	p->cmd_fd_dup = cmd_fd_dup;
	p->ufile_id = ufile_id;
	p->kernel_driver_id = kernel_driver_id;
	p->g = g;
	/* Move the handle_map -- caller no longer owns the storage. */
	p->handle_map = *handle_map;
	memset(handle_map, 0, sizeof(*handle_map));
	INIT_LIST_HEAD(&p->link);
	list_add_tail(&p->link, &rdma_pending_post_vma);
	return 0;
}

/*
 * Per-ufile restore dispatcher (Phase A, pre-VMA). Called from
 * uverbsfd_open() right after the plugin's RDMA_OPEN_UVERBS_CDEV
 * hook returns the open cdev fd. Walks the DAG group built by
 * rdma_collect_uobj_dag() for @ufile_id and issues the VA-
 * independent RESTORE_<TYPE> verbs (PD today; CQ/QP/SRQ/AH later)
 * in topological order, building a (restrack_id -> ufile_handle)
 * handle_map as it goes. VA-dependent verbs (MR; later DEVX_UMEM)
 * are deferred to rdma_restore_uobj_dag_post_vma() because their
 * kernel handlers pin_user_pages_fast() against current->mm and
 * the restored task's VMAs aren't laid out yet at this point in
 * the per-task restore flow (see rdma.h::rdma_restore_uobj_dag_
 * post_vma).
 *
 * S2..S4a scope: PD pre-VMA + MR post-VMA (rxe). CQ / QP / SRQ /
 * AH RESTORE_<TYPE> verbs land as the kernel side gains the
 * corresponding driver callbacks; until then those entries are
 * silently skipped (the post-restore application sees the empty-
 * of-CQ/QP ucontext, which is the same situation pre-S2 had).
 *
 * Skips entries without ufile_handle (kernel pre-K8a / future
 * resource classes that aren't NLDEV-emitted) -- without a target
 * handle there's nothing to ask the kernel for.
 *
 * On success Phase A stashes (cmd_fd_dup, ufile_id, kernel_driver_
 * id, handle_map, group) onto the rdma_pending_post_vma list iff
 * the group has any VA-dependent entries (MRs); the dup'd fd is
 * O_CLOEXEC and is closed by Phase B. If the DAG has no VA-
 * dependent entries we don't bother stashing -- there's nothing
 * for Phase B to do for this ufile.
 *
 * Returns 0 on success (including the no-DAG case); -1 on the
 * first per-entry Phase-A restore failure, with the offending
 * (ufile_id, type, ufile_handle) in the pr_err.
 */
int rdma_restore_uobj_dag_for_ufile(int cmd_fd, uint32_t ufile_id,
				    uint32_t kernel_driver_id)
{
	struct uobj_ufile_group *g;
	struct uobj_collected *c;
	struct uobj_handle_map handle_map = {};
	int n_pd_restored = 0;
	int n_pd_skipped = 0;
	int n_mr_pending = 0;
	int ret = -1;

	g = rdma_uobj_group_lookup(ufile_id);
	if (!g) {
		pr_debug("uobj DAG: ufile_id=%#x has no DAG group "
			 "(no rdma-uobj.img coverage); nothing to restore\n",
			 ufile_id);
		return 0;
	}

	/*
	 * Pass 1: PDs. PD has no parent xref so order within the
	 * pass doesn't matter; doing PDs first ensures every MR's
	 * parent_pd_handle is in handle_map for Phase B.
	 */
	list_for_each_entry(c, &g->entries, link) {
		const RdmaUobjEntry *e = c->e;
		int rc;

		if (e->type != R3_UOBJ_TYPE__R3UT_PD)
			continue;
		if (!e->has_ufile_handle) {
			/*
			 * Pre-K8a image, or NLDEV walk lost the
			 * field. Without target_handle we can't
			 * ask the kernel to install at a
			 * specific slot. Count + move on; the
			 * test fixture asserts handles>0 on a
			 * fresh image so this surfaces upstream.
			 */
			n_pd_skipped++;
			continue;
		}
		/*
		 * Source the FW pdn from the per-PD fw_pdn field
		 * (rdma_uobj.proto), which the dump side sourced
		 * from the kernel's named "fw_pdn" driver TLV.
		 * restrack_id is NOT the FW pdn -- it's
		 * RDMA_NLDEV_ATTR_RES_PDN's per-ibdev restrack
		 * counter -- and historically was passed here by
		 * accident (silently correct on freshly-booted
		 * hosts only). Falling back to restrack_id on
		 * an old image keeps backward-compat for rxe
		 * (which ignores UHW anyway), at the cost of
		 * mlx5 images dumped against a pre-fix kernel
		 * being rejected loudly by rdma_send_restore_pd.
		 */
		rc = rdma_send_restore_pd(cmd_fd, kernel_driver_id,
					  e->ufile_handle,
					  e->has_fw_pdn,
					  e->fw_pdn);
		if (rc) {
			pr_err("uobj DAG: ufile_id=%#x RESTORE_PD"
			       "(target_handle=%u, driver_id=%u, "
			       "fw_pdn=%s%u, fw_uid=%s%u) failed: "
			       "%d (%s)%s\n",
			       ufile_id, e->ufile_handle,
			       kernel_driver_id,
			       e->has_fw_pdn ? "" : "?",
			       e->has_fw_pdn ? e->fw_pdn : 0,
			       e->has_fw_uid ? "" : "?",
			       e->has_fw_uid ? e->fw_uid : 0,
			       rc, strerror(-rc),
			       rc == -EOPNOTSUPP
			       ? " -- kernel has no "
			         "ib_device_ops.restore_pd for this "
			         "driver (rxe needs the e06868342fce "
			         "patch; mlx5 needs 4baa782ba0af)"
			       : rc == -EPERM
			       ? " -- ucontext not in restore mode "
			         "(plugin's RDMA_OPEN_UVERBS_CDEV "
			         "must use a per-driver restore-mode "
			         "GET_CONTEXT: rxe needs "
			         "RXE_ALLOC_UCTX_RESTORE_MODE, mlx5 "
			         "needs MLX5_IB_ALLOC_UCTX_VFMIG_RESTORE)"
			       : rc == -EBUSY
			       ? " -- target_handle collision "
			         "(another uobject already at this "
			         "ufile slot; image is internally "
			         "inconsistent or the kernel ufile "
			         "is not pristine)"
			       : rc == -ENOENT &&
				 kernel_driver_id == RDMA_DRIVER_MLX5
			       ? " -- mlx5_ib_restore_pd FW probe "
			         "rejected (pdn, devx_uid). v0 "
			         "policy: dest ucontext is opened "
			         "WITHOUT DEVX so devx_uid=0 is the "
			         "expected probe lane; if -ENOENT "
			         "still fires, the image's fw_pdn "
			         "is stale (re-dump needed: kernel "
			         "ABI for fw_pdn is the named "
			         "driver TLV in RDMA_NLDEV_ATTR_"
			         "DRIVER, kernel d4acb54ebd3d). "
			         "DEVX-uid adoption is vestigial: "
			         "LOAD_VHCA_STATE does not preserve "
			         "the FW uctx registration table, "
			         "so non-zero uids are unrecoverable "
			         "(kernel 73c76f299c01, design "
			         "uobject_restore.md S3b). See dmesg "
			         "mlx5_ib_warn 'restore_pd: FW probe "
			         "rejected'."
			       : rc == -EINVAL &&
				 kernel_driver_id == RDMA_DRIVER_MLX5
			       ? " -- mlx5_ib_restore_pd rejected the "
			         "UHW (pdn=0 is reserved, reserved/"
			         "reserved2 must be 0, or udata size "
			         "mismatch -- check struct "
			         "mlx5_ib_restore_pd_req packing)"
			       : "");
			goto out;
		}
		n_pd_restored++;

		/*
		 * Add to handle_map so MRs (and future CQ/QP/SRQ/AH)
		 * in Pass 2+ can resolve PARENT_PD xrefs without
		 * doing a list-walk on every dispatch.
		 */
		if (e->has_restrack_id) {
			if (uobj_handle_map_add(&handle_map,
						R3_UOBJ_TYPE__R3UT_PD,
						e->restrack_id,
						e->ufile_handle) < 0) {
				pr_err("uobj DAG: ufile_id=%#x: handle_map "
				       "OOM after RESTORE_PD(handle=%u)\n",
				       ufile_id, e->ufile_handle);
				goto out;
			}
		} else {
			pr_warn("uobj DAG: ufile_id=%#x: PD entry handle=%u "
				"has no restrack_id; child MR/CQ/QP xrefs "
				"to this PD won't resolve\n",
				ufile_id, e->ufile_handle);
		}
	}

	/*
	 * Pass 2 (deferred): count VA-dependent entries (MRs) so we
	 * know whether to stash this ufile for Phase B. We don't
	 * issue RESTORE_MR here -- the kernel handler pins user
	 * pages and the restored task's VMAs aren't mapped yet.
	 */
	list_for_each_entry(c, &g->entries, link) {
		const RdmaUobjEntry *e = c->e;

		if (e->type == R3_UOBJ_TYPE__R3UT_MR && e->has_ufile_handle)
			n_mr_pending++;
	}

	if (n_mr_pending > 0) {
		int dup;

		/*
		 * Dup high. CRIU's per-task file restorer reinstalls
		 * source-side fds at their original numbers via
		 * move_fd_from -> fcntl(F_DUPFD, want_fd) (see util.c::
		 * reopen_fd_as_safe). Without allow_reuse_fd that's a
		 * hard "lowest >= want_fd that's free" allocator: if
		 * any of [0..want_fd) is occupied by a CRIU-internal
		 * fd, F_DUPFD returns a *higher* number than want_fd
		 * and CRIU errors with "fd N already in use". Our dup
		 * lands here too; if we let it grab fd 3 (or whatever
		 * the source's user-visible cdev fd was), the move-in
		 * for cmd_fd to fle->fe->fd fails. Starting the dup at
		 * a deliberately-high min keeps it out of the user-fd
		 * range that the per-task restorer needs to assign,
		 * while still being below CRIU's own service-fd range
		 * (service_fd_base ~= rlimit-256). 1<<14 is well above
		 * any plausible user-fd allocation in the restored
		 * task and well below service_fd_base on any current
		 * RLIMIT_NOFILE tuning.
		 */
		dup = fcntl(cmd_fd, F_DUPFD_CLOEXEC, 1 << 14);
		if (dup < 0) {
			pr_err("uobj DAG: ufile_id=%#x: F_DUPFD_CLOEXEC of "
			       "cdev fd for Phase B failed: %s\n",
			       ufile_id, strerror(errno));
			goto out;
		}
		if (rdma_pending_post_vma_add(dup, ufile_id,
					      kernel_driver_id, g,
					      &handle_map) < 0) {
			pr_err("uobj DAG: ufile_id=%#x: stashing Phase B "
			       "state failed (OOM); MR restore won't "
			       "run\n", ufile_id);
			goto out;
		}
		/*
		 * handle_map ownership was moved into the pending
		 * entry; the local copy is now zero-initialised so
		 * the cleanup path below is safe.
		 */
	}

	ret = 0;
out:
	if (n_pd_restored || n_pd_skipped || n_mr_pending)
		pr_info("uobj DAG: ufile_id=%#x Phase A: restored %d PD(s) "
			"[skipped %d]; %d MR(s) deferred to post-VMA "
			"Phase B\n",
			ufile_id, n_pd_restored, n_pd_skipped,
			n_mr_pending);
	xfree(handle_map.e);
	return ret;
}

int rdma_restore_uobj_dag_post_vma(void)
{
	struct uobj_pending_post_vma *p, *p_next;
	int ret = 0;

	if (list_empty(&rdma_pending_post_vma))
		return 0;

	list_for_each_entry_safe(p, p_next, &rdma_pending_post_vma, link) {
		struct uobj_collected *c;
		int n_mr_restored = 0;
		int n_mr_skipped = 0;
		int per_ret = 0;

		list_for_each_entry(c, &p->g->entries, link) {
			const RdmaUobjEntry *e = c->e;
			uint32_t parent_pd_handle = 0;
			uint32_t resp_lkey = 0, resp_rkey = 0;
			const RdmaMrAttrs *attrs;
			int rc;

			if (e->type != R3_UOBJ_TYPE__R3UT_MR)
				continue;
			if (!e->has_ufile_handle) {
				n_mr_skipped++;
				continue;
			}
			attrs = e->mr;
			if (!attrs ||
			    !attrs->has_lkey || !attrs->has_rkey ||
			    !attrs->has_length || !attrs->has_iova ||
			    !attrs->has_virt_addr ||
			    !attrs->has_access_flags) {
				pr_err("uobj DAG: ufile_id=%#x MR"
				       "(handle=%u, restrack_id=%s%u) "
				       "is missing one or more RESTORE_"
				       "MR feed fields (have lkey=%d "
				       "rkey=%d length=%d iova=%d "
				       "virt_addr=%d access_flags=%d). "
				       "RESTORE_MR needs the full set; "
				       "this image was dumped against a "
				       "kernel without QUERY_MR's user_"
				       "addr/access_flags attrs (kernel "
				       "35fb92467f68 'RDMA/uverbs: "
				       "surface user_addr + access_"
				       "flags via QUERY_MR'). Re-dump "
				       "against a current kernel.\n",
				       p->ufile_id, e->ufile_handle,
				       e->has_restrack_id ? "" : "?",
				       e->has_restrack_id ?
				       e->restrack_id : 0,
				       attrs ? attrs->has_lkey : 0,
				       attrs ? attrs->has_rkey : 0,
				       attrs ? attrs->has_length : 0,
				       attrs ? attrs->has_iova : 0,
				       attrs ? attrs->has_virt_addr : 0,
				       attrs ?
				       attrs->has_access_flags : 0);
				per_ret = -1;
				break;
			}
			if (!uobj_resolve_parent(
					e, R3_XREF_ROLE__R3XR_PARENT_PD,
					&p->handle_map,
					&parent_pd_handle)) {
				pr_err("uobj DAG: ufile_id=%#x MR"
				       "(handle=%u, restrack_id=%s%u) "
				       "has no resolvable PARENT_PD "
				       "xref (target PD missing from "
				       "handle_map -- either Phase A "
				       "didn't restore that PD, or the "
				       "dump-side xref was lost). "
				       "RESTORE_MR cannot proceed "
				       "without a parent PD.\n",
				       p->ufile_id, e->ufile_handle,
				       e->has_restrack_id ? "" : "?",
				       e->has_restrack_id ?
				       e->restrack_id : 0);
				per_ret = -1;
				break;
			}

			rc = rdma_send_restore_mr(p->cmd_fd_dup,
						  p->kernel_driver_id,
						  e->ufile_handle,
						  parent_pd_handle,
						  attrs->virt_addr,
						  attrs->length,
						  attrs->iova,
						  attrs->access_flags,
						  attrs->lkey,
						  attrs->rkey,
						  &resp_lkey,
						  &resp_rkey);
			if (rc) {
				pr_err("uobj DAG: ufile_id=%#x "
				       "RESTORE_MR"
				       "(target_handle=%u, "
				       "parent_pd_handle=%u, "
				       "addr=%#" PRIx64 ", "
				       "length=%" PRIu64 ", "
				       "iova=%#" PRIx64 ", "
				       "access=%#x, lkey_hint=%#x, "
				       "rkey_hint=%#x, driver_id=%u) "
				       "failed: %d (%s)%s\n",
				       p->ufile_id, e->ufile_handle,
				       parent_pd_handle,
				       attrs->virt_addr, attrs->length,
				       attrs->iova,
				       attrs->access_flags,
				       attrs->lkey, attrs->rkey,
				       p->kernel_driver_id,
				       rc, strerror(-rc),
				       rc == -EOPNOTSUPP
				       ? " -- kernel has no ib_device_"
				         "ops.restore_mr for this "
				         "driver (rxe needs "
				         "25f21678609e; mlx5 needs "
				         "follow-on S4b)"
				       : rc == -EFAULT
				       ? " -- pin_user_pages_fast "
				         "rejected the user_addr; "
				         "either Phase B fired before "
				         "open_vmas, or the dump's "
				         "user_addr no longer maps "
				         "the same kind of memory in "
				         "the restored task (e.g. "
				         "anonymous vs file-backed)"
				       : rc == -EPERM
				       ? " -- ucontext not in restore "
				         "mode (see RESTORE_PD "
				         "diagnostic)"
				       : rc == -EBUSY
				       ? " -- target_handle collision "
				         "OR rxe lkey/rkey-hint pool "
				         "slot is occupied (rxe MR "
				         "pool keys by lkey >> 8; "
				         "another MR with same prefix "
				         "is live)"
				       : "");
				per_ret = -1;
				break;
			}

			/*
			 * Identity assertion. With f422e6ba6bdc rxe
			 * honours lkey_hint/rkey_hint exactly; mlx5
			 * via the FW mkey_index UHW (S4b). RESP_LKEY/
			 * RKEY *should* equal the hints byte-for-byte.
			 */
			if (resp_lkey != attrs->lkey ||
			    resp_rkey != attrs->rkey) {
				pr_err("uobj DAG: ufile_id=%#x "
				       "RESTORE_MR(target_handle=%u): "
				       "kernel installed lkey/rkey "
				       "(%#x/%#x) differs from hints "
				       "(%#x/%#x). Identity hint not "
				       "honoured -- wire-visible rkey "
				       "is now stale on remote peers "
				       "and the in-process libibverbs "
				       "lkey/rkey caches will be "
				       "wrong. Driver-side regression "
				       "in restore_mr (rxe: "
				       "f422e6ba6bdc; mlx5: pending "
				       "S4b).\n",
				       p->ufile_id, e->ufile_handle,
				       resp_lkey, resp_rkey,
				       attrs->lkey, attrs->rkey);
				per_ret = -1;
				break;
			}
			n_mr_restored++;
		}

		pr_info("uobj DAG: ufile_id=%#x Phase B: restored %d "
			"MR(s) [skipped %d]\n",
			p->ufile_id, n_mr_restored, n_mr_skipped);

		close(p->cmd_fd_dup);
		list_del(&p->link);
		xfree(p->handle_map.e);
		xfree(p);

		if (per_ret < 0)
			ret = -1;
	}
	return ret;
}

int rdma_collect_uobj_dag(void)
{
	struct cr_img *img;
	struct uobj_ufile_group *g, *gnext;
	struct uobj_collected *c, *cnext;
	int ret = -1;
	int n_entries = 0;

	img = open_image(CR_FD_RDMA_UOBJ, O_RSTR);
	if (!img)
		return -1;
	if (empty_image(img)) {
		pr_debug("uobj DAG: no rdma-uobj.img in dump (no in-tree "
			 "RDMA at dump time); nothing to verify\n");
		close_image(img);
		return 0;
	}

	while (1) {
		RdmaUobjEntry *e = NULL;
		int r;

		r = pb_read_one_eof(img, &e, PB_RDMA_UOBJ);
		if (r < 0)
			goto out;
		if (r == 0)
			break;

		g = uobj_ufile_group_get_or_add(&rdma_uobj_groups,
						e->ufile_id,
						e->hw_driver_id);
		if (!g) {
			rdma_uobj_entry__free_unpacked(e, NULL);
			goto out;
		}

		c = xzalloc(sizeof(*c));
		if (!c) {
			rdma_uobj_entry__free_unpacked(e, NULL);
			goto out;
		}
		c->e = e;
		INIT_LIST_HEAD(&c->link);
		list_add_tail(&c->link, &g->entries);
		uobj_ufile_group_count(g, e->type);
		g->n_total++;
		if (e->has_ufile_handle)
			g->n_with_handle++;
		n_entries++;
	}

	/*
	 * Per-ufile validation. Run uniqueness + xref resolution per
	 * group; bail on the first inconsistency so the operator gets
	 * a single actionable error rather than a cascade.
	 */
	list_for_each_entry(g, &rdma_uobj_groups, link) {
		if (uobj_ufile_group_check_unique(g) < 0)
			goto out;
		if (uobj_ufile_group_check_xrefs(g) < 0)
			goto out;
		pr_info("uobj DAG: ufile_id=%#x hw_drv=%u "
			"pds=%d cqs=%d qps=%d mrs=%d srqs=%d ahs=%d "
			"ccs=%d aefs=%d xrefs=%d/%d handles=%d/%d\n",
			g->ufile_id, g->hw_driver_id,
			g->n_pd, g->n_cq, g->n_qp, g->n_mr, g->n_srq,
			g->n_ah, g->n_cc, g->n_aef,
			g->n_xref_resolved, g->n_xref_total,
			g->n_with_handle, g->n_total);
	}

	pr_info("uobj DAG: read+verify ok: %d entries across "
		"%d ufile_id group(s)\n",
		n_entries,
		({ int n = 0;
		   list_for_each_entry(g, &rdma_uobj_groups, link) n++;
		   n; }));

	close_image(img);
	return 0;
out:
	close_image(img);
	list_for_each_entry_safe(g, gnext, &rdma_uobj_groups, link) {
		list_for_each_entry_safe(c, cnext, &g->entries, link) {
			list_del(&c->link);
			rdma_uobj_entry__free_unpacked(c->e, NULL);
			xfree(c);
		}
		list_del(&g->link);
		xfree(g);
	}
	return ret;
}
