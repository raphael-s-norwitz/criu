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
#include "rdma.h"
#include "fdinfo.h"
#include "xmalloc.h"

#include "images/fdinfo.pb-c.h"
#include "images/rdma_criu.pb-c.h"
#include "images/uverbsfd.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "rdma: "

/* FIXME: Probably not a real max */
#define MAX_PROCESS_CONTEXTS 4096

/* FIXME: Probably replace with linked list or hasmap/xarray. */
static u32 ctxn_uverbsfd_id_map[MAX_PROCESS_CONTEXTS];

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
static int rdma_driver_name_from_ibdev(const char *ibdev,
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
static uint32_t rdma_driver_name_to_id(const char *name)
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
static int rdma_arbitrate_plugin_claim(const char *ibdev,
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

	fe.type = FD_TYPES__UVERBSFD;
	fe.id = uve.id;
	fe.uvfd = &uve;

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

static int
ib_uverbs_get_context_ioctl(int cmd_fd, uint32_t driver_id)
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
 * In all three cases the restore must abort here, before we hand a
 * cmd_fd to ib_uverbs_get_context_ioctl() that the kernel will
 * happily accept but that no per-resource restore code will
 * subsequently know how to populate.
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

static int uverbsfd_open(struct file_desc *d, int *new_fd)
{
	struct uverbsfd_file_info *ui;
	uint32_t driver_id;
	int fd, ret;

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

	fd = open_reg_by_id(ui->uvfe->id);
	if (fd < 0)
		return -1;

	ret = ib_uverbs_get_context_ioctl(fd, driver_id);
	if (ret)
		goto out_get_context;

	ctxn_uverbsfd_id_map[ui->uvfe->ctxn] = ui->uvfe->id;

	*new_fd = fd;
	return 0;

out_get_context:
	close(fd);
	return -1;
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
