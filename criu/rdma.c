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
	 */
	fd = rdma_dispatch_open_uverbs_cdev(ui->uvfe);
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
