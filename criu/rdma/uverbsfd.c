#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <rdma/rdma_user_ioctl_cmds.h>
#include <rdma/ib_user_ioctl_cmds.h>
#include <rdma/ib_user_ioctl_verbs.h>

#include "common/compiler.h"
#include "imgset.h"
#include "image.h"
#include "files.h"
#include "files-reg.h"
#include "int.h"
#include "log.h"
#include "protobuf.h"
#include "rdma.h"
#include "rdma/internal.h"
#include "fdinfo.h"
#include "xmalloc.h"

#include "images/fdinfo.pb-c.h"
#include "images/uverbsfd.pb-c.h"
#include "images/rdma_criu.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "rdma: "

/* FIXME: Probably not a real max */
#define MAX_PROCESS_CONTEXTS 4096

/* FIXME: Probably replace with linked list or hasmap/xarray. */
static u32 ctxn_uverbsfd_id_map[MAX_PROCESS_CONTEXTS];

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
 * Dump-time comp_channel pre-check. v0 RDMA-class plugins do not
 * support comp_channel (completion channel) save/restore: the kernel
 * UVERBS_METHOD_RESTORE_CQ declares COMP_CHANNEL UA_OPTIONAL but
 * hard-rejects with -EOPNOTSUPP if a caller actually supplies one
 * (drivers/infiniband/core/uverbs_std_types_restore.c), and
 * RESTORE_COMP_CHANNEL itself is future kernel work. A source CQ bound
 * to a comp_channel would otherwise dump cleanly and only surface as a
 * failure mid-restore, after the image has been moved off-host. Bail at
 * dump time so the operator sees a crisp diagnostic next to the dumpee.
 *
 * Fires UVERBS_METHOD_INFO_HANDLES on UVERBS_OBJECT_DEVICE asking for
 * UVERBS_OBJECT_COMP_CHANNEL handles. Best-effort: any ioctl failure
 * (older kernel, missing INFO_HANDLES support, transient EBUSY, ...)
 * downgrades to a warn-and-continue rather than a hard fail -- the
 * kernel RESTORE_CQ gate is the real backstop. The INFO_HANDLES handler
 * needs a non-empty HANDLES_LIST out buffer, so we pass a tiny one even
 * though only TOTAL_HANDLES is inspected.
 *
 * @lfd is the parasite-drained cdev fd (shares the dumpee's ucontext
 * IDR); @driver_id is validated by the ioctl dispatcher against the
 * per-ucontext rdma_driver_id, so it must be the kernel driver id from
 * CLAIM arbitration. Returns 0 if clear (or on a best-effort skip), -1
 * if the context has live comp_channel uobjects.
 */
#define RDMA_CC_PRECHECK_HANDLES_BUF 16
static int dump_uverbsfile_cc_precheck(int lfd, uint32_t driver_id, const char *ibdev, uint32_t ctxn)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[3];
	} cmd = {};
	uint32_t total = 0;
	uint32_t handles[RDMA_CC_PRECHECK_HANDLES_BUF];

	cmd.hdr.object_id = UVERBS_OBJECT_DEVICE;
	cmd.hdr.method_id = UVERBS_METHOD_INFO_HANDLES;
	cmd.hdr.driver_id = driver_id;

	/*
	 * INFO_OBJECT_ID is a UVERBS_ATTR_CONST_IN (sizeof(u64) min/max);
	 * the parser takes the inline-attr path (len <= 8) and reads the
	 * value -- UVERBS_OBJECT_COMP_CHANNEL from enum
	 * uverbs_default_objects -- verbatim from attr.data.
	 */
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
		pr_warn("dump_uverbsfile: INFO_HANDLES(COMP_CHANNEL) on ibdev=%s ctxn=%u failed: %m. Skipping "
			"comp_channel pre-check; a CC-bound CQ (if any) would surface as -EOPNOTSUPP at restore.\n",
			ibdev, ctxn);
		return 0;
	}

	if (total > 0) {
		pr_err("dump_uverbsfile: ibdev=%s ctxn=%u has %u live UVERBS_OBJECT_COMP_CHANNEL uobject(s); v0 "
		       "RDMA-class plugins do not support comp_channel save/restore. The dump would record per-CQ "
		       "state without the CC binding, and UVERBS_METHOD_RESTORE_CQ on the destination rejects any "
		       "CC-attached CQ with -EOPNOTSUPP. Aborting now to surface the limitation explicitly.\n",
		       ibdev, ctxn, total);
		return -1;
	}

	pr_debug("dump_uverbsfile: comp_channel pre-check ok for ibdev=%s ctxn=%u (no live comp_channel uobjects)\n",
		 ibdev, ctxn);
	return 0;
}

static int dump_uverbsfile(int lfd, u32 id, const struct fd_parms *p)
{
	UverbsFileEntry uve = UVERBS_FILE_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;
	struct cr_img *img;
	const char *claimer = NULL;
	char ibdev[64];
	char driver[64];
	int uctx_fd = -1;
	int rcd;
	int ret = -1;

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
		       "Add a mapping to rdma_driver_name_to_id() in criu/rdma/driver.c.\n",
		       driver, ibdev,
		       major(p->stat.st_rdev), minor(p->stat.st_rdev));
		goto out;
	}

	/*
	 * Stamp which CRIU plugin owns this context. The pre-suspend
	 * coverage check already ran the same arbitration whole-tree and
	 * passed, so this is expected to succeed; re-running it here binds
	 * the winning plugin's RdmaCriuDriver into the per-context image so
	 * restore can dispatch the cdev open by criu_driver without
	 * re-deriving it. Fail loudly on the (racy) miss rather than write
	 * an image no plugin could restore.
	 */
	rcd = rdma_arbitrate_plugin_claim(ibdev, uve.driver_id, &claimer);
	if (rcd < 0) {
		pr_err("Plugin arbitration failed for ibdev=%s driver=%s: %d\n", ibdev, driver, rcd);
		goto out;
	}
	if (rcd == RDMA_CRIU_DRIVER__RCD_UNKNOWN) {
		pr_err("No RDMA CRIU plugin claims ibdev=%s driver=%s (RDMA_DRIVER id=%u). Refusing to checkpoint a "
		       "context that no plugin can restore.\n",
		       ibdev, driver, uve.driver_id);
		goto out;
	}
	uve.criu_driver = rcd;
	uve.has_criu_driver = true;

	pr_info("Dumping uverbs char device %d with id %#x ibdev=%s driver=%s id=%u claimed by plugin '%s'", lfd, id,
		ibdev, driver, uve.driver_id, claimer);
	if (uve.has_ctxn)
		pr_info(" ctxn %u", uve.ctxn);
	pr_info("\n");

	/*
	 * v0 does not model comp_channel save/restore. Reject up front (on
	 * the drained cdev fd, which shares the ucontext IDR) rather than
	 * dumping a CQ whose CC binding the destination RESTORE_CQ would
	 * reject with -EOPNOTSUPP mid-restore.
	 */
	if (dump_uverbsfile_cc_precheck(lfd, uve.driver_id, ibdev, uve.ctxn)) {
		ret = -1;
		goto out;
	}

	/*
	 * Let the claiming plugin capture any per-ucontext driver-private
	 * state it needs to restore this context on the destination (mlx5:
	 * the UAR / bfreg snapshot its restore-mode GET_CONTEXT replays).
	 * Optional -- a no-op for plugins that register no such hook. lfd
	 * is the parasite-drained cdev fd, sharing the dumpee's ucontext
	 * IDR, so the plugin can QUERY_UCONTEXT against it.
	 */
	if (rdma_dispatch_dump_uverbs_context(rcd, ibdev, uve.driver_id, uve.ctxn, lfd, p->pid) < 0) {
		pr_err("Per-ucontext dump capture failed for ibdev=%s ctxn=%u\n", ibdev, uve.ctxn);
		ret = -1;
		goto out;
	}

	fe.type = FD_TYPES__UVERBSFD;
	fe.id = uve.id;
	fe.uvfd = &uve;

	img = img_from_set(glob_imgset, CR_FD_FILES);
	ret = pb_write_one(img, &fe, PB_FILE);
	if (ret)
		goto out;

	/*
	 * Record this context for the end-of-dump uobject DAG walk
	 * (rdma_dump_uobj_dag): it joins NLDEV-enumerated uobjects back to
	 * their owning ufile by ctxn, so it needs the (ctxn, uvfe_id,
	 * criu_driver, ibdev) tuple we just committed to the image.
	 *
	 * Also stash an O_CLOEXEC dup of lfd. lfd is the parasite-drained
	 * (SCM_RIGHTS) fd -- the dumpee's real struct file, sharing its
	 * ucontext IDR -- so the MR walk can QUERY_MR against it for the
	 * user_addr / iova / access_flags NLDEV never exposes. The dup
	 * outlives this callback (lfd is closed right after) and the walk
	 * owns it. A dup failure yields -1: the walk then fails closed for
	 * any MR on this context rather than emitting an unrestorable MR.
	 */
	uctx_fd = fcntl(lfd, F_DUPFD_CLOEXEC, 0);
	if (uctx_fd < 0)
		pr_warn("Can't dup uverbs cdev fd for MR QUERY on ibdev=%s: %m\n", ibdev);

	ret = rdma_note_dumped_ufile(uve.id, uve.has_ctxn, uve.ctxn, rcd, uve.driver_id, p->pid, ibdev, uctx_fd);
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
 * Restore-time counterpart of dump_uverbsfile()'s arbitration step.
 *
 * Re-run the per-plugin claim() probe against the restoring host's
 * loaded plugin set and confirm the plugin that would claim this ibdev
 * right now matches the one recorded in the image. Catches operator
 * misconfiguration before the cdev is opened:
 *
 *   (a) image carries criu_driver=RCD_X but the destination has no
 *       plugin returning RCD_X for this ibdev (e.g. the matching
 *       plugin .so was never installed on the destination);
 *   (b) the destination has a *different* plugin claiming this ibdev
 *       than the source did -- refuse to silently swap plugins;
 *   (c) the plugin is present but declines (a host-side gate the
 *       source had is missing on the destination).
 *
 * Abort here rather than let the open dispatcher hand the cdev to a
 * plugin the image was not dumped against.
 */
static int uverbsfd_validate_claim(const UverbsFileEntry *uvfe)
{
	const char *claimer = NULL;
	int rcd;

	if (!uvfe->has_criu_driver) {
		pr_err("uverbsfd id %#x has no criu_driver in image; image predates plugin-claim arbitration. "
		       "Re-dump with current criu.\n",
		       uvfe->id);
		return -1;
	}

	rcd = rdma_arbitrate_plugin_claim(uvfe->ib_dev ?: "?", uvfe->driver_id, &claimer);
	if (rcd < 0) {
		pr_err("uverbsfd id %#x: arbitration failed at restore: %d\n", uvfe->id, rcd);
		return -1;
	}
	if (rcd == RDMA_CRIU_DRIVER__RCD_UNKNOWN) {
		pr_err("uverbsfd id %#x: no RDMA plugin on this host claims ibdev=%s driver=%s. Image was dumped with "
		       "criu_driver=%d; install the matching plugin before restoring.\n",
		       uvfe->id, uvfe->ib_dev ?: "?", uvfe->driver_name ?: "?", (int)uvfe->criu_driver);
		return -1;
	}
	if ((int)uvfe->criu_driver != rcd) {
		pr_err("uverbsfd id %#x: image was dumped under criu_driver=%d but plugin '%s' (rcd=%d) claims "
		       "ibdev=%s on this host. Refusing to silently swap plugins between dump and restore.\n",
		       uvfe->id, (int)uvfe->criu_driver, claimer, rcd, uvfe->ib_dev ?: "?");
		return -1;
	}

	pr_info("uverbsfd id %#x: restore claim OK (plugin '%s' rcd=%d ibdev=%s)\n", uvfe->id, claimer, rcd,
		uvfe->ib_dev ?: "?");
	return 0;
}

static int uverbsfd_open(struct file_desc *d, int *new_fd)
{
	struct uverbsfd_file_info *ui;
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
		       "Re-dump with current criu.\n",
		       ui->uvfe->id);
		return -1;
	}

	/*
	 * Confirm a plugin on this host claims the context and matches the
	 * one the image was dumped under before we touch the kernel.
	 */
	if (uverbsfd_validate_claim(ui->uvfe))
		return -1;

	pr_info("Opening uverbsfd id %#x ibdev=%s driver=%s(%u) ctxn %u\n",
		ui->uvfe->id,
		ui->uvfe->ib_dev ?: "?",
		ui->uvfe->driver_name ?: "?",
		ui->uvfe->driver_id,
		ui->uvfe->has_ctxn ? ui->uvfe->ctxn : 0);

	/*
	 * Resolve and open the destination cdev via the claiming plugin
	 * rather than open_reg_by_id(). The image's reg_file_entry carries
	 * the source's cdev path, but the same ibdev may live at a
	 * different minor on the destination (cross-host move, reboot probe
	 * order, rdma link churn). The plugin maps ibdev -> current cdev
	 * and hands back an fd that already has a kernel ucontext on it, so
	 * uverbsfd_open() does not issue GET_CONTEXT itself (the kernel
	 * rejects two GET_CONTEXTs on one struct file). The source-recorded
	 * reg_file_entry stays in the image as a `crit decode` diagnostic
	 * but nothing on restore opens it.
	 */
	fd = rdma_dispatch_open_uverbs_cdev(ui->uvfe);
	if (fd < 0)
		return -1;

	/*
	 * R3 per-uobject restore. The plugin handed back a cdev with a
	 * restore-mode ucontext on it; replay every uobject the dump
	 * captured under this ufile by issuing the matching RESTORE_<TYPE>
	 * verb. PD only for now (the verb itself lands next); no-op when
	 * the dump produced no rdma_uobj.img coverage for this ufile_id,
	 * which matches the pre-R3 bare-context baseline.
	 *
	 * driver_id is the kernel's RDMA_DRIVER_* enum (what the
	 * UVERBS_OBJECT_RESTORE ioctl header matches), distinct from the
	 * per-plugin RdmaCriuDriver the DAG group caches as hw_driver_id.
	 */
	if (rdma_restore_uobj_dag_for_ufile(fd, ui->uvfe->id, ui->uvfe->driver_id)) {
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
