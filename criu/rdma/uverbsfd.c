#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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
#include "kerndat.h"
#include "log.h"
#include "protobuf.h"
#include "pstree.h"
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

/*
 * Every uverbs context collected from the image, in collection order.
 * file_desc lookups are by id and there is no iterator, but the late
 * dma-buf MR bind pass needs to visit them all.
 */
struct uverbs_collected_ufile {
	UverbsFileEntry *uvfe;
	struct list_head link;
};
static LIST_HEAD(uverbs_collected_ufiles);

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

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif

/*
 * Resolve a uverbs cdev (by its chrdev major/minor) to its ibdev,
 * backing kernel-driver id, and the CRIU driver id of the plugin that
 * wins CLAIM arbitration. Everything is derivable from the chrdev alone,
 * so both dump_uverbsfile() (per-fd, has an fd_parms) and the early
 * capture pass (has only a pidfd-acquired fd + the cdev rdev) can share
 * it. Fails the dump closed on an unattributable context.
 */
static int rdma_resolve_cdev_identity(unsigned int maj, unsigned int min, char *ibdev, size_t ibsz,
				      uint32_t *driver_id, int *criu_driver)
{
	char driver[64];
	const char *claimer = NULL;
	int rcd;

	if (rdma_ibdev_from_chrdev(maj, min, ibdev, ibsz)) {
		pr_err("Can't resolve ibdev for uverbs cdev %u:%u\n", maj, min);
		return -1;
	}
	if (rdma_driver_name_from_ibdev(ibdev, driver, sizeof(driver))) {
		pr_err("Can't resolve kernel driver for ibdev '%s'\n", ibdev);
		return -1;
	}
	*driver_id = rdma_driver_name_to_id(driver);
	if (*driver_id == RDMA_DRIVER_UNKNOWN) {
		pr_err("Unknown RDMA driver '%s' for ibdev '%s' (uverbs cdev %u:%u)\n", driver, ibdev, maj, min);
		return -1;
	}
	rcd = rdma_arbitrate_plugin_claim(ibdev, *driver_id, &claimer);
	if (rcd < 0) {
		pr_err("Plugin arbitration failed for ibdev=%s driver=%s: %d\n", ibdev, driver, rcd);
		return -1;
	}
	if (rcd == RDMA_CRIU_DRIVER__RCD_UNKNOWN) {
		pr_err("No RDMA CRIU plugin claims ibdev=%s driver=%s (RDMA_DRIVER id=%u)\n", ibdev, driver,
		       *driver_id);
		return -1;
	}
	*criu_driver = rcd;
	return 0;
}

/* Already captured this (pid, ctxn)? A process can hold several fds to
 * one ucontext (dup / fork-shared table); capture each ucontext once. */
static bool rdma_ufile_already_captured(pid_t pid, bool has_ctxn, uint32_t ctxn)
{
	struct rdma_dumped_ufile *uf;

	list_for_each_entry(uf, &rdma_dumped_ufiles, link) {
		if (uf->pid != pid || uf->has_ctxn != has_ctxn)
			continue;
		if (!has_ctxn || uf->ctxn == ctxn)
			return true;
	}
	return false;
}

/*
 * Early uverbs-context capture, one dumpee at a time. Walks /proc/<pid>/fd
 * for /dev/infiniband/uverbsN cdev fds (the async-event evfd is an anon
 * inode, so it's skipped), and for each distinct ucontext resolves its
 * ibdev/driver/plugin from the cdev rdev, reads its ctxn from fdinfo, and
 * dups the *same* struct file out of the (SEIZE-stopped) dumpee via
 * pidfd_getfd -- a re-open of /proc/<pid>/fd/N would mint a fresh, empty
 * ucontext, so pidfd_getfd is mandatory. The dup is stashed as the
 * ufile's holder_uctx_fd for the capture walk; uvfe_id is left 0 and
 * back-filled by dump_uverbsfile() once file collection assigns it.
 */
static int rdma_capture_pid_uverbs(pid_t pid)
{
	char path[64];
	DIR *d;
	struct dirent *de;
	int pidfd = -1, ret = -1;

	snprintf(path, sizeof(path), "/proc/%d/fd", pid);
	d = opendir(path);
	if (!d) {
		pr_perror("rdma capture: opendir %s", path);
		return -1;
	}

	while ((de = readdir(d))) {
		char link[PATH_MAX];
		ssize_t n;
		struct stat st;
		UverbsFileEntry uve = UVERBS_FILE_ENTRY__INIT;
		char ibdev[64];
		uint32_t driver_id;
		int criu_driver = 0, fd_no, uctx_fd;

		if (de->d_name[0] == '.')
			continue;

		n = readlinkat(dirfd(d), de->d_name, link, sizeof(link) - 1);
		if (n < 0)
			continue;
		link[n] = '\0';
		if (strncmp(link, "/dev/infiniband/uverbs", strlen("/dev/infiniband/uverbs")) != 0)
			continue;

		if (fstatat(dirfd(d), de->d_name, &st, 0) < 0 || !S_ISCHR(st.st_mode))
			continue;

		fd_no = atoi(de->d_name);

		if (parse_fdinfo_pid(pid, fd_no, FD_TYPES__UVERBSFD, &uve)) {
			pr_err("rdma capture: parse fdinfo for pid=%d fd=%d (%s) failed\n", pid, fd_no, link);
			goto out;
		}

		if (rdma_ufile_already_captured(pid, uve.has_ctxn, uve.ctxn))
			continue;

		if (rdma_resolve_cdev_identity(major(st.st_rdev), minor(st.st_rdev), ibdev, sizeof(ibdev),
					       &driver_id, &criu_driver))
			goto out;

		if (!kdat.has_pidfd_getfd) {
			pr_err("rdma capture: pidfd_getfd is required to dup the dumpee's uverbs context "
			       "(pid=%d %s) but the kernel does not support it\n",
			       pid, link);
			goto out;
		}

		if (pidfd < 0) {
			pidfd = syscall(__NR_pidfd_open, pid, 0);
			if (pidfd < 0) {
				pr_perror("rdma capture: pidfd_open(%d)", pid);
				goto out;
			}
		}

		uctx_fd = syscall(__NR_pidfd_getfd, pidfd, fd_no, 0);
		if (uctx_fd < 0) {
			pr_perror("rdma capture: pidfd_getfd(pid=%d fd=%d %s)", pid, fd_no, link);
			goto out;
		}

		/* uvfe_id deferred: dump_uverbsfile() back-fills it. */
		if (rdma_note_dumped_ufile(0, uve.has_ctxn, uve.ctxn, criu_driver, driver_id, pid, ibdev,
					   uctx_fd, fd_no))
			goto out;

		pr_info("rdma capture: pid=%d ibdev=%s ctxn=%u (fd=%d) captured for uobj DAG\n", pid, ibdev,
			uve.has_ctxn ? uve.ctxn : 0, fd_no);
	}

	ret = 0;
out:
	if (pidfd >= 0)
		close(pidfd);
	closedir(d);
	return ret;
}

/*
 * Early uverbs-context capture pass (see rdma.h). Runs after the RDMA
 * coverage/exclusivity checks and *before* the datapath freeze
 * (checkpoint_devices) and the memory snapshot: it records the tree's
 * uverbs contexts and drives the order-sensitive half of the uobject DAG
 * (rdma_capture_uobj_dag) while the device is still live, so the QP
 * enumeration's firmware QUERY_QP and the per-QP cap query hit a live
 * command ring rather than a suspended VF.
 */
int rdma_capture_uverbs_contexts(struct pstree_item *root)
{
	struct pstree_item *item;

	if (!root)
		return 0;

	/*
	 * dmabuf_fds is appended to, one line per exported MR, so a file left
	 * in the image directory by an earlier dump would put its stale fd
	 * numbers ahead of ours -- and the cuda plugin hands the file to
	 * cuda-checkpoint whenever it exists, even if this dump exports
	 * nothing. Start every dump without one.
	 */
	if (unlinkat(get_service_fd(IMG_FD_OFF), "dmabuf_fds", 0) && errno != ENOENT) {
		pr_perror("rdma capture: remove stale dmabuf_fds");
		return -1;
	}

	for_each_pstree_item(item) {
		if (!item->pid || item->pid->real <= 0)
			continue;
		if (rdma_capture_pid_uverbs(item->pid->real))
			return -1;
	}

	/* No uverbs contexts in the tree -> nothing to capture. */
	if (list_empty(&rdma_dumped_ufiles))
		return 0;

	return rdma_capture_uobj_dag();
}

static int dump_uverbsfile(int lfd, u32 id, const struct fd_parms *p)
{
	UverbsFileEntry uve = UVERBS_FILE_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;
	struct cr_img *img;
	const char *claimer = NULL;
	char ibdev[64];
	char driver[64];
	int holder_fd_no = -1;
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

	/*
	 * Back-fill this context's image id onto the record the early
	 * capture pass (rdma_capture_uverbs_contexts) already made before
	 * the datapath freeze. The uobject DAG walk ran there, on the live
	 * device, using a pidfd_getfd dup of this same ucontext; the emit
	 * phase reads uvfe_id back off the record to stamp each entry's
	 * ufile_id. A context with no capture record is a dump bug -- fail
	 * closed.
	 *
	 * Must precede the pb_write_one() below: it also yields the holder
	 * fd number, which goes into the same entry.
	 */
	ret = rdma_bind_dumped_ufile_id(p->pid, uve.has_ctxn, uve.ctxn, uve.id, &holder_fd_no);
	if (ret)
		goto out;
	if (holder_fd_no >= 0) {
		/*
		 * Where the restored task will hold this cdev: its pid is
		 * preserved by criu and setup_and_serve_out() reinstalls the
		 * fd at its original number, so the pair still addresses this
		 * context once the task is running. The dma-buf MR bind pass
		 * needs that, criu's own fd on the context being long gone by
		 * then.
		 */
		uve.holder_pid = p->pid;
		uve.has_holder_pid = true;
		uve.holder_fd = holder_fd_no;
		uve.has_holder_fd = true;
	}

	fe.type = FD_TYPES__UVERBSFD;
	fe.id = uve.id;
	fe.uvfd = &uve;

	img = img_from_set(glob_imgset, CR_FD_FILES);
	ret = pb_write_one(img, &fe, PB_FILE);
	if (ret)
		goto out;
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

	{
		struct uverbs_collected_ufile *cu = xzalloc(sizeof(*cu));

		if (!cu)
			return -1;
		cu->uvfe = ui->uvfe;
		list_add_tail(&cu->link, &uverbs_collected_ufiles);
	}

	pr_info("Collected uverbsfd ctxn %d\n", ui->uvfe->ctxn);

	return 0;
}

struct collect_image_info uverbsfd_cinfo = {
	.fd_type = CR_FD_UVERBS_FILE,
	.pb_type = PB_UVERBS_FILE,
	.priv_size = sizeof(struct uverbsfd_file_info),
	.collect = collect_one_uverbsfd,
};

/* ---------------- late DMA-BUF MR bind pass ---------------- */

struct dmabuf_bind_ctx {
	int cmd_fd;
	uint32_t driver_id;
	const int *fds;
	unsigned int n_fds;
	unsigned int n_bound;
	const char *ibdev;
};

/*
 * UAPI lag shim, as in uobj_dump.c: UVERBS_METHOD_MR_BIND_DMABUF is the 9th
 * entry of enum uverbs_methods_mr, its attributes the 1st and 2nd of enum
 * uverbs_attrs_mr_bind_dmabuf_ids. Numeric copies so criu builds against
 * kernel headers that predate the verb.
 */
#ifndef UVERBS_METHOD_MR_BIND_DMABUF
#define UVERBS_METHOD_MR_BIND_DMABUF 8
#endif
#ifndef UVERBS_ATTR_MR_BIND_DMABUF_HANDLE
#define UVERBS_ATTR_MR_BIND_DMABUF_HANDLE 0
#endif
#ifndef UVERBS_ATTR_MR_BIND_DMABUF_FD
#define UVERBS_ATTR_MR_BIND_DMABUF_FD 1
#endif

/*
 * Point unbound MR @handle at @dmabuf_fd, keeping the key. Core uverb,
 * the restore half of the UNBIND_DMABUF issued at dump; -EINVAL if the
 * MR is not in the unbound state, -EOPNOTSUPP if the driver lacks it.
 */
int rdma_send_bind_dmabuf_mr(int cmd_fd, uint32_t driver_id, uint32_t handle, int dmabuf_fd)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[2];
	} cmd = {};

	cmd.hdr.length = sizeof(cmd.hdr) + 2 * sizeof(cmd.attrs[0]);
	cmd.hdr.object_id = UVERBS_OBJECT_MR;
	cmd.hdr.method_id = UVERBS_METHOD_MR_BIND_DMABUF;
	cmd.hdr.num_attrs = 2;
	cmd.hdr.driver_id = driver_id;

	cmd.attrs[0].attr_id = UVERBS_ATTR_MR_BIND_DMABUF_HANDLE;
	cmd.attrs[0].len = 0;
	cmd.attrs[0].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[0].data = handle;

	/* RAW_FD wire form: len == 0, the fd in .data as a signed 64-bit. */
	cmd.attrs[1].attr_id = UVERBS_ATTR_MR_BIND_DMABUF_FD;
	cmd.attrs[1].len = 0;
	cmd.attrs[1].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[1].data = (uint64_t)(int64_t)dmabuf_fd;

	if (ioctl(cmd_fd, RDMA_VERBS_IOCTL, &cmd))
		return -errno;
	return 0;
}

static int dmabuf_bind_one_mr(uint32_t ufile_handle, uint32_t lkey, uint32_t dmabuf_index, void *arg)
{
	struct dmabuf_bind_ctx *c = arg;
	int ret;

	if (dmabuf_index >= c->n_fds) {
		pr_err("rdma dmabuf bind: MR handle=%u on ibdev=%s wants dmabuf_fds line %u but the file has %u\n",
		       ufile_handle, c->ibdev, dmabuf_index, c->n_fds);
		return -1;
	}

	ret = rdma_send_bind_dmabuf_mr(c->cmd_fd, c->driver_id, ufile_handle, c->fds[dmabuf_index]);
	if (ret) {
		pr_err("rdma dmabuf bind: BIND_DMABUF handle=%u lkey=%#x fd=%d on ibdev=%s failed: %d (%s)\n",
		       ufile_handle, lkey, c->fds[dmabuf_index], c->ibdev, ret, strerror(-ret));
		return -1;
	}

	pr_info("rdma dmabuf bind: MR handle=%u lkey=%#x on ibdev=%s bound to dmabuf_fds[%u]=%d\n", ufile_handle,
		lkey, c->ibdev, dmabuf_index, c->fds[dmabuf_index]);
	c->n_bound++;
	return 0;
}

/*
 * Read dmabuf_fds into @fds. Returns the count, 0 if the file is absent
 * (a checkpoint with no DMA-BUF-backed MRs), -1 on error.
 */
static int dmabuf_fds_read(int *fds, unsigned int max)
{
	char buf[32];
	unsigned int n = 0;
	FILE *f;
	int img_fd;

	img_fd = openat(get_service_fd(IMG_FD_OFF), "dmabuf_fds", O_RDONLY | O_CLOEXEC);
	if (img_fd < 0)
		return errno == ENOENT ? 0 : -1;

	f = fdopen(img_fd, "r");
	if (!f) {
		close(img_fd);
		return -1;
	}

	while (fgets(buf, sizeof(buf), f)) {
		char *end = NULL;
		long v;

		if (buf[0] == '\n')
			continue;
		if (n >= max) {
			pr_err("rdma dmabuf bind: dmabuf_fds has more than %u lines\n", max);
			fclose(f);
			return -1;
		}
		errno = 0;
		v = strtol(buf, &end, 10);
		if (errno || v < 0 || (*end != '\n' && *end != '\0')) {
			pr_err("rdma dmabuf bind: malformed dmabuf_fds line %u\n", n);
			fclose(f);
			return -1;
		}
		fds[n++] = (int)v;
	}

	fclose(f);
	return (int)n;
}

#define DMABUF_MAX_FDS 256

/*
 * Point every restored DMA-BUF-backed MR back at its buffer.
 *
 * Runs after RESUME_DEVICES_LATE, which is the earliest the buffers exist:
 * the plugin that owns them (a GPU plugin, say) recreates them there, and
 * rewrites dmabuf_fds in place with the fds they came back as. Until then
 * each such MR is an identity with nothing behind it, RESTORE_MR having
 * adopted its mkey unbacked.
 *
 * criu's own fd on the ucontext is long gone by now -- it was dup2'd into
 * the task and closed -- so the cdev is fetched back out of the restored
 * task with pidfd_getfd, using the pid and fd number recorded at dump. Both
 * survive: criu restores a task under its original pid and reinstalls each
 * fd at its original number.
 */
int rdma_bind_dmabuf_mrs_late(void)
{
	struct uverbs_collected_ufile *cu;
	int fds[DMABUF_MAX_FDS];
	unsigned int total_bound = 0;
	int n_fds, ret = 0;

	n_fds = dmabuf_fds_read(fds, DMABUF_MAX_FDS);
	if (n_fds < 0)
		return -1;
	if (n_fds == 0)
		return 0;

	list_for_each_entry(cu, &uverbs_collected_ufiles, link) {
		UverbsFileEntry *uvfe = cu->uvfe;
		struct dmabuf_bind_ctx c = {};
		int pidfd, cmd_fd;

		if (!uvfe->has_holder_pid || !uvfe->has_holder_fd)
			continue;

		pidfd = syscall(__NR_pidfd_open, uvfe->holder_pid, 0);
		if (pidfd < 0) {
			pr_perror("rdma dmabuf bind: pidfd_open(%u)", uvfe->holder_pid);
			return -1;
		}
		cmd_fd = syscall(__NR_pidfd_getfd, pidfd, uvfe->holder_fd, 0);
		close(pidfd);
		if (cmd_fd < 0) {
			pr_perror("rdma dmabuf bind: pidfd_getfd(pid=%u fd=%u)", uvfe->holder_pid,
				  uvfe->holder_fd);
			return -1;
		}

		c.cmd_fd = cmd_fd;
		c.driver_id = uvfe->driver_id;
		c.fds = fds;
		c.n_fds = (unsigned int)n_fds;
		c.ibdev = uvfe->ib_dev ?: "?";

		ret = rdma_uobj_foreach_dmabuf_mr(uvfe->id, dmabuf_bind_one_mr, &c);
		close(cmd_fd);
		if (ret)
			return -1;

		total_bound += c.n_bound;
	}

	/*
	 * Every line is a buffer some MR asked for. A shortfall means the
	 * image and the walk disagree about which MRs are dma-buf backed,
	 * which would otherwise surface as an MR that silently never gets
	 * its memory back.
	 */
	if (total_bound != (unsigned int)n_fds) {
		pr_err("rdma dmabuf bind: bound %u MR(s) but dmabuf_fds has %d line(s)\n", total_bound, n_fds);
		return -1;
	}

	pr_info("rdma dmabuf bind: %u DMA-BUF MR(s) rebound\n", total_bound);
	return 0;
}

/*
 * Let every ibdev the restore collected a uverbs file for come back
 * online, once each, after rdma_bind_dmabuf_mrs_late() has pointed the
 * restored MRs at real memory.
 *
 * Its own pass rather than something hung off the bind loop: that loop
 * returns early when the image carries no dma-buf fds at all, and an
 * ibdev with no DMA-BUF-backed MRs still has to be resumed.
 *
 * A failure is reported but neither stops the walk nor fails the restore.
 * The process is already restored by this point; tearing it down over a
 * late coordination failure would be worse than surfacing it.
 */
int rdma_resume_collected_ibdevs(void)
{
	struct uverbs_collected_ufile *cu, *prev;
	int resumed = 0, failed = 0, ret;

	list_for_each_entry(cu, &uverbs_collected_ufiles, link) {
		const char *ibdev = cu->uvfe->ib_dev ?: "?";
		bool seen = false;

		if (!cu->uvfe->has_criu_driver)
			continue;

		/* One ibdev, many contexts: resume it once. */
		list_for_each_entry(prev, &uverbs_collected_ufiles, link) {
			if (prev == cu)
				break;
			if (prev->uvfe->has_criu_driver && prev->uvfe->criu_driver == cu->uvfe->criu_driver &&
			    !strcmp(prev->uvfe->ib_dev ?: "?", ibdev)) {
				seen = true;
				break;
			}
		}
		if (seen)
			continue;

		ret = rdma_dispatch_resume_ibdev(cu->uvfe);
		if (ret == -ENOTSUP)
			continue;
		if (ret < 0) {
			pr_err("rdma: resume of ibdev=%s (criu_driver=%u) failed: %d\n", ibdev,
			       cu->uvfe->criu_driver, ret);
			failed++;
			continue;
		}
		resumed++;
	}

	if (resumed || failed)
		pr_info("rdma: resumed %d ibdev(s) after the DMA-BUF bind pass, %d failed\n", resumed, failed);
	return 0;
}
