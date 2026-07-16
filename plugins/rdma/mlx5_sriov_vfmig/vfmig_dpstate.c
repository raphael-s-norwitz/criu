/*
 * vfmig_dpstate.c
 *
 * Shared datapath-state (SUSPEND/RESUME_VHCA) ioctl helpers for the
 * rdma_mlx5_vfmig plugin. Both the dump path (CHECKPOINT_DEVICES
 * two-phase pause, fini resume) and the restore path (the
 * RESUME_DEVICES_LATE R1 park+release) drive the firmware RUNNING <-> RUNNING_P2P
 * <-> STOP ladder through these two entry points; keeping them in one
 * place means every caller opens /dev/mlx5_vfmig/<pf_bdf> the same way
 * and passes the same MLX5_VFMIG_DIR_FLAG_* direction selector.
 *
 * @dir_flags == 0 drives the legacy fused pair (all-or-nothing on
 * failure per the kernel contract); MLX5_VFMIG_DIR_FLAG_INITIATOR /
 * _RESPONDER drive a single ladder edge (truthful latch on failure).
 * Both ioctls are idempotent: a request already satisfied returns 0
 * with no firmware traffic.
 *
 * Returns 0 on success (including a kernel-side no-op) or -1 on error
 * (open / ioctl failure), matching the plugin's other -1 conventions.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/mlx5_vfmig.h>

#include "criu-log.h"

#include "vfmig_internal.h"

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "rdma_mlx5_vfmig_plugin: "

static int vfmig_dp_open_cdev(const char *pf_bdf)
{
	char cdev_path[PATH_MAX];
	int fd;

	snprintf(cdev_path, sizeof(cdev_path), "%s/%s",
		 MLX5_VFMIG_DEV_DIR, pf_bdf);
	fd = open(cdev_path, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		pr_perror("vfmig: dpstate: open(%s)", cdev_path);
	return fd;
}

int vfmig_dp_suspend(const char *pf_bdf, uint32_t vf_id, uint32_t dir_flags)
{
	struct mlx5_vfmig_suspend_vhca sv;
	int fd, rc;

	fd = vfmig_dp_open_cdev(pf_bdf);
	if (fd < 0)
		return -1;

	memset(&sv, 0, sizeof(sv));
	sv.vf_id = vf_id;
	sv.flags = dir_flags;
	rc = ioctl(fd, MLX5_VFMIG_IOC_SUSPEND_VHCA, &sv);
	close(fd);
	if (rc) {
		pr_perror("vfmig: SUSPEND_VHCA(pf=%s vf_id=%u flags=0x%x)",
			  pf_bdf, vf_id, dir_flags);
		return -1;
	}
	return 0;
}

int vfmig_dp_resume(const char *pf_bdf, uint32_t vf_id, uint32_t dir_flags)
{
	struct mlx5_vfmig_resume_vhca rv;
	int fd, rc;

	fd = vfmig_dp_open_cdev(pf_bdf);
	if (fd < 0)
		return -1;

	memset(&rv, 0, sizeof(rv));
	rv.vf_id = vf_id;
	rv.flags = dir_flags;
	rc = ioctl(fd, MLX5_VFMIG_IOC_RESUME_VHCA, &rv);
	close(fd);
	if (rc) {
		pr_perror("vfmig: RESUME_VHCA(pf=%s vf_id=%u flags=0x%x)",
			  pf_bdf, vf_id, dir_flags);
		return -1;
	}
	return 0;
}
