/*
 * vf_image.c
 *
 * On-disk format helpers for the mlx5_sriov_vfmig plugin's per-dump
 * sidecar image. Two artefacts:
 *
 *   1. <image-dir>/mlx5_vfmig.img -- a sequence of length-prefixed
 *      Mlx5VfmigStateEntry protobuf records. The length prefix is a
 *      fixed 4-byte little-endian count, no header / no compression.
 *      Hand-rolled framing is used in lieu of the criu/protobuf.c PB_*
 *      helpers because those are tied to criu_image_streamer and live
 *      in the criu binary, not in the plugin .so.
 *
 *   2. <image-dir>/<per-VF blob path> -- the raw byte stream from
 *      MLX5_VFMIG_IOC_SAVE_VHCA_STATE's anon-inode fd, one file per
 *      (pf_bdf, vf_id) the plugin captures.
 *
 * The functions here are intentionally independent of the dump/restore
 * aggregate types -- they take primitives and raw buffers, not plugin
 * state -- so vf_image.c reads as the canonical description of the
 * on-disk shape.
 *
 * This is the VF-firmware-state (device-level) schema. The uverbs-
 * context / ib_uobject restore layer carries an extra ucontext UAR
 * snapshot in mlx5_vfmig.proto; those fields are not written or read
 * here and will be handled when that layer lands.
 */

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include "criu-log.h"
#include "criu-plugin.h"

#include "images/mlx5_vfmig.pb-c.h"

#include "vfmig_internal.h"

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "rdma_mlx5_vfmig_plugin: "

#define MLX5_VFMIG_IMG_NAME "mlx5_vfmig.img"

/*
 * Image-directory fd override.
 *
 * Default: -1 (no override) -- vfmig_get_image_dir() falls back to
 * criu_get_image_dir(), which is criu's own service-fd lookup and is
 * the only valid path while criu is the loader of the plugin .so.
 *
 * Set to a non-negative value by the standalone restore path before it
 * drives the LOAD/bind dance outside criu, and cleared again before
 * that entry point returns. The caller owns the lifetime of the fd it
 * passes in (typically an O_PATH on the dump's image directory); the
 * plugin only reads from it (openat / fstat / read).
 *
 * Process-global rather than per-call because the plugin's read/LOAD
 * call graph threads through several files; an argument-passed fd would
 * require touching every step. The single-threaded, single-call-at-a-
 * time invariant of both `criu restore` and the standalone binary makes
 * the global safe in practice.
 */
static int vfmig_image_dir_override_fd = -1;

void vfmig_set_image_dir_override(int fd)
{
	vfmig_image_dir_override_fd = fd;
}

void vfmig_clear_image_dir_override(void)
{
	vfmig_image_dir_override_fd = -1;
}

int vfmig_get_image_dir(void)
{
	if (vfmig_image_dir_override_fd >= 0)
		return vfmig_image_dir_override_fd;
	return criu_get_image_dir();
}

/*
 * Stream the SAVE_VHCA_STATE save_fd byte-stream into a freshly-created
 * blob file under the image directory. Returns 0 on success with
 * @save_fd drained (but NOT closed -- the caller owns save_fd) and the
 * total bytes written into *@out_size; -1 on any I/O failure (the
 * partially-written blob is left in place for post-mortem -- the dump
 * fails regardless).
 */
int vfmig_drain_save_fd_to_blob(int save_fd, const char *blob_path, uint64_t *out_size)
{
	int img_dir, blob_fd;
	uint64_t total = 0;
	ssize_t n;
	char buf[64 * 1024];

	img_dir = vfmig_get_image_dir();
	if (img_dir < 0) {
		pr_err("vfmig: vfmig_get_image_dir() returned %d -- no image dir set, cannot write blob\n", img_dir);
		return -1;
	}

	blob_fd = openat(img_dir, blob_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (blob_fd < 0) {
		pr_perror("vfmig: openat(image_dir/%s) for blob write", blob_path);
		return -1;
	}

	for (;;) {
		ssize_t off = 0;

		n = read(save_fd, buf, sizeof(buf));
		if (n == 0)
			break;
		if (n < 0) {
			if (errno == EINTR)
				continue;
			pr_perror("vfmig: read(save_fd) for %s", blob_path);
			close(blob_fd);
			return -1;
		}
		while (off < n) {
			ssize_t w = write(blob_fd, buf + off, n - off);
			if (w < 0) {
				if (errno == EINTR)
					continue;
				pr_perror("vfmig: write(%s)", blob_path);
				close(blob_fd);
				return -1;
			}
			off += w;
		}
		total += (uint64_t)n;
	}

	if (close(blob_fd)) {
		pr_perror("vfmig: close(%s)", blob_path);
		return -1;
	}

	*out_size = total;
	return 0;
}

/*
 * Append one Mlx5VfmigStateEntry record to <img-dir>/mlx5_vfmig.img,
 * length-prefixed (uint32 LE byte length, then the protobuf-packed
 * bytes). Each record is independent; the restore-side reader walks
 * length-prefixed records until EOF.
 */
int vfmig_append_state_entry(uint32_t ctxn, const char *ibdev, const char *source_cdev_path, const char *pf_bdf,
			     uint32_t vf_id, uint32_t vhca_id, const uint8_t vf_uuid[16], const char *blob_path,
			     uint64_t blob_size)
{
	Mlx5VfmigStateEntry e = MLX5_VFMIG_STATE_ENTRY__INIT;
	uint8_t zero_uuid[16] = { 0 };
	int img_dir, fd;
	void *buf;
	size_t plen;
	uint32_t lenle;
	struct iovec iov[2];

	/*
	 * Defensive backstop: the dump-side capture path already hard-
	 * refuses an all-zeros @vf_uuid before any SAVE_VHCA_STATE is
	 * run. If a future caller forgets that invariant we want to
	 * fail the entry rather than emit a record that is
	 * by-construction unrestorable (vf_uuid is the sole stable
	 * restore-side match key).
	 */
	if (!memcmp(vf_uuid, zero_uuid, sizeof(zero_uuid))) {
		pr_err("vfmig: append_state_entry(ctxn=%u pf=%s vf_id=%u): vf_uuid is all-zeros (caller bug; capture "
		       "path should have refused)\n",
		       ctxn, pf_bdf, vf_id);
		return -1;
	}

	e.ctxn = ctxn;
	e.ibdev = (char *)ibdev;
	e.pf_bdf = (char *)pf_bdf;
	e.vf_id = vf_id;
	e.vhca_id = vhca_id;
	e.blob_path = (char *)blob_path;
	e.blob_size = blob_size;
	e.source_cdev_path = (char *)source_cdev_path;
	e.vf_uuid.data = (uint8_t *)vf_uuid;
	e.vf_uuid.len = 16;

	plen = mlx5_vfmig_state_entry__get_packed_size(&e);
	if (plen > 0xffffffffu) {
		pr_err("vfmig: state entry too large (%zu) for u32 prefix\n", plen);
		return -1;
	}
	buf = malloc(plen);
	if (!buf) {
		pr_err("vfmig: malloc(%zu) for state entry\n", plen);
		return -1;
	}
	if (mlx5_vfmig_state_entry__pack(&e, buf) != plen) {
		pr_err("vfmig: pack returned unexpected size\n");
		free(buf);
		return -1;
	}

	img_dir = vfmig_get_image_dir();
	if (img_dir < 0) {
		pr_err("vfmig: vfmig_get_image_dir() returned %d\n", img_dir);
		free(buf);
		return -1;
	}
	fd = openat(img_dir, MLX5_VFMIG_IMG_NAME, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (fd < 0) {
		pr_perror("vfmig: openat(image_dir/%s)", MLX5_VFMIG_IMG_NAME);
		free(buf);
		return -1;
	}

	lenle = htole32((uint32_t)plen);
	iov[0].iov_base = &lenle;
	iov[0].iov_len = sizeof(lenle);
	iov[1].iov_base = buf;
	iov[1].iov_len = plen;

	if (writev(fd, iov, 2) != (ssize_t)(sizeof(lenle) + plen)) {
		pr_perror("vfmig: writev(%s)", MLX5_VFMIG_IMG_NAME);
		close(fd);
		free(buf);
		return -1;
	}

	if (close(fd)) {
		pr_perror("vfmig: close(%s)", MLX5_VFMIG_IMG_NAME);
		free(buf);
		return -1;
	}
	free(buf);

	pr_info("vfmig: appended state entry ctxn=%u ibdev=%s pf=%s vf_id=%u -> %s\n", ctxn, ibdev, pf_bdf, vf_id,
		MLX5_VFMIG_IMG_NAME);
	return 0;
}

/*
 * Read mlx5_vfmig.img into an in-memory array of unpacked entries.
 * Returns 0 on success with @out_arr/@out_n populated; caller frees the
 * array (and each entry via mlx5_vfmig_state_entry__free_unpacked).
 * Empty or missing image is also success with @out_n == 0.
 */
int vfmig_read_image(Mlx5VfmigStateEntry ***out_arr, size_t *out_n)
{
	int img_dir, fd;
	struct stat st;
	void *blob = NULL;
	size_t off = 0;
	Mlx5VfmigStateEntry **arr = NULL;
	size_t cap = 0, n = 0, i;

	*out_arr = NULL;
	*out_n = 0;

	img_dir = vfmig_get_image_dir();
	if (img_dir < 0) {
		pr_err("vfmig: vfmig_get_image_dir() returned %d on restore\n", img_dir);
		return -1;
	}

	fd = openat(img_dir, MLX5_VFMIG_IMG_NAME, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT) {
			pr_info("vfmig: no %s in image dir; nothing to restore\n", MLX5_VFMIG_IMG_NAME);
			return 0;
		}
		pr_perror("vfmig: openat(image_dir/%s)", MLX5_VFMIG_IMG_NAME);
		return -1;
	}
	if (fstat(fd, &st)) {
		pr_perror("vfmig: fstat(%s)", MLX5_VFMIG_IMG_NAME);
		close(fd);
		return -1;
	}
	if (st.st_size == 0) {
		pr_info("vfmig: %s is empty; nothing to restore\n", MLX5_VFMIG_IMG_NAME);
		close(fd);
		return 0;
	}
	blob = malloc(st.st_size);
	if (!blob) {
		pr_err("vfmig: malloc(%lld) for image\n", (long long)st.st_size);
		close(fd);
		return -1;
	}
	if (read(fd, blob, st.st_size) != st.st_size) {
		pr_perror("vfmig: read(%s)", MLX5_VFMIG_IMG_NAME);
		free(blob);
		close(fd);
		return -1;
	}
	close(fd);

	while (off < (size_t)st.st_size) {
		uint32_t plen;
		Mlx5VfmigStateEntry *e;

		if (off + sizeof(plen) > (size_t)st.st_size) {
			pr_err("vfmig: truncated length prefix in %s at off %zu\n", MLX5_VFMIG_IMG_NAME, off);
			goto err;
		}
		memcpy(&plen, (char *)blob + off, sizeof(plen));
		plen = le32toh(plen);
		off += sizeof(plen);
		if (plen == 0 || plen > 0x10000000u || off + plen > (size_t)st.st_size) {
			pr_err("vfmig: bad record length %u at off %zu in %s\n", plen, off, MLX5_VFMIG_IMG_NAME);
			goto err;
		}
		e = mlx5_vfmig_state_entry__unpack(NULL, plen, (uint8_t *)blob + off);
		if (!e) {
			pr_err("vfmig: unpack failed at off %zu\n", off);
			goto err;
		}
		off += plen;
		if (n == cap) {
			size_t ncap = cap ? cap * 2 : 4;
			Mlx5VfmigStateEntry **na = realloc(arr, ncap * sizeof(*arr));
			if (!na) {
				mlx5_vfmig_state_entry__free_unpacked(e, NULL);
				pr_err("vfmig: realloc(arr)\n");
				goto err;
			}
			arr = na;
			cap = ncap;
		}
		arr[n++] = e;
	}

	free(blob);
	*out_arr = arr;
	*out_n = n;
	return 0;
err:
	free(blob);
	if (arr) {
		for (i = 0; i < n; i++)
			mlx5_vfmig_state_entry__free_unpacked(arr[i], NULL);
		free(arr);
	}
	return -1;
}
