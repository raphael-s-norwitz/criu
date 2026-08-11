/*
 * vfmig_image_test.c -- no-hardware unit test for the mlx5_sriov_vfmig
 * plugin's on-disk image helpers (plugins/rdma/mlx5_sriov_vfmig/
 * vf_image.c).
 *
 * Exercises the image format in isolation, without a tracked VF, a
 * running criu, or the plugin .so: it compiles vf_image.c straight into
 * the test binary, points the plugin's image-dir override at a temp
 * directory, and round-trips records + a blob through the real code.
 *
 * Covered:
 *   - vfmig_read_image() on a missing image -> success, 0 entries.
 *   - vfmig_append_state_entry() x2 -> vfmig_read_image() -> 2 entries,
 *     every field round-trips byte-for-byte (including the 16-byte
 *     vf_uuid).
 *   - vfmig_append_state_entry() with an all-zero vf_uuid is refused.
 *   - vfmig_drain_save_fd_to_blob() drains an fd to a blob file with the
 *     right size and contents.
 *
 * Built + run by run_vfmig_image_test.sh.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "vfmig_internal.h"

/* ---- shims for the criu-binary symbols vf_image.c references ---- */

unsigned int log_get_loglevel(void)
{
	return 4; /* LOG_DEBUG; the test prints everything to stderr */
}

void print_on_level(unsigned int loglevel, const char *format, ...)
{
	va_list ap;

	(void)loglevel;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

/*
 * criu_get_image_dir() is only reached when no override fd is set. The
 * test always sets an override, so this stub should never be hit; make
 * it loud if it ever is.
 */
int criu_get_image_dir(void)
{
	fprintf(stderr, "BUG: criu_get_image_dir() called in unit test\n");
	return -1;
}

/* ---- test scaffolding ---- */

static int failures;

#define CHECK(cond, msg)                                      \
	do {                                                  \
		if (!(cond)) {                                \
			fprintf(stderr, "FAIL: %s\n", (msg)); \
			failures++;                           \
		} else {                                      \
			fprintf(stderr, "ok:   %s\n", (msg)); \
		}                                             \
	} while (0)

static void free_entries(Mlx5VfmigStateEntry **arr, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		mlx5_vfmig_state_entry__free_unpacked(arr[i], NULL);
	free(arr);
}

int main(void)
{
	char tmpl[] = "/tmp/vfmig_img_test.XXXXXX";
	char *dir;
	int dir_fd, rc;
	Mlx5VfmigStateEntry **arr = NULL;
	size_t n = 0;

	const uint8_t uuid_a[16] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
				     0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01 };
	const uint8_t uuid_b[16] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
				     0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf };
	const uint8_t uuid_zero[16] = { 0 };

	dir = mkdtemp(tmpl);
	if (!dir) {
		perror("mkdtemp");
		return 2;
	}
	dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dir_fd < 0) {
		perror("open(tmpdir)");
		return 2;
	}
	vfmig_set_image_dir_override(dir_fd);

	/* 1. Missing image -> success, 0 entries. */
	rc = vfmig_read_image(&arr, &n);
	CHECK(rc == 0 && n == 0 && arr == NULL, "read of missing image returns 0 entries");

	/* 2. Append two entries, read them back, compare every field. */
	rc = vfmig_append_state_entry(7, "mlx5_2", "/dev/infiniband/uverbs2", "0000:08:00.0", 3, 0x123, uuid_a,
				      "mlx5_vfmig-pf0000:08:00.0-vf3.blob", 65536);
	CHECK(rc == 0, "append entry A");
	rc = vfmig_append_state_entry(9, "mlx5_5", "/dev/infiniband/uverbs5", "0000:08:00.1", 1, 0x456, uuid_b,
				      "mlx5_vfmig-pf0000:08:00.1-vf1.blob", 131072);
	CHECK(rc == 0, "append entry B");

	rc = vfmig_read_image(&arr, &n);
	CHECK(rc == 0 && n == 2, "read image returns 2 entries");
	if (rc == 0 && n == 2) {
		Mlx5VfmigStateEntry *a = arr[0];
		Mlx5VfmigStateEntry *b = arr[1];

		CHECK(a->ctxn == 7 && !strcmp(a->ibdev, "mlx5_2") && !strcmp(a->pf_bdf, "0000:08:00.0") &&
			      a->vf_id == 3 && a->vhca_id == 0x123 &&
			      !strcmp(a->source_cdev_path, "/dev/infiniband/uverbs2") &&
			      !strcmp(a->blob_path, "mlx5_vfmig-pf0000:08:00.0-vf3.blob") && a->blob_size == 65536 &&
			      a->vf_uuid.len == 16 && !memcmp(a->vf_uuid.data, uuid_a, 16),
		      "entry A round-trips all fields");
		CHECK(b->ctxn == 9 && !strcmp(b->ibdev, "mlx5_5") && !strcmp(b->pf_bdf, "0000:08:00.1") &&
			      b->vf_id == 1 && b->vhca_id == 0x456 &&
			      !strcmp(b->source_cdev_path, "/dev/infiniband/uverbs5") &&
			      !strcmp(b->blob_path, "mlx5_vfmig-pf0000:08:00.1-vf1.blob") && b->blob_size == 131072 &&
			      b->vf_uuid.len == 16 && !memcmp(b->vf_uuid.data, uuid_b, 16),
		      "entry B round-trips all fields");
	}
	free_entries(arr, n);
	arr = NULL;
	n = 0;

	/* 3. All-zero vf_uuid is refused. */
	rc = vfmig_append_state_entry(1, "mlx5_2", "/dev/infiniband/uverbs2", "0000:08:00.0", 0, 0, uuid_zero,
				      "x.blob", 0);
	CHECK(rc == -1, "append with all-zero vf_uuid is refused");

	/* 4. drain_save_fd_to_blob: fd -> blob file with right size + bytes. */
	{
		const char payload[] = "FW_DATA\x00 firmware blob bytes \x01\x02\x03";
		size_t plen = sizeof(payload); /* include trailing NUL to prove binary-safe */
		const char *blob = "drain.blob";
		int mfd, bfd;
		uint64_t out_size = 0;
		char rb[256];
		ssize_t got;

		mfd = memfd_create("vfmig_src", MFD_CLOEXEC);
		if (mfd < 0) {
			perror("memfd_create");
			return 2;
		}
		if (write(mfd, payload, plen) != (ssize_t)plen) {
			perror("write(memfd)");
			return 2;
		}
		lseek(mfd, 0, SEEK_SET);

		rc = vfmig_drain_save_fd_to_blob(mfd, blob, &out_size);
		CHECK(rc == 0 && out_size == plen, "drain reports correct byte count");
		close(mfd);

		bfd = openat(dir_fd, blob, O_RDONLY | O_CLOEXEC);
		got = bfd >= 0 ? read(bfd, rb, sizeof(rb)) : -1;
		CHECK(bfd >= 0 && got == (ssize_t)plen && !memcmp(rb, payload, plen),
		      "blob file contents match the drained fd byte-for-byte");
		if (bfd >= 0)
			close(bfd);
		unlinkat(dir_fd, blob, 0);
	}

	vfmig_clear_image_dir_override();
	unlinkat(dir_fd, "mlx5_vfmig.img", 0);
	close(dir_fd);
	rmdir(dir);

	if (failures) {
		fprintf(stderr, "\n%d check(s) FAILED\n", failures);
		return 1;
	}
	fprintf(stderr, "\nall checks passed\n");
	return 0;
}
