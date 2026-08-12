/*
 * mlx5_vfmig_restore_vf -- standalone VF firmware-state restore tool
 * for the rdma_mlx5_vfmig plugin.
 *
 * Drives the destination-side VF firmware restore for every VF in a
 * CRIU dump, via the plugin's exported
 * mlx5_vfmig_plugin_restore_vf_only() entry point. This is a
 * deliberately separate step from `criu restore`: it lets the VF
 * firmware layer be exercised on its own, before the uverbs-object
 * restore layer exists, and gives an operator an orderable pause point
 * for host-level setup (per-VF MAC, ARP, ...) that the in-process
 * restore path cannot do.
 *
 * The tool dlopens the plugin .so, dlsyms the entry point, and hands it
 * an O_PATH fd on the image directory. All the read-image / discovery /
 * LOAD / bind logic lives in the plugin; the tool is just the
 * out-of-criu driver. No state is persisted across runs.
 *
 * This commit is the boilerplate: CLI parsing and the dlopen / dlsym /
 * call scaffolding. The symbol-resolution shims the plugin .so needs
 * from its host (print_on_level and friends) are added in a following
 * commit, so this build of the tool cannot yet load the plugin at
 * runtime -- it is the scaffold the rest is fleshed out on.
 *
 * Usage:
 *   mlx5_vfmig_restore_vf -D <image-dir> [--plugin PATH] [--dry-run]
 *                         [--help]
 */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Default plugin install path: matches PLUGINDIR in the criu Makefile
 * (/usr/local/lib/criu with the default PREFIX). Overridable via
 * --plugin.
 */
#define DEFAULT_PLUGIN_PATH "/usr/local/lib/criu/rdma_mlx5_vfmig_plugin.so"

/*
 * Must match the symbol exported from the plugin .so (see
 * vfmig_restore.c). dlsym binds against the .so's actual entry, so a
 * signature mismatch would only surface at first call; the typedef is
 * for clarity, not type safety.
 */
typedef int (*mlx5_vfmig_plugin_restore_vf_only_fn)(int image_dir_fd);

/* -------- CLI -------- */

static void usage(FILE *out, const char *argv0)
{
	fprintf(out,
		"Usage: %s -D <image-dir> [options]\n"
		"\n"
		"Options:\n"
		"  -D, --dir=DIR      CRIU image directory (mandatory). Must contain\n"
		"                     mlx5_vfmig.img and the per-VF SAVE_VHCA_STATE\n"
		"                     blob files written by criu dump.\n"
		"  -p, --plugin=PATH  Override the plugin .so path. Default:\n"
		"                     %s\n"
		"      --dry-run      Resolve the plugin .so + entry symbol and open\n"
		"                     the image dir but do NOT drive any restore work.\n"
		"  -h, --help         Show this help text and exit.\n"
		"\n"
		"Exit status: 0 on success, non-zero on any error.\n",
		argv0, DEFAULT_PLUGIN_PATH);
}

struct opts {
	const char *image_dir;
	const char *plugin_path;
	bool dry_run;
	bool show_help;
};

static int parse_args(int argc, char **argv, struct opts *o)
{
	static const struct option long_opts[] = {
		{ "dir", required_argument, NULL, 'D' },
		{ "plugin", required_argument, NULL, 'p' },
		{ "dry-run", no_argument, NULL, 1 },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	int c;

	memset(o, 0, sizeof(*o));
	o->plugin_path = DEFAULT_PLUGIN_PATH;

	while ((c = getopt_long(argc, argv, "D:p:h", long_opts, NULL)) != -1) {
		switch (c) {
		case 'D':
			o->image_dir = optarg;
			break;
		case 'p':
			o->plugin_path = optarg;
			break;
		case 1:
			o->dry_run = true;
			break;
		case 'h':
			o->show_help = true;
			return 0;
		default:
			return -1;
		}
	}
	if (optind != argc) {
		fprintf(stderr, "mlx5_vfmig_restore_vf: stray positional argument '%s'\n", argv[optind]);
		return -1;
	}
	if (!o->image_dir) {
		fprintf(stderr, "mlx5_vfmig_restore_vf: missing -D <image-dir>\n");
		return -1;
	}
	return 0;
}

/* -------- main -------- */

int main(int argc, char **argv)
{
	struct opts o;
	void *plugin_handle = NULL;
	mlx5_vfmig_plugin_restore_vf_only_fn entry = NULL;
	int image_dir_fd = -1;
	int rc = 1;
	struct stat st;

	if (parse_args(argc, argv, &o) < 0) {
		usage(stderr, argv[0]);
		return 2;
	}
	if (o.show_help) {
		usage(stdout, argv[0]);
		return 0;
	}

	/*
	 * Open the image dir before touching the plugin -- a typo in -D is
	 * the most common failure and it is pointless to load the .so just
	 * to fail seconds later.
	 */
	image_dir_fd = open(o.image_dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (image_dir_fd < 0) {
		fprintf(stderr, "mlx5_vfmig_restore_vf: open(%s, O_PATH|O_DIRECTORY): %s\n", o.image_dir,
			strerror(errno));
		return 1;
	}
	if (fstat(image_dir_fd, &st) < 0 || !S_ISDIR(st.st_mode)) {
		fprintf(stderr, "mlx5_vfmig_restore_vf: -D %s is not a directory\n", o.image_dir);
		goto out;
	}

	/*
	 * RTLD_NOW: bind every undefined symbol immediately and fail loudly
	 * if our shim set is incomplete, rather than SIGSEGV later from
	 * inside a plugin log call on some error path. RTLD_GLOBAL is
	 * unnecessary: the plugin's outgoing references resolve against the
	 * executable's symbols, made visible via -rdynamic.
	 */
	plugin_handle = dlopen(o.plugin_path, RTLD_NOW);
	if (!plugin_handle) {
		fprintf(stderr, "mlx5_vfmig_restore_vf: dlopen(%s): %s\n", o.plugin_path, dlerror());
		goto out;
	}

	dlerror();
	entry = (mlx5_vfmig_plugin_restore_vf_only_fn)dlsym(plugin_handle, "mlx5_vfmig_plugin_restore_vf_only");
	if (!entry) {
		const char *e = dlerror();

		fprintf(stderr, "mlx5_vfmig_restore_vf: dlsym(%s, mlx5_vfmig_plugin_restore_vf_only): %s\n",
			o.plugin_path, e ? e : "(no error reported, symbol is NULL)");
		goto out;
	}

	if (o.dry_run) {
		fprintf(stderr,
			"mlx5_vfmig_restore_vf: --dry-run: plugin %s resolved, image dir %s opened "
			"(image_dir_fd=%d), entry symbol resolved; not calling.\n",
			o.plugin_path, o.image_dir, image_dir_fd);
		rc = 0;
		goto out;
	}

	fprintf(stderr, "mlx5_vfmig_restore_vf: starting: image_dir=%s plugin=%s\n", o.image_dir, o.plugin_path);
	rc = entry(image_dir_fd);
	if (rc) {
		fprintf(stderr,
			"mlx5_vfmig_restore_vf: FAILED (plugin returned %d); check dmesg and the plugin "
			"diagnostics on stderr above.\n",
			rc);
		rc = 1;
		goto out;
	}
	fprintf(stderr, "mlx5_vfmig_restore_vf: complete for image_dir=%s\n", o.image_dir);
	rc = 0;

out:
	if (plugin_handle)
		dlclose(plugin_handle);
	if (image_dir_fd >= 0)
		close(image_dir_fd);
	return rc;
}
