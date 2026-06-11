/*
 * mlx5_vfmig_restore_vf -- standalone prerestore tool for the
 * rdma_mlx5_vfmig_plugin.
 *
 * Drives the destination LOAD_VHCA_STATE + driver_override + bind
 * dance for every VF in a CRIU dump (via the plugin's exported
 * mlx5_vfmig_plugin_restore_vf_only() entry point) so the
 * destination VFs are bound and ibdev / uverbs cdev are visible
 * before `criu restore` runs against the same dump. This gives
 * the orchestrator a clean, operator-orderable pause point at
 * which to perform host-level setup that the in-process restore
 * path can't: setting per-VF MAC addresses on the bound netdev,
 * pinning ARP entries before the workload's first post_send, etc.
 *
 * See tools/testing/mlx5_vfmig/design/vf_prerestore_split.md §6.1
 * for the architectural rationale and §3 / §6.3 for the soft-
 * fallback contract that lets `criu restore` later detect this
 * pre-binding and skip its own LOAD/bind path.
 *
 * Usage:
 *   mlx5_vfmig_restore_vf -D <image-dir> [--dry-run] [--vfs UUID,UUID,...]
 *                         [--plugin /path/to/rdma_mlx5_vfmig_plugin.so]
 *                         [-v] [--help]
 *
 * The tool dlopens the plugin .so, dlsyms the prerestore entry
 * point, and hands it an O_PATH fd on the image directory. The
 * plugin's existing read-image / KS7.3 discovery / LOAD / bind /
 * ibdev-resolution logic does the rest. No state is persisted
 * across runs; the binary exits as soon as the symbol returns.
 *
 * Stand-alone runtime: the plugin .so references a handful of
 * criu-binary internal symbols (print_on_level, criu_get_image_dir,
 * log_get_loglevel) that the criu binary normally provides via
 * --export-dynamic. We provide minimal shims here so the plugin
 * resolves cleanly under our own dlopen and routes diagnostics to
 * stderr instead of criu's logfile.
 */

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Mirror criu/include/log.h's level constants so the shims agree. */
#define LOG_MSG   0
#define LOG_ERROR 1
#define LOG_WARN  2
#define LOG_INFO  3
#define LOG_DEBUG 4

/*
 * Default plugin install path: matches PLUGINDIR in the criu
 * Makefile (/usr/local/lib/criu when building from source with the
 * default PREFIX=/usr/local). Overridable via --plugin.
 */
#define DEFAULT_PLUGIN_PATH "/usr/local/lib/criu/rdma_mlx5_vfmig_plugin.so"

/*
 * The signature has to match exactly what's exported from the
 * plugin .so (see vfmig_restore.c). dlsym binds against the .so's
 * actual entry, so a mismatch would be caught at first call -- we
 * keep a typedef here for clarity, not type safety.
 */
typedef int (*mlx5_vfmig_plugin_restore_vf_only_fn)(int image_dir_fd);

static unsigned int g_loglevel = LOG_INFO;

/* -------- shims for plugin .so symbol resolution -------- */

/*
 * print_on_level -- the plugin's pr_err / pr_info / pr_perror
 * macros expand to print_on_level(LOG_*, fmt, ...). criu's binary
 * normally implements this; we route to stderr at our own loglevel.
 *
 * Public visibility (default) is required so the plugin's
 * dlopen()'d symbol resolution can find it; we link the binary
 * with -rdynamic in the Makefile to make sure the dynamic linker
 * exposes the binary's symbols to RTLD_LAZY-resolved references
 * from the plugin .so.
 */
__attribute__((visibility("default")))
void print_on_level(unsigned int level, const char *fmt, ...)
{
	va_list ap;

	if (level > g_loglevel && level != LOG_MSG)
		return;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

/*
 * log_get_loglevel -- the plugin's pr_quelled() helper checks
 * this. Returning our own loglevel keeps debug-vs-info gating
 * consistent across binary + plugin diagnostics.
 */
__attribute__((visibility("default")))
unsigned int log_get_loglevel(void)
{
	return g_loglevel;
}

/*
 * criu_get_image_dir -- inside the criu binary this returns
 * get_service_fd(IMG_FD_OFF). When we drive the plugin from this
 * binary, we always set the override-fd via
 * vfmig_set_image_dir_override() before calling the entry symbol,
 * so vfmig_get_image_dir() never falls back to this path. The
 * shim is here only to satisfy the dynamic linker.
 */
__attribute__((visibility("default")))
int criu_get_image_dir(void)
{
	fprintf(stderr,
		"mlx5_vfmig_restore_vf: BUG: criu_get_image_dir() called "
		"on the standalone-binary path -- the override-fd "
		"plumbing in vf_image.c should have intercepted this.\n");
	return -1;
}

/*
 * The plugin .so also references criu/rdma/netlink.c helpers that
 * only get hit on the dump path (vfmig_dump.c's NLDEV iteration to
 * pin source-side devx_uid). The prerestore symbol's call graph
 * never reaches them, but RTLD_NOW resolves every undefined symbol
 * at dlopen() time, so we'd fail to load the .so without these
 * stubs. They abort if accidentally called -- a calling-binary
 * bug in any future code path that pulls in dump logic.
 *
 * Signatures lifted from criu/criu/include/rdma_netlink.h. The
 * typedef forward-declarations let us match the exported
 * function prototypes without dragging the entire criu header
 * into the binary's include set.
 */

struct rdma_nl_res_entry;

typedef int (*rdma_nl_ibdev_cb_t)(uint32_t dev_index, const char *ibdev,
				  void *arg);
typedef int (*rdma_nl_res_cb_t)(const struct rdma_nl_res_entry *e,
				void *arg);

__attribute__((visibility("default")))
int rdma_nl_for_each_ibdev(rdma_nl_ibdev_cb_t cb, void *arg)
{
	(void)cb;
	(void)arg;
	fprintf(stderr,
		"mlx5_vfmig_restore_vf: BUG: rdma_nl_for_each_ibdev() "
		"called on the standalone-binary path -- this is a "
		"dump-side helper, the prerestore call graph should "
		"never reach it.\n");
	return -1;
}

__attribute__((visibility("default")))
int rdma_nl_for_each_resource(uint32_t dev_index, const char *ibdev,
			      int type, rdma_nl_res_cb_t cb, void *arg)
{
	(void)dev_index;
	(void)ibdev;
	(void)type;
	(void)cb;
	(void)arg;
	fprintf(stderr,
		"mlx5_vfmig_restore_vf: BUG: rdma_nl_for_each_resource()"
		" called on the standalone-binary path -- this is a "
		"dump-side helper, the prerestore call graph should "
		"never reach it.\n");
	return -1;
}

/* -------- CLI -------- */

static void usage(FILE *out, const char *argv0)
{
	fprintf(out,
"Usage: %s -D <image-dir> [options]\n"
"\n"
"Options:\n"
"  -D, --dir=DIR        CRIU image directory (mandatory). Must contain\n"
"                       mlx5_vfmig.img and the per-VF SAVE_VHCA_STATE\n"
"                       blob files written by criu dump.\n"
"  -p, --plugin=PATH    Override the plugin .so path. Default:\n"
"                       %s\n"
"      --vfs=LIST       Comma-separated list of vf_uuid values to\n"
"                       restrict the prerestore to. Reserved for\n"
"                       future use; passing this currently fails\n"
"                       with a clear error -- the plugin's exported\n"
"                       entry point doesn't yet accept a filter.\n"
"      --dry-run        Resolve the plugin .so + entry symbol and\n"
"                       open the image dir but DON'T drive any\n"
"                       LOAD_VHCA_STATE / bind work. Useful for CI.\n"
"  -v, --verbose        Increase log verbosity (repeat for debug).\n"
"  -q, --quiet          Decrease log verbosity (errors only).\n"
"  -h, --help           Show this help text and exit.\n"
"\n"
"Exit status: 0 on success (every VF in the image is now bound and\n"
"ibdev-up on this host), non-zero on any error.\n"
"\n"
"See tools/testing/mlx5_vfmig/design/vf_prerestore_split.md §6.1 for\n"
"the architectural rationale.\n",
		argv0, DEFAULT_PLUGIN_PATH);
}

struct opts {
	const char *image_dir;
	const char *plugin_path;
	const char *vfs_list;
	bool dry_run;
	bool show_help;
};

static int parse_args(int argc, char **argv, struct opts *o)
{
	static const struct option long_opts[] = {
		{ "dir",     required_argument, NULL, 'D' },
		{ "plugin",  required_argument, NULL, 'p' },
		{ "vfs",     required_argument, NULL,  1  },
		{ "dry-run", no_argument,       NULL,  2  },
		{ "verbose", no_argument,       NULL, 'v' },
		{ "quiet",   no_argument,       NULL, 'q' },
		{ "help",    no_argument,       NULL, 'h' },
		{ NULL,      0,                 NULL,  0  },
	};
	int c;

	memset(o, 0, sizeof(*o));
	o->plugin_path = DEFAULT_PLUGIN_PATH;

	while ((c = getopt_long(argc, argv, "D:p:vqh",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'D':
			o->image_dir = optarg;
			break;
		case 'p':
			o->plugin_path = optarg;
			break;
		case 1:
			o->vfs_list = optarg;
			break;
		case 2:
			o->dry_run = true;
			break;
		case 'v':
			if (g_loglevel < LOG_DEBUG)
				g_loglevel++;
			break;
		case 'q':
			if (g_loglevel > LOG_ERROR)
				g_loglevel--;
			break;
		case 'h':
			o->show_help = true;
			return 0;
		default:
			return -1;
		}
	}
	if (optind != argc) {
		fprintf(stderr,
			"mlx5_vfmig_restore_vf: stray positional "
			"argument '%s'\n", argv[optind]);
		return -1;
	}
	if (!o->image_dir) {
		fprintf(stderr,
			"mlx5_vfmig_restore_vf: missing -D <image-dir>\n");
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

	if (o.vfs_list) {
		fprintf(stderr,
			"mlx5_vfmig_restore_vf: --vfs is reserved for a "
			"future plugin API extension; the plugin's "
			"current mlx5_vfmig_plugin_restore_vf_only() "
			"entry point processes every VF in the image. "
			"Drop --vfs to proceed against the whole "
			"image, or wait for the filter API to land.\n");
		return 2;
	}

	/*
	 * Open the image dir before touching the plugin -- a typo in
	 * -D is the most common failure and it's pointless to load
	 * the .so just to fail seconds later.
	 */
	image_dir_fd = open(o.image_dir,
			    O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (image_dir_fd < 0) {
		fprintf(stderr,
			"mlx5_vfmig_restore_vf: open(%s, O_PATH|"
			"O_DIRECTORY): %s\n", o.image_dir,
			strerror(errno));
		return 1;
	}
	if (fstat(image_dir_fd, &st) < 0 || !S_ISDIR(st.st_mode)) {
		fprintf(stderr,
			"mlx5_vfmig_restore_vf: -D %s is not a "
			"directory\n", o.image_dir);
		goto out;
	}

	/*
	 * RTLD_NOW: bind every undefined symbol immediately and fail
	 * loudly if our shim set is incomplete. RTLD_LAZY would let
	 * us load the .so successfully and SIGSEGV later from inside
	 * a pr_err() call on the error path -- much harder to
	 * diagnose. RTLD_GLOBAL is unnecessary: the plugin's
	 * outgoing symbol references resolve against the executable's
	 * already-globally-visible symbol set (made visible via
	 * -rdynamic in the Makefile).
	 */
	plugin_handle = dlopen(o.plugin_path, RTLD_NOW);
	if (!plugin_handle) {
		fprintf(stderr,
			"mlx5_vfmig_restore_vf: dlopen(%s): %s\n",
			o.plugin_path, dlerror());
		goto out;
	}

	dlerror();
	entry = (mlx5_vfmig_plugin_restore_vf_only_fn)
		dlsym(plugin_handle, "mlx5_vfmig_plugin_restore_vf_only");
	if (!entry) {
		const char *e = dlerror();

		fprintf(stderr,
			"mlx5_vfmig_restore_vf: dlsym(%s, "
			"mlx5_vfmig_plugin_restore_vf_only): %s\n",
			o.plugin_path,
			e ? e : "(no error reported, symbol is NULL)");
		goto out;
	}

	if (o.dry_run) {
		fprintf(stderr,
			"mlx5_vfmig_restore_vf: --dry-run: plugin %s "
			"resolved, image dir %s opened "
			"(image_dir_fd=%d), entry symbol "
			"mlx5_vfmig_plugin_restore_vf_only=%p; not "
			"calling.\n",
			o.plugin_path, o.image_dir, image_dir_fd,
			(void *)entry);
		rc = 0;
		goto out;
	}

	fprintf(stderr,
		"mlx5_vfmig_restore_vf: prerestore starting: "
		"image_dir=%s plugin=%s\n",
		o.image_dir, o.plugin_path);
	rc = entry(image_dir_fd);
	if (rc) {
		fprintf(stderr,
			"mlx5_vfmig_restore_vf: prerestore FAILED "
			"(plugin returned %d); destination VFs may "
			"be in a partially-loaded state -- check "
			"dmesg and the plugin diagnostics on stderr "
			"above. Re-run after fixing the underlying "
			"issue, or fall back to letting `criu "
			"restore` drive the LOAD inline (the plugin's "
			"soft-fallback path).\n", rc);
		rc = 1;
		goto out;
	}
	fprintf(stderr,
		"mlx5_vfmig_restore_vf: prerestore complete; "
		"destination VFs are bound and ibdev-up. Operator "
		"may now run host-level setup (ip neigh, ip addr, "
		"...) before `criu restore -D %s ...`.\n",
		o.image_dir);
	rc = 0;

out:
	if (plugin_handle)
		dlclose(plugin_handle);
	if (image_dir_fd >= 0)
		close(image_dir_fd);
	return rc;
}
