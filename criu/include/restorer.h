#ifndef __CR_RESTORER_H__
#define __CR_RESTORER_H__

#include <signal.h>
#include <limits.h>
#include <sys/resource.h>
#include <linux/filter.h>

#include "common/config.h"
#include "types.h"
#include "int.h"
#include "types.h"
#include "common/compiler.h"
#include <compel/asm/fpu.h>
#include "common/lock.h"
#include "util.h"
#include "asm/restorer.h"
#include "posix-timer.h"
#include "timerfd.h"
#include "shmem.h"
#include "parasite-vdso.h"
#include "fault-injection.h"

#include <time.h>

#include "images/mm.pb-c.h"

/*
 * These *must* be power of two values.
 */
#define RESTORE_ARGS_SIZE     (512)
#define RESTORE_STACK_REDZONE (128)
#define RESTORE_STACK_SIZE    (KILO(32))

struct restore_mem_zone {
	u8 redzone[RESTORE_STACK_REDZONE];
	u8 stack[RESTORE_STACK_SIZE];
	u8 rt_sigframe[RESTORE_STACK_SIGFRAME];
} __stack_aligned__;

struct rst_sched_param {
	int policy;
	int nice;
	int prio;
};

struct rst_rseq_param {
	u64 rseq_abi_pointer;
	u32 rseq_abi_size;
	u32 signature;
};

struct restore_posix_timer {
	struct str_posix_timer spt;
	struct itimerspec val;
	int overrun;
};

#ifndef rst_shstk_info
struct rst_shstk_info {};
#endif

/*
 * We should be able to construct fpu sigframe in sigreturn_prep_fpu_frame,
 * so the mem_zone.rt_sigframe should be 64-bytes aligned. To make things
 * simpler, force both _args alignment be 64 bytes.
 */

struct thread_creds_args {
	CredsEntry creds;

	unsigned int cap_last_cap;

	u32 cap_inh[CR_CAP_SIZE];
	u32 cap_prm[CR_CAP_SIZE];
	u32 cap_eff[CR_CAP_SIZE];
	u32 cap_bnd[CR_CAP_SIZE];
	u32 cap_amb[CR_CAP_SIZE];

	char *lsm_profile;
	unsigned int *groups;
	char *lsm_sockcreate;

	unsigned long mem_lsm_profile_pos;
	unsigned long mem_lsm_sockcreate_pos;
	unsigned long mem_groups_pos;

	unsigned long mem_pos_next;
};

struct thread_seccomp_filter {
	struct sock_fprog sock_fprog;
	unsigned int flags;
};

struct thread_restore_args {
	struct restore_mem_zone *mz;

	int pid;
	UserRegsEntry gpregs;
	u64 clear_tid_addr;

	u64 futex_rla;
	u32 futex_rla_len;

	struct rst_sched_param sp;

	struct task_restore_args *ta;

	tls_t tls;
	struct rst_rseq_param rseq;

	siginfo_t *siginfo;
	unsigned int siginfo_n;

	int pdeath_sig;
	bool has_timerslack_ns;
	unsigned long timerslack_ns;

	struct thread_creds_args *creds_args;

	int seccomp_mode;
	unsigned long seccomp_filters_pos;
	struct thread_seccomp_filter *seccomp_filters;
	void *seccomp_filters_data;
	unsigned int seccomp_filters_n;
	bool seccomp_force_tsync;

	struct rst_shstk_info shstk;

	char comm[TASK_COMM_LEN];
	int cg_set;
	int cgroupd_sk;
} __aligned(64);

typedef long (*thread_restore_fcall_t)(struct thread_restore_args *args);

struct restore_vma_io {
	int nr_iovs;
	loff_t off;
	struct iovec iovs[0];
};

#define RIO_SIZE(niovs) (sizeof(struct restore_vma_io) + (niovs) * sizeof(struct iovec))

/*
 * Per-MR record consumed by the pie restorer to issue
 * UVERBS_METHOD_RESTORE_MR after the user VMAs have been laid out at
 * their original VAs by the restorer blob (see restore_rdma_mr in
 * criu/pie/restorer.c).
 *
 * Why this can't run from CRIU master (criu/rdma/uobj_restore.c, where
 * PDs are restored): rxe's restore_mr ends up in ib_umem_get ->
 * pin_user_pages_fast(addr, ...) against current->mm. Simple anon-
 * private VMAs are not premapped at their original VA by master's
 * prepare_mappings -- their content sits in vma_io until the pie blob
 * mmaps them at sigreturn_restore time -- so issuing RESTORE_MR earlier
 * returns -EFAULT. Deferring to the pie, after VMAs are in place, is
 * the fix.
 *
 * Field semantics mirror the pie encoder's wire-format contract: attrs
 * whose declared len <= sizeof(u64) pass their value inline in
 * attr->data, not a pointer to it.
 *
 * @cmd_fd is a per-MR high-fd dup of the destination ucontext's uverbs
 * cdev (rdma_prepare_rdma_mrs reserves it via fcntl(F_DUPFD_CLOEXEC,
 * 1 << 14) to stay above the user-fd range the per-task file restorer
 * needs and below service_fd_base). The pie helper closes it after the
 * ioctl so it does not leak into the restored task's fd table.
 *
 * rxe MR carries no driver-private UHW, so v0 has no plugin blob here;
 * mlx5's FW mkey_index UHW plugs in via its own hook in a later
 * milestone.
 */
/*
 * Upper bound on the driver-private UHW_IN a plugin's
 * RDMA_RESTORE_UOBJ_MR_UHW_PACK hook may stage for the pie's
 * RESTORE_MR. The bytes are packed master-side (plugins are gone by
 * pie time) and copied inline into the RM_PRIVATE args, so the buffer
 * is fixed-size rather than a pointer the pie could not dereference.
 * 24 covers mlx5's 16-byte struct mlx5_ib_restore_mr_req with margin.
 */
#define RST_RDMA_MR_UHW_IN_MAX 24

struct rst_rdma_mr {
	int cmd_fd;
	u32 ufile_id; /* diagnostics only */
	u32 kernel_driver_id;
	u32 target_handle;
	u32 parent_pd_handle;
	u64 addr;
	u64 length;
	u64 iova;
	u32 access_flags;
	u32 lkey_hint;
	u32 rkey_hint;
	u32 uhw_in_len; /* 0 -> no UHW_IN attr (rxe) */
	u8 uhw_in_buf[RST_RDMA_MR_UHW_IN_MAX];
};

/*
 * Upper bound on the driver-private UHW_IN a pie-deferred CQ carries.
 * The owning plugin packs it master-side (mlx5: a 32-byte struct
 * mlx5_ib_restore_cq_req -- cqn, cqe_size, buf_addr, db_addr); 40 covers
 * it with margin. Bounds the master-side staging record queued by
 * uobj_prepare_cq() (criu/rdma/uobj_restore.c), and later the pie
 * carrier that ferries it to RESTORE_CQ.
 */
#define RST_RDMA_CQ_UHW_IN_MAX 40

/*
 * Per-CQ carrier the stager (rdma_prepare_rdma_cqs) fills and the pie
 * restorer drains to issue UVERBS_METHOD_RESTORE_CQ after the user VMAs
 * are laid out (see restore_rdma_cq in criu/pie/restorer.c). The CQ twin
 * of struct rst_rdma_mr: only the pie-deferred camp (mlx5, whose
 * RESTORE_CQ pins the source CQE-ring / doorbell pages from current->mm)
 * uses it; the master-side camp (rxe) never queues here. See
 * CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_CQ_NEEDS_PIE for the split.
 *
 * @cmd_fd is a per-CQ high-fd dup of the ucontext cdev (reserved the
 * same way as struct rst_rdma_mr::cmd_fd); the pie closes it after the
 * ioctl. The driver-private UHW_IN is packed master-side by the owning
 * plugin's RDMA_RESTORE_UOBJ_CQ_UHW_PACK hook and carried inline.
 */
struct rst_rdma_cq {
	int cmd_fd;
	u32 ufile_id; /* diagnostics only */
	u32 kernel_driver_id;
	u32 target_handle;
	u32 cqe;
	u32 comp_vector;
	u32 flags;
	u32 uhw_in_len; /* 0 -> no UHW_IN attr */
	u8 uhw_in_buf[RST_RDMA_CQ_UHW_IN_MAX];
};

struct task_restore_args {
	struct thread_restore_args *t; /* thread group leader */

	int fd_exe_link; /* opened self->exe file */
	int logfd;
	unsigned int loglevel;
	struct timeval logstart;

	int uffd;
	bool thp_disabled;

	/* threads restoration */
	int nr_threads;				 /* number of threads */
	thread_restore_fcall_t clone_restore_fn; /* helper address for clone() call */
	struct thread_restore_args *thread_args; /* array of thread arguments */
	struct task_entries *task_entries;
	void *rst_mem;
	unsigned long rst_mem_size;

	/* Below arrays get remapped from RM_PRIVATE in sigreturn_restore */
	VmaEntry *vmas;
	unsigned int vmas_n;

	int vma_ios_fd;
	struct restore_vma_io *vma_ios;
	unsigned int vma_ios_n;

	struct restore_posix_timer *posix_timers;
	unsigned int posix_timers_n;
	bool posix_timer_cr_ids;

	struct restore_timerfd *timerfd;
	unsigned int timerfd_n;

	siginfo_t *siginfo;
	unsigned int siginfo_n;

	struct rst_tcp_sock *tcp_socks;
	unsigned int tcp_socks_n;

	struct rst_aio_ring *rings;
	unsigned int rings_n;

	struct rst_rdma_cq *rdma_cqs;
	unsigned int rdma_cqs_n;

	struct rst_rdma_mr *rdma_mrs;
	unsigned int rdma_mrs_n;

	struct rlimit64 *rlims;
	unsigned int rlims_n;

	pid_t *helpers /* the TASK_HELPERS to wait on at the end of restore */;
	unsigned int helpers_n;

	pid_t *zombies;
	unsigned int zombies_n;

	int *inotify_fds; /* fds to cleanup inotify events at CR_STATE_RESTORE_SIGCHLD stage */
	unsigned int inotify_fds_n;

	/* * * * * * * * * * * * * * * * * * * * */

	unsigned long task_size;
	unsigned long premmapped_addr;
	unsigned long premmapped_len;
	rt_sigaction_t sigchld_act;

	void *bootstrap_start;
	unsigned long bootstrap_len;

	struct itimerval itimers[3];

	MmEntry mm;
	auxv_t mm_saved_auxv[AT_VECTOR_SIZE];
	u32 mm_saved_auxv_size;
	char comm[TASK_COMM_LEN];

	/*
	 * proc_fd is a handle to /proc that the restorer blob can use to open
	 * files there, because some of them can't be opened before the
	 * restorer blob is called.
	 */
	int proc_fd;

	int seccomp_mode;

	bool compatible_mode;

	bool can_map_vdso;
	bool auto_dedup;
	unsigned long vdso_rt_size;
	struct vdso_maps vdso_maps_rt;	 /* runtime vdso symbols */
	unsigned long vdso_rt_parked_at; /* safe place to keep vdso */

	enum faults fault_strategy;
#ifdef ARCH_HAS_LONG_PAGES
	unsigned page_size;
#endif
	int lsm_type;
	int child_subreaper;
	int membarrier_registration_mask;
	bool has_clone3_set_tid;

	/*
	 * info about rseq from libc used to
	 * unregister it before memory restoration procedure
	 */
	struct rst_rseq_param libc_rseq;

	uid_t uid;
	u32 cap_eff[CR_CAP_SIZE];

	struct rst_shstk_info shstk;
} __aligned(64);

/*
 * For arm64 stack needs to aligned to 16 bytes.
 * Hence align to 16 bytes for all
*/
#define RESTORE_ALIGN_STACK(start, size) (ALIGN((start) + (size)-16, 16))

static inline unsigned long restorer_stack(struct restore_mem_zone *mz)
{
	return RESTORE_ALIGN_STACK((long)&mz->stack, RESTORE_STACK_SIZE);
}

enum {
	/*
	 * Restore stages. The stage is started by criu process, then
	 * confirmed by all tasks involved in it. Then criu does some
	 * actions and starts the next stage.
	 *
	 * The first stated stage is CR_STATE_ROOT_TASK which is started
	 * right before calling fork_with_pid() for the root_item.
	 */
	CR_STATE_FAIL = -1,
	/*
	 * Root task is created and does some pre-checks.
	 * After the stage ACT_SETUP_NS scripts are performed.
	 */
	CR_STATE_ROOT_TASK = 0,
	/*
	 * The prepare_namespace() is called.
	 * After the stage criu opens root task's mntns and
	 * calls ACT_POST_SETUP_NS scripts.
	 */
	CR_STATE_PREPARE_NAMESPACES,
	/*
	 * All tasks fork and call open_transport_socket().
	 * Stage is needed to make sure they all have the socket.
	 * Also this stage is a sync point after which the
	 * fini_restore_mntns() can be called.
	 *
	 * This stage is a little bit special. Normally all stages
	 * are controlled by criu process, but when this stage
	 * starts criu process starts waiting for the tasks to
	 * finish it, but by the time it gets woken up the stage
	 * finished is CR_STATE_RESTORE. The forking stage is
	 * barrier-ed by the root task, this task is also the one
	 * that switches the stage (into restoring).
	 *
	 * The above is done to lower the amount of context
	 * switches from root task to criu and back, since the
	 * separate forking stage is not needed by criu, it's
	 * purely to make sure all tasks be in sync.
	 */
	CR_STATE_FORKING,
	/*
	 * Main restore stage. By the end of it all tasks are
	 * almost ready and what's left is:
	 *   pick up zombies and helpers
	 *   restore sigchild handlers used to detect restore errors
	 *   restore credentials, seccomp, dumpable and pdeath_sig
	 */
	CR_STATE_RESTORE,
	/*
	 * Tasks restore sigchild handlers.
	 * Stage is needed to synchronize the change in error
	 * propagation via sigchild.
	 */
	CR_STATE_RESTORE_SIGCHLD,
	/*
	 * Final stage.
	 * For security reason processes can be resumed only when all
	 * credentials are restored. Otherwise someone can attach to a
	 * process, which are not restored credentials yet and execute
	 * some code.
	 * Seccomp needs to be restored after creds.
	 * Dumpable and pdeath signal are restored after seccomp.
	 */
	CR_STATE_RESTORE_CREDS,
	CR_STATE_COMPLETE
};

#define restore_finish_stage(__v, __stage)                  \
	({                                                  \
		futex_dec_and_wake(&(__v)->nr_in_progress); \
		futex_wait_while(&(__v)->start, __stage);   \
		(s32) futex_get(&(__v)->start);             \
	})

#define __r_sym(name)		  restorer_sym##name
#define restorer_sym(rblob, name) (void *)(rblob + __r_sym(name))

#ifndef arch_shstk_switch_to_restorer
static inline int arch_shstk_switch_to_restorer(struct rst_shstk_info *shstk)
{
	return 0;
}
#define arch_shstk_switch_to_restorer arch_shstk_switch_to_restorer
#endif

#ifndef arch_shstk_restore
static inline int arch_shstk_restore(struct rst_shstk_info *shstk)
{
	return 0;
}
#define arch_shstk_restore arch_shstk_restore
#endif

#ifndef shstk_vma_restore
static always_inline int shstk_vma_restore(VmaEntry *vma_entry)
{
	return -1;
}
#endif

#endif /* __CR_RESTORER_H__ */
