#include <stdio.h>
#include <stdlib.h>

#include <linux/securebits.h>
#include <linux/capability.h>
#include <linux/aio_abi.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <sys/resource.h>
#include <signal.h>
#include <sys/inotify.h>
#include <sys/socket.h>

#include "linux/userfaultfd.h"

#include "common/config.h"
#include "int.h"
#include "types.h"
#include "common/compiler.h"
#include <compel/plugins/std/syscall.h>
#include <compel/plugins/std/log.h>
#include <compel/ksigset.h>
#include "mman.h"
#include "signal.h"
#include "prctl.h"
#include "criu-log.h"
#include "util.h"
#include "image.h"
#include "sk-inet.h"
#include "vma.h"
#include "uffd.h"
#include "sched.h"

#include "common/lock.h"
#include "common/page.h"
#include "restorer.h"
#include "aio.h"
#include "seccomp.h"

#include "images/creds.pb-c.h"
#include "images/mm.pb-c.h"
#include "images/inventory.pb-c.h"

#include "shmem.h"

/*
 * sys_getgroups() buffer size. Not too much, to avoid stack overflow.
 */
#define MAX_GETGROUPS_CHECKED (512 / sizeof(unsigned int))

/*
 * Memory overhead limit for reading VMA when auto_dedup is enabled.
 * An arbitrarily chosen trade-off point between speed and memory usage.
 */
#define AUTO_DEDUP_OVERHEAD_BYTES (128 << 20)

#ifndef PR_SET_PDEATHSIG
#define PR_SET_PDEATHSIG 1
#endif

#ifndef PR_SET_CHILD_SUBREAPER
#define PR_SET_CHILD_SUBREAPER 36
#endif

#ifndef FALLOC_FL_KEEP_SIZE
#define FALLOC_FL_KEEP_SIZE 0x01
#endif

#ifndef FALLOC_FL_PUNCH_HOLE
#define FALLOC_FL_PUNCH_HOLE 0x02
#endif

#ifndef ARCH_RT_SIGRETURN_RST
#define ARCH_RT_SIGRETURN_RST ARCH_RT_SIGRETURN
#endif

#define sys_prctl_safe(opcode, val1, val2, val3)                                \
	({                                                                      \
		long __ret = sys_prctl(opcode, val1, val2, val3, 0);            \
		if (__ret)                                                      \
			pr_err("prctl failed @%d with %ld\n", __LINE__, __ret); \
		__ret;                                                          \
	})

static struct task_entries *task_entries_local;

static atomic_t thread_inprogress;
static void *rst_mem;
static long rst_mem_size;

static pid_t *helpers;
static int n_helpers;
static pid_t *zombies;
static int n_zombies;

static enum faults fi_strategy;
bool fault_injected(enum faults f)
{
	return __fault_injected(f, fi_strategy);
}

#ifdef ARCH_HAS_LONG_PAGES
/*
 * XXX: Make it compel's std plugin global variable. Drop parasite_size().
 * Hint: compel on aarch64 shall learn relocs for that.
 */
static unsigned __page_size;
unsigned long page_size(void)
{
	return __page_size;
}
#endif

/*
 * These are stubs for std compel plugin.
 */
int parasite_daemon_cmd(int cmd, void *args)
{
	return 0;
}

int parasite_trap_cmd(int cmd, void *args)
{
	return 0;
}

void parasite_cleanup(void)
{
}

extern void cr_restore_rt(void) asm("__cr_restore_rt") __attribute__((visibility("hidden")));

static void sigchld_handler(int signal, siginfo_t *siginfo, void *data)
{
	char *r;
	int i;

	/* We can ignore helpers that die, we expect them to after
	 * CR_STATE_RESTORE is finished. */
	for (i = 0; i < n_helpers; i++)
		if (siginfo->si_pid == helpers[i])
			return;

	for (i = 0; i < n_zombies; i++)
		if (siginfo->si_pid == zombies[i])
			return;

	if (siginfo->si_code == CLD_EXITED)
		r = "exited, status=";
	else if (siginfo->si_code == CLD_KILLED)
		r = "killed by signal";
	else if (siginfo->si_code == CLD_DUMPED)
		r = "terminated abnormally with";
	else if (siginfo->si_code == CLD_TRAPPED)
		r = "trapped with";
	else if (siginfo->si_code == CLD_STOPPED)
		r = "stopped with";
	else
		r = "disappeared with";

	pr_info("Task %d %s %d\n", siginfo->si_pid, r, siginfo->si_status);

	futex_abort_and_wake(&task_entries_local->nr_in_progress);
	/* sa_restorer may be unmaped, so we can't go back to userspace*/
	sys_kill(sys_getpid(), SIGSTOP);
	sys_exit_group(1);
}

static int lsm_set_label(char *label, char *type, int procfd)
{
	int ret = -1, len, lsmfd;
	char path[STD_LOG_SIMPLE_CHUNK];

	if (!label)
		return 0;

	pr_info("restoring lsm profile (%s) %s\n", type, label);

	std_sprintf(path, "self/task/%ld/attr/%s", sys_gettid(), type);

	lsmfd = sys_openat(procfd, path, O_WRONLY, 0);
	if (lsmfd < 0) {
		pr_err("failed openat %d\n", lsmfd);
		return -1;
	}

	for (len = 0; label[len]; len++)
		;

	ret = sys_write(lsmfd, label, len);
	sys_close(lsmfd);
	if (ret < 0) {
		pr_err("can't write lsm profile %d\n", ret);
		return -1;
	}

	return 0;
}

static int restore_creds(struct thread_creds_args *args, int procfd, int lsm_type, uid_t uid)
{
	CredsEntry *ce = &args->creds;
	int b, i, ret;
	struct cap_header hdr;
	struct cap_data data[_LINUX_CAPABILITY_U32S_3];
	int ruid, euid, suid, fsuid;
	int rgid, egid, sgid, fsgid;

	/*
	 * Setup supplementary group IDs early.
	 */
	if (args->groups) {
		/*
		 * We may be in an unprivileged user namespace where setgroups
		 * is disabled.  If the current list of groups is already what
		 * we want, skip the call to setgroups.
		 */
		unsigned int gids[MAX_GETGROUPS_CHECKED];
		int n = sys_getgroups(MAX_GETGROUPS_CHECKED, gids);
		if (n != ce->n_groups || memcmp(gids, args->groups, n * sizeof(*gids))) {
			ret = sys_setgroups(ce->n_groups, args->groups);
			if (ret) {
				pr_err("Can't setgroups([%zu gids]): %d\n", ce->n_groups, ret);
				return -1;
			}
		}
	}

	/*
	 * Compare xids with current values. If all match then we can skip
	 * setting them (which requires extra capabilities).
	 */
	fsuid = sys_setfsuid(-1);
	fsgid = sys_setfsgid(-1);
	if (sys_getresuid(&ruid, &euid, &suid) == 0 && sys_getresgid(&rgid, &egid, &sgid) == 0 && ruid == ce->uid &&
	    euid == ce->euid && suid == ce->suid && rgid == ce->gid && egid == ce->egid && sgid == ce->sgid &&
	    fsuid == ce->fsuid && fsgid == ce->fsgid) {
		goto skip_xids;
	}

	/*
	 * First -- set the SECURE_NO_SETUID_FIXUP bit not to
	 * lose caps bits when changing xids.
	 */

	if (!uid) {
		ret = sys_prctl(PR_SET_SECUREBITS, 1 << SECURE_NO_SETUID_FIXUP, 0, 0, 0);
		if (ret) {
			pr_err("Unable to set SECURE_NO_SETUID_FIXUP: %d\n", ret);
			return -1;
		}
	}

	/*
	 * Second -- restore xids. Since we still have the CAP_SETUID
	 * capability nothing should fail. But call the setfsXid last
	 * to override the setresXid settings.
	 */

	ret = sys_setresuid(ce->uid, ce->euid, ce->suid);
	if (ret) {
		pr_err("Unable to set real, effective and saved user ID: %d\n", ret);
		return -1;
	}

	sys_setfsuid(ce->fsuid);
	if (sys_setfsuid(-1) != ce->fsuid) {
		pr_err("Unable to set fsuid\n");
		return -1;
	}

	ret = sys_setresgid(ce->gid, ce->egid, ce->sgid);
	if (ret) {
		pr_err("Unable to set real, effective and saved group ID: %d\n", ret);
		return -1;
	}

	sys_setfsgid(ce->fsgid);
	if (sys_setfsgid(-1) != ce->fsgid) {
		pr_err("Unable to set fsgid\n");
		return -1;
	}

skip_xids:
	/*
	 * Third -- restore securebits. We don't need them in any
	 * special state any longer.
	 */

	if (sys_prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) != ce->secbits) {
		ret = sys_prctl(PR_SET_SECUREBITS, ce->secbits, 0, 0, 0);
		if (ret) {
			pr_err("Unable to set PR_SET_SECUREBITS: %d\n", ret);
			return -1;
		}
	}

	/*
	 * Fourth -- trim bset. This can only be done while
	 * having the CAP_SETPCAP capability.
	 */

	for (b = 0; b < CR_CAP_SIZE; b++) {
		for (i = 0; i < 32; i++) {
			if (b * 32 + i > args->cap_last_cap)
				break;
			if (args->cap_bnd[b] & (1 << i))
				/* already set */
				continue;
			ret = sys_prctl(PR_CAPBSET_DROP, i + b * 32, 0, 0, 0);
			if (!ret)
				continue;
			if (!ce->has_no_new_privs || !ce->no_new_privs || args->cap_prm[b] & (1 << i)) {
				pr_err("Unable to drop capability %d: %d\n", i + b * 32, ret);
				return -1;
			}
			/*
			 * If prctl(NO_NEW_PRIVS) is going to be set then it
			 * will prevent inheriting the capabilities not in
			 * the permitted set.
			 */
			pr_warn("Unable to drop capability %d from bset: %d (but NO_NEW_PRIVS will drop it)\n", i + b * 32, ret);
		}
	}

	/*
	 * Fifth -- restore caps. Nothing but cap bits are changed
	 * at this stage, so just do it.
	 */

	hdr.version = _LINUX_CAPABILITY_VERSION_3;
	hdr.pid = 0;

	BUILD_BUG_ON(_LINUX_CAPABILITY_U32S_3 != CR_CAP_SIZE);

	for (i = 0; i < CR_CAP_SIZE; i++) {
		data[i].eff = args->cap_eff[i];
		data[i].prm = args->cap_prm[i];
		data[i].inh = args->cap_inh[i];
	}

	ret = sys_capset(&hdr, data);
	if (ret) {
		pr_err("Unable to restore capabilities: %d\n", ret);
		return -1;
	}

	for (b = 0; b < CR_CAP_SIZE; b++) {
		for (i = 0; i < 32; i++) {
			if (b * 32 + i > args->cap_last_cap)
				break;
			if ((args->cap_amb[b] & (1 << i)) == 0)
				/* don't set */
				continue;
			ret = sys_prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, i + b * 32, 0, 0);
			if (!ret)
				continue;
			pr_err("Unable to raise ambient capability %d: %d\n", i + b * 32, ret);
			return -1;
		}
	}


	if (lsm_type != LSMTYPE__SELINUX) {
		/*
		 * SELinux does not support setting the process context for
		 * threaded processes. So this is skipped if running with
		 * SELinux and instead the process context is set before the
		 * threads are created.
		 */
		if (lsm_set_label(args->lsm_profile, "current", procfd) < 0)
			return -1;
	}

	/* Also set the sockcreate label for all threads */
	if (lsm_set_label(args->lsm_sockcreate, "sockcreate", procfd) < 0)
		return -1;

	if (ce->has_no_new_privs && ce->no_new_privs) {
		ret = sys_prctl(PR_SET_NO_NEW_PRIVS, ce->no_new_privs, 0, 0, 0);
		if (ret) {
			pr_err("Unable to set no_new_privs=%d: %d\n", ce->no_new_privs, ret);
			return -1;
		}
	}

	return 0;
}

/*
 * This should be done after creds restore, as
 * some creds changes might drop the value back
 * to zero.
 */

static inline int restore_pdeath_sig(struct thread_restore_args *ta)
{
	int ret;

	if (!ta->pdeath_sig)
		return 0;

	ret = sys_prctl(PR_SET_PDEATHSIG, ta->pdeath_sig, 0, 0, 0);
	if (ret) {
		pr_err("Unable to set PR_SET_PDEATHSIG(%d): %d\n", ta->pdeath_sig, ret);
		return -1;
	}

	return 0;
}

static int restore_dumpable_flag(MmEntry *mme)
{
	int current_dumpable;
	int ret;

	if (!mme->has_dumpable) {
		pr_warn("Dumpable flag not present in criu dump.\n");
		return 0;
	}

	if (mme->dumpable == 0 || mme->dumpable == 1) {
		ret = sys_prctl(PR_SET_DUMPABLE, mme->dumpable, 0, 0, 0);
		if (ret) {
			pr_err("Unable to set PR_SET_DUMPABLE: %d\n", ret);
			return -1;
		}
		return 0;
	}

	/*
	 * If dumpable flag is present but it is not 0 or 1, then we can not
	 * use prctl to set it back.  Try to see if it is already correct
	 * (which is likely if sysctl fs.suid_dumpable is the same when dump
	 * and restore are run), in which case there is nothing to do.
	 * Otherwise, set dumpable to 0 which should be a secure fallback.
	 */
	current_dumpable = sys_prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
	if (mme->dumpable != current_dumpable) {
		pr_warn("Dumpable flag [%d] does not match current [%d]. "
			"Will fallback to setting it to 0 to disable it.\n",
			mme->dumpable, current_dumpable);
		ret = sys_prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
		if (ret) {
			pr_err("Unable to set PR_SET_DUMPABLE: %d\n", ret);
			return -1;
		}
	}
	return 0;
}

static void restore_sched_info(struct rst_sched_param *p)
{
	struct sched_param param;

	pr_info("Restoring scheduler params %d.%d.%d\n", p->policy, p->nice, p->prio);

	sys_setpriority(PRIO_PROCESS, 0, p->nice);
	param.sched_priority = p->prio;
	sys_sched_setscheduler(0, p->policy, &param);
}

static void restore_rlims(struct task_restore_args *ta)
{
	int r;

	for (r = 0; r < ta->rlims_n; r++) {
		struct krlimit krlim;

		krlim.rlim_cur = ta->rlims[r].rlim_cur;
		krlim.rlim_max = ta->rlims[r].rlim_max;
		sys_setrlimit(r, &krlim);
	}
}

static int restore_signals(siginfo_t *ptr, int nr, bool group)
{
	int ret, i;

	for (i = 0; i < nr; i++) {
		siginfo_t *info = ptr + i;

		pr_info("Restore signal %d group %d\n", info->si_signo, group);
		if (group)
			ret = sys_rt_sigqueueinfo(sys_getpid(), info->si_signo, info);
		else
			ret = sys_rt_tgsigqueueinfo(sys_getpid(), sys_gettid(), info->si_signo, info);
		if (ret) {
			pr_err("Unable to send siginfo %d %x with code %d\n", info->si_signo, info->si_code, ret);
			return -1;
		}
	}

	return 0;
}

static int restore_rseq(struct rst_rseq_param *rseq)
{
	int ret;

	if (!rseq->rseq_abi_pointer) {
		pr_debug("rseq: nothing to restore\n");
		return 0;
	}

	pr_debug("rseq: rseq_abi_pointer = %lx signature = %x\n", (unsigned long)rseq->rseq_abi_pointer,
		 rseq->signature);

	ret = sys_rseq(decode_pointer(rseq->rseq_abi_pointer), rseq->rseq_abi_size, 0, rseq->signature);
	if (ret) {
		pr_err("failed sys_rseq(%lx, %lx, %x, %x) = %d\n", (unsigned long)rseq->rseq_abi_pointer,
		       (unsigned long)rseq->rseq_abi_size, 0, rseq->signature, ret);
		return -1;
	}

	return 0;
}

static int restore_seccomp_filter(pid_t tid, struct thread_restore_args *args)
{
	unsigned int flags = args->seccomp_force_tsync ? SECCOMP_FILTER_FLAG_TSYNC : 0;
	size_t i;
	int ret;

	for (i = 0; i < args->seccomp_filters_n; i++) {
		struct thread_seccomp_filter *filter = &args->seccomp_filters[i];

		pr_debug("seccomp: Restoring mode %d flags %x on tid %d filter %d\n", SECCOMP_SET_MODE_FILTER,
			 (filter->flags | flags), tid, (int)i);

		ret = sys_seccomp(SECCOMP_SET_MODE_FILTER, filter->flags | flags, (void *)&filter->sock_fprog);
		if (ret < 0) {
			if (ret == -ENOSYS) {
				pr_debug("seccomp: sys_seccomp is not supported in kernel, "
					 "switching to prctl interface\n");
				ret = sys_prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (long)(void *)&filter->sock_fprog,
						0, 0);
				if (ret) {
					pr_err("seccomp: PR_SET_SECCOMP returned %d on tid %d\n", ret, tid);
					return -1;
				}
			} else {
				pr_err("seccomp: SECCOMP_SET_MODE_FILTER returned %d on tid %d\n", ret, tid);
				return -1;
			}
		}
	}

	return 0;
}

static int restore_seccomp(struct thread_restore_args *args)
{
	pid_t tid = sys_gettid();
	int ret;

	switch (args->seccomp_mode) {
	case SECCOMP_MODE_DISABLED:
		pr_debug("seccomp: mode %d on tid %d\n", SECCOMP_MODE_DISABLED, tid);
		return 0;
		break;
	case SECCOMP_MODE_STRICT:
		/*
		 * Disable gettimeofday() from vdso: it may use TSC
		 * which is restricted by kernel:
		 *
		 * static long seccomp_set_mode_strict(void)
		 * {
		 * [..]
		 * #ifdef TIF_NOTSC
		 *	disable_TSC();
		 * #endif
		 * [..]
		 *
		 * XXX: It may need to be fixed in kernel under
		 * PTRACE_O_SUSPEND_SECCOMP, but for now just get timings
		 * with a raw syscall instead of vdso.
		 */
		std_log_set_gettimeofday(NULL);
		ret = sys_prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0);
		if (ret < 0) {
			pr_err("seccomp: SECCOMP_MODE_STRICT returned %d on tid %d\n", ret, tid);
		}
		break;
	case SECCOMP_MODE_FILTER:
		ret = restore_seccomp_filter(tid, args);
		break;
	default:
		pr_err("seccomp: Unknown seccomp mode %d on tid %d\n", args->seccomp_mode, tid);
		ret = -1;
		break;
	}

	if (!ret) {
		pr_debug("seccomp: Restored mode %d on tid %d\n", args->seccomp_mode, tid);
	}

	return ret;
}

static int restore_robust_futex(struct thread_restore_args *args)
{
	uint32_t futex_len = args->futex_rla_len;
	int ret;

	if (!args->futex_rla_len)
		return 0;

	/*
	 * XXX: We check here *task's* mode, not *thread's*.
	 * But it's possible to write an application with mixed
	 * threads (on x86): some in 32-bit mode, some in 64-bit.
	 * Quite unlikely that such application exists at all.
	 */
	if (args->ta->compatible_mode) {
		uint32_t futex = (uint32_t)args->futex_rla;
		ret = set_compat_robust_list(futex, futex_len);
	} else {
		void *futex = decode_pointer(args->futex_rla);
		ret = sys_set_robust_list(futex, futex_len);
	}

	if (ret)
		pr_err("Failed to recover futex robust list: %d\n", ret);

	return ret;
}

static int restore_thread_common(struct thread_restore_args *args)
{
	sys_set_tid_address((int *)decode_pointer(args->clear_tid_addr));

	if (restore_robust_futex(args))
		return -1;

	restore_sched_info(&args->sp);

	if (restore_nonsigframe_gpregs(&args->gpregs))
		return -1;

	restore_tls(&args->tls);

	if (restore_rseq(&args->rseq))
		return -1;

	return 0;
}

static void noinline rst_sigreturn(unsigned long new_sp, struct rt_sigframe *sigframe)
{
	ARCH_RT_SIGRETURN_RST(new_sp, sigframe);
}

static int send_cg_set(int sk, int cg_set)
{
	struct cmsghdr *ch;
	struct msghdr h;
	/*
	 * 0th is the dummy call address for compatibility with userns helper
	 * 1st is the cg_set
	 */
	struct iovec iov[2];
	char cmsg[CMSG_SPACE(sizeof(struct ucred))] = {};
	int ret, *dummy = NULL;
	struct ucred *ucred;

	iov[0].iov_base = &dummy;
	iov[0].iov_len = sizeof(dummy);
	iov[1].iov_base = &cg_set;
	iov[1].iov_len = sizeof(cg_set);

	h.msg_iov = iov;
	h.msg_iovlen = sizeof(iov) / sizeof(struct iovec);
	h.msg_name = NULL;
	h.msg_namelen = 0;
	h.msg_flags = 0;

	h.msg_control = cmsg;
	h.msg_controllen = sizeof(cmsg);
	ch = CMSG_FIRSTHDR(&h);
	ch->cmsg_len = CMSG_LEN(sizeof(struct ucred));
	ch->cmsg_level = SOL_SOCKET;
	ch->cmsg_type = SCM_CREDENTIALS;

	ucred = (struct ucred *)CMSG_DATA(ch);
	/*
	 * We still have privilege in this namespace so we can send
	 * thread id instead of pid of main thread, uid, gid as 0
	 * since these 2 are ignored in cgroupd
	 */
	ucred->pid = sys_gettid();
	ucred->uid = 0;
	ucred->gid = 0;

	ret = sys_sendmsg(sk, &h, 0);
	if (ret < 0) {
		pr_err("Unable to send packet to cgroupd %d\n", ret);
		return -1;
	}

	return 0;
}

/*
 * As the cgroupd socket is shared among threads and processes, this
 * should be called with task_entries->cgroupd_sync_lock held.
 */
static int recv_cg_set_restore_ack(int sk)
{
	struct cmsghdr *ch;
	struct msghdr h = {};
	char cmsg[CMSG_SPACE(sizeof(struct ucred))];
	struct ucred *cred;
	int ret;

	h.msg_control = cmsg;
	h.msg_controllen = sizeof(cmsg);

	ret = sys_recvmsg(sk, &h, 0);
	if (ret < 0) {
		pr_err("Unable to receive from cgroupd %d\n", ret);
		return -1;
	}

	if (h.msg_controllen != sizeof(cmsg)) {
		pr_err("The message from cgroupd is truncated\n");
		return -1;
	}

	ch = CMSG_FIRSTHDR(&h);
	cred = (struct ucred *)CMSG_DATA(ch);
	if (cred->pid != sys_gettid()) {
		pr_err("cred pid %d != gettid\n", cred->pid);
		return -1;
	}
	return 0;
}

static void thread_fini(void)
{
	if (!atomic_dec_and_test(&thread_inprogress))
		return;

	std_log_set_fd(-1);
	sys_munmap(rst_mem, rst_mem_size);
}

/*
 * Threads restoration via sigreturn. Note it's locked
 * routine and calls for unlock at the end.
 */
__visible long __export_restore_thread(struct thread_restore_args *args)
{
	struct rt_sigframe *rt_sigframe;
	k_rtsigset_t to_block;
	unsigned long new_sp;
	int my_pid = sys_gettid();
	int ret;

	if (my_pid != args->pid) {
		pr_err("Thread pid mismatch %d/%d\n", my_pid, args->pid);
		goto core_restore_end;
	}

	/* restore original shadow stack */
	if (arch_shstk_restore(&args->shstk))
		goto core_restore_end;

	/* All signals must be handled by thread leader */
	ksigfillset(&to_block);
	ret = sys_sigprocmask(SIG_SETMASK, &to_block, NULL, sizeof(k_rtsigset_t));
	if (ret) {
		pr_err("Unable to block signals %d\n", ret);
		goto core_restore_end;
	}

	rt_sigframe = (void *)&args->mz->rt_sigframe;

	if (args->cg_set != -1) {
		int err = 0;

		mutex_lock(&task_entries_local->cgroupd_sync_lock);

		pr_info("Restore cg_set in thread cg_set: %d\n", args->cg_set);

		err = send_cg_set(args->cgroupd_sk, args->cg_set);
		if (!err)
			err = recv_cg_set_restore_ack(args->cgroupd_sk);

		mutex_unlock(&task_entries_local->cgroupd_sync_lock);
		sys_close(args->cgroupd_sk);

		if (err)
			goto core_restore_end;
	}

	if (restore_thread_common(args))
		goto core_restore_end;

	ret = sys_prctl(PR_SET_NAME, (unsigned long)&args->comm, 0, 0, 0);
	if (ret) {
		pr_err("Unable to set a thread name: %d\n", ret);
		goto core_restore_end;
	}

	pr_info("%ld: Restored\n", sys_gettid());

	restore_finish_stage(task_entries_local, CR_STATE_RESTORE);

	if (restore_signals(args->siginfo, args->siginfo_n, false))
		goto core_restore_end;

	restore_finish_stage(task_entries_local, CR_STATE_RESTORE_SIGCHLD);

	/*
	 * Make sure it's before creds, since it's privileged
	 * operation bound to uid 0 in current user ns.
	 */
	if (restore_seccomp(args))
		BUG();

	ret = restore_creds(args->creds_args, args->ta->proc_fd, args->ta->lsm_type, args->ta->uid);
	ret = ret || restore_dumpable_flag(&args->ta->mm);
	ret = ret || restore_pdeath_sig(args);
	if (ret)
		BUG();

	restore_finish_stage(task_entries_local, CR_STATE_RESTORE_CREDS);

	thread_fini();

	new_sp = (long)rt_sigframe + RT_SIGFRAME_OFFSET(rt_sigframe);
	rst_sigreturn(new_sp, rt_sigframe);

core_restore_end:
	pr_err("Restorer abnormal termination for %ld\n", sys_getpid());
	futex_abort_and_wake(&task_entries_local->nr_in_progress);
	sys_exit_group(1);
	return -1;
}

static long restore_self_exe_late(struct task_restore_args *args)
{
	int fd = args->fd_exe_link, ret;

	pr_info("Restoring EXE link\n");
	ret = sys_prctl_safe(PR_SET_MM, PR_SET_MM_EXE_FILE, fd, 0);
	if (ret)
		pr_err("Can't restore EXE link (%d)\n", ret);
	sys_close(fd);

	return ret;
}

#ifndef ARCH_HAS_SHMAT_HOOK
unsigned long arch_shmat(int shmid, void *shmaddr, int shmflg, unsigned long size)
{
	return sys_shmat(shmid, shmaddr, shmflg);
}
#endif

static unsigned long restore_mapping(VmaEntry *vma_entry)
{
	int prot = vma_entry->prot;
	int flags = vma_entry->flags | MAP_FIXED;
	unsigned long addr;

	if (vma_entry_is(vma_entry, VMA_AREA_SYSVIPC)) {
		int att_flags;
		void *shmaddr = decode_pointer(vma_entry->start);
		unsigned long shmsize = (vma_entry->end - vma_entry->start);
		/*
		 * See comment in open_shmem_sysv() for what SYSV_SHMEM_SKIP_FD
		 * means and why we check for PROT_EXEC few lines below.
		 */
		if (vma_entry->fd == SYSV_SHMEM_SKIP_FD)
			return vma_entry->start;

		if (vma_entry->prot & PROT_EXEC) {
			att_flags = 0;
			vma_entry->prot &= ~PROT_EXEC;
		} else
			att_flags = SHM_RDONLY;

		pr_info("Attach SYSV shmem %d at %" PRIx64 "\n", (int)vma_entry->fd, vma_entry->start);
		return arch_shmat(vma_entry->fd, shmaddr, att_flags, shmsize);
	}

	/*
	 * Restore or shared mappings are tricky, since
	 * we open anonymous mapping via map_files/
	 * MAP_ANONYMOUS should be eliminated so fd would
	 * be taken into account by a kernel.
	 */
	if (vma_entry_is(vma_entry, VMA_ANON_SHARED) && (vma_entry->fd != -1UL))
		flags &= ~MAP_ANONYMOUS;

	/* See comment in premap_private_vma() for this flag change */
	if (vma_entry_is(vma_entry, VMA_AREA_AIORING))
		flags |= MAP_ANONYMOUS;

	/* A mapping of file with MAP_SHARED is up to date */
	if ((vma_entry->fd == -1 || !(vma_entry->flags & MAP_SHARED)) && !(vma_entry->status & VMA_NO_PROT_WRITE))
		prot |= PROT_WRITE;

	/* TODO: Drop MAP_LOCKED bit and restore it after reading memory.
	 *
	 * Code below tries to limit memory usage by running fallocate()
	 * after each preadv() to avoid doubling memory usage (once in
	 * image files, once in process). Unfortunately, MAP_LOCKED defeats
	 * that mechanism as it causes the process to be charged for memory
	 * immediately upon mmap, not later upon preadv().
	 */
	pr_debug("\tmmap(%" PRIx64 " -> %" PRIx64 ", %x %x %d)\n", vma_entry->start, vma_entry->end, prot, flags,
		 (int)vma_entry->fd);
	/*
	 * Should map memory here. Note we map them as
	 * writable since we're going to restore page
	 * contents.
	 */
	addr = sys_mmap(decode_pointer(vma_entry->start), vma_entry_len(vma_entry), prot, flags, vma_entry->fd,
			vma_entry->pgoff);

	if ((vma_entry->fd != -1) && (vma_entry->status & VMA_CLOSE))
		sys_close(vma_entry->fd);

	return addr;
}

/*
 * Issue UVERBS_METHOD_RESTORE_MR for one MR queued by Phase B-prep
 * (criu/rdma.c::rdma_prepare_rdma_mrs). Runs from inside the pie blob
 * after the user VMAs have been laid out at their original addresses,
 * so rxe's pin_user_pages_fast(addr, ...) can succeed against the
 * destination task's mm. See criu/include/restorer.h::struct rst_rdma
 * _mr for the timing rationale.
 *
 * Wire encoding intentionally mirrors criu/rdma.c::rdma_send_restore_
 * mr: PTR_IN / FLAGS_IN attrs whose declared len <= sizeof(u64) pass
 * the value inline in attr->data (NOT a pointer to it). This is the
 * uverbs_attr_ptr_is_inline() path on the kernel side. PTR_OUT attrs
 * pass a userspace pointer in data; the kernel writes via copy_to_
 * user. Constants and structs are duplicated rather than shared
 * because the pie blob compiles nostdlib + minimal include surface,
 * and dragging non-uapi headers in here is more fragile than the
 * shim. Kept in lock-step with rdma.c by the comment at the
 * declaration site -- if either side drifts, RESTORE_MR fails on the
 * next runner pass and the diff between the two encoders is the
 * first place to look.
 */

#include <rdma/ib_user_verbs.h>
#include <rdma/ib_user_ioctl_cmds.h>
#include <rdma/rdma_user_ioctl_cmds.h>

#ifndef UVERBS_OBJECT_RESTORE
#define UVERBS_OBJECT_RESTORE			18
#endif
#ifndef UVERBS_METHOD_RESTORE_MR
#define UVERBS_METHOD_RESTORE_MR		1
#endif
#ifndef UVERBS_METHOD_RESTORE_CQ
#define UVERBS_METHOD_RESTORE_CQ		2
#endif
#ifndef UVERBS_METHOD_RESTORE_QP
#define UVERBS_METHOD_RESTORE_QP		3
#endif
#ifndef UVERBS_ATTR_RESTORE_MR_HANDLE
#define UVERBS_ATTR_RESTORE_MR_HANDLE		0
#define UVERBS_ATTR_RESTORE_MR_PD_HANDLE	1
#define UVERBS_ATTR_RESTORE_MR_ADDR		2
#define UVERBS_ATTR_RESTORE_MR_LENGTH		3
#define UVERBS_ATTR_RESTORE_MR_IOVA		4
#define UVERBS_ATTR_RESTORE_MR_ACCESS_FLAGS	5
#define UVERBS_ATTR_RESTORE_MR_LKEY_HINT	6
#define UVERBS_ATTR_RESTORE_MR_RKEY_HINT	7
#define UVERBS_ATTR_RESTORE_MR_RESP_LKEY	8
#define UVERBS_ATTR_RESTORE_MR_RESP_RKEY	9
#endif
#ifndef UVERBS_ATTR_RESTORE_CQ_HANDLE
#define UVERBS_ATTR_RESTORE_CQ_HANDLE		0
#define UVERBS_ATTR_RESTORE_CQ_CQE		1
#define UVERBS_ATTR_RESTORE_CQ_USER_HANDLE	2
#define UVERBS_ATTR_RESTORE_CQ_COMP_VECTOR	3
#define UVERBS_ATTR_RESTORE_CQ_FLAGS		4
#define UVERBS_ATTR_RESTORE_CQ_COMP_CHANNEL	5	/* unused; UA_OPTIONAL FD */
#define UVERBS_ATTR_RESTORE_CQ_EVENT_FD		6	/* unused; UA_OPTIONAL FD */
#define UVERBS_ATTR_RESTORE_CQ_RESP_CQE		7
#endif
#ifndef UVERBS_ATTR_RESTORE_QP_HANDLE
#define UVERBS_ATTR_RESTORE_QP_HANDLE		0
#define UVERBS_ATTR_RESTORE_QP_PD_HANDLE	1
#define UVERBS_ATTR_RESTORE_QP_SEND_CQ_HANDLE	2
#define UVERBS_ATTR_RESTORE_QP_RECV_CQ_HANDLE	3
#define UVERBS_ATTR_RESTORE_QP_SRQ_HANDLE	4	/* unused for v0 RC/UD */
#define UVERBS_ATTR_RESTORE_QP_TYPE		5
#define UVERBS_ATTR_RESTORE_QP_STATE		6
#define UVERBS_ATTR_RESTORE_QP_USER_HANDLE	7
#define UVERBS_ATTR_RESTORE_QP_CAP		8
#define UVERBS_ATTR_RESTORE_QP_CREATE_FLAGS	9
#define UVERBS_ATTR_RESTORE_QP_EVENT_FD		10	/* unused; UA_OPTIONAL FD */
#define UVERBS_ATTR_RESTORE_QP_RESP_QPN		11
#endif

/*
 * UHW is the generic driver-private blob attribute. attr_id 4096
 * (== UVERBS_ID_DRIVER_NS = 1 << UVERBS_ID_NS_SHIFT) is the kernel's
 * namespace boundary between core and driver attrs. Driver-private
 * shape comes from the per-driver RDMA plugin's
 * RDMA_RESTORE_UOBJ_MR_UHW_PACK hook (run in CRIU master, see
 * criu/include/criu-plugin.h); the bytes are carried through to the
 * pie blob in @r->uhw_in_buf and attached as UVERBS_ATTR_UHW_IN here.
 */
#ifndef UVERBS_ATTR_UHW_IN
#define UVERBS_ATTR_UHW_IN			((uint16_t)4096)
#endif
#ifndef UVERBS_ATTR_UHW_OUT
#define UVERBS_ATTR_UHW_OUT			((uint16_t)4097)
#endif

/*
 * Issue UVERBS_METHOD_RESTORE_CQ for one CQ queued by Phase B-prep
 * (criu/rdma/uobj_restore.c::rdma_prepare_rdma_cqs). Runs from inside
 * the pie blob after the user VMAs have been laid out at their
 * original addresses, so mlx5_ib_umem_restore_cq's pin_user_pages_
 * fast() against the CQ buffer + doorbell user-VAs succeeds against
 * the destination task's mm. See criu/include/restorer.h::struct
 * rst_rdma_cq for the timing rationale -- mirrors restore_rdma_mr's
 * shape exactly, modulo the per-class attr id set.
 */
static int restore_rdma_cq(struct rst_rdma_cq *r)
{
	/*
	 * 8 attrs: 6 core (handle, cqe, user_handle, comp_vector,
	 * flags, resp_cqe) + up to 2 plugin-shaped UHW (UHW_IN,
	 * UHW_OUT). Worst-case sizing so we don't need conditional
	 * buffer math.
	 */
	struct {
		struct ib_uverbs_ioctl_hdr	hdr;
		struct ib_uverbs_attr		attrs[8];
	} cmd = {};
	uint32_t resp_cqe = 0;
	uint8_t  uhw_out_actual[RST_RDMA_CQ_UHW_OUT_MAX] = {};
	unsigned int n = 0;
	int ret;

	cmd.hdr.object_id = UVERBS_OBJECT_RESTORE;
	cmd.hdr.method_id = UVERBS_METHOD_RESTORE_CQ;
	cmd.hdr.driver_id = r->kernel_driver_id;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_CQ_HANDLE;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = r->target_handle;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_CQ_CQE;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = r->cqe;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_CQ_USER_HANDLE;
	cmd.attrs[n].len = sizeof(uint64_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = r->user_handle;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_CQ_COMP_VECTOR;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = r->comp_vector;
	n++;

	/*
	 * FLAGS_IN is optional; only emit when non-zero so we don't
	 * spend a slot for the common "no special CQ flags" case.
	 * Kernel uverbs_get_flags32 treats absent as zero already.
	 */
	if (r->flags) {
		cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_CQ_FLAGS;
		cmd.attrs[n].len = sizeof(uint32_t);
		cmd.attrs[n].flags = 0;
		cmd.attrs[n].data = r->flags;
		n++;
	}

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_CQ_RESP_CQE;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&resp_cqe;
	n++;

	/*
	 * Plugin-shaped UHW. PACK pre-staged the bytes into the
	 * static rst_rdma_cq.uhw_in_buf / uhw_out_expected at master
	 * time. We attach UHW_IN if uhw_in_len > 0 (mlx5 has 32B
	 * mlx5_ib_restore_cq_req; rxe optionally has 16B
	 * rxe_restore_cq_req when vm_pgoff != 0). We attach UHW_OUT
	 * if uhw_out_attr_len > 0 (rxe always 16B for
	 * rxe_create_cq_resp; mlx5 zero -- mlx5_ib_restore_cq
	 * rejects any non-zero udata->outlen). The kernel writes its
	 * echo into uhw_out_actual; we memcmp the first
	 * uhw_out_verify_len bytes against uhw_out_expected post-
	 * ioctl.
	 */
	if (r->uhw_in_len > 0) {
		cmd.attrs[n].attr_id = UVERBS_ATTR_UHW_IN;
		cmd.attrs[n].len = r->uhw_in_len;
		cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
		cmd.attrs[n].data = (uintptr_t)&r->uhw_in_buf;
		n++;
	}
	if (r->uhw_out_attr_len > 0) {
		cmd.attrs[n].attr_id = UVERBS_ATTR_UHW_OUT;
		cmd.attrs[n].len = r->uhw_out_attr_len;
		cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
		cmd.attrs[n].data = (uintptr_t)uhw_out_actual;
		n++;
	}

	cmd.hdr.num_attrs = n;
	cmd.hdr.length = sizeof(cmd.hdr) + n * sizeof(cmd.attrs[0]);

	ret = sys_ioctl(r->cmd_fd, RDMA_VERBS_IOCTL, (unsigned long)&cmd);
	sys_close(r->cmd_fd);
	if (ret < 0) {
		pr_err("RDMA: ufile_id=%x RESTORE_CQ(target_handle=%u, "
		       "cqe=%u, comp_vector=%u, flags=%x, "
		       "driver_id=%u, uhw_in=%u, uhw_out=%u) failed: %d\n",
		       r->ufile_id, r->target_handle, r->cqe,
		       r->comp_vector, r->flags, r->kernel_driver_id,
		       r->uhw_in_len, r->uhw_out_attr_len, ret);
		return -1;
	}

	if (r->uhw_out_verify_len > 0 &&
	    memcmp(uhw_out_actual, r->uhw_out_expected,
		   r->uhw_out_verify_len) != 0) {
		pr_err("RDMA: ufile_id=%x RESTORE_CQ(target_handle=%u): "
		       "kernel UHW_OUT echo (verify %u of %u bytes) does "
		       "not match plugin's expected bytes\n",
		       r->ufile_id, r->target_handle,
		       r->uhw_out_verify_len, r->uhw_out_attr_len);
		return -1;
	}

	pr_info("RDMA: ufile_id=%x RESTORE_CQ(target_handle=%u, "
		"cqe=%u, resp_cqe=%u, comp_vector=%u, "
		"driver_id=%u, uhw_in=%u, uhw_out=%u) ok\n",
		r->ufile_id, r->target_handle, r->cqe, resp_cqe,
		r->comp_vector, r->kernel_driver_id,
		r->uhw_in_len, r->uhw_out_attr_len);
	return 0;
}

/*
 * Issue UVERBS_METHOD_RESTORE_QP for one QP queued by Phase B-prep
 * (criu/rdma/uobj_restore.c::rdma_prepare_rdma_qps). Runs from
 * inside the pie blob after the user VMAs have been laid out at
 * their original addresses, so mlx5_ib_umem_restore_qp's
 * pin_user_pages_fast() against the WQ buffer + doorbell user-VAs
 * succeeds against the destination task's mm.
 *
 * Wire encoding mirrors restore_rdma_cq: PD_HANDLE / SEND_CQ_HANDLE /
 * RECV_CQ_HANDLE are IDR attrs (len=0, value inline in attr->data).
 * TYPE / STATE / CREATE_FLAGS are u32 PTR_IN attrs that fit inline.
 * USER_HANDLE is a u64 PTR_IN that fits inline. CAP is a 20-byte
 * PTR_IN(struct ib_uverbs_qp_cap) -- exceeds the inline threshold,
 * so attr->data carries a userspace VA (here, the address of the
 * cap_buf array we lay out below). RESP_QPN is a u32 PTR_OUT
 * attribute the kernel writes via copy_to_user; we receive the
 * actual installed qpn back via &resp_qpn.
 *
 * Identity assertion (Step 6): the kernel installed qpn must equal
 * the dump-side hint when @qpn_hint is non-zero. v0 mlx5 RESTORE_QP
 * adopts the FW qpn from the UHW byte-for-byte, so RESP_QPN ==
 * UHW.qpn == qpn_hint by construction. For rxe (future), RESP_QPN
 * may differ from rxe_pool_alloc's chosen qpn -- that case will
 * surface here as a "qpn drift" warning rather than a hard fail
 * once rxe lands; for now the assertion is hard.
 */
static int restore_rdma_qp(struct rst_rdma_qp *r)
{
	/*
	 * 12 attrs: 9 mandatory (handle, pd_handle, send_cq_handle,
	 * recv_cq_handle, type, state, user_handle, cap, resp_qpn) +
	 * 1 optional (create_flags, only when non-zero) + up to 2
	 * plugin-shaped UHW (UHW_IN, UHW_OUT). Worst-case sizing.
	 */
	struct {
		struct ib_uverbs_ioctl_hdr	hdr;
		struct ib_uverbs_attr		attrs[12];
	} cmd = {};
	/*
	 * struct ib_uverbs_qp_cap mirror, laid out inline so we can
	 * pass &cap_buf as the PTR_IN attr->data. Bytewise identical
	 * to include/uapi/rdma/ib_user_verbs.h::struct ib_uverbs_qp_cap;
	 * we mirror rather than include because pie compiles with a
	 * minimal include surface.
	 */
	struct {
		uint32_t max_send_wr;
		uint32_t max_recv_wr;
		uint32_t max_send_sge;
		uint32_t max_recv_sge;
		uint32_t max_inline_data;
	} cap_buf = {
		.max_send_wr = r->cap_max_send_wr,
		.max_recv_wr = r->cap_max_recv_wr,
		.max_send_sge = r->cap_max_send_sge,
		.max_recv_sge = r->cap_max_recv_sge,
		.max_inline_data = r->cap_max_inline_data,
	};
	uint32_t resp_qpn = 0;
	uint8_t  uhw_out_actual[RST_RDMA_QP_UHW_OUT_MAX] = {};
	unsigned int n = 0;
	int ret;

	cmd.hdr.object_id = UVERBS_OBJECT_RESTORE;
	cmd.hdr.method_id = UVERBS_METHOD_RESTORE_QP;
	cmd.hdr.driver_id = r->kernel_driver_id;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_QP_HANDLE;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = r->target_handle;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_QP_PD_HANDLE;
	cmd.attrs[n].len = 0;
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = r->parent_pd_handle;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_QP_SEND_CQ_HANDLE;
	cmd.attrs[n].len = 0;
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = r->send_cq_handle;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_QP_RECV_CQ_HANDLE;
	cmd.attrs[n].len = 0;
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = r->recv_cq_handle;
	n++;

	/*
	 * UVERBS_ATTR_CONST_IN(_, enum_type, ...) expands to a PTR_IN
	 * with min_len == max_len == sizeof(u64) regardless of the
	 * enum's storage size (see include/rdma/uverbs_ioctl.h). The
	 * value is carried inline in the attr data slot (which is u64
	 * already), so the only thing this affects is the framework's
	 * len gate -- it checks uattr->len >= 8 strictly.
	 */
	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_QP_TYPE;
	cmd.attrs[n].len = sizeof(uint64_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = r->qp_type;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_QP_STATE;
	cmd.attrs[n].len = sizeof(uint64_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = r->qp_state;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_QP_USER_HANDLE;
	cmd.attrs[n].len = sizeof(uint64_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = r->user_handle;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_QP_CAP;
	cmd.attrs[n].len = sizeof(cap_buf);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&cap_buf;
	n++;

	/*
	 * CREATE_FLAGS_IN is optional; only emit when non-zero so we
	 * don't burn a slot for the common "no special create flags"
	 * case. Kernel uverbs_get_flags32 treats absent as zero.
	 */
	if (r->create_flags) {
		cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_QP_CREATE_FLAGS;
		cmd.attrs[n].len = sizeof(uint32_t);
		cmd.attrs[n].flags = 0;
		cmd.attrs[n].data = r->create_flags;
		n++;
	}

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_QP_RESP_QPN;
	cmd.attrs[n].len = sizeof(resp_qpn);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&resp_qpn;
	n++;

	if (r->uhw_in_len > 0) {
		cmd.attrs[n].attr_id = UVERBS_ATTR_UHW_IN;
		cmd.attrs[n].len = r->uhw_in_len;
		cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
		cmd.attrs[n].data = (uintptr_t)&r->uhw_in_buf;
		n++;
	}
	if (r->uhw_out_attr_len > 0) {
		cmd.attrs[n].attr_id = UVERBS_ATTR_UHW_OUT;
		cmd.attrs[n].len = r->uhw_out_attr_len;
		cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
		cmd.attrs[n].data = (uintptr_t)uhw_out_actual;
		n++;
	}

	cmd.hdr.num_attrs = n;
	cmd.hdr.length = sizeof(cmd.hdr) + n * sizeof(cmd.attrs[0]);

	ret = sys_ioctl(r->cmd_fd, RDMA_VERBS_IOCTL, (unsigned long)&cmd);
	sys_close(r->cmd_fd);
	if (ret < 0) {
		pr_err("RDMA: ufile_id=%x RESTORE_QP(target_handle=%u, "
		       "pd_handle=%u, send_cq=%u, recv_cq=%u, "
		       "type=%u, state=%u, create_flags=%x, "
		       "qpn_hint=%u, driver_id=%u, uhw_in=%u, uhw_out=%u) "
		       "failed: %d\n",
		       r->ufile_id, r->target_handle, r->parent_pd_handle,
		       r->send_cq_handle, r->recv_cq_handle,
		       r->qp_type, r->qp_state, r->create_flags,
		       r->qpn_hint, r->kernel_driver_id,
		       r->uhw_in_len, r->uhw_out_attr_len, ret);
		return -1;
	}

	/*
	 * Identity assertion (Step 6): the kernel must install the
	 * QP at the same qpn the source had, otherwise wire-visible
	 * peer state (peer's RC connection state, peer's hardware
	 * AH cache, ...) is silently stale on the destination side
	 * and round-trip continuity is broken. Only checked when the
	 * dump-side captured a non-zero qpn_hint (NLDEV RES_LQPN);
	 * the v0 path always populates it, but defending against the
	 * rare image-without-LQPN case is cheap.
	 */
	if (r->qpn_hint != 0 && resp_qpn != r->qpn_hint) {
		pr_err("RDMA: ufile_id=%x RESTORE_QP(target_handle=%u): "
		       "kernel installed qpn=%u differs from dump-side "
		       "hint qpn=%u; FW qpn-adoption broke for "
		       "driver_id=%u\n",
		       r->ufile_id, r->target_handle, resp_qpn,
		       r->qpn_hint, r->kernel_driver_id);
		return -1;
	}

	if (r->uhw_out_verify_len > 0 &&
	    memcmp(uhw_out_actual, r->uhw_out_expected,
		   r->uhw_out_verify_len) != 0) {
		pr_err("RDMA: ufile_id=%x RESTORE_QP(target_handle=%u): "
		       "kernel UHW_OUT echo (verify %u of %u bytes) does "
		       "not match plugin's expected bytes\n",
		       r->ufile_id, r->target_handle,
		       r->uhw_out_verify_len, r->uhw_out_attr_len);
		return -1;
	}

	pr_info("RDMA: ufile_id=%x RESTORE_QP(target_handle=%u, "
		"resp_qpn=%u, type=%u, state=%u, "
		"driver_id=%u, uhw_in=%u, uhw_out=%u) ok\n",
		r->ufile_id, r->target_handle, resp_qpn, r->qp_type,
		r->qp_state, r->kernel_driver_id,
		r->uhw_in_len, r->uhw_out_attr_len);
	return 0;
}

static int restore_rdma_mr(struct rst_rdma_mr *r)
{
	/*
	 * 12 attrs: 10 core (handle, pd_handle, addr, length, iova,
	 * access_flags, lkey_hint, rkey_hint, resp_lkey, resp_rkey)
	 * + up to 2 plugin-shaped UHW (UHW_IN, UHW_OUT). Sized for the
	 * worst case so we don't need conditional buffer sizing.
	 */
	struct {
		struct ib_uverbs_ioctl_hdr	hdr;
		struct ib_uverbs_attr		attrs[12];
	} cmd = {};
	uint32_t resp_lkey = 0, resp_rkey = 0;
	uint8_t  uhw_out_actual[RST_RDMA_MR_UHW_OUT_MAX] = {};
	unsigned int n = 0;
	int ret;

	cmd.hdr.object_id = UVERBS_OBJECT_RESTORE;
	cmd.hdr.method_id = UVERBS_METHOD_RESTORE_MR;
	cmd.hdr.driver_id = r->kernel_driver_id;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_HANDLE;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = r->target_handle;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_PD_HANDLE;
	cmd.attrs[n].len = 0;
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = r->parent_pd_handle;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_ADDR;
	cmd.attrs[n].len = sizeof(uint64_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = r->addr;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_LENGTH;
	cmd.attrs[n].len = sizeof(uint64_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = r->length;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_IOVA;
	cmd.attrs[n].len = sizeof(uint64_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = r->iova;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_ACCESS_FLAGS;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = r->access_flags;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_LKEY_HINT;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = r->lkey_hint;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_RKEY_HINT;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = r->rkey_hint;
	n++;

	/*
	 * Driver-private UHW comes from the cached plugin's
	 * RDMA_RESTORE_UOBJ_MR_UHW_PACK hook (run pre-pie in
	 * rdma_prepare_rdma_mrs). @uhw_in_len == 0 means the plugin
	 * either declined the hook or had no UHW_IN to supply (rxe MR
	 * today -- the kernel dispatcher forwards no unknown UHW so
	 * the verb stays minimal). When the plugin asked for a
	 * UHW_OUT byte-equal echo check we declare a UHW_OUT
	 * attribute too; the kernel then writes the actual echo into
	 * uhw_out_actual and we memcmp post-ioctl.
	 */
	if (r->uhw_in_len > 0) {
		cmd.attrs[n].attr_id = UVERBS_ATTR_UHW_IN;
		cmd.attrs[n].len = r->uhw_in_len;
		cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
		cmd.attrs[n].data = (uintptr_t)&r->uhw_in_buf;
		n++;
	}
	if (r->uhw_out_attr_len > 0) {
		cmd.attrs[n].attr_id = UVERBS_ATTR_UHW_OUT;
		cmd.attrs[n].len = r->uhw_out_attr_len;
		cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
		cmd.attrs[n].data = (uintptr_t)uhw_out_actual;
		n++;
	}

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_RESP_LKEY;
	cmd.attrs[n].len = sizeof(resp_lkey);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&resp_lkey;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_MR_RESP_RKEY;
	cmd.attrs[n].len = sizeof(resp_rkey);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&resp_rkey;
	n++;

	cmd.hdr.num_attrs = n;
	cmd.hdr.length = sizeof(cmd.hdr) + n * sizeof(cmd.attrs[0]);

	ret = sys_ioctl(r->cmd_fd, RDMA_VERBS_IOCTL, (unsigned long)&cmd);
	/*
	 * Always close the per-MR cdev fd dup so it doesn't leak
	 * into the restored task's fd table -- the user task already
	 * has the cdev installed at the source-side fd number via
	 * CRIU's per-task file restore; this dup is purely a transit
	 * fd for the ioctl above.
	 */
	sys_close(r->cmd_fd);
	if (ret < 0) {
		/*
		 * Pie's printf is the std-plugin minimal one (criu/
		 * compel/plugins/std/log.c): only %s/%d/%x/%p/%u with
		 * the 'l' modifier; no '#' alt-form, no 'll' width.
		 * %x prints with a built-in "0x" prefix already.
		 */
		pr_err("RDMA: ufile_id=%x RESTORE_MR(target_handle=%u, "
		       "parent_pd_handle=%u, addr=%lx, length=%lu, "
		       "iova=%lx, access=%x, lkey_hint=%x, "
		       "rkey_hint=%x, driver_id=%u) failed: %d\n",
		       r->ufile_id, r->target_handle, r->parent_pd_handle,
		       (unsigned long)r->addr,
		       (unsigned long)r->length,
		       (unsigned long)r->iova,
		       r->access_flags, r->lkey_hint, r->rkey_hint,
		       r->kernel_driver_id, ret);
		return -1;
	}

	/*
	 * Identity assertion: with rxe f422e6ba6bdc honouring the
	 * lkey/rkey hints exactly, RESP_LKEY/_RKEY must equal the
	 * hints byte-for-byte. mlx5 (S4b) does the same via the FW
	 * mkey_index UHW. A mismatch means the wire-visible identity
	 * has shifted and any peer holding the old rkey, or any
	 * libibverbs cache holding the old lkey, is now stale -- a
	 * driver-side regression we want to catch loudly.
	 */
	if (resp_lkey != r->lkey_hint || resp_rkey != r->rkey_hint) {
		pr_err("RDMA: ufile_id=%x RESTORE_MR(target_handle=%u): "
		       "kernel installed lkey/rkey (%x/%x) differs from "
		       "hints (%x/%x); identity hint not honoured\n",
		       r->ufile_id, r->target_handle,
		       resp_lkey, resp_rkey, r->lkey_hint, r->rkey_hint);
		return -1;
	}

	/*
	 * Plugin-shaped UHW_OUT byte-equal verify. The cached plugin
	 * stuffed its expected echo into r->uhw_out_expected at PACK
	 * time; the kernel wrote the actual echo into uhw_out_actual.
	 * A mismatch means the kernel didn't honour a documented
	 * driver-private contract -- catch loudly. No driver registers
	 * an MR UHW_OUT today (mlx5 / rxe MR have none), so this is
	 * dormant in v0 and exists for forward compatibility with the
	 * hook contract declared in criu-plugin.h.
	 */
	if (r->uhw_out_verify_len > 0 &&
	    memcmp(uhw_out_actual, r->uhw_out_expected,
		   r->uhw_out_verify_len) != 0) {
		pr_err("RDMA: ufile_id=%x RESTORE_MR(target_handle=%u): "
		       "kernel UHW_OUT echo (verify %u of %u bytes) does "
		       "not match plugin's expected bytes\n",
		       r->ufile_id, r->target_handle,
		       r->uhw_out_verify_len, r->uhw_out_attr_len);
		return -1;
	}

	pr_info("RDMA: ufile_id=%x RESTORE_MR(target_handle=%u, "
		"lkey=%x, rkey=%x, driver_id=%u, uhw_in=%u) ok\n",
		r->ufile_id, r->target_handle, resp_lkey, resp_rkey,
		r->kernel_driver_id, r->uhw_in_len);
	return 0;
}

/*
 * This restores aio ring header, content, head and in-kernel position
 * of tail. To set tail, we write to /dev/null and use the fact this
 * operation is synchronous for the device. Also, we unmap temporary
 * anonymous area, used to store content of ring buffer during restore
 * and mapped in premap_private_vma().
 */
static int restore_aio_ring(struct rst_aio_ring *raio)
{
	struct aio_ring *ring = (void *)raio->addr, *new;
	int i, maxr, count, fd, ret;
	unsigned head = ring->head;
	unsigned tail = ring->tail;
	struct iocb *iocb, **iocbp;
	unsigned long ctx = 0;
	unsigned size;
	char buf[1];

	ret = sys_io_setup(raio->nr_req, &ctx);
	if (ret < 0) {
		pr_err("Ring setup failed with %d\n", ret);
		return -1;
	}

	new = (struct aio_ring *)ctx;
	i = (raio->len - sizeof(struct aio_ring)) / sizeof(struct io_event);
	if (tail >= ring->nr || head >= ring->nr || ring->nr != i || new->nr != ring->nr) {
		pr_err("wrong aio: tail=%x head=%x req=%x old_nr=%x new_nr=%x expect=%x\n", tail, head, raio->nr_req,
		       ring->nr, new->nr, i);

		return -1;
	}

	if (tail == 0 && head == 0)
		goto populate;

	fd = sys_open("/dev/null", O_WRONLY, 0);
	if (fd < 0) {
		pr_err("Can't open /dev/null for aio\n");
		return -1;
	}

	/*
	 * If tail < head, we have to do full turn and then submit
	 * tail more request, i.e. ring->nr + tail.
	 * If we do not do full turn, in-kernel completed_events
	 * will initialize wrong.
	 *
	 * Maximum number reqs to submit at once are ring->nr-1,
	 * so we won't allocate more.
	 */
	if (tail < head)
		count = ring->nr + tail;
	else
		count = tail;
	maxr = min_t(unsigned, count, ring->nr - 1);

	/*
	 * Since we only interested in moving the tail, the requests
	 * may be any. We submit count identical requests.
	 */
	size = sizeof(struct iocb) + maxr * sizeof(struct iocb *);
	iocb = (void *)sys_mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	iocbp = (void *)iocb + sizeof(struct iocb);

	if (IS_ERR(iocb)) {
		pr_err("Can't mmap aio tmp buffer: %ld\n", PTR_ERR(iocb));
		return -1;
	}

	iocb->aio_fildes = fd;
	iocb->aio_buf = (unsigned long)buf;
	iocb->aio_nbytes = 1;
	iocb->aio_lio_opcode = IOCB_CMD_PWRITE; /* Write is nop, read populates buf */

	for (i = 0; i < maxr; i++)
		iocbp[i] = iocb;

	i = 0;
	do {
		ret = sys_io_submit(ctx, count - i, iocbp);
		if (ret < 0) {
			pr_err("Can't submit aio iocbs: ret=%d\n", ret);
			return -1;
		}
		i += ret;

		/*
		  * We may submit less than requested, because of too big
		  * count OR behaviour of get_reqs_available(), which
		  * takes available requests only if their number is
		  * aliquot to kioctx::req_batch. Free part of buffer
		  * for next iteration.
		  *
		  * Direct set of head is equal to sys_io_getevents() call,
		  * and faster. See kernel for the details.
		  */
		((struct aio_ring *)ctx)->head = i < head ? i : head;
	} while (i < count);

	sys_munmap(iocb, size);
	sys_close(fd);

populate:
	i = offsetof(struct aio_ring, io_events);
	memcpy((void *)ctx + i, (void *)ring + i, raio->len - i);

	/*
	 * If we failed to get the proper nr_req right and
	 * created smaller or larger ring, then this remap
	 * will (should) fail, since AIO rings has immutable
	 * size.
	 *
	 * This is not great, but anyway better than putting
	 * a ring of wrong size into correct place.
	 *
	 * Also, this unmaps temporary anonymous area on raio->addr.
	 */

	ctx = sys_mremap(ctx, raio->len, raio->len, MREMAP_FIXED | MREMAP_MAYMOVE, raio->addr);
	if (ctx != raio->addr) {
		pr_err("Ring remap failed with %ld\n", ctx);
		return -1;
	}
	return 0;
}

static void rst_tcp_repair_off(struct rst_tcp_sock *rts)
{
	int aux, ret;

	aux = rts->reuseaddr;
	pr_debug("pie: Turning repair off for %d (reuse %d)\n", rts->sk, aux);
	tcp_repair_off(rts->sk);

	ret = sys_setsockopt(rts->sk, SOL_SOCKET, SO_REUSEADDR, &aux, sizeof(aux));
	if (ret < 0)
		pr_err("Failed to restore of SO_REUSEADDR on socket (%d)\n", ret);
}

static void rst_tcp_socks_all(struct task_restore_args *ta)
{
	int i;

	for (i = 0; i < ta->tcp_socks_n; i++)
		rst_tcp_repair_off(&ta->tcp_socks[i]);
}

static int enable_uffd(int uffd, unsigned long addr, unsigned long len)
{
	int rc;
	struct uffdio_register uffdio_register;
	unsigned long expected_ioctls;

	/*
	 * If uffd == -1, this means that userfaultfd is not enabled
	 * or it is not available.
	 */
	if (uffd == -1)
		return 0;

	uffdio_register.range.start = addr;
	uffdio_register.range.len = len;
	uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;

	pr_info("lazy-pages: register: %lx, len %lx\n", addr, len);

	rc = sys_ioctl(uffd, UFFDIO_REGISTER, (unsigned long)&uffdio_register);
	if (rc != 0) {
		pr_err("lazy-pages: register %lx failed: rc:%d, \n", addr, rc);
		return -1;
	}

	expected_ioctls = (1 << _UFFDIO_WAKE) | (1 << _UFFDIO_COPY) | (1 << _UFFDIO_ZEROPAGE);

	if ((uffdio_register.ioctls & expected_ioctls) != expected_ioctls) {
		pr_err("lazy-pages: unexpected missing uffd ioctl for anon memory\n");
	}

	return 0;
}

static int vma_remap(VmaEntry *vma_entry, int uffd)
{
	unsigned long src = vma_premmaped_start(vma_entry);
	unsigned long dst = vma_entry->start;
	unsigned long len = vma_entry_len(vma_entry);
	unsigned long guard = 0, tmp;

	pr_info("Remap %lx->%lx len %lx\n", src, dst, len);

	/*
	 * SHSTK VMAs are a bit special, in fact we create shstk vma right in the
	 * shstk_vma_restore() and populate it with contents from a premapped VMA
	 * (which in turns is just a normal anonymous VMA!). Then, we munmap() this
	 * premapped VMA. After, we need to adjust vma_premmaped_start(vma_entry)
	 * to point to a created shstk vma and treat it as a premmaped one in vma_remap().
	 */
	if (vma_entry_is(vma_entry, VMA_AREA_SHSTK)) {
		if (shstk_vma_restore(vma_entry)) {
			pr_err("Unable to prepare shadow stack vma for remap %lx -> %lx\n", src, dst);
			return -1;
		}

		/* shstk_vma_restore() modifies vma premapped address */
		src = vma_premmaped_start(vma_entry);
	}

	if (src - dst < len)
		guard = dst;
	else if (dst - src < len)
		guard = dst + len - PAGE_SIZE;

	if (src == dst)
		return 0;

	if (guard != 0) {
		/*
		 * mremap() returns an error if a target and source vma-s are
		 * overlapped. In this case the source vma are remapped in
		 * a temporary place and then remapped to the target address.
		 * Here is one hack to find non-ovelapped temporary place.
		 *
		 * 1. initial placement. We need to move src -> tgt.
		 * |       |+++++src+++++|
		 * |-----tgt-----|       |
		 *
		 * 2. map a guard page at the non-ovelapped border of a target vma.
		 * |       |+++++src+++++|
		 * |G|----tgt----|       |
		 *
		 * 3. remap src to any other place.
		 *    G prevents src from being remapped on tgt again
		 * |       |-------------| -> |+++++src+++++|
		 * |G|---tgt-----|                          |
		 *
		 * 4. remap src to tgt, no overlapping any longer
		 * |+++++src+++++|   <----    |-------------|
		 * |G|---tgt-----|                          |
		 */

		unsigned long addr;

		/* Map guard page (step 2) */
		tmp = sys_mmap((void *)guard, PAGE_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
		if (tmp != guard) {
			pr_err("Unable to map a guard page %lx (%lx)\n", guard, tmp);
			return -1;
		}

		/* Move src to non-overlapping place (step 3) */
		addr = sys_mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
		if (IS_ERR((void *)addr)) {
			pr_err("Unable to reserve memory (%lx)\n", addr);
			return -1;
		}

		tmp = sys_mremap(src, len, len, MREMAP_MAYMOVE | MREMAP_FIXED, addr);
		if (tmp != addr) {
			pr_err("Unable to remap %lx -> %lx (%lx)\n", src, addr, tmp);
			return -1;
		}

		src = addr;
	}

	tmp = sys_mremap(src, len, len, MREMAP_MAYMOVE | MREMAP_FIXED, dst);
	if (tmp != dst) {
		pr_err("Unable to remap %lx -> %lx\n", src, dst);
		return -1;
	}

	/*
	 * If running in userfaultfd/lazy-pages mode pages with
	 * MAP_ANONYMOUS and MAP_PRIVATE are remapped but without the
	 * real content.
	 * The function enable_uffd() marks the page(s) as userfaultfd
	 * pages, so that the processes will hang until the memory is
	 * injected via userfaultfd.
	 */
	if (vma_entry_can_be_lazy(vma_entry))
		if (enable_uffd(uffd, dst, len) != 0)
			return -1;

	return 0;
}

static int timerfd_arm(struct task_restore_args *args)
{
	int i;

	for (i = 0; i < args->timerfd_n; i++) {
		struct restore_timerfd *t = &args->timerfd[i];
		int ret;

		pr_debug("timerfd: arm for fd %d (%d)\n", t->fd, i);

		if (t->settime_flags & TFD_TIMER_ABSTIME) {
			struct timespec ts;

			/*
			 * We might need to adjust value because the checkpoint
			 * and restore procedure takes some time itself. Note
			 * we don't adjust nanoseconds, since the result may
			 * overflow the limit NSEC_PER_SEC FIXME
			 */
			if (sys_clock_gettime(t->clockid, &ts)) {
				pr_err("Can't get current time\n");
				return -1;
			}

			t->val.it_value.tv_sec += (time_t)ts.tv_sec;

			pr_debug("Adjust id %x it_value(%llu, %llu) -> it_value(%llu, %llu)\n", t->id,
				 (unsigned long long)ts.tv_sec, (unsigned long long)ts.tv_nsec,
				 (unsigned long long)t->val.it_value.tv_sec,
				 (unsigned long long)t->val.it_value.tv_nsec);
		}

		ret = sys_timerfd_settime(t->fd, t->settime_flags, &t->val, NULL);
		if (t->ticks)
			ret |= sys_ioctl(t->fd, TFD_IOC_SET_TICKS, (unsigned long)&t->ticks);
		if (ret) {
			pr_err("Can't restore ticks/time for timerfd - %d\n", i);
			return ret;
		}
	}
	return 0;
}

static int create_posix_timers(struct task_restore_args *args)
{
	int ret, i, exit_code = -1;
	kernel_timer_t next_id = 0, timer_id;
	struct sigevent sev;
	bool create_restore_ids = false;

	if (!args->posix_timers_n)
		return 0;

	/* prctl returns EINVAL if PR_TIMER_CREATE_RESTORE_IDS isn't supported. */
	ret = sys_prctl(PR_TIMER_CREATE_RESTORE_IDS,
			PR_TIMER_CREATE_RESTORE_IDS_ON, 0, 0, 0);
	if (ret == 0) {
		create_restore_ids = true;
	} else if (ret != -EINVAL) {
		pr_err("Can't enabled PR_TIMER_CREATE_RESTORE_IDS: %d\n", ret);
		return -1;
	}

	for (i = 0; i < args->posix_timers_n; i++) {
		sev.sigev_notify = args->posix_timers[i].spt.it_sigev_notify;
		sev.sigev_signo = args->posix_timers[i].spt.si_signo;
#ifdef __GLIBC__
		sev._sigev_un._tid = args->posix_timers[i].spt.notify_thread_id;
#else
		sev.sigev_notify_thread_id = args->posix_timers[i].spt.notify_thread_id;
#endif
		sev.sigev_value.sival_ptr = args->posix_timers[i].spt.sival_ptr;

		if (create_restore_ids) {
			/*
			 * With enabled PR_TIMER_CREATE_RESTORE_IDS, the
			 * timer_create syscall creates a new timer with the
			 * specified ID.
			 */
			timer_id = args->posix_timers[i].spt.it_id;
			ret = sys_timer_create(args->posix_timers[i].spt.clock_id, &sev, &timer_id);
			if (ret < 0) {
				pr_err("Can't create posix timer - %d: %d\n", i, ret);
				goto out;
			}
			if (timer_id != args->posix_timers[i].spt.it_id) {
				pr_err("Unexpected timer id %u (expected %lu)\n",
				       timer_id, args->posix_timers[i].spt.it_id);
				goto out;
			}
			continue;
		}

		while (1) {
			ret = sys_timer_create(args->posix_timers[i].spt.clock_id, &sev, &timer_id);
			if (ret < 0) {
				pr_err("Can't create posix timer - %d\n", i);
				goto out;
			}

			if (timer_id != next_id) {
				pr_err("Can't create timers, kernel don't give them consequently\n");
				goto out;
			}
			next_id++;

			if (timer_id == args->posix_timers[i].spt.it_id)
				break;

			ret = sys_timer_delete(timer_id);
			if (ret < 0) {
				pr_err("Can't remove temporaty posix timer 0x%x\n", timer_id);
				goto out;
			}
		}
	}

	exit_code = 0;
out:
	if (create_restore_ids) {
		ret = sys_prctl(PR_TIMER_CREATE_RESTORE_IDS,
				PR_TIMER_CREATE_RESTORE_IDS_OFF, 0, 0, 0);
		if (ret != 0) {
			pr_err("Can't disable PR_TIMER_CREATE_RESTORE_IDS: %d\n", ret);
			exit_code = -1;
		}
	}
	return exit_code;
}

static void restore_posix_timers(struct task_restore_args *args)
{
	int i;
	struct restore_posix_timer *rt;

	for (i = 0; i < args->posix_timers_n; i++) {
		rt = &args->posix_timers[i];
		sys_timer_settime((kernel_timer_t)rt->spt.it_id, 0, &rt->val, NULL);
	}
}

/*
 * sys_munmap must not return here. The control process must
 * trap us on the exit from sys_munmap.
 */
unsigned long vdso_rt_size = 0;

void *bootstrap_start = NULL;
unsigned int bootstrap_len = 0;

__visible void __export_unmap(void)
{
	sys_munmap(bootstrap_start, bootstrap_len - vdso_rt_size);
}

static int unregister_libc_rseq(struct rst_rseq_param *rseq)
{
	long ret;

	if (!rseq->rseq_abi_pointer)
		return 0;

	ret = sys_rseq(decode_pointer(rseq->rseq_abi_pointer), rseq->rseq_abi_size, 1, rseq->signature);
	if (ret) {
		pr_err("Failed to unregister libc rseq %ld\n", ret);
		return -1;
	}
	return 0;
}

/*
 * This function unmaps all VMAs, which don't belong to
 * the restored process or the restorer.
 *
 * The restorer memory is two regions -- area with restorer, its stack
 * and arguments and the one with private vmas of the tasks we restore
 * (a.k.a. premmaped area):
 *
 * 0                       task_size
 * +----+====+----+====+---+
 *
 * Thus to unmap old memory we have to do 3 unmaps:
 * [ 0 -- 1st area start ]
 * [ 1st end -- 2nd start ]
 * [ 2nd start -- task_size ]
 */
static int unmap_old_vmas(void *premmapped_addr, unsigned long premmapped_len, void *bootstrap_start,
			  unsigned long bootstrap_len, unsigned long task_size)
{
	unsigned long s1, s2;
	void *p1, *p2;
	int ret;

	if (premmapped_addr < bootstrap_start) {
		p1 = premmapped_addr;
		s1 = premmapped_len;
		p2 = bootstrap_start;
		s2 = bootstrap_len;
	} else {
		p2 = premmapped_addr;
		s2 = premmapped_len;
		p1 = bootstrap_start;
		s1 = bootstrap_len;
	}

	ret = sys_munmap(NULL, p1 - NULL);
	if (ret) {
		pr_err("Unable to unmap (%p-%p): %d\n", NULL, p1, ret);
		return -1;
	}

	ret = sys_munmap(p1 + s1, p2 - (p1 + s1));
	if (ret) {
		pr_err("Unable to unmap (%p-%p): %d\n", p1 + s1, p2, ret);
		return -1;
	}

	ret = sys_munmap(p2 + s2, task_size - (unsigned long)(p2 + s2));
	if (ret) {
		pr_err("Unable to unmap (%p-%p): %d\n", p2 + s2, (void *)task_size, ret);
		return -1;
	}

	return 0;
}

static int wait_helpers(struct task_restore_args *task_args)
{
	int i;

	for (i = 0; i < task_args->helpers_n; i++) {
		int status;
		pid_t pid = task_args->helpers[i];

		/* Check that a helper completed. */
		if (sys_wait4(pid, &status, 0, NULL) == -ECHILD) {
			/* It has been waited in sigchld_handler */
			continue;
		}
		if (!WIFEXITED(status) || WEXITSTATUS(status)) {
			pr_err("%d exited with non-zero code (%d,%d)\n", pid, WEXITSTATUS(status), WTERMSIG(status));
			return -1;
		}
	}

	return 0;
}

static int wait_zombies(struct task_restore_args *task_args)
{
	int i;

	for (i = 0; i < task_args->zombies_n; i++) {
		int ret, nr_in_progress;

		nr_in_progress = futex_get(&task_entries_local->nr_in_progress);

		ret = sys_waitid(P_PID, task_args->zombies[i], NULL, WNOWAIT | WEXITED, NULL);
		if (ret == -ECHILD) {
			/* A process isn't reparented to this task yet.
			 * Let's wait when someone complete this stage
			 * and try again.
			 */
			futex_wait_while_eq(&task_entries_local->nr_in_progress, nr_in_progress);
			i--;
			continue;
		}
		if (ret < 0) {
			pr_err("Wait on %d zombie failed: %d\n", task_args->zombies[i], ret);
			return -1;
		}
		pr_debug("%ld: Collect a zombie with pid %d\n", sys_getpid(), task_args->zombies[i]);
	}

	return 0;
}

static bool can_restore_vdso(struct task_restore_args *args)
{
	struct vdso_maps *rt = &args->vdso_maps_rt;
	bool had_vdso = false, had_vvar = false;
	unsigned int i;

	for (i = 0; i < args->vmas_n; i++) {
		VmaEntry *vma = &args->vmas[i];

		if (vma_entry_is(vma, VMA_AREA_VDSO))
			had_vdso = true;
		if (vma_entry_is(vma, VMA_AREA_VVAR))
			had_vvar = true;
	}

	if (had_vdso && (rt->vdso_start == VDSO_BAD_ADDR)) {
		pr_err("Task had vdso, restorer doesn't\n");
		return false;
	}

	/*
	 * There is a use-case for restoring vvar alone: valgrind (see #488).
	 * On the other side, we expect that vvar is touched by application
	 * only from vdso. So, we can put a stale page and proceed restore
	 * if kernel doesn't provide vvar [but provides vdso, if needede.
	 * Just warn aloud that we don't like it.
	 */
	if (had_vvar && (rt->vvar_start == VVAR_BAD_ADDR))
		pr_warn("Can't restore vvar - continuing regardless\n");

	return true;
}

static inline int restore_child_subreaper(int child_subreaper)
{
	int ret;

	if (!child_subreaper)
		return 0;

	ret = sys_prctl(PR_SET_CHILD_SUBREAPER, child_subreaper, 0, 0, 0);
	if (ret) {
		pr_err("Unable to set PR_SET_CHILD_SUBREAPER(%d): %d\n", child_subreaper, ret);
		return -1;
	}

	return 0;
}

static int map_vdso(struct task_restore_args *args, bool compatible)
{
	struct vdso_maps *rt = &args->vdso_maps_rt;
	int err;

	err = arch_map_vdso(args->vdso_rt_parked_at, compatible);
	if (err < 0) {
		pr_err("Failed to map vdso %d\n", err);
		return err;
	}

	/* kernel may provide only vdso */
	if (rt->sym.vvar_size == VVAR_BAD_SIZE) {
		rt->vdso_start = args->vdso_rt_parked_at;
		rt->vvar_start = VVAR_BAD_ADDR;
		return 0;
	}

	if (rt->sym.vdso_before_vvar) {
		rt->vdso_start = args->vdso_rt_parked_at;
		rt->vvar_start = rt->vdso_start + rt->sym.vdso_size;
	} else {
		rt->vvar_start = args->vdso_rt_parked_at;
		rt->vdso_start = rt->vvar_start + rt->sym.vvar_size;
	}

	return 0;
}

static int fd_poll(int inotify_fd)
{
	struct pollfd pfd = { inotify_fd, POLLIN, 0 };
	struct timespec tmo = { 0, 0 };

	return sys_ppoll(&pfd, 1, &tmo, NULL, sizeof(sigset_t));
}

/*
 * Call preadv() but limit size of the read. Zero `max_to_read` skips the limit.
 */
static ssize_t preadv_limited(int fd, struct iovec *iovs, int nr, off_t offs, size_t max_to_read)
{
	size_t saved_last_iov_len = 0;
	ssize_t ret;

	if (max_to_read) {
		for (int i = 0; i < nr; ++i) {
			if (iovs[i].iov_len <= max_to_read) {
				max_to_read -= iovs[i].iov_len;
				continue;
			}

			if (!max_to_read) {
				nr = i;
				break;
			}

			saved_last_iov_len = iovs[i].iov_len;
			iovs[i].iov_len = max_to_read;
			nr = i + 1;
			break;
		}
	}

	ret = sys_preadv(fd, iovs, nr, offs);
	if (saved_last_iov_len)
		iovs[nr - 1].iov_len = saved_last_iov_len;

	return ret;
}

/*
 * In the worst case buf size should be:
 *   sizeof(struct inotify_event) * 2 + PATH_MAX
 * See round_event_name_len() in kernel.
 */
#define EVENT_BUFF_SIZE ((sizeof(struct inotify_event) * 2 + PATH_MAX))

/*
 * Read all available events from inotify queue
 */
static int cleanup_inotify_events(int inotify_fd)
{
	char buf[EVENT_BUFF_SIZE * 3];
	int ret;

	/* Limit buf to be lesser than half of restorer's stack */
	BUILD_BUG_ON(ARRAY_SIZE(buf) >= RESTORE_STACK_SIZE / 2);

	while (1) {
		ret = fd_poll(inotify_fd);
		if (ret < 0) {
			pr_err("Failed to poll from inotify fd: %d\n", ret);
			return -1;
		} else if (ret == 0) {
			break;
		}

		ret = sys_read(inotify_fd, buf, sizeof(buf));
		if (ret < 0) {
			pr_err("Failed to read inotify events\n");
			return -1;
		}
	}

	return 0;
}

/*
 * When we restore inotifies we can open and close files we create a watch
 * for. So we need to cleanup these auxiliary events which we've generated.
 *
 * note: For now we don't have a way to c/r events in queue but we need to
 * at least leave the queue clean from events generated by our own.
 */
int cleanup_current_inotify_events(struct task_restore_args *task_args)
{
	int i;

	for (i = 0; i < task_args->inotify_fds_n; i++) {
		int inotify_fd = task_args->inotify_fds[i];

		pr_debug("Cleaning inotify events from %d\n", inotify_fd);

		if (cleanup_inotify_events(inotify_fd))
			return -1;
	}

	return 0;
}

/*
 * Restore membarrier() registrations.
 */
static int restore_membarrier_registrations(int mask)
{
	unsigned long bitmap[1] = { mask };
	int i, err, ret = 0;

	if (!mask)
		return 0;

	pr_info("Restoring membarrier() registrations %x\n", mask);

	for_each_bit(i, bitmap) {
		err = sys_membarrier(1 << i, 0, 0);
		if (!err)
			continue;
		pr_err("Can't restore membarrier(1 << %d) registration: %d\n", i, err);
		ret = -1;
	}

	return ret;
}

static int restore_madv_guard_regions(struct task_restore_args *args)
{
	int i, ret;

	for (i = 0; i < args->vmas_n; i++) {
		VmaEntry *vma_entry = args->vmas + i;
		size_t len;

		if (!vma_entry_is(vma_entry, VMA_AREA_GUARD))
			continue;

		len = vma_entry->end - vma_entry->start;
		ret = sys_madvise(vma_entry->start, len, MADV_GUARD_INSTALL);
		if (ret) {
			pr_err("madvise(%" PRIx64 ", %zu, MADV_GUARD_INSTALL) "
			       "failed with %d\n",
			       vma_entry->start, len, ret);
			return -1;
		}
	}

	return 0;
}

/*
 * The main routine to restore task via sigreturn.
 * This one is very special, we never return there
 * but use sigreturn facility to restore core registers
 * and jump execution to some predefined ip read from
 * core file.
 */
__visible long __export_restore_task(struct task_restore_args *args)
{
	long ret = -1;
	int i;
	VmaEntry *vma_entry;
	unsigned long va;
	struct restore_vma_io *rio;
	struct rt_sigframe *rt_sigframe;
	struct prctl_mm_map prctl_map;
	unsigned long new_sp;
	k_rtsigset_t to_block;
	pid_t my_pid = sys_getpid();
	rt_sigaction_t act;
	bool has_vdso_proxy;

	bootstrap_start = args->bootstrap_start;
	bootstrap_len = args->bootstrap_len;

	vdso_rt_size = args->vdso_rt_size;

	fi_strategy = args->fault_strategy;

	task_entries_local = args->task_entries;
	helpers = args->helpers;
	n_helpers = args->helpers_n;
	zombies = args->zombies;
	n_zombies = args->zombies_n;
#ifdef ARCH_HAS_LONG_PAGES
	__page_size = args->page_size;
#endif

	ksigfillset(&act.rt_sa_mask);
	act.rt_sa_handler = sigchld_handler;
	act.rt_sa_flags = SA_SIGINFO | SA_RESTORER | SA_RESTART;
	act.rt_sa_restorer = cr_restore_rt;
	ret = sys_sigaction(SIGCHLD, &act, NULL, sizeof(k_rtsigset_t));
	if (ret) {
		pr_err("Failed to set SIGCHLD %ld\n", ret);
		goto core_restore_end;
	}

	ksigemptyset(&to_block);
	ksigaddset(&to_block, SIGCHLD);
	ret = sys_sigprocmask(SIG_UNBLOCK, &to_block, NULL, sizeof(k_rtsigset_t));
	if (ret) {
		pr_err("Failed to unblock SIGCHLD %ld\n", ret);
		goto core_restore_end;
	}

	std_log_set_fd(args->logfd);
	std_log_set_loglevel(args->loglevel);
	std_log_set_start(&args->logstart);

	pr_info("Switched to the restorer %d\n", my_pid);

	if (args->uffd > -1) {
		pr_debug("lazy-pages: uffd %d\n", args->uffd);
	}

	if (arch_shstk_switch_to_restorer(&args->shstk))
		goto core_restore_end;

	/*
	 * Park vdso/vvar in a safe place if architecture doesn't support
	 * mapping them with arch_prctl().
	 * Always preserve/map rt-vdso pair if it's possible, regardless
	 * it's presence in original task: vdso will be used for fast
	 * gettimeofday() in restorer's log timings.
	 */
	if (!args->can_map_vdso && vdso_is_present(&args->vdso_maps_rt)) {
		/* It's already checked in kdat, but let's check again */
		if (args->compatible_mode) {
			pr_err("Compatible mode without vdso map support\n");
			goto core_restore_end;
		}
		if (!can_restore_vdso(args))
			goto core_restore_end;
		if (vdso_do_park(&args->vdso_maps_rt, args->vdso_rt_parked_at, vdso_rt_size))
			goto core_restore_end;
	}

	/*
	 * We may have rseq registered already if CRIU compiled against
	 * a fresh Glibc with rseq support. Anyway, we need to unregister it
	 * before doing unmap_old_vmas or we will get SIGSEGV from the kernel,
	 * for instance once the kernel will want to update (struct rseq).cpu_id field:
	 * https://github.com/torvalds/linux/blob/ce522ba9ef7e/kernel/rseq.c#L89
	 */
	if (unregister_libc_rseq(&args->libc_rseq))
		goto core_restore_end;

	if (unmap_old_vmas((void *)args->premmapped_addr, args->premmapped_len, bootstrap_start, bootstrap_len,
			   args->task_size))
		goto core_restore_end;

	/* Map vdso that wasn't parked */
	if (args->can_map_vdso && (map_vdso(args, args->compatible_mode) < 0))
		goto core_restore_end;

	vdso_update_gtod_addr(&args->vdso_maps_rt);

	/* Shift private vma-s to the left */
	for (i = 0; i < args->vmas_n; i++) {
		vma_entry = args->vmas + i;

		if (!vma_entry_is(vma_entry, VMA_PREMMAPED))
			continue;

		if (vma_entry->end >= args->task_size)
			continue;

		if (vma_entry->start > vma_entry->shmid)
			break;

		if (vma_remap(vma_entry, args->uffd))
			goto core_restore_end;
	}

	/* Shift private vma-s to the right */
	for (i = args->vmas_n - 1; i >= 0; i--) {
		vma_entry = args->vmas + i;

		if (!vma_entry_is(vma_entry, VMA_PREMMAPED))
			continue;

		if (vma_entry->start > args->task_size)
			continue;

		if (vma_entry->start < vma_entry->shmid)
			break;

		if (vma_remap(vma_entry, args->uffd))
			goto core_restore_end;
	}

	ret = sys_prctl(PR_SET_THP_DISABLE, args->thp_disabled, 0, 0, 0);
	if (ret) {
		pr_err("Cannot restore THP_DISABLE=%d flag: %ld\n", args->thp_disabled, ret);
		goto core_restore_end;
	}

	if (args->uffd > -1) {
		pr_debug("lazy-pages: closing uffd %d\n", args->uffd);
		/*
		 * All userfaultfd configuration has finished at this point.
		 * Let's close the UFFD file descriptor, so that the restored
		 * process does not have an opened UFFD FD for ever.
		 */
		sys_close(args->uffd);
	}

	/*
	 * OK, lets try to map new one.
	 */
	for (i = 0; i < args->vmas_n; i++) {
		vma_entry = args->vmas + i;

		if (!vma_entry_is(vma_entry, VMA_AREA_REGULAR) && !vma_entry_is(vma_entry, VMA_AREA_AIORING))
			continue;

		if (vma_entry_is(vma_entry, VMA_PREMMAPED))
			continue;

		va = restore_mapping(vma_entry);

		if (va != vma_entry->start) {
			pr_err("Can't restore %" PRIx64 " mapping with %lx\n", vma_entry->start, va);
			goto core_restore_end;
		}
	}

	/*
	 * Now read the contents (if any)
	 */

	rio = args->vma_ios;
	for (i = 0; i < args->vma_ios_n; i++) {
		struct iovec *iovs = rio->iovs;
		int nr = rio->nr_iovs;
		ssize_t r;

		while (nr) {
			pr_debug("Preadv %lx:%d... (%d iovs)\n", (unsigned long)iovs->iov_base, (int)iovs->iov_len, nr);
			/*
			 * If we're requested to punch holes in the file after reading we do
			 * it to save memory. Limit the reads then to an arbitrary block size.
			 */
			r = preadv_limited(args->vma_ios_fd, iovs, nr, rio->off,
					   args->auto_dedup ? AUTO_DEDUP_OVERHEAD_BYTES : 0);
			if (r < 0) {
				pr_err("Can't read pages data (%d)\n", (int)r);
				goto core_restore_end;
			}

			if (r == 0) {
				pr_err("Unexpected EOF reading pages data at offset %ld (%d iovs remaining)\n",
				       (long)rio->off, nr);
				goto core_restore_end;
			}

			pr_debug("`- returned %ld\n", (long)r);
			/* If the file is open for writing, then it means we should punch holes
			 * in it. */
			if (r > 0 && args->auto_dedup) {
				int fr = sys_fallocate(args->vma_ios_fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
						       rio->off, r);
				if (fr < 0) {
					pr_debug("Failed to punch holes with fallocate: %d\n", fr);
				}
			}
			rio->off += r;
			/* Advance the iovecs */
			do {
				if (iovs->iov_len <= r) {
					pr_debug("   `- skip pagemap\n");
					r -= iovs->iov_len;
					iovs++;
					nr--;
					continue;
				}

				iovs->iov_base += r;
				iovs->iov_len -= r;
				break;
			} while (nr > 0);
		}

		rio = ((void *)rio) + RIO_SIZE(rio->nr_iovs);
	}

	if (args->vma_ios_fd != -1)
		sys_close(args->vma_ios_fd);

	/*
	 * Proxify vDSO.
	 */
	if (vdso_proxify(&args->vdso_maps_rt, &has_vdso_proxy, args->vmas, args->vmas_n, args->compatible_mode,
			 fault_injected(FI_VDSO_TRAMPOLINES)))
		goto core_restore_end;

	/* unmap rt-vdso with restorer blob after restore's finished */
	if (!has_vdso_proxy)
		vdso_rt_size = 0;

	/*
	 * Walk though all VMAs again to drop PROT_WRITE
	 * if it was not there.
	 */
	for (i = 0; i < args->vmas_n; i++) {
		vma_entry = args->vmas + i;

		if (!(vma_entry_is(vma_entry, VMA_AREA_REGULAR)))
			continue;

		if ((vma_entry->prot & PROT_WRITE) || (vma_entry->status & VMA_NO_PROT_WRITE))
			continue;

		sys_mprotect(decode_pointer(vma_entry->start), vma_entry_len(vma_entry), vma_entry->prot);
	}

	/*
	 * Now when all VMAs are in their places time to set
	 * up AIO rings.
	 */

	for (i = 0; i < args->rings_n; i++)
		if (restore_aio_ring(&args->rings[i]) < 0)
			goto core_restore_end;

	/*
	 * RDMA per-uobject restore (CQs, QPs, MRs). Same "needs the
	 * user mm laid out at its final VAs" rationale as AIO rings --
	 * mlx5_ib_umem_restore_cq pins the CQ buffer / doorbell pages
	 * via pin_user_pages_fast against current->mm, mlx5_ib_umem_
	 * restore_qp does the same for the WQ buffer / doorbell, and
	 * rxe's RESTORE_MR pins the MR's user buffer the same way. All
	 * only succeed once anon-private VMAs have actually been
	 * mmap'd at the source-side addresses (the pie blob's job,
	 * just above this loop). Issued here so any -EFAULT surfaces
	 * against a fully-laid-out mm and is a real driver bug, not a
	 * CRIU ordering artefact.
	 *
	 * CQ before QP before MR: matches the kernel-side parent
	 * dependency graph. QP's IDR attrs reference SEND_CQ and
	 * RECV_CQ ufile_handles which the dispatcher resolves through
	 * the destination ucontext IDR; if those CQ uobjects haven't
	 * been installed yet, RESTORE_QP rejects with -ENOENT before
	 * the driver runs. MR is independent and could equally well
	 * run before CQ; QP-then-MR keeps the order forward-compat.
	 */
	if (args->rdma_cqs_n)
		pr_info("RDMA: pie restorer: dispatching %u CQ(s)\n",
			args->rdma_cqs_n);
	for (i = 0; i < args->rdma_cqs_n; i++)
		if (restore_rdma_cq(&args->rdma_cqs[i]) < 0)
			goto core_restore_end;
	if (args->rdma_qps_n)
		pr_info("RDMA: pie restorer: dispatching %u QP(s)\n",
			args->rdma_qps_n);
	for (i = 0; i < args->rdma_qps_n; i++)
		if (restore_rdma_qp(&args->rdma_qps[i]) < 0)
			goto core_restore_end;
	if (args->rdma_mrs_n)
		pr_info("RDMA: pie restorer: dispatching %u MR(s)\n",
			args->rdma_mrs_n);
	for (i = 0; i < args->rdma_mrs_n; i++)
		if (restore_rdma_mr(&args->rdma_mrs[i]) < 0)
			goto core_restore_end;

	/*
	 * Finally restore madivse() bits
	 */
	for (i = 0; i < args->vmas_n; i++) {
		unsigned long m;

		vma_entry = args->vmas + i;
		if (!vma_entry->has_madv || !vma_entry->madv)
			continue;

		for (m = 0; m < sizeof(vma_entry->madv) * 8; m++) {
			if (vma_entry->madv & (1ul << m)) {
				if (!(vma_entry_is(vma_entry, VMA_AREA_REGULAR)))
					continue;

				ret = sys_madvise(vma_entry->start, vma_entry_len(vma_entry), m);
				if (ret) {
					pr_err("madvise(%" PRIx64 ", %" PRIu64 ", %ld) "
					       "failed with %ld\n",
					       vma_entry->start, vma_entry_len(vma_entry), m, ret);
					goto core_restore_end;
				}
			}
		}
	}

	/*
	 * Restore madvise(MADV_GUARD_INSTALL)
	 */
	ret = restore_madv_guard_regions(args);
	if (ret)
		goto core_restore_end;

	/*
	 * Tune up the task fields.
	 */
	ret = sys_prctl_safe(PR_SET_NAME, (long)args->comm, 0, 0);
	if (ret)
		goto core_restore_end;

	/*
	 * New kernel interface with @PR_SET_MM_MAP will become
	 * more widespread once kernel get deployed over the world.
	 * Thus lets be opportunistic and use new interface as a try.
	 */
	prctl_map = (struct prctl_mm_map){
		.start_code = args->mm.mm_start_code,
		.end_code = args->mm.mm_end_code,
		.start_data = args->mm.mm_start_data,
		.end_data = args->mm.mm_end_data,
		.start_stack = args->mm.mm_start_stack,
		.start_brk = args->mm.mm_start_brk,
		.brk = args->mm.mm_brk,
		.arg_start = args->mm.mm_arg_start,
		.arg_end = args->mm.mm_arg_end,
		.env_start = args->mm.mm_env_start,
		.env_end = args->mm.mm_env_end,
		.auxv = (void *)args->mm_saved_auxv,
		.auxv_size = args->mm_saved_auxv_size,
		.exe_fd = args->fd_exe_link,
	};
	ret = sys_prctl(PR_SET_MM, PR_SET_MM_MAP, (long)&prctl_map, sizeof(prctl_map), 0);
	if (ret) {
		pr_debug("prctl PR_SET_MM_MAP failed with %d\n", (int)ret);
		pr_debug("  .start_code = %" PRIx64 "\n", prctl_map.start_code);
		pr_debug("  .end_code = %" PRIx64 "\n", prctl_map.end_code);
		pr_debug("  .start_data = %" PRIx64 "\n", prctl_map.start_data);
		pr_debug("  .end_data = %" PRIx64 "\n", prctl_map.end_data);
		pr_debug("  .start_stack = %" PRIx64 "\n", prctl_map.start_stack);
		pr_debug("  .start_brk = %" PRIx64 "\n", prctl_map.start_brk);
		pr_debug("  .brk = %" PRIx64 "\n", prctl_map.brk);
		pr_debug("  .arg_start = %" PRIx64 "\n", prctl_map.arg_start);
		pr_debug("  .arg_end = %" PRIx64 "\n", prctl_map.arg_end);
		pr_debug("  .env_start = %" PRIx64 "\n", prctl_map.env_start);
		pr_debug("  .env_end = %" PRIx64 "\n", prctl_map.env_end);
		pr_debug("  .auxv_size = %" PRIu32 "\n", prctl_map.auxv_size);
		for (i = 0; i < prctl_map.auxv_size / sizeof(uint64_t); i++)
			pr_debug("  .auxv[%d] = %" PRIx64 "\n", i, prctl_map.auxv[i]);
		pr_debug("  .exe_fd = %" PRIu32 "\n", prctl_map.exe_fd);
	}
	if (ret == -EINVAL) {
		ret = sys_prctl_safe(PR_SET_MM, PR_SET_MM_START_CODE, (long)args->mm.mm_start_code, 0);
		ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_END_CODE, (long)args->mm.mm_end_code, 0);
		ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_START_DATA, (long)args->mm.mm_start_data, 0);
		ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_END_DATA, (long)args->mm.mm_end_data, 0);
		ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_START_STACK, (long)args->mm.mm_start_stack, 0);
		ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_START_BRK, (long)args->mm.mm_start_brk, 0);
		ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_BRK, (long)args->mm.mm_brk, 0);
		ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_ARG_START, (long)args->mm.mm_arg_start, 0);
		ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_ARG_END, (long)args->mm.mm_arg_end, 0);
		ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_ENV_START, (long)args->mm.mm_env_start, 0);
		ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_ENV_END, (long)args->mm.mm_env_end, 0);
		ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_AUXV, (long)args->mm_saved_auxv, args->mm_saved_auxv_size);

		/*
		 * Because of requirements applied from kernel side
		 * we need to restore /proc/pid/exe symlink late,
		 * after old existing VMAs are superseded with
		 * new ones from image file.
		 */
		ret |= restore_self_exe_late(args);
	} else {
		if (ret)
			pr_err("sys_prctl(PR_SET_MM, PR_SET_MM_MAP) failed with %d\n", (int)ret);
		sys_close(args->fd_exe_link);
	}

	if (ret)
		goto core_restore_end;

	/* SELinux (1) process context needs to be set before creating threads. */
	if (args->lsm_type == LSMTYPE__SELINUX) {
		/* Only for SELinux */
		if (lsm_set_label(args->t->creds_args->lsm_profile, "current", args->proc_fd) < 0)
			goto core_restore_end;
	}

	/*
	 * We need to prepare a valid sigframe here, so
	 * after sigreturn the kernel will pick up the
	 * registers from the frame, set them up and
	 * finally pass execution to the new IP.
	 */
	rt_sigframe = (void *)&args->t->mz->rt_sigframe;

	if (restore_thread_common(args->t))
		goto core_restore_end;

	/*
	 * Threads restoration. This requires some more comments. This
	 * restorer routine and thread restorer routine has the following
	 * memory map, prepared by a caller code.
	 *
	 * | <-- low addresses                                          high addresses --> |
	 * +-------------------------------------------------------+-----------------------+
	 * | this proc body | own stack | rt_sigframe space | thread restore zone   |
	 * +-------------------------------------------------------+-----------------------+
	 *
	 * where each thread restore zone is the following
	 *
	 * | <-- low addresses                                     high addresses --> |
	 * +--------------------------------------------------------------------------+
	 * | thread restore proc | thread1 stack | thread1 rt_sigframe |
	 * +--------------------------------------------------------------------------+
	 */

	if (args->nr_threads > 1) {
		struct thread_restore_args *thread_args = args->thread_args;
		long clone_flags = CLONE_VM | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_FS;
		long last_pid_len;
		pid_t thread_pid;
		long parent_tid;
		int i, fd = -1;

		if (!args->has_clone3_set_tid) {
			/* One level pid ns hierarhy */
			fd = sys_openat(args->proc_fd, LAST_PID_PATH, O_RDWR, 0);
			if (fd < 0) {
				pr_err("can't open last pid fd %d\n", fd);
				goto core_restore_end;
			}
		}
		mutex_lock(&task_entries_local->last_pid_mutex);

		for (i = 0; i < args->nr_threads; i++) {
			char last_pid_buf[16], *s;

			/* skip self */
			if (thread_args[i].pid == args->t->pid)
				continue;

			new_sp = restorer_stack(thread_args[i].mz);
			if (args->has_clone3_set_tid) {
				struct _clone_args c_args = {};
				thread_pid = thread_args[i].pid;
				c_args.set_tid = ptr_to_u64(&thread_pid);
				c_args.flags = clone_flags;
				c_args.set_tid_size = 1;
				/* The kernel does stack + stack_size. */
				c_args.stack = new_sp - RESTORE_STACK_SIZE;
				c_args.stack_size = RESTORE_STACK_SIZE;
				c_args.child_tid = ptr_to_u64(&thread_args[i].pid);
				c_args.parent_tid = ptr_to_u64(&parent_tid);
				pr_debug("Using clone3 to restore the process\n");
				RUN_CLONE3_RESTORE_FN(ret, c_args, sizeof(c_args), &thread_args[i],
						      args->clone_restore_fn);
			} else {
				last_pid_len =
					std_vprint_num(last_pid_buf, sizeof(last_pid_buf), thread_args[i].pid - 1, &s);
				sys_lseek(fd, 0, SEEK_SET);
				ret = sys_write(fd, s, last_pid_len);
				if (ret < 0) {
					pr_err("Can't set last_pid %ld/%s\n", ret, s);
					sys_close(fd);
					mutex_unlock(&task_entries_local->last_pid_mutex);
					goto core_restore_end;
				}

				/*
				 * To achieve functionality like libc's clone()
				 * we need a pure assembly here, because clone()'ed
				 * thread will run with own stack and we must not
				 * have any additional instructions... oh, dear...
				 */
				RUN_CLONE_RESTORE_FN(ret, clone_flags, new_sp, parent_tid, thread_args,
						     args->clone_restore_fn);
			}
			if (ret != thread_args[i].pid) {
				pr_err("Unable to create a thread: %ld\n", ret);
				sys_close(fd);
				mutex_unlock(&task_entries_local->last_pid_mutex);
				goto core_restore_end;
			}
		}

		mutex_unlock(&task_entries_local->last_pid_mutex);
		if (fd >= 0)
			sys_close(fd);
	}

	restore_rlims(args);

	ret = create_posix_timers(args);
	if (ret < 0) {
		pr_err("Can't restore posix timers %ld\n", ret);
		goto core_restore_end;
	}

	ret = timerfd_arm(args);
	if (ret < 0) {
		pr_err("Can't restore timerfd %ld\n", ret);
		goto core_restore_end;
	}

	if (restore_membarrier_registrations(args->membarrier_registration_mask) < 0)
		goto core_restore_end;

	pr_info("%ld: Restored\n", sys_getpid());

	restore_finish_stage(task_entries_local, CR_STATE_RESTORE);

	if (wait_helpers(args) < 0)
		goto core_restore_end;
	if (wait_zombies(args) < 0)
		goto core_restore_end;

	ksigfillset(&to_block);
	ret = sys_sigprocmask(SIG_SETMASK, &to_block, NULL, sizeof(k_rtsigset_t));
	if (ret) {
		pr_err("Unable to block signals %ld\n", ret);
		goto core_restore_end;
	}

	if (cleanup_current_inotify_events(args))
		goto core_restore_end;

	if (!args->compatible_mode) {
		ret = sys_sigaction(SIGCHLD, &args->sigchld_act, NULL, sizeof(k_rtsigset_t));
	} else {
		void *stack = alloc_compat_syscall_stack();

		if (!stack) {
			pr_err("Failed to allocate 32-bit stack for sigaction\n");
			goto core_restore_end;
		}
		ret = arch_compat_rt_sigaction(stack, SIGCHLD, (void *)&args->sigchld_act);
		free_compat_syscall_stack(stack);
	}
	if (ret) {
		pr_err("Failed to restore SIGCHLD: %ld\n", ret);
		goto core_restore_end;
	}

	ret = restore_signals(args->siginfo, args->siginfo_n, true);
	if (ret)
		goto core_restore_end;

	ret = restore_signals(args->t->siginfo, args->t->siginfo_n, false);
	if (ret)
		goto core_restore_end;

	restore_finish_stage(task_entries_local, CR_STATE_RESTORE_SIGCHLD);

	rst_tcp_socks_all(args);

	/*
	 * Make sure it's before creds, since it's privileged
	 * operation bound to uid 0 in current user ns.
	 */
	if (restore_seccomp(args->t))
		goto core_restore_end;

	/*
	 * Writing to last-pid is CAP_SYS_ADMIN protected,
	 * turning off TCP repair is CAP_SYS_NED_ADMIN protected,
	 * thus restore* creds _after_ all of the above.
	 */
	ret = restore_creds(args->t->creds_args, args->proc_fd, args->lsm_type, args->uid);
	ret = ret || restore_dumpable_flag(&args->mm);
	ret = ret || restore_pdeath_sig(args->t);
	ret = ret || restore_child_subreaper(args->child_subreaper);

	atomic_set(&thread_inprogress, args->nr_threads);
	rst_mem = args->rst_mem;
	rst_mem_size = args->rst_mem_size;

	/*
	 * Shadow stack of the leader can be locked only after all other
	 * threads were cloned, otherwise they may start with read-only
	 * shadow stack.
	 */
	if (arch_shstk_restore(&args->shstk))
		goto core_restore_end;

	restore_finish_stage(task_entries_local, CR_STATE_RESTORE_CREDS);
	/*
	 * From this point forward, cross-process synchronization is strictly
	 * prohibited. compel_stop_tasks_on_syscall enumerates all restored
	 * tasks/threads sequentially, allowing each to execute one syscall
	 * per iteration. Any attempt to communicate with other tasks or
	 * threads may trigger a deadlock.
	 */
	if (ret)
		BUG();

	sys_close(args->proc_fd);

	/*
	 * The code that prepared the itimers makes sure that the
	 * code below doesn't fail due to bad timing values.
	 */

#define itimer_armed(args, i) (args->itimers[i].it_value.tv_sec || args->itimers[i].it_value.tv_usec)

	if (itimer_armed(args, 0))
		sys_setitimer(ITIMER_REAL, &args->itimers[0], NULL);
	if (itimer_armed(args, 1))
		sys_setitimer(ITIMER_VIRTUAL, &args->itimers[1], NULL);
	if (itimer_armed(args, 2))
		sys_setitimer(ITIMER_PROF, &args->itimers[2], NULL);

	restore_posix_timers(args);

	thread_fini();

	/*
	 * Sigframe stack.
	 */
	new_sp = (long)rt_sigframe + RT_SIGFRAME_OFFSET(rt_sigframe);

	/*
	 * Prepare the stack and call for sigreturn,
	 * pure assembly since we don't need any additional
	 * code insns from gcc.
	 */
	rst_sigreturn(new_sp, rt_sigframe);

core_restore_end:
	futex_abort_and_wake(&task_entries_local->nr_in_progress);
	pr_err("Restorer fail %ld\n", sys_getpid());
	sys_exit_group(1);
	return -1;
}

/*
 * For most of the restorer's objects -fstack-protector is disabled.
 * But we share some of them with CRIU, which may have it enabled.
 */
void __stack_chk_fail(void)
{
	pr_err("Restorer stack smash detected %ld\n", sys_getpid());
	sys_exit_group(1);
	BUG();
}
