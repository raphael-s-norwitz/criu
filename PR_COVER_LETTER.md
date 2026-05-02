# PR cover-letter scratch -- RDMA C/R series (rxe + mlx5_sriov_vfmig)

INTERNAL WORKING DOC -- not for upstream. Drop before sending the PR.

This file collects the "things the reviewer will ask about" for the
in-flight series, plus known gaps that have to be called out in the
cover letter (or as TODOs in the patch trailers) when we send it.

------------------------------------------------------------------------
Series shape (current branch: ib-context-support-plugins-recovered)
------------------------------------------------------------------------

In commit order, oldest first:

  1. criu: rdma: Add uverbs async event fd dump ops
  2. criu: rdma: Add uverbsfd_cinfo to restore chrdev
  3. criu: rdma: Support opening uverbs async event fds
  4. test/rdma: Add out-of-band rxe checkpoint/restore validator
  5. criu: rdma: Detect ibdev driver from sysfs and persist in image
  6. plugins: rdma: Add presence-detection plugin for the rxe driver
  7. plugins: rdma: Add presence-detection plugin for mlx5_sriov_vfmig
  8. criu, plugins: rdma: Wire per-context plugin claim arbitration
  9. criu: rdma: Add netlink scaffolding and pre-suspend coverage check
 10. criu, plugins: rdma: Cross-tree exclusivity check + per-plugin
     sharing policy
 11. test/rdma: Strengthen validator with PD round-trip strict check

The test/rdma/ commits are marked "INTERNAL VALIDATION ONLY -- drop
before upstream PR" in their commit messages and the in-tree files;
they are kept around so reviewers can see the validation harness used
during development, but they go away (or move to a separate test
repo) before send-out.

------------------------------------------------------------------------
Known gaps that must be called out in the cover letter
------------------------------------------------------------------------

1. crit proto-sync gap
----------------------

The `crit` decoder shipped by the system criu package does NOT know
about the new uverbsfd fields (`driver_name`, `driver_id`,
`criu_driver`) or the new `rdma_criu` enum. As a consequence:

  - `crit decode -i <imgdir>/files.img` against an image produced by
    THIS branch will silently elide those fields.
  - Anybody who points an older `crit` at a new image gets a usable-
    looking but lossy decode, NOT an error.

Workaround for reviewers: invoke the branch-local crit via
`PYTHONPATH`, e.g.

    PYTHONPATH=$(pwd)/lib/py:$(pwd)/lib ./crit/crit decode -i ...

This is mentioned because reviewers will reasonably try the system
crit first and report "the new fields seem missing." The cover
letter should pre-empt that with the PYTHONPATH recipe.

Long-term fix: bump the crit pyproto schema in the same patch series
that introduces each new image field. We have not done that yet; it
would be its own commit (or commits) at the end of the series.

2. comp-channel anonymous fd disambiguation
-------------------------------------------

The kernel exposes both `[infinibandevent]` async-event fds (created
by `UVERBS_OBJECT_ASYNC_EVENT`) and comp-channel fds (created by
`UVERBS_OBJECT_COMP_CHANNEL`) under the same anon_inode link string
(`anon_inode:[infinibandevent]`). Their `show_fdinfo` callbacks both
emit only `ctxn:\t%u\n` -- there is NO way for userspace to tell
them apart from `/proc/<pid>/fdinfo/<fd>`.

Today, CRIU's `is_async_eventfd()` recognises both as async-event
fds. A process that holds a comp channel will be misclassified at
dump time (treated as async-event) and the restore path will create
an async-event fd in its place. That is silently wrong.

This series does not fix this. v0 only validates the async-event
case (rxe holder allocates one ucontext, no comp channel).

To close the gap we need either:

  (a) a small kernel patch making `ib_uverbs_show_comp_event_fdinfo`
      emit a distinguishing line (e.g. `event_type:\tcomp\n`,
      symmetric `event_type:\tasync\n` from the async side), and a
      CRIU-side recognizer that keys off it; or

  (b) a netlink-side disambiguation via `RDMA_NLDEV_CMD_RES_*` --
      enumerable, but joining "[infinibandevent] anon fd in process
      X" to "comp channel resource Y in ucontext Z" is not direct
      and would need new kernel reporting too.

(a) is much simpler. Plan: separate kernel patch + separate CRIU
patch in a follow-up series. Until then, hold workloads to "async-
event fds only" -- which is what the in-tree validator does.

3. PD / MR / CQ / QP uobject preservation
-----------------------------------------

The strict PD round-trip in test/rdma/ (commit 11) FAILS today
because `dump_uverbsfile()` only preserves the cdev fd, not the
ucontext's uobject table. After restore the kernel hands us a fresh
ucontext via GET_CONTEXT, and any pre-dump PD/MR/CQ/QP is gone --
the userspace `struct ibv_pd*` is restored from the heap but its
kernel handle no longer maps to anything.

Closing this is the next major work item ("uobject save/replay").
The PR cover letter should call out (a) that v0 only restores the
cdev + async-event fd, (b) that the PD round-trip test is in the
tree as the regression-test fixture for the upcoming work, (c) that
the pre-suspend coverage check (commit 9) prevents v0 from being
asked to dump anything more complex than a bare ucontext today --
the dump fails fast if no plugin claims the device, and the
per-plugin claim() implementations in commits 6 and 7 are gated on
"this device is one of the few we know how to round-trip
correctly."

4. mlx5_vfmig real integration (VF SAVE_VF / LOAD_VF)
-----------------------------------------------------

The mlx5_sriov_vfmig plugin in commit 7 is presence-detection only.
It claims any uverbs context whose ibdev is a "tracked" VF surfaced
by `MLX5_VFMIG_IOC_QUERY_VF`, but at restore time it does no SAVE/
LOAD work -- the cdev round-trip alone is what gets it through the
generic restore path, same as rxe.

Wiring the actual SAVE_VF/LOAD_VF kernel calls into the dump and
restore phases is the *next* milestone (separate series). The
sequence is non-trivial:

  SAVE side: VFs must be created unbound (PF sysfs auto-bind off),
             marked "tracked" via the chardev, then bound to
             mlx5_core; then SAVE_VF.

  RESTORE side: new VFs created unbound, marked "restored",
                LOAD_VF, then bound to mlx5_core.

See `linux/.../test_m2r_iova.sh` for the canonical reference flow.

This will land as a separate series after the cover letter for v0
goes out, since v0 is "the architectural skeleton" and the
mlx5_vfmig SAVE/LOAD is a meaningful chunk of work that benefits
from being reviewed independently.

5. RDMA-subsystem freeze / locking API
--------------------------------------

The cross-tree exclusivity check (commit 10) and the pre-suspend
coverage check (commit 9) both have a TOCTOU window: a non-tree
process can open a fresh context against a relevant ibdev between
the netlink poll and the actual dump. v0 inherits the same window
that already exists for the per-fd dump path's sysfs probes; we
have not introduced a new race.

A future "freeze the RDMA subsystem to new uverbs opens" locking
API will close it. Out of scope for v0 (Raphael's track).
