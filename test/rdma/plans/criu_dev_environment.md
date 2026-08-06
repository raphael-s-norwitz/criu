# CRIU RDMA rebase — dev environment setup

Read this first if you are a CRIU agent starting work in
`/opt/builds/criu` (build-up tree) against `/opt/builds/criu-poc-ref`
(oracle). It captures how to make a host ready to build + commit, and
the handful of environment issues that have repeatedly cost debugging
rounds so you don't rediscover them.

## TL;DR — one command

```bash
/opt/builds/criu-poc-ref/test/rdma/hooks/setup-criu-dev-env.sh
```

Idempotent. It:

1. installs `clang-format` + `git-clang-format` if missing,
2. installs the versioned `commit-msg` + `pre-commit` hooks into both
   `/opt/builds/linux` and `/opt/builds/criu` (which also covers the
   `*-poc-ref` worktrees — hooks live in the repo's *common* git dir),
3. verifies tooling, `.clang-format`, and the hooks, with a live
   `git clang-format` smoke run.

Build criu itself with `make` from the repo root (deps:
`./contrib/dependencies/apt-packages.sh`, per `CONTRIBUTING.md`).

## Repo / worktree topology

- `/opt/builds/criu` — build-up tree (our incremental series).
- `/opt/builds/criu-poc-ref` — oracle (`criu-dev-poc-rebase`). Two
  worktrees of **one** repo at `/opt/builds/criu/.git`.
- `/opt/builds/linux` + `/opt/builds/linux-poc-ref` — same deal for the
  kernel side.
- The hook sources + this env tooling live in
  `/opt/builds/criu-poc-ref/test/rdma/hooks/`; see its `README.md` for
  hook internals. The installer still installs into *both* repos (the
  criu clang-format gate and the kernel checkpatch gate), it just lives
  on the criu side.

## Coding-style policy (the big one)

**criu uses clang-format, NOT checkpatch.** From criu `CONTRIBUTING.md`:
it "mostly follows Linux kernel coding style, but is less strict." The
real gate is:

- `make indent` → `git clang-format --style file --extensions c,h`
  against the tracked `.clang-format` (kernel-derived; `ColumnLimit: 0`
  → no hard line-length limit). Compliance is explicitly **optional**
  upstream, but our pre-commit enforces "clang-format clean on the
  staged diff" to keep the series tidy.
- `make lint` → ruff + shellcheck + codespell (+ a couple of criu C
  checks). **No** checkpatch, **no** `scripts/checkpatch.pl`, **no**
  `.checkpatch.conf` anywhere in criu.

The kernel tree, in contrast, is gated with `checkpatch.pl --strict`.
The `pre-commit` hook is therefore repo-aware, keyed off the presence of
`scripts/checkpatch.pl`.

## Issues we hit (and their fixes, now encoded in the tooling)

1. **Ran checkpatch on criu.** The first pre-commit blindly ran
   `checkpatch --strict` on criu and flagged `uint32_t` vs `u32`, SPDX
   comment style, "do not initialise globals to false", "prefer BIT()
   macro", etc. — none of which are criu policy. Fix: repo-aware
   pre-commit (checkpatch for kernel, clang-format for criu).

2. **`git clang-format` not installed.** On a fresh host the clang-format
   gate silently skipped because neither `clang-format` nor the
   `git-clang-format` wrapper existed. Fix: `apt-get install -y
   clang-format` (Ubuntu 22.04 → clang-format 14, ships both binaries);
   `setup-criu-dev-env.sh` handles it.

3. **Vendored kernel UAPI headers vs clang-format.** When adding a
   vendored `.../uapi/linux/*.h` mirror, `git clang-format --staged
   --diff` treats the new file as all-changed and wants to reformat it
   to criu style (kernel tabs/alignment → criu `.clang-format`),
   failing the commit. We keep vendored mirrors **byte-identical to the
   kernel source**, so the pre-commit excludes any `*/uapi/*` path from
   the criu clang-format check; the plugin Makefile warns on drift from
   `/usr/include/linux/<hdr>` instead.

4. **SPDX headers.** criu sources carry no per-file SPDX tag (the oracle
   plugins have none). We added MIT SPDX tags early, which diverged from
   criu norm (and trip checkpatch on shared files). Fix: no SPDX in
   criu sources.

5. **Installing hooks per worktree.** Git stores hooks in the repo's
   *common* git dir, so all worktrees of a repo share one hooks
   directory. Install once per repo (two total), not once per worktree.

6. **commit-msg auto-trailers.** The `commit-msg` hook appends and
   de-duplicates `Assisted-by: Cursor:...` and `Signed-off-by:` (from
   `git config user.name`/`user.email`) itself, enforces subject
   `<= 52` chars and body wrap `<= 72`. Don't hand-add the trailers or
   fight the wrap; just write the subject + body.

## Commit conventions for this series

- Granular, reviewable, upstream-friendly commits; one logical change
  each (criu `CONTRIBUTING.md` "Separate your changes").
- Subject prefix names the component, e.g.
  `plugins/rdma/mlx5_sriov_vfmig: presence detection`.
- Trailers `Assisted-by:` + `Signed-off-by:` are auto-appended by the
  hook — do not add them manually.
- Prefix non-upstreamable dev-gate/test commits with `[NOT-FOR-MERGE]`.
- Use `git commit --no-verify` only for a genuine hook false positive,
  and say so in the commit body.

## Runtime gotchas (not hook-related, but they bit us)

- **Plugins load during dump/restore, not `criu check`.** To load a
  build-tree plugin, pass `--libdir <abs dir containing the .so>`.
- **`--libdir` must be absolute under `sudo`.** A relative `--libdir`
  resolves against root's CWD after `sudo` and fails with "Unable to
  open directory ...". Always pass an absolute path.

## Where things live

| Thing                         | Path                                                                   |
|-------------------------------|------------------------------------------------------------------------|
| Setup orchestrator            | `criu-poc-ref/test/rdma/hooks/setup-criu-dev-env.sh`                   |
| Hook sources + installer      | `criu-poc-ref/test/rdma/hooks/`                                        |
| Hook internals / gotchas      | `criu-poc-ref/test/rdma/hooks/README.md`                              |
| Build-up plan / kickoff       | `criu-poc-ref/test/rdma/plans/{criu_build_up_plan,mlx5_vfmig_kickoff}.md` |
| criu style policy (upstream)  | `criu-poc-ref/CONTRIBUTING.md`, `criu-poc-ref/.clang-format`           |
