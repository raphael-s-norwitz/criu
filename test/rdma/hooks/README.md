# Rebase git hooks

Versioned git hooks (and their installer) for the CRIU RDMA rebase effort.
These are the single source of truth; the copies living inside each repo's
`.git/hooks/` are installed from here by `install-hooks.sh`.

## Files

| File                    | Role                                                        |
|-------------------------|-------------------------------------------------------------|
| `commit-msg`            | Validates + normalizes commit messages.                     |
| `pre-commit`            | Repo-aware C style gate: checkpatch (kernel) / clang-format (criu). |
| `install-hooks.sh`      | Copies the two hooks into the rebase repositories.          |
| `setup-criu-dev-env.sh` | One-shot env setup: installs clang-format tooling, then the hooks, then verifies. Start here on a fresh host. |

## Quick start (fresh host)

```bash
test/rdma/hooks/setup-criu-dev-env.sh
```

Installs `clang-format` + `git-clang-format` if missing, installs both
hooks into `/opt/builds/linux` and `/opt/builds/criu` (covering their
`*-poc-ref` worktrees), and verifies the result. Idempotent. See
`../plans/criu_dev_environment.md` for the *why* behind each step and
the full list of gotchas this prevents.

## What the hooks enforce

### `commit-msg`
- Subject line `<= 52` characters.
- Blank line required after the subject.
- Body wrapped at `<= 72` characters. Exempt: trailer lines
  (`Key: value`) and lines whose longest single token already exceeds 72
  (e.g. URLs), which cannot be wrapped.
- Auto-appends these trailers at the very end, in order, de-duplicated:
  - `Assisted-by: Cursor:claude-opus-4.8-high`
  - `Signed-off-by: <name> <email>` — derived from the repo's
    `git config user.name` / `user.email` (omitted if either is unset).
- Skips `Merge`, `Revert "..."`, `fixup!`, `squash!`, `amend!` commits.

### `pre-commit`
- Collects the staged `*.c`, `*.h` (and `*.S` for the kernel) files
  (docs/plans and other non-code changes are ignored, so those commits
  are never blocked).
- **Repo-aware**, keyed off the presence of `scripts/checkpatch.pl`
  (the kernel tree ships one, criu does not):
  - **kernel repo** -> feeds the staged diff to `checkpatch.pl --strict
    --no-signoff --ignore=FILE_PATH_CHANGES` (run in-tree, `--root`) and
    blocks unless **fully clean: 0 errors, 0 warnings, 0 checks**.
    `FILE_PATH_CHANGES` (the "does MAINTAINERS need updating?" nag) is
    suppressed because it fires on every new file and is a
    final-submission concern, not a per-commit style issue.
  - **criu repo** -> runs `git clang-format --style file --extensions
    c,h --staged --diff` against the repo's `.clang-format` and blocks
    if the staged changes are not already clang-format clean. This is
    criu's own convention (see criu `CONTRIBUTING.md` / `make indent`);
    criu is userspace and "less strict than the kernel", so checkpatch
    would false-positive (uint32_t vs u32, SPDX comment style, `BIT()`
    in vendored UAPI headers, ...). Vendored kernel UAPI mirrors (any
    `*/uapi/*` path) are excluded from the clang-format check so they
    stay byte-identical to the kernel source. Skipped with a notice if
    `git-clang-format` is not installed.

Bypass either hook for a single commit with `git commit --no-verify`.

## Gotchas (why this tooling exists)

Every one of these cost us a debugging round at least once; the hooks +
setup script now encode the resolution so they don't recur.

1. **criu uses clang-format, NOT checkpatch.** criu's `CONTRIBUTING.md`
   says it "mostly follows Linux kernel coding style, but is less
   strict"; its actual gate is `make indent` (= `git clang-format
   --style file --extensions c,h`) against the tracked `.clang-format`,
   and `make lint` (ruff + shellcheck + codespell). There is **no**
   `scripts/checkpatch.pl` and no `.checkpatch.conf` in criu. Running
   checkpatch on criu code produces false positives (`uint32_t` vs
   `u32`, SPDX comment style, "do not initialise globals to false",
   "prefer BIT() macro", ...). The pre-commit therefore keys off
   `scripts/checkpatch.pl`: present -> kernel -> checkpatch; absent ->
   criu -> clang-format.

2. **`git clang-format` needs the `clang-format` package.** On a fresh
   host neither `clang-format` nor the `git-clang-format` wrapper is
   present, and the pre-commit *silently skips* the gate (by design, so
   the hook is portable). Install with `apt-get install -y
   clang-format` (Ubuntu 22.04 -> clang-format 14, ships both binaries).
   `setup-criu-dev-env.sh` does this for you.

3. **Vendored kernel UAPI headers vs clang-format.** A newly-added file
   is seen as all-changed by `git clang-format --staged --diff`, so it
   tries to reformat vendored kernel headers (kernel tabs/alignment vs
   criu's `.clang-format`) and fails the commit. We keep vendored
   mirrors byte-identical to the kernel source, so the pre-commit
   excludes any `*/uapi/*` path from the criu clang-format check;
   plugin Makefiles warn on drift instead.

4. **criu sources carry no SPDX header.** The oracle plugins have none;
   criu does not use per-file SPDX tags. Don't add them (they also trip
   checkpatch style checks in the kernel branch if a file is shared).

5. **Hooks live in the repo's *common* git dir, not per worktree.**
   `/opt/builds/linux` + `/opt/builds/linux-poc-ref` share one hooks
   dir; likewise the two criu worktrees. Install once per repo (two
   installs total), not once per worktree. `install-hooks.sh` resolves
   the exact dir with `git rev-parse --path-format=absolute --git-path
   hooks`.

6. **commit-msg auto-appends trailers.** `Assisted-by:` and
   `Signed-off-by:` (from `git config user.name`/`user.email`) are
   appended and de-duplicated automatically; subject must be `<= 52`
   chars and the body wraps at `<= 72`. Don't hand-add those trailers or
   fight the wrap.

## How the installer works

`install-hooks.sh` copies `commit-msg` and `pre-commit` from this directory
into each target repository's hooks directory.

Key points:

- **Targets are repositories, not worktrees.** Git stores hooks in the
  *common* git dir, so a repo's worktrees all share one hooks directory.
  The default targets are therefore just the two repos:
  - `/opt/builds/linux` — kernel; the shared hooks also apply to the
    `linux-poc-ref` worktree.
  - `/opt/builds/criu` — criu; the shared hooks also apply to the
    `criu-poc-ref` worktree.
- **Destination resolution.** For each repo it runs
  `git -C <repo> rev-parse --path-format=absolute --git-path hooks`
  to get the exact directory git will use (this also honours
  `core.hooksPath` if it is ever set), then installs the hooks there with
  mode `0755`.
- **Safe + idempotent.** If a destination hook already exists and differs,
  it is copied to `<hook>.bak.<timestamp>` before being overwritten.
  Re-running with the same sources makes no further changes.

### Usage

Run from anywhere (the script locates its own sources):

```bash
# Install into the two default repos (/opt/builds/linux, /opt/builds/criu):
test/rdma/hooks/install-hooks.sh

# Install into explicit repositories instead:
test/rdma/hooks/install-hooks.sh /path/to/linux /path/to/criu

# Preview actions without changing anything:
CRIU_HOOKS_DRYRUN=1 test/rdma/hooks/install-hooks.sh
```

`setup-criu-dev-env.sh` runs this script (after ensuring the
clang-format tooling is present) so that both repos get the hooks
automatically.
