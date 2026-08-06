#!/usr/bin/env bash
#
# setup-criu-dev-env.sh -- one-shot setup of the CRIU RDMA rebase dev
# environment (the git hooks + the tooling the hooks depend on).
#
# This exists because the pre-commit style gate has bitten us several
# times, always for the same handful of reasons (see the "Gotchas"
# section of README.md next to this script and
# ../plans/criu_dev_environment.md). Running this script makes a fresh
# host ready to commit into either rebase repo without re-discovering
# any of them.
#
# What it does (idempotent; safe to re-run):
#   1. Ensures clang-format AND git-clang-format are installed -- the
#      criu pre-commit gate is clang-format, not checkpatch, and the
#      wrapper `git clang-format` ships in the clang-format package on
#      Debian/Ubuntu. Without it the gate silently skips.
#   2. Installs the versioned commit-msg + pre-commit hooks into both
#      rebase repos via install-hooks.sh (hooks live in each repo's
#      *common* git dir, so this also covers the poc-ref worktrees).
#   3. Verifies the result: tools on PATH, .clang-format present in the
#      criu repo, hooks executable, and a live `git clang-format`
#      smoke run.
#
# Usage:
#   ./setup-criu-dev-env.sh                 # default repos
#   ./setup-criu-dev-env.sh /path/linux /path/criu
#   CRIU_SETUP_INSTALL=0 ./setup-criu-dev-env.sh   # skip apt install,
#                                                    # verify/install-hooks only
#
# Environment:
#   CRIU_SETUP_INSTALL   1 (default) to apt/dnf-install clang-format if
#                        missing; 0 to only verify + install hooks.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL="${CRIU_SETUP_INSTALL:-1}"
DEFAULT_REPOS=(/opt/builds/linux /opt/builds/criu)

if [ "$#" -gt 0 ]; then
	REPOS=("$@")
else
	REPOS=("${DEFAULT_REPOS[@]}")
fi

note()    { printf '  %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
warn()    { printf 'WARN: %s\n' "$*" >&2; }
die()     { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. clang-format + git-clang-format.
# ---------------------------------------------------------------------------
section "clang-format tooling"

install_clang_format() {
	if command -v apt-get >/dev/null 2>&1; then
		note "apt-get install -y clang-format"
		sudo apt-get update -qq || true
		sudo apt-get install -y clang-format
	elif command -v dnf >/dev/null 2>&1; then
		note "dnf install -y clang-tools-extra git-clang-format"
		sudo dnf install -y clang-tools-extra git-clang-format
	elif command -v yum >/dev/null 2>&1; then
		note "yum install -y clang-tools-extra git-clang-format"
		sudo yum install -y clang-tools-extra git-clang-format
	else
		die "no supported package manager (apt-get/dnf/yum) found; install clang-format + git-clang-format manually"
	fi
}

have_cf=1
command -v clang-format     >/dev/null 2>&1 || have_cf=0
command -v git-clang-format >/dev/null 2>&1 || have_cf=0

if [ "$have_cf" -eq 1 ]; then
	note "already present: $(command -v clang-format), $(command -v git-clang-format)"
elif [ "$INSTALL" = 1 ]; then
	install_clang_format
else
	warn "clang-format/git-clang-format missing and CRIU_SETUP_INSTALL=0; the pre-commit gate will SKIP."
fi

# ---------------------------------------------------------------------------
# 2. Install the git hooks into every target repo.
# ---------------------------------------------------------------------------
section "git hooks"
[ -x "$SCRIPT_DIR/install-hooks.sh" ] || die "missing $SCRIPT_DIR/install-hooks.sh"
"$SCRIPT_DIR/install-hooks.sh" "${REPOS[@]}"

# ---------------------------------------------------------------------------
# 3. Verify.
# ---------------------------------------------------------------------------
section "verify"
fail=0

if command -v clang-format >/dev/null 2>&1 && command -v git-clang-format >/dev/null 2>&1; then
	note "clang-format: $(clang-format --version)"
else
	warn "clang-format/git-clang-format not on PATH -- criu pre-commit gate will skip (non-fatal)."
fi

for repo in "${REPOS[@]}"; do
	git -C "$repo" rev-parse --git-dir >/dev/null 2>&1 || { warn "$repo: not a git repo, skipping verify"; continue; }
	hooksdir="$(git -C "$repo" rev-parse --path-format=absolute --git-path hooks)"

	for h in commit-msg pre-commit; do
		if [ -x "$hooksdir/$h" ] && cmp -s "$SCRIPT_DIR/$h" "$hooksdir/$h"; then
			note "$repo: $h installed + current"
		else
			warn "$repo: $h missing or stale at $hooksdir/$h"
			fail=1
		fi
	done

	# criu repo (no scripts/checkpatch.pl) must carry a .clang-format,
	# otherwise `git clang-format --style file` has nothing to key off.
	if [ ! -x "$repo/scripts/checkpatch.pl" ]; then
		if [ -f "$repo/.clang-format" ]; then
			note "$repo: .clang-format present"
		else
			warn "$repo: .clang-format MISSING (run 'make fetch-clang-format' in the repo)"
			fail=1
		fi
	fi
done

# Live smoke: run the exact command the criu pre-commit uses, on nothing
# staged, to prove the wrapper resolves and exits cleanly.
if command -v git-clang-format >/dev/null 2>&1; then
	for repo in "${REPOS[@]}"; do
		[ -x "$repo/scripts/checkpatch.pl" ] && continue
		if git -C "$repo" clang-format --style file --extensions c,h --staged --diff >/dev/null 2>&1; then
			note "$repo: 'git clang-format' smoke OK"
		else
			# A non-zero here on an empty index is not necessarily a
			# failure (older wrappers print "no modified files"); only
			# flag if the binary is genuinely unusable.
			git -C "$repo" clang-format --help >/dev/null 2>&1 || { warn "$repo: 'git clang-format' unusable"; fail=1; }
		fi
	done
fi

section "done"
if [ "$fail" -eq 0 ]; then
	note "environment ready."
else
	warn "environment set up with warnings above -- review before committing."
	exit 1
fi
