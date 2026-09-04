#!/usr/bin/env bash
# difftest-guard.selftest.sh — regression test for the `read`-at-EOF fix in
# scripts/difftest-guard.sh.
#
# Bug (CodeRabbit, PR #309): `read` returns 1 at EOF under `set -e` (re-enabled
# a few lines above the `read ... < <(sed ...)` that parses the per-surface
# `oracle: checks=... surfaces=... unique_classes=... total_divergences=...`
# summary line). A log missing that line (e.g. the binary crashed before
# printing it) made `sed` emit nothing, `read` return 1, and — because `set -e`
# was live — the WHOLE script aborted right there with a bare exit status 1.
# That is indistinguishable from `EXIT_FINDING` (1, "an unbaselined pending
# divergence"), exactly the wrong signal: a run that never finished planning
# its checks must fail loudly as `EXIT_HARNESS` (3), not read as a quiet
# "finding".
#
# This test stubs `scala-cli` (satisfies the PATH check) and `DIFFTEST_BIN`
# (a fake campaign binary that writes a log with NO summary line and exits 0,
# reproducing "the binary died before printing its own report") and asserts
# the guard now exits 3 with a HARNESS ERROR message, rather than crashing
# out at exit 1 with no diagnostic.
#
# Usage: scripts/difftest-guard.selftest.sh   (exits 0 on pass, 1 on failure)

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
GUARD="$REPO_ROOT/scripts/difftest-guard.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# ----- stub scala-cli (only the `command -v` presence check matters) -----
mkdir -p "$WORK/bin"
cat >"$WORK/bin/scala-cli" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$WORK/bin/scala-cli"

# ----- stub difftest binary: writes a log with NO "oracle: checks=..." line -----
cat >"$WORK/fake-difftest" <<'EOF'
#!/usr/bin/env bash
echo "difftest: STRUCTURED seed=1 iters=1 surface=fake-surface (stub, no summary line)"
exit 0
EOF
chmod +x "$WORK/fake-difftest"

# ----- run the guard against a single fake surface -----
out="$WORK/guard.out"
set +e
PATH="$WORK/bin:$PATH" \
    DIFFTEST_BIN="$WORK/fake-difftest" \
    "$GUARD" --surfaces "fake-surface" --iters 5 --keep-regressions \
    --regressions-dir "$WORK/regressions" \
    >"$out" 2>&1
rc=$?
set -e

echo "--- guard output ---"
cat "$out"
echo "--- guard exit code: $rc ---"

[[ $rc -eq 3 ]] || fail "expected exit 3 (EXIT_HARNESS), got $rc"
grep -q 'HARNESS ERROR' "$out" || fail "expected a HARNESS ERROR line in the output"
grep -q 'ran 0 checks, expected 5' "$out" || fail "expected the missing-summary line to read as '0 checks ran', not crash silently"

echo "PASS: missing oracle summary line is classified as a harness error (exit 3), not a set -e crash"
