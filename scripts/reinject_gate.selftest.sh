#!/usr/bin/env bash
# reinject_gate.selftest.sh — regression test for the calendar-aware
# blocked_until parse in scripts/reinject_gate.sh.
#
# Bug (CodeRabbit, PR #309): `blocked_until` was only validated by shape
# (`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`), so a calendar-impossible date like
# "9999-99-99" passed the regex and then, compared as a STRING against
# `date -u +%Y-%m-%d`, always sorted greater than any real date — an entry
# with that value never expires, defeating the whole "blocked_on requires an
# expiry" rule.
#
# This test builds a throwaway git repo shaped like the real one (just enough
# of `ergo-difftest/known_bugs/` for the manifest parser) with two `[[bug]]`
# entries — one `blocked_until = "9999-99-99"`, one `blocked_until` set to a
# real date generated at test time (`date -u -d '+400 days' +%F`, so this
# fixture never itself goes stale) — and runs the real `reinject_gate.sh`
# with `--only` against each, asserting:
#   * the impossible date is REJECTED ("not a real calendar date"), not
#     silently accepted as "blocked forever";
#   * the valid future date is accepted and the entry is SKIPPED (not FAILed)
#     for the ordinary "blocked, not yet expired" reason.
#
# A third entry runs one clean/patched pair through a stub `cargo` that
# "builds" a shell detector, so nothing is compiled. It asserts the pair
# passes and that the entry's source copy and release build directory are
# removed while its logs remain.
#
# Usage: scripts/reinject_gate.selftest.sh   (exits 0 on pass, 1 on failure)

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
GATE="$REPO_ROOT/scripts/reinject_gate.sh"

WORK="$(mktemp -d)"
GATE_TMP="$(mktemp -d)"
trap 'rm -rf "$WORK" "$GATE_TMP"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# ----- fake repo shaped like the real one (manifest parser only needs this) -----
mkdir -p "$WORK/ergo-difftest/known_bugs/patches"
git -C "$WORK" init -q

# A fixed literal future date goes stale the day it arrives — generate one
# relative to "now" so this test keeps passing indefinitely. +400 days is
# comfortably past any plausible `blocked_until` window used elsewhere in the
# repo, so it never collides with a real entry's expiry during this run.
FUTURE_DATE="$(date -u -d '+400 days' +%F)"

cat >"$WORK/ergo-difftest/known_bugs/manifest.toml" <<EOF
[[bug]]
id = "impossible_date"
class = "WR"
wire_reachable = "true"
trigger_hex = ""
blocked_on = "PR #1"
blocked_until = "9999-99-99"

[[bug]]
id = "valid_future_date"
class = "WR"
wire_reachable = "true"
trigger_hex = ""
blocked_on = "PR #2"
blocked_until = "$FUTURE_DATE"

[[bug]]
id = "stub_pair"
class = "panic"
surface = "ergo_tree"
wire_reachable = true
trigger_hex = "00"
EOF

gate_rc=0
run_gate() {
    local id="$1" out="$WORK/out.$1"
    set +e
    (cd "$WORK" && "$GATE" --only "$id") >"$out" 2>&1
    gate_rc=$?
    set -e
    echo "--- reinject_gate --only $id (exit $gate_rc) ---"
    cat "$out"
}

# ----- impossible date: must FAIL as "not a real calendar date" -----
run_gate impossible_date
out1="$WORK/out.impossible_date"
[[ $gate_rc -ne 0 ]] || fail "impossible_date: expected non-zero exit (a bad blocked_until is a gate FAIL), got 0"
grep -q "not a real calendar date" "$out1" || fail "impossible_date: expected 'not a real calendar date', the string-compare bug would instead print nothing and skip forever"

# ----- valid future date: must be accepted and SKIPped (not FAILed) as still-blocked -----
run_gate valid_future_date
out2="$WORK/out.valid_future_date"
[[ $gate_rc -eq 3 ]] || fail "valid_future_date: expected incomplete exit3 when the only selected pair is skipped, got $gate_rc"
grep -q "not a real calendar date" "$out2" && fail "valid_future_date: a real calendar date must not be rejected"
grep -q "SKIP.*valid_future_date: blocked on PR #2 until $FUTURE_DATE" "$out2" || fail "valid_future_date: expected the ordinary still-blocked SKIP line"

# ----- executed pair: the source copy and release build go, the logs stay -----
mkdir -p "$WORK/scripts" "$WORK/stub-bin"
cp "$REPO_ROOT/scripts/reinject-result.py" "$WORK/scripts/"
printf 'clean\n' >"$WORK/marker.txt"
cat >"$WORK/ergo-difftest/known_bugs/patches/stub_pair.patch" <<'EOF'
--- a/marker.txt
+++ b/marker.txt
@@ -1 +1 @@
-clean
+patched
EOF
cat >"$WORK/stub-bin/cargo" <<'EOF'
#!/usr/bin/env bash
# `build --target-dir D` writes a shell detector to D/release/difftest that
# reports the declared panic marker only after the patch changed marker.txt.
set -euo pipefail
case "$1" in
    build)
        while [[ $# -gt 0 && "$1" != "--target-dir" ]]; do shift; done
        mkdir -p "$2/release"
        printf '%s\n' '#!/usr/bin/env bash' 'grep -q patched marker.txt || exit 0' \
            'echo "  [BUG] ergo_tree: PANIC: stub detector"' 'exit 1' >"$2/release/difftest"
        chmod +x "$2/release/difftest"
        ;;
    metadata) printf '{"target_directory": "%s"}\n' "$CARGO_TARGET_DIR" ;;
    *) echo "stub cargo: unexpected $*" >&2; exit 2 ;;
esac
EOF
chmod +x "$WORK/stub-bin/cargo"
out3="$WORK/out.stub_pair"
set +e
(cd "$WORK" && PATH="$WORK/stub-bin:$PATH" TMPDIR="$GATE_TMP" "$GATE" --only stub_pair) >"$out3" 2>&1
gate_rc=$?
set -e
echo "--- reinject_gate --only stub_pair (exit $gate_rc) ---"
cat "$out3"
[[ $gate_rc -eq 0 ]] || fail "stub_pair: expected one passing clean/patched pair, got exit $gate_rc"
grep -q '\[PASS\] stub_pair' "$out3" || fail "stub_pair: expected a PASS line"
logs="$(sed -n 's/^  preserved build\/detector logs: //p' "$out3")"
[[ -n "$logs" && -d "$logs" ]] || fail "stub_pair: preserved log directory is missing"
for kept in clean-build.log clean.log patch.log patched-build.log patched.log command.txt; do
    [[ -f "$logs/$kept" ]] || fail "stub_pair: $kept was not preserved"
done
[[ ! -e "$logs/source" ]] || fail "stub_pair: the source copy was left behind"
[[ ! -e "$logs/target" ]] || fail "stub_pair: the release build directory was left behind"

echo "PASS: blocked_until is calendar-validated — impossible dates are rejected, real future dates still SKIP as blocked"
echo "PASS: an executed pair removes its source copy and release build directory and keeps its logs"
