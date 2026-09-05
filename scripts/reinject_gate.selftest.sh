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
# Usage: scripts/reinject_gate.selftest.sh   (exits 0 on pass, 1 on failure)

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
GATE="$REPO_ROOT/scripts/reinject_gate.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

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
[[ $gate_rc -eq 0 ]] || fail "valid_future_date: expected exit 0 (a valid not-yet-passed blocked_until is a clean SKIP), got $gate_rc"
grep -q "not a real calendar date" "$out2" && fail "valid_future_date: a real calendar date must not be rejected"
grep -q "SKIP.*valid_future_date: blocked on PR #2 until $FUTURE_DATE" "$out2" || fail "valid_future_date: expected the ordinary still-blocked SKIP line"

echo "PASS: blocked_until is calendar-validated — impossible dates are rejected, real future dates still SKIP as blocked"
