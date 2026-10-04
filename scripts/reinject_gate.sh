#!/usr/bin/env bash
# reinject_gate.sh — Known-bug re-injection gate for the Ergo differential harness.
#
# For each WR bug in ergo-difftest/known_bugs/manifest.toml that has a non-empty
# trigger_hex and a patch in ergo-difftest/known_bugs/patches/:
#
#   1. CLEAN HEAD: run the detection command; assert it exits 0 (no divergence).
#   2. PATCHED HEAD: apply the patch to a scratch worktree, build difftest, run the
#      detection command; assert finding exit 1 AND the declared class/surface marker.
#   3. Tear down the scratch worktree.
#
# Usage:
#   scripts/reinject_gate.sh [--generated] [--only <id>] [--oracle-script <path>]
#
# Options:
#   --generated      Unsupported generated-rediscovery obligation. Refused with
#                    usage exit 2; skipping every check is never a passing gate.
#   --only <id>      Run the gate only for the named bug id (useful for debugging).
#   --oracle-script  Path to ErgoSerdeOracle.scala (default: scripts/jvm_serde_oracle/ErgoSerdeOracle.scala).
#
# Exit codes:
#   0  at least one detector pair ran; all executed pairs passed
#   1  at least one assertion/build failed
#   2  usage error or unsupported generated mode
#   3  no detector pair executed (all selected entries were skipped)
#
# Every selected class uses owned source copies. Build and detector logs survive
# cleanup of those copies and of each release build directory. No caller
# source or Git worktree is patched.
# A passing source/unit test does not certify clean/patched detector execution.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
MANIFEST="$REPO_ROOT/ergo-difftest/known_bugs/manifest.toml"
PATCHES_DIR="$REPO_ROOT/ergo-difftest/known_bugs/patches"
ORACLE_SCRIPT="${ORACLE_SCRIPT:-$REPO_ROOT/scripts/jvm_serde_oracle/ErgoSerdeOracle.scala}"

GENERATED=false
ONLY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --only|--oracle-script)
            [[ $# -ge 2 && -n "$2" ]] || { echo >&2 "missing value for $1"; exit 2; } ;;
    esac
    case "$1" in
        --generated)   GENERATED=true ;;
        --only)        ONLY="$2"; shift ;;
        --oracle-script) ORACLE_SCRIPT="$2"; shift ;;
        -h|--help)
            sed -n '2,/^$/p' "$0"
            exit 0
            ;;
        *)
            echo >&2 "unknown argument: $1"
            exit 2
            ;;
    esac
    shift
done

if $GENERATED; then
    echo >&2 "reinject_gate: --generated rediscovery is unsupported; no generated detector checks ran."
    exit 2
fi

# ---------------------------------------------------------------------------
# Parse manifest.toml into arrays (pure bash, no external TOML library).
# Fields extracted per [[bug]] entry: id, class, wire_reachable, trigger_hex,
# expected_canonical, budget_iters, surface.
# ---------------------------------------------------------------------------

declare -a BUG_IDS=()
declare -A BUG_CLASS=()
declare -A BUG_WR=()
declare -A BUG_TRIGGER=()
declare -A BUG_EXPECTED=()
declare -A BUG_ITERS=()
declare -A BUG_SURFACE=()
declare -A BUG_BLOCKED=()
declare -A BUG_BLOCKED_UNTIL=()

_cur_id=""
_cur_class=""
_cur_wr=""
_cur_trigger=""
_cur_expected=""
_cur_iters="50000"
_cur_surface=""
_cur_blocked=""
_cur_blocked_until=""

flush_bug() {
    if [[ -n "$_cur_id" ]]; then
        BUG_IDS+=("$_cur_id")
        BUG_CLASS["$_cur_id"]="$_cur_class"
        BUG_WR["$_cur_id"]="$_cur_wr"
        BUG_TRIGGER["$_cur_id"]="$_cur_trigger"
        BUG_EXPECTED["$_cur_id"]="$_cur_expected"
        BUG_ITERS["$_cur_id"]="$_cur_iters"
        BUG_SURFACE["$_cur_id"]="$_cur_surface"
        BUG_BLOCKED["$_cur_id"]="$_cur_blocked"
        BUG_BLOCKED_UNTIL["$_cur_id"]="$_cur_blocked_until"
    fi
    _cur_id=""
    _cur_class=""
    _cur_wr=""
    _cur_trigger=""
    _cur_expected=""
    _cur_iters="50000"
    _cur_surface=""
    _cur_blocked=""
    _cur_blocked_until=""
}

toml_val() {
    # Extract the value after '= ' from a TOML key = "val" or key = val line.
    local line="$1"
    local val="${line#*= }"
    # Strip surrounding quotes
    val="${val#\"}"
    val="${val%\"}"
    echo "$val"
}

# Strip a trailing TOML comment WITHOUT cutting a '#' that lives inside a quoted
# value. `blocked_on = "PR #301"` is exactly that case, and a naive `${line%%#*}`
# silently truncated it to `PR ` — a validation rule that reads its own input
# wrong is worse than no rule.
strip_comment() {
    local line="$1" out="" in_quote=0 i ch
    for (( i = 0; i < ${#line}; i++ )); do
        ch="${line:i:1}"
        [[ "$ch" == '"' ]] && in_quote=$(( 1 - in_quote ))
        [[ "$ch" == "#" && $in_quote -eq 0 ]] && break
        out+="$ch"
    done
    printf '%s' "$out"
}

while IFS= read -r line; do
    line="$(strip_comment "$line")"
    line="${line%"${line##*[! ]}"}"  # rtrim
    case "$line" in
        "[[bug]]")
            flush_bug
            ;;
        id\ *=*)
            _cur_id="$(toml_val "$line")"
            ;;
        class\ *=*)
            _cur_class="$(toml_val "$line")"
            ;;
        wire_reachable\ *=*)
            _cur_wr="$(toml_val "$line")"
            ;;
        trigger_hex\ *=*)
            _cur_trigger="$(toml_val "$line")"
            ;;
        expected_canonical\ *=*)
            _cur_expected="$(toml_val "$line")"
            ;;
        budget_iters\ *=*)
            _cur_iters="$(toml_val "$line")"
            ;;
        surface\ *=*)
            _cur_surface="$(toml_val "$line")"
            ;;
        blocked_on\ *=*)
            _cur_blocked="$(toml_val "$line")"
            ;;
        blocked_until\ *=*)
            _cur_blocked_until="$(toml_val "$line")"
            ;;
    esac
done < "$MANIFEST"
flush_bug

# ---------------------------------------------------------------------------
# Detection command per bug class
# ---------------------------------------------------------------------------

detection_args() {
    local id="$1" difftest="$2"
    DETECTION_ARGS=("$difftest" --repro "${BUG_TRIGGER[$id]}" --surface "${BUG_SURFACE[$id]}")
    case "${BUG_CLASS[$id]}" in
        canonical) DETECTION_ARGS+=(--check-canonical "${BUG_EXPECTED[$id]}") ;;
        panic) ;;
        accept-reject|cost|reduce|verify)
            DETECTION_ARGS+=(--oracle --oracle-script "$ORACLE_SCRIPT") ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Gate runner
# ---------------------------------------------------------------------------

PASS=0
FAIL=0
SKIP=0
if [[ -n "$ONLY" && -z "${BUG_CLASS[$ONLY]:-}" ]]; then
    echo >&2 "reinject_gate: unknown catalog id: $ONLY"
    exit 2
fi

for id in "${BUG_IDS[@]}"; do
    # Filter by --only if set
    if [[ -n "$ONLY" && "$id" != "$ONLY" ]]; then
        continue
    fi

    wr="${BUG_WR[$id]}"
    trigger="${BUG_TRIGGER[$id]}"
    patch_file="$PATCHES_DIR/${id}.patch"
    class="${BUG_CLASS[$id]}"

    # An entry whose FIX is not on this branch cannot assert a clean HEAD: the
    # bug IS the current behaviour, so step 1 would fail by construction. Skip
    # with the blocker named, so the entry stays armed and self-documenting
    # until the fix lands.
    blocked="${BUG_BLOCKED[$id]:-}"
    blocked_until="${BUG_BLOCKED_UNTIL[$id]:-}"
    if [[ -n "$blocked" ]]; then
        # A blocker must name a tracking PR/issue and carry an expiry. Without
        # both, "blocked" is indistinguishable from "quietly disabled forever".
        if ! [[ "$blocked" =~ ^(PR|issue)\ \#[0-9]+ ]]; then
            echo "  [FAIL] $id: blocked_on '$blocked' must start with 'PR #<n>' or 'issue #<n>'"
            ((FAIL++)) || true
            continue
        fi
        if ! [[ "$blocked_until" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
            echo "  [FAIL] $id: blocked_on requires blocked_until = \"YYYY-MM-DD\" (got '${blocked_until}')"
            ((FAIL++)) || true
            continue
        fi
        # The regex above only checks digit SHAPE — "9999-99-99" matches it and
        # then, as a string, compares greater than any real date forever, so a
        # calendar-impossible blocked_until would never expire. Round-trip it
        # through `date` (GNU date normalizes to `+%F`; an impossible date like
        # month 99 or Feb 30 either fails to parse or normalizes to a DIFFERENT
        # date) and require the output match verbatim before trusting the
        # string comparison below.
        normalized_blocked_until="$(date -u -d "$blocked_until" +%F 2>/dev/null)" || normalized_blocked_until=""
        if [[ "$normalized_blocked_until" != "$blocked_until" ]]; then
            echo "  [FAIL] $id: blocked_until '$blocked_until' is not a real calendar date"
            ((FAIL++)) || true
            continue
        fi
        if [[ "$(date -u +%Y-%m-%d)" > "$blocked_until" ]]; then
            echo "  [FAIL] $id: blocked_until $blocked_until has passed — re-check $blocked and either"
            echo "         drop blocked_on (the fix landed: add the patch and gate it) or extend the date deliberately."
            ((FAIL++)) || true
            continue
        fi
        echo "[SKIP] $id: blocked on $blocked until $blocked_until (fix not present on this branch — clean-HEAD assertion cannot hold)"
        ((SKIP++)) || true
        continue
    fi

    # SD bugs and WR bugs without trigger_hex cannot be gated here
    if [[ "$wr" != "true" ]]; then
        echo "[SKIP] $id: state-dependent bug (SD), no wire trigger"
        ((SKIP++)) || true
        continue
    fi

    if [[ -z "$trigger" ]]; then
        echo "[SKIP] $id: trigger_hex not yet crafted"
        ((SKIP++)) || true
        continue
    fi

    if [[ ! -f "$patch_file" ]]; then
        echo "[SKIP] $id: patch file not found: $patch_file"
        ((SKIP++)) || true
        continue
    fi

    if ! detection_args "$id" difftest; then
        echo "[SKIP] $id: no detection command for class '$class'"
        ((SKIP++)) || true
        continue
    fi

    echo ""
    echo "=== $id ($class) ==="
    gate_dir="$(mktemp -d "${TMPDIR:-/tmp}/ergo-reinject.XXXXXX")"
    scratch="$gate_dir/source"
    mkdir "$scratch"
    # Each entry builds into its own release target; remove it with the
    # source copy so only the logs remain.
    cleanup_source() { rm -rf -- "$scratch" "$gate_dir/target"; }
    trap cleanup_source EXIT
    echo "  preserved build/detector logs: $gate_dir"
    # Copy the current authored source, including uncommitted edits. Both clean
    # and patched builds use this same snapshot, rather than mixing it with HEAD.
    if ! git -C "$REPO_ROOT" ls-files --cached --others --exclude-standard -z |
        tar -C "$REPO_ROOT" --null -T - -cf - | tar -xf - -C "$scratch"; then
        echo "  [FAIL] $id: source snapshot failed"
        ((FAIL++)) || true
        cleanup_source
        trap - EXIT
        continue
    fi
    if ! (cd "$scratch" && cargo build --locked --release -p ergo-difftest --target-dir "$gate_dir/target" \
        >"$gate_dir/clean-build.log" 2>&1); then
        echo "  [FAIL] $id: clean build failed; see $gate_dir/clean-build.log"
        ((FAIL++)) || true
        cleanup_source
        trap - EXIT
        continue
    fi
    if ! target_dir="$(cd "$scratch" && CARGO_TARGET_DIR="$gate_dir/target" cargo metadata --locked --no-deps --format-version 1 \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"; then
        echo "  [FAIL] $id: cannot resolve the actual Cargo output directory"
        ((FAIL++)) || true
        cleanup_source
        trap - EXIT
        continue
    fi
    binary="$target_dir/release/difftest"
    if [[ ! -x "$binary" ]]; then
        echo "  [FAIL] $id: compiled detector binary missing at $binary"
        ((FAIL++)) || true
        cleanup_source
        trap - EXIT
        continue
    fi
    detection_args "$id" "$binary"
    printf '%q ' "${DETECTION_ARGS[@]}" > "$gate_dir/command.txt"
    printf '\n' >> "$gate_dir/command.txt"
    set +e
    (cd "$scratch" && "${DETECTION_ARGS[@]}") > "$gate_dir/clean.log" 2>&1
    clean_exit=$?
    set -e
    printf '%s\n' "$clean_exit" > "$gate_dir/clean.exit"
    cat "$gate_dir/clean.log"
    if [[ $clean_exit -ne 0 ]]; then
        echo "  [FAIL] $id: clean detector expected exit0, got $clean_exit"
        ((FAIL++)) || true
        cleanup_source
        trap - EXIT
        continue
    fi
    if ! (cd "$scratch" && patch --batch --forward -p1 < "$patch_file" \
        > "$gate_dir/patch.log" 2>&1); then
        echo "  [FAIL] $id: patch failed; see $gate_dir/patch.log"
        ((FAIL++)) || true
        cleanup_source
        trap - EXIT
        continue
    fi
    if ! (cd "$scratch" && cargo build --locked --release -p ergo-difftest --target-dir "$gate_dir/target" \
        > "$gate_dir/patched-build.log" 2>&1); then
        echo "  [FAIL] $id: patched build failed; not a detected finding"
        ((FAIL++)) || true
        cleanup_source
        trap - EXIT
        continue
    fi
    set +e
    (cd "$scratch" && "${DETECTION_ARGS[@]}") > "$gate_dir/patched.log" 2>&1
    patched_exit=$?
    set -e
    printf '%s\n' "$patched_exit" > "$gate_dir/patched.exit"
    cat "$gate_dir/patched.log"
    cleanup_source
    trap - EXIT
    if python3 "$REPO_ROOT/scripts/reinject-result.py" --class "$class" \
        --surface "${BUG_SURFACE[$id]}" --exit-code "$patched_exit" --log "$gate_dir/patched.log"; then
        echo "  [PASS] $id: clean exit0; patched finding exit1 matches $class/${BUG_SURFACE[$id]}"
        ((PASS++)) || true
    else
        echo "  [FAIL] $id: patched exit $patched_exit did not establish the declared detector result"
        ((FAIL++)) || true
    fi
done

echo ""
echo "=== reinject_gate summary ==="
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
if [[ $PASS -eq 0 ]]; then
    echo "reinject_gate: INCOMPLETE — no clean/patched detector pair executed."
    exit 3
fi
exit 0
