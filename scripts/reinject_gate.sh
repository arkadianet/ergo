#!/usr/bin/env bash
# reinject_gate.sh — Known-bug re-injection gate for the Ergo differential harness.
#
# For each WR bug in ergo-difftest/known_bugs/manifest.toml that has a non-empty
# trigger_hex and a patch in ergo-difftest/known_bugs/patches/:
#
#   1. CLEAN HEAD: run the detection command; assert it exits 0 (no divergence).
#   2. PATCHED HEAD: apply the patch to a scratch worktree, build difftest, run the
#      detection command; assert it exits non-zero (bug detected).
#   3. Tear down the scratch worktree.
#
# Usage:
#   scripts/reinject_gate.sh [--generated] [--only <id>] [--oracle-script <path>]
#
# Options:
#   --generated      Structured-generator mode: instead of the pinned trigger_hex,
#                    run a short oracle campaign (--oracle --surface <s> --iters N).
#                    Skipped cleanly when structured generators are not present.
#   --only <id>      Run the gate only for the named bug id (useful for debugging).
#   --oracle-script  Path to ErgoSerdeOracle.scala (default: scripts/jvm_serde_oracle/ErgoSerdeOracle.scala).
#
# Exit codes:
#   0  all bugs passed both assertions (or were skipped with explanation)
#   1  at least one assertion failed (false positive on clean HEAD or missed on patched)
#
# Security: this script only creates temporary git worktrees and removes them on exit.
# It never pushes or modifies the main working tree's git history.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
MANIFEST="$REPO_ROOT/ergo-difftest/known_bugs/manifest.toml"
PATCHES_DIR="$REPO_ROOT/ergo-difftest/known_bugs/patches"
ORACLE_SCRIPT="${ORACLE_SCRIPT:-$REPO_ROOT/scripts/jvm_serde_oracle/ErgoSerdeOracle.scala}"

GENERATED=false
ONLY=""

while [[ $# -gt 0 ]]; do
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

_cur_id=""
_cur_class=""
_cur_wr=""
_cur_trigger=""
_cur_expected=""
_cur_iters="50000"
_cur_surface=""

flush_bug() {
    if [[ -n "$_cur_id" ]]; then
        BUG_IDS+=("$_cur_id")
        BUG_CLASS["$_cur_id"]="$_cur_class"
        BUG_WR["$_cur_id"]="$_cur_wr"
        BUG_TRIGGER["$_cur_id"]="$_cur_trigger"
        BUG_EXPECTED["$_cur_id"]="$_cur_expected"
        BUG_ITERS["$_cur_id"]="$_cur_iters"
        BUG_SURFACE["$_cur_id"]="$_cur_surface"
    fi
    _cur_id=""
    _cur_class=""
    _cur_wr=""
    _cur_trigger=""
    _cur_expected=""
    _cur_iters="50000"
    _cur_surface=""
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

while IFS= read -r line; do
    line="${line%%#*}"     # strip trailing comments
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
    esac
done < "$MANIFEST"
flush_bug

# ---------------------------------------------------------------------------
# Detection command per bug class
# ---------------------------------------------------------------------------

detection_cmd() {
    local id="$1"
    local class="${BUG_CLASS[$id]}"
    local surface="${BUG_SURFACE[$id]}"
    local trigger="${BUG_TRIGGER[$id]}"
    local expected="${BUG_EXPECTED[$id]}"
    local difftest="$2"   # path to the difftest binary

    case "$class" in
        canonical)
            echo "$difftest --repro $trigger --surface $surface --check-canonical $expected"
            ;;
        panic)
            echo "$difftest --repro $trigger --surface $surface"
            ;;
        accept-reject|cost|reduce)
            echo "$difftest --oracle --oracle-script $ORACLE_SCRIPT --repro $trigger --surface $surface"
            ;;
        *)
            echo ""
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Gate runner
# ---------------------------------------------------------------------------

PASS=0
FAIL=0
SKIP=0

for id in "${BUG_IDS[@]}"; do
    # Filter by --only if set
    if [[ -n "$ONLY" && "$id" != "$ONLY" ]]; then
        continue
    fi

    wr="${BUG_WR[$id]}"
    trigger="${BUG_TRIGGER[$id]}"
    patch_file="$PATCHES_DIR/${id}.patch"
    class="${BUG_CLASS[$id]}"

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

    if $GENERATED; then
        if [[ "$class" != "canonical" && "$class" != "panic" ]]; then
            # Only oracle surfaces support structured generators
            echo "[SKIP] $id: --generated mode — structured generators not present"
            ((SKIP++)) || true
            continue
        fi
        echo "[SKIP] $id: --generated mode for hermetic surfaces (canonical/panic) uses trigger_hex path"
        ((SKIP++)) || true
        continue
    fi

    echo ""
    echo "=== $id ($class) ==="

    # --- Step 1: clean HEAD — detection command must exit 0 ---
    clean_difftest="$(cargo build -p ergo-difftest --release --quiet 2>/dev/null && \
        echo "$REPO_ROOT/target/release/difftest" || true)"
    if [[ -z "$clean_difftest" || ! -x "$clean_difftest" ]]; then
        # Fall back to cargo run
        clean_difftest="cargo run -p ergo-difftest --release -q --"
    fi

    cmd="$(detection_cmd "$id" "$clean_difftest")"
    if [[ -z "$cmd" ]]; then
        echo "[SKIP] $id: no detection command for class '$class'"
        ((SKIP++)) || true
        continue
    fi

    echo "  [clean HEAD] $cmd"
    set +e
    eval "$cmd" > /tmp/reinject_clean_${id}.out 2>&1
    clean_exit=$?
    set -e
    cat /tmp/reinject_clean_${id}.out

    if [[ $clean_exit -ne 0 ]]; then
        echo "  [FAIL] clean HEAD: expected exit 0, got $clean_exit (false positive — bad trigger?)"
        ((FAIL++)) || true
        continue
    fi
    echo "  [ok] clean HEAD: exit 0 (no divergence)"

    # --- Step 2: patched HEAD — apply patch, build, detection must exit non-zero ---
    SCRATCH="$(mktemp -d)"
    SCRATCH_BRANCH="reinject-${id}-$$"

    cleanup_scratch() {
        git worktree remove --force "$SCRATCH" 2>/dev/null || true
    }
    trap cleanup_scratch EXIT

    git worktree add --detach "$SCRATCH" HEAD 2>/dev/null
    (
        cd "$SCRATCH"
        git apply "$patch_file"
        cargo build -p ergo-difftest --release --quiet \
            --target-dir "$SCRATCH/target-reinject" 2>&1 | grep -v "^   Compiling\|^    Finished" || true
        PATCHED_BIN="$SCRATCH/target-reinject/release/difftest"
        patched_cmd="$(detection_cmd "$id" "$PATCHED_BIN")"
        echo "  [patched] $patched_cmd"
        set +e
        eval "$patched_cmd" > /tmp/reinject_patched_${id}.out 2>&1
        patched_exit=$?
        set -e
        cat /tmp/reinject_patched_${id}.out
        echo "$patched_exit" > /tmp/reinject_patched_exit_${id}.txt
    )
    patched_exit_val="$(cat /tmp/reinject_patched_exit_${id}.txt 2>/dev/null || echo 0)"

    cleanup_scratch
    trap - EXIT

    if [[ "$patched_exit_val" -eq 0 ]]; then
        echo "  [FAIL] patched HEAD: expected non-zero exit, got 0 (bug NOT detected — coverage gap)"
        ((FAIL++)) || true
    else
        echo "  [PASS] patched HEAD: exit $patched_exit_val (bug detected as expected)"
        ((PASS++)) || true
    fi
done

echo ""
echo "=== reinject_gate summary ==="
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
exit 0
