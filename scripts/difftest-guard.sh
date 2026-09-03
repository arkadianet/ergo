#!/usr/bin/env bash
# difftest-guard.sh — the standing consensus guard.
#
# Runs the structure-aware generators against the live JVM oracle on the
# consensus-complete surfaces, minimizes + classifies every unique divergence,
# and prints a per-surface table. Exits non-zero when any divergence is filed
# as PENDING (a genuine candidate); KnownArtifact records are reported but do
# not fail the run.
#
# This is the same set the nightly `consensus-guard` job in
# .github/workflows/fuzz.yml runs, so a local reproduction is one command.
#
# Usage:
#   scripts/difftest-guard.sh [--seed N] [--iters N] [--surfaces "a b c"]
#                             [--oracle-script PATH] [--regressions-dir DIR]
#                             [--keep-regressions]
#
# Defaults: --seed 991 --iters 2000 over
#   reduce  reduce_ctx  transaction  ergo_box_candidate  validate
#
# Requires `scala-cli` on PATH and the oracle's dependencies resolvable
# (sigma-state 6.0.2 from Maven, ergo-core 6.0.2 from a local `sbt
# ergoCore/publishLocal` — see ergo-difftest/README.md "Oracle setup").

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"

SEED=991
ITERS=2000
SURFACES="reduce reduce_ctx transaction ergo_box_candidate validate"
ORACLE_SCRIPT="$REPO_ROOT/scripts/jvm_serde_oracle/ErgoSerdeOracle.scala"
REGRESSIONS_DIR="$REPO_ROOT/ergo-difftest/regressions"
KEEP_REGRESSIONS=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --seed)            SEED="$2"; shift 2 ;;
        --iters)           ITERS="$2"; shift 2 ;;
        --surfaces)        SURFACES="$2"; shift 2 ;;
        --oracle-script)   ORACLE_SCRIPT="$2"; shift 2 ;;
        --regressions-dir) REGRESSIONS_DIR="$2"; shift 2 ;;
        --keep-regressions) KEEP_REGRESSIONS=true; shift ;;
        -h|--help)         sed -n '2,/^set -euo/p' "$0"; exit 0 ;;
        *) echo >&2 "unknown argument: $1"; exit 2 ;;
    esac
done

if ! command -v scala-cli >/dev/null 2>&1; then
    echo >&2 "difftest-guard: scala-cli not on PATH — the guard needs the JVM oracle."
    exit 2
fi

DIFFTEST_BIN="${DIFFTEST_BIN:-}"
if [[ -z "$DIFFTEST_BIN" ]]; then
    echo "difftest-guard: building ergo-difftest (release)…"
    cargo build --release --quiet -p ergo-difftest
    DIFFTEST_BIN="$(cargo metadata --format-version 1 --no-deps \
        | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')/release/difftest"
fi
if [[ ! -x "$DIFFTEST_BIN" ]]; then
    echo >&2 "difftest-guard: difftest binary not found at $DIFFTEST_BIN"
    exit 2
fi

# One log per surface so a failure keeps its full evidence.
LOG_DIR="$(mktemp -d)"
trap 'rm -rf "$LOG_DIR"' EXIT

$KEEP_REGRESSIONS || rm -rf "$REGRESSIONS_DIR"

echo "difftest-guard: seed=$SEED iters=$ITERS oracle=$ORACLE_SCRIPT"
echo "difftest-guard: surfaces: $SURFACES"
echo

declare -A CHECKS DIVERGENCES CLASSES PENDING ARTIFACTS

for surface in $SURFACES; do
    echo "── $surface ──────────────────────────────────────────────"
    log="$LOG_DIR/$surface.log"
    # `--structured` feeds each surface its own targeted generator; `--minimize`
    # shrinks + classifies + files every unique divergence under the regressions
    # directory. A non-zero exit here only means "divergences were found" — the
    # PENDING count below decides whether the guard fails.
    set +e
    "$DIFFTEST_BIN" --oracle --structured --minimize \
        --oracle-script "$ORACLE_SCRIPT" \
        --regressions-dir "$REGRESSIONS_DIR" \
        --surface "$surface" --iters "$ITERS" --seed "$SEED" >"$log" 2>&1
    set -e
    tail -n 40 "$log"
    echo

    read -r checks divergences classes < <(
        sed -n 's/^oracle: checks=\([0-9]*\) surfaces=[0-9]* unique_classes=\([0-9]*\) total_divergences=\([0-9]*\)$/\1 \3 \2/p' "$log" | tail -n 1
    )
    CHECKS[$surface]="${checks:-0}"
    DIVERGENCES[$surface]="${divergences:-0}"
    CLASSES[$surface]="${classes:-0}"
    PENDING[$surface]="$(grep -c '\[PENDING\]' "$log" || true)"
    ARTIFACTS[$surface]="$(grep -c '\[KnownArtifact\]' "$log" || true)"
done

echo "=============================================================="
printf '%-20s %8s %12s %8s %8s %10s\n' surface checks divergences classes pending artifacts
printf '%-20s %8s %12s %8s %8s %10s\n' -------------------- -------- ------------ -------- -------- ----------
total_pending=0
for surface in $SURFACES; do
    printf '%-20s %8s %12s %8s %8s %10s\n' \
        "$surface" "${CHECKS[$surface]}" "${DIVERGENCES[$surface]}" \
        "${CLASSES[$surface]}" "${PENDING[$surface]}" "${ARTIFACTS[$surface]}"
    total_pending=$(( total_pending + ${PENDING[$surface]} ))
done
echo "=============================================================="
echo "regressions filed under: $REGRESSIONS_DIR"

if [[ $total_pending -gt 0 ]]; then
    echo
    echo "difftest-guard: FAIL — $total_pending PENDING divergence(s) need triage."
    echo "See $REGRESSIONS_DIR/QUEUE.md."
    exit 1
fi

echo
echo "difftest-guard: PASS — no PENDING divergences."
