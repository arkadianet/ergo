#!/usr/bin/env bash
# difftest-guard.sh — the standing consensus guard.
#
# Runs the structure-aware generators against the live JVM oracle on the
# supported codec and reduction surfaces, minimizes + classifies every unique divergence,
# and prints a per-surface table.
#
# Verdict:
#   exit 0  every planned check ran, and no UNBASELINED pending divergence.
#   exit 1  an unbaselined pending divergence — a candidate for human triage.
#   exit 2  usage / environment error (no scala-cli, no binary, bad baseline).
#   exit 3  HARNESS error — the oracle died, or a surface checked fewer inputs
#           than it planned. A run that checked almost nothing must never read
#           as a pass, so this is louder than a finding, not quieter.
#
# Accepted baseline: ergo-difftest/known_bugs/baseline.toml. Divergences already
# known and tracked are listed there by their content-addressed record key and
# printed separately; only unlisted pendings fail the run.
#
# This is the same set the `consensus-guard` job in .github/workflows/fuzz.yml
# runs, so a local reproduction is one command.
#
# Usage:
#   scripts/difftest-guard.sh [--seed N] [--iters N] [--surfaces "a b c"]
#                             [--oracle-script PATH] [--regressions-dir DIR]
#                             [--baseline PATH] [--keep-regressions]
#
# Defaults: --seed 991 --iters 2000 over
#   reduce  reduce_ctx  transaction  ergo_box_candidate  validate
#
# DIFFTEST_ORACLE_LOG=<path> records the oracle request/response transcript; the
# script gives each surface its own `<path>.<surface>` file so one surface's
# process cannot overwrite another's evidence.
#
# Requires `scala-cli` on PATH and the oracle's dependencies resolvable
# (sigma-state 6.0.6 from Maven, ergo-core 6.0.6 from a local `sbt
# ergoCore/publishLocal` — see ergo-difftest/README.md "Oracle setup").

set -euo pipefail

EXIT_FINDING=1
EXIT_USAGE=2
EXIT_HARNESS=3

REPO_ROOT="$(git rev-parse --show-toplevel)"

SEED=991
ITERS=2000
SURFACES="reduce reduce_ctx transaction ergo_box_candidate validate"
ORACLE_SCRIPT="$REPO_ROOT/scripts/jvm_serde_oracle/ErgoSerdeOracle.scala"
REGRESSIONS_DIR=""
BASELINE="$REPO_ROOT/ergo-difftest/known_bugs/baseline.toml"
KEEP_REGRESSIONS=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --seed|--iters|--surfaces|--oracle-script|--regressions-dir|--baseline)
            [[ $# -ge 2 && -n "$2" ]] || { echo >&2 "missing value for $1"; exit "$EXIT_USAGE"; } ;;
    esac
    case "$1" in
        --seed)            SEED="$2"; shift 2 ;;
        --iters)           ITERS="$2"; shift 2 ;;
        --surfaces)        SURFACES="$2"; shift 2 ;;
        --oracle-script)   ORACLE_SCRIPT="$2"; shift 2 ;;
        --regressions-dir) REGRESSIONS_DIR="$2"; shift 2 ;;
        --baseline)        BASELINE="$2"; shift 2 ;;
        --keep-regressions) KEEP_REGRESSIONS=true; shift ;;
        -h|--help)         sed -n '2,/^set -euo/p' "$0"; exit 0 ;;
        *) echo >&2 "unknown argument: $1"; exit "$EXIT_USAGE" ;;
    esac
done

if ! python3 - "$SEED" "$ITERS" <<'CHECK_ARGUMENTS'
import sys
for value in sys.argv[1:]:
    if not value.isascii() or not value.isdigit() or not 0 < int(value) <= 2**64 - 1:
        sys.exit(1)
if int(sys.argv[2]) > 1_000_000_000_000:
    sys.exit(1)
CHECK_ARGUMENTS
then
    echo >&2 "difftest-guard: positive u64 seed and iteration count in 1..1000000000000 required"
    exit "$EXIT_USAGE"
fi
# Normalize leading zeros before comparing the printed completed-check count.
SEED="$(python3 -c 'import sys; print(int(sys.argv[1]))' "$SEED")"
ITERS="$(python3 -c 'import sys; print(int(sys.argv[1]))' "$ITERS")"
read -r -a SURFACE_LIST <<< "$SURFACES"
[[ ${#SURFACE_LIST[@]} -gt 0 ]] || { echo >&2 "difftest-guard: empty surface set"; exit "$EXIT_USAGE"; }
declare -A SEEN_SURFACE=()
for surface in "${SURFACE_LIST[@]}"; do
    case "$surface" in
        ergo_tree|ergo_box_candidate|transaction|header|reduce|reduce_ctx|validate) ;;
        *) echo >&2 "difftest-guard: unsupported structured oracle surface: $surface"; exit "$EXIT_USAGE" ;;
    esac
    [[ -z "${SEEN_SURFACE[$surface]:-}" ]] || { echo >&2 "duplicate surface: $surface"; exit "$EXIT_USAGE"; }
    SEEN_SURFACE[$surface]=1
done
if ! command -v scala-cli >/dev/null 2>&1; then
    echo >&2 "difftest-guard: scala-cli not on PATH — the guard needs the JVM oracle."
    exit "$EXIT_USAGE"
fi
RECORD_VALIDATOR="$REPO_ROOT/scripts/difftest-records.py"
python3 "$RECORD_VALIDATOR" --baseline "$BASELINE" --check-baseline || exit "$EXIT_USAGE"

# ---------------------------------------------------------------------------
# Binary.
# ---------------------------------------------------------------------------

DIFFTEST_BIN="${DIFFTEST_BIN:-}"
if [[ -z "$DIFFTEST_BIN" ]]; then
    echo "difftest-guard: building ergo-difftest (release)…"
    cargo build --locked --release -p ergo-difftest
    DIFFTEST_BIN="$(cargo metadata --locked --format-version 1 --no-deps \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/release/difftest"
fi
if [[ ! -x "$DIFFTEST_BIN" ]]; then
    echo >&2 "difftest-guard: difftest binary not found at $DIFFTEST_BIN"
    exit "$EXIT_USAGE"
fi

# Default to a fresh owned output directory. Explicit existing output is kept
# only with --keep-regressions; the guard never clears caller-owned evidence.
if [[ -z "$REGRESSIONS_DIR" ]]; then
    REGRESSIONS_DIR="$(mktemp -d "$REPO_ROOT/ergo-difftest/regressions-run.XXXXXX")"
elif [[ -e "$REGRESSIONS_DIR" || -L "$REGRESSIONS_DIR" ]]; then
    if ! $KEEP_REGRESSIONS || [[ ! -d "$REGRESSIONS_DIR" || -L "$REGRESSIONS_DIR" ]]; then
        echo >&2 "difftest-guard: output exists; preserve it and select a fresh directory, or explicitly use --keep-regressions"
        exit "$EXIT_USAGE"
    fi
else
    mkdir -p "$REGRESSIONS_DIR"
fi
REGRESSIONS_DIR="$(cd "$REGRESSIONS_DIR" && pwd -P)"
mkdir -p "$REGRESSIONS_DIR/logs"
LOG_DIR="$(mktemp -d "$REGRESSIONS_DIR/logs/run.XXXXXX")"

echo "difftest-guard: seed=$SEED iters=$ITERS oracle=$ORACLE_SCRIPT"
echo "difftest-guard: surfaces: $SURFACES"
echo "difftest-guard: baseline: $BASELINE"
echo "difftest-guard: preserved logs: $LOG_DIR"
echo

declare -A CHECKS DIVERGENCES CLASSES PENDING ARTIFACTS RC
harness_failed=0

for surface in "${SURFACE_LIST[@]}"; do
    echo "── $surface ──────────────────────────────────────────────"
    log="$LOG_DIR/$surface.log"
    # Per-surface transcript: the guard spawns one oracle process per surface,
    # and they must not share one file.
    surface_env=(env "DIFFTEST_ORACLE_LOG=${DIFFTEST_ORACLE_LOG:-$LOG_DIR/oracle-transcript.log}.${surface}")
    # `--structured` feeds each surface its own targeted generator; `--minimize`
    # shrinks + classifies + files every unique divergence under the regressions
    # directory.
    set +e
    "${surface_env[@]}" "$DIFFTEST_BIN" --oracle --structured --minimize \
        --oracle-script "$ORACLE_SCRIPT" \
        --regressions-dir "$REGRESSIONS_DIR" \
        --surface "$surface" --iters "$ITERS" --seed "$SEED" >"$log" 2>&1
    rc=$?
    set -e
    RC[$surface]=$rc
    tail -n 40 "$log"
    echo

    # `read` returns 1 at EOF — under `set -e` (re-enabled just above) a log
    # missing the `oracle: checks=...` summary line (e.g. the binary crashed
    # before printing it) would abort the script right here with a bare
    # status 1, instead of falling through to the liveness checks below that
    # classify a missing summary as the HARNESS error (exit 3) it is. `|| true`
    # lets a failed/empty read through; `checks`/`divergences`/`classes` then
    # stay unset and the `${var:-0}` defaults below make CHECKS[$surface]
    # read as "0 checks ran", which the loop's liveness assertion (3) below
    # already turns into `harness_failed=1`.
    checks= divergences= classes=
    read -r checks divergences classes < <(
        sed -n 's/^oracle: checks=\([0-9]*\) surfaces=[0-9]* unique_classes=\([0-9]*\) total_divergences=\([0-9]*\)$/\1 \3 \2/p' "$log" | tail -n 1
    ) || true
    CHECKS[$surface]="${checks:-0}"
    DIVERGENCES[$surface]="${divergences:-0}"
    CLASSES[$surface]="${classes:-0}"
    PENDING[$surface]="$(grep -c '\[PENDING\]' "$log" || true)"
    ARTIFACTS[$surface]="$(grep -c '\[KnownArtifact\]' "$log" || true)"

    # Three independent liveness assertions, because a guard that reports a
    # green run it never actually performed is worse than no guard:
    #   (1) the exit code is one the campaign is allowed to produce,
    #   (2) the log carries no harness-error marker,
    #   (3) the surface checked exactly as many inputs as it planned.
    if [[ $rc -ne 0 && $rc -ne "$EXIT_FINDING" ]]; then
        echo "difftest-guard: HARNESS ERROR — $surface exited $rc (expected 0 or $EXIT_FINDING); see $log"
        harness_failed=1
    fi
    if grep -q 'oracle: HARNESS ERROR:' "$log"; then
        echo "difftest-guard: HARNESS ERROR — $surface reported an oracle pipe failure:"
        grep 'oracle: HARNESS ERROR:' "$log" | sed 's/^/    /'
        harness_failed=1
    fi
    if [[ "${CHECKS[$surface]}" != "$ITERS" ]]; then
        echo "difftest-guard: HARNESS ERROR — $surface ran ${CHECKS[$surface]} checks, expected $ITERS"
        harness_failed=1
    fi

    # A completed input loop does not establish that detected evidence was
    # processed/filed. Every observed class must have a pending record.
    if (( ${CLASSES[$surface]} > 0 )); then
        minimized_unique= filed_pending= filed_artifacts=
        read -r minimized_unique filed_pending filed_artifacts < <(
            sed -n 's/^minimize summary: checks=[0-9]* unique_divergences=\([0-9]*\) minimized=[0-9]* pending_queued=\([0-9]*\) known_artifacts=\([0-9]*\)$/\1 \2 \3/p' "$log" | tail -n 1
        ) || true
        if [[ "${minimized_unique:-}" != "${CLASSES[$surface]}" ||
              "${filed_pending:-}" != "${CLASSES[$surface]}" ||
              "${filed_artifacts:-}" != "0" ]]; then
            echo "difftest-guard: HARNESS ERROR — $surface detected ${CLASSES[$surface]} class(es), but pending filing was incomplete"
            harness_failed=1
        fi
    elif [[ $rc -eq "$EXIT_FINDING" ]]; then
        echo "difftest-guard: HARNESS ERROR — $surface exited finding with zero reported classes"
        harness_failed=1
    fi
    echo
done

# Validate full JSON identities and source-bound authority before any baseline
# hit. Filenames alone, including historical short keys, cannot mute findings.
set +e
python3 "$RECORD_VALIDATOR" --root "$REGRESSIONS_DIR" --baseline "$BASELINE" \
    --surfaces "${SURFACE_LIST[@]}" > "$LOG_DIR/record-validation.log" 2>&1
record_rc=$?
set -e
cat "$LOG_DIR/record-validation.log"
if [[ $record_rc -ne 0 && $record_rc -ne "$EXIT_FINDING" ]]; then
    harness_failed=1
fi
for surface in "${SURFACE_LIST[@]}"; do
    validated="$(sed -n "s/^VALIDATED $surface \\([0-9]*\\)$/\\1/p" "$LOG_DIR/record-validation.log")"
    if [[ -z "$validated" ]] || (( validated < ${CLASSES[$surface]} )); then
        echo "difftest-guard: HARNESS ERROR — $surface has fewer validated records than detected classes"
        harness_failed=1
    fi
done

echo "=============================================================="
printf '%-20s %8s %12s %8s %8s %10s %4s\n' surface checks divergences classes pending artifacts rc
printf '%-20s %8s %12s %8s %8s %10s %4s\n' -------------------- -------- ------------ -------- -------- ---------- ----
for surface in "${SURFACE_LIST[@]}"; do
    printf '%-20s %8s %12s %8s %8s %10s %4s\n' \
        "$surface" "${CHECKS[$surface]}" "${DIVERGENCES[$surface]}" \
        "${CLASSES[$surface]}" "${PENDING[$surface]}" "${ARTIFACTS[$surface]}" "${RC[$surface]}"
done
echo "=============================================================="
echo "regressions filed under: $REGRESSIONS_DIR"
echo

if (( harness_failed )); then
    echo "difftest-guard: HARNESS FAILURE — the run did not check what it planned to."
    echo "A partial run says nothing about consensus parity. Fix the oracle and re-run."
    exit "$EXIT_HARNESS"
fi

if [[ $record_rc -eq "$EXIT_FINDING" ]]; then
    echo "difftest-guard: FAIL — unbaselined authority-bound pending divergence(s); see $LOG_DIR/record-validation.log"
    echo
    echo "Triage each one. If it is a genuine, tracked divergence, file an issue and"
    echo "add it to $BASELINE with its ref. Never baseline to make the run green."
    exit "$EXIT_FINDING"
fi

echo "difftest-guard: PASS — every planned check ran; no unbaselined pending divergences."
