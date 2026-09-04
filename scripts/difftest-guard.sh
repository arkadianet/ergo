#!/usr/bin/env bash
# difftest-guard.sh — the standing consensus guard.
#
# Runs the structure-aware generators against the live JVM oracle on the
# consensus-complete surfaces, minimizes + classifies every unique divergence,
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
# (sigma-state 6.0.2 from Maven, ergo-core 6.0.2 from a local `sbt
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
DEFAULT_REGRESSIONS_DIR="$REPO_ROOT/ergo-difftest/regressions"
REGRESSIONS_DIR="$DEFAULT_REGRESSIONS_DIR"
BASELINE="$REPO_ROOT/ergo-difftest/known_bugs/baseline.toml"
KEEP_REGRESSIONS=false

while [[ $# -gt 0 ]]; do
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

case "$SEED$ITERS" in
    *[!0-9]*) echo >&2 "difftest-guard: --seed and --iters must be integers"; exit "$EXIT_USAGE" ;;
esac

if ! command -v scala-cli >/dev/null 2>&1; then
    echo >&2 "difftest-guard: scala-cli not on PATH — the guard needs the JVM oracle."
    exit "$EXIT_USAGE"
fi

# ---------------------------------------------------------------------------
# Baseline: `key = "<surface>/<hash16>"` + a REQUIRED `ref` naming a PR/issue.
# Parsed with the same pure-bash approach as reinject_gate.sh (no TOML library
# in the toolchain).
# ---------------------------------------------------------------------------

declare -A BASELINE_REF=()
declare -A BASELINE_HIT=()

# Strip a trailing TOML comment WITHOUT cutting a '#' inside a quoted value —
# `ref = "PR #301"` is exactly that case, and a naive `${line%%#*}` truncates it
# to `PR `, so the required-reference rule would reject its own valid input.
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

load_baseline() {
    [[ -f "$BASELINE" ]] || {
        echo >&2 "difftest-guard: baseline file not found: $BASELINE"
        exit "$EXIT_USAGE"
    }
    local line key="" ref="" bad=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="$(strip_comment "$line")"
        line="${line#"${line%%[![:space:]]*}"}"
        case "$line" in
            "[[baseline]]"*)
                if [[ -n "$key" ]]; then BASELINE_REF["$key"]="$ref"; fi
                key=""; ref="" ;;
            key*=*)  key="$(printf '%s' "${line#*=}" | tr -d ' "')" ;;
            ref*=*)  ref="$(printf '%s' "${line#*=}" | sed 's/^ *"//; s/" *$//')" ;;
        esac
    done < "$BASELINE"
    if [[ -n "$key" ]]; then BASELINE_REF["$key"]="$ref"; fi

    for key in "${!BASELINE_REF[@]}"; do
        # A baseline entry without a tracking reference is a muted divergence,
        # not an accepted one. Refuse the whole run rather than silently honour it.
        if ! [[ "${BASELINE_REF[$key]}" =~ ^(PR|issue)\ \#[0-9]+$ ]]; then
            echo >&2 "difftest-guard: baseline entry $key has ref '${BASELINE_REF[$key]}' — must match '(PR|issue) #<number>'"
            bad=1
        fi
        if ! [[ "$key" =~ ^[a-z_]+/[0-9a-f]{16}$ ]]; then
            echo >&2 "difftest-guard: baseline key '$key' is not '<surface>/<16 hex chars>'"
            bad=1
        fi
    done
    (( bad == 0 )) || exit "$EXIT_USAGE"
}

load_baseline

# ---------------------------------------------------------------------------
# Binary.
# ---------------------------------------------------------------------------

DIFFTEST_BIN="${DIFFTEST_BIN:-}"
if [[ -z "$DIFFTEST_BIN" ]]; then
    echo "difftest-guard: building ergo-difftest (release)…"
    cargo build --release --quiet -p ergo-difftest
    DIFFTEST_BIN="$(cargo metadata --format-version 1 --no-deps \
        | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')/release/difftest"
fi
if [[ ! -x "$DIFFTEST_BIN" ]]; then
    echo >&2 "difftest-guard: difftest binary not found at $DIFFTEST_BIN"
    exit "$EXIT_USAGE"
fi

# `rm -rf` on a caller-supplied path: only ever the default, or something under
# the repository. A typo in --regressions-dir must not cost somebody their home
# directory.
if ! $KEEP_REGRESSIONS; then
    abs_regressions="$(cd "$(dirname "$REGRESSIONS_DIR")" 2>/dev/null && pwd)/$(basename "$REGRESSIONS_DIR")" || abs_regressions=""
    if [[ "$abs_regressions" != "$DEFAULT_REGRESSIONS_DIR" && "$abs_regressions" != "$REPO_ROOT"/* ]]; then
        echo >&2 "difftest-guard: refusing to clear '$REGRESSIONS_DIR' — it is outside the repository."
        echo >&2 "                 pass --keep-regressions, or point --regressions-dir under $REPO_ROOT."
        exit "$EXIT_USAGE"
    fi
    rm -rf "$abs_regressions"
fi

# One log per surface so a failure keeps its full evidence.
LOG_DIR="$(mktemp -d)"
trap 'rm -rf "$LOG_DIR"' EXIT

echo "difftest-guard: seed=$SEED iters=$ITERS oracle=$ORACLE_SCRIPT"
echo "difftest-guard: surfaces: $SURFACES"
echo "difftest-guard: baseline: $BASELINE (${#BASELINE_REF[@]} accepted entries)"
echo

declare -A CHECKS DIVERGENCES CLASSES PENDING ARTIFACTS RC
harness_failed=0

for surface in $SURFACES; do
    echo "── $surface ──────────────────────────────────────────────"
    log="$LOG_DIR/$surface.log"
    # Per-surface transcript: the guard spawns one oracle process per surface,
    # and they must not share one file.
    surface_env=()
    if [[ -n "${DIFFTEST_ORACLE_LOG:-}" ]]; then
        surface_env=(env "DIFFTEST_ORACLE_LOG=${DIFFTEST_ORACLE_LOG}.${surface}")
    fi
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
    echo
done

# ---------------------------------------------------------------------------
# Split the filed PENDING records into baselined and new.
# ---------------------------------------------------------------------------

new_keys=()
baselined_keys=()
for surface in $SURFACES; do
    dir="$REGRESSIONS_DIR/$surface"
    [[ -d "$dir" ]] || continue
    for record in "$dir"/*.json; do
        [[ -e "$record" ]] || continue
        key="$surface/$(basename "$record" .json)"
        if [[ -n "${BASELINE_REF[$key]:-}" ]]; then
            baselined_keys+=("$key")
            BASELINE_HIT[$key]=1
        else
            new_keys+=("$key")
        fi
    done
done

echo "=============================================================="
printf '%-20s %8s %12s %8s %8s %10s %4s\n' surface checks divergences classes pending artifacts rc
printf '%-20s %8s %12s %8s %8s %10s %4s\n' -------------------- -------- ------------ -------- -------- ---------- ----
for surface in $SURFACES; do
    printf '%-20s %8s %12s %8s %8s %10s %4s\n' \
        "$surface" "${CHECKS[$surface]}" "${DIVERGENCES[$surface]}" \
        "${CLASSES[$surface]}" "${PENDING[$surface]}" "${ARTIFACTS[$surface]}" "${RC[$surface]}"
done
echo "=============================================================="
echo "regressions filed under: $REGRESSIONS_DIR"
echo

if (( ${#baselined_keys[@]} > 0 )); then
    echo "accepted baseline (known, tracked — not a failure):"
    printf '%-40s %s\n' record tracked-as
    for key in "${baselined_keys[@]}"; do
        printf '%-40s %s\n' "$key" "${BASELINE_REF[$key]}"
    done
    echo
fi

# A baseline entry the run did NOT reproduce is worth saying out loud: either the
# fix landed (delete the entry) or the campaign stopped reaching the class.
stale=()
for key in "${!BASELINE_REF[@]}"; do
    [[ -n "${BASELINE_HIT[$key]:-}" ]] || stale+=("$key")
done
if (( ${#stale[@]} > 0 )); then
    echo "baseline entries NOT reproduced by this run (fix landed, or coverage lost):"
    for key in "${stale[@]}"; do
        printf '  %-38s %s\n' "$key" "${BASELINE_REF[$key]}"
    done
    echo "  (not a failure at this seed/iteration budget — but if a fix merged, delete the entry)"
    echo
fi

if (( harness_failed )); then
    echo "difftest-guard: HARNESS FAILURE — the run did not check what it planned to."
    echo "A partial run says nothing about consensus parity. Fix the oracle and re-run."
    exit "$EXIT_HARNESS"
fi

if (( ${#new_keys[@]} > 0 )); then
    echo "difftest-guard: FAIL — ${#new_keys[@]} UNBASELINED pending divergence(s):"
    for key in "${new_keys[@]}"; do
        echo "  $key  →  $REGRESSIONS_DIR/$key.json"
    done
    echo
    echo "Triage each one. If it is a genuine, tracked divergence, file an issue and"
    echo "add it to $BASELINE with its ref. Never baseline to make the run green."
    exit "$EXIT_FINDING"
fi

echo "difftest-guard: PASS — every planned check ran; no unbaselined pending divergences."
