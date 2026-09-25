#!/usr/bin/env bash
# shadow-compare.sh — run the embedded-vs-daemon wallet shadow harness.
#
# Phase-2 item 5. The harness lives in `ergo-walletd/tests/it/shadow.rs` and
# proves that the node's *embedded* wallet (a real `ergo-state` `StateStore`
# whose redb also holds the wallet tables, advanced by the production
# `StateStore::apply_block` + `ergo_node::WalletStateHook`) and the standalone
# watch-only daemon (a real `RedbWalletStore::open_standalone` advanced by the
# real `StandaloneSyncer` over the real `HttpChainClient` against the real
# `ergo-api` chain router) reach the *same* `WalletRead` state from the same
# blocks. The comparison is on normalized wallet state, not on daemon DTOs —
# see the module doc for why.
#
# All five scenarios are `#[ignore]`d so the default `cargo nextest run
# --workspace` CI job never pays for them. This script is the local entry
# point; CI runs the same command in the separate `wallet-shadow` job.
#
# Every `cargo test` invocation goes through `run_tests`, which parses the
# libtest summary and fails the run when it reports zero passed tests. Plain
# `cargo test` exits 0 for a filter that matches nothing ("0 passed; …; N
# filtered out"), so without that guard a renamed or deleted scenario would
# leave this script reporting a successful shadow comparison it never made.
#
# Usage:
#   scripts/shadow-compare.sh              # cheap negative controls only
#   scripts/shadow-compare.sh --all        # negative controls + all 5 slow scenarios
#   scripts/shadow-compare.sh --list       # print the scenario names and exit
#   scripts/shadow-compare.sh <name>...    # run only the named scenarios
#          synthetic | reorg | restart | rescan | sweep
#
# Environment:
#   CARGO_TARGET_DIR   Overridden below to an isolated directory unless the
#                      caller already set one. The shadow harness links
#                      `ergo-node` + `ergo-api` + `ergo-state` test binaries,
#                      which is a multi-GB build; sharing the developer's
#                      day-to-day target dir means a shadow run evicts (or is
#                      evicted by) their normal build cache.
#   TMPDIR             Also redirected into the same isolated tree, because the
#                      scenarios create several redb databases under
#                      `tempfile::tempdir()` and a shared /tmp on a small disk
#                      is the other way this run can take the machine down.
#   SHADOW_TARGET_DIR  Override the isolated directory itself.
#   SHADOW_KEEP        Set to 1 to keep the isolated tree after the run. The
#                      per-invocation logs also live there, so a failed run
#                      always leaves its full output behind.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# The workspace's test target. Kept as the existing single `it` target on
# purpose: adding a second target would change `scripts/ci-shards.py`'s
# crate-group coverage ledger, so the shadow scenarios live inside `it`.
TEST_TARGET=( -p ergo-walletd --test it )

# Test-name filters. `shadow_` alone would also match the two cheap
# negative-control tests, which is intentional for --all: the comparator has to
# be proven able to fail on every run, not only alongside the slow scenarios.
declare -A SCENARIOS=(
    [synthetic]=shadow_synthetic_smoke_agrees_embedded_and_daemon
    [reorg]=shadow_reorg_rewinds_and_reapplies_on_both_sides
    [restart]=shadow_survives_a_node_and_daemon_restart
    [rescan]=shadow_daemon_rescan_from_zero_reproduces_the_embedded_state
    [sweep]=shadow_sweep_digest_1_1000_agrees_embedded_and_daemon
)
SLOW_SCENARIOS=( synthetic reorg restart rescan sweep )

# Print this file's leading comment block, so the documented usage can never
# drift from the implemented one.
usage() { sed -n '2,/^$/p' "$0"; }

list_scenarios() {
    for key in "${SLOW_SCENARIOS[@]}"; do
        printf '%-10s %s\n' "$key" "${SCENARIOS[$key]}"
    done
}

select_scenarios() {
    local out=()
    for key in "$@"; do
        if [ -z "${SCENARIOS[$key]:-}" ]; then
            echo "error: unknown scenario '$key'; valid: ${SLOW_SCENARIOS[*]}" >&2
            echo "       run '$0 --list' for the test names" >&2
            exit 2
        fi
        out+=("${SCENARIOS[$key]}")
    done
    printf '%s\n' "${out[@]}"
}

# ----- isolated build + temp environment -----
SHADOW_TARGET_DIR="${SHADOW_TARGET_DIR:-${REPO_ROOT}/.shadow-target}"
export TMPDIR="${TMPDIR:-$SHADOW_TARGET_DIR/tmp}"
mkdir -p "$TMPDIR"
# Per-invocation logs. Under the isolated tree, so a failing run leaves its
# full output on disk for inspection instead of only in a scrolled buffer.
SHADOW_LOG_DIR="$SHADOW_TARGET_DIR/logs"
mkdir -p "$SHADOW_LOG_DIR"
# Only claim CARGO_TARGET_DIR when the caller did not choose one: an explicit
# setting is a deliberate choice and overriding it would be rude.
if [ -z "${CARGO_TARGET_DIR:-}" ]; then
    export CARGO_TARGET_DIR="$SHADOW_TARGET_DIR/target"
fi

# Run one libtest invocation and require that it actually ran something.
#
# `cargo test` exits 0 when its filter matches no test at all ("0 passed;
# 0 failed; 0 measured; N filtered out"), which is precisely the failure mode
# this harness must not have: rename a scenario, or typo a module path, and a
# script that only trusts the exit code reports a green shadow comparison it
# never performed. So every invocation — the negative controls and each named
# scenario — is teed to a log and its final `test result:` line is parsed; a
# run that executed zero tests is a failure, with the test names printed so a
# renamed scenario is obvious from the message alone.
run_tests() {
    local label="$1"
    shift
    local log="$SHADOW_LOG_DIR/$(printf '%s' "$label" | tr -c 'A-Za-z0-9._-' '_').log"
    echo "==> $label"
    # `set -o pipefail` is what makes a `cargo test` failure survive the pipe;
    # without it `tee`'s status would mask it and the run would look green.
    if ! cargo test "${TEST_TARGET[@]}" "$@" 2>&1 | tee "$log"; then
        echo "error: '$label' failed; full output: $log" >&2
        return 1
    fi
    local summary passed
    summary="$(grep -aE '^test result: ' "$log" | tail -n 1 || true)"
    if [ -z "$summary" ]; then
        echo "error: '$label' printed no 'test result:' summary, so libtest never" >&2
        echo "       reported a run at all; full output: $log" >&2
        return 1
    fi
    # The count is read back out of the summary rather than trusted from
    # libtest's `running N tests` line, because that line counts what the
    # *filter* selected, not what the test binary actually executed. Both the
    # passed count and the "N filtered out" tail are part of the same line, so
    # the number immediately before ` passed` is the one that matters.
    passed="$(printf '%s' "$summary" | sed -n 's/.*[^0-9]\([0-9][0-9]*\) passed;.*/\1/p')"
    if [ -z "$passed" ] || [ "$passed" -lt 1 ]; then
        echo "error: '$label' ran ${passed:-0} tests: $summary" >&2
        echo "       a filter that matches nothing exits 0 and compares nothing;" >&2
        echo "       check the names in SCENARIOS against:" >&2
        echo "         cargo test ${TEST_TARGET[*]} -- --list" >&2
        return 1
    fi
    echo "    $summary"
}

case "${1:-}" in
    --all)
        if [ "$#" -ne 1 ]; then
            echo "error: --all takes no arguments; name the scenarios instead" >&2
            exit 2
        fi
        mapfile -t FILTERS < <(select_scenarios "${SLOW_SCENARIOS[@]}")
        ;;
    "")
        # No arguments: the negative controls only. Deliberately the default —
        # the five scenarios are minutes of work and asking for them by name (or
        # with --all) keeps an accidental bare invocation cheap.
        FILTERS=()
        ;;
    --list)
        list_scenarios
        exit 0
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        mapfile -t FILTERS < <(select_scenarios "$@")
        ;;
esac

echo "==> workspace: $REPO_ROOT"
echo "==> CARGO_TARGET_DIR=${CARGO_TARGET_DIR}"
echo "==> TMPDIR=${TMPDIR}"

# The cheap negative controls. They run on every invocation: a shadow
# comparison whose comparator cannot fail is not evidence, so the controls are
# not optional and are not `#[ignore]`d.
run_tests "shadow negative controls" shadow_comparator -- --nocapture

if [ "${#FILTERS[@]}" -eq 0 ]; then
    echo "==> negative controls passed; pass --all (or scenario names) for the slow scenarios"
    exit 0
fi

# The slow scenarios. `--ignored` selects exactly the `#[ignore]`d shadow
# tests; `--test-threads` is left at cargo's default because the scenarios each
# build their own pair of redb databases and the 1-1000 sweep is the long pole
# either way.
for filter in "${FILTERS[@]}"; do
    # `--exact` with the module-qualified name: the `it` target runs every
    # module in one binary, so the bare test fn name is not a unique filter
    # there. An unqualified name would match nothing, and `run_tests` turns
    # "nothing matched" into a failure rather than a green run.
    run_tests "shadow scenario: $filter" "shadow::$filter" -- --ignored --exact --nocapture
done

if [ "${SHADOW_KEEP:-0}" != "1" ]; then
    # Nothing under .shadow-target is a source artifact; leaving multi-GB
    # build output behind after every run is how a laptop fills up.
    rm -rf "$SHADOW_TARGET_DIR"
    echo "==> removed $SHADOW_TARGET_DIR (set SHADOW_KEEP=1 to retain it)"
fi

echo "==> shadow comparison complete"
