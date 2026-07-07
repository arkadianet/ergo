#!/usr/bin/env bash
# tc1.sh — fresh-JVM typer oracle: one process per input line.
#
# WHY this exists (Risk R1):
# Height/Inputs/Outputs/Self/Context/Global/MinerPubkey/LastBlockUtxoRootHash are
# Scala case OBJECTS. Their `_sourceContext` field is write-once (values.scala:81-90):
# the FIRST typecheck that touches the singleton sets its position; every subsequent
# typecheck in the SAME JVM sees that stale position in error messages. This makes
# reject line:col non-reproducible across batch runs.
#
# Example (proven with golden_seed.txt):
#   batch: `if (HEIGHT) 1 else 2` after `HEIGHT > 0` → REJECT 1:1  (stale, wrong)
#   fresh: `if (HEIGHT) 1 else 2` alone            → REJECT 1:5  (correct)
#
# tc1.sh spawns one `scala-cli run` JVM per input line, so each source starts with a
# pristine singleton state → correct, reproducible positions. Slow (each spawn is
# ~2-4 s first call, cached thereafter), only for reject-position grading.
#
# Usage (from worktree root):
#   ORACLE_TREE_VERSION=3 scripts/jvm_typer_oracle/tc1.sh < input.txt
#
# Each input line: `verb <hex>`   where verb is tc or tce and hex is Base16(UTF-8 src).
# Each output line: same protocol as batch mode (OK / REJECT / ERR).
#
# ORACLE_TREE_VERSION and ORACLE_NETWORK are forwarded to each subprocess.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while IFS= read -r line; do
    trimmed="${line#"${line%%[![:space:]]*}"}"   # ltrim
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"  # rtrim
    if [ -z "$trimmed" ]; then
        continue
    fi
    printf '%s\n' "$trimmed" | \
        ORACLE_TREE_VERSION="${ORACLE_TREE_VERSION:-3}" \
        ORACLE_NETWORK="${ORACLE_NETWORK:-testnet}" \
        scala-cli run "$SCRIPT_DIR" 2>/dev/null | \
        grep -E '^(OK|REJECT|ERR) '
done
