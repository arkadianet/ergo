#!/usr/bin/env bash
# Drive the upstream Scala FullBlockPruningProcessor over our prune-formula
# vectors and emit `runtime-vectors.json`.
#
# Layout:
#   test-vectors/mode3-pruning/
#     prune-formula-vectors.json        (input fixture)
#     runtime-vectors.json              (output, produced here)
#     oracle-harness/PruneFormulaOracle.scala  (harness)
#     oracle-harness/run.sh             (this script)
#
# Requires a cloned upstream `ergoplatform/ergo` checkout reachable via
# the ERGO_REFERENCE_PATH env var (default: ../../../reference/ergo
# relative to this directory) and a portable `sbt` (default:
# ../../../tools/sbt/bin/sbt.bat). Both defaults match the layout used in
# this repo.
#
# What it does:
#   1. Stages PruneFormulaOracle.scala into the ergo test source tree.
#   2. Runs `sbt "Test/runMain ... ..."` to compile + execute against
#      the real upstream classpath.
#   3. Removes the staged file.
#   4. The harness writes runtime-vectors.json directly via its second
#      argument (we pass an absolute path to test-vectors/mode3-pruning).
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VECTORS_DIR="$(cd "$HARNESS_DIR/.." && pwd)"
DEFAULT_ERGO="$(cd "$VECTORS_DIR/../../../reference/ergo" 2>/dev/null && pwd || echo "")"
DEFAULT_SBT="$(cd "$VECTORS_DIR/../../../tools/sbt/bin" 2>/dev/null && pwd || echo "")/sbt.bat"

ERGO_REFERENCE_PATH="${ERGO_REFERENCE_PATH:-$DEFAULT_ERGO}"
SBT_BIN="${SBT_BIN:-$DEFAULT_SBT}"

if [[ -z "$ERGO_REFERENCE_PATH" || ! -d "$ERGO_REFERENCE_PATH" ]]; then
  echo "ergoplatform/ergo checkout not found at ${ERGO_REFERENCE_PATH:-<unset>}" >&2
  echo "set ERGO_REFERENCE_PATH to the cloned repo root and re-run" >&2
  exit 1
fi
if [[ ! -x "$SBT_BIN" && ! -f "$SBT_BIN" ]]; then
  echo "sbt not found at ${SBT_BIN:-<unset>}" >&2
  echo "set SBT_BIN to a working sbt launcher and re-run" >&2
  exit 1
fi

STAGE_DIR="$ERGO_REFERENCE_PATH/src/test/scala/org/ergoplatform/nodeView/history/storage/modifierprocessors"
mkdir -p "$STAGE_DIR"
STAGED_FILE="$STAGE_DIR/PruneFormulaOracle.scala"
cp "$HARNESS_DIR/PruneFormulaOracle.scala" "$STAGED_FILE"

# Override Test/javaOptions to drop --add-modules=java.xml.bind (the
# upstream build sets it for Java 8 compat but the module was removed
# in Java 11+). Done via a local-only overlay sbt file because
# Windows shell quoting mangles the `set Test/javaOptions := ...`
# command if passed as a CLI arg.
OVERLAY_FILE="$ERGO_REFERENCE_PATH/oracle-overlay.sbt"
cat > "$OVERLAY_FILE" <<'EOF'
Test / javaOptions := Seq(
  "-Xms256m",
  "-Xmx2G",
  "-XX:+IgnoreUnrecognizedVMOptions"
)
Test / fork := true
EOF
trap 'rm -f "$STAGED_FILE" "$OVERLAY_FILE"' EXIT

INPUT_JSON="$VECTORS_DIR/prune-formula-vectors.json"
OUTPUT_JSON="$VECTORS_DIR/runtime-vectors.json"

# Convert to Windows-friendly paths for the JVM
INPUT_WIN="$(cygpath -w "$INPUT_JSON" 2>/dev/null || echo "$INPUT_JSON")"
OUTPUT_WIN="$(cygpath -w "$OUTPUT_JSON" 2>/dev/null || echo "$OUTPUT_JSON")"

cd "$ERGO_REFERENCE_PATH"
"$SBT_BIN" -Dsbt.log.noformat=true \
  "Test/runMain org.ergoplatform.nodeView.history.storage.modifierprocessors.PruneFormulaOracle $INPUT_WIN $OUTPUT_WIN"

echo "runtime-vectors.json written to $OUTPUT_JSON"
