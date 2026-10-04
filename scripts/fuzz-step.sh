#!/usr/bin/env bash
# Capture one scheduled command's exact argv, exit and transcript. No eval.
set -euo pipefail
if [[ $# -lt 3 ]]; then
  echo 'usage: fuzz-step.sh <fresh evidence bundle> <phase> <command> [args...]' >&2
  exit 2
fi
bundle=$1
phase=$2
shift 2
case "$phase" in
  locked-precheck|build|run|locked-postcheck) ;;
  *) echo "unsupported evidence phase: $phase" >&2; exit 2 ;;
esac
repo_root=$(git rev-parse --show-toplevel)
mkdir -p "$bundle/transcripts"
log="$bundle/transcripts/$phase.log"
if [[ -e "$log" ]]; then
  echo "transcript exists; refusing overwrite: $log" >&2
  exit 2
fi
set +e
"$@" 2>&1 | tee "$log"
statuses=("${PIPESTATUS[@]}")
set -e
python3 "$repo_root/scripts/fuzz-evidence.py" record --out "$bundle" \
  --phase "$phase" --exit-code "${statuses[0]}" --logger-exit-code "${statuses[1]}" \
  --log "$log" -- "$@"
if [[ ${statuses[0]} -ne 0 ]]; then
  exit "${statuses[0]}"
fi
exit "${statuses[1]}"
