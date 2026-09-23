#!/usr/bin/env bash
# Build the Matrix (input blocks) integration branch `matrix-fixes-all`:
# `matrix-fixes-base` plus every PR-tier patch branch, merged in a fixed
# order. A conflict aborts the merge and fails the script; the branches are
# never hand-edited here. The F03/F10 sketch is not a patch and is not merged.
#
# usage: integrate.sh [<scala-repo>] [<integration-worktree>]
set -euo pipefail

REPO=${1:-$HOME/coding/development/arkadianet/ergo-scala}
WT=${2:-$HOME/coding/development/arkadianet/ergo-scala-wt-all}
BASE=matrix-fixes-base
TARGET=matrix-fixes-all
# Order is load-bearing only where two patches touch the same file; it is
# the plan's order (spec §3) so the result is reproducible.
BRANCHES=(
  matrix/F01-threshold-doc
  matrix/F16-input-block-routes
  matrix/F12-F05-reconstruction
  matrix/F14-waitlist-graph-walk
  matrix/F13-pending-root-announcements
  matrix/F04-announcement-binding
  matrix/F11-candidate-retained-work
)
TRAILERS=${INTEGRATE_TRAILERS:-}

git -C "$REPO" rev-parse --verify --quiet "$BASE^{commit}" >/dev/null \
  || { echo "integrate: $BASE not found in $REPO" >&2; exit 1; }
for b in "${BRANCHES[@]}"; do
  git -C "$REPO" rev-parse --verify --quiet "$b^{commit}" >/dev/null \
    || { echo "integrate: $b not found in $REPO" >&2; exit 1; }
done

if [[ -d "$WT" ]]; then
  [[ "$(git -C "$WT" rev-parse --abbrev-ref HEAD)" == "$TARGET" ]] \
    || { echo "integrate: $WT is not on $TARGET" >&2; exit 1; }
  # Refuse to discard work: only tracked changes count (build output is untracked).
  if [[ -n "$(git -C "$WT" status --porcelain --untracked-files=no)" ]]; then
    echo "integrate: $WT has uncommitted tracked changes" >&2
    exit 1
  fi
  git -C "$WT" reset --quiet --hard "$BASE"
else
  git -C "$REPO" worktree add -B "$TARGET" "$WT" "$BASE"
fi

for b in "${BRANCHES[@]}"; do
  msg="Merge $b into $TARGET"
  [[ -n "$TRAILERS" ]] && msg+=$'\n\n'"$TRAILERS"
  if ! git -C "$WT" merge --no-ff --no-edit -m "$msg" "$b"; then
    echo "integrate: CONFLICT merging $b:" >&2
    git -C "$WT" diff --name-only --diff-filter=U >&2 || true
    git -C "$WT" merge --abort || true
    exit 1
  fi
  echo "integrate: merged $b @ $(git -C "$REPO" rev-parse --short=9 "$b")"
done
echo "integrate: $TARGET @ $(git -C "$WT" rev-parse HEAD) (base $(git -C "$REPO" rev-parse --short=9 "$BASE"))"
