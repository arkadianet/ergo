#!/usr/bin/env bash
# One sbt process; Python 3 reads ScalaTest summaries and sbt task wall times.
set -euo pipefail
if [[ $# != 3 ]]; then
  echo 'usage: scala-gate.sh <scala-worktree> <sbt-project> "<testOnly patterns>"' >&2
  exit 1
fi
export SIGMASTATE_VERSION=6.0.5-22-368a860b-SNAPSHOT
exec python3 - "$@" <<'PY'
import os
import re
import subprocess
import sys
import time

worktree, project, patterns = sys.argv[1:]
# Allow test selectors, not extra sbt commands or ScalaTest runner options.
if (not os.path.isfile(os.path.join(worktree, "build.sbt"))
        or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", project)
        or not patterns.split()
        or any(not re.fullmatch(r"[A-Za-z0-9_.$*?]+", p) for p in patterns.split())):
    print("gate: invalid worktree, project ID, or test patterns", file=sys.stderr)
    sys.exit(1)
commands = ["sbt", "-batch", "++2.12.20", f"{project}/compile",
            f"{project}/Test/testOnly {patterns}", "++2.13.18",
            f"{project}/compile", f"{project}/Test/testOnly {patterns}"]
env = os.environ.copy()
env["JDK_JAVA_OPTIONS"] = (env.get("JDK_JAVA_OPTIONS", "")
                           + " -Dsbt.log.noformat=true -Dsbt.supershell=false -Dsbt.server.autostart=false")
started = time.monotonic()
times = []
counts = [0, 0]
versions = set()
errors = []
ansi = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
try:
    proc = subprocess.Popen(commands, cwd=worktree, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, errors="replace")
    for raw in proc.stdout:
        print(raw, end="", flush=True)
        line = ansi.sub("", raw).strip()
        version = re.search(r"Setting Scala version to (2\.(?:12\.20|13\.18))\b", line)
        if version:
            versions.add(version.group(1))
            expected = "2.12.20" if len(times) < 2 else "2.13.18"
            if version.group(1) != expected:
                errors.append("unexpected Scala switch order")
        summary = re.search(r"Tests: succeeded (\d+), failed (\d+)", line)
        if summary:
            phase = len(times)
            if phase not in (1, 3):
                errors.append("test summary outside expected test task")
            else:
                counts[phase // 2] += int(summary.group(1))
            if int(summary.group(2)):
                errors.append("failed tests")
        if re.search(r"Suites:.*aborted [1-9]\d*", line) or "*** FAILED ***" in line or "*** ABORTED ***" in line:
            errors.append("failed test or aborted suite")
        if line.startswith("[error]"):
            errors.append(line)
        elapsed = re.match(r"\[success\] Total time: (\d+) s\b", line)
        if elapsed:
            expected = "2.12.20" if len(times) < 2 else "2.13.18"
            if expected not in versions:
                errors.append("missing Scala version confirmation")
            times.append(int(elapsed.group(1)))
    status = proc.wait()
except OSError as exc:
    print(f"gate: cannot run sbt: {exc}", file=sys.stderr)
    sys.exit(1)
values = [str(t) for t in times[:4]] + ["n/a"] * max(0, 4 - len(times))
print(f"gate: 2.12 compile {values[0]}s tests {values[1]}s | "
      f"2.13 compile {values[2]}s tests {values[3]}s")
print(f"gate: succeeded 2.12={counts[0]} 2.13={counts[1]}; "
      f"wall={time.monotonic() - started:.2f}s; sbt exit={status}")
if status or errors or len(times) != 4 or not all(counts):
    print("gate: FAIL (requires four successful tasks and nonzero tests per version)", file=sys.stderr)
    for error in dict.fromkeys(errors):
        print(f"gate: {error}", file=sys.stderr)
    sys.exit(1)
PY
