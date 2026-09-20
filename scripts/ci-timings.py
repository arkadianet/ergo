#!/usr/bin/env python3
"""Report CI job/step minutes and nextest PASS/FAIL seconds (requires gh auth).

Controller examples:
  python3 scripts/ci-timings.py 35522674758
  python3 scripts/ci-timings.py --last 24 --branch main --json baseline.json
  python3 scripts/ci-timings.py RUN_ID --baseline baseline.json
The supplied .superpowers/sdd/ci-speed/baseline-timings.json also works as a
baseline. Compare warm branch runs against baseline medians: environment/cache
key changes require a cold rebuild, so never judge them from a single run.
Windows shard jobs are reported separately; their maximum, not their sum,
approximates the Windows critical path (excluding queueing). Each job's slowest
steps and tests are printed. --json preserves all samples, including tests.
Only the controller should execute GitHub reads in the CI speed program.
"""

import argparse
from datetime import datetime
import json
import re
import statistics
import subprocess
import sys


ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
TEST = re.compile(r"\b(PASS|FAIL)\s+\[\s*([0-9.]+)s\]\s+(?:\(\d+/\d+\)\s+)?(.+?)\s*$")


def gh(*args):
    result = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(f"gh {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


def api_pages(endpoint, key):
    pages = json.loads(gh("api", "--paginate", "--slurp", endpoint))
    return [item for page in pages for item in page[key]]


def minutes(item):
    start, end = item.get("started_at"), item.get("completed_at")
    if not start or not end:
        return None
    return (datetime.fromisoformat(end.replace("Z", "+00:00"))
            - datetime.fromisoformat(start.replace("Z", "+00:00"))).total_seconds() / 60


def parse_tests(log):
    tests = []
    for line in ANSI.sub("", log).splitlines():
        match = TEST.search(line)
        if match:
            status, seconds, name = match.groups()
            tests.append({"status": status, "seconds": float(seconds), "name": name})
    return tests


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run_id", nargs="?", type=positive)
    parser.add_argument("--last", type=positive, help="last N successful workflow runs")
    parser.add_argument("--repo", help="OWNER/REPO; defaults to this checkout")
    parser.add_argument("--workflow", default="ci.yml")
    parser.add_argument("--branch", help="branch filter for --last")
    parser.add_argument("--top", type=positive, default=10)
    parser.add_argument("--baseline", help="compare against job/step median minutes in JSON")
    parser.add_argument("--json", dest="json_path", help="write sample data for later comparisons")
    args = parser.parse_args()
    if (args.run_id is None) == (args.last is None):
        parser.error("provide either a run id or --last N")
    if args.branch and not args.last:
        parser.error("--branch requires --last")
    repo = args.repo or json.loads(gh("repo", "view", "--json", "nameWithOwner"))["nameWithOwner"]
    baseline = {"jobs": {}, "steps": {}}
    if args.baseline:
        with open(args.baseline, encoding="utf-8") as source:
            baseline = json.load(source)
    if args.run_id:
        run_ids = [args.run_id]
    else:
        command = ["run", "list", "--repo", repo, "--workflow", args.workflow,
                   "--status", "success", "--limit", str(args.last), "--json", "databaseId"]
        if args.branch:
            command += ["--branch", args.branch]
        run_ids = [run["databaseId"] for run in json.loads(gh(*command))]
        if not run_ids:
            raise RuntimeError("no successful runs matched")
    samples = {"jobs": {}, "steps": {}, "runs": []}
    for run_id in run_ids:
        jobs = api_pages(f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100", "jobs")
        run = {"id": run_id, "jobs": []}
        print(f"Run {run_id}")
        for job in jobs:
            name = job["name"]
            duration = minutes(job)
            if duration is not None:
                samples["jobs"].setdefault(name, []).append(duration)
            label = f"{duration:.2f} min" if duration is not None else "incomplete"
            print(f"  {name}: {label} ({job.get('conclusion') or job['status']})")
            steps = []
            for step in job.get("steps", []):
                elapsed = minutes(step)
                if elapsed is not None:
                    steps.append((elapsed, step["name"]))
                    samples["steps"].setdefault(f"{name} | {step['name']}", []).append(elapsed)
            for elapsed, step_name in sorted(steps, reverse=True)[:args.top]:
                print(f"    step {elapsed:8.2f} min  {step_name}")
            # Fetch only completed, non-skipped jobs: queued jobs have no logs.
            tests = []
            if job["status"] == "completed" and job.get("conclusion") != "skipped":
                tests = parse_tests(gh("api", f"repos/{repo}/actions/jobs/{job['id']}/logs"))
            print(f"    parsed {len(tests)} nextest PASS/FAIL records; "
                  f"sum {sum(test['seconds'] for test in tests) / 60:.2f} min")
            for test in sorted(tests, key=lambda test: test["seconds"], reverse=True)[:args.top]:
                print(f"    test {test['seconds']:8.3f} s  {test['status']} {test['name']}")
            run["jobs"].append({"id": job["id"], "name": name, "minutes": duration, "tests": tests})
        samples["runs"].append(run)
    print("Median durations (minutes; delta versus baseline where available)")
    for kind in ("jobs", "steps"):
        entries = sorted(samples[kind].items(), key=lambda item: statistics.median(item[1]), reverse=True)
        # Show all job medians; step details above are per-job, this is global.
        for name, values in entries if kind == "jobs" else entries[:args.top]:
            median = statistics.median(values)
            previous = baseline.get(kind, {}).get(name, [])
            delta = f"; delta {median - statistics.median(previous):+.2f}" if previous else ""
            print(f"  {kind}: {name}: {median:.2f} (n={len(values)}{delta})")
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as output:
            json.dump(samples, output, indent=2)
            output.write("\n")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
