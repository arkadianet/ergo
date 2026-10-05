#!/usr/bin/env python3
"""Repeat archival IndexerTask runs, retaining samples and checking every table.

Build the Linux ignored tests with --profile release-prof first. All generated
files stay under target; the archive is opened only by redb::ReadOnlyDatabase.
"""

import argparse
import json
import hashlib
from pathlib import Path
import statistics
import subprocess
import os

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "target"
REPLAY = "task::task_mainnet_bench::benchmark_archival_catchup"
COMPARE = "task::task_mainnet_bench::archival_indexes_are_identical"


def invoke(executable, test, environment, log):
    with log.open("w") as output:
        subprocess.run(
            [str(executable), "--exact", test, "--ignored", "--nocapture", "--test-threads=1"],
            env={**os.environ, **environment}, stdout=output, stderr=subprocess.STDOUT, check=True,
            cwd=ROOT,
        )
    return log.read_text()


def parse_sample(output):
    records = [line.partition("BENCH ")[2] for line in output.splitlines() if "BENCH " in line]
    if len(records) != 1:
        raise ValueError("expected exactly one BENCH record")
    sample = json.loads(records[0])
    for phase in ["load", "apply", "commit"]:
        prefix = f"{phase.upper()}_SECONDS "
        values = [line.partition(prefix)[2] for line in output.splitlines() if prefix in line]
        if len(values) != 1:
            raise ValueError(f"expected exactly one {phase} timing")
        sample[f"{phase}_seconds"] = float(values[0])
    return sample


def copy_base(base, index):
    subprocess.run(["cp", "--reflink=auto", "--sparse=always", str(base), str(index)], check=True)
    # Keep dirty copy pages out of the first timed Immediate commit.
    with index.open("rb") as copied:
        os.fsync(copied.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--compare-executable", type=Path)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--base", type=Path)
    parser.add_argument("--end", type=int, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--modes", nargs="+", choices=["single", "legacy", "adaptive", "prefetch"], default=["legacy", "adaptive", "prefetch"])
    args = parser.parse_args()
    if not args.name or args.name in {".", ".."} or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for c in args.name):
        parser.error("name must be a single directory name")
    if args.rounds < 3:
        parser.error("use at least three measured rounds")
    if not args.state.parent.joinpath("READY").is_file():
        parser.error("archive READY marker is absent")
    if args.base and not args.base.resolve().is_relative_to(TARGET.resolve()):
        parser.error("base must be inside this worktree's target")
    directory = TARGET / "indexer-bench" / args.name
    directory.mkdir(parents=True, exist_ok=False)
    directory = directory.resolve()
    if not directory.is_relative_to(TARGET.resolve()):
        parser.error("output must be inside target")
    environment = {"INDEXER_BENCH_STATE": str(args.state.resolve()), "INDEXER_BENCH_END": str(args.end)}
    with args.executable.open("rb") as executable:
        executable_hash = hashlib.file_digest(executable, "sha256").hexdigest()
    compare_executable = args.compare_executable or args.executable
    with compare_executable.open("rb") as executable:
        comparison_hash = hashlib.file_digest(executable, "sha256").hexdigest()
    metadata = {
        "comparison_executable_sha256": comparison_hash,
        "executable_sha256": executable_hash,
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "state": str(args.state.resolve()),
        "base": str(args.base.resolve()) if args.base else None,
        "end": args.end,
        "rounds": args.rounds,
        "modes": args.modes,
    }
    (directory / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    samples = []
    for iteration in range(args.rounds + 1):
        # Rotate order to reduce bias from concurrent builds and cache warmth.
        offset = (iteration * max(1, len(args.modes) // 3)) % len(args.modes)
        modes = args.modes[offset:] + args.modes[:offset]
        for mode in modes:
            index = directory / f"{mode}.redb"
            index.unlink(missing_ok=True)
            if args.base:
                copy_base(args.base, index)
            log = directory / f"{iteration}-{mode}.log"
            output = invoke(args.executable, REPLAY, {**environment, "INDEXER_BENCH_INDEX": str(index), "INDEXER_BENCH_MODE": mode}, log)
            sample = parse_sample(output)
            sample["iteration"] = iteration
            print(json.dumps(sample), flush=True)
            if iteration:
                samples.append(sample)
            (directory / "samples.json").write_text(json.dumps(samples, indent=2) + "\n")
    reference = directory / f"{args.modes[0]}.redb"
    for mode in args.modes[1:]:
        invoke(args.compare_executable or args.executable, COMPARE, {"INDEXER_BENCH_INDEX": str(directory / f"{mode}.redb"), "INDEXER_BENCH_REFERENCE": str(reference)}, directory / f"equivalence-{mode}.log")
    summary = {}
    for mode in args.modes:
        rows = [row for row in samples if row["mode"] == mode]
        summary[mode] = {
            key: {"median": statistics.median(row[key] for row in rows),
                  "min": min(row[key] for row in rows), "max": max(row[key] for row in rows)}
            for key in ["blocks_per_second", "seconds", "commits", "file_bytes", "write_bytes", "cpu_seconds", "load_seconds", "apply_seconds", "commit_seconds"]
        }
    (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
