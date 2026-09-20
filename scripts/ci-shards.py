#!/usr/bin/env python3
"""Validate crate-group coverage and emit nextest package arguments for CI."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import subprocess


# Windows aggregate test-minutes: 18.9 / 16.9 / 15.4 (not shard wall time).
# macOS uses Windows timings as a balancing proxy: 25.3 / 25.9 minutes;
# actual macOS execution is faster and needs runner measurements.
GROUPS = {
    "Windows": (
        ("ergo-state", "ergo-chain-spec", "ergo-primitives", "ergo-indexer-types"),
        ("ergo-node", "ergo-mining", "ergo-p2p"),
        (
            "ergo-indexer", "ergo-api", "ergo-sync", "ergo-compiler",
            "ergo-sigma", "ergo-validation", "ergo-ser", "ergo-wallet",
            "ergo-difftest", "ergo-mempool", "ergo-crypto", "ergo-rest-json",
        ),
    ),
    "macOS": (
        (
            "ergo-state", "ergo-indexer", "ergo-compiler", "ergo-sigma",
            "ergo-chain-spec", "ergo-primitives", "ergo-indexer-types",
        ),
        (
            "ergo-node", "ergo-mining", "ergo-p2p", "ergo-api", "ergo-sync",
            "ergo-validation", "ergo-ser", "ergo-wallet", "ergo-difftest",
            "ergo-mempool", "ergo-crypto", "ergo-rest-json",
        ),
    ),
}


def validate_groups(groups, members):
    """Require every workspace member exactly once, with no stale names."""
    counts = Counter(package for group in groups for package in group)
    missing = sorted(members - counts.keys())
    extra = sorted(counts.keys() - members)
    duplicates = sorted(package for package, count in counts.items() if count != 1)
    if missing or extra or duplicates or any(not group for group in groups):
        raise ValueError(
            f"invalid crate groups: missing={missing}, extra={extra}, "
            f"duplicates={duplicates}, empty_groups={any(not group for group in groups)}"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--os", choices=GROUPS, required=True)
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--shards", type=int, required=True)
    args = parser.parse_args()
    groups = GROUPS[args.os]
    if args.shards != len(groups) or not 1 <= args.shard <= len(groups):
        parser.error("matrix shard count/index does not match configured crate groups")

    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"], text=True,
    ))
    member_ids = set(metadata["workspace_members"])
    members = {p["name"] for p in metadata["packages"] if p["id"] in member_ids}
    # Validate both platforms on every shard so neither assignment can drift.
    for platform_groups in GROUPS.values():
        validate_groups(platform_groups, members)

    packages = " ".join(f"-p {package}" for package in groups[args.shard - 1])
    print(f"{args.os} shard {args.shard}/{args.shards}: {packages}")
    if "GITHUB_OUTPUT" in os.environ:
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write(f"packages={packages}\n")


if __name__ == "__main__":
    main()
