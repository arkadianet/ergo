#!/usr/bin/env python3
"""Validate workspace test-target coverage and emit/run CI nextest commands."""

import argparse
from collections import Counter
import json
import shlex
import subprocess


# Run 35546223655: Windows build/test minutes were 2.7/3.1, 6.8/3.2,
# 8.5/1.9. Estimate 0.25 min per ordinary binary, 3 min per node lib/it,
# and 1.5 min job overhead. Test allocations below are estimates: the run
# measures whole groups, not individual targets. Four shards predict:
# 1: 3.8 build + 1.5 test + 1.6 clippy + 1.5 overhead = 8.4 min
# 2: 5.25 build + 1.8 test + 1.5 overhead = 8.55 min
# 3: 3.7 build + 3.4 test + 1.5 overhead = 8.6 min
# 4: 5.25 build + 1.5 test + 1.5 overhead = 8.25 min
# This beats the roughly 10 min three-shard budget. Unattributed build
# overhead and serial target invocations need warm-run controller validation.
# macOS: split node lib/it and distribute 20/26 default-feature test binaries.
# Scaling the measured 7.3 build minutes by these counts gives 3.2/4.1;
# estimated tests 1.0/0.9 + overhead 1.5 gives 5.7/6.5 min before clippy.
# Shard 1 takes clippy to use that 0.8 min headroom.
GROUPS = {
    "Windows": (
        # Measured on run 35547586766 (windows): the previous split ran
        # 4.3 / 5.7 / 7.3 / 11.5 min because ergo-api, ergo-indexer and
        # ergo-sync carry large `it` binaries. They move onto the two
        # node shards, which had the headroom.
        ("ergo-node --lib", "ergo-node --bin ergo-node", "ergo-api"),
        (
            "ergo-node --test it", "ergo-wallet", "ergo-wallet-service", "ergo-wallet-protocol",
            "ergo-difftest", "ergo-rest-json", "ergo-indexer", "ergo-sync",
        ),
        (
            "ergo-state", "ergo-chain-spec", "ergo-primitives", "ergo-indexer-types",
            "ergo-compiler", "ergo-sigma",
        ),
        # The last shard is the lightest and also runs the platform clippy.
        ("ergo-validation", "ergo-ser", "ergo-mempool", "ergo-crypto", "ergo-mining", "ergo-p2p"),
    ),
    "macOS": (
        (
            "ergo-node --lib", "ergo-node --bin ergo-node", "ergo-state",
            "ergo-chain-spec", "ergo-primitives", "ergo-indexer-types",
            "ergo-mining", "ergo-p2p", "ergo-sigma", "ergo-compiler",
            "ergo-wallet", "ergo-wallet-service", "ergo-wallet-protocol",
        ),
        (
            "ergo-node --test it", "ergo-indexer", "ergo-api", "ergo-sync", "ergo-validation",
            "ergo-ser", "ergo-difftest", "ergo-mempool", "ergo-crypto", "ergo-rest-json",
        ),
    ),
}


def test_targets(package):
    """Include feature-gated targets too, so new targets cannot escape a split."""
    targets = set()
    for target in package["targets"]:
        if not target["test"]:
            continue
        kinds = set(target["kind"])
        if kinds & {"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"}:
            targets.add(("--lib",))
        else:
            kind = next((k for k in ("bin", "test", "example", "bench") if k in kinds), None)
            if kind is None:
                raise ValueError(f"unsupported test target: {target}")
            targets.add((f"--{kind}", target["name"]))
    return targets


def validate_groups(groups, members):
    """Require every member and every test target exactly once."""
    counts = Counter()
    whole_packages = Counter()
    seen = set()
    for group in groups:
        if not group:
            raise ValueError("empty crate group")
        for entry in group:
            package, *selector = shlex.split(entry)
            if package not in members:
                raise ValueError(f"unknown workspace member: {package}")
            seen.add(package)
            targets = members[package]
            if selector:
                if tuple(selector) not in targets:
                    raise ValueError(f"unknown test target: {entry}")
                counts[(package, tuple(selector))] += 1
            else:
                whole_packages[package] += 1
                counts.update((package, target) for target in targets)
    expected = {(package, target) for package, targets in members.items() for target in targets}
    missing = sorted(expected - counts.keys())
    duplicates = sorted(key for key, count in counts.items() if count != 1)
    if missing or duplicates or seen != members.keys() or any(n != 1 for n in whole_packages.values()):
        raise ValueError(f"invalid coverage: missing={missing}, duplicates={duplicates}, "
                         f"missing_members={sorted(members.keys() - seen)}")


def nextest_commands(group, platform):
    """Target selectors are invocation-wide; isolate them from whole crates."""
    packages = []
    selectors = {}
    for entry in group:
        package, *selector = shlex.split(entry)
        if selector:
            selectors.setdefault(package, []).extend(selector)
        else:
            packages.extend(("-p", package))
    selections = ([packages] if packages else []) + [
        ["-p", package, *selection] for package, selection in selectors.items()
    ]
    threads = ["--test-threads", "8"] if platform == "Windows" else []
    return [["cargo", "nextest", "run", *selection, *threads] for selection in selections]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--os", choices=GROUPS, required=True)
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--shards", type=int, required=True)
    parser.add_argument("--run", action="store_true", help="execute the validated commands serially")
    args = parser.parse_args()
    groups = GROUPS[args.os]
    if args.shards != len(groups) or not 1 <= args.shard <= len(groups):
        parser.error("matrix shard count/index does not match configured crate groups")
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"], text=True,
    ))
    member_ids = set(metadata["workspace_members"])
    members = {p["name"]: test_targets(p) for p in metadata["packages"] if p["id"] in member_ids}
    for platform_groups in GROUPS.values():
        validate_groups(platform_groups, members)
    print(f"{args.os} shard {args.shard}/{args.shards}: exact workspace target coverage", flush=True)
    for command in nextest_commands(groups[args.shard - 1], args.os):
        print(shlex.join(command), flush=True)
        if args.run:
            subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
