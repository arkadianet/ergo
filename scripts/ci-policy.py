#!/usr/bin/env python3
"""Check shared compiler/lint/action policy and emit CI tool versions (Python 3.11+)."""

import argparse
import os
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[1]
CARGO_COMMAND = r"\bcargo\s+(?:\+(?:\$\{\{.*?\}\}|\S+)\s+)?"


def read_versions(root=ROOT):
    toolchain = tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"]
    config = tomllib.loads((root / ".github/ci-tools.toml").read_text())
    versions = config["tools"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", toolchain["channel"]):
        raise ValueError("stable Rust must name an exact release")
    if any(not re.fullmatch(r"\d+\.\d+\.\d+", v) for v in versions.values()):
        raise ValueError("Cargo tools must name exact releases")
    nightly = config["toolchains"]["fuzz"]
    if not re.fullmatch(r"nightly-\d{4}-\d{2}-\d{2}", nightly):
        raise ValueError("fuzz Rust must name an exact nightly date")
    return {"channel": toolchain["channel"], "nightly": nightly, **versions}


def check_policy(root=ROOT):
    versions = read_versions(root)
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    workspace = manifest["workspace"]
    fuzz_manifest = root / "ergo-difftest/fuzz/Cargo.toml"
    if fuzz_manifest.exists() and not fuzz_manifest.with_name("Cargo.lock").is_file():
        raise ValueError("the separate fuzz workspace requires its own committed Cargo.lock")
    if workspace["package"].get("rust-version") != versions["channel"]:
        raise ValueError("workspace rust-version must match rust-toolchain.toml")
    for member in workspace["members"]:
        package = tomllib.loads((root / member / "Cargo.toml").read_text())
        if package["package"].get("rust-version") != {"workspace": True}:
            raise ValueError(f"{member} must inherit rust-version")
        if package.get("lints") != {"workspace": True}:
            raise ValueError(f"{member} must inherit workspace lints")
    paths = list((root / ".github/workflows").glob("*.yml"))
    paths += list((root / ".github/actions").glob("*/action.yml"))
    for path in paths:
        text = path.read_text()
        for action in re.findall(r"\buses:\s*([^\s#]+)", text):
            if action.startswith("./"):
                continue
            if not re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", action):
                raise ValueError(f"{path.relative_to(root)}: action must use full commit: {action}")
        if re.search(r"toolchain:\s*\d+\.\d+", text):
            raise ValueError(f"{path.relative_to(root)} duplicates stable Rust version")
        for line in text.splitlines():
            if line.lstrip().startswith("#") or line.strip().startswith("- name:"):
                continue
            if re.search(CARGO_COMMAND + r"fuzz\s+(?:run|build)\b", line):
                if "--locked" in line.split(" -- ", 1)[0]:
                    raise ValueError(f"{path.relative_to(root)}: cargo-fuzz has no --locked option; use locked metadata and a drift check")
            if re.search(CARGO_COMMAND + r"(?:build|check|clippy|doc|test|run|metadata|nextest\s+run)\b", line):
                if "--locked" not in line:
                    raise ValueError(f"{path.relative_to(root)}: missing --locked: {line.strip()}")
            if re.search(r"\bcargo\s+install\s+cargo-(?:audit|deny|machete|fuzz)\b", line):
                if "--version" not in line or "--locked" not in line:
                    raise ValueError(f"{path.relative_to(root)}: tool install needs --version and --locked")
    return versions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-output", action="store_true")
    args = parser.parse_args()
    if args.github_output:
        versions = read_versions()
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            for key, value in versions.items():
                print(f"{key}={value}", file=output)
    else:
        check_policy()
        print("compiler requirements, workspace lints, action pins and locked Cargo commands agree")


if __name__ == "__main__":
    main()
