#!/usr/bin/env python3
"""Rustfmt-check literal include! fragments that cargo fmt does not discover."""

from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
members = manifest["workspace"]["members"]
edition = manifest["workspace"]["package"]["edition"]
paths = subprocess.check_output(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "*.rs"],
    cwd=ROOT,
).decode("utf-8").split("\0")
fragments = set()
for name in paths:
    if not any(name.startswith(member + "/") for member in members):
        continue
    source = ROOT / name
    for included in re.findall(r'\binclude!\s*\(\s*"([^"\\]+\.rs)"\s*\)', source.read_text(encoding="utf-8")):
        fragment = (source.parent / included).resolve()
        if not fragment.is_relative_to(ROOT) or not fragment.is_file():
            raise SystemExit(f"invalid Rust fragment: {name}: {included}")
        fragments.add(str(fragment))
if fragments:
    subprocess.run(["rustfmt", "--edition", edition, "--check", *sorted(fragments)], cwd=ROOT, check=True)
print(f"checked {len(fragments)} included Rust fragments")
