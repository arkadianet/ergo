#!/usr/bin/env python3
"""Fail when the portable wallet's normal dependency graph acquires host services."""
import subprocess

forbidden = {"clap", "rpassword", "md5", "uuid", "tempfile", "redb", "tokio", "tracing-subscriber", "ergo-validation", "ergo-state", "ergo-api", "ergo-node"}
output = subprocess.check_output(
    ["cargo", "tree", "--locked", "-p", "ergo-wallet", "--no-default-features", "--edges", "normal", "--prefix", "none", "--format", "{p}"], text=True
)
found = {row.split()[0] for row in output.splitlines() if row.split()} & forbidden
if found:
    raise SystemExit("portable wallet acquired host dependencies: " + ", ".join(sorted(found)))
print("portable wallet dependency boundary passed")
