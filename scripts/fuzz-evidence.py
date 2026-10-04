#!/usr/bin/env python3
"""Preserve scheduled fuzz command evidence; this collector does not run a campaign.

Only `start` queries tool versions. Recorded exit codes describe CI commands, not
an independently verified Bug/crash/export chain or signed build attestation.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import time
import tomllib

PHASES = ("locked-precheck", "build", "run", "locked-postcheck")
ENVIRONMENT = ("ASAN_OPTIONS", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_JOBS",
               "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def fingerprint(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular file: {path}")
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": digest(data)}


def inventory(directory, copy_to=None):
    """Read every regular file in stable relative-path order, preserving bytes."""
    if not directory.exists():
        return []
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError(f"expected regular directory: {directory}")
    rows = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"symlink is not evidence: {path}")
        if path.is_file():
            relative = path.relative_to(directory).as_posix()
            row = {"path": relative, **fingerprint(path)}
            if copy_to is not None:
                destination = copy_to / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
                if fingerprint(destination) != {key: row[key] for key in ("bytes", "sha256")}:
                    raise ValueError(f"file changed while copying: {path}")
            rows.append(row)
    return rows


def query(command, cwd):
    try:
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                                timeout=30, check=False)
        return {"argv": command, "exit_code": result.returncode,
                "stdout": result.stdout, "stderr": result.stderr}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"argv": command, "exit_code": None, "error": str(error)}


def git_state(root):
    revision = query(["git", "rev-parse", "HEAD"], root)
    dirty = query(["git", "status", "--porcelain"], root)
    return {"revision": revision, "dirty": dirty}


def source_inventory(root, copy_to=None):
    result = subprocess.run(["git", "ls-files", "-z", "--cached", "--others",
                             "--exclude-standard"], cwd=root, capture_output=True, check=True)
    paths = sorted(set(os.fsdecode(value) for value in result.stdout.split(b"\0") if value))
    rows = []
    for relative in paths:
        # Mutable campaign inputs have their own initial/final inventories.
        if relative.startswith("ergo-difftest/fuzz/corpus/"):
            continue
        path = root / relative
        row = {"path": relative, **fingerprint(path)}
        if copy_to and (path.suffix in (".rs", ".py", ".sh", ".toml", ".lock")
                        or path.name == "Cargo.lock"):
            destination = copy_to / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
            if fingerprint(destination) != {key: row[key] for key in ("bytes", "sha256")}:
                raise ValueError(f"source changed while copying: {path}")
        rows.append(row)
    return {"files": rows, "inventory_sha256": digest(canonical(rows))}


def binaries(build_directory, target):
    paths = sorted(build_directory.glob(f"**/release/{target}"))
    return [{"path": str(path), **fingerprint(path)} for path in paths]


def tool_identity(command, cwd):
    executable = shutil.which(command[0])
    return {"version": query(command, cwd), "executable": str(executable) if executable else None,
            "executable_identity": fingerprint(Path(executable).resolve()) if executable else None}


def rustc_identity(toolchain, root):
    command = ["rustup", "run", toolchain, "rustc"]
    identity = tool_identity(command + ["-vV"], root)
    sysroot = query(command + ["--print", "sysroot"], root)
    identity["sysroot"] = sysroot
    binary = Path(sysroot.get("stdout", "").strip()) / "bin/rustc"
    identity["selected_compiler_identity"] = fingerprint(binary) if sysroot.get("exit_code") == 0 and binary.is_file() else None
    return identity


def start(root, output, target, toolchain, build_directory):
    if output.exists():
        raise ValueError("evidence output must be fresh; previous runs are never cleared")
    output.mkdir(parents=True)
    source = source_inventory(root, output / "source")
    pins = tomllib.loads((root / ".github/ci-tools.toml").read_text())
    metadata = {"schema": 1, "target": target, "toolchain_requested": toolchain,
                "root": str(root), "build_directory": str(build_directory),
                "requested_pins": {"cargo_fuzz": pins["tools"]["fuzz"], "nightly": pins["toolchains"]["fuzz"]},
                "started_unix": time.time(), "host": platform.platform(),
                "git_start": git_state(root), "source_start": source,
                "environment": {name: os.environ.get(name) for name in ENVIRONMENT},
                "tools": {"cargo_fuzz": tool_identity(["cargo-fuzz", "--version"], root),
                          "rustc": rustc_identity(toolchain, root)},
                "instrumentation_requested": "cargo-fuzz --sanitizer address; symbol/runtime certification separate",
                "initial_seeds": inventory(root / "ergo-difftest/fuzz/corpus" / target,
                                           output / "initial-seeds"),
                "locks_start": {str(path.relative_to(root)): fingerprint(path)
                                for path in (root / "Cargo.lock", root / "ergo-difftest/fuzz/Cargo.lock")},
                "phases": {}, "scope": "captured command evidence; no independent Bug/artifact/replay/upload proof"}
    save(output / "metadata.json", metadata)


def record(output, phase, code, log, argv, logger_code=0):
    metadata_path = output / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    if phase in metadata["phases"]:
        raise ValueError(f"phase already recorded: {phase}")
    destination = output / "logs" / (phase + ".log")
    destination.parent.mkdir(exist_ok=True)
    shutil.copyfile(log, destination)
    metadata["phases"][phase] = {"argv": argv, "exit_code": code,
                                 "log": str(destination.relative_to(output)), "logger_exit_code": logger_code, **fingerprint(destination),
                                 "recorded_unix": time.time(),
                                 "environment": {name: os.environ.get(name) for name in ENVIRONMENT}}
    if phase in ("build", "run"):
        metadata["phases"][phase]["binaries"] = binaries(Path(metadata["build_directory"]), metadata["target"])
    save(metadata_path, metadata)


def assessment(metadata):
    missing = [phase for phase in PHASES if phase not in metadata["phases"]]
    failed = [phase for phase, value in metadata["phases"].items() if value["exit_code"] != 0 or value.get("logger_exit_code", 0) != 0]
    tools = metadata.get("tools", {})
    version = tools.get("cargo_fuzz", {}).get("version", {}).get("stdout", "").strip()
    pins_match = (version == "cargo-fuzz " + metadata.get("requested_pins", {}).get("cargo_fuzz", "")
                  and bool(metadata.get("toolchain_requested"))
                  and metadata["toolchain_requested"] == metadata.get("requested_pins", {}).get("nightly"))
    tools_known = (set(tools) == {"cargo_fuzz", "rustc"}
                   and all(value["version"].get("exit_code") == 0 and value.get("executable_identity") for value in tools.values())
                   and bool(tools["rustc"].get("selected_compiler_identity")) and pins_match)
    source_same = bool(metadata.get("source_start", {}).get("inventory_sha256")) and metadata["source_start"]["inventory_sha256"] == metadata.get("source_end", {}).get("inventory_sha256")
    lock_same = (set(metadata.get("locks_start", {})) == {"Cargo.lock", "ergo-difftest/fuzz/Cargo.lock"}
                 and metadata["locks_start"] == metadata.get("locks_end"))
    built = metadata["phases"].get("build", {}).get("binaries", [])
    ran = metadata["phases"].get("run", {}).get("binaries", [])
    binary_same = len(built) == 1 and built == ran
    complete = not missing and not failed and tools_known and source_same and lock_same and binary_same
    return {"status": "COMMANDS_COMPLETED" if complete else "INCOMPLETE_OR_FAILED",
            "missing_phases": missing, "nonzero_phases": failed, "tools_known": tools_known,
            "tool_pins_match": pins_match,
            "source_unchanged": source_same, "locks_unchanged": lock_same,
            "single_binary_unchanged": binary_same,
            "limits": "Exit/log/static identities are recorded. No independently certified detector, native Bug-to-artifact, replay or upload chain."}


def finish(root, output, target):
    path = output / "metadata.json"
    if not path.exists():
        # An earlier CI prerequisite or start failed. Preserve an explicit gap.
        output.mkdir(parents=True, exist_ok=True)
        save(path, {"schema": 1, "target": target, "phases": {}, "tools": {},
                    "start_error": "evidence start did not complete", "git_end": git_state(root),
                    "assessment": {"status": "NOT_RUN", "missing_phases": list(PHASES)}})
        return
    metadata = json.loads(path.read_text())
    if metadata["target"] != target:
        raise ValueError("target does not match initial evidence")
    metadata.update({"finished_unix": time.time(), "git_end": git_state(root),
                     "source_end": source_inventory(root),
                     "locks_end": {str(path.relative_to(root)): fingerprint(path)
                                   for path in (root / "Cargo.lock", root / "ergo-difftest/fuzz/Cargo.lock")},
                     "final_corpus": inventory(root / "ergo-difftest/fuzz/corpus" / target, output / "final-corpus"),
                     "artifacts": inventory(root / "ergo-difftest/fuzz/artifacts" / target, output / "artifacts")})
    metadata["assessment"] = assessment(metadata)
    save(path, metadata)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("start", "finish"):
        child = commands.add_parser(name)
        child.add_argument("--root", type=Path, required=True)
        child.add_argument("--out", type=Path, required=True)
        child.add_argument("--target", required=True)
        if name == "start":
            child.add_argument("--toolchain", required=True)
            child.add_argument("--build-directory", type=Path, required=True)
    child = commands.add_parser("record")
    child.add_argument("--out", type=Path, required=True)
    child.add_argument("--phase", choices=PHASES, required=True)
    child.add_argument("--exit-code", type=int, required=True)
    child.add_argument("--log", type=Path, required=True)
    child.add_argument("--logger-exit-code", type=int, default=0)
    child.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command in ("start", "finish") and not re.fullmatch(r"[a-z][a-z_0-9]*", args.target):
        parser.error("target must be a simple target name")
    if args.command == "start":
        start(args.root.resolve(), args.out.resolve(), args.target, args.toolchain,
              args.build_directory.resolve())
    elif args.command == "record":
        argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
        if not argv:
            parser.error("record requires command argv after --")
        record(args.out.resolve(), args.phase, args.exit_code, args.log, argv, args.logger_exit_code)
    else:
        finish(args.root.resolve(), args.out.resolve(), args.target)


if __name__ == "__main__":
    main()
