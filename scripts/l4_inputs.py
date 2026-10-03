#!/usr/bin/env python3
"""Verify and repair the hash-pinned L4 captures, preserving unrelated fixtures."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent.parent
ARCHIVE_SHA256 = "8b51c4873ea953eafa26047aa6f5a7f7fe7a03b9354847b704e3948a1e93bad8"
TAG = "l4-inputs-2026-09-20"
MARKER = ".l4-inputs.sha256"


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def verified(directory, manifest):
    marker = directory / MARKER
    if not marker.is_file() or marker.read_text().strip() != manifest["archive_sha256"]:
        return False
    for name, expected in manifest["files"].items():
        path = directory / name
        if not path.is_file() or digest(path) != expected:
            return False
    return True


def install(archive, directory, manifest):
    if digest(archive) != manifest["archive_sha256"]:
        raise ValueError("L4 archive SHA-256 does not match the pinned manifest")
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".l4-staging-", dir=directory.parent) as temporary:
        staging = Path(temporary)
        with tarfile.open(archive, "r:gz") as bundle:
            members = bundle.getmembers()
            names = [member.name for member in members]
            if len(names) != len(set(names)) or set(names) != set(manifest["files"]):
                raise ValueError("L4 archive inventory does not match the pinned manifest")
            for member in members:
                if not member.isfile() or Path(member.name).name != member.name:
                    raise ValueError(f"invalid L4 archive member: {member.name}")
                with bundle.extractfile(member) as source, (staging / member.name).open("wb") as output:
                    shutil.copyfileobj(source, output)
                if digest(staging / member.name) != manifest["files"][member.name]:
                    raise ValueError(f"L4 capture SHA-256 mismatch: {member.name}")
        # Publish only after every member is verified. An interrupted publication
        # has no readiness marker and is repaired on the next invocation.
        (directory / MARKER).unlink(missing_ok=True)
        for name in names:
            (staging / name).replace(directory / name)
        marker = staging / MARKER
        marker.write_text(manifest["archive_sha256"] + "\n")
        marker.replace(directory / MARKER)


def main():
    manifest = json.loads((ROOT / "scripts/l4-inputs-manifest.json").read_text())
    if (manifest.get("schema") != 1 or manifest.get("archive_sha256") != ARCHIVE_SHA256
            or not isinstance(manifest.get("files"), dict) or len(manifest["files"]) != 1179):
        raise ValueError("unexpected L4 manifest version or archive pin")
    destination = ROOT / "test-vectors/mainnet"
    if verified(destination, manifest):
        print(f"L4 inputs verified ({len(manifest['files'])} captures, {ARCHIVE_SHA256})")
        return
    with tempfile.TemporaryDirectory(prefix="l4-download-") as temporary:
        archive = Path(temporary) / manifest["archive"]
        if shutil.which("gh"):
            subprocess.run(["gh", "release", "download", TAG, "--repo", "arkadianet/ergo",
                            "--pattern", manifest["archive"], "--dir", temporary], check=True)
        else:
            url = f"https://github.com/arkadianet/ergo/releases/download/{TAG}/{manifest['archive']}"
            with urlopen(url, timeout=60) as response, archive.open("wb") as output:
                shutil.copyfileobj(response, output)
        install(archive, destination, manifest)
    print(f"L4 inputs verified and installed ({len(manifest['files'])} captures)")


if __name__ == "__main__":
    main()
