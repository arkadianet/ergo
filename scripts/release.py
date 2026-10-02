#!/usr/bin/env python3
"""Resolve exact release tags; package and smoke-test archives on every release OS."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = (
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
)
TAG_PATTERN = re.compile(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?")
DOCS = ("operating.md", "configuration.md", "compatibility.md", "logging.md")


def validate_tag(tag, version):
    if not TAG_PATTERN.fullmatch(tag):
        raise ValueError("tag must be vMAJOR.MINOR.PATCH with an optional prerelease suffix")
    if tag[1:] != version:
        raise ValueError(f"tag {tag} does not match workspace version {version}")


def git(*args, root=ROOT):
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def resolve(tag, root=ROOT):
    version = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    validate_tag(tag, version)
    sha = git("rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}", root=root)
    if sha != git("rev-parse", "HEAD", root=root):
        raise ValueError("checkout does not match the requested tag's exact commit")
    return {"tag": tag, "sha": sha, "version": version}


def remote_tag_commit(output, tag):
    refs = dict(line.split()[::-1] for line in output.splitlines() if line.strip())
    commit = refs.get(f"refs/tags/{tag}^{{}}", refs.get(f"refs/tags/{tag}"))
    if commit is None or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("release tag is missing from origin")
    return commit


def verify_remote(tag, expected_sha):
    output = git("ls-remote", "origin", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}")
    if remote_tag_commit(output, tag) != expected_sha:
        raise ValueError("release tag moved after validation; refusing publication")


def configure_section(text, section, values):
    """Override scalar smoke settings while retaining the packaged config's other keys."""
    header = f"[{section}]"
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.strip() == header), None)
    replacement = [f"{key} = {value}" for key, value in values.items()]
    if start is None:
        return text.rstrip() + "\n\n" + header + "\n" + "\n".join(replacement) + "\n"
    end = next((i for i in range(start + 1, len(lines)) if lines[i].lstrip().startswith("[")), len(lines))
    retained = [line for line in lines[start + 1:end]
                if not any(re.match(rf"\s*{re.escape(key)}\s*=", line) for key in values)]
    return "\n".join(lines[:start + 1] + replacement + retained + lines[end:]) + "\n"


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def request_api(port, path, *, key=None):
    headers = {"api_key": key} if key is not None else {}
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers,
                                     method="POST" if key is not None else "GET")
    # A CI host's proxy configuration must not turn a loopback smoke into a network request.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=2) as response:
        body = response.read().decode()
        return body if key is not None else json.loads(body)


def smoke_node(binary, config_template, work):
    api_port = free_port()
    peer_port = free_port()
    key = secrets.token_hex(32)
    config = config_template.read_text()
    config = configure_section(config, "peers", {
        "known": f'["127.0.0.1:{peer_port}"]', "bind_addr": '""',
        "target_outbound": "1", "max_connections": "1", "max_inbound": "0",
        "allow_local": "true",
    })
    config = configure_section(config, "api", {
        "disabled": "false", "bind": f'"127.0.0.1:{api_port}"', "public_bind": "false",
        "peer_details.auto_download": "false", "peer_details.reverse_dns": "false",
    })
    config = configure_section(config, "api.security", {
        "api_key_hash": json.dumps(hashlib.blake2b(key.encode(), digest_size=32).hexdigest()),
    })
    config = configure_section(config, "store", {
        "cache_bytes": "1048576", "state_redb_cache_bytes": "1048576",
        "indexer_redb_cache_bytes": "1048576", "peers_redb_cache_bytes": "1048576",
    })
    config = configure_section(config, "mining", {"enabled": "false"})
    config_path = work / "smoke.toml"
    config_path.write_text(config)
    # Devnet has no public seeds. CLI precedence also tests the packaged config's
    # documented override path without creating state under the archive directory.
    command = [str(binary), "--config", str(config_path), "--network", "devnet",
               "--data-dir", str(work / "data")]
    for boot in ("fresh", "reopen"):
        log_path = work / f"{boot}.log"
        with log_path.open("wb") as log:
            process = subprocess.Popen(command, stdout=log, stderr=log,
                                       env={**os.environ, "RUST_LOG": "info"})
            try:
                deadline = time.monotonic() + 60
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(f"{boot} boot exited with {process.returncode}")
                    try:
                        info = request_api(api_port, "/info")
                        if not isinstance(info, dict):
                            raise RuntimeError("/info did not return a JSON object")
                        break
                    except (urllib.error.URLError, TimeoutError, OSError):
                        if time.monotonic() >= deadline:
                            raise RuntimeError(f"{boot} boot did not expose /info") from None
                        time.sleep(0.1)
                if request_api(api_port, "/node/shutdown", key=key) != "shutdown_requested":
                    raise RuntimeError("shutdown endpoint did not accept the request")
                code = process.wait(timeout=30)
                if code != 0:
                    raise RuntimeError(f"{boot} shutdown exited with {code}")
            except Exception as error:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
                raise RuntimeError(f"{error}\n{log_path.read_text(errors='replace')[-8000:]}") from error
    if not (work / "data" / "state.redb").is_file():
        raise RuntimeError("offline boot did not create its state database")


def checksum(path):
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    path.with_name(path.name + ".sha256").write_text(f"{digest}  {path.name}\n")
    return digest


def package(target, binaries, output, *, root=ROOT):
    if target not in TARGETS:
        raise ValueError("unsupported release target")
    output.mkdir(parents=True, exist_ok=True)
    version = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    manifest = {"target": target, "version": version, "sha": git("rev-parse", "HEAD", root=root), "sha256": {}}
    extension = ".exe" if target.endswith("windows-msvc") else ""
    with tempfile.TemporaryDirectory(prefix="ergo-release-") as directory:
        temp = Path(directory)
        for name in ("ergo-node", "ergo-wallet"):
            stage = temp / name
            stage.mkdir()
            shutil.copy2(binaries / (name + extension), stage / (name + extension))
            shutil.copy2(root / "docs/release-quickstart.md", stage / "README.md")
            for file in ("LICENSE-MIT", "LICENSE-APACHE", "CHANGELOG.md", "SECURITY.md", "ARCHITECTURE.md", "rust-toolchain.toml"):
                shutil.copy2(root / file, stage / file)
            (stage / "docs").mkdir()
            for doc in DOCS:
                content = (root / "docs" / doc).read_text()
                content = content.replace("../ergo-node/ergo-node.toml", "../config/ergo-node.toml")
                content = content.replace("../ergo-node/src/config/", "https://github.com/arkadianet/ergo/tree/main/ergo-node/src/config/")
                (stage / "docs" / doc).write_text(content)
            (stage / "config").mkdir()
            for config in ("ergo-node.toml", "ergo-node.toml.example"):
                shutil.copy2(root / "ergo-node" / config, stage / "config" / config)
            artifact = output / f"{name}-{target}{extension}"
            shutil.copy2(stage / (name + extension), artifact)
            archive = output / f"{name}-{target}{'.zip' if extension else '.tar.gz'}"
            if extension:
                with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
                    for file in sorted(stage.rglob("*")):
                        if file.is_file():
                            bundle.write(file, file.relative_to(stage))
            else:
                with tarfile.open(archive, "w:gz") as bundle:
                    for file in sorted(stage.iterdir()):
                        bundle.add(file, arcname=file.name)
            # Execute extracted artifacts, so missing archive contents and permissions
            # fail before any upload or publication.
            extracted = temp / f"{name}-extracted"
            extracted.mkdir()
            if extension:
                with zipfile.ZipFile(archive) as bundle:
                    bundle.extractall(extracted)
            else:
                with tarfile.open(archive) as bundle:
                    bundle.extractall(extracted, filter="data")
            binary = extracted / (name + extension)
            for flag in ("--help", "--version"):
                result = subprocess.run([str(binary), flag], check=True, capture_output=True, text=True, timeout=20)
                if flag == "--version" and result.stdout.strip() != f"{name} {version}":
                    raise RuntimeError(f"unexpected version: {result.stdout.strip()}")
            if name == "ergo-node":
                smoke_work = temp / "node-smoke"
                smoke_work.mkdir()
                smoke_node(binary, extracted / "config/ergo-node.toml", smoke_work)
            for path in (artifact, archive):
                manifest["sha256"][path.name] = checksum(path)
    (output / f"release-{target}.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"packaged {target}: version/help, extracted archive, offline boot/reopen/shutdown passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    resolve_parser = sub.add_parser("resolve")
    resolve_parser.add_argument("--tag", default=os.environ.get("RELEASE_TAG"))
    resolve_parser.add_argument("--github-output", action="store_true")
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--tag", default=os.environ.get("RELEASE_TAG"))
    verify_parser.add_argument("--sha", default=os.environ.get("RELEASE_SHA"))
    package_parser = sub.add_parser("package")
    package_parser.add_argument("--target", choices=TARGETS, required=True)
    package_parser.add_argument("--binaries", type=Path, required=True)
    package_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "resolve":
        result = resolve(args.tag)
        if args.github_output:
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
                for key, value in result.items():
                    print(f"{key}={value}", file=output)
        print(json.dumps(result))
    elif args.command == "verify":
        result = resolve(args.tag)
        if result["sha"] != args.sha:
            raise ValueError("publication checkout differs from validated commit")
        verify_remote(args.tag, args.sha)
    else:
        package(args.target, args.binaries.resolve(), args.output.resolve())


if __name__ == "__main__":
    main()
