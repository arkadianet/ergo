#!/usr/bin/env python3
"""Resolve exact release tags; package and smoke-test archives on every release OS."""

import argparse
import hashlib
import io
import gzip
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import secrets
import stat
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = (
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-gnu",
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
)
TAG_PATTERN = re.compile(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?")
DOCS = ("operating.md", "configuration.md", "compatibility.md", "logging.md", "operator-controls.md", "deployment.md", "operator-recovery.md")


def validate_tag(tag, version):
    if not TAG_PATTERN.fullmatch(tag):
        raise ValueError("tag must be vMAJOR.MINOR.PATCH with an optional prerelease suffix")
    if tag[1:] != version:
        raise ValueError(f"tag {tag} does not match workspace version {version}")


def git(*args, root=ROOT):
    return subprocess.check_output(["git", *args], cwd=root, text=True, encoding="utf-8").strip()


def resolve(tag, root=ROOT):
    version = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
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
        body = response.read().decode("utf-8")
        return body if key is not None else json.loads(body)


def smoke_node(binary, config_template, work):
    api_port = free_port()
    peer_port = free_port()
    key = secrets.token_hex(32)
    config = config_template.read_text(encoding="utf-8")
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
    config_path.write_text(config, encoding="utf-8")
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
                raise RuntimeError(f"{error}\n{log_path.read_text(encoding='utf-8', errors='replace')[-8000:]}") from error
    if not (work / "data" / "state.redb").is_file():
        raise RuntimeError("offline boot did not create its state database")


def checksum(path):
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return digest


def packaged_document(content, document, stage, source_sha, *, extension="", root=ROOT):
    """Adapt archive commands and keep omitted source references revision-pinned."""
    source_document = "docs/release-quickstart.md" if document == "README.md" else document
    if document == "docs/operating.md":
        quickstart = f"""## Quick start

Extract the combined archive into its own directory. Review the bundled
[`config/ergo-node.toml`](../config/ergo-node.toml) and the commented
[`config/ergo-node.toml.example`](../config/ergo-node.toml.example), then
copy the config, edit it and start the packaged binary. Keep the data
directory outside the extracted archive so upgrades do not replace it.

```sh
./ergo-node{extension} --version
./ergo-node{extension} --help
cp config/ergo-node.toml ./ergo-node.toml
./ergo-node{extension} --config ./ergo-node.toml --data-dir ../ergo-data
```

"""
        content, count = re.subn(r"## Quick start\n.*?(?=The config path is optional\.)",
                                lambda _: quickstart, content, count=1, flags=re.DOTALL)
        if count != 1:
            raise ValueError("operating quick start changed; update the archive adaptation")
        content = content.replace("in the README for the cargo one-shot form",
                                  "in the source README for the cargo one-shot form")
    elif document == "README.md":
        content = content.replace("./ergo-node --config", f"./ergo-node{extension} --config")
        content = content.replace("Use `ergo-wallet --help`", f"Use `./ergo-wallet{extension} --help`")
    content = content.replace("../ergo-node/ergo-node.toml", "../config/ergo-node.toml")

    def rewrite_link(match):
        if match.group("code") is not None:
            return match.group(0)
        link = urllib.parse.urlsplit(match.group("target"))
        if link.scheme or link.netloc or not link.path:
            return match.group(0)
        relative = PurePosixPath(posixpath.normpath(posixpath.join(
            str(PurePosixPath(source_document).parent), urllib.parse.unquote(link.path))))
        # The archive README is a quick start; source documents link to the
        # repository README's build/status sections, not that replacement.
        if relative.as_posix() != "README.md" and stage.joinpath(*relative.parts).exists():
            archive_path = posixpath.relpath(relative.as_posix(), str(PurePosixPath(document).parent))
            target = urllib.parse.urlunsplit(("", "", urllib.parse.quote(archive_path), link.query, link.fragment))
            return f"]({target})"
        source = root.joinpath(*relative.parts)
        if relative.is_absolute() or ".." in relative.parts or not source.exists():
            raise ValueError(f"{document}: missing source link target: {link.path}")
        kind = "tree" if source.is_dir() else "blob"
        path = f"/arkadianet/ergo/{kind}/{source_sha}/{urllib.parse.quote(relative.as_posix())}"
        if source.is_dir():
            path += "/"
        target = urllib.parse.urlunsplit(("https", "github.com", path, link.query, link.fragment))
        return f"]({target})"

    return re.sub(r"(?P<code>```.*?```|`[^`\n]*`)|\]\((?P<target>[^)\s]+)\)",
                  rewrite_link, content, flags=re.DOTALL)


SUPPORT_FILES = (
    "README.md", "LICENSE-MIT", "LICENSE-APACHE", "CHANGELOG.md", "SECURITY.md",
    "ARCHITECTURE.md", "rust-toolchain.toml", *(f"docs/{doc}" for doc in DOCS),
    "config/ergo-node.toml", "config/ergo-node.toml.example",
    "deploy/compose.yml", "deploy/ergo-node.service", "deploy/ergo-node.container.toml",
)
SMOKE_CHECKS = {"help": True, "versions": True, "devnet_boot_reopen_shutdown": True}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def read_json(stream):
    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    return json.load(stream, object_pairs_hook=unique_keys)


def archive_name(target):
    return f"ergo-{target}{'.zip' if target.endswith('windows-msvc') else '.tar.gz'}"


def executable_names(target):
    extension = ".exe" if target.endswith("windows-msvc") else ""
    return tuple(name + extension for name in ("ergo-node", "ergo-wallet"))


def validate_identity(info, tag, sha):
    if not isinstance(info, dict) or type(info.get("schema_version")) is not int or info["schema_version"] != 1:
        raise ValueError("unsupported release schema_version")
    if info.get("tag") != tag or info.get("sha") != sha or info.get("version") != tag[1:]:
        raise ValueError("release tag/version/sha mismatch")
    validate_tag(tag, info["version"])
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("invalid release sha")


def validate_target(info, target):
    if target not in TARGETS:
        raise ValueError("unsupported release target")
    if not isinstance(info, dict):
        raise ValueError("invalid target metadata")
    executables = info.get("executables")
    if not isinstance(executables, dict) or set(executables) != set(executable_names(target)):
        raise ValueError("expected both target executable names")
    for executable in executables.values():
        if (not isinstance(executable, dict) or set(executable) != {"sha256"}
                or not isinstance(executable["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", executable["sha256"])):
            raise ValueError("invalid executable sha256")
    if info.get("archive") != archive_name(target):
        raise ValueError("unexpected archive name")
    if type(info.get("size")) is not int or info["size"] <= 0:
        raise ValueError("invalid archive size")
    if not isinstance(info.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", info["sha256"]):
        raise ValueError("invalid archive sha256")


def validate_archive(path, info, target, identity):
    """Inspect members without extracting untrusted transport artifacts."""
    validate_target(info, target)
    if path.stat().st_size != info["size"] or checksum(path) != info["sha256"]:
        raise ValueError("archive size/sha256 mismatch")
    names = set()
    files = set()
    metadata = None

    def inspect(name, is_directory, mode, open_member):
        nonlocal metadata
        name = name.removesuffix("/") if is_directory else name
        parts = PurePosixPath(name)
        if (not name or parts.is_absolute()
                or any(part in ("", ".", "..") for part in name.split("/"))
                or "\\" in name or ":" in name or any(ord(char) < 32 for char in name)):
            raise ValueError(f"unsafe archive member: {name!r}")
        if name in names:
            raise ValueError(f"duplicate archive member: {name}")
        names.add(name)
        if is_directory:
            return
        files.add(name)
        if name in info["executables"]:
            if not target.endswith("windows-msvc") and mode & 0o111 != 0o111:
                raise ValueError(f"missing executable permissions: {name}")
            with open_member() as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != info["executables"][name]["sha256"]:
                    raise ValueError(f"executable sha256 mismatch: {name}")
        elif name == "release-info.json":
            with open_member() as stream:
                metadata = read_json(stream)

    if target.endswith("windows-msvc"):
        with zipfile.ZipFile(path) as bundle:
            for member in bundle.infolist():
                mode = member.external_attr >> 16
                if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ValueError("unsupported archive member type")
                inspect(member.filename, member.is_dir(), mode, lambda m=member: bundle.open(m))
    else:
        with tarfile.open(path, "r:gz") as bundle:
            for member in bundle:
                if not member.isfile() and not member.isdir():
                    raise ValueError("unsupported archive member type")
                inspect(member.name, member.isdir(), member.mode, lambda m=member: bundle.extractfile(m))
    required = set(SUPPORT_FILES) | set(executable_names(target)) | {"release-info.json"}
    if not required <= files:
        raise ValueError(f"missing archive contents: {sorted(required - files)}")
    if any(name not in required and not name.startswith("deploy/") for name in files):
        raise ValueError("unexpected archive contents")
    validate_identity(metadata, identity["tag"], identity["sha"])
    expected = {**identity, "target": target, "executables": info["executables"]}
    if metadata != expected:
        raise ValueError("release-info.json mismatch")


def build_archive(stage, archive, target, timestamp):
    """Normalize order, ownership, modes and timestamps; supplied binaries are unchanged."""
    executables = set(executable_names(target))
    if target.endswith("windows-msvc"):
        # ZIP timestamps have two-second resolution and cannot predate 1980.
        date_time = time.gmtime(max(315532800, min(timestamp, 4354819198)))[:6]
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for file in sorted(stage.rglob("*")):
                if file.is_file():
                    name = file.relative_to(stage).as_posix()
                    member = zipfile.ZipInfo(name, date_time)
                    member.create_system = 3
                    member.external_attr = (stat.S_IFREG | (0o755 if name in executables else 0o644)) << 16
                    member.compress_type = zipfile.ZIP_DEFLATED
                    with file.open("rb") as source, bundle.open(member, "w") as destination:
                        shutil.copyfileobj(source, destination)
    else:
        with archive.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as bundle:
                for file in sorted(stage.rglob("*")):
                    name = file.relative_to(stage).as_posix()
                    member = bundle.gettarinfo(str(file), arcname=name)
                    member.uid = member.gid = 0
                    member.uname = member.gname = ""
                    member.mtime = timestamp
                    member.mode = 0o755 if file.is_dir() or name in executables else 0o644
                    if file.is_file():
                        with file.open("rb") as stream:
                            bundle.addfile(member, stream)
                    else:
                        bundle.addfile(member)


def package(target, binaries, output, *, tag=None, sha=None, root=ROOT):
    if target not in TARGETS:
        raise ValueError("unsupported release target")
    if output.exists() and any(output.iterdir()):
        raise ValueError("package output must be empty")
    version = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
    source_sha = git("rev-parse", "HEAD", root=root)
    if sha is not None and sha != source_sha:
        raise ValueError("package checkout differs from validated commit")
    identity = {"schema_version": 1, "tag": tag or f"v{version}", "version": version, "sha": source_sha}
    validate_identity(identity, identity["tag"], source_sha)
    timestamp = int(git("show", "-s", "--format=%ct", "HEAD", root=root))
    public = output / "public"
    internal = output / "internal"
    public.mkdir(parents=True)
    internal.mkdir()
    extension = ".exe" if target.endswith("windows-msvc") else ""
    archive = public / archive_name(target)
    with tempfile.TemporaryDirectory(prefix="ergo-release-") as directory:
        temp = Path(directory)
        stage = temp / "stage"
        stage.mkdir()
        executables = {}
        for name in executable_names(target):
            shutil.copy2(binaries / name, stage / name)
            (stage / name).chmod(0o755)
            executables[name] = {"sha256": checksum(stage / name)}
        shutil.copy2(root / "docs/release-quickstart.md", stage / "README.md")
        for file in SUPPORT_FILES:
            if file == "README.md" or file.startswith("deploy/"):
                continue
            destination = stage / file
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = root / "ergo-node" / destination.name if file.startswith("config/") else root / file
            shutil.copy2(source, destination)
        shutil.copytree(root / "deploy", stage / "deploy")
        for document in stage.rglob("*.md"):
            document.write_text(packaged_document(
                document.read_text(encoding="utf-8"), document.relative_to(stage).as_posix(),
                stage, source_sha, extension=extension, root=root), encoding="utf-8", newline="\n")
        write_json(stage / "release-info.json", {**identity, "target": target, "executables": executables})
        build_archive(stage, archive, target, timestamp)
        receipt = {**identity, "target": target, "archive": archive.name,
                   "size": archive.stat().st_size, "sha256": checksum(archive), "executables": executables}
        validate_archive(archive, receipt, target, identity)
        extracted = temp / "extracted"
        extracted.mkdir()
        if extension:
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(extracted)
        else:
            with tarfile.open(archive) as bundle:
                bundle.extractall(extracted, filter="data")
        for name in executable_names(target):
            for flag in ("--help", "--version"):
                result = subprocess.run([str(extracted / name), flag], check=True, capture_output=True,
                                        text=True, encoding="utf-8", timeout=20)
                if flag == "--version" and result.stdout.strip() != f"{name.removesuffix('.exe')} {version}":
                    raise RuntimeError(f"unexpected version: {result.stdout.strip()}")
        smoke_work = temp / "node-smoke"
        smoke_work.mkdir()
        smoke_node(extracted / ("ergo-node" + extension), extracted / "config/ergo-node.toml", smoke_work)
        receipt["smoke"] = dict(SMOKE_CHECKS)
        write_json(internal / f"receipt-{target}.json", receipt)
    print(f"packaged {target}: both versions/help, combined archive, offline boot/reopen/shutdown passed")


def transport_files(directory):
    files = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError("symlink in release input")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("unsupported release input")
        if path.name in files:
            raise ValueError(f"duplicate input name: {path.name}")
        files[path.name] = path
    return files


def aggregate(input_dir, output, tag, sha, *, test_target=None):
    """Validate CI receipts and payloads before creating the public allowlist."""
    targets = (test_target,) if test_target is not None else TARGETS
    if any(target not in TARGETS for target in targets):
        raise ValueError("unsupported release target")
    if (input_dir.resolve() == output.resolve()
            or input_dir.resolve() in output.resolve().parents
            or output.resolve() in input_dir.resolve().parents):
        raise ValueError("aggregation input and output must be separate")
    if output.exists() and any(output.iterdir()):
        raise ValueError("aggregate output must be empty")
    identity = {"schema_version": 1, "tag": tag, "version": tag[1:], "sha": sha}
    validate_identity(identity, tag, sha)
    files = transport_files(input_dir)
    expected = {archive_name(target) for target in targets} | {f"receipt-{target}.json" for target in targets}
    if set(files) != expected:
        raise ValueError(f"unexpected or missing release inputs: {sorted(set(files) ^ expected)}")
    manifest = {**identity, "targets": {}}
    for target in sorted(targets):
        with files[f"receipt-{target}.json"].open(encoding="utf-8") as stream:
            receipt = read_json(stream)
        validate_identity(receipt, tag, sha)
        if receipt.get("target") != target:
            raise ValueError("receipt target mismatch")
        if receipt.get("smoke") != SMOKE_CHECKS or any(value is not True for value in receipt["smoke"].values()):
            raise ValueError("receipt must record successful smoke checks")
        validate_archive(files[archive_name(target)], receipt, target, identity)
        manifest["targets"][target] = {key: receipt[key] for key in ("archive", "size", "sha256", "executables")}
    output.mkdir(parents=True, exist_ok=True)
    for target in targets:
        shutil.copyfile(files[archive_name(target)], output / archive_name(target))
    write_json(output / "release.json", manifest)
    hashes = {info["archive"]: info["sha256"] for info in manifest["targets"].values()}
    hashes["release.json"] = checksum(output / "release.json")
    (output / "SHA256SUMS").write_text("".join(f"{hashes[name]}  {name}\n" for name in sorted(hashes)), encoding="utf-8", newline="\n")
    verify_assets(output, tag, sha, test_target=test_target)
    print(f"aggregated and verified {len(targets)} targets, {len(hashes) + 1} public assets")


def verify_assets(directory, tag, sha, *, test_target=None):
    targets = (test_target,) if test_target is not None else TARGETS
    files = transport_files(directory)
    expected = {archive_name(target) for target in targets} | {"release.json", "SHA256SUMS"}
    if set(files) != expected:
        raise ValueError("unexpected or missing public assets")
    with files["release.json"].open(encoding="utf-8") as stream:
        manifest = read_json(stream)
    validate_identity(manifest, tag, sha)
    if not isinstance(manifest.get("targets"), dict) or set(manifest["targets"]) != set(targets):
        raise ValueError("manifest target mismatch")
    identity = {key: manifest[key] for key in ("schema_version", "tag", "version", "sha")}
    hashes = {"release.json": checksum(files["release.json"])}
    for target in targets:
        info = manifest["targets"][target]
        validate_archive(files[archive_name(target)], info, target, identity)
        hashes[info["archive"]] = info["sha256"]
    expected_sums = "".join(f"{hashes[name]}  {name}\n" for name in sorted(hashes)).encode("utf-8")
    if files["SHA256SUMS"].read_bytes() != expected_sums:
        raise ValueError("SHA256SUMS mismatch (hashes, duplicate names, ordering or format)")


def verify_published_assets(directory, tag, repository):
    """Read-only rerun guard: never silently replace already-published bytes."""
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repository):
        raise ValueError("invalid release repository")
    endpoint = f"repos/{repository}/releases/tags/{urllib.parse.quote(tag, safe='')}"
    result = subprocess.run(["gh", "api", endpoint], capture_output=True, text=True, encoding="utf-8")
    if result.returncode:
        if "(HTTP 404)" in result.stderr:
            print("no existing release assets to compare")
            return
        raise RuntimeError(f"could not inspect existing release: {result.stderr}")
    existing = read_json(io.StringIO(result.stdout))
    files = transport_files(directory)
    seen = set()
    with tempfile.TemporaryDirectory(prefix="ergo-published-check-") as temporary:
        downloaded = Path(temporary) / "asset"
        for asset in existing["assets"]:
            name = asset["name"]
            if name in seen:
                raise ValueError(f"duplicate published asset: {name}")
            seen.add(name)
            if name not in files:
                raise ValueError(f"unexpected published asset: {name}; use a new tag or maintainer recovery")
            if type(asset["id"]) is not int or asset["id"] <= 0:
                raise ValueError("invalid published asset id")
            if asset["size"] != files[name].stat().st_size:
                raise ValueError(f"published asset differs: {name}; use a new tag or maintainer recovery")
            with downloaded.open("wb") as stream:
                subprocess.run(["gh", "api", f"repos/{repository}/releases/assets/{asset['id']}",
                                "-H", "Accept: application/octet-stream"], stdout=stream, check=True)
            if checksum(downloaded) != checksum(files[name]):
                raise ValueError(f"published asset differs: {name}; use a new tag or maintainer recovery")
    print(f"verified {len(seen)} existing published assets match; missing assets may be uploaded")


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
    package_parser.add_argument("--tag", default=os.environ.get("RELEASE_TAG"))
    package_parser.add_argument("--sha", default=os.environ.get("RELEASE_SHA"))
    for command in ("aggregate", "verify-assets"):
        command_parser = sub.add_parser(command)
        command_parser.add_argument("--input", type=Path, required=True)
        if command == "aggregate":
            command_parser.add_argument("--output", type=Path, required=True)
        command_parser.add_argument("--tag", default=os.environ.get("RELEASE_TAG"), required="RELEASE_TAG" not in os.environ)
        command_parser.add_argument("--sha", default=os.environ.get("RELEASE_SHA"), required="RELEASE_SHA" not in os.environ)
        command_parser.add_argument("--test-target", choices=TARGETS, help="local fixture only: validate a single target instead of all six")
    published_parser = sub.add_parser("verify-published")
    published_parser.add_argument("--input", type=Path, required=True)
    published_parser.add_argument("--tag", default=os.environ.get("RELEASE_TAG"), required="RELEASE_TAG" not in os.environ)
    published_parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"), required="GITHUB_REPOSITORY" not in os.environ)
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
    elif args.command == "package":
        package(args.target, args.binaries.resolve(), args.output.resolve(), tag=args.tag, sha=args.sha)
    elif args.command == "aggregate":
        aggregate(args.input, args.output, args.tag, args.sha, test_target=args.test_target)
    elif args.command == "verify-published":
        verify_published_assets(args.input, args.tag, args.repository)
    else:
        verify_assets(args.input, args.tag, args.sha, test_target=args.test_target)
        print("public release assets verified")


if __name__ == "__main__":
    main()
