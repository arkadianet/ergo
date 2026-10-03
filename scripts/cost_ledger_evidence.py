#!/usr/bin/env python3
"""Run the ledger suites and bind their results to the exact local inputs.

The sidecar records reproducibility information, not a signed attestation.
Strict checks trust the CI runner that produces it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

REPO = Path(__file__).resolve().parent.parent
DELEGATED = {
    "ergo-validation::it$cost_parity::ranges::cost_parity_stratified_ranges_match_jvm",
    "ergo-validation::it$cost_parity::ranges::cost_parity_required_selection_matches_jvm",
    "ergo-validation::it$l4_manifest::l4_manifest_compressed_vectors_preserve_input_hashes",
}
REPLAY_FILTER = (
    "test(/cost_parity_stratified_ranges_match_jvm|"
    "cost_parity_required_selection_matches_jvm|"
    "l4_manifest_compressed_vectors_preserve_input_hashes/)"
)
COMMANDS = [
    ["cargo", "nextest", "run", "--locked", "--workspace", "--features",
     "ergo-validation/diagnostics", "--no-fail-fast", "-E",
     "not (binary(/^diagnose_block_/) | binary(/^trace_/) | binary(parity_triage) | "
     f"binary(eval_error_triage) | {REPLAY_FILTER})", "--message-format", "libtest-json"],
    ["cargo", "nextest", "run", "--locked", "-p", "ergo-validation", "--features",
     "diagnostics", "--no-fail-fast", "--run-ignored", "only", "-E", REPLAY_FILTER,
     "--message-format", "libtest-json"],
]


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def revision(repo: Path) -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()


def input_digest(repo: Path) -> str:
    """Hash tracked/unignored inputs and the ignored replay captures consumed by tests."""
    listed = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=repo
    )
    paths = {os.fsdecode(name) for name in listed.split(b"\0") if name}
    vectors = repo / "test-vectors/mainnet"
    for pattern in ("*.json", "*.json.gz"):
        paths.update(str(path.relative_to(repo)) for path in vectors.glob(pattern))
    fingerprint = hashlib.sha256()
    for name in sorted(paths):
        path = repo / name
        # The workspace contains regular source/data files. Treat missing files
        # as an error rather than silently dropping a deleted tracked input.
        fingerprint.update(os.fsencode(name) + b"\0" + bytes.fromhex(digest(path)))
    return fingerprint.hexdigest()


def read_events(path: Path) -> list[dict]:
    events = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError(f"{path}:{number}: expected an event object")
        events.append(event)
    return events


def merge_events(ordinary: list[dict], manual: list[dict]) -> list[dict]:
    terminal = {name: [] for name in DELEGATED}
    for event in manual:
        if event.get("type") != "test":
            continue
        name, outcome = event.get("name"), event.get("event")
        if name in DELEGATED:
            if outcome != "started":
                terminal[name].append(outcome)
        elif outcome not in {"started", "ignored"}:
            raise ValueError(f"unexpected replay result: {event}")
    if any(outcomes != ["ok"] for outcomes in terminal.values()):
        raise ValueError(f"replay tests must each pass exactly once: {terminal}")
    evidence = []
    for event in ordinary:
        if event.get("type") == "test" and event.get("name") in DELEGATED:
            if event.get("event") not in {"started", "ignored"}:
                raise ValueError(f"replay test also executed in workspace suite: {event}")
        else:
            evidence.append(event)
    evidence.extend(event for event in manual
                    if event.get("type") == "test" and event.get("name") in DELEGATED)
    return evidence


def sidecar(path: Path) -> Path:
    return path.with_name(path.name + ".provenance.json")


def validate(repo: Path, results: Path) -> None:
    if not results.is_file():
        raise ValueError(f"STRICT: passing evidence is missing: {results}")
    provenance_path = sidecar(results)
    if not provenance_path.is_file():
        raise ValueError(f"STRICT: evidence provenance is missing: {provenance_path}")
    provenance = json.loads(provenance_path.read_text())
    if not isinstance(provenance, dict):
        raise ValueError("STRICT: evidence provenance must be an object")
    expected = {
        "schema": 1,
        "revision": revision(repo),
        "inputs_sha256": input_digest(repo),
        "commands": COMMANDS,
        "results_sha256": digest(results),
    }
    for key, value in expected.items():
        if provenance.get(key) != value:
            raise ValueError(f"STRICT: evidence {key} does not match this checkout")
    # A failed/interrupted invocation never writes a sidecar. Retain tool
    # versions for reproduction without requiring identical host platforms.
    if not all(isinstance(provenance.get(key), str) and provenance[key].strip()
               for key in ("rustc", "nextest")):
        raise ValueError("STRICT: evidence tool versions are missing")


def atomic_write(path: Path, contents: str) -> None:
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def capture(repo: Path, results: Path) -> None:
    results.parent.mkdir(parents=True, exist_ok=True)
    results.unlink(missing_ok=True)
    sidecar(results).unlink(missing_ok=True)
    before_revision, before_inputs = revision(repo), input_digest(repo)
    versions = {
        "rustc": subprocess.check_output(["rustc", "-Vv"], cwd=repo, text=True).strip(),
        "nextest": subprocess.check_output(["cargo", "nextest", "--version"], cwd=repo, text=True).strip(),
    }
    environment = dict(os.environ, NEXTEST_EXPERIMENTAL_LIBTEST_JSON="1",
                       NEXTEST_MESSAGE_FORMAT_VERSION="0.1")
    logs = [results.with_name("cost-ledger-workspace.jsonl"),
            results.with_name("cost-ledger-manual.jsonl")]
    for command, log in zip(COMMANDS, logs):
        with log.open("w") as output:
            subprocess.run(command, cwd=repo, env=environment, stdout=output, check=True)
    events = merge_events(*(read_events(path) for path in logs))
    if revision(repo) != before_revision or input_digest(repo) != before_inputs:
        raise ValueError("checkout inputs changed while the ledger tests were running")
    atomic_write(results, "".join(json.dumps(event) + "\n" for event in events))
    provenance = dict(schema=1, revision=before_revision, inputs_sha256=before_inputs,
                      commands=COMMANDS, results_sha256=digest(results), **versions)
    atomic_write(sidecar(results), json.dumps(provenance, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=Path(os.environ.get(
        "COST_LEDGER_TEST_RESULTS", str(REPO / "target/cost-ledger-test-results.json"))))
    args = parser.parse_args()
    try:
        capture(REPO, args.results.resolve())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"ledger evidence failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
