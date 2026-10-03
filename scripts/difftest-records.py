#!/usr/bin/env python3
"""Validate immutable differential records before applying an authority baseline."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib


def digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False)
    return hashlib.sha256(encoded.encode()).hexdigest()


def read_json(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"not a regular evidence file: {path}")
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON field {key!r}: {path}")
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def stable_oracle(source):
    runtime = source.get("actual_runtime", {})
    properties = runtime.get("properties", {})
    jars = [{"name": jar.get("name"), "sha256": jar.get("sha256")}
            for jar in runtime.get("resolved_jars", [])]
    result = {
        "source_sha256": source.get("source_sha256"),
        "runtime": {name: properties.get(name)
                    for name in ("java.runtime.version", "java.vm.name", "java.vendor")}
                   | {"resolved_jars_in_classpath_order": jars},
        "complete": isinstance(properties.get("java.runtime.version"), str) and bool(jars),
    }
    if "verify_sidecar" in source:
        result["verify_sidecar"] = stable_oracle(source["verify_sidecar"])
    return result


def load_baseline(path):
    with path.open("rb") as stream:
        rows = tomllib.load(stream).get("baseline", [])
    baseline = {}
    for row in rows:
        key, reference = row.get("key", ""), row.get("ref", "")
        if not re.fullmatch(r"[a-z_]+/(?:[0-9a-f]{16}|[0-9a-f]{64})", key):
            raise ValueError(f"invalid baseline key: {key!r}")
        if not re.fullmatch(r"(?:PR|issue) #[0-9]+", reference):
            raise ValueError(f"baseline {key} needs a tracking reference")
        if key in baseline:
            raise ValueError(f"duplicate baseline key: {key}")
        baseline[key] = reference
    return baseline


def validate_journal(journal, root, identity):
    if digest(journal) != identity:
        raise ValueError("execution journal identity mismatch")
    build = journal["build"]
    if digest(build["files"]) != build["source_sha256"]:
        raise ValueError("compiled source snapshot identity mismatch")
    expected_contract = {
        "schema": 1,
        "rust": {name: build[name] for name in ("source_sha256", "rustc", "target", "profile",
                                                "features", "encoded_rustflags")},
        "oracle": stable_oracle(journal["oracle"]),
        "scala_cli_sha256": journal["scala_cli_executable"].get("sha256"),
    }
    if journal["comparison_contract"] != expected_contract:
        raise ValueError("journal comparison contract disagrees with captured authority")
    for name, source in (("primary", journal["oracle"]),
                         ("verify_sidecar", journal["oracle"].get("verify_sidecar"))):
        if source is None:
            continue
        text = source["source_snapshot_utf8"]
        source_hash = hashlib.sha256(text.encode()).hexdigest()
        if source.get("source_sha256") != source_hash:
            raise ValueError("oracle source identity mismatch")
        archive = f"runs/{source_hash}.scala"
        if journal["source_archives"].get(name) != archive:
            raise ValueError("oracle source archive reference mismatch")
        archived = root / archive
        if archived.is_symlink() or archived.read_bytes() != text.encode():
            raise ValueError("oracle source archive content mismatch")


def complete_authority(journal, surface):
    authority = journal["comparison_contract"]["oracle"]
    if surface == "verify":
        authority = authority.get("verify_sidecar", {})
    runtime = authority.get("runtime", {})
    return (authority.get("complete") is True and bool(runtime.get("java.runtime.version"))
            and bool(runtime.get("resolved_jars_in_classpath_order")))


def validate_record(path, root, surface):
    record = read_json(path)
    if record.get("surface") != surface or record.get("triage") != "PENDING":
        raise ValueError(f"pending record surface/disposition mismatch: {path}")
    if path.stem != digest(record):
        raise ValueError(f"record content identity mismatch: {path}")
    execution = record.get("execution")
    if not isinstance(execution, dict) or execution.get("authority_complete") is not True:
        raise ValueError(f"record lacks complete execution authority: {path}")
    metadata_hash = execution.get("metadata_sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", metadata_hash):
        raise ValueError(f"invalid metadata identity: {path}")
    reference = f"runs/{metadata_hash}.json"
    if execution.get("metadata") != reference:
        raise ValueError(f"invalid metadata reference: {path}")
    journal = read_json(root / reference)
    validate_journal(journal, root, metadata_hash)
    contract = execution["comparison_contract"].copy()
    policy = contract.pop("surface_policy", None)
    if not isinstance(policy, str) or not policy:
        raise ValueError(f"missing surface/context policy: {path}")
    if contract != journal["comparison_contract"]:
        raise ValueError(f"record/journal comparison contract mismatch: {path}")
    if not complete_authority(journal, surface):
        raise ValueError(f"journal lacks actual JVM/JAR identity: {path}")
    contract["surface_policy"] = policy
    key = digest({name: record[name] for name in ("surface", "kind", "input_hex", "rust", "jvm")}
                 | {"comparison_contract": contract})
    if execution.get("baseline_key") != key:
        raise ValueError(f"baseline comparison identity mismatch: {path}")
    return f"{surface}/{key}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--check-baseline", action="store_true")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--surfaces", nargs="+")
    args = parser.parse_args()
    try:
        baseline = load_baseline(args.baseline)
    except (OSError, ValueError, TypeError, AttributeError) as error:
        print(f"difftest-guard: invalid baseline: {error}", file=sys.stderr)
        return 2
    if args.check_baseline:
        print(f"{len(baseline)} entries; legacy 16-character input keys cannot mute authority-bound records")
        return 0
    if args.root is None or not args.surfaces:
        parser.error("--root and --surfaces are required when validating records")
    if any(not re.fullmatch(r"[a-z_]+", surface) for surface in args.surfaces):
        parser.error("surface must be a plain lowercase identifier")
    hits, new = set(), []
    try:
        if args.root.is_symlink() or (args.root / "runs").is_symlink():
            raise ValueError("execution directory must not be a symlink")
        journals = []
        for path in sorted((args.root / "runs").glob("*.json")):
            journal = read_json(path)
            validate_journal(journal, args.root, path.stem)
            journals.append(journal)
        for surface in args.surfaces:
            count = 0
            if not any(surface in journal["request"]["surfaces"]
                       and complete_authority(journal, surface) for journal in journals):
                raise ValueError(f"no complete execution journal for {surface}")
            directory = args.root / surface
            if directory.is_symlink():
                raise ValueError(f"surface directory is a symlink: {directory}")
            for path in sorted(directory.glob("*.json")):
                key = validate_record(path, args.root, surface)
                count += 1
                if key in baseline:
                    hits.add(key)
                    print(f"BASELINED {key} {baseline[key]} → {path}")
                else:
                    new.append(key)
                    print(f"NEW {key} → {path}")
            print(f"VALIDATED {surface} {count}")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f"difftest-guard: HARNESS ERROR: invalid evidence: {error}", file=sys.stderr)
        return 3
    for key in sorted(baseline.keys() - hits):
        print(f"STALE {key} {baseline[key]} (not reproduced with matching authority)")
    return int(bool(new))


if __name__ == "__main__":
    sys.exit(main())
