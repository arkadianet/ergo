#!/usr/bin/env python3
"""Snapshot and join the 2026-10-03 audit with subsequent remediation evidence.

The generator records reported dispositions and exact receipt scopes. It does
not turn a commit, a successful test, or historical source coverage into a
reference-node certification. Refresh reads local files and Git objects only.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "docs/reference-audit/20261004"
INPUTS = (
    "baseline.json", "findings.json", "api-status.json", "state-status.json",
    "sigma-status.json", "engineering-status.json", "pull-requests.json",
)
LANES = ("api", "state", "sigma", "engineering")
SHARED = (("ES006", "API005"), ("ES010", "EC002"), ("ECSP003", "EV005"))
EVIDENCE = re.compile(
    r"(?:api|state|sigma|engineering|rest|indexer|root-control)-evidence/"
    r"[A-Za-z0-9_./-]+\.json"
)
HEX = re.compile(r"[0-9a-f]{7,40}\Z")
COMPACT_COVERAGE = (
    "completed-coverage-verification.json", "ergo-difftest-fuzz-coverage.json",
    "root-shared-coverage.json",
)
MAX_RECEIPT_BYTES = 131072


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse(data: bytes):
    return json.loads(data, object_pairs_hook=reject_duplicates)


def dump(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def normalize(value: str) -> str:
    return value.replace("-", "").upper()


def walk(value):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def git_commit(repo: Path, revision: str) -> str:
    if not HEX.fullmatch(revision):
        raise ValueError(f"not a commit identifier: {revision}")
    return subprocess.check_output(
        ["git", "rev-parse", "--verify", f"{revision}^{{commit}}"],
        cwd=repo, text=True,
    ).strip()


def fix_revisions(row: dict) -> list[str]:
    result = []
    keys = [key for key in ("prior_fix_commits", "fix_commits", "commits", "fix_commit", "commit") if row.get(key)]
    # Some owners record a later inspection/gate head in current_revision.
    # Prefer their explicit fix citations; the observation head is a fallback.
    if not keys:
        keys = ["current_commit", "current_revision"]
    for key in keys:
        value = row.get(key, [])
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, str) and HEX.fullmatch(item) and item not in result:
                result.append(item)
    return result


def index_owners(inputs: dict) -> dict:
    owners = {}
    for lane in LANES:
        for row in inputs[f"{lane}-status.json"]["findings"]:
            identifier = normalize(row.get("id", row.get("original_id", "")))
            if not identifier or identifier in owners:
                raise ValueError(f"missing or repeated owner ID: {identifier}")
            status = row.get("status", row.get("disposition"))
            if not isinstance(status, str) or not status:
                raise ValueError(f"missing owner disposition: {identifier}")
            owners[identifier] = {
                "lane": lane,
                "reported_status": status,
                "owner_record": row,
            }
    return owners


def receipt_scope(value) -> dict:
    """Report exit codes/result fields without promoting other JSON to a gate."""
    rows = value if isinstance(value, list) else value.get("checks", []) if isinstance(value, dict) else []
    commands = [r for r in rows if isinstance(r, dict) and "exit_code" in r]
    heads = sorted({str(v) for r in commands for k, v in r.items()
                    if k in ("revision", "head", "commit")})
    if isinstance(value, dict):
        heads.extend(str(value[k]) for k in ("revision", "head", "commit") if k in value)
    return {
        "recorded_heads": sorted(set(heads)),
        "recorded_result": value.get("result") if isinstance(value, dict) else None,
        "recorded_complete": value.get("complete") if isinstance(value, dict) else None,
        "recorded_command_count": len(commands),
        "recorded_exit_codes": [r["exit_code"] for r in commands],
        "scope": "Recorded fields only; an absent result/head is not inferred.",
    }


def snapshot(source: Path, control: Path, record: Path, repo: Path,
             additional_receipts: tuple[str, ...] = ()):
    # Require a stable set of live ledgers rather than reading an interrupted
    # writer's partially replaced JSON or joining different owner snapshots.
    for attempt in range(5):
        raw = {name: (control / name).read_bytes() for name in INPUTS}
        try:
            inputs = {name: parse(data) for name, data in raw.items()}
        except (ValueError, json.JSONDecodeError):
            if attempt == 4:
                raise
            continue
        if all((control / name).read_bytes() == data for name, data in raw.items()):
            break
    else:
        raise ValueError("live ledgers changed repeatedly; retry after owner writes")
    manifest = {
        "schema_version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "source_audit_revision": inputs["baseline.json"]["audit_revision"],
        "implementation_base": inputs["baseline.json"]["implementation_base"],
        "live_statuses_frozen": False,
        "files": [],
        "coverage_catalog": [],
    }

    def archive(relative: str, data: bytes, origin: str, category: str):
        target = record / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        manifest["files"].append({"path": relative, "sha256": digest(data),
                                  "bytes": len(data), "source": origin, "category": category})

    for name, data in raw.items():
        archive(f"inputs/{name}", data, str(control / name), "remediation snapshot")
    prompts = sorted((source / "docs/audit-prompts").glob("*.md"))
    if len(prompts) != 23:
        raise ValueError(f"expected 23 authored prompts, got {len(prompts)}")
    prompt_rows = []
    for prompt in prompts:
        data = prompt.read_bytes()
        target = repo / "docs/audit-prompts" / prompt.name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        prompt_rows.append({"path": f"docs/audit-prompts/{prompt.name}",
                            "sha256": digest(data), "bytes": len(data)})
    archive("inputs/prompt-manifest.json", dump(prompt_rows),
            str(source / "docs/audit-prompts"), "exact authored prompt copies")

    originals = inputs["findings.json"]["raw_findings"]
    reports = {row["report"]: row["report_sha256"] for row in originals}
    if len(reports) != 21:
        raise ValueError(f"expected 21 historical reports, got {len(reports)}")
    for filename, expected in sorted(reports.items()):
        data = Path(filename).read_bytes()
        if digest(data) != expected:
            raise ValueError(f"historical report changed: {filename}")
        archive(f"historical/reports/{Path(filename).name}", data, filename,
                "historical audit report, not current source coverage")

    report_root = Path(next(iter(reports))).parent
    for file in sorted(report_root.glob("*coverage*.json")):
        data = file.read_bytes()
        value = parse(data)
        counts = Counter(v["status"] for v in walk(value)
                         if isinstance(v, dict) and "path" in v and "status" in v)
        manifest["coverage_catalog"].append({
            "source": str(file), "sha256": digest(data), "bytes": len(data),
            "status_occurrences": dict(sorted(counts.items())),
            "count_scope": "Status occurrences, including any repeated history; not unique full-read counts.",
            "archived": file.name in COMPACT_COVERAGE,
            "scope": "Historical 5d62fd58 coverage only.",
        })
        if file.name in COMPACT_COVERAGE:
            archive(f"historical/coverage/{file.name}", data, str(file),
                    "historical scoped/incomplete coverage receipt")

    owners = index_owners(inputs)
    base = git_commit(repo, manifest["implementation_base"])
    provenance = {}
    for identifier, owner in owners.items():
        if owner["reported_status"] != "already_fixed":
            continue
        revisions = []
        for supplied in fix_revisions(owner["owner_record"]):
            resolved = git_commit(repo, supplied)
            ancestor = subprocess.run(["git", "merge-base", "--is-ancestor", resolved, base],
                                      cwd=repo, check=False).returncode == 0
            if not ancestor:
                raise ValueError(f"upstream-fixed {identifier}: {resolved} is not in base {base}")
            revisions.append({"supplied": supplied, "resolved_commit": resolved,
                              "is_ancestor_of_implementation_base": True})
        if not revisions:
            raise ValueError(f"upstream-fixed {identifier} has no source/fix revision")
        provenance[identifier] = {"source_or_fix_revisions": revisions,
                                  "observed_implementation_base": base,
                                  "scope": "Resolved owner-cited source/fix commits; base observation is not automatically the introducing fix."}
    archive("inputs/upstream-commit-provenance.json", dump(provenance), str(repo),
            "local exact Git resolution and base ancestry")
    pr_provenance = {}
    for pr in inputs["pull-requests.json"]:
        pr_provenance[str(pr["number"])] = {
            "supplied": pr["commit"], "exact_commit": git_commit(repo, pr["commit"]),
            "scope": "Local resolution of the registry's cited immutable commit; no live GitHub state is inferred.",
        }
    archive("inputs/pr-commit-provenance.json", dump(pr_provenance), str(repo),
            "local exact Git resolution of published registry heads")

    references = {match.group() for value in walk(inputs) if isinstance(value, str)
                  for match in EVIDENCE.finditer(value)}
    references.add("api-evidence/normalized-wallet-stack.json")
    for reference in additional_receipts:
        relative = Path(reference)
        if relative.is_absolute() or ".." in relative.parts or relative.suffix != ".json":
            raise ValueError(f"additional receipt must be a relative JSON file: {reference}")
        references.add(reference)
    manifest["additional_receipts"] = list(additional_receipts)
    evidence = []
    for relative in sorted(references):
        file = control / relative
        if not file.is_file():
            evidence.append({"reference": relative, "archived": False, "available_at_snapshot": False})
            continue
        data = file.read_bytes()
        value = parse(data)
        row = {"reference": relative, "sha256": digest(data), "bytes": len(data),
               "available_at_snapshot": True, "archived": len(data) <= MAX_RECEIPT_BYTES,
               "recorded_scope": receipt_scope(value)}
        if row["archived"]:
            row["archive_path"] = f"receipts/{relative}"
            archive(row["archive_path"], data, str(file), "remediation receipt, with original head/scope")
        evidence.append(row)
    archive("inputs/evidence-catalog.json", dump(evidence), str(control),
            "referenced evidence inventory; missing and large captures remain explicit")
    (record / "manifest.json").write_bytes(dump(manifest))


def generate(record: Path, repo: Path) -> dict[str, bytes]:
    manifest = parse((record / "manifest.json").read_bytes())
    for row in manifest["files"]:
        data = (record / row["path"]).read_bytes()
        if len(data) != row["bytes"] or digest(data) != row["sha256"]:
            raise ValueError(f"snapshot integrity mismatch: {row['path']}")
    prompts = parse((record / "inputs/prompt-manifest.json").read_bytes())
    if len(prompts) != 23 or len({row["path"] for row in prompts}) != 23:
        raise ValueError("expected 23 distinct authored prompt copies")
    for row in prompts:
        data = (repo / row["path"]).read_bytes()
        if digest(data) != row["sha256"] or len(data) != row["bytes"]:
            raise ValueError(f"authored prompt mismatch: {row['path']}")
    inputs = {name: parse((record / "inputs" / name).read_bytes()) for name in INPUTS}
    raw = inputs["findings.json"]["raw_findings"]
    identifiers = [normalize(row["id_normalized"]) for row in raw]
    baseline = inputs["baseline.json"]["finding_heading_inventory"]
    expected_reports = {f"historical/reports/{Path(row['report']).name}" for row in raw}
    archived_reports = {row["path"] for row in manifest["files"]
                        if row["category"].startswith("historical audit report")}
    if len(expected_reports) != 21 or archived_reports != expected_reports:
        raise ValueError("historical report archive does not match all 21 originals")
    if len(raw) != 160 or len(set(identifiers)) != 160:
        raise ValueError("expected 160 distinct original findings")
    if set(identifiers) != {normalize(r["id_normalized"]) for r in baseline}:
        raise ValueError("baseline and original finding inventories differ")
    if inputs["findings.json"]["reviewed_revision"] != manifest["source_audit_revision"]:
        raise ValueError("original finding revision differs from the archived audit revision")
    if {tuple(v) for v in inputs["findings.json"]["shared_causes"]} != set(SHARED):
        raise ValueError("shared root causes differ from the recorded three pairs")
    owners = index_owners(inputs)
    if set(owners) != set(identifiers):
        raise ValueError(f"owner coverage mismatch: missing {set(identifiers)-set(owners)}, extra {set(owners)-set(identifiers)}")
    provenance = parse((record / "inputs/upstream-commit-provenance.json").read_bytes())
    evidence = parse((record / "inputs/evidence-catalog.json").read_bytes())
    pairs = {member: pair[0] for pair in SHARED for member in pair}
    pr_provenance = parse((record / "inputs/pr-commit-provenance.json").read_bytes())
    prs = [{**pr, **pr_provenance[str(pr["number"])]}
           for pr in inputs["pull-requests.json"]]
    findings = []
    for original in raw:
        identifier = normalize(original["id_normalized"])
        owner = owners[identifier]
        related = [pr for pr in prs if identifier in [normalize(i) for i in pr["findings"]]]
        findings.append({
            "id": identifier, "original_id": original["id"],
            "canonical_cause": pairs.get(identifier, identifier),
            "crate": original["owner"], "original_heading": original["heading"],
            "historical_report": f"historical/reports/{Path(original['report']).name}",
            "historical_report_sha256": original["report_sha256"],
            **owner,
            "upstream_commit_provenance": provenance.get(identifier),
            "published_pull_requests": related,
        })
    causes = []
    for cause in sorted({row["canonical_cause"] for row in findings}):
        members = [row for row in findings if row["canonical_cause"] == cause]
        statuses = [r["reported_status"] for r in members]
        causes.append({"id": cause, "members": [r["id"] for r in members],
                       "reported_statuses": statuses,
                       "has_unfinished_reported_work": any(s not in ("fixed", "already_fixed", "reclassified") for s in statuses)})
    if len(causes) != 157:
        raise ValueError(f"expected 157 canonical causes, got {len(causes)}")
    counts = dict(sorted(Counter(r["reported_status"] for r in findings).items()))
    result = {
        "schema_version": 1, "captured_at": manifest["captured_at"],
        "audit_revision": manifest["source_audit_revision"],
        "implementation_base": manifest["implementation_base"],
        "scope": "Remediation snapshot of owner dispositions and published drafts, not current whole-source review or reference certification.",
        "counts": {"original_findings": 160, "canonical_causes": 157,
                   "reported_dispositions": counts, "published_prs": len(prs)},
        "findings": findings, "canonical_causes": causes,
        "published_pull_requests": prs,
        "owner_gate_and_scope_records": {lane: {key: value for key, value in inputs[f"{lane}-status.json"].items()
                                                if key != "findings"} for lane in LANES},
        "evidence_catalog": evidence,
    }
    lines = ["# Reference audit review record", "", f"Snapshot: {manifest['captured_at']}.", "",
             "This record connects 160 original findings to 157 causes, owner dispositions and published draft PRs. It is a remediation record, not a current full source review or a reference-node certification.", "",
             f"The historical audit reviewed `{manifest['source_audit_revision']}`. Remediation was revalidated against `{manifest['implementation_base']}` before fixes. The source moved substantially between those revisions.", "",
             "## Current owner dispositions", "", "| Reported status | Original findings |", "|---|---:|"]
    lines += [f"| {status} | {count} |" for status, count in counts.items()]
    lines += ["", "Statuses are copied from the owners. `remaining_evidence` can mean partial evidence, an external fixture prerequisite, or work still in progress; the full owner record preserves that distinction. A published draft is not merged work. Missing receipt fields do not imply a PASS.", "",
              "The full ST009 owner record distinguishes cached-state checks, captured activation costs and any remaining historical prerequisites. The historical fuzz ledger retains HASH_ONLY files and does not establish executed decoder or provenance checks.", "",
              "## Finding and PR index", "", "| Original ID | Cause | Owner status | Historical report | Draft PRs |", "|---|---|---|---|---|"]
    for row in findings:
        pr_links = ", ".join(f"[#{pr['number']}]({pr['url']})" for pr in row["published_pull_requests"]) or "—"
        report = row["historical_report"]
        lines.append(f"| {row['id']} | {row['canonical_cause']} | {row['reported_status']} | [{row['crate']}]({report}) | {pr_links} |")
    lines += ["", "## Evidence scope and reproduction", "",
              "[findings-map.json](findings-map.json) preserves every original ID and heading, the full owner row, shared-cause membership, all registry PRs, exact receipt fields and upstream source/fix SHAs resolved against the implementation base. The archived owner snapshots retain normalized wallet tree-equality qualifications and state/REST/indexer gates executed on cumulative heads; those gates are not relabeled as executions of a different focused head.", "",
              "[manifest.json](manifest.json) hashes exact prompt copies, all 21 historical reports, owner snapshots and compact receipt copies. Larger coverage ledgers are inventoried with hashes and status-occurrence summaries; three compact historical ledgers are retained. Historical FULL_READ/PARTIAL_READ/HASH_ONLY claims apply only to their recorded audit hashes. No cache, JAR, build tree or large corpus is archived.", "",
              "Historical reports retain their original bytes and references. Some old links point to session artifacts outside this compact archive; the manifest and evidence catalog identify the retained files without inventing missing evidence.", "",
              "Verify the frozen copies and regenerate the index/map offline:", "", "```sh", "python3 scripts/reference-review-record.py --check", "python3 scripts/reference-review-record.py", "```", "",
              "Refresh from the local live session after owners freeze their final dispositions:", "", "```sh", "python3 scripts/reference-review-record.py --refresh-source /path/to/original-checkout --control /path/to/audit/remediation/20261004-audit", "```", "",
              "Refreshing records a new timestamp and input hashes. It does not run native gates or resolve outstanding evidence. Include final integrated gates or strict cost receipts with repeated `--additional-receipt relative/path.json` arguments, relative to the control directory; the manifest lists those selections. Absent receipts remain absent.", ""]
    return {"findings-map.json": dump(result), "index.md": "\n".join(lines).encode()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh-source", type=Path)
    parser.add_argument("--control", type=Path)
    parser.add_argument("--additional-receipt", action="append", default=[])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if bool(args.refresh_source) != bool(args.control) or args.check and args.refresh_source:
        parser.error("supply --refresh-source and --control together; --check is read-only")
    if args.additional_receipt and not args.refresh_source:
        parser.error("--additional-receipt requires a refresh")
    if args.refresh_source:
        snapshot(args.refresh_source.resolve(), args.control.resolve(), RECORD, ROOT,
                 tuple(args.additional_receipt))
    outputs = generate(RECORD, ROOT)
    for relative, expected in outputs.items():
        file = RECORD / relative
        if args.check:
            if not file.is_file() or file.read_bytes() != expected:
                raise ValueError(f"generated review record differs: {relative}")
        else:
            file.write_bytes(expected)
    print("PASS: 23 exact prompts, 21 historical reports, 160 findings, 157 causes; reported scopes preserved")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
