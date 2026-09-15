#!/usr/bin/env python3
"""JIT-cost conformance ledger tool.

    scripts/cost-ledger.py render   # regenerate test-vectors/ergo-sigma/cost-ledger/LEDGER.md
    scripts/cost-ledger.py check    # validate ledger.toml + LEDGER.md freshness + test references
    scripts/cost-ledger.py check --strict   # release mode: no OPEN/DIVERGENT rows; resolved inventory audit
    scripts/cost-ledger.py --selftest       # hermetic checker regression tests

`ledger.toml` is authoritative; `LEDGER.md` is derived. `check` exits non-zero when:
  * a row is malformed (missing field, unknown category/state/layer),
  * a CLOSED row names no test, or names a test not found in the tree with a
    `// ledger: <id>` comment referencing that row,
  * a source file references a ledger id that does not exist,
  * an N-A or DIVERGENT row has an empty note,
  * LEDGER.md is stale relative to ledger.toml.

Passing evidence uses nextest libtest-json events from $COST_LEDGER_TEST_RESULTS
or target/cost-ledger-test-results.json. Absent results skip only the passing
check with a note; CI produces fresh results without committing them.

Standard library only (tomllib, Python >= 3.11).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import tempfile
import unittest
import subprocess
import sys
import tomllib
from collections import Counter
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parent.parent
LEDGER_DIR = REPO / "test-vectors" / "ergo-sigma" / "cost-ledger"
TOML = LEDGER_DIR / "ledger.toml"
MD = LEDGER_DIR / "LEDGER.md"

CATEGORIES = {"OP", "METHOD", "EVAL", "INTERP", "TX", "BLOCK", "ORDER", "ROUND", "LIMIT", "VERSION"}
STATES = {"OPEN", "CLOSED", "DIVERGENT", "N-A"}
LAYERS = {"L1", "L2", "L3", "L4", "L5", "L6"}
FIELDS = ("id", "cat", "scala", "rust", "layer", "state", "tests", "note")
ID = r"(?:OP|METHOD|EVAL|INTERP|TX|BLOCK|ORDER|ROUND|LIMIT|VERSION)-[A-Za-z0-9._-]+"
REF_RE = re.compile(r"ledger:\s*(" + ID + r"(?:\s*,\s*" + ID + r")*)")


def load() -> tuple[dict, list[dict]]:
    data = tomllib.loads(TOML.read_text())
    return data["meta"], data["rows"]


def render(meta: dict, rows: list[dict]) -> str:
    counts = Counter((r["cat"], r["state"]) for r in rows)
    cats = [c for c in ("OP", "METHOD", "EVAL", "INTERP", "ROUND", "ORDER", "LIMIT", "TX", "BLOCK", "VERSION")]
    out = [
        "# JIT-cost conformance ledger",
        "",
        f"Generated from `ledger.toml` by `scripts/cost-ledger.py render` — do not edit by hand.",
        "",
        f"Source ledger: sigmastate `{meta['scala_sigmastate']}`, ergo `{meta['scala_ergo']}`. "
        f"Oracle: {meta['oracle_node']}. Updated {meta['updated']}.",
        "",
        "## Coverage",
        "",
        "| category | OPEN | CLOSED | DIVERGENT | N-A | total |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    tot = Counter()
    for c in cats:
        row = [counts[(c, s)] for s in ("OPEN", "CLOSED", "DIVERGENT", "N-A")]
        for s, n in zip(("OPEN", "CLOSED", "DIVERGENT", "N-A"), row):
            tot[s] += n
        out.append(f"| {c} | {row[0]} | {row[1]} | {row[2]} | {row[3]} | {sum(row)} |")
    out.append(
        f"| **all** | {tot['OPEN']} | {tot['CLOSED']} | {tot['DIVERGENT']} | {tot['N-A']} | {sum(tot.values())} |"
    )
    out += ["", "States: OPEN = no independent-oracle evidence yet; CLOSED = named passing test with an "
            "independent oracle; DIVERGENT = confirmed mismatch, fix pending; N-A = reviewed rationale in note.", ""]
    for c in cats:
        sub = [r for r in rows if r["cat"] == c]
        if not sub:
            continue
        out += [f"## {c}", "", "| id | state | Scala | Rust | layers | tests | note |", "|---|---|---|---|---|---|---|"]
        for r in sub:
            tests = "<br>".join(f"`{t}`" for t in r["tests"]) or "—"
            out.append(
                f"| `{r['id']}` | {r['state']} | {esc(r['scala'])} | `{esc(r['rust'])}` | {r['layer']} | {tests} | {esc(r['note'])} |"
            )
        out.append("")
    return "\n".join(out)


def esc(s: str) -> str:
    return s.replace("|", "\\|")


def resolve_test(repo: Path, reference: str, rid: str) -> set[str]:
    """Resolve a ledger name to fully qualified nextest libtest-JSON names."""
    parts = reference.split("::")
    if len(parts) == 4 and parts[1] == "it":
        parts.pop(1)
    if len(parts) != 3 or not all(re.fullmatch(r"[A-Za-z0-9_-]+", p) for p in parts):
        raise ValueError(f"invalid test reference {reference!r}; expected <crate>::<file>::<fn>")
    crate, stem, function = parts
    root = repo / crate
    candidates = [(root / "tests" / "it" / f"{stem}.rs", f"{crate}::it", [stem]),
                  (root / "tests" / f"{stem}.rs", f"{crate}::{stem}", [])]
    for path in sorted((root / "src").rglob(f"{stem}.rs")):
        modules = list(path.relative_to(root / "src").with_suffix("").parts)
        if modules[-1] in {"lib", "main", "mod"}:
            modules.pop()
        manifest_path = root / "Cargo.toml"
        manifest = tomllib.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
        binary = manifest.get("lib", {}).get("name", crate.replace("-", "_"))
        if path == root / "src" / "main.rs":
            binary = crate
        candidates.append((path, f"{crate}::{binary}", modules))
    matches = []
    for path, binary, modules in candidates:
        if not path.is_file():
            continue
        source = path.read_text()
        lines = source.splitlines()
        # Preserve line positions while ignoring comments and string contents.
        clean = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"',
                       lambda m: "".join("\n" if c == "\n" else " " for c in m[0]),
                       source, flags=re.S)
        depth = 0
        inline = []
        for token in re.finditer(r"\bmod\s+(\w+)\s*\{|[{}]|\bfn\s+(\w+)\s*\(", clean):
            if token[1]:
                depth += 1
                inline.append((depth, token[1]))
            elif token[0] == "{":
                depth += 1
            elif token[0] == "}":
                if inline and inline[-1][0] == depth:
                    inline.pop()
                depth -= 1
            elif token[2] == function:
                line = clean.count("\n", 0, token.start())
                preceding = lines[max(0, line - 3):line]
                annotated = any(rid in re.split(r"\s*,\s*", m[1])
                                for text in preceding
                                if text.strip().startswith("// ledger:")
                                for m in REF_RE.finditer(text))
                if not annotated or not any(re.fullmatch(r"\s*#\[test\]\s*", t) for t in preceding):
                    raise ValueError(f"{reference}: fn {function} needs #[test] and // ledger: {rid} within 3 lines")
                oracle = re.search(
                    r"^\s*//! Oracle:\s*.*?(?:test-vectors/[^\s`]+|scripts/[^\s`]*jvm[^\s`]*|[^\s`]+\.scala)(?:\s|`|$)",
                    source, re.M)
                if not oracle:
                    raise ValueError(f"{reference}: {path.relative_to(repo)} needs //! Oracle: naming test-vectors/... or a JVM script")
                name = "::".join(modules + [name for _, name in inline] + [function])
                matches.append(f"{binary}${name}")
    if len(matches) != 1:
        raise ValueError(f"{reference}: expected one test definition, found {len(matches)}")
    return set(matches)


def read_results(path: Path) -> dict[str, list[str]] | None:
    """Read nextest's newline-delimited libtest-json, retaining all outcomes."""
    if not path.exists():
        print(f"NOTE: {path} absent; skipping passing-evidence check")
        return None
    results: dict[str, list[str]] = {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{number}: invalid test-results JSON: {exc.msg}") from exc
        if not isinstance(event, dict):
            raise ValueError(f"{path}:{number}: expected an event object")
        if event.get("type") == "test":
            name, outcome = event.get("name"), event.get("event")
            if not isinstance(name, str) or not isinstance(outcome, str):
                raise ValueError(f"{path}:{number}: test event requires name and event strings")
            if outcome != "started":
                results.setdefault(name, []).append(outcome)
    return results


def closure_errors(repo: Path, rows: list[dict], results: dict | None) -> list[str]:
    errors = []
    for row in rows:
        if row.get("state") != "CLOSED":
            continue
        for reference in row.get("tests", []):
            try:
                names = resolve_test(repo, reference, row["id"])
                if results is not None and not all(results.get(name) == ["ok"] for name in names):
                    raise ValueError(f"{reference}: missing or non-ok passing evidence")
            except ValueError as exc:
                errors.append(f"{row['id']}: {exc}")
    return errors


def audit_errors(directory: Path) -> list[str]:
    audit = directory / "inventory-audit.md"
    if not audit.is_file():
        return ["STRICT: inventory-audit.md is missing"]
    if "UNRESOLVED" in audit.read_text():
        return ["STRICT: inventory-audit.md contains UNRESOLVED"]
    return []


def check(meta: dict, rows: list[dict]) -> int:
    errors: list[str] = []
    ids = set()
    for r in rows:
        for f in FIELDS:
            if f not in r:
                errors.append(f"{r.get('id', '?')}: missing field {f}")
        rid = r.get("id", "?")
        if rid in ids:
            errors.append(f"{rid}: duplicate id")
        ids.add(rid)
        if r.get("cat") not in CATEGORIES:
            errors.append(f"{rid}: unknown category {r.get('cat')}")
        if r.get("state") not in STATES:
            errors.append(f"{rid}: unknown state {r.get('state')}")
        for layer in str(r.get("layer", "")).split(","):
            if layer and layer not in LAYERS:
                errors.append(f"{rid}: unknown layer {layer}")
        if r.get("state") in {"N-A", "DIVERGENT"} and not r.get("note"):
            errors.append(f"{rid}: {r['state']} requires a rationale in note")
        if r.get("state") == "CLOSED" and not r.get("tests"):
            errors.append(f"{rid}: CLOSED requires at least one test")

    # Source references must name real ledger rows.
    try:
        files = subprocess.run(
            ["git", "-C", str(REPO), "grep", "-l", "ledger:", "--", "*.rs", "*.scala", "*.py", "*.sh", "*.json"],
            capture_output=True, text=True, check=False,
        ).stdout.split()
    except FileNotFoundError:
        files = []
    for f in files:
        if f.startswith("test-vectors/ergo-sigma/cost-ledger/"):
            continue
        text = (REPO / f).read_text(errors="replace")
        for m in REF_RE.finditer(text):
            for rid in re.split(r"\s*,\s*", m.group(1)):
                if rid not in ids:
                    errors.append(f"{f}: references unknown ledger id {rid}")
    try:
        results = read_results(Path(os.environ.get("COST_LEDGER_TEST_RESULTS", str(REPO / "target" / "cost-ledger-test-results.json"))))
        errors.extend(closure_errors(REPO, rows, results))
    except (ValueError, OSError) as exc:
        errors.append(str(exc))

    if not MD.exists() or MD.read_text() != render(meta, rows):
        errors.append("LEDGER.md is stale: run scripts/cost-ledger.py render")

    counts = Counter(r["state"] for r in rows)
    print("rows:", len(rows), dict(counts))
    for e in errors:
        print("ERROR:", e)
    return 1 if errors else 0


def selftest() -> int:
    class LedgerTests(unittest.TestCase):
        def setUp(self):
            self.temp = tempfile.TemporaryDirectory(dir=REPO)
            self.addCleanup(self.temp.cleanup)
            self.repo = Path(self.temp.name)
            self.path = self.repo / "sample/tests/it/pin.rs"
            self.path.parent.mkdir(parents=True)
            self.source = "//! Oracle: test-vectors/oracle.json\n// ledger: OP-0x72, OP-0x73\n#[test]\nfn cost_pin_matches_oracle() {}\n"
            self.path.write_text(self.source)
            self.row = dict(id="OP-0x72", state="CLOSED", tests=["sample::pin::cost_pin_matches_oracle"])
            self.name = "sample::it$pin::cost_pin_matches_oracle"

        def errors(self, results=None):
            return closure_errors(self.repo, [self.row], results)

        def test_closure_valid_it_passes(self):
            self.assertEqual(self.errors({self.name: ["ok"]}), [])
            self.row["tests"] = ["sample::it::pin::cost_pin_matches_oracle"]
            self.assertEqual(self.errors(), [])

        def test_closure_flat_integration_passes(self):
            self.path.rename(self.repo / "sample/tests/pin.rs")
            self.assertEqual(self.errors({"sample::pin$cost_pin_matches_oracle": ["ok"]}), [])

        def test_closure_nested_unit_passes(self):
            self.path.unlink()
            unit = self.repo / "sample/src/evaluator/pin.rs"
            unit.parent.mkdir(parents=True)
            unit.write_text("#[cfg(test)]\nmod tests {\n" + self.source + "}\n")
            self.assertEqual(self.errors({"sample::sample$evaluator::pin::tests::cost_pin_matches_oracle": ["ok"]}), [])

        def test_closure_mod_unit_passes(self):
            self.path.unlink()
            unit = self.repo / "sample/src/evaluator/mod.rs"
            unit.parent.mkdir(parents=True)
            unit.write_text("mod tests {\n" + self.source + "}\n")
            self.row["tests"] = ["sample::mod::cost_pin_matches_oracle"]
            self.assertEqual(self.errors({"sample::sample$evaluator::tests::cost_pin_matches_oracle": ["ok"]}), [])

        def test_closure_jvm_script_passes(self):
            self.path.write_text(self.source.replace("test-vectors/oracle.json", "scripts/jvm_cost_oracle/main.scala"))
            self.assertEqual(self.errors(), [])

        def test_closure_invalid_source_rejected(self):
            variants = [self.source.replace("OP-0x72", "OP-other"),
                        self.source.replace("#[test]", "#[inline]"),
                        self.source.replace("#[test]", "\n\n#[test]"),
                        self.source.replace("cost_pin_matches_oracle", "another_test"),
                        self.source.replace("test-vectors/oracle.json", "Rust computes expected"),
                        "/*\n" + self.source + "*/\n",
                        self.source.replace("//! Oracle:", "// Oracle:")]
            for source in variants:
                with self.subTest(source=source):
                    self.path.write_text(source)
                    self.assertTrue(self.errors())

        def test_closure_missing_or_ambiguous_rejected(self):
            duplicate = self.repo / "sample/tests/pin.rs"
            duplicate.write_text(self.source)
            self.assertTrue(self.errors())
            duplicate.unlink()
            self.path.unlink()
            self.assertTrue(self.errors())

        def test_closure_invalid_reference_rejected(self):
            for reference in ["sample::pin", "../sample::pin::test", "sample::pin::missing"]:
                with self.subTest(reference=reference):
                    self.row["tests"] = [reference]
                    self.assertTrue(self.errors())

        def test_closure_nonpassing_evidence_rejected(self):
            for results in [{}, {self.name: ["failed"]}, {self.name: ["ignored"]},
                            {self.name: ["ok", "failed"]}, {"other::it$pin::cost_pin_matches_oracle": ["ok"]}]:
                with self.subTest(results=results):
                    self.assertTrue(self.errors(results))

        def test_results_events_parsed(self):
            path = self.repo / "results.json"
            events = [dict(type="suite", event="started"),
                      dict(type="test", event="started", name=self.name),
                      dict(type="test", event="ok", name=self.name),
                      dict(type="suite", event="ok")]
            path.write_text("\n".join(json.dumps(e) for e in events))
            self.assertEqual(read_results(path), {self.name: ["ok"]})

        def test_results_invalid_rejected(self):
            path = self.repo / "results.json"
            for contents in ["broken", "[]", '{"type":"test"}']:
                with self.subTest(contents=contents):
                    path.write_text(contents)
                    with self.assertRaises(ValueError):
                        read_results(path)
            path.write_text("")
            self.assertEqual(read_results(path), {})

        def test_results_absent_skips(self):
            self.assertIsNone(read_results(self.repo / "missing.json"))

        def test_check_freshness_references_and_results_enforced(self):
            meta = dict(scala_sigmastate="6.0.2", scala_ergo="6.0.2", oracle_node="6.0.5", updated="2026-09-15")
            row = dict(self.row, cat="OP", scala="oracle", rust="sample", layer="L1", note="")
            second = dict(row, id="OP-0x73", state="OPEN", tests=[])
            rows = [row, second]
            md = self.repo / "LEDGER.md"
            md.write_text(render(meta, rows))
            default_results = self.repo / "target/cost-ledger-test-results.json"
            default_results.parent.mkdir()
            override = self.repo / "override.json"
            with patch.dict(os.environ, {}, clear=True), patch.dict(globals(), REPO=self.repo, MD=md), \
                    patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout="sample/tests/it/pin.rs")), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(check(meta, rows), 0)
                md.write_text("stale")
                self.assertEqual(check(meta, rows), 1)
                md.write_text(render(meta, rows))
                self.path.write_text(self.source.replace("OP-0x73", "OP-unknown"))
                self.assertEqual(check(meta, rows), 1)
                self.path.write_text(self.source)
                default_results.write_text("")
                self.assertEqual(check(meta, rows), 1)
                override.write_text(json.dumps(dict(type="test", event="ok", name=self.name)))
                with patch.dict(os.environ, COST_LEDGER_TEST_RESULTS=str(override)):
                    self.assertEqual(check(meta, rows), 0)

        def test_audit_missing_unresolved_rejected(self):
            self.assertTrue(audit_errors(self.repo))
            audit = self.repo / "inventory-audit.md"
            audit.write_text("UNRESOLVED obligation")
            self.assertTrue(audit_errors(self.repo))
            audit.write_text("All obligations accounted for.")
            self.assertEqual(audit_errors(self.repo), [])

    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(LedgerTests))
    return 0 if result.wasSuccessful() else 1


def main() -> int:
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    if len(sys.argv) not in (2, 3) or sys.argv[1] not in {"render", "check"} or (len(sys.argv) == 3 and sys.argv[2] != "--strict"):
        print(__doc__)
        return 2
    meta, rows = load()
    if sys.argv[1] == "render":
        MD.write_text(render(meta, rows))
        print(f"wrote {MD.relative_to(REPO)} ({len(rows)} rows)")
        return 0
    rc = check(meta, rows)
    if len(sys.argv) == 3:  # --strict: release mode, no OPEN/DIVERGENT rows allowed
        for error in audit_errors(LEDGER_DIR):
            print(error)
            rc = 1
        bad = [r["id"] for r in rows if r["state"] in {"OPEN", "DIVERGENT"}]
        if bad:
            print(f"STRICT: {len(bad)} rows not CLOSED/N-A:", ", ".join(bad[:10]), "..." if len(bad) > 10 else "")
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
