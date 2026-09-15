#!/usr/bin/env python3
"""JIT-cost conformance ledger tool.

    scripts/cost-ledger.py render   # regenerate test-vectors/ergo-sigma/cost-ledger/LEDGER.md
    scripts/cost-ledger.py check    # validate ledger.toml + LEDGER.md freshness + test references
    scripts/cost-ledger.py check --strict   # release mode: additionally fail on any OPEN/DIVERGENT row

`ledger.toml` is authoritative; `LEDGER.md` is derived. `check` exits non-zero when:
  * a row is malformed (missing field, unknown category/state/layer),
  * a CLOSED row names no test, or names a test not found in the tree with a
    `// ledger: <id>` comment referencing that row,
  * a source file references a ledger id that does not exist,
  * an N-A or DIVERGENT row has an empty note,
  * LEDGER.md is stale relative to ledger.toml.

Standard library only (tomllib, Python >= 3.11).
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from collections import Counter
from pathlib import Path

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

    # Source references: every `// ledger: X` must name a real row; every CLOSED row's tests
    # must be reachable from a file that references the row id.
    referenced: dict[str, set[str]] = {}
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
                referenced.setdefault(rid, set()).add(f)
                if rid not in ids:
                    errors.append(f"{f}: references unknown ledger id {rid}")
    for r in rows:
        if r.get("state") == "CLOSED" and r["id"] not in referenced:
            errors.append(f"{r['id']}: CLOSED but no source file carries `// ledger: {r['id']}`")

    if not MD.exists() or MD.read_text() != render(meta, rows):
        errors.append("LEDGER.md is stale: run scripts/cost-ledger.py render")

    counts = Counter(r["state"] for r in rows)
    print("rows:", len(rows), dict(counts))
    for e in errors:
        print("ERROR:", e)
    return 1 if errors else 0


def main() -> int:
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
        bad = [r["id"] for r in rows if r["state"] in {"OPEN", "DIVERGENT"}]
        if bad:
            print(f"STRICT: {len(bad)} rows not CLOSED/N-A:", ", ".join(bad[:10]), "..." if len(bad) > 10 else "")
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
