#!/usr/bin/env python3
"""Diff the blind Scala inventory against explicitly source-audited counterparts.

Empty discrepancy lists are silent. Exit 1 means inventory drift; exit 2 means
invalid inputs. Reviewed snapshots are not runtime cost oracles. See the audit
for shared-descriptor mappings and source-verified formula resolutions.
"""

import argparse
import json
from pathlib import Path
import re
import sys
import tomllib
import unittest

REPO = Path(__file__).resolve().parent.parent
DIRECTORY = REPO / "test-vectors/ergo-sigma/cost-ledger"
ENTRY = re.compile(r"[AMEITBG]\d{3}\Z")


def normalize(value: str) -> str:
    """Canonicalize Markdown, opcode hex and familiar SType.method aliases."""
    value = value.replace("`", "").replace("**", "")
    value = re.sub(r"0[xX]([0-9a-fA-F]+)", lambda m: f"0x{int(m[1], 16):02X}", value)
    value = re.sub(r"\bS(Boolean|Byte|Short|Int|Long|BigInt|UnsignedBigInt|GroupElement|SigmaProp|Coll|Option|Box|AvlTree|Context|Header|PreHeader|Global)\s*\.", r"\1.", value)
    value = re.sub(r"\s*\.\s*(?=[A-Za-z])", ".", value)
    return " ".join(value.split())


def enumeration_rows(markdown: str) -> dict[str, list[str]]:
    result = {}
    for line in markdown.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        # Escaped Markdown pipes belong to a cell, not the table structure.
        cells = [cell.strip().replace(r"\|", "|") for cell in re.split(r"(?<!\\)\|", line.strip())[1:-1]]
        if not cells or not ENTRY.fullmatch(cells[0]):
            continue
        if len(cells) != 6:
            raise ValueError(f"{cells[0]}: expected six Markdown cells, got {len(cells)}")
        if cells[0] in result:
            raise ValueError(f"duplicate enumeration id: {cells[0]}")
        result[cells[0]] = [normalize(cell) for cell in cells[1:]]
    if not result:
        raise ValueError("no enumeration rows found")
    return result


def ledger_rows(document: dict) -> dict[str, dict]:
    result = {}
    for row in document["rows"]:
        rid = normalize(row["id"])
        if rid in result:
            raise ValueError(f"duplicate ledger id: {rid}")
        result[rid] = row
    if not result:
        raise ValueError("no ledger rows found")
    return result


def reviewed_fields(row: dict) -> dict[str, str]:
    # Scala anchors include the audited declarations and formulas. Notes track evidence.
    return {"scala": normalize(row["scala"])}


def normalized_keys(values: dict, label: str) -> dict:
    result = {}
    for key, value in values.items():
        normalized = normalize(key)
        if normalized in result:
            raise ValueError(f"duplicate {label} id after normalization: {normalized}")
        result[normalized] = value
    return result


def differences(enumeration: dict, ledger: dict, audit: dict) -> dict[str, list[str]]:
    if audit["schema"] != 1:
        raise ValueError("unsupported inventory map schema")
    mappings = normalized_keys(audit["enumeration"], "enumeration")
    mappings = {
        eid: {**entry, "ledger": [normalize(rid) for rid in entry["ledger"]]}
        for eid, entry in mappings.items()
    }
    reviewed = normalized_keys(audit["ledger"], "ledger")
    categories = {"in enumeration only": [], "in ledger only": [], "matched-with-different-constant": []}
    enum_only, ledger_only, changed = categories.values()
    for eid, cells in sorted(enumeration.items()):
        entry = mappings.get(eid)
        if entry is None:
            enum_only.append(eid)
            continue
        if not entry["ledger"]:
            raise ValueError(f"{eid}: empty counterpart mapping")
        missing = sorted(set(entry["ledger"]) - ledger.keys())
        if missing:
            enum_only.append(f"{eid}: missing counterparts {', '.join(missing)}")
        # The last cell is commentary; identity, anchor, formula and gating are audited.
        if cells[:4] != entry["cells"][:4]:
            changed.append(f"{eid}: enumeration declaration/formula/gating changed")
    owners = {}
    for eid, entry in mappings.items():
        for rid in entry["ledger"]:
            if rid not in reviewed:
                raise ValueError(f"{eid}: unreviewed counterpart {rid}")
            owners.setdefault(rid, []).append(eid)
    for rid, row in sorted(ledger.items()):
        review = reviewed.get(rid)
        if review is None:
            ledger_only.append(rid)
            continue
        mapped = owners.get(rid, [])
        if mapped:
            absent = sorted(set(mapped) - enumeration.keys())
            if absent:
                ledger_only.append(f"{rid}: missing enumeration entries {', '.join(absent)}")
        elif not review.get("ledger_only_finding"):
            ledger_only.append(f"{rid}: no counterpart or source-reviewed finding")
        if reviewed_fields(row) != review["fields"]:
            changed.append(f"{rid}: reviewed Scala formula/anchor changed")
    # Deletions must not silently shrink either audited denominator.
    for eid in sorted(mappings.keys() - enumeration.keys()):
        changed.append(f"{eid}: audited enumeration entry deleted")
    for rid in sorted(reviewed.keys() - ledger.keys()):
        changed.append(f"{rid}: audited ledger row deleted")
    return categories


def selftest() -> int:
    class InventoryTests(unittest.TestCase):
        def setUp(self):
            self.text = "| A001 | 1 | values.scala:380 | `Constant`: F(5) | — | Evaluated. |"
            self.enumeration = enumeration_rows(self.text)
            self.ledger = {"OP-0x72": {"scala": "values.scala:380 F(5)", "note": ""}}
            self.audit = {"schema": 1, "enumeration": {"A001": {"ledger": ["OP-0x72"], "cells": self.enumeration["A001"]}}, "ledger": {"OP-0x72": {"fields": reviewed_fields(self.ledger["OP-0x72"])}}}

        def diff(self):
            return differences(self.enumeration, self.ledger, self.audit)

        def test_inventory_complete_empty(self):
            self.assertFalse(any(self.diff().values()))

        def test_normalization_aliases_equal(self):
            self.assertEqual(normalize("`SColl` . map  0xff"), normalize("Coll.map 0xFF"))

        def test_inventory_audit_aliases_equal(self):
            self.ledger = {"OP-0xFF": self.ledger["OP-0x72"]}
            entry = self.audit["enumeration"].pop("A001")
            entry["ledger"] = ["OP-0xff"]
            self.audit["enumeration"]["`A001`"] = entry
            self.audit["ledger"]["OP-0xff"] = self.audit["ledger"].pop("OP-0x72")
            self.assertFalse(any(self.diff().values()))

        def test_inventory_audit_normalized_collisions_rejected(self):
            for section, alias in (("enumeration", "`A001`"), ("ledger", "OP-0X72")):
                with self.subTest(section=section):
                    entries = self.audit[section]
                    entries[alias] = next(iter(entries.values()))
                    with self.assertRaisesRegex(ValueError, f"duplicate {section} id"):
                        self.diff()
                    del entries[alias]

        def test_enumeration_new_entry_reported(self):
            self.enumeration["A002"] = self.enumeration["A001"]
            self.assertEqual(self.diff()["in enumeration only"], ["A002"])

        def test_ledger_new_row_reported(self):
            self.ledger["OP-new"] = self.ledger["OP-0x72"]
            self.assertEqual(self.diff()["in ledger only"], ["OP-new"])

        def test_constant_changed_reported(self):
            self.ledger["OP-0x72"]["scala"] = "values.scala:380 F(6)"
            self.assertTrue(self.diff()["matched-with-different-constant"])
            self.enumeration = enumeration_rows(self.text.replace("F(5)", "F(7)"))
            self.assertEqual(len(self.diff()["matched-with-different-constant"]), 2)

        def test_evidence_note_changed_ignored(self):
            self.ledger["OP-0x72"]["note"] = "Fixture renamed; PR #337"
            self.assertFalse(any(self.diff().values()))

        def test_enumeration_note_changed_ignored(self):
            self.enumeration["A001"][-1] = "Evidence refreshed"
            self.assertFalse(any(self.diff().values()))

        def test_counterpart_deleted_reported(self):
            del self.ledger["OP-0x72"]
            self.assertTrue(self.diff()["in enumeration only"])
            self.assertTrue(self.diff()["matched-with-different-constant"])

        def test_enumeration_deleted_reported(self):
            del self.enumeration["A001"]
            self.assertTrue(self.diff()["in ledger only"])
            self.assertTrue(self.diff()["matched-with-different-constant"])

        def test_ledger_only_review_accepted(self):
            self.audit["enumeration"] = {}
            self.enumeration = {}
            self.assertTrue(self.diff()["in ledger only"])
            self.audit["ledger"]["OP-0x72"]["ledger_only_finding"] = "Registry verifies absence."
            self.assertFalse(any(self.diff().values()))

        def test_mapping_shared_descriptor_accepted(self):
            self.enumeration["M001"] = self.enumeration["A001"]
            self.audit["enumeration"]["M001"] = self.audit["enumeration"]["A001"]
            self.assertFalse(any(self.diff().values()))

        def test_markdown_invalid_rejected(self):
            for text in ("", self.text + "\n" + self.text, "| A001 | missing cells |"):
                with self.subTest(text=text), self.assertRaises(ValueError):
                    enumeration_rows(text)

        def test_markdown_escaped_pipe_preserved(self):
            parsed = enumeration_rows(self.text.replace("Evaluated.", r"left \| right"))
            self.assertEqual(parsed["A001"][-1], "left | right")

        def test_ledger_opcode_alias_normalized(self):
            self.assertEqual(set(ledger_rows({"rows": [{"id": "OP-0xff"}]})), {"OP-0xFF"})

        def test_enumeration_method_alias_normalized(self):
            left = enumeration_rows(self.text.replace("`Constant`", "`SColl . map`"))
            right = enumeration_rows(self.text.replace("`Constant`", "`Coll.map`"))
            self.assertEqual(left, right)

        def test_ledger_duplicate_rejected(self):
            with self.assertRaises(ValueError):
                ledger_rows({"rows": [{"id": "same"}, {"id": "same"}]})

    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(InventoryTests))
    return 0 if result.wasSuccessful() else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enumeration", type=Path, default=DIRECTORY / "scala-enumeration.md")
    parser.add_argument("--ledger", type=Path, default=DIRECTORY / "ledger.toml")
    parser.add_argument("--mapping", type=Path, default=DIRECTORY / "inventory-map.json")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    try:
        result = differences(enumeration_rows(args.enumeration.read_text()), ledger_rows(tomllib.loads(args.ledger.read_text())), json.loads(args.mapping.read_text()))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"inventory diff: {exc}", file=sys.stderr)
        return 2
    for heading, items in result.items():
        if items:
            print(heading + ":")
            for item in items:
                print("  " + item)
    return int(any(result.values()))


if __name__ == "__main__":
    sys.exit(main())
