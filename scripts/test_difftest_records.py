"""Diagnostic JSON unit tests; synthetic authority is never an execution receipt."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "difftest_records", Path(__file__).with_name("difftest-records.py"))
RECORDS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECORDS)


class RecordIntegrityTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "runs").mkdir()
        (self.root / "reduce").mkdir()
        source = "// synthetic unit-test source, never executed\n"
        source_hash = hashlib.sha256(source.encode()).hexdigest()
        oracle = {"source_sha256": source_hash, "source_snapshot_utf8": source,
                  "actual_runtime": {
                      "properties": {"java.runtime.version": "unit-test", "java.vm.name": "fixture",
                                     "java.vendor": "fixture"},
                      "resolved_jars": [{"name": "fixture.jar", "sha256": "a" * 64}]}}
        files = [{"path": "source.rs", "bytes": 1, "sha256": "b" * 64}]
        build = {"files": files, "source_sha256": RECORDS.digest(files), "rustc": "fixture",
                 "target": "fixture", "profile": "test", "features": [], "encoded_rustflags": None}
        contract = {"schema": 1, "rust": {name: value for name, value in build.items() if name != "files"},
                    "oracle": RECORDS.stable_oracle(oracle), "scala_cli_sha256": "c" * 64}
        self.journal = {"build": build, "oracle": oracle, "comparison_contract": contract,
                        "scala_cli_executable": {"sha256": "c" * 64},
                        "request": {"surfaces": ["reduce"]},
                        "source_archives": {"primary": f"runs/{source_hash}.scala"}}
        (self.root / f"runs/{source_hash}.scala").write_text(source)
        self.identity = RECORDS.digest(self.journal)
        self.write_journal()
        contract = copy.deepcopy(contract) | {"surface_policy": "synthetic unit-test policy"}
        self.record = {"surface": "reduce", "kind": "Canonical", "input_hex": "0008d3",
                       "rust": {"verdict": "Accept", "detail": "fixture-a"},
                       "jvm": {"verdict": "Accept", "detail": "fixture-b"},
                       "triage": "PENDING", "seed": {"seed": 7, "iter": 42},
                       "execution": {"metadata": f"runs/{self.identity}.json",
                                     "metadata_sha256": self.identity, "comparison_contract": contract,
                                     "authority_complete": True}}
        self.record["execution"]["baseline_key"] = RECORDS.digest(
            {name: self.record[name] for name in ("surface", "kind", "input_hex", "rust", "jvm")}
            | {"comparison_contract": contract})
        self.path = self.write_record()

    def write_journal(self):
        (self.root / f"runs/{self.identity}.json").write_text(json.dumps(self.journal))

    def write_record(self):
        path = self.root / "reduce" / f"{RECORDS.digest(self.record)}.json"
        path.write_text(json.dumps(self.record))
        return path

    def test_complete_bound_record_validates_and_keeps_later_iteration(self):
        key = RECORDS.validate_record(self.path, self.root, "reduce")
        self.assertEqual(key, "reduce/" + self.record["execution"]["baseline_key"])
        self.assertEqual(RECORDS.read_json(self.path)["seed"]["iter"], 42)

    def test_truncated_or_renamed_json_cannot_be_a_baseline_hit(self):
        self.path.write_text("{")
        with self.assertRaises(ValueError):
            RECORDS.validate_record(self.path, self.root, "reduce")
        self.path.write_text(json.dumps(self.record))
        renamed = self.path.with_name("0" * 64 + ".json")
        self.path.rename(renamed)
        with self.assertRaisesRegex(ValueError, "record content identity"):
            RECORDS.validate_record(renamed, self.root, "reduce")

    def test_duplicate_json_fields_are_refused(self):
        self.path.write_text('{"surface":"reduce","surface":"header"}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            RECORDS.read_json(self.path)

    def test_changed_record_authority_is_not_a_near_miss_baseline_hit(self):
        self.record["execution"]["comparison_contract"]["rust"]["profile"] = "release"
        with self.assertRaisesRegex(ValueError, "comparison contract mismatch"):
            RECORDS.validate_record(self.write_record(), self.root, "reduce")

    def test_changed_journal_bytes_are_refused(self):
        self.journal["build"]["rustc"] = "changed"
        self.write_journal()
        with self.assertRaisesRegex(ValueError, "journal identity"):
            RECORDS.validate_record(self.path, self.root, "reduce")

    def test_self_consistent_journal_must_still_match_captured_authority(self):
        self.journal["comparison_contract"]["oracle"]["runtime"]["java.runtime.version"] = "changed"
        identity = RECORDS.digest(self.journal)
        with self.assertRaisesRegex(ValueError, "captured authority"):
            RECORDS.validate_journal(self.journal, self.root, identity)

    def test_changed_archived_source_is_refused(self):
        archive = self.root / self.journal["source_archives"]["primary"]
        archive.write_text("changed source")
        with self.assertRaisesRegex(ValueError, "archive content"):
            RECORDS.validate_record(self.path, self.root, "reduce")

    def test_unavailable_runtime_never_counts_as_complete_authority(self):
        journal = copy.deepcopy(self.journal)
        journal["comparison_contract"]["oracle"]["complete"] = False
        self.assertFalse(RECORDS.complete_authority(journal, "reduce"))

    def test_baseline_requires_unique_keys_and_tracking_references(self):
        baseline = self.root / "baseline.toml"
        key = "reduce/" + "d" * 64
        baseline.write_text(f'[[baseline]]\nkey="{key}"\nref="PR #123"\n')
        self.assertEqual(RECORDS.load_baseline(baseline), {key: "PR #123"})
        baseline.write_text(baseline.read_text() * 2)
        with self.assertRaisesRegex(ValueError, "duplicate baseline"):
            RECORDS.load_baseline(baseline)
        baseline.write_text(f'[[baseline]]\nkey="{key}"\nref="untracked"\n')
        with self.assertRaisesRegex(ValueError, "tracking reference"):
            RECORDS.load_baseline(baseline)

    def test_legacy_input_key_is_distinct_from_authority_key(self):
        baseline = self.root / "baseline.toml"
        baseline.write_text('[[baseline]]\nkey="reduce/0123456789abcdef"\nref="issue #123"\n')
        self.assertNotIn(RECORDS.validate_record(self.path, self.root, "reduce"),
                         RECORDS.load_baseline(baseline))


if __name__ == "__main__":
    unittest.main()
