"""Filesystem/manifest unit tests only; no native fuzz or upload is executed."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("fuzz_evidence", Path(__file__).with_name("fuzz-evidence.py"))
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def manifest(self):
        identity = {"version": {"exit_code": 0, "stdout": "cargo-fuzz 0.13.1"}, "executable_identity": {"sha256": "fixture"},
                    "selected_compiler_identity": {"sha256": "fixture"}}
        binary = [{"path": "owned-fixture", "bytes": 7, "sha256": "fixture"}]
        return {"requested_pins": {"cargo_fuzz": "0.13.1", "nightly": "fixture-nightly"},
                "toolchain_requested": "fixture-nightly", "phases": {name: {"exit_code": 0, "binaries": binary} for name in EVIDENCE.PHASES},
                "tools": {"cargo_fuzz": identity, "rustc": identity},
                "source_start": {"inventory_sha256": "fixture"},
                "source_end": {"inventory_sha256": "fixture"},
                "locks_start": {"Cargo.lock": "fixture", "ergo-difftest/fuzz/Cargo.lock": "fixture"},
                "locks_end": {"Cargo.lock": "fixture", "ergo-difftest/fuzz/Cargo.lock": "fixture"}}

    def test_inventory_is_ordered_and_preserves_exact_bytes(self):
        directory = self.root / "inputs"
        directory.mkdir()
        (directory / "z").write_bytes(b"last")
        (directory / "a").write_bytes(b"first\x00")
        rows = EVIDENCE.inventory(directory, self.root / "copy")
        self.assertEqual([row["path"] for row in rows], ["a", "z"])
        self.assertEqual(rows[0]["sha256"], EVIDENCE.digest(b"first\x00"))
        self.assertEqual((self.root / "copy/a").read_bytes(), b"first\x00")

    def test_missing_inventory_is_explicitly_empty(self):
        self.assertEqual(EVIDENCE.inventory(self.root / "absent"), [])

    def test_symlinks_are_not_accepted_as_evidence(self):
        directory = self.root / "inputs"
        directory.mkdir()
        (directory / "real").write_text("fixture")
        (directory / "alias").symlink_to("real")
        with self.assertRaisesRegex(ValueError, "symlink"):
            EVIDENCE.inventory(directory)

    def test_complete_commands_do_not_claim_a_detector_or_upload_proof(self):
        result = EVIDENCE.assessment(self.manifest())
        self.assertEqual(result["status"], "COMMANDS_COMPLETED")
        self.assertIn("No independently certified", result["limits"])

    def test_missing_failed_or_unknown_commands_cannot_be_green(self):
        for phase in EVIDENCE.PHASES:
            value = self.manifest()
            del value["phases"][phase]
            self.assertEqual(EVIDENCE.assessment(value)["status"], "INCOMPLETE_OR_FAILED")
            value = self.manifest()
            value["phases"][phase]["exit_code"] = 1
            self.assertIn(phase, EVIDENCE.assessment(value)["nonzero_phases"])
        value = self.manifest()
        value["tools"] = {}
        self.assertFalse(EVIDENCE.assessment(value)["tools_known"])

    def test_cached_tool_must_match_the_requested_pin(self):
        value = self.manifest()
        value["requested_pins"]["cargo_fuzz"] = "0.13.2"
        self.assertFalse(EVIDENCE.assessment(value)["tools_known"])
        self.assertFalse(EVIDENCE.assessment(value)["tool_pins_match"])
        value = self.manifest()
        value["toolchain_requested"] = "different-nightly"
        self.assertFalse(EVIDENCE.assessment(value)["tool_pins_match"])

    def test_source_lock_and_binary_changes_are_visible(self):
        for field in ("source_end", "locks_end"):
            value = self.manifest()
            value[field] = {}
            self.assertEqual(EVIDENCE.assessment(value)["status"], "INCOMPLETE_OR_FAILED")
        value = self.manifest()
        value["phases"]["run"]["binaries"] = []
        self.assertFalse(EVIDENCE.assessment(value)["single_binary_unchanged"])

    def test_records_retain_log_argv_exit_and_refuse_overwriting(self):
        output = self.root / "bundle"
        output.mkdir()
        EVIDENCE.save(output / "metadata.json", {"phases": {}, "target": "constant",
                                                "build_directory": str(self.root / "build")})
        log = self.root / "fixture.log"
        log.write_text("ordinary fixture text\n")
        EVIDENCE.record(output, "run", 3, log, ["fixture-command", "--argument"])
        metadata = json.loads((output / "metadata.json").read_text())
        result = metadata["phases"]["run"]
        self.assertEqual(result["exit_code"], 3)
        self.assertEqual(result["argv"], ["fixture-command", "--argument"])
        self.assertEqual(result["sha256"], EVIDENCE.digest(log.read_bytes()))
        self.assertEqual((output / result["log"]).read_bytes(), log.read_bytes())
        with self.assertRaisesRegex(ValueError, "already recorded"):
            EVIDENCE.record(output, "run", 0, log, ["fixture-command"])

    def test_finalizer_retains_not_run_when_start_is_absent(self):
        output = self.root / "bundle"
        with patch.object(EVIDENCE, "git_state", return_value={"fixture": True}):
            EVIDENCE.finish(self.root, output, "constant")
        metadata = json.loads((output / "metadata.json").read_text())
        self.assertEqual(metadata["assessment"]["status"], "NOT_RUN")
        self.assertEqual(metadata["assessment"]["missing_phases"], list(EVIDENCE.PHASES))

    def test_finalizer_copies_corpus_and_artifact_bytes_without_interpreting_them(self):
        output = self.root / "bundle"
        output.mkdir()
        target = "constant"
        for name in ("corpus", "artifacts"):
            directory = self.root / "ergo-difftest/fuzz" / name / target
            directory.mkdir(parents=True)
            (directory / "fixture.txt").write_bytes(b"ordinary saved text")
        for relative in ("Cargo.lock", "ergo-difftest/fuzz/Cargo.lock"):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture lock")
        metadata = self.manifest()
        metadata["target"] = target
        metadata["locks_start"] = {relative: EVIDENCE.fingerprint(self.root / relative)
                                  for relative in ("Cargo.lock", "ergo-difftest/fuzz/Cargo.lock")}
        EVIDENCE.save(output / "metadata.json", metadata)
        with patch.object(EVIDENCE, "git_state", return_value={"fixture": True}), \
             patch.object(EVIDENCE, "source_inventory", return_value=metadata["source_start"]):
            EVIDENCE.finish(self.root, output, target)
        final = json.loads((output / "metadata.json").read_text())
        self.assertEqual(final["assessment"]["status"], "COMMANDS_COMPLETED")
        self.assertEqual(final["artifacts"][0]["sha256"], EVIDENCE.digest(b"ordinary saved text"))
        self.assertEqual((output / "artifacts/fixture.txt").read_bytes(), b"ordinary saved text")
        self.assertEqual((output / "final-corpus/fixture.txt").read_bytes(), b"ordinary saved text")

    def test_start_never_clears_previous_output(self):
        output = self.root / "previous"
        output.mkdir()
        (output / "user-text").write_text("preserved")
        with self.assertRaisesRegex(ValueError, "fresh"):
            EVIDENCE.start(self.root, output, "constant", "fixture", self.root / "build")
        self.assertEqual((output / "user-text").read_text(), "preserved")


if __name__ == "__main__":
    unittest.main()
