"""Hermetic regressions for release evidence freshness and replay outcomes."""

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import cost_ledger_evidence as evidence


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        subprocess.run(["git", "init", "--quiet", str(self.repo)], check=True)
        (self.repo / ".gitignore").write_text("target/\ntest-vectors/mainnet/*.json.gz\n")
        (self.repo / "source.rs").write_text("original source")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                        "commit", "--quiet", "-m", "fixture"], cwd=self.repo, check=True)
        self.results = self.repo / "target/results.json"
        self.results.parent.mkdir()
        self.results.write_text('{"type":"test","event":"ok","name":"sample"}\n')
        self.provenance = dict(schema=1, revision=evidence.revision(self.repo),
                               inputs_sha256=evidence.input_digest(self.repo),
                               commands=copy.deepcopy(evidence.COMMANDS),
                               results_sha256=evidence.digest(self.results),
                               rustc="rustc fixture", nextest="nextest fixture")
        self.write_provenance()

    def write_provenance(self):
        evidence.sidecar(self.results).write_text(json.dumps(self.provenance))

    def test_current_evidence_passes(self):
        evidence.validate(self.repo, self.results)

    def test_missing_results_or_sidecar_fails(self):
        evidence.sidecar(self.results).unlink()
        with self.assertRaisesRegex(ValueError, "provenance is missing"):
            evidence.validate(self.repo, self.results)
        self.results.unlink()
        with self.assertRaisesRegex(ValueError, "passing evidence is missing"):
            evidence.validate(self.repo, self.results)

    def test_stale_revision_commands_and_digest_fail(self):
        for field, value in (("revision", "old"), ("commands", [[]]),
                             ("inputs_sha256", "old"), ("results_sha256", "old"),
                             ("schema", 0), ("rustc", "")):
            with self.subTest(field=field):
                original = self.provenance[field]
                self.provenance[field] = value
                self.write_provenance()
                with self.assertRaises(ValueError):
                    evidence.validate(self.repo, self.results)
                self.provenance[field] = original

    def test_changed_source_untracked_source_or_results_fails(self):
        for path in (self.repo / "source.rs", self.repo / "new.rs", self.results):
            with self.subTest(path=path):
                original = path.read_bytes() if path.exists() else None
                path.write_text("changed")
                with self.assertRaises(ValueError):
                    evidence.validate(self.repo, self.results)
                if original is None:
                    path.unlink()
                else:
                    path.write_bytes(original)

    def test_ignored_replay_inputs_are_bound(self):
        capture = self.repo / "test-vectors/mainnet/tx_costs_1_2.json.gz"
        capture.parent.mkdir(parents=True)
        capture.write_bytes(b"captured data")
        with self.assertRaisesRegex(ValueError, "inputs_sha256"):
            evidence.validate(self.repo, self.results)

    def test_deleted_tracked_source_fails(self):
        (self.repo / "source.rs").unlink()
        with self.assertRaises(FileNotFoundError):
            evidence.validate(self.repo, self.results)

    def test_exactly_one_passing_manual_outcome_required(self):
        manual = [dict(type="test", name=name, event="ok") for name in evidence.DELEGATED]
        ordinary = [dict(type="test", name=name, event="ignored") for name in evidence.DELEGATED]
        self.assertEqual(evidence.merge_events(ordinary, manual), manual)
        variants = [manual[:-1], manual + manual[:1],
                    [dict(event, event="failed") for event in manual],
                    manual + [dict(type="test", name="unexpected", event="ok")]]
        for events in variants:
            with self.subTest(events=events), self.assertRaises(ValueError):
                evidence.merge_events(ordinary, events)
        with self.assertRaises(ValueError):
            evidence.merge_events(manual, manual)

    def test_failed_runner_removes_old_evidence(self):
        real_run = subprocess.run
        def run(command, **kwargs):
            if command in evidence.COMMANDS:
                raise subprocess.CalledProcessError(1, command)
            if command[0] in {"rustc", "cargo"}:
                return subprocess.CompletedProcess(command, 0, stdout="fixture version")
            return real_run(command, **kwargs)
        with patch.object(evidence.subprocess, "run", side_effect=run):
            with self.assertRaises(subprocess.CalledProcessError):
                evidence.capture(self.repo, self.results)
        self.assertFalse(self.results.exists())
        self.assertFalse(evidence.sidecar(self.results).exists())

    def test_source_change_during_successful_runs_rejects_evidence(self):
        real_run = subprocess.run
        def run(command, **kwargs):
            if command not in evidence.COMMANDS:
                if command[0] in {"rustc", "cargo"}:
                    return subprocess.CompletedProcess(command, 0, stdout="fixture version")
                return real_run(command, **kwargs)
            if command == evidence.COMMANDS[1]:
                for name in evidence.DELEGATED:
                    kwargs["stdout"].write(json.dumps(dict(type="test", name=name, event="ok")) + "\n")
                (self.repo / "source.rs").write_text("changed during run")
            return subprocess.CompletedProcess(command, 0)
        with patch.object(evidence.subprocess, "run", side_effect=run):
            with self.assertRaisesRegex(ValueError, "inputs changed"):
                evidence.capture(self.repo, self.results)
        self.assertFalse(self.results.exists())
        self.assertFalse(evidence.sidecar(self.results).exists())


if __name__ == "__main__":
    unittest.main()
