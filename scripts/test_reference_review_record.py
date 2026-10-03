"""Identity joins and scope guards for the durable review record."""

import importlib.util
import pathlib
import shutil
import tempfile
import unittest

MODULE = pathlib.Path(__file__).with_name("reference-review-record.py")
SPEC = importlib.util.spec_from_file_location("reference_review_record", MODULE)
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)


class ReviewRecordTests(unittest.TestCase):
    def owners(self):
        return {
            "api-status.json": {"findings": [{"id": "API-005", "status": "fixed"}]},
            "state-status.json": {"findings": [{"id": "ST009", "disposition": "remaining_evidence",
                                                 "resolution_state": "external_fixture_prerequisite"}]},
            "sigma-status.json": {"findings": [{"original_id": "ES-006", "status": "fixed"}]},
            "engineering-status.json": {"findings": [{"id": "WS001", "status": "already_fixed"}]},
        }

    def test_owner_key_variants_preserve_partial_evidence(self):
        rows = review.index_owners(self.owners())
        self.assertEqual(set(rows), {"API005", "ST009", "ES006", "WS001"})
        self.assertEqual(rows["ST009"]["reported_status"], "remaining_evidence")
        self.assertEqual(rows["ST009"]["owner_record"]["resolution_state"], "external_fixture_prerequisite")

    def test_duplicate_owner_assignment_fails(self):
        inputs = self.owners()
        inputs["state-status.json"]["findings"].append({"id": "API005", "disposition": "fixed"})
        with self.assertRaisesRegex(ValueError, "repeated owner ID"):
            review.index_owners(inputs)

    def test_missing_owner_disposition_fails(self):
        inputs = self.owners()
        del inputs["api-status.json"]["findings"][0]["status"]
        with self.assertRaisesRegex(ValueError, "missing owner disposition"):
            review.index_owners(inputs)

    def test_explicit_upstream_fix_does_not_include_later_observation(self):
        row = {"commits": ["f7d72c58"], "current_revision": "2af7dab5"}
        self.assertEqual(review.fix_revisions(row), ["f7d72c58"])
        self.assertEqual(review.fix_revisions({"current_commit": "71bb7016"}), ["71bb7016"])

    def test_receipt_without_head_or_result_is_not_certified(self):
        scope = review.receipt_scope([{"check": "fmt", "exit_code": 0}])
        self.assertEqual(scope["recorded_exit_codes"], [0])
        self.assertEqual(scope["recorded_heads"], [])
        self.assertIsNone(scope["recorded_result"])
        self.assertIsNone(scope["recorded_complete"])

    def test_receipt_retains_failed_command_and_actual_execution_head(self):
        scope = review.receipt_scope({"revision": "def9e240", "complete": True,
                                      "checks": [{"exit_code": 1, "revision": "def9e240"}]})
        self.assertEqual(scope["recorded_heads"], ["def9e240"])
        self.assertEqual(scope["recorded_exit_codes"], [1])
        self.assertIsNone(scope["recorded_result"])

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            review.parse(b'{"status":"fixed","status":"remaining_evidence"}')

    def test_archived_record_reproduces_without_live_owner_files(self):
        outputs = review.generate(review.RECORD, review.ROOT)
        for name, expected in outputs.items():
            self.assertEqual((review.RECORD / name).read_bytes(), expected, name)

    def test_tampered_archived_disposition_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            copy = pathlib.Path(directory) / "record"
            shutil.copytree(review.RECORD, copy)
            ledger = copy / "inputs/state-status.json"
            # Tamper a byte independently of any finding's current disposition.
            ledger.write_bytes(ledger.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "snapshot integrity mismatch"):
                review.generate(copy, review.ROOT)


if __name__ == "__main__":
    unittest.main()
