"""The recorded capture inventory must match the replay's storage selection."""

import gzip
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "record_l4_provenance", Path(__file__).resolve().parents[1]
    / "test-vectors/scripts/record_l4_provenance.py")
PROVENANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVENANCE)


class ProvenanceTests(unittest.TestCase):
    def test_plain_compressed_and_overlapping_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            names = ["tx_costs_100_101", "transactions_100_101", "input_boxes_100_101",
                     "headers_90_100", "headers_101_110", "l4_boxes"]
            for name in names:
                (directory / f"{name}.json").write_text("[]")
            (directory / "headers_1_2.json").write_text("[]")
            files, missing = PROVENANCE.selected_inputs(directory, [[100, 101]])
            self.assertEqual(files, {directory / f"{name}.json" for name in names})
            self.assertEqual(missing, [])
            for name in names:
                (directory / f"{name}.json.gz").write_bytes(gzip.compress(b"[1]"))
            files, missing = PROVENANCE.selected_inputs(directory, [[100, 101]])
            self.assertEqual(files, {directory / f"{name}.json.gz" for name in names})
            self.assertEqual(missing, [])
            for name in names:
                (directory / f"{name}.json").unlink()
            self.assertEqual(PROVENANCE.selected_inputs(directory, [[100, 101]]), (files, []))

    def test_missing_required_captures_remain_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            files, missing = PROVENANCE.selected_inputs(directory, [[100, 101]])
            self.assertEqual(files, set())
            self.assertEqual(missing, [directory / "tx_costs_100_101.json",
                                       directory / "transactions_100_101.json"])


if __name__ == "__main__":
    unittest.main()
