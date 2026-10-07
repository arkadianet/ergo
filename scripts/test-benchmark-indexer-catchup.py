#!/usr/bin/env python3
"""Regression coverage for Rust test-harness prefixes on benchmark output."""

import importlib.util
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch
import os

SPEC = importlib.util.spec_from_file_location("benchmark_indexer", Path(__file__).with_name("benchmark-indexer-catchup.py"))
BENCHMARK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCHMARK)


class BenchmarkOutputTests(unittest.TestCase):
    def test_prefixed_metric_record_without_progress_lines(self):
        output = 'running 1 test\ntest task::benchmark ... BENCH {"commits": 71}\nLOAD_SECONDS 1.5\nAPPLY_SECONDS 2.5\nCOMMIT_SECONDS 0.5\nok\n'
        self.assertEqual(BENCHMARK.parse_sample(output), {
            "commits": 71, "load_seconds": 1.5, "apply_seconds": 2.5, "commit_seconds": 0.5,
        })

    def test_progress_lines_and_unprefixed_record(self):
        output = 'height=1000 elapsed=1s\nBENCH {"commits": 10000}\nLOAD_SECONDS 1\nAPPLY_SECONDS 2\nCOMMIT_SECONDS 3\n'
        self.assertEqual(BENCHMARK.parse_sample(output)["commits"], 10000)

    def test_copied_base_is_flushed_before_returning(self):
        with tempfile.TemporaryDirectory(dir=BENCHMARK.TARGET) as directory:
            base = Path(directory) / "base.redb"
            copied = Path(directory) / "copy.redb"
            base.write_bytes(b"completed checkpoint")
            observed = []
            def flushed(fd):
                observed.append(os.read(fd, 1024))
            with patch.object(BENCHMARK.os, "fsync", side_effect=flushed):
                BENCHMARK.copy_base(base, copied)
            self.assertEqual(observed, [base.read_bytes()])
            self.assertEqual(copied.read_bytes(), base.read_bytes())

    def test_missing_or_duplicate_records_fail(self):
        for output in ['', 'BENCH {}\nBENCH {}\n', 'BENCH {}\nLOAD_SECONDS 1\nAPPLY_SECONDS 2\n']:
            with self.assertRaises(ValueError):
                BENCHMARK.parse_sample(output)


if __name__ == "__main__":
    unittest.main()
