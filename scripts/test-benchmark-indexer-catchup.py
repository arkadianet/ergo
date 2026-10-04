#!/usr/bin/env python3
"""Regression coverage for Rust test-harness prefixes on benchmark output."""

import importlib.util
from pathlib import Path
import unittest

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

    def test_missing_or_duplicate_records_fail(self):
        for output in ['', 'BENCH {}\nBENCH {}\n', 'BENCH {}\nLOAD_SECONDS 1\nAPPLY_SECONDS 2\n']:
            with self.assertRaises(ValueError):
                BENCHMARK.parse_sample(output)


if __name__ == "__main__":
    unittest.main()
