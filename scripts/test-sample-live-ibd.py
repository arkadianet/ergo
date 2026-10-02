#!/usr/bin/env python3
"""Throughput and adjacent-sample validation for the live IBD sampler."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('sample_live_ibd', Path(__file__).with_name('sample-live-ibd.py'))
SAMPLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SAMPLER)


class LiveSamplerTest(unittest.TestCase):
    def observe(self, heights, roots=None, elapsed=None):
        roots = roots if roots is not None else ['root'] * len(heights)
        elapsed = elapsed if elapsed is not None else list(range(1, len(heights) + 1))
        infos = iter({'fullHeight': height, 'headersHeight': 100, 'stateRoot': root}
                     for height, root in zip(heights, roots))

        def fetch(url, endpoint):
            if endpoint == '/info':
                return json.dumps(next(infos))
            if endpoint == '/api/v1/sync':
                return json.dumps({'pending_blocks': 2})
            if endpoint == '/metrics':
                return 'ergo_node_last_apply_duration_ms 3\n'
            self.fail(f'unexpected endpoint: {endpoint}')

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            proc = base / 'proc' / '123'
            proc.mkdir(parents=True)
            (proc / 'exe').write_bytes(b'node executable')
            (proc / 'stat').write_text('123 (node) ' + ' '.join(['0'] * 19 + ['42']))
            (proc / 'status').write_text('VmRSS: 100 kB\nRssAnon: 80 kB\nRssFile: 20 kB\n')
            (proc / 'smaps_rollup').write_text('Rss: 100 kB\nPss: 90 kB\n')
            (proc / 'smaps').write_text('1000-2000 rw-p 00000000 00:00 0 [heap]\nSize: 4 kB\nRss: 4 kB\n')
            output = base / 'results'
            argv = ['sample-live-ibd.py', '--url', 'http://sampler.test', '--pid', '123',
                    '--output-dir', str(output), '--duration', str(elapsed[-1]), '--interval', '1']
            stdout = io.StringIO()
            with patch.object(SAMPLER, 'Path', side_effect=lambda path: base / 'proc' if path == '/proc' else Path(path)), \
                    patch.object(SAMPLER, 'fetch', side_effect=fetch), \
                    patch.object(SAMPLER.time, 'monotonic', side_effect=[0] + elapsed), \
                    patch.object(SAMPLER.time, 'sleep'), \
                    patch('sys.argv', argv), contextlib.redirect_stdout(stdout):
                SAMPLER.main()
            summary = json.loads((output / 'summary.json').read_text())
            self.assertEqual(json.loads(stdout.getvalue()), summary)
            samples = [json.loads(line) for line in (output / 'samples.jsonl').read_text().splitlines()]
            self.assertEqual([row['full_height'] for row in samples], heights)
            self.assertEqual(summary['sample_count'], len(heights))
            self.assertEqual(summary['rss_sampled_peak_kib'], 100)
            return summary

    def test_throughput_starts_at_first_non_null_height(self):
        summary = self.observe([None, None, 100, 120], elapsed=[1, 2, 4, 9])
        self.assertEqual(summary['start_height'], 100)
        self.assertEqual(summary['end_height'], 120)
        self.assertEqual(summary['duration_seconds'], 8)
        self.assertEqual(summary['throughput_duration_seconds'], 5)
        self.assertEqual(summary['blocks_per_second'], 4)

    def test_no_usable_heights_still_writes_summary(self):
        summary = self.observe([None, None])
        self.assertIsNone(summary['start_height'])
        self.assertIsNone(summary['end_height'])
        self.assertIsNone(summary['blocks_per_second'])
        self.assertIsNone(summary['throughput_duration_seconds'])
        self.assertEqual(summary['throughput_status'], 'no usable height samples')

    def test_single_usable_height_reports_unavailable_throughput(self):
        summary = self.observe([None, 0, None])
        self.assertEqual(summary['start_height'], 0)
        self.assertEqual(summary['end_height'], 0)
        self.assertIsNone(summary['blocks_per_second'])
        self.assertEqual(summary['throughput_status'], 'need at least two distinct usable height samples')

    def test_trailing_null_height_uses_last_usable_sample(self):
        summary = self.observe([0, 10, None], elapsed=[1, 3, 10])
        self.assertEqual(summary['start_height'], 0)
        self.assertEqual(summary['end_height'], 10)
        self.assertEqual(summary['throughput_duration_seconds'], 2)
        self.assertEqual(summary['blocks_per_second'], 5)

    def test_adjacent_equal_heights_with_different_roots_reject_window(self):
        with self.assertRaisesRegex(RuntimeError, 'reorg in interval'):
            self.observe([10, 10], roots=['root-a', 'root-b'])

    def test_decreasing_heights_reject_window(self):
        for heights in ([10, 9], [10, 12, 11]):
            with self.subTest(heights=heights), self.assertRaisesRegex(RuntimeError, 'reorg in interval'):
                self.observe(heights)

    def test_increasing_heights_can_have_different_roots(self):
        summary = self.observe([10, 12, 12, 14], roots=['root-a', 'root-b', 'root-b', 'root-c'])
        self.assertEqual(summary['blocks_per_second'], 4 / 3)

    def test_null_gap_does_not_trigger_non_adjacent_root_comparison(self):
        summary = self.observe([10, None, 10], roots=['root-a', None, 'root-b'])
        self.assertEqual(summary['blocks_per_second'], 0)

    def test_unchanged_height_and_root_reports_zero_throughput(self):
        summary = self.observe([10, 10])
        self.assertEqual(summary['blocks_per_second'], 0)
        self.assertEqual(summary['throughput_status'], 'available')


if __name__ == '__main__':
    unittest.main()
