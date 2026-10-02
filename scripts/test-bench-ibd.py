#!/usr/bin/env python3
"""Safety and matching contracts for the offline replay runner."""
import argparse
import fcntl
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('bench_ibd', Path(__file__).with_name('bench-ibd.py'))
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


class ReplayRunnerTest(unittest.TestCase):
    def test_locked_snapshot_refuses_an_open_database(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.redb'
            path.write_bytes(b'closed snapshot')
            with path.open('rb') as owner:
                fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError):
                    with BENCH.locked_snapshot(path):
                        self.fail('must not copy a database owned by a node')
            self.assertEqual(path.read_bytes(), b'closed snapshot')

    def test_locked_snapshot_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.redb'
            path.write_bytes(b'closed snapshot')
            alias = Path(directory) / 'alias.redb'
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                with BENCH.locked_snapshot(alias):
                    self.fail('symlink must be refused')

    def test_profile_accepts_explicit_disabled_cache_and_rejects_unsafe_names(self):
        self.assertEqual(BENCH.profile('small:16:1'), ('small', 16 * 1024**2, 1024**2))
        self.assertEqual(BENCH.profile('disabled:0:0'), ('disabled', 0, 0))
        for bad in ['../../escape:1:1', 'neg:-1:1', 'missing:1', 'a:1:x']:
            with self.assertRaises(argparse.ArgumentTypeError):
                BENCH.profile(bad)

    def fixture(self, directory, behavior='valid'):
        directory = Path(directory)
        snapshot = directory / 'snapshot.redb'
        snapshot.write_bytes(b'closed snapshot')
        binary = directory / 'binary'
        binary.write_text('''#!/usr/bin/env python3
import csv, json, os, pathlib, sys, time
args = sys.argv
value = lambda key: args[args.index(key) + 1]
if BEHAVIOR == 'timeout': time.sleep(10)
path = pathlib.Path(args[2])
assert (path / '.ergo-replay-copy').read_text() == 'disposable ergo replay copy\\n'
assert (path / 'state.redb').read_bytes() == b'closed snapshot'
with open(os.environ['ERGO_MEM_CSV'], 'w') as stream:
    writer = csv.writer(stream)
    writer.writerow(['sync_phase', 'vm_rss_kb', 'rss_anon_kb', 'avl_cache_clean_bytes', 'redb_state_evictions'])
    writer.writerow(['Retained', 123, 100, 42, 2])
print(json.dumps(dict(start_height=850, end_height=1000, root='different' if BEHAVIOR == 'different' and value('--avl-cache-bytes') == '2097152' else 'pinned', restart_verified=BEHAVIOR != 'no_reopen',
    avl_cache_bytes=int(value('--avl-cache-bytes')), redb_cache_bytes=int(value('--redb-cache-bytes')),
    committed_seconds=.1, durable_seconds=.6, committed_blocks_per_second=1500, durable_blocks_per_second=250,
    persist_channel_observed_peak_jobs=1, unpersisted_pinned_observed_peak_bytes=12, phases_ms={'validation':10})))
'''.replace('BEHAVIOR', repr(behavior)))
        binary.chmod(0o700)
        return argparse.Namespace(binary=binary, source_commit='a' * 40, baseline_binary=None,
                                  baseline_source_commit=None, snapshot=snapshot, snapshot_sha256=BENCH.sha(snapshot),
                                  output_dir=directory / 'output', runs=2, profile=[BENCH.profile('one:1:1'), BENCH.profile('two:2:2')],
                                  blocks=150, proof_policy='regenerate', persist_jobs=64, flush_interval=500,
                                  retained_seconds=1, timeout_seconds=5)

    def test_profiles_rotate_and_preserve_source_and_raw_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            summary = BENCH.run(args)
            self.assertEqual([r['profile'] for r in summary['records']], ['one', 'two', 'two', 'one'])
            self.assertEqual(summary['medians']['one/candidate']['retained_rss_kib'], 123)
            self.assertEqual(args.snapshot.read_bytes(), b'closed snapshot')
            self.assertTrue((args.output_dir / 'run-1-one-candidate.stdout').is_file())
            self.assertFalse(any(args.output_dir.glob('owned-replay-*')))
            with self.assertRaisesRegex(RuntimeError, 'directory must be new'):
                BENCH.run(args)

    def test_wrong_hash_refuses_output_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            args.snapshot_sha256 = '0' * 64
            with self.assertRaisesRegex(RuntimeError, 'pinned SHA-256'):
                BENCH.run(args)
            self.assertFalse(args.output_dir.exists())

    def test_reopen_failure_and_root_mismatch_are_not_successes(self):
        for behavior, message in [('no_reopen', 'clean reopen'), ('different', 'roots differ')]:
            with self.subTest(behavior=behavior), tempfile.TemporaryDirectory() as directory:
                args = self.fixture(directory, behavior)
                with self.assertRaisesRegex(RuntimeError, message):
                    BENCH.run(args)
                self.assertFalse((args.output_dir / 'summary.json').exists())
                self.assertEqual(args.snapshot.read_bytes(), b'closed snapshot')

    def test_timeout_cleans_only_owned_scratch_and_retains_failure_output(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory, 'timeout')
            args.timeout_seconds = .05
            with self.assertRaisesRegex(RuntimeError, 'timeout'):
                BENCH.run(args)
            self.assertFalse(any(args.output_dir.glob('owned-replay-*')))
            self.assertTrue((args.output_dir / 'run-1-one-candidate.stderr').is_file())
            self.assertEqual(args.snapshot.read_bytes(), b'closed snapshot')


if __name__ == '__main__':
    unittest.main()
