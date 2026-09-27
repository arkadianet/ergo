"""Offline verdict regressions: python3 verdict_self_test.py --self-test."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import campaign
import lifecycle
import smoke
from scenarios import common, fork, miner_self_reject, reconstruct_rate
from relay_self_test import RelayTests
from relay_classification_self_test import ClassificationTests


# ----- helpers -----
class WindowClosed(Exception):
    pass


def context(blocks=2):
    ctx = SimpleNamespace(
        args=SimpleNamespace(ordering_blocks=blocks), roles={}, evidence={},
        run=SimpleNamespace(series=[], deadline=time.monotonic() + 60,
                            idle=Mock()), fail=Mock())
    ctx.note = lambda key, value: ctx.evidence.update({key: value})
    return ctx


@contextlib.contextmanager
def scenario_io(ctx, heights):
    with contextlib.ExitStack() as stack:
        for name, value in [('fund_miner', (100, 'address')),
                            ('fan_out', list(range(30))),
                            ('wait_ordering_blocks', None),
                            ('seed_second_miner', None),
                            ('scala_reference_nodes', (['scala'], [])),
                            ('_scala_log_lines', [])]:
            stack.enter_context(patch.object(common, name, return_value=value))
        stack.enter_context(patch.object(common, 'api', return_value={'events': []}))
        stack.enter_context(patch.object(smoke, 'scala_height', side_effect=heights))
        stack.enter_context(patch.object(smoke, 'api', return_value={}))
        stack.enter_context(patch.object(smoke, 'assertion_1_peering'))
        stack.enter_context(patch.object(campaign, 'drain_utxo_watch'))
        stack.enter_context(patch.object(reconstruct_rate, '_follower_peered_with_miner'))
        yield stack


class ReviewTests(unittest.TestCase):
    # ----- happy path -----
    def test_spawn_append_log_ignores_previous_fatal(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            log = work / 'rust.log'
            old = 'Failed to initialize storage: old launch\nUTF8: é\n'
            log.write_text(old)
            response = io.StringIO(json.dumps({'stateRoot': lifecycle.GENESIS_STATE_ROOT}))
            with patch.object(lifecycle, 'WORK', work), \
                    patch.object(lifecycle, '_command', return_value=['unused']), \
                    patch.object(lifecycle, '_config_path', return_value='unused'), \
                    patch.object(lifecycle.subprocess, 'Popen', return_value=SimpleNamespace(pid=123)), \
                    patch.object(lifecycle.urllib.request, 'urlopen', side_effect=[OSError(), response]), \
                    patch.object(lifecycle.time, 'sleep'):
                lifecycle.spawn('rust')
            self.assertEqual(log.read_text(), old)

    def test_fork_target_height_does_not_pump(self):
        ctx = context()
        with scenario_io(ctx, [10, 11, 12]), \
                patch.object(common, 'pump_payments_to_all') as pump, \
                patch.object(common, 'close_measurement_window', side_effect=WindowClosed):
            with self.assertRaises(WindowClosed):
                fork.run(ctx)
        self.assertEqual(pump.call_count, 2)

    def test_payment_replaced_pool_box_keeps_complete_batch(self):
        sent, refused = [], []
        replies = [(404, {}), (200, {'bytes': 'raw'}),
                   (200, {'id': 'tx'}), (200, {}), (200, {})]
        with patch.object(common, '_post', side_effect=replies):
            common.pump_payments_to_all(context(), 'address', sent,
                                       ('scala', 'scala2'), count=1,
                                       rejected=refused, pool=['gone', 'available'])
        self.assertEqual(sent, ['tx'])
        self.assertEqual(len(refused), 1)

    def test_window_interior_failed_poll_recovered_is_accepted(self):
        ctx = context()
        collector = common.EventCollector(ctx)
        with patch.object(collector, '_fetch_page', side_effect=[[], smoke.Unavailable('down'), []]):
            common.open_measurement_window(ctx, collector)
            collector.poll()
            common.close_measurement_window(ctx)
        ctx.fail.assert_not_called()

    # ----- round-trips -----
    def test_settle_committed_confirmation_survives_final_evaluation(self):
        series = [{'ordering': 'O', 'scala_chain': ['A'], 'rust_chain': ['A'],
                   'scala_tip': 'A', 'rust_tip': 'A', 'at': 0}] * smoke.MIN_QUALIFYING_SAMPLES
        series += [{'ordering': 'O', 'scala_chain': ['A'], 'rust_chain': ['T', 'A'],
                    'scala_tip': 'A', 'rust_tip': 'T', 'at': 1}]
        run = SimpleNamespace(series=series, propagation_lags=[])
        def transport(node, path):
            if path == '/blocks/bestInputChain':
                return {'bestOrdering': 'NEXT'}
            return {'header': {'parentId': 'O'}, 'extension': {'fields': [['0302', 'T']]}}
        with patch.object(smoke, 'api', side_effect=transport):
            result = smoke.settle_unconfirmed_chain_tips(run, set())
        kwargs = {'confirmed_committed': result['confirmed_committed']}
        chain = smoke.evaluate_chain_consistency(run.series, **kwargs)
        tip = smoke.evaluate_tip_consistency(run.series, **kwargs)
        self.assertEqual((chain['prefix_violation_count'], tip['unconfirmed_count']), (0, 0),
                         (chain, tip))
        self.assertFalse(chain['violations'])
        self.assertFalse(tip['violations'])
        self.assertEqual(len(run.series), smoke.MIN_QUALIFYING_SAMPLES + 1)
        run.unavailable_samples = 0
        run.series_path = smoke.WORK / 'test-series.jsonl'
        run.live_artifact_paths = []
        run.failures = []
        run.fail = Mock()
        evidence = {}
        with patch.object(smoke, 'api', side_effect=transport), \
                patch.object(smoke, 'scala_log_lines', return_value=[]), \
                patch.object(smoke, 'mined_log_plausible', return_value=True):
            smoke.finalize_agreement(run, evidence)
        run.fail.assert_not_called()
        self.assertEqual(evidence['2_best_input_block']['result'], 'PASS')
        self.assertEqual(evidence['3_best_input_chain']['result'], 'PASS')
        self.assertEqual(evidence['3_best_input_chain']['allowed_prefix_by_one_count'], 1)
        self.assertEqual(evidence['3_best_input_chain']['not_measured_tail_count'], 0)

    # ----- error paths -----
    def test_spawn_current_launch_fatal_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            def launch(*args, **kwargs):
                kwargs['stdout'].write('Failed to initialize storage: current launch\n')
                return SimpleNamespace(pid=123)
            with patch.object(lifecycle, 'WORK', work), \
                    patch.object(lifecycle, '_command', return_value=['unused']), \
                    patch.object(lifecycle, '_config_path', return_value='unused'), \
                    patch.object(lifecycle.subprocess, 'Popen', side_effect=launch), \
                    patch.object(lifecycle.urllib.request, 'urlopen', side_effect=OSError()):
                with self.assertRaisesRegex(RuntimeError, 'current launch'):
                    lifecycle.spawn('rust')

    def test_window_boundary_failed_poll_is_rejected(self):
        for boundary in ('open', 'close'):
            with self.subTest(boundary=boundary):
                ctx = context()
                collector = common.EventCollector(ctx)
                pages = [smoke.Unavailable('down'), []] if boundary == 'open' else [[], smoke.Unavailable('down')]
                with patch.object(collector, '_fetch_page', side_effect=pages):
                    common.open_measurement_window(ctx, collector)
                    common.close_measurement_window(ctx)
                self.assertEqual(ctx.fail.call_count, 1)

    def test_settle_many_repeated_candidates_checks_each_key_once(self):
        series = [{'ordering': 'bad', 'scala_chain': ['X'], 'rust_chain': ['Y']}] * 10
        for i in range(12):
            series += [{'ordering': f'O{i}', 'scala_chain': [], 'rust_chain': [f'T{i}']}] * 3
        run = SimpleNamespace(series=series, propagation_lags=[])
        with patch.object(smoke, 'api', side_effect=smoke.Unavailable('down')) as api:
            result = smoke.settle_unconfirmed_chain_tips(run, set())
        self.assertEqual(result['checked'], 12)
        self.assertEqual(api.call_count, 12)
        self.assertEqual(len(result['unreachable']), 12)

    def test_committed_allowance_other_history_still_fails(self):
        sample = {'ordering': 'O', 'scala_chain': ['X'], 'rust_chain': ['T', 'Y'], 'rust_tip': 'U'}
        allowance = {('O', 'T')}
        self.assertEqual(smoke.evaluate_chain_consistency(
            [sample], confirmed_committed=allowance)['prefix_violation_count'], 1)
        self.assertEqual(smoke.evaluate_tip_consistency(
            [sample], confirmed_committed=allowance)['unconfirmed_count'], 1)
        wrong_ordering = {'ordering': 'OTHER', 'scala_chain': [],
                          'rust_chain': ['T'], 'rust_tip': 'T'}
        self.assertEqual(smoke.evaluate_chain_consistency(
            [wrong_ordering], confirmed_committed=allowance)['prefix_violation_count'], 1)
        self.assertEqual(smoke.evaluate_tip_consistency(
            [wrong_ordering], confirmed_committed=allowance)['unconfirmed_count'], 1)

    def test_committed_confirmation_without_coverage_still_fails(self):
        sample = {'ordering': 'O', 'scala_chain': [], 'rust_chain': ['T'], 'rust_tip': 'T'}
        tip = smoke.evaluate_tip_consistency([sample], confirmed_committed={('O', 'T')})
        chain = smoke.evaluate_chain_consistency([sample], confirmed_committed={('O', 'T')})
        self.assertEqual(tip['lag_samples'], 0)
        self.assertTrue(tip['violations'])
        self.assertTrue(chain['violations'])

    def test_reconstruction_known_before_counts_in_denominator(self):
        ctx = context(blocks=3)
        ctx.roles = {'scala': 'scala_miner'}
        events = [{'seq': 1, 'kind': 'ordering_reconstructed', 'headerId': 'h11'}]
        def transport(node, path):
            if path == '/info':
                return {'fullHeight': 13}
            return ['h' + path.rsplit('/', 1)[-1]]
        with scenario_io(ctx, [10, 13]), \
                patch.object(reconstruct_rate, 'api', side_effect=transport), \
                patch.object(common.EventCollector, 'window', return_value=events), \
                patch.object(common, 'announced_headers', return_value={'h11', 'h12'}), \
                patch.object(common, 'header_known_first', return_value={'h12'}), \
                patch.object(common, 'pump_payments'), \
                patch.object(reconstruct_rate, '_scala_log_counts', side_effect=WindowClosed):
            with self.assertRaises(WindowClosed):
                reconstruct_rate.run(ctx)
        self.assertEqual(ctx.evidence['rust_outcomes']['reconstructed_over_all_blocks'], 0.3333)

    def test_payment_windows_target_height_does_not_pump(self):
        for module in (reconstruct_rate, miner_self_reject):
            with self.subTest(scenario=module.__name__):
                ctx = context()
                with scenario_io(ctx, [10, 11, 12]), \
                        patch.object(module, 'api', return_value={'fullHeight': 12}), \
                        patch.object(common, 'pump_payments') as pump, \
                        patch.object(common, 'close_measurement_window', side_effect=WindowClosed):
                    with self.assertRaises(WindowClosed):
                        module.run(ctx)
                self.assertEqual(pump.call_count, 1)

    def test_wait_target_height_does_not_pump(self):
        ctx, pump = context(), Mock()
        with patch.object(smoke, 'scala_height', side_effect=[10, 11, 12]), \
                patch.object(campaign, 'drain_utxo_watch'):
            common.wait_ordering_blocks(ctx, 2, 'window', on_block=pump)
        self.assertEqual(pump.call_count, 1)

    # ----- oracle parity -----
    # These tests exercise harness judgments; they do not execute a Scala node.


if __name__ == '__main__':
    import sys
    unittest.main(argv=[sys.argv[0]] + [arg for arg in sys.argv[1:] if arg != '--self-test'])
