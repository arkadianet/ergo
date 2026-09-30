"""Offline #2597 acceptance metrics from captured A1 lines and controlled omissions."""
import json
from pathlib import Path
import tempfile
import unittest

import relay_acceptance as acceptance
import relay_measurement as relay
from relay_rescore import rescore

FIXTURE = Path(__file__).with_name('fixtures') / 'relay-acceptance.json'


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads(FIXTURE.read_text())
        self.lines = {n: [r['text'] for r in rows] for n, rows in self.fixture['source_lines'].items()}
        self.intervals = {25: {'a', 'b'}, 26: set(), 27: {'c'}}
        self.result = {'window': self.fixture['window'], 'M3': {}}

    def metrics(self, steady=None):
        return acceptance.acceptance_metrics(self.lines, self.intervals, self.result, steady)

    def test_m4_verbatim_receipts_are_unique_and_relative_to_miner_apply(self):
        metric = self.metrics()['M4']['scala2']
        self.assertEqual((metric['mined'], metric['received'], metric['never_observed']), (3, 3, 0))
        self.assertEqual(metric['per_interval'], {str(h): {'mined': 1, 'received': 1} for h in self.intervals})
        for block, gap in zip(metric['blocks'], (-.003, -.005, -.018)):
            self.assertAlmostEqual(block['receipt_minus_miner_apply_seconds'], gap, places=3)
            line = self.lines['scala2'][block['announcement']['source_line'] - 1]
            self.assertIn(block['id'], line)
            self.assertIn('ErgoNodeViewSynchronizer - Processing', line)
        self.lines['scala2'] *= 2
        self.assertEqual(metric, self.metrics()['M4']['scala2'])
        bid = metric['blocks'][0]['id']
        self.lines['scala2'] = [l.rsplit(' | relay_ts=', 1)[0] + ' | relay_ts=2026-09-27T18:48:21.890Z'
                                if bid in l and acceptance.ANNOUNCEMENT.search(l) else l
                                for l in self.lines['scala2']]
        self.assertEqual(self.metrics()['M4']['scala2']['blocks'][0]['receipt_minus_miner_apply_seconds'], .007)

    def test_m4_header_and_application_do_not_prove_announcement_receipt(self):
        bid = self.metrics()['M4']['scala3']['blocks'][1]['id']
        self.lines['scala3'] = [l for l in self.lines['scala3']
                                if not (bid in l and acceptance.ANNOUNCEMENT.search(l))]
        # The holder's similarly worded processing line remains, as do header
        # and full-block application. A height-only gap log cannot name an ID.
        self.lines['scala3'].append('DEBUG x - Ignoring ordering block announcement at height 27, '
                                    'our full block height is 24 (gap > 2 blocks)')
        metric = self.metrics()['M4']['scala3']
        self.assertEqual((metric['received'], metric['never_observed']), (2, 1))
        self.assertEqual(metric['missing_ids'], [bid])
        self.assertEqual((metric['header_without_announcement'], metric['applied_without_announcement']), (1, 1))
        self.assertFalse(metric['receipt_logging_complete'])
        self.assertIsNone(metric['never_received'])

    def test_m4_cutoffs_missing_apply_and_terminal_mining(self):
        original = self.metrics()['M4']['scala2']
        bid = original['blocks'][0]['id']
        self.lines['scala'] = [l for l in self.lines['scala'] if not (bid in l and acceptance.APPLIED.search(l))]
        metric = self.metrics()['M4']['scala2']
        self.assertEqual(metric['mined'], 3)  # mining, not application, is the denominator
        self.assertIsNone(metric['blocks'][0]['miner_apply'])
        self.assertIsNone(metric['blocks'][0]['receipt_minus_miner_apply_seconds'])
        self.result['window'] = dict(self.result['window'], receipt_cutoff=original['blocks'][1]['mined_at'])
        self.assertGreater(self.metrics()['M4']['scala2']['never_observed'], 0)
        empty = acceptance.ordering_coverage({}, acceptance.follower_observations([], self.result['window']), {})
        self.assertEqual(empty['mined'], 0)

    def test_m5_verbatim_all_directed_links_and_m3_event_reuse(self):
        existing = dict(relay.peer_traffic(self.lines['scala3'], self.lines['scala'],
                                          self.result['window']['boundaries']), receiver='scala')
        self.result['M3']['scala3'] = existing
        metrics = self.metrics()['M5']
        self.assertEqual(len(metrics), 6)
        link = metrics['scala3->scala']
        self.assertEqual((link['messages'], link['gap_pairs'], link['pairs_below_250ms']), (5, 4, 0))
        self.assertEqual(link['messages_per_ordering_interval'], 5 / 3)
        self.assertEqual(link['messages_per_input_block'], 5 / 3)
        self.assertEqual(link['min_gap_seconds'], .266)
        self.assertEqual(link['per_interval']['26']['messages'], 2)
        self.assertIsNone(link['per_interval']['26']['messages_per_input_block'])
        self.assertEqual(metrics['scala->scala2']['pairs_below_250ms'], 1)
        self.assertEqual(existing['messages'], 5)  # M3 wasn't mutated

    def test_m5_threshold_percentiles_boundaries_and_input_normalization(self):
        event = relay.sync_received(self.lines['scala'])[0]
        start = event['at']
        # 100 adjacent gaps: 0ms, exactly 250ms, then 98 one-second gaps.
        times = [start, start, start + .250] + [start + .250 + i for i in range(1, 99)]
        events = [dict(event, at=t) for t in [start - 1, *times, start + 100]]
        boundaries = [start, start + 50, start + 100]
        metric = relay.traffic(events, None, boundaries)
        metric.update(receiver_events=events, available=True)
        intervals = {1: set(), 2: {'a', 'b'}}
        density = acceptance.sync_density(metric, intervals, boundaries)
        self.assertEqual((density['messages'], density['gap_pairs'], density['pairs_below_250ms']), (101, 100, 1))
        self.assertEqual((density['min_gap_seconds'], density['p1_gap_seconds'], density['p5_gap_seconds']), (0, 0, 1))
        self.assertEqual(density['messages_per_input_block'], 50.5)
        more_inputs = acceptance.sync_density(metric, {1: set(), 2: set('abcdef')}, boundaries)
        self.assertEqual(more_inputs['messages'], density['messages'])
        self.assertEqual(more_inputs['messages_per_input_block'], 101 / 6)
        empty = acceptance.sync_density({}, {}, [start])
        self.assertFalse(empty['available'])
        self.assertIsNone(empty['p1_gap_seconds'])
        self.assertIsNone(empty['messages_per_input_block'])

    def test_reconstruction_decisions_and_archived_scenario_scope(self):
        steady = {'roles': {'scala2': 'scala_follower'}, 'reconstruction_accounting': {
            'scala_follower': {'reconstructed': 24, 'download_missing_tx': 0,
                               'download_root_mismatch': 51, 'download_no_prev_input_block': 6}}}
        metric = self.metrics(steady)['reconstruction']['scala2']
        self.assertEqual((metric['rebuilt'], metric['full_download_requested'], metric['without_decision']), (1, 2, 0))
        self.assertEqual(metric['archived_steady']['reconstructed'], 24)
        self.assertEqual(metric['archived_steady']['download_root_mismatch'], 51)
        self.lines['scala2'] *= 2
        self.assertEqual(metric, self.metrics(steady)['reconstruction']['scala2'])
        # The synchronizer also requests a full download before reaching the
        # holder when the last input block is unavailable.
        self.lines['scala2'] = [l.replace('Downloading block transactions fully for ',
                                         'Requesting all the block transactions for ')
                                for l in self.lines['scala2']]
        self.assertEqual(metric, self.metrics(steady)['reconstruction']['scala2'])
        self.lines['scala2'] = [l for l in self.lines['scala2'] if not acceptance.DOWNLOAD.search(l)]
        self.assertEqual(self.metrics()['reconstruction']['scala2']['without_decision'], 2)

    def test_rescore_inline_and_sidecar_compute_identical_new_metrics(self):
        saved = dict(self.result, source_lines=self.lines,
                     M1={'scala2': relay.coverage(self.intervals, set()), 'scala3': relay.coverage(self.intervals, set())},
                     M2={n: {'raw_samples': []} for n in ('scala2', 'scala3')})
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / 'steady.json').write_text(json.dumps({'relay_refresh': saved}))
            inline = rescore(root)
            saved.pop('source_lines')
            saved['source_line_files'] = {}
            for node, lines in self.lines.items():
                path = root / f'{node}.jsonl'
                path.write_text(''.join(json.dumps(l) + '\n' for l in lines))
                saved['source_line_files'][node] = {'path': path.name, 'line_count': len(lines)}
            (root / 'steady.json').write_text(json.dumps({'relay_refresh': saved}))
            sidecar = rescore(root)
            for key in ('M4', 'M5', 'reconstruction'):
                self.assertEqual(inline[key], sidecar[key])
            self.assertEqual(sidecar['M4']['scala2']['received'], 3)
            self.assertEqual(sidecar['M5']['scala3->scala']['messages'], 5)


if __name__ == '__main__':
    unittest.main()
