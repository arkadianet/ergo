"""Captured relay regression: smoke 2026-09-27, three completed measurement intervals."""
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

import relay_measurement as relay

FIXTURES = Path(__file__).with_name('fixtures')
START = 1790532377.0621312
END = 1790532474.795


def logs(node):
    return (FIXTURES / f'relay-{node}.log').read_text().splitlines(keepends=True)


class RelayTests(unittest.TestCase):
    # ----- helpers -----
    def collect(self, mode=None):
        import lifecycle
        nodes = ('scala', 'scala2', 'scala3', 'rust')
        samples = json.loads((FIXTURES / 'relay-samples.json').read_text())
        with tempfile.TemporaryDirectory() as raw, patch.object(relay.smoke, 'WORK', Path(raw)), patch.object(lifecycle, 'NODES', nodes):
            for node in nodes[:-1]:
                (Path(raw) / f'{node}.log').touch()
            with patch.object(relay.time, 'time', return_value=START):
                measurement = relay.Measurement(20)
            for node in nodes[:-1]:
                (Path(raw) / f'{node}.log').write_text(''.join(logs(node)))
            miner_reads = iter((20, 21))
            def api(node, path, **kwargs):
                if mode == 'offline':
                    raise relay.smoke.Unavailable('offline')
                if mode == 'moving' and node == 'scala' and path == '/info':
                    return {'fullHeight': next(miner_reads)}
                if path == '/peers/syncInfo':
                    return samples['scala2'][0]['raw_statuses']
                return {'fullHeight': 20}
            with patch.object(relay.smoke, 'api', side_effect=api), patch.object(relay.smoke, 'request', return_value=(200, [])), patch.object(relay.time, 'time', return_value=START + 1):
                return measurement.finish()

    # ----- happy path -----
    def test_m1_captured_interval_receipts_match(self):
        result = self.collect()
        self.assertEqual(result['window']['boundaries'], [START, 1790532392.298, 1790532409.300, END])
        mined = relay.smoke.mined_input_blocks([s for s in logs('scala') if relay.timestamp(s) < END])
        self.assertEqual(len(mined), 6)
        self.assertEqual(len(relay.smoke.mined_input_blocks(logs('scala'))), 8)
        for node in ('scala2', 'scala3'):
            received = relay.scala_received(logs(node))
            self.assertEqual(result['M1'][node]['mined'], len(mined))
            self.assertEqual(result['M1'][node]['received_ids'], sorted(mined & received))
            self.assertEqual(result['M1'][node]['received'], 6)
            self.assertEqual(relay.scala_received(logs(node) * 2), received)
        self.assertEqual(result['M1']['rust']['received'], len(mined))
        intervals, _ = relay.miner_window(logs('scala'), 20, START)
        partial = relay.coverage(dict(intervals, empty=set()), intervals[20])
        self.assertEqual((partial['received'], partial['never_observed'], partial['zero_receipt_intervals']), (2, 4, 2))
        self.assertEqual(partial['nonempty_intervals'], 3)

    def test_m2_captured_scala_statuses_survive_window_cutoff(self):
        result = self.collect()
        for node in ('scala2', 'scala3'):
            self.assertEqual(result['M2'][node]['samples'], 1)
            self.assertEqual(result['M2'][node]['share'], 0)
        self.assertEqual(result['M2']['rust']['samples'], 0)
        for mode in ('moving', 'offline'):
            self.assertEqual(self.collect(mode)['M2']['scala2']['samples'], 0)
        rows = json.loads((FIXTURES / 'relay-stale.json').read_text())
        metric = relay.staleness(rows)
        self.assertEqual((metric['samples'], metric['stale_samples'], metric['share']), (7, 7, 1))
        self.assertAlmostEqual(metric['longest_stretch_seconds'], 6.206458, places=5)
        # Perturb a captured sample to exercise unknown and genuinely far peers.
        for middle in (dict(rows[3], tracked=None), dict(rows[3], actual=rows[3]['miner'] - 3)):
            broken = relay.staleness(rows[:3] + [middle] + rows[4:])
            self.assertAlmostEqual(broken['longest_stretch_seconds'], 2.1250455, places=5)

    def test_m3_captured_socket_pairs_have_counts_and_gaps(self):
        empty = relay.peer_traffic(logs('scala2'), logs('scala'), [START])
        self.assertFalse(empty['available'])
        result = self.collect()
        for node in ('scala', 'scala2', 'scala3'):
            metric = result['M3'][node]
            self.assertEqual(metric['per_interval'], [0, 2, 2] if node == 'scala3' else [0, 1, 1])
            self.assertEqual(metric['mean_per_block'], metric['messages'] / 3)
            self.assertEqual(metric['max_per_block'], max(metric['per_interval']))
            self.assertAlmostEqual(metric['min_gap_seconds'], 4.607 if node == 'scala3' else 60.181, places=3)
        event = relay.sync_received(logs('scala'))[0]
        with self.assertRaises(ValueError):
            relay.sync_received([event['line'].split(' | relay_ts=')[0]])
        self.assertEqual(relay.traffic([event], event['host'], [event['at'], event['at'] + 1], event['port'])['messages'], 1)
        self.assertEqual(relay.traffic([event], event['host'], [event['at'] - 1, event['at']], event['port'])['messages'], 0)
        self.assertEqual(relay.traffic([event], event['host'], [event['at'], event['at'] + 1], event['port'] + 1)['messages'], 0)
        self.assertIsNone(empty['mean_per_block'])


    def test_logback_receiver_and_receipt_logging_enabled(self):
        from pathlib import Path
        config = relay.logback(Path(relay.__file__).with_name('logback.xml').read_text())
        self.assertIn('relay_ts=', config)
        self.assertIn('name="scorex.core.network.PeerConnectionHandler" level="DEBUG"', config)
        self.assertIn('name="org.ergoplatform.nodeView.history.ErgoHistory" level="DEBUG"', config)

    def test_rust_api_empty_block_is_receipt(self):
        with patch.object(relay.smoke, 'request', return_value=(200, [])):
            self.assertTrue(relay.rust_receipt('a' * 64))

    def test_rust_api_not_found_is_absence(self):
        error = urllib.error.HTTPError('url', 404, 'missing', {}, None)
        with patch.object(error, 'close', wraps=error.close) as close, patch.object(relay.smoke, 'request', side_effect=error):
            self.assertFalse(relay.rust_receipt('a' * 64))
            close.assert_called_once()

    def test_rust_api_failed_read_is_not_absence(self):
        for response in [(500, []), (200, {}), (200, None)]:
            with patch.object(relay.smoke, 'request', return_value=response):
                with self.assertRaises(ValueError):
                    relay.rust_receipt('a' * 64)
        error = urllib.error.HTTPError('url', 503, 'unavailable', {}, None)
        with patch.object(relay.smoke, 'request', side_effect=error):
            with self.assertRaises(urllib.error.HTTPError):
                relay.rust_receipt('a' * 64)

    def test_roles_identical_builds_supported(self):
        import campaign
        import os
        roles = campaign.resolve_roles('steady', 'both')
        for build in ('base', 'syncfix'):
            with patch.dict(os.environ):
                campaign.configure_environment('steady', campaign.nodes_for_roles(roles), roles, build, build)
                self.assertEqual({os.environ[f'MATRIX_BUILD_{n.upper()}'] for n in ('scala', 'scala2', 'scala3')}, {build})
                self.assertEqual(os.environ['MATRIX_RELAY_MEASUREMENT'], '1')

    def test_build_verify_unprovisioned_returns_failure(self):
        import builds
        from types import SimpleNamespace
        with patch.object(builds, 'registry', return_value={'absent': SimpleNamespace(available=False, work_dir='absent')}):
            self.assertEqual(builds.main(['--verify', 'absent']), 1)

    def test_registry_refresh_builds_pinned(self):
        import builds
        self.assertEqual(builds.registry()['syncfix'].declared['ergo_ref'], '6fad0e04e1377380a1b95e99d8f23d0935ec2ea9')
        self.assertEqual(builds.registry()['2566'].declared['ergo_ref'], '516b30efdd3d2a61668db9c0ae92d97f9574406c')

if __name__ == '__main__':
    unittest.main()
