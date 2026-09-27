"""Relay measurement tests; fixtures are source-derived until a smoke is captured."""
import unittest
from unittest.mock import patch
import urllib.error

import relay_measurement as relay


# ----- helpers -----
def line(message, second=0):
    return f'DEBUG org.ergoplatform.nodeView.history.ErgoHistory - {message} | relay_ts=2026-09-28T00:00:{second:02d}.000Z'


class RelayTests(unittest.TestCase):
    # ----- happy path -----
    def test_receipts_duplicate_and_disconnected_count_once(self):
        a, b = 'a' * 64, 'b' * 64
        lines = [line(f'Adding input block {a} to existing tree for ordering block {b}'),
                 line(f'Successfully added input block {a} to tree for ordering block {b}'),
                 line(f'Creating new tree for input block {b} and ordering block {a}'),
                 line(f'Put input block to disconnected queue: {b}')]
        self.assertEqual(relay.scala_received(lines), {a, b})

    def test_coverage_empty_intervals_excluded_and_ids_deduplicated(self):
        result = relay.coverage({10: {'a', 'b'}, 11: {'c'}, 12: set()}, {'a', 'z'})
        self.assertEqual((result['received'], result['never_observed'], result['zero_receipt_intervals']), (1, 2, 1))
        self.assertEqual(result['missing_ids'], ['b', 'c'])
        self.assertEqual(result['nonempty_intervals'], 2)

    def test_sync_receiver_only_counts_code65(self):
        messages = [line('Received message MessageSpec(65: Sync) from ConnectionId(remote=/127.0.0.2:45000, local=/127.0.0.1:19570, direction=Incoming)', s) for s in (1, 2, 5)]
        messages += [line('Send message MessageSpec(65: Sync) to ConnectionId(remote=/127.0.0.2:45000)', 3), line('Received message MessageSpec(55: Inv) from ConnectionId(remote=/127.0.0.2:45000)', 4)]
        events = relay.sync_received(messages)
        self.assertEqual(len(events), 3)
        t = relay.timestamp(messages[0]) - 1
        result = relay.traffic(events, '127.0.0.2', [t, t + 4, t + 8])
        self.assertEqual(result['per_interval'], [2, 1])
        self.assertEqual((result['mean_per_block'], result['max_per_block'], result['min_gap_seconds']), (1.5, 2, 1))

    def test_stale_height_near_far_and_unknown_break_stretches(self):
        rows = [{'at': t, 'miner': 10, 'actual': actual, 'tracked': tracked} for t, actual, tracked in [(0, 10, 7), (1, 11, 7), (2, 10, None), (3, 6, 6), (4, 12, 8)]]
        result = relay.staleness(rows)
        self.assertEqual(result['stale_samples'], 2)
        self.assertEqual(result['share'], .5)
        self.assertEqual(result['longest_stretch_seconds'], 1)
        self.assertEqual(result['unknown_samples'], 1)

    def test_miner_window_terminal_interval_excluded(self):
        a, b = 'a' * 64, 'b' * 64
        t = relay.timestamp(line('x'))
        logs = [line(f'Input-block {a} mined @ height 11!', 1),
                line(f'Updating state with new ordering block {b}, height: 11', 2),
                line(f'Input-block {b} mined @ height 12!', 3)]
        intervals, boundaries = relay.miner_window(logs, 10, t)
        self.assertEqual(intervals, {10: {a}})
        self.assertEqual(boundaries, [t, t + 2])

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

    def test_sync_wrong_peer_and_outside_window_excluded(self):
        events = [{'at': t, 'host': host, 'port': port} for t, host, port in
                  [(-1, 'a', 1), (0, 'b', 1), (0, 'a', 2), (1, 'a', 1), (2, 'a', 1)]]
        self.assertEqual(relay.traffic(events, 'a', [0, 2], 1)['messages'], 1)

    def test_sync_ephemeral_source_matches_reversed_connection(self):
        sender = [line('Send message MessageSpec(65: Sync) to ConnectionId(remote=/127.0.0.1:19570, local=/127.0.0.1:45000, direction=Outgoing)')]
        receiver = [line('Received message MessageSpec(65: Sync) from ConnectionId(remote=/127.0.0.1:45000, local=/127.0.0.1:19570, direction=Incoming)', 1),
                    line('Received message MessageSpec(65: Sync) from ConnectionId(remote=/127.0.0.1:45001, local=/127.0.0.1:19570, direction=Incoming)', 2)]
        result = relay.peer_traffic(sender, receiver, [relay.timestamp(line('x')), relay.timestamp(line('x', 3))])
        self.assertEqual(result['messages'], 1)
        self.assertEqual(result['matched_connections'], 1)

    def test_roles_identical_builds_supported(self):
        import campaign
        import os
        roles = campaign.resolve_roles('steady', 'both')
        for build in ('base', 'syncfix'):
            with patch.dict(os.environ):
                campaign.configure_environment('steady', campaign.nodes_for_roles(roles), roles, build, build)
                self.assertEqual({os.environ[f'MATRIX_BUILD_{n.upper()}'] for n in ('scala', 'scala2', 'scala3')}, {build})
                self.assertEqual(os.environ['MATRIX_RELAY_MEASUREMENT'], '1')

    def test_collector_real_parsers_and_mock_api_produce_metrics(self):
        import tempfile
        from pathlib import Path
        import lifecycle
        import campaign
        a, b = 'a' * 64, 'b' * 64
        t = relay.timestamp(line('x'))
        with tempfile.TemporaryDirectory() as raw, patch.object(relay.smoke, 'WORK', Path(raw)), patch.object(lifecycle, 'NODES', ('scala', 'scala2', 'scala3', 'rust')):
            for node in ('scala', 'scala2', 'scala3'):
                (Path(raw) / f'{node}.log').write_text('before window\n')
            with patch.object(relay.time, 'time', return_value=t):
                measurement = relay.Measurement(10)
            (Path(raw) / 'scala.log').write_text('before window\n' + line(f'Input-block {a} mined @ height 11!', 1) + '\n' + line(f'Updating state with new ordering block {b}, height: 11', 2) + '\n')
            for node in ('scala2', 'scala3'):
                with (Path(raw) / f'{node}.log').open('a') as out:
                    out.write(line(f'Adding input block {a} to existing tree for ordering block {b}', 1) + '\n')
            statuses = [{'address': f'/{campaign.CAMPAIGN_P2P_HOST[n]}:{campaign.CAMPAIGN_P2P[n]}', 'height': 7} for n in measurement.nodes]
            def api(node, path, **kwargs):
                return statuses if path == '/peers/syncInfo' else {'fullHeight': 10}
            with patch.object(relay.smoke, 'api', side_effect=api), patch.object(relay.smoke, 'request', return_value=(200, [])), patch.object(relay.time, 'time', return_value=t + 1):
                measurement.poll()
                heights = iter((10, 11))
                def moving_api(node, path, **kwargs):
                    return statuses if path == '/peers/syncInfo' else {'fullHeight': next(heights) if node == 'scala' else 10}
                with patch.object(relay.smoke, 'api', side_effect=moving_api):
                    measurement.poll()
                with patch.object(relay.smoke, 'api', side_effect=relay.smoke.Unavailable('offline')):
                    measurement.poll()
                result = measurement.finish()
            self.assertEqual({n: m['received'] for n, m in result['M1'].items()}, {'scala2': 1, 'scala3': 1, 'rust': 1})
            self.assertEqual(result['M2']['rust']['share'], 1)
            self.assertEqual(result['M2']['rust']['unknown_samples'], 2)
            self.assertEqual(result['window']['end'], t + 2)

    def test_stale_unknown_and_far_samples_break_stretch(self):
        for middle in ({'at': 2}, {'at': 2, 'miner': 10, 'actual': 5, 'tracked': 7}):
            rows = [{'at': t, 'miner': 10, 'actual': 10, 'tracked': 7} for t in (0, 1)] + [middle] + [{'at': t, 'miner': 10, 'actual': 10, 'tracked': 7} for t in (3, 4)]
            self.assertEqual(relay.staleness(rows)['longest_stretch_seconds'], 1)

    # ----- round-trips -----
    def test_timestamp_utc_parses(self):
        self.assertEqual(relay.timestamp(line('x', 1)) - relay.timestamp(line('x')), 1)

    # ----- error paths -----
    def test_measurement_missing_sources_not_reported_as_success(self):
        evidence = {'M1': {'rust': {'mined': 0}}, 'M2': {'rust': {'samples': 0}},
                    'M3': {'scala': {'available': False}}, 'rust_api_errors': [{'error': 'offline'}]}
        self.assertEqual(len(relay.measurement_issues(evidence)), 4)
        good = {'M1': {'rust': {'mined': 1}}, 'M2': {'rust': {'samples': 1}},
                'M3': {'scala': {'available': True}}, 'rust_api_errors': []}
        self.assertEqual(relay.measurement_issues(good), [])


    def test_sync_missing_timestamp_refused(self):
        with self.assertRaises(ValueError):
            relay.sync_received(['Received message MessageSpec(65: Sync) from ConnectionId(remote=/127.0.0.2:1)'])

    def test_traffic_empty_denominator_unknown(self):
        self.assertIsNone(relay.traffic([], '127.0.0.2', [0])['mean_per_block'])

    def test_build_verify_unprovisioned_returns_failure(self):
        import builds
        from types import SimpleNamespace
        with patch.object(builds, 'registry', return_value={'absent': SimpleNamespace(available=False, work_dir='absent')}):
            self.assertEqual(builds.main(['--verify', 'absent']), 1)

    # ----- oracle parity -----
    def test_registry_refresh_builds_pinned(self):
        import builds
        self.assertEqual(builds.registry()['syncfix'].declared['ergo_ref'], '6fad0e04e1377380a1b95e99d8f23d0935ec2ea9')
        self.assertEqual(builds.registry()['2566'].declared['ergo_ref'], '516b30efdd3d2a61668db9c0ae92d97f9574406c')


if __name__ == '__main__':
    unittest.main()
