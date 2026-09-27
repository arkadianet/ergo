"""A1 verbatim regression and explicitly perturbed negative controls."""
import json
import os
from pathlib import Path
import unittest


class ClassificationTests(unittest.TestCase):
    # ----- helpers -----
    def fixture(self):
        f = json.loads(Path(__file__).with_name('fixtures').joinpath('relay-a1.json').read_text())
        cases = f['cases']
        return {'window': {'start': min(c['mined']['at'] for c in cases) - 1,
                           'end': max(c['mined']['at'] for c in cases) + 2},
                'source_lines': {n: [x['text'] for x in rows] for n, rows in f['source_lines'].items()},
                'M1': {'scala2': {'missing_ids': [c['id'] for c in cases], 'received_ids': [],
                                 'per_interval': {str(c['interval']): {} for c in cases}}},
                'M2': {'scala2': {'raw_samples': sorted([s for c in cases for s in c['samples']], key=lambda s: s['at'])}}}

    def score(self, data):
        from relay_classification import classify
        return classify(data)['scala2']

    # ----- happy path -----
    def test_a1_classes_verbatim_match(self):
        out = self.score(self.fixture())
        self.assertEqual(out['never_admitted'], {'a-stale-not-sent': 1, 'a-not-sent-other': 0,
                         'b-plus2-dropped': 1, 'b-gap-dropped': 1, 'other': 0})

    def test_nonstale_nonsend_is_separate(self):
        data = self.fixture()
        data['M2']['scala2']['raw_samples'] = []
        self.assertEqual(self.score(data)['never_admitted']['a-not-sent-other'], 1)

    def test_received_without_reason_is_other(self):
        data = self.fixture()
        data['source_lines']['scala2'] = [s for s in data['source_lines']['scala2'] if 'Ignoring input' not in s]
        self.assertEqual(self.score(data)['never_admitted']['other'], 1)

    def test_recovery_real_a1_episode_and_distribution(self):
        from relay_classification import classify, episodes
        f = json.loads(Path(__file__).with_name('fixtures').joinpath('relay-a1.json').read_text())['recovery']
        data = {'window': {'start': 1790535847.429, 'end': 1790535908.568},
                'source_lines': {n: [e['text'] for e in rows] for n, rows in f['source_lines'].items()},
                'M1': {'scala3': {'missing_ids': [], 'received_ids': f['ids'], 'per_interval': {'55': {}}}},
                'M2': {'scala3': {'raw_samples': f['samples']}}}
        out = classify(data)['scala3']
        delay = out['withheld_then_recovered']
        self.assertEqual(delay['distribution']['count'], 70)
        self.assertEqual(delay['per_interval']['55']['count'], 70)
        self.assertAlmostEqual(delay['distribution']['min_seconds'], .585, places=3)
        self.assertAlmostEqual(delay['distribution']['max_seconds'], 39.173, places=3)
        self.assertEqual(out['stale_episodes'][0]['blocks_mined'], 67)
        self.assertAlmostEqual(out['stale_episodes'][0]['duration_seconds'], 37.443815, places=5)
        threshold = delay['distribution']['min_seconds']
        self.assertEqual(classify(data, threshold)['scala3']['withheld_then_recovered']['distribution']['count'], 69)
        # A repeated admission log cannot replace the first admission time.
        data['source_lines']['scala3'] *= 2
        self.assertEqual(classify(data)['scala3']['withheld_then_recovered'], delay)
        rows = f['samples']
        middle = len(rows) // 2
        broken = rows[:middle] + [dict(rows[middle], tracked=None)] + rows[middle + 1:]
        self.assertEqual(len(episodes(broken, {})), 2)
        self.assertEqual(episodes([dict(r, actual=0) for r in rows], {}), [])
        for value in (-1, float('inf'), float('nan')):
            with self.assertRaises(ValueError): classify(data, value)

    # ----- error paths -----
    def test_missing_logs_not_nonsend(self):
        data = self.fixture()
        data['source_lines']['scala2'] = []
        out = self.score(data)
        self.assertFalse(out['available'])
        self.assertEqual(out['never_admitted']['other'], 3)

    def test_stale_requires_near_actual_and_consistent_recent_samples(self):
        for mode in ('far', 'unknown', 'old'):
            data = self.fixture()
            rows = data['M2']['scala2']['raw_samples']
            if mode == 'far':
                for row in rows: row['actual'] = 0
            if mode == 'unknown':
                for row in rows: row['tracked'] = None
            if mode == 'old':
                for row in rows: row['at'] -= 100
            self.assertEqual(self.score(data)['never_admitted']['a-stale-not-sent'], 0, mode)

    def test_gap_requires_unique_frame_and_reason_within_tolerance(self):
        for mode in ('duplicate', 'late', 'wrong_socket', 'wrong_direction', 'wrong_code'):
            data = self.fixture()
            lines = data['source_lines']['scala2']
            target = next(s for s in lines if '100: SubBlock' in s and '19:03:55.615' in s)
            if mode == 'duplicate': lines.append(target)
            if mode == 'late': lines[lines.index(target)] = target.replace('19:03:55.615', '19:03:56.615')
            if mode == 'wrong_socket': lines[lines.index(target)] = target.replace('46670', '46671')
            if mode == 'wrong_direction': lines[lines.index(target)] = target.replace('Received message', 'Send message')
            if mode == 'wrong_code': lines[lines.index(target)] = target.replace('100: SubBlock', '55: Inv')
            self.assertEqual(self.score(data)['never_admitted']['b-gap-dropped'], 0, mode)

    def test_absence_requires_no_send_or_id_mention(self):
        data = self.fixture()
        data['source_lines']['scala2'] = [line for line in data['source_lines']['scala2']
                                         if '19:03:55.615' not in line and 'Ignoring input' not in line]
        # Miner send remains; wire loss/unlogged receipt is not a non-send.
        self.assertEqual(self.score(data)['never_admitted']['other'], 1)
        data = self.fixture()
        bid = data['M1']['scala2']['missing_ids'][0]
        data['source_lines']['scala2'].append(next(line for line in data['source_lines']['scala'] if bid in line))
        self.assertEqual(self.score(data)['never_admitted']['a-stale-not-sent'], 0)

    def test_gap_reason_late_or_ambiguous_is_other(self):
        for mode in ('late', 'duplicate', 'two_blocks'):
            data = self.fixture()
            lines = data['source_lines']['scala2']
            reason = next(line for line in lines if 'Ignoring input' in line)
            if mode == 'late': lines[lines.index(reason)] = reason.replace('19:03:55.616', '19:03:55.716')
            if mode == 'duplicate': lines.append(reason)
            if mode == 'two_blocks':
                lines = data['source_lines']['scala']
                mined = next(line for line in lines if 'New input block' in line and '19:03:55.615' in line)
                bid = data['M1']['scala2']['missing_ids'][0]
                import re
                lines.append(re.sub(r'[0-9a-f]{64}', bid, mined))
                # Remove the original mining line so this block competes for the same frame.
                lines[:] = [line for line in lines if not (bid in line and '19:07:57' in line)]
            self.assertEqual(self.score(data)['never_admitted']['b-gap-dropped'], 0, mode)

    def test_stale_brackets_age_and_refresh_controls(self):
        for mode in ('unbracketed', 'old', 'unknown_actual', 'not_stale', 'refreshed'):
            data = self.fixture()
            rows = data['M2']['scala2']['raw_samples'][-2:]
            data['M2']['scala2']['raw_samples'] = rows
            if mode == 'unbracketed': data['M2']['scala2']['raw_samples'] = rows[:1]
            if mode == 'old': rows[0]['at'] -= 10
            if mode == 'unknown_actual': rows[0]['actual'] = None
            if mode == 'not_stale':
                for row in rows: row['tracked'] = 65
            if mode == 'refreshed':
                f = json.loads(Path(__file__).with_name('fixtures').joinpath('relay-a1.json').read_text())
                rows[1]['tracked'] = 65
                # Changed following sample is safe only with no refresh before mining.
                self.assertEqual(self.score(data)['never_admitted']['a-stale-not-sent'], 1)
                data['source_lines']['scala'].append(f['refresh_line']['text'].replace('19:08:04.881', '19:07:57.500'))
            self.assertEqual(self.score(data)['never_admitted']['a-stale-not-sent'], 0, mode)

    def test_plus2_from_other_peer_is_not_miner_drop(self):
        data = self.fixture()
        data['source_lines']['scala2'] = [s.replace('46670', '46671') if 'downloading its parent' in s else s
                                         for s in data['source_lines']['scala2']]
        self.assertEqual(self.score(data)['never_admitted']['b-plus2-dropped'], 0)

    def test_denominator_and_episode_window_exclude_external_observations(self):
        from relay_classification import classify
        data = self.fixture()
        expected = self.score(data)
        import re
        mined = next(s for s in data['source_lines']['scala'] if 'New input block' in s and '19:03:55.615' in s)
        data['source_lines']['scala'].append(re.sub(r'[0-9a-f]{64}', 'f' * 64, mined))
        self.assertEqual(self.score(data), expected)
        data['window']['end'] = data['window']['start']
        self.assertEqual(classify(data)['scala2']['stale_episodes'], [])

    # ----- oracle parity -----
    @unittest.skipUnless(os.environ.get('RELAY_A1_EVIDENCE'), 'set RELAY_A1_EVIDENCE for archived A1 parity')
    def test_whole_a1_q3_table_matches(self):
        from relay_rescore import rescore
        result = rescore(Path(os.environ['RELAY_A1_EVIDENCE']))
        archived = json.loads((Path(os.environ['RELAY_A1_EVIDENCE']) / 'campaign' / 'steady.json').read_text())['relay_refresh']
        for metric in ('M1', 'M2', 'M3'):
            self.assertEqual(result[metric], archived[metric], metric)
        for node, expected in [('scala2', (13, 68, 13)), ('scala3', (0, 86, 35))]:
            counts = result['classification'][node]['never_admitted']
            self.assertEqual(tuple(counts[k] for k in ('a-stale-not-sent', 'b-plus2-dropped', 'b-gap-dropped')), expected)
            self.assertEqual(counts['a-not-sent-other'] + counts['other'], 0)
        recovered = result['classification']['scala3']['withheld_then_recovered']['blocks']
        self.assertEqual(sum(b['interval'] == 55 for b in recovered), 70)
        self.assertAlmostEqual(result['classification']['scala3']['stale_episodes'][0]['duration_seconds'], 37.443815, places=5)
        self.assertEqual(result['M1']['scala2']['received'], 3626)
        self.assertEqual(result['M1']['scala3']['received'], 3599)


if __name__ == '__main__':
    unittest.main()
