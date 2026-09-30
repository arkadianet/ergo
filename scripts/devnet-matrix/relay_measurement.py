"""Receiver coverage and SyncInfo observations for the steady workload.

All counts are unique input-block IDs. Missing means never observed before
window close, not proof that a packet never arrived. Raw samples are retained.
"""
from bisect import bisect_right
from datetime import datetime
import json
import re
import tempfile
import time
import urllib.error

import smoke
from relay_evidence import LineFile

ID = r'[0-9a-f]{64}'
RECEIPT = re.compile(rf'(?:Adding input block ({ID}) to existing tree|Creating new tree for input block ({ID}) and ordering block)')
SYNC = re.compile(r'Received message MessageSpec\(65: Sync\) from ConnectionId\(remote=/([^,:]+):(\d+)')
CONNECTION = re.compile(r'ConnectionId\(remote=/([^,]+), local=/([^,]+), direction=')
# UtxoState logs successful full-block application on the miner as well as followers.
HEIGHT = re.compile(r'Valid modifier with header [0-9a-f]{64} and emission box .* applied to UtxoState at height (\d+)')


def timestamp(line):
    return datetime.fromisoformat(line.rsplit(' | relay_ts=', 1)[1].strip().replace('Z', '+00:00')).timestamp()


def scala_received(lines):
    return {m.group(1) or m.group(2) for line in lines if (m := RECEIPT.search(line))}


def sync_received(lines):
    out = []
    for line in lines:
        match = SYNC.search(line)
        if match:
            try:
                at = timestamp(line)
            except (IndexError, ValueError) as error:
                raise ValueError('SyncInfo receiver line lacks relay timestamp') from error
            out.append({'at': at, 'host': match[1], 'port': int(match[2]), 'line': line})
    return out


def miner_window(lines, start_height, started):
    """Completed intervals only; the final still-open input tree is excluded."""
    height = start_height
    pending = set()
    intervals = {}
    boundaries = [started]
    for line in lines:
        match = HEIGHT.search(line)
        if match and int(match[1]) != height:
            intervals[height] = pending
            pending = set()
            boundaries.append(timestamp(line))
            height = int(match[1])
        pending.update(smoke.mined_input_blocks([line]))
    return intervals, boundaries


def coverage(intervals, received):
    mined = set().union(*intervals.values()) if intervals else set()
    nonempty = [ids for ids in intervals.values() if ids]
    return {'mined': len(mined), 'received': len(mined & received),
            'never_observed': len(mined - received), 'missing_ids': sorted(mined - received),
            'received_ids': sorted(mined & received), 'nonempty_intervals': len(nonempty),
            'zero_receipt_intervals': sum(not (ids & received) for ids in nonempty),
            'per_interval': {str(h): {'mined': len(ids), 'received': len(ids & received)}
                             for h, ids in intervals.items()}}


def traffic(events, host, boundaries, port=None):
    counts = [0] * max(0, len(boundaries) - 1)
    times = []
    for event in events:
        if (host is not None and event['host'] != host) or (port is not None and event['port'] != port):
            continue
        i = bisect_right(boundaries, event['at']) - 1
        if 0 <= i < len(counts):
            counts[i] += 1
            times.append(event['at'])
    times.sort()
    return {'messages': sum(counts), 'per_interval': counts,
            'mean_per_block': sum(counts) / len(counts) if counts else None,
            'max_per_block': max(counts) if counts else None,
            'min_gap_seconds': min((b - a for a, b in zip(times, times[1:])), default=None)}


def peer_traffic(sender_lines, receiver_lines, boundaries):
    """Attribute receiver frames by the reverse socket pair at the sender.

    Scala outgoing sockets need not bind to the node's declared address.
    Both endpoints, not just source IP or declared port, identify the peer.
    """
    reverse = {(m[2], m[1]) for line in sender_lines if (m := CONNECTION.search(line))}
    events = sync_received(receiver_lines)
    selected = [e for e in events if (m := CONNECTION.search(e['line'])) and (m[1], m[2]) in reverse]
    result = traffic(selected, None, boundaries)
    result['matched_connections'] = len({CONNECTION.search(e['line']).groups() for e in selected})
    result['receiver_events'] = selected
    result['available'] = bool(selected) and bool(result['per_interval'])
    return result


def staleness(rows):
    valid = stale = 0
    first = None
    longest = 0
    for row in rows:
        known = all(row.get(k) is not None for k in ('miner', 'actual', 'tracked'))
        valid += known
        bad = known and abs(row['actual'] - row['miner']) <= 2 and abs(row['tracked'] - row['miner']) > 2
        stale += bad
        if bad:
            first = row['at'] if first is None else first
            longest = max(longest, row['at'] - first)
        else:
            first = None
    return {'samples': valid, 'unknown_samples': len(rows) - valid,
            'stale_samples': stale, 'share': stale / valid if valid else None,
            'longest_stretch_seconds': longest}


def rust_receipt(bid):
    """A 200, including an empty transaction list, proves a retained record."""
    try:
        status, body = smoke.request('rust', f'/blocks/{bid}/inputBlockTransactionIds', timeout=2)
    except urllib.error.HTTPError as error:
        error.close()
        if error.code == 404:
            return False
        raise
    if status != 200 or not isinstance(body, list):
        raise ValueError('unexpected inputBlockTransactionIds response')
    return True


def logback(source):
    """Keep ordinary prefixes intact for the existing verdict parsers."""
    return source.replace('%msg%n', '%msg | relay_ts=%d{yyyy-MM-dd\'T\'HH:mm:ss.SSS\'Z\',UTC}%n').replace(
        '<root level=', '<logger name="org.ergoplatform.nodeView.history.ErgoHistory" level="DEBUG"/>'
        '<logger name="scorex.core.network.PeerConnectionHandler" level="DEBUG"/><root level=')


def measurement_issues(result):
    issues = []
    if not any(m['mined'] for m in result['M1'].values()):
        issues.append('M1: no mined input blocks in completed measurement intervals')
    if result['rust_api_errors']:
        issues.append('M1: Rust API errors leave receipt coverage incomplete')
    for node, metric in result['M2'].items():
        if not metric['samples']:
            issues.append(f'M2: no comparable sync-height samples for {node}')
    for node, metric in result['M3'].items():
        if not metric.get('available'):
            issues.append(f'M3: no attributable receiver SyncInfo frames from {node}')
    return issues


class Measurement:
    def __init__(self, start_height, evidence_dir=None):
        import lifecycle
        self.nodes = [n for n in lifecycle.NODES if n != 'scala']
        self.files = {n: (smoke.WORK / f'{n}.log').open() for n in lifecycle.NODES if n.startswith('scala')}
        for file in self.files.values():
            file.seek(0, 2)
        self.evidence_dir = evidence_dir if evidence_dir is not None else smoke.WORK / 'campaign'
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        # Unique names keep earlier attempts' sidecars intact. JSONL preserves
        # even partial lines as separate entries, with the original indices.
        self.line_outputs = {n: tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                             dir=self.evidence_dir, prefix=f'relay-lines-{n}-', suffix='.log', delete=False)
                             for n in self.files}
        self.lines = {n: LineFile(file.name) for n, file in self.line_outputs.items()}
        self.started = time.time()
        self.start_height = start_height
        self.height = start_height
        self.boundaries = [self.started]
        self.intervals = {start_height: set()}
        self.rust_received = set()
        self.rust_errors = []
        self.rust_reads = {}
        self.samples = {n: [] for n in self.nodes}
        self.status_polls = []
        self.last_retry_height = None

    def poll(self):
        import campaign
        for node, file in self.files.items():
            while line := file.readline():
                self.line_outputs[node].write(json.dumps(line) + '\n')
                self.lines[node].count += 1
                if node == 'scala':
                    match = HEIGHT.search(line)
                    if match:
                        height = int(match[1])
                        if height != self.height:
                            self.boundaries.append(timestamp(line))
                            self.height = height
                            self.intervals.setdefault(height, set())
                    self.intervals[self.height].update(smoke.mined_input_blocks([line]))
        mined = set().union(*self.intervals.values())
        retry = self.last_retry_height != self.height
        self.last_retry_height = self.height
        for bid in sorted(mined - self.rust_received):
            if not retry and bid in self.rust_reads:
                continue
            self.rust_reads[bid] = time.time()
            try:
                if rust_receipt(bid):
                    self.rust_received.add(bid)
            except (OSError, ValueError) as error:
                self.rust_errors.append({'id': bid, 'error': str(error)})
        at = time.time()
        try:
            before = smoke.api('scala', '/info', timeout=2)['fullHeight']
            statuses = smoke.api('scala', '/peers/syncInfo', timeout=2)
            actual = {n: smoke.api(n, '/info', timeout=2)['fullHeight'] for n in self.nodes}
            after = smoke.api('scala', '/info', timeout=2)['fullHeight']
            tracked = {s['address'].lstrip('/'): s['height'] for s in statuses}
            poll = len(self.status_polls)
            self.status_polls.append({'at': at, 'raw_statuses': statuses})
            for node in self.nodes:
                address = f'{campaign.CAMPAIGN_P2P_HOST[node]}:{campaign.CAMPAIGN_P2P[node]}'
                self.samples[node].append({'at': at, 'end': time.time(), 'miner': before if before == after else None,
                                           'actual': actual[node], 'tracked': tracked.get(address),
                                           'raw_statuses_ref': poll})
        except (smoke.Unavailable, KeyError, TypeError) as error:
            for node in self.nodes:
                self.samples[node].append({'at': at, 'error': str(error)})

    def finish(self):
        self.last_retry_height = None
        self.poll()
        ended = time.time()
        for file in self.files.values():
            file.close()
        for file in self.line_outputs.values():
            file.close()
        intervals, boundaries = miner_window(self.lines['scala'], self.start_height, self.started)
        cutoff = boundaries[-1]
        receipts = {n: scala_received(lines) for n, lines in self.lines.items() if n != 'scala'}
        receipts['rust'] = self.rust_received
        traffic_out = {}
        for sender in self.files:
            receiver = 'scala2' if sender == 'scala' else 'scala'
            if receiver not in self.lines:
                traffic_out[sender] = {'unavailable': 'no stock Scala receiver'}
                continue
            traffic_out[sender] = peer_traffic(self.lines[sender], self.lines[receiver], boundaries)
            traffic_out[sender]['receiver'] = receiver
        result = {'window': {'start': self.started, 'end': cutoff, 'receipt_cutoff': ended, 'boundaries': boundaries,
                            'initial_interval_partial': True, 'terminal_interval_excluded': True},
                'M1': {n: coverage(intervals, ids) for n, ids in receipts.items()},
                'M2': {n: dict(staleness([r for r in rows if r['at'] < cutoff]), raw_samples=rows) for n, rows in self.samples.items()},
                'M3': traffic_out, 'rust_api_errors': self.rust_errors,
                'rust_last_probes': self.rust_reads,
                'source_line_files': {n: lines.reference() for n, lines in self.lines.items()},
                'status_polls': self.status_polls,
                'limitations': ['M1 never_observed is bounded by the measurement cutoff; Rust API polling can miss evicted records.',
                                'M3 counts at one named receiver per sender; socket pairs are matched across both logs.',
                                'M2 stretch spans observed stale samples, not continuous-time proof; unknown samples break stretches.']}

        from relay_classification import classify
        result['classification'] = classify(result, evidence_dir=self.evidence_dir)
        return result
