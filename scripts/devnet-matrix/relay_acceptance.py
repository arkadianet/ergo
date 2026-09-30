"""Additive #2597 observations; no acceptance verdicts or packet-absence claims."""
from bisect import bisect_right
import json
import math
import re

from relay_measurement import HEIGHT, ID, peer_traffic, timestamp

MINED = re.compile(r'New block mined, header: Header\((\{.*\})\)')
APPLIED = re.compile(rf'Valid modifier with header ({ID}) and emission box')
ANNOUNCEMENT = re.compile(rf'org\.ergoplatform\.network\.ErgoNodeViewSynchronizer - '
                          rf'(?:Processing ordering block announcement for |'
                          rf'Ignoring ordering block announcement as it is already known: )({ID})')
HEADER = re.compile(rf'New best header ({ID}) with score')
REBUILT = re.compile(rf'Applying block transactions from input-blocks for ({ID})')
DOWNLOAD = re.compile(rf'(?:Downloading block transactions fully for |'
                      rf'Requesting all the block transactions for )({ID})')


def ordering_blocks(lines, window, intervals):
    """Use mining IDs, never assume every miner application was locally mined."""
    mined, applied = {}, {}
    heights = list(intervals)
    for number, line in enumerate(lines, 1):
        if match := MINED.search(line):
            header = json.loads(match[1])
            at = timestamp(line)
            if window['start'] <= at < window['end']:
                i = bisect_right(window['boundaries'], at) - 1
                mined.setdefault(header['id'], {'height': header['height'], 'mined_at': at,
                                               'source_line': number,
                                               'interval': heights[i] if 0 <= i < len(heights) else None})
        if APPLIED.search(line) and HEIGHT.search(line):
            applied.setdefault(APPLIED.search(line)[1], {'at': timestamp(line), 'source_line': number})
    for bid, block in mined.items():
        block['miner_apply'] = applied.get(bid)
    return mined


def follower_observations(lines, window):
    observations = {k: {} for k in ('announcement', 'header', 'rebuilt', 'full_download_requested', 'applied')}
    for number, line in enumerate(lines, 1):
        for kind, pattern in zip(observations, (ANNOUNCEMENT, HEADER, REBUILT, DOWNLOAD, APPLIED)):
            if match := pattern.search(line):
                at = timestamp(line)
                if window['start'] <= at <= window['receipt_cutoff']:
                    previous = observations[kind].get(match[1])
                    if previous is None or at < previous['at']:
                        observations[kind][match[1]] = {'at': at, 'source_line': number}
    return observations


def ordering_coverage(mined, observed, intervals):
    received = set(mined) & observed['announcement'].keys()
    missing = set(mined) - received
    blocks = []
    for bid, block in mined.items():
        receipt = observed['announcement'].get(bid)
        blocks.append({'id': bid, **block, 'announcement': receipt,
                       'receipt_minus_miner_apply_seconds':
                           round(receipt['at'] - block['miner_apply']['at'], 3)
                           if receipt and block['miner_apply'] else None,
                       'other_observations': {k: v[bid] for k, v in observed.items()
                                              if k != 'announcement' and bid in v}})
    return {'mined': len(mined), 'received': len(received), 'never_observed': len(missing),
            'missing_ids': sorted(missing), 'received_ids': sorted(received),
            'receipt_logging_complete': False, 'never_received': None,
            'limitation': 'ID-bearing network processing logs prove receipt from some peer, not its identity. '
                          'The pre-processing height-gap return has no enabled ID-bearing receipt log; '
                          'never_observed is not proof of never received. Header/application logs do not identify the transport.',
            'header_without_announcement': len(missing & observed['header'].keys()),
            'applied_without_announcement': len(missing & observed['applied'].keys()),
            'per_interval': {str(h): {'mined': sum(b['interval'] == h for b in mined.values()),
                                     'received': sum(mined[bid]['interval'] == h for bid in received)}
                             for h in intervals}, 'blocks': blocks}


def sync_density(metric, intervals, boundaries):
    """Receiver arrivals, across connections for one peer link; nearest-rank percentiles."""
    times = sorted(e['at'] for e in metric.get('receiver_events', [])
                   if boundaries[0] <= e['at'] < boundaries[-1])
    # relay_ts has millisecond resolution. Round differences before testing
    # 250ms so epoch-float cancellation cannot turn exactly 250ms into <250ms.
    gaps = sorted(round((b - a) * 1000) / 1000 for a, b in zip(times, times[1:]))
    counts = metric.get('per_interval', [])
    total_inputs = len(set().union(*intervals.values())) if intervals else 0
    messages = sum(counts)
    return {'receiver': metric.get('receiver'), 'measurement': 'receiver arrival, not sender transmission',
            'available': metric.get('available', False), 'messages': messages,
            'ordering_intervals': len(counts), 'input_blocks': total_inputs,
            'messages_per_ordering_interval': messages / len(counts) if counts else None,
            'messages_per_input_block': messages / total_inputs if total_inputs else None,
            'per_interval': {str(h): {'messages': count, 'input_blocks': len(ids),
                                     'messages_per_input_block': count / len(ids) if ids else None,
                                     'start': boundaries[i], 'end': boundaries[i + 1]}
                             for i, ((h, ids), count) in enumerate(zip(intervals.items(), counts))},
            'gap_pairs': len(gaps), 'min_gap_seconds': min(gaps, default=None),
            'p1_gap_seconds': gaps[math.ceil(.01 * len(gaps)) - 1] if gaps else None,
            'p5_gap_seconds': gaps[math.ceil(.05 * len(gaps)) - 1] if gaps else None,
            'pairs_below_250ms': sum(gap < .250 for gap in gaps)}


def acceptance_metrics(lines, intervals, result, steady=None):
    window = result['window']
    mined = ordering_blocks(lines['scala'], window, intervals)
    m4, m5, reconstruction = {}, {}, {}
    for node in lines:
        if node == 'scala':
            continue
        observed = follower_observations(lines[node], window)
        m4[node] = ordering_coverage(mined, observed, intervals)
        rebuilt = set(mined) & observed['rebuilt'].keys()
        downloaded = set(mined) & observed['full_download_requested'].keys()
        reconstruction[node] = {
            'source': 'captured follower logs for M4 mining IDs, through receipt_cutoff',
            'rebuilt': len(rebuilt), 'full_download_requested': len(downloaded),
            'rebuilt_ids': sorted(rebuilt), 'full_download_requested_ids': sorted(downloaded),
            'both_ids': sorted(rebuilt & downloaded),
            'without_decision': len(set(mined) - rebuilt - downloaded),
            'limitation': 'Full-download lines are requests, not proof of completed downloads; '
                          'absence of a decision is unknown, not a zero-download claim.'}
        if steady:
            role = steady.get('roles', {}).get(node)
            saved = steady.get('reconstruction_accounting', {}).get(role)
            if saved is not None:
                reconstruction[node]['archived_steady'] = {
                    'source': f'steady.json.reconstruction_accounting.{role} (scenario scope, not M4 window)',
                    **{k: saved.get(k) for k in ('reconstructed', 'download_missing_tx', 'download_root_mismatch',
                                               'download_no_prev_input_block', 'skipped_no_chain', 'unaccounted')}}
    for sender in lines:
        for receiver in lines:
            if sender == receiver:
                continue
            existing = result['M3'].get(sender, {})
            metric = existing if existing.get('receiver') == receiver else dict(
                peer_traffic(lines[sender], lines[receiver], window['boundaries']), receiver=receiver)
            m5[f'{sender}->{receiver}'] = dict(sync_density(metric, intervals, window['boundaries']), sender=sender)
    return {'M4': m4, 'M5': m5, 'reconstruction': reconstruction}


def summary(result):
    return ' | '.join(
        f'{node}: M4 announcements={m["received"]}/{m["mined"]} never-observed={m["never_observed"]} '
        f'rebuilt={result["reconstruction"][node]["rebuilt"]} '
        f'full-download-requested={result["reconstruction"][node]["full_download_requested"]}'
        for node, m in result['M4'].items()) + ' | M5 ' + '; '.join(
            f'{link}: messages/ordering={m["messages_per_ordering_interval"]} '
            f'messages/input={m["messages_per_input_block"]} pairs<250ms={m["pairs_below_250ms"]}'
            for link, m in result['M5'].items())
