#!/usr/bin/env python3
"""Offline relay re-score: relay_rescore.py <archived run or campaign directory>."""
import argparse
import json
import sys
from pathlib import Path

from relay_classification import DELAY_SECONDS, classify
from relay_measurement import coverage, miner_window, peer_traffic, scala_received, staleness


def rescore(directory, delay_seconds=DELAY_SECONDS):
    path = directory / 'steady.json'
    if not path.is_file():
        path = directory / 'campaign' / 'steady.json'
    saved = json.loads(path.read_text())['relay_refresh']
    # Embedded lines preserve exactly the live poll window, including receipt
    # cutoff; full node logs contain warm-up and post-measurement activity.
    lines = saved['source_lines']
    start_height = int(next(iter(next(iter(saved['M1'].values()))['per_interval'])))
    intervals, boundaries = miner_window(lines['scala'], start_height, saved['window']['start'])
    result = dict(saved)
    result['window'] = dict(saved['window'], end=boundaries[-1], boundaries=boundaries)
    result['M1'] = {node: coverage(intervals, scala_received(lines[node]) if node in lines
                                   else set(metric['received_ids']))
                    for node, metric in saved['M1'].items()}
    result['M2'] = {node: dict(staleness([r for r in metric['raw_samples'] if r['at'] < boundaries[-1]]),
                              raw_samples=metric['raw_samples']) for node, metric in saved['M2'].items()}
    result['M3'] = {}
    for sender in lines:
        receiver = 'scala2' if sender == 'scala' else 'scala'
        result['M3'][sender] = (dict(peer_traffic(lines[sender], lines[receiver], boundaries), receiver=receiver)
                                if receiver in lines else {'unavailable': 'no stock Scala receiver'})
    result['classification'] = classify(result, delay_seconds)
    result['rescore'] = {'source': str(path), 'rust_coverage_source': 'archived successful API IDs; no offline re-probe'}
    # Source-line references in classifications index the embedded arrays, 1-based.
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence_dir', type=Path)
    parser.add_argument('--delay-seconds', type=float, default=DELAY_SECONDS)
    args = parser.parse_args()
    result = rescore(args.evidence_dir, args.delay_seconds)
    result.pop('source_lines')
    # Raw observations stay in the immutable archive; output keeps computed
    # metrics and per-block cause evidence without duplicating all log traffic.
    for metric in result['M3'].values():
        metric.pop('receiver_events', None)
    json.dump(result, sys.stdout, indent=2)
    print()


if __name__ == '__main__':
    main()
