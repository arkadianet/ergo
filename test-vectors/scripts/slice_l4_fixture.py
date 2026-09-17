#!/usr/bin/env python3
"""Pin selected transactions from a completed JVM COST_FIXTURE capture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('output', type=Path)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--heights', type=int, nargs='+')
    selection.add_argument('--transactions', nargs='+')
    args = parser.parse_args()
    raw = args.capture.read_bytes()
    fixture = json.loads(raw)
    selected = [tx for tx in fixture['transactions'] if
                (tx['height'] in args.heights if args.heights else tx['tx_id'] in args.transactions)]
    if not selected:
        raise ValueError('Empty selection')
    heights = {tx['height'] for tx in selected}
    ids = {tx['tx_id'] for tx in selected}
    if (args.heights and heights != set(args.heights)) or (args.transactions and ids != set(args.transactions)):
        raise ValueError('Incomplete selection')
    node = os.environ.get('NODE_URL', 'http://localhost:9053').rstrip('/')

    def get(path):
        with urllib.request.urlopen(node + path, timeout=60) as response:
            return json.load(response)

    box_ids = set()
    for height in sorted(heights):
        block_id = get(f'/blocks/at/{height}')[0]
        block = get('/blocks/' + block_id)
        for tx in block['blockTransactions']['transactions']:
            if tx['id'] in ids:
                box_ids.update(i['boxId'] for i in tx['inputs'] + tx['dataInputs'])
    fixture['transactions'] = selected
    fixture['headers'] = [h for h in fixture['headers'] if any(height - 9 <= h['height'] <= height for height in heights)]
    fixture['parameters'] = {h: p for h, p in fixture['parameters'].items() if int(h) in heights}
    fixture['contexts'] = {h: c for h, c in fixture['contexts'].items() if int(h) in heights}
    fixture['boxes'] = [b for b in fixture['boxes'] if b['box_id'] in box_ids]
    if {b['box_id'] for b in fixture['boxes']} != box_ids:
        raise ValueError('Capture lacks selected input boxes')
    fixture['manifest']['capture_sha256'] = hashlib.sha256(raw).hexdigest()
    fixture['manifest']['selected_heights'] = sorted(heights)
    fixture['manifest']['selected_transactions'] = sorted(ids)
    args.output.write_text(json.dumps(fixture, indent=2) + '\n')
    print(f'{len(selected)} JVM observations, {len(box_ids)} input boxes -> {args.output}')


if __name__ == '__main__':
    main()
