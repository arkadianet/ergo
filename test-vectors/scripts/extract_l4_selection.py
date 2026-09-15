#!/usr/bin/env python3
"""Capture sparse L4 windows serially in one pinned JVM oracle invocation.

The selection is the Rust runner's required_ranges diagnostic. A single JVM
preserves unmodified validateStateful observations and avoids a compiler launch
per voted-parameter change. Each gap reloads its epoch and nine-header context.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('selection', type=Path)
    parser.add_argument('work', type=Path)
    parser.add_argument('--resume-fixture', action='store_true', help='Split a completed COST_FIXTURE capture')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    vectors = root / 'test-vectors/mainnet'
    required = json.loads(args.selection.read_text())['required_ranges']
    fixture_file = work / 'fixture.json'
    if args.resume_fixture:
        fixture = json.loads(fixture_file.read_text())
        heights = sorted(map(int, fixture['parameters']))
        captured_heights = set(heights)
        ranges = [(a, b) for a, b in required if set(range(a, b + 1)) <= captured_heights]
    else:
        header_ranges = []
        for path in vectors.glob('headers_*.json'):
            parts = path.stem.split('_')
            if len(parts) == 3 and all(part.isdigit() for part in parts[1:]):
                header_ranges.append(tuple(map(int, parts[1:])))

        def complete(start, end):
            return (all((vectors / f'{kind}_{start}_{end}.json').exists() for kind in ('tx_costs', 'transactions'))
                    and any(a <= start - 9 and b >= end for a, b in header_ranges)
                    and ((vectors / 'l4_boxes.json').exists() or (vectors / f'input_boxes_{start}_{end}.json').exists()))

        ranges = [(a, b) for a, b in required if not complete(a, b)]
        if not ranges:
            print('All required replay bundles already exist')
            return
        heights = sorted({h for a, b in ranges for h in range(a, b + 1)})
        height_file = work / 'heights.json'
        height_file.write_text(json.dumps(heights))
        env = dict(os.environ, COST_HEIGHTS=str(height_file), COST_FIXTURE=str(fixture_file), TMPDIR=str(work))
        with (work / 'oracle-stdout.log').open('w') as output, (work / 'oracle.log').open('w') as log:
            subprocess.run(['bash', str(root / 'test-vectors/scripts/extract_block_costs_voted_params.sh'),
                            str(heights[0]), str(heights[-1]), str(work / 'costs.json')],
                           env=env, stdout=output, stderr=log, check=True)
        fixture = json.loads(fixture_file.read_text())
    # COST_FIXTURE is written only after every validateStateful call reconciles.
    # JVM logging may precede JSON on stdout; the dedicated fixture is JSON only.
    if fixture['manifest']['node_app_version'] != '6.0.5':
        raise ValueError('Wrong oracle node version')
    if sorted(map(int, fixture['parameters'])) != heights:
        raise ValueError('Captured heights differ from the required selection')
    if any('bytes_to_sign' not in tx for tx in fixture['transactions']):
        unsigned_input = work / 'signing-input.hex'
        unsigned_output = work / 'signing-output.hex'
        unsigned_input.write_text(''.join(f"{tx['tx_id']} {tx['tx_bytes']}\n" for tx in fixture['transactions']))
        subprocess.run(['scala-cli', 'run', str(root / 'test-vectors/scripts/scala/CompleteCostFixture.scala'),
                        '--server=false', '--suppress-outdated-dependency-warning', '--',
                        str(unsigned_input), str(unsigned_output)], check=True)
        signing_bytes = dict(line.split() for line in unsigned_output.read_text().splitlines())
        for tx in fixture['transactions']:
            tx['bytes_to_sign'] = signing_bytes[tx['tx_id']]
    costs = [{k: v for k, v in tx.items() if k not in ('tx_bytes', 'bytes_to_sign')} for tx in fixture['transactions']]
    for start, end in ranges:
        selected = [tx for tx in fixture['transactions'] if start <= tx['height'] <= end]
        files = {
            f'tx_costs_{start}_{end}.json': [tx for tx in costs if start <= tx['height'] <= end],
            f'transactions_{start}_{end}.json': [dict(id=tx['tx_id'], bytes=tx['tx_bytes'], bytesToSign=tx['bytes_to_sign'], height=tx['height']) for tx in selected],
            f'headers_{start-9}_{end}.json': [h for h in fixture['headers'] if start-9 <= h['height'] <= end],
        }
        for name, data in files.items():
            temporary = vectors / (name + '.tmp')
            temporary.write_text(json.dumps(data) + '\n')
            temporary.replace(vectors / name)
    # Canonical JVM box bytes shared by the captured sparse ranges.
    box_file = vectors / 'l4_boxes.json'
    boxes = {b['box_id']: b for b in json.loads(box_file.read_text())} if box_file.exists() else {}
    for box in fixture['boxes']:
        if box['box_id'] in boxes and boxes[box['box_id']] != box:
            raise ValueError('Conflicting canonical bytes for the same box ID')
        boxes[box['box_id']] = box
    temporary = box_file.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(list(boxes.values())) + '\n')
    temporary.replace(box_file)
    print(f'Captured {len(ranges)} ranges, {len(heights)} heights, {len(costs)} transactions')


if __name__ == '__main__':
    main()
