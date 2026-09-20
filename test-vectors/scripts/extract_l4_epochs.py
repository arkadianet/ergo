#!/usr/bin/env python3
"""Record every mainnet epoch extension and locate block-version transitions."""
import argparse
import json
import os
import sys
from pathlib import Path
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from cost_fixture_io import write_fixture_text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    node = os.environ.get('NODE_URL', 'http://localhost:9053').rstrip('/')

    def get(path):
        with urllib.request.urlopen(node + path, timeout=60) as response:
            return json.load(response)

    info = get('/info')
    if info['appVersion'] != '6.0.5' or info['network'] != 'mainnet':
        raise ValueError('Expected mainnet oracle node 6.0.5')
    records = []
    for height in range(1024, info['fullHeight'] + 1, 1024):
        block_id = get(f'/blocks/at/{height}')[0]
        block = get('/blocks/' + block_id)
        records.append(dict(height=height, block_id=block_id,
                            header_version=block['header']['version'], fields=block['extension']['fields']))
    activations = []
    previous_version = records[0]['header_version']
    for epoch in records[1:]:
        version = epoch['header_version']
        if version == previous_version:
            continue
        low, high = epoch['height'] - 1024, epoch['height']
        while high - low > 1:
            middle = (low + high) // 2
            block_id = get(f'/blocks/at/{middle}')[0]
            if get('/blocks/' + block_id + '/header')['version'] >= version:
                high = middle
            else:
                low = middle
        boundary = []
        for height in (high - 1, high):
            block_id = get(f'/blocks/at/{height}')[0]
            boundary.append(get('/blocks/' + block_id + '/header'))
        activations.append(dict(height=high, version=version, headers=boundary))
        previous_version = version
    write_fixture_text(args.output, json.dumps(dict(node_version=info['appVersion'], tip_height=info['fullHeight'],
                                         activations=activations, epochs=records), indent=2) + '\n')
    print(f'{len(records)} epochs, activations: {[(a["height"], a["version"]) for a in activations]}')


if __name__ == '__main__':
    main()
