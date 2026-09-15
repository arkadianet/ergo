#!/usr/bin/env python3
"""Fetch the exact missing input IDs itemized by the L4 replay harness."""
import json
import os
from pathlib import Path
import sys
import urllib.request


def main():
    manifest = json.loads(Path(os.environ['L4_DIAGNOSTICS']).read_text())
    output = Path(sys.argv[3])
    start, end = map(int, sys.argv[1:3])
    selected = next(r for r in manifest['ranges'] if (r['start'], r['end']) == (start, end))
    ids = sorted({box for skipped in selected['skipped'] for box in skipped['missing_boxes']})
    boxes = {b['boxId']: b for b in json.loads(output.read_text())} if output.exists() else {}
    node = os.environ.get('NODE_URL', 'http://localhost:9053').rstrip('/')
    for index, box_id in enumerate(ids):
        if box_id in boxes:
            continue
        with urllib.request.urlopen(f'{node}/blockchain/box/byId/{box_id}', timeout=60) as response:
            box = json.load(response)
        if box['boxId'] != box_id:
            raise ValueError(f'Wrong box returned for {box_id}')
        boxes[box_id] = box
        if index % 1000 == 0:
            print(f'Fetched {index + 1}/{len(ids)} missing boxes', flush=True)
    temporary = output.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(list(boxes.values())) + '\n')
    temporary.replace(output)
    print(f'{output}: {len(boxes)} boxes; all {len(ids)} missing IDs fetched')


if __name__ == '__main__':
    main()
