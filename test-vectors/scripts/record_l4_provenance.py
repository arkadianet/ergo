#!/usr/bin/env python3
"""Attach source and input hashes to an observed L4 result without changing it."""
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[2]
    result_path = Path(sys.argv[1])
    result = json.loads(result_path.read_text())
    files = {root / 'ergo-validation/tests/it/cost_parity.rs',
             root / 'test-vectors/scripts/scala/ComputeTransactionCosts.scala',
             root / result['epoch_manifest']}
    for crate in ('ergo-validation', 'ergo-sigma', 'ergo-ser', 'ergo-primitives', 'ergo-crypto'):
        files.update((root / crate / 'src').rglob('*.rs'))
    vectors = root / 'test-vectors/mainnet'
    for start, end in result['required_ranges']:
        for kind in ('tx_costs', 'transactions', 'input_boxes'):
            path = vectors / f'{kind}_{start}_{end}.json'
            if path.exists():
                files.add(path)
    for path in vectors.glob('headers_*.json'):
        parts = path.stem.split('_')
        if len(parts) == 3 and all(p.isdigit() for p in parts[1:]):
            a, b = map(int, parts[1:])
            if any(a <= end and b >= start - 9 for start, end in result['required_ranges']):
                files.add(path)
    if (vectors / 'l4_boxes.json').exists():
        files.add(vectors / 'l4_boxes.json')
    def fingerprint(path):
        # Evidence identifies JSON bytes independently of archive storage.
        opener = gzip.open if path.suffix == '.gz' else open
        with opener(path, 'rb') as source:
            return hashlib.file_digest(source, 'sha256').hexdigest()

    result['source_and_input_sha256'] = {
        str(path.relative_to(root)): fingerprint(path) for path in sorted(files)
    }
    result['worktree_dirty'] = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=root).strip())
    result['conformance_status'] = 'DIVERGENT' if result['failed'] else 'MATCHED'
    result_path.write_text(json.dumps(result, indent=2) + '\n')
    print(f'Hashed {len(files)} source/input files; selected/executed/failed unchanged')


if __name__ == '__main__':
    main()
