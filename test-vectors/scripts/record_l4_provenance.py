#!/usr/bin/env python3
"""Attach source and input hashes to an observed L4 result without changing it."""
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from cost_fixture_io import fixture_path, fixture_paths


def selected_inputs(vectors, ranges):
    """Mirror the replay consumer's gzip preference and overlapping headers."""
    files = set()
    missing = []
    for start, end in ranges:
        for kind in ('tx_costs', 'transactions', 'input_boxes'):
            path = fixture_path(vectors / f'{kind}_{start}_{end}.json')
            if path.exists():
                files.add(path)
            elif kind != 'input_boxes':
                missing.append(path)
    for path in fixture_paths(vectors, 'headers_*'):
        name = path.name.removesuffix('.gz').removesuffix('.json')
        parts = name.split('_')
        if len(parts) == 3 and all(p.isdigit() for p in parts[1:]):
            a, b = map(int, parts[1:])
            if any(a <= end and b >= start - 9 for start, end in ranges):
                files.add(path)
    captured = fixture_path(vectors / 'l4_boxes.json')
    if captured.exists():
        files.add(captured)
    return files, missing


def main():
    root = Path(__file__).resolve().parents[2]
    result_path = Path(sys.argv[1])
    result = json.loads(result_path.read_text())
    files = {root / 'ergo-validation/tests/it/cost_parity.rs',
             root / 'test-vectors/scripts/scala/ComputeTransactionCosts.scala',
             root / result['epoch_manifest']}
    for crate in ('ergo-validation', 'ergo-sigma', 'ergo-ser', 'ergo-primitives', 'ergo-crypto'):
        files.update((root / crate / 'src').rglob('*.rs'))
    selected, missing = selected_inputs(root / 'test-vectors/mainnet', result['required_ranges'])
    files.update(selected)
    def fingerprint(path):
        # Evidence identifies JSON bytes independently of archive storage.
        opener = gzip.open if path.suffix == '.gz' else open
        with opener(path, 'rb') as source:
            return hashlib.file_digest(source, 'sha256').hexdigest()

    result['source_and_input_sha256'] = {
        str(path.relative_to(root)): fingerprint(path) for path in sorted(files)
    }
    result['missing_selected_inputs'] = [str(path.relative_to(root)) for path in missing]
    result['worktree_dirty'] = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=root).strip())
    result['conformance_status'] = 'DIVERGENT' if result['failed'] else 'MATCHED'
    result_path.write_text(json.dumps(result, indent=2) + '\n')
    print(f'Hashed {len(files)} source/input files; selected/executed/failed unchanged')


if __name__ == '__main__':
    main()
