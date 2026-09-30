#!/usr/bin/env python3
"""Compare offline replay binaries on identical disposable database copies."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--blocks', type=int, default=150)
    args = parser.parse_args()
    if args.runs < 1 or not 1 <= args.blocks <= 150:
        parser.error('runs must be positive; blocks must be 1..150')
    for path in (args.snapshot, args.baseline, args.candidate):
        if not path.is_file():
            parser.error(f'file missing: {path}')
    if args.output.exists():
        parser.error('output exists; choose a new path')
    args.work_dir.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(args.work_dir).free < args.snapshot.stat().st_size + 1024**3:
        parser.error('insufficient space for a disposable snapshot copy')
    records = []
    binaries = {'baseline': args.baseline.resolve(), 'candidate': args.candidate.resolve()}
    for iteration in range(args.runs):
        order = ['baseline', 'candidate'] if iteration % 2 == 0 else ['candidate', 'baseline']
        for mode in order:
            with tempfile.TemporaryDirectory(prefix='ergo-replay-', dir=args.work_dir) as directory:
                scratch = Path(directory)
                database = scratch / 'state.redb'
                shutil.copyfile(args.snapshot, database)
                database.chmod(0o600)
                # Exclude flushing the initial multi-GB copy from measured commits.
                with database.open('rb') as stream:
                    os.fsync(stream.fileno())
                (scratch / '.benchmark-copy').write_text('disposable ergo sync benchmark\n')
                result = subprocess.run([str(binaries[mode]), str(database), str(args.blocks)],
                                        capture_output=True, text=True, check=True)
                lines = [line for line in result.stdout.splitlines() if line.startswith('replay ')]
                if len(lines) != 1:
                    raise RuntimeError(f'unexpected replay output: {result.stdout}\n{result.stderr}')
                fields = dict(re.findall(r'(\w+)=([^ ]+)', lines[0]))
                record = {'iteration': iteration + 1, 'mode': mode, **fields}
                records.append(record)
                print(json.dumps(record), flush=True)
    if len({record['root'] for record in records}) != 1:
        raise RuntimeError('baseline and candidate roots differ')
    medians = {mode: statistics.median(float(r['durable_secs']) for r in records if r['mode'] == mode)
               for mode in binaries}
    summary = {'median_durable_seconds': medians,
               'throughput_speedup': medians['baseline'] / medians['candidate'],
               'time_reduction_percent': 100 * (1 - medians['candidate'] / medians['baseline']),
               'records': records}
    args.output.write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k != 'records'}), flush=True)


if __name__ == '__main__':
    main()
