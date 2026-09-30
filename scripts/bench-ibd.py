#!/usr/bin/env python3
"""Compare cache budgets on identical disposable early-mainnet IBD replays."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--cache-mib', type=int, nargs='+', default=[16, 128, 1024])
    args = parser.parse_args()
    if args.runs < 1 or any(budget < 1 for budget in args.cache_mib):
        parser.error('runs and cache budgets must be positive')
    if not args.binary.is_file() or not args.snapshot.is_file():
        parser.error('binary and snapshot must exist')
    if args.output_dir.exists():
        parser.error('output directory must be new')
    args.output_dir.mkdir(parents=True)
    snapshot_sha = sha(args.snapshot)
    records = []
    for iteration in range(args.runs):
        # Rotate order to reduce systematic warm-up / time-of-day bias.
        offset = iteration % len(args.cache_mib)
        for budget in args.cache_mib[offset:] + args.cache_mib[:offset]:
            name = f'run-{iteration + 1}-{budget}mib'
            csv_path = args.output_dir.resolve() / f'{name}.csv'
            environment = {**os.environ, 'ERGO_MEM_CSV': str(csv_path), 'ERGO_MEM_MAPS': '1'}
            with tempfile.TemporaryDirectory(prefix='scratch-', dir=args.output_dir) as scratch:
                result = subprocess.run([str(args.binary.resolve()), 'replay', str(Path(scratch) / 'data'),
                                         str(budget * 1024 * 1024), str(args.snapshot.resolve())],
                                        env=environment, text=True, capture_output=True, check=True)
            (args.output_dir / f'{name}.stderr').write_text(result.stderr)
            record = json.loads(result.stdout)
            if not record['restart_verified']:
                raise RuntimeError('replay did not verify restart')
            with csv_path.open() as stream:
                rows = list(csv.DictReader(stream))
            plateau = [row for row in rows if row['sync_phase'] == 'Plateau']
            if not plateau:
                raise RuntimeError('no retained-memory samples')
            record.update(iteration=iteration + 1, sample_count=len(rows),
                          rss_sampled_peak_kib=max(int(row['vm_rss_kb']) for row in rows),
                          plateau_rss_kib=statistics.median(int(row['vm_rss_kb']) for row in plateau),
                          plateau_anon_kib=statistics.median(int(row['rss_anon_kb']) for row in plateau),
                          plateau_file_kib=statistics.median(int(row['rss_file_kb']) for row in plateau),
                          avl_clean_sampled_peak_bytes=max(int(row['avl_cache_clean_bytes']) for row in rows),
                          raw_csv=csv_path.name, host_load_average=list(os.getloadavg()))
            records.append(record)
            (args.output_dir / f'{name}.json').write_text(json.dumps(record, indent=2) + '\n')
            print(json.dumps(record), flush=True)
    if sha(args.snapshot) != snapshot_sha:
        raise RuntimeError('input snapshot changed')
    if len({record['root'] for record in records}) != 1:
        raise RuntimeError('consensus roots differ between runs')
    numeric = ['enqueue_seconds', 'committed_seconds', 'durable_seconds', 'blocks_per_second',
               'rss_sampled_peak_kib', 'plateau_rss_kib', 'plateau_anon_kib', 'plateau_file_kib',
               'avl_clean_sampled_peak_bytes', 'persist_queue_sampled_peak',
               'unpersisted_pinned_bytes_sampled_peak']
    medians = {}
    for budget in args.cache_mib:
        runs = [record for record in records if record['cache_bytes'] == budget * 1024 * 1024]
        medians[str(budget)] = {key: statistics.median(record[key] for record in runs) for key in numeric}
        medians[str(budget)]['phases_ms'] = {
            key: statistics.median(record['phases_ms'][key] for record in runs)
            for key in runs[0]['phases_ms']}
    summary = {'source_commit': command('git', 'rev-parse', 'HEAD'),
               'source_dirty': bool(command('git', 'status', '--porcelain')),
               'binary_sha256': sha(args.binary), 'snapshot_sha256': snapshot_sha,
               'platform': platform.platform(), 'cpu': next(line.split(':', 1)[1].strip()
                  for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')),
               'mem_total': Path('/proc/meminfo').read_text().splitlines()[0],
               'filesystem': command('findmnt', '-T', str(args.output_dir), '-n', '-o', 'SOURCE,FSTYPE'),
               'rustc': command('rustc', '--version'),
               'cache_conditions': 'fresh process and disposable DB copy; fixture/snapshot OS page cache warm; no global cache drop',
               'scope': 'offline mainnet blocks 851..1000, full scripts and shipped-proof verification, no checkpoint; excludes header preparation, downloads, indexer, wallet and mining',
               'runs_per_budget': args.runs, 'medians_by_cache_mib': medians, 'records': records}
    (args.output_dir / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(medians, indent=2))


if __name__ == '__main__':
    main()
