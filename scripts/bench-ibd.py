#!/usr/bin/env python3
"""Matched Linux replay profiles on locked, closed snapshots; never launches a node."""
import argparse
import contextlib
import csv
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MARKER = 'disposable ergo replay copy\n'


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


@contextlib.contextmanager
def locked_snapshot(path):
    """The redb Unix backend also uses flock. Lock before hashing or copying."""
    path = Path(path).absolute()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not path.is_file() or path.stat().st_ino != os.fstat(descriptor).st_ino:
            raise RuntimeError('snapshot changed identity or is not a regular file')
        yield path
        if path.stat().st_ino != os.fstat(descriptor).st_ino:
            raise RuntimeError('snapshot was replaced while locked')
    finally:
        os.close(descriptor)


def profile(value):
    try:
        name, avl, redb = value.split(':')
        if not name or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in name):
            raise ValueError()
        avl, redb = int(avl), int(redb)
        if avl < 0 or redb < 0:
            raise ValueError()
        return name, avl * 1024**2, redb * 1024**2
    except ValueError as error:
        raise argparse.ArgumentTypeError('profile must be NAME:AVL_MIB:REDB_MIB with nonnegative budgets') from error


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True, timeout=10).strip()


def run(args):
    if args.output_dir.exists():
        raise RuntimeError('output directory must be new')
    if len({p[0] for p in args.profile}) != len(args.profile):
        raise RuntimeError('profile names must be unique')
    versions = [('candidate', args.binary.resolve(), args.source_commit)]
    if args.baseline_binary:
        if not args.baseline_source_commit:
            raise RuntimeError('--baseline-source-commit is required for a baseline binary')
        versions.append(('baseline', args.baseline_binary.resolve(), args.baseline_source_commit))
    for _, binary, commit in versions:
        if not binary.is_file() or len(commit) != 40 or any(c not in '0123456789abcdef' for c in commit):
            raise RuntimeError('binaries must exist and source commits must be complete lowercase Git hashes')
        command('git', 'cat-file', '-e', commit + '^{commit}')
    with locked_snapshot(args.snapshot) as snapshot:
        source_hash = sha(snapshot)
        if source_hash != args.snapshot_sha256:
            raise RuntimeError('snapshot does not match pinned SHA-256')
        args.output_dir.mkdir(parents=True)
        output = args.output_dir.resolve()
        metadata = {
            'snapshot_sha256': source_hash, 'snapshot_bytes': snapshot.stat().st_size,
            'runner_commit': command('git', 'rev-parse', 'HEAD'),
            'runner_dirty': bool(command('git', 'status', '--porcelain')),
            'binaries': {label: {'sha256': sha(binary), 'source_commit': commit} for label, binary, commit in versions},
            'platform': platform.platform(), 'cpu': next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), 'unknown'),
            'ram': Path('/proc/meminfo').read_text().splitlines()[0],
            'filesystem': command('findmnt', '-T', str(output), '-n', '-o', 'SOURCE,FSTYPE'),
            'rustc': command('rustc', '--version'),
            'conditions': 'fresh processes and AVL/redb caches; snapshot pages OS-cache warm; no global cache drop; other host work uncontrolled',
            'scope': 'mainnet UTXO full-body validation, current voted params, EIP-27, root checks and clean reopen; excludes header PoW/downloads, indexer, wallets, mining and APIs',
            'blocks': args.blocks, 'proof_policy': args.proof_policy,
            'persist_jobs': args.persist_jobs, 'flush_interval': args.flush_interval,
            'retained_seconds': args.retained_seconds, 'timeout_seconds': args.timeout_seconds,
        }
        (output / 'provenance.json').write_text(json.dumps(metadata, indent=2) + '\n')
        cases = [(p, v) for p in args.profile for v in versions]
        records = []
        try:
            for iteration in range(args.runs):
                offset = iteration % len(cases)
                for (name, avl, redb), (version, binary, _) in cases[offset:] + cases[:offset]:
                    stem = f'run-{iteration + 1}-{name}-{version}'
                    csv_path = output / f'{stem}.csv'
                    with tempfile.TemporaryDirectory(prefix='owned-replay-', dir=output) as scratch:
                        directory = Path(scratch).resolve()
                        shutil.copyfile(snapshot, directory / 'state.redb')
                        (directory / '.ergo-replay-copy').write_text(MARKER)
                        environment = {**os.environ, 'ERGO_MEM_CSV': str(csv_path)}
                        argv = [str(binary), 'replay', str(directory), '--blocks', str(args.blocks),
                                '--avl-cache-bytes', str(avl), '--redb-cache-bytes', str(redb),
                                '--proof-policy', args.proof_policy, '--persist-jobs', str(args.persist_jobs),
                                '--flush-interval', str(args.flush_interval), '--retained-seconds', str(args.retained_seconds)]
                        try:
                            result = subprocess.run(argv, env=environment, text=True, capture_output=True, timeout=args.timeout_seconds, check=False)
                        except subprocess.TimeoutExpired as error:
                            (output / f'{stem}.stderr').write_bytes(error.stderr or b'')
                            (output / f'{stem}.stdout').write_bytes(error.stdout or b'')
                            raise RuntimeError(f'{stem} exceeded timeout; partial output retained') from error
                    (output / f'{stem}.stderr').write_text(result.stderr)
                    (output / f'{stem}.stdout').write_text(result.stdout)
                    if result.returncode:
                        raise RuntimeError(f'{stem} failed ({result.returncode}); output retained')
                    record = json.loads(result.stdout)
                    if not record.get('restart_verified'):
                        raise RuntimeError('replay did not verify clean reopen')
                    with csv_path.open() as stream:
                        rows = list(csv.DictReader(stream))
                    retained = [r for r in rows if r['sync_phase'] == 'Retained']
                    if not retained:
                        raise RuntimeError('no retained-memory samples')
                    record.update(iteration=iteration + 1, profile=name, version=version,
                                  sampled_peak_rss_kib=max(int(r['vm_rss_kb']) for r in rows),
                                  retained_rss_kib=statistics.median(int(r['vm_rss_kb']) for r in retained),
                                  retained_anon_kib=statistics.median(int(r['rss_anon_kb']) for r in retained),
                                  avl_clean_observed_peak_bytes=max(int(r['avl_cache_clean_bytes']) for r in rows),
                                  redb_evictions_after=int(rows[-1]['redb_state_evictions']),
                                  host_load_average=list(os.getloadavg()), samples=len(rows))
                    if record['avl_cache_bytes'] != avl or record['redb_cache_bytes'] != redb:
                        raise RuntimeError('binary did not use requested budgets')
                    records.append(record)
                    (output / f'{stem}.json').write_text(json.dumps(record, indent=2) + '\n')
                    (output / 'records.json').write_text(json.dumps(records, indent=2) + '\n')
                    print(f'{stem}: {record["committed_blocks_per_second"]:.2f} committed blocks/s, {record["retained_rss_kib"]} KiB retained RSS', flush=True)
            if len({(r['start_height'], r['end_height'], r['root']) for r in records}) != 1:
                raise RuntimeError('matched replay heights or roots differ')
            numeric = ['committed_seconds', 'durable_seconds', 'committed_blocks_per_second', 'durable_blocks_per_second',
                       'sampled_peak_rss_kib', 'retained_rss_kib', 'retained_anon_kib', 'redb_evictions_after',
                       'avl_clean_observed_peak_bytes', 'persist_channel_observed_peak_jobs', 'unpersisted_pinned_observed_peak_bytes']
            medians = {}
            for name, _, _ in args.profile:
                for version, _, _ in versions:
                    group = [r for r in records if r['profile'] == name and r['version'] == version]
                    medians[f'{name}/{version}'] = {key: statistics.median(r[key] for r in group) for key in numeric}
                    medians[f'{name}/{version}']['phases_ms'] = {key: statistics.median(r['phases_ms'][key] for r in group) for key in group[0]['phases_ms']}
            metadata.update(medians=medians, records=records)
            (output / 'summary.json').write_text(json.dumps(metadata, indent=2) + '\n')
        finally:
            if sha(snapshot) != source_hash:
                raise RuntimeError('locked input snapshot changed')
            for label, binary, _ in versions:
                if sha(binary) != metadata['binaries'][label]['sha256']:
                    raise RuntimeError(f'{label} executable changed during measurement')
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--baseline-binary', type=Path)
    parser.add_argument('--baseline-source-commit')
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--snapshot-sha256', required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--profile', type=profile, nargs='+', default=[profile('constrained:16:16'), profile('default:1024:1024')])
    parser.add_argument('--blocks', type=int, default=150)
    parser.add_argument('--proof-policy', choices=['regenerate', 'verify-shipped'], default='regenerate')
    parser.add_argument('--persist-jobs', type=int, default=64)
    parser.add_argument('--flush-interval', type=int, default=500)
    parser.add_argument('--retained-seconds', type=int, default=3)
    parser.add_argument('--timeout-seconds', type=float, default=300)
    args = parser.parse_args()
    if min(args.runs, args.blocks, args.persist_jobs, args.retained_seconds, args.timeout_seconds) <= 0 or args.flush_interval < 0:
        parser.error('counts/timeouts must be positive, flush interval nonnegative')
    run(args)


if __name__ == '__main__':
    main()
