#!/usr/bin/env python3
"""Read-only Linux IBD/RSS sampling. Does not restart or reconfigure the node."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import statistics
import time
import urllib.request


def proc_values(path):
    result = {}
    for line in path.read_text().splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            token = value.split()
            if token and token[0].isdigit():
                result[key] = int(token[0])
    return result


def mappings(path):
    buckets = {}
    current = None
    for line in path.read_text().splitlines():
        fields = line.split(maxsplit=5)
        if fields and '-' in fields[0]:
            name = fields[5] if len(fields) > 5 else ''
            if name == '[heap]':
                current = 'heap'
            elif name.startswith('[stack'):
                current = 'stack'
            elif not name or name.startswith('[anon'):
                current = 'anonymous'
            elif '.redb' in name:
                current = 'redb_file'
            else:
                current = 'other_file_or_special'
            buckets.setdefault(current, {'virtual_kib': 0, 'rss_kib': 0})
        elif current and fields and fields[0] in ('Size:', 'Rss:'):
            key = 'virtual_kib' if fields[0] == 'Size:' else 'rss_kib'
            buckets[current][key] += int(fields[1])
    return buckets


def fetch(base, endpoint):
    with urllib.request.urlopen(base.rstrip('/') + endpoint, timeout=10) as response:
        return response.read().decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--duration', type=float, default=120)
    parser.add_argument('--interval', type=float, default=1)
    args = parser.parse_args()
    if args.output_dir.exists() or args.duration <= 0 or args.interval <= 0:
        parser.error('choose a new output directory and positive durations')
    proc = Path('/proc') / str(args.pid)
    # No process discovery, signals, credentials or environment reads.
    executable_sha = hashlib.sha256((proc / 'exe').read_bytes()).hexdigest()
    args.output_dir.mkdir(parents=True)
    start_maps = mappings(proc / 'smaps')
    rows = []
    started = time.monotonic()
    with (args.output_dir / 'samples.jsonl').open('w') as stream:
        while True:
            info = json.loads(fetch(args.url, '/info'))
            sync = json.loads(fetch(args.url, '/api/v1/sync'))
            metrics = {}
            for line in fetch(args.url, '/metrics').splitlines():
                if line and not line.startswith('#') and '{' not in line:
                    key, value = line.split()
                    if key.startswith(('ergo_dl_', 'ergo_orphan_', 'ergo_rss_', 'ergo_node_last_apply_', 'ergo_node_apply_', 'ergo_node_block_apply_errors_')):
                        metrics[key] = float(value)
            status = proc_values(proc / 'status')
            rollup = proc_values(proc / 'smaps_rollup')
            row = {'elapsed_seconds': time.monotonic() - started,
                   'timestamp_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   'full_height': info['fullHeight'], 'header_height': info['headersHeight'],
                   'state_root': info['stateRoot'], 'sync': sync, 'metrics': metrics,
                   'resident_kib': {key: status.get(key, 0) for key in ('VmRSS', 'RssAnon', 'RssFile')},
                   'smaps_kib': {key: rollup.get(key, 0) for key in ('Rss', 'Pss', 'Anonymous', 'Private_Dirty', 'Private_Clean')}}
            stream.write(json.dumps(row) + '\n')
            stream.flush()
            rows.append(row)
            if row['elapsed_seconds'] >= args.duration:
                break
            time.sleep(args.interval)
    end_maps = mappings(proc / 'smaps')
    if hashlib.sha256((proc / 'exe').read_bytes()).hexdigest() != executable_sha:
        raise RuntimeError('node executable changed during observation')
    duration = rows[-1]['elapsed_seconds'] - rows[0]['elapsed_seconds']
    blocks = rows[-1]['full_height'] - rows[0]['full_height']
    if blocks < 0:
        raise RuntimeError('reorg in interval: do not report forward IBD throughput')
    summary = {'executable_sha256': executable_sha, 'pid': args.pid, 'sample_count': len(rows),
               'started_utc': rows[0]['timestamp_utc'], 'ended_utc': rows[-1]['timestamp_utc'],
               'start_height': rows[0]['full_height'], 'end_height': rows[-1]['full_height'],
               'duration_seconds': duration, 'blocks_per_second': blocks / duration,
               'rss_sampled_peak_kib': max(row['resident_kib']['VmRSS'] for row in rows),
               'rss_first_kib': rows[0]['resident_kib']['VmRSS'], 'rss_last_kib': rows[-1]['resident_kib']['VmRSS'],
               'anon_first_kib': rows[0]['resident_kib']['RssAnon'], 'anon_last_kib': rows[-1]['resident_kib']['RssAnon'],
               'file_first_kib': rows[0]['resident_kib']['RssFile'], 'file_last_kib': rows[-1]['resident_kib']['RssFile'],
               'pending_blocks_sampled_peak': max(row['sync']['pending_blocks'] for row in rows),
               'metric_sampled_peaks': {key: max(row['metrics'][key] for row in rows) for key in rows[0]['metrics']},
               'last_apply_duration_ms_median': statistics.median(row['metrics']['ergo_node_last_apply_duration_ms'] for row in rows),
               'mapping_buckets_start': start_maps, 'mapping_buckets_end': end_maps,
               'scope': 'live observation, no cache change, restart, global cache drop or phase-counter reset; sampled peaks are lower bounds'}
    (args.output_dir / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
