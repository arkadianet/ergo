#!/usr/bin/env python3
"""Emit L4 provenance, or add/refresh only the manifest of a recorded result.

--manifest-only never replays transactions. Historical rust/run metadata remains
attributed to its recorded revision; a new collection records today's commands.
The diagnostics harness supplies a closed range-summary log via --log.
Existing manifests are validated and preserved, including collection metadata.
Offline idempotence check (from the worktree root):
    NODE_URL=http://127.0.0.1:1 python3 scripts/l4-results-manifest.py \
        --manifest-only test-vectors/ergo-sigma/cost-ledger/results/l4-2026-09-16.json \
        --log .superpowers/task-8.1-l4.log
    git diff --exit-code -- test-vectors/ergo-sigma/cost-ledger/results/l4-2026-09-16.json
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
EPOCHS = 'test-vectors/ergo-sigma/cost-total/mainnet-epochs.json.gz'
ORACLE = 'test-vectors/scripts/scala/ComputeTransactionCosts.scala'
WRITER = 'scripts/l4-results-manifest.py'
PREFIX = b'{\n  "manifest": '


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, stderr=subprocess.STDOUT, text=True).strip()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def recorded_bytes(raw):
    """Remove only our leading member, retaining all original bytes after `{`."""
    data = json.loads(raw)
    if 'manifest' not in data:
        if not raw.startswith(b'{'):
            raise ValueError('results must start with an object')
        return raw
    if not raw.startswith(PREFIX):
        raise ValueError('refusing to rewrite a manifest in an unknown layout')
    suffix = raw[len(PREFIX):].decode()
    _, end = json.JSONDecoder().raw_decode(suffix)
    if not suffix[end:].startswith(','):
        raise ValueError('manifest must precede recorded results')
    return b'{' + suffix[end + 1:].encode()


def with_manifest(raw, manifest):
    original = recorded_bytes(raw)
    return PREFIX + json.dumps(manifest, indent=2).encode() + b',' + original[1:]


def range_context(ranges):
    snapshot = json.loads(gzip.decompress((ROOT / EPOCHS).read_bytes()))
    epochs = snapshot['epochs']
    mapped = []
    for item in ranges:
        start, end = item['start'], item['end']
        segments = []
        for index, epoch in enumerate(epochs):
            stop = epochs[index + 1]['height'] - 1 if index + 1 < len(epochs) else snapshot['tip_height']
            low, high = max(start, epoch['height']), min(end, stop)
            if low > high:
                continue
            fields = dict(epoch['fields'])
            params = {str(i): int.from_bytes(bytes.fromhex(fields[f'00{i:02x}']), 'big', signed=True) for i in range(4, 9)}
            version = int(fields['007b'], 16)
            segments.append({'heights': [low, high], 'epoch_height': epoch['height'],
                             'activated_script_version': version - 1,
                             'block_version': version, 'params': params})
        if not segments or segments[0]['heights'][0] != start or segments[-1]['heights'][1] != end:
            raise ValueError(f'epoch snapshot does not cover {start}-{end}')
        if any(a['heights'][1] + 1 != b['heights'][0] for a, b in zip(segments, segments[1:])):
            raise ValueError('gap in epoch snapshot')
        mapped.append({'heights': [start, end], 'segments': segments})
    return {'network': 'mainnet', 'heights': [min(r['start'] for r in ranges), max(r['end'] for r in ranges)],
            'mapping': 'Inclusive per-range segments from mainnet epoch extension bytes; these describe chain parameters, not any historical runner approximation.',
            'ranges': mapped}


def vector_evidence():
    """Hash logical JSON inputs, preserving evidence keys across compression."""
    directory = ROOT / 'test-vectors/mainnet'
    paths = {path.with_suffix('') for path in directory.glob('*.json.gz')}
    paths.update(directory.glob('*.json'))
    evidence = {}
    for path in sorted(paths):
        if path.name.startswith(('tx_costs_', 'transactions_', 'headers_', 'input_boxes_', 'l4_boxes')):
            compressed = path.with_suffix('.json.gz')
            raw = gzip.decompress(compressed.read_bytes()) if compressed.exists() else path.read_bytes()
            evidence[str(path.relative_to(ROOT))] = digest(raw)
    return evidence


def collect(data, original, log, manifest_only, run_command, features, previous=None):
    home = Path.home()
    references = {
        'sigmastate_v6.0.2': (home / 'coding/reference/ergo-core/sigmastate-interpreter-v6.0.2', 'v6.0.2'),
        'ergo_v6.0.2': (home / 'coding/reference/ergo-core/ergo', 'v6.0.2'),
        'ergo_v6.0.5': (home / 'coding/development/arkadianet/ergo-scala', 'v6.0.5'),
        'sigmastate_v6.0.6': (home / 'coding/development/arkadianet/sigmastate-interpreter', 'v6.0.6'),
    }
    shas = {name: command('git', '-C', str(path), 'rev-parse', tag + '^{commit}') for name, (path, tag) in references.items()}
    evidence = {EPOCHS: digest((ROOT / EPOCHS).read_bytes()), str(log): digest((ROOT / log).read_bytes()),
                'recorded_results_bytes_without_manifest': digest(original)}
    context = range_context(data['ranges'])
    if manifest_only and previous is not None:
        if any(previous['evidence'].get(name) != sha for name, sha in evidence.items()):
            raise ValueError('recorded evidence hash missing or changed')
        if previous['context'] != context:
            raise ValueError('recorded context changed')
        for name, sha in previous['scala']['source_shas'].items():
            if name in shas and sha != shas[name]:
                raise ValueError(f'recorded source pin differs: {name}')
        return previous
    source = (ROOT / ORACLE).read_text()
    if manifest_only:
        scala = data['scala']
    else:
        with urlopen(os.environ.get('NODE_URL', 'http://localhost:9053').rstrip('/') + '/info', timeout=30) as response:
            node = json.load(response)
        versions = dict(re.findall(r'//> using dep [\w.]+::([\w-]+):([\d.]+)', source))
        scala = {'ergo_version': versions['ergo-core'], 'sigmastate_version': versions['sigma-state'],
                 'node_app_version': node['appVersion'], 'source_shas': shas}
        if scala['node_app_version'] != scala['ergo_version']:
            raise ValueError('node and extractor versions differ')
    rust = {'git_sha': command('git', 'rev-parse', 'HEAD'), 'toolchain': command('rustc', '--version'), 'features': features,
            'working_diff_sha256': digest(command('git', 'diff', 'HEAD', '--', 'ergo-validation', WRITER).encode())}
    tool = {'script': ORACLE, 'script_sha': command('git', 'log', '-1', '--format=%H', '--', ORACLE),
            'script_sha256': digest(source.encode()), 'scala_cli': command('scala-cli', 'version'),
            'jvm': command('java', '-version'), 'writer': WRITER, 'writer_sha256': digest((ROOT / WRITER).read_bytes())}
    now = datetime.now(timezone.utc).isoformat()
    run = {'command': run_command, 'seeds': [], 'timestamp': now}
    if manifest_only:
        # Recomputed hashes validate the original log; current tools cannot be
        # represented as the tools that executed an earlier replay.
        previous_log = data.get('run', {}).get('log_sha256') or data.get('evidence', {}).get('sha256', {}).get(str(log))
        if previous_log is None or previous_log != evidence[str(log)]:
            raise ValueError('recorded replay log hash missing or changed')
        for name, sha in data['scala']['source_shas'].items():
            if name in shas and sha != shas[name]:
                raise ValueError(f'recorded source pin differs: {name}')
        historical_run = data['run']
        replay_command = historical_run.get('command') or historical_run['replay_command']
        manifest = {'scala': data['scala'], 'rust': data['rust'], 'tool': dict(data['tool']),
                    'run': {'command': replay_command, 'seeds': historical_run['seeds'], 'timestamp': historical_run['timestamp']}}
        old_tool = manifest['tool']
        old_tool['script_sha'] = old_tool.get('git_sha', 'unavailable; see captures')
        old_tool['scala_cli'] = old_tool.get('scala_cli_version', 'unavailable; see captures')
        old_tool['jvm'] = old_tool.get('jvm_version', 'unavailable; see captures')
        manifest['collection'] = {'mode': 'manifest-only; no replay', 'scala': scala, 'rust': rust, 'tool': tool, 'run': run}
        manifest['recorded_evidence'] = data.get('evidence', data.get('source_and_input_sha256', {}))
    else:
        manifest = {'scala': scala, 'rust': rust, 'tool': tool, 'run': run}
        # The harness scans overlapping header files as well as per-range vectors.
        evidence.update(vector_evidence())
    manifest['context'] = context
    manifest['evidence'] = evidence
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest-only', type=Path, help='update a recorded result in place, without replay')
    parser.add_argument('--log', required=True, type=Path, help='closed replay log, relative to the worktree')
    parser.add_argument('--run-command', help='exact replay invocation (required for stdin emission)')
    parser.add_argument('--features', default='diagnostics,cost-trace,test-helpers', help='enabled ergo-validation features')
    args = parser.parse_args()
    if not args.manifest_only and not args.run_command:
        parser.error('--run-command is required for replay emission')
    raw = args.manifest_only.read_bytes() if args.manifest_only else sys.stdin.buffer.read()
    original = recorded_bytes(raw)
    invocation = shlex.join(['python3', WRITER, *sys.argv[1:]])
    previous = json.loads(raw).get('manifest')
    manifest = collect(json.loads(original), original, args.log, bool(args.manifest_only),
                       invocation if args.manifest_only else args.run_command, args.features.split(','), previous)
    output = with_manifest(raw, manifest)
    assert recorded_bytes(output) == original
    if args.manifest_only:
        args.manifest_only.write_bytes(output)
    else:
        sys.stdout.buffer.write(output)


if __name__ == '__main__':
    main()
