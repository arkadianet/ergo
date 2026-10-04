#!/usr/bin/env python3
"""Compile the shipped offline helper and replay both fixed bundled triplets."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java', required=True)
    parser.add_argument('--scalac-classpath', required=True,
                        help='Scala2.12.20 compiler, reflect and library jars')
    parser.add_argument('--assembly', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    provenance = json.loads((here / 'provenance.json').read_text())
    artifact = args.assembly.read_bytes()
    require(len(artifact) == provenance['release_size'], 'release size mismatch')
    require(sha(artifact) == provenance['release_sha256'], 'release SHA-256 mismatch')
    bundle = json.loads((here / 'capture-inputs.json').read_text())
    for name, expected in provenance['bundled_raw_capture_hashes'].items():
        require(sha(bundle[name].encode('utf-8')) == expected, 'capture hash mismatch: ' + name)
    for name, expected in provenance['reference_source_hashes'].items():
        require(sha((here / name).read_bytes()) == expected, 'source hash mismatch: ' + name)
    helper = here / 'OfflineHistoricalCosts.scala'
    require(sha(helper.read_bytes()) == provenance['helper_sha256'], 'helper hash mismatch')
    compiler = {}
    supplied_names = set()
    for entry in args.scalac_classpath.split(os.pathsep):
        p = Path(entry)
        require(p.name in provenance['compiler_jars'], 'unexpected compiler jar: ' + p.name)
        require(p.name not in supplied_names, 'duplicate compiler jar: ' + p.name)
        supplied_names.add(p.name)
        actual_hash = sha(p.read_bytes())
        require(actual_hash == provenance['compiler_jars'][p.name], 'compiler hash mismatch: ' + p.name)
        compiler[str(p)] = actual_hash
    require(supplied_names == set(provenance['compiler_jars']), 'incomplete compiler jar set')
    args.output.mkdir(parents=True, exist_ok=False)
    classes = args.output / 'classes'
    classes.mkdir()
    env = os.environ.copy()
    env['ERGO_REFERENCE'] = str(here / 'reference')
    commands = [('compile', [args.java, '-cp', args.scalac_classpath,
                 'scala.tools.nsc.Main', '-Xfatal-warnings', '-classpath',
                 str(args.assembly.resolve()), '-d', str(classes.resolve()), str(helper)])]
    runtime_cp = str(classes.resolve()) + os.pathsep + str(args.assembly.resolve())
    commands += [(name, [args.java, '-Xmx512m', '-cp', runtime_cp,
                  'OfflineHistoricalCosts', str(here), name + '-spec.json'])
                 for name in ('v1v2', 'eip37')]
    results = []
    for name, command in commands:
        start = time.monotonic()
        run = subprocess.run(command, cwd=args.output, env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=60, check=False)
        (args.output / (name + '.stdout')).write_bytes(run.stdout)
        (args.output / (name + '.stderr')).write_bytes(run.stderr)
        row = dict(name=name, command=command, exit_code=run.returncode,
                   seconds=time.monotonic() - start,
                   stdout_sha256=sha(run.stdout), stderr_sha256=sha(run.stderr))
        results.append(row)
        record = dict(scope='Offline fixed public data; no node or network requests.',
                      assembly_sha256=sha(artifact), helper_sha256=sha(helper.read_bytes()),
                      compiler_jars=compiler, results=results)
        (args.output / 'results.json').write_text(json.dumps(record, indent=2) + '\n')
        require(run.returncode == 0, name + ' failed: ' + run.stderr.decode())
        if name != 'compile':
            fixture = json.loads(run.stdout)
            expected = json.loads((here / (name + '.json')).read_text())
            for field in ('initial_boxes', 'headers', 'parameters', 'contexts', 'transactions'):
                require(fixture[field] == expected[field], name + ' parity mismatch: ' + field)
            require(len(fixture['transactions']) == expected['expected_transaction_count'], name + ' transaction count mismatch')
            require(len(fixture['initial_boxes']) == expected['expected_box_count'], name + ' initial box count mismatch')
            row['parity_verdict'] = 'PASS'
            row['transactions'] = len(fixture['transactions'])
            row['initial_boxes'] = len(fixture['initial_boxes'])
            (args.output / 'results.json').write_text(json.dumps(record, indent=2) + '\n')
    print('PASS: shipped helper reproduced all43 costs and both initial input subsets')


if __name__ == '__main__':
    main()
