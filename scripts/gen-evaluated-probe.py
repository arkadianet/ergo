#!/usr/bin/env python3
"""Capture a direct EvaluatedValueOracle probe with reproducibility metadata."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from cost_fixture_io import write_fixture_text

root = Path(__file__).resolve().parent.parent
command_name, destination = sys.argv[1:]
script = 'scripts/jvm_evaluated_value_oracle/EvaluatedValueOracle.scala'
command = ['scala-cli', '--skip-cli-updates', 'run', script, '--server=false',
           '--suppress-outdated-dependency-warning', '--', command_name]
request = sys.stdin.buffer.read()
response = subprocess.run(command, cwd=root, input=request, stdout=subprocess.PIPE,
                          check=True).stdout
value = json.loads(response)

def output(*args):
    return subprocess.check_output(args, cwd=root, text=True, stderr=subprocess.STDOUT).strip()

def sha(data):
    return hashlib.sha256(data).hexdigest()

revision = output('git', 'rev-parse', 'HEAD')
manifest = json.loads((root / 'test-vectors/ergo-sigma/verify/manifest.json').read_text())
manifest.update(scala_sigmastate='6.0.2', date=datetime.datetime.now(datetime.timezone.utc).isoformat())
manifest['rust'] = {'git_sha': revision, 'toolchain': output('rustc', '--version'), 'features': []}
manifest['tool'] = {'script': script, 'git_sha': revision,
                    'oracle_sha256': sha((root / script).read_bytes()),
                    'generator': 'scripts/gen-evaluated-probe.py',
                    'scala_cli': output('scala-cli', 'version'), 'scala_directive': '2.12',
                    'jvm': output('java', '-version')}
manifest['context'] = {'network': 'offline direct JVM probe', 'activated_script_version': 3,
                       'ergo_tree_versions': [2, 3], 'voted_params': {}}
manifest['run'] = {'command': ' '.join(command), 'timestamp_utc': manifest['date'],
                   'selected': len(value['cases']), 'executed': len(value['cases']),
                   'skipped': 0, 'failed': 0, 'seeds': None}
manifest['evidence'] = {'request_jsonl_sha256': sha(request), 'response_json_sha256': sha(response)}
value['manifest'] = manifest
serialized = json.dumps(value, indent=2) + '\n'
if destination.endswith('.gz'):
    write_fixture_text(root / destination, serialized)
else:
    (root / destination).write_text(serialized)
print(f"{destination}: {len(value['cases'])} cases captured")
