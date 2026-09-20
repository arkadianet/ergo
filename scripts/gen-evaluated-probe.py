#!/usr/bin/env python3
"""Capture a direct EvaluatedValueOracle probe with reproducibility metadata."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from cost_fixture_io import read_fixture_text, write_fixture_text

root = Path(__file__).resolve().parent.parent
command_name, destination = sys.argv[1:]
script = 'scripts/jvm_evaluated_value_oracle/EvaluatedValueOracle.scala'
command = ['scala-cli', '--skip-cli-updates', 'run', script, '--server=false',
           '--suppress-outdated-dependency-warning', '--', command_name]
request = sys.stdin.buffer.read()
response = subprocess.run(command, cwd=root, input=request, stdout=subprocess.PIPE,
                          check=True).stdout
# scala-cli may print its cached update notice even with --skip-cli-updates.
lines = []
launcher_notice = False
for line in response.splitlines():
    if re.fullmatch(rb"Your Scala CLI \d+\.\d+\.\d+ is outdated, please update Scala CLI to \d+\.\d+\.\d+", line):
        launcher_notice = True
        print(line.decode(), file=sys.stderr)
        continue
    if launcher_notice and line == b"Run 'curl -sSLf https://scala-cli.virtuslab.org/get | sh' to update Scala CLI.":
        launcher_notice = False
        print(line.decode(), file=sys.stderr)
        continue
    lines.append(line)
value = json.loads(b"\n".join(lines))

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
if command_name == 'raw_coll_equals' and destination.endswith('.json.gz'):
    # Keep the verify requests/results together with their direct representation probe.
    fixture = json.loads(read_fixture_text(root / destination))
    fixture['raw_probe'] = value
    value = fixture
serialized = json.dumps(value, indent=2) + '\n'
if destination.endswith('.gz'):
    write_fixture_text(root / destination, serialized)
else:
    (root / destination).write_text(serialized)
print(f"{destination}: {manifest['run']['executed']} cases captured")
