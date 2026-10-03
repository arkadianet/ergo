#!/usr/bin/env python3
"""Capture direct JVM probes from an immutable, hash-linked source snapshot."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from cost_fixture_io import read_fixture_text, write_fixture_text

SCRIPT = 'scripts/jvm_evaluated_value_oracle/EvaluatedValueOracle.scala'
GENERATOR = 'scripts/gen-evaluated-probe.py'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def output(root, *args):
    return subprocess.check_output(args, cwd=root, text=True, stderr=subprocess.STDOUT).strip()


def snapshot_source(root, script=SCRIPT):
    """Read once, archive before execution, and distinguish base from source state."""
    raw = (root / script).read_bytes()
    revision = output(root, 'git', 'rev-parse', 'HEAD')
    tracked = subprocess.run(['git', 'show', f'{revision}:{script}'], cwd=root,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    tracked_hash = sha(tracked.stdout) if tracked.returncode == 0 else None
    status = subprocess.check_output(['git', 'status', '--porcelain=v1'], cwd=root)
    relative = Path('test-vectors/scala/source-snapshots') / sha(raw) / 'EvaluatedValueOracle.scala'
    archive = root / relative
    archive.parent.mkdir(parents=True, exist_ok=True)
    try:
        with archive.open('xb') as stream:
            stream.write(raw)
    except FileExistsError:
        if archive.read_bytes() != raw:
            raise ValueError(f'source snapshot collision at {relative}')
    state = {'base_revision': revision, 'tracked_source_at_base_sha256': tracked_hash,
             'source_matches_base': tracked_hash == sha(raw),
             'source_revision': revision if tracked_hash == sha(raw) else None,
             'source_snapshot': relative.as_posix(), 'source_sha256': sha(raw),
             'checkout_dirty_before_snapshot': bool(status),
             'checkout_status_sha256_before_snapshot': sha(status)}
    return archive, state


def parse_response(response):
    # A cached Scala CLI update notice is launcher output, not an oracle record.
    lines = []
    notice = False
    for line in response.splitlines():
        if re.fullmatch(rb'Your Scala CLI \d+\.\d+\.\d+ is outdated, please update Scala CLI to \d+\.\d+\.\d+', line):
            notice = True
            print(line.decode(), file=sys.stderr)
            continue
        if notice and line == b"Run 'curl -sSLf https://scala-cli.virtuslab.org/get | sh' to update Scala CLI.":
            notice = False
            print(line.decode(), file=sys.stderr)
            continue
        lines.append(line)
    value = json.loads(b'\n'.join(lines))
    if not isinstance(value, dict) or not isinstance(value.get('cases'), list):
        raise ValueError('direct oracle response must contain a cases array')
    return value


RUNTIME_WRAPPER = b"""// Runtime provenance only; delegate to the unchanged pinned reference probe.
import io.circe.Json
object DirectProbeRuntime {
  def main(args: Array[String]): Unit = {
    val properties = Seq("java.class.path", "java.runtime.version", "java.vm.name", "java.vendor", "java.home")
    val metadata = Json.obj(properties.map(key => key -> Json.fromString(System.getProperty(key, ""))): _*)
    System.err.println("DIRECT_PROBE_RUNTIME_JSON=" + metadata.noSpaces)
    EvaluatedValueOracle.main(args)
  }
}
"""


def runtime_provenance(stderr):
    records = [line.removeprefix(b'DIRECT_PROBE_RUNTIME_JSON=') for line in stderr.splitlines()
               if line.startswith(b'DIRECT_PROBE_RUNTIME_JSON=')]
    if len(records) != 1:
        raise ValueError('expected exactly one actual JVM runtime provenance record')
    runtime = json.loads(records[0])
    import os
    artifacts = []
    for entry in runtime['java.class.path'].split(os.pathsep):
        path = Path(entry)
        if path.suffix == '.jar':
            raw = path.read_bytes()
            artifacts.append({'name': path.name, 'path': str(path), 'sha256': sha(raw), 'bytes': len(raw)})
    if not artifacts:
        raise ValueError('actual JVM classpath did not identify any resolved JARs')
    runtime['resolved_jars'] = artifacts
    return runtime


def capture(root, command_name, destination, request):
    archive, state = snapshot_source(root)
    generator_hash = sha((root / GENERATOR).read_bytes())
    wrapper = archive.parent / sha(RUNTIME_WRAPPER) / 'DirectProbeRuntime.scala'
    wrapper.parent.mkdir(exist_ok=True)
    try:
        with wrapper.open('xb') as stream:
            stream.write(RUNTIME_WRAPPER)
    except FileExistsError:
        if wrapper.read_bytes() != RUNTIME_WRAPPER:
            raise ValueError('runtime wrapper snapshot changed')
    command = ['scala-cli', '--skip-cli-updates', 'run', str(archive), str(wrapper), '--server=false',
               '--main-class', 'DirectProbeRuntime', '--suppress-outdated-dependency-warning', '--', command_name]
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result = subprocess.run(command, cwd=root, input=request, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=True, timeout=180)
    sys.stderr.buffer.write(result.stderr)
    if sha(archive.read_bytes()) != state['source_sha256'] or wrapper.read_bytes() != RUNTIME_WRAPPER:
        raise ValueError('executed source snapshot changed during capture')
    runtime = runtime_provenance(result.stderr)
    value = parse_response(result.stdout)
    authority = json.loads((root / 'test-vectors/ergo-sigma/verify/manifest.json').read_text())['scala']
    # Copy only dependency/source authority. A rent/verify run is separate work
    # and must not be inherited as evidence for a direct probe.
    manifest = {'scala': authority, 'scala_sigmastate': '6.0.6',
                'date': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'rust': {'git_sha': state['base_revision'], 'toolchain': output(root, 'rustc', '--version'), 'features': []},
                'tool': {'script': SCRIPT, 'git_sha': state['base_revision'],
                         'git_sha_role': 'checkout base; source_state identifies executed snapshot',
                         'oracle_sha256': state['source_sha256'], 'source_state': state,
                         'generator': GENERATOR, 'generator_sha256': generator_hash,
                         'runtime_wrapper_snapshot': wrapper.relative_to(root).as_posix(),
                         'runtime_wrapper_sha256': sha(RUNTIME_WRAPPER), 'actual_runtime': runtime,
                         'scala_cli': output(root, 'scala-cli', 'version'), 'scala_directive': '2.12',
                         'jvm': output(root, 'java', '-version')},
                'context': {'network': 'offline direct JVM probe',
                            'version_context': 'command-specific; see archived source'},
                'run': {'command_argv': command, 'timestamp_utc': start,
                        'completed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        'selected': len(value['cases']), 'executed': len(value['cases']),
                        'skipped': 0, 'failed': 0, 'seeds': None,
                        'count_semantics': 'cases reported by oracle; capture only, no expected-result comparison'},
                'evidence': {'request_jsonl_sha256': sha(request), 'response_json_sha256': sha(result.stdout),
                             'stderr_sha256': sha(result.stderr)}}
    value['manifest'] = manifest
    path = root / destination
    if command_name == 'raw_coll_equals' and str(destination).endswith('.json.gz'):
        fixture = json.loads(read_fixture_text(path))
        fixture['raw_probe'] = value
        value = fixture
    serialized = json.dumps(value, indent=2) + '\n'
    if path.suffix == '.gz':
        write_fixture_text(path, serialized)
    else:
        # Keep direct include_str! fixtures plain when explicitly requested.
        path.write_text(serialized)
    print(f"{destination}: {manifest['run']['executed']} cases captured from {state['source_sha256']}")


def main():
    if len(sys.argv) != 3:
        raise SystemExit('usage: gen-evaluated-probe.py COMMAND DESTINATION < requests')
    capture(Path(__file__).resolve().parent.parent, sys.argv[1], Path(sys.argv[2]), sys.stdin.buffer.read())


if __name__ == '__main__':
    main()
