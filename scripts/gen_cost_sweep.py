"""Capture JVM boundary verdicts without inferring them from measured costs."""
import copy
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import sys

from cost_fixture_io import fixture_paths, read_fixture_text, write_fixture_text

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'test-vectors/ergo-sigma/cost-ledger/sweeps'
VERIFY = 'scripts/jvm_evaluated_value_oracle/EvaluatedValueOracle.scala'
TX = 'scripts/jvm_cost_sweep_oracle/CostSweepOracle.scala'
SOURCE = 'test-vectors/scala/multi_input_conjunction_cost.json'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True, stderr=subprocess.STDOUT).strip()


def scala(script, args, requests=None):
    argv = ['scala-cli', '--skip-cli-updates', 'run', script, '--server=false',
            '--suppress-outdated-dependency-warning', '--', *args]
    return subprocess.run(argv, cwd=ROOT, input=requests, stdout=subprocess.PIPE, check=True).stdout


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    original = json.loads((ROOT / SOURCE).read_text())
    manifest = copy.deepcopy(original['manifest'])
    manifest['rust'] = {'git_sha': command('git', 'rev-parse', 'HEAD'),
                        'toolchain': command('rustc', '--version'), 'features': ['test-helpers']}
    manifest['tool'] = {'script': 'scripts/gen-cost-sweep.sh', 'git_sha': command('git', 'rev-parse', 'HEAD'),
        'scala_cli_version': command('scala-cli', 'version', '--cli-version'),
        'jvm_version': command('java', '-version'),
        'script_sha256': {p: sha((ROOT / p).read_bytes()) for p in
                          [VERIFY, TX, 'scripts/gen_cost_sweep.py', 'scripts/gen-cost-sweep.sh']}}
    manifest['run'] = {'command': 'scripts/gen-cost-sweep.sh', 'seeds': 'TX-A/TX-B replay captured bytes; synthetic transactions use fresh keys',
                       'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    classes = {}

    def save(name, classes_for_file, source, ledger, accumulated, points, **fields):
        m = copy.deepcopy(manifest)
        m['context'] = {'network': 'synthetic offline mainnet settings',
                        **fields.pop('manifest_context', fields.get('context', original['context'])),
                        'accumulated_block_cost': accumulated, 'limit_override': 'points[].limit'}
        m['run'].update(selected=len(points), executed=len(points), skipped=0, failed=0)
        m['evidence'] = {'input_sha256': sha(read_fixture_text(ROOT / source).encode()),
                         'points_sha256': sha(json.dumps(points, sort_keys=True).encode()),
                         'replay_inputs_sha256': sha(json.dumps(fields, sort_keys=True).encode())}
        result = dict(manifest=m, ledger=ledger, base_fixture=source,
                      accumulated_block_cost=accumulated, points=points, **fields)
        path = name + '.json.gz'
        m['evidence']['output_sha256'] = path + '.sha256 (uncompressed JSON)'
        rendered = json.dumps(result, indent=2) + '\n'
        write_fixture_text(OUT / path, rendered)
        (OUT / (path + '.sha256')).write_text(sha(rendered.encode()) + '  ' + path + '\n')
        for cls in classes_for_file:
            classes.setdefault(cls, []).append(path)

    for case in original['cases']:
        points = [dict(limit=p['limit'], verdict=p['verdict'],
                       total=case['block_cost'] if p['verdict'] == 'Accept' else 'unavailable') for p in case['sweep']]
        save(case['name'], [case['name']], SOURCE, ['LIMIT-per-input', 'TX-accumulator-shared'], 0,
             points, surface='transaction', case=case, context=original['context'], measured_total=case['block_cost'])
    with tempfile.TemporaryDirectory(dir=ROOT, prefix='.sweep-') as tmp:
        raw = Path(tmp) / 'tx.json'
        scala(TX, [str(Path.home() / 'coding/reference/ergo-core/ergo/src/main/resources'), str(raw), SOURCE])
        tx = json.loads(raw.read_text())
    base = 'test-vectors/ergo-sigma/cost-ledger/sweeps/base/transactions.json.gz'
    (ROOT / base).parent.mkdir(exist_ok=True)
    base_manifest = copy.deepcopy(manifest)
    base_manifest['scala']['artifacts'] = tx['artifacts']
    base_manifest['context'] = {'network': 'synthetic offline mainnet settings', **tx['context']}
    point_count = sum(len(case['sweep']) for case in tx['cases'])
    base_manifest['run'].update(selected=point_count, executed=point_count, skipped=0, failed=0)
    base_manifest['evidence'] = {'cases_sha256': sha(json.dumps(tx['cases'], sort_keys=True).encode())}
    base_manifest['evidence']['output_sha256'] = 'transactions.json.gz.sha256 (uncompressed JSON)'
    rendered_base = json.dumps(dict(manifest=base_manifest, **tx), indent=2) + '\n'
    write_fixture_text(ROOT / base, rendered_base)
    (ROOT / (base + '.sha256')).write_text(sha(rendered_base.encode()) + '  transactions.json.gz\n')
    for case in tx['cases']:
        cls = [case['name']] if case['name'] in ['TX-A', 'TX-B'] else []
        if case['name'] == 'TX-B':
            cls += ['later-input-exhaustion', 'init-only-exhaustion']
        rows = ['LIMIT-tx-start', 'LIMIT-per-input', 'TX-accumulator-shared']
        if case['name'] == 'rent-success':
            cls = ['storage-rent-success']
            rows = ['TX-storage-rent']
        if case['name'] == 'eval-remainders':
            cls = ['rounding-remainders']
            rows = ['ROUND-snap-per-input', 'LIMIT-per-input']
        if case['name'] == 'token-exhaustion':
            cls = ['token-exhaustion']
            rows = ['ORDER-init-token', 'LIMIT-tx-start']
        save(case['name'] + '-accumulated', cls, base, rows, case['accumulated_block_cost'],
             case['sweep'], surface='transaction', case=case, context=tx['context'], measured_total=case['block_cost'])
    selected = []
    for family in ['interpreter', 'op-fixed', 'op-per-item', 'eval', 'method', 'version']:
        directory = ROOT / 'test-vectors/ergo-sigma/cost-ledger/fixtures' / family
        for path in fixture_paths(directory):
            fixture = json.loads(read_fixture_text(path))
            case = next((c for c in fixture.get('cases', [fixture])
                         if c['expected']['verdict'] == 'Accept'
                         and c['expected']['total_block_cost'] != 'unavailable'
                         and not c['request'].get('rent')
                         and c['request']['tree_version_expected'] <= 3), None)
            if case:
                selected.append((family, str(path.relative_to(ROOT)), case['request'], ['L2-' + family], ['INTERP-costlimit-op']))
                break
        else:
            raise RuntimeError('no representative for ' + family)
    for filename in ['upcast-v2.json.gz', 'upcast-v2-wide.json.gz']:
        source = 'test-vectors/ergo-sigma/cost-ledger/fixtures/version/' + filename
        for index, case in enumerate(json.loads(read_fixture_text(ROOT / source))['cases']):
            selected.append((filename.split('.')[0] + '-' + str(index), source, case['request'],
                             ['pre-v3-upcast'], ['ORDER-pre-v3-upcast']))
    rent_source = 'test-vectors/ergo-sigma/verify/cases.json'
    for case in json.loads((ROOT / rent_source).read_text()):
        if case['name'] == 'rent_fallback':
            case['request']['ctx_ext_hex'] = '017f0302'  # Invalid output index triggers wallet recoverWith.
            selected.append((case['name'], rent_source, case['request'],
                             ['storage-rent-fallback'], ['TX-storage-rent']))
    p = ROOT / 'test-vectors/ergo-sigma/cost-ledger/fixtures/interpreter/p2pk.json.gz'
    r = json.loads(read_fixture_text(p))['request']
    r['proof_hex'] = ''
    selected.append(('failed-proof', str(p.relative_to(ROOT)), r,
                     ['failed-proof-at-C', 'competing-failures'], ['ORDER-crypto-before-verify']))
    def verify_many(requests):
        raw = scala(VERIFY, ['verify'], ''.join(json.dumps(r) + '\n' for r in requests).encode())
        responses = []
        for line in raw.splitlines():
            if line.startswith(b'{'):
                responses.append(json.loads(line))
            else:
                print(line.decode(), file=sys.stderr)
        assert len(responses) == len(requests), 'JVM response count mismatch'
        return responses

    baselines = [dict(item[2], init_cost_block=item[2]['init_cost_block'] + 1000,
                      cost_limit_block=1000000) for item in selected]
    measured = verify_many(baselines)
    assert len(measured) == len(selected)
    all_requests = []
    for request, result in zip(baselines, measured):
        cost = result['total_block_cost']
        assert isinstance(cost, int), result
        all_requests.extend(dict(request, cost_limit_block=limit) for limit in [cost - 1, cost, cost + 1])
    responses = verify_many(all_requests)
    assert len(responses) == len(all_requests)
    for index, (name, source, _, cls, rows) in enumerate(selected):
        request = baselines[index]
        points = [dict(limit=r['cost_limit_block'], verdict=e['verdict'], total=e['total_block_cost'])
                  for r, e in zip(all_requests[index * 3:index * 3 + 3], responses[index * 3:index * 3 + 3])]
        pre = bytes.fromhex(request['pre_header_hex'])
        save(name, cls, source, rows, 1000, points, surface='input', request=request, measured_total=measured[index]['total_block_cost'],
             manifest_context={'network': 'synthetic offline', 'height': int.from_bytes(pre[49:53], 'big'),
                 'activated_script_version': request['activated_version'], 'block_version': pre[0],
                 'voted_params': {str(i): None for i in range(4, 9)}})
    (OUT / 'CLASSES.toml').write_text('# Required task-4.1 sweep classes; every entry must execute.\n' +
        '\n'.join('[[classes]]\nname = ' + json.dumps(c) + '\nfiles = ' + json.dumps(files) + '\n'
                  for c, files in sorted(classes.items())))
    print(f'generated {len(list(OUT.glob("*.json.gz")))} sweeps, {len(classes)} classes')


if __name__ == '__main__':
    main()
