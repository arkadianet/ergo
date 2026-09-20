#!/usr/bin/env python3
"""Binding and constant-pool parser probes using the existing wire helpers.

Run with PYTHONDONTWRITEBYTECODE=1 from the repository root. The pinned JVM
parser supplies SelectField verdicts. Then run gen-cost-fixture.sh for
version/parser-data-gates.json.gz, this script with --limits, and the fixture
oracle again. Only JVM measurements supply costs and derived limits.
"""
import copy
import datetime
import hashlib
import json
import subprocess
import sys

from eval_cost import ROOT, block, num, coll, vlq, eq
from version_branches import probe, DIRECTORY
from cost_fixture_io import read_fixture_text, write_fixture_text

FIXTURE = DIRECTORY / 'version/parser-data-gates.json.gz'


def main():
    fixture = json.loads(read_fixture_text(FIXTURE))
    if sys.argv[1:] == ['--limits']:
        originals = [c for c in fixture['cases'] if '-limit' not in c['name']
                     and c['name'].startswith('byindex-type')]
        fixture['cases'] = [c for c in fixture['cases']
                            if not (c['name'].startswith('byindex-type') and '-limit' in c['name'])]
        for case in originals:
            measured = case['expected']['total_block_cost']
            if not isinstance(measured, int):
                measured = case['expected']['evaluator_failure_block_cost']
            if not isinstance(measured, int):
                raise ValueError(f"JVM did not expose a cost: {case['name']}")
            for limit in (measured - 1, measured, measured + 1):
                bounded = copy.deepcopy(case)
                bounded['name'] += f'-limit{limit}'
                bounded['request']['cost_limit_block'] = limit
                bounded['construction']['limit_from_jvm_block_cost'] = measured
                bounded.pop('expected')
                fixture['cases'].append(bounded)
    elif not sys.argv[1:]:
        path = ROOT / 'test-vectors/scala/select_field_index_bounds.json'
        vectors = json.loads(path.read_text())
        vectors['cases'] = vectors['cases'][:4]
        pair = b'\x86\x02' + num(4, 1) + num(4, 2)
        for shape in ('binding', 'placeholder', 'block-result', 'lambda-arg', 'rebind'):
            for index in (0, 1, 2, 3):
                def select(value):
                    return b'\xd1' + eq(b'\x8c' + value + bytes([index]),
                                        num(4, 2 if index == 2 else 1))
                if shape == 'binding':
                    body = block([pair], select(b'\x72\x0a'))
                elif shape == 'placeholder':
                    body = select(b'\x73\x00')
                elif shape == 'block-result':
                    body = select(block([pair], b'\x72\x0a'))
                elif shape == 'lambda-arg':
                    body = block([b'\xd9\x01\x0a\x3c\x04\x04' + select(b'\x72\x0a')])
                else:
                    body = b'\xd8\x02\xd6\x0a' + num(4) + b'\xd6\x0a' + pair + select(b'\x72\x0a')
                pool = b'\x01\x3c\x04\x04\x02\x04' if shape == 'placeholder' else b''
                tree = bytes([0x18 if pool else 8]) + vlq(len(pool + body)) + pool + body
                vectors['cases'].append(dict(name=f'{shape}-index{index}', tree_hex=tree.hex()))
        requests = ''.join('ergo_tree ' + c['tree_hex'] + '\n' for c in vectors['cases'])
        output = subprocess.run([
            'scala-cli', '--skip-cli-updates', 'run',
            'scripts/jvm_serde_oracle/ErgoSerdeOracle.scala', '--server=false',
            '--suppress-outdated-dependency-warning'],
            input=requests, text=True, stdout=subprocess.PIPE, check=True).stdout.splitlines()
        if len(output) != len(vectors['cases']):
            raise ValueError('JVM parser response count mismatch')
        for case, response in zip(vectors['cases'], output):
            verdict, _, detail = response.partition(' ')
            if verdict not in ('ACCEPT', 'REJECT'):
                raise ValueError(response)
            case.update(jvm=verdict.title(), jvm_detail=detail if verdict == 'REJECT' else None)
        oracle = ROOT / 'scripts/jvm_serde_oracle/ErgoSerdeOracle.scala'
        vectors['manifest'] = {
            'scala': {'sigmastate_version': '6.0.2', 'ergo_version': '6.0.2'},
            'tool': {'generator': 'ergo-difftest/src/gen/parser_type_store.py',
                     'oracle_script': str(oracle.relative_to(ROOT)),
                     'oracle_sha256': hashlib.sha256(oracle.read_bytes()).hexdigest()},
            'run': {'command': 'PYTHONDONTWRITEBYTECODE=1 python3 ergo-difftest/src/gen/parser_type_store.py',
                    'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    'selected': len(output), 'executed': len(output), 'skipped': 0},
            'evidence': {'requests_sha256': hashlib.sha256(requests.encode()).hexdigest(),
                         'responses_sha256': hashlib.sha256(('\n'.join(output) + '\n').encode()).hexdigest()},
        }
        path.write_text(json.dumps(vectors, indent=2) + '\n')
        previous = {c['name']: c for c in fixture['cases']}
        fixture['cases'] = [c for c in fixture['cases'] if not c['name'].startswith('byindex-type')]
        for version in (2, 3):
            for tpe in (2, 3):
                for shape in ('binding', 'placeholder'):
                    index = b'\x72\x0a' if shape == 'binding' else b'\x73\x00'
                    target = b'\xb2' + coll(4, [num(4)]) + index + b'\x00'
                    body = block([num(tpe, 0), target]) if shape == 'binding' else block([target])
                    case = probe(f'byindex-type{tpe}-{shape}', body, version, 3, failure=version == 3)
                    if shape == 'placeholder':
                        content = b'\x01' + num(tpe, 0) + body
                        case['request']['tree_hex'] = (bytes([0x18 + version]) + vlq(len(content)) + content).hex()
                    old = previous.get(case['name'])
                    if old and old['request'] == case['request']:
                        case = old
                    fixture['cases'].append(case)
        fixture['cases'].extend(c for c in previous.values()
                                if c['name'].startswith('byindex-type') and '-limit' in c['name'])
    else:
        sys.exit('usage: parser_type_store.py [--limits]')
    write_fixture_text(FIXTURE, json.dumps(fixture, indent=2) + '\n')


if __name__ == '__main__':
    main()
