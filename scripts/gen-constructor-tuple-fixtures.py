#!/usr/bin/env python3
"""Build serialized probes; all expected costs are filled by gen-cost-fixture.sh."""
import argparse
import copy
import json
from pathlib import Path

from cost_fixture_io import read_fixture_text, write_fixture_text

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / 'test-vectors/ergo-sigma/cost-ledger/fixtures/method'


def vlq(n):
    result = bytearray()
    while n >= 128:
        result.append((n & 127) | 128)
        n >>= 7
    result.append(n)
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('family', choices=['tuple', 'avl'])
    parser.add_argument('--boundaries', action='store_true')
    args = parser.parse_args()
    if args.boundaries:
        path = FIXTURES / ('tuple-accessors.json.gz' if args.family == 'tuple' else 'avl-constructor.json.gz')
        fixture = json.loads(read_fixture_text(path))
        cases = fixture['cases']
        assert all(c['request']['cost_limit_block'] == 1000000 for c in cases)
        for case in list(cases):
            result = case['expected']
            cost = result['total_block_cost']
            if not isinstance(cost, int):
                cost = result['evaluator_failure_block_cost']
            assert isinstance(cost, int), case['name']
            for limit in sorted({max(0, cost - 1), cost, cost + 1}):
                boundary = copy.deepcopy(case)
                boundary.pop('expected')
                boundary['name'] += f'-limit{limit}'
                boundary['request']['cost_limit_block'] = limit
                cases.append(boundary)
        write_fixture_text(path, json.dumps(fixture, indent=2) + '\n')
        print(f'{path.name}: {len(cases)} boundary requests; regenerate JVM results')
        return
    base = json.loads(read_fixture_text(FIXTURES / 'failure-avl.json.gz'))['cases'][0]['request']
    cases = []

    def add(name, target, metadata):
        for version in [2, 3]:
            # Prefix constants vary JIT remainder without changing the target.
            for prefix in (range(10) if args.family == 'tuple' else [0, 9]):
                bindings = b''.join(b'\xd6' + vlq(i + 1) + b'\x04\x00' for i in range(prefix))
                body = b'\xd8' + vlq(prefix + 1) + bindings + b'\xd6\x0a' + target + b'\x08\xd3'
                request = copy.deepcopy(base)
                request.update(tree_hex=(bytes([version | 8]) + vlq(len(body)) + body).hex(),
                               tree_version_expected=version, observe_evaluator_failure=(metadata.get('arity', 2) != 2 or metadata.get('method') == 10))
                cases.append({'name': f'{name}-v{version}-prefix{prefix}', 'probe': metadata,
                              'request': request})

    if args.family == 'tuple':
        for arity in [2, 3, 4, 127]:
            for field in sorted({1, min(arity, 2), min(arity, 127)}):
                target = b'\x8c\x86' + bytes([arity]) + b'\x04\x02' * arity + bytes([field])
                add(f'tuple-arity{arity}-field{field}', target, {'arity': arity, 'field': field})
        destination = 'tuple-accessors.json.gz'
        row = 'METHOD-unclaimed-inventory'
    else:
        probe = json.loads((ROOT / 'target/task-10.4/avl-probe.json').read_text())
        for index, entry in enumerate(probe['cases']):
            dl, kl, vl = entry['digest_length'], entry['key_length'], entry['value_length']
            if entry['result']['exception'] is not None:
                continue  # Fatal VM allocation errors have no Interpreter.verify result.
            # Constants carry a fixed-size digest. updateDigest reaches every other length.
            tree = b'\x64' + bytes([1]) * 33 + b'\x07' + vlq(kl & 0xffffffff)
            tree += b'\x00' if vl is None else b'\x01' + vlq(vl & 0xffffffff)
            if dl != 33:
                tree = b'\xdc\x64\x0f' + tree + b'\x01\x0e' + vlq(dl) + bytes([1]) * dl
            proof = bytes.fromhex(entry['proof_hex'])
            for method in [9, 10]:
                target = b'\xdc\x64' + bytes([method]) + tree + b'\x02\x0e\x20' + bytes([1]) * 32
                target += b'\x0e' + vlq(len(proof)) + proof
                add(f'avl-probe{index}-method{method}', target, dict(entry, method=method))
        destination = 'avl-constructor.json.gz'
        row = 'ORDER-avl-escaping-constructor'
    fixture = {'ledger': [row], 'cases': cases}
    if args.family == 'avl':
        fixture['constructor_probe'] = probe
    write_fixture_text(FIXTURES / destination, json.dumps(fixture, indent=2) + '\n')
    print(f'{destination}: {len(cases)} requests; run scripts/gen-cost-fixture.sh')


if __name__ == '__main__':
    main()
