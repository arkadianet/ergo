#!/usr/bin/env python3
"""Hand-serialize VERSION probes; only gen-cost-fixture.sh supplies expectations.

Wire authority: ergo-ser/src/opcode/write.rs and ergo_tree/read.rs.
Uses the EVAL generator's ten prefixes to expose every block-cost remainder.
"""
import copy
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'scripts'))
from cost_fixture_io import read_fixture_text, write_fixture_text

import eval_cost as wire
from eval_cost import BASE, ROOT, TRUE, block, coll, eq, num, prefixes, vlq

wire.OUT = ROOT / 'test-vectors/ergo-sigma/cost-ledger/fixtures/version'


def cases(name, body, version, activated, prefixed=True, init=0):
    result = []
    for p, wrapped in prefixes(body) if prefixed else [(0, body)]:
        tree = bytes([8 + version]) + vlq(len(wrapped)) + wrapped
        request = dict(BASE, tree_hex=tree.hex(), tree_version_expected=version,
                       activated_version=activated, init_cost_block=init)
        result.append({'name': f'{name}-prefix{p}',
                       'construction': {'body_hex': body.hex(), 'prefix': p},
                       'request': request})
    return result


def main():
    wire.OUT.mkdir(exist_ok=True)
    # Mixed Byte/Long arithmetic: pre-v3 inserts an Upcast; v3 throws on execution.
    mixed = block([b'\x9a' + num(2, 1) + num(5, 2)])
    for v in (2, 3):
        probes = cases('mixed-width', mixed, v, 3)
        if v == 3:
            for probe in probes:
                probe['request']['observe_evaluator_failure'] = True
        wire.save(f'upcast-v{v}', ['VERSION-pre-v3-upcast'], probes)
        wire.save(f'upcast-v{v}-wide', ['VERSION-pre-v3-upcast'],
                  cases('matched-width', block([b'\x9a' + num(5, 1) + num(5, 2)]), v, 3))
    probes = cases('boolean-root', b'\x01\x01', 3, 3, False)
    probes[0]['request']['parse_only'] = True
    wire.save('bool-root', ['VERSION-v3-bool-root'], probes)
    # Global.serialize is a v6 method; v3 body parses, then activation gate rejects.
    method = block([b'\xdc\x6a\x03\xdd\x01' + num(4, 1)])
    wire.save('method-activation', ['VERSION-v6-method-gate'], cases('v6-method', method, 3, 2, False, 17))
    wire.save('method-activated', ['VERSION-v6-method-gate'], cases('v6-method', method, 3, 3, False, 17))
    for activated in (1, 2):
        expected_index = b'\x04\x01' if activated == 1 else b'\x04\x00'
        body = b'\xd1' + eq(b'\xdb\x65\x08\xfe', expected_index)
        wire.save(f'self-index-a{activated}', ['VERSION-selfboxindex-bug'], cases('self-index', body, 1, activated))
    wire.save('gate-supported', ['VERSION-tree-version-gate'], cases('supported-rejection', TRUE, 3, 2, False, 17))
    wire.save('gate-future', ['VERSION-tree-version-gate'], cases('future-bypass', TRUE, 4, 4, False, 17))
    # DeserializeContext expects SigmaProp but receives Boolean: rule 1000
    # escapes trySoftForkable because the default validation settings enable it.
    probes = cases('validation-exception', b'\xd4\x08\x00', 3, 3, False, 17)
    probes[0]['request']['ctx_ext_hex'] = '01000e020101'
    probes[0]['request']['observe_deserialization_failure'] = True
    tree = bytes.fromhex(probes[0]['request']['tree_hex'])
    self_box = (vlq(1000000) + tree + bytes(36)).hex()
    probes[0]['request'].update(self_box_hex=self_box, inputs_hex=[self_box])
    wire.save('gate-validation', ['VERSION-tree-version-gate'], probes)
    for v in (2, 3):
        for variant, default in [('cheap', num(4, 9)), ('expensive', b'\x9a' + num(4, 8) + num(4, 1))]:
            body = b'\xd1' + eq(b'\xb2' + coll(4, [num(4, 7)]) + num(4, 0) + b'\x01' + default, num(4, 7))
            wire.save(f'lazy-default-v{v}-{variant}', ['VERSION-v6-lazy-defaults'], cases('unused-default', body, v, 3))


def failure_limits():
    """Build budgets from JVM observations, never calculate expected costs."""
    for name in ('upcast-v3', 'gate-validation'):
        path = wire.OUT / f'{name}.json.gz'
        fixture = json.loads(read_fixture_text(path))
        originals = [c for c in fixture['cases'] if '-limit' not in c['name']]
        previous = {c['name']: c for c in fixture['cases']}
        expanded = []
        for case in originals:
            expected = case['expected']
            cost = expected['total_block_cost'] if name == 'gate-validation' else expected['evaluator_failure_block_cost']
            if not isinstance(cost, int):
                raise ValueError(f'{name}: missing JVM failure observation')
            for limit in range(case['request']['init_cost_block'], cost + 2):
                probe = copy.deepcopy(case)
                probe['name'] += f'-limit{limit}'
                probe['request']['cost_limit_block'] = limit
                probe['construction']['limit_from_jvm_block_cost'] = cost
                probe.pop('expected')
                old = previous.get(probe['name'])
                if old and old['request'] == probe['request'] and 'expected' in old:
                    probe['expected'] = old['expected']
                expanded.append(probe)
        fixture['cases'] = originals + expanded
        write_fixture_text(path, json.dumps(fixture, indent=2) + '\n')


if __name__ == '__main__':
    if sys.argv[1:] == ['--failure-limits']:
        failure_limits()
    elif sys.argv[1:]:
        sys.exit('usage: version_cost.py [--failure-limits]')
    else:
        main()
