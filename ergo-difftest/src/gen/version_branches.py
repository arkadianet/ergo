#!/usr/bin/env python3
"""Paired version branches; gen-cost-fixture.sh alone writes expected values.

Run with PYTHONDONTWRITEBYTECODE=1. --limits derives budgets from measured
JVM costs. Headers vary only for tree-version gates; activation pairs retain
identical tree bytes. Wire helpers follow version_cost.py and method_cost.py.
"""
import copy
import json
import sys

import eval_cost as wire
from eval_cost import BASE, ROOT, TRUE, block, coll, eq, num, vlq, header
from method_cost import bytecoll, call
from cost_fixture_io import read_fixture_text, write_fixture_text
from fixed_cost import save

DIRECTORY = ROOT / 'test-vectors/ergo-sigma/cost-ledger/fixtures'
FILES = ('downcast-gate', 'jit-semantics', 'subst-retention', 'subst-bytes',
         'avl-insert-gate', 'collection-gates', 'parser-data-gates')


def probe(name, body, version, activated, *, failure=False, init=0, extension='00', self_tree=False):
    tree = bytes([8 + version]) + vlq(len(body)) + body
    request = dict(BASE, tree_hex=tree.hex(), tree_version_expected=version,
                   activated_version=activated, init_cost_block=init,
                   proof_hex='', ctx_ext_hex=extension, cost_limit_block=1000000)
    if failure:
        request['observe_evaluator_failure'] = True
    if self_tree:
        box = (vlq(1000000) + tree + bytes(36)).hex()
        request.update(self_box_hex=box, inputs_hex=[box])
    return {'name': f'{name}-t{version}-a{activated}',
            'construction': {'body_hex': body.hex(), 'tree_bytes': len(tree),
                             'wire': 'hand serialized; version header and activation are independent'},
            'request': request}


def emit(name, ids, cases):
    save('version/' + name, ids, cases)


def main():
    cases = []
    for version in range(4):
        for source, targets in ((6, (2, 3, 4, 5, 6)), (9, (2, 3, 4, 5))):
            for target in targets:
                body = block([b'\x7d' + num(source) + bytes([target])])
                cases.append(probe(f'downcast-source{source}-target{target}', body,
                                   version, 3, failure=source == 6 and version < 3))
    emit('downcast-gate', ['VERSION-downcast-gate'], cases)

    cases = []
    # JIT activates at script version 2 (A6 instead activates at 3).
    for activated in (1, 2, 3):
        for name, value in [('boolean', b'\x01\x01'), ('sigma-true', TRUE),
                            ('sigma-false', b'\x08\xd2'),
                            ('sigma-dlog', b'\x08\xcd' + wire.G)]:
            cases.append(probe('bool-to-sigma-' + name, b'\xd1' + value, 1, activated,
                               failure=name.startswith('sigma') and activated >= 2))
        for bits in ([], [True], [False], [True, True], [True, False],
                     [True, True, False], [True, True, True], [False] * 33):
            body = b'\xd1\xff' + coll(1, [bytes([1, b]) for b in bits])
            cases.append(probe('xor-' + ''.join(str(int(b)) for b in bits), body, 1, activated))
        # Identical tree bytes on both sides: expected-index 0 and -1 controls.
        for index, encoded in [(0, b'\x04\x00'), (-1, b'\x04\x01')]:
            cases.append(probe(f'self-index-equals{index}', b'\xd1' + eq(b'\xdb\x65\x08\xfe', encoded), 1, activated))
    emit('jit-semantics', ['VERSION-G009', 'VERSION-G010', 'VERSION-G011'], cases)

    cases = []
    for version in (0, 1, 2):
        for activated in (2, 3):
            for live in (False, True):
                body = b'\x95\x01' + bytes([live]) + b'\xd4\x08\x00' + TRUE
                cases.append(probe(f'deserialize-live{live}', body, version, activated,
                                   init=17, extension='01000e0208d3', self_tree=True))
    emit('subst-retention', ['VERSION-subst-retention'], cases)

    cases = []
    for version, activated in ((1, 1), (1, 2), (2, 3), (3, 3)):
        for sized in (False, True):
            for segregated in (False, True):
                inner = b'\x01\x01\x01\xd1\x73\x00' if segregated else TRUE
                h = (8 if sized else 0) + (16 if segregated else 0)
                tree = bytes([h]) + (vlq(len(inner)) if sized else b'') + inner
                subst = b'\x74' + bytecoll(tree) + coll(4, []) + coll(1, [])
                # Equality exposes the serialized bytes without a Rust byte oracle.
                cases.append(probe(f'subst-sized{sized}-pool{segregated}', b'\xd1' + eq(subst, bytecoll(tree)), version, activated))
    emit('subst-bytes', ['VERSION-G008'], cases)

    source = json.loads(read_fixture_text(DIRECTORY / 'method/avl-insert.json.gz'))['cases'][0]
    target = bytes.fromhex(source['construction']['target_hex'])
    # Repeating an insertion with the same proof forces the second performInsert
    # to fail. Preserve its valid verifier and first insert rather than corrupting
    # the proof before per-entry charging.
    marker = bytes.fromhex('83013c0e0e')
    start = target.index(marker)
    # entry is CreateTuple(ByteArray[32], ByteArray[2]).
    end = start + len(marker) + 2 + 2 + 32 + 2 + 2
    entry = target[start + len(marker):end]
    duplicate = target[:start] + bytes.fromhex('83023c0e0e') + entry * 2 + target[end:]
    cases = []
    for version in (2, 3):
        for name, value in [('valid', target), ('duplicate', duplicate)]:
            cases.append(probe('insert-' + name, block([value]), version, 3,
                               failure=name == 'duplicate' and version < 3))
    emit('avl-insert-gate', ['VERSION-G007'], cases)

    cases = []
    pair = b'\x86\x02' + num(4) + num(4, 2)
    # Mapping identity over PairColl materializes CollOverArray. indexOf
    # uses DataValueComparer, so these are representation controls only;
    # they do not establish the raw Coll.equals version branch by themselves.
    pairs = b'\x83\x01\x3c\x04\x04' + pair
    mapped = b'\xad' + pairs + b'\xd9\x01\x01\x3c\x04\x04\x72\x01'
    zipped = call(12, 29, coll(4, [num(4)]), coll(4, [num(4, 2)]))
    for version, activated in ((1, 1), (1, 2), (2, 3), (3, 3)):
        for name, lhs, rhs in [('pair-array', zipped, mapped), ('array-pair', mapped, zipped)]:
            # Exercise both argument directions of nested collection equality.
            nested = b'\x83\x01\x0c\x3c\x04\x04' + lhs
            index = call(12, 26, nested, rhs, num(4, 0))
            cases.append(probe(name, b'\xd1' + eq(index, num(4, 0)), version, activated))
        cases.append(probe('append-pair-array', block([b'\xb3' + mapped + mapped]), version, activated,
                           failure=activated == 1))
        left = call(12, 29, coll(4, [num(4), num(4, 3)]), coll(4, [num(4, 2)]))
        right = call(12, 29, coll(4, [num(4, 4)]), coll(4, [num(4, 5)]))
        expected = b'\x83\x02\x3c\x04\x04' + pair + b'\x86\x02' + num(4, 4) + num(4, 5)
        cases.append(probe('append-unequal-zips', b'\xd1' + eq(b'\xb3' + left + right, expected), version, activated))
    emit('collection-gates', ['VERSION-G012', 'VERSION-G013'], cases)

    cases = []
    for version in (2, 3):
        for name, value in [('unsigned', num(9)), ('option-none', b'\x28\x00'),
                            ('option-some', b'\x28\x01\x02'), ('header', b'\x68' + header())]:
            cases.append(probe('constant-' + name, block([value]), version, 3))
            cases.append(probe('serialize-' + name, block([call(106, 3, b'\xdd', value)]), version, 3))
            cases.append(probe('deserializeTo-' + name,
                               block([call(106, 4, b'\xdd', bytecoll(value[1:]), types=value[:1])]),
                               version, 3))
        cases.append(probe('byindex-byte', block([b'\xb2' + coll(4, [num(4)]) + num(2, 0) + b'\x00']), version, 3,
                           failure=version == 3))
        cases.append(probe('method-empty-args', block([b'\xdc\x0c\x0e' + coll(4, []) + b'\x00']), version, 3))
        cases.append(probe('bigint-upcast-identity', block([b'\x7e' + num(6) + b'\x06']), version, 3,
                           failure=version < 3))
        # An unused closure parameter still exercises function-type parsing.
        func = b'\x70\x01\x04\x04\x00'  # (Int) => Int; no type parameters
        cases.append(probe('function-parameter', block([b'\xd9\x01\x01' + func + num(4)]), version, 3))
        minimum = b'\x06\x20\x80' + bytes(31)
        negative_one = b'\x06\x01\xff'
        cases.append(probe('bigint-divide-minimum-negative-one',
                           block([b'\x9d' + minimum + negative_one]), version, 3,
                           failure=version == 3))
    emit('parser-data-gates', ['VERSION-G014', 'VERSION-G016', 'VERSION-G017', 'VERSION-G018'], cases)

    # Validation settings are a JVM-only surface until Rust verification
    # accepts cumulative SigmaValidationSettings from the block context.
    cases = []
    for activated in (2, 3):
        for name, embedded, rule, replacement in [
                ('unknown-method', bytes.fromhex('dc04ff0402010402'), 1011, 1016),
                ('primitive-type', bytes.fromhex('d40a00'), 1007, 1017),
                ('unknown-type', bytes.fromhex('d46f00'), 1008, 1018),
                ('result-type', bytes.fromhex('0101'), 1000, 1001),
                ('arithmetic', b'\xd1' + eq(b'\x9d' + num(4) + num(4, 0), num(4)), 1000, 1001)]:
            for replaced in (False, True):
                case = probe(f'{name}-replaced{replaced}', b'\xd4\x08\x00', 1, activated,
                             init=17, extension=(b'\x01\x00' + bytecoll(embedded)).hex(), self_tree=True)
                if replaced:
                    case['request']['validation_settings_replaced_rules'] = {str(rule): replacement}
                cases.append(case)
    path = DIRECTORY / 'version/validation-settings.jvm'
    fixture = {'ledger': ['VERSION-G018', 'VERSION-G019', 'VERSION-G020'], 'cases': cases}
    if path.exists():
        old = json.loads(read_fixture_text(path))
        originals = [c for c in old['cases'] if '-limit' not in c['name']]
        if [c['request'] for c in originals] == [c['request'] for c in cases]:
            fixture = old
    write_fixture_text(path, json.dumps(fixture, indent=2) + '\n')


def limits():
    for name in FILES:
        path = DIRECTORY / f'version/{name}.json.gz'
        fixture = json.loads(read_fixture_text(path))
        originals = [c for c in fixture['cases'] if '-limit' not in c['name']]
        previous = {c['name']: c for c in fixture['cases']}
        expanded = []
        for case in originals:
            cost = case['expected']['total_block_cost']
            if not isinstance(cost, int):
                cost = case['expected'].get('evaluator_failure_block_cost')
            if not isinstance(cost, int):
                continue
            budgets = {max(0, cost - 1), cost, cost + 1}
            if name == 'subst-retention':
                other = next(c for c in originals
                             if c['request']['tree_hex'] == case['request']['tree_hex']
                             and c['request']['activated_version'] != case['request']['activated_version'])
                retained = abs(cost - other['expected']['total_block_cost'])
                check_cost = case['request']['init_cost_block'] + retained
                budgets.update((check_cost - 1, check_cost, check_cost + 1))
            for limit in sorted(budgets):
                probe = copy.deepcopy(case)
                probe['name'] += f'-limit{limit}'
                probe['request']['cost_limit_block'] = limit
                probe['construction']['limit_from_jvm_block_cost'] = cost
                probe.pop('expected')
                probe.pop('known_divergence', None)
                old = previous.get(probe['name'])
                if old and old['request'] == probe['request'] and 'expected' in old:
                    probe['expected'] = old['expected']
                    if 'known_divergence' in old:
                        probe['known_divergence'] = old['known_divergence']
                expanded.append(probe)
        fixture['cases'] = originals + expanded
        write_fixture_text(path, json.dumps(fixture, indent=2) + '\n')

    path = DIRECTORY / 'version/validation-settings.jvm'
    fixture = json.loads(read_fixture_text(path))
    originals = [c for c in fixture['cases'] if '-limit' not in c['name']]
    previous = {c['name']: c for c in fixture['cases']}
    # All requests share tree bytes and init. Use the measured recognized
    # fallback total for both enabled and replaced-rule boundary controls.
    measured = next(c['expected']['total_block_cost'] for c in originals
                    if c['expected']['verdict'] == 'Accept')
    expanded = []
    for case in originals:
        for limit in (measured - 1, measured, measured + 1):
            probe = copy.deepcopy(case)
            probe['name'] += f'-limit{limit}'
            probe['request']['cost_limit_block'] = limit
            probe['construction']['limit_from_jvm_block_cost'] = measured
            probe.pop('expected')
            old = previous.get(probe['name'])
            if old and old['request'] == probe['request'] and 'expected' in old:
                probe['expected'] = old['expected']
            expanded.append(probe)
    fixture['cases'] = originals + expanded
    write_fixture_text(path, json.dumps(fixture, indent=2) + '\n')


if __name__ == '__main__':
    if sys.argv[1:] == ['--limits']:
        limits()
    elif sys.argv[1:]:
        sys.exit('usage: version_branches.py [--limits]')
    else:
        main()
