#!/usr/bin/env python3
"""Throwing-operand ORDER probes; only gen-cost-fixture.sh supplies expectations.

Run this script, regenerate order-throwing through the JVM, run --sweep, then
regenerate again. Sweeps retain their high-limit JVM observations as authority.
"""
import copy
import json
import sys

from eval_cost import OUT, block, cases_for, coll, num, save
from cost_fixture_io import read_fixture_text, write_fixture_text

NAME = 'order-throwing'
IDS = ['ORDER-blockvalue-valdef', 'OP-0xD6', 'ORDER-hof-charge',
       'ORDER-comparison-charge']


def main():
    if '--sweep' in sys.argv:
        path = OUT / f'{NAME}.json.gz'
        fixture = json.loads(read_fixture_text(path))
        originals = [c for c in fixture['cases'] if '-limit' not in c['name']]
        previous = {c['name']: c for c in fixture['cases']}
        expanded = []
        for case in originals:
            expected = case['expected']
            cost = (expected['total_block_cost'] if expected['verdict'] == 'Accept'
                    else expected['evaluator_failure_block_cost'])
            if not isinstance(cost, int):
                raise ValueError(f"No JVM cost: {case['name']}: {expected}")
            for init in (0, 17):
                for limit in range(init + cost + 2):
                    probe = copy.deepcopy(case)
                    probe['name'] += f'-limit{limit}-init{init}'
                    probe['request'].update(cost_limit_block=limit, init_cost_block=init)
                    if init:
                        probe['request'].pop('observe_evaluator_failure', None)
                    probe['construction']['limit_from_jvm_block_cost'] = cost
                    probe.pop('expected')
                    old = previous.get(probe['name'])
                    if old and old['request'] == probe['request'] and 'expected' in old:
                        probe['expected'] = old['expected']
                    expanded.append(probe)
        fixture['cases'] = originals + expanded
        write_fixture_text(path, json.dumps(fixture, indent=2) + '\n')
        print(f'{len(originals)} high-limit cases, {len(expanded)} sweep cases')
        return

    cases = []
    throw = b'\x9d' + num(4, 1) + num(4, 0)
    good = b'\x9d' + num(4, 1) + num(4, 1)
    # The successful RHS control reaches the environment insertion charge.
    for label, rhs in [('throw', throw), ('success', good)]:
        cases += cases_for(f'valdef-{label}', rhs, failure=label == 'throw')
    for opcode, name in [(0x8f, 'lt'), (0x90, 'le'), (0x91, 'gt'), (0x92, 'ge')]:
        for label, left, right in [('left-throw', throw, good),
                                   ('right-throw', good, throw),
                                   ('success', good, good)]:
            # Bind the Boolean result so false comparisons still accept.
            cases += cases_for(f'{name}-{label}', bytes([opcode]) + left + right,
                               failure=label != 'success')
    for opcode, name in [(0xad, 'map'), (0xae, 'exists')]:
        for n in (0, 1, 9, 10, 11, 21):
            collection = coll(4, [num(4)] * n)
            body = b'\x72\x01' if name == 'map' else b'\x01\x01'
            failing_body = throw if name == 'map' else b'\x93' + throw + num(4)
            closure = b'\xd9\x01\x01\x04' + body
            for label, xs, fn in [
                ('collection-throw', block([throw], collection), closure),
                ('function-throw', collection, block([throw], closure)),
                ('body-throw', collection, b'\xd9\x01\x01\x04' + failing_body),
                ('success', collection, closure),
            ]:
                cases += cases_for(f'{name}-n{n}-{label}', bytes([opcode]) + xs + fn,
                                   failure=label != 'success' and not (label == 'body-throw' and n == 0))
    save(NAME, IDS, cases)
    print(f'{len(cases)} high-limit cases')


if __name__ == '__main__':
    main()
