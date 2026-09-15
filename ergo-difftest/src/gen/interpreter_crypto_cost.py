#!/usr/bin/env python3
"""Hand-serialize SigmaBoolean constants; all expected fields come from JVM verify.

Use --limits after JVM generation to copy its measured totals into boundary
requests, then regenerate expectations with scripts/gen-cost-fixture.sh.
"""
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'scripts'))
from cost_fixture_io import fixture_path, read_fixture_text, write_fixture_text

from interpreter_cost import BASE, OUT, vlq


def main():
    path = OUT / 'crypto-shapes.json.gz'
    old = json.loads(read_fixture_text(path)) if fixture_path(path).exists() else {}
    point = bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
    dlog = b'\xcd' + point
    dht = b'\xce' + point * 4
    shapes = [('true', b'\xd3'), ('false', b'\xd2'), ('dlog', dlog), ('dht', dht),
              ('and', b'\x96\x02' + dlog + dht), ('or', b'\x97\x02' + dlog + dht)]
    shapes += [(f'threshold-{k}-of-3', b'\x98' + vlq(k) + b'\x03' + dlog * 3)
               for k in (3, 2, 1)]
    cases = []
    for name, prop in shapes:
        tree = b'\x00\x08' + prop
        self_box = (vlq(1000000) + tree + b'\x00\x00\x00' + bytes(33)).hex()
        request = dict(BASE, tree_hex=tree.hex(), self_box_hex=self_box,
                       inputs_hex=[self_box], init_cost_block=17)
        cases.append({'name': name, 'request': request})
    value = {'ledger': ['INTERP-eval-sigmaprop-constant', 'INTERP-crypto-dlog',
                        'INTERP-crypto-dht', 'INTERP-crypto-conjunction',
                        'INTERP-crypto-threshold', 'INTERP-crypto-trivial-I013'], 'cases': cases}
    if old.get('cases') and [c['request'] for c in old['cases']] == [c['request'] for c in cases]:
        value['manifest'] = old['manifest']
        for case, previous in zip(cases, old['cases']):
            if 'expected' in previous:
                case['expected'] = previous['expected']
    write_fixture_text(path, json.dumps(value, indent=2) + '\n')
    if '--limits' in sys.argv:
        # JVM-measured totals only; no Rust cost function participates.
        substitution = json.loads(read_fixture_text(OUT / 'deserialize-substitution.json.gz'))['cases'][0]
        for filename, measured in [('cost-limit.json.gz', cases[0]),
                                   ('deserialize-cost-limit.json.gz', substitution)]:
            total = measured['expected']['total_block_cost']
            limits = [{'name': name, 'request': dict(measured['request'], cost_limit_block=limit)}
                      for name, limit in [('at-total', total), ('below-total', total - 1)]]
            limit_path = OUT / filename
            limit_value = {'ledger': ['INTERP-costlimit-op'], 'cases': limits}
            if fixture_path(limit_path).exists():
                previous = json.loads(read_fixture_text(limit_path))
                if [c['request'] for c in previous['cases']] == [c['request'] for c in limits]:
                    limit_value = previous
            write_fixture_text(limit_path, json.dumps(limit_value, indent=2) + '\n')


if __name__ == '__main__':
    main()
