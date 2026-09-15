#!/usr/bin/env python3
"""Hand-serialize substitution type probes; gen-cost-fixture.sh supplies the oracle."""
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'scripts'))
from cost_fixture_io import fixture_path, read_fixture_text, write_fixture_text
from interpreter_cost import BASE, OUT, vlq


def main():
    cases = []
    true = bytes.fromhex('08d3')
    for source in ('register', 'context'):
        probes = [('collection-mismatch', bytes.fromhex('830004'), True),
                  ('constant-mismatch', bytes.fromhex('0402'), True)]
        coll = bytes.fromhex('830108') + true
        index = bytes.fromhex('0400')
        identity = bytes.fromhex('d90101087201')
        def by_index(value):
            return b'\xb2' + value + index + b'\x00'
        def method(type_id, method_id, obj, *args):
            return (bytes([0xdc, type_id, method_id]) + obj + vlq(len(args)) + b''.join(args)
                    if args else bytes([0xdb, type_id, method_id]) + obj)
        probes += [(label, value, True) for label, value in [
            ('tuple-select', b'\x8c\x86\x02' + true + true + b'\x01'),
            ('by-index', by_index(coll)),
            ('option-get-or-else', bytes.fromhex('e5e30108') + true),
            ('method-sigma', method(12, 10, coll, index)),
            ('if-sigma', b'\x95\x7f' + true + true),
            ('block-sigma', b'\xd8\x01\xd6\x01' + true + b'\x72\x01'),
            ('slice-index', by_index(b'\xb4' + coll + index + bytes.fromhex('0402'))),
            ('map-index', by_index(b'\xad' + coll + identity)),
            ('append-index', by_index(b'\xb3' + coll + coll)),
            ('filter-index', by_index(b'\xb5' + coll + bytes.fromhex('d90101087f'))),
            ('fold-sigma', b'\xb0' + coll + true + bytes.fromhex('d90101600208088c720101')),
            ('apply-sigma', b'\xda' + identity + b'\x01' + true),
            ('method-map-index', by_index(method(12, 3, coll, identity))),
            ('method-size-index', method(12, 10, coll, method(12, 1, bytes.fromhex('830008')))),
            ('method-option-get', b'\xe4' + method(106, 9, b'\xdd', true) + b'\x08'),
            ('context-height-if', b'\x95\x93' + method(101, 6, b'\xfe') + bytes.fromhex('0400') + true + true),
        ]]
        if source == 'register':
            probes += [('absent-default', None, False),
                       ('int-default', bytes.fromhex('0402'), False),
                       ('ints-default', bytes.fromhex('100102'), False),
                       ('bytes-default', true, True)]
        for label, value, embedded in probes:
            for live in (True, False):
                node = bytes.fromhex('d5040801') + true if source == 'register' else bytes.fromhex('d40800')
                payload = b'\x01\x01' + bytes([live]) + b'\x95\x73\x00' + node + true
                tree = b'\x1b' + vlq(len(payload)) + payload
                constant = b'\x0e' + vlq(len(value)) + value if embedded else value
                registers = b'\x01' + constant if source == 'register' and constant is not None else b'\x00'
                box = (vlq(1000000) + tree + b'\x00\x00' + registers + bytes(33)).hex()
                request = dict(BASE, tree_hex=tree.hex(), self_box_hex=box, inputs_hex=[box],
                               init_cost_block=17, tree_version_expected=3, activated_version=3,
                               ctx_ext_hex=(b'\x01\x00' + constant).hex() if source == 'context' else '00')
                cases.append({'name': f'{source}-{label}-{"live" if live else "dead"}', 'request': request})
    path = OUT / 'deserialize-types.json.gz'
    fixture = {'ledger': ['INTERP-deser-subst', 'INTERP-embedded-script-deser'], 'cases': cases}
    if fixture_path(path).exists():
        old = json.loads(read_fixture_text(path))
        if [c['request'] for c in old['cases']] == [c['request'] for c in cases]:
            fixture = old
    write_fixture_text(path, json.dumps(fixture, indent=2) + '\n')


if __name__ == '__main__':
    main()
