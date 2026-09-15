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
