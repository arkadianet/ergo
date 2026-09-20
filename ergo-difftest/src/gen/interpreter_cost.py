#!/usr/bin/env python3
"""Hand-serialize interpreter substitution probes; JVM supplies expectations.

Wire authority: ergo-ser opcode/write.rs, sigma_value and ergo_box writers.
Run scripts/gen-cost-fixture.sh on the output to populate expected fields.
"""
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'scripts'))
from cost_fixture_io import fixture_path, read_fixture_text, write_fixture_text

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'test-vectors/ergo-sigma/cost-ledger/fixtures/interpreter'
BASE = json.loads(read_fixture_text(OUT / 'p2pk.json.gz'))['request']


def vlq(n):
    result = bytearray()
    while n >= 128:
        result.append((n & 127) | 128)
        n >>= 7
    result.append(n)
    return bytes(result)


def main():
    cases = []
    tiny = bytes.fromhex('08d3')  # SigmaPropConstant(True)
    data = bytes(146)
    coll = b'\x0e' + vlq(len(data)) + data
    long = b'\xd1\x93' + coll + coll  # BoolToSigmaProp(EQ(bytes, bytes))
    assert len(long) == 300
    for source in ('context', 'register'):
        for name, script in [('tiny', tiny), ('long', long), ('dead', long), ('missing-live', tiny), ('missing-dead', tiny)]:
            node = bytes.fromhex('d40800' if source == 'context' else 'd5040800')
            # Segregated v3 tree: one Boolean constant, referenced as If condition.
            condition = 0 if name in ('dead', 'missing-dead') else 1
            payload = b'\x01\x01' + bytes([condition]) + b'\x95\x73\x00' + node + tiny
            tree = b'\x1b' + vlq(len(payload)) + payload
            script_constant = b'\x0e' + vlq(len(script)) + script
            registers = b'\x01' + script_constant if source == 'register' and not name.startswith('missing') else b'\x00'
            self_box = (vlq(1000000) + tree + b'\x00\x00' + registers + bytes(33)).hex()
            request = dict(BASE, tree_hex=tree.hex(), self_box_hex=self_box,
                           inputs_hex=[self_box], init_cost_block=17,
                           tree_version_expected=3, activated_version=3,
                           ctx_ext_hex=(b'\x01\x00' + script_constant).hex()
                           if source == 'context' and not name.startswith('missing') else '00')
            cases.append({'name': f'{source}-{name}',
                          'construction': {'embedded_script_hex': script.hex(),
                                           'embedded_script_bytes': len(script),
                                           'tree_bytes': len(tree)},
                          'request': request})
    path = OUT / 'deserialize-substitution.json.gz'
    value = {'ledger': ['INTERP-deser-subst', 'INTERP-embedded-script-deser',
                        'OP-0xD4', 'OP-0xD5'], 'cases': cases}
    if fixture_path(path).exists():
        old = json.loads(read_fixture_text(path))
        if [c['request'] for c in old['cases']] == [c['request'] for c in cases]:
            value['manifest'] = old['manifest']
        for case in cases:
            for previous in old['cases']:
                if previous['request'] == case['request'] and 'expected' in previous:
                    case['expected'] = previous['expected']
    write_fixture_text(path, json.dumps(value, indent=2) + '\n')


if __name__ == '__main__':
    main()
