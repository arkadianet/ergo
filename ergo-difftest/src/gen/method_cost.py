#!/usr/bin/env python3
"""Hand-serialized METHOD trees; expected costs are written only by the JVM.

Wire authority: ergo-ser/src/opcode/write.rs and sigma_value serializers.
Run with PYTHONDONTWRITEBYTECODE=1; select avl-serialize or rest.
"""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'scripts'))
from cost_fixture_io import read_fixture_text
import eval_cost as wire
from eval_cost import G, H, ROOT, cases_for, coll, num, scalar, vlq

wire.OUT = ROOT / 'test-vectors/ergo-sigma/cost-ledger/fixtures/method'


def call(t, m, obj, *args, types=b''):
    return bytes([0xdc, t, m]) + obj + vlq(len(args)) + b''.join(args) + types


def prop(t, m, obj, types=b''):
    return bytes([0xdb, t, m]) + obj + types


def bytecoll(data):
    return b'\x0e' + vlq(len(data)) + data


def save(name, ids, cases):
    wire.save(name, ids, cases)


def avl_serialize():
    vectors = json.loads(read_fixture_text(ROOT / 'test-vectors/ergo-sigma/avl-proof-parity/scala_avl_vectors.json.gz'))
    for name, mid, kind in [('contains', 9, 'lookup'), ('get', 10, 'lookup'),
                            ('getMany', 11, 'lookup'), ('insert', 12, 'insert'),
                            ('update', 13, 'update'), ('insertOrUpdate', 16, 'update'),
                            ('remove', 14, 'remove')]:
        cases = []
        kinds = ('insert', 'update') if mid == 16 else (kind,)
        selected = [v for v in vectors if v['op']['kind'] in kinds and v['name'].startswith('valid_')]
        for v in selected:
            avl = b'\x64' + bytes.fromhex(v['startDigestHex']) + b'\x07' + vlq(v['keyLength'])
            avl += b'\x00' if v['valueLength'] is None else b'\x01' + vlq(v['valueLength'])
            key = bytecoll(bytes.fromhex(v['op']['keyHex']))
            arg = key
            if mid in (11, 14):
                arg = coll(14, [key])
            elif mid in (12, 13, 16):
                value = bytecoll(bytes.fromhex(v['op']['valueHex']))
                arg = b'\x83\x01\x3c\x0e\x0e\x86\x02' + key + value
            proof = bytecoll(bytes.fromhex(v['proofHex']))
            cases += cases_for(v['name'], call(100, mid, avl, arg, proof))
            if mid == 11:
                for count in (0, 2):
                    cases += cases_for(f"{v['name']}-keys{count}",
                                       call(100, mid, avl, coll(14, [key] * count), proof))
            if mid == 9:
                # Valid metadata retains the digest height even when proof reconstruction fails.
                for n in (0, 1, 63, 64, 65, 129):
                    cases += cases_for(f"{v['name']}-bad-proof-{n}", call(100, mid, avl, arg, bytecoll(bytes(n))))
        ids = ['METHOD-avl-' + name]
        if mid == 9:
            ids += ['EVAL-avl-cost-height']
        save('avl-' + name, ids, cases)

    shapes = {name: scalar(t) for name, t in [('byte', 2), ('short', 3), ('int', 4),
              ('long', 5), ('bigint', 6), ('group', 7)]}
    shapes.update({'option-some': b'\xe3\x01\x04', 'option-none': b'\xe3\x02\x04',
                   'tuple': b'\x86\x02' + num(4) + num(5),
                   'box': b'\xa7',
                   'nested-coll': coll(14, [bytecoll(b''), bytecoll(bytes(128))])})
    for n in (0, 1, 127, 128):
        shapes[f'bytes-{n}'] = bytecoll(bytes(n))
    # Bool collection uses bit-array callbacks, with bit count rather than packed byte count.
    for n in (0, 1, 7, 8, 9, 127, 128):
        shapes[f'bits-{n}'] = b'\x0d' + vlq(n) + bytes((n + 7) // 8)
    dlog = b'\xcd' + G
    dht = b'\xce' + G + H + G + H
    for label, sb in [('true', b'\xd3'), ('false', b'\xd2'), ('dlog', dlog), ('dht', dht),
                      ('and', b'\x96\x02' + dlog + dht), ('or', b'\x97\x02' + dlog + dht),
                      ('threshold', b'\x98\x01\x02' + dlog + dht)]:
        shapes['sigma-' + label] = b'\x08' + sb
    for name, value in shapes.items():
        ids = ['METHOD-global-serialize']
        if name in ('byte', 'option-some', 'option-none') or name.startswith('sigma-'):
            ids += ['METHOD-global-serialize-E042']
        if name in ('short', 'int', 'long'):
            ids += ['METHOD-global-serialize-E043']
        if name.startswith(('bytes-', 'bits-')) or name == 'bigint':
            ids += ['METHOD-global-serialize-E044']
        if name.startswith('bytes-') or name in ('bigint', 'group'):
            ids += ['METHOD-global-serialize-E045']
        if name.startswith('bits-'):
            ids += ['METHOD-global-serialize-E046']
        if name == 'box':
            ids += ['METHOD-global-serialize-E047']
        cases = cases_for(name, call(106, 3, b'\xdd', value), ctx_ext_hex='01010402')
        if name == 'box':
            # Additional registers call putValue/putType, including nested
            # CreateTuple and ConcreteCollection values and their count writes.
            for label, register in [('int', num(4)), ('tuple', shapes['tuple']),
                                    ('collection', shapes['nested-coll'])]:
                box_bytes = (vlq(1000000) + b'\x00\x08\xd3\x00\x00\x01'
                             + register + bytes(33)).hex()
                cases += cases_for('box-register-' + label, call(106, 3, b'\xdd', value),
                                   self_box_hex=box_bytes, inputs_hex=[box_bytes])
        save('serialize-' + name, ids, cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('family', choices=['avl-serialize'])
    parser.parse_args()
    wire.OUT.mkdir(exist_ok=True)
    avl_serialize()


if __name__ == '__main__':
    main()
