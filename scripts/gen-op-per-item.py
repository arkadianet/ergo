#!/usr/bin/env python3
"""Hand-serialize per-item trees; expected fields are written only by the JVM tool."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'test-vectors/ergo-sigma/cost-ledger/fixtures/op-per-item'
BASE = json.loads((OUT.parent / 'interpreter/p2pk.json').read_text())['request']


def vlq(n):
    out = bytearray()
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def integer(n):
    return b'\x04' + vlq(2 * n)


def byte_coll(data):
    return b'\x0e' + vlq(len(data)) + data


def bool_coll(n, value):
    bits = bytes([255 if value else 0]) * (n // 8)
    if n % 8:
        bits += bytes([(1 << (n % 8)) - 1 if value else 0])
    return b'\x0d' + vlq(n) + bits


def closure(body, tpe=b'\x01'):
    return b'\xd9\x01\x01' + tpe + body


def block(items, result=b'\x08\xd3'):
    return b'\xd8' + vlq(len(items)) + b''.join(
        b'\xd6' + vlq(i + 10) + item for i, item in enumerate(items)) + result


def expression(name, op, n):
    opcode = bytes([op])
    if name in ('and', 'or', 'xor-of'):
        return opcode + bool_coll(n, name == 'and')
    if name == 'xor':
        return opcode + byte_coll(bytes(n)) * 2
    if name == 'append':
        return opcode + byte_coll(bytes(n // 2)) + byte_coll(bytes(n - n // 2))
    if name == 'slice':
        # Empty receiver distinguishes requested interval from result length.
        return opcode + byte_coll(b'') + integer(0) + integer(n)
    if name in ('filter', 'map', 'exists', 'forall'):
        body = b'\x72\x01' if name == 'map' else bytes([1, name != 'exists'])
        return opcode + bool_coll(n, True) + closure(body)
    if name == 'fold':
        # Fold receives one Tuple(Boolean, Boolean) argument; ignore it.
        return opcode + bool_coll(n, True) + b'\x01\x01' + closure(b'\x01\x01', b'\x3c\x01\x01')
    if name in ('blake2b256', 'sha256'):
        return opcode + byte_coll(bytes(n))
    if name in ('sigma-and', 'sigma-or'):
        return opcode + vlq(n) + b'\x08\xd3' * n
    if name == 'at-least':
        return opcode + integer(0) + b'\x14' + vlq(n) + b'\xd3' * n
    if name == 'subst-constants':
        # Original pool size n; zero replacements. Pool need not be referenced.
        tree = b'\x10' + vlq(n) + b'\x01\x01' * n + b'\x08\xd3'
        return opcode + byte_coll(tree) + b'\x10\x00' + bool_coll(0, False)
    if name == 'block-value':
        return block([b'\x01\x01'] * n)
    if name == 'sigma-prop-bytes':
        # A unary Cand preserves a two-node proposition in the wire constant.
        prop = b'\xd3' if n == 1 else b'\x96' + vlq(n - 1) + b'\xd3' * (n - 1)
        return opcode + b'\x08' + prop
    raise ValueError(name)


FAMILIES = [
    ('and', 0x96, 32), ('or', 0x97, 64), ('xor-of', 0xff, 32),
    ('xor', 0x9b, 128), ('append', 0xb3, 100), ('slice', 0xb4, 100),
    ('filter', 0xb5, 10), ('map', 0xad, 10), ('exists', 0xae, 10),
    ('forall', 0xaf, 10), ('fold', 0xb0, 10), ('blake2b256', 0xcb, 128),
    ('sha256', 0xcc, 64), ('sigma-and', 0xea, 1), ('sigma-or', 0xeb, 1),
    ('at-least', 0x98, 5), ('subst-constants', 0x74, 1), ('block-value', 0xd8, 10),
    ('sigma-prop-bytes', 0xd0, 1),
]


def main():
    OUT.mkdir(exist_ok=True)
    for name, op, k in FAMILIES:
        lengths = sorted(set([0, 1, k - 1, k, k + 1, 2 * k + 1]))
        if name == 'sigma-prop-bytes':
            lengths.remove(0)  # No SigmaBoolean has zero nodes.
        cases = []
        for n in lengths:
            target = expression(name, op, n)
            for prefix in range(10):
                body = block([target])
                # Empty blocks add 2 JIT; If(true, ..., true) adds 15 JIT.
                # Five even offsets and five odd offsets cover all residues.
                body = b'\xd8\x00' * (prefix % 5) + body
                if prefix >= 5:
                    body = b'\x95\x01\x01' + body + b'\x08\xd3'
                request = dict(BASE, tree_hex=(b'\x00' + body).hex(), proof_hex='',
                               init_cost_block=0, cost_limit_block=1000000,
                               activated_version=3, tree_version_expected=0)
                if name in ('sigma-and', 'sigma-or') and n == 0:
                    request['observe_evaluator_failure'] = True
                cases.append({'name': f'{name}-n{n}-prefix{prefix}',
                              'construction': {'n': n, 'prefix': prefix,
                                               'target_hex': target.hex(), 'body_hex': body.hex()},
                              'request': request})
        groups = {name: cases}
        if name in ('sigma-and', 'sigma-or'):
            groups = {
                name: [c for c in cases if c['construction']['n'] != 0],
                name + '-empty': [c for c in cases if c['construction']['n'] == 0],
            }
        for group_name, group_cases in groups.items():
            path = OUT / f'{group_name}.json'
            fixture = {'ledger': [f'OP-0x{op:02X}'], 'chunk_size': k, 'cases': group_cases}
            if name in ('subst-constants', 'block-value'):
                fixture['ledger'].append('ROUND-perItem-chunking')
            # Preserve independently generated expectations only for identical inputs.
            if path.exists():
                old = json.loads(path.read_text())
                if [c['request'] for c in old['cases']] == [c['request'] for c in group_cases]:
                    if 'manifest' in old:
                        fixture['manifest'] = old['manifest']
                    for case, previous in zip(group_cases, old['cases']):
                        if 'expected' in previous:
                            case['expected'] = previous['expected']
            path.write_text(json.dumps(fixture, indent=2) + '\n')



if __name__ == '__main__':
    main()
