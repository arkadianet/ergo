#!/usr/bin/env python3
"""Hand-serialized EVAL trees. Only gen-cost-fixture.sh writes expected costs.

Wire authority: ergo-ser opcode/write.rs, sigma_type/write.rs, sigma_value/,
header.rs and ergo_box/candidate.rs; Scala DataValueComparer.scala descriptors.
No ErgoScript compiler is involved. Ten prefixes expose every JIT remainder.
"""
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'scripts'))
from cost_fixture_io import fixture_path, read_fixture_text, write_fixture_text

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'test-vectors/ergo-sigma/cost-ledger/fixtures/eval'
BASE = json.loads(read_fixture_text(OUT.parent / 'interpreter/p2pk.json.gz'))['request']
G = bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
H = bytes([3]) + G[1:]  # Negated generator, also a valid curve point.
TRUE = b'\x08\xd3'


def vlq(n):
    out = bytearray()
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def num(t, n=1):
    return bytes([t]) + (bytes([n]) if t == 2 else
                         b'\x01' + bytes([n]) if t in (6, 9) else vlq(2 * n))


def coll(t, items):
    return b'\x83' + vlq(len(items)) + bytes([t]) + b''.join(items)


def block(items, result=TRUE):
    return b'\xd8' + vlq(len(items)) + b''.join(
        b'\xd6' + vlq(i + 10) + x for i, x in enumerate(items)) + result


def eq(a, b):
    return b'\x93' + a + b


def box(n=0, changed=False, changed_id=False):
    tokens = b''.join(bytes([9 if changed_id and i == 0 else i + 1]) * 32 + vlq(2 if changed and i == 0 else 1)
                      for i in range(n))
    return vlq(1000000) + b'\x00' + TRUE + b'\x00' + bytes([n]) + tokens + b'\x00' + bytes(33)


def header(changed=False):
    return (b'\x02' + bytes(32 * 3 + 33) + vlq(2 if changed else 1)
            + bytes(32) + bytes.fromhex('01010000') + b'\x00' + bytes(4) + G + bytes(8))


def scalar(t, changed=False):
    if t == 1:
        return bytes([1, not changed])
    if t in (2, 3, 4, 5, 6, 9):
        return num(t, 2 if changed else 1)
    if t == 7:
        return b'\x07' + (H if changed else G)
    if t == 8:
        return b'\x08' + (b'\xd2' if changed else b'\xd3')
    if t == 99:
        return b'\x63' + box(1 if changed else 0)
    if t == 100:
        return b'\x64' + bytes([changed]) + bytes(32) + b'\x07\x20\x00'
    if t == 104:
        return b'\x68' + header(changed)
    if t == 105:
        # PreHeader has no constant serializer; use runtime context property.
        # No second PreHeader value is constructible within one context.
        return b'\xdb\x65\x03\xfe'
    raise ValueError(t)


def prefixes(body):
    for p in range(10):
        wrapped = b'\xd8\x00' * (p % 5) + body
        if p >= 5:
            wrapped = b'\x95\x01\x01' + wrapped + TRUE
        yield p, wrapped


def cases_for(name, target, *, result=False, failure=False, pool=None, self_tree=False, **context):
    cases = []
    body = b'\xd1' + target if result else block([target])
    for p, wrapped in prefixes(body):
        # v3 preserves explicit Upcast and enables unsigned/header constants.
        payload = (vlq(len(pool)) + b''.join(pool) if pool is not None else b'') + wrapped
        tree = bytes([0x1b if pool is not None else 0x0b]) + vlq(len(payload)) + payload
        req = dict(BASE, tree_hex=tree.hex(), proof_hex='', init_cost_block=0,
                   cost_limit_block=1000000, activated_version=3, tree_version_expected=3)
        req.update(context)
        if self_tree:
            # Consensus spends evaluate the SELF guard; Rust takes its original
            # bytes for the deserialize-substitution charge.
            self_box = (vlq(1000000) + tree + bytes(3 + 33)).hex()
            req.update(self_box_hex=self_box, inputs_hex=[self_box])
        if failure:
            req['observe_evaluator_failure'] = True
        cases.append({'name': f'{name}-prefix{p}',
                      'construction': {'target_hex': target.hex(), 'prefix': p}, 'request': req})
    return cases


def save(name, ids, cases):
    path = OUT / f'{name}.json.gz'
    value = {'ledger': ids, 'cases': cases}
    if fixture_path(path).exists():
        old = json.loads(read_fixture_text(path))
        if [c['request'] for c in old['cases']] == [c['request'] for c in cases]:
            if 'manifest' in old:
                value['manifest'] = old['manifest']
            for c, prev in zip(cases, old['cases']):
                for field in ('expected', 'known_divergence'):
                    if field in prev:
                        c[field] = prev[field]
    write_fixture_text(path, json.dumps(value, indent=2) + '\n')


def main():
    OUT.mkdir(exist_ok=True)
    cases = cases_for('inline-constant', b'\x01\x01', result=True)
    for n in (0, 1, 9, 10, 11, 21):
        closure = b'\xd9\x01\x01\x04\x72\x01'
        cases += cases_for(f'addtoenv-map-n{n}', b'\xad' + coll(4, [num(4)] * n) + closure)
        cases += cases_for(f'addtoenv-apply-n{n}', block([b'\xda' + closure + b'\x01' + num(4)] * n))
    for t in (2, 3, 4, 5, 6, 9):
        cases += cases_for(f'upcast-target-{t}', b'\x7e' + num(2) + bytes([t]))
        if t in (2, 3, 4, 5):
            cases += cases_for(f'downcast-bigint-target-{t}', b'\x7d' + num(6) + bytes([t]))
    for name, op in [('minus', 0x99), ('plus', 0x9a), ('multiply', 0x9c),
                     ('divide', 0x9d), ('modulo', 0x9e), ('min', 0xa1), ('max', 0xa2)]:
        cases += cases_for(f'bigint-{name}', bytes([op]) + num(6, 6) + num(6, 2))
    save('constants-env-numeric', ['EVAL-const-inline', 'EVAL-addtoenv', 'EVAL-numeric-cast', 'EVAL-arith-bigint'], cases)

    cases = []
    for n in (1, 2, 5):
        for fork in (False, True):
            # The missing R4 uses an explicit SigmaProp default, so substitution
            # succeeds even though the deserialize node lies on the dead branch.
            live = block([b'\x73\x00'] * n)
            target = b'\x95\x7f' + live + (b'\xd5\x04\x08\x01' + TRUE if fork else TRUE)
            cases += cases_for(f'hasdeserialize-{fork}-refs{n}', target, pool=[num(4)], self_tree=True)
    save('deserialize', ['EVAL-hasdeserialize-fork'], cases)

    cases = []
    ids = ['EVAL-eq-prim', 'EVAL-eq-matchtype', 'EVAL-eq-bigint', 'EVAL-eq-groupelement',
           'EVAL-eq-avltree', 'EVAL-eq-box', 'EVAL-eq-preheader', 'EVAL-eq-header',
           'EVAL-eq-tuple', 'EVAL-eq-option', 'EVAL-eq-mismatch-and-unit-E032']
    for t in (1, 2, 3, 4, 5, 6, 9, 7, 99, 100, 104, 105):
        for changed in (False, True):
            if t == 105 and changed:
                continue
            cases += cases_for(f'scalar-{t}-mismatch{changed}', eq(scalar(t), scalar(t, changed)), result=True)
    for left, right, label in [(b'\x62', b'\x62', 'unit'),
                              (b'\xe3\x01\x04', b'\xe3\x01\x04', 'option-none'),
                              (b'\xe3\x01\x04', b'\xe3\x02\x04', 'option-none-distinct'),
                              (b'\xe3\x01\x04', b'\xe3\x02\x04', 'option-some-none')]:
        ctx = {'ctx_ext_hex': '01010402'} if label == 'option-some-none' else {}
        cases += cases_for(label, eq(left, right), result=True, **ctx)
    cases += cases_for('option-some-some', eq(b'\xe3\x01\x04', b'\xe3\x01\x04'), result=True, ctx_ext_hex='01010402')
    for changed in (False, True):
        a = b'\x86\x02' + num(4) + scalar(7)
        b = b'\x86\x02' + num(4, 2 if changed else 1) + scalar(7)
        cases += cases_for(f'tuple-mismatch{changed}', eq(a, b), result=True)
    save('equality-scalars', ids, cases)

    for t, name, k in [(1, 'boolean', 128), (2, 'byte', 128), (3, 'short', 96),
                        (4, 'int', 64), (5, 'long', 48), (6, 'bigint', 5), (9, 'unsigned-bigint', 5),
                        (7, 'group', 1), (99, 'box', 1), (100, 'avl', 2), (104, 'header', 1),
                        (105, 'preheader', 1), (8, 'sigmaprop', 1)]:
        cases = []
        for n in sorted(set([0, 1, k - 1, k, k + 1, 2 * k + 1])):
            a = coll(t, [scalar(t)] * n)
            cases += cases_for(f'{name}-equal-n{n}', eq(a, a), result=True)
        n = 2 * k + 1
        a = coll(t, [scalar(t)] * n)
        if t != 105:
            b = coll(t, [scalar(t, True)] + [scalar(t)] * (n - 1))
            cases += cases_for(f'{name}-early-mismatch-n{n}', eq(a, b), result=True)
        cases += cases_for(f'{name}-length-mismatch', eq(a, coll(t, [])), result=True)
        ids = ['EVAL-eq-coll-sigmaprop-descriptor'] if t == 8 else ['EVAL-eq-coll-descriptor']
        save(f'collection-{name}', ids, cases)

    cases = []
    def string_pair(s):
        # EQ checks the outer Tuple type shallowly. Its recursive comparer can
        # then reach String; a bare SString operand fails Scala isValueOfType.
        return b'\x3c\x66\x04' + s[1:] + b'\x02'

    for n in (0, 1, 95, 96, 97, 193):
        a = string_pair(b'\x66' + vlq(n) + b'a' * n)
        cases += cases_for(f'string-equal-n{n}', eq(a, a), result=True)
    cases += cases_for('string-early-mismatch', eq(string_pair(b'\x66' + vlq(193) + b'a' * 193),
                                                 string_pair(b'\x66' + vlq(193) + b'b' + b'a' * 192)), result=True)
    cases += cases_for('string-length-mismatch', eq(string_pair(b'\x66\x01a'), string_pair(b'\x66\x00')), result=True)
    save('strings', ['EVAL-eq-coll-descriptor'], cases)
    save('strings-direct', ['EVAL-eq-coll-descriptor'],
         cases_for('bare-string-equality', eq(b'\x66\x01a', b'\x66\x01a'), result=True))

    cases = []
    for n in (0, 1, 2, 3):
        a = b'\xdb\x63\x08\x63' + box(n)
        cases += cases_for(f'tokens-equal-n{n}', eq(a, a), result=True)
        if n:
            b = b'\xdb\x63\x08\x63' + box(n, True)
            cases += cases_for(f'tokens-amount-mismatch-n{n}', eq(a, b), result=True)
    # Nested collections take generic fallback recursion instead of a descriptor.
    for n in (0, 1, 2, 3):
        a = b'\x83' + vlq(n) + b'\x0e' + b'\x0e\x01\x01' * n
        cases += cases_for(f'fallback-equal-n{n}', eq(a, a), result=True)
    save('tokens-fallback', ['EVAL-eq-tokens', 'EVAL-eq-coll-fallback'], cases)

    cases = []
    dlog = b'\xcd' + G
    dht = b'\xce' + G * 4
    shapes = [b'\xd3', dlog, dht, b'\x96\x02' + dlog * 2,
              b'\x97\x02' + dlog * 2, b'\x98\x01\x02' + dlog * 2]
    for i, shape in enumerate(shapes):
        cases += cases_for(f'sigma-shape{i}-equal', eq(b'\x08' + shape, b'\x08' + shape), result=True)
        cases += cases_for(f'sigma-shape{i}-constructor-mismatch', eq(b'\x08' + shape, b'\x08\xd2'),
                           result=True, failure=i >= 3)
    for i in range(4):
        right = b'\xce' + G * i + H + G * (3 - i)
        cases += cases_for(f'dht-mismatch-point{i}', eq(b'\x08' + dht, b'\x08' + right), result=True)
    cases += cases_for('sigma-collection-throw', eq(coll(8, [b'\x08' + shapes[3]]), coll(8, [TRUE])), result=True, failure=True)
    # Keep BoolToSigmaProp wrapping failures to expose its charge ordering too.
    save('sigma-booleans', ['EVAL-eq-sigmaboolean', 'EVAL-eq-coll-sigmaprop-descriptor',
                           'EVAL-deferred-charge-on-exception'], cases)

    cases = []
    for n in (0, 1, 2, 3):
        # Lazy BoxCollection carrier, distinct from ConcreteCollection[Box].
        cases += cases_for(f'lazy-boxes-equal-n{n}', eq(b'\xa5', b'\xa5'), result=True,
                           outputs_hex=[box()[:-33].hex()] * n)
    save('lazy-boxes', ['EVAL-eq-boxcollection'], cases)

    cases = []
    for n in (1, 3):
        a = b'\xdb\x63\x08\x63' + box(n)
        changed_box = box(n, changed_id=True)
        b = b'\xdb\x63\x08\x63' + changed_box
        cases += cases_for(f'tokens-id-mismatch-n{n}', eq(a, b), result=True)
    cases += cases_for('tokens-length-mismatch', eq(b'\xdb\x63\x08\x63' + box(1),
                                                  b'\xdb\x63\x08\x63' + box()), result=True)
    a = b'\x83\x03\x0e' + b'\x0e\x01\x01' * 3
    b = b'\x83\x03\x0e' + b'\x0e\x01\x02' + b'\x0e\x01\x01' * 2
    cases += cases_for('fallback-early-mismatch', eq(a, b), result=True)
    cases += cases_for('fallback-length-mismatch', eq(a, b'\x83\x00\x0e'), result=True)
    for op in (0x96, 0x97):
        a = bytes([8, op, 2]) + dlog * 2
        b = bytes([8, op, 2]) + b'\xcd' + H + dlog
        cases += cases_for(f'conjecture-{op}-child-mismatch', eq(a, b), result=True)
        cases += cases_for(f'conjecture-{op}-length-mismatch', eq(a, bytes([8, op, 1]) + dlog), result=True)
        cases += cases_for(f'leaf-left-conjecture-{op}-false', eq(b'\x08' + dlog, a), result=True)
    cases += cases_for('threshold-k-mismatch', eq(b'\x08\x98\x01\x02' + dlog * 2,
                                                b'\x08\x98\x02\x02' + dlog * 2), result=True)
    cases += cases_for('lazy-boxes-early-mismatch', eq(b'\xa4', b'\xa5'), result=True,
                       inputs_hex=[BASE['self_box_hex']] * 3,
                       outputs_hex=[box(1)[:-33].hex()] + [box()[:-33].hex()] * 2)
    cases += cases_for('lazy-boxes-length-mismatch', eq(b'\xa4', b'\xa5'), result=True)
    save('equality-edges', ['EVAL-eq-tokens', 'EVAL-eq-coll-fallback',
                          'EVAL-eq-sigmaboolean', 'EVAL-eq-boxcollection'], cases)

    cases = []
    for i in (3, 4, 5):
        cases += cases_for(f'isolated-conjecture-{i}-throw', eq(b'\x08' + shapes[i], TRUE), failure=True)
    cases += cases_for('isolated-sigma-collection-throw', eq(coll(8, [b'\x08' + shapes[3]]),
                                                         coll(8, [TRUE])), failure=True)
    save('sigma-throws', ['EVAL-eq-sigmaboolean', 'EVAL-eq-coll-sigmaprop-descriptor'], cases)


if __name__ == '__main__':
    main()
