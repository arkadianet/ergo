#!/usr/bin/env python3
"""Hand-serialized collection, global and option METHOD cost fixtures.

Only scripts/gen-cost-fixture.sh supplies oracle expectations. Run with
PYTHONDONTWRITEBYTECODE=1 python3 ergo-difftest/src/gen/method_rest_cost.py.
"""
from method_cost import bytecoll, call, prop, save, wire
from eval_cost import cases_for, coll, num


def lengths(k):
    return sorted({0, 1, k - 1, k, k + 1, 2 * k + 1})


def closure(t, body):
    return bytes([0xd9, 1, 1, t]) + body


def failure_probes():
    # OptionGet(None) throws while evaluating the receiver, before either envelope.
    receiver = b'\xe4\xe3\x02\x0e'
    cases = []
    for label, target in [('property', prop(12, 14, receiver)),
                          ('method', call(12, 29, receiver, bytecoll(b''))),
                          ('argument', call(12, 29, bytecoll(b''), receiver))]:
        cases += cases_for('throwing-' + label, target, failure=True)
    save('failure-envelope', ['METHOD-coll-indices', 'METHOD-coll-zip', 'ORDER-propertycall-receiver', 'ORDER-methodcall-arguments', 'ORDER-optionget-input'], cases)

    cases = []
    for k, table in [(0, 16), (1, 16), (33, 16), (2, 0), (32, 15)]:
        for n in (0, 129):
            target = call(106, 8, b'\xdd', num(4, k), bytecoll(bytes(n)),
                          bytecoll(b''), bytecoll(b''), num(4, table))
            cases += cases_for(f'invalid-powHit-k{k}-N{table}-n{n}', target, failure=True)
    save('failure-powHit', ['METHOD-global-powHit', 'ORDER-powHit-validation'], cases)

    cases = []
    for label, target in [('header-property', prop(104, 9, b'\xa7')),
                          ('encodeNbits-method', call(106, 6, b'\xdd', num(4)))]:
        cases += cases_for('malformed-' + label, target, failure=True)
    save('failure-fixed', ['METHOD-header-props', 'METHOD-global-encodeNbits', 'ORDER-fixed-method-invocation'], cases)


def main():
    wire.OUT.mkdir(exist_ok=True)
    failure_probes()
    for name, mid, k in [('indices', 14, 16), ('reverse', 30, 100), ('indexOf', 26, 2),
                         ('zip', 29, 10), ('startsEndsWith', 31, 10), ('flatMap', 15, 8),
                         ('patch', 19, 10), ('updated', 20, 10), ('updateMany', 21, 10)]:
        cases = []
        for n in lengths(k):
            xs = bytecoll(bytes(n))
            targets = []
            if mid in (14, 30):
                targets.append(('receiver', prop(12, mid, xs)))
            elif mid == 26:
                for start in sorted({0, -1, n}):
                    start_expr = b'\x04\x01' if start == -1 else num(4, start)
                    for needle in (0, 1):
                        targets.append((f'from{start}-needle{needle}', call(12, mid, xs, num(2, needle), start_expr)))
            elif mid in (29, 31):
                for m in sorted({0, 1, n + 11}):
                    for method in ([mid] if mid == 29 else [31, 32]):
                        targets.append((f'method{method}-arg{m}', call(12, method, xs, bytecoll(bytes(m)))))
            elif mid == 15:
                # One receiver element and n output elements distinguishes the charged length.
                targets.append(('one-to-n', call(12, mid, bytecoll(b'\x00'), closure(2, xs))))
                targets.append(('empty-receiver', call(12, mid, bytecoll(b''), closure(2, xs))))
                targets.append(('n-to-two-n', call(12, mid, xs, closure(2, bytecoll(bytes(2))))))
            elif mid == 19:
                for a in sorted({0, n // 2, n}):
                    targets.append((f'receiver{a}-patch{n-a}', call(12, mid, bytecoll(bytes(a)), num(4, 0), bytecoll(bytes(n-a)), num(4, 0))))
            elif mid == 20:
                targets.append(('index0', call(12, mid, xs, num(4, 0), num(2, 1))))
            elif mid == 21:
                targets.append(('empty-updates', call(12, mid, xs, coll(4, []), bytecoll(b''))))
                if n:
                    targets.append(('one-update', call(12, mid, xs, coll(4, [num(4, n-1)]), bytecoll(b'\x01'))))
            for label, target in targets:
                cases += cases_for(f'{name}-n{n}-{label}', target, failure=(mid == 20 and n == 0))
        save('coll-' + name, ['METHOD-coll-' + name], cases)

    cases = []
    for n in lengths(128):
        cases += cases_for(f'xor-n{n}', call(106, 2, b'\xdd', bytecoll(bytes(n)), bytecoll(bytes(n))))
    save('global-xor', ['METHOD-global-xor'], cases)

    cases = []
    for n in lengths(32):
        # Unit's data serializer consumes zero bytes; other lengths encode Coll[Byte].
        data = b'' if n == 0 else bytes([n - 1]) + bytes(n - 1)
        tpe = b'\x62' if n == 0 else b'\x0e'
        cases += cases_for(f'deserializeTo-bytes{n}', call(106, 4, b'\xdd', bytecoll(data), types=tpe))
    save('global-deserializeTo', ['METHOD-global-deserializeTo'], cases)

    cases = []
    for k in (2, 3, 32):
        for n in lengths(128):
            for table in (16, 32):
                for split in ('msg', 'nonce', 'h'):
                    parts = [bytecoll(bytes(n if split == label else 0)) for label in ('msg', 'nonce', 'h')]
                    cases += cases_for(f'powHit-k{k}-length{n}-{split}-N{table}', call(106, 8, b'\xdd', num(4, k), *parts, num(4, table)))
    save('global-powHit', ['METHOD-global-powHit'], cases)

    for name, mid in [('map', 7), ('filter', 8)]:
        cases = []
        for option in (1, 2):
            variants = [('identity', b'\x72\x01'), ('constant', num(4, 2))] if mid == 7 else [
                ('false', b'\x01\x00'), ('true', b'\x01\x01')]
            for label, body in variants:
                cases += cases_for(f'option-{name}-var{option}-{label}',
                                   call(36, mid, bytes([0xe3, option, 4]), closure(4, body)),
                                   ctx_ext_hex='01010402')
        save('option-' + name, ['METHOD-option-' + name], cases)


if __name__ == '__main__':
    main()
