#!/usr/bin/env python3
"""Task 9.1 hand-serialized probes. JVM alone supplies expected fields.

Run with PYTHONDONTWRITEBYTECODE=1. Run --limits after gen-cost-fixture.sh
has observed the unrestricted cases, then refresh every fixture again.
NumericCastCostKind prices the target type, never the source type.
"""
import copy
import json
import sys

import eval_cost as wire
from eval_cost import ROOT, TRUE, G, cases_for, header, num, vlq
from cost_fixture_io import read_fixture_text, write_fixture_text

DIRECTORY = ROOT / 'test-vectors/ergo-sigma/cost-ledger/fixtures'
FILES = ('op-fixed/relational', 'op-fixed/arith', 'op-fixed/casts',
         'op-fixed/zero-cost-rejects', 'method/box-registers',
         'method/groupelement-exp', 'version/header-checkpow',
         'interpreter/toblockcost')


def save(path, ids, cases):
    family, name = path.split('/')
    wire.OUT = DIRECTORY / family
    path = wire.OUT / (name + '.json.gz')
    if path.exists():
        old = json.loads(read_fixture_text(path))
        originals = [c for c in old['cases'] if '-limit' not in c['name']]
        if old['ledger'] == ids and originals == cases:
            return
        # Preserve independently measured expectations and derived limit cases
        # when regeneration leaves every unrestricted request unchanged.
        if (old['ledger'] == ids and
                [c['request'] for c in originals] == [c['request'] for c in cases] and
                [c['name'] for c in originals] == [c['name'] for c in cases]):
            return
    wire.save(name, ids, cases)


def main():
    cases = []
    for op in range(0x8f, 0x95):
        for t in (2, 3, 4, 5, 6, 9):
            for right in (1, 2):
                cases += cases_for(f'op{op:02x}-type{t}-right{right}',
                                   bytes([op]) + num(t) + num(t, right))
    save(FILES[0], [f'OP-0x{op:02X}' for op in range(0x8f, 0x95)], cases)
    cases = []
    ops = (0x99, 0x9a, 0x9c, 0x9d, 0x9e, 0xa1, 0xa2)
    for op in ops:
        for t in (2, 3, 4, 5, 6, 9):
            cases += cases_for(f'op{op:02x}-type{t}', bytes([op]) + num(t, 6) + num(t, 2))
    save(FILES[1], [f'OP-0x{op:02X}' for op in ops], cases)
    cases = []
    for op in (0x7d, 0x7e):
        for source in (2, 3, 4, 5, 6, 9):
            for target in (2, 3, 4, 5, 6, 9):
                cases += cases_for(f'op{op:02x}-source{source}-target{target}',
                                   bytes([op]) + num(source) + bytes([target]))
    save(FILES[2], ['OP-0x7D', 'OP-0x7E'], cases)
    cases = cases_for('control-without-unsupported-op', num(4))
    # Deprecated nodes retain their Scala serializer operand grammar.
    for op, value in [(0xb6, b'\xb6' + num(2, 7) + b'\x0e\x21' + bytes(33)
                       + num(4, 32) + b'\xe3\x01\x04'),
                      (0xb7, b'\xb7\x64' + bytes(33) + b'\x07\x20\x00\x0e\x00\x0e\x00'),
                      (0xcf, b'\xcf' + TRUE),
                      (0xd7, b'\xd7\x01\x00' + num(4)),
                      (0xf1, b'\xf1' + num(4))]:
        cases += cases_for(f'op{op:02x}', value, failure=True)
    save(FILES[3], [f'OP-0x{op:02X}' for op in (0xb6, 0xb7, 0xcf, 0xd7, 0xf1)], cases)
    cases = []
    for reg in range(10):
        for present in (False, True):
            # All six optional registers are populated densely with Ints.
            box = (vlq(1000000) + b'\x00' + TRUE + b'\x00\x00'
                   + (b'\x06' + num(4) * 6 if present else b'\x00') + bytes(33)).hex()
            # R0..R3 are mandatory: the empty/full optional-register contexts
            # test the same accessor identity, never claim mandatory absence.
            value = bytes([0xdb, 99, 9 + reg]) + b'\xa7'
            cases += cases_for(f'R{reg}-optional-present{present}', value,
                               self_box_hex=box, inputs_hex=[box])
    save(FILES[4], ['METHOD-box-registers-R0-R3', 'METHOD-box-registers-R4-R9'], cases)
    cases = []
    for n in (0, 1, 127, (1 << 255) - 1):
        encoded = n.to_bytes(max(1, (n.bit_length() + 8) // 8), 'big')
        exponent = b'\x06' + vlq(len(encoded)) + encoded
        cases += cases_for(f'exp-{n}', b'\xdc\x07\x03\x07' + G + b'\x01' + exponent)
    save(FILES[5], ['METHOD-groupelement-exp'], cases)
    cases = []
    for version in (1, 2):
        h = header()
        if version == 1:
            h = bytes([1]) + h[1:-42] + G + G + bytes(8) + b'\x01\x01'
        cases += cases_for(f'inspected-header-v{version}', b'\xdb\x68\x10\x68' + h,
                               failure=version == 1)
    save(FILES[6], ['VERSION-header-checkPow-G023'], cases)
    # Ten prefix costs cover all residues modulo ten. Nonzero init verifies
    # rounding composes with an already accumulated block cost.
    cases = []
    for init in (0, 17):
        cases += cases_for(f'rounding-init{init}', num(4), init_cost_block=init)
    save(FILES[7], ['INTERP-toblockcost'], cases)


def limits():
    for name in FILES:
        path = DIRECTORY / (name + '.json.gz')
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
            for limit in sorted({max(0, cost - 1), cost, cost + 1}):
                probe = copy.deepcopy(case)
                probe['name'] += f'-limit{limit}'
                probe['request']['cost_limit_block'] = limit
                probe['construction']['limit_from_jvm_block_cost'] = cost
                probe.pop('expected')
                # Divergences are specific to a request, including its budget.
                probe.pop('known_divergence', None)
                old = previous.get(probe['name'])
                if old and old['request'] == probe['request']:
                    probe['expected'] = old['expected']
                    if 'known_divergence' in old:
                        probe['known_divergence'] = old['known_divergence']
                expanded.append(probe)
        fixture['cases'] = originals + expanded
        write_fixture_text(path, json.dumps(fixture, indent=2) + '\n')


if __name__ == '__main__':
    if sys.argv[1:] == ['--limits']:
        limits()
    elif not sys.argv[1:]:
        main()
    else:
        sys.exit('usage: fixed_cost.py [--limits]')
