#!/usr/bin/env python3
"""Deterministic interpreter requests; gen-cost-fixture.sh supplies expectations.

Run once, populate JVM expectations, then run with --limits and populate again.
"""
import json
import sys
from interpreter_cost import BASE, OUT, ROOT, vlq, fixture_path, read_fixture_text, write_fixture_text


def main():
    signed = json.loads((ROOT / 'test-vectors/scala/multi_sig_mixed_dlog_dht.json').read_text())
    dlog, dht = signed['proposition']['children']
    # SigmaPropConstant(CAND(ProveDlog, ProveDHTuple)), without compiler folding.
    tree = bytes.fromhex('00089602cd' + dlog['pk'] + 'ce' + ''.join(dht[k] for k in ('g', 'h', 'u', 'v')))
    box = (vlq(1000000) + tree + bytes(36)).hex()
    base = dict(BASE, tree_hex=tree.hex(), self_box_hex=box, inputs_hex=[box],
                proof_hex=signed['proof_hex'], message_hex=signed['message_hex'])
    path = OUT / 'profiling-isolation.json.gz'
    old = json.loads(read_fixture_text(path)) if fixture_path(path).exists() else {}
    requests = []
    for proof in ('valid', 'invalid'):
        for initial in (0, 17):
            for timing in (False, True):
                request = dict(base, init_cost_block=initial, cost_limit_block=1000000,
                               measure_operation_time=timing)
                if proof == 'invalid':
                    signature = bytearray.fromhex(request['proof_hex'])
                    signature[-1] ^= 1
                    request['proof_hex'] = signature.hex()
                requests.append((f'{proof}-init{initial}-timing{timing}', request))
    if '--limits' in sys.argv:
        for previous in old['cases']:
            if previous['request']['cost_limit_block'] != 1000000:
                continue
            total = previous['expected']['total_block_cost']
            assert isinstance(total, int), 'JVM-measured total required'
            for limit in (total - 1, total, total + 1):
                requests.append((previous['name'] + f'-limit{limit}',
                                 dict(previous['request'], cost_limit_block=limit)))
    cases = [{'name': name, 'construction': 'Hand-serialized mixed DLog/DHT conjunction; frozen Scala proof/message; invalid proof flips final byte; paired operation timing and JVM-measured limits.',
              'request': request} for name, request in requests]
    value = {'ledger': ['INTERP-profiling-cost-isolation-I023'], 'cases': cases}
    if old:
        if [c['request'] for c in old['cases']] == [c['request'] for c in cases]:
            value['manifest'] = old['manifest']
        for case in cases:
            for previous in old['cases']:
                if previous['request'] == case['request'] and 'expected' in previous:
                    case['expected'] = previous['expected']
    write_fixture_text(path, json.dumps(value, indent=2) + '\n')


if __name__ == '__main__':
    main()
