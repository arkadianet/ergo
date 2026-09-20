#!/usr/bin/env python3
"""Build wrapped-tree requests, then obtain every expectation from pinned JVM verify."""
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from cost_fixture_io import write_fixture_text

PATH = ROOT / 'test-vectors/ergo-sigma/cost-ledger/fixtures/version/soft-fork-wrapped.json.gz'
SOURCE = ROOT / 'scripts/jvm_evaluated_value_oracle/EvaluatedValueOracle.scala'
COMMAND = ['scala-cli', '--skip-cli-updates', 'run', str(SOURCE), '--server=false',
           '--suppress-outdated-dependency-warning', '--']


def vlq(n):
    result = bytearray()
    while n >= 128:
        result.append((n & 127) | 128)
        n >>= 7
    result.append(n)
    return bytes(result)


def main():
    base = json.loads(gzip.decompress((PATH.parent / 'subst-bytes.json.gz').read_bytes()))['cases'][0]['request']
    cases = []
    shapes = [
        (1001, '0402', False, None),
        (1019, '63c0843d0008d30000010c2800' + '00' * 33, False, None),
        (1002, 'fd', False, 'fd'),
        (1007, '0a', False, '0a'),
        (1008, '01ff', True, 'ff'),
        (1009, '2800', False, None),
        (1010, 'dbffff0402', False, 'ff'),
        (1011, 'db04ff0402', False, '04ff'),
        (1014, (bytes.fromhex('d1930e') + vlq(4100) + bytes(4100) + bytes.fromhex('0e00')).hex(), False, None),
    ]
    for rule, body_hex, segregated, matching in shapes:
        body = bytes.fromhex(body_hex)
        for parse_version in [1, 3]:
            raised_rule = {1007:1017,1008:1018,1011:1016}.get(rule, rule) if parse_version == 3 else rule
            # Option data is serializable at tree v3; these trees retain header v0.
            for activated in ([2, 3] if parse_version == 1 else [3]):
                for sized in [True, False]:
                    for status in ['enabled', 'disabled', 'replaced', 'changed_match', 'changed_miss']:
                        tree = bytes([(8 if sized else 0) | (16 if segregated else 0)])
                        tree += (vlq(len(body)) if sized else b'') + body
                        req = dict(base, tree_hex=tree.hex(), tree_version_expected=0,
                                   activated_version=activated, init_cost_block=17, ctx_ext_hex='00',
                                   parse_activated_version=parse_version, validation_settings_version=parse_version)
                        if status == 'disabled':
                            req['validation_settings_disabled_rules'] = [raised_rule]
                        elif status == 'replaced':
                            req['validation_settings_replaced_rules'] = {str(raised_rule):2000}
                        elif status.startswith('changed'):
                            req['validation_settings_changed_rules'] = {str(raised_rule): matching if status == 'changed_match' and matching else 'fe'}
                        cases.append(dict(name=f'rule_{raised_rule}_parse_{parse_version}_activation_{activated}_sized_{sized}_{status}',
                                          rule_id=raised_rule, sized=sized, request=req))
    # UnparsedErgoTree uses DefaultHeader even when the preserved wire header
    # has a higher version than the later verification context.
    for tree_version in [1, 2, 3]:
        for activated in [1, 2, 3]:
            for status in ['enabled', 'replaced']:
                req = dict(base, tree_hex=bytes([8 | tree_version, 1, 253]).hex(),
                           tree_version_expected=tree_version, activated_version=activated,
                           init_cost_block=17, ctx_ext_hex='00', parse_activated_version=1)
                if status == 'replaced':
                    req['validation_settings_replaced_rules'] = {'1002':2000}
                cases.append(dict(name=f'wrapped_header_{tree_version}_activation_{activated}_{status}',
                                  rule_id=1002, sized=True, request=req))
    # Header validation occurs before the wrapping catch; its status cannot rescue it.
    for status in ['enabled', 'replaced']:
        req = dict(base, tree_hex='0108d3', tree_version_expected=1, parse_activated_version=1, activated_version=2, ctx_ext_hex='00')
        if status == 'replaced':
            req['validation_settings_replaced_rules'] = {'1012':2000}
        cases.append(dict(name=f'header_size_{status}', rule_id=1012, sized=False, request=req))
    for limit in [21, 22, 23]:
        req = dict(base, tree_hex='0801fd', tree_version_expected=0, activated_version=2,
                   init_cost_block=17, cost_limit_block=limit, ctx_ext_hex='00',
                   validation_settings_replaced_rules={'1002':2000})
        cases.append(dict(name=f'wrapped_limit_{limit}', rule_id=1002, sized=True, request=req))
    write_fixture_text(PATH, json.dumps(dict(ledger=['VERSION-soft-fork-wrapped-rules'], cases=cases)))
    subprocess.run([str(ROOT / 'scripts/gen-cost-fixture.sh'), str(PATH)], check=True, cwd=ROOT)
    raw = subprocess.check_output(COMMAND + ['validation_rules_probe'], cwd=ROOT)
    probe = json.loads(raw)
    fixture = json.loads(gzip.decompress(PATH.read_bytes()))
    fixture['rule_status_probe'] = probe
    fixture['rule_status_probe_command'] = ' '.join(COMMAND + ['validation_rules_probe'])
    fixture['rule_status_probe_sha256'] = hashlib.sha256(raw).hexdigest()
    write_fixture_text(PATH, json.dumps(fixture, indent=2) + '\n')
    print(f'{len(cases)} verify cases; {len(probe["cases"])} status cases')


if __name__ == '__main__':
    main()
