#!/usr/bin/env python3
"""Expand METHOD failure probes over every observable budget up to JVM C + 1.

Run both method generators and scripts/gen-cost-fixture.sh on failure-*.json.gz
first. Then run this script and regenerate those files through the JVM again.
Only the JVM supplies C and expected records; this script only builds requests.
"""
import copy
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'scripts'))
from cost_fixture_io import fixture_paths, read_fixture_text, write_fixture_text

ROOT = Path(__file__).resolve().parents[3]


def main():
    for path in sorted(fixture_paths(ROOT / 'test-vectors/ergo-sigma/cost-ledger/fixtures/method', 'failure-*')):
        fixture = json.loads(read_fixture_text(path))
        originals = [case for case in fixture['cases'] if '-limit' not in case['name']]
        previous = {case['name']: case for case in fixture['cases']}
        expanded = []
        for case in originals:
            expected = case['expected']
            cost = expected['eval_block_cost'] if expected['verdict'] == 'Accept' else expected['evaluator_failure_block_cost']
            if not isinstance(cost, int):
                raise ValueError(f"{path}: {case['name']} has no JVM-observed cost")
            for limit in range(cost + 2):
                probe = copy.deepcopy(case)
                probe['name'] += f'-limit{limit}'
                probe['request']['cost_limit_block'] = limit
                probe['construction']['limit_from_jvm_block_cost'] = cost
                probe.pop('expected')
                old = previous.get(probe['name'])
                if old and old['request'] == probe['request'] and 'expected' in old:
                    probe['expected'] = old['expected']
                expanded.append(probe)
        fixture['cases'] = originals + expanded
        write_fixture_text(path, json.dumps(fixture, indent=2) + '\n')
        print(f'{path.name}: {len(originals)} high-limit probes, {len(expanded)} budgets')


if __name__ == '__main__':
    main()
