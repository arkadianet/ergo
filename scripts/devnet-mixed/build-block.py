#!/usr/bin/env python3
"""Mine a difficulty-one synthetic block using Ergo's JVM AVL and PoW code."""
import argparse
import json
import os
import urllib.request
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('request', type=Path, nargs='?', help='JSON parent state and signed transactions')
    parser.add_argument('output', type=Path, help='output fixture, including canonical block section bytes')
    parser.add_argument('--live', action='store_true', help='replay the private Scala devnet tip; request is a signed transaction JSON array (default: emission)')
    parser.add_argument('--count', type=int, default=1, help='number of consecutive emission blocks')
    parser.add_argument('--campaign-stage', choices=('fund', 'sum-at-cap', 'sum-over-cap', 'single-at-cap', 'workload'))
    parser.add_argument('--funding', type=Path, help='funding transaction JSON')
    parser.add_argument('--workload-trees', type=Path, help='array of serialized spendable ErgoTrees')
    parser.add_argument('--workload-index', type=int, default=0)
    parser.add_argument('--allow-cost-rejection', action='store_true')
    args = parser.parse_args()
    if args.count < 1 or (args.count != 1 and args.campaign_stage):
        parser.error('count must be positive; campaign stages build exactly one block')
    root = Path(__file__).resolve().parents[2]
    if args.live:
        here = root / 'scripts/devnet-mixed'
        work = here / '.work'
        work.mkdir(exist_ok=True)
        def get(path):
            with urllib.request.urlopen('http://127.0.0.1:19553' + path, timeout=30) as response:
                return json.load(response)
        info = get('/info')
        parents = []
        block_id = info['bestFullHeaderId']
        for height in range(info['fullHeight'] or 0, 0, -1):
            block = get('/blocks/' + block_id)
            if block['header']['height'] != height or block['header']['id'] != block_id:
                raise RuntimeError('inconsistent accepted parent chain')
            parents.append(block)
            block_id = block['header']['parentId']
        parents.reverse()
        transactions = json.loads(args.request.read_text()) if args.request else []
        request = work / 'build-request.json'
        payload = {'parents': parents, 'transactions': transactions, 'count': args.count,
                   'allow_cost_rejection': args.allow_cost_rejection}
        if args.campaign_stage:
            payload['campaign_stage'] = args.campaign_stage
            payload['workload_index'] = args.workload_index
        if args.funding:
            payload['funding'] = json.loads(args.funding.read_text())
        if args.workload_trees:
            payload['workload_trees'] = json.loads(args.workload_trees.read_text())
        request.write_text(json.dumps(payload))
        cp = (root / 'scripts/jvm_block_oracle/.work/classpath').read_text().strip()
        sources = [str(here / 'BuildBlock.scala'), str(here / 'CampaignTransactions.scala')]
        if os.environ.get('CAMPAIGN_CLASSPATH'):
            cp = os.environ['CAMPAIGN_CLASSPATH'] + ':' + cp
            classes = work / 'builder-classes'
            subprocess.run(['scala-cli', 'compile', *sources, '--server=false',
                '--suppress-outdated-dependency-warning', '--scala', '2.12.20', '--classpath', cp,
                '-d', str(classes)], check=True, cwd=root)
            command = ['java', '-Xmx2g', '-Dlogback.configurationFile=' + str(here / 'logback.xml'),
                       '-cp', str(classes) + ':' + cp, 'BuildBlock']
        else:
            command = ['scala-cli', 'run', *sources, '--server=false',
                '--suppress-outdated-dependency-warning', '--scala', '2.12.20', '--classpath', cp,
                '--java-opt', '-Dlogback.configurationFile=' + str(here / 'logback.xml'),
                '--main-class', 'BuildBlock', '--']
        subprocess.run(command + [str(request), str(args.output.resolve())], check=True, cwd=root)
        if get('/info')['bestFullHeaderId'] != info['bestFullHeaderId']:
            raise RuntimeError('tip changed while building; rebuild before submission')
        return 0
    if args.request is None:
        parser.error('synthetic fixture mode requires request and output')
    return subprocess.call([sys.executable, str(root / 'scripts/jvm_block_oracle/run.py'),
                            'build', str(args.request.resolve()), str(args.output.resolve())], cwd=root)


if __name__ == '__main__':
    sys.exit(main())
