#!/usr/bin/env python3
"""Mine a difficulty-one synthetic block using Ergo's JVM AVL and PoW code."""
import argparse
import json
import urllib.request
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('request', type=Path, nargs='?', help='JSON parent state and signed transactions')
    parser.add_argument('output', type=Path, help='output fixture, including canonical block section bytes')
    parser.add_argument('--live', action='store_true', help='replay the private Scala devnet tip; request is a signed transaction JSON array (default: emission)')
    args = parser.parse_args()
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
        for height in range(1, (info['fullHeight'] or 0) + 1):
            ids = get('/blocks/at/' + str(height))
            if len(ids) != 1:
                raise RuntimeError('live builder requires an unforked private devnet')
            parents.append(get('/blocks/' + ids[0]))
        transactions = json.loads(args.request.read_text()) if args.request else []
        request = work / 'build-request.json'
        request.write_text(json.dumps({'parents': parents, 'transactions': transactions}))
        cp = (root / 'scripts/jvm_block_oracle/.work/classpath').read_text().strip()
        subprocess.run(['scala-cli', 'run', str(here / 'BuildBlock.scala'), '--server=false',
            '--suppress-outdated-dependency-warning', '--scala', '2.12.20', '--classpath', cp,
            '--java-opt', '-Dlogback.configurationFile=' + str(here / 'logback.xml'),
            '--main-class', 'BuildBlock', '--', str(request), str(args.output.resolve())],
            check=True, cwd=root)
        if get('/info')['bestFullHeaderId'] != info['bestFullHeaderId']:
            raise RuntimeError('tip changed while building; rebuild before submission')
        return 0
    if args.request is None:
        parser.error('synthetic fixture mode requires request and output')
    return subprocess.call([sys.executable, str(root / 'scripts/jvm_block_oracle/run.py'),
                            'build', str(args.request.resolve()), str(args.output.resolve())], cwd=root)


if __name__ == '__main__':
    sys.exit(main())
