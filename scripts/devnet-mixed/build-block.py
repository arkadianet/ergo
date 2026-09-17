#!/usr/bin/env python3
"""Mine a difficulty-one synthetic block using Ergo's JVM AVL and PoW code."""
import argparse
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('request', type=Path, help='JSON parent state and signed transactions')
    parser.add_argument('output', type=Path, help='output fixture, including canonical block section bytes')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    return subprocess.call([sys.executable, str(root / 'scripts/jvm_block_oracle/run.py'),
                            'build', str(args.request.resolve()), str(args.output.resolve())], cwd=root)


if __name__ == '__main__':
    sys.exit(main())
