#!/usr/bin/env python3
"""Run the oracle against the isolated, provisioned node classpath."""
from pathlib import Path
import os
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def main():
    classpath = HERE / '.work/classpath'
    if not classpath.exists():
        raise SystemExit('Run python3 scripts/jvm_block_oracle/provision.py first')
    command = ['scala-cli', 'run', str(HERE / 'BlockOracle.scala'), '--server=false',
               '--suppress-outdated-dependency-warning', '--scala', '2.12.20', '--classpath', classpath.read_text().strip(),
               '--java-opt', '-Dlogback.configurationFile=' + str(HERE / 'logback.xml'),
               '--main-class', 'BlockOracle', '--', *sys.argv[1:]]
    return subprocess.call(command, cwd=ROOT, env=os.environ.copy())


if __name__ == '__main__':
    sys.exit(main())
