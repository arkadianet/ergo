#!/usr/bin/env python3
"""Use the provisioned, pinned node classpath without changing production code."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
classpath = root / 'scripts/jvm_block_oracle/.work/classpath'
command = ['scala-cli', 'run', str(Path(__file__).with_name('CheckpointOracle.scala')),
           '--server=false', '--suppress-outdated-dependency-warning', '--scala', '2.12.20',
           '--classpath', classpath.read_text().strip(), '--java-opt',
           '-Dlogback.configurationFile=' + str(root / 'scripts/jvm_block_oracle/logback.xml'),
           '--main-class', 'CheckpointOracle', '--', *sys.argv[1:]]
sys.exit(subprocess.call(command, cwd=root))
