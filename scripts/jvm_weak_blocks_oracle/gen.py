#!/usr/bin/env python3
"""Regenerate test-vectors/weak-blocks/*.json from the pinned Scala oracle."""
import datetime
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
OUT = ROOT / 'test-vectors/weak-blocks'
VECTORS = ['announcement', 'ordering_announcement', 'messages', 'weak_ids', 'pow', 'extension_proof', 'soft_fields', 'input_block_validation']


def main():
    names = sys.argv[1:] or VECTORS
    manifest = json.loads((HERE / '.work/manifest.json').read_text())
    oracle = HERE / 'WeakBlocksOracle.scala'
    OUT.mkdir(parents=True, exist_ok=True)
    for name in names:
        classpath_file = '.work/test-classpath' if name == 'input_block_validation' else '.work/classpath'
        classpath = (HERE / classpath_file).read_text().strip()
        result = subprocess.run(['scala-cli', '--skip-cli-updates', 'run', str(oracle), '--server=false',
                                 '--scala', '2.12.20', '--classpath', classpath, '--', name],
                                text=True, stdout=subprocess.PIPE, check=True).stdout
        # logback initialization banner (and scala-cli's outdated-version nag) land on
        # stdout ahead of the JSON payload, and can themselves contain '{' (log pattern
        # strings), so anchor on the line that is exactly the JSON object's opening
        # brace rather than the first '{' anywhere in the output.
        lines = result.splitlines()
        json_start = next(i for i, line in enumerate(lines) if line.strip() == '{')
        doc = json.loads('\n'.join(lines[json_start:]))
        doc['manifest'] = {
            'ergo_commit': manifest['ergo_commit'], 'sigma_commit': manifest['sigma_commit'],
            'sigma_version': manifest['sigma_version'],
            'generator': 'scripts/jvm_weak_blocks_oracle/WeakBlocksOracle.scala',
            'generator_sha256': hashlib.sha256(oracle.read_bytes()).hexdigest(),
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        (OUT / f'{name}.json').write_text(json.dumps(doc, indent=2) + '\n')
        print(f'wrote {name}.json ({len(doc.get("cases", []))} cases)')


if __name__ == '__main__':
    main()
