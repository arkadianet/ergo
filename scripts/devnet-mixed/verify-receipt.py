#!/usr/bin/env python3
"""Audit the recorded 100-block campaign and its committed source inputs offline."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'scripts/devnet-mixed'



def require(condition, message):
    """`assert` is removed under `python -O` / PYTHONOPTIMIZE, which would let
    this auditor print PASS for invalid evidence. Raise explicitly instead."""
    if not condition:
        raise SystemExit(f'receipt verification failed: {message}')

def main():
    receipt = json.loads((HERE / 'smoke-evidence.json').read_text())
    environment = json.loads((HERE / 'smoke-environment.json').read_text())
    require(
        receipt['status'] == 'PASS',
        'receipt[status]',
    )
    require(
        [receipt[k] for k in ('selected', 'executed', 'skipped', 'failed')] == [100, 100, 0, 0],
        '[receipt[k] for k in (selected, executed, skipped, failed)]',
    )
    require(
        receipt['mined'] == {'rust': 50, 'scala': 50},
        'receipt[mined]',
    )
    require(
        len(receipt['blocks']) == 100,
        'len(receipt[blocks])',
    )
    for height, block in enumerate(receipt['blocks'], 1):
        require(
            block['height'] == height,
            'block[height]',
        )
        require(
            block['miner'] == ('rust' if height % 2 else 'scala'),
            'block[miner]',
        )
        require(
            block['header_version'] == 4,
            'block[header_version]',
        )
        require(
            set(block['observations']) == {'rust', 'scala'},
            'set(block[observations])',
        )
        require(
            block['observations']['rust'] == block['observations']['scala'],
            'block[observations][rust]',
        )
        require(
            block['observations']['rust'] == {k: block[k] for k in ('height', 'block_id', 'state_root')},
            'block[observations][rust]',
        )
    for node in ('rust', 'scala'):
        final = receipt['final'][node]
        require(
            receipt['blocks'][-1]['observations'][node] == {
            'height': final['fullHeight'], 'block_id': final['bestFullHeaderId'],
            'state_root': final['stateRoot']},
            'receipt[blocks][-1][observations][node]',
        )
    rust = receipt['rust']
    require(
        rust['git_status_porcelain'] == rust['git_status_porcelain_after'] == '',
        'rust[git_status_porcelain]',
    )
    require(
        rust['git_sha'] == rust['git_sha_after'],
        'rust[git_sha]',
    )
    provenance = environment['source_provenance']
    require(
        provenance['git_sha'] == rust['git_sha'],
        'provenance[git_sha]',
    )
    require(
        provenance['git_status_porcelain'] == '',
        'provenance[git_status_porcelain]',
    )
    require(
        provenance['binary_sha256'] == rust['binary_sha256'],
        'provenance[binary_sha256]',
    )
    hashes = dict(rust['source_sha256'])
    hashes.update({'scripts/devnet-mixed/' + name: digest for name, digest in receipt['sha256'].items()})
    for path, digest in hashes.items():
        committed = subprocess.check_output(['git', 'show', rust['git_sha'] + ':' + path], cwd=ROOT)
        require(
            hashlib.sha256(committed).hexdigest() == digest,
            'hashlib.sha256(committed).hexdigest()',
        )
    evidence_path = 'scripts/devnet-mixed/smoke-evidence.json'
    require(
        hashlib.sha256((ROOT / evidence_path).read_bytes()).hexdigest() == environment['evidence_sha256'][evidence_path],
        'hashlib.sha256((ROOT / evidence_path).read_bytes()).hexdigest()',
    )
    require(
        environment['shutdown']['pid_files_absent'],
        'environment[shutdown][pid_files_absent]',
    )
    require(
        environment['shutdown']['closed_ports'] == [19530, 19531, 19553, 19554],
        'environment[shutdown][closed_ports]',
    )
    print('PASS: 100 paired node observations, clean committed inputs, binary identity and receipt hash')


if __name__ == '__main__':
    main()
