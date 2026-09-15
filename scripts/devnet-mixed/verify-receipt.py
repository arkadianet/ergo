#!/usr/bin/env python3
"""Audit the recorded 100-block campaign and its committed source inputs offline."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'scripts/devnet-mixed'


def main():
    receipt = json.loads((HERE / 'smoke-evidence.json').read_text())
    environment = json.loads((HERE / 'smoke-environment.json').read_text())
    assert receipt['status'] == 'PASS'
    assert [receipt[k] for k in ('selected', 'executed', 'skipped', 'failed')] == [100, 100, 0, 0]
    assert receipt['mined'] == {'rust': 50, 'scala': 50}
    assert len(receipt['blocks']) == 100
    for height, block in enumerate(receipt['blocks'], 1):
        assert block['height'] == height
        assert block['miner'] == ('rust' if height % 2 else 'scala')
        assert block['header_version'] == 4
        assert set(block['observations']) == {'rust', 'scala'}
        assert block['observations']['rust'] == block['observations']['scala']
        assert block['observations']['rust'] == {k: block[k] for k in ('height', 'block_id', 'state_root')}
    for node in ('rust', 'scala'):
        final = receipt['final'][node]
        assert receipt['blocks'][-1]['observations'][node] == {
            'height': final['fullHeight'], 'block_id': final['bestFullHeaderId'],
            'state_root': final['stateRoot']}
    rust = receipt['rust']
    assert rust['git_status_porcelain'] == rust['git_status_porcelain_after'] == ''
    assert rust['git_sha'] == rust['git_sha_after']
    provenance = environment['source_provenance']
    assert provenance['git_sha'] == rust['git_sha']
    assert provenance['git_status_porcelain'] == ''
    assert provenance['binary_sha256'] == rust['binary_sha256']
    hashes = dict(rust['source_sha256'])
    hashes.update({'scripts/devnet-mixed/' + name: digest for name, digest in receipt['sha256'].items()})
    for path, digest in hashes.items():
        committed = subprocess.check_output(['git', 'show', rust['git_sha'] + ':' + path], cwd=ROOT)
        assert hashlib.sha256(committed).hexdigest() == digest, path
    evidence_path = 'scripts/devnet-mixed/smoke-evidence.json'
    assert hashlib.sha256((ROOT / evidence_path).read_bytes()).hexdigest() == environment['evidence_sha256'][evidence_path]
    assert environment['shutdown']['pid_files_absent']
    assert environment['shutdown']['closed_ports'] == [19530, 19531, 19553, 19554]
    print('PASS: 100 paired node observations, clean committed inputs, binary identity and receipt hash')


if __name__ == '__main__':
    main()
