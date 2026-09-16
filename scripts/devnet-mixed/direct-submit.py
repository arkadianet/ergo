#!/usr/bin/env python3
"""Build on the private devnet tip and submit one full block to each node."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from smoke import ROOT, HERE, WORK, URLS, api, tips, wait_for


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    output = HERE / 'direct-submit-evidence.json'
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    info = api('scala', '/info')
    height = info['fullHeight'] or 0
    wait_for(lambda: tips(height), 'matching starting tips')
    manifest = {
        'status': 'RUNNING', 'selected': 2, 'executed': 0, 'skipped': 0, 'failed': 0,
        'scala': {'ergo_version': '6.0.5', 'sigmastate_version': '6.0.6',
                  'node_app_version': info['appVersion'],
                  'source_shas': {'ergo': '5528ef569a41ebccbc8658212e6ee3c97d990b96',
                                 'sigmastate': 'ab0b15ceb9d34f2ccd6e68e3e2a8aa27cd16a042'}},
        'rust': {'git_sha': revision, 'features': 'default',
                 'toolchain': subprocess.check_output(['rustc', '--version'], text=True).strip(),
                 'binary_sha256': sha(Path('/proc') / (WORK/'rust.pid').read_text().strip() / 'exe'),
                 'working_diff_sha256': hashlib.sha256(subprocess.check_output(['git', 'diff', 'HEAD'], cwd=ROOT)).hexdigest()},
        'tool': {'script': 'scripts/devnet-mixed/direct-submit.py', 'git_sha': revision,
                 'scala_cli_version': subprocess.check_output(['scala-cli', 'version', '--cli'], text=True).strip(),
                 'jvm': subprocess.run(['java', '-version'], capture_output=True, text=True).stderr.strip()},
        'context': {'network': 'private devnet / Scala devnet60', 'height_range': [height + 1, height + 2],
                    'chain_id': 'cb63aa99a3060f341781d8662b58bf18b9ad258db4fe88d09f8f71cb668cad4502',
                    'activated_script_version': info['parameters']['blockVersion'] - 1,
                    'block_version': info['parameters']['blockVersion'], 'voted_params': info['parameters']},
        'run': {'command': 'python3 scripts/devnet-mixed/direct-submit.py', 'seeds': None,
                'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()},
        'evidence': {str(p.relative_to(ROOT)): sha(p) for p in
                     (HERE/'BuildBlock.scala', HERE/'build-block.py', HERE/'direct-submit.py',
                      HERE/'rust-node.toml', HERE/'scala-node.conf', HERE/'genesis.conf')},
        'blocks': [],
    }
    try:
        for node in ('rust', 'scala'):
            height += 1
            block_path = WORK / f'direct-{node}.json'
            with (WORK / f'direct-{node}-build.log').open('w') as log:
                subprocess.run([sys.executable, str(HERE/'build-block.py'), '--live', str(block_path)],
                               check=True, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
            block = json.loads(block_path.read_text())
            assert block['header']['height'] == height
            before = {n: api(n, '/info')['bestFullHeaderId'] for n in URLS}
            response = api(node, '/blocks', block)
            infos = wait_for(lambda: tips(height), f'both nodes validate direct {node} block {height}')
            assert all(i['bestFullHeaderId'] == block['header']['id'] for i in infos.values())
            manifest['blocks'].append({'recipient': node, 'height': height, 'http_status': 200,
                'response': response, 'block_id': block['header']['id'], 'before': before,
                'block_sha256': sha(block_path), 'request_sha256': sha(WORK/'build-request.json'),
                'observations': {n: {'height': i['fullHeight'], 'block_id': i['bestFullHeaderId'],
                                    'state_root': i['stateRoot']} for n, i in infos.items()}})
            manifest['executed'] += 1
            print(f'{node}: POST /blocks 200, both nodes at {height} {block["header"]["id"]}', flush=True)
        manifest['status'] = 'PASS'
    except BaseException as error:
        manifest['status'] = 'FAIL'
        manifest['failed'] = 1
        manifest['error'] = str(error)
        raise
    finally:
        payload = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
        manifest['payload_sha256_excluding_this_field'] = hashlib.sha256(payload).hexdigest()
        output.write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    main()
