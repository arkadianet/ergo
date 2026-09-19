#!/usr/bin/env python3
"""Mine 100 strictly alternating node candidates; wait for P2P validation each time."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'scripts/devnet-mixed'
WORK = HERE / '.work'
URLS = {'scala': 'http://127.0.0.1:19553', 'rust': 'http://127.0.0.1:19554'}
PK = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'


def api(node, path, data=None):
    request = urllib.request.Request(URLS[node] + path,
        data=None if data is None else json.dumps(data).encode(),
        headers={'api_key': 'hello', 'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=10) as response:
        payload = response.read()
        return json.loads(payload) if payload else None


def wait_for(callback, description, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = callback()
            if result:
                return result
        except (OSError, ValueError):
            pass
        time.sleep(0.25)
    raise RuntimeError('timeout: ' + description)


def tips(height):
    infos = {node: api(node, '/info') for node in URLS}
    if any((i['fullHeight'] or 0) != height for i in infos.values()):
        return None
    if any(i['stateRoot'] is None for i in infos.values()):
        return None
    if infos['scala']['stateRoot'] != infos['rust']['stateRoot']:
        raise RuntimeError('STATE ROOT DIVERGENCE: ' + json.dumps(infos))
    if height and infos['scala']['bestFullHeaderId'] != infos['rust']['bestFullHeaderId']:
        raise RuntimeError('BLOCK ID DIVERGENCE: ' + json.dumps(infos))
    return infos


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--first', choices=('rust', 'scala'), default='rust')
    parser.add_argument('--blocks', type=int, default=100)
    args = parser.parse_args()
    git_sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    git_status = subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True)
    if git_status:
        raise RuntimeError('smoke requires a clean committed tree: ' + git_status)
    rust_pid = (WORK / 'rust.pid').read_text().strip()
    binary = Path('/proc') / rust_pid / 'exe'
    binary_hash = hashlib.file_digest(binary.open('rb'), 'sha256').hexdigest()
    source_files = subprocess.check_output(['git', 'ls-files', '*.rs', 'Cargo.lock', 'Cargo.toml',
                                           '*/Cargo.toml', '.cargo/config.toml'], cwd=ROOT, text=True).splitlines()
    source_files += ['ergo-mining/src/genesis.rs']
    source_hashes = {f: hashlib.sha256((ROOT/f).read_bytes()).hexdigest() for f in sorted(set(source_files))}
    manifest = {
        'status': 'RUNNING', 'scala': {'ergo_version': '6.0.5', 'sigmastate_version': '6.0.6',
            'source_sha': '5528ef569a41ebccbc8658212e6ee3c97d990b96'},
        'rust': {'git_sha': git_sha, 'git_status_porcelain': git_status,
                 'toolchain': subprocess.check_output(['rustc', '--version'], text=True).strip(),
                 'features': 'default', 'binary_sha256': binary_hash, 'source_sha256': source_hashes},
        'command': f'python3 scripts/devnet-mixed/smoke.py --first {args.first} --blocks {args.blocks}',
        'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'context': {'network': 'private devnet / Scala devnet60', 'launch_block_version': 4,
                    'interpreter_release': '6.0', 'difficulty': 1, 'epoch_length': 33554432},
        'tool': {'path': 'scripts/devnet-mixed/smoke.py',
                 'git_sha': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                 'scala_cli_version': subprocess.check_output(['scala-cli', 'version', '--cli'], text=True).strip(),
                 'jvm': subprocess.run(['java', '-version'], capture_output=True, text=True).stderr.strip()},
        'selected': args.blocks, 'executed': 0, 'skipped': 0, 'failed': 0, 'blocks': [],
        'mined': {'rust': 0, 'scala': 0},
        'sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in
                   (HERE/'genesis.conf', HERE/'scala-node.conf', HERE/'rust-node.toml', HERE/'smoke.py',
                    HERE/'Solve.scala', HERE/'lifecycle.py', HERE/'logback.xml')},
    }
    output = WORK / 'smoke.json'
    try:
        manifest['genesis'] = wait_for(lambda: tips(0), 'both nodes at shared genesis')
        wait_for(lambda: all(api(n, '/peers/connected') for n in URLS), 'P2P handshake')
        order = [args.first, 'scala' if args.first == 'rust' else 'rust']
        for height in range(1, args.blocks + 1):
            node = order[(height - 1) % 2]
            def candidate_ready():
                c = api(node, '/mining/candidate')
                return c if c.get('h', 1) == height else None
            candidate = wait_for(candidate_ready, f'{node} candidate {height}')
            solution = {'pk': PK, 'w': PK, 'n': '0000000000000000', 'd': 0}
            if 'h' not in candidate:
                cp = (ROOT/'scripts/jvm_block_oracle/.work/classpath').read_text().strip()
                result = subprocess.run(['scala-cli', 'run', str(HERE/'Solve.scala'), '--server=false',
                    '--suppress-outdated-dependency-warning', '--scala', '2.12.20', '--classpath', cp,
                    '--java-opt', '-Dlogback.configurationFile='+str(HERE/'logback.xml'),
                    '--main-class', 'org.ergoplatform.mining.Solve'], input=json.dumps(candidate)+'\n',
                    text=True, capture_output=True, check=True, cwd=ROOT)
                solution = json.loads(next(l[9:] for l in result.stdout.splitlines() if l.startswith('SOLUTION ')))
            api(node, '/mining/solution', solution)
            info = wait_for(lambda: tips(height), f'both nodes validate {height}')
            manifest['blocks'].append({'height': height, 'miner': node,
                'block_id': info[node]['bestFullHeaderId'], 'state_root': info[node]['stateRoot'],
                'header_version': api(node, '/blocks/'+info[node]['bestFullHeaderId'])['header']['version'],
                'candidate': candidate, 'solution': solution,
                'observations': {n: {'height': i['fullHeight'],
                    'block_id': i['bestFullHeaderId'], 'state_root': i['stateRoot']}
                    for n, i in info.items()}})
            output.write_text(json.dumps(manifest, indent=2)+'\n')
            persisted = json.loads(output.read_text())['blocks'][-1]
            assert persisted['observations']['rust'] == persisted['observations']['scala']
            assert persisted['observations']['rust'] == {k: persisted[k]
                for k in ('height', 'block_id', 'state_root')}
            manifest['executed'] += 1
            manifest['mined'][node] += 1
            manifest['final'] = info
            output.write_text(json.dumps(manifest, indent=2)+'\n')
            print(f'{height}: {node} {info[node]["bestFullHeaderId"]}', flush=True)
        final_status = subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True)
        final_sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        manifest['rust']['git_status_porcelain_after'] = final_status
        manifest['rust']['git_sha_after'] = final_sha
        if final_status or final_sha != git_sha:
            raise RuntimeError('source tree changed during smoke')
        manifest['status'] = 'PASS'
    except BaseException as error:
        manifest['status'] = 'FAIL'
        manifest['failed'] = 1
        manifest['error'] = str(error)
        manifest['observed'] = {n: api(n, '/info') for n in URLS}
        raise
    finally:
        output.write_text(json.dumps(manifest, indent=2)+'\n')


if __name__ == '__main__':
    main()
