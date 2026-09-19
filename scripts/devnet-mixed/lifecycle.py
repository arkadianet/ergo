#!/usr/bin/env python3
"""Start/stop only this worktree's private nodes, preserving their data."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'scripts/devnet-mixed'
WORK = HERE / '.work'


def owned(pid, configs=None):
    """A process this recipe started: running from this checkout, against one of
    the config paths we launched. `configs` carries the resolved paths recorded
    with the PID, so a node started with a custom SCALA_CONFIG / RUST_CONFIG is
    still matched — otherwise stop() would drop its PID file and leave it
    running, and the next campaign would fail to bind its ports."""
    proc = Path('/proc') / str(pid)
    known = tuple(configs) if configs else (
        'devnet-mixed/scala-node.conf', 'devnet-mixed/rust-node.toml',
        'devnet-mixed/.work/campaign-scala-node.conf',
        'devnet-mixed/.work/campaign-rust-node.toml')
    try:
        cmd = (proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode()
        return proc.joinpath('cwd').resolve() == ROOT and any(s in cmd for s in known)
    except FileNotFoundError:
        return False


def stop():
    for name in ('rust', 'scala'):
        path = WORK / (name + '.pid')
        if not path.exists():
            continue
        pid = int(path.read_text())
        config_path = WORK / (name + '.config')
        configs = [config_path.read_text().strip()] if config_path.exists() else None
        if owned(pid, configs):
            os.kill(pid, signal.SIGTERM)
            deadline = time.monotonic() + 30
            while owned(pid, configs) and time.monotonic() < deadline:
                time.sleep(0.2)
            if owned(pid, configs):
                raise RuntimeError(f'{name} did not stop; PID {pid} retained')
        path.unlink()
        config_path.unlink(missing_ok=True)



def _workspace_node_binary() -> str:
    """Path to the built `ergo-node` in this checkout's cargo target directory."""
    metadata = subprocess.run(
        ['cargo', 'metadata', '--no-deps', '--format-version', '1'],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    target = json.loads(metadata.stdout)['target_directory']
    candidate = Path(target) / 'debug' / 'ergo-node'
    if not candidate.exists():
        raise SystemExit(
            f'ergo-node not built at {candidate}; run `cargo build -p ergo-node` '
            'or set RUST_NODE to the binary path'
        )
    return str(candidate)

def start():
    for port in (19530, 19531, 19553, 19554):
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('127.0.0.1', port))
    WORK.mkdir(exist_ok=True)
    (WORK / 'scala').mkdir(exist_ok=True)
    cp = (ROOT / 'scripts/jvm_block_oracle/.work/classpath').read_text().strip()
    if os.environ.get('CAMPAIGN_CLASSPATH'):
        cp = os.environ['CAMPAIGN_CLASSPATH'] + ':' + cp
    scala_config = os.environ.get('SCALA_CONFIG', str(HERE / 'scala-node.conf'))
    rust_config = os.environ.get('RUST_CONFIG', str(HERE / 'rust-node.toml'))
    # No host-specific default: resolve the workspace target dir, else require
    # RUST_NODE explicitly.
    binary = os.environ.get('RUST_NODE') or _workspace_node_binary()
    commands = {
        'scala': ['java', '-Xmx2g', '-Dlogback.configurationFile=' + str(HERE / 'logback.xml'),
                  '-cp', cp, 'org.ergoplatform.ErgoApp', '--config', scala_config],
        'rust': [binary, '--config', rust_config],
    }
    try:
        for name, command in commands.items():
            with (WORK / (name + '.log')).open('a') as log:
                process = subprocess.Popen(command, cwd=ROOT, stdout=log,
                                           stderr=subprocess.STDOUT, start_new_session=True)
            # Record the resolved config with the PID so stop() can recognise a
            # node launched from a custom SCALA_CONFIG / RUST_CONFIG path.
            (WORK / (name + '.pid')).write_text(str(process.pid))
            (WORK / (name + '.config')).write_text(
                {'scala': scala_config, 'rust': rust_config}[name])
            port = {'scala': 19553, 'rust': 19554}[name]
            deadline = time.monotonic() + 60
            while True:
                try:
                    with urllib.request.urlopen(f'http://127.0.0.1:{port}/info', timeout=2) as response:
                        info = json.load(response)
                    if info.get('stateRoot') is None:
                        raise ValueError('node state is not initialized yet')
                    if name == 'scala' and info['appVersion'] != '6.0.5':
                        raise RuntimeError('Scala must be version 6.0.5')
                    break
                except (OSError, ValueError):
                    if time.monotonic() > deadline:
                        raise RuntimeError(f'{name} did not become ready; see .work/{name}.log')
                    time.sleep(0.5)
        deadline = time.monotonic() + 180
        while True:
            connected = []
            for port in (19553, 19554):
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/peers/connected', timeout=2) as response:
                    connected.append(len(json.load(response)) >= 1)
            if all(connected):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('both nodes must complete the P2P handshake before mining')
            time.sleep(0.25)
    except BaseException:
        stop()
        raise


if __name__ == '__main__':
    os.chdir(ROOT)
    {'start': start, 'stop': stop}[sys.argv[1]]()
