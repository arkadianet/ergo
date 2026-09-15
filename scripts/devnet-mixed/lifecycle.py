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


def owned(pid):
    proc = Path('/proc') / str(pid)
    try:
        cmd = (proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode()
        return proc.joinpath('cwd').resolve() == ROOT and any(
            s in cmd for s in ('devnet-mixed/scala-node.conf', 'devnet-mixed/rust-node.toml'))
    except FileNotFoundError:
        return False


def stop():
    for name in ('rust', 'scala'):
        path = WORK / (name + '.pid')
        if not path.exists():
            continue
        pid = int(path.read_text())
        if owned(pid):
            os.kill(pid, signal.SIGTERM)
            deadline = time.monotonic() + 30
            while owned(pid) and time.monotonic() < deadline:
                time.sleep(0.2)
            if owned(pid):
                raise RuntimeError(f'{name} did not stop; PID {pid} retained')
        path.unlink()


def start():
    for port in (19530, 19531, 19553, 19554):
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('127.0.0.1', port))
    WORK.mkdir(exist_ok=True)
    (WORK / 'scala').mkdir(exist_ok=True)
    cp = (ROOT / 'scripts/jvm_block_oracle/.work/classpath').read_text().strip()
    binary = os.environ.get('RUST_NODE', '/home/rkadias/.cache/cargo-target/debug/ergo-node')
    commands = {
        'scala': ['java', '-Xmx2g', '-Dlogback.configurationFile=' + str(HERE / 'logback.xml'),
                  '-cp', cp, 'org.ergoplatform.ErgoApp', '--config', str(HERE / 'scala-node.conf')],
        'rust': [binary, '--config', str(HERE / 'rust-node.toml')],
    }
    try:
        for name, command in commands.items():
            with (WORK / (name + '.log')).open('a') as log:
                process = subprocess.Popen(command, cwd=ROOT, stdout=log,
                                           stderr=subprocess.STDOUT, start_new_session=True)
            (WORK / (name + '.pid')).write_text(str(process.pid))
        for name, port in (('scala', 19553), ('rust', 19554)):
            deadline = time.monotonic() + 60
            while True:
                try:
                    with urllib.request.urlopen(f'http://127.0.0.1:{port}/info', timeout=2) as response:
                        info = json.load(response)
                    if name == 'scala' and info['appVersion'] != '6.0.5':
                        raise RuntimeError('Scala must be version 6.0.5')
                    break
                except (OSError, ValueError):
                    if time.monotonic() > deadline:
                        raise RuntimeError(f'{name} did not become ready; see .work/{name}.log')
                    time.sleep(0.5)
    except BaseException:
        stop()
        raise


if __name__ == '__main__':
    os.chdir(ROOT)
    {'start': start, 'stop': stop}[sys.argv[1]]()
