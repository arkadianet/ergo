#!/usr/bin/env python3
"""Start/stop only this recipe's private Matrix devnet nodes.

A Scala `weak-blocks` node mines both ordering and input blocks with its
internal CPU miner; the Rust node only follows. Ports are private to this
recipe (Scala 19560/19580, Rust 19561/19581) and never overlap the
`devnet-mixed` recipe or any long-running node on this host.
"""
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
HERE = ROOT / 'scripts/devnet-matrix'
WORK = HERE / '.work'

P2P = {'scala': 19560, 'rust': 19561}
REST = {'scala': 19580, 'rust': 19581}

# The weak-blocks branch builds without a git tag, so `/info.appVersion`
# is a branch-and-hash SNAPSHOT string rather than a release number.
# Pinning the literal would break on every rebuild, so the readiness
# check pins the two properties that actually matter: the build is NOT a
# stock release (which has no input blocks at all), and its `/info`
# carries the `bestInputBlock` key that only `ErgoStatsCollector` on the
# weak-blocks branch emits.
STOCK_VERSIONS = ('6.0.5', '6.0.4', '6.0.3')


def classpath_file() -> Path:
    """Classpath of the Scala `weak-blocks` build.

    Overridable because the provisioned build may live in a sibling
    worktree; the default is this checkout's own oracle work dir.
    """
    return Path(os.environ.get(
        'MATRIX_CLASSPATH', str(ROOT / 'scripts/jvm_weak_blocks_oracle/.work/classpath')))


def owned(pid, configs=None):
    """A process this recipe started: running from this checkout, against one of
    the config paths we launched. Only PIDs recorded in `.work/*.pid` are ever
    considered, and only those still matching are signalled — nothing is ever
    matched by process-name pattern."""
    proc = Path('/proc') / str(pid)
    known = tuple(configs) if configs else (
        'devnet-matrix/scala-node.conf', 'devnet-matrix/rust-node.toml')
    try:
        cmd = (proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode()
        return proc.joinpath('cwd').resolve() == ROOT and any(s in cmd for s in known)
    except FileNotFoundError:
        return False


def stop(names=('rust', 'scala')):
    for name in names:
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


def _command(name):
    cp = classpath_file()
    if not cp.exists():
        raise SystemExit(
            f'Scala weak-blocks classpath not found at {cp}; set MATRIX_CLASSPATH')
    if name == 'scala':
        return ['java', '-Xmx2g', '-Dlogback.configurationFile=' + str(HERE / 'logback.xml'),
                '-cp', cp.read_text().strip(), 'org.ergoplatform.ErgoApp',
                '--config', os.environ.get('SCALA_CONFIG', str(HERE / 'scala-node.conf'))]
    binary = os.environ.get('RUST_NODE') or _workspace_node_binary()
    return [binary, '--config', os.environ.get('RUST_CONFIG', str(HERE / 'rust-node.toml'))]


def _config_path(name):
    return os.environ.get({'scala': 'SCALA_CONFIG', 'rust': 'RUST_CONFIG'}[name]) or str(
        HERE / {'scala': 'scala-node.conf', 'rust': 'rust-node.toml'}[name])


def spawn(name):
    """Launch one node and wait for its REST `/info` to report a live state."""
    WORK.mkdir(exist_ok=True)
    (WORK / name).mkdir(exist_ok=True)
    with (WORK / (name + '.log')).open('a') as log:
        process = subprocess.Popen(_command(name), cwd=ROOT, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
    (WORK / (name + '.pid')).write_text(str(process.pid))
    (WORK / (name + '.config')).write_text(_config_path(name))
    deadline = time.monotonic() + 120
    while True:
        try:
            with urllib.request.urlopen(
                    f'http://127.0.0.1:{REST[name]}/info', timeout=2) as response:
                info = json.load(response)
            if info.get('stateRoot') is None:
                raise ValueError('node state is not initialized yet')
            if name == 'scala':
                version = info.get('appVersion')
                if version in STOCK_VERSIONS or 'bestInputBlock' not in info:
                    raise RuntimeError(
                        f'Scala node at {REST[name]} is not a weak-blocks build '
                        f'(appVersion={version!r}, bestInputBlock key '
                        f'{"present" if "bestInputBlock" in info else "absent"}); '
                        'point MATRIX_CLASSPATH at the weak-blocks classpath')
            (WORK / (name + '.appVersion')).write_text(str(info.get('appVersion')))
            return info
        except (OSError, ValueError):
            if time.monotonic() > deadline:
                raise RuntimeError(f'{name} did not become ready; see .work/{name}.log')
            time.sleep(0.5)


WALLET_PASS = 'matrix-devnet'
API_KEY = 'hello'


def _scala_post(path, body):
    request = urllib.request.Request(
        f'http://127.0.0.1:{REST["scala"]}' + path, data=json.dumps(body).encode(),
        headers={'api_key': API_KEY, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = response.read()
        return json.loads(payload) if payload else None


def init_wallet():
    """Initialize and unlock the Scala wallet.

    The internal miner refuses to build candidates without it ("Miner
    can't load secret key from wallet: Wallet is locked"), so the whole
    recipe is inert until this runs. The mnemonic is recorded under
    `.work/` so a re-start of the same data dir restores the same wallet.
    """
    mnemonic_file = WORK / 'scala-wallet.mnemonic'
    deadline = time.monotonic() + 120
    while True:
        try:
            with urllib.request.urlopen(
                    urllib.request.Request(f'http://127.0.0.1:{REST["scala"]}/wallet/status',
                                           headers={'api_key': API_KEY}), timeout=5) as response:
                status = json.load(response)
            if status.get('isUnlocked'):
                return status
            if status.get('isInitialized'):
                _scala_post('/wallet/unlock', {'pass': WALLET_PASS})
            elif mnemonic_file.exists():
                _scala_post('/wallet/restore', {
                    'pass': WALLET_PASS, 'mnemonic': mnemonic_file.read_text().strip(),
                    'usePre1627KeyDerivation': False})
            else:
                result = _scala_post('/wallet/init', {'pass': WALLET_PASS})
                mnemonic_file.write_text(result['mnemonic'])
        except (OSError, ValueError, KeyError):
            pass
        if time.monotonic() > deadline:
            raise RuntimeError('Scala wallet did not unlock; the internal miner cannot mine')
        time.sleep(1)


def wait_peered(timeout=180):
    deadline = time.monotonic() + timeout
    while True:
        try:
            counts = {}
            for name, port in REST.items():
                with urllib.request.urlopen(
                        f'http://127.0.0.1:{port}/peers/connected', timeout=2) as response:
                    counts[name] = len(json.load(response))
            if all(count >= 1 for count in counts.values()):
                return counts
        except (OSError, ValueError):
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError('both nodes must complete the P2P handshake')
        time.sleep(0.25)


def start():
    for port in sorted({*P2P.values(), *REST.values()}):
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('127.0.0.1', port))
    try:
        # Order matters. The Scala node mines with `offlineGeneration`,
        # so it would run away from a follower that has not joined yet —
        # but it cannot build a candidate until its wallet is unlocked.
        # Unlocking LAST is therefore the start gun: both nodes are up
        # and peered before the first block exists.
        spawn('scala')
        spawn('rust')
        wait_peered()
        init_wallet()
    except BaseException:
        stop()
        raise


if __name__ == '__main__':
    os.chdir(ROOT)
    {'start': start, 'stop': stop}[sys.argv[1]]()
