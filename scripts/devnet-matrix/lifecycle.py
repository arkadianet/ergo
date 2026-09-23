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

# The role table (which node does what, and on which build). A SEPARATE
# module because `campaign.py` has to resolve roles BEFORE it configures
# the ports this module reads from the environment AT IMPORT: asking
# `lifecycle` for the role table would drag that import forward, freeze
# the two-node smoke defaults, and every campaign scenario would
# silently run on the smoke's ports.
from roles import ROLES, Role, role_node, roles_for_nodes  # noqa: F401

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'scripts/devnet-matrix'
# Where this run keeps its pid files, logs, series and evidence.
# `MATRIX_WORK` moves ALL of it: a separate port band is not isolation,
# because two runs driving one checkout still share `<name>.pid` and
# `<name>.config` — the second `start` overwrites them and the first
# `stop` then kills the second run's nodes — and they append to one
# `scala.log` and one `agreement-series.jsonl`, which is the evidence
# each of them is measured from.
# Resolved ONCE, here: a relative value means the directory it was given
# in, and every later `relative_to(ROOT)` needs an absolute path.
WORK = Path(os.environ.get('MATRIX_WORK', HERE / '.work')).resolve()

# Which nodes this process drives, and on which ports. The smoke recipe
# keeps the two-node defaults it has always had (Scala 19560/19580, Rust
# 19561/19581); the M3 campaign sets `MATRIX_NODES=scala,scala2,rust`
# and the port variables below so it can run a three-node devnet
# CONCURRENTLY with a smoke run in another worktree, on 19570-19572 /
# 19590-19592. Nothing is hardcoded any more, and nothing about the
# default two-node set changed: an unset environment reproduces the
# previous dicts exactly.
#
# `scala3` (M4) is the patched reference FOLLOWER's slot: the ablation
# runs the stock and the patched follower side by side against one
# miner, so the two cannot share a node. It is opt-in like `scala2`.
DEFAULT_P2P = {'scala': 19560, 'rust': 19561, 'scala2': 19562,
               'scala3': 19563}
DEFAULT_REST = {'scala': 19580, 'rust': 19581, 'scala2': 19582,
                'scala3': 19583}

# P2P LISTEN ADDRESS per node, distinct from the port.
#
# Two Scala nodes on the SAME IP can never dial each other:
# `NetworkController.getPeerAddress` (scorex, line 495 at the pin) treats
# a candidate whose declared address shares this node's own external
# address as one reachable only through the UPnP gateway, and with no
# gateway it returns `None` — so no outbound connection is ever
# attempted. On loopback that is every peer, and scorex's
# `allowLocal = false` default refuses the rest. The campaign therefore
# moves its Scala FOLLOWERS to their own 127.x addresses with
# `allowLocal = true` (`campaign.CAMPAIGN_P2P_HOST`); the smoke keeps
# 127.0.0.1 everywhere, which is correct for it because it runs one Scala
# node and only the Rust node dials.
#
# REST is NOT moved: the harness talks to 127.0.0.1:<rest port> for every
# node, and nothing about these bindings changes that.
DEFAULT_P2P_HOST = {'scala': '127.0.0.1', 'rust': '127.0.0.1',
                    'scala2': '127.0.0.1', 'scala3': '127.0.0.1'}

# `scala2` is OPT-IN. Every consumer iterates these dicts — the sampler
# sweeps `REST`, `start()` binds `P2P` — so listing a node that is not
# running would turn every sweep into an unavailable sample.
NODES = tuple(name for name in os.environ.get('MATRIX_NODES', 'scala,rust').split(',')
              if name.strip())


def _ports(kind, defaults):
    return {name: int(os.environ.get(f'MATRIX_{kind}_{name.upper()}',
                                     defaults[name]))
            for name in NODES}


P2P = _ports('P2P', DEFAULT_P2P)
REST = _ports('REST', DEFAULT_REST)
P2P_HOST = {name: os.environ.get(f'MATRIX_P2P_HOST_{name.upper()}',
                                 DEFAULT_P2P_HOST[name])
            for name in NODES}

# Config path per node, so a campaign can point a node at a rendered
# copy without editing the committed recipe files.
CONFIG_ENV = {'scala': 'SCALA_CONFIG', 'scala2': 'SCALA2_CONFIG',
              'scala3': 'SCALA3_CONFIG', 'rust': 'RUST_CONFIG'}
# `scala3` shares the second Scala node's recipe file: it is the same
# kind of node (a second Scala peer on this host), and what makes it a
# FOLLOWER rather than a miner is the campaign's overlay, exactly as it
# is for `scala2` in `reconstruct_rate`.
DEFAULT_CONFIG = {'scala': 'scala-node.conf', 'scala2': 'scala-miner2.conf',
                  'scala3': 'scala-miner2.conf', 'rust': 'rust-node.toml'}

# Build selection per NODE, set by the campaign before `lifecycle` is
# asked for a classpath. Kept in the environment rather than in a module
# global because `--scenario all` re-execs one process per scenario.
BUILD_ENV = 'MATRIX_BUILD_%s'

# Verified builds, by build name. See `_build_for`.
_VERIFIED_BUILDS = {}


def node_build(node):
    """The build name a node was told to run (`stock` unless set)."""
    return os.environ.get(BUILD_ENV % node.upper(), 'stock')


# The weak-blocks branch builds without a git tag, so `/info.appVersion`
# is a branch-and-hash SNAPSHOT string. It is pinned EXACTLY: the hash in
# it is the provisioned ergo commit
# (62c10315e1ebcac4480dba6bacdc2100a38119e5, the M4 pin — see
# scripts/jvm_weak_blocks_oracle/README.md), and "some build that also
# has input blocks" is not a reference — every vector and every ruling in
# this port is against that one commit. A rebuild at a different commit
# must fail loudly here rather than silently reinterpret the results.
#
# This is the FALLBACK, for a run driven by `MATRIX_CLASSPATH` rather
# than the build registry. When a node runs a registered build, its own
# manifest states the version (`scala_app_version`), which is what lets a
# patched build run beside the stock one. Override only to re-pin
# deliberately.
SCALA_APP_VERSION = os.environ.get(
    'MATRIX_SCALA_APP_VERSION', '6.0.6-493-62c10315-SNAPSHOT')


def scala_app_version(node='scala'):
    """The `/info.appVersion` THIS node's build must report.

    Per node, because M4 runs two Scala builds at once: a patched
    follower beside a stock miner reports a different version string,
    and one global constant would either fail the patched node or stop
    checking the stock one. The build registry is the source; the
    environment overrides it for a deliberate re-pin.
    """
    override = os.environ.get(f'MATRIX_SCALA_APP_VERSION_{node.upper()}')
    if override:
        return override
    build = _build_for(node)
    return build.app_version() if build is not None else SCALA_APP_VERSION


# Height-0 state root both nodes must report. `minerRewardDelay` feeds
# the emission box's proposition, so the Scala `genesisStateDigestHex`
# and the Rust `[chain] devnet_miner_reward_delay` genesis box set have
# to line up; a mismatch forks the two nodes at genesis and every later
# assertion becomes meaningless.
GENESIS_STATE_ROOT = os.environ.get(
    'MATRIX_GENESIS_STATE_ROOT',
    'c01a142d004a917b4af35385265748e37f7c77ab8a4e8b2080b9c193516b845602')

# Announcement bytes land in the Rust node's debug log, and a divergence
# findings artifact is required to carry them. The recipe therefore sets
# the filter itself rather than relying on the operator's environment.
# `announcements=trace` is what puts the RAW announcement frame in the
# log, keyed by block id, so a divergence artifact can carry the exact
# bytes rather than "no payload bytes logged for this id". It is one
# line per announcement — roughly one a second here — which is fine for
# a 25-minute recipe and far too much for a real node, hence TRACE.
DEFAULT_RUST_LOG = (
    'info,ergo_node::node::input_blocks=debug,ergo_inputblocks=debug,'
    'ergo_node::node::input_blocks::announcements=trace'
)


def _build_for(node):
    """The registry entry this node was told to run, or `None`.

    `None` means ONE thing: an explicit `MATRIX_CLASSPATH` override was
    set by hand, so there is no registry answer to give. That is how an
    operator points the harness at a one-off classpath, and
    `campaign.py` refuses it for a measured run.

    Every other failure — a build that is not provisioned, an unreadable
    `builds.toml`, and above all a `class_dir_sha256` that no longer
    matches the manifest — PROPAGATES. It used to be caught here and
    answered with `None`, and `classpath_file` then selected the legacy
    `.work/classpath`: the devnet came up on an unidentified build while
    the evidence recorded the registered one. Verification that falls
    back on failure is not verification.
    """
    if os.environ.get(f'MATRIX_CLASSPATH_{node.upper()}') or \
            os.environ.get('MATRIX_CLASSPATH'):
        return None
    name = node_build(node)
    if name in _VERIFIED_BUILDS:
        return _VERIFIED_BUILDS[name]
    sys.path.insert(0, str(HERE))
    import builds
    build = builds.load(name)
    # Cached because `builds.load` VERIFIES, which hashes every class
    # file on the classpath; the answer is asked for once per spawn and
    # again for every evidence record, and the build is immutable while
    # the devnet runs (spec §7a).
    _VERIFIED_BUILDS[name] = build
    return build


def classpath_file(node='scala') -> Path:
    """Classpath of the Scala build this NODE runs.

    Two sources: an explicit override (a hand-driven run, which
    `campaign.py` refuses for a measured one), and the build registry —
    which is also what VERIFIES the build, so a node started through it
    cannot be running compiled output that has moved since its manifest
    was written.

    There is no third. The legacy `.work/classpath` fallback used to sit
    here and was selected whenever verification FAILED, which is exactly
    when it must not be.
    """
    override = (os.environ.get(f'MATRIX_CLASSPATH_{node.upper()}')
                or os.environ.get('MATRIX_CLASSPATH'))
    if override:
        return Path(override)
    return _build_for(node).classpath_file


def owned(pid, configs=None):
    """A process this recipe started: running from this checkout, against one of
    the config paths we launched. Only PIDs recorded in `.work/*.pid` are ever
    considered, and only those still matching are signalled — nothing is ever
    matched by process-name pattern."""
    proc = Path('/proc') / str(pid)
    known = tuple(configs) if configs else tuple(
        'devnet-matrix/' + name for name in DEFAULT_CONFIG.values())
    try:
        cmd = (proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode()
        return proc.joinpath('cwd').resolve() == ROOT and any(s in cmd for s in known)
    except FileNotFoundError:
        return False


def stop(names=None):
    # Rust first, then the miners: a follower that outlives its peers
    # spends its last seconds logging failed dials.
    names = names or [n for n in ('rust', 'scala3', 'scala2', 'scala')
                      if n in NODES]
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
    # Release first: the input-block processor's throughput is what the
    # +-2 height window and the reconstruction rate are measured against,
    # and a debug build is not a measurement of the shipped node.
    for profile in ('release', 'debug'):
        candidate = Path(target) / profile / 'ergo-node'
        if candidate.exists():
            return str(candidate)
    raise SystemExit(
        f'ergo-node not built under {target}; run '
        '`cargo build --release -p ergo-node` or set RUST_NODE to the binary path'
    )


def node_binary() -> str:
    """The Rust binary this recipe will launch (release preferred)."""
    return os.environ.get('RUST_NODE') or _workspace_node_binary()


def _command(name):
    cp = classpath_file(name)
    if not cp.exists():
        raise SystemExit(
            f'Scala weak-blocks classpath for {name} not found at {cp}; '
            f'provision the build or set MATRIX_CLASSPATH_{name.upper()}')
    if name.startswith('scala'):
        return ['java', '-Xmx2g', '-Dlogback.configurationFile=' + str(HERE / 'logback.xml'),
                '-cp', cp.read_text().strip(), 'org.ergoplatform.ErgoApp',
                '--config', _config_path(name)]
    return [node_binary(), '--config', _config_path(name)]


def _config_path(name):
    return os.environ.get(CONFIG_ENV[name]) or str(HERE / DEFAULT_CONFIG[name])


def spawn(name):
    """Launch one node and wait for its REST `/info` to report a live state."""
    WORK.mkdir(exist_ok=True)
    (WORK / name).mkdir(exist_ok=True)
    env = dict(os.environ)
    env.setdefault('RUST_LOG', DEFAULT_RUST_LOG)
    with (WORK / (name + '.log')).open('a') as log:
        process = subprocess.Popen(_command(name), cwd=ROOT, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True,
                                   env=env)
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
            if name.startswith('scala'):
                version = info.get('appVersion')
                expected = scala_app_version(name)
                if version != expected:
                    raise RuntimeError(
                        f'Scala node at {REST[name]} reports appVersion '
                        f'{version!r}, not the {expected!r} its build '
                        f'({node_build(name)}) declares; point '
                        f'MATRIX_CLASSPATH_{name.upper()} at the provisioned '
                        'build, or re-pin deliberately')
                if 'bestInputBlock' not in info:
                    raise RuntimeError(
                        f'Scala node at {REST[name]} has no bestInputBlock key in '
                        '/info — that build has no input blocks')
            if info['stateRoot'] != GENESIS_STATE_ROOT and (info.get('fullHeight') or 0) == 0:
                raise RuntimeError(
                    f'{name} genesis state root {info["stateRoot"]} != the shared '
                    f'{GENESIS_STATE_ROOT}: the two nodes would fork at height 0. '
                    "Check monetary.minerRewardDelay / devnet_miner_reward_delay.")
            (WORK / (name + '.appVersion')).write_text(str(info.get('appVersion')))
            return info
        except (OSError, ValueError):
            if time.monotonic() > deadline:
                raise RuntimeError(f'{name} did not become ready; see .work/{name}.log')
            time.sleep(0.5)


WALLET_PASS = 'matrix-devnet'
API_KEY = 'hello'


def _scala_post(path, body, node='scala'):
    request = urllib.request.Request(
        f'http://127.0.0.1:{REST[node]}' + path, data=json.dumps(body).encode(),
        headers={'api_key': API_KEY, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = response.read()
        return json.loads(payload) if payload else None


def init_wallet(node='scala'):
    """Initialize and unlock a Scala node's wallet.

    The internal miner refuses to build candidates without it ("Miner
    can't load secret key from wallet: Wallet is locked"), so the whole
    recipe is inert until this runs. The mnemonic is recorded under
    `.work/` so a re-start of the same data dir restores the same wallet.
    """
    mnemonic_file = WORK / (node + '-wallet.mnemonic')
    deadline = time.monotonic() + 120
    while True:
        try:
            with urllib.request.urlopen(
                    urllib.request.Request(
                        f'http://127.0.0.1:{REST[node]}/wallet/status',
                        headers={'api_key': API_KEY}), timeout=5) as response:
                status = json.load(response)
            if status.get('isUnlocked'):
                return status
            if status.get('isInitialized'):
                _scala_post('/wallet/unlock', {'pass': WALLET_PASS}, node)
            elif mnemonic_file.exists():
                _scala_post('/wallet/restore', {
                    'pass': WALLET_PASS, 'mnemonic': mnemonic_file.read_text().strip(),
                    'usePre1627KeyDerivation': False}, node)
            else:
                result = _scala_post('/wallet/init', {'pass': WALLET_PASS}, node)
                mnemonic_file.write_text(result['mnemonic'])
        except (OSError, ValueError, KeyError):
            pass
        if time.monotonic() > deadline:
            raise RuntimeError(
            f'{node} wallet did not unlock; its internal miner cannot mine')
        time.sleep(1)


def wait_peered(timeout=180, names=None):
    """Every RUNNING node has at least one connected peer.

    `names` defaults to the whole node set; a scenario that brings a node
    up later passes the subset that is actually running, or this would
    wait out its whole timeout on a REST port nothing is listening on.
    """
    ports = {n: REST[n] for n in (names or NODES) if n in REST}
    deadline = time.monotonic() + timeout
    while True:
        try:
            counts = {}
            for name, port in ports.items():
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


def start(names=None):
    names = names or [n for n in ('scala', 'scala2', 'scala3', 'rust')
                      if n in NODES]
    wanted = {(P2P_HOST[n], P2P[n]) for n in names}
    wanted |= {('127.0.0.1', REST[n]) for n in names}
    for host, port in sorted(wanted):
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
    try:
        # Order matters. The Scala node mines with `offlineGeneration`,
        # so it would run away from a follower that has not joined yet —
        # but it cannot build a candidate until its wallet is unlocked.
        # Unlocking LAST is therefore the start gun: both nodes are up
        # and peered before the first block exists.
        for name in names:
            spawn(name)
        wait_peered(names=names)
        for name in names:
            if name.startswith('scala'):
                init_wallet(name)
    except BaseException:
        stop()
        raise


if __name__ == '__main__':
    os.chdir(ROOT)
    {'start': start, 'stop': stop}[sys.argv[1]]()
