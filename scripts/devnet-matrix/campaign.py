#!/usr/bin/env python3
"""The M3 Matrix (input blocks) devnet campaign (plan 2 task 9, spec §12).

Eight scenarios drive the Rust follower against the pinned Scala
`weak-blocks` miner(s) and record what it did:

  steady            60 ordering blocks, one miner: tip equality with lag,
                    mempool agreement modulo D1/F6, zero penalties.
  fork              two miners: every input-tree fork switch on Rust has
                    the same applied / rolled-back sets as Scala's, and
                    D3 sibling completion never invents a chain Scala
                    lacks.
  rollback          a full-block reorg: trees off the best chain are
                    pruned, `/info.bestInputBlock` clears, mempool
                    restores are recorded.
  reconstruct_rate  100 ordering blocks: reconstructed vs fallback on
                    Rust, beside the Scala node's own log equivalent —
                    the measurement of F5.
  restart           kill -9 the follower mid-chain: convergence within 3
                    ordering blocks (reconstruct/fallback is telemetry,
                    D7 makes either outcome legitimate).
  evict             the fallback path on purpose: a follower with no
                    input-block bodies for the announced tree must fall
                    back to a full download and land on Scala's block.
  flood             the p2p adversary against the follower only: every
                    §7.4 bound holds, memory stays inside the caps, the
                    honest peer is never penalised, the chain advances.
  miner_self_reject (M4) 40 ordering blocks against ONE miner running
                    `--build`: what the Scala miner does to its own input
                    solutions (F11). A MEASUREMENT — no pass criterion;
                    a stock run is what a patched run is read against.

Every scenario writes `.work/campaign/<scenario>.json`, records
divergences as artifacts under `.work/findings/`, and NEVER absorbs one:
an observation that could not be made fails the scenario rather than
passing quietly. The evaluators are smoke.py's — this module reuses
them rather than writing weaker per-scenario versions.

Ports are the campaign's own (19570-19573 p2p, 19590-19593 REST) so a
smoke run in another worktree can proceed concurrently.

M4 adds three things on top (spec §4, §7a, §8): a BUILD registry, so a
role can run a patch branch's build and a measurement is attributable to
compiled output rather than to a commit; ROLES, so the experiment says
what each node is doing rather than inferring it from the node's name;
and the reconstruction accounting every scenario now records per role,
so a patched follower can be read against a stock one. See
`builds.toml`, `roles.py` and this directory's README.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import threading
import time

# The node set and its ports have to be decided BEFORE `lifecycle` is
# imported: `lifecycle.P2P` / `REST` are read at import time and
# `smoke.URLS` is derived from them at ITS import time. Setting them here
# keeps the campaign a single command rather than a command plus six
# environment variables a reader has to get right.
# `scala3` (M4) is the patched reference follower's slot, extending the
# band to 19573 / 19593. It is opt-in: only `--reference-follower
# patched|both` starts it.
#
# The band is the DEFAULT, not the answer: `MATRIX_P2P_<NODE>` /
# `MATRIX_REST_<NODE>` — the same variables `lifecycle` reads — move the
# whole campaign onto another block. Two agents can already hold the
# smoke's band and this one at the same time, and a third run needs
# somewhere to bind; Task 2 ran on 19600-19603 / 19620-19623 beside a
# live Plan-2 campaign. Read HERE rather than only in
# `configure_environment`, because the config renderers close over these
# tables: an override that reached only the environment would bind one
# band and write the other into every node's config file.
DEFAULT_CAMPAIGN_P2P = {'scala': 19570, 'scala2': 19571, 'rust': 19572,
                        'scala3': 19573}
DEFAULT_CAMPAIGN_REST = {'scala': 19590, 'scala2': 19591, 'rust': 19592,
                         'scala3': 19593}


def _band(kind, defaults):
    return {name: int(os.environ.get(f'MATRIX_{kind}_{name.upper()}', port))
            for name, port in defaults.items()}


CAMPAIGN_P2P = _band('P2P', DEFAULT_CAMPAIGN_P2P)
CAMPAIGN_REST = _band('REST', DEFAULT_CAMPAIGN_REST)

# Every node listens on 127.0.0.1; only the ports differ.
#
# A detour worth recording, because the obvious fix is wrong here. Two
# Scala nodes on ONE address can never dial each other —
# `NetworkController.getPeerAddress` resolves a candidate whose declared
# address shares this node's own external address through the UPnP
# gateway, and with no gateway returns `None`. Giving each node its own
# 127.x address fixes that, and breaks something worse: the Rust
# follower then stops dialling the second miner at all, and a follower
# that holds one of two miners is no use to a two-miner scenario.
#
# It does not matter, because the second miner is SEEDED from the
# first's data directory (`common.seed_second_miner`) rather than
# synced over the network, so Scala-to-Scala peering is not needed. The
# follower's per-IP admission limit is raised in the scenarios that run
# three nodes, and nowhere else.
CAMPAIGN_P2P_HOST = {'scala': '127.0.0.1', 'scala2': '127.0.0.1',
                     'rust': '127.0.0.1', 'scala3': '127.0.0.1'}

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
WORK = HERE / '.work'
CAMPAIGN_WORK = WORK / 'campaign'
CONF = CAMPAIGN_WORK / 'conf'

# Scenarios that need a THIRD node, and what it is for. `fork` and
# `rollback` need a second MINER; `reconstruct_rate` needs a second
# FOLLOWER, because the reference miner never makes the
# reconstruct-or-download decision at all — it generates its blocks
# locally, so `processOrderingBlock` never runs on it and neither of the
# two log lines the measurement compares against is ever emitted. Only a
# reference FOLLOWER produces the reference half of the F5 ratio.
#
# Everything else runs the two-node set: a node that is up but idle
# still competes for the follower's sync budget, and would make `steady`
# a different measurement from the M2 smoke it has to be comparable
# with.
# (M4: which scenario gets which extra node is now stated by
# `SCENARIO_ROLES` below, and whether a Scala node mines is a property of
# its ROLE rather than of its node name — `scala2` is the second miner in
# `fork` and the reference follower in `reconstruct_rate`, and the role
# is what says which.)

# A Scala node whose role does not mine. Without this it would race the
# miner and `reconstruct_rate` would be a two-miner scenario by accident.
# Applied from the role, so a new follower role cannot forget it.
FOLLOWER_EXTRA = (
    'ergo.node.mining = false\n'
    'ergo.node.offlineGeneration = false\n'
)

# The order `--scenario all` runs them in: cheapest and most diagnostic
# first, so a broken build is caught in minutes rather than after the
# 100-block reconstruction measurement. `miner_self_reject` is a
# MEASUREMENT with no pass criterion, so it runs last: it can neither
# fail the campaign nor tell anyone a build is broken.
ORDER = ('steady', 'restart', 'evict', 'fork', 'rollback', 'flood',
         'reconstruct_rate', 'miner_self_reject')

# The node set per scenario, stated HERE rather than read off the
# scenario module: `lifecycle.P2P` and `smoke.URLS` are built at import
# time, so the environment has to be settled before the first of those
# imports happens — and a scenario module cannot be imported to ask it
# which nodes it wants without dragging `smoke` in with it. The
# `--self-test` checks this table against every module's own `NODES`, so
# the two cannot drift apart silently.
SCENARIO_NODES = {
    'steady': ('scala', 'rust'),
    'fork': ('scala', 'scala2', 'rust'),
    'rollback': ('scala', 'scala2', 'rust'),
    'reconstruct_rate': ('scala', 'scala2', 'rust'),
    'restart': ('scala', 'rust'),
    'evict': ('scala', 'rust'),
    'flood': ('scala', 'rust'),
    'miner_self_reject': ('scala', 'rust'),
}

# ----- roles and the ablation switch (M4, spec §4 and §8) -----
#
# Each scenario's BASE role set: what every node in `SCENARIO_NODES` is
# doing. `--reference-follower` may add to it, and `--build` decides
# which build the `*_patched` roles run. Kept beside the node table for
# the same reason that one is here: the environment has to be settled
# before `lifecycle` (and through it `smoke.URLS`) is imported.
SCENARIO_ROLES = {
    'steady': ('scala_miner', 'rust_follower'),
    'fork': ('scala_miner', 'scala_miner2', 'rust_follower'),
    'rollback': ('scala_miner', 'scala_miner2', 'rust_follower'),
    'reconstruct_rate': ('scala_miner', 'scala_follower', 'rust_follower'),
    'restart': ('scala_miner', 'rust_follower'),
    'evict': ('scala_miner', 'rust_follower'),
    'flood': ('scala_miner', 'rust_follower'),
    # The F11 measurement is about what the MINER does to its own
    # solutions, so the miner is the node under test and runs `--build`.
    # With `--build stock` it is the baseline the patch is compared
    # against, which is the same command with a different build.
    'miner_self_reject': ('scala_miner_patched', 'rust_follower'),
}

# Which scenarios take `--reference-follower` (spec §8). The others
# refuse it rather than accepting it and measuring nothing with it.
REFERENCE_FOLLOWER_SCENARIOS = ('steady', 'restart', 'fork',
                                'reconstruct_rate')


def resolve_roles(scenario, reference_follower=None):
    """The role set for one run, after `--reference-follower`.

    `reconstruct_rate` already carries a STOCK reference follower — it
    cannot measure anything without one — so for it the flag chooses
    between stock, patched and both. For the others the flag ADDS a
    reference follower that the base scenario does not have.

    `fork` and `rollback` spend the `scala2` slot on a second MINER, so
    a stock reference follower has nowhere to run there; that is refused
    with the reason rather than silently downgraded to `patched`.
    """
    roles = list(SCENARIO_ROLES[scenario])
    if reference_follower is None:
        return tuple(roles)
    if scenario not in REFERENCE_FOLLOWER_SCENARIOS:
        raise SystemExit(
            f'--reference-follower does not apply to {scenario}; it is '
            f'accepted by {", ".join(REFERENCE_FOLLOWER_SCENARIOS)}')
    wanted = {'stock': ['scala_follower'],
              'patched': ['scala_follower_patched'],
              'both': ['scala_follower', 'scala_follower_patched']}[
                  reference_follower]
    roles = [r for r in roles if r not in
             ('scala_follower', 'scala_follower_patched')]
    for role in wanted:
        node = lifecycle_roles()[role].node
        taken = {lifecycle_roles()[r].node for r in roles}
        if node in taken:
            holder = next(r for r in roles if lifecycle_roles()[r].node == node)
            raise SystemExit(
                f'{scenario} cannot run the {role} reference follower: its '
                f'{node} slot is already the {holder}. Use '
                '--reference-follower patched, which has its own slot.')
        roles.append(role)
    return tuple(roles)


def lifecycle_roles():
    """The role table.

    From `roles`, NOT from `lifecycle`: `lifecycle` reads its ports from
    the environment at import, and roles are resolved before
    `configure_environment` sets them. Importing `lifecycle` here would
    freeze the two-node smoke defaults over every campaign scenario.
    """
    sys.path.insert(0, str(HERE))
    import roles
    return roles.ROLES


def nodes_for_roles(role_set):
    """The node set a role set occupies, in start order."""
    sys.path.insert(0, str(HERE))
    import roles
    return roles.nodes_for_roles(role_set)


# Ports this harness must never bind, whatever the environment says:
# the operator's production and devnet nodes. The band is overridable
# (see `_band`), so the guard runs against the RESOLVED ports — a typo in
# `MATRIX_REST_SCALA` must not put a mining node's REST port in a
# campaign config file.
FORBIDDEN_PORTS = (9052, 9053, 9063, 9072, 9073, 19099)


def check_band(p2p, rest):
    """Refuse a resolved port band that is not this harness's to bind."""
    both = list(p2p.items()) + list(rest.items())
    clash = sorted({port for _, port in both if port in FORBIDDEN_PORTS})
    if clash:
        raise SystemExit(
            f'refusing to bind {clash}: those ports belong to the operator\'s '
            'nodes, not to this harness')
    seen = {}
    for node, port in both:
        if port in seen and seen[port] != node:
            raise SystemExit(
                f'port {port} is claimed twice ({seen[port]} and {node}); '
                'every node needs its own p2p and REST port')
        seen[port] = node
    return None


def configure_environment(scenario, nodes, roles=(), build='stock'):
    """Point `lifecycle` at this campaign's ports, configs, dirs and builds."""
    os.environ['MATRIX_NODES'] = ','.join(nodes)
    for name in nodes:
        os.environ[f'MATRIX_P2P_{name.upper()}'] = str(CAMPAIGN_P2P[name])
        os.environ[f'MATRIX_REST_{name.upper()}'] = str(CAMPAIGN_REST[name])
        os.environ[f'MATRIX_P2P_HOST_{name.upper()}'] = CAMPAIGN_P2P_HOST[name]
    # `--build` selects the build for the PATCHED roles only. Every
    # other Scala role stays on `stock`, which is what makes a run an
    # ablation (base + one patch vs base) rather than a comparison of
    # two integration builds (spec §7a).
    for role in roles:
        spec = lifecycle_roles()[role]
        if spec.kind != 'scala':
            continue
        os.environ[f'MATRIX_BUILD_{spec.node.upper()}'] = (
            build if spec.patched else 'stock')


# ----- config rendering -----

def scala_override(scenario, node, nodes, data_dir, extra=''):
    """A HOCON overlay over the committed Scala recipe file.

    An overlay rather than an edited copy: the committed file stays the
    single statement of what the recipe IS, and the campaign states only
    what it moves — ports, data directory, peers. A reader diffing the
    two sees the campaign's whole deviation.
    """
    base = HERE / ('scala-node.conf' if node == 'scala' else 'scala-miner2.conf')
    known = [f'"{CAMPAIGN_P2P_HOST[n]}:{CAMPAIGN_P2P[n]}"'
             for n in nodes if n != node]
    listen = f'{CAMPAIGN_P2P_HOST[node]}:{CAMPAIGN_P2P[node]}'
    return (
        f'include file("{base}")\n'
        f'ergo.directory = "{data_dir}"\n'
        'ergo.wallet.secretStorage.secretDir = ${ergo.directory}"/wallet/keystore"\n'
        f'scorex.network.bindAddress = "{listen}"\n'
        f'scorex.network.declaredAddress = "{listen}"\n'
        f'scorex.network.knownPeers = [{", ".join(known)}]\n'
        f'scorex.restApi.bindAddress = "127.0.0.1:{CAMPAIGN_REST[node]}"\n'
        f'{extra}'
    )


def render_rust_config(template, data_dir, nodes, overrides=()):
    """The Rust follower's config for this scenario.

    TOML has no include, so this is a substitution over the committed
    recipe file — and a pure one, so `--self-test` can prove it changes
    the keys it claims to and nothing else. `overrides` is a sequence of
    `(section, key, rendered value)`; a key already present in that
    section is replaced in place, and a missing one is appended to the
    section so an override can never be silently dropped.
    """
    lines = template.splitlines()
    known = [f'"{CAMPAIGN_P2P_HOST[n]}:{CAMPAIGN_P2P[n]}"'
             for n in nodes if n != 'rust']
    wanted = [
        ('', 'data_dir', f'"{data_dir}"'),
        ('peers', 'known', '[' + ', '.join(known) + ']'),
        ('peers', 'bind_addr',
         f'"{CAMPAIGN_P2P_HOST["rust"]}:{CAMPAIGN_P2P["rust"]}"'),
        ('peers', 'target_outbound', str(max(1, len(known)))),
        ('api', 'bind', f'"127.0.0.1:{CAMPAIGN_REST["rust"]}"'),
    ] + list(overrides)
    out, section, applied = [], '', set()
    for line in lines + ['']:
        stripped = line.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            # Leaving a section: append whatever it was missing.
            for sec, key, value in wanted:
                if sec == section and (sec, key) not in applied:
                    out.append(f'{key} = {value}')
                    applied.add((sec, key))
            section = stripped[1:-1]
            out.append(line)
            continue
        key = stripped.split('=')[0].strip() if '=' in stripped else None
        replacement = next((v for sec, k, v in wanted
                            if sec == section and k == key
                            and (sec, k) not in applied), None)
        if replacement is not None:
            out.append(f'{key} = {replacement}')
            applied.add((section, key))
            continue
        out.append(line)
    for sec, key, value in wanted:
        if (sec, key) not in applied:
            out.append(f'[{sec}]' if sec else '')
            out.append(f'{key} = {value}')
            applied.add((sec, key))
    return '\n'.join(out).rstrip() + '\n'


def ensure_data_dirs(data_root, nodes):
    """Create each node's data directory.

    The Scala node REQUIRES `ergo.directory` to exist and be writable
    before it will read the rest of its config — it fails in the settings
    reader, long before any log line about input blocks. A scenario that
    wipes a directory has to put it back for the same reason.
    """
    for node in nodes:
        (data_root / node).mkdir(parents=True, exist_ok=True)
    return data_root


def scala_extra_for(node, roles, scala_extra='', scala2_extra=''):
    """The HOCON a Scala node gets on top of the recipe file.

    Two sources, and the ROLE's comes first: a node whose role does not
    mine is told not to mine here, so a follower role added later cannot
    quietly become a second miner because its scenario forgot the
    constant. The scenario's own extra is appended, and HOCON's
    last-wins means a scenario can still override deliberately.
    """
    spec = lifecycle_roles()[roles[node]] if node in roles else None
    role_extra = '' if spec is None or spec.mines else FOLLOWER_EXTRA
    own = {'scala': scala_extra, 'scala2': scala2_extra}.get(node, '')
    return role_extra + own


def write_configs(scenario, nodes, roles=None, rust_overrides=(),
                  scala_extra='', scala2_extra=''):
    """Render every node's config for one scenario and point `lifecycle`
    at them. Returns the scenario's data directory."""
    CONF.mkdir(parents=True, exist_ok=True)
    roles = roles or {}
    data_root = CAMPAIGN_WORK / scenario
    data_root.mkdir(parents=True, exist_ok=True)
    ensure_data_dirs(data_root, nodes)
    for node in nodes:
        if node == 'rust':
            path = CONF / f'{scenario}-rust.toml'
            path.write_text(render_rust_config(
                (HERE / 'rust-node.toml').read_text(),
                data_root / 'rust', nodes, rust_overrides))
            os.environ['RUST_CONFIG'] = str(path)
        else:
            path = CONF / f'{scenario}-{node}.conf'
            path.write_text(scala_override(
                scenario, node, nodes, data_root / node,
                extra=scala_extra_for(node, roles, scala_extra, scala2_extra)))
            os.environ[{'scala': 'SCALA_CONFIG', 'scala2': 'SCALA2_CONFIG',
                        'scala3': 'SCALA3_CONFIG'}[node]] = str(path)
    return data_root


# ----- scenario plumbing -----

class Divergence(Exception):
    """A scenario could not make an observation it needs. Never absorbed."""


class Context:
    """What a scenario is handed: the sampler, the evidence dict, and the
    two ways to record an outcome.

    `fail` is the ONLY way a scenario reports a problem, and it always
    writes an artifact: a divergence that leaves nothing behind cannot be
    investigated, and a campaign whose findings are printed and lost is
    not evidence.
    """

    def __init__(self, scenario, run, evidence, args, nodes, data_root,
                 roles=None):
        self.scenario = scenario
        self.run = run
        self.evidence = evidence
        self.args = args
        self.nodes = nodes
        # `{node: role}` for this run. A scenario reads it to find the
        # node playing a role rather than hardcoding `scala2`, which is
        # the second miner in one scenario and the reference follower in
        # another.
        self.roles = dict(roles or {})
        self.data_root = data_root
        self.divergences = []
        self.not_measured_reasons = []
        # A scenario that polls the event feed INCREMENTALLY parks its
        # collector here, so the driver's reconstruction accounting can
        # use a window that is known to be complete rather than a single
        # post-hoc read the bounded ring may already have evicted from.
        self.collector = None
        self.collector_watermark = 0
        # The watch item the controller added: an input block whose
        # inputs Rust could not find in its own UTXO set. Counted per
        # scenario, with the input block and the node's state captured.
        self.utxo_validation_failures = []
        # The live drain (`UtxoWatch`), started with the nodes.
        self.utxo_watch = None

    def fail(self, message, evidence=None, ids=None):
        self.divergences.append({'scenario': self.scenario, 'message': message,
                                 'evidence': evidence})
        self.run.fail(self.scenario, message, evidence or {}, ids=ids)

    def note(self, key, value):
        self.evidence[key] = value

    def not_measured(self, message, evidence=None):
        """A property this host cannot establish.

        Neither a pass nor a failure: nothing about the node is wrong,
        and the property the scenario exists to establish is
        unestablished. Recorded, and it decides the verdict only when
        there is no real failure to outrank it.
        """
        entry = {'scenario': self.scenario, 'message': message,
                 'evidence': evidence}
        self.evidence.setdefault('not_measured', []).append(entry)
        self.not_measured_reasons.append(entry)
        return entry


UTXO_WATCH_PHRASE = 'input box not found in UTXO set'


def capture_utxo_validation_failure(ctx, line):
    """Capture the state a `input box not found in UTXO set` needs.

    Retaining the log line and the ids it mentions is not enough: the
    condition is transient, and by finalization the box may exist and
    the input block may have been pruned. Everything that explains it
    has to be read WHEN IT IS OBSERVED — the announcement and
    transaction ids of the input block, its bodies if the node serves
    them, and whether Rust's UTXO set has the missing box right now.
    """
    import smoke
    ids = smoke.ids_in(line)
    captured = {'line': line, 'ids': ids,
                'observed_at_unix': time.time(), 'input_block': None,
                'utxo': {}, 'rust_info': None}
    try:
        captured['rust_info'] = smoke.api('rust', '/info')
    except smoke.Unavailable as error:
        captured['rust_info'] = f'unavailable: {error}'
    for candidate in ids[:4]:
        # Which id is the input block and which is the box is not
        # knowable from the line, so both questions are asked of each.
        for route, key in (('/blocks/{}/inputBlockTransactionIds', 'input_block_txids'),
                           ('/utxo/byId/{}', 'utxo')):
            try:
                answer = smoke.api('rust', route.format(candidate))
            except smoke.Unavailable as error:
                answer = f'unavailable: {error}'
            if key == 'utxo':
                captured['utxo'][candidate] = answer
            elif answer and not isinstance(answer, str):
                # `answer` is the string `unavailable: ...` when the
                # route could not be read, and that is not a lookup. And
                # the FIRST id that resolves is the input block: a later
                # candidate that also resolves is recorded beside it,
                # never over it — overwriting is how the captured block
                # used to be replaced by whatever id the line named last.
                if captured['input_block'] is not None:
                    captured.setdefault('also_resolved', []).append(candidate)
                    continue
                captured['input_block'] = {'id': candidate, 'txids': answer}
                try:
                    captured['input_block']['bodies'] = smoke.api(
                        'rust', f'/blocks/{candidate}/inputBlockTransactions')
                except smoke.Unavailable as error:
                    captured['input_block']['bodies'] = f'unavailable: {error}'
    # The raw announcement bytes for the ids, from the debug log.
    captured['announcement_bytes'] = smoke.announcement_hex_for(
        ids[:4], smoke.rust_log_window(captured['observed_at_unix']))
    ctx.utxo_validation_failures.append(captured)
    ctx.run.fail('utxo_watch',
                 'an input block referenced a box the UTXO set does not have',
                 captured, ids=ids[:4])
    return captured


class UtxoWatch:
    """The watch item, drained LIVE for the whole scenario.

    Draining only from the scenario loops that remembered to call it left
    every other phase — flood delivery, lifecycle restarts, the waits
    between them — with no live capture, and a line seen first at
    finalization has no state behind it. This runs on its own thread from
    the moment the nodes start until they stop, reading the follower's
    log INCREMENTALLY (from a byte offset, so a 16 MB log is not re-read
    every poll) and capturing each new line's state as it appears.

    `scan()` is the whole mechanism and is called directly by the probe;
    the thread only calls it on a cadence.
    """

    def __init__(self, ctx, log_path=None, interval=2.0):
        self.ctx = ctx
        self.log_path = Path(log_path) if log_path else WORK / 'rust.log'
        self.interval = interval
        self.offset = 0
        self.partial = ''
        self.seen = set()
        self.scans = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def scan(self):
        import smoke
        with self._lock:
            self.scans += 1
            try:
                size = self.log_path.stat().st_size
            except OSError:
                return []
            if size < self.offset:
                # Truncated or replaced: start again from the top.
                self.offset, self.partial = 0, ''
            with self.log_path.open('rb') as handle:
                handle.seek(self.offset)
                chunk = handle.read()
            self.offset += len(chunk)
            text = self.partial + chunk.decode('utf-8', errors='replace')
            lines = text.split('\n')
            self.partial = lines.pop()  # an unterminated last line waits
            captured = []
            for line in lines:
                line = smoke.strip_ansi(line)
                if UTXO_WATCH_PHRASE not in line or line in self.seen:
                    continue
                self.seen.add(line)
                captured.append(capture_utxo_validation_failure(self.ctx, line))
            return captured

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.scan()
            except Exception as error:  # noqa: BLE001 — recorded, watch continues
                self.ctx.evidence.setdefault('utxo_watch_errors', []).append(
                    f'{type(error).__name__}: {error}')
            self._stop.wait(self.interval)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=30)
            self._thread = None
        self.scan()  # one last pass while the nodes are still up
        return self


def drain_utxo_watch(ctx, seen=None):
    """Drain the watch now, from a scenario loop. The live thread does the
    same on its own cadence; this only makes the capture prompter."""
    watch = getattr(ctx, 'utxo_watch', None)
    return watch.scan() if watch is not None else []


def scan_utxo_validation_failures(ctx):
    """Final sweep, for lines no scenario loop happened to drain.

    Anything captured live already carries its state; anything found only
    here is recorded WITH the fact that its state was not captured, so
    the evidence never implies an investigation it cannot support.
    """
    import smoke
    captured_lines = {h['line'] for h in ctx.utxo_validation_failures}
    late = []
    for line in smoke.rust_log_lines(UTXO_WATCH_PHRASE, limit=200000):
        if line in captured_lines:
            continue
        late.append({'line': line, 'ids': smoke.ids_in(line),
                     'state_captured': False,
                     'note': 'seen only at finalization; the box and the input '
                             'block were not read while the condition was live'})
    ctx.utxo_validation_failures.extend(late)
    ctx.note('utxo_validation_failures', {
        'count': len(ctx.utxo_validation_failures),
        'captured_live': sum(1 for h in ctx.utxo_validation_failures
                             if h.get('state_captured') is not False),
        'seen_only_at_finalization': len(late),
        'sample': ctx.utxo_validation_failures[:5],
    })
    return ctx.utxo_validation_failures


def input_block_status(node='rust'):
    """The §7.4 bound counters the node publishes."""
    import smoke
    return ((smoke.api(node, '/api/v1/status') or {}).get('input_blocks') or {})


def rss_kib(pid):
    """Resident set of a process, in KiB. `None` when it is gone."""
    try:
        for line in Path(f'/proc/{pid}/status').read_text().splitlines():
            if line.startswith('VmRSS:'):
                return int(line.split()[1])
    except OSError:
        return None
    return None


def node_pid(name):
    path = WORK / (name + '.pid')
    return int(path.read_text()) if path.exists() else None


# How long to wait after a killed node's PID disappears before starting
# its replacement. See `kill_hard`.
KILL_SETTLE_SECONDS = 3.0


def _holds_resources(pid):
    """Is this PID still holding its files, ports and database locks?

    Three states have to be told apart, and the first two attempts each
    conflated a different pair:

    * GONE — nothing to wait for;
    * ZOMBIE — exited, every resource released by the kernel, and merely
      waiting to be reaped. `os.kill(pid, 0)` still succeeds on one, so
      treating that as "alive" made a SIGKILL look like it had failed
      and the scenario aborted after 60 s;
    * RUNNING — still holds the data directory, and a replacement
      started now dies with "Database already open".

    `lifecycle.owned` answers none of these: a zombie's
    `/proc/<pid>/cmdline` is empty, so it reports False for a process
    that may not have finished dying.

    The zombie is also REAPED here when we are its parent, so it does not
    linger for the rest of the run.
    """
    try:
        os.waitpid(pid, os.WNOHANG)
    except (ChildProcessError, OSError):
        pass
    try:
        state = (Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1]
                 .split(' ', 1)[0])
    except (OSError, IndexError):
        return False
    return state != 'Z' 


def kill_hard(name):
    """SIGKILL one node this recipe started, by PID, after checking the
    process is still the one we launched.

    Returns only once the PID is GONE from the process table, not merely
    unrecognizable: the data directory's lock is held until then, and the
    replacement node refuses to open a database that is still open.
    """
    import lifecycle
    pid = node_pid(name)
    config = (WORK / (name + '.config'))
    configs = [config.read_text().strip()] if config.exists() else None
    if pid is None or not lifecycle.owned(pid, configs):
        raise Divergence(f'{name} is not running under this recipe; refusing to kill')
    os.kill(pid, signal.SIGKILL)
    deadline = time.monotonic() + 60
    while _holds_resources(pid) and time.monotonic() < deadline:
        time.sleep(0.2)
    if _holds_resources(pid):
        raise Divergence(
            f'{name} (PID {pid}) survived SIGKILL for 60s; refusing to start a '
            'replacement over a data directory the old process still holds')
    # The PID being gone is necessary and, measurably, not sufficient:
    # the replacement started 60 ms later still lost the race for the
    # data directory's redb lock ("Database already open. Cannot acquire
    # lock."). The kernel releases file locks as the process is torn
    # down, and the teardown outlives the PID's visibility. A real
    # operator restart has a gap too; this one is explicit and short.
    time.sleep(KILL_SETTLE_SECONDS)
    (WORK / (name + '.pid')).unlink(missing_ok=True)
    config.unlink(missing_ok=True)
    return pid


def purge_address_book(data_root):
    """Drop the follower's peer database.

    The p2p adversary harness poisons the address book with unreachable
    127.k.0.1 entries; leaving them behind starves the NEXT run's dialer.
    """
    removed = []
    for path in (data_root / 'rust').rglob('peers.redb'):
        path.unlink()
        removed.append(str(path))
    return removed


# ----- the driver -----

def rotate_logs(scenario, nodes, tag=''):
    """Move the node logs aside so a scenario reads only its OWN.

    `lifecycle.spawn` APPENDS, so without this every scenario reads the
    whole campaign's log as its own — `reconstruct_rate` would count the
    reference node's reconstruct-vs-download lines from six earlier
    scenarios, and every `rust_log_lines` window would carry runs that
    are not this one.

    Called twice: once BEFORE the nodes start, to set aside whatever an
    earlier run left behind (`tag='-prior'`, kept rather than deleted —
    it may be the evidence for why that run ended), and once after they
    stop, to keep this scenario's logs beside its evidence.
    """
    moved = {}
    for node in nodes:
        live = WORK / (node + '.log')
        if not live.exists():
            continue
        kept = CAMPAIGN_WORK / f'{scenario}-{node}{tag}.log'
        live.replace(kept)
        moved[node] = str(kept)
    return moved


# The controller's cap: a scenario gets three attempts. More than that
# and the reruns are hunting for a pass rather than measuring anything.
MAX_ATTEMPTS = 3


def _write_bytes(handle, data, path):
    """The one place a verdict file's bytes are written — a seam, so the
    self-test can fail a write part-way exactly where codex's r5 probe did."""
    handle.write(data)


def write_json_atomically(path, obj):
    """Replace `path` with `obj` as JSON, all-or-nothing.

    A truncating `write_text` that fails part-way leaves invalid JSON in
    place of the previous verdict. The bytes go to a temp file in the
    SAME directory, are fsynced, and only then `os.replace`d over the
    target (atomic on POSIX); the directory is fsynced so the rename
    survives a crash. On any failure the temp file is removed and the
    previous content is untouched.
    """
    import tempfile
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(obj, indent=2, default=str) + '\n').encode()
    fd, tmp = tempfile.mkstemp(prefix=f'.{path.name}.', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            _write_bytes(handle, data, path)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass
    return path


def attempts_path():
    return CAMPAIGN_WORK / 'attempts.json'


def read_attempts():
    """Every attempt this campaign has recorded, per scenario."""
    try:
        return json.loads(attempts_path().read_text())
    except (OSError, ValueError):
        return {}


def record_attempt(name, evidence):
    """Append one attempt's verdict, and KEEP its evidence file.

    `--attempt` used to be unchecked metadata that the runner set to 1
    every time, so repeated reruns quietly overwrote the canonical
    evidence until one of them passed. Each attempt now keeps its own
    copy beside the canonical one, and the history is what the cap is
    enforced against.
    """
    CAMPAIGN_WORK.mkdir(parents=True, exist_ok=True)
    history = read_attempts()
    entries = history.setdefault(name, [])
    number = len(entries) + 1
    kept = CAMPAIGN_WORK / 'attempts' / f'{name}-{number}.json'
    kept.parent.mkdir(parents=True, exist_ok=True)
    # ABORTED first, the real verdict LAST. Writing the real evidence
    # before the history meant a failing history write left this file
    # DONE/PASS while the canonical verdict was ABORTED (codex r4).
    placeholder = dict(evidence, status='FINALIZING', result='ABORTED',
                       aborted=evidence.get('aborted')
                       or 'the attempt history was not written')
    write_json_atomically(kept, placeholder)
    entries.append({
        'attempt': number,
        'result': evidence.get('result'),
        'aborted': evidence.get('aborted'),
        'finished': evidence.get('finished'),
        'failures': [f.get('message') for f in (evidence.get('failures') or [])],
        'evidence': str(kept),
    })
    _write_history(history)
    write_json_atomically(kept, evidence)
    return number


def _write_history(history):
    """The attempt HISTORY write — its own function so a probe can make it
    fail exactly where codex's r4 probe did."""
    write_json_atomically(attempts_path(), history)


def check_attempt_cap(name, force=False):
    """Refuse a fourth attempt unless it is explicitly forced.

    Returns the number this attempt will be. Raises `SystemExit` at the
    cap: the point of the cap is that it stops the run, not that it is
    mentioned in a report afterwards.
    """
    entries = read_attempts().get(name, [])
    number = len(entries) + 1
    if number > MAX_ATTEMPTS and not force:
        previous = '; '.join(
            f"#{e['attempt']} {e.get('result')}" for e in entries)
        raise SystemExit(
            f'{name} has already had {len(entries)} attempts ({previous}). '
            f'The cap is {MAX_ATTEMPTS}. Re-run with --force-attempt only if '
            'the controller has ruled that the earlier attempts measured a '
            'harness defect rather than the node.')
    return number


def verdict_for(aborted, failures, not_measured=None):
    """The one verdict rule, in one place.

    `NOT MEASURED` is its own kind: a scenario whose comparison could
    not be made on this host has not failed — nothing about the node is
    wrong — and it has not passed either, because the property it exists
    to establish is unestablished. It never outranks a real failure or
    an abort.
    """
    if aborted:
        return 'ABORTED'
    if failures:
        return 'FAIL'
    if not_measured:
        return 'NOT MEASURED'
    return 'PASS'


def persist_verdict(name, evidence, aborted, failures, save):
    """Write the verdict LAST.

    ABORTED goes to disk first; the attempt is recorded; only then is the
    real verdict written, as the final step. Any exception in between
    leaves ABORTED on disk. Previously DONE/PASS was saved BEFORE the
    attempt was recorded, and codex's r3 probe — the attempt recording
    raising after a clean run — left the persisted verdict at DONE/PASS.
    """
    verdict = verdict_for(aborted, failures, evidence.get('not_measured'))
    finished = datetime.datetime.now(datetime.timezone.utc).isoformat()
    evidence.update({'status': 'FINALIZING', 'result': 'ABORTED',
                     'aborted': aborted or 'the verdict was not persisted',
                     'verdict_pending': verdict, 'finished': finished})
    save()
    final = {k: v for k, v in evidence.items() if k != 'verdict_pending'}
    final.update({'status': 'DONE', 'result': verdict, 'aborted': aborted})
    try:
        record_attempt(name, final)
    except BaseException as error:  # noqa: BLE001 — recorded, then re-raised
        evidence['aborted'] = (f'the attempt could not be recorded: '
                               f'{type(error).__name__}: {error}')
        try:
            save()
        except BaseException:  # noqa: BLE001 — ABORTED is already on disk
            pass
        raise
    evidence.clear()
    evidence.update(final)
    save()
    return verdict


def check_build(name):
    """Refuse an unknown or unprovisioned `--build` before anything starts.

    An unknown name is a typo; a declared-but-unprovisioned one is a
    patch branch nobody has built yet, and the error says which command
    would build it. Either way the devnet does not start: a run that
    silently fell back to `stock` would be a patched claim measured on
    the base build.
    """
    sys.path.insert(0, str(HERE))
    import builds
    try:
        known = builds.registry()
    except builds.BuildError as error:
        raise SystemExit(str(error)) from error
    if name not in known:
        raise SystemExit(
            f'unknown build {name!r}; declared builds: {", ".join(known)}')
    build = known[name]
    if not build.available:
        raise SystemExit(
            f'build {name!r} is declared but not provisioned at '
            f'{build.work_dir}. Provision it first:\n  '
            + builds.provision_command(
                name, '~/coding/development/arkadianet/ergo-scala',
                build.declared.get('ergo_ref', '<ref>')))
    try:
        build.verify()
    except builds.BuildError as error:
        raise SystemExit(str(error)) from error
    return build


def common_module():
    """`scenarios.common`, imported lazily (it pulls `smoke` in with it)."""
    from scenarios import common
    return common


def build_manifests(by_node):
    """`{role: manifest summary}` for every Scala role in a run.

    Read through the registry, which VERIFIES the build first, so the
    manifest recorded beside a measurement is one that was checked
    against the compiled output the node actually ran — not a file that
    happened to sit next to it.
    """
    import builds
    import lifecycle
    out = {}
    for node, role in by_node.items():
        if lifecycle.ROLES[role].kind != 'scala':
            continue
        name = lifecycle.node_build(node)
        try:
            out[role] = builds.load(name).summary()
        except builds.BuildError as error:
            # Recorded, never absorbed: a run whose build could not be
            # identified says so in its own evidence file.
            out[role] = {'build': name, 'node': node,
                         'unidentified': str(error)}
        out[role]['node'] = node
    return out


def admission_overrides(nodes, overrides):
    """Raise the follower's per-IP admission limit to fit the node set.

    Every Scala node shares 127.0.0.1, and the limit gates outbound dial
    SELECTION as well as inbound admission, so a follower left at the
    default holds exactly ONE of them and a multi-Scala scenario
    measures nothing. It was a per-scenario constant, which is wrong the
    moment `--reference-follower` adds a node at RUNTIME: the resolved
    node set is what the limit has to fit.

    A scenario that states its own limit keeps it — `flood` is about
    admission, and a scenario that tests a bound may not have it widened
    underneath it. Nothing is raised for a single Scala node.
    """
    stated = {(sec, key) for sec, key, _ in overrides}
    scala_nodes = sum(1 for n in nodes if n != 'rust')
    if scala_nodes < 2:
        return tuple(overrides)
    extra = [o for o in (('peers', 'per_ip_limit', str(scala_nodes)),
                         ('peers', 'per_subnet_limit', str(scala_nodes * 2)))
             if (o[0], o[1]) not in stated]
    return tuple(overrides) + tuple(extra)


def run_scenario(name, args):
    import lifecycle
    import smoke
    from scenarios import SCENARIOS

    scenario = SCENARIOS[name]
    roles = resolve_roles(name, args.reference_follower)
    by_node = lifecycle.roles_for_nodes(roles)
    nodes = list(nodes_for_roles(roles))
    attempt = args.attempt or 1
    data_root = write_configs(
        name, nodes, roles=by_node,
        rust_overrides=admission_overrides(
            nodes, getattr(scenario, 'RUST_OVERRIDES', ())),
        scala_extra=getattr(scenario, 'SCALA_EXTRA', ''),
        scala2_extra=getattr(scenario, 'SCALA2_EXTRA', ''))
    if args.fresh:
        for node in nodes:
            shutil.rmtree(data_root / node, ignore_errors=True)
        ensure_data_dirs(data_root, nodes)

    evidence = {
        'scenario': name,
        'description': (scenario.__doc__ or '').strip().splitlines()[0],
        'status': 'RUNNING',
        'started': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'nodes': nodes,
        'roles': {node: role for node, role in by_node.items()},
        'reference_follower': args.reference_follower,
        'build': args.build,
        # The IDENTITY of every Scala build this run used, per role
        # (spec §7a "build identity"): source commit, sigma jars and the
        # sha256 of the compiled class output the node was launched
        # from. A number in this file is attributable to a build or it
        # is not evidence.
        'builds': build_manifests(by_node),
        'ports': {'p2p': {n: CAMPAIGN_P2P[n] for n in nodes},
                  'rest': {n: CAMPAIGN_REST[n] for n in nodes}},
        'rust': {
            'git_sha': subprocess.check_output(
                ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
            'binary': lifecycle.node_binary(),
        },
        'scala': {'classpath': str(lifecycle.classpath_file('scala')),
                  'pinned_app_version': lifecycle.scala_app_version('scala')},
        'attempt': args.attempt,
        'attempt_cap': MAX_ATTEMPTS,
        'previous_attempts': [
            {k: v for k, v in e.items() if k != 'evidence'}
            for e in read_attempts().get(name, [])],
    }
    CAMPAIGN_WORK.mkdir(parents=True, exist_ok=True)
    output = CAMPAIGN_WORK / f'{name}.json'

    def save():
        write_json_atomically(output, evidence)

    evidence['logs_set_aside_at_start'] = rotate_logs(name, nodes, tag='-prior')
    save()
    run = smoke.Run(time.monotonic() + args.timeout)
    ctx = Context(name, run, evidence, args, nodes, data_root,
                  roles=by_node)
    # A scenario may bring a node up itself, part-way through. The
    # two-miner scenarios do: the second miner is seeded from the
    # first's data directory once there is a chain to copy, because the
    # reference node cannot hand it over on this host.
    started = [n for n in nodes if n in getattr(scenario, 'START_NODES', nodes)]
    evidence['started_at_launch'] = started
    # Set by the abort arm below; read by the `finally` when it decides
    # the verdict. A scenario that did not finish is ABORTED, never PASS.
    aborted = None
    save()
    # INSIDE the try: a failure in `start` used to leave the nodes it did
    # manage to launch running, with the evidence file still saying
    # RUNNING — and the next scenario then collided with them over ports
    # and data directories. Whatever happens, the `finally` stops them.
    try:
        lifecycle.start(started)
        for node in started:
            run.started(node)
        run.start_sampling()
        ctx.utxo_watch = UtxoWatch(ctx).start()
        scenario.run(ctx)
    except smoke.Unavailable as error:
        ctx.fail(f'an observation the scenario needs was unavailable: {error}')
    except Divergence as error:
        ctx.fail(str(error))
    except BaseException as error:  # noqa: BLE001 — recorded, then re-raised
        # ANY other exception aborts the scenario. Previously only the
        # two named types became failures and everything else fell
        # through to the `finally`, which derived the verdict from
        # `run.failures` alone — so a lifecycle error raised after the
        # samples were taken but before the assertions ran persisted
        # `DONE / PASS / []`. A run that did not finish has not passed.
        aborted = f'{type(error).__name__}: {error}'
        raise
    finally:
        # THREE nested scopes, and the order matters. Evidence
        # collection is wrapped so a failure in it cannot bypass node
        # shutdown; node shutdown is in the inner `finally` so it runs
        # whatever happened above; and the verdict is decided AFTERWARDS,
        # so a shutdown that fails cannot leave a saved PASS behind.
        shutdown_error = None
        try:
            try:
                run.stop_sampling()
                if getattr(ctx, 'utxo_watch', None) is not None:
                    ctx.utxo_watch.stop()
                    evidence['utxo_watch_scans'] = ctx.utxo_watch.scans
                smoke.check_sampler(run, evidence)
                scan_utxo_validation_failures(ctx)
                # EVERY scenario carries the reconstruction accounting, per
                # role (spec §7a "honest denominators"), not just the one
                # that measures it: the patched-vs-stock comparisons in the
                # findings drafts quote these five numbers, and a scenario
                # that happened not to collect them would be a hole in the
                # ablation rather than a scenario with nothing to say.
                evidence['reconstruction_accounting'] = \
                    common_module().reconstruction_accounting(ctx)
                evidence['divergences'] = ctx.divergences
                evidence['failures'] = run.failures
                evidence['artifacts'] = smoke.write_findings(run, evidence)
                # Per ATTEMPT, not per scenario: an attempt's verdict
                # file used to point at a series and logs the next
                # attempt had already replaced.
                evidence['logs'] = rotate_logs(name, nodes, tag=f'-{attempt}')
                series = run.series_path
                if series.exists():
                    kept = (CAMPAIGN_WORK
                            / f'{name}-{attempt}-agreement-series.jsonl')
                    series.replace(kept)
                    evidence['series_file'] = str(kept)
                evidence['samples'] = run.samples
                evidence['unavailable_samples'] = run.unavailable_samples
                evidence['drop_totals'] = run.totals()
                evidence['peer_states'] = sorted(run.peer_states)
                evidence['penalty_observations'] = run.penalty_observations
                evidence['max_height_gap'] = run.max_height_gap
            except BaseException as error:  # noqa: BLE001 — recorded, then abort
                evidence['evidence_collection_error'] = (
                    f'{type(error).__name__}: {error}')
                if aborted is None:
                    aborted = evidence['evidence_collection_error']
        finally:
            # UNCONDITIONAL. Nothing above may leave the nodes running.
            try:
                lifecycle.stop()
            except BaseException as error:  # noqa: BLE001 — recorded below
                shutdown_error = f'{type(error).__name__}: {error}'
            if getattr(scenario, 'PURGE_ADDRESS_BOOK', False):
                try:
                    evidence['address_book_purged'] = purge_address_book(data_root)
                except BaseException as error:  # noqa: BLE001 — recorded below
                    shutdown_error = (shutdown_error or '') + (
                        f' purge failed: {type(error).__name__}: {error}')
        # A run whose nodes would not stop has not finished cleanly, and
        # its verdict is not a pass.
        evidence['shutdown_error'] = shutdown_error
        if shutdown_error and aborted is None:
            aborted = f'node shutdown failed: {shutdown_error}'
        persist_verdict(name, evidence, aborted, run.failures, save)
    return evidence


# ----- self-test -----

def _self_test():
    """The campaign's own pure parts, red-first like smoke.py's.

    Only the parts that decide something: a config renderer that silently
    dropped an override would point the campaign at the wrong ports and
    every scenario after it would measure the wrong node.
    """
    template = (
        'network = "devnet"\n'
        'data_dir = "scripts/devnet-matrix/.work/rust"\n'
        '\n'
        '[peers]\n'
        'known = ["127.0.0.1:19560"]\n'
        'bind_addr = "127.0.0.1:19561"\n'
        'allow_local = true\n'
        'target_outbound = 1\n'
        '\n'
        '[api]\n'
        'bind = "127.0.0.1:19581"\n'
        '\n'
        '[input_blocks]\n'
        'enabled = true\n'
    )
    rendered = render_rust_config(template, Path('/tmp/x/rust'),
                                  ['scala', 'scala2', 'rust'])
    assert 'data_dir = "/tmp/x/rust"' in rendered, rendered
    # Each node on its own loopback address, REST on 127.0.0.1 for all.
    assert 'bind_addr = "127.0.0.1:19572"' in rendered, rendered
    assert 'bind = "127.0.0.1:19592"' in rendered, rendered
    assert ('known = ["127.0.0.1:19570", "127.0.0.1:19571"]' in rendered), rendered
    assert 'target_outbound = 2' in rendered, rendered
    # Untouched keys survive verbatim, and nothing is duplicated.
    assert 'allow_local = true' in rendered, rendered
    assert rendered.count('bind_addr') == 1, rendered
    assert rendered.count('data_dir') == 1, rendered
    assert 'network = "devnet"' in rendered, rendered

    # An override for a key the template does not carry is APPENDED to
    # its section, never dropped: the `evict` scenario's whole point is a
    # bound the recipe file does not set.
    with_bounds = render_rust_config(
        template, Path('/tmp/x/rust'), ['scala', 'rust'],
        overrides=[('input_blocks.bounds', 'max_bodies', '4')])
    assert '[input_blocks.bounds]' in with_bounds, with_bounds
    assert 'max_bodies = 4' in with_bounds, with_bounds
    # And one for a key it DOES carry replaces it in place.
    toggled = render_rust_config(
        template, Path('/tmp/x/rust'), ['scala', 'rust'],
        overrides=[('input_blocks', 'enabled', 'false')])
    assert 'enabled = false' in toggled, toggled
    assert toggled.count('enabled') == 1, toggled

    # The Scala overlay includes the committed file rather than copying
    # it, and moves exactly the three things it claims to.
    overlay = scala_override('fork', 'scala2', ['scala', 'scala2', 'rust'],
                             Path('/tmp/x/scala2'))
    assert 'include file(' in overlay and 'scala-miner2.conf")' in overlay, overlay
    assert 'bindAddress = "127.0.0.1:19571"' in overlay, overlay
    assert 'restApi.bindAddress = "127.0.0.1:19591"' in overlay, overlay
    assert '"127.0.0.1:19570", "127.0.0.1:19572"' in overlay, overlay
    # Every scenario that runs three nodes on one address has to raise
    # the follower's per-IP admission limit, or it holds exactly one of
    # the two Scala nodes and the scenario measures nothing.
    from scenarios import SCENARIOS as _all
    for _name, _nodes in SCENARIO_NODES.items():
        if len(_nodes) < 3:
            continue
        _overrides = dict(
            ((sec, key), value)
            for sec, key, value in getattr(_all[_name], 'RUST_OVERRIDES', ()))
        assert _overrides.get(('peers', 'per_ip_limit')) == '3', _name
    # ...and a node set that grows at RUNTIME gets the same treatment,
    # because `--reference-follower` is not in any scenario's constant.
    assert admission_overrides(('scala', 'rust'), ()) == ()
    assert dict(((s, k), v) for s, k, v in admission_overrides(
        ('scala', 'scala2', 'rust'), ()))[('peers', 'per_ip_limit')] == '2'
    assert dict(((s, k), v) for s, k, v in admission_overrides(
        ('scala', 'scala2', 'scala3', 'rust'), ()))[
            ('peers', 'per_ip_limit')] == '3'
    # A scenario that states the bound keeps it: `flood` tests admission
    # and may not have it widened underneath it.
    stated = (('peers', 'per_ip_limit', '1'),)
    assert admission_overrides(('scala', 'scala2', 'rust'), stated)[0] == \
        stated[0]
    assert sum(1 for s, k, _ in admission_overrides(
        ('scala', 'scala2', 'rust'), stated)
        if (s, k) == ('peers', 'per_ip_limit')) == 1
    assert '19571' not in overlay.split('knownPeers')[1], \
        'a node must not be listed as its own peer'

    # ----- M4: a THIRD port block, for a run beside a live campaign -----
    #
    # Two agents can hold the two documented bands at once (the smoke's
    # 19560-19563 / 19580-19583 and the campaign's 19570-19573 /
    # 19590-19593), and a third run then has nowhere to bind. The
    # environment names the band — the same `MATRIX_P2P_<NODE>` /
    # `MATRIX_REST_<NODE>` variables `lifecycle` already reads — and the
    # campaign's own tables are the DEFAULT rather than the answer.
    #
    # It has to hold in a FRESH interpreter: the tables are module-level
    # and the rendering functions close over them, so an override that
    # only reached `configure_environment` would render the default band
    # into every config file while binding the overridden one.
    probe = (
        'import os, sys; sys.path.insert(0, %r); import campaign;'
        'print(campaign.CAMPAIGN_P2P["scala"], campaign.CAMPAIGN_REST["rust"]);'
        'print(campaign.scala_override("steady", "scala", ["scala", "rust"],'
        ' __import__("pathlib").Path("/tmp/x/scala")))'
    ) % str(HERE)
    env = dict(os.environ, MATRIX_P2P_SCALA='19600', MATRIX_P2P_RUST='19602',
               MATRIX_REST_SCALA='19620', MATRIX_REST_RUST='19622')
    out = subprocess.run([sys.executable, '-c', probe], env=env,
                         capture_output=True, text=True, check=True).stdout
    assert out.splitlines()[0] == '19600 19622', out
    assert 'bindAddress = "127.0.0.1:19600"' in out, out
    assert 'restApi.bindAddress = "127.0.0.1:19620"' in out, out
    assert '"127.0.0.1:19602"' in out, out
    # An unset environment still reproduces the documented band exactly.
    out = subprocess.run([sys.executable, '-c', probe],
                         env={k: v for k, v in os.environ.items()
                              if not k.startswith(('MATRIX_P2P', 'MATRIX_REST'))},
                         capture_output=True, text=True, check=True).stdout
    assert out.splitlines()[0] == '19570 19592', out

    # The port bands are the controller's, and must never collide with a
    # production node or with the smoke recipe's own defaults.
    import lifecycle
    forbidden = {9052, 9053, 9063, 9072, 9073, 19099}
    used = set(DEFAULT_CAMPAIGN_P2P.values()) | set(DEFAULT_CAMPAIGN_REST.values())
    assert not (used & forbidden), used & forbidden
    assert not (used & set(lifecycle.DEFAULT_P2P.values())), used
    assert not (used & set(lifecycle.DEFAULT_REST.values())), used
    # ----- M4: the role/port table has no collisions -----
    #
    # Every node has its OWN p2p and REST port, in both the smoke and
    # the campaign band, and the two bands do not overlap. A duplicate
    # here binds one node's port for another and the run fails at start
    # — or worse, two nodes share a data directory.
    for table in (DEFAULT_CAMPAIGN_P2P, DEFAULT_CAMPAIGN_REST,
                  lifecycle.DEFAULT_P2P, lifecycle.DEFAULT_REST):
        assert len(set(table.values())) == len(table), table
    assert set(CAMPAIGN_P2P) == set(CAMPAIGN_REST) == set(
        lifecycle.DEFAULT_P2P) == set(lifecycle.DEFAULT_REST) == set(
        lifecycle.DEFAULT_P2P_HOST) == set(CAMPAIGN_P2P_HOST), \
        'every node needs an entry in every port table'
    # The M4 slot, at the band the plan states.
    assert DEFAULT_CAMPAIGN_P2P['scala3'] == 19573, DEFAULT_CAMPAIGN_P2P
    assert DEFAULT_CAMPAIGN_REST['scala3'] == 19593, DEFAULT_CAMPAIGN_REST
    assert not (set(CAMPAIGN_P2P.values()) & set(CAMPAIGN_REST.values()))
    # Whatever band a run is moved onto, the guard that keeps it off a
    # production node runs against the RESOLVED ports, not the defaults.
    assert check_band(dict(CAMPAIGN_P2P), dict(CAMPAIGN_REST)) is None
    try:
        check_band({'scala': 9053}, {'scala': 19620})
    except SystemExit as error:
        assert '9053' in str(error), str(error)
    else:
        raise AssertionError('a production port must be refused')
    try:
        check_band({'scala': 19600, 'rust': 19600}, {'scala': 19620})
    except SystemExit as error:
        assert 'twice' in str(error), str(error)
    else:
        raise AssertionError('a duplicated port must be refused')
    # Every role names a node that HAS a slot, and the node sets the
    # roles cover are exactly the ones the port tables know about.
    for role, spec in lifecycle.ROLES.items():
        assert spec.node in CAMPAIGN_P2P, (role, spec.node)
        assert spec.node in lifecycle.DEFAULT_CONFIG, (role, spec.node)
        assert spec.kind in ('scala', 'rust'), role
        assert spec.why, f'{role} must say what it is for'
    # Two roles may SHARE a slot (they are alternatives), and asking for
    # both at once is an error rather than a silent single node.
    try:
        lifecycle.roles_for_nodes(('scala_miner', 'scala_miner_patched'))
    except ValueError as error:
        assert 'both want the' in str(error), str(error)
    else:
        raise AssertionError('two roles in one slot must be refused')
    try:
        lifecycle.roles_for_nodes(('scala_miner', 'nonsense_role'))
    except KeyError as error:
        assert 'unknown role' in str(error), str(error)
    else:
        raise AssertionError('an unknown role must be refused')

    # Every scenario the docstring promises exists, names its nodes, and
    # asks for the second miner only if it is a two-miner scenario.
    from scenarios import SCENARIOS
    expected = {'steady', 'fork', 'rollback', 'reconstruct_rate', 'restart',
                'evict', 'flood', 'miner_self_reject'}
    assert set(SCENARIOS) == expected, sorted(SCENARIOS)
    assert set(SCENARIO_NODES) == expected, sorted(SCENARIO_NODES)
    assert set(SCENARIO_ROLES) == expected, sorted(SCENARIO_ROLES)
    assert set(ORDER) == expected, sorted(ORDER)
    import lifecycle
    for name, module in SCENARIOS.items():
        assert callable(module.run), name
        # The table the driver uses and the module's own statement of
        # what it needs have to agree, or a scenario would be started
        # with a node set it was not written for.
        assert tuple(module.NODES) == SCENARIO_NODES[name], name
        assert set(module.NODES) <= {'scala', 'scala2', 'scala3', 'rust'}, name
        assert 'rust' in module.NODES, name
        # ----- M4: the role table decides the node set -----
        #
        # Every role a scenario declares has to have its own slot, and
        # the slots it occupies have to be exactly the nodes the driver
        # starts. A role table that drifted from the node table would
        # bind a port nothing uses, or run two roles as one node.
        assigned = lifecycle.roles_for_nodes(SCENARIO_ROLES[name])
        assert tuple(sorted(assigned)) == tuple(sorted(module.NODES)), \
            (name, assigned, module.NODES)
        assert nodes_for_roles(SCENARIO_ROLES[name]) == SCENARIO_NODES[name], \
            name
        # Exactly one Rust follower, and it never mines.
        assert sum(1 for r in SCENARIO_ROLES[name]
                   if lifecycle.ROLES[r].kind == 'rust') == 1, name
        # Whatever a scenario starts itself has to be one of its own
        # nodes, or `lifecycle.start` would bind a port nothing uses.
        assert set(getattr(module, 'START_NODES', module.NODES)) <= set(
            module.NODES), name
        # A Scala node whose ROLE does not mine is told not to mine —
        # from the role, so a scenario cannot forget it. Without this
        # `reconstruct_rate` silently becomes a two-miner scenario.
        for node, role in assigned.items():
            extra = scala_extra_for(
                node, assigned,
                getattr(module, 'SCALA_EXTRA', ''),
                getattr(module, 'SCALA2_EXTRA', ''))
            if lifecycle.ROLES[role].kind == 'scala' and \
                    not lifecycle.ROLES[role].mines:
                assert 'mining = false' in extra, (name, node, role)

    # ----- M4: `--reference-follower` -----
    #
    # It adds a reference follower where there is a slot for one, keeps
    # the roles one-to-one with the nodes, and REFUSES the combination
    # that has no slot rather than quietly running something else.
    assert resolve_roles('steady', None) == SCENARIO_ROLES['steady']
    for _mode, _want in (('stock', 'scala_follower'),
                         ('patched', 'scala_follower_patched')):
        _roles = resolve_roles('steady', _mode)
        assert _want in _roles, (_mode, _roles)
        lifecycle.roles_for_nodes(_roles)
    both = resolve_roles('steady', 'both')
    assert {'scala_follower', 'scala_follower_patched'} <= set(both), both
    assert nodes_for_roles(both) == ('scala', 'scala2', 'scala3', 'rust'), both
    # `reconstruct_rate` already HAS a stock follower; `patched` replaces
    # it rather than adding a second one on the same slot.
    assert resolve_roles('reconstruct_rate', 'patched') == (
        'scala_miner', 'rust_follower', 'scala_follower_patched'), \
        resolve_roles('reconstruct_rate', 'patched')
    # `fork` spends `scala2` on a second MINER, so a stock reference
    # follower has nowhere to go; that is an error with the reason.
    for _mode in ('stock', 'both'):
        try:
            resolve_roles('fork', _mode)
        except SystemExit as error:
            assert 'slot is already the scala_miner2' in str(error), str(error)
        else:
            raise AssertionError(
                f'fork --reference-follower {_mode} must be refused')
    assert 'scala_follower_patched' in resolve_roles('fork', 'patched')
    # And a scenario the flag does not apply to says so.
    try:
        resolve_roles('flood', 'stock')
    except SystemExit as error:
        assert 'does not apply to flood' in str(error), str(error)
    else:
        raise AssertionError('--reference-follower must be scenario-checked')

    # Resolving roles must NOT import `lifecycle`. `lifecycle.P2P` /
    # `REST` are read from the environment at import and `smoke.URLS` is
    # derived from them at ITS import, so an import here — before
    # `configure_environment` runs — would freeze the two-node smoke
    # defaults and every campaign scenario would quietly drive the
    # smoke's ports. Checked in a fresh interpreter, because this one
    # has imported `lifecycle` already.
    _probe = subprocess.run(
        [sys.executable, '-c',
         'import sys; sys.path.insert(0, %r); import campaign; '
         'r = campaign.resolve_roles("fork", "patched"); '
         'campaign.nodes_for_roles(r); '
         'assert "lifecycle" not in sys.modules, sorted(sys.modules); '
         'print("clean")' % str(HERE)],
        capture_output=True, text=True, cwd=ROOT)
    assert _probe.returncode == 0 and 'clean' in _probe.stdout, \
        ('resolving roles must not import lifecycle', _probe.stdout,
         _probe.stderr)

    # ----- M4: the build registry and the ablation switch -----
    import builds as _builds
    # `--build` selects the build for the PATCHED roles only; every
    # other Scala role stays on stock, which is what makes a run an
    # ablation rather than two integration builds compared.
    _saved = {k: v for k, v in os.environ.items()
              if k.startswith('MATRIX_BUILD_')}
    try:
        configure_environment('miner_self_reject',
                              nodes_for_roles(SCENARIO_ROLES['miner_self_reject']),
                              SCENARIO_ROLES['miner_self_reject'], 'F11')
        assert os.environ['MATRIX_BUILD_SCALA'] == 'F11', os.environ
        _fork_roles = resolve_roles('fork', 'patched')
        configure_environment('fork', nodes_for_roles(_fork_roles),
                              _fork_roles, 'F13')
        # The stock miners stay stock; only the patched follower moves.
        assert os.environ['MATRIX_BUILD_SCALA'] == 'stock', os.environ
        assert os.environ['MATRIX_BUILD_SCALA2'] == 'stock', os.environ
        assert os.environ['MATRIX_BUILD_SCALA3'] == 'F13', os.environ
    finally:
        for key in [k for k in os.environ if k.startswith('MATRIX_BUILD_')]:
            del os.environ[key]
        os.environ.update(_saved)

    # An unknown `--build` is refused, and the message names the
    # alternatives rather than falling back to stock.
    try:
        check_build('not-a-build')
    except SystemExit as error:
        assert 'unknown build' in str(error) and 'stock' in str(error), str(error)
    else:
        raise AssertionError('an unknown --build must stop the run')
    # A DECLARED but unprovisioned build is refused too, with the
    # command that would provision it.
    _unprovisioned = [n for n, b in _builds.registry().items()
                      if not b.available]
    if _unprovisioned:
        try:
            check_build(_unprovisioned[0])
        except SystemExit as error:
            assert 'not provisioned' in str(error), str(error)
            assert 'provision.py' in str(error), str(error)
        else:
            raise AssertionError(
                'an unprovisioned build must stop the run, not fall back')
    # The stock build is the one every baseline is measured on: it has
    # to be present and to still match its recorded compiled output.
    _stock = check_build('stock')
    assert _stock.summary()['ergo_commit'].startswith('62c10315'), \
        _stock.summary()
    assert _stock.app_version() == '6.0.6-493-62c10315-SNAPSHOT', \
        _stock.app_version()
    # The manifest a scenario records names the build AND its compiled
    # output, per role.
    _manifests = build_manifests({'scala': 'scala_miner', 'rust': 'rust_follower'})
    assert set(_manifests) == {'scala_miner'}, _manifests
    assert len(_manifests['scala_miner']['class_dir_sha256']) == 64, _manifests

    # ----- M4: the reconstruction accounting -----
    from scenarios import common as _common
    _rust = _common.rust_accounting([
        {'kind': 'ordering_reconstructed'},
        {'kind': 'ordering_reconstructed'},
        {'kind': 'ordering_reconstruct_fallback', 'detail': 'root_mismatch'},
        {'kind': 'ordering_reconstruct_fallback', 'detail': 'missing_input_body'},
        {'kind': 'ordering_reconstruct_fallback',
         'detail': 'missing_broadcasted_tx'},
        {'kind': 'ordering_reconstruct_skipped', 'detail': 'no_chain'},
        {'kind': 'ordering_reconstruct_skipped', 'detail': 'no_prev_input_block'},
        # Not one of the five, and never folded into one of them.
        {'kind': 'ordering_reconstruct_fallback', 'detail': 'storage_error'},
        {'kind': 'blockApplied'},
    ])
    assert _rust['reconstructed'] == 2, _rust
    assert _rust['download_root_mismatch'] == 1, _rust
    assert _rust['download_missing_tx'] == 2, _rust
    assert _rust['skipped_no_chain'] == 2, _rust
    assert _rust['other_outcomes'] == {'fallback:storage_error': 1}, _rust
    assert _rust['eligible_announcements'] == 8, _rust
    assert _rust['unaccounted'] == 1, _rust
    assert _rust['reconstructed_ratio'] == 0.25, _rust
    # The reference's log lines map onto the SAME five names, which is
    # the whole point: a patched follower is read against a stock one.
    _scala = _common.scala_accounting([
        'INFO Processing ordering block announcement for aa',
        'INFO Applying block transactions from input-blocks for aa with transactions: 3',
        'INFO Processing ordering block announcement for bb',
        'WARN Downloading block transactions fully for bb as Merkle root does not match',
        'INFO Processing ordering block announcement for cc',
        'WARN Downloading block transactions fully for cc as not all the transactions available',
        'INFO Processing ordering block announcement for dd',
        'WARN Parent header not found for ordering block dd, caching its header and requesting parent ee',
    ])
    assert [_scala[f] for f in _common.ACCOUNTING_FIELDS] == [4, 1, 1, 1, 1], _scala
    assert _scala['unaccounted'] == 0, _scala
    assert _scala['reconstructed_ratio'] == 0.25, _scala
    # A build that logs none of the five is UNKNOWN, not a clean zero.
    _silent = _common.scala_accounting(['INFO something else entirely'])
    assert 'UNKNOWN, not zero' in _silent['unmatched'], _silent

    # ----- M4: the miner_self_reject denominators -----
    from scenarios import miner_self_reject as _msr
    _log = [
        'INFO Found solution for input block, sending it for validation',
        'INFO Input-block ' + 'ab' * 32 + ' mined @ height 7!',
        'INFO Processed solution x with the result Success(())',
        'INFO Solution accepted',
        'INFO Found solution for input block, sending it for validation',
        'WARN Removing candidate due to invalid input block',
        'INFO Processed solution y with the result Error(java.lang.Exception: '
        'Invalid input block! PoW valid: false)',
        'ERROR Accepting solution or preparing candidate did not succeed',
        # The F11c case: submitted, never answered.
        'INFO Found solution for ordering block, sending it for validation',
    ]
    _counts = _msr.count(_log)
    assert _counts['submissions'] == 3, _counts
    assert _counts['submissions_input'] == 2, _counts
    assert _counts['replies_success'] == 1, _counts
    assert _counts['replies_error'] == 1, _counts
    assert _counts['replies_missing'] == 1, _counts
    assert _counts['pow_failures'] == 1, _counts
    # The two PoW-failure sites agree; a loose substring would have
    # counted this one failure twice.
    assert _counts['pow_failure_replies'] == 1, _counts
    assert _counts['pow_failure_sites_disagree'] is False, _counts
    assert _counts['distinct_applied_input_blocks'] == 1, _counts
    assert _counts['applied_input_block_ids'] == ['ab' * 32], _counts
    # An empty window is UNKNOWN, not a run with no submissions.
    assert 'UNKNOWN, not zero' in _msr.count([])['unmatched']
    # The result line renders, names the build, and carries every
    # denominator §7a asks for.
    _line = _msr.result_line({
        'build': 'F11', 'miner': _counts,
        'winning_chain': {'on_winning_chain': 1}})
    assert _line.startswith('miner_self_reject [F11]:'), _line
    for _fragment in ('submissions 3', 'replies 1 ok / 1 err / 1 missing',
                      'pow_failures 1', 'input_blocks_applied 1',
                      'on_winning_chain 1'):
        assert _fragment in _line, (_fragment, _line)
    assert 'NOT MEASURED' in _msr.result_line({'miner': _msr.count([])})

    # The REAL recipe file, rendered with the real overrides, has to parse
    # as TOML and carry the values the scenario asked for. A renderer
    # checked only against a toy template can still emit something the
    # node refuses to read — and the node refusing its config looks, from
    # the outside, exactly like a devnet that would not start.
    import tomllib

    # `evict` no longer overrides any bound — the fallback is forced by a
    # peer, not by starving a cache — so the renderer is exercised with
    # the overrides a three-node scenario does use.
    from scenarios import fork as fork_scenario
    real = render_rust_config((HERE / 'rust-node.toml').read_text(),
                              Path('/tmp/x/rust'), ['scala', 'rust'],
                              fork_scenario.RUST_OVERRIDES)
    parsed = tomllib.loads(real)
    assert parsed['data_dir'] == '/tmp/x/rust', parsed['data_dir']
    assert parsed['peers']['bind_addr'] == '127.0.0.1:19572', parsed['peers']
    assert parsed['peers']['known'] == ['127.0.0.1:19570'], parsed['peers']
    assert parsed['api']['bind'] == '127.0.0.1:19592', parsed['api']
    # Every override the scenario declares landed in the bounds table,
    # and the recipe file's own settings survived alongside them.
    assert parsed['peers']['per_ip_limit'] == 3, parsed['peers']
    assert parsed['peers']['per_subnet_limit'] == 6, parsed['peers']
    # The recipe file's own settings survive alongside the overrides.
    assert parsed['input_blocks']['bounds']['waitlist_entries'] == 8192, parsed
    # And an override for a key the recipe ALREADY sets replaces it
    # rather than appending a second copy.
    replaced = render_rust_config(
        (HERE / 'rust-node.toml').read_text(), Path('/tmp/x/rust'),
        ['scala', 'rust'],
        overrides=[('input_blocks.bounds', 'waitlist_entries', '7')])
    assert replaced.count('waitlist_entries') == 1, replaced
    assert tomllib.loads(replaced)['input_blocks']['bounds'][
        'waitlist_entries'] == 7, replaced
    # Untouched settings survive the render.
    assert parsed['input_blocks']['strict_field_binding'] is False, parsed
    assert parsed['mining']['enabled'] is False, parsed

    def smoke_series_keys():
        """The keys the sampler actually writes into a series sample."""
        import inspect

        import smoke as _smoke
        source = inspect.getsource(_smoke.Run._accumulate_agreement)
        return {line.split("'")[1] for line in source.splitlines()
                if line.strip().startswith("'") and "':" in line}

    # ----- the fork evaluator, which decides the `fork` scenario -----
    from scenarios import common

    def sample(ordering, rust, scala):
        return {'ordering': ordering, 'rust_chain': list(rust),
                'scala_chain': list(scala)}

    # A pure EXTENSION is not a fork switch.
    grew = [sample('O1', ['a'], ['a']), sample('O1', ['b', 'a'], ['b', 'a'])]
    assert common.fork_switches(grew, 'rust') == [], common.fork_switches(grew, 'rust')

    # Dropping a block that was on the chain IS one.
    switched = [sample('O1', ['b', 'a'], ['b', 'a']),
                sample('O1', ['c', 'a'], ['c', 'a'])]
    rust_switches = common.fork_switches(switched, 'rust')
    assert len(rust_switches) == 1, rust_switches
    assert rust_switches[0]['applied'] == ['c'], rust_switches
    assert rust_switches[0]['rolled_back'] == ['b'], rust_switches

    # A different ORDERING block is a different tree: the chains are not
    # comparable and the difference is not a rollback.
    moved_on = [sample('O1', ['b', 'a'], ['b', 'a']),
                sample('O2', ['z'], ['z'])]
    assert common.fork_switches(moved_on, 'rust') == [], \
        'a new ordering block is not a fork switch'

    # A switch onto a chain the miner never had matches no reference.
    invented = [sample('O1', ['b', 'a'], ['b', 'a']),
                sample('O1', ['x', 'a'], ['b', 'a'])]
    verdict = common.compare_fork_switches(invented)
    assert verdict['switches_matching_no_reference'], verdict

    # A rollback of a block Scala still holds is a switch Scala did not
    # make.
    unilateral = [sample('O1', ['b', 'a'], ['b', 'a']),
                  sample('O1', ['a'], ['b', 'a'])]
    verdict = common.compare_fork_switches(unilateral)
    assert verdict['rolled_back_blocks_still_held_by_a_miner'], verdict
    assert verdict['rolled_back_blocks_still_held_by_a_miner'][0]['block'] == 'b', \
        verdict
    assert verdict['single_miner_series'] is True, verdict

    # And a switch the miner made TOO — Scala dropped `b` by its last
    # sample — is lag, not a divergence.
    followed = [sample('O1', ['b', 'a'], ['b', 'a']),
                sample('O1', ['c', 'a'], ['c', 'a'])]
    verdict = common.compare_fork_switches(followed)
    assert verdict['switches_matching_no_reference'] == [], verdict
    assert verdict['rolled_back_blocks_still_held_by_a_miner'] == [], verdict

    # The whole-chain orphan check catches a block that is never a tip.
    orphan = [sample('O1', ['c', 'q', 'a'], ['c', 'b', 'a'])]  # q is mid-chain
    found, off = common.chain_members_scala_never_had(orphan)
    assert [o['block'] for o in found] == ['q'], found
    assert off == [], off
    # A block the reference DID publish, recorded by its tearing read
    # route under a neighbouring ordering id, is not invented — it is
    # counted separately. Keying the check by ordering id reported 66 of
    # these as invented in one run, and every one had been published.
    # `x` sits BELOW the tip, so the tip allowance does not cover it.
    torn = [sample('O1', [], ['x', 'seen']),
            sample('O2', ['tip', 'x'], ['tip', 'seen'])]
    found, off = common.chain_members_scala_never_had(torn)
    assert found == [], found
    assert [o['block'] for o in off] == ['x'], off
    # A sample where the two nodes name DIFFERENT ordering blocks is not
    # comparable and is skipped. The reference serves the chain of its
    # CURRENT best ordering block and nothing else, so a follower still
    # on the previous one lists blocks the reference will never list
    # again — one run's first sample had 120 of them.
    straddling = [{'ordering': None, 'rust_chain': ['a', 'b'],
                   'scala_chain': [], 'scala2_chain': []}]
    assert common.chain_members_scala_never_had(straddling) == ([], []), \
        'a sample straddling an ordering boundary decides nothing'
    # Chains are newest-first, so index 0 is the TIP, and a follower one
    # block ahead of the miner's published chain is assertion 2's
    # business (it grants that allowance explicitly), not this check's.
    ahead = [{'ordering': 'O1', 'rust_chain': ['tip', 'b', 'a'],
              'scala_chain': ['b', 'a'], 'scala2_chain': []}]
    assert common.chain_members_scala_never_had(ahead) == ([], []), \
        'a tip the miner has not published yet is lag, not an invented chain'
    # A sibling completed into the MIDDLE of the chain is exactly what
    # this check exists to catch, and it still is.
    middle = [{'ordering': 'O1', 'rust_chain': ['b', 'sneaked', 'a'],
               'scala_chain': ['b', 'a'], 'scala2_chain': []}]
    found, _ = common.chain_members_scala_never_had(middle)
    assert [o['block'] for o in found] == ['sneaked'], found
    assert found[0]['position'] == 1, found

    # ----- two miners: the follower is judged against BOTH -----
    #
    # With one reference chain, every block the follower took from the
    # OTHER miner reads as a block no miner ever had — 21,546 of them in
    # one run, not one of them a divergence.
    two = [{'ordering': 'O1', 'rust_chain': ['m2c', 'm2b', 'm2a'],
            'scala_chain': ['m1b', 'm1a'],
            'scala2_chain': ['m2c', 'm2b', 'm2a']}]
    assert common.reference_chain(two[0]) == {
        'm1a', 'm1b', 'm2a', 'm2b', 'm2c'}, common.reference_chain(two[0])
    assert common.chain_members_scala_never_had(two)[0] == [], \
        'a block the SECOND miner published is not an orphan'
    # And a block neither miner ever had still is.
    invented_two = [{'ordering': 'O1', 'rust_chain': ['m2a', 'zz'],
                     'scala_chain': ['m1a'], 'scala2_chain': ['m2a']}]
    assert [o['block'] for o in
            common.chain_members_scala_never_had(invented_two)[0]] == ['zz'], \
        'a block no miner published is still an orphan'
    # The sampler publishes the second chain under the name the
    # evaluators read; a rename would make the union silently empty.
    assert 'scala2_chain' in smoke_series_keys(), smoke_series_keys()

    # ----- the kill-state test the `restart` scenario turns on -----
    #
    # Three states, and the first two attempts each conflated a different
    # pair: a running process holds its data directory, a zombie holds
    # nothing, and a missing PID holds nothing. Getting the middle one
    # wrong aborted `restart` after a 60 s wait for a process that had
    # already exited.
    import subprocess as _sp
    probe = _sp.Popen(['sleep', '30'])
    assert _holds_resources(probe.pid), 'a running process holds its resources'
    os.kill(probe.pid, signal.SIGKILL)
    for _ in range(50):
        if not _holds_resources(probe.pid):
            break
        time.sleep(0.1)
    assert not _holds_resources(probe.pid), \
        'a SIGKILLed child must read as released, zombie or not'
    assert not _holds_resources(999_999), 'a missing PID holds nothing'

    # ----- finding 7: event loss is detected, not filtered away -----
    #
    # Codex's probe: the feed is a bounded ring; early fallbacks evicted
    # by later block and peer events leave only reconstructions and an
    # apparent 100 % rate, and filtering by sequence cannot tell that
    # from a window that genuinely had no fallbacks.
    class FakeCollector(common.EventCollector):
        """Replaces ONLY the network read. `poll` — the gap detection and
        retention under test — is the production method."""

        def __init__(self, pages):
            super().__init__(ctx=None)
            self.pages = list(pages)

        def _fetch_page(self):
            return self.pages.pop(0) if self.pages else []

    assert 'poll' not in FakeCollector.__dict__, \
        'the probe must drive the production poll, not a copy of it'

    def ev(seq, kind):
        return {'seq': seq, 'kind': kind}

    # The ring evicted 1-3 (two fallbacks among them) between polls.
    lossy = FakeCollector([
        [ev(1, 'ordering_reconstruct_fallback')],
        [ev(4, 'ordering_reconstructed'), ev(5, 'ordering_reconstructed')],
    ])
    lossy.poll()
    lossy.poll()
    assert lossy.lost_in_window(0), 'an eviction between polls must be detected'
    assert lossy.summary(0)['events_lost'] == 2, lossy.summary(0)
    # The old shape — ONE read at the end, filtered by sequence — sees
    # only the surviving page and reports a clean 100 %, with nothing to
    # say that two fallbacks were evicted.
    single_read = [ev(4, 'ordering_reconstructed'), ev(5, 'ordering_reconstructed')]
    assert all(e['kind'] == 'ordering_reconstructed' for e in single_read)
    assert lossy.summary(0)['events_lost'] == 2, \
        'incremental collection is what turns that into a detected loss'
    # Incremental collection also RETAINS the early fallback the single
    # read had already lost.
    assert any(e['kind'] == 'ordering_reconstruct_fallback'
               for e in lossy.window(0)), lossy.window(0)

    # Contiguous polling loses nothing, and keeps events the later page
    # no longer carries.
    whole = FakeCollector([
        [ev(1, 'ordering_reconstruct_fallback'), ev(2, 'ordering_reconstructed')],
        [ev(2, 'ordering_reconstructed'), ev(3, 'ordering_reconstructed')],
    ])
    whole.poll()
    whole.poll()
    assert whole.lost_in_window(0) == [], whole.gaps
    assert len(whole.window(0)) == 3, whole.window(0)
    assert whole.window(1)[0]['seq'] == 2, whole.window(1)
    # A gap entirely BEFORE the window does not condemn the window.
    assert lossy.lost_in_window(99) == [], lossy.lost_in_window(99)

    # ----- findings 3/4: peaks, and a missing counter stays UNKNOWN ---
    #
    # Codex's probe: the status route omits `staged_bytes` throughout,
    # the peak dict was seeded with zero for every key and merged over
    # the post-hoc reading, and `check_bounds`' missing-counter failure
    # was defeated. He reproduced the resulting no-failure verdict.
    class Recorder:
        def __init__(self):
            self.failures = []
            self.evidence = {}

        def fail(self, message, evidence=None, ids=None):
            self.failures.append(message)

        def note(self, key, value):
            self.evidence[key] = value

    caps = {'waitlist': 10, 'forks': 4, 'staged_bytes': 1024}

    missing = Recorder()
    common.check_bounds(missing, {'waitlist': 0, 'forks': 1,
                                  'staged_bytes': None}, caps, 'probe',
                        unavailable_bounds=('tx_cache_entries',))
    assert any('staged_bytes' in f and 'unknown, not zero' in f
               for f in missing.failures), missing.failures

    over = Recorder()
    common.check_bounds(over, {'waitlist': 11, 'forks': 1, 'staged_bytes': 0},
                        caps, 'probe')
    assert any('peaked at 11' in f for f in over.failures), over.failures

    clean = Recorder()
    result = common.check_bounds(clean, {'waitlist': 10, 'forks': 4,
                                         'staged_bytes': 1024}, caps, 'probe',
                                 unavailable_bounds=('trees_total',))
    assert clean.failures == [], clean.failures
    assert result['not_exposed_by_the_status_route'] == ['trees_total'], result
    assert all(v['status'] == 'measured' for v in result['checked'].values()), result

    # The peak sampler keeps the MAXIMUM across its window, and a key the
    # route never published stays None rather than becoming zero.
    class ScriptedSampler(common.PeakSampler):
        """Replaces ONLY the status read; `_observe` is production."""

        def __init__(self, readings):
            super().__init__(('waitlist', 'forks', 'staged_bytes'))
            self.readings = list(readings)

        def _read_status(self):
            return self.readings.pop(0)

    assert '_observe' not in ScriptedSampler.__dict__
    sampler = ScriptedSampler(({'waitlist': 3, 'forks': 1},
                               {'waitlist': 9, 'forks': 2},
                               {'waitlist': 1, 'forks': 1}))
    for _ in range(3):
        sampler._observe()
    assert sampler.peaks['waitlist'] == 9, sampler.peaks
    assert sampler.peaks['staged_bytes'] is None, \
        'a counter the route never published is UNKNOWN, not zero'
    summary = sampler.summary()
    assert summary['measured'] == ['forks', 'waitlist'], summary
    assert summary['never_published'] == ['staged_bytes'], summary
    # ...and that unknown fails, which is the whole point.
    drained = Recorder()
    common.check_bounds(drained, sampler.peaks, caps, 'probe')
    assert any('staged_bytes' in f for f in drained.failures), drained.failures

    # ----- finding 2: F6 is counted PER ORDERING BLOCK -----
    #
    # Codex's probe: an input-chain transaction is omitted and lost at
    # block 40. A6 ran once before the window, so its attribution stayed
    # clean and F6 read as zero — and because BOTH pools lost it, the
    # pool difference could never have shown it either.
    def blk(h, chain, ordering, rust_pool, scala_pool):
        return {'height': h, 'ordering_block': f'O{h}',
                'input_chain_txids': set(chain), 'ordering_txids': set(ordering),
                'rust_pool': set(rust_pool), 'scala_pool': set(scala_pool)}

    # Block 40 drops `lost` and neither pool has it, ever.
    window = [blk(h, ['keep'], ['keep'], [], []) for h in range(38, 40)]
    window.append(blk(40, ['keep', 'lost'], ['keep'], [], []))
    window += [blk(h, ['keep'], ['keep'], [], []) for h in range(41, 61)]
    f6 = common.evaluate_f6(window)
    assert f6['lost_on_both_total'] == 1, f6
    assert f6['lost_on_both_txids'] == ['lost'], f6
    assert f6['f6_total'] == 1, f6
    # The end-of-run pool DIFFERENCE is empty for the same series, which
    # is exactly why it could not see it.
    assert window[-1]['rust_pool'] ^ window[-1]['scala_pool'] == set()

    # Dropped but back in Rust's pool: neither F6 nor a loss.
    restored = [blk(1, ['a', 'b'], ['a'], ['b'], ['b'])]
    f6 = common.evaluate_f6(restored)
    assert f6['f6_total'] == 0 and f6['lost_on_both_total'] == 0, f6
    assert f6['blocks'][0]['returned_to_rust_pool'] == 1, f6['blocks']

    # Dropped, gone from Rust's pool, but confirmed by a LATER ordering
    # block: not F6 either — it was not lost, only deferred.
    deferred = [blk(1, ['a', 'b'], ['a'], [], []),
                blk(2, [], ['b'], [], [])]
    f6 = common.evaluate_f6(deferred)
    assert f6['f6_total'] == 0, f6
    assert f6['blocks'][0]['confirmed_by_another_block'] == 1, f6['blocks']

    # ...and confirmed by an EARLIER one is equally not a loss. Counting
    # only forward turned a chain still listing already-confirmed
    # transactions into 5,157 phantom losses over 60 blocks.
    already = [blk(1, [], ['a'], [], []),
               blk(2, ['a', 'b'], ['b'], [], [])]
    f6 = common.evaluate_f6(already)
    assert f6['f6_total'] == 0, f6
    assert f6['lost_on_both_total'] == 0, f6
    assert f6['blocks'][1]['confirmed_by_another_block'] == 1, f6['blocks']

    # Dropped, gone from Rust's pool, still in SCALA's: that is F6 (the
    # port reproducing the reference behaviour), and NOT a loss.
    port_only = [blk(1, ['a', 'b'], ['a'], [], ['b'])]
    f6 = common.evaluate_f6(port_only)
    assert f6['f6_total'] == 1 and f6['lost_on_both_total'] == 0, f6

    # ----- round 2: codex's reproduced false-pass probes -----
    #
    # Each drives the PRODUCTION evaluator. r2's note was that the
    # previous round's self-tests duplicated implementation logic.

    def rs(ordering, rust, s1=None, s2=None, o1=None, o2=None):
        return {'ordering': ordering, 'rust_chain': list(rust),
                'scala_chain': list(s1 or []), 'scala2_chain': list(s2 or []),
                'scala_ordering': o1 if o1 is not None else ordering,
                'scala2_ordering': o2 if o2 is not None else ordering}

    # (r2-1) Rust rolls back to the EMPTY chain while both miners keep
    # theirs. Inclusion accepted it vacuously; equality does not.
    empty_rollback = common.compare_fork_switches(
        [rs('O1', ['a'], ['a'], ['b']), rs('O1', [], ['a'], ['b'])])
    assert len(empty_rollback['rust_switches']) == 1, empty_rollback
    # It is reported as a RESET, not as a matched switch: no reference
    # publishes an empty chain, so there is no transition to compare it
    # against. `fork` fails on a reset it did not cause; the one thing
    # that must never happen is it passing silently.
    assert empty_rollback['resets_to_the_empty_chain'], empty_rollback
    assert empty_rollback['switches_matching_no_reference'] == [], empty_rollback
    reported = (empty_rollback['resets_to_the_empty_chain']
                + empty_rollback['switches_matching_no_reference'])
    assert len(reported) == 1, 'the rollback to nothing is reported exactly once'
    # And a switch onto a chain nobody published is still unmatched
    # rather than excused as a reset.
    invented_nonempty = common.compare_fork_switches(
        [rs('O1', ['b', 'a'], ['b', 'a'], ['z']),
         rs('O1', ['q', 'a'], ['b', 'a'], ['z'])])
    assert invented_nonempty['switches_matching_no_reference'], invented_nonempty
    assert invented_nonempty['resets_to_the_empty_chain'] == [], invented_nonempty
    # A genuine move between the two miners' exact chains still matches.
    genuine = common.compare_fork_switches(
        [rs('O1', ['m1b', 'm1a'], ['m1b', 'm1a'], ['m2b', 'm2a']),
         rs('O1', ['m2b', 'm2a'], ['m1b', 'm1a'], ['m2b', 'm2a'])])
    assert genuine['switches_matching_no_reference'] == [], genuine

    # (r2-2a) The snapshot an ordering block CLOSES.
    walker = common.WindowWalker(37)
    closed = {}
    walker.note_chain({'keep'})
    for h, snap in walker.observe(39):
        closed[h] = snap
    walker.note_chain({'keep', 'lost'})
    for h, snap in walker.observe(40):
        closed[h] = snap
    assert 'lost' in closed.get(40, set()), \
        'block 40 closes the chain observed before it landed'

    # (r2-2b) Restored one block later is not a permanent loss.
    def blk(h, chain, ordering, rp, sp):
        return {'height': h, 'ordering_block': f'O{h}',
                'input_chain_txids': set(chain), 'ordering_txids': set(ordering),
                'rust_pool': set(rp), 'scala_pool': set(sp)}

    restored_next = common.evaluate_f6(
        [blk(1, ['a', 'b'], ['a'], [], []), blk(2, [], ['x'], ['b'], ['b'])])
    assert restored_next['f6_total'] == 0, restored_next
    assert restored_next['lost_on_both_total'] == 0, restored_next
    # ...and a real loss on both nodes at block 40 still counts.
    window = [blk(h, ['keep'], ['keep'], [], []) for h in range(38, 40)]
    window.append(blk(40, ['keep', 'lost'], ['keep'], [], []))
    window += [blk(h, ['keep'], ['keep'], [], []) for h in range(41, 61)]
    both = common.evaluate_f6(window)
    assert both['lost_on_both_total'] == 1, both

    # (r2-2c) Per-block pool agreement, with attribution.
    unexplained = common.evaluate_pool_agreement([blk(40, [], [], [], ['x'])])
    assert unexplained['unexplained_total'] == 1, unexplained
    assert common.evaluate_pool_agreement(
        [blk(41, ['y'], [], [], ['y'])])['unexplained_total'] == 0
    assert common.evaluate_pool_agreement(
        [blk(42, [], [], [], ['z'])], d1_refusals={'z'})['unexplained_total'] == 0
    assert common.evaluate_pool_agreement(
        [blk(43, [], [], ['r'], [])])['unexplained_total'] == 1, \
        'residue in RUST\'s pool is explained by neither D1 nor F6'

    # (r2-5) A stale chain RELABELLED with the new ordering id.
    stale = common.evaluate_post_reorg_state(
        chain={'bestOrdering': 'new', 'bestInputBlocks': ['staletip', 's2']},
        info={'bestInputBlock': 'staletip', 'bestFullHeaderId': 'new'},
        status={'forks': 3, 'waitlist': 12, 'staged_bytes': 0,
                'deferred_triggers': 0},
        dropped={'old1', 'old2'}, miner_chain=['freshtip'])
    assert stale['problems'], 'a relabelled stale chain must not pass'
    assert any(p['what'] == 'tip_not_on_any_miner_chain_for_this_block'
               for p in stale['problems']), stale
    clean = common.evaluate_post_reorg_state(
        chain={'bestOrdering': 'new', 'bestInputBlocks': []},
        info={'bestInputBlock': '', 'bestFullHeaderId': 'new'},
        status={'forks': 0, 'waitlist': 0, 'staged_bytes': 0,
                'deferred_triggers': 0, 'retained_trees': []},
        dropped={'old1'}, miner_chain=[])
    assert clean['problems'] == [], clean
    unpublished = common.evaluate_post_reorg_state(
        chain={'bestOrdering': 'new', 'bestInputBlocks': []},
        info={'bestInputBlock': '', 'bestFullHeaderId': 'new'},
        status={'forks': 0, 'waitlist': 0, 'deferred_triggers': 0},
        dropped={'old1'})
    assert any(p['what'] == 'counter_not_published'
               for p in unpublished['problems']), unpublished

    # (r2-7) 96 outcomes for 100 ordering blocks.
    blocks = {h: f'H{h}' for h in range(1, 101)}
    short = common.reconcile_outcomes(blocks, [
        {'kind': 'ordering_reconstructed', 'headerId': f'H{h}', 'height': h}
        for h in range(1, 97)])
    assert len(short['missing']) == 4, short
    full = common.reconcile_outcomes(blocks, [
        {'kind': 'ordering_reconstruct_skipped', 'headerId': f'H{h}', 'height': h}
        for h in range(1, 101)])
    assert full['missing'] == [], full

    # ----- finding 1: codex's three fork false-pass probes -----
    #
    # All three were ACCEPTED by the union-membership evaluator: every
    # block in them had been published by somebody, which is not the
    # property. What is asserted is the HISTORY.

    def ref_sample(ordering, rust, s1=None, s2=None, o1=None, o2=None):
        return {'ordering': ordering, 'rust_chain': list(rust),
                'scala_chain': list(s1 or []), 'scala2_chain': list(s2 or []),
                'scala_ordering': o1 if o1 is not None else ordering,
                'scala2_ordering': o2 if o2 is not None else ordering}

    # (1a) an INVENTED, never-confirmed tip. Rust leads by one and no
    # reference ever publishes that block.
    invented_tip = [ref_sample('O1', ['ghost', 'b', 'a'], ['b', 'a'])] * 3
    v = common.evaluate_fork_coherence(invented_tip)
    assert v['unconfirmed_one_block_leads'], v
    assert v['incoherent_samples'] == [], v
    # The SAME shape, with the reference publishing it soon after, is the
    # documented one-block allowance and must still pass.
    confirmed_tip = [ref_sample('O1', ['t', 'b', 'a'], ['b', 'a']),
                     ref_sample('O1', ['t', 'b', 'a'], ['t', 'b', 'a'])]
    v = common.evaluate_fork_coherence(confirmed_tip)
    assert v['unconfirmed_one_block_leads'] == [], v
    assert v['incoherent_samples'] == [], v
    # ...but not if the confirmation is beyond the bound.
    far = ([ref_sample('O1', ['t', 'b', 'a'], ['b', 'a'])]
           * (common.LATER_CONFIRMATION_SAMPLES + 2)
           + [ref_sample('O1', ['t', 'b', 'a'], ['t', 'b', 'a'])])
    v = common.evaluate_fork_coherence(far)
    assert v['unconfirmed_one_block_leads'], 'later must be BOUNDED later'

    # (1b) a chain MIXING two incompatible branches. Every member was
    # published — `m1b` by miner 1, `m2a` by miner 2 — and the history
    # is one neither of them has.
    mixed = [ref_sample('O1', ['m1b', 'm2a'], ['m1b', 'm1a'], ['m2b', 'm2a'])]
    v = common.evaluate_fork_coherence(mixed)
    assert v['incoherent_samples'], 'a chain mixing two branches is not coherent'
    assert v['judged_samples'] == 1, v
    # Following either branch cleanly is fine.
    for clean in (['m1b', 'm1a'], ['m2b', 'm2a'], ['m2a']):
        v = common.evaluate_fork_coherence(
            [ref_sample('O1', clean, ['m1b', 'm1a'], ['m2b', 'm2a'])])
        assert v['incoherent_samples'] == [], (clean, v)

    # A chain a reference published a moment EARLIER, and has since moved
    # off, still vouches for a follower that has not caught up — with two
    # miners the other one may publish nothing under this ordering id at
    # this instant. Judging only against the same sample reported 17
    # disagreements in one run, every one of them this.
    lagging = [ref_sample('O1', [], [], ['m2b', 'm2a']),
               ref_sample('O1', ['m2b', 'm2a'], ['m1b', 'm1a'], [])]
    v = common.evaluate_fork_coherence(lagging)
    assert v['incoherent_samples'] == [], v
    # The window is not a loophole: a chain nobody published anywhere in
    # it still fails.
    never = [ref_sample('O1', [], [], ['m2b', 'm2a']),
             ref_sample('O1', ['zz', 'm2a'], ['m1b', 'm1a'], [])]
    v = common.evaluate_fork_coherence(never)
    assert v['incoherent_samples'], v
    # ...and so does a mix of two branches, wherever they were seen.
    mixed_window = [ref_sample('O1', [], [], ['m2b', 'm2a']),
                    ref_sample('O1', ['m1b', 'm2a'], ['m1b', 'm1a'], [])]
    v = common.evaluate_fork_coherence(mixed_window)
    assert v['incoherent_samples'], v

    # A reference on a DIFFERENT ordering block contributes nothing: its
    # chain must not be usable to excuse a follower chain under ours.
    elsewhere = [ref_sample('O1', ['m2a'], ['m1a'], ['m2a'], o2='O2')]
    v = common.evaluate_fork_coherence(elsewhere)
    assert v['incoherent_samples'], \
        "a reference on another ordering block cannot vouch for this chain"

    # (1c) Rust rolls back to an EMPTY chain while both miners keep
    # theirs. Nothing was applied, so "every applied block was
    # published" holds vacuously.
    to_empty = [ref_sample('O1', ['b', 'a'], ['b', 'a'], ['b', 'a']),
                ref_sample('O1', [], ['b', 'a'], ['b', 'a'])]
    v = common.compare_fork_switches(to_empty)
    assert len(v['rust_switches']) == 1, v['rust_switches']
    assert v['resets_to_the_empty_chain'], \
        'a rollback to nothing is reported as a reset, never silently accepted'
    # A genuine switch between the two miners' branches matches one.
    across = [ref_sample('O1', ['m1b', 'm1a'], ['m1b', 'm1a'], ['m2b', 'm2a']),
              ref_sample('O1', ['m2b', 'm2a'], ['m1b', 'm1a'], ['m2b', 'm2a'])]
    v = common.compare_fork_switches(across)
    assert len(v['rust_switches']) == 1, v['rust_switches']
    assert v['switches_matching_no_reference'] == [], v
    # And a switch onto a chain nobody has does not.
    invented_switch = [
        ref_sample('O1', ['m1b', 'm1a'], ['m1b', 'm1a'], ['m2b', 'm2a']),
        ref_sample('O1', ['zz', 'm1a'], ['m1b', 'm1a'], ['m2b', 'm2a'])]
    v = common.compare_fork_switches(invented_switch)
    assert v['switches_matching_no_reference'], v

    # ----- finding 10: the attempt cap is ENFORCED -----
    #
    # `--attempt` was unchecked metadata the runner set to 1 every time,
    # so reruns overwrote the canonical evidence until one passed.
    import tempfile
    global CAMPAIGN_WORK
    real_work = CAMPAIGN_WORK
    try:
        with tempfile.TemporaryDirectory() as tmp:
            CAMPAIGN_WORK = Path(tmp)
            assert read_attempts() == {}, 'a fresh campaign has no history'
            for expected in (1, 2, 3):
                assert check_attempt_cap('probe') == expected, expected
                record_attempt('probe', {'result': 'FAIL', 'failures': [
                    {'message': f'attempt {expected}'}]})
            history = read_attempts()['probe']
            assert [e['attempt'] for e in history] == [1, 2, 3], history
            # Every attempt's evidence is KEPT, not overwritten.
            assert len({e['evidence'] for e in history}) == 3, history
            for entry in history:
                assert Path(entry['evidence']).exists(), entry
            try:
                check_attempt_cap('probe')
            except SystemExit as error:
                assert 'cap is 3' in str(error), str(error)
            else:
                raise AssertionError('a fourth attempt must be refused')
            # ...unless the controller forces it, and the forced one is
            # still recorded as attempt 4 rather than silently reusing 3.
            assert check_attempt_cap('probe', force=True) == 4
            # A scenario with no history is unaffected by another's.
            assert check_attempt_cap('untouched') == 1
    finally:
        CAMPAIGN_WORK = real_work

    # ----- finding 6: an exception may not persist a PASS -----
    #
    # Through the PRODUCTION rule and the PRODUCTION driver: codex's r2
    # note was that the self-test duplicated the logic it claimed to
    # check, and the previous replacement only grepped the driver's
    # source. `run_scenario` itself is driven here, with fake node
    # modules, and made to fail at each point codex named.
    for aborted, failures, not_measured, expected in (
            (None, [], None, 'PASS'),
            (None, [{'message': 'x'}], None, 'FAIL'),
            (None, [], 'no reference', 'NOT MEASURED'),
            (None, [{'message': 'x'}], 'no reference', 'FAIL'),
            ('RuntimeError: rust did not become ready', [], None, 'ABORTED'),
            ('RuntimeError: boom', [{'message': 'x'}], 'y', 'ABORTED')):
        got = verdict_for(aborted, failures, not_measured)
        assert got == expected, (aborted, failures, not_measured, got, expected)
    _self_test_driver()
    _self_test_round_2()

    print('campaign self-test OK: rendering, ports and the scenario set')


def _fake_node_modules(work, calls, stop_raises=False, findings_raise=False):
    """A `lifecycle` and a `smoke` that start nothing and record what the
    driver asked of them — the driver under test is the real one."""
    import types

    import smoke as real_smoke

    lifecycle = types.ModuleType('lifecycle')
    lifecycle.SCALA_APP_VERSION = 'fake'
    lifecycle.node_binary = lambda: '/fake/ergo-node'
    lifecycle.classpath_file = lambda: Path('/fake/classpath')

    def start(names):
        calls.append(('start', tuple(names)))
        for name in names:
            (work / f'{name}.log').write_text(f'{name} log of this attempt\n')

    def stop(names=None):
        calls.append(('stop', names))
        if stop_raises:
            raise RuntimeError('a node would not stop')

    lifecycle.start, lifecycle.stop = start, stop

    smoke = types.ModuleType('smoke')
    smoke.Unavailable = real_smoke.Unavailable
    smoke.strip_ansi = real_smoke.strip_ansi
    smoke.ids_in = real_smoke.ids_in
    smoke.rust_log_lines = lambda match, limit=40: []
    smoke.check_sampler = lambda run, evidence: None

    def write_findings(run, evidence):
        if findings_raise:
            raise OSError('the findings directory is not writable')
        return []

    smoke.write_findings = write_findings

    class Run:
        def __init__(self, deadline):
            self.deadline = deadline
            self.failures, self.findings = [], []
            self.series_path = work / 'agreement-series.jsonl'
            self.samples = self.unavailable_samples = self.max_height_gap = 0
            self.peer_states, self.penalty_observations = set(), []

        def started(self, node):
            pass

        def start_sampling(self):
            self.series_path.write_text('{"sample": "of this attempt"}\n')

        def stop_sampling(self):
            pass

        def totals(self):
            return {}

        def fail(self, assertion, message, evidence=None, ids=None):
            self.failures.append({'assertion': assertion, 'message': message})

    smoke.Run = Run
    return lifecycle, smoke


def _drive(name, scenario_run, tmp, **faults):
    """Run the REAL `run_scenario` once against fake node modules."""
    import types

    from scenarios import SCENARIOS
    global CAMPAIGN_WORK, CONF, WORK
    saved = (CAMPAIGN_WORK, CONF, WORK)
    CAMPAIGN_WORK, CONF, WORK = tmp / 'campaign', tmp / 'campaign' / 'conf', tmp / 'work'
    WORK.mkdir(parents=True, exist_ok=True)
    calls = []
    fake_lifecycle, fake_smoke = _fake_node_modules(WORK, calls, **faults)
    module = types.ModuleType(f'fake_{name}')
    module.__doc__ = 'A probe scenario.'
    module.NODES = SCENARIO_NODES[name]
    module.run = scenario_run
    real_modules = {k: sys.modules.get(k) for k in ('lifecycle', 'smoke')}
    real_scenario = SCENARIOS[name]
    sys.modules['lifecycle'], sys.modules['smoke'] = fake_lifecycle, fake_smoke
    SCENARIOS[name] = module
    raised = None
    try:
        args = types.SimpleNamespace(attempt=check_attempt_cap(name), fresh=False,
                                     timeout=5, ordering_blocks=None)
        try:
            evidence = run_scenario(name, args)
        except BaseException as error:  # noqa: BLE001 — the probe inspects it
            raised = error
            evidence = json.loads((CAMPAIGN_WORK / f'{name}.json').read_text())
        return evidence, calls, raised, read_attempts()
    finally:
        SCENARIOS[name] = real_scenario
        for key, value in real_modules.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value
        CAMPAIGN_WORK, CONF, WORK = saved


def _self_test_driver():
    """Findings 6 and 10, through the production driver."""
    import tempfile

    def stopped(calls):
        return any(c[0] == 'stop' and c[1] is None for c in calls)

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        # A clean run passes, and stops its nodes.
        evidence, calls, raised, _ = _drive('steady', lambda ctx: None, tmp / 'clean')
        assert raised is None and evidence['result'] == 'PASS', evidence['result']
        assert stopped(calls), calls

        # Evidence collection throws AFTER the scenario body succeeded —
        # the shape codex named: it used to bypass node shutdown and
        # leave a saved PASS. ABORTED, and the nodes are stopped.
        evidence, calls, raised, history = _drive(
            'steady', lambda ctx: None, tmp / 'save', findings_raise=True)
        assert evidence['result'] == 'ABORTED', evidence['result']
        assert 'findings directory' in (evidence['aborted'] or ''), evidence['aborted']
        assert stopped(calls), 'a failure in evidence collection must not skip shutdown'
        assert history['steady'][-1]['result'] == 'ABORTED', history

        # Shutdown itself fails after a clean scenario body: ABORTED,
        # never PASS.
        evidence, calls, raised, _ = _drive(
            'steady', lambda ctx: None, tmp / 'stop', stop_raises=True)
        assert evidence['result'] == 'ABORTED', evidence['result']
        assert 'would not stop' in evidence['shutdown_error'], evidence

        # The scenario body throws: ABORTED, nodes stopped, re-raised.
        def boom(ctx):
            raise RuntimeError('rust did not become ready')
        evidence, calls, raised, _ = _drive('steady', boom, tmp / 'boom')
        assert isinstance(raised, RuntimeError), raised
        assert evidence['result'] == 'ABORTED', evidence['result']
        assert stopped(calls), calls

        # Finding 10: two attempts of one scenario, and each attempt's
        # verdict file names logs and a series that IT wrote and that
        # the later attempt did not replace.
        _drive('fork', lambda ctx: None, tmp / 'two')
        _, _, _, history = _drive('fork', lambda ctx: None, tmp / 'two')
        entries = history['fork']
        assert [e['attempt'] for e in entries] == [1, 2], entries
        named = []
        for entry in entries:
            kept = json.loads(Path(entry['evidence']).read_text())
            files = list(kept['logs'].values()) + [kept['series_file']]
            for path in files:
                assert Path(path).exists(), (entry['attempt'], path)
                assert f"-{entry['attempt']}" in Path(path).name, (entry, path)
            named.append(set(files))
        assert not (named[0] & named[1]), \
            'an attempt must never name evidence another attempt wrote'


def _self_test_round_2():
    """Round 2's probes, each through the production code path."""
    import tempfile
    import types

    from scenarios import common
    import smoke as real_smoke

    def rs(o, rust, s1=(), s2=()):
        return {'ordering': o, 'rust_chain': list(rust), 'scala_chain': list(s1),
                'scala2_chain': list(s2), 'scala_ordering': o, 'scala2_ordering': o}

    # fork: a run whose ONLY switch is the follower restart's reset has
    # not observed a fork switch.
    reset_only = common.compare_fork_switches(
        [rs('O1', ['a'], ['a'], ['b']), rs('O1', [], ['a'], ['b'])])
    judged = common.judge_fork_switches(reset_only, range(0, 50))
    assert judged['genuine_switches'] == 0, judged
    assert judged['qualifier'] == 'NOT ESTABLISHED', judged
    assert any('no genuine' in m for m, _ in judged['failures']), judged
    # ...and the reset itself, inside the restart window, is not a failure.
    assert judged['resets_caused'] and not judged['resets_uncaused'], judged
    across = common.compare_fork_switches(
        [rs('O1', ['m1b', 'm1a'], ['m1b', 'm1a'], ['m2b', 'm2a']),
         rs('O1', ['m2b', 'm2a'], ['m1b', 'm1a'], ['m2b', 'm2a'])])
    judged = common.judge_fork_switches(across, range(0))
    assert judged['failures'] == [] and judged['genuine_switches'] == 1, judged
    elsewhere = common.judge_fork_switches(reset_only, range(100, 200))
    assert any('outside the restart' in m for m, _ in elsewhere['failures']), elsewhere

    # steady: a block that landed in the same reading as the one before
    # it closed a tree nobody sampled — unread, not an empty chain.
    walker = common.WindowWalker(10)
    walker.note_chain({'t'})
    assert walker.observe(12) == [(11, {'t'}), (12, None)]
    walker.note_chain(set())
    assert walker.observe(13) == [(13, set())], 'an EMPTY reading is a reading'

    # rollback: a reorg the RESTARTED follower emitted is not hidden by a
    # watermark from the process before the restart.
    events = [{'seq': s, 'kind': k} for s, k in
              ((1, 'peerConnected'), (2, 'blockApplied'), (3, 'reorg'))]
    assert common.events_after(events, 400) == [], 'the old filter hid it'
    assert [e['kind'] for e in common.follower_events_since(events, 400, True)
            if e['kind'] == 'reorg'] == ['reorg']
    assert common.follower_events_since(events, 2, False) == [events[2]]

    # rollback: a stale tip relabelled with the new ordering id, with no
    # miner chain to compare against, is unknown — not a pass.
    stale = common.evaluate_post_reorg_state(
        chain={'bestOrdering': 'new', 'bestInputBlocks': ['staletip']},
        info={'bestInputBlock': 'staletip', 'bestFullHeaderId': 'new'},
        status={'forks': 1, 'waitlist': 0, 'staged_bytes': 0, 'deferred_triggers': 0,
                'retained_trees': []},
        dropped={'old'}, miner_chain=None)
    assert [p['what'] for p in stale['problems']] == [
        'tip_not_compared_against_a_miner_chain'], stale
    cleared = common.evaluate_post_reorg_state(
        chain={'bestOrdering': 'new', 'bestInputBlocks': []},
        info={'bestInputBlock': '', 'bestFullHeaderId': 'new'},
        status={'forks': 0, 'waitlist': 0, 'staged_bytes': 0, 'deferred_triggers': 0,
                'retained_trees': []},
        dropped={'old'}, miner_chain=None)
    assert cleared['problems'] == [], 'a CLEARED tip needs no miner chain'

    # rollback/fork/reconstruct_rate: restarting the follower clears the
    # dial backoff its address book persisted, BEFORE it starts again.
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        (root / 'rust').mkdir()
        (root / 'rust' / 'peers.redb').write_text('persisted backoff')
        (root / 'rust' / 'chain.redb').write_text('the chain')
        calls, notes = [], {}
        fake = types.SimpleNamespace(
            stop=lambda names=None: calls.append(('stop', names)),
            spawn=lambda name: calls.append(
                ('spawn', name, (root / 'rust' / 'peers.redb').exists())))
        ctx = types.SimpleNamespace(
            data_root=root, run=types.SimpleNamespace(started=lambda n: None),
            note=lambda k, v: notes.__setitem__(k, v))
        common.restart_follower(ctx, sys.modules[__name__], fake)
        assert calls == [('stop', ('rust',)), ('spawn', 'rust', False)], calls
        assert (root / 'rust' / 'chain.redb').exists(), 'only the address book goes'

    # reconstruct_rate: 96 outcomes for 100 blocks FAILS when all 100
    # were announced; blocks the follower was provably never announced
    # are attributed, not excused wholesale; an unread height is missing.
    blocks = {h: f'H{h}' for h in range(1, 101)}
    outcomes = [{'kind': 'ordering_reconstructed', 'headerId': f'H{h}', 'height': h}
                for h in range(1, 97)]
    everything = set(blocks.values())
    assert len(common.reconcile_outcomes(blocks, outcomes, announced=everything)
               ['missing']) == 4
    partly = common.reconcile_outcomes(
        blocks, outcomes, announced={f'H{h}' for h in range(1, 99)})
    assert [m['height'] for m in partly['missing']] == [97, 98], partly['missing']
    assert [m['height'] for m in partly['not_announced']] == [99, 100], partly
    assert len(common.reconcile_outcomes(blocks, outcomes)['missing']) == 4, \
        'with no announcement evidence nothing is attributed'
    unread = common.reconcile_outcomes({}, [], announced=set(), unread_heights=[7])
    assert unread['missing'] == [{'height': 7, 'header': None,
                                  'why': 'the reference could not be read at this height'}]
    assert common.announced_headers('nothing relevant\n') is None, \
        'a log without the TRACE line is no evidence, not "never announced"'
    line = f"x {common.ANNOUNCEMENT_LINE} block={'ab' * 32} payload=00"
    assert common.announced_headers(line) == {'ab' * 32}

    # UTXO watch: the FIRST resolving id is the input block; a later
    # candidate is recorded beside it, never over it; an `unavailable`
    # string is not a lookup.
    def fake_smoke(api):
        return types.SimpleNamespace(
            ids_in=lambda line: ['a' * 64, 'b' * 64, 'c' * 64],
            Unavailable=real_smoke.Unavailable, api=api,
            strip_ansi=real_smoke.strip_ansi,
            announcement_hex_for=lambda ids, window: {},
            rust_log_window=lambda t: [])

    def resolves(node, route):
        if route.startswith('/blocks/' + 'a' * 64) or route.startswith('/blocks/' + 'c' * 64):
            return ['tx']
        if route.startswith('/blocks/' + 'b' * 64):
            raise real_smoke.Unavailable('route down')
        return None

    real = sys.modules['smoke']
    sys.modules['smoke'] = fake_smoke(resolves)
    try:
        probe_ctx = types.SimpleNamespace(
            utxo_validation_failures=[], evidence={},
            run=types.SimpleNamespace(fail=lambda *a, **k: None))
        got = capture_utxo_validation_failure(probe_ctx, 'input box not found in UTXO set')
        assert got['input_block']['id'] == 'a' * 64, got['input_block']
        assert got['also_resolved'] == ['c' * 64], got

        # ...and it is drained LIVE, by the watch thread, with no
        # scenario loop calling anything — the flood-delivery shape.
        with tempfile.TemporaryDirectory() as raw:
            log = Path(raw) / 'rust.log'
            log.write_text('boot\n')
            watch = UtxoWatch(probe_ctx, log_path=log, interval=0.05).start()
            with log.open('a') as handle:
                handle.write('\x1b[2mERROR ValidationFailed: input box not found '
                             'in UTXO set\x1b[0m\n')
            for _ in range(100):
                if len(probe_ctx.utxo_validation_failures) >= 2:
                    break
                time.sleep(0.05)
            # Captured by the THREAD, before `stop()`'s final pass could
            # have done it.
            assert len(probe_ctx.utxo_validation_failures) == 2, \
                'the live watch must capture the line while the nodes run'
            watch.stop()
            live = probe_ctx.utxo_validation_failures[-1]
            assert live['input_block']['id'] == 'a' * 64, live
            assert live.get('state_captured') is not False, live
            # The same line is captured once, however often it is scanned.
            watch.scan()
            assert len(probe_ctx.utxo_validation_failures) == 2
    finally:
        sys.modules['smoke'] = real

    # steady: a payment submitted to the miner moments before a reading,
    # and PROVEN to reach the follower afterwards, is relay lag at that
    # instant; one that never arrives is still a disagreement.
    def pb(h, ordering, rp, sp, read_at):
        return {'height': h, 'input_chain_txids': set(), 'ordering_txids': set(ordering),
                'rust_pool': set(rp), 'scala_pool': set(sp), 'read_at': read_at}
    lag = common.evaluate_pool_agreement(
        [pb(25, [], [], ['p'], 1000.0), pb(26, ['p'], [], [], 1030.0)],
        submitted_at={'p': 998.0})
    assert lag['unexplained_total'] == 0 and lag['blocks'][0]['propagating'] == ['p'], lag
    never = common.evaluate_pool_agreement(
        [pb(25, [], [], ['q'], 1000.0), pb(26, [], [], [], 1030.0)],
        submitted_at={'q': 998.0})
    assert never['unexplained_total'] == 1, 'a payment that never arrives is not lag'
    stale = common.evaluate_pool_agreement(
        [pb(25, [], [], ['r'], 1000.0), pb(26, ['r'], [], [], 1030.0)],
        submitted_at={'r': 1000.0 - common.PROPAGATION_SECONDS - 1})
    assert stale['unexplained_total'] == 1, 'the window is bounded'

    # evict: delivery is the NODE's receipt, and a fallback is caused by
    # the adversary only when it rebuilds a poisoned tree.
    stdout = ('[wrong_body] pushed id=' + 'a' * 64 + ' ordering=' + 'o' * 64 + '\n'
              '[wrong_body] pushed id=' + 'b' * 64 + ' ordering=relayed\n'
              '[wrong_body] relayed 0, pushed 2 ...\n')
    pushed = common.parse_pushed_bodies(stdout)
    assert pushed == [{'id': 'a' * 64, 'ordering': 'o' * 64},
                      {'id': 'b' * 64, 'ordering': None}], pushed
    receipts = common.wrong_body_receipts(
        [f"DEBUG {common.BODIES_RECEIVED_LINE} peer=127.211.0.1:40000 block={'a' * 64}",
         f"DEBUG {common.BODIES_RECEIVED_LINE} peer=127.0.0.1:19570 block={'b' * 64}"],
        '127.211.0.1', ['a' * 64, 'b' * 64])
    assert list(receipts) == ['a' * 64], 'a body from ANOTHER peer is not delivery'
    # EVICT (r3): nothing is ever attributed to the adversary. A NATURAL
    # mismatch after an ignored decoy — even under the very ordering
    # parent a body was pushed under — leaves the verdict NOT ESTABLISHED.
    natural = [{'kind': 'ordering_reconstruct_fallback', 'detail': 'root_mismatch',
                'headerId': 'H'}]
    assert not hasattr(common, 'attribute_wrong_body_fallbacks'), \
        'the parent-based attribution must not come back'
    failures, notes = common.evict_verdict(pushed[:1], receipts, natural)
    assert len(failures) == 1 and failures[0][0].startswith('NOT ESTABLISHED'), failures
    assert 'not attributed to the adversary' in failures[0][0], failures
    assert notes['mismatch_fallbacks_all_natural'] == 1, notes
    assert 'search_staging' in failures[0][0] and 'on_bodies' in failures[0][0]
    # No delivery -> a plain failure, not NOT ESTABLISHED.
    undelivered, _ = common.evict_verdict(pushed[:1], {}, natural)
    assert 'delivery is not established' in undelivered[0][0], undelivered
    nothing, _ = common.evict_verdict([], {}, [])
    assert 'pushed no wrong body' in nothing[0][0], nothing

    _self_test_round_3()


def _self_test_round_3():
    """Codex's r3 probes, through the production code."""
    import tempfile

    from scenarios import common

    # (5) a completed tree kept under an ABANDONED ordering id, every
    # counter clean. `forks` answers for the current tip only, so only
    # the per-ordering `retained_trees` list can show it.
    clean_counters = {'forks': 0, 'waitlist': 0, 'staged_bytes': 0,
                      'deferred_triggers': 0}
    base = dict(chain={'bestOrdering': 'new', 'bestInputBlocks': []},
                info={'bestInputBlock': '', 'bestFullHeaderId': 'new'},
                dropped={'old'}, miner_chain=[])
    kept = common.evaluate_post_reorg_state(
        status={**clean_counters, 'retained_trees': [
            {'ordering_id': 'old', 'height': 8, 'tree': True, 'forks': 1, 'records': 4}]},
        on_chain={'new'}, **base)
    assert [p['what'] for p in kept['problems']] == [
        'tree_retained_under_an_off_chain_ordering_id'], kept['problems']
    # Off the best chain but NOT in the reorg's dropped list: still caught.
    side = common.evaluate_post_reorg_state(
        status={**clean_counters, 'retained_trees': [
            {'ordering_id': 'side', 'height': 9, 'tree': True, 'forks': 1, 'records': 1}]},
        on_chain={'new'}, **base)
    assert side['problems'][0]['what'] == 'tree_retained_under_an_off_chain_ordering_id'
    # A tree under the surviving chain, and records (no tree) under the
    # dropped id inside the pruning window, are fine — the latter reported.
    fine = common.evaluate_post_reorg_state(
        status={**clean_counters, 'retained_trees': [
            {'ordering_id': 'new', 'height': 10, 'tree': True, 'forks': 1, 'records': 2},
            {'ordering_id': 'old', 'height': 8, 'tree': False, 'forks': 0, 'records': 4}]},
        on_chain={'new'}, **base)
    assert fine['problems'] == [], fine['problems']
    assert len(fine['observed']['records_under_off_chain_ordering_ids']) == 1
    # A route that does not publish the list is unknown, not clean.
    unpublished = common.evaluate_post_reorg_state(
        status=dict(clean_counters), on_chain={'new'}, **base)
    assert {'what': 'counter_not_published', 'counter': 'retained_trees'} in \
        unpublished['problems'], unpublished['problems']

    # (6) codex's injection: attempt recording raises after a clean run.
    # The persisted verdict must be ABORTED, and the nodes stopped.
    real_record = globals()['record_attempt']

    def failing_record(name, evidence):
        raise OSError('attempts.json is not writable')

    globals()['record_attempt'] = failing_record
    try:
        with tempfile.TemporaryDirectory() as raw:
            evidence, calls, raised, _ = _drive('steady', lambda ctx: None, Path(raw))
    finally:
        globals()['record_attempt'] = real_record
    assert isinstance(raised, OSError), raised
    assert evidence['result'] == 'ABORTED', (evidence['status'], evidence['result'])
    assert evidence['status'] != 'DONE', evidence['status']
    assert 'could not be recorded' in evidence['aborted'], evidence['aborted']
    assert any(c[0] == 'stop' and c[1] is None for c in calls), calls
    # ...and without the fault the real verdict is the LAST thing written.
    with tempfile.TemporaryDirectory() as raw:
        evidence, _, raised, history = _drive('steady', lambda ctx: None, Path(raw))
    assert raised is None and (evidence['status'], evidence['result']) == ('DONE', 'PASS')
    assert 'verdict_pending' not in evidence
    assert history['steady'][-1]['result'] == 'PASS', history

    # (6, r4) codex's probe: the HISTORY write fails inside
    # `record_attempt`. Both the canonical verdict and the attempt
    # artifact must be ABORTED — the artifact used to be written DONE/PASS
    # before the history write was attempted.
    real_history = globals().get('_write_history')

    def failing_history(history):
        raise OSError('attempts.json: disk full')

    globals()['_write_history'] = failing_history
    try:
        with tempfile.TemporaryDirectory() as raw:
            evidence, _, raised, _ = _drive('steady', lambda ctx: None, Path(raw))
            artifacts = sorted((Path(raw) / 'campaign' / 'attempts').glob('steady-*.json'))
            artifact = json.loads(artifacts[0].read_text()) if artifacts else None
    finally:
        if real_history is None:
            globals().pop('_write_history', None)
        else:
            globals()['_write_history'] = real_history
    assert isinstance(raised, OSError), raised
    assert evidence['result'] == 'ABORTED', (evidence['status'], evidence['result'])
    assert artifact is not None, 'the attempt artifact is written ABORTED first'
    assert (artifact['status'], artifact['result']) != ('DONE', 'PASS'), artifact['result']
    assert artifact['result'] == 'ABORTED', (artifact['status'], artifact['result'])

    # (6, r5) codex's probe: the FINAL overwrite of the attempt artifact
    # fails PART-WAY. A truncating write left unparsable JSON while the
    # history said PASS; the atomic replace leaves the ABORTED
    # placeholder intact and parseable.
    real_bytes = globals()['_write_bytes']
    seen = {'attempt_writes': 0}

    def partial_bytes(handle, data, path):
        if path.parent.name == 'attempts' and b'"status": "DONE"' in data:
            seen['attempt_writes'] += 1
            handle.write(data[:len(data) // 2])
            raise OSError('disk full mid-write')
        return real_bytes(handle, data, path)

    globals()['_write_bytes'] = partial_bytes
    try:
        with tempfile.TemporaryDirectory() as raw:
            evidence, _, raised, _ = _drive('steady', lambda ctx: None, Path(raw))
            attempts_dir = Path(raw) / 'campaign' / 'attempts'
            artifact = json.loads(next(attempts_dir.glob('steady-*.json')).read_text())
            leftovers = list(attempts_dir.glob('.*.tmp'))
    finally:
        globals()['_write_bytes'] = real_bytes
    assert seen['attempt_writes'] == 1, 'the failure must hit the FINAL attempt write'
    assert isinstance(raised, OSError), raised
    assert evidence['result'] == 'ABORTED', evidence['result']
    assert (artifact['status'], artifact['result']) == ('FINALIZING', 'ABORTED'), \
        (artifact['status'], artifact['result'])
    assert leftovers == [], leftovers

    # (7) codex's probe: an outcome for a DIFFERENT header at the expected
    # height is unmatched, and the block is missing.
    wrong = common.reconcile_outcomes({30: 'H30'}, [
        {'kind': 'ordering_reconstructed', 'headerId': 'OTHER', 'height': 30}],
        announced={'H30'})
    assert [m['header'] for m in wrong['missing']] == ['H30'], wrong
    assert wrong['with_an_outcome'] == 0, wrong
    assert wrong['unmatched_events'] == 1 and wrong['unmatched'][0]['header'] == 'OTHER'
    assert wrong['unmatched'][0]['announced'] is False, \
        'checked against the announcement set, not the events themselves'
    # An outcome with no header at all is unmatched too.
    anon = common.reconcile_outcomes({30: 'H30'}, [
        {'kind': 'ordering_reconstructed', 'headerId': 'H30', 'height': 30},
        {'kind': 'ordering_reconstruct_skipped', 'height': 31}], announced={'H30'})
    assert anon['missing'] == [] and anon['unmatched_events'] == 1, anon
    # The block just outside the window is not unmatched.
    edge = common.reconcile_outcomes({30: 'H30'}, [
        {'kind': 'ordering_reconstructed', 'headerId': 'H30', 'height': 30},
        {'kind': 'ordering_reconstructed', 'headerId': 'H29', 'height': 29}],
        announced={'H30', 'H29'}, adjacent_headers={'H29'})
    assert edge['unmatched'] == [] and edge['outcomes_for_adjacent_blocks'] == 1, edge


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', help='one scenario name, or "all"')
    parser.add_argument('--timeout', type=int, default=9000,
                        help='per-scenario polling budget, seconds')
    parser.add_argument('--ordering-blocks', type=int, default=None,
                        help='override the scenario\'s own block budget')
    parser.add_argument('--fresh', action='store_true',
                        help='delete the scenario\'s data directories first')
    parser.add_argument('--attempt', type=int, default=None,
                        help='informational; the real number comes from the '
                             'attempt history and the cap is enforced against it')
    parser.add_argument('--force-attempt', action='store_true',
                        help='run past the three-attempt cap (controller ruling '
                             'required — say why in the report)')
    parser.add_argument('--build', default='stock',
                        help='the provisioned Scala build every *_patched '
                             'role runs (scripts/devnet-matrix/builds.toml); '
                             'every other Scala role stays on stock, so a run '
                             'is base+one-patch vs base')
    parser.add_argument('--reference-follower', default=None,
                        choices=('stock', 'patched', 'both'),
                        help='which Scala reference follower(s) to run beside '
                             'the Rust one; accepted by '
                             + ', '.join(REFERENCE_FOLLOWER_SCENARIOS))
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        sys.path.insert(0, str(HERE))
        _self_test()
        return 0
    if not args.scenario:
        parser.error('--scenario is required (or --self-test)')

    sys.path.insert(0, str(HERE))
    # Refused HERE rather than at the first spawn: an unknown build must
    # not start a devnet, and a declared-but-unprovisioned one must say
    # what would provision it. The resolved port band is checked in the
    # same breath, for the same reason.
    check_band(CAMPAIGN_P2P, CAMPAIGN_REST)
    check_build(args.build)
    names = list(ORDER) if args.scenario == 'all' else [args.scenario]
    # The node set is fixed for the whole process: `lifecycle.REST` and
    # `smoke.URLS` are read at import time, so one process drives one
    # node set. `--scenario all` therefore re-execs itself per scenario.
    if len(names) > 1:
        failures = []
        for name in names:
            result = subprocess.run(
                [sys.executable, str(HERE / 'campaign.py'), '--scenario', name,
                 '--timeout', str(args.timeout)]
                + ['--build', args.build]
                + (['--reference-follower', args.reference_follower]
                   if args.reference_follower else [])
                + (['--fresh'] if args.fresh else [])
                + (['--force-attempt'] if args.force_attempt else []), cwd=ROOT)
            if result.returncode != 0:
                failures.append(name)
        print('campaign:', 'FAIL ' + ','.join(failures) if failures else 'PASS')
        return 1 if failures else 0

    name = names[0]
    if name not in SCENARIO_NODES:
        parser.error(f'unknown scenario {name!r}; have {sorted(SCENARIO_NODES)}')
    # BEFORE the scenario module — and therefore before `smoke` — is
    # imported: `smoke.URLS` is frozen at its import.
    role_set = resolve_roles(name, args.reference_follower)
    configure_environment(name, nodes_for_roles(role_set), role_set, args.build)
    # Enforced BEFORE anything is started: a refused attempt must not
    # leave a devnet running or overwrite the canonical evidence.
    args.attempt = check_attempt_cap(name, force=args.force_attempt)
    evidence = run_scenario(name, args)
    print(f'{name}: {evidence["result"]} '
          f'({len(evidence.get("divergences") or [])} divergences, '
          f'{evidence.get("samples")} samples)')
    # A measurement scenario's one line, printed beside its verdict.
    if evidence.get('result_line'):
        print('  ' + evidence['result_line'])
    for failure in evidence.get('failures') or []:
        print(f'  - {failure["message"]}')
    for entry in evidence.get('not_measured') or []:
        print(f'  ~ NOT MEASURED: {entry["message"]}')
    # NOT MEASURED is not a pass, and it is not an error the runner
    # should treat as a broken scenario either: it exits 0 with the
    # verdict on the line above, so a campaign does not abort on a
    # limitation of the host.
    return 0 if evidence['result'] in ('PASS', 'NOT MEASURED') else 1


if __name__ == '__main__':
    os.chdir(ROOT)
    sys.path.insert(0, str(HERE))
    raise SystemExit(main())
