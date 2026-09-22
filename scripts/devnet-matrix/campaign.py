#!/usr/bin/env python3
"""The M3 Matrix (input blocks) devnet campaign (plan 2 task 9, spec §12).

Seven scenarios drive the Rust follower against the pinned Scala
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

Every scenario writes `.work/campaign/<scenario>.json`, records
divergences as artifacts under `.work/findings/`, and NEVER absorbs one:
an observation that could not be made fails the scenario rather than
passing quietly. The evaluators are smoke.py's — this module reuses
them rather than writing weaker per-scenario versions.

Ports are the campaign's own (19570-19572 p2p, 19590-19592 REST) so a
smoke run in another worktree can proceed concurrently.
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
import time

# The node set and its ports have to be decided BEFORE `lifecycle` is
# imported: `lifecycle.P2P` / `REST` are read at import time and
# `smoke.URLS` is derived from them at ITS import time. Setting them here
# keeps the campaign a single command rather than a command plus six
# environment variables a reader has to get right.
CAMPAIGN_P2P = {'scala': 19570, 'scala2': 19571, 'rust': 19572}
CAMPAIGN_REST = {'scala': 19590, 'scala2': 19591, 'rust': 19592}

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
                     'rust': '127.0.0.1'}

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
SCALA2_ROLE = {
    'fork': 'miner',
    'rollback': 'miner',
    'reconstruct_rate': 'follower',
}

# A second Scala node that must NOT mine. Without this it would race the
# first miner and `reconstruct_rate` would be a two-miner scenario by
# accident.
SCALA2_FOLLOWER_EXTRA = (
    'ergo.node.mining = false\n'
    'ergo.node.offlineGeneration = false\n'
)

# The order `--scenario all` runs them in: cheapest and most diagnostic
# first, so a broken build is caught in minutes rather than after the
# 100-block reconstruction measurement.
ORDER = ('steady', 'restart', 'evict', 'fork', 'rollback', 'flood',
         'reconstruct_rate')

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
}


def configure_environment(scenario, nodes):
    """Point `lifecycle` at this campaign's ports, configs and data dirs."""
    os.environ['MATRIX_NODES'] = ','.join(nodes)
    for name in nodes:
        os.environ[f'MATRIX_P2P_{name.upper()}'] = str(CAMPAIGN_P2P[name])
        os.environ[f'MATRIX_REST_{name.upper()}'] = str(CAMPAIGN_REST[name])
        os.environ[f'MATRIX_P2P_HOST_{name.upper()}'] = CAMPAIGN_P2P_HOST[name]


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


def write_configs(scenario, nodes, rust_overrides=(), scala_extra='',
                  scala2_extra=''):
    """Render every node's config for one scenario and point `lifecycle`
    at them. Returns the scenario's data directory."""
    CONF.mkdir(parents=True, exist_ok=True)
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
                extra=scala_extra if node == 'scala' else scala2_extra))
            os.environ[{'scala': 'SCALA_CONFIG',
                        'scala2': 'SCALA2_CONFIG'}[node]] = str(path)
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

    def __init__(self, scenario, run, evidence, args, nodes, data_root):
        self.scenario = scenario
        self.run = run
        self.evidence = evidence
        self.args = args
        self.nodes = nodes
        self.data_root = data_root
        self.divergences = []
        self.not_measured_reasons = []
        # The watch item the controller added: an input block whose
        # inputs Rust could not find in its own UTXO set. Counted per
        # scenario, with the input block and the node's state captured.
        self.utxo_validation_failures = []

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
                # route could not be read. Treating that as a successful
                # lookup let a later candidate id overwrite the block we
                # had actually captured.
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


def drain_utxo_watch(ctx, seen):
    """Capture any NEW watch-item line since the last call.

    Called from the scenario's own polling loops, so the state is read
    while the condition is live rather than at finalization.
    """
    import smoke
    for line in smoke.rust_log_lines(UTXO_WATCH_PHRASE, limit=2000):
        if line in seen:
            continue
        seen.add(line)
        capture_utxo_validation_failure(ctx, line)
    return seen


def scan_utxo_validation_failures(ctx):
    """Final sweep, for lines no scenario loop happened to drain.

    Anything captured live already carries its state; anything found only
    here is recorded WITH the fact that its state was not captured, so
    the evidence never implies an investigation it cannot support.
    """
    import smoke
    captured_lines = {h['line'] for h in ctx.utxo_validation_failures}
    late = []
    for line in smoke.rust_log_lines(UTXO_WATCH_PHRASE, limit=2000):
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
    kept.write_text(json.dumps(evidence, indent=2, default=str) + '\n')
    entries.append({
        'attempt': number,
        'result': evidence.get('result'),
        'aborted': evidence.get('aborted'),
        'finished': evidence.get('finished'),
        'failures': [f.get('message') for f in (evidence.get('failures') or [])],
        'evidence': str(kept),
    })
    attempts_path().write_text(json.dumps(history, indent=2) + '\n')
    return number


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


def run_scenario(name, args):
    import lifecycle
    import smoke
    from scenarios import SCENARIOS

    scenario = SCENARIOS[name]
    nodes = list(SCENARIO_NODES[name])
    attempt = args.attempt or 1
    data_root = write_configs(
        name, nodes,
        rust_overrides=getattr(scenario, 'RUST_OVERRIDES', ()),
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
        'ports': {'p2p': {n: CAMPAIGN_P2P[n] for n in nodes},
                  'rest': {n: CAMPAIGN_REST[n] for n in nodes}},
        'rust': {
            'git_sha': subprocess.check_output(
                ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
            'binary': lifecycle.node_binary(),
        },
        'scala': {'classpath': str(lifecycle.classpath_file()),
                  'pinned_app_version': lifecycle.SCALA_APP_VERSION},
        'attempt': args.attempt,
        'attempt_cap': MAX_ATTEMPTS,
        'previous_attempts': [
            {k: v for k, v in e.items() if k != 'evidence'}
            for e in read_attempts().get(name, [])],
    }
    CAMPAIGN_WORK.mkdir(parents=True, exist_ok=True)
    output = CAMPAIGN_WORK / f'{name}.json'

    def save():
        output.write_text(json.dumps(evidence, indent=2, default=str) + '\n')

    evidence['logs_set_aside_at_start'] = rotate_logs(name, nodes, tag='-prior')
    save()
    run = smoke.Run(time.monotonic() + args.timeout)
    ctx = Context(name, run, evidence, args, nodes, data_root)
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
                smoke.check_sampler(run, evidence)
                scan_utxo_validation_failures(ctx)
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
        evidence['aborted'] = aborted
        evidence['result'] = verdict_for(aborted, run.failures,
                                         evidence.get('not_measured'))
        evidence['finished'] = datetime.datetime.now(
            datetime.timezone.utc).isoformat()
        evidence['status'] = 'DONE'
        save()
        record_attempt(name, evidence)
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
    for _name in SCALA2_ROLE:
        _overrides = dict(
            ((sec, key), value)
            for sec, key, value in getattr(_all[_name], 'RUST_OVERRIDES', ()))
        assert _overrides.get(('peers', 'per_ip_limit')) == '3', _name
    assert '19571' not in overlay.split('knownPeers')[1], \
        'a node must not be listed as its own peer'

    # The port bands are the controller's, and must never collide with a
    # production node or with the smoke recipe's own defaults.
    import lifecycle
    forbidden = {9052, 9053, 9063, 9072, 9073, 19099}
    used = set(CAMPAIGN_P2P.values()) | set(CAMPAIGN_REST.values())
    assert not (used & forbidden), used & forbidden
    assert not (used & set(lifecycle.DEFAULT_P2P.values())), used
    assert not (used & set(lifecycle.DEFAULT_REST.values())), used

    # Every scenario the docstring promises exists, names its nodes, and
    # asks for the second miner only if it is a two-miner scenario.
    from scenarios import SCENARIOS
    expected = {'steady', 'fork', 'rollback', 'reconstruct_rate', 'restart',
                'evict', 'flood'}
    assert set(SCENARIOS) == expected, sorted(SCENARIOS)
    assert set(SCENARIO_NODES) == expected, sorted(SCENARIO_NODES)
    for name, module in SCENARIOS.items():
        assert callable(module.run), name
        # The table the driver uses and the module's own statement of
        # what it needs have to agree, or a scenario would be started
        # with a node set it was not written for.
        assert tuple(module.NODES) == SCENARIO_NODES[name], name
        assert set(module.NODES) <= {'scala', 'scala2', 'rust'}, name
        assert 'rust' in module.NODES, name
        assert ('scala2' in module.NODES) == (name in SCALA2_ROLE), name
        # Whatever a scenario starts itself has to be one of its own
        # nodes, or `lifecycle.start` would bind a port nothing uses.
        assert set(getattr(module, 'START_NODES', module.NODES)) <= set(
            module.NODES), name
        # A second Scala node that is meant to FOLLOW has to be told not
        # to mine, or the scenario silently becomes a two-miner one.
        if SCALA2_ROLE.get(name) == 'follower':
            assert 'mining = false' in getattr(module, 'SCALA2_EXTRA', ''), name

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
        def __init__(self, pages):
            super().__init__(ctx=None)
            self.pages = list(pages)

        def poll(self):
            page = self.pages.pop(0) if self.pages else []
            self.polls += 1
            numbered = [e for e in page if e.get('seq') is not None]
            if numbered:
                lowest = min(e['seq'] for e in numbered)
                if self.highest_seen and lowest > self.highest_seen + 1:
                    self.gaps.append({'after_seq': self.highest_seen,
                                      'next_available_seq': lowest,
                                      'lost': lowest - self.highest_seen - 1})
            for event in page:
                if event.get('seq') is None:
                    continue
                self.events[event['seq']] = event
                self.highest_seen = max(self.highest_seen, event['seq'])
            return self

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
    sampler = common.PeakSampler(('waitlist', 'forks', 'staged_bytes'))
    for reading in ({'waitlist': 3, 'forks': 1},
                    {'waitlist': 9, 'forks': 2},
                    {'waitlist': 1, 'forks': 1}):
        for key in sampler.keys:
            value = reading.get(key)
            if value is None:
                continue
            current = sampler.peaks[key]
            sampler.peaks[key] = value if current is None else max(current, value)
        sampler.samples += 1
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
                'deferred_triggers': 0},
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

    import inspect

    # ----- finding 6: an exception may not persist a PASS -----
    #
    # Through the PRODUCTION rule, not a copy of it: codex's r2 note was
    # that the self-test duplicated the logic it claimed to check.
    for aborted, failures, not_measured, expected in (
            (None, [], None, 'PASS'),
            (None, [{'message': 'x'}], None, 'FAIL'),
            (None, [], 'no reference', 'NOT MEASURED'),
            (None, [{'message': 'x'}], 'no reference', 'FAIL'),
            ('RuntimeError: rust did not become ready', [], None, 'ABORTED'),
            ('RuntimeError: boom', [{'message': 'x'}], 'y', 'ABORTED')):
        got = verdict_for(aborted, failures, not_measured)
        assert got == expected, (aborted, failures, not_measured, got, expected)
    driver = inspect.getsource(run_scenario)
    assert 'verdict_for(aborted, run.failures' in driver, \
        'the driver must call the shared rule, not restate it'
    # Node shutdown is UNCONDITIONAL and the verdict is decided AFTER it,
    # so a shutdown that fails cannot leave a saved PASS behind.
    assert driver.index('lifecycle.stop()') < driver.index("evidence['result']"), \
        'shutdown must run before the verdict is decided'
    assert "shutdown_error and aborted is None" in driver, \
        'a failed shutdown has to abort the run'
    assert driver.index('finally:\n            # UNCONDITIONAL') < driver.index(
        "evidence['result']"), 'the shutdown finally must enclose the verdict path'
    assert "record_attempt(name, evidence)" in driver, \
        'every attempt has to be recorded, pass or fail'
    # Item 10: an attempt's evidence must name files only IT wrote.
    assert "f'-{attempt}'" in driver and "f'{name}-{attempt}-agreement-series" in driver, \
        'series and logs have to be per attempt, not per scenario'

    print('campaign self-test OK: rendering, ports and the scenario set')


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
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        sys.path.insert(0, str(HERE))
        _self_test()
        return 0
    if not args.scenario:
        parser.error('--scenario is required (or --self-test)')

    sys.path.insert(0, str(HERE))
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
    configure_environment(name, SCENARIO_NODES[name])
    # Enforced BEFORE anything is started: a refused attempt must not
    # leave a devnet running or overwrite the canonical evidence.
    args.attempt = check_attempt_cap(name, force=args.force_attempt)
    evidence = run_scenario(name, args)
    print(f'{name}: {evidence["result"]} '
          f'({len(evidence.get("divergences") or [])} divergences, '
          f'{evidence.get("samples")} samples)')
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
