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

# Each node listens on its OWN loopback address. Not cosmetic: two Scala
# nodes on one IP can never dial each other, because
# `NetworkController.getPeerAddress` resolves a candidate whose declared
# address shares this node's own external address through the UPnP
# gateway, and with no gateway returns `None`. The first three-node run
# died on exactly that — the second Scala node never reached the miner,
# never synced past genesis, and so (with `offlineGeneration = false`)
# never mined a block. REST stays on 127.0.0.1 for every node, so the
# harness is unaffected.
CAMPAIGN_P2P_HOST = {'scala': '127.0.0.1', 'scala2': '127.0.0.2',
                     'rust': '127.0.0.3'}

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


def scan_utxo_validation_failures(ctx):
    """Count the `input box not found in UTXO set` event seen once in M2.

    It is a watch item, not yet a verdict: the campaign records how often
    it fires and against which input block, so the findings report can
    say whether it is a race the follower recovers from or a divergence.
    """
    import smoke
    hits = []
    for line in smoke.rust_log_lines('input box not found in UTXO set', limit=200):
        ids = smoke.ids_in(line)
        hits.append({'line': line, 'ids': ids})
    ctx.utxo_validation_failures = hits
    ctx.note('utxo_validation_failures', {'count': len(hits), 'sample': hits[:10]})
    return hits


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


def _alive(pid):
    """Does this PID still exist at all — zombie included?

    `lifecycle.owned` answers a different question, and answers it wrong
    here: a SIGKILLed process becomes a zombie whose `/proc/<pid>/cmdline`
    is EMPTY, so `owned` reports False while the process is still in the
    table. Restarting the node on that signal raced the old one's
    teardown and the replacement died with "Database already open".
    """
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


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
    while _alive(pid) and time.monotonic() < deadline:
        time.sleep(0.2)
    if _alive(pid):
        raise Divergence(
            f'{name} (PID {pid}) survived SIGKILL for 60s; refusing to start a '
            'replacement over a data directory the old process still holds')
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


def run_scenario(name, args):
    import lifecycle
    import smoke
    from scenarios import SCENARIOS

    scenario = SCENARIOS[name]
    nodes = list(SCENARIO_NODES[name])
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
    finally:
        run.stop_sampling()
        smoke.check_sampler(run, evidence)
        scan_utxo_validation_failures(ctx)
        evidence['divergences'] = ctx.divergences
        evidence['failures'] = run.failures
        evidence['artifacts'] = smoke.write_findings(run, evidence)
        # This scenario's own node logs and sample series, kept beside
        # its evidence rather than left to be overwritten by the next.
        evidence['logs'] = rotate_logs(name, nodes)
        series = run.series_path
        if series.exists():
            kept = CAMPAIGN_WORK / f'{name}-agreement-series.jsonl'
            series.replace(kept)
            evidence['series_file'] = str(kept)
        evidence['samples'] = run.samples
        evidence['unavailable_samples'] = run.unavailable_samples
        evidence['drop_totals'] = run.totals()
        evidence['peer_states'] = sorted(run.peer_states)
        evidence['penalty_observations'] = run.penalty_observations
        evidence['max_height_gap'] = run.max_height_gap
        evidence['result'] = 'FAIL' if run.failures else 'PASS'
        evidence['finished'] = datetime.datetime.now(
            datetime.timezone.utc).isoformat()
        evidence['status'] = 'DONE'
        save()
        try:
            lifecycle.stop()
        finally:
            if getattr(scenario, 'PURGE_ADDRESS_BOOK', False):
                evidence['address_book_purged'] = purge_address_book(data_root)
                save()
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
    assert 'bind_addr = "127.0.0.3:19572"' in rendered, rendered
    assert 'bind = "127.0.0.1:19592"' in rendered, rendered
    assert ('known = ["127.0.0.1:19570", "127.0.0.2:19571"]' in rendered), rendered
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
    assert 'bindAddress = "127.0.0.2:19571"' in overlay, overlay
    # REST is NOT moved: the harness talks to 127.0.0.1 for every node.
    assert 'restApi.bindAddress = "127.0.0.1:19591"' in overlay, overlay
    assert '"127.0.0.1:19570", "127.0.0.3:19572"' in overlay, overlay
    # Every node listens on a DISTINCT address. Two Scala nodes that
    # share one can never dial each other (scorex
    # `NetworkController.getPeerAddress` resolves a same-address peer
    # through a UPnP gateway that does not exist and returns None), which
    # is what stranded the second node at genesis on the first attempt.
    assert len(set(CAMPAIGN_P2P_HOST.values())) == len(CAMPAIGN_P2P_HOST), \
        CAMPAIGN_P2P_HOST
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

    from scenarios import evict as evict_scenario
    real = render_rust_config((HERE / 'rust-node.toml').read_text(),
                              Path('/tmp/x/rust'), ['scala', 'rust'],
                              evict_scenario.RUST_OVERRIDES)
    parsed = tomllib.loads(real)
    assert parsed['data_dir'] == '/tmp/x/rust', parsed['data_dir']
    assert parsed['peers']['bind_addr'] == '127.0.0.3:19572', parsed['peers']
    assert parsed['peers']['known'] == ['127.0.0.1:19570'], parsed['peers']
    assert parsed['api']['bind'] == '127.0.0.1:19592', parsed['api']
    # Every override the scenario declares, and nothing else, landed in
    # the bounds table — including the one the recipe file already sets,
    # which has to be REPLACED rather than duplicated.
    assert parsed['input_blocks']['bounds'] == {
        key: int(value) for _, key, value in evict_scenario.RUST_OVERRIDES
    }, parsed['input_blocks']['bounds']
    # Untouched settings survive the render.
    assert parsed['input_blocks']['strict_field_binding'] is False, parsed
    assert parsed['mining']['enabled'] is False, parsed

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

    # A switch onto a block the miner never had is a chain Scala lacks.
    invented = [sample('O1', ['b', 'a'], ['b', 'a']),
                sample('O1', ['x', 'a'], ['b', 'a'])]
    verdict = common.compare_fork_switches(invented)
    assert verdict['applied_blocks_scala_never_had'], verdict
    assert verdict['applied_blocks_scala_never_had'][0]['block'] == 'x', verdict

    # A rollback of a block Scala still holds is a switch Scala did not
    # make.
    unilateral = [sample('O1', ['b', 'a'], ['b', 'a']),
                  sample('O1', ['a'], ['b', 'a'])]
    verdict = common.compare_fork_switches(unilateral)
    assert verdict['rolled_back_blocks_scala_kept'], verdict
    assert verdict['rolled_back_blocks_scala_kept'][0]['block'] == 'b', verdict

    # And a switch the miner made TOO — Scala dropped `b` by its last
    # sample — is lag, not a divergence.
    followed = [sample('O1', ['b', 'a'], ['b', 'a']),
                sample('O1', ['c', 'a'], ['c', 'a'])]
    verdict = common.compare_fork_switches(followed)
    assert verdict['applied_blocks_scala_never_had'] == [], verdict
    assert verdict['rolled_back_blocks_scala_kept'] == [], verdict

    # The whole-chain orphan check catches a block that is never a tip.
    orphan = [sample('O1', ['c', 'q', 'a'], ['c', 'b', 'a'])]
    found = common.chain_members_scala_never_had(orphan)
    assert [o['block'] for o in found] == ['q'], found

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
    parser.add_argument('--attempt', type=int, default=1)
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
                 '--timeout', str(args.timeout), '--attempt', str(args.attempt)]
                + (['--fresh'] if args.fresh else []), cwd=ROOT)
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
    evidence = run_scenario(name, args)
    print(f'{name}: {evidence["result"]} '
          f'({len(evidence.get("divergences") or [])} divergences, '
          f'{evidence.get("samples")} samples)')
    for failure in evidence.get('failures') or []:
        print(f'  - {failure["message"]}')
    return 0 if evidence['result'] == 'PASS' else 1


if __name__ == '__main__':
    os.chdir(ROOT)
    sys.path.insert(0, str(HERE))
    raise SystemExit(main())
