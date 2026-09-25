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
import tempfile
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

# The miner and the Rust follower listen on 127.0.0.1; `scala2` and
# `scala3` each get their own loopback address. REST stays on 127.0.0.1.
#
# A Scala follower has to peer DIRECTLY with the Scala miner. Neither
# implementation relays a remote input block (Scala
# `ErgoNodeViewSynchronizer.scala:2309-2310` sends only locally mined
# ones; Rust matches it, `processor.rs:1482`), so a follower whose only
# peer is the Rust node never holds an input block, and every decision
# it logs is the "prev input block not found" download. Scorex puts two
# gates in front of a Scala node dialling a Scala node on one host, and
# both have to be cleared (follower-peering-investigation.md §3, an
# experiment on stock 62c10315):
#
#   1. `NetworkController.getPeerAddress` resolves a peer on the node's
#      OWN declared IP through a UPnP gateway that does not exist, and
#      silently gets `None` — so the follower needs a different address;
#   2. `connectTo` refuses every loopback peer unless
#      `scorex.network.allowLocal = true` — which `FOLLOWER_EXTRA` sets.
#
# Distinct addresses alone did not peer; with `allowLocal` they peered
# in ~21 s. The miner stays on 127.0.0.1 and gets no `allowLocal`: the
# followers dial it (inbound is not filtered for locality), and in
# `fork`/`rollback`, where `scala2` is the SECOND MINER, the two miners
# still cannot dial each other, which keeps the topology those
# scenarios measure. The second node is still SEEDED from the miner's
# data directory (`common.seed_second_miner`). All 127.x addresses are
# one /16 to the Rust follower, so its per-IP and per-/16 admission
# limits are raised to fit the node set (`admission_overrides`).
CAMPAIGN_P2P_HOST = {'scala': '127.0.0.1', 'scala2': '127.0.0.2',
                     'rust': '127.0.0.1', 'scala3': '127.0.0.3'}

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
# See `lifecycle.WORK`: `MATRIX_WORK` moves the whole run, resolved once.
WORK = Path(os.environ.get('MATRIX_WORK', HERE / '.work')).resolve()
# ...and PINNED, absolute, in the environment before anything changes
# directory: `__main__` chdirs to ROOT and only then imports `lifecycle`
# (and re-execs per-scenario children with `cwd=ROOT`), each of which
# would otherwise resolve a relative value against a different base.
if 'MATRIX_WORK' in os.environ:
    os.environ['MATRIX_WORK'] = str(WORK)
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
    # Lets the follower dial the miner on loopback; see CAMPAIGN_P2P_HOST.
    'scorex.network.allowLocal = true\n'
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

# Scenarios with NO pass criterion (spec §7a, `task-0-brief.md:32`).
# They exist to produce denominators a patched run is read against, so
# "nothing failed" says nothing about them: the question is whether the
# measurement was TAKEN, over the window it asked for, with the phrases
# it counts actually matching the build.
MEASUREMENT_SCENARIOS = ('miner_self_reject',)

# The verdicts that exit 0: the run did what it was asked. A completed
# measurement is one of them; an incomplete measurement is not, and
# neither is a PASS it was never eligible for. NOT MEASURED exits 0 as
# well — a comparison this host could not make is a limitation of the
# host, not a broken scenario — and is reported as its own verdict.
OK_RESULTS = ('PASS', 'MEASURED', 'NOT MEASURED')


def verdict_of(scenario, aborted, failures, measurement_complete=None,
               not_measured=None):
    """One run's verdict. The driver's rule, in one testable place.

    A measurement-only scenario can be MEASURED or INCOMPLETE, never
    PASS or FAIL: it has no criterion, so it cannot meet one. It used to
    be given PASS whenever no assertion happened to fail, which made a
    run that covered 3 of its 40 ordering blocks indistinguishable from
    one that covered all 40, and let a campaign summary count a
    measurement among its passes.

    `measurement_complete` is the scenario's OWN statement that its
    window opened, ran to the end, and matched the phrases it counts. Not
    stated is not complete: a scenario that never said so has not shown
    it.

    `NOT MEASURED` is its own kind: a scenario whose comparison could
    not be made on this host has not failed — nothing about the node is
    wrong — and it has not passed either, because the property it exists
    to establish is unestablished. It never outranks a real failure or
    an abort.
    """
    if aborted:
        return 'ABORTED'
    if scenario in MEASUREMENT_SCENARIOS:
        return 'MEASURED' if measurement_complete and not failures \
            else 'INCOMPLETE'
    if failures:
        return 'FAIL'
    if not_measured:
        return 'NOT MEASURED'
    return 'PASS'


# Which scenarios take `--reference-follower` (spec §8). The others
# refuse it rather than accepting it and measuring nothing with it.
REFERENCE_FOLLOWER_SCENARIOS = ('steady', 'restart', 'fork',
                                'reconstruct_rate', 'flood')
# `flood` aims its adversary at the ONE Scala follower the flag adds (F13's
# pending store is attack surface on the Scala side); with two there is
# no single target, so `both` is refused rather than guessed.
SINGLE_FOLLOWER_SCENARIOS = ('flood',)


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
    if reference_follower == 'both' and scenario in SINGLE_FOLLOWER_SCENARIOS:
        raise SystemExit(
            f'{scenario} takes one target follower, so --reference-follower '
            'both is refused; run it once with stock and once with patched')
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


# `restart --restart-victim`: which process the scenario SIGKILLs.
# `rust` (the default) is the M3 scenario. `scala-followers` kills every
# Scala reference follower in the run at the same instant and respawns
# them, which is the only way to watch a Scala node's in-memory pending
# store start empty (#2563) and a sender-side tip replay (#2506) act on
# the reconnect.
RESTART_VICTIMS = ('rust', 'scala-followers')
# `flood --flood-mode`: how the root-flood adversary uses its hosts.
# `hit-and-run` (the default) is the plan 3 shape: fresh hosts every
# wave, each connection closed half a second after its last frame.
# `held` keeps ONE connection per host open for the whole flood and past
# the store's TTL, sending every wave over it, with more announcements
# per host than the per-host cap: once a store drops a host's entries on
# disconnect, only a connection that stays up keeps them held.
FLOOD_MODES = ('hit-and-run', 'held')


def check_scenario_knobs(scenario, reference_follower=None,
                         restart_victim='rust', flood_mode='hit-and-run',
                         post_ordering_blocks=None):
    """Refuse a scenario knob the scenario would silently ignore.

    Pure, so `--self-test` pins it. A run that accepted
    `--restart-victim scala-followers` and killed the Rust node anyway
    would be reported as the Scala-follower restart it never was.
    """
    if restart_victim not in RESTART_VICTIMS:
        raise SystemExit(f'--restart-victim must be one of {RESTART_VICTIMS}')
    if flood_mode not in FLOOD_MODES:
        raise SystemExit(f'--flood-mode must be one of {FLOOD_MODES}')
    if restart_victim != 'rust':
        if scenario != 'restart':
            raise SystemExit(
                f'--restart-victim {restart_victim} applies to restart only, '
                f'not {scenario}')
        if reference_follower is None:
            raise SystemExit(
                '--restart-victim scala-followers needs a Scala follower to '
                'kill; add --reference-follower stock|patched|both')
    if post_ordering_blocks is not None:
        if scenario != 'restart':
            raise SystemExit(
                f'--post-ordering-blocks applies to restart only, not {scenario}')
        if post_ordering_blocks < 1:
            raise SystemExit('--post-ordering-blocks must be at least 1')
    if flood_mode != 'hit-and-run':
        if scenario != 'flood':
            raise SystemExit(
                f'--flood-mode {flood_mode} applies to flood only, not '
                f'{scenario}')
        if reference_follower is None:
            raise SystemExit(
                '--flood-mode held is the ROOT flood against a Scala '
                'follower; add --reference-follower stock|patched (the Rust '
                'follower\'s flood has no connection-hold mode)')
    return None


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


def builds_in_use(names, reference_follower, build, base_build):
    """The builds these scenarios' Scala roles would run, in role order. Pure.

    `--build` reaches only the patched roles and `--base-build` every
    other Scala role, so a build that no role runs is not checked: a run
    with no patched role must not be refused over an unprovisioned
    `--build`. An unknown scenario, or one that refuses its knobs during
    role resolution, is skipped here; its own run refuses it with the
    reason.
    """
    used = []
    for name in names:
        if name not in SCENARIO_ROLES:
            continue
        try:
            role_set = resolve_roles(name, reference_follower)
        except SystemExit:
            continue
        for role in role_set:
            spec = lifecycle_roles()[role]
            if spec.kind != 'scala':
                continue
            chosen = build if spec.patched else base_build
            if chosen not in used:
                used.append(chosen)
    return used


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
    # EVERY duplicate, including one node's own two listeners. The
    # earlier `seen[port] != node` exemption let a node's REST and p2p
    # share a port: one of the two binds, the other fails, and what is
    # left is a REST port speaking the p2p handshake.
    seen = {}
    for node, port in both:
        if port in seen:
            raise SystemExit(
                f'port {port} is claimed twice ({seen[port]} and {node}); '
                'every listener needs its own port')
        seen[port] = f'{node} p2p' if (node, port) in p2p.items() else \
            f'{node} REST'
    return None


def configure_environment(scenario, nodes, roles=(), build='stock',
                          base_build='stock'):
    """Point `lifecycle` at this campaign's ports, configs, dirs and builds."""
    os.environ['MATRIX_NODES'] = ','.join(nodes)
    for name in nodes:
        os.environ[f'MATRIX_P2P_{name.upper()}'] = str(CAMPAIGN_P2P[name])
        os.environ[f'MATRIX_REST_{name.upper()}'] = str(CAMPAIGN_REST[name])
        os.environ[f'MATRIX_P2P_HOST_{name.upper()}'] = CAMPAIGN_P2P_HOST[name]
    # `--build` selects the build for the PATCHED roles only. Every
    # other Scala role — the miner(s) and the stock follower — runs
    # `--base-build` (`stock` unless told otherwise), which is what makes
    # a run an ablation (base + one patch vs base) rather than a
    # comparison of two integration builds (spec §7a). The base is a
    # knob because the base moves: the #2563 re-measure runs its miner
    # and stock follower on weak-blocks @ a1bd938ef (and on a1bd938ef +
    # #2506, a SENDER-side change the miner has to carry), not on the
    # M4 pin.
    for role in roles:
        spec = lifecycle_roles()[role]
        if spec.kind != 'scala':
            continue
        os.environ[f'MATRIX_BUILD_{spec.node.upper()}'] = (
            build if spec.patched else base_build)


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
    pending = ''
    if scenario == 'flood':
        from scenarios.flood import ROOT_FLOOD_CAPS
        # The fixed store reads this under ergo.node; stock builds ignore it.
        pending = ''.join(f'ergo.node.matrix.pendingAnnouncements.{key} = {value}\n'
                          for key, value in ROOT_FLOOD_CAPS.items())
    return (
        f'include file("{base}")\n'
        f'ergo.directory = "{data_dir}"\n'
        'ergo.wallet.secretStorage.secretDir = ${ergo.directory}"/wallet/keystore"\n'
        f'scorex.network.bindAddress = "{listen}"\n'
        f'scorex.network.declaredAddress = "{listen}"\n'
        f'scorex.network.knownPeers = [{", ".join(known)}]\n'
        f'scorex.restApi.bindAddress = "127.0.0.1:{CAMPAIGN_REST[node]}"\n'
        f'{pending}{extra}'
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
    """SIGKILL one node this recipe started. See `kill_hard_many`."""
    return kill_hard_many([name])[name]


def kill_hard_many(names):
    """SIGKILL nodes this recipe started, by PID, at the SAME instant,
    after checking every process is still the one we launched.

    Every PID is checked before any is signalled, so a refusal kills
    nothing; then the signals go out back to back, so two followers die
    together rather than one a teardown apart from the other.

    Returns `{name: pid}` only once every PID is GONE from the process
    table, not merely unrecognizable: the data directory's lock is held
    until then, and the replacement node refuses to open a database that
    is still open.
    """
    import lifecycle
    targets = {}
    for name in names:
        pid = node_pid(name)
        config = (WORK / (name + '.config'))
        configs = [config.read_text().strip()] if config.exists() else None
        if pid is None or not lifecycle.owned(pid, configs):
            raise Divergence(
                f'{name} is not running under this recipe; refusing to kill')
        targets[name] = (pid, config)
    for name, (pid, _config) in targets.items():
        os.kill(pid, signal.SIGKILL)
    deadline = time.monotonic() + 60
    while (any(_holds_resources(pid) for pid, _ in targets.values())
           and time.monotonic() < deadline):
        time.sleep(0.2)
    for name, (pid, _config) in targets.items():
        if _holds_resources(pid):
            raise Divergence(
                f'{name} (PID {pid}) survived SIGKILL for 60s; refusing to '
                'start a replacement over a data directory the old process '
                'still holds')
    # The PID being gone is necessary and, measurably, not sufficient:
    # the replacement started 60 ms later still lost the race for the
    # data directory's redb lock ("Database already open. Cannot acquire
    # lock."). The kernel releases file locks as the process is torn
    # down, and the teardown outlives the PID's visibility. A real
    # operator restart has a gap too; this one is explicit and short.
    time.sleep(KILL_SETTLE_SECONDS)
    for name, (pid, config) in targets.items():
        (WORK / (name + '.pid')).unlink(missing_ok=True)
        config.unlink(missing_ok=True)
    return {name: pid for name, (pid, _config) in targets.items()}


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
    """`verdict_of` for a scenario that HAS a pass criterion."""
    return verdict_of(None, aborted, failures, not_measured=not_measured)


def persist_verdict(name, evidence, aborted, failures, save):
    """Write the verdict LAST.

    ABORTED goes to disk first; the attempt is recorded; only then is the
    real verdict written, as the final step. Any exception in between
    leaves ABORTED on disk. Previously DONE/PASS was saved BEFORE the
    attempt was recorded, and codex's r3 probe — the attempt recording
    raising after a clean run — left the persisted verdict at DONE/PASS.
    """
    verdict = verdict_of(name, aborted, failures,
                         evidence.get('measurement_complete'),
                         evidence.get('not_measured'))
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


def check_no_classpath_override(environ):
    """Refuse a hand-set classpath for a MEASURED campaign.

    `MATRIX_CLASSPATH[_<NODE>]` is how an operator drives the harness
    against a one-off build; it is also the one path that skips
    `Build.verify()` entirely. A campaign scenario's numbers are
    attributed to a build in its evidence file, so the two cannot both
    be true: either the registry says which build ran and checked it, or
    the run is not a measurement. `smoke.py` and `lifecycle.py start`
    keep the override.
    """
    named = sorted(k for k in environ
                   if k == 'MATRIX_CLASSPATH'
                   or k.startswith('MATRIX_CLASSPATH_'))
    if named:
        raise SystemExit(
            f'{", ".join(named)} is set, which points the devnet at a '
            'classpath the build registry never verified. A campaign '
            'attributes every number to a build, so it takes its classpath '
            'from --build alone. Unset it, or register the build in '
            'scripts/devnet-matrix/builds.toml.')


def check_launch_classpath(role, node, summary, launch_classpath):
    """The evidence entry for one role, bound to the ACTUAL launch.

    The manifest is read from the registry and the classpath is read
    from `lifecycle`, which is what the JVM is started with. They were
    recorded independently, so a per-node override could put the
    registered build in the evidence and a different one on the
    classpath. Here they have to be the same file.
    """
    entry = dict(summary)
    entry['node'] = node
    entry['launch_classpath'] = str(launch_classpath)
    if entry.get('classpath') != str(launch_classpath):
        raise SystemExit(
            f'the {role} evidence would name build {entry.get("build")!r} '
            f'({entry.get("classpath")}) but the {node} node was launched from '
            f'{launch_classpath}. Evidence that describes a different '
            'classpath from the one the JVM ran is not evidence.')
    return entry


def build_manifests(by_node):
    """`{role: manifest summary}` for every Scala role in a run.

    Read through the registry, which VERIFIES the build first, so the
    manifest recorded beside a measurement is one that was checked
    against the compiled output the node actually ran — and bound to the
    classpath `lifecycle` will hand the JVM, so the two cannot describe
    different builds.

    A `BuildError` ABORTS. It used to be caught and written into the
    evidence as `unidentified`, which let a whole campaign run and be
    reported on a build nobody could name.
    """
    import builds
    import lifecycle
    out = {}
    for node, role in by_node.items():
        if lifecycle.ROLES[role].kind != 'scala':
            continue
        name = lifecycle.node_build(node)
        try:
            summary = builds.load(name).summary()
        except builds.BuildError as error:
            raise SystemExit(
                f'the {role} role on {node} cannot run build {name!r}: {error}'
            ) from error
        out[role] = check_launch_classpath(
            role, node, summary, lifecycle.classpath_file(node))
    return out


def admission_overrides(nodes, overrides):
    """Raise the follower's per-IP admission limit to fit the node set.

    Every 127.x address is one /16 to the follower, and a Scala node's
    outbound socket comes from 127.0.0.1 whatever address it listens on.
    The limit gates outbound dial SELECTION as well as inbound
    admission, so a follower left at the
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
        # The build every NON-patched Scala role ran (miner(s), stock
        # follower). `builds` below is the per-role identity; this is the
        # knob that chose it.
        'base_build': getattr(args, 'base_build', 'stock'),
        'restart_victim': getattr(args, 'restart_victim', 'rust'),
        'flood_mode': getattr(args, 'flood_mode', 'hit-and-run'),
        'post_ordering_blocks': getattr(args, 'post_ordering_blocks', None),
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
            'binary_provenance': lifecycle.node_binary_provenance(),
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
    # Rust and the miner on 127.0.0.1, `scala2` on its own loopback
    # address (CAMPAIGN_P2P_HOST), REST on 127.0.0.1 for all.
    assert 'bind_addr = "127.0.0.1:19572"' in rendered, rendered
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

    # ----- a Scala follower peers DIRECTLY with the Scala miner -----
    #
    # Neither implementation relays a REMOTE input block (Scala
    # `ErgoNodeViewSynchronizer.scala:2309-2310`, Rust `processor.rs:1482`),
    # so a Scala follower whose only peer is the Rust node never holds an
    # input block. Every stock decision was then the synchronizer's
    # "prev input block not found" download (80 of 81 in Task 2, 15 of
    # 15 in the `both` validation). Scorex applies two gates to a Scala
    # node dialling a Scala node on one host
    # (follower-peering-investigation.md §3, experiment-confirmed): a
    # peer on the node's OWN declared IP resolves through a UPnP gateway
    # that does not exist, and `allowLocal = false` refuses every
    # loopback peer. A follower therefore gets its own loopback address
    # and `allowLocal`. The miner and Rust stay on 127.0.0.1.
    assert CAMPAIGN_P2P_HOST['scala'] == '127.0.0.1', CAMPAIGN_P2P_HOST
    assert CAMPAIGN_P2P_HOST['rust'] == '127.0.0.1', CAMPAIGN_P2P_HOST
    assert CAMPAIGN_P2P_HOST['scala2'] == '127.0.0.2', CAMPAIGN_P2P_HOST
    assert CAMPAIGN_P2P_HOST['scala3'] == '127.0.0.3', CAMPAIGN_P2P_HOST
    import lifecycle as _lc
    _roles_both = _lc.roles_for_nodes(
        resolve_roles('reconstruct_rate', 'both'))
    for _node in ('scala2', 'scala3'):
        _fo = scala_override(
            'reconstruct_rate', _node, ['scala', 'scala2', 'scala3', 'rust'],
            Path(f'/tmp/x/{_node}'),
            extra=scala_extra_for(_node, _roles_both))
        _host = CAMPAIGN_P2P_HOST[_node]
        assert f'bindAddress = "{_host}:' in _fo, _fo
        assert f'declaredAddress = "{_host}:' in _fo, _fo
        assert 'scorex.network.allowLocal = true' in _fo, (
            'a follower that may not dial loopback never reaches the miner',
            _fo)
        # The miner is in its known peers, at the miner's own address.
        assert f'"127.0.0.1:{CAMPAIGN_P2P["scala"]}"' in \
            _fo.split('knownPeers')[1].splitlines()[0], _fo
    # A MINER role gets no `allowLocal`: in `fork`/`rollback` `scala2` is
    # the second miner, and letting the two miners dial each other would
    # change the topology those scenarios measure.
    _roles_fork = _lc.roles_for_nodes(SCENARIO_ROLES['fork'])
    for _node in ('scala', 'scala2'):
        assert 'allowLocal' not in scala_extra_for(_node, _roles_fork), _node
    # `localOnly` is read by no Scala source at 62c10315, so a recipe that
    # carries it states a guard that does not exist.
    for _conf in ('scala-node.conf', 'scala-miner2.conf'):
        assert 'localOnly' not in (HERE / _conf).read_text(), _conf

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

    import tempfile

    # ----- M4: a run's WORKING DIRECTORY, not just its ports -----
    #
    # A separate port band is not isolation. Two agents driving this one
    # worktree share `.work/`, so the second run's `lifecycle.start`
    # overwrites `scala.pid` / `scala.config` and the first run's `stop`
    # then reads them and kills the SECOND run's nodes — and both runs
    # append to one `scala.log` and one `agreement-series.jsonl`, which
    # is the evidence both of them are measured from. This happened on
    # 2026-09-23 between Task 2 and a concurrent F16 smoke. `MATRIX_WORK`
    # moves pid files, logs, series and evidence together; `smoke`
    # imports `WORK` from `lifecycle`, so one variable settles all three
    # modules.
    probe = (
        'import sys; sys.path.insert(0, %r);'
        'import lifecycle, campaign, smoke;'
        'print(lifecycle.WORK, smoke.WORK, campaign.WORK, campaign.CAMPAIGN_WORK)'
    ) % str(HERE)
    with tempfile.TemporaryDirectory() as tmp:
        out = subprocess.run(
            [sys.executable, '-c', probe],
            env=dict(os.environ, MATRIX_WORK=tmp),
            capture_output=True, text=True, check=True).stdout.split()
        assert out[0] == out[1] == out[2] == tmp, out
        assert out[3] == str(Path(tmp) / 'campaign'), out
    out = subprocess.run(
        [sys.executable, '-c', probe],
        env={k: v for k, v in os.environ.items() if k != 'MATRIX_WORK'},
        capture_output=True, text=True, check=True).stdout.split()
    assert out[0] == str(HERE / '.work'), out
    # A RELATIVE `MATRIX_WORK` (`cd scripts/devnet-matrix;
    # MATRIX_WORK=.work-m4-f11 python3 campaign.py …`, the launch shape
    # proof-F11.md records) is resolved against the directory it was
    # given in, ONCE, at load. Left relative, the first
    # `path.relative_to(ROOT)` (a mismatch artifact written during
    # `fund_miner`) raised ValueError and aborted the run before any
    # devnet state existed. A work directory OUTSIDE the checkout (a
    # tempdir) is shown as an absolute path instead of raising.
    rel_probe = (
        'import sys; sys.path.insert(0, %r);'
        'import lifecycle, campaign, smoke;'
        'print(lifecycle.WORK, smoke.WORK, campaign.WORK,'
        ' smoke.display_path(smoke.FINDINGS / "x.json"))'
    ) % str(HERE)
    rel_env = dict(os.environ, MATRIX_WORK='.work-selftest-relative')
    out = subprocess.run(
        [sys.executable, '-c', rel_probe], cwd=str(HERE), env=rel_env,
        capture_output=True, text=True).stdout.split()
    assert out and out[0] == str(HERE / '.work-selftest-relative'), (
        'a relative MATRIX_WORK must be absolute once loaded', out)
    assert out[0] == out[1] == out[2], out
    assert out[3] == ('scripts/devnet-matrix/.work-selftest-relative/'
                      'findings/x.json'), out
    with tempfile.TemporaryDirectory() as tmp:
        out = subprocess.run(
            [sys.executable, '-c', rel_probe],
            env=dict(os.environ, MATRIX_WORK=tmp),
            capture_output=True, text=True, check=True).stdout.split()
        # The gate runs with TMPDIR inside the worktree, where the tempdir
        # IS inside the checkout and is named relative to it; outside it,
        # the name is absolute. Either way it never raises.
        found = Path(tmp).resolve() / 'findings' / 'x.json'
        try:
            want = str(found.relative_to(ROOT))
        except ValueError:
            want = str(found)
        assert out[3] == want, (want, out)
    # ----- step A (5): the SAME work dir after `main`'s chdir -----
    #
    # `campaign.py` is loaded (and resolves `MATRIX_WORK`) in the launch
    # directory, then `__main__` changes to the checkout root and imports
    # `lifecycle` lazily, which resolved the same relative value against
    # the ROOT: launched from `scripts/devnet-matrix`, the campaign's
    # evidence and the nodes' pid files and logs went to two different
    # directories, and so did every re-exec'd child (`cwd=ROOT`). The
    # probe replays main's order: load in HERE, chdir, lazy import, and
    # a child started from ROOT.
    chdir_probe = (
        'import os, subprocess, sys; sys.path.insert(0, %r);'
        'import campaign; os.chdir(campaign.ROOT);'
        'import lifecycle, smoke;'
        'child = subprocess.run([sys.executable, "-c", "import os;'
        ' print(os.environ[\'MATRIX_WORK\'])"], capture_output=True,'
        ' text=True, cwd=str(campaign.ROOT)).stdout.strip();'
        'print(campaign.WORK, lifecycle.WORK, smoke.WORK,'
        ' os.environ["MATRIX_WORK"], child)'
    ) % str(HERE)
    out = subprocess.run(
        [sys.executable, '-c', chdir_probe], cwd=str(HERE),
        env=dict(os.environ, MATRIX_WORK='.work-selftest-chdir'),
        capture_output=True, text=True).stdout.split()
    assert out and len(set(out)) == 1 and \
        out[0] == str(HERE / '.work-selftest-chdir'), (
            'one absolute work dir before and after the chdir, in this '
            'process and its children', out)

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
    # Including ONE node's own two listeners (codex review-2): the
    # `seen[port] != node` condition let a node's REST and p2p share a
    # port, which binds once and then fails as a REST port that speaks
    # the p2p handshake — an unreadable devnet rather than a refused
    # configuration.
    try:
        check_band({'scala': 19600}, {'scala': 19600})
    except SystemExit as error:
        assert 'twice' in str(error) and '19600' in str(error), str(error)
    else:
        raise AssertionError(
            "a node's own p2p and REST port must not be the same port")
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
    # A follower ADDED AT RUNTIME must be told not to mine and must fit
    # the admission limit, exactly like one a scenario declares. The
    # loop above only walks each scenario's BASE role set, so without
    # this a `--reference-follower` node could quietly race the miner —
    # which is the one thing that would make every reference number
    # meaningless.
    for _name in REFERENCE_FOLLOWER_SCENARIOS:
        for _mode in ('stock', 'patched', 'both'):
            try:
                _roles = resolve_roles(_name, _mode)
            except SystemExit:
                continue          # refused, with its reason, above
            _assigned = lifecycle.roles_for_nodes(_roles)
            _module = _all[_name]
            for _node, _role in _assigned.items():
                if lifecycle.ROLES[_role].kind != 'scala' or \
                        lifecycle.ROLES[_role].mines:
                    continue
                _extra = scala_extra_for(
                    _node, _assigned, getattr(_module, 'SCALA_EXTRA', ''),
                    getattr(_module, 'SCALA2_EXTRA', ''))
                assert 'mining = false' in _extra, (_name, _mode, _node, _role)
            _scala = [n for n in _assigned if n != 'rust']
            _ov = dict(((sec, key), value) for sec, key, value in
                       admission_overrides(
                           tuple(_assigned),
                           getattr(_module, 'RUST_OVERRIDES', ())))
            assert int(_ov[('peers', 'per_ip_limit')]) >= len(_scala), \
                (_name, _mode, _ov)
            # And a node that is not started at launch has to be one a
            # scenario actually brings up itself, or it never runs at
            # all and its numbers read as a silent zero.
            _late = set(_assigned) - set(
                getattr(_module, 'START_NODES', tuple(_assigned)))
            assert _late <= set(getattr(_module, 'SEEDED_NODES', ())), (
                _name, _mode, _late,
                'a node outside START_NODES that the scenario does not seed '
                'never runs, and its numbers read as a silent zero')
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
        resolve_roles('evict', 'stock')
    except SystemExit as error:
        assert 'does not apply to evict' in str(error), str(error)
    else:
        raise AssertionError('--reference-follower must be scenario-checked')
    # ----- proofs step B: the F13 flood aims at a Scala FOLLOWER -----
    #
    # F13's pending store is new attack surface on the SCALA follower,
    # and `flood` could only ever aim at the Rust one: `flood --build
    # F13` ran no patched role at all. The flag adds ONE follower as the
    # target; `both` has two candidates and is refused with the reason.
    assert 'scala_follower_patched' in resolve_roles('flood', 'patched')
    assert 'scala_follower' in resolve_roles('flood', 'stock')
    try:
        resolve_roles('flood', 'both')
    except SystemExit as error:
        assert 'one target' in str(error), str(error)
    else:
        raise AssertionError('flood --reference-follower both must be refused')
    from scenarios import flood as _flood_eval
    _adv = '/127.105.0.1:5555'
    _miner = '/127.0.0.1:19600'

    def _root(block, remote):
        return ('INFO org.ergoplatform.network.ErgoNodeViewSynchronizer - On '
                f'processing {block}, downloading its parent and unknown '
                f'ordering block ff from ConnectedPeer(connection: '
                f'ConnectionId(remote={remote}, local=/127.0.0.3:19603, '
                'direction=Incoming) , remote version: Some(6.5.0))')
    _lines = [
        _root('a1', _adv), _root('a2', _adv),
        _root('b1', _miner), _root('b2', _miner),
        'INFO org.ergoplatform.network.ErgoNodeViewSynchronizer - Processing '
        'valid sub-block b1 with parent sub-block None and parent block ff',
        'INFO org.ergoplatform.network.peer.PeerManager - /127.105.0.1:5555 '
        'penalized, penalty: NonDeliveryPenalty',
        'INFO org.ergoplatform.network.peer.PeerManager - /127.0.0.1:19600 '
        'penalized, penalty: NonDeliveryPenalty',
        'INFO org.ergoplatform.network.peer.PeerManager - /127.0.0.1:19600 '
        'penalized, penalty: MisbehaviorPenalty',
        # STOCK behaviour, seen in every peered run with no flood at all:
        # a block applied twice is declared permanently invalid and its
        # sender penalised. Attributed, not charged to the flood.
        'org.ergoplatform.validation.MalformedModifierError: Double '
        'application of a modifier is prohibited. cc already applied',
        'INFO org.ergoplatform.network.peer.PeerManager - /127.0.0.1:19600 '
        'penalized, penalty: MisbehaviorPenalty',
    ]
    # Samples: (log line count at the sample, store size, store bytes).
    _samples = [{'lines': 0, 'size': 0, 'bytes': 0},
                {'lines': 3, 'size': 256, 'bytes': 70000},
                {'lines': 8, 'size': 250, 'bytes': 69000}]
    _ev = _flood_eval.evaluate_root_flood(
        _lines, _samples, {'maxEntries': 256, 'maxBytes': 4194304},
        adversary_octets=range(100, 220))
    assert _ev['adversary_root_lines'] == 2, _ev
    assert _ev['honest_roots'] == 2 and _ev['honest_roots_landed'] == 1, _ev
    assert _ev['honest_roots_while_saturated'] == 1, _ev
    assert _ev['honest_roots_landed_while_saturated'] == 0, _ev
    assert _ev['peak_size'] == 256 and _ev['caps_held'], _ev
    assert _ev['honest_penalties'] == {'NonDeliveryPenalty': 1,
                                       'MisbehaviorPenalty': 2}, _ev
    assert _ev['honest_misbehaviour_penalties'] == 1, _ev
    assert _ev['honest_misbehaviour_after_double_application'] == 1, _ev
    assert _ev['adversary_penalties'] == 1, _ev
    _over = _flood_eval.evaluate_root_flood(
        _lines, _samples + [{'lines': 8, 'size': 257, 'bytes': 1}],
        {'maxEntries': 256, 'maxBytes': 4194304},
        adversary_octets=range(100, 220))
    assert not _over['caps_held'], _over
    # Honest ROOT announcements (+2) only exist while the follower has not
    # yet applied the miner's newest ordering block. An unfunded chain
    # applies coinbase-only blocks at once, and the first F13 flood run
    # (`.work-m4p-f13-flood`) saw 0 honest roots in 12 flooded blocks:
    # the scenario funds the miner and keeps payments in flight so the
    # blocks carry work, as `steady` does.
    import inspect as _insp_fl
    _src_fl = _insp_fl.getsource(_flood_eval._run_against_scala_follower)
    assert 'common.fund_miner(' in _src_fl and 'pump_payments' in \
        _insp_fl.getsource(_flood_eval), 'the root flood must carry a workload'
    # `restart` is where F13's replay of held roots is measured, and its
    # first two runs (`.work-m4p-f13-restart`) were 6 unfunded blocks from
    # genesis: too short and too quiet to say whether the patched follower's
    # lag after the kill is the patch or the recipe. It funds the miner,
    # keeps payments in flight on both sides of the kill, lets
    # `--ordering-blocks` set the pre-kill length, and reports every
    # follower's lag over the samples AFTER the kill separately.
    import scenarios.restart as _restart
    _src_rs = _insp_fl.getsource(_restart.run)
    assert 'common.fund_miner(' in _src_rs and 'pump_payments' in \
        _insp_fl.getsource(_restart), 'restart must carry a workload'
    assert 'ctx.args.ordering_blocks' in _src_rs, \
        'restart must let --ordering-blocks set the pre-kill length'
    _rows = [{'at': 1.0, 'scala_chain': ['a'], 'scala_ordering': 'o',
              'scala2_ordering': 'o', 'scala2_tip': 'a'},
             {'at': 5.0, 'scala_chain': ['c', 'b', 'a'], 'scala_ordering': 'o',
              'scala2_ordering': 'o', 'scala2_tip': 'a'}]
    _after = _restart.lag_after(_rows, 3.0)
    assert _after['scala_follower']['lag_samples'] == 1, _after
    assert _after['scala_follower']['p50'] == 2, _after
    assert _after['since_epoch_s'] == 3.0 and _after['samples'] == 1, _after

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
        # `--base-build` moves EVERY non-patched Scala role — both
        # miners here — and nothing else.
        configure_environment('fork', nodes_for_roles(_fork_roles),
                              _fork_roles, 'F13', 'base')
        assert os.environ['MATRIX_BUILD_SCALA'] == 'base', os.environ
        assert os.environ['MATRIX_BUILD_SCALA2'] == 'base', os.environ
        assert os.environ['MATRIX_BUILD_SCALA3'] == 'F13', os.environ
        # ...the reconstruction measurement's miner AND stock follower...
        _rr_roles = resolve_roles('reconstruct_rate', 'both')
        configure_environment('reconstruct_rate', nodes_for_roles(_rr_roles),
                              _rr_roles, 'F13', 'base')
        assert os.environ['MATRIX_BUILD_SCALA'] == 'base', os.environ
        assert os.environ['MATRIX_BUILD_SCALA2'] == 'base', os.environ
        assert os.environ['MATRIX_BUILD_SCALA3'] == 'F13', os.environ
        # ...and a miner-under-test role is PATCHED, so it follows
        # `--build`, never the base.
        configure_environment('miner_self_reject',
                              nodes_for_roles(SCENARIO_ROLES['miner_self_reject']),
                              SCENARIO_ROLES['miner_self_reject'], 'F11', 'base')
        assert os.environ['MATRIX_BUILD_SCALA'] == 'F11', os.environ
        # The default is still the M4 pin.
        _steady_roles = resolve_roles('steady', 'both')
        configure_environment('steady', nodes_for_roles(_steady_roles),
                              _steady_roles, 'F13')
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
    # A LIVE build is one this host can verify right now. The M4 `stock`
    # pin moved to the shared archive from a worktree that was deleted,
    # and its classpath still names that tree, so until it is
    # re-provisioned it is REFUSED — with the reason — rather than
    # launched. The re-measure base is checked the same way. At least one
    # of the two has to be live, or nothing below exercises a real build.
    _pins = {'stock': ('62c10315', '6.0.6-493-62c10315-SNAPSHOT'),
             'base': ('a1bd938e', None)}
    _live = []
    for _name, (_commit, _version) in _pins.items():
        _entry = _builds.registry()[_name]
        if not _entry.available:
            continue
        try:
            _checked = check_build(_name)
        except SystemExit as error:
            # Refused, and the refusal says what to do about it.
            assert 're-provision' in str(error).lower(), str(error)
            continue
        assert _checked.summary()['ergo_commit'].startswith(_commit), \
            _checked.summary()
        if _version:
            assert _checked.app_version() == _version, _checked.app_version()
        _live.append(_name)
    assert _live, ('neither the stock pin nor the re-measure base is a '
                   'provisioned, verifiable build on this host; provision '
                   'base (builds.toml) before running the self-test')
    # The manifest a scenario records names the build AND its compiled
    # output, per role — here for the base-build knob's slot, the miner.
    _saved_build = os.environ.get('MATRIX_BUILD_SCALA')
    os.environ['MATRIX_BUILD_SCALA'] = _live[0]
    try:
        _manifests = build_manifests(
            {'scala': 'scala_miner', 'rust': 'rust_follower'})
    finally:
        if _saved_build is None:
            os.environ.pop('MATRIX_BUILD_SCALA', None)
        else:
            os.environ['MATRIX_BUILD_SCALA'] = _saved_build
    assert set(_manifests) == {'scala_miner'}, _manifests
    assert _manifests['scala_miner']['build'] == _live[0], _manifests
    assert len(_manifests['scala_miner']['class_dir_sha256']) == 64, _manifests
    # The evidence names the classpath the node was LAUNCHED from, and
    # it is the registered build's own — not a file that happened to sit
    # beside it.
    assert _manifests['scala_miner']['launch_classpath'] == \
        _manifests['scala_miner']['classpath'], _manifests

    # ----- fix round 1, item 2: build verification FAILS CLOSED -----
    #
    # `lifecycle._build_for` used to catch every `BuildError` — a
    # missing build, an unreadable registry, and the one that matters, a
    # class hash that no longer matches the manifest — return `None`,
    # and let `classpath_file` fall back to the legacy
    # `.work/classpath`. The devnet then ran, and the evidence recorded
    # the REGISTERED build while the JVM ran whatever was in `.work`. A
    # number attributed to the wrong build is worse than no number, so
    # the error propagates and the run never starts.
    with tempfile.TemporaryDirectory() as _empty:
        _probe = subprocess.run(
            [sys.executable, '-c',
             'import sys\n'
             'sys.path.insert(0, %r)\n'
             'import builds, lifecycle\n'
             'try:\n'
             '    path = lifecycle.classpath_file("scala")\n'
             'except builds.BuildError as error:\n'
             '    print("REFUSED", error)\n'
             'else:\n'
             '    print("FELL BACK TO", path)\n' % str(HERE)],
            capture_output=True, text=True, cwd=ROOT,
            env={**os.environ, 'MATRIX_BUILDS_ROOT': _empty})
        assert 'REFUSED' in _probe.stdout, \
            ('a build that cannot be verified must abort the run, not fall '
             'back to the legacy classpath', _probe.stdout, _probe.stderr)

    # An explicit classpath override bypasses verification entirely, so
    # a measured campaign refuses one rather than measuring a build
    # nothing checked.
    for _var in ('MATRIX_CLASSPATH', 'MATRIX_CLASSPATH_SCALA2'):
        try:
            check_no_classpath_override({_var: '/tmp/some/classpath'})
        except SystemExit as error:
            assert _var in str(error), (str(error), _var)
        else:
            raise AssertionError(
                f'{_var} must be refused for a measured campaign')
    # An environment without one is fine, and an unrelated MATRIX_ var
    # is not mistaken for one.
    check_no_classpath_override({'MATRIX_NODES': 'scala,rust',
                                 'MATRIX_BUILD_SCALA': 'F11'})

    # And a build whose registered classpath is not the one the node was
    # launched from is an attribution error, not a footnote.
    _good = check_launch_classpath(
        'scala_miner', 'scala', {'build': 'stock', 'classpath': '/a/classpath'},
        '/a/classpath')
    assert _good['launch_classpath'] == '/a/classpath', _good
    assert _good['node'] == 'scala', _good
    try:
        check_launch_classpath(
            'scala_miner', 'scala',
            {'build': 'stock', 'classpath': '/a/classpath'}, '/b/classpath')
    except SystemExit as error:
        assert 'was launched from' in str(error), str(error)
    else:
        raise AssertionError(
            'evidence may not describe a classpath the node did not run')

    # ----- proofs step A (2): never a Rust binary from somewhere else -----
    #
    # With `RUST_NODE` unset the node binary came from `cargo metadata`'s
    # target directory, which on this host is the GLOBAL shared cache: a
    # build from another worktree and another day, launched silently
    # while the evidence named this checkout's commit. Only RUST_NODE or
    # THIS checkout's own release build may be started.
    import lifecycle as _lc_bin
    _saved_root_bin = _lc_bin.ROOT
    _saved_env_bin = os.environ.pop('RUST_NODE', None)
    try:
        with tempfile.TemporaryDirectory() as _tmp_bin:
            _lc_bin.ROOT = Path(_tmp_bin)
            try:
                _lc_bin.node_binary()
            except SystemExit as _refused:
                assert 'RUST_NODE' in str(_refused), _refused
            else:
                raise AssertionError(
                    'a checkout with no release build must refuse to start '
                    'a Rust node, not resolve one elsewhere')
            _local_bin = Path(_tmp_bin) / 'target' / 'release' / 'ergo-node'
            _local_bin.parent.mkdir(parents=True)
            _local_bin.write_text('#!/bin/sh\n')
            _local_bin.chmod(0o755)
            assert _lc_bin.node_binary() == str(_local_bin), \
                _lc_bin.node_binary()
            _prov = _lc_bin.node_binary_provenance()
            assert _prov['source'] == 'worktree release build', _prov
            assert _prov['path'] == str(_local_bin), _prov
            assert len(_prov['sha256']) == 64, _prov
            # An explicit RUST_NODE wins, and must name a real executable.
            os.environ['RUST_NODE'] = str(Path(_tmp_bin) / 'nowhere')
            try:
                _lc_bin.node_binary()
            except SystemExit as _refused:
                assert 'nowhere' in str(_refused), _refused
            else:
                raise AssertionError('RUST_NODE naming no file must refuse')
            os.environ['RUST_NODE'] = str(_local_bin)
            assert _lc_bin.node_binary_provenance()['source'] == 'RUST_NODE'
    finally:
        _lc_bin.ROOT = _saved_root_bin
        os.environ.pop('RUST_NODE', None)
        if _saved_env_bin is not None:
            os.environ['RUST_NODE'] = _saved_env_bin

    # ----- proofs step B: a seeded node AT GENESIS is up, not missing -----
    #
    # `steady` and `restart` seed their reference followers before the
    # first block, where every Scala node answers `/info` with
    # `fullHeight: null`. The seed check read that null as "did not come
    # up" and failed `.work-m4p-f14-steady` although both followers ran,
    # peered and logged 60 blocks. Only a node that did not ANSWER is
    # missing.
    from scenarios import common as _cs
    assert _cs.seeded_nodes_missing(
        {'scala2': None, 'scala3': 0}, unavailable=()) == [], 'genesis is up'
    assert _cs.seeded_nodes_missing(
        {'scala2': None, 'scala3': 7}, unavailable=('scala2',)) == ['scala2']

    # ----- proofs step A (3): the funding wait follows the chain -----
    #
    # `fund_miner` waited a FIXED 900 s. The coinbase is spendable only
    # after `minerRewardDelay` (10) blocks, and ordering-block cadence
    # varies about 5x with host load: `.work-r1both2` reached height 11
    # with 0 balance when 900 s ran out. The budget is now derived from
    # the cadence the wait itself observes.
    from scenarios import common as _cf
    # Nothing observed yet: the prior cadence, over every block to go.
    _d0, _r0 = _cf.funding_deadline([(0.0, 0)])
    assert _r0['cadence_s'] == _cf.FUNDING_CADENCE_PRIOR_S, _r0
    assert _r0['blocks_to_go'] == _cf.FUNDING_TARGET_HEIGHT, _r0
    assert _d0 == (_cf.FUNDING_TARGET_HEIGHT * _cf.FUNDING_CADENCE_PRIOR_S
                   * _cf.FUNDING_SAFETY + _cf.FUNDING_SLACK_S), (_d0, _r0)
    # A loaded host (100 s per block, at height 5) gets MORE than the old
    # fixed 900 s from its last block; a fast one gets less.
    _slow = [(0.0, 1), (100.0, 2), (200.0, 3), (300.0, 4), (400.0, 5)]
    _ds, _rs = _cf.funding_deadline(_slow)
    assert _rs['cadence_s'] == 100.0, _rs
    assert _ds - 400.0 > 900.0, (_ds, _rs)
    _fast = [(0.0, 1), (10.0, 2), (20.0, 3), (30.0, 4), (40.0, 5)]
    _df, _rf = _cf.funding_deadline(_fast)
    assert _rf['cadence_s'] == 10.0 and _df < _ds, (_df, _rf)
    # The budget restarts at every new block, so a live chain is never
    # abandoned mid-maturity, while a stalled one is: the deadline is
    # measured from the LAST block seen.
    _dl, _ = _cf.funding_deadline(_slow + [(900.0, 6)])
    assert _dl > _ds, (_dl, _ds)
    # Well past maturity with nothing to spend is not a cadence problem:
    # the wait ends at once instead of burning the run.
    _past = [(0.0, 1), (10.0, _cf.FUNDING_TARGET_HEIGHT
                       + _cf.FUNDING_OVERRUN_BLOCKS)]
    _dp, _rp = _cf.funding_deadline(_past)
    assert _dp == 10.0 and _rp['overrun'], (_dp, _rp)

    # ----- M4: the reconstruction accounting -----
    import inspect
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
    assert [_scala[f] for f in _common.ACCOUNTING_FIELDS] == \
        [4, 1, 1, 1, 1, 0], _scala
    assert _scala['unaccounted'] == 0, _scala
    assert _scala['reconstructed_ratio'] == 0.25, _scala
    # ----- M4: the GATE, which decides before `processOrderingBlock` -----
    #
    # `ErgoNodeViewSynchronizer.scala:1856-1866` at 62c10315 checks
    # whether the previous input block's transactions are stored and, if
    # they are not, requests the full block WITHOUT ever sending
    # `ProcessOrderingBlock`. None of the five phrases above is then
    # logged. Task 2 measured a stock follower that took that branch 80
    # times in 81 announcements, and the accounting reported the whole
    # reference half as UNKNOWN — a measured 0 % reconstruction rate
    # read as "no data".
    _gated = _common.scala_accounting([
        'INFO On processing ordering block ff, it is last input block Some(gg)',
        'INFO Requesting all the block transactions for ff as prev input '
        'block not found',
    ])
    assert _gated['eligible_announcements'] == 1, _gated
    assert _gated['download_no_prev_input_block'] == 1, _gated
    assert _gated['decided'] == 1 and _gated['unaccounted'] == 0, _gated
    assert _gated['reconstructed_ratio'] == 0.0, _gated
    assert 'unmatched' not in _gated, _gated
    # The gate's own line is the denominator when the entry line is
    # absent, and the two are never double-counted.
    _both = _common.scala_accounting([
        'INFO On processing ordering block aa, it is last input block Some(bb)',
        'INFO Processing ordering block announcement for aa',
        'INFO Applying block transactions from input-blocks for aa with '
        'transactions: 3',
    ])
    assert _both['eligible_announcements'] == 1, _both
    assert _both['reconstructed'] == 1 and _both['unaccounted'] == 0, _both
    assert _both['gate_announcements'] == 1, _both
    assert _both['entry_announcements'] == 1, _both
    # A build that logs none of the five is UNKNOWN, not a clean zero.
    _silent = _common.scala_accounting(['INFO something else entirely'])
    assert 'UNKNOWN, not zero' in _silent['unmatched'], _silent

    # ----- proofs step A (1): one announcement, one decision, per ID -----
    #
    # A follower peered with the miner AND the Rust node hears each
    # announcement from every peer, and the holder logs the entry phrase
    # again after the synchronizer. `.work-r1peer2`'s scala2 log carries
    # 42 entry lines for 18 ordering blocks, so the accounting read 41
    # eligible and 20 unaccounted. Every stage is counted once per
    # ordering-block id; the first decision is the id's outcome and a
    # later one is recorded, never added.
    _sync = 'INFO org.ergoplatform.network.ErgoNodeViewSynchronizer - '
    _hold = 'INFO org.ergoplatform.nodeView.UtxoNodeViewHolder - '
    _dup = _common.scala_accounting([
        # aa: synchronizer entry, gate, holder entry, reconstructed, then
        # the same announcement from a second peer.
        _sync + 'Processing ordering block announcement for aa',
        _sync + 'On processing ordering block aa, it is last input block Some(11)',
        _hold + 'Processing ordering block announcement for aa',
        _hold + 'Applying block transactions from input-blocks for aa with '
                'transactions: 1',
        _sync + 'Processing ordering block announcement for aa',
        # bb: gate download from two peers.
        _sync + 'Processing ordering block announcement for bb',
        _sync + 'On processing ordering block bb, it is last input block Some(22)',
        _sync + 'Requesting all the block transactions for bb as prev input '
                'block not found',
        _sync + 'Processing ordering block announcement for bb',
        _sync + 'On processing ordering block bb, it is last input block Some(22)',
        _sync + 'Requesting all the block transactions for bb as prev input '
                'block not found',
        # cc: root mismatch at the holder, repeated entry after it.
        _sync + 'Processing ordering block announcement for cc',
        _sync + 'On processing ordering block cc, it is last input block Some(33)',
        _hold + 'Processing ordering block announcement for cc',
        'WARN org.ergoplatform.nodeView.UtxoNodeViewHolder - Downloading block '
        'transactions fully for cc as Merkle root does not match',
        _sync + 'Processing ordering block announcement for cc',
    ])
    assert _dup['eligible_announcements'] == 3, _dup
    assert _dup['entry_announcements'] == 3, _dup
    assert _dup['gate_announcements'] == 3, _dup
    assert _dup['reconstructed'] == 1, _dup
    assert _dup['download_no_prev_input_block'] == 1, _dup
    assert _dup['download_root_mismatch'] == 1, _dup
    assert _dup['decided'] == 3 and _dup['unaccounted'] == 0, _dup
    # The duplicates are still visible, as evidence rather than as counts.
    assert _dup['raw_line_counts']['entry_announcements'] == 8, _dup
    assert _dup['repeat_decisions'] == 1, _dup
    assert _dup['conflicting_outcomes'] == {}, _dup
    # Two DIFFERENT decisions about one id: the first is the outcome, the
    # second is named, and the id is not counted twice.
    _flip = _common.scala_accounting([
        _sync + 'On processing ordering block dd, it is last input block Some(44)',
        _sync + 'Requesting all the block transactions for dd as prev input '
                'block not found',
        _hold + 'Applying block transactions from input-blocks for dd with '
                'transactions: 2',
    ])
    assert _flip['eligible_announcements'] == 1, _flip
    assert _flip['download_no_prev_input_block'] == 1, _flip
    assert _flip['reconstructed'] == 0, _flip
    assert _flip['conflicting_outcomes'] == {
        'dd': ['download_no_prev_input_block', 'reconstructed']}, _flip
    # The scenario's own per-follower counter reads the same de-duplicated
    # decisions, so its F5 table cannot disagree with the accounting.
    from scenarios import reconstruct_rate as _rr_dedup
    import smoke as _smoke_dd
    _saved_work_dd = _smoke_dd.WORK
    try:
        with tempfile.TemporaryDirectory() as _tmp_dd:
            _smoke_dd.WORK = Path(_tmp_dd)
            (_smoke_dd.WORK / 'scala2.log').write_text('\n'.join([
                _sync + 'On processing ordering block bb, it is last input '
                        'block Some(22)',
                _sync + 'Requesting all the block transactions for bb as prev '
                        'input block not found',
                _sync + 'Requesting all the block transactions for bb as prev '
                        'input block not found',
                _hold + 'Applying block transactions from input-blocks for aa '
                        'with transactions: 1',
                _hold + 'Applying block transactions from input-blocks for aa '
                        'with transactions: 1',
            ]) + '\n')
            _counts_dd = _rr_dedup._scala_log_counts(None, 'scala2', 0)
            assert _counts_dd['decided'] == 2, _counts_dd
            assert _counts_dd['reconstructed'] == 1, _counts_dd
            assert _counts_dd['fallback_at_gate'] == 1, _counts_dd
            assert _counts_dd['reconstructed_ratio'] == 0.5, _counts_dd
    finally:
        _smoke_dd.WORK = _saved_work_dd

    # ----- fix round 1, item 3: both halves count the SAME interval -----
    #
    # The Rust half was a watermarked collector over the scenario's
    # window; the Scala half was the node's WHOLE log, which starts at
    # spawn and covers start-up and funding as well. An input block
    # applied before the window opened therefore appeared in one
    # accounting and not the other, and `miner_self_reject` counted the
    # miner's entire log against a best-chain sample that began after
    # funding — so applied blocks outside the sampled interval read as
    # blocks that never reached the winning chain.
    class _StubCollector:
        """Only what the accounting asks of a collector."""

        def __init__(self, events):
            self.events = list(events)
            self.highest_seen = 41

        def poll(self):
            return self.events

        def window(self, watermark, until=None):
            return self.events

        def summary(self, watermark):
            return {'watermark': watermark}

        def lost_in_window(self, watermark):
            return False

    class _StubCtx:
        def __init__(self, role_map):
            self.roles = dict(role_map)
            self.collector = None
            self.collector_watermark = 0

    _startup = (
        'INFO On processing ordering block aa, it is last input block Some(bb)\n'
        'INFO Requesting all the block transactions for aa as prev input '
        'block not found\n')
    _in_window = (
        'INFO Processing ordering block announcement for cc\n'
        'INFO Applying block transactions from input-blocks for cc with '
        'transactions: 3\n')
    import smoke as _smoke
    _saved_work = _smoke.WORK
    try:
        with tempfile.TemporaryDirectory() as _tmp:
            _smoke.WORK = Path(_tmp)
            (_smoke.WORK / 'scala2.log').write_text(_startup)
            _ctx = _StubCtx({'scala2': 'scala_follower',
                             'rust': 'rust_follower'})
            _collector = _StubCollector([{'kind': 'ordering_reconstructed'}])
            # ONE boundary for both halves.
            _offsets = _common.open_measurement_window(_ctx, _collector)
            assert _offsets == {'scala2': 2}, _offsets
            assert _ctx.collector_watermark == 41, _ctx.collector_watermark
            with (_smoke.WORK / 'scala2.log').open('a') as _fh:
                _fh.write(_in_window)
            _acct = _common.reconstruction_accounting(_ctx)
            _half = _acct['scala_follower']
            assert _half['from_line'] == 2, _half
            assert _half['eligible_announcements'] == 1, _half
            assert _half['reconstructed'] == 1, _half
            # The two start-up lines are BEFORE the boundary and belong
            # to neither half.
            assert _half['download_no_prev_input_block'] == 0, _half
            assert _acct['rust_follower']['reconstructed'] == 1, _acct
            # Only what was written after the boundary is this window.
            assert _common.scala_window_lines(_ctx, 'scala2') == \
                _in_window.splitlines(), _common.scala_window_lines(_ctx, 'scala2')
            # A scenario that never opened a window reads the whole log
            # and SAYS so, rather than presenting it as a measurement.
            _bare = _StubCtx({'scala2': 'scala_follower'})
            _whole = _common.reconstruction_accounting(_bare)['scala_follower']
            assert _whole['from_line'] == 0, _whole
            assert 'window' in _whole.get('interval', ''), _whole
    finally:
        _smoke.WORK = _saved_work
    # ----- step A (4): ONE closing boundary for every half -----
    #
    # The window had a common OPENING but no common close: Rust event
    # collection stopped where the scenario stopped polling, while the
    # Scala logs were read at finalisation, after the peering and
    # agreement checks — `.work-r1both3` shows 14 vs 15 Scala decisions
    # from the same start offset. The close is one snapshot (the event
    # sequence AND every Scala log's line count), and every accounting
    # reads up to it. Exercised through the REAL collector and the
    # production accounting, with only the feed and the logs stubbed.
    _feed_close = {'events': []}
    _saved_api_close = _common.api
    _saved_work_close = _smoke.WORK
    try:
        with tempfile.TemporaryDirectory() as _tmp_close:
            _smoke.WORK = Path(_tmp_close)
            _common.api = lambda node, path, *a, **k: _feed_close
            (_smoke.WORK / 'scala2.log').write_text('INFO start-up\n')
            _ctx_close = _StubCtx({'scala2': 'scala_follower',
                                   'rust': 'rust_follower'})
            _col = _common.EventCollector(_ctx_close)
            _common.open_measurement_window(_ctx_close, _col)
            _feed_close['events'] = [
                {'seq': 1, 'kind': 'ordering_reconstructed'}]
            with (_smoke.WORK / 'scala2.log').open('a') as _fh:
                _fh.write(
                    'INFO On processing ordering block aa, it is last input '
                    'block Some(11)\n'
                    'INFO Applying block transactions from input-blocks for aa '
                    'with transactions: 1\n')
            _snap = _common.close_measurement_window(_ctx_close)
            assert _snap == {'rust_event_seq': 1,
                             'scala_log_lines': {'scala2': 3}}, _snap
            # After the close: one more decision on EACH side.
            _feed_close['events'] = [
                {'seq': 1, 'kind': 'ordering_reconstructed'},
                {'seq': 2, 'kind': 'ordering_reconstruct_fallback',
                 'detail': 'root_mismatch'}]
            _col.poll()
            with (_smoke.WORK / 'scala2.log').open('a') as _fh:
                _fh.write(
                    'INFO On processing ordering block bb, it is last input '
                    'block Some(22)\n'
                    'INFO Requesting all the block transactions for bb as prev '
                    'input block not found\n')
            # A second close is the same snapshot, never a later one.
            assert _common.close_measurement_window(_ctx_close) == _snap
            _acct_close = _common.reconstruction_accounting(_ctx_close)
            assert _acct_close['closing_boundary'] == _snap, _acct_close
            _sc = _acct_close['scala_follower']
            assert _sc['eligible_announcements'] == 1, _sc
            assert _sc['download_no_prev_input_block'] == 0, _sc
            _rc = _acct_close['rust_follower']
            assert _rc['eligible_announcements'] == 1, _rc
            assert _rc['download_root_mismatch'] == 0, _rc
            assert _common.scala_window_lines(_ctx_close, 'scala2') == [
                'INFO On processing ordering block aa, it is last input '
                'block Some(11)',
                'INFO Applying block transactions from input-blocks for aa '
                'with transactions: 1']
            # And the scenario's own per-follower table reads up to the
            # same close.
            from scenarios import reconstruct_rate as _rr_close
            _counts_close = _rr_close._scala_log_counts(
                _ctx_close, 'scala2', 1, _snap['scala_log_lines']['scala2'])
            assert _counts_close['decided'] == 1, _counts_close
    finally:
        _common.api = _saved_api_close
        _smoke.WORK = _saved_work_close

    # And the measurement scenario counts its miner over that same
    # window rather than over the node's whole lifetime.
    from scenarios import miner_self_reject as _msr_src
    assert 'scala_window_lines' in inspect.getsource(_msr_src.run), \
        ('miner_self_reject must count the window it sampled, not the '
         'miner\'s entire log')

    # ----- fix round 1, item 1: the F5 counter reads EVERY follower -----
    #
    # `reconstruct_rate` counted its reference half from the literal
    # node name `scala2`. With `--reference-follower patched` the stock
    # follower is not in the run at all and the counter read a log that
    # was never written; with `both` the patched follower's decisions —
    # the entire point of the ablation — were collected by the driver's
    # accounting but not by the scenario's own F5 counter.
    _table = lifecycle.ROLES
    _miners, _followers = _common.scala_reference_nodes(
        lifecycle.roles_for_nodes(resolve_roles('reconstruct_rate', 'both')),
        _table)
    assert _miners == ('scala',), _miners
    assert _followers == ('scala2', 'scala3'), _followers
    # `patched` alone: the stock follower is NOT in the run, so nothing
    # may read its log.
    _m, _f = _common.scala_reference_nodes(
        lifecycle.roles_for_nodes(resolve_roles('reconstruct_rate', 'patched')),
        _table)
    assert _f == ('scala3',), _f
    # A second MINER is not a reference follower: it decides nothing,
    # because it generates its blocks locally.
    _m, _f = _common.scala_reference_nodes(
        lifecycle.roles_for_nodes(SCENARIO_ROLES['fork']), _table)
    assert _m == ('scala', 'scala2') and _f == (), (_m, _f)
    # The Rust node is never a Scala reference.
    assert 'rust' not in _m and 'rust' not in _f, (_m, _f)
    # And the scenario no longer names a node literally.
    from scenarios import reconstruct_rate as _rr
    _run_source = inspect.getsource(_rr.run)
    assert "'scala2'" not in _run_source and "'scala'" not in _run_source, \
        ('reconstruct_rate.run must resolve its reference nodes from the '
         'roles, not from literal node names', _run_source)

    # ----- fix round 1: the seed's rust restart must CLEAR the backoff -
    #
    # Measured on the first `--reference-follower both` validation run:
    # the follower had been dialling `scala2` and `scala3` for the whole
    # funding wait, with nothing there, so both addresses were deep in an
    # exponential dial backoff. `seed_second_miner` restarts the follower
    # to clear that — but the address book PERSISTS the backoff
    # timestamps (`ergo_node::node::util::wall_to_instant` restores
    # them), so it came back and immediately logged "peer bootstrap
    # starved: no dial candidates (all known addresses in dial-backoff)".
    # It held the miner and neither follower, and the run produced 0
    # follower samples.
    with tempfile.TemporaryDirectory() as _tmp:
        _root = Path(_tmp)
        for _node in ('rust', 'scala2'):
            (_root / _node).mkdir(parents=True)
        _book = _root / 'rust' / 'peers.redb'
        _book.write_bytes(b'backoff state')
        (_root / 'scala2' / 'peers.redb').write_bytes(b'not the follower')
        _removed = purge_address_book(_root)
        assert not _book.exists(), 'the follower\'s address book must go'
        assert [str(_book)] == _removed, _removed
        assert (_root / 'scala2' / 'peers.redb').exists(), \
            'only the follower\'s book is purged'
        # Idempotent: a run with no book is not an error.
        assert purge_address_book(_root) == []
    # And the seed does it, between stopping the follower and starting it
    # again — a purge with the node running would be a no-op it then
    # rewrites.
    # The seed restarts the follower through `restart_follower`, which
    # owns the purge.
    assert 'restart_follower(ctx, campaign, lifecycle)' in inspect.getsource(
        _common.seed_second_miner), (
        'seed_second_miner restarts the follower to clear its dial '
        'backoff; the backoff is persisted, so the address book has to go '
        'with it')
    _seed = inspect.getsource(_common.restart_follower)
    assert 'purge_address_book' in _seed, (
        'restart_follower must drop the persisted dial backoff')
    assert _seed.index('purge_address_book') > _seed.index("stop(('rust',))"), \
        'the purge belongs between the stop and the respawn'
    assert _seed.index('purge_address_book') < _seed.index("spawn('rust')"), \
        'the purge belongs between the stop and the respawn'

    # ----- a seeded Scala node must not inherit the miner's peer DB -----
    #
    # Measured on the first run with the followers on their own loopback
    # addresses: `seed_second_miner` copies the miner's data directory,
    # `peers/` included, and Scala's PeerManager seeds from
    # `scorex.network.knownPeers` ONLY when that database is empty
    # (PeerManager.scala:24-33). The copy held one peer (the Rust node),
    # so the follower logged "1 peers read from the database", never
    # learned the miner's address, and dialled Rust alone. Gossip cannot
    # fill the gap: PeerManager refuses local addresses from peers
    # (:53, :67).
    with tempfile.TemporaryDirectory() as _tmp:
        _seeded = Path(_tmp) / 'scala2'
        (_seeded / 'peers').mkdir(parents=True)
        (_seeded / 'peers' / 'x.ldb').write_bytes(b'the miner\'s peers')
        (_seeded / 'history').mkdir()
        _common.drop_copied_peer_db(_seeded)
        assert not (_seeded / 'peers').exists(), 'the copied peer DB must go'
        assert (_seeded / 'history').exists(), 'the chain must stay'
        _common.drop_copied_peer_db(_seeded)   # idempotent
    _seed_src = inspect.getsource(_common.seed_second_miner)
    assert 'drop_copied_peer_db(target)' in _seed_src, (
        'every seeded node needs the miner\'s peer DB removed')
    assert _seed_src.index('drop_copied_peer_db(target)') > \
        _seed_src.index('copytree'), 'the drop belongs after the copy'

    # ----- fix round 1 (codex review-2): seed, THEN assert peering ---
    #
    # `--reference-follower` deliberately leaves its node out of
    # `START_NODES` and brings it up in the seed. A scenario that
    # asserted peering first therefore asked a node that did not exist
    # yet whether it had peers, which is an unavoidable false failure —
    # Task 2's steady evidence carries the connection refusal.
    for _name in REFERENCE_FOLLOWER_SCENARIOS:
        _src = inspect.getsource(_all[_name].run)
        if 'seed_second_miner' not in _src or 'assertion_1_peering' not in _src:
            continue
        assert _src.index('seed_second_miner') < \
            _src.index('assertion_1_peering'), (
                _name, 'peering is asserted before the follower is seeded')

    # ----- fix round 1, item 8: ONE workload, not two copies -----
    #
    # `reconstruct_rate` and `miner_self_reject` each carried a verbatim
    # copy of the funding and payment-pump helpers, and the two
    # measurements they feed are read against each other — so a fix to
    # one workload would silently not apply to the other.
    from scenarios import miner_self_reject as _msr_mod
    for _mod in (_rr, _msr_mod):
        _src = inspect.getsource(_mod)
        assert 'def _fund(' not in _src and 'def _pump(' not in _src, _mod
        assert 'common.fund_miner(' in _src and 'common.pump_payments(' in _src, \
            _mod
    # EVERY scenario that pumps payments does it through the shared
    # helper. `evict` and `steady` kept their own copies too, and
    # `steady` is where the stock follower's lag is measured.
    for _name, _module in _all.items():
        _src = inspect.getsource(_module)
        if '/wallet/payment/send' not in _src:
            continue
        assert 'common.pump_payments(' in _src, (
            _name, 'a scenario that submits payments must use the shared '
            'workload, or a fix to it reaches some windows and not others')
        assert "smoke.request(" not in _src, (
            _name, 'a private copy of the payment submission')
    # And the shared pump records what the node REFUSED rather than
    # dropping it: a window whose workload never landed measured the
    # quiet case, and the evidence has to be able to say so.
    _answers = [(200, 'aa'), (400, None), (200, None)]
    _saved_request = _smoke.request
    try:
        _smoke.request = lambda node, route, body: _answers.pop(0)
        _sent, _refused = [], []
        _common.pump_payments(None, 'addr', _sent, 'scala', count=3,
                              rejected=_refused)
        assert _sent == ['aa'], _sent
        assert len(_refused) == 2, _refused
        assert all('HTTP' in r for r in _refused), _refused
    finally:
        _smoke.request = _saved_request

    # ----- M4: the miner_self_reject denominators -----
    from scenarios import miner_self_reject as _msr
    _log = [
        'INFO Found solution for input block, sending it for validation',
        'INFO Input-block ' + 'ab' * 32 + ' mined @ height 7!',
        # The send to the node view that follows it at 62c10315
        # (`sendInputToNodeView`, CandidateGenerator.scala:87). Both
        # lines name ONE block, which must be counted once.
        'INFO New input block ' + 'ab' * 32 + ' w. nonce 91',
        'INFO Processed solution x with the result Success(())',
        'INFO Solution accepted',
        'INFO Found solution for input block, sending it for validation',
        # The WARN as the pinned build logs it: level, logger, ` - `.
        # The PoW-failure count is anchored on that prefix, so a fixture
        # without it would not be the line a real run holds.
        'WARN org.ergoplatform.mining.CandidateGenerator - '
        'Removing candidate due to invalid input block',
        'INFO Processed solution y with the result Error(java.lang.Exception: '
        'Invalid input block! PoW valid: false)',
        'ERROR Accepting solution or preparing candidate did not succeed',
        # The stack trace the ERROR above carries. It is the SECOND line
        # per failure holding the exception text, and leaving it out of
        # this fixture is what made `pow_failure_sites_disagree` fire on
        # every real run: the Task 2 trial at stock 62c10315 counted 83
        # WARNs against 166 exception-text lines, exactly two per
        # failure.
        'java.lang.Exception: Invalid input block! PoW valid: false',
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
    # ONE failure, TWO lines carrying the exception text, and the flag
    # stays quiet: it exists to catch a build that stops logging them in
    # that proportion, not to fire on every stock run.
    assert _counts['pow_failure_reply_lines'] == 2, _counts
    assert _counts['pow_failure_sites_disagree'] is False, _counts
    # A build that logged the text once per failure HAS changed, and
    # says so.
    _changed = _msr.count([ln for ln in _log
                           if not ln.startswith('java.lang.Exception')])
    assert _changed['pow_failure_sites_disagree'] is True, _changed
    # With neither site logging there is nothing to disagree about.
    assert _msr.count(
        ['INFO Found solution for input block, sending it for validation',
         'INFO Solution accepted'])['pow_failure_sites_disagree'] is False
    # But a build whose WARN has DISAPPEARED while the exception text
    # survives is the same drift in the other direction, and gating the
    # comparison on a nonzero WARN count reported agreement for it
    # (codex review-2). Zero against zero already agrees; zero against
    # two does not.
    _warn_gone = _msr.count([
        'INFO Found solution for input block, sending it for validation',
        'INFO Processed solution y with the result Error(java.lang.Exception: '
        'Invalid input block! PoW valid: false)',
        'java.lang.Exception: Invalid input block! PoW valid: false'])
    assert _warn_gone['pow_failures'] == 0, _warn_gone
    assert _warn_gone['pow_failure_reply_lines'] == 2, _warn_gone
    assert _warn_gone['pow_failure_sites_disagree'] is True, _warn_gone
    assert _counts['distinct_applied_input_blocks'] == 1, _counts
    assert _counts['applied_input_block_ids'] == ['ab' * 32], _counts
    # ----- F11's own wording for the same rejection -----
    #
    # F11 replaced the stock WARN with `No retained candidate matches
    # input solution PoW` and logs its reply text ONCE, as the
    # `StatusReply$ErrorMessage` line under `ErgoMiningThread`'s ERROR —
    # not twice, as stock does. A counter that knew only the stock
    # phrase read 0 on every F11 run, and the 2:1 cross-check passed
    # because 0 = 2 x 0 (batch review, 2026-09-24). Taken from the saved
    # F11 run 2 log, lines 62-66.
    _f11_reject = [
        'INFO org.ergoplatform.mining.ErgoMiningThread - Found solution for '
        'input block, sending it for validation',
        'WARN org.ergoplatform.mining.CandidateGenerator - No retained '
        'candidate matches input solution PoW',
        'ERROR org.ergoplatform.mining.ErgoMiningThread - Accepting solution '
        'or preparing candidate did not succeed',
        'akka.pattern.StatusReply$ErrorMessage: No retained candidate '
        'matches input solution PoW',
    ]
    _f11c = _msr.count(_f11_reject)
    assert _f11c['pow_failures'] == 1, _f11c
    # The echo line carries the same words and must not count twice.
    assert _f11c['pow_failure_reply_lines'] == 1, _f11c
    assert _f11c['pow_failure_sites_disagree'] is False, _f11c
    assert _f11c['replies_error'] == 1, _f11c
    assert _f11c['rejections_exceed_error_replies'] is False, _f11c
    # The echo alone is not a failure the generator logged.
    _echo_only = _msr.count(_f11_reject[-1:])
    assert _echo_only['pow_failures'] == 0, _echo_only
    assert _echo_only['pow_failure_sites_disagree'] is True, _echo_only
    # The ordering arm, in either wording, counts apart from the input
    # arm; stock's plural WARN has no `input` in it.
    _ordering = _msr.count([
        'WARN org.ergoplatform.mining.CandidateGenerator - '
        'Removing candidates due to invalid block',
        'WARN org.ergoplatform.mining.CandidateGenerator - '
        'No retained candidate matches ordering solution PoW',
        'WARN org.ergoplatform.mining.CandidateGenerator - '
        'Stale input ordering parent abc',
    ])
    assert _ordering['pow_failures'] == 0, _ordering
    assert _ordering['pow_failures_ordering'] == 2, _ordering
    assert _ordering['stale_parent_rejections'] == 1, _ordering
    # F11's other reply arms are rejections too, counted by arm and never
    # as PoW failures.
    _other = _msr.count([
        'INFO org.ergoplatform.mining.CandidateGenerator - '
        'Input block already known: ab',
        'WARN org.ergoplatform.mining.CandidateGenerator - '
        'Input processing timed out: ab',
        'ERROR org.ergoplatform.mining.ErgoMiningThread - Accepting solution '
        'or preparing candidate did not succeed',
    ])
    assert _other['pow_failures'] == 0, _other
    assert _other['other_rejections'] == {
        'already_known': 1, 'pending': 0, 'already_solved': 0,
        'invalid_wrapped': 0, 'invalid_unwrapped': 0, 'pending_timeout': 1,
        'pending_deferral': 0}, _other
    # Two rejections, one error reply: the phrases no longer describe the
    # build, and the evidence says so.
    assert _other['rejections_exceed_error_replies'] is True, _other
    assert _counts['rejections_exceed_error_replies'] is False, _counts
    # ----- the patched miner's log line -----
    #
    # F11 (`matrix/F11-candidate-retained-work`) rewrote the
    # `InputSolutionFound` arm and dropped `Input-block <id> mined @
    # height <h>!`. Only `sendInputToNodeView`'s `New input block <id> w.
    # nonce <n>` is left, and at 62c10315 that line sits at the same call.
    # Matching the stock line alone made the F11 proof run report
    # `input_blocks_applied 0` and `on_winning_chain 0`, although the same
    # window held about 3 020 applied input blocks.
    assert _counts['input_blocks_applied'] == 1, (
        'the stock pair of lines is ONE block', _counts)
    _f11 = _msr.count([
        'INFO Found solution for input block, sending it for validation',
        'INFO New input block ' + 'cd' * 32 + ' w. nonce 22',
        'INFO Solution accepted'])
    assert _f11['input_blocks_applied'] == 1, _f11
    assert _f11['applied_input_block_ids'] == ['cd' * 32], _f11
    assert _f11['applied_sites_disagree'] is False, (
        'a build that logs only the send site is not disagreement', _f11)
    # Both sites logging different blocks means the two lines no longer
    # mark the same call, and the evidence has to say so.
    _split = _msr.count([
        'INFO Input-block ' + 'ab' * 32 + ' mined @ height 7!',
        'INFO New input block ' + 'cd' * 32 + ' w. nonce 22'])
    assert _split['applied_sites_disagree'] is True, _split
    assert _counts['applied_sites_disagree'] is False, _counts
    # An empty window is UNKNOWN, not a run with no submissions.
    assert 'UNKNOWN, not zero' in _msr.count([])['unmatched']
    # The result line renders, names the build, and carries every
    # denominator §7a asks for.
    # ----- fix round 1, Minor: the winning-chain count is a FLOOR -----
    #
    # The best input chain is sampled periodically and resets at every
    # ordering block, so a block that was on the winning chain between
    # two samples is never seen; and a read that was unavailable used to
    # be skipped silently. The number is an observed lower bound and the
    # evidence says so, with the sampling that produced it.
    _chain = _msr.winning_chain_note(
        applied={'aa', 'bb', 'cc'}, winning={'aa', 'bb', 'zz'},
        reads=100, failures=7)
    assert _chain['on_winning_chain'] == 2, _chain
    assert _chain['on_winning_chain_is_lower_bound'] is True, _chain
    assert _chain['chain_reads'] == 100, _chain
    assert _chain['chain_read_failures'] == 7, _chain
    assert _chain['applied_but_never_sampled_on_the_chain'] == ['cc'], _chain
    assert 'lower bound' in _chain['source'], _chain
    # A run in which every read failed has not observed the chain at all.
    _blind = _msr.winning_chain_note({'aa'}, set(), reads=5, failures=5)
    assert _blind['chain_never_observed'] is True, _blind
    assert 'UNKNOWN' in _blind['unmatched'], _blind
    assert _msr.winning_chain_note({'aa'}, {'aa'}, 5, 0).get(
        'chain_never_observed') is False

    _line = _msr.result_line({
        'build': 'F11', 'miner': _counts,
        'winning_chain': _msr.winning_chain_note({'ab' * 32}, {'ab' * 32},
                                                 10, 0)})
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
        # `verdict_for` is `verdict_of` for a scenario WITH a criterion.
        assert verdict_of('steady', aborted, failures, None, not_measured) \
            == expected, (aborted, failures, not_measured)
    verdicts = []
    for aborted, failures, expected in (
            (None, [], 'PASS'),
            (None, [{'message': 'x'}], 'FAIL'),
            ('RuntimeError: rust did not become ready', [], 'ABORTED'),
            ('RuntimeError: boom', [{'message': 'x'}], 'ABORTED')):
        got = verdict_of('steady', aborted, failures)
        verdicts.append(got)
        assert got == expected, (aborted, failures, got, expected)
    assert 'ABORTED' in verdicts, verdicts

    # ----- fix round 1, item 4: a MEASUREMENT does not PASS -----
    #
    # `miner_self_reject` has no pass criterion by construction — its
    # own docstring says so, and `task-0-brief.md:32` requires it. The
    # driver nevertheless wrote PASS whenever nothing failed, so a run
    # that covered 3 of its 40 ordering blocks and a run that covered
    # all 40 read identically, and a campaign summary counted the
    # measurement among its passes.
    assert 'miner_self_reject' in MEASUREMENT_SCENARIOS, MEASUREMENT_SCENARIOS
    assert verdict_of('miner_self_reject', None, [], True) == 'MEASURED'
    # A short window, a phrase set that matched nothing, or any failure
    # at all leaves the measurement INCOMPLETE — never PASS, and never
    # FAIL either, because there is no criterion to fail.
    assert verdict_of('miner_self_reject', None, [], False) == 'INCOMPLETE'
    assert verdict_of('miner_self_reject', None, [{'message': 'x'}], True) == \
        'INCOMPLETE'
    # A scenario that never stated whether its window completed has not
    # shown that it did.
    assert verdict_of('miner_self_reject', None, [], None) == 'INCOMPLETE'
    # An abort still outranks everything.
    assert verdict_of('miner_self_reject', 'RuntimeError: boom', [], True) == \
        'ABORTED'
    # PASS is not silently widened for the scenarios that do have a
    # criterion.
    assert verdict_of('steady', None, [], True) == 'PASS'
    # The exit code and the campaign summary treat a completed
    # measurement as a run that did what it was asked, and INCOMPLETE as
    # one that did not. NOT MEASURED exits 0 too (a limitation of the
    # host, not a broken scenario) — it is its own verdict, never PASS.
    assert set(OK_RESULTS) == {'PASS', 'MEASURED', 'NOT MEASURED'}, OK_RESULTS
    for _bad in ('FAIL', 'ABORTED', 'INCOMPLETE'):
        assert _bad not in OK_RESULTS, _bad

    # And the rule the driver uses is THIS function, not a copy that has
    # drifted: the driver persists through `persist_verdict`, and that
    # has to call it. (That every attempt is recorded, pass or fail, is
    # proven by driving the real `run_scenario` below.)
    import inspect
    assert 'persist_verdict(name, evidence' in inspect.getsource(run_scenario), \
        'the driver must persist through persist_verdict'
    assert 'verdict_of(name, aborted' in inspect.getsource(persist_verdict), \
        'the driver must use this rule'
    assert 'OK_RESULTS' in inspect.getsource(main), \
        'the exit code has to come from the same table'
    # And every measurement scenario STATES whether its window
    # completed; without that the driver can only call it INCOMPLETE.
    for _name in MEASUREMENT_SCENARIOS:
        assert "ctx.note('measurement_complete'" in inspect.getsource(
            _all[_name].run), (
                _name, 'a measurement scenario has to say whether it measured')
    _self_test_driver()
    _self_test_round_2()
    _self_test_remeasure()

    print('campaign self-test OK: rendering, ports and the scenario set')


def _self_test_remeasure():
    """The #2563 re-measure's knobs (REVIEW-2563 §3.3), through the
    production code: the base build, the Scala-follower restart, the
    flood modes at the shipped caps, the waitlist counter, and a
    simultaneous kill that refuses before it signals anything."""
    import inspect
    import types

    from scenarios import common, flood, restart

    # ----- knobs are refused where they would be ignored -----
    for _scenario in ORDER:
        check_scenario_knobs(_scenario)            # the defaults: always fine
    check_scenario_knobs('restart', 'both', 'scala-followers')
    check_scenario_knobs('restart', 'patched', 'scala-followers')
    check_scenario_knobs('flood', 'patched', flood_mode='held')
    check_scenario_knobs('flood', 'stock', flood_mode='held')
    check_scenario_knobs('restart', 'both', 'scala-followers',
                         post_ordering_blocks=10)
    _post = types.SimpleNamespace(args=types.SimpleNamespace(
        post_ordering_blocks=None))
    assert restart.post_restart_blocks(_post) == restart.BLOCKS_AFTER_RESTART
    _post.args.post_ordering_blocks = 10
    assert restart.post_restart_blocks(_post) == 10
    for _bad, _why in (
            (('restart', None, 'scala-followers'), 'needs a Scala follower'),
            (('steady', 'both', 'scala-followers'), 'applies to restart only'),
            (('flood', None, 'rust', 'held'), 'ROOT flood'),
            (('steady', 'both', 'rust', 'held'), 'applies to flood only'),
            (('restart', 'both', 'miner'), '--restart-victim must be'),
            (('flood', 'stock', 'rust', 'sometimes'), '--flood-mode must be'),
            (('steady', None, 'rust', 'hit-and-run', 10), 'restart only'),
            (('restart', None, 'rust', 'hit-and-run', 0), 'at least 1')):
        try:
            check_scenario_knobs(*_bad)
        except SystemExit as error:
            assert _why in str(error), (_bad, str(error))
        else:
            raise AssertionError(f'{_bad} must be refused')
    # ...and refused by the CLI before any build is checked or node started.
    _cli = subprocess.run(
        [sys.executable, str(HERE / 'campaign.py'), '--scenario', 'restart',
         '--restart-victim', 'scala-followers'],
        capture_output=True, text=True, cwd=ROOT, timeout=60)
    assert _cli.returncode != 0 and 'needs a Scala follower' in _cli.stderr, \
        (_cli.returncode, _cli.stdout, _cli.stderr)

    # ----- the Rust node has no Scala build to verify -----
    # Its launch resolved a classpath too, verifying `stock` by default,
    # so with every build unverifiable the follower refused to start in a
    # run that asked for no stock role (the first `--base-build base`
    # validation run).
    with tempfile.TemporaryDirectory() as _empty:
        _rust = subprocess.run(
            [sys.executable, '-c',
             'import sys\n'
             'sys.path.insert(0, %r)\n'
             'import lifecycle\n'
             'print(lifecycle._command("rust")[0])\n' % str(HERE)],
            capture_output=True, text=True, cwd=ROOT,
            env={**os.environ, 'MATRIX_BUILDS_ROOT': _empty,
                 'RUST_NODE': sys.executable})
        assert _rust.returncode == 0 and sys.executable in _rust.stdout, \
            (_rust.stdout, _rust.stderr)

    # ----- `--scenario all` forwards each knob to its own scenario -----
    _args = types.SimpleNamespace(
        timeout=60, build='F13', base_build='base', reference_follower='both',
        restart_victim='scala-followers', flood_mode='held', fresh=True,
        force_attempt=False, post_ordering_blocks=10, ordering_blocks=7)
    _restart = child_argv('restart', _args)
    assert _restart[_restart.index('--base-build') + 1] == 'base', _restart
    assert _restart[_restart.index('--build') + 1] == 'F13', _restart
    assert '--restart-victim' in _restart and '--flood-mode' not in _restart
    assert _restart[_restart.index('--post-ordering-blocks') + 1] == '10'
    _flood = child_argv('flood', _args)
    assert '--flood-mode' in _flood and '--restart-victim' not in _flood, _flood
    assert '--post-ordering-blocks' not in _flood, _flood
    _steady = child_argv('steady', _args)
    assert '--flood-mode' not in _steady and '--restart-victim' not in _steady
    # The campaign-wide block count reaches every child.
    for _child in (_restart, _flood, _steady):
        assert _child[_child.index('--ordering-blocks') + 1] == '7', _child
    # An explicit zero post-kill window is forwarded (and refused there),
    # an absent one is not forwarded at all.
    _args.post_ordering_blocks, _args.ordering_blocks = 0, None
    _zero = child_argv('restart', _args)
    assert _zero[_zero.index('--post-ordering-blocks') + 1] == '0', _zero
    assert '--ordering-blocks' not in _zero, _zero
    _args.post_ordering_blocks = None
    assert '--post-ordering-blocks' not in child_argv('restart', _args)
    assert '--base-build' in _steady and '--fresh' in _steady, _steady

    # ----- which builds a run checks before starting -----
    # No patched role: `--build` is not checked, whatever it names.
    assert builds_in_use(['steady'], None, 'soak', 'base') == ['base']
    assert builds_in_use(['steady'], 'patched', 'soak', 'base') == \
        ['base', 'soak']
    # A patched miner needs `--build` even with no reference follower.
    assert builds_in_use(['miner_self_reject'], None, 'soak', 'base') == \
        ['soak']
    # Refused during role resolution, or unknown: skipped, refused later.
    assert builds_in_use(['flood'], 'both', 'soak', 'base') == []
    assert builds_in_use(['nonesuch'], None, 'soak', 'base') == []
    # `all` checks the union once, in first-use order.
    assert builds_in_use(list(ORDER), None, 'soak', 'base') == ['base', 'soak']

    # ----- restart: who dies -----
    assert restart.victims_for('rust', ('scala', 'scala2', 'rust')) == ('rust',)
    assert restart.victims_for(
        'scala-followers', ('scala', 'scala2', 'scala3', 'rust')) == \
        ('scala2', 'scala3')
    assert restart.victims_for('scala-followers', ('scala', 'scala3', 'rust')) \
        == ('scala3',)
    try:
        restart.victims_for('scala-followers', ('scala', 'rust'))
    except ValueError:
        pass
    else:
        raise AssertionError('a Scala-follower restart with no follower must stop')
    _src = inspect.getsource(restart._run_scala_victims)
    # One simultaneous kill, and the sampler told the victims are down on
    # purpose — so the miner and the Rust follower stay sampled.
    assert 'kill_hard_many(victims)' in _src and 'expect_down(victims)' in _src
    assert 'restart_recovery' in _src and 'scala_waitlist' in _src
    # ...and they come back together, not one JVM start apart.
    assert 'ThreadPoolExecutor' in _src, 'the victims respawn concurrently'

    # ----- a simultaneous kill refuses BEFORE it signals anything -----
    global WORK, KILL_SETTLE_SECONDS
    _saved_work, _saved_settle = WORK, KILL_SETTLE_SECONDS
    _procs = []
    with tempfile.TemporaryDirectory() as _tmp:
        try:
            WORK, KILL_SETTLE_SECONDS = Path(_tmp), 0.0
            for _name in ('victim_a', 'victim_b'):
                _proc = subprocess.Popen(['sleep', '300'], cwd=ROOT)
                _procs.append(_proc)
                (WORK / f'{_name}.pid').write_text(str(_proc.pid))
                (WORK / f'{_name}.config').write_text('sleep 300')
            try:
                kill_hard_many(['victim_a', 'victim_b', 'not_running'])
            except Divergence as error:
                assert 'not_running' in str(error), str(error)
            else:
                raise AssertionError('a victim we did not start must stop the kill')
            assert all(_p.poll() is None for _p in _procs), \
                'a refused kill must not have signalled anyone'
            _killed = kill_hard_many(['victim_a', 'victim_b'])
            assert _killed == {'victim_a': _procs[0].pid,
                               'victim_b': _procs[1].pid}, _killed
            # Gone, and reaped by the kill itself (it waits for the
            # teardown), so no status is left for `Popen` to read.
            assert not any(Path(f'/proc/{_p.pid}').exists() for _p in _procs)
            assert not list(WORK.glob('victim_*')), sorted(WORK.iterdir())
        finally:
            WORK, KILL_SETTLE_SECONDS = _saved_work, _saved_settle
            for _p in _procs:
                if _p.poll() is None:
                    _p.kill()
                    _p.wait(timeout=10)

    # ----- flood: the shipped caps and the two adversary shapes -----
    assert flood.ROOT_FLOOD_CAPS == {'maxEntries': 256, 'maxBytes': 4194304,
                                     'perPeer': 128, 'ttlMs': 120000, 'replayPerParent': 64}, \
        flood.ROOT_FLOOD_CAPS
    _hit = flood.root_flood_plan('hit-and-run')
    _held = flood.root_flood_plan('held')
    # The default is the plan 3 flood, byte for byte on the command line.
    assert flood.root_flood_command('/b', 't:1', 'a:2', _hit) == [
        '/b', 't:1', 'devnet', 'a:2', 'input_block_root_flood',
        '10', '40', '12', '20000', '100'], flood.root_flood_command(
            '/b', 't:1', 'a:2', _hit)
    assert flood.root_flood_command('/b', 't:1', 'a:2', _held)[-2:] == \
        ['--hold-ms', '130000']
    # Each mode tests what it is for: hit-and-run saturates the entry cap
    # every wave; held exceeds the per-host cap every wave and holds past
    # the TTL, on few enough connections for Scala's maxConnections (30).
    assert _hit['hosts'] * _hit['per_host'] > flood.ROOT_FLOOD_CAPS['maxEntries']
    assert _held['per_host'] >= 160 > flood.ROOT_FLOOD_CAPS['perPeer']
    assert _held['hold_ms'] > flood.ROOT_FLOOD_CAPS['ttlMs']
    assert _held['hosts'] <= 25, _held
    assert list(flood.adversary_octets(_hit)) == list(range(100, 220))
    assert list(flood.adversary_octets(_held)) == list(range(100, 110))
    try:
        flood.root_flood_plan('slow')
    except ValueError:
        pass
    else:
        raise AssertionError('an unknown flood mode must be refused')
    # Store counters move by reason once the store splits them, and the
    # old single `drops` number still reads.
    assert flood.counters_between(
        {'size': 9, 'evictions': 1, 'drops': 4},
        {'size': 2, 'evictions': 5, 'drops': 10}) == \
        {'drops': 6, 'evictions': 4}
    assert flood.counters_between(
        {'drops': {'duplicate': 1, 'hostLimit': 0}, 'replayed': 3},
        {'drops': {'duplicate': 4, 'hostLimit': 7, 'staleParent': 2},
         'replayed': 3}) == {'drops.duplicate': 3, 'drops.hostLimit': 7,
                             'replayed': 0}
    # A held-flood target must publish the fixed store's counters, and
    # only those: `replayNotForwarded`, and `drops` by seven reasons.
    assert flood.STORE_COUNTERS == (
        'admitted', 'replayed', 'replayNotForwarded', 'evictions',
        'drops.duplicate', 'drops.hostLimit', 'drops.variantLimit',
        'drops.oversize', 'drops.expired', 'drops.staleParent',
        'drops.disconnected'), flood.STORE_COUNTERS
    assert flood.counters_between(None, {'drops': 1}) == {}
    flood.self_test_held_evaluation()
    flood_conf = scala_override('flood', 'scala3', ('scala', 'scala3'), '/tmp/test')
    for key, value in flood.ROOT_FLOOD_CAPS.items():
        assert f'ergo.node.matrix.pendingAnnouncements.{key} = {value}' in flood_conf
    assert 'pendingAnnouncements' not in scala_override(
        'steady', 'scala3', ('scala', 'scala3'), '/tmp/test')
    _flood_src = inspect.getsource(flood._run_against_scala_follower)
    assert 'root_flood_command(' in _flood_src and \
        'adversary_octets(plan)' in _flood_src, 'the scenario uses the plan'

    # ----- the waitlist counter, per ordering block -----
    def _entry(block):
        return ('INFO org.ergoplatform.network.ErgoNodeViewSynchronizer - '
                f'Processing ordering block announcement for {block}')

    def _put(block):
        return ('INFO org.ergoplatform.nodeView.history.ErgoHistory - '
                f'Put input block to disconnected queue: {block}')
    _wait = common.scala_waitlist([
        _put('00'),                           # before any ordering block
        _entry('a1'), _put('11'), _put('12'), _put('11'),
        _entry('a1'),                         # the same announcement again
        _put('13'),
        _entry('b2'),
        'INFO x - On processing 99, downloading its parent and unknown '
        'ordering block b2 from ConnectedPeer(...)',
        _entry('c3'), _put('31'),
    ])
    assert _wait['insertions'] == 6 and _wait['distinct_input_blocks'] == 5, _wait
    assert _wait['ordering_blocks'] == 3, _wait
    assert _wait['before_first_ordering_block'] == 1, _wait
    assert _wait['per_ordering_block']['max'] == 4, _wait     # a1: 11 12 11 13
    assert _wait['per_ordering_block']['blocks_with_any'] == 2, _wait
    assert _wait['root_parent_downloads'] == 1, _wait
    _none = common.scala_waitlist([])
    assert _none['insertions'] == 0 and _none['ordering_blocks'] == 0 and \
        _none['per_ordering_block']['p50'] is None, _none
    assert "entry['waitlist'] = scala_waitlist(window)" in inspect.getsource(
        common.reconstruction_accounting), 'every Scala role carries it'
    # Root announcements seen vs landed, per Scala follower, outside a flood.
    _roots = common.scala_root_announcements([
        'INFO x - On processing a1, downloading its parent and unknown '
        'ordering block ff from ConnectedPeer(connection: ConnectionId('
        'remote=/127.0.0.1:19570, local=/127.0.0.2:1, direction=Outgoing))',
        'INFO x - On processing a2, downloading its parent and unknown '
        'ordering block ff from ConnectedPeer(connection: ConnectionId('
        'remote=/127.0.0.1:19570, local=/127.0.0.2:1, direction=Outgoing))',
        'INFO x - Processing valid sub-block a1 with parent sub-block None '
        'and parent block ff'])
    assert _roots['honest_roots'] == 2 and _roots['honest_roots_landed'] == 1, \
        _roots
    assert "scala_root_announcements(window)" in inspect.getsource(
        common.reconstruction_accounting)
    _self_test_fork_workload()


def _self_test_fork_workload():
    """The #2562 two-miner run (`fork`): a funded window with its own
    measurement boundary, and each ordering block's named input tip
    against what every follower held under its parent."""
    import inspect

    from scenarios import common, fork

    # ----- the window is funded and bounded, in this order -----
    _src = inspect.getsource(fork.run)
    for _earlier, _later in (('fund_miner(', 'fan_out('),
                             ('fan_out(', 'seed_second_miner('),
                             ('fund_miner(', 'seed_second_miner('),
                             ('seed_second_miner(', 'open_measurement_window('),
                             ('open_measurement_window(', 'collector.poll()'),
                             ('collector.poll()', 'close_measurement_window('),
                             ('close_measurement_window(', 'ordering_blocks_between(')):
        assert _src.index(_earlier) < _src.index(_later), (_earlier, _later)
    assert 'pump()' in _src and 'named_tip_vs_held(' in _src, _src

    # ----- each class, on a synthetic series -----
    # Miner chains, newest first: P's tree a1 <- a2 <- a3, and a sibling
    # branch b2 under a1. The follower `rust` is sampled on P twice (the
    # LAST sample counts); `scala3` holds the sibling branch.
    series = [
        {'scala_ordering': 'P', 'scala_chain': ['a2', 'a1'],
         'rust_ordering': 'P', 'rust_chain': ['a1'],
         'scala3_ordering': 'P', 'scala3_chain': []},
        {'scala_ordering': 'P', 'scala_chain': ['a3', 'a2', 'a1'],
         'rust_ordering': 'P', 'rust_chain': ['a3', 'a2', 'a1'],
         'scala3_ordering': 'P', 'scala3_chain': ['b2', 'a1'],
         'scala2_chain': ['b2', 'a1']},
        {'rust_ordering': 'Q', 'rust_chain': ['q1'],
         'scala3_ordering': 'Q', 'scala3_chain': ['q1']},
    ]
    blocks = [
        {'height': 5, 'id': 'B1', 'rank': 0, 'parent': 'P',
         'named_input_tip': 'a3'},                 # rust equal, scala3 other
        {'height': 5, 'id': 'B2', 'rank': 1, 'parent': 'P',
         'named_input_tip': 'a1'},                 # both hold more
        {'height': 6, 'id': 'B3', 'rank': 0, 'parent': 'Q',
         'named_input_tip': 'q2'},                 # never sampled below q2
        {'height': 6, 'id': 'B4', 'rank': 1, 'parent': 'P',
         'named_input_tip': None},                 # names nothing
        {'height': 7, 'id': 'B5', 'rank': 0, 'parent': 'R',
         'named_input_tip': 'r1'},                 # parent never sampled
        {'height': 7, 'id': 'B6', 'rank': 1, 'unread': 'HTTP 404'},
    ]
    result = common.named_tip_vs_held(blocks, series, ['rust', 'scala3'])
    rust = {r['id']: (r['class'], r['depth']) for r in result['rust']['rows']}
    assert rust == {'B1': ('equal', 0), 'B2': ('held_more', 2),
                    'B3': ('named_chain_unknown', None),
                    'B4': ('names_nothing', None),
                    'B5': ('not_sampled', None), 'B6': ('unread', None)}, rust
    assert result['rust']['held_more_depths'] == [2], result['rust']
    scala3 = {r['id']: (r['class'], r['depth'])
              for r in result['scala3']['rows']}
    assert scala3['B1'] == ('other_branch', None), scala3
    assert scala3['B2'] == ('held_more', 1), scala3
    assert sum(result['scala3']['counts'].values()) == len(blocks), result
    # A follower whose tip is BELOW the named tip holds less, and one that
    # held nothing under the parent says so.
    behind = common.named_tip_vs_held(
        [{'id': 'B', 'parent': 'P', 'named_input_tip': 'a3'}],
        [{'scala_chain': ['a3', 'a2', 'a1'], 'rust_ordering': 'P',
          'rust_chain': ['a1']},
         {'scala3_ordering': 'P', 'scala3_chain': []}], ['rust', 'scala3'])
    assert behind['rust']['rows'][0]['class'] == 'held_less', behind
    assert behind['rust']['rows'][0]['depth'] == 2, behind
    assert behind['scala3']['rows'][0]['class'] == 'held_nothing', behind

    # ----- the window's blocks are read from the node, never dropped -----
    _pages = {
        '/blocks/at/5': ['B1', 'B2'], '/blocks/at/6': [],
        '/blocks/B1': {'header': {'parentId': 'P'},
                       'extension': {'fields': [['0100', 'aa'],
                                                ['0302', 'a3']]},
                       'blockTransactions': {'transactions': [{}, {}, {}]}},
    }

    def _fake_api(node, path, *args, **kwargs):
        if path == '/blocks/at/7':
            raise common.Unavailable('down')
        if path not in _pages:
            raise common.Unavailable(f'{path}: 404')
        return _pages[path]

    _saved_api = common.api
    try:
        common.api = _fake_api
        read, unread = common.ordering_blocks_between('scala', 5, 7)
    finally:
        common.api = _saved_api
    assert unread == [7], unread
    assert read[0] == {'height': 5, 'id': 'B1', 'rank': 0, 'parent': 'P',
                       'named_input_tip': 'a3', 'transactions': 3}, read
    assert read[1]['id'] == 'B2' and read[1]['rank'] == 1 and \
        'unread' in read[1], read
    assert len(read) == 2, read

    # ----- every payment is posted to every miner, the signer first -----
    import io
    import urllib.error

    import smoke
    assert 'pump_payments_to_all(' in _src, 'fork pays both miners'
    _calls = []
    _generated = iter([(200, {'id': 't1'}), (400, 'not enough boxes'),
                       (200, {'id': 't3'}), (200, {'id': 't4'})])

    def _refuse(path, detail):
        return urllib.error.HTTPError(path, 400, 'Bad Request', {},
                                      io.BytesIO(detail.encode()))

    def _fake_request(node, path, data=None, timeout=15):
        _calls.append((node, path, data.get('id') if isinstance(data, dict)
                       else None))
        if path == '/wallet/transaction/generate':
            # The fee `/wallet/payment/send` adds; without it the wallet
            # signs a zero-fee payment that is never mined.
            assert data['fee'] == common.PAYMENT_FEE_NANOERG == 1_000_000, data
            status, body = next(_generated)
            if status != 200:
                raise _refuse(path, body)
            return status, body
        if (node, data['id']) in (('scala2', 't3'), ('scala', 't4')):
            raise _refuse(path, 'double spending attempt')
        return 200, data['id']

    _saved_request = smoke.request
    _sent, _refused, _forwarded = [], [], {}
    try:
        smoke.request = _fake_request
        common.pump_payments_to_all(None, 'addr', _sent, ('scala', 'scala2'),
                                    count=4, rejected=_refused,
                                    forwarded=_forwarded)
    finally:
        smoke.request = _saved_request
    assert _sent == ['t1', 't3'], _sent
    assert _forwarded == {'scala2': {'accepted': 1, 'HTTP 400': 1}}, _forwarded
    assert len(_refused) == 2 and 'not enough boxes' in _refused[0] and \
        'double spending' in _refused[1], _refused
    _posts = [(n, i) for n, p, i in _calls if p == '/transactions']
    # Signed once, posted to the signer first; a payment its own node
    # refused is never forwarded.
    assert _posts == [('scala', 't1'), ('scala2', 't1'), ('scala', 't3'),
                      ('scala2', 't3'), ('scala', 't4')], _posts
    _self_test_seed_artifact()
    _self_test_switch_granularity()
    _self_test_payment_pool()
    _self_test_lead_confirmation()


def _self_test_lead_confirmation():
    """A one-block lead is confirmed only by evidence the block is real
    (`common.lead_confirmation`); the rm-B-fork-stockctl-4 shapes, an
    input-chain switch and a stale read pass, and an invented tip and a
    stitched chain still fail."""
    from scenarios import common

    def s(rust, s1, s2, o='O1', o2=None, s3=(), o3=None):
        return {'ordering': o, 'rust_chain': list(rust),
                'scala_chain': list(s1), 'scala_ordering': o,
                'scala2_chain': list(s2), 'scala2_ordering': o2 or o,
                'scala3_chain': list(s3), 'scala3_ordering': o3 or o}

    def verdict(series, evidence=None):
        return common.evaluate_fork_coherence(series, evidence=evidence)

    # Shape 1 (7705e85e): miner 2 mines `lead` and moves to its own next
    # ordering block, which names `lead` as its input tip, before any
    # sample lists `lead` under O1.
    turnover = [s(['t', 'a'], ['m1', 'a'], ['t', 'a']),
                s(['lead', 't', 'a'], ['m1', 'a'], ['t', 'a']),
                s(['lead', 't', 'a'], ['m1', 'a'], [], o2='O2')]
    strict = verdict(turnover)
    assert len(strict['unconfirmed_one_block_leads']) == 2, strict
    mined = {'lead': 'scala2'}
    named = verdict(turnover, {'named': {('O1', 'lead')}, 'mined_by': mined})
    assert not named['unconfirmed_one_block_leads'], named
    assert named['lead_confirmations'] == {'named_tip': 2}, named
    # A named tip alone proves the block is real, not that it sits on the
    # rest of the chain: without its miner's record it confirms nothing.
    assert len(verdict(turnover, {'named': {('O1', 'lead')}})[
        'unconfirmed_one_block_leads']) == 2
    # ...and the naming block's PARENT has to be the lead's ordering block
    # (here the miner's departure still makes it an orphaned lead).
    wrong_parent = verdict(turnover, {'named': {('O9', 'lead')}, 'mined_by': mined})
    assert wrong_parent['lead_confirmations'] == {'orphaned_lead': 2}, wrong_parent
    # Shape 2 (32d1d349): miner 2 mined it and left O1: an orphaned lead,
    # confirmed and LISTED.
    orphan = verdict(turnover, {'mined_by': {'lead': 'scala2'}})
    assert not orphan['unconfirmed_one_block_leads'], orphan
    assert orphan['lead_confirmations'] == {'orphaned_lead': 2}, orphan
    assert orphan['orphaned_leads'][0]['how'] == 'left_ordering_block', orphan
    assert orphan['orphaned_leads'][0]['miner'] == 'scala2', orphan
    # A block orphaned by an input-chain switch: miner 2 moves to miner
    # 1's fork under the SAME ordering block.
    switched = [s(['t', 'a'], ['m1', 'a'], ['t', 'a']),
                s(['lead', 't', 'a'], ['m1', 'a'], ['t', 'a']),
                s(['lead', 't', 'a'], ['m1', 'a'], ['m1', 'a'])]
    by_switch = verdict(switched, {'mined_by': {'lead': 'scala2'}})
    assert not by_switch['unconfirmed_one_block_leads'], by_switch
    assert {o['how'] for o in by_switch['orphaned_leads']} == {'switched_fork'}
    # The scala3 stale read: the Scala follower later holds the whole
    # chain, reported under the next ordering id.
    stale = [s(['t', 'a'], ['m1', 'a'], ['t', 'a']),
             s(['lead', 't', 'a'], ['m1', 'a'], ['t', 'a']),
             s(['lead', 't', 'a'], ['m1', 'a'], [], o2='O2',
               s3=['lead', 't', 'a'], o3='O2')]
    by_holder = verdict(stale)
    assert not by_holder['unconfirmed_one_block_leads'], by_holder
    assert set(by_holder['lead_confirmations']) == {'later_prefix'}, by_holder
    # Still failing: an invented tip no miner mined, whatever else is
    # known; a mined block whose miner never moved on; a stitched chain.
    invented = [s(['t', 'a'], ['m1', 'a'], ['t', 'a']),
                s(['zz', 't', 'a'], ['m1', 'a'], ['t', 'a']),
                s(['zz', 't', 'a'], ['m1', 'a'], [], o2='O2')]
    assert len(verdict(invented, {'mined_by': {'lead': 'scala2'},
                                  'named': {('O1', 'lead')}})[
        'unconfirmed_one_block_leads']) == 2
    stayed = [s(['t', 'a'], ['m1', 'a'], ['t', 'a']),
              s(['lead', 't', 'a'], ['m1', 'a'], ['t', 'a']),
              s(['lead', 't', 'a'], ['m1', 'a'], ['t', 'a'])]
    assert len(verdict(stayed, {'mined_by': {'lead': 'scala2'}})[
        'unconfirmed_one_block_leads']) == 2
    # A stitched chain: miner 2's real block `t` (built on `a`) on top of
    # miner 1's `m1`. `t` is mined, named, and its miner later moves away,
    # and it still fails: miner 2 never held `m1`.
    stitched = [s(['t', 'a'], ['m1', 'a'], ['t', 'a']),
                s(['t', 'm1', 'a'], ['m1', 'a'], ['t', 'a']),
                s(['t', 'm1', 'a'], ['m1', 'a'], [], o2='O2')]
    stitched_verdict = verdict(stitched, {'mined_by': {'t': 'scala2'},
                                          'named': {('O1', 't')}})
    assert stitched_verdict['unconfirmed_one_block_leads'] or \
        stitched_verdict['incoherent_samples'], stitched_verdict
    assert not stitched_verdict['orphaned_leads'], stitched_verdict
    assert 'named_tip' not in stitched_verdict['lead_confirmations'], stitched_verdict
    # The miner log parser reads the miner's own line only.
    assert common.mined_input_blocks([
        'INFO org.ergoplatform.mining.CandidateGenerator - Input-block '
        + 'ab' * 32 + ' mined @ height 12!',
        'INFO x - Processing valid sub-block ' + 'cd' * 32]) == {'ab' * 32}


def _self_test_payment_pool():
    """The fork window pays from a pool split off one coinbase before the
    seed: each payment spends exactly one pool box, never the wallet's own
    choice (which, after a reorg, is change that exists only in orphaned
    input blocks)."""
    import types

    import smoke
    from scenarios import common

    calls = []
    utxo = {'p1': 'b1', 'p3': 'b3'}      # p2 is spent: not in the UTXO set

    def _fake_request(node, path, data=None, timeout=15):
        calls.append((node, path, data))
        if path.startswith('/utxo/byIdBinary/'):
            box = path.rsplit('/', 1)[1]
            if box in utxo:
                return 200, {'boxId': box, 'bytes': utxo[box]}
            raise urllib.error.HTTPError(path, 404, 'Not Found', {},
                                         io.BytesIO(b'not found'))
        if path == '/wallet/transaction/generate':
            return 200, {'id': 'tx-' + data['inputsRaw'][0]}
        return 200, data['id']

    import io
    import urllib.error
    saved = smoke.request
    pool, sent, refused = ['p1', 'p2', 'p3'], [], []
    try:
        smoke.request = _fake_request
        common.pump_payments_to_all(None, 'addr', sent, ('scala', 'scala2'),
                                    count=3, rejected=refused, pool=pool)
    finally:
        smoke.request = saved
    # One pool box per payment, in order; the spent one is skipped and
    # named; the third payment finds the pool empty.
    assert sent == ['tx-b1', 'tx-b3'], sent
    assert pool == [], pool
    assert refused == ['pool box p2: HTTP 404',
                       'the payment pool is exhausted'], refused
    signed = [d for n, p, d in calls if p == '/wallet/transaction/generate']
    assert [d['inputsRaw'] for d in signed] == [['b1'], ['b3']], signed
    assert all(d['fee'] == common.PAYMENT_FEE_NANOERG for d in signed), signed

    # ----- the split: count boxes of value, confirmed before it returns -----
    calls.clear()
    polls = iter([404, 404, 200])
    split = {'id': 'split', 'outputs': [
        {'boxId': f'f{i}', 'value': common.FANOUT_VALUE_NANOERG}
        for i in range(4)] + [{'boxId': 'change', 'value': 5},
                              {'boxId': 'fee', 'value': 1_000_000}]}

    def _fake_split(node, path, data=None, timeout=15):
        calls.append((node, path, data))
        if path == '/wallet/transaction/generate':
            return 200, split
        if path == '/transactions':
            return 200, 'split'
        if path.startswith('/utxo/byId/'):
            code = next(polls)
            if code != 200:
                raise urllib.error.HTTPError(path, code, 'x', {}, io.BytesIO(b''))
            return 200, {'boxId': 'f0'}
        raise AssertionError(path)

    ctx = types.SimpleNamespace(evidence={}, failures=[], run=types.SimpleNamespace(
        deadline=time.monotonic() + 30, idle=lambda s: None))
    ctx.note = ctx.evidence.__setitem__
    ctx.fail = lambda message, evidence=None, ids=None: ctx.failures.append(message)
    saved_api = common.api
    try:
        smoke.request = _fake_split
        common.api = lambda node, path, *a, **k: {'fullHeight': 20}
        boxes = common.fan_out(ctx, 'addr', 'scala', 4)
    finally:
        smoke.request = saved
        common.api = saved_api
    assert boxes == ['f0', 'f1', 'f2', 'f3'], boxes
    assert not ctx.failures, ctx.failures
    request = next(d for n, p, d in calls if p == '/wallet/transaction/generate')
    assert request['requests'] == [{'address': 'addr', 'value':
                                    common.FANOUT_VALUE_NANOERG}] * 4, request
    assert ctx.evidence['payment_pool_split']['confirmed'] is True, ctx.evidence
    assert [p for n, p, d in calls].count('/utxo/byId/f0') == 3, calls


def _self_test_switch_granularity():
    """A fork switch is judged on HISTORY: either end may be a non-empty
    prefix of a reference's sampled chain, never an invented or stitched
    one (rm-B-fork-2562f-3)."""
    from scenarios import common

    def rs(o, rust, s1=(), s2=()):
        return {'ordering': o, 'rust_chain': list(rust), 'scala_chain': list(s1),
                'scala2_chain': list(s2), 'scala_ordering': o, 'scala2_ordering': o}

    # The follower (read after the miner in the same sweep) leaves miner
    # 1's chain at a length miner 1 was never sampled at: 1, then 3.
    granular = common.compare_fork_switches(
        [rs('O1', ['m1b', 'm1a'], ['m1a'], ['m2b', 'm2a']),
         rs('O1', ['m2b', 'm2a'], ['m1c', 'm1b', 'm1a'], ['m2b', 'm2a'])])
    assert granular['switches_matching_no_reference'] == [], granular
    # ...and the match says which kind it was.
    match = granular['matched_switches'][0]
    assert match['left_a_reference_chain'] == {
        'node': 'scala', 'sample': 1, 'match': 'prefix'}, match
    assert match['landed_on_a_reference_chain']['match'] == 'exact', match
    # A stitched chain (miner 2's block on miner 1's root) is a prefix of
    # neither miner's chain, and still matches nothing.
    stitched = common.compare_fork_switches(
        [rs('O1', ['m1b', 'm1a'], ['m1b', 'm1a'], ['m2b', 'm2a']),
         rs('O1', ['m2b', 'm1a'], ['m1b', 'm1a'], ['m2b', 'm2a'])])
    assert stitched['switches_matching_no_reference'], stitched
    unmatched = stitched['switches_matching_no_reference'][0]
    assert unmatched['left_a_reference_chain']['match'] == 'exact', unmatched
    assert unmatched['landed_on_a_reference_chain'] is None, unmatched
    # A landing that is a strict prefix of the other miner's chain (the
    # follower trailing it) is its history, and says so.
    trailing = common.compare_fork_switches(
        [rs('O1', ['m1b', 'm1a'], ['m1b', 'm1a'], ['m2c', 'm2b', 'm2a']),
         rs('O1', ['m2b', 'm2a'], ['m1b', 'm1a'], ['m2c', 'm2b', 'm2a'])])
    assert trailing['switches_matching_no_reference'] == [], trailing
    # A reset to the empty chain is still a reset, not a prefix match.
    reset = common.compare_fork_switches(
        [rs('O1', ['m1a'], ['m1a'], ['m2a']), rs('O1', [], ['m1a'], ['m2a'])])
    assert reset['resets_to_the_empty_chain'] and \
        not reset['switches_matching_no_reference'], reset
    # A landing carrying a block no reference ever published matches
    # nothing, whether it replaces a block or leads by one that is never
    # confirmed.
    for landing in (['q', 'm2a'], ['q', 'm2b', 'm2a']):
        unpublished = common.compare_fork_switches(
            [rs('O1', ['m1b', 'm1a'], ['m1b', 'm1a'], ['m2b', 'm2a']),
             rs('O1', landing, ['m1b', 'm1a'], ['m2b', 'm2a'])])
        assert unpublished['switches_matching_no_reference'], (landing, unpublished)
    # Rolling back and applying nothing is a truncation, and fails, even
    # though the chain landed on is a prefix of the miner's.
    truncated = common.compare_fork_switches(
        [rs('O1', ['m1c', 'm1b', 'm1a'], ['m1c', 'm1b', 'm1a'], ['m2a']),
         rs('O1', ['m1b', 'm1a'], ['m1c', 'm1b', 'm1a'], ['m2a'])])
    assert truncated['truncations'] and \
        not truncated['switches_matching_no_reference'] and \
        not truncated['matched_switches'], truncated
    judged = common.judge_fork_switches(truncated, range(0))
    assert any('truncated' in m for m, _ in judged['failures']), judged
    assert judged['genuine_switches'] == 0, judged
    # And the observed pattern is a genuine switch the gate passes.
    judged = common.judge_fork_switches(granular, range(0))
    assert judged['failures'] == [] and judged['genuine_switches'] == 1, judged


def _self_test_seed_artifact():
    """The seed step must not leave a follower holding input blocks the
    restarted miner has forgotten (rm-B-fork-stockctl-1), and the
    coherence evaluator must trace such a chain only on evidence."""
    import types

    from scenarios import common

    # ----- the seed stops the follower with miner 1, first -----
    calls = []

    class _Lifecycle:
        NODES = ('scala', 'scala2', 'scala3', 'rust')

        @staticmethod
        def stop(names):
            calls.append(('stop', tuple(names)))

        @staticmethod
        def spawn(name):
            calls.append(('spawn', name))

        @staticmethod
        def init_wallet(name):
            calls.append(('wallet', name))

        @staticmethod
        def wait_peered(names=None, timeout=180):
            calls.append(('peered', tuple(names or ())))

    class _Campaign:
        @staticmethod
        def ensure_data_dirs(root, nodes):
            for node in nodes:
                (root / node).mkdir(parents=True, exist_ok=True)

        @staticmethod
        def purge_address_book(root):
            calls.append(('purge',))
            return []

    class _Run:
        deadline = time.monotonic() + 30

        def started(self, node):
            calls.append(('started', node))

        def idle(self, seconds):
            pass

    pages = {'/info': {'fullHeight': 11, 'launchTime': 1000},
             '/blocks/bestInputChain': {'bestOrdering': 'O',
                                        'bestInputBlocks': ['x']},
             '/peers/connected': [1, 2, 3]}

    def _fake_api(node, path, *args, **kwargs):
        calls.append(('api', node, path))
        return pages[path]

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / 'scala').mkdir()
        (root / 'scala' / 'marker').write_text('chain')
        ctx = types.SimpleNamespace(data_root=root, run=_Run(), evidence={},
                                    failures=[])
        ctx.note = ctx.evidence.__setitem__
        ctx.fail = lambda message, evidence=None, ids=None: \
            ctx.failures.append(message)
        saved_api = common.api
        try:
            common.api = _fake_api
            common.seed_second_miner(ctx, _Campaign, _Lifecycle,
                                     nodes=('scala2', 'scala3'))
        finally:
            common.api = saved_api
        assert (root / 'scala3' / 'marker').exists(), 'the chain was copied'
    assert not ctx.failures, ctx.failures
    stops = [c for c in calls if c[0] == 'stop']
    # One stop takes the follower and miner 1 down together, Rust first...
    assert stops[0] == ('stop', ('rust', 'scala')), stops
    first_stop = calls.index(stops[0])
    # ...after miner 1's chain and process were snapshotted...
    snapshot_reads = [i for i, c in enumerate(calls)
                      if c[:2] == ('api', 'scala') and c[2] != '/peers/connected']
    assert snapshot_reads and max(snapshot_reads[:2]) < first_stop, calls
    snapshot = ctx.evidence['reference_snapshots'][0]
    assert {k: snapshot[k] for k in ('node', 'launch', 'ordering', 'chain')} == {
        'node': 'scala', 'launch': 1000, 'ordering': 'O', 'chain': ['x']}, snapshot
    # ...and the follower comes back only after every seeded node is up.
    spawns = [c[1] for c in calls if c[0] == 'spawn']
    assert spawns.index('rust') > max(spawns.index('scala2'),
                                      spawns.index('scala3')), spawns
    assert spawns.index('scala') < spawns.index('scala2'), spawns

    # ----- the evaluator stays strict, and traces only on evidence -----
    series = [{'ordering': 'O', 'scala_ordering': 'O', 'scala2_ordering': 'O',
               'rust_ordering': 'O', 'rust_chain': ['x'],
               'scala_chain': [f'a{j}' for j in range(k + 1, 0, -1)],
               'scala2_chain': [f'c{j}' for j in range(k + 1, 0, -1)],
               'launch': {'scala': 2000, 'scala2': 3000, 'rust': 500}}
              for k in range(9)]
    strict = common.evaluate_fork_coherence(series)
    assert len(strict['incoherent_samples']) == 9, strict
    assert not strict['held_from_restarted_reference'], strict
    assert strict['incoherent_samples'][0][
        'references_restarted_since_follower_start'] == ['scala', 'scala2']
    # miner 1's EARLIER process (launch 1000) held ['x'] just before the
    # harness stopped it; the follower (launch 500) predates that.
    snap = [{'node': 'scala', 'at': 1.5, 'launch': 1000, 'ordering': 'O',
             'chain': ['x']}]
    traced = common.evaluate_fork_coherence(series, snap)
    assert not traced['incoherent_samples'], traced
    assert len(traced['held_from_restarted_reference']) == 9, traced
    assert traced['held_from_restarted_reference'][0]['held_from'] == {
        'node': 'scala', 'snapshot_at': 1.5, 'snapshot_launch': 1000,
        'launch_at_sample': 2000}, traced
    # Strict otherwise: no restart since the snapshot, a follower that
    # started after it, another history, another ordering block, or no
    # launch times at all are all still incoherent.
    for variant, bad_series in (
            ([dict(snap[0], launch=2000)], series),
            (snap, [dict(s, launch=dict(s['launch'], rust=5000)) for s in series]),
            ([dict(snap[0], chain=['y'])], series),
            ([dict(snap[0], ordering='P')], series),
            (snap, [{k: v for k, v in s.items() if k != 'launch'} for s in series])):
        verdict = common.evaluate_fork_coherence(bad_series, variant)
        assert len(verdict['incoherent_samples']) == 9, (variant, verdict)
        assert not verdict['held_from_restarted_reference'], variant


def _fake_node_modules(work, calls, stop_raises=False, findings_raise=False):
    """A `lifecycle` and a `smoke` that start nothing and record what the
    driver asked of them — the driver under test is the real one."""
    import types

    import smoke as real_smoke

    import lifecycle as real_lifecycle

    lifecycle = types.ModuleType('lifecycle')
    # Constants and pure role resolution come from the real module; every
    # function that would touch a process, a build or a port is faked
    # below, so an attribute this list misses fails loudly rather than
    # starting something.
    for _attr in ('ROLES', 'Role', 'role_node', 'roles_for_nodes', 'NODES',
                  'P2P', 'REST', 'WORK', 'DEFAULT_CONFIG', 'DEFAULT_P2P',
                  'DEFAULT_P2P_HOST', 'DEFAULT_REST', 'P2P_HOST'):
        if hasattr(real_lifecycle, _attr):
            setattr(lifecycle, _attr, getattr(real_lifecycle, _attr))
    lifecycle.SCALA_APP_VERSION = 'fake'
    lifecycle.node_binary = lambda: '/fake/ergo-node'
    lifecycle.node_binary_provenance = lambda: {'fake': True}
    lifecycle.classpath_file = lambda node='scala': Path('/fake/classpath')
    lifecycle.scala_app_version = lambda node='scala': 'fake'
    lifecycle.node_build = lambda node: 'stock'

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

    # The build registry would VERIFY a real provisioned build (hashing
    # its class output); the driver only needs a summary bound to the
    # launch classpath the fake lifecycle reports.
    builds = types.ModuleType('builds')

    class BuildError(Exception):
        pass

    class _Build:
        def __init__(self, name):
            self.name = name

        def summary(self):
            return {'build': self.name, 'classpath': '/fake/classpath'}

    builds.BuildError = BuildError
    builds.load = _Build
    return lifecycle, smoke, builds


def _drive(name, scenario_run, tmp, **faults):
    """Run the REAL `run_scenario` once against fake node modules."""
    import types

    from scenarios import SCENARIOS
    global CAMPAIGN_WORK, CONF, WORK
    saved = (CAMPAIGN_WORK, CONF, WORK)
    CAMPAIGN_WORK, CONF, WORK = tmp / 'campaign', tmp / 'campaign' / 'conf', tmp / 'work'
    WORK.mkdir(parents=True, exist_ok=True)
    calls = []
    fake_lifecycle, fake_smoke, fake_builds = _fake_node_modules(
        WORK, calls, **faults)
    module = types.ModuleType(f'fake_{name}')
    module.__doc__ = 'A probe scenario.'
    module.NODES = SCENARIO_NODES[name]
    module.run = scenario_run
    real_modules = {k: sys.modules.get(k)
                    for k in ('lifecycle', 'smoke', 'builds')}
    real_scenario = SCENARIOS[name]
    common = common_module()
    real_accounting = common.reconstruction_accounting
    # The accounting reads the nodes' feeds and logs; its own rules are
    # tested on their own. Here the driver only has to CALL it, for every
    # scenario, before the verdict.
    common.reconstruction_accounting = lambda ctx: (
        calls.append(('reconstruction_accounting', tuple(ctx.roles)))
        or {'fields': list(common.ACCOUNTING_FIELDS), 'probe': True})
    sys.modules['lifecycle'], sys.modules['smoke'] = fake_lifecycle, fake_smoke
    sys.modules['builds'] = fake_builds
    SCENARIOS[name] = module
    raised = None
    try:
        args = types.SimpleNamespace(attempt=check_attempt_cap(name), fresh=False,
                                     timeout=5, ordering_blocks=None,
                                     reference_follower=None, build='stock')
        try:
            evidence = run_scenario(name, args)
        except BaseException as error:  # noqa: BLE001 — the probe inspects it
            raised = error
            evidence = json.loads((CAMPAIGN_WORK / f'{name}.json').read_text())
        return evidence, calls, raised, read_attempts()
    finally:
        SCENARIOS[name] = real_scenario
        common.reconstruction_accounting = real_accounting
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
        # Every scenario's evidence carries the reconstruction accounting
        # and the build identity of each Scala role.
        assert any(c[0] == 'reconstruction_accounting' for c in calls), calls
        assert evidence['reconstruction_accounting'].get('probe'), evidence
        assert evidence['builds']['scala_miner']['build'] == 'stock', evidence

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


def child_argv(name, args):
    """The per-scenario command `--scenario all` re-execs. Pure.

    Every campaign-wide knob is forwarded; a scenario-specific one only
    to its own scenario, whose child refuses it otherwise.
    """
    return ([sys.executable, str(HERE / 'campaign.py'), '--scenario', name,
             '--timeout', str(args.timeout)]
            + ['--build', args.build, '--base-build', args.base_build]
            + (['--reference-follower', args.reference_follower]
               if args.reference_follower else [])
            + (['--ordering-blocks', str(args.ordering_blocks)]
               if args.ordering_blocks is not None else [])
            + (['--restart-victim', args.restart_victim]
               if name == 'restart' else [])
            # `is not None`, not truthiness: an explicit 0 must reach the
            # child, which refuses it.
            + (['--post-ordering-blocks', str(args.post_ordering_blocks)]
               if name == 'restart' and args.post_ordering_blocks is not None
               else [])
            + (['--flood-mode', args.flood_mode]
               if name == 'flood' else [])
            + (['--fresh'] if args.fresh else [])
            + (['--force-attempt'] if args.force_attempt else []))


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
                             'every other Scala role runs --base-build, so a run '
                             'is base+one-patch vs base')
    parser.add_argument('--base-build', default='stock',
                        help='the provisioned Scala build every NON-patched '
                             'Scala role runs: the miner(s) and the stock '
                             'reference follower (default stock, the M4 pin)')
    parser.add_argument('--restart-victim', default='rust',
                        choices=RESTART_VICTIMS,
                        help='restart only: SIGKILL the Rust follower (default) '
                             'or every Scala reference follower at once '
                             '(needs --reference-follower)')
    parser.add_argument('--post-ordering-blocks', type=int, default=None,
                        help='restart only: funded ordering blocks observed '
                             'after convergence (default 5)')
    parser.add_argument('--flood-mode', default='hit-and-run',
                        choices=FLOOD_MODES,
                        help='flood against a Scala follower only: fresh hosts '
                             'per wave, closed at once (default), or one held '
                             'connection per host past the store TTL with more '
                             'announcements per host than the per-host cap')
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
    # A knob the scenario would ignore is refused before anything is
    # checked or started. `all` routes each knob to its own scenario,
    # whose child process checks it.
    if args.scenario != 'all':
        check_scenario_knobs(args.scenario, args.reference_follower,
                             args.restart_victim, args.flood_mode,
                             args.post_ordering_blocks)

    sys.path.insert(0, str(HERE))
    # Refused HERE rather than at the first spawn: an unknown build must
    # not start a devnet, and a declared-but-unprovisioned one must say
    # what would provision it. The resolved port band is checked in the
    # same breath, for the same reason.
    check_band(CAMPAIGN_P2P, CAMPAIGN_REST)
    # A hand-set classpath would bypass `Build.verify()` for the node it
    # names, and the run would still record `--build` in its evidence.
    check_no_classpath_override(os.environ)
    names = list(ORDER) if args.scenario == 'all' else [args.scenario]
    for used_build in builds_in_use(names, args.reference_follower,
                                    args.build, args.base_build):
        check_build(used_build)
    # The node set is fixed for the whole process: `lifecycle.REST` and
    # `smoke.URLS` are read at import time, so one process drives one
    # node set. `--scenario all` therefore re-execs itself per scenario.
    if len(names) > 1:
        failures = []
        for name in names:
            result = subprocess.run(child_argv(name, args), cwd=ROOT)
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
    configure_environment(name, nodes_for_roles(role_set), role_set, args.build,
                          args.base_build)
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
    # A completed MEASUREMENT exits 0 like a PASS: it did what it was
    # asked; an INCOMPLETE one does not. NOT MEASURED is not a pass, and
    # it is not an error the runner should treat as a broken scenario
    # either: it exits 0 with the verdict on the line above, so a
    # campaign does not abort on a limitation of the host.
    return 0 if evidence['result'] in OK_RESULTS else 1


if __name__ == '__main__':
    os.chdir(ROOT)
    sys.path.insert(0, str(HERE))
    raise SystemExit(main())
