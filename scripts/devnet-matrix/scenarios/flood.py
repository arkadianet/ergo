"""The adversarial peer, against the follower only.

`ergo-node/examples/p2p_adversary input_block_flood` connects as a peer
and sends 10,000 syntactically valid input-block announcements at
height + 1, each naming a parent input block nobody has, then 1,000
`InputBlockTransactions` (code 104) deliveries for input blocks nobody
requested. Everything is well-formed on the wire: a malformed frame
would be rejected by the codec and would say nothing about §7.4.

The miner is never a target. What has to hold on the follower:

* every spec §7.4 bound the node publishes stays under its cap;
* resident memory grows by less than the byte caps plus 64 MiB — a
  bounded structure that still pins bytes is not bounded;
* the honest Scala peer is never penalised or dropped;
* the honest chain keeps advancing across the flood.

Afterwards the follower's `peers.redb` is purged: the harness binds each
slot to its own `127.<k>.0.1` and those addresses poison the address
book, starving the next run's dialer.
"""
from pathlib import Path
import json
import re
import subprocess
import threading
import time

import smoke
from smoke import Unavailable, api, api_retry

from . import common

# The source address the harness binds its flood connection to
# (`src(210)` = 127.210.0.1). Log lines naming it are how this scenario
# proves the traffic actually reached the processor.
ADVERSARY_SOURCE = '127.210.0.1'

NODES = ('scala', 'rust')
# `--reference-follower stock|patched` adds ONE Scala follower, seeded
# from the miner's directory, and the adversary is aimed at IT instead of
# the Rust follower (F13's pending store is Scala-side attack surface).
START_NODES = ('scala', 'rust')
SEEDED_NODES = ('scala2', 'scala3')
ANNOUNCEMENTS = 10_000
DELIVERIES = 1_000
BLOCKS_BEFORE_FLOOD = 3
BLOCKS_AFTER_FLOOD = 3
PURGE_ADDRESS_BOOK = True

# The §7.4 caps this recipe's follower runs with. `waitlist_entries` is
# raised by `rust-node.toml` (the Scala miner publishes ~64 input blocks
# per ordering block, far above the crate default); everything else is
# the crate default. Stated here so the assertion is against a number a
# reader can check against `ergo-inputblocks/src/bounds.rs`, not against
# whatever the node happens to report.
CAPS = {
    'waitlist': 8192,                 # [input_blocks.bounds] waitlist_entries
    'forks': 64,                      # Bounds::forks_per_ordering
    'staged_bytes': 64 * 1024 * 1024,  # Bounds::staging_bytes_total
    # Not a spec bound but an implementation queue that must not grow
    # without limit, and the route publishes it, so it is measured.
    'deferred_triggers': 4096,        # Bounds::pending_triggers headroom
}

# The §7.4 bounds `/api/v1/status.input_blocks` does NOT expose. Listed
# so the evidence says which bounds this run covered and which it could
# not, rather than leaving the uncovered ones unmentioned and implying
# the flood checked all of §7.4. Each would need a new counter on the
# status route to become measurable here.
BOUNDS_NOT_EXPOSED = (
    'tx_cache_entries', 'tx_cache_bytes', 'records_per_ordering',
    'records_total', 'trees_total', 'ordering_announcements',
    'requests_per_peer', 'retired_jobs',
)

RSS_HEADROOM_KIB = 64 * 1024


def _adversary_binary():
    """The built harness. Not built here: a compile inside a running
    devnet competes with the node for the machine, and a scenario that
    silently rebuilt would measure a different binary than the campaign
    reported.

    `P2P_ADVERSARY` names a prebuilt binary, the way `RUST_NODE` names the
    node — for a checkout whose cargo target directory is not `target/`.
    """
    import os

    import lifecycle
    explicit = os.environ.get('P2P_ADVERSARY')
    target = (Path(explicit) if explicit else
              smoke.ROOT / 'target' / 'release' / 'examples' / 'p2p_adversary')
    if not target.exists():
        raise RuntimeError(
            f'{target} not built; run `cargo build --release --example '
            f'p2p_adversary -p ergo-node` or set P2P_ADVERSARY '
            f'(node binary: {lifecycle.node_binary()})')
    return target


def _binary_provenance(path):
    """Which adversary ran: path, sha256, mtime."""
    import hashlib
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    return {'path': str(path), 'sha256': digest,
            'mtime': time.strftime('%Y-%m-%dT%H:%M:%S%z',
                                   time.localtime(Path(path).stat().st_mtime))}


# ----- the Scala-follower ROOT flood (plan 3 Task 7, F13) -----
#
# F13 holds UNVALIDATED announcements at height + 2 — the ones that root
# the next ordering block's input-block tree — in a bounded store until
# their ordering parent is applied. It is admitted before any PoW check
# (`ErgoNodeViewSynchronizer.scala` +2 branch), so it is the new attack
# surface: the flood fills it from many hosts and the scenario checks
# that (a) its caps hold, (b) HONEST roots still land while it is
# saturated, (c) the honest peers are not punished for the flood, and
# (d) the follower keeps applying blocks on time.
#
# The store's caps as #2563 ships them (`upstream/pending-root-announcement-
# store` @ 3e20c270b, `ergo.node.matrix.pendingAnnouncements`); the flood overlay pins
# these defaults explicitly. Builds without the store ignore those keys. The
# early F13 build ran `perPeer = 32`; its flood runs are not evidence for
# the shipped cap (REVIEW-2563 §3.1).
ROOT_FLOOD_CAPS = {'maxEntries': 256, 'maxBytes': 4 * 1024 * 1024,
                   'perPeer': 128, 'ttlMs': 120_000, 'replayPerParent': 64}
# The two adversary shapes `--flood-mode` selects (REVIEW-2563 §3.3
# items 4-5). They differ once the store drops a host's entries when its
# connection closes and keeps an unknown-parent entry until the TTL: a
# hit-and-run host's entries leave with it, a held host's stay.
#
# * `hit-and-run` (the default, the plan 3 shape): 10 FRESH hosts per
#   wave x 40 announcements, each connection closed half a second after
#   its last frame. 400 per wave is past the 256-entry cap, so capacity
#   eviction and its fairness rule run every wave; 40 is under
#   `perPeer = 128`, so the per-host cap is never reached. 12 waves 20 s
#   apart keep it saturated for about four ordering blocks; the hosts
#   are 127.100.0.1 .. 127.219.0.1.
# * `held`: 10 hosts, each on ONE connection held open for the whole
#   flood and 130 s (past `ttlMs`) after its last wave, every wave sent
#   over it, 160 announcements per host per wave — past `perPeer`, so the
#   per-host cap refuses the excess on every wave. The adversary drains
#   what the node sends it and reports how many of its connections the
#   node closed early. 10 held connections stay inside the Scala node's
#   default `maxConnections = 30` beside its honest peers.
ROOT_FLOOD_PLANS = {
    'hit-and-run': {'hosts': 10, 'per_host': 40, 'waves': 12,
                    'interval_ms': 20_000, 'first_octet': 100,
                    'hold_ms': None},
    'held': {'hosts': 10, 'per_host': 160, 'waves': 12,
             'interval_ms': 20_000, 'first_octet': 100,
             'hold_ms': 130_000},
}
# The default plan, under its old name.
ROOT_FLOOD = ROOT_FLOOD_PLANS['hit-and-run']


def root_flood_plan(mode):
    """The adversary plan for one `--flood-mode`. Pure."""
    if mode not in ROOT_FLOOD_PLANS:
        raise ValueError(f'unknown flood mode {mode!r}; have '
                         f'{sorted(ROOT_FLOOD_PLANS)}')
    return dict(ROOT_FLOOD_PLANS[mode], mode=mode)


def root_flood_command(binary, target, api, plan):
    """The `p2p_adversary input_block_root_flood` argv for a plan. Pure.

    A `held` plan adds the adversary's own `--hold-ms` flag; without it
    the command is exactly the plan 3 one.
    """
    command = [str(binary), target, 'devnet', api, 'input_block_root_flood',
               str(plan['hosts']), str(plan['per_host']), str(plan['waves']),
               str(plan['interval_ms']), str(plan['first_octet'])]
    if plan.get('hold_ms') is not None:
        command += ['--hold-ms', str(plan['hold_ms'])]
    return command


def adversary_octets(plan):
    """The second octets of every source host a plan uses. Pure.

    Fresh hosts per wave (`hit-and-run`) use `hosts x waves` of them; a
    `held` plan reuses its `hosts` on every wave.
    """
    count = plan['hosts'] * (1 if plan.get('hold_ms') is not None
                             else plan['waves'])
    return range(plan['first_octet'], plan['first_octet'] + count)


def counters_between(first, last):
    """How much each store counter moved between two `/info` readings.

    Pure. Reads the pre-review single `drops` number and the per-reason
    `drops` object alike (`smoke.flatten_counters`); a counter missing
    from either reading is left out rather than read as zero.
    """
    a = smoke.flatten_counters(first or {})
    b = smoke.flatten_counters(last or {})
    return {key: b[key] - a[key] for key in sorted(set(a) & set(b))
            if key not in smoke.PENDING_GAUGES}
BLOCKS_BEFORE_ROOT_FLOOD = 4
ROOT_FLOOD_PAYMENTS_PER_BLOCK = 3
BLOCKS_AFTER_ROOT_FLOOD = 3
# A sample at or above this share of the entry cap counts as SATURATED.
SATURATED_SHARE = 0.9
ROOT_FLOOD_SAMPLE_SECONDS = 0.5

_ROOT_LINE = re.compile(
    r'On processing (?P<id>[0-9a-f]+), downloading its parent and unknown '
    r'ordering block (?P<parent>[0-9a-f]+) from .*?remote=/(?P<host>[0-9.]+):')
_VALID_LINE = re.compile(r'Processing valid sub-block (?P<id>[0-9a-f]+)')
_PENALTY_LINE = re.compile(
    r'/(?P<host>[0-9.]+):\d+ penalized, penalty: (?P<kind>\w+)')
_BLACKLIST_LINE = re.compile(r'/(?P<host>[0-9.]+):\d+ blacklisted')
# The stock cause of a misbehaviour penalty against the honest miner in
# a peered run with no adversary: a block the holder already applied is
# re-applied, declared permanently invalid, and its sender penalised
# (`.work-m4p-f12f05`: 18 stock / 16 patched in 100 blocks, no flood).
_DOUBLE_APPLICATION = 'double application of a modifier is prohibited'
DOUBLE_APPLICATION_LOOKBACK = 150


def _adversary_host(host, adversary_octets):
    parts = host.split('.')
    return (len(parts) == 4 and parts[0] == '127' and parts[2:] == ['0', '1']
            and int(parts[1]) in adversary_octets)


def evaluate_root_flood(lines, samples, caps, adversary_octets):
    """What the follower's log and `/info` samples say about the flood.

    Pure, so `campaign.py --self-test` pins it. `lines` is the follower's
    log over the flood window; `samples` are `{'lines', 'size', 'bytes'}`
    taken during it, where `lines` is the log length at the sample, which
    is how a log line is placed in time (the Scala log carries no
    timestamps). A root announcement is HONEST when its sender is not one
    of the adversary's source hosts, and it LANDED when the follower
    later logged it as a valid sub-block — for a +2 announcement that
    only happens through the pending store's replay.
    """
    def size_at(index):
        # The newest sample taken at or before this line.
        size = None
        for sample in samples:
            if sample['lines'] <= index:
                size = sample.get('size') if _number(sample.get('size')) else None
        return size

    saturated_at = caps['maxEntries'] * SATURATED_SHARE
    honest, adversary, landed = {}, 0, set()
    penalties_honest, penalties_adversary, blacklisted_honest = {}, 0, []
    unexplained, after_double = 0, 0
    last_double = None
    for index, line in enumerate(lines):
        if _DOUBLE_APPLICATION in line.lower():
            last_double = index
            continue
        root = _ROOT_LINE.search(line)
        if root:
            if _adversary_host(root['host'], adversary_octets):
                adversary += 1
            else:
                honest.setdefault(root['id'], index)
            continue
        valid = _VALID_LINE.search(line)
        if valid and valid['id'] in honest:
            landed.add(valid['id'])
            continue
        penalty = _PENALTY_LINE.search(line)
        if penalty:
            if _adversary_host(penalty['host'], adversary_octets):
                penalties_adversary += 1
            else:
                penalties_honest[penalty['kind']] = \
                    penalties_honest.get(penalty['kind'], 0) + 1
                if penalty['kind'] != 'NonDeliveryPenalty':
                    if (last_double is not None and index - last_double
                            <= DOUBLE_APPLICATION_LOOKBACK):
                        after_double += 1
                        last_double = None
                    else:
                        unexplained += 1
            continue
        banned = _BLACKLIST_LINE.search(line)
        if banned and not _adversary_host(banned['host'], adversary_octets):
            blacklisted_honest.append(line)
    while_saturated = {block for block, index in honest.items()
                       if (size_at(index) or 0) >= saturated_at}
    sizes = [s['size'] for s in samples if _number(s.get('size'))]
    byte_counts = [s['bytes'] for s in samples if _number(s.get('bytes'))]
    peak_size = max(sizes) if sizes else None
    peak_bytes = max(byte_counts) if byte_counts else None
    return {
        'adversary_root_lines': adversary,
        'honest_roots': len(honest),
        'honest_roots_landed': len(landed),
        'honest_roots_while_saturated': len(while_saturated),
        'honest_roots_landed_while_saturated': len(while_saturated & landed),
        'saturated_at_entries': saturated_at,
        'samples': len(samples),
        'saturated_samples': sum(1 for x in sizes if x >= saturated_at),
        'peak_size': peak_size,
        'peak_bytes': peak_bytes,
        'caps': caps,
        'caps_held': (bool(samples) and len(sizes) == len(samples)
                      and len(byte_counts) == len(samples)
                      and min(sizes) >= 0 and min(byte_counts) >= 0
                      and peak_size <= caps['maxEntries']
                      and peak_bytes <= caps['maxBytes']),
        'honest_penalties': penalties_honest,
        # A NonDeliveryPenalty against the honest miner is STOCK behaviour
        # (the peered stock follower logs it without any flood), and so is
        # a misbehaviour penalty that follows a double application; what
        # the flood must never cause is any OTHER misbehaviour verdict
        # against an honest peer — which is what a failed replay of a
        # held announcement gives its sender.
        'honest_misbehaviour_penalties': unexplained,
        'honest_misbehaviour_after_double_application': after_double,
        'honest_blacklisted': blacklisted_honest[:10],
        'adversary_penalties': penalties_adversary,
    }


# Every counter a held-flood target must publish: the fixed #2563 store's,
# stated once in `smoke` (`replayNotForwarded`, and `drops` by seven
# reasons with no `fairness`).
STORE_COUNTERS = smoke.PENDING_FIXED_COUNTERS


def _number(value):
    return type(value) in (int, float) and 0 <= value < float('inf')


def parse_root_result(stdout):
    records = [line.removeprefix('ROOT_FLOOD_RESULT ') for line in stdout.splitlines()
               if line.startswith('ROOT_FLOOD_RESULT ')]
    try:
        result = json.loads(records[0]) if len(records) == 1 else None
        return result if isinstance(result, dict) else None
    except (ValueError, TypeError):
        return None


def held_coverage(result, plan):
    """Zero early closures allowed: a rejected peer cannot prove held coverage.

    EOF and I/O errors remain separate evidence, but neither excuses missing
    traffic. All configured hosts must survive every wave and the whole hold.
    """
    if not isinstance(result, dict) or result.get('ok') is not True:
        return False
    waves, conns = result.get('waves'), result.get('connections')
    if not isinstance(waves, list) or not isinstance(conns, list):
        return False
    expected_sources = {f'127.{k}.0.1' for k in adversary_octets(plan)}
    if len(waves) != plan['waves'] or len(conns) != plan['hosts']:
        return False
    if any(not isinstance(w, dict) or w.get('wave') != i
           or w.get('sent') != plan['hosts'] * plan['per_host']
           or w.get('write_errors') != 0 or w.get('height_observed') is not True
           for i, w in enumerate(waves)):
        return False
    if any(not isinstance(c, dict) or c.get('opened') is not True
           or c.get('survived') is not True or c.get('closure') is not None
           for c in conns):
        return False
    if {c.get('source') for c in conns} != expected_sources:
        return False
    for key in ('started_unix_ms', 'sockets_open_ms', 'last_send_ms',
                'hold_end_ms', 'finished_ms'):
        if not _number(result.get(key)):
            return False
    return (result['sockets_open_ms'] <= result['last_send_ms']
            and result['hold_end_ms'] - result['last_send_ms'] == plan['hold_ms']
            and result['finished_ms'] >= result['hold_end_ms'])


def evaluate_store_window(samples, baseline, patched, plan, result):
    """Pure verdict; an unavailable measurement is incomplete, never zero."""
    errors = []
    present = any(isinstance(s.get('pending'), dict) for s in samples)
    shape = smoke.pending_telemetry_label(
        [baseline] + [s.get('pending') for s in samples])
    old = shape == 'old telemetry'
    report = {'store_present': present,
              'telemetry': shape if present or old else 'missing',
              'errors': errors}
    held = plan.get('hold_ms') is not None
    coverage = held_coverage(result, plan) if held else None
    report['held_coverage'] = coverage
    if held and not coverage:
        errors.append('incomplete held experiment: all waves and surviving hosts required')
    if not patched and not present:
        report['exemption'] = 'stock target: store telemetry is not applicable'
        return report
    if not present:
        errors.append('incomplete: patched target has no store telemetry in window')
    readings = [baseline] + [s.get('pending') for s in samples]
    flat = [smoke.flatten_counters(p or {}) for p in readings]
    if (not samples or any(not isinstance(p, dict) for p in readings)
            or any(not _number(p.get(k)) for p in flat
                   for k in ('size', 'bytes') + STORE_COUNTERS)):
        errors.append('incomplete: required fixed-store gauges or counters missing'
                      + (' (old telemetry)' if old else ''))
    if any(not _number(p.get(k)) or p[k] > ROOT_FLOOD_CAPS[cap]
           for p in flat for k, cap in (('size', 'maxEntries'), ('bytes', 'maxBytes'))):
        errors.append('store bounds exceeded or unobserved')
    if any(b.get(k, -1) < a.get(k, -1)
           for a, b in zip(flat, flat[1:]) for k in STORE_COUNTERS
           if _number(a.get(k)) and _number(b.get(k))):
        errors.append('store counter reset during experiment')
    report['store_counters_in_window'] = counters_between(baseline, readings[-1])
    report['evictions_in_window'] = report['store_counters_in_window'].get('evictions')
    if held and patched:
        # Both ends of the REST request must lie inside the all-sockets-open
        # window. A sample completed during disconnect/drain cannot prove TTL.
        opened = (result['started_unix_ms'] + result['sockets_open_ms']) if coverage else 0
        ended = (result['started_unix_ms'] + result['hold_end_ms']) if coverage else 0
        live = [s for s in samples if coverage
                and opened <= s.get('request_started_ms', -1)
                and s.get('request_finished_ms', float('inf')) < ended]
        deltas = [counters_between(baseline, s.get('pending')) for s in live]
        report['live_samples'] = len(live)
        report['live_counter_deltas'] = deltas[-1] if deltas else {}
        for key, exercised in (
                ('drops.hostLimit', plan['per_host'] > ROOT_FLOOD_CAPS['perPeer']),
                ('drops.expired', plan['hold_ms'] > ROOT_FLOOD_CAPS['ttlMs'])):
            if not exercised or not any(d.get(key, 0) > 0 for d in deltas):
                errors.append(f'{key} growth not observed while sockets were open')
    return report


def self_test_held_evaluation():
    from copy import deepcopy
    plan = root_flood_plan('held')
    baseline = dict(size=0, bytes=0, admitted=100, replayed=10,
                    replayNotForwarded=0, evictions=20,
                    drops={k.removeprefix('drops.'): 30 for k in STORE_COUNTERS
                           if k.startswith('drops.')})
    pending = deepcopy(baseline)
    pending.update(size=256, bytes=40000)
    pending['drops'].update(hostLimit=31, expired=31)
    result = dict(ok=True, started_unix_ms=1000, sockets_open_ms=10,
                  last_send_ms=220000, hold_end_ms=350000, finished_ms=350010,
                  waves=[dict(wave=i, sent=1600, write_errors=0, height_observed=True)
                         for i in range(12)],
                  connections=[dict(source=f'127.{k}.0.1', opened=True,
                                    survived=True, closure=None)
                               for k in adversary_octets(plan)])
    sample = dict(pending=pending, request_started_ms=340000,
                  request_finished_ms=340100)

    def verdict(samples=None, base=None, outcome=None, patched=True):
        return evaluate_store_window([sample] if samples is None else samples,
                                     baseline if base is None else base,
                                     patched, plan, result if outcome is None else outcome)

    assert not verdict()['errors'], verdict()
    assert verdict()['telemetry'] == 'fixed telemetry', verdict()
    # A 2563f target: the fixed store's own JSON (13fc25df2
    # `PendingInputAnnouncements.Stats.jsonEncoder`), key for key, with
    # the host-limit and expiry growth a held flood produces.
    shipped = json.loads(
        '{"size": 256, "bytes": 40000, "admitted": 900, "replayed": 12, '
        '"replayNotForwarded": 3, "evictions": 40, "drops": {'
        '"duplicate": 30, "hostLimit": 90, "variantLimit": 30, '
        '"oversize": 30, "expired": 45, "staleParent": 30, '
        '"disconnected": 30}}')
    shipped_verdict = verdict(samples=[dict(sample, pending=shipped)])
    assert not shipped_verdict['errors'], shipped_verdict
    assert shipped_verdict['telemetry'] == 'fixed telemetry', shipped_verdict
    # The draft counters the harness used to require (`replayInvalid`, a
    # `fairness` drop) never shipped; a store carrying them instead of
    # `replayNotForwarded` is incomplete, and named as unrecognised.
    draft = deepcopy(shipped)
    draft['replayInvalid'] = draft.pop('replayNotForwarded')
    draft['drops']['fairness'] = 0
    draft_verdict = verdict(samples=[dict(sample, pending=draft)])
    assert any('incomplete' in e for e in draft_verdict['errors']), draft_verdict
    assert draft_verdict['telemetry'] == 'unrecognised telemetry', draft_verdict
    assert parse_root_result('log\nROOT_FLOOD_RESULT ' + json.dumps(result)) == result
    assert parse_root_result('ROOT_FLOOD_RESULT bad') is None
    assert parse_root_result('no result') is None
    assert verdict(samples=[{}])['errors']  # patched missing store
    stock = verdict(samples=[{}], patched=False)
    assert not stock['errors'] and 'stock' in stock['exemption']
    missing = deepcopy(sample)
    del missing['pending']['bytes']
    assert verdict(samples=[sample, missing])['errors']
    assert not evaluate_root_flood([], [{'lines': 0, 'size': 1}],
                                   ROOT_FLOOD_CAPS, ())['caps_held']
    for key in ('hostLimit', 'expired'):
        unchanged = deepcopy(sample)
        unchanged['pending']['drops'][key] = baseline['drops'][key]
        assert any(f'drops.{key}' in e for e in verdict(samples=[unchanged])['errors'])
    # Large baseline counts do not count as growth, even if a sampler started
    # before those counts were accumulated during the honest baseline blocks.
    assert verdict(base=deepcopy(pending))['errors']
    assert verdict(base=deepcopy(pending))['store_counters_in_window']['drops.expired'] == 0
    late = dict(sample, request_finished_ms=351001)
    assert verdict(samples=[late])['errors']
    for mutate in ('wave', 'close', 'short_hold', 'write_error'):
        truncated = deepcopy(result)
        if mutate == 'wave':
            truncated['waves'].pop()
        elif mutate == 'close':
            truncated['connections'][0].update(survived=False,
                closure={'kind': 'eof', 'observed_ms': 2, 'error': None})
        elif mutate == 'short_hold':
            truncated['hold_end_ms'] -= 1000
        else:
            truncated['waves'][0]['write_errors'] = 1
        assert not held_coverage(truncated, plan), mutate
        assert verdict(outcome=truncated)['errors'], mutate
    old = deepcopy(sample)
    old['pending']['drops'] = 999
    assert verdict(samples=[old])['telemetry'] == 'old telemetry'
    assert verdict(samples=[old])['errors']
    # The pre-review store as it really published (F13, #2563 before the
    # review): four keys, one `drops` number. Still reported as old.
    prereview = {'size': 256, 'bytes': 87083, 'evictions': 1675, 'drops': 3075}
    prereview_verdict = verdict(samples=[dict(sample, pending=prereview)],
                                base=dict(prereview, evictions=0, drops=0))
    assert prereview_verdict['telemetry'] == 'old telemetry', prereview_verdict
    assert any('(old telemetry)' in e for e in prereview_verdict['errors']), \
        prereview_verdict
    over = deepcopy(sample)
    over['pending']['bytes'] = ROOT_FLOOD_CAPS['maxBytes'] + 1
    assert verdict(samples=[over, sample])['errors']


def _percentiles(values):
    if not values:
        return {'n': 0}
    ordered = sorted(values)
    return {'n': len(ordered), 'p50': smoke.percentile(ordered, 50),
            'p95': smoke.percentile(ordered, 95), 'max': ordered[-1]}


class _FollowerSampler:
    """`/info` of the target follower and the miner, every half second.

    Records each height's FIRST sighting on both, so the follower's delay
    in applying each block is measurable, plus the store's size and the
    REST latency — the synchronizer and the REST route share the actor
    system, so a follower wedged by its store answers late or not at all.
    """

    def __init__(self, target, miner, on_new_miner_height=None):
        self.target, self.miner = target, miner
        # Called (in this thread) whenever the miner's height rises, so the
        # workload keeps pace with the chain while the main thread is
        # blocked on the adversary.
        self.on_new_miner_height = on_new_miner_height
        self.workload_errors = []
        self.samples, self.first_seen = [], {target: {}, miner: {}}
        self.phase = 'before'
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=10)

    def _loop(self):
        while not self._stop.is_set():
            now = time.monotonic()
            sample = {'t': now, 'phase': self.phase,
                      'lines': len(common._scala_log_lines(self.target))}
            for node in (self.target, self.miner):
                began = time.monotonic()
                request_started_ms = time.time() * 1000
                try:
                    info = api(node, '/info', timeout=10) or {}
                except Unavailable:
                    sample[f'{node}_unavailable'] = True
                    continue
                if node == self.target:
                    sample['request_started_ms'] = request_started_ms
                    sample['request_finished_ms'] = time.time() * 1000
                    sample['latency_s'] = round(time.monotonic() - began, 3)
                    pending = info.get('pendingInputAnnouncements')
                    sample['store_present'] = isinstance(pending, dict)
                    if isinstance(pending, dict):
                        sample.update(size=pending.get('size'),
                                      bytes=pending.get('bytes'),
                                      evictions=pending.get('evictions'),
                                      drops=pending.get('drops'),
                                      pending=pending)
                height = info.get('fullHeight')
                sample[f'{node}_height'] = height
                if height is not None:
                    new = height not in self.first_seen[node]
                    self.first_seen[node].setdefault(height, (now, self.phase))
                    if new and node == self.miner and self.on_new_miner_height:
                        try:
                            self.on_new_miner_height()
                        except Exception as error:  # recorded, never fatal
                            self.workload_errors.append(repr(error))
            self.samples.append(sample)
            self._stop.wait(ROOT_FLOOD_SAMPLE_SECONDS)

    def apply_delays(self):
        """Per height: seconds from the miner's first sighting to the
        follower's, grouped by the phase the miner produced it in."""
        out = {}
        for height, (t_miner, phase) in self.first_seen[self.miner].items():
            seen = self.first_seen[self.target].get(height)
            if seen is not None:
                out.setdefault(phase, []).append(round(max(0.0, seen[0] - t_miner), 2))
        return out


def _run_against_scala_follower(ctx, target):
    import campaign
    import lifecycle

    common.seed_second_miner(ctx, campaign, lifecycle, nodes=SEEDED_NODES)
    smoke.assertion_1_peering(ctx.run, ctx.evidence)
    role = (ctx.roles or {}).get(target)
    plan = root_flood_plan(getattr(ctx.args, 'flood_mode', None)
                           or 'hit-and-run')
    ctx.note('flood_target', {'node': target, 'role': role,
                              'p2p': f'{lifecycle.P2P_HOST[target]}:'
                                     f'{lifecycle.P2P[target]}',
                              'plan': plan, 'caps': ROOT_FLOOD_CAPS})

    # A WORKLOAD, as in `steady`: honest root (+2) announcements only
    # exist while the follower has not yet applied the miner's newest
    # ordering block, and an unfunded chain's coinbase-only blocks are
    # applied at once — the first F13 run saw 0 honest roots in 12
    # flooded blocks against 18 in the 3 before.
    balance, address = common.fund_miner(ctx, 'scala')
    ctx.note('funding', {'balance_nano': balance, 'address': address})
    sent, refused = [], []

    def pump():
        if balance and address:
            common.pump_payments(ctx, address, sent, 'scala',
                                 ROOT_FLOOD_PAYMENTS_PER_BLOCK,
                                 rejected=refused)

    sampler = _FollowerSampler(target, 'scala', pump).start()
    common.wait_ordering_blocks(ctx, BLOCKS_BEFORE_ROOT_FLOOD, 'pre_flood')
    height_before = api_retry(target, '/info', ctx.run.deadline,
                              what='the target follower height').get('fullHeight')
    log_from = len(common._scala_log_lines(target))

    binary = _adversary_binary()
    command = root_flood_command(
        binary, f'{lifecycle.P2P_HOST[target]}:{lifecycle.P2P[target]}',
        f'127.0.0.1:{lifecycle.REST[target]}', plan)
    ctx.note('adversary_command', ' '.join(command))
    ctx.note('adversary_binary', _binary_provenance(binary))
    try:
        baseline = (api(target, '/info', timeout=10) or {}).get('pendingInputAnnouncements')
    except Unavailable:
        baseline = None
    ctx.note('store_pre_launch_snapshot', baseline)
    result = None
    sampler.phase = 'flood'
    started = time.monotonic()
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=1800, check=False)
        result = parse_root_result(completed.stdout)
        ctx.note('adversary_result', result)
        ctx.note('adversary', {'returncode': completed.returncode,
                               'seconds': round(time.monotonic() - started, 1),
                               'stdout': completed.stdout[-4000:],
                               'stderr': completed.stderr[-2000:]})
        if completed.returncode != 0:
            ctx.fail('the root-flood harness did not deliver its traffic '
                     f'(exit {completed.returncode})',
                     {'stdout': completed.stdout[-4000:]})
    except subprocess.TimeoutExpired as error:
        ctx.fail('the root-flood harness timed out', {'error': str(error)})
    # Entries outlive the flood by up to the store's TTL: watch it drain.
    sampler.phase = 'drain'
    drain_until = min(ctx.run.deadline,
                      time.monotonic() + ROOT_FLOOD_CAPS['ttlMs'] / 1000 + 10)
    while time.monotonic() < drain_until:
        ctx.run.idle(0.5)
    log_to = len(common._scala_log_lines(target))
    sampler.phase = 'after'
    common.wait_ordering_blocks(ctx, BLOCKS_AFTER_ROOT_FLOOD, 'post_flood')
    sampler.stop()
    ctx.note('workload', {'funded_balance_nano': balance,
                          'payments_submitted': len(sent),
                          'payments_refused': len(refused),
                          'refusals': refused[:10],
                          'errors': sampler.workload_errors[:10]})
    if not balance:
        ctx.fail('the miner was never funded, so the flooded blocks carried no '
                 'workload and honest root announcements are not representative',
                 {'balance_nano': balance})

    lines = common._scala_log_lines(target)
    window = lines[log_from:log_to]
    flood_samples = [dict(s, lines=s['lines'] - log_from)
                     for s in sampler.samples if s['phase'] in ('flood', 'drain')]
    octets = adversary_octets(plan)
    verdict = evaluate_root_flood(window, flood_samples, ROOT_FLOOD_CAPS, octets)
    # Only an explicitly stock role receives the missing-store exemption.
    spec = campaign.lifecycle_roles().get(role)
    patched = spec is None or spec.patched
    store_verdict = evaluate_store_window(
        flood_samples, baseline, patched, plan, result)
    verdict.update(store_verdict)
    store_present = verdict['store_present']
    verdict['log_window'] = {'from_line': log_from, 'to_line': log_to}
    verdict['drops_in_window'] = {
        k: v for k, v in verdict.get('store_counters_in_window', {}).items()
        if k == 'drops' or k.startswith('drops.')}
    for error in store_verdict['errors']:
        ctx.fail(error, store_verdict)
    ctx.note('root_flood', verdict)

    # The same three counts BEFORE the flood, as the honest baseline the
    # flood window is read against (no adversary line can appear there).
    before = evaluate_root_flood(
        lines[:log_from], [], ROOT_FLOOD_CAPS, octets)
    phase_blocks = {}
    for _height, (_t, phase) in sampler.first_seen[target].items():
        phase_blocks[phase] = phase_blocks.get(phase, 0) + 1
    flood_blocks = phase_blocks.get('flood', 0) + phase_blocks.get('drain', 0)
    ctx.note('root_flood_baseline_before', {
        **{k: before[k] for k in (
            'honest_roots', 'honest_roots_landed', 'honest_penalties',
            'honest_misbehaviour_penalties',
            'honest_misbehaviour_after_double_application')},
        'blocks_applied_before': phase_blocks.get('before', 0),
        'blocks_applied_during_flood_and_drain': flood_blocks,
        # Misbehaviour/spam penalties against the honest miner that no
        # double application explains, per applied block, before vs during.
        # Reported beside each other rather than failed on: the peered
        # STOCK follower logs them with no adversary at all
        # (`.work-m4p-f13-steady`: 8 stock / 4 F13 in 60 blocks).
        'unexplained_honest_penalties_per_block': {
            'before': round(before['honest_misbehaviour_penalties']
                            / max(1, phase_blocks.get('before', 0)), 3),
            'flood': round(verdict['honest_misbehaviour_penalties']
                           / max(1, flood_blocks), 3)},
    })

    delays = sampler.apply_delays()
    latencies = {}
    for s in sampler.samples:
        if 'latency_s' in s:
            latencies.setdefault(s['phase'], []).append(s['latency_s'])
    unavailable = {}
    for s in sampler.samples:
        if s.get(f'{target}_unavailable'):
            unavailable[s['phase']] = unavailable.get(s['phase'], 0) + 1
    ctx.note('responsiveness', {
        'block_apply_delay_s': {p: _percentiles(v) for p, v in delays.items()},
        'rest_latency_s': {p: _percentiles(v) for p, v in latencies.items()},
        'rest_unavailable_samples': unavailable,
        'samples': len(sampler.samples),
    })

    connected = api(target, '/peers/connected') or []
    miner_addr = f'{lifecycle.P2P_HOST["scala"]}:{lifecycle.P2P["scala"]}'
    miner_connected = any(miner_addr in str(p.get('address', '')) for p in connected)
    height_after = api_retry(target, '/info', ctx.run.deadline,
                             what='the target follower height').get('fullHeight')
    ctx.note('honest_peers', {'miner_connected_at_end': miner_connected,
                              'connected': [p.get('address') for p in connected]})
    ctx.note('chain_progress', {'before': height_before, 'after': height_after})

    # ----- verdicts -----
    if not verdict['adversary_root_lines']:
        ctx.fail('no root announcement from an adversary host reached the '
                 'follower\'s +2 branch, so the store was never attacked',
                 {'stdout': (ctx.evidence.get('adversary') or {}).get('stdout')})
    if store_present:
        if not verdict['caps_held']:
            ctx.fail('the pending store exceeded its caps under the flood',
                     {'peak_size': verdict['peak_size'],
                      'peak_bytes': verdict['peak_bytes'],
                      'caps': ROOT_FLOOD_CAPS})
        if not verdict['saturated_samples'] and not verdict['evictions_in_window']:
            ctx.fail('the store was never saturated, so the caps and honest '
                     'admission under saturation were not tested',
                     {'peak_size': verdict['peak_size']})
        if not verdict['honest_roots_while_saturated']:
            ctx.fail('no honest root announcement arrived while the store was '
                     'saturated, so "honest roots still land" was not observed',
                     {'honest_roots': verdict['honest_roots']})
        elif not verdict['honest_roots_landed_while_saturated']:
            ctx.fail('no honest root announcement that arrived during '
                     'saturation was replayed into the input chain',
                     {'while_saturated': verdict['honest_roots_while_saturated']})
    elif not patched:
        ctx.note('store_absent', 'this build publishes no pendingInputAnnouncements '
                                 '(stock): caps and replay are not applicable, '
                                 'the honest-root counts are the stock comparison')
    if verdict['honest_blacklisted']:
        ctx.fail('an honest peer was blacklisted during the flood',
                 {'penalties': verdict['honest_penalties'],
                  'blacklisted': verdict['honest_blacklisted']})
    if not miner_connected:
        ctx.fail('the honest miner was not connected to the follower after the '
                 'flood', {'connected': [p.get('address') for p in connected]})
    if (height_after or 0) <= (height_before or 0):
        ctx.fail('the follower did not advance across the flood',
                 {'before': height_before, 'after': height_after})
    smoke.finalize_agreement(ctx.run, ctx.evidence)


def run(ctx):
    import campaign
    import lifecycle

    followers = [n for n in SEEDED_NODES if n in lifecycle.NODES]
    if followers:
        _run_against_scala_follower(ctx, followers[0])
        return

    smoke.assertion_1_peering(ctx.run, ctx.evidence)
    common.wait_ordering_blocks(ctx, BLOCKS_BEFORE_FLOOD, 'pre_flood')

    pid = campaign.node_pid('rust')
    rss_before = campaign.rss_kib(pid)
    status_before = campaign.input_block_status()
    height_before = (api_retry('rust', '/info', ctx.run.deadline,
                               what='the follower height before the flood')
                     .get('fullHeight'))
    ctx.note('before_flood', {'pid': pid, 'rss_kib': rss_before,
                              'input_blocks': status_before,
                              'rust_height': height_before})
    if rss_before is None:
        ctx.fail('the follower\'s resident memory could not be read before the '
                 'flood, so the memory bound cannot be checked', {'pid': pid})

    binary = _adversary_binary()
    command = [str(binary),
               f'{lifecycle.P2P_HOST["rust"]}:{lifecycle.P2P["rust"]}', 'devnet',
               f'127.0.0.1:{lifecycle.REST["rust"]}',
               'input_block_flood', str(ANNOUNCEMENTS), str(DELIVERIES)]
    ctx.note('adversary_command', ' '.join(command))

    # Measurement STARTS BEFORE the traffic and runs through delivery.
    # `subprocess.run` blocks until the adversary exits, so sampling
    # afterwards could not see a structure that overflowed during
    # delivery and drained before exit.
    peaks = common.PeakSampler(CAPS).start(pid=pid)
    started = time.monotonic()
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=1800, check=False)
        ctx.note('adversary', {
            'returncode': completed.returncode,
            'seconds': round(time.monotonic() - started, 1),
            'stdout': completed.stdout[-4000:],
            'stderr': completed.stderr[-2000:],
        })
        if completed.returncode != 0:
            ctx.fail('the adversary harness did not deliver its traffic '
                     f'(exit {completed.returncode}), so the flood was not run',
                     {'stdout': completed.stdout[-4000:],
                      'stderr': completed.stderr[-2000:]})
    except subprocess.TimeoutExpired as error:
        ctx.fail('the adversary harness timed out, so the flood is not a complete '
                 'experiment', {'error': str(error)})

    # Keep watching past the adversary's exit: a structure that is still
    # draining is still holding bytes.
    watch_deadline = min(ctx.run.deadline, time.monotonic() + 120)
    while time.monotonic() < watch_deadline:
        ctx.run.idle(0.5)
    peaks.stop()
    ctx.note('peak_sampling', peaks.summary())
    if not peaks.samples:
        ctx.fail('no §7.4 counter reading was taken across the flood, so no '
                 'bound was measured', {'sampler': peaks.summary()})

    status_after = campaign.input_block_status()
    ctx.note('after_flood', {'input_blocks': status_after,
                             'peaks': peaks.peaks,
                             'peak_rss_kib': peaks.rss_peak,
                             'rss_before_kib': rss_before})

    # DID IT LAND? A flood the node never read would leave every bound
    # inside its cap for the best possible reason, and this scenario
    # would report that as the node withstanding an attack it never
    # received. The node's own log naming the adversary's source address
    # is the proof, and it is required.
    reached = [line for line in smoke.rust_log_lines(ADVERSARY_SOURCE, limit=20000)
               if ADVERSARY_SOURCE in line]
    ctx.note('flood_reached_the_processor', {
        'source': ADVERSARY_SOURCE,
        'log_lines_naming_it': len(reached),
        'sample': reached[:5],
        'announcements_sent': ANNOUNCEMENTS,
        'note': 'fewer lines than announcements is expected: the node bans the '
                'source once its penalties accumulate, which is the bound '
                'working, and the count is how far it got',
    })
    if not reached:
        ctx.fail('no log line names the adversary, so the flood cannot be shown to '
                 'have reached the node at all — every bound below would then be '
                 'inside its cap for the wrong reason',
                 {'source': ADVERSARY_SOURCE,
                  'adversary_stdout': (ctx.evidence.get('adversary') or {})
                  .get('stdout')})

    # The PEAKS, never merged with a post-hoc reading: a counter the
    # route never published stays unknown and fails.
    ctx.note('bounds', common.check_bounds(ctx, peaks.peaks, CAPS, 'flood',
                                           unavailable_bounds=BOUNDS_NOT_EXPOSED))
    ctx.note('where_the_flood_was_stopped', {
        'announcement_gate_rejections_naming_the_adversary': len(reached),
        'peak_waitlist': peaks.peaks.get('waitlist'),
        'peak_staged_bytes': peaks.peaks.get('staged_bytes'),
        'reading': 'announcements with an invalid PoW solution are refused '
                   'upstream of the §7.4 memory structures, so a zero here is '
                   'the gate holding, not the memory bounds being exercised',
    })

    # Memory: the byte caps plus headroom.
    if rss_before is not None and peaks.rss_peak is not None:
        allowed = (CAPS['staged_bytes'] // 1024) + RSS_HEADROOM_KIB
        peak_rss = peaks.rss_peak
        growth = peak_rss - rss_before
        ctx.note('rss_growth', {'kib': growth, 'allowed_kib': allowed})
        if growth > allowed:
            ctx.fail(f'the follower\'s resident memory grew {growth} KiB under the '
                     f'flood, past the {allowed} KiB the byte caps plus headroom '
                     'allow', {'rss_before_kib': rss_before,
                               'peak_rss_kib': peak_rss,
                               'input_blocks': status_after})

    # The honest peer, and the honest chain.
    penalties = smoke.rust_log_lines('penalizing peer')
    scala_penalties = [line for line in penalties
                       if str(lifecycle.P2P['scala']) in line]
    ctx.note('penalty_log_lines', penalties)
    ctx.note('penalty_log_lines_naming_the_miner', scala_penalties)
    if scala_penalties or ctx.run.penalty_observations:
        ctx.fail('the honest Scala peer was penalised while an adversary flooded '
                 'the follower',
                 {'log': scala_penalties,
                  'observations': ctx.run.penalty_observations})
    if 'absent' in ctx.run.peer_states:
        ctx.fail('the honest Scala peer was dropped during the flood',
                 {'peer_states': sorted(ctx.run.peer_states)})

    common.wait_ordering_blocks(ctx, BLOCKS_AFTER_FLOOD, 'post_flood')
    height_after = (api_retry('rust', '/info', ctx.run.deadline,
                              what='the follower height after the flood')
                    .get('fullHeight'))
    ctx.note('chain_progress', {'before': height_before, 'after': height_after})
    if (height_after or 0) <= (height_before or 0):
        ctx.fail('the honest chain did not advance on the follower across the flood',
                 {'before': height_before, 'after': height_after,
                  'scala': api('scala', '/info')})

    # Drops are EXPECTED here — that is the bound working — but a
    # byte-level disagreement is not.
    totals = ctx.run.totals()
    ctx.note('drop_totals', totals)
    fatal = {r: totals[r] for r in smoke.FATAL_DROPS if totals.get(r)}
    if fatal:
        ctx.fail(f'byte-level disagreement recorded during the flood: {fatal}',
                 {'drops': totals})
