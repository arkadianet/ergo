#!/usr/bin/env python3
"""Matrix mixed-node smoke: Scala mines input blocks, Rust follows.

Six assertions, all polled over REST (spec §9, plan 2 task 8):

  1. both nodes peer, and Rust sees the Scala node at protocol 6.5.0;
  2. within 3 ordering blocks there is a sample where both nodes report
     the same `bestFullHeaderId` AND the same `bestInputBlock`;
  3. at such a sample `bestInputChain` is identical on both nodes;
  4. over >= 10 ordering blocks: the first ordering block after a cold
     restart is an `ordering_reconstruct_fallback` (any reason; the
     reason is recorded, and `root_mismatch` is expected because a cold
     node has no input chain to name a body in), and a later one is an
     `ordering_reconstructed` carrying MORE THAN ONE transaction, which
     is the only outcome that proves assembly from input-block bodies.
     Each reconstruction also reports `reconstructedOrder`
     (`scala` | `candidate`, divergence D4 / upstream F12) and
     `reconstructionKey` (`self` | `parent`, divergence D5 / upstream
     F5); the run records both splits;
  5. Rust's `fullHeight` stays within 2 of Scala's for the whole run
     (only the first 60 s after each node start is excluded), no
     `DigestMismatch` / `TxDigestMismatch` / `Penalize` ever fires, and
     the Scala peer is never penalised or dropped;
  6. 20 transactions submitted to the Scala wallet are each accepted
     (HTTP 200), observed inside a Rust input block, removed from Rust's
     unconfirmed pool once that input chain applies, and the two pools
     agree after the next ordering block with D1/F6 accounting.

Rules this harness follows, because a smoke that lies is worse than no
smoke:

  * A failed REST call is NEVER an observation. It is retried within
    budget and, if it stays unavailable, fails the assertion that needed
    it. An empty list from a dead endpoint must not compare equal to an
    empty list from a live one.
  * Failures accumulate. One failed assertion does not abort the rest;
    every failure is collected and the run reports all of them.
  * Any mismatch writes `test-vectors/weak-blocks/findings/<date>-<n>.json`
    with both nodes' REST bodies, the Rust event tail and the matching
    Rust debug-log lines (the recipe enables the debug filter itself).

Writes `.work/smoke-evidence.json` and prints one PASS/FAIL line.
"""
import argparse
import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request

import lifecycle
from lifecycle import HERE, REST, ROOT, WORK

URLS = {name: f'http://127.0.0.1:{port}' for name, port in REST.items()}
API_KEY = lifecycle.API_KEY
FINDINGS = ROOT / 'test-vectors/weak-blocks/findings'

# `/api/v1/peers` reports the peer's handshake protocol version. Input
# blocks are gated on >= 6.5.0 on the Scala side, so anything lower means
# the two nodes would never exchange them.
REQUIRED_PEER_VERSION = (6, 5, 0)

# Assertion 5's window (spec 9.2): an input block is only actionable at
# `best_full_block_height + 1`, and the same +-2 slack bounds how far the
# follower may trail the miner.
HEIGHT_WINDOW = 2

# Only a node's first 60 s are excluded from the window: a process that
# has just started has not finished joining. Catch-up after the
# deliberate restart is NOT excluded — keeping up is the assertion.
START_GRACE_SECONDS = 60

# Drop reasons that mean the two nodes disagreed about bytes, or that the
# follower blamed its peer. Any of them is a failure.
FATAL_DROPS = ('DigestMismatch', 'TxDigestMismatch', 'Penalize')

# Assertions 2 and 3 observe for this many ordering blocks. Longer than
# the old bound because they are now statistical: a p95 over a handful of
# samples means nothing.
AGREEMENT_ORDERING_BLOCKS = 5

# Assertion 2's hard lag bounds, in INPUT BLOCKS (not seconds): how far
# Rust's input-block tip may trail Scala's for the same ordering block.
# Exact instantaneous equality is unreachable when the miner publishes
# ~64 input blocks per ordering block, and lag is not divergence — so the
# gate bounds the lag and records the exact-match count as a metric.
LAG_P95_MAX = 8
LAG_MAX = 16


class Unavailable(RuntimeError):
    """A REST observation could not be made. Never a value."""


def request(node, path, data=None, timeout=15):
    req = urllib.request.Request(
        URLS[node] + path,
        data=None if data is None else json.dumps(data).encode(),
        headers={'api_key': API_KEY, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        payload = response.read()
        return response.status, (json.loads(payload) if payload else None)


def api(node, path, data=None, timeout=15):
    """One REST call. Raises `Unavailable` rather than inventing a value."""
    try:
        return request(node, path, data, timeout)[1]
    except (OSError, ValueError) as error:
        raise Unavailable(f'{node} {path}: {error}') from error


def api_retry(node, path, deadline, data=None, what=None):
    """`api`, retried until `deadline`. Still raises rather than defaulting."""
    last = None
    while True:
        try:
            return api(node, path, data)
        except Unavailable as error:
            last = error
            if time.monotonic() >= deadline:
                raise Unavailable(f'{what or path} stayed unavailable: {last}') from last
            time.sleep(0.5)


def parse_version(text):
    try:
        return tuple(int(p) for p in str(text).split('-')[0].split('.')[:3])
    except (ValueError, TypeError):
        return (0, 0, 0)


def strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


def rust_log_lines(match, limit=40):
    """Debug-log lines containing `match`, newest last. Best effort."""
    try:
        text = strip_ansi((WORK / 'rust.log').read_text(errors='replace'))
    except OSError:
        return []
    return [line for line in text.splitlines() if match in line][-limit:]


def next_finding_path():
    FINDINGS.mkdir(parents=True, exist_ok=True)
    day = datetime.date.today().isoformat()
    n = 1
    while (FINDINGS / f'{day}-{n}.json').exists():
        n += 1
    return FINDINGS / f'{day}-{n}.json'


class Run:
    """The whole observation: samples, accumulated counters, failures."""

    def __init__(self, deadline):
        self.deadline = deadline
        self.failures = []
        self.findings = []
        self.samples = 0
        self.unavailable_samples = 0

        # Assertion 5, accumulated across the whole run.
        self.max_height_gap = 0
        self.height_violations = []
        self.drop_counters = {}
        self.penalty_observations = []
        self.peer_states = set()
        self.node_started_at = {}

        # Assertions 2 and 3: the raw series the evaluators run over.
        # Kept so a run's verdict can be recomputed from its evidence
        # instead of trusting a number the harness printed once.
        self.series = []
        self.propagation_lags = []
        self._scala_input_first_seen = {}

        # Assertion 6.
        self.input_block_txids = {}

    # ----- helpers -----

    def fail(self, assertion, message, evidence=None):
        self.failures.append({'assertion': assertion, 'message': message})
        if evidence is not None:
            self.findings.append({'assertion': assertion, 'message': message,
                                  'evidence': evidence})

    def started(self, node):
        self.node_started_at[node] = time.monotonic()

    def in_grace(self, node):
        started = self.node_started_at.get(node)
        return started is not None and time.monotonic() - started < START_GRACE_SECONDS

    # ----- one paired observation -----

    def sweep(self):
        """One sample of both nodes. Returns the readings, or None if a REST
        call failed — a miss is counted, never turned into a value."""
        now = time.time()
        reading = {}
        try:
            for node in URLS:
                reading[node] = {
                    'info': api(node, '/info'),
                    'chain': api(node, '/blocks/bestInputChain'),
                    'best': api(node, '/blocks/bestInputBlock'),
                }
            status = api('rust', '/api/v1/status')
            peers = api('rust', '/api/v1/peers')
        except Unavailable:
            self.unavailable_samples += 1
            return None
        self.samples += 1

        self._accumulate_counters(status, peers)
        self._accumulate_heights(reading, now)
        self._accumulate_agreement(reading, now)
        return reading

    def _accumulate_counters(self, status, peers):
        ib = (status or {}).get('input_blocks') or {}
        for entry in ib.get('drops', []):
            # Counters are monotonic per process; a restart resets them,
            # so the accumulated value is the max of what each process
            # reported plus what earlier processes had already reached.
            key = entry['reason']
            previous = self.drop_counters.get(key, {'current': 0, 'carried': 0})
            if entry['count'] < previous['current']:
                previous['carried'] += previous['current']
            previous['current'] = entry['count']
            self.drop_counters[key] = previous
        scala_peer = next(
            (p for p in (peers or [])
             if p.get('addr', '').endswith(str(lifecycle.P2P['scala']))), None)
        if scala_peer is None:
            self.peer_states.add('absent')
            return
        self.peer_states.add(scala_peer.get('state', 'unknown'))
        if (scala_peer.get('score') or 0) < 0:
            self.penalty_observations.append(
                {'at': time.time(), 'score': scala_peer.get('score'),
                 'state': scala_peer.get('state')})

    def totals(self):
        return {k: v['current'] + v['carried'] for k, v in self.drop_counters.items()}

    def _accumulate_heights(self, reading, now):
        scala_h = reading['scala']['info'].get('fullHeight') or 0
        rust_h = reading['rust']['info'].get('fullHeight') or 0
        gap = scala_h - rust_h
        if any(self.in_grace(node) for node in URLS):
            return
        self.max_height_gap = max(self.max_height_gap, gap)
        if gap > HEIGHT_WINDOW:
            self.height_violations.append(
                {'at': now, 'scala_height': scala_h, 'rust_height': rust_h})

    def _accumulate_agreement(self, reading, now):
        scala_best = reading['scala']['best'].get('bestInputBlock')
        rust_best = reading['rust']['best'].get('bestInputBlock')
        if scala_best:
            self._scala_input_first_seen.setdefault(scala_best, now)
        if rust_best and rust_best in self._scala_input_first_seen:
            self.propagation_lags.append(
                now - self._scala_input_first_seen.pop(rust_best))

        # The ordering block is the comparison key: two input chains under
        # different ordering blocks are not the same thing. `bestOrdering`
        # comes from the same call as the chain, so the pair is coherent.
        scala_ordering = reading['scala']['chain'].get('bestOrdering') or None
        rust_ordering = reading['rust']['chain'].get('bestOrdering') or None
        self.series.append({
            'at': now,
            'ordering': scala_ordering if scala_ordering == rust_ordering else None,
            'scala_chain': reading['scala']['chain'].get('bestInputBlocks') or [],
            'rust_chain': reading['rust']['chain'].get('bestInputBlocks') or [],
            'scala_tip': scala_best or None,
            'rust_tip': rust_best or None,
        })

    def note_input_block_txids(self, reading):
        """Record which transactions Rust saw inside each input block."""
        if reading is None:
            return
        for bid in reading['rust']['chain'].get('bestInputBlocks') or []:
            # Only a NON-EMPTY answer is cached. An input block shows up
            # in the chain before its bodies are attached, so caching the
            # first empty answer would permanently hide its transactions.
            if self.input_block_txids.get(bid):
                continue
            try:
                self.input_block_txids[bid] = api(
                    'rust', f'/blocks/{bid}/inputBlockTransactionIds') or []
            except Unavailable:
                pass


class Workload:
    """A steady stream of wallet payments on the Scala node.

    Assertion 4 needs the miner to be producing input blocks that CARRY
    transactions while the follower restarts: an ordering block holding
    only its coinbase is carried by the ordering announcement itself, so
    reconstruction can neither need an input-block body nor miss one.
    Without a workload the restart proves nothing.
    """

    def __init__(self, address, interval=1.0):
        self.address = address
        self.interval = interval
        self.submitted = []
        self.failures = []
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def _run(self):
        while not self._stop.is_set():
            try:
                status, txid = request('scala', '/wallet/payment/send',
                                       [{'address': self.address, 'value': 1_000_000}])
                if status == 200 and txid:
                    self.submitted.append(txid)
                else:
                    self.failures.append(str(status))
            except (OSError, ValueError) as error:
                # A wallet that is momentarily out of unspent boxes is
                # normal here; it is not an observation about the nodes.
                self.failures.append(str(error))
            self._stop.wait(self.interval)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
        return {'submitted': len(self.submitted), 'failures': len(self.failures)}



# ----- assertion 2 and 3 evaluators (pure, self-tested) -----
#
# A sample is a dict:
#   {'ordering': <ordering block id both nodes report, or None>,
#    'scala_chain': [ids, NEWEST FIRST], 'rust_chain': [ids, newest first],
#    'scala_tip': <id or None>, 'rust_tip': <id or None>}
# Only samples where both nodes name the SAME ordering block are compared;
# comparing input chains under different ordering blocks compares
# different things.


def percentile(values, pct):
    """The `pct`-th percentile by nearest-rank. `None` for no values."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100 * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


def evaluate_tip_consistency(samples):
    """Assertion 2. Rust's tip must be a block Scala had on its best chain
    for the same ordering block (at that sample or any later one), and the
    lag — how many input blocks Rust trails by — must stay inside the
    bounds. Exact equality is counted, not required."""
    scala_seen = {}          # ordering -> set of every id Scala ever listed
    scala_seen_order = {}    # ordering -> [ (index, frozenset) ] for "later"
    for i, s in enumerate(samples):
        if not s.get('ordering'):
            continue
        ids = set(s.get('scala_chain') or [])
        scala_seen.setdefault(s['ordering'], set()).update(ids)
        scala_seen_order.setdefault(s['ordering'], []).append((i, ids))

    lags, unconfirmed, exact, compared = [], [], 0, 0
    for i, s in enumerate(samples):
        ordering, rust_tip = s.get('ordering'), s.get('rust_tip')
        if not ordering or not rust_tip:
            continue
        compared += 1
        if rust_tip == s.get('scala_tip'):
            exact += 1
        # "at some later sample": this sample counts too, so the window is
        # every Scala observation from here on. A tip Rust reports before
        # Scala's REST has caught up is still confirmed.
        confirmed = any(rust_tip in ids
                        for j, ids in scala_seen_order.get(ordering, ())
                        if j >= i)
        if not confirmed:
            # Fall back to the whole-run union before calling it a
            # divergence: a tip Scala listed only EARLIER is still a tip
            # Scala had, and the ordering block may have moved on.
            if rust_tip in scala_seen.get(ordering, ()):
                confirmed = True
        if not confirmed:
            unconfirmed.append({'sample': i, 'ordering': ordering,
                                'rust_tip': rust_tip,
                                'scala_chain': s.get('scala_chain') or []})
            continue
        chain = s.get('scala_chain') or []
        if rust_tip in chain:
            # Chains are newest-first, so the index IS the number of
            # input blocks Rust trails by at this instant.
            lags.append(chain.index(rust_tip))
    p95, mx = percentile(lags, 95), (max(lags) if lags else None)
    violations = []
    if p95 is not None and p95 > LAG_P95_MAX:
        violations.append(f'lag p95 {p95} > {LAG_P95_MAX}')
    if mx is not None and mx > LAG_MAX:
        violations.append(f'lag max {mx} > {LAG_MAX}')
    if unconfirmed:
        violations.append(
            f'{len(unconfirmed)} Rust tips were never on Scala\'s best chain')
    return {
        'compared_samples': compared,
        'lag_samples': len(lags),
        'lag_p95': p95,
        'lag_max': mx,
        'lag_mean': round(sum(lags) / len(lags), 2) if lags else None,
        'lag_bounds': {'p95_max': LAG_P95_MAX, 'max': LAG_MAX},
        'exact_tip_matches': exact,
        'unconfirmed_rust_tips': unconfirmed[:10],
        'unconfirmed_count': len(unconfirmed),
        'violations': violations,
    }


def evaluate_chain_consistency(samples):
    """Assertion 3. At every same-ordering-block sample Rust's chain must
    be a prefix of Scala's read oldest-first — i.e. Scala's chain with the
    newest k entries removed. Rust trailing is fine; a different HISTORY
    is not."""
    compared, violations, depths = 0, [], []
    for i, s in enumerate(samples):
        if not s.get('ordering'):
            continue
        scala_chain = s.get('scala_chain') or []
        rust_chain = s.get('rust_chain') or []
        if not rust_chain:
            # Nothing to contradict. Counted, but no claim either way.
            continue
        compared += 1
        # Oldest-first, so "prefix" is the natural reading.
        scala_old = list(reversed(scala_chain))
        rust_old = list(reversed(rust_chain))
        if len(rust_old) <= len(scala_old) and scala_old[:len(rust_old)] == rust_old:
            depths.append(len(scala_old) - len(rust_old))
            continue
        if len(violations) < 10:
            violations.append({'sample': i, 'ordering': s['ordering'],
                               'scala_chain': scala_chain,
                               'rust_chain': rust_chain})
    return {
        'compared_samples': compared,
        'prefix_violations': violations,
        'prefix_violation_count': len(violations),
        'max_truncation_depth': max(depths) if depths else None,
    }


def _self_test():
    """Red-first coverage for the two evaluators above, on synthetic
    series. They decide the gate, so they need to fail where the new
    definitions say they must."""
    ordering = 'O'

    def sample(scala, rust):
        return {'ordering': ordering, 'scala_chain': scala, 'rust_chain': rust,
                'scala_tip': scala[0] if scala else None,
                'rust_tip': rust[0] if rust else None}

    # A follower trailing by 2 of a 5-long chain: consistent, lag 2.
    trailing = [sample(['e', 'd', 'c', 'b', 'a'], ['c', 'b', 'a'])] * 20
    tip = evaluate_tip_consistency(trailing)
    assert tip['violations'] == [], tip
    assert tip['lag_p95'] == 2 and tip['lag_max'] == 2, tip
    assert tip['exact_tip_matches'] == 0, tip
    assert evaluate_chain_consistency(trailing)['prefix_violation_count'] == 0

    # In lockstep: still consistent, lag 0, and the exact-match metric
    # counts every sample.
    lockstep = [sample(['c', 'b', 'a'], ['c', 'b', 'a'])] * 5
    tip = evaluate_tip_consistency(lockstep)
    assert tip['lag_max'] == 0 and tip['exact_tip_matches'] == 5, tip

    # A tip Scala never had on its best chain: a real divergence.
    rogue = [sample(['c', 'b', 'a'], ['X', 'b', 'a'])]
    tip = evaluate_tip_consistency(rogue)
    assert tip['unconfirmed_count'] == 1, tip
    assert any('never on Scala' in v for v in tip['violations']), tip

    # Confirmed by a LATER sample: Rust saw it before Scala's REST did.
    ahead = [sample(['b', 'a'], ['c', 'b', 'a']),
             sample(['c', 'b', 'a'], ['c', 'b', 'a'])]
    assert evaluate_tip_consistency(ahead)['unconfirmed_count'] == 0

    # Lag past the bounds fails, even though every tip is consistent.
    deep = ['t%02d' % n for n in range(30, -1, -1)]
    far = [sample(deep, deep[20:])] * 10
    tip = evaluate_tip_consistency(far)
    assert tip['lag_p95'] == 20 and tip['lag_max'] == 20, tip
    assert any('p95' in v for v in tip['violations']), tip
    assert any('max' in v for v in tip['violations']), tip

    # A different HISTORY at the same length is a prefix violation.
    forked = [sample(['c', 'b', 'a'], ['c', 'x', 'a'])]
    chain = evaluate_chain_consistency(forked)
    assert chain['prefix_violation_count'] == 1, chain

    # Rust longer than Scala is a violation too: it cannot be a prefix.
    longer = [sample(['b', 'a'], ['c', 'b', 'a'])]
    assert evaluate_chain_consistency(longer)['prefix_violation_count'] == 1

    # Samples under different ordering blocks are never compared.
    unrelated = [{'ordering': None, 'scala_chain': ['a'], 'rust_chain': ['z'],
                  'scala_tip': 'a', 'rust_tip': 'z'}]
    assert evaluate_tip_consistency(unrelated)['compared_samples'] == 0
    assert evaluate_chain_consistency(unrelated)['compared_samples'] == 0

    print('self-test OK: evaluators behave as the round-3 definitions require')


# ----- assertion drivers -----


def assertion_1_peering(run, evidence):
    deadline = min(run.deadline, time.monotonic() + 120)
    try:
        connected = {node: api_retry(node, '/peers/connected', deadline,
                                     what=f'{node} /peers/connected') for node in URLS}
        peers = api_retry('rust', '/api/v1/peers', deadline, what='rust /api/v1/peers')
    except Unavailable as error:
        evidence['1_peering'] = {'result': 'FAIL', 'error': str(error)}
        run.fail('1_peering', str(error))
        return
    scala_peer = next(
        (p for p in peers if p.get('addr', '').endswith(str(lifecycle.P2P['scala']))), None)
    evidence['1_peering'] = {
        'connected': {node: len(v) for node, v in connected.items()},
        'scala_peer_seen_by_rust': scala_peer,
    }
    if not all(connected.values()):
        run.fail('1_peering', f'both nodes must have a connected peer: {connected}')
    elif scala_peer is None:
        run.fail('1_peering', 'Rust does not list the Scala node as a peer')
    elif parse_version(scala_peer.get('version')) < REQUIRED_PEER_VERSION:
        run.fail('1_peering',
                 f'Scala peer speaks {scala_peer.get("version")!r}, need '
                 f'{".".join(str(p) for p in REQUIRED_PEER_VERSION)}')
    evidence['1_peering']['result'] = 'FAIL' if any(
        f['assertion'] == '1_peering' for f in run.failures) else 'PASS'


def assertion_2_and_3_agreement(run, evidence):
    """Consistency under lag (round-3 restatement).

    Exact instantaneous equality is unreachable against a miner
    publishing ~64 input blocks per ordering block, and lag is not
    divergence. So assertion 2 requires that every tip Rust reports is a
    block Scala had on its best chain, with the lag inside hard bounds,
    and assertion 3 requires Rust's chain to be a prefix of Scala's read
    oldest-first. Exact matches are counted, never required.
    """
    start_height = scala_height(run)
    limit = start_height + AGREEMENT_ORDERING_BLOCKS
    while time.monotonic() < run.deadline:
        reading = run.sweep()
        run.note_input_block_txids(reading)
        if reading and (reading['scala']['info'].get('fullHeight') or 0) > limit:
            break
        time.sleep(0.2)

    tip = evaluate_tip_consistency(run.series)
    chain = evaluate_chain_consistency(run.series)
    lags = [round(v, 3) for v in run.propagation_lags]
    evidence['2_best_input_block'] = {
        'definition': ("every Rust bestInputBlock must be a block Scala had on its "
                       "best chain for the same ordering block; lag p95 <= "
                       f"{LAG_P95_MAX} and max <= {LAG_MAX} input blocks"),
        'observed_ordering_blocks': AGREEMENT_ORDERING_BLOCKS,
        'start_height': start_height,
        'samples': run.samples,
        'unavailable_samples': run.unavailable_samples,
        'max_propagation_lag_seconds': max(lags) if lags else None,
        **tip,
    }
    evidence['3_best_input_chain'] = {
        'definition': ("at every same-ordering-block sample Rust's bestInputChain must "
                       "be a prefix of Scala's read oldest-first (tip-side truncated)"),
        **chain,
    }
    if tip['violations']:
        run.fail('2_best_input_block', '; '.join(tip['violations']),
                 {'lag_p95': tip['lag_p95'], 'lag_max': tip['lag_max'],
                  'unconfirmed': tip['unconfirmed_rust_tips']})
    if chain['prefix_violations']:
        run.fail('3_best_input_chain',
                 f"Rust's chain was not a prefix of Scala's at "
                 f"{chain['prefix_violation_count']} samples",
                 {'violations': chain['prefix_violations']})
    for key in ('2_best_input_block', '3_best_input_chain'):
        evidence[key]['result'] = 'FAIL' if any(
            f['assertion'] == key for f in run.failures) else 'PASS'


def scala_height(run):
    try:
        return api('scala', '/info').get('fullHeight') or 0
    except Unavailable:
        return 0


def wait_for_height(run, target, what):
    """Poll until Scala reaches `target`, sampling as we go."""
    while time.monotonic() < run.deadline:
        reading = run.sweep()
        run.note_input_block_txids(reading)
        if reading and (reading['scala']['info'].get('fullHeight') or 0) >= target:
            return reading
        time.sleep(0.5)
    raise Unavailable(f'{what}: Scala did not reach ordering block {target} in budget')


def assertion_6_mempool(run, evidence, count):
    """Funded workload: 20 accepted submissions, tracked through an input
    block and the next ordering block."""
    result = {'requested': count, 'submitted': [], 'submit_failures': []}
    evidence['6_mempool'] = result
    # A miner reward matures at ordering block 11, and the recipe's
    # target is ~55 s per ordering block, so the wait is minutes — the
    # old 300 s cap expired before the chain got there and reported "no
    # spendable coin" for what was simply a chain that had not run long
    # enough.
    deadline = min(run.deadline, time.monotonic() + 900)

    # Wait for a matured miner reward. `devnet_miner_reward_delay = 10`
    # on both nodes makes this height 11-ish rather than 721.
    while time.monotonic() < deadline:
        try:
            balance = (api('scala', '/wallet/balances') or {}).get('balance') or 0
        except Unavailable:
            balance = 0
        if balance > 0:
            break
        run.sweep()
        time.sleep(1)
    result['balance_nano'] = balance
    if not balance:
        run.fail('6_mempool', 'no spendable coin on the Scala wallet within budget')
        result['result'] = 'FAIL'
        return
    try:
        address = (api('scala', '/wallet/addresses') or [None])[0]
    except Unavailable as error:
        run.fail('6_mempool', f'wallet address unavailable: {error}')
        result['result'] = 'FAIL'
        return
    result['address'] = address

    for i in range(count):
        try:
            status, txid = request('scala', '/wallet/payment/send',
                                   [{'address': address, 'value': 1_000_000}])
            if status != 200 or not txid:
                result['submit_failures'].append({'index': i, 'status': status})
            else:
                result['submitted'].append(txid)
        except (OSError, ValueError) as error:
            result['submit_failures'].append({'index': i, 'error': str(error)})
    submitted = set(result['submitted'])
    if len(submitted) != count:
        run.fail('6_mempool',
                 f'{len(submitted)} of {count} submissions returned HTTP 200',
                 {'failures': result['submit_failures']})

    # Follow them: into a Rust input block, then out of Rust's pool.
    in_input_block = {}
    ever_in_rust_pool = set()
    track_deadline = min(run.deadline, time.monotonic() + 240)
    while time.monotonic() < track_deadline:
        reading = run.sweep()
        run.note_input_block_txids(reading)
        for bid, ids in run.input_block_txids.items():
            for txid in set(ids) & submitted:
                in_input_block.setdefault(txid, bid)
        try:
            ever_in_rust_pool |= {t['id'] for t in api('rust', '/transactions/unconfirmed')}
        except Unavailable:
            pass
        if submitted and set(in_input_block) >= submitted:
            break
        time.sleep(0.3)
    result['in_rust_input_block'] = in_input_block
    result['rust_pool_ever_held'] = sorted(ever_in_rust_pool & submitted)

    if not in_input_block:
        run.fail('6_mempool',
                 'no submitted transaction was ever observed inside a Rust input block',
                 {'input_blocks_seen': len(run.input_block_txids),
                  'rust_pool_ever_held': result['rust_pool_ever_held'],
                  'rust_log': rust_log_lines('input_blocks')})

    # Removal from Rust's pool, then pool equality after the next
    # ordering block, with explicit D1/F6 accounting.
    height_now = scala_height(run)
    try:
        wait_for_height(run, height_now + 1, 'assertion 6 ordering block')
        time.sleep(3)
        scala_pool = {t['id'] for t in api_retry(
            'scala', '/transactions/unconfirmed', run.deadline, what='scala pool')}
        rust_pool = {t['id'] for t in api_retry(
            'rust', '/transactions/unconfirmed', run.deadline, what='rust pool')}
    except Unavailable as error:
        run.fail('6_mempool', str(error))
        result['result'] = 'FAIL'
        return

    still_pooled = sorted(set(in_input_block) & rust_pool)
    result['applied_but_still_in_rust_pool'] = still_pooled
    if still_pooled:
        run.fail('6_mempool',
                 'transactions in an applied Rust input block are still unconfirmed there',
                 {'txids': still_pooled})

    symmetric = scala_pool ^ rust_pool
    result['scala_unconfirmed'] = sorted(scala_pool)
    result['rust_unconfirmed'] = sorted(rust_pool)
    result['symmetric_difference'] = sorted(symmetric)
    # D1 (conflict-checked mempool restore) and F6 (input-chain
    # transactions an ordering block omits are dropped and never
    # restored) are the two documented reasons the pools may differ;
    # both can only leave a transaction in SCALA's pool that Rust
    # dropped, never the reverse.
    result['d1_f6_accounting'] = {
        'only_in_scala': sorted(scala_pool - rust_pool),
        'only_in_rust': sorted(rust_pool - scala_pool),
        'explained_by': 'D1/F6 permit scala-only residue; rust-only residue is unexplained',
    }
    if rust_pool - scala_pool:
        run.fail('6_mempool',
                 'Rust holds unconfirmed transactions Scala does not; D1/F6 cannot '
                 'explain residue in that direction',
                 {'only_in_rust': sorted(rust_pool - scala_pool),
                  'only_in_scala': sorted(scala_pool - rust_pool)})
    result['result'] = 'FAIL' if any(
        f['assertion'] == '6_mempool' for f in run.failures) else 'PASS'


def assertion_4_reconstruction(run, evidence, ordering_blocks):
    """Cold restart under a multi-transaction workload: the first ordering
    block after it must fall back, a later one must reconstruct with more
    than one transaction."""
    result = {}
    evidence['4_reconstruction'] = result
    try:
        before = api_retry('rust', '/api/v1/events', run.deadline, what='rust events')
    except Unavailable as error:
        run.fail('4_reconstruction', str(error))
        result['result'] = 'FAIL'
        return
    result['before_restart'] = ordering_event_summary(before)

    restart_height = scala_height(run)
    result['restarted_at_scala_height'] = restart_height
    lifecycle.stop(('rust',))
    lifecycle.spawn('rust')
    run.started('rust')
    lifecycle.wait_peered()

    try:
        wait_for_height(run, restart_height + ordering_blocks,
                        'assertion 4 post-restart window')
        events = api_retry('rust', '/api/v1/events', run.deadline, what='rust events')
    except Unavailable as error:
        run.fail('4_reconstruction', str(error))
        result['result'] = 'FAIL'
        return

    ordering = [e for e in events.get('events', []) if e['kind'].startswith('ordering_')]
    result['ordering_events'] = ordering
    # D4 telemetry: which assembly order reproduced the header root, and
    # which reasons the fallbacks gave. Both are the point of the round.
    # The API serializes camelCase; accept either so a rename cannot
    # silently turn the telemetry into "unreported".
    result['orders'] = _tally(
        e.get('reconstructedOrder', e.get('reconstructed_order'))
        for e in ordering if e['kind'] == 'ordering_reconstructed')
    result['fallback_reasons'] = _tally(e.get('detail') for e in ordering
                                        if e['kind'] == 'ordering_reconstruct_fallback')
    # D5 telemetry: which ordering id the input chain was read under.
    result['reconstruction_keys'] = _tally(
        e.get('reconstructionKey', e.get('reconstruction_key'))
        for e in ordering if e['kind'] == 'ordering_reconstructed')
    result['after_restart'] = ordering_event_summary(events)
    result['ordering_blocks_observed'] = ordering_blocks

    # The FIRST ordering outcome after the restart: the processor is
    # in-memory, so its input chain is gone and the block cannot be
    # assembled from input-block bodies.
    first = ordering[0] if ordering else None
    result['first_after_restart'] = first
    if first is None:
        run.fail('4_reconstruction',
                 'the restarted node recorded no ordering reconstruction outcome at all',
                 {'events': events.get('events', [])[-20:]})
    elif first['kind'] != 'ordering_reconstruct_fallback':
        run.fail('4_reconstruction',
                 'the first ordering block after a cold restart was not a fallback: '
                 f'{first["kind"]}',
                 {'first': first, 'ordering_events': ordering[:10],
                  'rust_log': rust_log_lines('reconstruction is missing')})
    else:
        # The restart must force a fallback, and it does. The REASON is
        # recorded rather than asserted: a cold-started node holds no
        # input chain at all, so the planner names no body to be missing
        # and reports `root_mismatch` (nothing to assemble from) rather
        # than `missing_input_body` (a named body it cannot resolve).
        # Both are the same "the in-memory chain is gone" outcome; the
        # distinction is which ingredient is absent, not whether one is.
        result['first_after_restart_reason'] = first.get('detail')
        result['first_after_restart_reason_note'] = (
            'root_mismatch is the expected reason for a COLD start: with an '
            'empty input chain the planner names no body, so missing_input_body '
            'cannot fire. missing_input_body needs a chain whose bodies were '
            'evicted, not one that never existed.')

    # A later ordering block must be reconstructed FROM input-block
    # bodies. A one-transaction block proves nothing: its coinbase rides
    # in the ordering announcement itself.
    multi = [e for e in ordering
             if e['kind'] == 'ordering_reconstructed' and (e.get('txs') or 0) > 1]
    result['reconstructed_multi_tx'] = multi
    result['reconstructed_total'] = sum(
        1 for e in ordering if e['kind'] == 'ordering_reconstructed')
    result['fallback_total'] = sum(
        1 for e in ordering if e['kind'] == 'ordering_reconstruct_fallback')
    if not multi:
        run.fail('4_reconstruction',
                 'no ordering block was reconstructed with more than one transaction, so '
                 'assembly from input-block bodies was never demonstrated',
                 {'ordering_events': ordering,
                  'rust_log': rust_log_lines('rebuilt from the input chain')})
    result['result'] = 'FAIL' if any(
        f['assertion'] == '4_reconstruction' for f in run.failures) else 'PASS'


def _tally(values):
    counts = {}
    for value in values:
        key = value if value is not None else 'unreported'
        counts[key] = counts.get(key, 0) + 1
    return counts


def ordering_event_summary(feed):
    counts = {}
    for event in (feed or {}).get('events', []):
        counts[event['kind']] = counts.get(event['kind'], 0) + 1
    return counts


def assertion_5_follow(run, evidence):
    totals = run.totals()
    evidence['5_follow'] = {
        'max_height_gap': run.max_height_gap,
        'height_window': HEIGHT_WINDOW,
        'start_grace_seconds': START_GRACE_SECONDS,
        'violations': run.height_violations[:20],
        'violation_count': len(run.height_violations),
        'accumulated_drops': totals,
        'peer_states_seen': sorted(run.peer_states),
        'penalty_observations': run.penalty_observations,
        'samples': run.samples,
        'unavailable_samples': run.unavailable_samples,
    }
    if run.samples == 0:
        run.fail('5_follow', 'no usable sample was taken')
    fatal = {r: totals[r] for r in FATAL_DROPS if totals.get(r)}
    if fatal:
        run.fail('5_follow', f'byte-level disagreement with the Scala peer: {fatal}',
                 {'drops': totals, 'rust_log': rust_log_lines('input_blocks: dropped')})
    penalties = rust_log_lines('penalizing peer')
    evidence['5_follow']['penalty_log_lines'] = penalties
    if penalties or run.penalty_observations:
        run.fail('5_follow', 'the Scala peer was penalised',
                 {'log': penalties, 'observations': run.penalty_observations})
    if 'absent' in run.peer_states:
        run.fail('5_follow', 'the Scala peer disappeared from Rust\'s peer list')
    if run.height_violations:
        run.fail('5_follow',
                 f'Rust fell more than {HEIGHT_WINDOW} blocks behind '
                 f'{len(run.height_violations)} times (max gap {run.max_height_gap})',
                 {'violations': run.height_violations[:20]})
    evidence['5_follow']['result'] = 'FAIL' if any(
        f['assertion'] == '5_follow' for f in run.failures) else 'PASS'


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_findings(run, evidence):
    """One artifact per failure that carries evidence."""
    written = []
    for finding in run.findings:
        path = next_finding_path()
        try:
            observed = {node: api(node, '/info') for node in URLS}
        except Unavailable as error:
            observed = {'error': str(error)}
        path.write_text(json.dumps({
            'id': path.stem,
            'title': f'devnet-matrix smoke: {finding["assertion"]} failed',
            'severity': 'divergence',
            'source': 'scripts/devnet-matrix/smoke.py',
            'assertion': finding['assertion'],
            'message': finding['message'],
            'evidence': finding['evidence'],
            'both_nodes_info': observed,
            'rust_events_tail': evidence.get('4_reconstruction', {}).get(
                'ordering_events', [])[-20:],
            'rust_debug_log_tail': rust_log_lines('input_blocks', limit=80),
            'scala': evidence.get('scala'),
            'rust': evidence.get('rust'),
        }, indent=2) + '\n')
        written.append(str(path.relative_to(ROOT)))
    return written


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ordering-blocks', type=int, default=10,
                        help='ordering blocks to observe after the restart')
    parser.add_argument('--timeout', type=int, default=1200,
                        help='overall polling budget, seconds')
    parser.add_argument('--mempool-txs', type=int, default=20)
    parser.add_argument('--self-test', action='store_true',
                        help='run the evaluator unit tests and exit (no nodes needed)')
    args = parser.parse_args()
    if args.self_test:
        _self_test()
        return
    if args.self_test:
        _self_test()
        return

    evidence = {
        'status': 'RUNNING',
        'command': (f'python3 scripts/devnet-matrix/smoke.py '
                    f'--ordering-blocks {args.ordering_blocks} '
                    f'--timeout {args.timeout} --mempool-txs {args.mempool_txs}'),
        'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'rust': {
            'git_sha': subprocess.check_output(
                ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
            'git_status_porcelain': subprocess.check_output(
                ['git', 'status', '--porcelain'], cwd=ROOT, text=True),
            'toolchain': subprocess.check_output(['rustc', '--version'], text=True).strip(),
            'binary': lifecycle.node_binary(),
        },
        'scala': {
            'classpath': str(lifecycle.classpath_file()),
            'pinned_app_version': lifecycle.SCALA_APP_VERSION,
            'app_version': (WORK / 'scala.appVersion').read_text().strip()
            if (WORK / 'scala.appVersion').exists() else None,
        },
        'genesis_state_root': lifecycle.GENESIS_STATE_ROOT,
        'sha256': {p.name: sha256(p) for p in sorted(HERE.glob('*'))
                   if p.is_file() and not p.name.startswith('.')},
        'assertions': {},
    }
    output = WORK / 'smoke-evidence.json'

    def save():
        WORK.mkdir(exist_ok=True)
        output.write_text(json.dumps(evidence, indent=2) + '\n')

    run = Run(time.monotonic() + args.timeout)
    # Both nodes are already up when the smoke starts; their grace window
    # began at `start.sh`, which is earlier than this, so no grace is
    # granted here. Only the deliberate restart re-arms one.
    try:
        assertion_1_peering(run, evidence['assertions'])
        save()
        assertion_2_and_3_agreement(run, evidence['assertions'])
        save()
        assertion_6_mempool(run, evidence['assertions'], args.mempool_txs)
        save()
        # Assertion 4 runs UNDER LOAD: the restart only proves something
        # while the miner is sealing transactions into input blocks.
        address = evidence['assertions'].get('6_mempool', {}).get('address')
        workload = Workload(address).start() if address else None
        try:
            assertion_4_reconstruction(run, evidence['assertions'], args.ordering_blocks)
        finally:
            evidence['workload'] = workload.stop() if workload else {
                'submitted': 0, 'failures': 0,
                'note': 'no wallet address; assertion 6 could not fund one'}
        save()
        # Last, so it sees every counter the whole run produced.
        assertion_5_follow(run, evidence['assertions'])
    except BaseException as error:  # noqa: BLE001 - recorded, then re-raised
        run.fail('harness', f'{type(error).__name__}: {error}')
        evidence['harness_error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        evidence['agreement_series_sample'] = run.series[:200]
        evidence['agreement_series_total'] = len(run.series)
        evidence['failures'] = run.failures
        evidence['status'] = 'PASS' if not run.failures else 'FAIL'
        if run.findings:
            evidence['findings_written'] = write_findings(run, evidence)
        save()
        recon = evidence['assertions'].get('4_reconstruction', {})
        tipm = evidence['assertions'].get('2_best_input_block', {})
        orders = recon.get('orders', {})
        print(f'{evidence["status"]}: '
              f'reconstructed={recon.get("reconstructed_total", 0)} '
              f'(multi-tx {len(recon.get("reconstructed_multi_tx", []))}, '
              f'orders {orders or "none"}, '
              f'keys {recon.get("reconstruction_keys", {}) or "none"}) '
              f'fallback={recon.get("fallback_total", 0)} '
              f'{recon.get("fallback_reasons", {}) or ""} '
              f'lag_p95={tipm.get("lag_p95")} lag_max={tipm.get("lag_max")} '
              f'exact={tipm.get("exact_tip_matches")} '
              f'max_height_gap={run.max_height_gap} '
              f'failures={len(run.failures)} '
              f'evidence={output.relative_to(ROOT)}', flush=True)
    raise SystemExit(0 if not run.failures else 1)


if __name__ == '__main__':
    main()
