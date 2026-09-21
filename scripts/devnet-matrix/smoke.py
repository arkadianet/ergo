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

# Assertions 2 and 3 are statistical, so they need coverage before a
# verdict means anything. Fewer qualifying samples than this — or a lag
# that could not be measured at all — is a FAIL, never a quiet PASS on an
# empty series.
MIN_QUALIFYING_SAMPLES = 50

# Assertion 6 allows this many of the 20 submissions to go missing from
# every observed Rust input block. The Scala miner's `cachedCandidate`
# race loses input blocks outright, so a hard 20/20 would gate on the
# reference node's bug; every miss is recorded.
MEMPOOL_MIN_LOCATED = 18

# Assertion 5 fails when more than this fraction of monitoring sweeps
# could not be taken. A run that could not watch the nodes has not
# watched them, however few violations it saw.
MAX_UNAVAILABLE_FRACTION = 0.05


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


def rust_log_window(unix_seconds, before=10.0, after=5.0, limit=400):
    """Every debug-log line the Rust node emitted around `unix_seconds`.

    The artifact has to carry the announcement bytes for the observation
    that actually mismatched, not the last 80 lines of an unrelated tail.
    Lines are timestamped RFC3339 by `tracing`, so the window is exact.
    """
    try:
        text = strip_ansi((WORK / 'rust.log').read_text(errors='replace'))
    except OSError:
        return []
    lo = datetime.datetime.fromtimestamp(
        unix_seconds - before, datetime.timezone.utc)
    hi = datetime.datetime.fromtimestamp(
        unix_seconds + after, datetime.timezone.utc)
    out = []
    for line in text.splitlines():
        stamp = re.match(r'^(\d{4}-\d{2}-\d{2}T[\d:.]+Z)', line)
        if not stamp:
            continue
        try:
            when = datetime.datetime.fromisoformat(
                stamp.group(1).replace('Z', '+00:00'))
        except ValueError:
            continue
        if lo <= when <= hi:
            out.append(line)
            if len(out) >= limit:
                break
    return out


def write_mismatch_artifact(assertion, message, evidence, at=None, context=None):
    """Write a divergence artifact NOW, while the observation is fresh.

    Deferring these to the end of the run meant the `/info` bodies were
    the final ones and the log tail was whatever had scrolled past since
    — neither describing the mismatch they were filed for.
    """
    path = next_finding_path()
    try:
        observed = {node: api(node, '/info') for node in URLS}
    except Unavailable as error:
        observed = {'error': str(error)}
    body = {
        'id': path.stem,
        'title': f'devnet-matrix smoke: {assertion} mismatch',
        'severity': 'divergence',
        'source': 'scripts/devnet-matrix/smoke.py',
        'written': 'at mismatch time',
        'assertion': assertion,
        'message': message,
        'observed_at_unix': at,
        'evidence': evidence,
        'both_nodes_info_at_mismatch': observed,
        'rust_debug_log_window': (
            rust_log_window(at) if at else rust_log_lines('input_blocks', limit=80)),
    }
    if context:
        body.update(context)
    path.write_text(json.dumps(body, indent=2) + '\n')
    return str(path.relative_to(ROOT))


def next_finding_path():
    FINDINGS.mkdir(parents=True, exist_ok=True)
    day = datetime.date.today().isoformat()
    n = 1
    while (FINDINGS / f'{day}-{n}.json').exists():
        n += 1
    return FINDINGS / f'{day}-{n}.json'


class Run:
    """The whole observation: samples, accumulated counters, failures.

    Sampling happens on its OWN thread for the whole run. Every previous
    round drove it from the assertion drivers, so monitoring stopped
    while the harness was submitting payments, waiting on a blocking REST
    call, or restarting the node — exactly the windows where a height
    violation is most likely and least likely to be seen.
    """

    def __init__(self, deadline):
        self.deadline = deadline
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._latest = None
        self.series_path = WORK / 'agreement-series.jsonl'
        self._series_file = None
        self.failures = []
        self.findings = []
        self.samples = 0
        self.unavailable_samples = 0
        self.unavailable_reasons = []
        self.live_artifacts = 0
        self.live_artifact_paths = []
        self.peer_absent_in_grace = 0

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

    # ----- the sampler thread -----

    def start_sampling(self, interval=0.3):
        WORK.mkdir(exist_ok=True)
        self._series_file = self.series_path.open('w')
        self._thread = threading.Thread(target=self._sample_loop, args=(interval,),
                                        daemon=True)
        self._thread.start()

    def _sample_loop(self, interval):
        while not self._stop.is_set() and time.monotonic() < self.deadline:
            self.sweep()
            self._stop.wait(interval)

    def stop_sampling(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)
        if self._series_file:
            self._series_file.close()
            self._series_file = None

    def latest_reading(self):
        with self._lock:
            return self._latest

    def carry_counters_forward(self):
        """Fold the live process's counters into the carried totals.

        Called immediately BEFORE a node is killed. Inferring a reset from
        a decreasing counter loses every count a restarted process
        reaches or exceeds before the next sample, so the restart says so
        explicitly instead of leaving it to be guessed.
        """
        with self._lock:
            for value in self.drop_counters.values():
                value['carried'] += value['current']
                value['current'] = 0

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
        except Unavailable as error:
            with self._lock:
                self.unavailable_samples += 1
                if len(self.unavailable_reasons) < 20:
                    self.unavailable_reasons.append(str(error))
            return None
        with self._lock:
            self.samples += 1
            self._accumulate_counters(status, peers)
            self._accumulate_heights(reading, now)
            self._accumulate_agreement(reading, now)
            self._latest = reading
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
                # Belt to `carry_counters_forward`'s braces: a reset the
                # restart path did not announce (a node that died on its
                # own) still folds forward.
                previous['carried'] += previous['current']
            previous['current'] = entry['count']
            self.drop_counters[key] = previous
        scala_peer = next(
            (p for p in (peers or [])
             if p.get('addr', '').endswith(str(lifecycle.P2P['scala']))), None)
        if scala_peer is None:
            # Now that the sampler never stops, it sees the deliberate
            # restart: a node that has just come back has an empty peer
            # list until the handshake completes. That is the restart,
            # not a dropped peer. The same start grace the height window
            # uses applies here, and the observations it covers are
            # counted so the exclusion is visible rather than assumed.
            if self.in_grace('rust'):
                self.peer_absent_in_grace += 1
            else:
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
        entry = {
            'at': now,
            'ordering': scala_ordering if scala_ordering == rust_ordering else None,
            'scala_ordering': scala_ordering,
            'rust_ordering': rust_ordering,
            'scala_chain': reading['scala']['chain'].get('bestInputBlocks') or [],
            'rust_chain': reading['rust']['chain'].get('bestInputBlocks') or [],
            'scala_tip': scala_best or None,
            'rust_tip': rust_best or None,
        }
        # EVERY sample is retained and streamed to disk as it is taken:
        # the evaluators run over the whole run at finalization, and a
        # crash still leaves the series behind to re-evaluate.
        self.series.append(entry)
        if self._series_file:
            self._series_file.write(json.dumps(entry) + '\n')
            self._series_file.flush()
        self._maybe_write_live_mismatch(entry, reading)

    def _maybe_write_live_mismatch(self, entry, reading):
        """Write an artifact for a prefix mismatch AS IT IS OBSERVED.

        Only the chain-prefix check is decidable from a single sample;
        the tip and lag verdicts need the whole series and are filed at
        finalization. Bounded, so a persistent mismatch does not fill the
        findings directory.
        """
        if entry['ordering'] is None or self.live_artifacts >= 3:
            return
        scala_old = list(reversed(entry['scala_chain']))
        rust_old = list(reversed(entry['rust_chain']))
        if not rust_old:
            return
        if len(rust_old) <= len(scala_old) and scala_old[:len(rust_old)] == rust_old:
            return
        self.live_artifacts += 1
        try:
            path = write_mismatch_artifact(
                '3_best_input_chain',
                "Rust's bestInputChain is not a prefix of Scala's",
                {'sample': entry, 'ordering': entry['ordering']},
                at=entry['at'],
                context={'rust_best_input_block': reading['rust']['best'],
                         'scala_best_input_block': reading['scala']['best'],
                         'rust_info': reading['rust']['info'],
                         'scala_info': reading['scala']['info']})
            self.live_artifact_paths.append(path)
        except OSError:
            # Evidence collection must never take the run down.
            pass

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
#
# One more sampling rule, and it is not a loophole. On BOTH nodes
# `/blocks/bestInputChain` pairs `bestOrdering` — the best HEADER id —
# with a chain read from the input-block processor, and Scala's route
# does exactly the same (`bestHeaderOpt` + `bestInputBlocksChain()`).
# Those two sources move independently at an ordering-block boundary, so
# for a moment a node can name the NEW ordering block beside the chain it
# still holds for the OLD one — on either side, independently. A pair
# caught mid-transition is not an observation of one tree, so
# `settled_samples` drops it: a sample counts only when its ordering id
# also held at the previous sample, and when Scala's chain is non-empty
# (an empty chain makes no claim about history to contradict).


def percentile(values, pct):
    """The `pct`-th percentile by nearest-rank. `None` for no values."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100 * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


def qualifying_samples(samples):
    """The samples an assertion may draw a conclusion from, plus why the
    rest were excluded.

    The ONLY exclusion is the one the comparison cannot survive: the two
    nodes naming DIFFERENT ordering blocks, where the two input chains
    are not chains of the same thing. Round 3 also dropped samples whose
    ordering id differed from the previous sample's, and samples with an
    empty Scala chain; both are gone, because "every Rust tip" and "every
    same-ordering-block sample" cannot be weakened by the harness. What
    survives is counted and reported per reason.
    """
    kept, excluded = [], {'different_ordering_block': 0}
    for i, s in enumerate(samples):
        if s.get('ordering') is None:
            excluded['different_ordering_block'] += 1
            continue
        kept.append((i, s))
    return kept, excluded


def _coverage_violations(kept, lags, what):
    """Shared required-coverage gate for assertions 2 and 3."""
    out = []
    if len(kept) < MIN_QUALIFYING_SAMPLES:
        out.append(f'only {len(kept)} qualifying samples for {what}, '
                   f'need {MIN_QUALIFYING_SAMPLES}')
    if lags is not None and not lags:
        out.append('lag was never measurable: no sample placed a Rust tip in '
                   "Scala's chain for the same ordering block")
    return out


def evaluate_tip_consistency(samples):
    """Assertion 2. Every Rust tip must be a block Scala had on its best
    chain for the same ordering block, the lag must stay inside the
    bounds, and there must be enough qualifying samples to say so."""
    scala_seen = {}          # ordering -> set of every id Scala ever listed
    scala_later = {}         # ordering -> [ (index, ids) ], for "at or later"
    for i, s in enumerate(samples):
        if not s.get('ordering'):
            continue
        ids = set(s.get('scala_chain') or [])
        scala_seen.setdefault(s['ordering'], set()).update(ids)
        scala_later.setdefault(s['ordering'], []).append((i, ids))

    kept, excluded = qualifying_samples(samples)
    lags, unconfirmed, earlier_only, exact, compared = [], [], [], 0, 0
    for i, s in kept:
        ordering, rust_tip = s['ordering'], s.get('rust_tip')
        if not rust_tip:
            # Rust has no tip yet; nothing to confirm, and it cannot be
            # wrong. Counted as a qualifying sample all the same.
            continue
        compared += 1
        if rust_tip == s.get('scala_tip'):
            exact += 1
        confirmed = any(rust_tip in ids
                        for j, ids in scala_later.get(ordering, ())
                        if j >= i)
        if not confirmed:
            # Scala listed it, but only BEFORE this sample. Recorded in
            # its own bucket rather than waved through: it is how the
            # ordering-block boundary shows up, and the count is the
            # measure of that boundary, not an excuse for it.
            if rust_tip in scala_seen.get(ordering, ()):
                earlier_only.append({'sample': i, 'ordering': ordering,
                                     'rust_tip': rust_tip})
            else:
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
    violations = _coverage_violations(kept, lags, 'tip consistency')
    if p95 is not None and p95 > LAG_P95_MAX:
        violations.append(f'lag p95 {p95} > {LAG_P95_MAX}')
    if mx is not None and mx > LAG_MAX:
        violations.append(f'lag max {mx} > {LAG_MAX}')
    if unconfirmed:
        violations.append(
            f'{len(unconfirmed)} Rust tips were never on Scala\'s best chain')
    if earlier_only:
        violations.append(
            f'{len(earlier_only)} Rust tips were on a chain Scala had already '
            'moved past')
    return {
        'qualifying_samples': len(kept),
        'excluded_samples': excluded,
        'compared_samples': compared,
        'lag_samples': len(lags),
        'lag_p95': p95,
        'lag_max': mx,
        'lag_mean': round(sum(lags) / len(lags), 2) if lags else None,
        'lag_bounds': {'p95_max': LAG_P95_MAX, 'max': LAG_MAX},
        'min_qualifying_samples': MIN_QUALIFYING_SAMPLES,
        'exact_tip_matches': exact,
        'unconfirmed_count': len(unconfirmed),
        'unconfirmed_rust_tips_sample': unconfirmed[:10],
        'confirmed_only_earlier_count': len(earlier_only),
        'confirmed_only_earlier_sample': earlier_only[:10],
        'violations': violations,
    }


def evaluate_chain_consistency(samples):
    """Assertion 3. At every same-ordering-block sample Rust's chain must
    be a prefix of Scala's read oldest-first — Scala's chain with the
    newest k entries removed. Rust trailing is fine; a different HISTORY
    is not. Counts are TOTALS; the recorded list is a sample of them."""
    kept, excluded = qualifying_samples(samples)
    compared, violation_count, violations, depths = 0, 0, [], []
    for i, s in kept:
        scala_chain = s.get('scala_chain') or []
        rust_chain = s.get('rust_chain') or []
        if not rust_chain:
            # Rust has no chain yet: nothing to contradict.
            continue
        compared += 1
        # Oldest-first, so "prefix" is the natural reading.
        scala_old = list(reversed(scala_chain))
        rust_old = list(reversed(rust_chain))
        if len(rust_old) <= len(scala_old) and scala_old[:len(rust_old)] == rust_old:
            depths.append(len(scala_old) - len(rust_old))
            continue
        violation_count += 1
        if len(violations) < 10:
            violations.append({'sample': i, 'ordering': s['ordering'],
                               'scala_chain': scala_chain,
                               'rust_chain': rust_chain})
    result = {
        'qualifying_samples': len(kept),
        'excluded_samples': excluded,
        'compared_samples': compared,
        'min_qualifying_samples': MIN_QUALIFYING_SAMPLES,
        'prefix_violation_count': violation_count,
        'prefix_violations_sample': violations,
        'max_truncation_depth': max(depths) if depths else None,
        'violations': _coverage_violations(kept, None, 'chain consistency'),
    }
    if compared == 0 and kept:
        result['violations'].append(
            'Rust never reported a chain to compare in any qualifying sample')
    if violation_count:
        result['violations'].append(
            f"Rust's chain was not a prefix of Scala's at {violation_count} samples")
    return result


def _self_test():
    """Red-first coverage for the evaluators. They decide the gate, so
    they have to fail where the definitions say they must — and, after
    round 4, they have to fail when there is nothing to conclude from."""
    ordering = 'O'

    def sample(scala, rust, ordering_id=ordering):
        return {'ordering': ordering_id, 'scala_chain': scala, 'rust_chain': rust,
                'scala_tip': scala[0] if scala else None,
                'rust_tip': rust[0] if rust else None}

    def series(scala, rust, n=MIN_QUALIFYING_SAMPLES):
        return [sample(scala, rust) for _ in range(n)]

    # ----- required coverage (round 4) -----

    # An EMPTY series must FAIL both assertions. Before round 4 it passed
    # both: no samples, so no violations, so nothing to report.
    for evaluate in (evaluate_tip_consistency, evaluate_chain_consistency):
        out = evaluate([])
        assert out['violations'], f'empty series must fail: {out}'
        assert any('qualifying samples' in v for v in out['violations']), out

    # Just under the threshold fails; at the threshold passes.
    short = series(['c', 'b', 'a'], ['b', 'a'], MIN_QUALIFYING_SAMPLES - 1)
    assert any('qualifying samples' in v
               for v in evaluate_tip_consistency(short)['violations'])
    assert any('qualifying samples' in v
               for v in evaluate_chain_consistency(short)['violations'])
    enough = series(['c', 'b', 'a'], ['b', 'a'])
    assert evaluate_tip_consistency(enough)['violations'] == []
    assert evaluate_chain_consistency(enough)['violations'] == []

    # Lag that is never measurable fails even with plenty of samples:
    # every Rust tip is confirmed by a LATER Scala chain, but no sample
    # ever lists it beside a chain that contains it, so there is no index
    # to read a lag off.
    never_measurable = (series(['c', 'b'], ['z'], MIN_QUALIFYING_SAMPLES)
                        + [sample(['z', 'c', 'b'], [])])
    out = evaluate_tip_consistency(never_measurable)
    assert out['lag_samples'] == 0, out
    assert out['unconfirmed_count'] == 0, out
    assert any('never measurable' in v for v in out['violations']), out

    # Rust reporting no chain at all in every qualifying sample is not a
    # pass: there was nothing to compare.
    no_rust_chain = series(['c', 'b', 'a'], [])
    out = evaluate_chain_consistency(no_rust_chain)
    assert out['compared_samples'] == 0, out
    assert any('never reported a chain' in v for v in out['violations']), out

    # ----- the FIRST sample counts (round 4) -----

    # A rogue tip in sample 0 used to be excluded by the settled-sample
    # rule. It must count.
    rogue_first = ([sample(['c', 'b', 'a'], ['X', 'b', 'a'])]
                   + series(['c', 'b', 'a'], ['b', 'a']))
    out = evaluate_tip_consistency(rogue_first)
    assert out['unconfirmed_count'] == 1, out
    assert any('never on Scala' in v for v in out['violations']), out
    forked_first = ([sample(['c', 'b', 'a'], ['c', 'x', 'a'])]
                    + series(['c', 'b', 'a'], ['b', 'a']))
    out = evaluate_chain_consistency(forked_first)
    assert out['prefix_violation_count'] == 1, out

    # An empty Scala chain beside a non-empty Rust one is no longer
    # excluded either: it is counted as the violation it is.
    boundary = ([sample([], ['b', 'a'])]
                + series(['c', 'b', 'a'], ['b', 'a']))
    assert evaluate_chain_consistency(boundary)['prefix_violation_count'] == 1

    # A Rust tip Scala listed only EARLIER is its own bucket and its own
    # violation — the ordering-block boundary is measured, not excused.
    moved_past = (series(['b', 'a'], ['b', 'a'])
                  + [sample(['d', 'c'], ['b', 'a'])])
    out = evaluate_tip_consistency(moved_past)
    assert out['confirmed_only_earlier_count'] == 1, out
    assert out['unconfirmed_count'] == 0, out
    assert any('already moved past' in v for v in out['violations']), out

    # ----- totals, not capped lists (round 4) -----

    many = series(['c', 'b', 'a'], ['c', 'x', 'a'])
    out = evaluate_chain_consistency(many)
    assert out['prefix_violation_count'] == MIN_QUALIFYING_SAMPLES, out
    assert len(out['prefix_violations_sample']) == 10, out
    assert any(str(MIN_QUALIFYING_SAMPLES) in v for v in out['violations']), out

    # ----- the definitions themselves -----

    # A follower trailing by 2 of a 5-long chain: consistent, lag 2, and
    # zero exact matches — the case the pre-round-3 gate failed.
    trailing = series(['e', 'd', 'c', 'b', 'a'], ['c', 'b', 'a'])
    tip = evaluate_tip_consistency(trailing)
    assert tip['violations'] == [], tip
    assert tip['lag_p95'] == 2 and tip['lag_max'] == 2, tip
    assert tip['exact_tip_matches'] == 0, tip
    assert evaluate_chain_consistency(trailing)['prefix_violation_count'] == 0

    # In lockstep: lag 0, and every sample an exact match.
    lockstep = series(['c', 'b', 'a'], ['c', 'b', 'a'])
    tip = evaluate_tip_consistency(lockstep)
    assert tip['lag_max'] == 0, tip
    assert tip['exact_tip_matches'] == MIN_QUALIFYING_SAMPLES, tip

    # Confirmed by a LATER sample: Rust saw it before Scala's REST did.
    ahead = ([sample(['b', 'a'], ['c', 'b', 'a'])]
             + series(['c', 'b', 'a'], ['c', 'b', 'a']))
    assert evaluate_tip_consistency(ahead)['unconfirmed_count'] == 0

    # Lag past the bounds fails, even though every tip is consistent.
    deep = ['t%02d' % n for n in range(30, -1, -1)]
    tip = evaluate_tip_consistency(series(deep, deep[20:]))
    assert tip['lag_p95'] == 20 and tip['lag_max'] == 20, tip
    assert any('p95' in v for v in tip['violations']), tip
    assert any('max' in v for v in tip['violations']), tip

    # Rust longer than Scala cannot be a prefix.
    assert evaluate_chain_consistency(
        series(['b', 'a'], ['c', 'b', 'a']))['prefix_violation_count'] == \
        MIN_QUALIFYING_SAMPLES

    # Samples where the two nodes name DIFFERENT ordering blocks are the
    # one exclusion, and it is counted.
    unrelated = [{'ordering': None, 'scala_chain': ['a'], 'rust_chain': ['z'],
                  'scala_tip': 'a', 'rust_tip': 'z'}] * 10
    out = evaluate_tip_consistency(unrelated)
    assert out['qualifying_samples'] == 0, out
    assert out['excluded_samples']['different_ordering_block'] == 10, out
    assert evaluate_chain_consistency(unrelated)['compared_samples'] == 0

    # ----- assertion 6's D1/F6 attribution (round 4) -----

    attributed = attribute_scala_residue(
        ['d1tx', 'f6tx'], applied_input_block_txids={'f6tx'},
        ordering_block_txids=set(), d1_refusals={'d1tx'})
    assert attributed['d1'] == ['d1tx'], attributed
    assert attributed['f6'] == ['f6tx'], attributed
    assert attributed['unexplained'] == [], attributed
    # Residue with no evidence for either rule is a divergence, never a
    # shrug.
    attributed = attribute_scala_residue(
        ['mystery'], applied_input_block_txids=set(),
        ordering_block_txids=set(), d1_refusals=set())
    assert attributed['unexplained'] == ['mystery'], attributed
    # A transaction the ordering block DID include is not F6.
    attributed = attribute_scala_residue(
        ['included'], applied_input_block_txids={'included'},
        ordering_block_txids={'included'}, d1_refusals=set())
    assert attributed['unexplained'] == ['included'], attributed

    print('self-test OK: evaluators behave as the round-4 definitions require')


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


def observe_for_ordering_blocks(run, blocks, what):
    """Let the sampler thread run for `blocks` ordering blocks.

    The loop itself takes NO samples: the dedicated sampler is already
    running, and the point of round 4 is that sampling never depends on
    which assertion happens to be driving.
    """
    try:
        start = scala_height(run)
    except Unavailable as error:
        run.fail(what, f'could not read the starting height: {error}')
        return None
    while time.monotonic() < run.deadline:
        run.note_input_block_txids(run.latest_reading())
        try:
            if scala_height(run) > start + blocks:
                break
        except Unavailable:
            pass
        time.sleep(0.5)
    return start


def finalize_agreement(run, evidence):
    """Evaluate assertions 2 and 3 over EVERY retained sample.

    Called at the end of the run, not when the sampling window closes:
    samples taken during funding, the workload and the restart are
    observations of the same two nodes and used to be discarded.
    """
    tip = evaluate_tip_consistency(run.series)
    chain = evaluate_chain_consistency(run.series)
    lags = [round(v, 3) for v in run.propagation_lags]
    evidence['2_best_input_block'] = {
        'definition': ("every Rust bestInputBlock must be a block Scala had on its "
                       "best chain for the same ordering block; lag p95 <= "
                       f"{LAG_P95_MAX} and max <= {LAG_MAX} input blocks; at least "
                       f"{MIN_QUALIFYING_SAMPLES} qualifying samples and a measurable "
                       "lag"),
        'evaluated_over': 'every sample taken in the run',
        'total_samples': len(run.series),
        'unavailable_samples': run.unavailable_samples,
        'series_file': str(run.series_path.relative_to(ROOT)),
        'max_propagation_lag_seconds': max(lags) if lags else None,
        **tip,
    }
    evidence['3_best_input_chain'] = {
        'definition': ("at every same-ordering-block sample Rust's bestInputChain must "
                       "be a prefix of Scala's read oldest-first (tip-side truncated); "
                       f"at least {MIN_QUALIFYING_SAMPLES} qualifying samples"),
        'evaluated_over': 'every sample taken in the run',
        'artifacts_written_at_mismatch_time': run.live_artifact_paths,
        **chain,
    }
    if tip['violations']:
        run.fail('2_best_input_block', '; '.join(tip['violations']),
                 {'lag_p95': tip['lag_p95'], 'lag_max': tip['lag_max'],
                  'qualifying_samples': tip['qualifying_samples'],
                  'unconfirmed_count': tip['unconfirmed_count'],
                  'unconfirmed': tip['unconfirmed_rust_tips_sample'],
                  'confirmed_only_earlier_count': tip['confirmed_only_earlier_count']})
    if chain['violations']:
        run.fail('3_best_input_chain', '; '.join(chain['violations']),
                 {'prefix_violation_count': chain['prefix_violation_count'],
                  'qualifying_samples': chain['qualifying_samples'],
                  'violations': chain['prefix_violations_sample']})
    for key in ('2_best_input_block', '3_best_input_chain'):
        evidence[key]['result'] = 'FAIL' if any(
            f['assertion'] == key for f in run.failures) else 'PASS'


def scala_height(run):
    """Scala's full height. Raises `Unavailable` rather than returning 0:
    a failed request is not a chain at genesis, and treating it as one
    silently moved every height-relative deadline."""
    info = api_retry('scala', '/info', min(run.deadline, time.monotonic() + 60),
                     what='scala /info for the current height')
    height = info.get('fullHeight')
    if height is None:
        # A node that has applied no block reports null, which IS height
        # zero — distinct from a request that failed.
        return 0
    return height


def wait_for_height(run, target, what):
    """Block until Scala reaches `target`. Takes no samples of its own —
    the sampler thread never stops, which is the point."""
    while time.monotonic() < run.deadline:
        run.note_input_block_txids(run.latest_reading())
        try:
            if scala_height(run) >= target:
                return
        except Unavailable:
            pass
        time.sleep(0.5)
    raise Unavailable(f'{what}: Scala did not reach ordering block {target} in budget')


def attribute_scala_residue(only_in_scala, applied_input_block_txids,
                            ordering_block_txids, d1_refusals):
    """Explain each transaction left in Scala's pool but not Rust's.

    Only two documented reasons are allowed, and each has to be shown,
    not assumed:

    * **D1** — the node LOGGED a refused conflict-checked restore for it.
    * **F6** — it was in an input block Rust applied, and the ordering
      block did NOT include it, so Rust dropped it and never restored it.

    Anything else is a divergence finding. The old code excused every
    Scala-only transaction categorically, which made the assertion
    unfalsifiable in that direction.
    """
    d1, f6, unexplained = [], [], []
    for txid in sorted(only_in_scala):
        if txid in d1_refusals:
            d1.append(txid)
        elif txid in applied_input_block_txids and txid not in ordering_block_txids:
            f6.append(txid)
        else:
            unexplained.append(txid)
    return {'d1': d1, 'f6': f6, 'unexplained': unexplained}


def d1_refusals_from_log():
    """Transaction ids the node logged a refused mempool restore for."""
    ids = set()
    for line in rust_log_lines('restore', limit=400):
        if 'refus' not in line.lower() and 'conflict' not in line.lower():
            continue
        ids.update(re.findall(r'[0-9a-f]{64}', line))
    return ids


def assertion_6_mempool(run, evidence, count):
    """Funded workload: `count` accepted submissions, each located inside
    a Rust input block, each gone from Rust's pool at the first sample
    AFTER that input block and BEFORE the next ordering block, then pool
    agreement with every Scala-only residue attributed to D1 or F6."""
    result = {'requested': count, 'submitted': [], 'submit_failures': []}
    evidence['6_mempool'] = result
    # A miner reward matures at ordering block 11, and the recipe's
    # target is ~55 s per ordering block, so the wait is minutes.
    deadline = min(run.deadline, time.monotonic() + 900)

    balance = 0
    while time.monotonic() < deadline:
        try:
            balance = (api('scala', '/wallet/balances') or {}).get('balance') or 0
        except Unavailable:
            balance = 0
        if balance > 0:
            break
        time.sleep(1)
    result['balance_nano'] = balance
    if not balance:
        run.fail('6_mempool', 'no spendable coin on the Scala wallet within budget')
        result['result'] = 'FAIL'
        return
    try:
        address = (api('scala', '/wallet/addresses') or [None])[0]
        start_height = scala_height(run)
    except Unavailable as error:
        run.fail('6_mempool', f'wallet setup unavailable: {error}')
        result['result'] = 'FAIL'
        return
    result['address'] = address
    result['submitted_at_height'] = start_height

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

    # Locate each one inside a Rust input block, and check removal from
    # Rust's pool at the first observation AFTER it was seen in an input
    # block and BEFORE the ordering block that would confirm it anyway —
    # otherwise ordinary block confirmation conceals a missing
    # input-block eviction.
    in_input_block = {}
    removed_before_ordering = {}
    still_pooled_after_input_block = {}
    ever_in_rust_pool = set()
    track_deadline = min(run.deadline, time.monotonic() + 300)
    while time.monotonic() < track_deadline:
        run.note_input_block_txids(run.latest_reading())
        for bid, ids in run.input_block_txids.items():
            for txid in set(ids) & submitted:
                in_input_block.setdefault(txid, bid)
        try:
            pool = {t['id'] for t in api('rust', '/transactions/unconfirmed')}
        except Unavailable:
            pool = None
        if pool is not None:
            ever_in_rust_pool |= pool
            for txid in in_input_block:
                if txid in removed_before_ordering:
                    continue
                if txid in pool:
                    still_pooled_after_input_block[txid] = in_input_block[txid]
                else:
                    removed_before_ordering[txid] = in_input_block[txid]
                    still_pooled_after_input_block.pop(txid, None)
        try:
            if scala_height(run) > start_height:
                # The next ordering block has landed; anything not
                # resolved by now cannot be attributed to the input block.
                break
        except Unavailable:
            pass
        if submitted and set(removed_before_ordering) >= submitted:
            break
        time.sleep(0.3)
    result['in_rust_input_block'] = in_input_block
    result['located_count'] = len(in_input_block)
    result['min_located'] = MEMPOOL_MIN_LOCATED
    result['removed_before_next_ordering_block'] = removed_before_ordering
    result['still_pooled_after_its_input_block'] = still_pooled_after_input_block
    result['rust_pool_ever_held'] = sorted(ever_in_rust_pool & submitted)

    if len(in_input_block) < MEMPOOL_MIN_LOCATED:
        run.fail('6_mempool',
                 f'only {len(in_input_block)} of {count} submissions were located '
                 f'inside a Rust input block, need {MEMPOOL_MIN_LOCATED}',
                 {'located': sorted(in_input_block),
                  'input_blocks_seen': len(run.input_block_txids),
                  'rust_pool_ever_held': result['rust_pool_ever_held'],
                  'rust_log': rust_log_lines('input_blocks')})
    missing_removal = sorted(set(in_input_block) - set(removed_before_ordering))
    result['never_removed_before_ordering'] = missing_removal
    if missing_removal:
        run.fail('6_mempool',
                 f'{len(missing_removal)} transactions were still unconfirmed on the '
                 'Rust node after the input block that carried them applied, up to '
                 'the next ordering block',
                 {'txids': missing_removal,
                  'input_blocks': {t: in_input_block[t] for t in missing_removal}})

    # Pool agreement after the next ordering block, with every Scala-only
    # residue attributed.
    try:
        wait_for_height(run, start_height + 1, 'assertion 6 ordering block')
        time.sleep(3)
        scala_pool = {t['id'] for t in api_retry(
            'scala', '/transactions/unconfirmed', run.deadline, what='scala pool')}
        rust_pool = {t['id'] for t in api_retry(
            'rust', '/transactions/unconfirmed', run.deadline, what='rust pool')}
        ordering_txids = set()
        for hid in api_retry('scala', f'/blocks/at/{start_height + 1}', run.deadline,
                             what='ordering block at the confirmation height') or []:
            block = api_retry('scala', f'/blocks/{hid}', run.deadline,
                              what='ordering block body')
            ordering_txids |= {
                t['id'] for t in block['blockTransactions']['transactions']}
    except Unavailable as error:
        run.fail('6_mempool', str(error))
        result['result'] = 'FAIL'
        return

    result['scala_unconfirmed'] = sorted(scala_pool)
    result['rust_unconfirmed'] = sorted(rust_pool)
    result['symmetric_difference'] = sorted(scala_pool ^ rust_pool)
    result['ordering_block_txids'] = sorted(ordering_txids)
    applied = {t for ids in run.input_block_txids.values() for t in ids}
    attribution = attribute_scala_residue(
        scala_pool - rust_pool, applied, ordering_txids, d1_refusals_from_log())
    attribution['only_in_rust'] = sorted(rust_pool - scala_pool)
    result['d1_f6_accounting'] = attribution
    if attribution['unexplained']:
        run.fail('6_mempool',
                 f"{len(attribution['unexplained'])} transactions are unconfirmed on "
                 'Scala but not on Rust with neither a D1 refusal nor an F6 omission '
                 'to explain them',
                 {'unexplained': attribution['unexplained'],
                  'd1': attribution['d1'], 'f6': attribution['f6']})
    if attribution['only_in_rust']:
        run.fail('6_mempool',
                 'Rust holds unconfirmed transactions Scala does not; D1/F6 cannot '
                 'explain residue in that direction',
                 {'only_in_rust': attribution['only_in_rust']})
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

    try:
        restart_height = scala_height(run)
    except Unavailable as error:
        run.fail('4_reconstruction', f'height unavailable before the restart: {error}')
        result['result'] = 'FAIL'
        return
    result['restarted_at_scala_height'] = restart_height
    # The node's own drop counters reset with the process. Fold the live
    # totals into the carried ones BEFORE the kill rather than inferring
    # the reset later from a decreasing counter — a restarted counter
    # that races past its previous value would otherwise lose the whole
    # first lifetime.
    run.carry_counters_forward()
    result['counters_carried_at_restart'] = run.totals()
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
    attempted = run.samples + run.unavailable_samples
    unavailable_fraction = (run.unavailable_samples / attempted) if attempted else 1.0
    evidence['5_follow'] = {
        'max_height_gap': run.max_height_gap,
        'height_window': HEIGHT_WINDOW,
        'start_grace_seconds': START_GRACE_SECONDS,
        'violations_sample': run.height_violations[:20],
        'violation_count': len(run.height_violations),
        'accumulated_drops': totals,
        'counters_carried_across_restart': True,
        'peer_states_seen': sorted(run.peer_states),
        'peer_absent_within_start_grace': run.peer_absent_in_grace,
        'penalty_observations': run.penalty_observations,
        'samples': run.samples,
        'attempted_samples': attempted,
        'unavailable_samples': run.unavailable_samples,
        'unavailable_fraction': round(unavailable_fraction, 4),
        'max_unavailable_fraction': MAX_UNAVAILABLE_FRACTION,
        'unavailable_reasons_sample': run.unavailable_reasons,
        'sampling': 'dedicated thread for the whole run, including submission, '
                    'blocking waits and the restart',
    }
    if run.samples == 0:
        run.fail('5_follow', 'no usable sample was taken')
    # A run that could not watch the nodes has not watched them, however
    # few violations it happened to see.
    if unavailable_fraction > MAX_UNAVAILABLE_FRACTION:
        run.fail('5_follow',
                 f'{run.unavailable_samples} of {attempted} monitoring sweeps could '
                 f'not be taken ({unavailable_fraction:.1%} > '
                 f'{MAX_UNAVAILABLE_FRACTION:.0%})',
                 {'reasons': run.unavailable_reasons})
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
                 {'violation_count': len(run.height_violations),
                  'violations': run.height_violations[:20]})
    evidence['5_follow']['result'] = 'FAIL' if any(
        f['assertion'] == '5_follow' for f in run.failures) else 'PASS'


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_findings(run, evidence):
    """Artifacts for failures that did not already write one at mismatch
    time — the coverage and bound failures, which are properties of the
    whole run rather than of one observation."""
    written = []
    for finding in run.findings:
        if finding.get('artifact'):
            written.append(finding['artifact'])
            continue
        written.append(write_mismatch_artifact(
            finding['assertion'], finding['message'], finding['evidence'],
            context={
                'rust_events_tail': evidence.get('assertions', {})
                .get('4_reconstruction', {}).get('ordering_events', [])[-20:],
                'scala': evidence.get('scala'),
                'rust': evidence.get('rust'),
            }))
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
    run.start_sampling()
    try:
        assertion_1_peering(run, evidence['assertions'])
        save()
        # Observe for a few ordering blocks before funding. The verdict
        # itself is computed at the END of the run, over every sample the
        # sampler thread took, including these.
        observe_for_ordering_blocks(run, AGREEMENT_ORDERING_BLOCKS,
                                    '2_best_input_block')
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
        # Last, so they see every counter and every sample the whole run
        # produced.
        run.stop_sampling()
        finalize_agreement(run, evidence['assertions'])
        assertion_5_follow(run, evidence['assertions'])
    except BaseException as error:  # noqa: BLE001 - recorded, then re-raised
        run.fail('harness', f'{type(error).__name__}: {error}')
        evidence['harness_error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        run.stop_sampling()
        # The full series lives in `.work/agreement-series.jsonl`; the
        # evidence carries a readable head plus the total, and the
        # verdict above was computed over ALL of it.
        evidence['agreement_series_head'] = run.series[:200]
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
