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
import queue
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
# Artifacts are written to the run's own `.work/` (gitignored). A run
# uncapped in its mismatch recording writes hundreds of near-identical
# files, and committing those is noise, not evidence: only findings a
# human PROMOTES land under `test-vectors/weak-blocks/findings/`.
FINDINGS = WORK / 'findings'

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

# How long `pause_sampling` will wait for a sweep already underway to
# finish. Generous: a sweep is a handful of REST calls, and a timeout is
# recorded (`sweep_join_timeouts`) rather than silently tolerated.
SWEEP_JOIN_SECONDS = 15.0

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

# Assertion 6, round 2: the STRICT path has to be exercised, but how
# many payments take it is the miner's choice, not the follower's. The
# `cachedCandidate` race (F11) rejects most of the miner's own input
# solutions, so a payment can be confirmed by an ordering block having
# never been sealed into one. One located payment proves the follower
# evicts on an input block; the rest are routed and counted.
MEMPOOL_MIN_LOCATED = 1

# How long assertion 6 follows its payments before calling them
# unresolved. Keyed to input-block production rather than to the next
# ordering block: an ordering-height window closes on the miner's
# schedule, and a follower cannot be failed for that.
MEMPOOL_ROUTE_SECONDS = 420.0

# How many input-block id lookups one sweep will make. The lookups are
# inside the sweep's tip bracket, so they cost the sampler latency; a
# cold chain can list dozens of blocks at once and a sweep that fetched
# them all would stall the monitoring it exists to do. The rest are
# picked up by the sweeps that follow, a third of a second apart.
INPUT_BLOCK_ID_FETCHES_PER_SWEEP = 8

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


# The node logs the raw announcement frame on exactly one line, in
# exactly this shape (`input_blocks::dispatch::log_announcement_payload`,
# TRACE on target `ergo_node::node::input_blocks::announcements`). The
# extractor below matches ONLY this line: scraping any long hex run off
# any line mentioning the id used to turn a PARENT id into "announcement
# evidence". `ergo-node`'s
# `the_announcement_payload_line_has_the_shape_the_harness_parses` pins
# the other end of this contract.
ANNOUNCEMENT_LINE = re.compile(
    r'input_blocks: raw announcement payload'
    r'\s+block=(?P<block>[0-9a-f]{64})'
    r'\s+payload=(?P<payload>[0-9a-f]*)')


def announcement_hex_for(ids, window):
    """The raw announcement bytes for `ids`, from the debug-log `window`.

    Only the node's dedicated payload line counts. Three outcomes, all
    explicit, so an artifact never implies it looked and found emptiness
    when it simply had nothing to look at:

    * the payload hex, when the node logged that line for the id;
    * `no_payload_bytes_logged_for_this_id` when the window mentions the
      id but carries no payload line for it (TRACE not enabled, or the
      announcement arrived outside the window);
    * `not_in_log_window` when the window does not mention the id at all.
    """
    out = {}
    payloads = {}
    for line in window:
        match = ANNOUNCEMENT_LINE.search(line)
        if match:
            payloads.setdefault(match.group('block'), []).append(
                (match.group('payload'), line))
    for block_id in [i for i in ids if i]:
        found = payloads.get(block_id)
        if found:
            out[block_id] = {'announcement_hex': [p for p, _ in found],
                             'lines': [line for _, line in found][:5]}
            continue
        lines = [line for line in window if block_id in line]
        if not lines:
            out[block_id] = {'announcement_hex': None,
                             'reason': 'not_in_log_window'}
        else:
            out[block_id] = {'announcement_hex': None,
                             'reason': 'no_payload_bytes_logged_for_this_id',
                             'lines': lines[:5]}
    return out


def write_mismatch_artifact(assertion, message, evidence, at=None, context=None,
                            ids=None):
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
    window = (rust_log_window(at) if at
              else rust_log_lines('input_blocks', limit=80))
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
        'rust_debug_log_window': window,
        'announcement_bytes': announcement_hex_for(ids or [], window),
    }
    if context:
        body.update(context)
    path.write_text(json.dumps(body, indent=2) + '\n')
    return str(path.relative_to(ROOT))


def ids_in(value, limit=20):
    """Every distinct 64-hex id an evidence blob mentions, in order.

    A failure artifact is only as useful as the blocks it can fetch
    announcement bytes for, and the callers already put those ids in the
    evidence. Pulling them back out here is what stops each new
    `run.fail` site from having to remember.
    """
    out = []
    seen = set()
    for match in re.finditer(r'\b[0-9a-f]{64}\b', json.dumps(value, default=str)):
        block_id = match.group(0)
        if block_id not in seen:
            seen.add(block_id)
            out.append(block_id)
        if len(out) >= limit:
            break
    return out


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
        # The pause handshake. An `Event` pair could not express it:
        # clearing a "sweep done" flag after asking for the pause can
        # erase the signal of a sweep that has just finished, and a
        # sampler sitting between sweeps never sets it again while
        # paused — so the main thread waited out the whole timeout and
        # then carried on as if the sampler were quiescent. One
        # condition variable guarding two booleans states the thing that
        # actually matters: the sampler is NOT inside a sweep and has
        # acknowledged the pause.
        self._quiet = threading.Condition()
        self._pause_requested = False
        self._in_sweep = False
        self._paused_ack = False
        # Monotonic sweep number, so a consumer can tell two readings
        # apart without relying on object identity — CPython reuses
        # addresses, so `id(reading)` silently deduplicated distinct
        # sweeps.
        self.sweep_seq = 0
        self.series_path = WORK / 'agreement-series.jsonl'
        self._series_file = None
        self.sampler_error = None
        self.last_sample_at = None
        self.sampling_ended_at = None
        # Mismatches the sampler spots are QUEUED, never written from the
        # sampler thread: an artifact costs several blocking REST calls
        # and a log scan, and monitoring must not stop to write evidence.
        self.mismatch_queue = queue.Queue()
        self.failures = []
        self.findings = []
        self.samples = 0
        self.unavailable_samples = 0
        self.unavailable_reasons = []
        self.live_artifacts = 0
        self.live_artifact_paths = []
        self.peer_absent_in_grace = 0
        self.sweep_join_timeouts = 0
        # Sweeps whose ordering tip moved across the pool read; their
        # pool observation is recorded but never credits an eviction.
        self.pool_tip_moved_samples = 0

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

        # Assertion 6. `input_block_txids` is the block's transaction
        # ids; `input_block_seen_under` is the ordering tip of the SWEEP
        # THAT BLOCK WAS OBSERVED IN, which is the tip a removal has to
        # be credited against. Associating every cached block with
        # whatever tip happens to be current lets an entry first seen
        # under one ordering block be credited under a later one, after
        # ordinary confirmation had already removed its transactions.
        self.input_block_txids = {}
        self.input_block_seen_under = {}
        self._fetched_this_sweep = 0

    # ----- the sampler thread -----

    def start_sampling(self, interval=0.3):
        WORK.mkdir(exist_ok=True)
        self._series_file = self.series_path.open('w')
        self._thread = threading.Thread(target=self._sample_loop, args=(interval,),
                                        daemon=True)
        self._thread.start()

    def _sample_loop(self, interval):
        """The sampler. Any exception here is FATAL for the run.

        A thread that dies quietly leaves finalization computing verdicts
        from the samples it managed to take before it died — which is how
        assertion 5 could still report PASS after the sampler was gone.
        The reason is recorded and `check_sampler_health` turns it into a
        failure.
        """
        try:
            while not self._stop.is_set() and time.monotonic() < self.deadline:
                # Acknowledge a pause BEFORE entering a sweep, and hold
                # here until it is lifted. `_paused_ack` is what
                # `pause_sampling` waits for; setting it inside the
                # condition is what makes "the sampler is idle" a fact
                # the main thread can observe rather than infer.
                with self._quiet:
                    while self._pause_requested and not self._stop.is_set():
                        self._paused_ack = True
                        self._quiet.notify_all()
                        self._quiet.wait(0.1)
                    self._paused_ack = False
                    if self._stop.is_set():
                        self._quiet.notify_all()
                        break
                    self._in_sweep = True
                try:
                    reading = self.sweep()
                finally:
                    with self._quiet:
                        self._in_sweep = False
                        self._quiet.notify_all()
                with self._lock:
                    # ONLY a sweep that produced a reading counts as a
                    # heartbeat. Advancing it on a failed sweep let a
                    # final interval in which every REST call failed
                    # still satisfy `check_sampler_health`'s freshness
                    # bound — the run would report a live sampler while
                    # observing nothing.
                    if reading is not None:
                        self.last_sample_at = time.monotonic()
                self._stop.wait(interval)
        except BaseException as error:  # noqa: BLE001 — recorded, then fatal
            with self._lock:
                self.sampler_error = f'{type(error).__name__}: {error}'
        finally:
            # However the loop ends — stop, deadline, or an exception —
            # the sampler is no longer sweeping. Saying so releases a
            # `pause_sampling` that would otherwise wait out its whole
            # timeout for a thread that is already gone.
            with self._quiet:
                self._in_sweep = False
                self._paused_ack = True
                self._quiet.notify_all()

    def check_sampler_health(self, max_silence=10.0):
        """Why the run may NOT trust its own samples.

        Returns a list of reasons: the sampler raised, or it stopped
        producing samples more than `max_silence` seconds before the end
        of sampling. Either way the series is incomplete and every
        verdict drawn from it is unsafe.
        """
        reasons = []
        with self._lock:
            error = self.sampler_error
            last = self.last_sample_at
            ended = self.sampling_ended_at or time.monotonic()
        if error:
            reasons.append(f'sampler_failed: {error}')
        if last is None:
            reasons.append('sampler_failed: the sampler never produced a sample')
        else:
            silence = ended - last
            if silence > max_silence:
                reasons.append(
                    f'sampler_failed: no sample in the last {silence:.1f}s of the run '
                    f'(limit {max_silence:.0f}s)')
        return reasons

    def stop_sampling(self):
        with self._quiet:
            self._pause_requested = False
            self._quiet.notify_all()
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)
            self._thread = None
        with self._lock:
            if self.sampling_ended_at is None:
                self.sampling_ended_at = time.monotonic()
        if self._series_file:
            self._series_file.close()
            self._series_file = None

    def pause_sampling(self):
        """Bring the sampler to a stop between sweeps, and SAY whether
        that succeeded.

        Used around the deliberate restart: the counter snapshot has to
        be the last word from the dying process, and a sampler that
        finishes an old-process observation after the carry-forward
        would add that lifetime's counts a second time.

        Returns `True` only when the sampler has acknowledged the pause
        while not inside a sweep, or is not running at all. On timeout
        it returns `False` and the caller MUST NOT proceed as if
        quiescence were established — nothing here pretends a wait that
        ran out is the same as a sampler that stopped.
        """
        deadline = time.monotonic() + SWEEP_JOIN_SECONDS
        with self._quiet:
            self._pause_requested = True
            self._quiet.notify_all()
            while True:
                alive = self._thread is not None and self._thread.is_alive()
                if not alive or (self._paused_ack and not self._in_sweep):
                    return True
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.sweep_join_timeouts += 1
                    return False
                self._quiet.wait(min(remaining, 0.1))

    def resume_sampling(self):
        with self._quiet:
            self._pause_requested = False
            self._quiet.notify_all()

    def latest_reading(self):
        with self._lock:
            return self._latest

    def snapshot_counters_before_kill(self):
        """Take a FRESH counter reading from the node that is about to
        die, fold it forward, and zero the live column.

        Folding the last CACHED sample forward loses everything the node
        counted between that sample and the kill. The snapshot is its own
        REST call, made on the main thread with the sampler paused.
        """
        try:
            status = api('rust', '/api/v1/status')
        except Unavailable as error:
            # The node is already gone or unreachable; the cached column
            # is the best record of it that exists.
            status = None
            snapshot_error = str(error)
        else:
            snapshot_error = None
        # The Scala node is not restarted and publishes no drop
        # counters, but the restart is a seam in the evidence for BOTH
        # nodes: what the miner had reached when the follower died is
        # what the post-restart catch-up is measured against. Recorded
        # here so a later reading cannot be mistaken for it.
        peer_snapshot = {}
        for node in URLS:
            try:
                info = api(node, '/info') or {}
            except Unavailable as error:
                peer_snapshot[node] = {'error': str(error)}
            else:
                peer_snapshot[node] = {
                    'fullHeight': info.get('fullHeight'),
                    'bestFullHeaderId': info.get('bestFullHeaderId'),
                    'bestInputBlock': info.get('bestInputBlock'),
                }
        with self._lock:
            if status is not None:
                ib = status.get('input_blocks') or {}
                for entry in ib.get('drops', []):
                    value = self.drop_counters.setdefault(
                        entry['reason'], {'current': 0, 'carried': 0})
                    # The snapshot supersedes the cached column: it is
                    # strictly later in the same process's lifetime.
                    value['current'] = max(value['current'], entry['count'])
            for value in self.drop_counters.values():
                value['carried'] += value['current']
                value['current'] = 0
            totals = {k: v['carried'] for k, v in self.drop_counters.items()}
        return {'totals': totals, 'snapshot_error': snapshot_error,
                'both_nodes': peer_snapshot}

    # ----- helpers -----

    def fail(self, assertion, message, evidence=None, at=None, ids=None):
        """Record a failure, and enough to write a focused artifact for it.

        `at` and `ids` are what turn an artifact from "the last 80 log
        lines and no announcement bytes" into a log window around the
        observation with the raw frames for the blocks it names. They
        default to now and to every block id the evidence mentions, so a
        caller cannot forget them.
        """
        at = time.time() if at is None else at
        self.failures.append({'assertion': assertion, 'message': message,
                              'observed_at_unix': at})
        if evidence is not None:
            self.findings.append({'assertion': assertion, 'message': message,
                                  'evidence': evidence, 'at': at,
                                  'ids': ids if ids is not None
                                  else ids_in(evidence)})

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
            # Assertion 6's pool observation belongs to THIS sweep, not
            # to a separate read the assertion makes later against a
            # cached tip. The tip is re-read straight after the pool: if
            # an ordering block landed across the pair, the pool and the
            # tip describe different moments and the observation cannot
            # decide whether an input block or ordinary confirmation
            # removed a transaction. Such a sweep keeps its pool but is
            # marked unusable for crediting.
            pool = {t['id'] for t in api('rust', '/transactions/unconfirmed')}
            # Assertion 6's transaction ids belong to the SAME bracket as
            # the pool read. Fetching them afterwards, on the main
            # thread, meant the ids and the pool could describe different
            # moments: a body can become available between the sampled
            # pool and the lookup, so a transaction could be credited
            # against a pool snapshot taken before its block was
            # servable. Bracketing them together is what makes "this
            # block held this transaction while the pool looked like
            # that" a single observation.
            staged_ids, staged_tip = self._collect_input_block_txids(reading)
            tip_after = (api('rust', '/info') or {}).get('bestFullHeaderId')
        except Unavailable as error:
            with self._lock:
                self.unavailable_samples += 1
                if len(self.unavailable_reasons) < 20:
                    self.unavailable_reasons.append(str(error))
            return None
        tip_before = reading['rust']['info'].get('bestFullHeaderId')
        reading['rust']['pool'] = pool
        # The ids gathered in this bracket, so a consumer can tell what
        # THIS sweep saw from what earlier sweeps had cached.
        reading['rust']['input_block_txids_fetched'] = self._fetched_this_sweep
        reading['rust']['pool_tip'] = tip_before
        reading['rust']['pool_tip_stable'] = (
            tip_before is not None and tip_before == tip_after)
        with self._lock:
            self.samples += 1
            self.sweep_seq += 1
            reading['seq'] = self.sweep_seq
            # Commit and publish as ONE step, under the lock, now that
            # the bracket has been decided.
            self._publish_sweep_ids(reading, staged_ids, staged_tip)
            if not reading['rust']['pool_tip_stable']:
                self.pool_tip_moved_samples += 1
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
        self._maybe_queue_live_mismatch(entry, reading)

    def _maybe_queue_live_mismatch(self, entry, reading):
        """QUEUE a prefix mismatch for the main thread to write up.

        Only the chain-prefix check is decidable from a single sample;
        the tip and lag verdicts need the whole series and are filed at
        finalization. Nothing is written here: an artifact costs several
        blocking REST calls and a scan of the debug log, and the sampler
        stopping to do that is exactly the monitoring gap round 4 set out
        to remove. Uncapped — the queue is bounded by the run's own
        length, and a mismatch that is not recorded did not happen as far
        as the evidence is concerned.
        """
        if entry['ordering'] is None:
            return
        scala_old = list(reversed(entry['scala_chain']))
        rust_old = list(reversed(entry['rust_chain']))
        if not rust_old:
            return
        if len(rust_old) <= len(scala_old) and scala_old[:len(rust_old)] == rust_old:
            return
        self.mismatch_queue.put({
            'assertion': '3_best_input_chain',
            'message': "Rust's bestInputChain is not a prefix of Scala's",
            'at': entry['at'],
            'evidence': {'sample': entry, 'ordering': entry['ordering']},
            'ids': [entry['ordering']] + entry['rust_chain'][:2]
                   + entry['scala_chain'][:2],
            'context': {'rust_best_input_block': reading['rust']['best'],
                        'scala_best_input_block': reading['scala']['best'],
                        'rust_info': reading['rust']['info'],
                        'scala_info': reading['scala']['info']},
        })

    def idle(self, seconds):
        """Wait on the MAIN thread, writing queued artifacts while it
        waits.

        Every blocking wait in the harness goes through this, so the
        mismatch queue is drained roughly every sampler interval for the
        whole run instead of once at the end — an artifact written at
        the end carries the final `/info` bodies and whatever log had
        scrolled past, neither of which describes the mismatch it was
        filed for.
        """
        self.drain_mismatch_queue()
        time.sleep(seconds)

    def drain_mismatch_queue(self, budget=None):
        """Write every queued mismatch artifact. Main thread only."""
        written = 0
        while True:
            try:
                item = self.mismatch_queue.get_nowait()
            except queue.Empty:
                return written
            try:
                self.live_artifact_paths.append(write_mismatch_artifact(
                    item['assertion'], item['message'], item['evidence'],
                    at=item['at'], ids=item['ids'], context=item['context']))
                self.live_artifacts += 1
                written += 1
            except OSError:
                # Evidence collection must never take the run down.
                pass
            if budget is not None and written >= budget:
                return written

    def _collect_input_block_txids(self, reading):
        """Read this sweep's input-block transaction ids, INSIDE the
        sweep's own tip bracket. Called from [`Self.sweep`] only.

        The tip each block is attributed to is recorded here too: it is
        the tip this sweep read, which the bracket then either confirms
        held still or marks unusable. Attributing a block to whatever tip
        happens to be current when a later lookup runs is the mistake
        this replaces.

        Bounded per sweep. A cold chain can list dozens of blocks at
        once and a sweep that stopped to fetch all of them would stall
        the monitoring it exists to do; the rest are picked up by the
        sweeps that follow, a third of a second apart.
        """
        self._fetched_this_sweep = 0
        staged = {}
        tip = reading['rust']['info'].get('bestFullHeaderId')
        for bid in reading['rust']['chain'].get('bestInputBlocks') or []:
            if self._fetched_this_sweep >= INPUT_BLOCK_ID_FETCHES_PER_SWEEP:
                break
            # Only a NON-EMPTY answer is cached. An input block shows up
            # in the chain before its bodies are attached, so caching the
            # first empty answer would permanently hide its transactions.
            if self.input_block_txids.get(bid):
                continue
            ids = api('rust', f'/blocks/{bid}/inputBlockTransactionIds') or []
            self._fetched_this_sweep += 1
            staged[bid] = ids
        return staged, tip

    def _publish_sweep_ids(self, reading, staged, tip):
        """Commit a sweep's staged ids, but ONLY if its bracket held.

        Writing them as they were fetched published observations the
        sweep had not yet validated: the main thread iterated the live
        caches, so ids from a newer — or an unstable — sweep could be
        credited against an older pool snapshot, and a dict growing
        under iteration could raise outright. Staging and committing
        once makes a sweep all-or-nothing, and the consumer reads the
        immutable copy hung on the reading rather than the live cache.
        """
        if reading['rust'].get('pool_tip_stable'):
            for bid, ids in staged.items():
                self.input_block_txids[bid] = ids
                if ids:
                    self.input_block_seen_under[bid] = tip
        # Published snapshot: what a consumer of THIS reading may use.
        # An unstable sweep publishes the standing set, never its own
        # unvalidated observations.
        reading['rust']['input_block_txids'] = dict(self.input_block_txids)
        reading['rust']['input_block_seen_under'] = dict(
            self.input_block_seen_under)


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
    """Assertion 3, as amended by the controller after round 1.

    At every same-ordering-block sample Rust's chain must be a prefix of
    Scala's read oldest-first — Scala's chain with the newest k entries
    removed. Rust trailing is fine; a different HISTORY is not.

    ONE exception, and only one: a sample where Scala's chain is a
    strict prefix of Rust's by EXACTLY ONE block is accepted **if that
    Rust tip block appears in Scala's chain for the same ordering id at
    a LATER sample**. This is the miner's own read window seen from the
    other side — Scala announces an input block, the follower applies
    it, and Scala's `bestChain` (its *processed* prefix) catches up a
    moment later. Anything else fails: a different block at any
    position, a prefix by two or more, or a tip Scala never went on to
    confirm.

    Counts are TOTALS; the recorded lists are samples of them.
    """
    kept, excluded = qualifying_samples(samples)
    # The LAST sample index at which Scala listed each block under each
    # ordering id. "Later" has to mean later than the sample being
    # judged — but it must not mean "the FIRST time Scala listed it is
    # later", which is what keeping only the first occurrence meant. A
    # miner that lists a block, drops it from its read for a sample or
    # two, then lists it again has confirmed it; judging against the
    # first occurrence alone rejected exactly that sequence.
    scala_last_listed = {}
    for i, s in kept:
        for block in s.get('scala_chain') or []:
            scala_last_listed[(s['ordering'], block)] = i

    compared, violation_count, violations, depths = 0, 0, [], []
    allowed_by_one, allowed_samples = 0, []
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
        # The amended allowance: Scala's whole chain is a prefix of
        # Rust's, short by exactly one, and Scala goes on to list that
        # one block under the same ordering id.
        ahead_by_one = (
            len(rust_old) == len(scala_old) + 1
            and rust_old[:len(scala_old)] == scala_old
        )
        if ahead_by_one:
            tip = rust_old[-1]
            confirmed_at = scala_last_listed.get((s['ordering'], tip))
            if confirmed_at is not None and confirmed_at > i:
                allowed_by_one += 1
                if len(allowed_samples) < 10:
                    allowed_samples.append({
                        'sample': i, 'ordering': s['ordering'],
                        'rust_only_tip': tip,
                        'scala_confirmed_at_sample': confirmed_at,
                    })
                continue
        violation_count += 1
        if len(violations) < 10:
            violations.append({'sample': i, 'ordering': s['ordering'],
                               'scala_chain': scala_chain,
                               'rust_chain': rust_chain,
                               'ahead_by_one': ahead_by_one,
                               'rust_only_tip_confirmed_later': False})
    result = {
        'definition_amended': 'round 1: Scala a strict prefix of Rust by exactly '
                              'one block is allowed only when Scala lists that tip '
                              'for the same ordering id at ANY later sample '
                              '(round 3: any later occurrence, not only a '
                              'first-ever one)',
        'qualifying_samples': len(kept),
        'excluded_samples': excluded,
        'compared_samples': compared,
        'min_qualifying_samples': MIN_QUALIFYING_SAMPLES,
        'prefix_violation_count': violation_count,
        'prefix_violations_sample': violations,
        'allowed_prefix_by_one_count': allowed_by_one,
        'allowed_prefix_by_one_sample': allowed_samples,
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


# Fallback reasons that mean "the transactions root did not come out
# right", as opposed to "an ingredient was missing". Both are honest
# fallbacks; only these say the node rebuilt something and rejected its
# own result, which is the case where a wrong fallback would be a
# consensus bug rather than a download.
MERKLE_MISMATCH_REASONS = ('root_mismatch', 'tx_digest_mismatch', 'digest_mismatch')


# Every route the PINNED Scala build serves an input block's contents
# on, read from its own `BlocksApiRoute` (`getInputBlockTransactionsR`
# and `getInputBlockTransactionIdsR`, both under `blocks/{id}`).
# Querying only the ids route and accepting silence made "the miner
# never sealed it" indistinguishable from "we never asked properly".
SCALA_INPUT_BLOCK_ROUTES = (
    ('ids', '/blocks/{id}/inputBlockTransactionIds'),
    ('bodies', '/blocks/{id}/inputBlockTransactions'),
)


def scala_input_block_txids(block_id, routes_tried=None):
    """Transaction ids Scala reports for one of ITS OWN input blocks.

    Tries every route the pinned build exposes and returns the union.
    `routes_tried` (a set) records which routes actually answered with
    content, so the run can say whether the miner's corpus was readable
    at all rather than inferring innocence from silence.
    """
    found = set()
    for name, path in SCALA_INPUT_BLOCK_ROUTES:
        try:
            answer = api('scala', path.format(id=block_id))
        except Unavailable:
            continue
        for entry in answer or []:
            # The ids route yields strings; the bodies route yields
            # transaction objects. Both name the same thing.
            txid = entry if isinstance(entry, str) else (entry or {}).get('id')
            if txid:
                found.add(txid)
                if routes_tried is not None:
                    routes_tried.add(name)
    return found


def evaluate_mismatch_recovery(ordering_events, scala_block_at_height):
    """Assertion 4's "zero Merkle-mismatch-then-wrong-fallback", over the
    events the node actually emits.

    Two properties, both checked against Scala's own block at the height:

    * **A Merkle/root-mismatch fallback must recover correctly.** The
      node refused its own rebuild and downloaded instead; the block it
      then applied at that height must be the one Scala has. A fallback
      that lands on a different block is the wrong fallback.
    * **A reconstructed block must not be replaced at its height.** If a
      LATER event applies a DIFFERENT header at a height the node
      reported reconstructed, the rebuild it published was wrong and was
      silently swapped out.

    `ordering_events` is the MERGED stream — `ordering_*` events and
    `blockApplied` together, in the order the node emitted them. Both
    halves are needed and so is the order: the recovery of a fallback
    can only be an application that came after it, and an application
    that came before a reconstruction is not a replacement of it. Given
    only the `ordering_*` events, as this was, a wrong recovery had no
    application to compare against and silently became `unverifiable`.

    An `unverifiable` mismatch fallback is a FAILURE: the node refused
    its own rebuild and the run cannot show what it did instead.

    `scala_block_at_height` maps height -> Scala's header id there (or
    `None` when Scala has no block at that height yet). Pure, so
    `--self-test` drives it with a fabricated stream.
    """
    # ONE pass, in event order. Chronology is the whole point: an
    # application that came BEFORE a mismatch fallback says nothing
    # about how that fallback recovered, and an application before a
    # reconstruction is not a replacement of it.
    reconstructed_at = {}   # height -> (index, header) of the last rebuild
    mismatch_fallbacks = []  # (index, event)
    applications = []        # (index, height, header)
    for i, e in enumerate(ordering_events):
        height = e.get('height')
        header = e.get('header_id') or e.get('headerId')
        kind = e.get('kind')
        if kind in ('blockApplied', 'ordering_reconstructed'):
            applications.append((i, height, header))
        if kind == 'ordering_reconstructed':
            reconstructed_at[height] = (i, header)
        elif kind == 'ordering_reconstruct_fallback':
            if (e.get('detail') or '') in MERKLE_MISMATCH_REASONS:
                mismatch_fallbacks.append((i, e))

    bad_recoveries, replaced, unverifiable = [], [], []
    for i, e in mismatch_fallbacks:
        height = e.get('height')
        expected = scala_block_at_height.get(height)
        # Only applications AFTER the fallback can be its recovery.
        landed = [h for (j, hh, h) in applications
                  if j > i and hh == height and h]
        if not landed or expected is None:
            # The node refused its own rebuild and we cannot show what it
            # did next. A run that cannot verify its recovery has not
            # verified it — this is a FAILURE, not a shrug.
            unverifiable.append({'height': height, 'fallback': e,
                                 'scala_block': expected,
                                 'applied_after_fallback': landed})
            continue
        if expected not in landed:
            bad_recoveries.append({'height': height, 'fallback': e,
                                   'scala_block': expected,
                                   'applied_after_fallback': landed})

    for height, (ri, header) in reconstructed_at.items():
        # Only an application AFTER the reconstruction replaces it.
        later = [h for (j, hh, h) in applications
                 if j > ri and hh == height and h and h != header]
        if later:
            replaced.append({'height': height, 'reconstructed': header,
                             'replaced_by': later})

    failures = []
    if bad_recoveries:
        failures.append((
            f'{len(bad_recoveries)} Merkle-mismatch fallbacks did not recover onto '
            "Scala's block at that height",
            {'bad_recoveries': bad_recoveries[:10]}))
    if replaced:
        failures.append((
            f'{len(replaced)} reconstructed ordering blocks were replaced at their '
            'own height',
            {'replaced': replaced[:10]}))
    if unverifiable:
        failures.append((
            f'{len(unverifiable)} Merkle-mismatch fallbacks had no subsequent '
            "application to check against Scala's block at that height",
            {'unverifiable': unverifiable[:10]}))
    return {
        'mismatch_fallbacks': len(mismatch_fallbacks),
        'mismatch_reasons_checked': list(MERKLE_MISMATCH_REASONS),
        'bad_recoveries': bad_recoveries,
        'reconstructed_then_replaced': replaced,
        'unverifiable': unverifiable,
        'failures': failures,
    }


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

    # ----- round 5, item 1: pool removal is credited only under the
    # ordering tip the transaction was located under -----

    # The strict path keeps this rule verbatim; it is asserted against
    # the tracker production actually runs.
    def strict(txid='tx'):
        t = PaymentOutcomeTracker({txid})
        t.saw_in_input_block(txid, 'ib1', 'H1')
        return t

    # Credited: absent from the pool while the tip has not moved.
    t = strict()
    t.observe_pool('H1', {'tx'})     # still pooled
    t.observe_pool('H1', set())      # gone, same tip
    assert t.credited == {'tx': 'ib1'}, t.credited
    assert t.confirmed_by_ordering == {}, t.confirmed_by_ordering

    # NOT credited: it was still pooled under H1 and only disappeared
    # after the ordering tip moved — ordinary confirmation explains it.
    t = strict()
    t.observe_pool('H1', {'tx'})
    t.observe_pool('H2', set())
    assert t.credited == {}, t.credited
    assert 'tx' in t.confirmed_by_ordering, t.confirmed_by_ordering

    # A later same-tip observation must NOT erase that verdict — this is
    # the round-4 hole: a transaction confirmed by an ordering block
    # could be re-credited to the input block on a subsequent sample.
    t.observe_pool('H2', set())
    assert t.credited == {}, t.credited
    assert 'tx' in t.confirmed_by_ordering, t.confirmed_by_ordering

    # Never observed absent at all: neither credited nor excused.
    t = strict()
    t.observe_pool('H1', {'tx'})
    assert t.strict_not_evicted() == ['tx'], t.strict_not_evicted()

    # An unknown tip cannot credit anything.
    t = strict()
    t.observe_pool(None, set())
    assert t.credited == {}, t.credited
    assert 'tx' in t.confirmed_by_ordering, t.confirmed_by_ordering

    # ----- round 5, item 2: the sampler queues mismatches, never writes
    # them inline -----

    run = Run.__new__(Run)
    run.mismatch_queue = queue.Queue()
    entry = {'ordering': 'O', 'at': 1.0,
             'scala_chain': ['c', 'b', 'a'], 'rust_chain': ['c', 'x', 'a']}
    reading = {'rust': {'best': {}, 'info': {}}, 'scala': {'best': {}, 'info': {}}}
    Run._maybe_queue_live_mismatch(run, entry, reading)
    assert run.mismatch_queue.qsize() == 1, 'a mismatch must be queued'
    queued = run.mismatch_queue.get_nowait()
    assert queued['ids'][0] == 'O', queued
    assert queued['at'] == 1.0, queued
    # A consistent sample queues nothing, and neither does one where the
    # two nodes name different ordering blocks.
    Run._maybe_queue_live_mismatch(
        run, {'ordering': 'O', 'at': 2.0,
              'scala_chain': ['c', 'b', 'a'], 'rust_chain': ['b', 'a']}, reading)
    Run._maybe_queue_live_mismatch(
        run, {'ordering': None, 'at': 3.0,
              'scala_chain': ['c'], 'rust_chain': ['z']}, reading)
    assert run.mismatch_queue.qsize() == 0, 'no false positives'
    # And there is no cap: a hundred mismatches queue a hundred times.
    for n in range(100):
        Run._maybe_queue_live_mismatch(
            run, {'ordering': 'O', 'at': float(n),
                  'scala_chain': ['c', 'b', 'a'], 'rust_chain': ['c', 'x', 'a']},
            reading)
    assert run.mismatch_queue.qsize() == 100, run.mismatch_queue.qsize()

    # ----- round 5, item 3: a dead sampler fails the run -----

    def health(error=None, last=None, ended=100.0, max_silence=10.0):
        r = Run.__new__(Run)
        r._lock = threading.Lock()
        r.sampler_error = error
        r.last_sample_at = last
        r.sampling_ended_at = ended
        return Run.check_sampler_health(r, max_silence)

    assert health(last=95.0) == [], 'a healthy sampler reports nothing'
    assert any('sampler_failed' in h for h in health(error='OSError: disk full')), \
        'an exception must be fatal'
    assert any('never produced a sample' in h for h in health(last=None)), \
        'a sampler that never sampled must be fatal'
    assert any('no sample in the last' in h for h in health(last=80.0)), \
        'a sampler silent for 20s of a 10s budget must be fatal'
    assert health(last=91.0) == [], 'silence inside the budget is fine'

    # ----- round 5, item 4: artifacts carry announcement bytes or say
    # why they do not -----

    block_id = 'ab' * 32
    parent_id = 'ef' * 32
    payload = 'cd' * 60
    window = [f'2026-09-22T00:00:00.1Z TRACE '
              f'input_blocks: raw announcement payload '
              f'block={block_id} payload={payload}']
    out = announcement_hex_for([block_id], window)
    assert out[block_id]['announcement_hex'] == [payload], out
    # A long hex run on a line that merely MENTIONS the id is not its
    # payload — this is the fabricated-evidence breakage round 5 left
    # open. A parent id sitting beside it must never be reported.
    decoy = [f'2026-09-22T00:00:00.1Z DEBUG input_blocks: dropped '
             f'id={block_id} parent={parent_id} reason=AlreadyKnown']
    out = announcement_hex_for([block_id], decoy)
    assert out[block_id]['announcement_hex'] is None, out
    assert out[block_id]['reason'] == 'no_payload_bytes_logged_for_this_id', out
    # Another block's payload line is not this block's payload either.
    other = [f'2026-09-22T00:00:00.1Z TRACE '
             f'input_blocks: raw announcement payload '
             f'block={parent_id} payload={payload}',
             f'2026-09-22T00:00:00.1Z DEBUG input_blocks: dropped id={block_id}']
    out = announcement_hex_for([block_id], other)
    assert out[block_id]['announcement_hex'] is None, out
    assert out[block_id]['reason'] == 'no_payload_bytes_logged_for_this_id', out
    # Nothing in the window at all is stated explicitly, never implied.
    out = announcement_hex_for([block_id], [])
    assert out[block_id] == {'announcement_hex': None,
                             'reason': 'not_in_log_window'}, out

    # ----- task 8b: ids and timestamps on every failure artifact -----

    block_id = 'ab' * 32
    other_id = 'ef' * 32
    found = ids_in({'txids': [block_id], 'nested': {'parent': other_id},
                    'noise': 'short', 'dupe': block_id})
    assert found == [block_id, other_id], found
    assert ids_in({'x': 'zz' * 32}) == [], 'non-hex is not an id'
    assert len(ids_in({'ids': [f'{i:064x}' for i in range(50)]})) == 20, \
        'the id list is capped'

    class Recorder:
        """Just `Run.fail`, so the recording rule is tested on its own."""

        fail = Run.fail

        def __init__(self):
            self.failures = []
            self.findings = []

    r = Recorder()
    r.fail('2_tip', 'boom', {'block': block_id})
    assert r.failures[0]['observed_at_unix'] is not None, r.failures
    assert r.findings[0]['ids'] == [block_id], r.findings
    assert r.findings[0]['at'] == r.failures[0]['observed_at_unix']

    # ----- fix round 1: assertion 3's amended prefix-by-one allowance ---

    def chain_series(pairs):
        """`pairs` is [(scala_chain, rust_chain)], newest-first, padded to
        the coverage threshold with agreeing samples so only the shape
        under test decides the verdict."""
        pad = [sample(['b1'], ['b1'])
               for _ in range(MIN_QUALIFYING_SAMPLES - len(pairs))]
        return [sample(sc, rc) for sc, rc in pairs] + pad

    # Scala short by exactly one, and Scala lists that tip LATER: the
    # miner's own read window, allowed and counted.
    later_confirmed = evaluate_chain_consistency(chain_series([
        (['b1'], ['b2', 'b1']),
        (['b2', 'b1'], ['b2', 'b1']),
    ]))
    assert later_confirmed['violations'] == [], later_confirmed
    assert later_confirmed['allowed_prefix_by_one_count'] == 1, later_confirmed
    assert later_confirmed['allowed_prefix_by_one_sample'][0]['rust_only_tip'] == 'b2'

    # Short by one but Scala NEVER lists that tip: a block Scala does not
    # have is a divergence, not a window.
    never_confirmed = evaluate_chain_consistency(chain_series([
        (['b1'], ['bX', 'b1']),
    ]))
    assert never_confirmed['prefix_violation_count'] == 1, never_confirmed
    assert never_confirmed['allowed_prefix_by_one_count'] == 0, never_confirmed
    assert never_confirmed['violations'], never_confirmed

    # Short by TWO is never allowed, even when both tips are confirmed
    # later: the allowance is exactly one block wide.
    by_two = evaluate_chain_consistency(chain_series([
        (['b1'], ['b3', 'b2', 'b1']),
        (['b3', 'b2', 'b1'], ['b3', 'b2', 'b1']),
    ]))
    assert by_two['prefix_violation_count'] == 1, by_two
    assert by_two['allowed_prefix_by_one_count'] == 0, by_two

    # A different block at a position is a history disagreement whatever
    # the lengths are.
    differing = evaluate_chain_consistency(chain_series([
        (['b2', 'b1'], ['bY', 'b1']),
    ]))
    assert differing['prefix_violation_count'] == 1, differing
    assert differing['allowed_prefix_by_one_count'] == 0, differing

    # Rust trailing is still fine, and still not counted as an allowance.
    trailing = evaluate_chain_consistency(chain_series([
        (['b3', 'b2', 'b1'], ['b1']),
    ]))
    assert trailing['violations'] == [], trailing
    assert trailing['allowed_prefix_by_one_count'] == 0, trailing

    # Round 3, codex's probe: Scala lists the tip BEFORE the sample,
    # drops it from its read, then lists it AGAIN afterwards. Keeping
    # only the FIRST occurrence made "later" mean "first seen later",
    # so this sequence was reported as 1 violation / 0 allowances even
    # though the miner plainly confirmed the block. Any later listing
    # counts.
    confirmed_before_and_after = evaluate_chain_consistency(chain_series([
        (['b2', 'b1'], ['b2', 'b1']),   # Scala already listed b2 here
        (['b1'], ['b2', 'b1']),         # then reads short by one
        (['b2', 'b1'], ['b2', 'b1']),   # and lists it again
    ]))
    assert confirmed_before_and_after['prefix_violation_count'] == 0, \
        confirmed_before_and_after
    assert confirmed_before_and_after['allowed_prefix_by_one_count'] == 1, \
        confirmed_before_and_after
    assert confirmed_before_and_after['violations'] == [], \
        confirmed_before_and_after

    # And the guard the probe must not loosen: listed only BEFORE, never
    # again, is still a violation.
    only_before = evaluate_chain_consistency(chain_series([
        (['b2', 'b1'], ['b2', 'b1']),
        (['b1'], ['b2', 'b1']),
    ]))
    assert only_before['prefix_violation_count'] == 1, only_before
    assert only_before['allowed_prefix_by_one_count'] == 0, only_before

    # ----- fix round 1: the REAL sampler, not a copy of its conditional -

    def sampler_over(sweeps, interval=0.0):
        """Drive `Run._sample_loop` itself with a scripted `sweep`."""
        r = Run.__new__(Run)
        Run.__init__(r, deadline=time.monotonic() + 30)
        r._series_file = None
        remaining = list(sweeps)

        def scripted():
            if not remaining:
                r._stop.set()
                return None
            return remaining.pop(0)

        r.sweep = scripted
        r._sample_loop(interval)
        return r

    only_failures = sampler_over([None, None])
    assert only_failures.last_sample_at is None, \
        'failed sweeps must not advance the heartbeat'
    assert only_failures.sampler_error is None, only_failures.sampler_error
    assert only_failures.check_sampler_health(max_silence=0.0), \
        'a sampler that never produced a reading is unhealthy'

    mixed = sampler_over([None, {'ok': True}, None])
    assert mixed.last_sample_at is not None, \
        'a successful sweep does advance the heartbeat'

    # The pause handshake: a sweep already in flight must be JOINED, and
    # a sweep that overruns must be reported as a failure to quiesce
    # rather than waved through.
    def paused_against(sweep_seconds, budget):
        r = Run.__new__(Run)
        Run.__init__(r, deadline=time.monotonic() + 30)
        r._series_file = None
        entered = threading.Event()
        release = threading.Event()

        def slow():
            entered.set()
            release.wait(5)
            return {'ok': True}

        r.sweep = slow
        r._thread = threading.Thread(target=r._sample_loop, args=(0.01,), daemon=True)
        r._thread.start()
        entered.wait(5)
        global SWEEP_JOIN_SECONDS
        saved, SWEEP_JOIN_SECONDS = SWEEP_JOIN_SECONDS, budget
        try:
            if sweep_seconds is not None:
                threading.Timer(sweep_seconds, release.set).start()
            quiesced = r.pause_sampling()
        finally:
            SWEEP_JOIN_SECONDS = saved
            release.set()
            r.stop_sampling()
        return r, quiesced

    joined, ok = paused_against(sweep_seconds=0.05, budget=5.0)
    assert ok, 'a sweep that finishes inside the budget must be joined'
    assert not joined._in_sweep, 'and the sampler must be out of its sweep'
    assert joined.sweep_join_timeouts == 0, joined.sweep_join_timeouts

    overran, ok = paused_against(sweep_seconds=None, budget=0.2)
    assert not ok, 'a sweep that overruns the budget must NOT report quiescence'
    assert overran.sweep_join_timeouts == 1, overran.sweep_join_timeouts

    # ----- fix round 2: assertion 6's two routes -----

    # (1) sealed then evicted under its own tip: the strict path, PASS.
    t = PaymentOutcomeTracker({'a'})
    t.saw_in_input_block('a', 'ib1', 'H1')
    t.observe_pool('H1', {'a'})
    t.observe_pool('H1', set())
    t.cross_check_scala({'zz'})
    assert t.located == {'a': 'ib1'}, t.located
    assert t.credited == {'a': 'ib1'}, t.credited
    assert t.unresolved() == [] and t.strict_not_evicted() == []
    assert t.never_sealed == {}, t.never_sealed
    assert t.missing_on_rust == {}, t.missing_on_rust

    # (2) never sealed, then confirmed by an ordering block Rust has
    # APPLIED: counted as F11 telemetry, not failed.
    t = PaymentOutcomeTracker({'b'})
    t.saw_in_ordering_block('b', 'O9', 9)
    t.observe_pool('O9', {'b'}, rust_tip_height=9, rust_block_at={9: 'O9'})
    t.observe_pool('O9', set(), rust_tip_height=9, rust_block_at={9: 'O9'})
    t.cross_check_scala({'zz'})
    assert t.never_sealed == {'b': {'ordering_block': 'O9', 'height': 9}}, \
        t.never_sealed
    assert t.unresolved() == [], t.unresolved()
    assert t.never_sealed_still_pooled() == [], t.never_sealed_still_pooled()
    assert t.located == {}, t.located
    # A never-sealed payment that never leaves the pool IS a failure.
    t2 = PaymentOutcomeTracker({'b'})
    t2.saw_in_ordering_block('b', 'O9', 9)
    t2.observe_pool('O9', {'b'}, rust_tip_height=9, rust_block_at={9: 'O9'})
    assert t2.never_sealed_still_pooled() == ['b'], t2.never_sealed_still_pooled()

    # ----- fix round 4, finding 1: codex's O8/O9 probe -----
    #
    # The payment is confirmed in O9. Rust's pool is empty while Rust is
    # still on O8 — that is not evidence the follower processed O9, and
    # crediting it satisfied the exit condition an ordering block early.
    probe = PaymentOutcomeTracker({'p'})
    probe.saw_in_ordering_block('p', 'O9', 9)
    probe.observe_pool('O8', set(), rust_tip_height=8, rust_block_at={8: 'O8'})
    assert probe.removed_after_ordering == {}, probe.removed_after_ordering
    assert probe.never_sealed_still_pooled() == ['p'], \
        'an absence under O8 must NOT credit a payment confirmed in O9'
    # Rust applies O9: now it credits.
    probe.observe_pool('O9', set(), rust_tip_height=9,
                       rust_block_at={8: 'O8', 9: 'O9'})
    assert 'p' in probe.removed_after_ordering, probe.removed_after_ordering
    assert probe.never_sealed_still_pooled() == [], \
        probe.never_sealed_still_pooled()

    # Right height, WRONG block — Rust is on a different chain there.
    forked = PaymentOutcomeTracker({'p'})
    forked.saw_in_ordering_block('p', 'O9', 9)
    forked.observe_pool('X9', set(), rust_tip_height=9, rust_block_at={9: 'X9'})
    assert forked.never_sealed_still_pooled() == ['p'], \
        'a different block at that height is not the confirming block'
    # Deeper tip, with the confirming block an ancestor Rust applied.
    deeper = PaymentOutcomeTracker({'p'})
    deeper.saw_in_ordering_block('p', 'O9', 9)
    deeper.observe_pool('O11', set(), rust_tip_height=11,
                        rust_block_at={9: 'O9', 11: 'O11'})
    assert 'p' in deeper.removed_after_ordering, deeper.removed_after_ordering

    # ----- fix round 4, finding 2: an unreadable miner corpus is stated -

    verified = PaymentOutcomeTracker({'v'})
    verified.saw_in_ordering_block('v', 'O9', 9)
    verified.cross_check_scala({'other'}, corpus_available=True)
    assert verified.scala_corpus_available, verified.summary()
    assert verified.summary()['scala_corpus_unavailable'] is False
    assert verified.never_sealed_unverified == [], verified.never_sealed_unverified

    silent = PaymentOutcomeTracker({'v'})
    silent.saw_in_ordering_block('v', 'O9', 9)
    silent.cross_check_scala(set(), corpus_available=False)
    assert silent.summary()['scala_corpus_unavailable'] is True, silent.summary()
    assert silent.never_sealed_unverified == ['v'], silent.never_sealed_unverified
    assert silent.missing_on_rust == {}, 'silence is not a verdict either way'
    # And with a readable corpus, the cross-check still names the defect.
    caught = PaymentOutcomeTracker({'v'})
    caught.saw_in_ordering_block('v', 'O9', 9)
    caught.cross_check_scala({'v'}, corpus_available=True)
    assert caught.missing_on_rust and caught.never_sealed == {}, caught.summary()

    # (3) neither route inside the budget: unresolved, and that FAILS.
    t = PaymentOutcomeTracker({'c'})
    t.observe_pool('H1', {'c'})
    t.cross_check_scala({'zz'})
    assert t.unresolved() == ['c'], t.unresolved()
    assert not t.all_routed()

    # (4) located = 0 fails even when everything else is clean: a run in
    # which the strict path was never exercised proved nothing.
    t = PaymentOutcomeTracker({'d'})
    t.saw_in_ordering_block('d', 'O9', 9)
    t.observe_pool('O9', set(), rust_tip_height=9, rust_block_at={9: 'O9'})
    t.cross_check_scala({'zz'})
    assert t.unresolved() == [] and not t.located, t.located

    # The cross-check: Scala sealed it, Rust never served it. That is a
    # FOLLOWER defect and must not hide in the telemetry bucket.
    t = PaymentOutcomeTracker({'e'})
    t.saw_in_ordering_block('e', 'O9', 9)
    t.observe_pool('O9', set(), rust_tip_height=9, rust_block_at={9: 'O9'})
    t.cross_check_scala({'e'})
    assert t.missing_on_rust == {'e': {'ordering_block': 'O9', 'height': 9}}, \
        t.missing_on_rust
    assert t.never_sealed == {}, 'it is pulled out of never_sealed'
    assert t.unresolved() == [], t.unresolved()

    # The route is decided by FIRST sighting: an input-block payment that
    # is later confirmed stays on the strict path.
    t = PaymentOutcomeTracker({'f'})
    t.saw_in_input_block('f', 'ib1', 'H1')
    t.saw_in_ordering_block('f', 'O9', 9)
    assert t.route['f'] == 'input_block', t.route
    assert t.never_sealed == {}, t.never_sealed

    # ----- fix round 3: assertion 4's mismatch guard, against the event
    # shapes the producer ACTUALLY emits (pinned by ergo-node's
    # `reconstruction_events_have_the_shape_the_smoke_harness_parses`) --

    def ev(kind, height, header_id, **rest):
        return dict(kind=kind, height=height, headerId=header_id, **rest)

    # PASS: the node refused its own rebuild at h5 and downloaded the
    # block Scala has; and its rebuild at h6 was never replaced.
    good = evaluate_mismatch_recovery(
        [ev('ordering_reconstruct_fallback', 5, 'S5', detail='root_mismatch'),
         ev('blockApplied', 5, 'S5', txs=2),
         ev('ordering_reconstructed', 6, 'S6', txs=2,
            reconstructedOrder='candidate', reconstructionKey='parent')],
        {5: 'S5', 6: 'S6'})
    assert good['failures'] == [], good
    assert good['mismatch_fallbacks'] == 1, good
    assert good['bad_recoveries'] == [] and good['unverifiable'] == [], good

    # FAIL shape 1: the mismatch fallback landed on a block that is NOT
    # Scala's at that height — the wrong fallback.
    wrong = evaluate_mismatch_recovery(
        [ev('ordering_reconstruct_fallback', 5, 'X5', detail='root_mismatch'),
         ev('blockApplied', 5, 'X5', txs=2)],
        {5: 'S5'})
    assert wrong['bad_recoveries'], wrong
    assert any('did not recover' in m for m, _ in wrong['failures']), wrong

    # FAIL shape 2: a block the node reported RECONSTRUCTED was replaced
    # at its own height — the rebuild it published was wrong.
    swapped = evaluate_mismatch_recovery(
        [ev('ordering_reconstructed', 6, 'R6', txs=2,
            reconstructedOrder='candidate', reconstructionKey='parent'),
         ev('blockApplied', 6, 'S6', txs=2)],
        {6: 'S6'})
    assert swapped['reconstructed_then_replaced'], swapped
    assert any('replaced at their own height' in m for m, _ in swapped['failures']), \
        swapped

    # A fallback for a MISSING INGREDIENT is not a Merkle mismatch and is
    # not policed here — the node downloading a block it could not
    # assemble is the feature working.
    ingredient = evaluate_mismatch_recovery(
        [ev('ordering_reconstruct_fallback', 5, 'S5', detail='missing_input_body'),
         ev('blockApplied', 5, 'S5', txs=2)],
        {5: 'S5'})
    assert ingredient['mismatch_fallbacks'] == 0, ingredient
    assert ingredient['failures'] == [], ingredient

    # Round 4 addendum: nothing to compare against is now a FAILURE. The
    # node refused its own rebuild and the run cannot show what it did
    # next; "unverified" is not "verified".
    blind = evaluate_mismatch_recovery(
        [ev('ordering_reconstruct_fallback', 9, 'S9', detail='root_mismatch')],
        {9: None})
    assert blind['unverifiable'], blind
    assert any('no subsequent application' in m for m, _ in blind['failures']), \
        blind

    # ----- round 4 addendum: the merged stream and its chronology -----
    #
    # Codex's production-filter probe. Under the old caller the evaluator
    # saw only `ordering_*` events, so this — a mismatch fallback
    # followed by the WRONG full block — produced zero failures.
    wrong_recovery = evaluate_mismatch_recovery(
        [ev('ordering_reconstruct_fallback', 5, 'S5', detail='root_mismatch'),
         ev('blockApplied', 5, 'X5', txs=2)],
        {5: 'S5'})
    assert wrong_recovery['failures'], \
        'a mismatch fallback that applied the wrong block must FAIL'
    assert wrong_recovery['bad_recoveries'], wrong_recovery
    # And the same stream with only the ordering events reproduces the
    # hole, which is why the caller must pass the merged one.
    filtered = evaluate_mismatch_recovery(
        [e for e in
         [ev('ordering_reconstruct_fallback', 5, 'S5', detail='root_mismatch'),
          ev('blockApplied', 5, 'X5', txs=2)]
         if e['kind'].startswith('ordering_')],
        {5: 'S5'})
    assert filtered['bad_recoveries'] == [], \
        'the ordering-only stream cannot see the wrong recovery at all'

    # Chronology: an application BEFORE the fallback is not its recovery.
    prior_then_wrong = evaluate_mismatch_recovery(
        [ev('blockApplied', 5, 'S5', txs=2),
         ev('ordering_reconstruct_fallback', 5, 'S5', detail='root_mismatch')],
        {5: 'S5'})
    assert prior_then_wrong['failures'], \
        'a correct application BEFORE the fallback must not excuse it'
    assert prior_then_wrong['unverifiable'], prior_then_wrong

    # Chronology: an application BEFORE a reconstruction is not a
    # replacement of it.
    applied_then_rebuilt = evaluate_mismatch_recovery(
        [ev('blockApplied', 6, 'S6', txs=2),
         ev('ordering_reconstructed', 6, 'R6', txs=2,
            reconstructedOrder='candidate', reconstructionKey='parent')],
        {6: 'S6'})
    assert applied_then_rebuilt['reconstructed_then_replaced'] == [], \
        applied_then_rebuilt
    assert applied_then_rebuilt['failures'] == [], applied_then_rebuilt
    # But an application AFTER it still is.
    rebuilt_then_swapped = evaluate_mismatch_recovery(
        [ev('ordering_reconstructed', 6, 'R6', txs=2,
            reconstructedOrder='candidate', reconstructionKey='parent'),
         ev('blockApplied', 6, 'S6', txs=2)],
        {6: 'S6'})
    assert rebuilt_then_swapped['reconstructed_then_replaced'], \
        rebuilt_then_swapped

    # ----- round 4 addendum: a sweep publishes only after it validates -

    def staged_run():
        r = Run.__new__(Run)
        r.input_block_txids = {}
        r.input_block_seen_under = {}
        return r

    # Codex's mocked sweep: the bracket did NOT hold, so nothing of that
    # sweep's own observations may be retained or published.
    r = staged_run()
    unstable = {'rust': {'pool_tip_stable': False}}
    r._publish_sweep_ids(unstable, {'ibX': ['tx']}, 'H9')
    assert r.input_block_txids == {}, r.input_block_txids
    assert r.input_block_seen_under == {}, r.input_block_seen_under
    assert unstable['rust']['input_block_txids'] == {}, unstable
    # A stable sweep commits and publishes the same thing.
    r2 = staged_run()
    stable = {'rust': {'pool_tip_stable': True}}
    r2._publish_sweep_ids(stable, {'ibX': ['tx']}, 'H9')
    assert r2.input_block_txids == {'ibX': ['tx']}, r2.input_block_txids
    assert r2.input_block_seen_under == {'ibX': 'H9'}, r2.input_block_seen_under
    assert stable['rust']['input_block_txids'] == {'ibX': ['tx']}, stable
    # The published snapshot is a COPY: later sampler writes do not
    # retroactively change what an earlier reading offered.
    r2.input_block_txids['ibY'] = ['tx2']
    assert stable['rust']['input_block_txids'] == {'ibX': ['tx']}, stable

    # The guard must key off the REAL shapes: a `detail` on a
    # reconstructed event is a shape the producer never emits, and
    # looking for it is what made round 2's guard inert.
    inert = evaluate_mismatch_recovery(
        [ev('ordering_reconstructed', 7, 'R7', txs=2, detail='root_mismatch')],
        {7: 'R7'})
    assert inert['mismatch_fallbacks'] == 0, \
        'a reconstructed event is never a mismatch fallback'
    assert inert['failures'] == [], inert

    # ----- fix round 4, finding 3: a failed ordering read is RETRIED ---
    #
    # The scan used to advance its cursor before the fetch succeeded, so
    # one transient REST failure lost that height for the rest of the
    # window and a payment confirmed there read as `unresolved`. The
    # height now stays pending until a read succeeds.

    def scan_once(tracker, pending, scanned, height_now, fetch):
        """The driver's scan loop, with `api` replaced by `fetch`."""
        if height_now > scanned:
            pending.update(range(scanned + 1, height_now + 1))
            scanned = height_now
        for height in sorted(pending):
            try:
                for hid, txids in fetch(height):
                    for txid in txids:
                        tracker.saw_in_ordering_block(txid, hid, height)
            except Unavailable:
                continue
            pending.discard(height)
        return pending, scanned

    attempts = {'n': 0}

    def flaky(height):
        attempts['n'] += 1
        if attempts['n'] == 1:
            raise Unavailable('transient')
        return [('O9', ['pay'])]

    rt = PaymentOutcomeTracker({'pay'})
    pend, scanned = scan_once(rt, set(), 8, 9, flaky)
    assert rt.unresolved() == ['pay'], 'the failed read is not an observation'
    assert pend == {9}, f'the height stays pending for retry: {pend}'
    pend, scanned = scan_once(rt, pend, scanned, 9, flaky)
    assert rt.unresolved() == [], 'the retry resolves it'
    assert pend == set(), f'and the height is done: {pend}'
    assert rt.never_sealed['pay']['height'] == 9, rt.never_sealed

    # A height that never reads stays pending, so the run reports it
    # rather than quietly losing it.
    def always_fails(height):
        raise Unavailable('down')

    stuck = PaymentOutcomeTracker({'pay'})
    pend, scanned = scan_once(stuck, set(), 8, 9, always_fails)
    pend, scanned = scan_once(stuck, pend, scanned, 9, always_fails)
    assert pend == {9}, pend
    assert stuck.unresolved() == ['pay'], stuck.unresolved()

    # ----- fix round 4, finding 2: both Scala routes are read ---------

    assert [name for name, _ in SCALA_INPUT_BLOCK_ROUTES] == ['ids', 'bodies'], \
        SCALA_INPUT_BLOCK_ROUTES
    assert dict(SCALA_INPUT_BLOCK_ROUTES)['bodies'] == \
        '/blocks/{id}/inputBlockTransactions', SCALA_INPUT_BLOCK_ROUTES

    served = {}

    def fake_api(node, path, data=None):
        if path not in served:
            raise Unavailable(f'no route {path}')
        return served[path]

    real_api, globals()['api'] = api, fake_api
    try:
        # Ids route silent, bodies route answers with transaction OBJECTS.
        served = {'/blocks/B/inputBlockTransactions': [{'id': 'tx1'},
                                                       {'id': 'tx2'}]}
        tried = set()
        assert scala_input_block_txids('B', tried) == {'tx1', 'tx2'}
        assert tried == {'bodies'}, tried
        # Ids route answers with plain strings.
        served = {'/blocks/B/inputBlockTransactionIds': ['tx1']}
        tried = set()
        assert scala_input_block_txids('B', tried) == {'tx1'}
        assert tried == {'ids'}, tried
        # Neither route serves anything: an empty corpus, not a verdict.
        served = {}
        tried = set()
        assert scala_input_block_txids('B', tried) == set()
        assert tried == set(), tried
    finally:
        globals()['api'] = real_api

    print('self-test OK: evaluators behave as the round-5 definitions require')


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
        try:
            if scala_height(run) > start + blocks:
                break
        except Unavailable:
            pass
        run.idle(0.5)
    return start


def check_sampler(run, evidence):
    """The run may only trust its own samples if the sampler survived.

    A sampler that raised — a JSONL write failure, a bug in the
    accumulators — used to end the thread quietly and leave every
    assertion drawing verdicts from a truncated series. Assertion 5 in
    particular could still report PASS. Any sampler fault is a failure of
    the run, recorded as `sampler_failed`.
    """
    reasons = run.check_sampler_health()
    evidence['sampler'] = {
        'samples': run.samples,
        'unavailable_samples': run.unavailable_samples,
        'error': run.sampler_error,
        'health': reasons or ['ok'],
    }
    for reason in reasons:
        run.fail('sampler', reason)


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
        try:
            if scala_height(run) >= target:
                return
        except Unavailable:
            pass
        run.idle(0.5)
    raise Unavailable(f'{what}: Scala did not reach ordering block {target} in budget')


class PaymentOutcomeTracker:
    """Assertion 6, as amended by the controller in round 2.

    Each submitted payment takes ONE of two routes, decided by where it
    is first seen:

    * **(a) a Rust-served input block** — the strict path, unchanged: it
      must be located in a Rust input block AND observed leaving Rust's
      pool while that block's own ordering tip is still current. This is
      what the assertion exists to test.
    * **(b) an ordering block, without ever having been seen in an input
      block on Rust** — the miner never sealed it. That is upstream F11
      (`CandidateGenerator` clears `cachedCandidate` after every accepted
      input block, so most of its own input solutions are rejected), not
      a follower defect. Counted as `never_sealed_by_miner` telemetry;
      the only requirement is that it leaves Rust's pool once **RUST has
      applied its confirming ordering block** — not merely that it is
      absent under some earlier tip, which is how a payment confirmed in
      O9 could be credited while Rust was still on O8.

    A payment that reaches neither inside the budget is `unresolved` and
    FAILS the run: an observation that did not happen is not a pass.

    The route is decided by FIRST sighting and never revisited — a tx
    seen in an input block and then confirmed is still a strict-path tx.

    The guard against route (b) absorbing a real defect is
    [`Self::cross_check_scala`]: if SCALA's input chain carried the
    transaction and Rust's never did, the miner plainly sealed it and
    the follower failed to serve it. That is `missing_on_rust`, and it
    is a failure.

    Pure: no I/O, so `--self-test` drives it directly.
    """

    def __init__(self, submitted):
        self.submitted = set(submitted)
        self.route = {}               # txid -> 'input_block' | 'ordering'
        self.located = {}             # txid -> Rust input block id
        self.located_under = {}       # txid -> ordering tip when located
        # txid -> {'ordering_block': id, 'height': h}. The HEIGHT is what
        # makes "its ordering block is applied on Rust" checkable.
        self.never_sealed = {}
        self.credited = {}            # strict path: evicted under its own tip
        self.confirmed_by_ordering = {}
        self.removed_after_ordering = {}   # route (b): gone once confirmed
        self.missing_on_rust = {}
        # Set by `cross_check_scala`: whether the miner's own input-block
        # corpus was readable at all, and which route-(b) payments went
        # unverified because it was not.
        self.scala_corpus_available = True
        self.never_sealed_unverified = []

    # ----- sightings -----

    def saw_in_input_block(self, txid, input_block_id, ordering_tip):
        """`txid` appears in a Rust-served input block."""
        if txid not in self.submitted or txid in self.route:
            return
        self.route[txid] = 'input_block'
        self.located[txid] = input_block_id
        self.located_under[txid] = ordering_tip

    def saw_in_ordering_block(self, txid, ordering_block_id, height=None):
        """`txid` appears in an ordering block at `height`."""
        if txid not in self.submitted or txid in self.route:
            return
        self.route[txid] = 'ordering'
        self.never_sealed[txid] = {'ordering_block': ordering_block_id,
                                   'height': height}

    def observe_pool(self, ordering_tip, pool, rust_tip_height=None,
                     rust_block_at=None):
        """One observation of Rust's unconfirmed pool at `ordering_tip`.

        Strict-path transactions keep the round-5 credit rule.

        Route (b) credits an absence ONLY once Rust has applied the
        payment's own confirming ordering block: its tip must have
        reached that height, and the block Rust holds at that height
        must be the confirming one. `rust_block_at` maps height to the
        header id Rust applied there. An absence observed before that is
        not evidence the follower processed the block — a pool can be
        empty for any number of reasons — and crediting it satisfied the
        exit condition a whole ordering block early.
        """
        rust_block_at = rust_block_at or {}
        for txid, route in self.route.items():
            if txid in pool:
                continue
            if route == 'input_block':
                if txid in self.credited or txid in self.confirmed_by_ordering:
                    continue
                if (ordering_tip is not None
                        and ordering_tip == self.located_under[txid]):
                    self.credited[txid] = self.located[txid]
                else:
                    self.confirmed_by_ordering[txid] = {
                        'input_block': self.located[txid],
                        'located_under': self.located_under[txid],
                        'observed_under': ordering_tip,
                    }
            elif route == 'ordering':
                if txid in self.removed_after_ordering:
                    continue
                entry = self.never_sealed.get(txid)
                if entry is None:
                    continue
                height, block = entry.get('height'), entry.get('ordering_block')
                if height is None or rust_tip_height is None:
                    continue
                if rust_tip_height < height:
                    continue
                if rust_block_at.get(height) != block:
                    continue
                self.removed_after_ordering[txid] = {
                    'observed_under': ordering_tip,
                    'rust_tip_height': rust_tip_height,
                    'confirming_block': block,
                    'confirming_height': height,
                }

    def cross_check_scala(self, scala_input_chain_txids, corpus_available=True):
        """Route (b) is only honest if the MINER never sealed it.

        `scala_input_chain_txids` is every transaction id Scala's own
        input chain was observed to carry, across every route Scala
        serves. A payment Scala sealed into an input block but Rust never
        served is a follower defect wearing the miner's clothes, so it
        is pulled back out of the telemetry bucket and named.

        `corpus_available` is whether Scala answered ANY of those routes
        with content. When it did not, the check cannot run: route (b)
        is then UNVERIFIED, and the evidence says so
        (`scala_corpus_unavailable`) rather than implying the miner was
        exonerated. An empty answer from a node that serves nothing must
        never read the same as an empty answer from one that does.
        """
        self.scala_corpus_available = bool(corpus_available)
        if not corpus_available:
            self.never_sealed_unverified = sorted(self.never_sealed)
            return
        self.never_sealed_unverified = []
        for txid in sorted(self.never_sealed):
            if txid in scala_input_chain_txids:
                self.missing_on_rust[txid] = self.never_sealed.pop(txid)
                self.route[txid] = 'missing_on_rust'

    # ----- verdict inputs -----

    def unresolved(self):
        """Payments that reached neither route inside the budget."""
        return sorted(self.submitted - set(self.route))

    def all_routed(self):
        return not self.unresolved()

    def strict_not_evicted(self):
        """Strict-path payments never seen leaving the pool under their
        own ordering tip."""
        strict = {t for t, r in self.route.items() if r == 'input_block'}
        return sorted(strict - set(self.credited))

    def never_sealed_still_pooled(self):
        """Route (b) payments never seen leaving the pool at all."""
        return sorted(set(self.never_sealed) - set(self.removed_after_ordering))

    def summary(self):
        return {
            'located_in_rust_input_block': len(self.located),
            'never_sealed_by_miner': len(self.never_sealed),
            'scala_corpus_unavailable': not self.scala_corpus_available,
            'never_sealed_unverified': self.never_sealed_unverified,
            'missing_on_rust': sorted(self.missing_on_rust),
            'unresolved': self.unresolved(),
            'credited_under_own_tip': self.credited,
            'confirmed_by_ordering': self.confirmed_by_ordering,
            'never_sealed_detail': self.never_sealed,
            'never_sealed_removed_after_ordering': self.removed_after_ordering,
        }


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
        run.idle(1)
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

    # Route each payment. The window is keyed to INPUT-BLOCK
    # PRODUCTION, not to ordering height: the old loop stopped at the
    # next ordering block, so when the miner's `cachedCandidate` race
    # (F11) delayed sealing, the run reported "0 of 20 located" for a
    # follower that had done nothing wrong. Now each payment is followed
    # until it appears in a Rust input block (the strict path) or in an
    # ordering block (never sealed — telemetry), or the ceiling is hit.
    tracker = PaymentOutcomeTracker(submitted)
    ever_in_rust_pool = set()
    scala_input_chain_txids = set()
    scala_ids_cache = {}
    scala_routes_tried = set()
    # Heights whose ordering block has NOT been read yet. A height stays
    # here until a read succeeds, so a transient REST failure costs a
    # retry rather than the height — losing one made a confirmed payment
    # read as `unresolved` for the rest of the window.
    pending_heights = set()
    # What Rust has APPLIED, height -> header id. Route (b) credits an
    # absence only once Rust holds the payment's own confirming block.
    rust_block_at = {}
    rust_tip_height = None
    track_deadline = min(run.deadline, time.monotonic() + MEMPOOL_ROUTE_SECONDS)
    # Every input below comes from ONE sampler sweep: the ordering tip,
    # the chain the transaction ids are read against, and the pool. The
    # old loop took a CACHED tip and then made its own pool call, so an
    # ordering block landing between the two credited ordinary
    # confirmation to the input block under a stale tip. A sweep whose
    # tip moved across its own pool read is recorded and skipped.
    seen_sweeps = set()
    unstable_sweeps = 0
    scanned_height = start_height
    while time.monotonic() < track_deadline:
        reading = run.latest_reading()
        # Sweeps are told apart by the sampler's own monotonic counter.
        # `id(reading)` looked like a cheap identity and was not one:
        # CPython reuses addresses, so a freed reading's address could
        # make a later, distinct sweep look already-seen.
        seq = reading.get('seq') if reading else None
        if seq is not None and seq not in seen_sweeps:
            seen_sweeps.add(seq)
            if reading['rust'].get('pool_tip_stable'):
                header_now = reading['rust']['pool_tip']
                # The sweep's OWN published snapshot, never the live
                # cache: the cache is mutated by the sampler thread, so
                # iterating it credited ids from a newer sweep against
                # this sweep's pool — and could raise mid-iteration.
                published_ids = reading['rust'].get('input_block_txids') or {}
                published_seen = reading['rust'].get(
                    'input_block_seen_under') or {}
                for bid, ids in published_ids.items():
                    # The tip to credit against is the one the BLOCK was
                    # observed under, not the one current now.
                    located_under = published_seen.get(bid)
                    if located_under is None:
                        continue
                    for txid in set(ids) & submitted:
                        tracker.saw_in_input_block(txid, bid, located_under)
                pool = reading['rust']['pool']
                ever_in_rust_pool |= pool
                rust_tip_height = reading['rust']['info'].get('fullHeight')
                if rust_tip_height is not None and header_now:
                    rust_block_at[rust_tip_height] = header_now
                tracker.observe_pool(header_now, pool,
                                     rust_tip_height=rust_tip_height,
                                     rust_block_at=rust_block_at)
            else:
                unstable_sweeps += 1
            # The miner's OWN input chain, for the cross-check: a payment
            # Scala sealed but Rust never served is a follower defect,
            # not a miner one, and must not hide in the telemetry bucket.
            for bid in reading['scala']['chain'].get('bestInputBlocks') or []:
                if bid in scala_ids_cache:
                    continue
                found = scala_input_block_txids(bid, scala_routes_tried)
                if found:
                    scala_ids_cache[bid] = sorted(found)
                    scala_input_chain_txids |= found
        # Ordering blocks are the OTHER route. Every block from the
        # submission height onwards is scanned once.
        try:
            height_now = scala_height(run)
        except Unavailable:
            height_now = scanned_height
        if height_now > scanned_height:
            pending_heights.update(range(scanned_height + 1, height_now + 1))
            scanned_height = height_now
        for height in sorted(pending_heights):
            try:
                hids = api('scala', f'/blocks/at/{height}') or []
                for hid in hids:
                    block = api('scala', f'/blocks/{hid}')
                    for t in block['blockTransactions']['transactions']:
                        tracker.saw_in_ordering_block(t['id'], hid, height)
            except (Unavailable, KeyError, TypeError):
                # Not an observation. The height stays PENDING and is
                # retried on the next pass; dropping it lost whatever it
                # carried for the rest of the window, and a payment
                # confirmed there then read as `unresolved`.
                continue
            pending_heights.discard(height)
        if tracker.all_routed() and not tracker.strict_not_evicted() \
                and not tracker.never_sealed_still_pooled():
            break
        run.idle(0.3)
    tracker.cross_check_scala(scala_input_chain_txids,
                              corpus_available=bool(scala_input_chain_txids))
    result['sweeps_skipped_tip_moved'] = unstable_sweeps
    result['route_window_seconds'] = MEMPOOL_ROUTE_SECONDS
    result['scala_input_chain_txids_seen'] = len(scala_input_chain_txids)
    result['scala_routes_tried'] = sorted(scala_routes_tried)
    result['ordering_heights_unread'] = sorted(pending_heights)
    result['rust_applied_heights'] = len(rust_block_at)
    in_input_block = tracker.located
    credited = tracker.credited
    confirmed_by_ordering = tracker.confirmed_by_ordering
    unresolved = tracker.unresolved()
    strict_not_evicted = tracker.strict_not_evicted()
    never_sealed_pooled = tracker.never_sealed_still_pooled()
    result.update(tracker.summary())
    result['in_rust_input_block'] = in_input_block
    result['located_count'] = len(in_input_block)
    result['min_located'] = MEMPOOL_MIN_LOCATED
    result['located_under_header'] = tracker.located_under
    result['removed_before_next_ordering_block'] = credited
    result['confirmed_by_ordering'] = confirmed_by_ordering
    result['never_removed_before_ordering'] = strict_not_evicted
    result['rust_pool_ever_held'] = sorted(ever_in_rust_pool & submitted)
    result['definition_amended'] = (
        'round 2: the window follows input-block production. A payment first seen '
        'in a Rust input block takes the strict path (located + evicted under its '
        'own ordering tip); one first seen in an ordering block is '
        'never_sealed_by_miner (upstream F11) and need only leave the pool. '
        'PASS needs located >= 1, unresolved = 0, and no missing_on_rust.'
    )

    # A payment Scala sealed into an input block that Rust never served
    # is a FOLLOWER defect, and the whole reason route (b) is allowed to
    # be telemetry rather than a failure.
    if tracker.missing_on_rust:
        run.fail('6_mempool',
                 f'{len(tracker.missing_on_rust)} payments were in SCALA\'s input '
                 'chain but never in a Rust input block',
                 {'missing_on_rust': sorted(tracker.missing_on_rust),
                  'scala_input_chain_txids_seen': len(scala_input_chain_txids),
                  'rust_log': rust_log_lines('input_blocks')})

    # An observation that did not happen is not a pass.
    if unresolved:
        run.fail('6_mempool',
                 f'{len(unresolved)} payments reached neither a Rust input block nor '
                 f'an ordering block within {MEMPOOL_ROUTE_SECONDS:.0f}s',
                 {'unresolved': unresolved,
                  'input_blocks_seen': len(dict(run.input_block_txids)),
                  'rust_log': rust_log_lines('input_blocks')})

    # The strict path has to be EXERCISED. A run in which the miner
    # sealed nothing proves nothing about input-block eviction, so it is
    # a failure to be rerun, not a pass.
    if not in_input_block:
        run.fail('6_mempool',
                 'no payment was ever located inside a Rust input block, so the '
                 'input-block eviction path was never exercised',
                 {'never_sealed_by_miner': len(tracker.never_sealed),
                  'input_blocks_seen': len(dict(run.input_block_txids)),
                  'scala_input_chain_txids_seen': len(scala_input_chain_txids),
                  'rust_log': rust_log_lines('input_blocks')})

    if strict_not_evicted:
        run.fail('6_mempool',
                 f'{len(strict_not_evicted)} transactions in an applied Rust input '
                 'block were not observed leaving the pool while that ordering block '
                 f'was still the tip ({len(confirmed_by_ordering)} of them only '
                 'disappeared after the next ordering block)',
                 {'txids': strict_not_evicted,
                  'confirmed_by_ordering': confirmed_by_ordering,
                  'input_blocks': {t: in_input_block[t] for t in strict_not_evicted}})

    if never_sealed_pooled:
        run.fail('6_mempool',
                 f'{len(never_sealed_pooled)} payments confirmed by an ordering block '
                 "never left Rust's pool",
                 {'txids': never_sealed_pooled,
                  'never_sealed': tracker.never_sealed})

    # Pool agreement after the next ordering block, with every Scala-only
    # residue attributed.
    try:
        wait_for_height(run, start_height + 1, 'assertion 6 ordering block')
        run.idle(3)
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
    # A COPY: the sampler thread is still writing this cache, and a dict
    # iterated while it grows raises.
    applied = {t for ids in dict(run.input_block_txids).values() for t in ids}
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
    """Reconstruction, as amended by the controller after round 1.

    M2 requires assembly from input-block bodies to be DEMONSTRATED:
    at least one ordering block reconstructed with more than one
    transaction (a coinbase-only block rides in the ordering
    announcement itself and proves nothing), every reconstructed block
    reporting its assembly order and chain key, and no block that
    reconstructed on a root that did not match.

    The fallback path is NOT required in M2 — it moves to M3's
    body-eviction scenario. Round 1's runs showed why: with the input
    chain reconnecting promptly, a cold-started node recovers fast
    enough to reconstruct the very next ordering block, so demanding a
    fallback demands that the node be worse at the thing the assertion
    exists to test. The fallback count stays in the evidence as
    telemetry.

    The cold restart still happens, and everything after it is still
    what is measured.
    """
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
    # The node's own drop counters reset with the process. Pause the
    # sampler, take a FRESH reading from the node that is about to die,
    # fold it forward, then kill. Folding the last cached sample forward
    # would lose everything counted since that sample, and a sampler
    # finishing an old-process observation after the fold would add that
    # lifetime twice.
    quiesced = run.pause_sampling()
    result['sampler_quiesced_for_restart'] = quiesced
    if quiesced:
        result['counters_carried_at_restart'] = run.snapshot_counters_before_kill()
    else:
        # The sampler did not confirm it was idle inside the budget, so
        # an old-process observation may still land after the fold and
        # count that lifetime twice. Proceeding would leave assertion
        # 5's accumulated counters quietly wrong; the run says so
        # instead.
        result['counters_carried_at_restart'] = {
            'totals': None, 'snapshot_error': None, 'both_nodes': None,
            'skipped': 'sampler did not quiesce within '
                       f'{SWEEP_JOIN_SECONDS:.0f}s',
        }
        run.fail('5_follow',
                 'the sampler did not confirm it was idle before the restart, so '
                 'the drop counters carried across it cannot be trusted',
                 {'sweep_join_timeouts': run.sweep_join_timeouts})
    lifecycle.stop(('rust',))
    lifecycle.spawn('rust')
    run.resume_sampling()
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
    # The recovery check needs `blockApplied` too, in the order the node
    # emitted it: a fallback's recovery is whatever it applied NEXT, and
    # without the applications every wrong recovery merely looked
    # unverifiable. The feed is already chronological.
    recovery_stream = [e for e in events.get('events', [])
                       if e['kind'].startswith('ordering_')
                       or e['kind'] == 'blockApplied']
    result['recovery_stream_events'] = len(recovery_stream)
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

    # The first ordering outcome after the restart is TELEMETRY under
    # the amended gate, not a requirement: whether a cold-started node
    # falls back or has already recovered its input chain is a fact
    # about how fast it recovers, and M3's body-eviction scenario is
    # where the fallback path is required.
    first = ordering[0] if ordering else None
    result['first_after_restart'] = first
    result['first_after_restart_kind'] = first['kind'] if first else None
    result['first_after_restart_reason'] = first.get('detail') if first else None
    result['fallback_required'] = False
    result['fallback_requirement_note'] = (
        'M2: the fallback path is telemetry only; it is required in M3, under a '
        'scenario that evicts bodies from a LIVE chain rather than cold-starting '
        'the node. A cold start that reconstructs instead of falling back is the '
        'node recovering faster, not the assertion being unmet.')
    if first is None:
        run.fail('4_reconstruction',
                 'the restarted node recorded no ordering reconstruction outcome at all',
                 {'events': events.get('events', [])[-20:]})

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
    # Every reconstructed block must SAY which order and which chain key
    # reproduced the header root (divergences D4/F12 and D5/F5). An
    # `unreported` here means the telemetry was renamed or dropped, and
    # the run can no longer say how the block was assembled.
    unreported = [e for e in ordering
                  if e['kind'] == 'ordering_reconstructed'
                  and (e.get('reconstructedOrder', e.get('reconstructed_order')) is None
                       or e.get('reconstructionKey',
                                e.get('reconstruction_key')) is None)]
    result['reconstructed_without_telemetry'] = unreported
    if unreported:
        run.fail('4_reconstruction',
                 f'{len(unreported)} reconstructed ordering blocks did not report '
                 'their assembly order and chain key',
                 {'events': unreported[:10]})
    # "Zero Merkle-mismatch-then-wrong-fallback", checked against the
    # events the node ACTUALLY emits. Round 2 looked for an
    # `ordering_reconstructed` event carrying `detail == "root_mismatch"`
    # — a shape the producer never emits (a mismatch reason rides on a
    # FALLBACK; a reconstructed event has no `detail` at all), so the
    # guard could never fire. `ergo-node`'s
    # `reconstruction_events_have_the_shape_the_smoke_harness_parses`
    # pins that.
    try:
        scala_at_height = {}
        for e in recovery_stream:
            h = e.get('height')
            if h is None or h in scala_at_height:
                continue
            ids = api('scala', f'/blocks/at/{h}') or []
            scala_at_height[h] = ids[0] if ids else None
    except Unavailable as error:
        scala_at_height = None
        result['mismatch_recovery_unavailable'] = str(error)
    if scala_at_height is None:
        run.fail('4_reconstruction',
                 'could not read Scala\'s blocks at the reconstruction heights, so '
                 'mismatch recovery could not be checked',
                 {'error': result.get('mismatch_recovery_unavailable')})
    else:
        recovery = evaluate_mismatch_recovery(recovery_stream, scala_at_height)
        result['mismatch_recovery'] = recovery
        result['reconstructed_on_root_mismatch'] = recovery['bad_recoveries']
        for message, evidence in recovery['failures']:
            run.fail('4_reconstruction', message, evidence)
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
            at=finding.get('at'), ids=finding.get('ids'),
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
        run.drain_mismatch_queue()
        check_sampler(run, evidence)
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
        chainm = evidence['assertions'].get('3_best_input_chain', {})
        poolm = evidence['assertions'].get('6_mempool', {})
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
              f'prefix_by_one_allowed={chainm.get("allowed_prefix_by_one_count", 0)} '
              f'prefix_violations={chainm.get("prefix_violation_count", 0)} '
              f'requests_full={run.totals().get("RequestsFull", 0)} '
              f'located={poolm.get("located_count", 0)} '
              f'never_sealed={poolm.get("never_sealed_by_miner", 0)} '
              f'missing_on_rust={len(poolm.get("missing_on_rust", []))} '
              f'unresolved={len(poolm.get("unresolved", []))} '
              f'scala_corpus_unavailable='
              f'{bool(poolm.get("scala_corpus_unavailable"))} '
              f'max_height_gap={run.max_height_gap} '
              f'failures={len(run.failures)} '
              f'evidence={output.relative_to(ROOT)}', flush=True)
    raise SystemExit(0 if not run.failures else 1)


if __name__ == '__main__':
    main()
