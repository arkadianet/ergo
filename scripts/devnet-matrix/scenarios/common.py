"""Shared scenario helpers.

Everything decisive here is PURE and exercised by `campaign.py
--self-test`: a scenario that computed its own verdict from live REST
calls could not be shown to fail when it should, and an evaluator that
cannot fail is not an evaluator.
"""
import shutil
import threading
import time

import smoke
from smoke import Unavailable, api, api_retry


def wait_ordering_blocks(ctx, blocks, what):
    """Let the sampler run while Scala mines `blocks` ordering blocks.

    Returns `(start_height, reached_height)`. A miner that stalls — the
    upstream F11 `cachedCandidate` race does exactly that — makes this
    return SHORT rather than hanging to the deadline, and the caller
    reports the shortfall instead of drawing a verdict from a window
    that never opened.
    """
    import campaign
    start = smoke.scala_height(ctx.run)
    target = start + blocks
    reached = start
    seen = set()
    while time.monotonic() < ctx.run.deadline:
        try:
            reached = smoke.scala_height(ctx.run)
        except Unavailable:
            pass
        # The UTXO watch item is transient: by finalization the box may
        # exist and the input block may be pruned, so its state is
        # captured here, while the condition is live.
        campaign.drain_utxo_watch(ctx, seen)
        if reached >= target:
            break
        ctx.run.idle(0.5)
    ctx.note(f'{what}_window', {'start_height': start, 'target': target,
                                'reached': reached,
                                'short_by': max(0, target - reached)})
    if reached < target:
        ctx.fail(
            f'the miner produced {reached - start} of the {blocks} ordering blocks '
            f'{what} needs within the budget (upstream F11 stalls the candidate '
            'generator; the shortfall is reported, never absorbed)',
            {'start_height': start, 'reached': reached, 'target': target,
             'scala_log_tail': smoke.rust_log_lines('ordering', limit=20)})
    return start, reached


def _wait_for_peer_count(ctx, node, wanted, budget=180.0):
    """Block until `node` reports `wanted` connected peers.

    Returns the count it ended on — short is reported by the caller, not
    swallowed: a follower that never reached the second miner has not
    observed anything about two miners.
    """
    deadline = min(ctx.run.deadline, time.monotonic() + budget)
    count = 0
    while time.monotonic() < deadline:
        try:
            count = len(api(node, '/peers/connected') or [])
        except Unavailable:
            count = 0
        if count >= wanted:
            return count
        ctx.run.idle(1)
    return count


def seed_second_miner(ctx, campaign, lifecycle, nodes=('scala2',)):
    """Give miner 2 the chain by COPYING miner 1's data directory.

    The reference node cannot hand it over. Two Scala nodes on one host
    never complete a mutual connection here — `getPeerAddress` refuses to
    resolve a same-address peer without a UPnP gateway, and giving each
    its own 127.x address gets the dial attempted but not established —
    so a second miner brought up cold sits at genesis indefinitely and,
    with `offlineGeneration = false`, never mines at all. Two runs were
    lost to that, each reporting "no fork switch observed", which was a
    true statement about a scenario that had not run.

    Copying the directory removes the dependency entirely: miner 2 starts
    on miner 1's exact chain and can mine from its tip immediately. The
    WALLET is deliberately NOT copied — a fresh keystore is what gives
    miner 2 its own mining key, and therefore coinbases (and blocks) that
    differ from miner 1's.

    Miner 1 is stopped for the copy. A LevelDB copied out from under a
    live writer is not a database, and a scenario built on one would fail
    for a reason that has nothing to do with input blocks.

    `nodes` (M4) is every Scala node to seed this way, so the same
    mechanism serves a reference FOLLOWER — the node's role decides
    whether it mines, not this function — and more than one of them:
    `--reference-follower both` runs a stock follower beside a patched
    one, which is the §7a ablation. A name not in the running node set is
    skipped, so a scenario may ask for `scala3` unconditionally.
    """
    nodes = tuple(n for n in nodes if n in lifecycle.NODES)
    if not nodes:
        return {}
    lifecycle.stop(('scala',))
    source = ctx.data_root / 'scala'
    targets = []
    for node in nodes:
        target = ctx.data_root / node
        shutil.rmtree(target, ignore_errors=True)
        shutil.copytree(source, target)
        shutil.rmtree(target / 'wallet', ignore_errors=True)
        targets.append(target)
    campaign.ensure_data_dirs(ctx.data_root, list(nodes))
    lifecycle.spawn('scala')
    ctx.run.started('scala')
    lifecycle.init_wallet('scala')
    for node in nodes:
        lifecycle.spawn(node)
        ctx.run.started(node)
        lifecycle.init_wallet(node)
    # The follower has been dialling miner 2 since it started, and miner
    # 2 was not there — so it is several failures into an exponential
    # dial backoff that outlasts the scenario. See `restart_follower`.
    restart_follower(ctx, campaign, lifecycle)
    # Reported, never raised: a seed that came up but did not peer is a
    # scenario that cannot run, and the evidence has to say which of the
    # two it was rather than dying with a stack trace that says neither.
    try:
        lifecycle.wait_peered(names=['scala', *nodes, 'rust'], timeout=120)
        peered = True
    except RuntimeError as error:
        peered = str(error)
    ctx.note('peered_after_seed', peered)
    # RECORDED, not failed. Whether the follower has reached the second
    # miner within three minutes of the seed is a fact about dial
    # timing, and the last run contradicted its own precondition: it
    # held one peer here and went on to retain two competing trees and
    # switch between them. The scenario's own evidence — `forks > 1`,
    # or a two-peer sighting at any point in the window — is what
    # decides whether it ran, and the scenario checks that itself.
    connected = _wait_for_peer_count(ctx, 'rust', 1 + len(nodes))
    ctx.note('follower_peers_after_seed', connected)
    heights = {}
    for node in ('scala', *nodes):
        try:
            heights[node] = (api(node, '/info') or {}).get('fullHeight')
        except Unavailable:
            heights[node] = None
    ctx.note('second_miner_seeded', {
        'copied_from': str(source), 'to': [str(t) for t in targets],
        'wallet_copied': False,
        'heights_after_seed': heights,
        'why': 'the reference node cannot hand the chain to a second Scala '
               'node on this host; see the docstring',
    })
    missing = [n for n in nodes if heights.get(n) is None]
    if missing:
        ctx.fail(f'{", ".join(missing)} did not come up on the copied chain, so '
                 'the scenario is missing a node it was told to run',
                 {'heights': heights, 'seeded': list(nodes)})
    return heights


def restart_follower(ctx, campaign, lifecycle):
    """Restart the follower with its dial state CLEARED.

    A restart alone does not clear it. The address book persists each
    peer's `last_failure` and backoff across restarts
    (`ergo-node/src/node/boot/peers.rs::setup` restores them BEFORE the
    configured known peers are seeded, precisely so they survive), so a
    follower that failed to reach an absent miner comes back still
    backing off from it. Round 2's rollback attempt 1 is that shape: the
    seed restarted the follower, it restored `peers=2`, never dialled
    the second miner again, and the scenario had one peer throughout.

    The chain database is untouched, so the follower resumes on the
    chain it already had; only `peers.redb` goes. Returns the paths
    removed.
    """
    lifecycle.stop(('rust',))
    removed = campaign.purge_address_book(ctx.data_root)
    lifecycle.spawn('rust')
    ctx.run.started('rust')
    ctx.note('follower_restart_purged', removed)
    return removed


def follower_events_since(events, watermark, restarted):
    """The follower's events after `watermark`, across a restart.

    The event feed is an in-memory ring whose `seq` starts again at 1 in
    every process (`ergo-node/src/node/event_feed.rs`). A watermark taken
    from the process that was running BEFORE a restart therefore names a
    sequence number the new process may never reach, and filtering the
    new feed by it hides exactly the events the restart was performed to
    provoke: rollback's reorg was emitted during the restarted
    follower's catch-up and filtered out by the old watermark, and the
    scenario reported "switched branches without emitting a reorg".

    With `restarted`, everything the NEW process reports is after the
    watermark by construction.
    """
    return list(events) if restarted else events_after(events, watermark)


def scala_reference_nodes(role_map, role_table):
    """`(miner nodes, follower nodes)` for one resolved run.

    Pure, and keyed by ROLE rather than by node name, because the same
    slot is a second miner in `fork` and a reference follower in
    `reconstruct_rate` — and because `--reference-follower patched`
    leaves `scala2` out of the run entirely while `both` adds `scala3`.
    A scenario that named `scala2` literally read a log that was never
    written in the first case, and ignored the patched follower's
    decisions in the second, which is the ablation itself.

    Only a FOLLOWER decides: a miner generates its blocks locally, so
    `processOrderingBlock` never runs on it and it logs neither side of
    the reconstruct-or-download choice.
    """
    miners, followers = [], []
    for node, role in sorted((role_map or {}).items()):
        spec = role_table.get(role)
        if spec is None or spec.kind != 'scala':
            continue
        (miners if spec.mines else followers).append(node)
    return tuple(miners), tuple(followers)


def rust_events(ctx):
    """The node's event feed, or a failure — never an empty list."""
    feed = api_retry('rust', '/api/v1/events', ctx.run.deadline,
                     what='the Rust event feed')
    return feed.get('events', [])


def latest_event_seq(ctx):
    """The node's newest event sequence number, as a WATERMARK.

    Scenarios that want "what happened after this point" must key off the
    sequence, not off the length of the list: the feed is a ring, so once
    it wraps a positional slice silently drops the very events the
    scenario went to the trouble of provoking.
    """
    feed = api_retry('rust', '/api/v1/events', ctx.run.deadline,
                     what='the Rust event feed watermark')
    # The route serializes camelCase (`ApiNodeEvents` carries
    # `#[serde(rename_all = "camelCase")]`). Reading the snake_case name
    # returned 0 for a feed that was not empty, which silently widened
    # every window keyed to it — so both spellings are accepted and a
    # feed that offers NEITHER is a failure rather than a zero.
    seq = feed.get('latestSeq', feed.get('latest_seq'))
    if seq is None:
        raise Unavailable(
            'the Rust event feed reports no latestSeq, so a window cannot be '
            'keyed to it')
    return seq


def events_after(events, seq):
    """Events newer than a watermark taken with `latest_event_seq`.

    An event with no `seq` is KEPT: dropping it would silently narrow the
    window, and a feed that stopped numbering is something the scenario
    should see rather than something it should filter out.
    """
    return [e for e in events if e.get('seq') is None or e['seq'] > seq]


class EventCollector:
    """Collect the node's event feed INCREMENTALLY, detecting loss.

    The feed is a bounded ring. Taking a watermark, waiting a hundred
    ordering blocks and reading once cannot recover entries the ring
    evicted in between, and filtering by sequence hides that it
    happened: early fallbacks evicted by later block and peer events
    leave only reconstructions and an apparent 100 % rate.

    So the feed is polled as the scenario runs, every event is kept by
    its sequence number, and a gap between the highest sequence seen and
    the lowest the feed still offers is recorded as LOSS. A scenario
    whose measurement window lost events has not measured it.
    """

    def __init__(self, ctx, node='rust'):
        self.ctx = ctx
        self.node = node
        self.events = {}
        self.highest_seen = 0
        self.gaps = []
        self.polls = 0
        self.failed_polls = 0

    def _fetch_page(self):
        """One read of the feed. The ONLY part a probe replaces: the
        gap detection and retention below are what the self-test has to
        exercise, so they are never re-implemented by a fake."""
        return (api(self.node, '/api/v1/events') or {}).get('events') or []

    def poll(self):
        try:
            page = self._fetch_page()
        except Unavailable:
            self.failed_polls += 1
            return self
        self.polls += 1
        numbered = [e for e in page if e.get('seq') is not None]
        if numbered:
            lowest = min(e['seq'] for e in numbered)
            # Everything between what we had and what the feed still
            # offers has been evicted since the last poll.
            if self.highest_seen and lowest > self.highest_seen + 1:
                self.gaps.append({'after_seq': self.highest_seen,
                                  'next_available_seq': lowest,
                                  'lost': lowest - self.highest_seen - 1})
        for event in page:
            seq = event.get('seq')
            if seq is None:
                continue
            self.events[seq] = event
            self.highest_seen = max(self.highest_seen, seq)
        return self

    def window(self, after_seq):
        """Every collected event newer than `after_seq`, in order."""
        return [self.events[s] for s in sorted(self.events) if s > after_seq]

    def lost_in_window(self, after_seq):
        return [g for g in self.gaps if g['next_available_seq'] > after_seq]

    def summary(self, after_seq=0):
        lost = self.lost_in_window(after_seq)
        return {'polls': self.polls, 'failed_polls': self.failed_polls,
                'events_collected': len(self.events),
                'highest_seq': self.highest_seen,
                'sequence_gaps': lost,
                'events_lost': sum(g['lost'] for g in lost)}


def ordering_stream(events):
    """`ordering_*` plus `blockApplied`, in emission order.

    Both halves, because `evaluate_mismatch_recovery` needs the
    applications to tell a recovered fallback from an unverifiable one.
    """
    return [e for e in events
            if e['kind'].startswith('ordering_') or e['kind'] == 'blockApplied']


def scala_blocks_by_height(ctx, low, high):
    """Scala's header id at each height in `[low, high]`.

    A height Scala could not answer for is OMITTED, and the caller is
    told which: `evaluate_mismatch_recovery` treats a missing height as
    "no block to compare against", which is a failure there, and that is
    the right outcome — a recovery nobody can check is not checked.
    """
    at, unread = {}, []
    for height in range(low, high + 1):
        try:
            ids = api('scala', f'/blocks/at/{height}')
        except Unavailable:
            unread.append(height)
            continue
        at[height] = ids[0] if ids else None
    return at, unread


# ----- fork-switch evaluation (pure) -----

def fork_switches(series, side):
    """Every input-chain fork switch one node made, from the sampled series.

    A switch is a sample where blocks that were on the node's best input
    chain for an ordering block are no longer on it — a pure extension
    (only additions) is not a switch. Consecutive samples under DIFFERENT
    ordering ids are not compared: two chains under different ordering
    blocks are not the same tree, and treating their difference as a
    rollback invents switches that never happened.

    `side` is `'rust'` or `'scala'`. Returns a list of
    `{'index', 'ordering', 'applied', 'rolled_back'}`, newest last.
    """
    out, previous, previous_chain = [], None, []
    for i, sample in enumerate(series):
        ordering = sample.get('ordering')
        chain = set(sample.get(f'{side}_chain') or [])
        if ordering is None:
            previous = None
            previous_chain = []
            continue
        if previous is not None and previous[0] == ordering:
            rolled_back = previous[1] - chain
            if rolled_back:
                out.append({'index': i, 'ordering': ordering,
                            'applied': sorted(chain - previous[1]),
                            'rolled_back': sorted(rolled_back),
                            # The chain it landed on, newest first: the
                            # switch is judged on the HISTORY it produced,
                            # not only on which members moved.
                            'chain_after': list(
                                sample.get(f'{side}_chain') or []),
                            # And the chain it left, so the switch can be
                            # judged as a transition between two chains a
                            # reference actually published rather than by
                            # set inclusion, which a rollback to nothing
                            # satisfies vacuously.
                            'chain_before': list(previous_chain)})
        previous = (ordering, chain)
        previous_chain = list(sample.get(f'{side}_chain') or [])
    return out


# How many later samples may confirm a Rust tip the reference has not
# published yet. smoke.py allows a one-block lead when the tip turns up
# in the reference's chain for the same ordering id at a LATER sample;
# unbounded, "later" means "at any point in a 90-minute run", which is
# not an allowance but an absence of one. 200 samples is ~60 s at the
# sampler's 0.3 s cadence.
LATER_CONFIRMATION_SAMPLES = 200

REFERENCE_NODES = ('scala', 'scala2')


def reference_chains(sample):
    """Each reference's chain, under ITS OWN ordering id.

    Keyed by the ordering block that reference is actually on, not by the
    first one's: attributing the second miner's chain to whatever block
    the first happened to be on is how an evaluator ends up accepting a
    follower chain that mixes members of two incompatible branches.
    Returns `[(node, ordering, chain_newest_first), ...]`, skipping a
    reference that published no chain in this sample.
    """
    out = []
    for node in REFERENCE_NODES:
        chain = sample.get(f'{node}_chain') or []
        if not chain:
            continue
        key = f'{node}_ordering'
        # A series recorded BEFORE the per-reference ordering id existed
        # has no such key, and for those the sample's shared ordering id
        # is the only thing available. A key that is present and None is
        # a reference that published no ordering id, which is different
        # and must not be papered over. `fork` requires the key, so new
        # runs never take this path.
        out.append((node, sample.get(key, sample.get('ordering')), list(chain)))
    return out


def series_carries_reference_ordering(series):
    """Does this series record each reference's OWN ordering id?

    Without it a two-miner evaluator falls back to the shared id and can
    attribute the second miner's chain to the first miner's ordering
    block — the mis-attribution finding 1 names.
    """
    return all('scala2_ordering' in sample for sample in series
               if sample.get('scala2_chain'))


def reference_chain(sample, ordering=None):
    """Every input block a reference listed for `ordering`.

    With `ordering` given, ONLY references that are themselves on that
    ordering block contribute — which is what makes the union safe. With
    it omitted, the union is over every reference, which is what the
    whole-chain "did anyone ever publish this" test wants.
    """
    out = set()
    for _, ref_ordering, chain in reference_chains(sample):
        if ordering is None or ref_ordering == ordering:
            out |= set(chain)
    return out


def _is_coherent_with(rust_chain, ref_chain):
    """Is Rust's chain the same history as this reference's?

    Chains arrive newest-first; history is read oldest-first. Coherent
    means Rust's chain is a prefix of the reference's (Rust trailing), or
    the reference's is a prefix of Rust's by EXACTLY ONE block (Rust one
    ahead of the miner's published prefix — F15/D8 seen from the other
    side). Returns `(coherent, rust_lead_tip)`; the tip is the block that
    later confirmation has to account for, or None.
    """
    rust_old = list(reversed(rust_chain))
    ref_old = list(reversed(ref_chain))
    if len(rust_old) <= len(ref_old):
        return (ref_old[:len(rust_old)] == rust_old, None)
    if len(rust_old) == len(ref_old) + 1 and rust_old[:len(ref_old)] == ref_old:
        return (True, rust_old[-1])
    return (False, None)


def evaluate_fork_coherence(series):
    """Every Rust chain must be the same HISTORY as some reference's.

    Membership in a union is not the property. A follower chain built
    from blocks of two incompatible branches has every member published
    by someone and is still a chain nobody has; so is one carrying an
    invented tip that no reference ever confirms.

    A sample is judged only when Rust and at least one reference are on
    the SAME ordering block — two chains under different ordering blocks
    are not chains of the same thing. Of those, Rust's chain has to be
    coherent (prefix, or one ahead) with at least ONE chain a reference
    published under that ordering id within `LATER_CONFIRMATION_SAMPLES`
    of this sample, and a one-block lead has to be confirmed by that
    reference inside the same bound. The window is not a loophole: a
    chain mixing two branches, or one carrying a block nobody published,
    matches nothing anywhere in it.
    """
    # Where each reference published each block, per ordering id, so a
    # lead can be confirmed against the reference it led.
    published = {}
    for i, sample in enumerate(series):
        for node, ref_ordering, chain in reference_chains(sample):
            if ref_ordering is None:
                continue
            for block in chain:
                published.setdefault((node, ref_ordering, block), []).append(i)

    # Every chain each reference published under each ordering id, with
    # the sample it was seen at. The follower legitimately lags, and a
    # reference legitimately moves on, so the chain it is coherent with
    # may be one a reference published a moment before or after this
    # sample — and with two miners, the OTHER miner may be publishing
    # nothing under this ordering id at this instant. Judging only
    # against the same sample reported 17 disagreements in one run, all
    # of them the follower sitting on a chain miner 2 had just moved off.
    history = {}
    for i, sample in enumerate(series):
        ordering = sample.get('ordering')
        for node, ref_ordering, chain in reference_chains(sample):
            if ref_ordering is not None:
                history.setdefault((node, ref_ordering), []).append((i, chain))

    incoherent, unconfirmed_leads, judged = [], [], 0
    for i, sample in enumerate(series):
        ordering = sample.get('ordering')
        rust_chain = sample.get('rust_chain') or []
        if ordering is None or not rust_chain:
            continue
        peers = [(node, chain) for node, ref_ordering, chain
                 in reference_chains(sample) if ref_ordering == ordering]
        nearby = []
        for node in REFERENCE_NODES:
            for j, chain in history.get((node, ordering), ()):
                if abs(j - i) <= LATER_CONFIRMATION_SAMPLES:
                    nearby.append((node, chain))
        if not peers and not nearby:
            continue
        peers = peers + nearby
        judged += 1
        matched, lead_problem = False, None
        for node, chain in peers:
            coherent, lead = _is_coherent_with(rust_chain, chain)
            if not coherent:
                continue
            if lead is None:
                matched = True
                break
            confirmations = [j for j in published.get((node, ordering, lead), ())
                             if i < j <= i + LATER_CONFIRMATION_SAMPLES]
            if confirmations:
                matched = True
                break
            lead_problem = {'sample': i, 'ordering': ordering, 'node': node,
                            'unconfirmed_tip': lead,
                            'within_samples': LATER_CONFIRMATION_SAMPLES}
        if matched:
            continue
        if lead_problem is not None:
            unconfirmed_leads.append(lead_problem)
        else:
            at_sample = [(node, chain) for node, ref_ordering, chain
                         in reference_chains(sample) if ref_ordering == ordering]
            incoherent.append({
                'sample': i, 'ordering': ordering,
                'rust_chain': rust_chain[:8],
                'references_at_this_sample': {node: chain[:8]
                                              for node, chain in at_sample},
                'references_compared': len(peers),
                'window': LATER_CONFIRMATION_SAMPLES,
            })
    return {
        'judged_samples': judged,
        'incoherent_samples': incoherent,
        'unconfirmed_one_block_leads': unconfirmed_leads,
        'later_confirmation_samples': LATER_CONFIRMATION_SAMPLES,
    }


def compare_fork_switches(series):
    """Did each Rust fork switch land on a chain a reference actually has?

    Judged as EQUALITY, not inclusion. The previous rule asked whether
    the applied blocks were a subset of some reference's chain and the
    rolled-back ones disjoint from it, which a rollback to the EMPTY
    chain satisfies vacuously — codex's probe moved the follower from
    `['a']` to `[]` while the miners held `['a']` and `['b']`, and it
    passed. An empty chain is also a prefix of every chain, so the
    coherence test cannot catch it either.

    A switch is matched when BOTH of these hold, against chains observed
    within `LATER_CONFIRMATION_SAMPLES` of it:

    * the chain it left EQUALS a chain some reference published, and
    * the chain it landed on EQUALS a chain some reference published.

    A transition to the EMPTY chain is reported separately, as a reset:
    no reference publishes an empty chain, so there is no transition to
    match it against, and a follower that has just restarted produces
    one legitimately. The caller says whether it caused the reset.

    Equality is on the ordered list, so "the follower moved from one
    miner's exact chain to another miner's exact chain" is the only
    shape that passes — which is what a two-miner fork switch IS. A
    follower that invented either end matches nothing.
    """
    # Every chain each reference published under each ordering id.
    seen = {}
    for i, sample in enumerate(series):
        for node, ref_ordering, chain in reference_chains(sample):
            if ref_ordering is not None:
                seen.setdefault(ref_ordering, []).append((i, node, list(chain)))

    def published(ordering, chain, at):
        """Which reference published exactly `chain`, near sample `at`."""
        for j, node, ref_chain in seen.get(ordering, ()):
            if abs(j - at) > LATER_CONFIRMATION_SAMPLES:
                continue
            if ref_chain == list(chain):
                return {'node': node, 'sample': j}
        return None

    rust = fork_switches(series, 'rust')
    unmatched, resets, rolled_back_still_held = [], [], []
    for switch in rust:
        ordering = switch['ordering']
        before = switch.get('chain_before') or []
        after = switch.get('chain_after') or []
        left = published(ordering, before, switch['index'])
        landed = published(ordering, after, switch['index'])
        entry = {**switch, 'chain_before': before[:8], 'chain_after': after[:8],
                 'left_a_reference_chain': left,
                 'landed_on_a_reference_chain': landed}
        if not after:
            # The chain went to NOTHING. That is not a move between two
            # competing histories — no reference ever publishes an empty
            # chain, so there is no transition to match it against — it
            # is a RESET: a restart, a prune, or an ordering turnover.
            # Reported separately so the caller can say whether it
            # caused the reset itself; a reset it did not cause is still
            # a chain nobody has, and still has to be explained.
            resets.append(entry)
        elif left is None or landed is None:
            unmatched.append(entry)
        # Telemetry: was it still on a reference's LAST chain for this
        # ordering id? Per node, so one miner's stale earlier reading
        # cannot answer for the other's current one.
        last_per_node = {}
        for j, node, ref_chain in seen.get(ordering, ()):
            last_per_node[node] = ref_chain
        for block in switch['rolled_back']:
            for node, ref_chain in last_per_node.items():
                if block in set(ref_chain):
                    rolled_back_still_held.append({**switch, 'block': block,
                                                   'node': node})
                    break
    return {
        'rust_switches': rust,
        'scala_switches': fork_switches(series, 'scala'),
        'scala2_switches': fork_switches(series, 'scala2'),
        # THE guard: a switch whose BEFORE and AFTER chains are not both
        # chains a reference actually published.
        'switches_matching_no_reference': unmatched,
        # Transitions to the EMPTY chain, which no reference publishes.
        'resets_to_the_empty_chain': resets,
        # Telemetry with two miners that cannot peer with each other:
        # each keeps its own fork, so a legitimate switch necessarily
        # rolls back blocks the other is still holding.
        'rolled_back_blocks_still_held_by_a_miner': rolled_back_still_held,
        'single_miner_series': not any(s.get('scala2_chain') for s in series),
    }


def judge_fork_switches(comparison, restart_window):
    """The `fork` scenario's verdict over `compare_fork_switches`' output.

    Pure, so the gate itself can be driven by a probe. Three rules:

    * a reset to the empty chain OUTSIDE the restart the scenario
      performs fails — no miner publishes an empty chain;
    * a non-reset switch that is not a transition between two chains a
      reference published fails;
    * a PASS requires at least one GENUINE switch — a non-empty chain
      replaced by a different non-empty chain. A reset is not a switch
      between competing histories, and counting it as one let a run whose
      only "switch" was the scenario's own follower restart satisfy the
      gate (round 2's attempt 1 had exactly that shape: one switch, and
      it was the reset at sample 9).

    Returns `{'failures': [(message, evidence), ...], 'genuine_switches',
    'resets_caused', 'resets_uncaused', 'qualifier'}`.
    """
    resets = comparison['resets_to_the_empty_chain']
    reset_indices = {r['index'] for r in resets}
    caused = [r for r in resets if r['index'] in restart_window]
    uncaused = [r for r in resets if r['index'] not in restart_window]
    genuine = [s for s in comparison['rust_switches'] if s['index'] not in reset_indices]
    failures, qualifier = [], None
    if uncaused:
        failures.append((
            f'{len(uncaused)} times the follower emptied its input chain outside '
            'the restart this scenario performs — no miner publishes an empty '
            'chain, so that is a chain nobody has', {'sample': uncaused[:5]}))
    unmatched = comparison['switches_matching_no_reference']
    if unmatched:
        failures.append((
            f'{len(unmatched)} fork switches produced a chain matching no miner: '
            'the chain the follower left or the one it landed on is not a chain '
            'any reference published under the same ordering block',
            {'sample': unmatched[:5]}))
    if not genuine:
        qualifier = 'NOT ESTABLISHED'
        failures.append((
            'no genuine input-chain fork switch (one non-empty chain replaced by '
            'another) was observed on Rust, so the switch property was never '
            'judged — NOT ESTABLISHED, not a pass'
            + (f'; the {len(resets)} reset(s) to the empty chain are restarts, '
               'not switches' if resets else ''),
            {'rust_switches': len(comparison['rust_switches']),
             'resets_to_the_empty_chain': len(resets),
             'scala_switches': len(comparison['scala_switches']),
             'scala2_switches': len(comparison['scala2_switches'])}))
    return {'failures': failures, 'genuine_switches': len(genuine),
            'resets_caused': caused, 'resets_uncaused': uncaused,
            'qualifier': qualifier}


def chain_members_scala_never_had(series):
    """Blocks on Rust's input chain that NO reference node ever published.

    The whole-chain companion to `evaluate_tip_consistency`'s tip check:
    a sibling completed into the middle of a chain would never be a tip
    and so would never be caught there.

    The test is "no reference node listed this block ANYWHERE in the
    run", not "under this ordering id". Keying it by ordering id
    measures the REFERENCE's read route, not the follower: F15/D8 is
    exactly a route that pairs a new `bestOrdering` with the previous
    block's chain, so a block both miners published lands in the sample
    under a neighbouring ordering id and reads as invented. One run
    reported 66 that way, and every one of the follower's 874 distinct
    chain ids had in fact been published by a miner.

    An invented block appears in no reference sample at all, so the
    check still fails on the thing it exists to catch. The per-ordering
    count is returned as telemetry, because a large one is worth seeing.

    Only samples where BOTH nodes name the SAME ordering block are
    scanned — smoke.py's `qualifying_samples` rule, and it is load
    bearing here. The reference's `bestInputBlocksChain()` returns the
    chain of its CURRENT best ordering block and nothing else, so a
    follower momentarily still on the PREVIOUS ordering block lists
    blocks the reference will never list again. One run's very first
    sample caught exactly that: the follower held a 120-block chain
    under its own tip while both miners reported an empty one, and all
    120 read as invented.
    """
    ever_anywhere = set()
    per_ordering = {}
    for sample in series:
        chain = reference_chain(sample)
        ever_anywhere |= chain
        ordering = sample.get('ordering')
        if ordering is not None:
            per_ordering.setdefault(ordering, set()).update(chain)
    orphans, off_by_ordering = [], []
    for i, sample in enumerate(series):
        ordering = sample.get('ordering')
        if ordering is None:
            continue
        # Chains are newest-first, so index 0 is the TIP. The tip is
        # assertion 2's job, not this check's: a follower one block
        # ahead of the miner's PUBLISHED chain is the documented F15/D8
        # lag seen from the other side — the miner's processed prefix
        # trailing its own announcements — and assertion 2 grants it an
        # explicit allowance. One run had exactly one such sighting in
        # 3,530 samples, at position 0, with both miners at 46 entries
        # and the follower at 47. What THIS check exists to catch is a
        # sibling completed into the MIDDLE of a chain, which is never a
        # tip and so never reaches assertion 2.
        for position, block in enumerate(sample.get('rust_chain') or []):
            if position == 0:
                continue
            if block not in ever_anywhere:
                orphans.append({'index': i, 'ordering': ordering,
                                'position': position, 'block': block})
            elif block not in per_ordering.get(ordering, set()):
                off_by_ordering.append(
                    {'index': i, 'ordering': ordering, 'position': position,
                     'block': block})
    return orphans, off_by_ordering


class WindowWalker:
    """Which chain snapshot belongs to which ordering block.

    The snapshot an ordering block CLOSES is the last one observed while
    the height was still the previous value. The first version refreshed
    the snapshot at the top of its loop and only then read the height,
    so by the time it noticed block N had landed it was holding the tree
    that came AFTER N — and a transaction dropped by N looked like one
    that had never been in the chain. Codex's block-40 probe lost a
    transaction from both nodes and the accounting reported zero.

    Pure state machine so the ordering can be driven directly: `observe`
    takes a height reading and returns the heights to record, each with
    the snapshot that belongs to it.
    """

    def __init__(self, start_height):
        self.scanned = start_height
        # None = no chain reading has been taken since the last block
        # landed. Distinct from an EMPTY reading, which is an observation.
        self.snapshot = None

    def note_chain(self, txids):
        """A chain reading taken while the height has not yet advanced."""
        self.snapshot = set(txids)

    def observe(self, height):
        """Heights that have landed, each paired with the snapshot it
        closes. Returns `[(height, snapshot), ...]`, oldest first.

        The FIRST block of a run of advances closes the snapshot we were
        holding. Any further block in the same reading closed a tree
        nobody sampled, and gets `None` — NOT an empty set. An empty set
        reads as "the chain was empty, nothing was dropped", which is a
        false zero; `None` makes the caller count the block as unread.
        """
        out = []
        while self.scanned < height:
            self.scanned += 1
            out.append((self.scanned,
                        None if self.snapshot is None else set(self.snapshot)))
            self.snapshot = None
        return out


# How recently a payment may have been submitted to the miner for its
# absence from the follower's pool at one reading to be relay lag rather
# than a disagreement. The harness submits payments immediately after
# reading a block, so the next block can land before the relay does.
PROPAGATION_SECONDS = 30.0


def evaluate_pool_agreement(blocks, d1_refusals=(), submitted_at=None):
    """Per-ordering-block pool agreement, with every residue attributed.

    The end-of-run comparison assertion 6 makes is one instant. A
    disagreement at block 40 that both pools have forgotten by block 60
    is invisible to it, which is the same blind spot the per-block F6
    accounting exists to close.

    For each block, the symmetric difference of the two pools is
    attributed exactly as `smoke.attribute_scala_residue` does: a logged
    D1 refusal, or an F6 omission (in the applied input chain, not in
    the ordering block). Anything else is UNEXPLAINED and fails.
    """
    submitted_at = submitted_at or {}
    per_block, unexplained_total = [], []
    for i, block in enumerate(blocks):
        rust_pool = set(block['rust_pool'])
        scala_pool = set(block['scala_pool'])
        only_scala = scala_pool - rust_pool
        only_rust = rust_pool - scala_pool
        applied = set(block['input_chain_txids'])
        ordering = set(block['ordering_txids'])
        # Where each residue ended up LATER: in Rust's pool or confirmed.
        arrived_later = set()
        for other in blocks[i + 1:]:
            arrived_later |= set(other['rust_pool']) | set(other['ordering_txids'])
        d1, f6, propagating, unexplained = [], [], [], []
        for txid in sorted(only_scala):
            sent = submitted_at.get(txid)
            read_at = block.get('read_at')
            if txid in d1_refusals:
                d1.append(txid)
            elif txid in applied and txid not in ordering:
                f6.append(txid)
            elif (sent is not None and read_at is not None
                  and 0 <= read_at - sent <= PROPAGATION_SECONDS
                  and txid in arrived_later):
                # Submitted to the miner moments before this reading, and
                # PROVEN to have reached the follower (its pool, or a
                # block it applied) afterwards: relay lag at one instant.
                # Both conditions are required — a fresh payment that
                # never arrives stays unexplained.
                propagating.append(txid)
            else:
                unexplained.append(txid)
        entry = {'height': block.get('height'), 'only_in_scala': len(only_scala),
                 'only_in_rust': sorted(only_rust), 'd1': d1, 'f6': f6,
                 'propagating': propagating, 'unexplained': unexplained}
        per_block.append(entry)
        # Residue Rust holds and Scala does not cannot be explained by
        # D1 or F6 at all — those only ever leave transactions in
        # SCALA's pool.
        unexplained_total.extend(unexplained + sorted(only_rust))
    return {'blocks': per_block,
            'unexplained_total': len(unexplained_total),
            'unexplained_txids': sorted(set(unexplained_total))[:50]}


# ----- F6, per ordering block (pure, self-tested) -----

def evaluate_f6(blocks):
    """Per-ordering-block accounting for the transactions an ordering
    block dropped from the applied input chain.

    `blocks` is one entry per ordering block IN ORDER:

        {'height', 'ordering_block', 'input_chain_txids', 'ordering_txids',
         'rust_pool', 'scala_pool'}

    `input_chain_txids` is the chain THIS ordering block closes — the
    transactions of the input blocks on the follower's best input chain
    just before it landed — NOT every input-block transaction the run
    has ever seen. Using the accumulated cache makes every block appear
    to drop every transaction of every earlier round. For each block:

    * **dropped** — in the applied input chain, not in the ordering block;
    * **F6** — dropped, not back in RUST's pool at this block OR ANY
      later one, and never confirmed by another ordering block in the
      window. Restoration one block later is still restoration. This is
      the reference
      behaviour the port reproduces (spec §12 F6), so it is counted, not
      failed;
    * **lost_on_both** — dropped, in NEITHER pool, and confirmed by no
      block in the window. A transaction in that state is irrecoverable on both
      implementations, and comparing the two pools can never reveal it
      because they agree. It FAILS.

    A single end-of-run pool comparison cannot see any of this: an
    input-chain transaction lost at block 40 leaves both pools agreeing
    at block 60.
    """
    # Confirmation ANYWHERE in the window, not only later. A transaction
    # the input chain still lists but an EARLIER ordering block already
    # confirmed was not dropped by this one, and counting it as lost
    # turned one run's 60 blocks into 5,157 phantom losses.
    confirmed_elsewhere = {}
    for i in range(len(blocks)):
        elsewhere = set()
        for j, other in enumerate(blocks):
            if j != i:
                elsewhere |= set(other['ordering_txids'])
        confirmed_elsewhere[i] = elsewhere
    # A transaction back in a pool at ANY later block was restored, not
    # lost. Looking only at this block's pool classified a transaction
    # the node returned one block later as permanently gone.
    restored_rust, restored_either = {}, {}
    for i in range(len(blocks)):
        rust_later, either_later = set(), set()
        for other in blocks[i:]:
            rust_later |= set(other['rust_pool'])
            either_later |= set(other['rust_pool']) | set(other['scala_pool'])
        restored_rust[i], restored_either[i] = rust_later, either_later
    per_block, f6_total, lost_total = [], [], []
    for i, block in enumerate(blocks):
        dropped = set(block['input_chain_txids']) - set(block['ordering_txids'])
        later = confirmed_elsewhere.get(i, set())
        f6 = sorted(dropped - restored_rust[i] - later)
        lost = sorted(dropped - restored_either[i] - later)
        per_block.append({
            'height': block.get('height'),
            'ordering_block': block.get('ordering_block'),
            'input_chain_txs': len(block['input_chain_txids']),
            'dropped': len(dropped),
            'f6': f6,
            'lost_on_both': lost,
            'returned_to_rust_pool': len(dropped & restored_rust[i]),
            'confirmed_by_another_block': len(dropped & later),
        })
        f6_total.extend(f6)
        lost_total.extend(lost)
    return {
        'blocks': per_block,
        'f6_total': len(f6_total),
        'f6_txids': sorted(set(f6_total)),
        'lost_on_both_total': len(lost_total),
        'lost_on_both_txids': sorted(set(lost_total)),
    }


def evaluate_post_reorg_state(chain, info, status, dropped, miner_chain=None,
                              expectations=None, on_chain=None):
    """Did the follower actually clear and prune after a reorg?

    Three separate questions, because hanging all of them off "is
    `bestOrdering` one of the dropped headers" let a stale chain
    RELABELLED with the new ordering id pass every one of them:

    * **keyed to the surviving branch** — `bestOrdering` is not a
      dropped header AND equals the node's own best full header, so a
      relabelled chain is caught by the mismatch rather than by the
      label;
    * **the tip is cleared or current** — `/info.bestInputBlock` is
      empty, or it is on the chain the node now publishes AND (when a
      reference chain for the same ordering id is available) on that
      too, so a tip from an abandoned tree cannot be excused by the
      node's own relabelled list;
    * **the abandoned trees are gone** — OBSERVED, not inferred: every
      entry of `status.retained_trees` (one per ordering id the node
      still holds state under) that keeps a TREE must be under an
      ordering id on the node's best chain (`on_chain`) and not under a
      dropped one. The counters alone could not establish this — `forks`
      is computed for the current ordering tip only
      (`ergo-node/src/node/input_blocks/runtime.rs::api_status`), so a
      completed tree under an abandoned id was invisible while every
      counter passed. Records without a tree under a dropped id are
      reported, not failed: records outlive their tree for
      `prune_threshold` ordering blocks by design (Scala `prune()`, spec
      2.5). The remaining counters are still checked, and a counter or
      list the route does not publish is unknown rather than zero.

    Pure: returns `{'problems': [...], 'observed': {...}}`.
    """
    expectations = expectations or {'forks': 1, 'waitlist': 0,
                                    'staged_bytes': 0, 'deferred_triggers': 0}
    dropped = set(dropped or ())
    problems = []
    best_ordering = chain.get('bestOrdering')
    listed = list(chain.get('bestInputBlocks') or [])
    tip = (info.get('bestInputBlock') or '') or None

    if best_ordering in dropped:
        problems.append({'what': 'chain_keyed_to_a_dropped_ordering_block',
                         'bestOrdering': best_ordering})
    node_best = info.get('bestFullHeaderId')
    if best_ordering and node_best and best_ordering != node_best:
        problems.append({'what': 'chain_ordering_id_is_not_the_node_best_header',
                         'bestOrdering': best_ordering, 'bestFullHeaderId': node_best})

    if tip is not None:
        if tip not in listed:
            problems.append({'what': 'tip_not_on_the_published_chain', 'tip': tip})
        elif miner_chain is None:
            # The node's own list can be relabelled, so it cannot vouch
            # for its own tip. With no miner chain for the same ordering
            # block to compare against, a stale tip relabelled with the
            # new id is indistinguishable from a current one — unknown,
            # which is not a pass.
            problems.append({'what': 'tip_not_compared_against_a_miner_chain',
                             'tip': tip})
        elif tip not in set(miner_chain):
            # The miner's list cannot be relabelled BY the node.
            problems.append({'what': 'tip_not_on_any_miner_chain_for_this_block',
                             'tip': tip})

    trees = status.get('retained_trees')
    abandoned_records = []
    if trees is None:
        problems.append({'what': 'counter_not_published', 'counter': 'retained_trees'})
    else:
        for entry in trees:
            oid = entry.get('ordering_id')
            off_chain = oid in dropped or (on_chain is not None and oid not in on_chain)
            if not off_chain:
                continue
            if entry.get('tree') or entry.get('forks'):
                problems.append({'what': 'tree_retained_under_an_off_chain_ordering_id',
                                 'ordering_id': oid, 'entry': entry,
                                 'dropped': oid in dropped})
            elif entry.get('records'):
                abandoned_records.append(entry)
        if on_chain is None and trees:
            problems.append({'what': 'retained_trees_not_compared_against_the_best_chain',
                             'ordering_ids': [t.get('ordering_id') for t in trees]})

    retained = {}
    for key, ceiling in expectations.items():
        value = status.get(key)
        retained[key] = {'value': value, 'at_most': ceiling}
        if value is None:
            problems.append({'what': 'counter_not_published', 'counter': key})
        elif value > ceiling:
            problems.append({'what': 'abandoned_state_retained', 'counter': key,
                             'value': value, 'at_most': ceiling})
    return {'problems': problems,
            'observed': {'bestOrdering': best_ordering, 'tip': tip,
                         'chain_length': len(listed), 'retained': retained,
                         'compared_against_a_miner_chain': miner_chain is not None,
                         'retained_trees': trees,
                         'records_under_off_chain_ordering_ids': abandoned_records}}


def reconcile_outcomes(ordering_blocks, events, announced=None, unread_heights=(),
                       adjacent_headers=()):
    """Every ordering block in the window must have exactly one outcome.

    By HEADER IDENTITY only. `ordering_blocks` maps height -> header id;
    `events` is the collected `ordering_*` stream. Height is never used
    to match: an outcome for a DIFFERENT header at the expected height
    used to satisfy the block (codex's r3 probe: `missing=[]`,
    `with_an_outcome=1`), which let a decision about some other block
    stand in for the one that was never reported.

    * `missing` — a window block with no outcome naming it. A block NOT
      in `announced` (the header ids the follower's log shows an
      announcement for) is `not_announced` instead: the node asks for an
      announced ordering block only when it does not hold the header
      (`ergo-node/src/node/input_blocks/dispatch.rs::handle_ordering_inv`),
      so a header that arrives first by ordinary sync is downloaded
      without a decision. `announced=None` attributes nothing.
    * `unmatched` — an outcome naming a header that is not a window
      block and not one of `adjacent_headers` (the best-chain headers
      just outside the window, which a watermark can legitimately
      straddle), or naming no header at all. Checked against the
      window's own header ids and the announcement set, never against an
      index built from the same events. Each is also marked with whether
      that header was ever announced. It FAILS.
    * A height the reference could not be read for is `missing`.
    """
    kinds = ('ordering_reconstructed', 'ordering_reconstruct_fallback',
             'ordering_reconstruct_skipped')
    window_headers = set(ordering_blocks.values())
    adjacent = set(adjacent_headers)
    by_header, unmatched, adjacent_outcomes = {}, [], 0
    for event in events:
        if event.get('kind') not in kinds:
            continue
        header = event.get('headerId') or event.get('header_id')
        if header in window_headers:
            by_header.setdefault(header, []).append(event['kind'])
        elif header in adjacent:
            adjacent_outcomes += 1
        else:
            unmatched.append({'kind': event['kind'], 'header': header,
                              'height': event.get('height'),
                              'announced': (None if announced is None
                                            else header in announced)})
    missing, duplicated, not_announced = [], [], []
    for height in sorted(unread_heights):
        missing.append({'height': height, 'header': None,
                        'why': 'the reference could not be read at this height'})
    for height, header in sorted(ordering_blocks.items()):
        outcomes = by_header.get(header) or []
        if not outcomes:
            if announced is not None and header not in announced:
                not_announced.append({'height': height, 'header': header})
            else:
                missing.append({'height': height, 'header': header})
        elif len(outcomes) > 1:
            duplicated.append({'height': height, 'header': header,
                               'outcomes': outcomes})
    blocks = len(ordering_blocks) + len(unread_heights)
    return {'blocks': blocks,
            'with_an_outcome': sum(1 for h in window_headers if by_header.get(h)),
            'missing': missing, 'duplicated': duplicated,
            'not_announced': not_announced,
            'announcement_evidence': announced is not None,
            'unmatched': unmatched,
            'unmatched_events': len(unmatched),
            'outcomes_for_adjacent_blocks': adjacent_outcomes}


ANNOUNCEMENT_LINE = 'input_blocks: raw announcement payload'


def announced_headers(log_text):
    """Header ids the follower logged an announcement payload for.

    `dispatch.rs::log_announcement_payload` writes one TRACE line per
    received announcement (input-block AND ordering-block, keyed by the
    announced id). Returns `None` when the log carries no such line at
    all: that is a log without the evidence (the TRACE target switched
    off), not a follower that was never announced anything, and treating
    it as the latter would excuse every missing outcome.
    """
    ids, any_line = set(), False
    for line in log_text.splitlines():
        if ANNOUNCEMENT_LINE not in line:
            continue
        any_line = True
        marker = 'block='
        i = line.find(marker)
        if i >= 0:
            ids.add(line[i + len(marker):i + len(marker) + 64])
    return ids if any_line else None


# ----- evict: delivery and causality (pure, self-tested) -----

BODIES_RECEIVED_LINE = 'input_blocks: bodies received'


def parse_pushed_bodies(stdout):
    """`[{'id', 'ordering'}]` from the adversary's `pushed id=… ordering=…`
    lines. `ordering` is the best ordering block the id sat under when it
    was pushed, or None when the adversary could not say."""
    out = []
    for line in stdout.splitlines():
        if '[wrong_body] pushed id=' not in line:
            continue
        fields = dict(part.split('=', 1) for part in line.split() if '=' in part)
        ordering = fields.get('ordering')
        out.append({'id': fields.get('id'),
                    'ordering': None if ordering in (None, 'none', 'relayed')
                    else ordering})
    return out


def wrong_body_receipts(log_lines, source_ip, pushed_ids):
    """The node's OWN receipt of a pushed body: a `bodies received` line
    from the adversary's source address naming a pushed id. What the
    adversary says it sent is not delivery; this is.

    Returns `{id: [line, ...]}` for every pushed id the node logged.
    """
    wanted = set(pushed_ids)
    out = {}
    for line in log_lines:
        if BODIES_RECEIVED_LINE not in line or f'peer={source_ip}:' not in line:
            continue
        i = line.find('block=')
        if i < 0:
            continue
        block = line[i + 6:i + 6 + 64]
        if block in wanted:
            out.setdefault(block, []).append(line)
    return out


EVICT_DESIGN_PROPERTY = (
    'the reconstruction fallback is NOT peer-forceable by design: a delivered '
    'code-104 body is placed only at a staging position whose ANNOUNCED weak id '
    'it matches (ergo-inputblocks/src/processor.rs::on_bodies), and a block is '
    'admitted only when the Merkle root over the selection\'s full transaction '
    'ids equals the announced digest (processor.rs::search_staging). A wrong '
    'body is placed nowhere, or fails the digest, and never reaches assembly; '
    'the only body that would pass both and still change the rebuilt root is '
    'the same transaction re-signed with a different valid witness whose '
    'witness id also matches the 3-byte weak-id half, which needs the '
    'spending key, not a peer')


def evict_verdict(pushed, receipts, mismatch_fallbacks):
    """The `evict` verdict. Pure, and it NEVER attributes a fallback to the
    adversary.

    Round 2 attributed any mismatch fallback under the ordering parent a
    body was pushed under, without proving that body entered the rebuild,
    so a NATURAL mismatch after an ignored decoy read as adversary-caused
    and bypassed the NOT ESTABLISHED gate. Given the design property
    (`EVICT_DESIGN_PROPERTY`), no fallback can be the adversary's: every
    mismatch fallback in the window is reported as natural.

    Returns `(failures, notes)`; `failures` is `[(message, evidence)]`.
    """
    notes = {'wrong_bodies_pushed': len(pushed),
             'receipts_logged_by_the_node': len(receipts),
             'mismatch_fallbacks_all_natural': len(mismatch_fallbacks),
             'design_property': EVICT_DESIGN_PROPERTY}
    if not pushed:
        return ([('the adversary pushed no wrong body at all, so the lever was not '
                  'applied', notes)], notes)
    if not receipts:
        return ([(f'the adversary pushed {len(pushed)} wrong bodies and the node '
                  'logged receipt of none of them from its address, so delivery '
                  'is not established', notes)], notes)
    return ([('NOT ESTABLISHED: the adversary\'s wrong bodies WERE delivered '
              f'({len(receipts)} receipts logged by the node) and cannot cause the '
              'fallback — ' + EVICT_DESIGN_PROPERTY + '. '
              + (f'{len(mismatch_fallbacks)} mismatch fallback(s) in the window are '
                 'natural and are not attributed to the adversary.'
                 if mismatch_fallbacks else 'No mismatch fallback occurred.'),
              notes)], notes)


# ----- §7.4 bounds -----

class PeakSampler:
    """Poll a node's §7.4 counters on their own thread and keep the PEAKS.

    Started BEFORE the traffic it is measuring and stopped after: the
    previous flood ran `subprocess.run` to completion and only then began
    sampling, so a structure that overflowed during delivery and drained
    before the adversary exited was never seen. The smoke sampler runs
    throughout but retains none of these counters.

    A counter the route never published stays `None` — UNKNOWN, not zero.
    Seeding every key with 0 is what let a missing `staged_bytes` merge
    into a passing measurement.
    """

    def __init__(self, keys, poll=0.2):
        self.keys = tuple(keys)
        self.poll = poll
        self.peaks = {key: None for key in self.keys}
        self.rss_peak = None
        self.samples = 0
        self.unavailable = 0
        self._stop = threading.Event()
        self._thread = None
        self._pid = None

    def _read_status(self):
        """One read of the §7.4 counters — the only part a probe replaces."""
        import campaign
        return campaign.input_block_status()

    def _observe(self):
        import campaign
        try:
            status = self._read_status()
        except Unavailable:
            self.unavailable += 1
            return
        self.samples += 1
        for key in self.keys:
            value = status.get(key)
            if value is None:
                continue
            current = self.peaks[key]
            self.peaks[key] = value if current is None else max(current, value)
        if self._pid is not None:
            rss = campaign.rss_kib(self._pid)
            if rss is not None:
                self.rss_peak = rss if self.rss_peak is None else max(
                    self.rss_peak, rss)

    def start(self, pid=None):
        self._pid = pid
        self._observe()          # one reading before any traffic
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def _loop(self):
        while not self._stop.is_set():
            self._observe()
            self._stop.wait(self.poll)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None
        self._observe()          # and one after
        return self

    def summary(self):
        return {'peaks': dict(self.peaks), 'rss_peak_kib': self.rss_peak,
                'samples': self.samples, 'unavailable_samples': self.unavailable,
                'measured': sorted(k for k, v in self.peaks.items() if v is not None),
                'never_published': sorted(
                    k for k, v in self.peaks.items() if v is None)}


def check_bounds(ctx, observed_peaks, caps, what, unavailable_bounds=()):
    """Every §7.4 counter the node publishes, against its cap.

    `observed_peaks` maps each counter to the PEAK observed across the
    whole measurement window, or `None` when the route never published
    it. `None` is a FAILURE: a bound nobody measured is not a bound that
    held, and merging a missing counter with a zero is how one passed.

    `unavailable_bounds` names the §7.4 bounds this route does not expose
    at all. They are recorded as unmeasured rather than quietly omitted,
    so the report can say which bounds the run actually covered.
    """
    observed = {}
    for key, cap in caps.items():
        value = observed_peaks.get(key)
        observed[key] = {'peak': value, 'cap': cap,
                         'status': 'unknown' if value is None else 'measured'}
        if value is None:
            ctx.fail(f'{what}: the node never published `{key}`, so its §7.4 '
                     'bound was not measured — unknown, not zero',
                     {'peaks': observed_peaks})
        elif cap is not None and value > cap:
            ctx.fail(f'{what}: `{key}` peaked at {value}, past its §7.4 cap {cap}',
                     {'peaks': observed_peaks})
    return {'checked': observed,
            'not_exposed_by_the_status_route': sorted(unavailable_bounds)}


# ----- reconstruction accounting (M4, spec §7a "honest denominators") -----
#
# The same five numbers from every node that makes the
# reconstruct-or-download decision, so a patched follower can be put
# beside a stock one and the difference read off. Stated as an explicit
# vocabulary rather than per-scenario ad-hoc tallies, because the
# findings drafts quote these names and two scenarios counting
# "fallbacks" differently would make the batch's numbers incomparable.
#
#   eligible_announcements  ordering announcements the node decided about
#   reconstructed           rebuilt from input-block bodies, root matched
#   download_missing_tx     fell back: an ingredient was missing
#   download_root_mismatch  fell back: the rebuild did not reproduce the root
#   skipped_no_chain        no rebuild attempted: no input chain to rebuild from
#
# `eligible_announcements` is the DENOMINATOR and is counted
# independently (Rust: every outcome event; Scala: its own
# "Processing ordering block announcement" line), so a node that
# reported no outcome for an announcement shows up as `unaccounted`
# rather than vanishing from the ratio.
ACCOUNTING_FIELDS = ('eligible_announcements', 'reconstructed',
                     'download_missing_tx', 'download_root_mismatch',
                     'skipped_no_chain',
                     # The GATE, which decides before the holder is ever
                     # asked: `ErgoNodeViewSynchronizer.scala:1856-1866`
                     # at 62c10315 requests the full block and never
                     # sends `ProcessOrderingBlock` when the previous
                     # input block's transactions are not stored. It is
                     # a download, and until M4 it was invisible.
                     'download_no_prev_input_block')

# The Rust event feed's own strings (`ergo-node` `reconstruct.rs`
# `MISSING_*`/`ROOT_MISMATCH`, `ergo-inputblocks` `NO_PREV_INPUT_BLOCK` /
# `NO_INPUT_CHAIN`). Matched exactly: a renamed reason must read as
# `other`, never be folded into a bucket it no longer belongs to.
RUST_MISSING_REASONS = ('missing_broadcasted_tx', 'missing_input_body')
RUST_ROOT_MISMATCH_REASONS = ('root_mismatch',)
RUST_SKIP_REASONS = ('no_prev_input_block', 'no_chain')

# The pinned Scala build's log lines for the same five outcomes
# (`ErgoNodeViewHolder.processOrderingBlock`, 62c10315 lines 431, 470,
# 476, 480, 490). Lower-cased substrings, so a wording change reads as
# "not found" rather than as a silent zero.
SCALA_PHRASES = {
    # `ErgoNodeViewSynchronizer.processOrderingBlockAnnouncement`
    # (62c10315): the ENTRY line, logged for every announcement that
    # survives the height-gap and already-known checks.
    'entry_announcements': 'processing ordering block announcement for',
    # `ErgoNodeViewHolder.processOrderingBlock` (62c10315):
    'reconstructed': 'applying block transactions from input-blocks for',
    'download_missing_tx': 'as not all the transactions available',
    'download_root_mismatch': 'as merkle root does not match',
    'skipped_no_chain': 'parent header not found for ordering block',
    # The GATE, `ErgoNodeViewSynchronizer.scala:1854/:1865`. Line 1854
    # precedes the branch; line 1865 requests the full block and the
    # holder never runs — which is why a stock follower that downloaded
    # 80 of 81 ordering blocks used to read as "none of the phrases
    # appears", i.e. UNKNOWN, when it was a measured 0 %.
    'gate_announcements': 'on processing ordering block',
    'download_no_prev_input_block': 'as prev input block not found',
}


def _empty_accounting(source, **extra):
    out = {field: 0 for field in ACCOUNTING_FIELDS}
    out['source'] = source
    out.update(extra)
    return out


def rust_accounting(events):
    """The five numbers from a window of the Rust node's event feed."""
    out = _empty_accounting('rust event feed')
    other = {}
    for event in events:
        kind = event.get('kind')
        detail = event.get('detail')
        if kind == 'ordering_reconstructed':
            out['reconstructed'] += 1
        elif kind == 'ordering_reconstruct_fallback':
            if detail in RUST_MISSING_REASONS:
                out['download_missing_tx'] += 1
            elif detail in RUST_ROOT_MISMATCH_REASONS:
                out['download_root_mismatch'] += 1
            else:
                # A storage error is a fallback, and it is NOT one of
                # the two the comparison is about; counting it as either
                # would misattribute it.
                other[f'fallback:{detail}'] = other.get(
                    f'fallback:{detail}', 0) + 1
        elif kind == 'ordering_reconstruct_skipped':
            if detail in RUST_SKIP_REASONS:
                out['skipped_no_chain'] += 1
            else:
                other[f'skipped:{detail}'] = other.get(
                    f'skipped:{detail}', 0) + 1
        else:
            continue
        # The denominator counts every outcome, INCLUDING the ones that
        # are none of the five: a storage-error fallback is an
        # announcement the node decided about, and dropping it would
        # flatter the ratio.
        out['eligible_announcements'] += 1
    out['other_outcomes'] = other
    return _with_ratio(out)


def scala_accounting(lines):
    """The six numbers from a window of a Scala node's log.

    The denominator is the SYNCHRONIZER's, not the holder's. At
    62c10315 an announcement passes three stages — the synchronizer's
    entry line, its gate at :1854, and only then
    `ErgoNodeViewHolder.processOrderingBlock` — and the gate at :1865
    requests the full block without the holder ever running. Counting
    the holder's phrases alone made a follower that downloaded 80 of 81
    ordering blocks look like a node that logged nothing at all.
    """
    out = _empty_accounting(
        'scala log (ErgoNodeViewSynchronizer gate :1854/:1865 and '
        'ErgoNodeViewHolder.processOrderingBlock, 62c10315)')
    for field in SCALA_PHRASES:
        out.setdefault(field, 0)
    for line in lines:
        low = line.lower()
        for field, phrase in SCALA_PHRASES.items():
            if phrase in low:
                out[field] += 1
    # Entry precedes the gate, which precedes the holder, and each
    # stage sees a subset of the one before. The largest is the honest
    # denominator, and one announcement is never counted twice.
    out['eligible_announcements'] = max(out['gate_announcements'],
                                        out['entry_announcements'])
    out['log_lines'] = len(lines)
    if not out['eligible_announcements'] and not any(
            out[f] for f in ACCOUNTING_FIELDS):
        # A build that logs none of them is UNKNOWN, not a run of
        # zeroes: the reference half of a ratio has to be measured.
        out['unmatched'] = (
            'none of the phrases appears in this node\'s log for the '
            'window; its reconstruction accounting is UNKNOWN, not zero')
    return _with_ratio(out)


def _with_ratio(out):
    """Add the derived ratio and the unaccounted remainder."""
    eligible = out['eligible_announcements']
    decided = (out['reconstructed'] + out['download_missing_tx']
               + out['download_root_mismatch'] + out['skipped_no_chain']
               # The gate's download branch is an OUTCOME, not a gap.
               + out.get('download_no_prev_input_block', 0))
    out['decided'] = decided
    # Announcements the node decided about but reported no outcome for.
    # Never silently dropped from the denominator.
    out['unaccounted'] = max(0, eligible - decided)
    out['reconstructed_ratio'] = (
        round(out['reconstructed'] / eligible, 4) if eligible else None)
    return out


def _scala_log_lines(node):
    path = smoke.WORK / f'{node}.log'
    try:
        return path.read_text(errors='replace').splitlines()
    except OSError:
        return []


def open_measurement_window(ctx, collector):
    """Open ONE measurement boundary for every half of the accounting.

    The Rust half is a watermarked event collector; the Scala half is a
    log file. They were opened independently, so the Rust numbers covered
    the scenario's window while the Scala numbers covered the node's
    whole lifetime — start-up, wallet initialisation and funding
    included. Announcements decided before the window opened then
    appeared in one accounting and not the other, and a scenario that
    sampled the best chain from here on compared it against blocks
    applied long before.

    Returns the per-node line offsets, which the scenario records as
    evidence: a window has to be quotable, not merely applied.
    """
    collector.poll()
    ctx.collector = collector
    ctx.collector_watermark = collector.highest_seen
    ctx.scala_log_offsets = {
        node: len(_scala_log_lines(node))
        for node in (ctx.roles or {}) if node != 'rust'}
    return ctx.scala_log_offsets


def scala_window_lines(ctx, node):
    """One Scala node's log lines SINCE the measurement window opened.

    Without a window the whole log is returned — every caller then says
    so in its own evidence rather than presenting a node's lifetime as a
    measured interval.
    """
    offset = (getattr(ctx, 'scala_log_offsets', None) or {}).get(node, 0)
    return _scala_log_lines(node)[offset:]


def reconstruction_accounting(ctx):
    """The five numbers for every node in a run, keyed by ROLE.

    Called by the driver at finalization, so every scenario's evidence
    carries them. The node logs are already scenario-scoped (the driver
    rotates them before the nodes start), so the whole live log IS this
    scenario's window.

    The Rust half prefers a scenario's own incremental collector, whose
    completeness is known; without one it reads the feed once and SAYS
    the window may be incomplete rather than presenting a post-hoc read
    as a measurement.
    """
    out = {'fields': list(ACCOUNTING_FIELDS)}
    offsets = getattr(ctx, 'scala_log_offsets', None) or {}
    for node, role in (ctx.roles or {}).items():
        if node == 'rust':
            collector, watermark = ctx.collector, ctx.collector_watermark
            if collector is not None:
                entry = rust_accounting(collector.window(watermark))
                entry['collection'] = collector.summary(watermark)
                entry['complete'] = not collector.lost_in_window(watermark)
            else:
                try:
                    events = rust_events(ctx)
                except Unavailable as error:
                    out[role] = {'node': node,
                                 'unavailable': f'{error}'}
                    continue
                entry = rust_accounting(events)
                entry['collection'] = {
                    'mode': 'single post-hoc read of a BOUNDED ring',
                    'caveat': 'entries evicted before this read are not '
                              'counted; the scenario kept no incremental '
                              'collector, so completeness is unknown'}
                entry['complete'] = None
        else:
            offset = offsets.get(node, 0)
            entry = scala_accounting(_scala_log_lines(node)[offset:])
            entry['from_line'] = offset
            entry['interval'] = (
                'the measurement window the scenario opened, the same '
                'boundary the Rust event watermark was taken at'
                if node in offsets else
                'the node\'s WHOLE log: this scenario opened no measurement '
                'window, so the interval includes start-up and funding and '
                'is not the one the Rust half covers')
        entry['node'] = node
        out[role] = entry
    return out
