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


def seed_second_miner(ctx, campaign, lifecycle):
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
    """
    lifecycle.stop(('scala',))
    source = ctx.data_root / 'scala'
    target = ctx.data_root / 'scala2'
    shutil.rmtree(target, ignore_errors=True)
    shutil.copytree(source, target)
    shutil.rmtree(target / 'wallet', ignore_errors=True)
    campaign.ensure_data_dirs(ctx.data_root, ['scala2'])
    lifecycle.spawn('scala')
    ctx.run.started('scala')
    lifecycle.init_wallet('scala')
    lifecycle.spawn('scala2')
    ctx.run.started('scala2')
    lifecycle.init_wallet('scala2')
    # The follower has been dialling miner 2 since it started, and miner
    # 2 was not there — so it is several failures into an exponential
    # dial backoff (30 s, 2 min, 10 min, …) that outlasts the scenario.
    # Restarting it clears that: it comes back with no backoff state and
    # dials both miners at once. Its data directory is untouched, so it
    # resumes on the chain it already had.
    lifecycle.stop(('rust',))
    lifecycle.spawn('rust')
    ctx.run.started('rust')
    # Reported, never raised: a seed that came up but did not peer is a
    # scenario that cannot run, and the evidence has to say which of the
    # two it was rather than dying with a stack trace that says neither.
    try:
        lifecycle.wait_peered(names=['scala', 'scala2', 'rust'], timeout=120)
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
    connected = _wait_for_peer_count(ctx, 'rust', 2)
    ctx.note('follower_peers_after_seed', connected)
    heights = {}
    for node in ('scala', 'scala2'):
        try:
            heights[node] = (api(node, '/info') or {}).get('fullHeight')
        except Unavailable:
            heights[node] = None
    ctx.note('second_miner_seeded', {
        'copied_from': str(source), 'to': str(target),
        'wallet_copied': False,
        'heights_after_seed': heights,
        'why': 'the reference node cannot hand the chain to a second Scala '
               'node on this host; see the docstring',
    })
    if heights.get('scala2') is None:
        ctx.fail('the second miner did not come up on the copied chain, so the '
                 'scenario has no second miner', {'heights': heights})
    return heights


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

    def poll(self):
        try:
            feed = api(self.node, '/api/v1/events')
        except Unavailable:
            self.failed_polls += 1
            return self
        self.polls += 1
        page = feed.get('events') or []
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
    out, previous = [], None
    for i, sample in enumerate(series):
        ordering = sample.get('ordering')
        chain = set(sample.get(f'{side}_chain') or [])
        if ordering is None:
            previous = None
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
                                sample.get(f'{side}_chain') or [])})
        previous = (ordering, chain)
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

    A switch is judged as a pair of sets. The blocks it APPLIED must all
    belong to the chain of the reference it landed on, the blocks it
    ROLLED BACK must all be absent from that chain, and the resulting
    chain must be coherent with it — the same history, not merely the
    same members. A follower that rolled its chain back to nothing while
    both miners kept theirs satisfies "every applied block was
    published" trivially and is exactly the regression this has to
    catch.
    """
    # The chain each reference held under each ordering id, last first.
    seen = {}
    for i, sample in enumerate(series):
        for node, ref_ordering, chain in reference_chains(sample):
            if ref_ordering is not None:
                seen.setdefault((node, ref_ordering), []).append((i, chain))

    rust = fork_switches(series, 'rust')
    unmatched, rolled_back_still_held = [], []
    for switch in rust:
        ordering = switch['ordering']
        after = switch.get('chain_after') or []
        applied, rolled_back = set(switch['applied']), set(switch['rolled_back'])
        landed_on = None
        for node in REFERENCE_NODES:
            for j, chain in seen.get((node, ordering), ()):
                if j < switch['index'] - LATER_CONFIRMATION_SAMPLES:
                    continue
                if j > switch['index'] + LATER_CONFIRMATION_SAMPLES:
                    break
                members = set(chain)
                coherent, _ = _is_coherent_with(after, chain)
                if coherent and applied <= members and not (rolled_back & members):
                    landed_on = {'node': node, 'sample': j}
                    break
            if landed_on:
                break
        if landed_on is None:
            unmatched.append({**switch, 'chain_after': after[:8]})
        for block in switch['rolled_back']:
            for node in REFERENCE_NODES:
                held = seen.get((node, ordering), ())
                if held and block in set(held[-1][1]):
                    rolled_back_still_held.append({**switch, 'block': block,
                                                   'node': node})
                    break
    return {
        'rust_switches': rust,
        'scala_switches': fork_switches(series, 'scala'),
        'scala2_switches': fork_switches(series, 'scala2'),
        # THE guard: a switch whose applied and rolled-back sets do not
        # match any reference's chain under the same ordering block.
        'switches_matching_no_reference': unmatched,
        # Telemetry with two miners that cannot peer with each other:
        # each keeps its own fork, so a legitimate switch necessarily
        # rolls back blocks the other is still holding.
        'rolled_back_blocks_still_held_by_a_miner': rolled_back_still_held,
        'single_miner_series': not any(s.get('scala2_chain') for s in series),
    }


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
    * **F6** — dropped and not back in RUST's pool, and never confirmed
      by ANY other ordering block in the window. This is the reference
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
    per_block, f6_total, lost_total = [], [], []
    for i, block in enumerate(blocks):
        dropped = set(block['input_chain_txids']) - set(block['ordering_txids'])
        later = confirmed_elsewhere.get(i, set())
        f6 = sorted(dropped - set(block['rust_pool']) - later)
        lost = sorted(dropped - set(block['rust_pool'])
                      - set(block['scala_pool']) - later)
        per_block.append({
            'height': block.get('height'),
            'ordering_block': block.get('ordering_block'),
            'input_chain_txs': len(block['input_chain_txids']),
            'dropped': len(dropped),
            'f6': f6,
            'lost_on_both': lost,
            'returned_to_rust_pool': len(dropped & set(block['rust_pool'])),
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

    def _observe(self):
        import campaign
        try:
            status = campaign.input_block_status()
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
