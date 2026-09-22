"""Shared scenario helpers.

Everything decisive here is PURE and exercised by `campaign.py
--self-test`: a scenario that computed its own verdict from live REST
calls could not be shown to fail when it should, and an evaluator that
cannot fail is not an evaluator.
"""
import shutil
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
    start = smoke.scala_height(ctx.run)
    target = start + blocks
    reached = start
    while time.monotonic() < ctx.run.deadline:
        try:
            reached = smoke.scala_height(ctx.run)
        except Unavailable:
            pass
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
    connected = _wait_for_peer_count(ctx, 'rust', 2)
    ctx.note('follower_peers_after_seed', connected)
    if connected < 2:
        ctx.fail('the follower did not connect to BOTH miners, so it cannot see '
                 'the competing chains this scenario exists to produce',
                 {'connected': connected})
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
                            'rolled_back': sorted(rolled_back)})
        previous = (ordering, chain)
    return out


def reference_chain(sample):
    """Every input block ANY reference node listed in this sample.

    With two miners the follower may legitimately be on either one's
    input chain, so judging it against miner 1 alone reports the whole of
    miner 2's chain as blocks "no miner ever had" — 21,546 of them in one
    run, none of them a divergence. The union is the comparison the
    two-miner scenarios actually mean.
    """
    return set(sample.get('scala_chain') or []) | set(
        sample.get('scala2_chain') or [])


def compare_fork_switches(series):
    """Did Rust's fork switches agree with the miner's?

    Instant-by-instant equality is not the property — the follower learns
    of a switch after the miner makes it — so each Rust switch is judged
    against everything Scala was EVER seen holding for the same ordering
    block:

    * a block Rust APPLIED that Scala never listed under that ordering id
      is a chain Scala does not have. That is the D3 sibling-completion
      guard: completing a sibling must never manufacture a chain the
      miner has no counterpart for.
    * a block Rust ROLLED BACK that Scala still held on its LAST sample
      for that ordering id is a switch Scala did not make.

    Both are divergences. Everything else is lag.
    """
    scala_ever, scala_last = {}, {}
    for sample in series:
        ordering = sample.get('ordering')
        if ordering is None:
            continue
        chain = reference_chain(sample)
        scala_ever.setdefault(ordering, set()).update(chain)
        scala_last[ordering] = chain
    rust = fork_switches(series, 'rust')
    unmatched_applied, unmatched_rollback = [], []
    for switch in rust:
        ordering = switch['ordering']
        for block in switch['applied']:
            if block not in scala_ever.get(ordering, set()):
                unmatched_applied.append({**switch, 'block': block})
        for block in switch['rolled_back']:
            if block in scala_last.get(ordering, set()):
                unmatched_rollback.append({**switch, 'block': block})
    return {
        'rust_switches': rust,
        'scala_switches': fork_switches(series, 'scala'),
        'applied_blocks_scala_never_had': unmatched_applied,
        'rolled_back_blocks_scala_kept': unmatched_rollback,
    }


def chain_members_scala_never_had(series):
    """Blocks on Rust's input chain that Scala never listed under the
    same ordering block.

    The whole-chain companion to `evaluate_tip_consistency`'s tip check:
    a sibling completed into the middle of a chain would never be a tip
    and so would never be caught there.
    """
    scala_ever = {}
    for sample in series:
        ordering = sample.get('ordering')
        if ordering is None:
            continue
        scala_ever.setdefault(ordering, set()).update(reference_chain(sample))
    orphans = []
    for i, sample in enumerate(series):
        ordering = sample.get('ordering')
        if ordering is None:
            continue
        for block in sample.get('rust_chain') or []:
            if block not in scala_ever.get(ordering, set()):
                orphans.append({'index': i, 'ordering': ordering, 'block': block})
    return orphans


# ----- §7.4 bounds -----

def check_bounds(ctx, status, caps, what):
    """Every §7.4 counter the node publishes, against its cap.

    A counter the node does NOT publish is a failure, not a pass: a
    bound nobody measured is not a bound that held.
    """
    observed = {}
    for key, cap in caps.items():
        value = status.get(key)
        observed[key] = {'value': value, 'cap': cap}
        if value is None:
            ctx.fail(f'{what}: the node publishes no `{key}`, so its §7.4 bound '
                     'could not be checked', {'status': status})
        elif cap is not None and value > cap:
            ctx.fail(f'{what}: `{key}` = {value} exceeds its §7.4 cap {cap}',
                     {'status': status})
    return observed
