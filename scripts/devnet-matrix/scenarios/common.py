"""Shared scenario helpers.

Everything decisive here is PURE and exercised by `campaign.py
--self-test`: a scenario that computed its own verdict from live REST
calls could not be shown to fail when it should, and an evaluator that
cannot fail is not an evaluator.
"""
import re
import shutil
import threading
import time
import urllib.error

import smoke
from smoke import Unavailable, api, api_retry


def wait_ordering_blocks(ctx, blocks, what, on_block=None):
    """Let the sampler run while Scala mines `blocks` ordering blocks.

    `on_block`, if given, is called once each time the miner's height
    rises, so a workload keeps pace with the chain inside the wait.

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
            now = smoke.scala_height(ctx.run)
            if on_block is not None and now > reached:
                on_block()
            reached = now
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


def drop_copied_peer_db(target):
    """Remove the peer database a seeded Scala node copied from the miner.

    Scala's PeerManager seeds from `scorex.network.knownPeers` ONLY when
    its database is empty (`PeerManager.scala:24-33` at 62c10315). The
    miner's database holds the peers the MINER knows, which never
    includes the miner itself, so a follower that kept the copy never
    learned the miner's address and dialled the Rust node alone. Gossip
    cannot fill that gap, because PeerManager refuses local addresses
    from peers (`:53`, `:67`). With the database gone, the node's own
    rendered `knownPeers` (every other node) is what it starts from.
    """
    shutil.rmtree(target / 'peers', ignore_errors=True)


def seeded_nodes_missing(heights, unavailable):
    """The seeded nodes that did not come up: the ones that did not ANSWER.

    A node at genesis answers `/info` with `fullHeight: null`, and
    `steady`/`restart` seed before the first block, so a null height is
    a node that is up on an empty chain, not a missing one.
    """
    return [node for node in heights if node in set(unavailable)]


def seed_second_miner(ctx, campaign, lifecycle, nodes=('scala2',)):
    """Give miner 2 the chain by COPYING miner 1's data directory.

    The reference node cannot hand it over in time. Two Scala MINERS on
    one host never connect here — `getPeerAddress` refuses to resolve a
    same-address peer without a UPnP gateway, and `allowLocal = false`
    refuses a loopback one (only the follower roles set it; see
    `campaign.CAMPAIGN_P2P_HOST`) — so a second miner brought up cold
    sits at genesis indefinitely and,
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
    for a reason that has nothing to do with input blocks. The Rust
    follower is stopped with it, first, because the stop also discards
    miner 1's in-memory input blocks; a snapshot of miner 1's chain and
    process is taken just before (`reference_snapshots`).

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
    # What miner 1's process holds right before the stop, so a chain that
    # only that process ever published can still be traced to it.
    ctx.evidence.setdefault('reference_snapshots', []).append(
        reference_snapshot('scala'))
    # Miner 1's input-block tree lives only in memory (Scala
    # `InputBlocksProcessor.inputBlockTrees`), so this stop forgets every
    # input block it published under the current ordering block. A
    # follower still running across it keeps them as its best chain: a
    # history no running miner has and no sample can have recorded
    # (rm-B-fork-stockctl-1). So the follower goes down WITH the miner,
    # and first; `restart_follower` then finds it stopped.
    lifecycle.stop(('rust', 'scala'))
    source = ctx.data_root / 'scala'
    targets = []
    for node in nodes:
        target = ctx.data_root / node
        shutil.rmtree(target, ignore_errors=True)
        shutil.copytree(source, target)
        shutil.rmtree(target / 'wallet', ignore_errors=True)
        drop_copied_peer_db(target)
        targets.append(target)
    campaign.ensure_data_dirs(ctx.data_root, list(nodes))
    lifecycle.spawn('scala')
    ctx.run.started('scala')
    lifecycle.init_wallet('scala')
    for node in nodes:
        lifecycle.spawn(node)
        ctx.run.started(node)
        lifecycle.init_wallet(node)
    # The follower has been dialling the seeded nodes since it started,
    # and they were not there — so it is several failures into an
    # exponential dial backoff (30 s, 2 min, 10 min, …) that outlasts the
    # scenario. It is restarted to clear that, AND its address book is
    # deleted: the backoff windows are persisted there
    # (`ergo_node::node::util::wall_to_instant` restores them), so a
    # restart alone brings the same backoff back. Measured on the first
    # `--reference-follower both` validation run — the follower came back
    # and immediately logged "peer bootstrap starved: no dial candidates
    # (all known addresses in dial-backoff)", held the miner and neither
    # follower, and the run produced 0 follower samples. The purge costs
    # nothing: every node it needs is in the config's `known` list. See
    # `restart_follower`, which purges between the stop and the respawn.
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
    heights, unavailable = {}, []
    for node in ('scala', *nodes):
        try:
            heights[node] = (api(node, '/info') or {}).get('fullHeight')
        except Unavailable:
            heights[node] = None
            unavailable.append(node)
    ctx.note('second_miner_seeded', {
        'copied_from': str(source), 'to': [str(t) for t in targets],
        'wallet_copied': False,
        'heights_after_seed': heights,
        'unavailable_after_seed': unavailable,
        'why': 'the reference node cannot hand the chain to a second Scala '
               'node on this host; see the docstring',
    })
    missing = seeded_nodes_missing({n: heights.get(n) for n in nodes},
                                   unavailable)
    if missing:
        ctx.fail(f'{", ".join(missing)} did not come up on the copied chain, so '
                 'the scenario is missing a node it was told to run',
                 {'heights': heights, 'seeded': list(nodes)})
    return heights


def reference_snapshot(node):
    """One node's input chain, ordering id and process, read now. Never
    raises: a node that did not answer is recorded as such."""
    snapshot = {'node': node, 'at': time.time()}
    try:
        info = api(node, '/info') or {}
        chain = api(node, '/blocks/bestInputChain') or {}
    except Unavailable as error:
        snapshot['unavailable'] = str(error)
        return snapshot
    snapshot.update(launch=info.get('launchTime'),
                    ordering=chain.get('bestOrdering') or None,
                    chain=chain.get('bestInputBlocks') or [])
    return snapshot


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


# The workload every measurement window needs. ONE implementation:
# `reconstruct_rate` and `miner_self_reject` each carried a verbatim
# copy, so Task 2's fix for a workload whose payments were mutually
# exclusive landed in one of them and not the other — and the two
# measurements they feed are read against each other.
PAYMENT_NANOERG = 1_000_000


# The funding wait's budget, derived from the chain rather than fixed.
# The miner's coinbase is spendable once `minerRewardDelay` blocks have
# passed (`genesis.conf` `monetary.minerRewardDelay = 10`, mirrored by
# the Rust `devnet_miner_reward_delay`), and the wallet reports it a
# block or two later. Ordering-block cadence on this host varies about
# 5x with load, so a fixed 900 s either wastes a quiet evening or fails
# a busy one (`.work-r1both2`: height 11, balance 0, 900 s gone).
MINER_REWARD_DELAY = 10
FUNDING_TARGET_HEIGHT = MINER_REWARD_DELAY + 3
# Before the wait has seen two blocks: a conservative per-block prior
# (the recipe measures ~40 s per ordering block on a quiet host).
FUNDING_CADENCE_PRIOR_S = 60.0
FUNDING_SAFETY = 3.0
FUNDING_SLACK_S = 120.0
# This far past the target with nothing to spend, the wallet (not the
# cadence) is the problem, and waiting longer measures nothing.
FUNDING_OVERRUN_BLOCKS = 10


def funding_deadline(observations):
    """`(deadline, rule)` for the funding wait, from the heights it saw.

    `observations` is `[(monotonic_time, height), ...]`, the first entry
    taken when the wait began and one more each time the height rose.
    Rule: cadence = seconds per block over the observed span (the prior
    until two heights are seen); deadline = time of the LAST height seen
    + max(1, blocks still to the target) x cadence x SAFETY + SLACK. The
    budget therefore restarts with every block, so a live chain is never
    abandoned before maturity, and a stall ends the wait after SAFETY
    times the cadence it had. Past target + OVERRUN blocks it ends at
    once. Pure, so the self-test pins it.
    """
    first_t, first_h = observations[0]
    last_t, last_h = observations[-1]
    cadence = ((last_t - first_t) / (last_h - first_h)
               if last_h > first_h else FUNDING_CADENCE_PRIOR_S)
    to_go = max(0, FUNDING_TARGET_HEIGHT - last_h)
    rule = {'cadence_s': round(cadence, 3), 'height': last_h,
            'target_height': FUNDING_TARGET_HEIGHT, 'blocks_to_go': to_go,
            'safety': FUNDING_SAFETY, 'slack_s': FUNDING_SLACK_S,
            'overrun': last_h >= FUNDING_TARGET_HEIGHT + FUNDING_OVERRUN_BLOCKS,
            'rule': 'deadline = last block seen + max(1, blocks to target) '
                    'x measured s/block x safety + slack; ends at once '
                    'past target + overrun blocks'}
    if rule['overrun']:
        return last_t, rule
    return last_t + max(1, to_go) * cadence * FUNDING_SAFETY + FUNDING_SLACK_S, rule


def fund_miner(ctx, node='scala'):
    """`(balance_nano, address)` for the miner whose blocks carry the load.

    An unfunded chain seals coinbase-only input blocks: the reconstruction
    succeeds without ever exercising the lookup key, and the candidate is
    never replaced by an arriving transaction. Either way the window
    measures the quiet case and says nothing about the finding.

    The wait is budgeted by `funding_deadline` from the cadence it
    observes, and the rule, cadence and outcome are noted as evidence.
    Short is RETURNED, never raised: the caller decides what an unfunded
    window means for its own measurement.
    """
    def height():
        try:
            return int((api(node, '/info') or {}).get('fullHeight') or 0)
        except (Unavailable, TypeError, ValueError):
            return None

    began = time.monotonic()
    observations = [(began, height() or 0)]
    deadline, rule = funding_deadline(observations)
    balance = 0
    while time.monotonic() < min(ctx.run.deadline, deadline):
        try:
            balance = (api(node, '/wallet/balances') or {}).get('balance') or 0
        except Unavailable:
            balance = 0
        if balance:
            break
        now_h = height()
        if now_h is not None and now_h > observations[-1][1]:
            observations.append((time.monotonic(), now_h))
            deadline, rule = funding_deadline(observations)
        ctx.run.idle(1)
    rule = dict(rule, waited_s=round(time.monotonic() - began, 1),
                funded=bool(balance), heights_seen=len(observations),
                start_height=observations[0][1],
                ended_by=('balance' if balance else
                          'overrun' if rule['overrun'] else
                          'run deadline' if time.monotonic() >= ctx.run.deadline
                          else 'cadence budget'))
    ctx.note('funding_wait', rule)
    address = (api_retry(node, '/wallet/addresses', ctx.run.deadline,
                         what=f'the {node} miner wallet address') or [None])[0]
    return balance, address


def pump_payments(ctx, address, sent, node='scala', count=3,
                  value=PAYMENT_NANOERG, rejected=None):
    """Submit `count` self-payments, appending the accepted txids.

    A submission the node refused is recorded rather than dropped: a
    window whose workload never landed is a window that measured the
    quiet case, and the evidence has to be able to say so.
    """
    for _ in range(count):
        try:
            status, txid = smoke.request(
                node, '/wallet/payment/send', [{'address': address,
                                                'value': value}])
        except (OSError, ValueError) as error:
            if rejected is not None:
                rejected.append(f'{type(error).__name__}: {error}')
            continue
        if status == 200 and txid:
            sent.append(txid)
        elif rejected is not None:
            rejected.append(f'HTTP {status}: {txid!r}')
    return sent


def _post(node, path, body=None):
    """`(status, payload)` for one POST (a GET without `body`), with an
    HTTP error's body kept."""
    try:
        return smoke.request(node, path, body)
    except urllib.error.HTTPError as error:
        try:
            detail = error.read().decode(errors='replace')[:300]
        except OSError:
            detail = ''
        return error.code, detail
    except (OSError, ValueError) as error:
        return None, f'{type(error).__name__}: {error}'


# The fee `/wallet/payment/send` adds to every payment (the Scala wallet's
# `defaultTransactionFee`). `/wallet/transaction/generate` adds a fee
# output only when the request names one (`RequestsHolder.withFee`), and a
# payment without one is never mined.
PAYMENT_FEE_NANOERG = 1_000_000


# The fork window's payment POOL: boxes split off one matured coinbase and
# confirmed BEFORE the second miner is seeded, so each lies in both miners'
# history. Each payment spends one pool box, so it is valid on either
# miner's chain whatever the other one did. The wallet's own box choice
# is not: after the first reorg between the two miners it keeps spending
# change that exists only in orphaned input blocks, and every later
# payment is refused ("Every input of the transaction should be in
# UTXO": 33 of 72 in rm-B-fork-2562f-3, 57 of 72 in rm-B-fork-stockctl-3).
FANOUT_VALUE_NANOERG = 100_000_000
# Pool boxes beyond one window's worth, for refused or lost payments.
FANOUT_SPARE_BLOCKS = 10
# Ordering blocks the split may take to confirm before the run gives up.
FANOUT_CONFIRM_BLOCKS = 6


def fan_out(ctx, address, node, count, value=FANOUT_VALUE_NANOERG,
            fee=PAYMENT_FEE_NANOERG):
    """Split `node`'s wallet into `count` boxes of `value` and wait until
    the split is in its UTXO set. Returns the new boxes' ids (the pool),
    or [] with the reason recorded as a failure."""
    status, tx = _post(node, '/wallet/transaction/generate',
                       {'requests': [{'address': address, 'value': value}] * count,
                        'fee': fee})
    if status != 200 or not isinstance(tx, dict) or not tx.get('id'):
        ctx.fail(f'the payment pool split could not be signed: HTTP {status}',
                 {'answer': str(tx)[:500]})
        return []
    code, answer = _post(node, '/transactions', tx)
    if code != 200:
        ctx.fail(f'the payment pool split was refused: HTTP {code}',
                 {'answer': str(answer)[:500]})
        return []
    boxes = [out['boxId'] for out in tx.get('outputs') or []
             if out.get('value') == value][:count]
    heights, confirmed = [], False
    while time.monotonic() < ctx.run.deadline and boxes:
        code, _ = _post(node, f'/utxo/byId/{boxes[0]}')
        if code == 200:
            confirmed = True
            break
        try:
            heights.append((api(node, '/info') or {}).get('fullHeight') or 0)
        except Unavailable:
            pass
        if len(set(heights)) > FANOUT_CONFIRM_BLOCKS:
            break
        ctx.run.idle(1)
    ctx.note('payment_pool_split', {
        'tx': tx['id'], 'boxes': len(boxes), 'value_nano': value,
        'confirmed': confirmed, 'heights_waited': sorted(set(heights))})
    if not confirmed:
        ctx.fail('the payment pool split was not confirmed within '
                 f'{FANOUT_CONFIRM_BLOCKS} ordering blocks', {'tx': tx['id']})
        return []
    return boxes


def pump_payments_to_all(ctx, address, sent, nodes, count=3,
                         value=PAYMENT_NANOERG, rejected=None, forwarded=None,
                         fee=PAYMENT_FEE_NANOERG, pool=None):
    """`pump_payments` for a run with more than one miner: every payment
    reaches EVERY miner's mempool directly.

    The first node's wallet signs each payment, with the same fee
    `/wallet/payment/send` would add (`/wallet/transaction/generate`, which
    does not submit it), and the same signed transaction is posted to
    `/transactions` on every node in `nodes`, the signing node first so its
    wallet sees the spend before it signs the next payment. Gossip does not
    carry it between miners
    reliably: a Scala node requests a transaction inv only while its
    full-block height equals its header height and its best header is not
    behind its peers' (`ErgoNodeViewSynchronizer.processInv`,
    `txAcceptanceFilter`), which a miner racing another miner's chain
    often is not. In rm-B-fork-stockctl-1 the second miner never held a
    payment, won 22 of the window's 26 blocks, and the window carried no
    transaction at all.

    With a `pool` (`fan_out`), each payment spends exactly one pool box,
    taken in order and never reused; a box the signing node no longer has
    is skipped and recorded.

    `sent` gets the ids the signing node accepted; `forwarded` counts,
    per other node, how each post was answered.
    """
    for _ in range(count):
        request = {'requests': [{'address': address, 'value': value}],
                   'fee': fee}
        if pool is not None:
            raw = None
            while pool and raw is None:
                box = pool.pop(0)
                code, answer = _post(nodes[0], f'/utxo/byIdBinary/{box}')
                if code == 200 and isinstance(answer, dict) and answer.get('bytes'):
                    raw = answer['bytes']
                elif rejected is not None:
                    rejected.append(f'pool box {box}: HTTP {code}')
            if raw is None:
                if rejected is not None:
                    rejected.append('the payment pool is exhausted')
                continue
            request['inputsRaw'] = [raw]
        status, tx = _post(nodes[0], '/wallet/transaction/generate', request)
        if status != 200 or not isinstance(tx, dict) or not tx.get('id'):
            if rejected is not None:
                rejected.append(f'generate: HTTP {status}: {str(tx)[:200]}')
            continue
        for index, node in enumerate(nodes):
            code, answer = _post(node, '/transactions', tx)
            if index == 0:
                if code == 200:
                    sent.append(tx['id'])
                else:
                    if rejected is not None:
                        rejected.append(f'{node} /transactions: HTTP {code}: '
                                        f'{str(answer)[:200]}')
                    break
            elif forwarded is not None:
                outcome = 'accepted' if code == 200 else f'HTTP {code}'
                counts = forwarded.setdefault(node, {})
                counts[outcome] = counts.get(outcome, 0) + 1
    return sent


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

    def window(self, after_seq, until_seq=None):
        """Every collected event in `(after_seq, until_seq]`, in order.

        `until_seq` is the window's CLOSE (`close_measurement_window`);
        without it the window runs to whatever was collected last.
        """
        return [self.events[s] for s in sorted(self.events)
                if s > after_seq and (until_seq is None or s <= until_seq)]

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


# The extension key under which an ordering block names the input block
# its committed input chain ends at (weak-blocks `Extension.PrevInputBlockIdKey`,
# `InputBlocksDataPrefix` 0x03 then 0x02). The committed chain is a
# prefix, possibly empty, of the chain ending there.
NAMED_INPUT_TIP_KEY = '0302'


def ordering_blocks_between(node, low, high):
    """Every ordering block `node` holds at heights `[low, high]`: its id,
    parent, rank at its height (0 = best), the input tip it names and its
    transaction count. Returns `(blocks, unread_heights)`.

    Read while the nodes are up, because the named tip lives only in the
    block's extension. A block whose body `node` cannot serve (a losing
    fork's header) is kept with `unread`, never dropped.
    """
    blocks, unread = [], []
    for height in range(low, high + 1):
        try:
            ids = api(node, f'/blocks/at/{height}') or []
        except Unavailable:
            unread.append(height)
            continue
        for rank, header_id in enumerate(ids):
            try:
                block = api(node, f'/blocks/{header_id}') or {}
            except Unavailable as error:
                blocks.append({'height': height, 'id': header_id,
                               'rank': rank, 'unread': str(error)})
                continue
            fields = {k: v for k, v in
                      (block.get('extension') or {}).get('fields') or []}
            blocks.append({
                'height': height, 'id': header_id, 'rank': rank,
                'parent': (block.get('header') or {}).get('parentId'),
                'named_input_tip': fields.get(NAMED_INPUT_TIP_KEY),
                'transactions': len((block.get('blockTransactions') or {})
                                    .get('transactions') or [])})
    return blocks, unread


NAMED_TIP_CLASSES = ('equal', 'held_more', 'held_less', 'other_branch',
                     'held_nothing', 'names_nothing', 'not_sampled',
                     'named_chain_unknown', 'unread')


def named_tip_vs_held(ordering_blocks, series, followers):
    """Per follower: how each ordering block's NAMED input tip compares
    with the input chain the follower held under the block's parent. Pure.

    The held chain is the follower's `<node>_chain` (newest first) at the
    LAST sample in which its `<node>_ordering` was the block's parent. The
    classes, one per (block, follower):

    * `equal`: the follower's tip is the named tip;
    * `held_more`: the named tip is `depth` >= 1 blocks below the
      follower's tip, so the follower held input blocks this ordering
      block did not commit (the #2562 case: a held chain that outruns the
      commitment);
    * `held_less`: the follower's tip is `depth` >= 1 blocks below the
      named tip;
    * `other_branch`: the two tips are on different branches;
    * `held_nothing`: the follower held no chain under the parent;
    * `names_nothing`: the block names no input tip;
    * `not_sampled`: the follower was never sampled on the parent;
    * `named_chain_unknown`: the named tip is not on the held chain, and
      no sample of any node carried the chain below it;
    * `unread`: the block's body could not be read.

    It compares the NAMED tip only. A miner names its latest input block
    but commits only the bodies it processed, so a block can commit fewer
    blocks than it names; that is not visible here, and `held_more` is
    therefore a LOWER bound on "committed a shorter prefix than held".
    """
    held, ancestry = {}, {}
    for sample in series:
        for key, chain in sample.items():
            if not key.endswith('_chain') or not chain:
                continue
            for index, block in enumerate(chain):
                # The longest chain seen below each block wins.
                if len(chain) - index > len(ancestry.get(block, ())):
                    ancestry[block] = chain[index:]
        for node in followers:
            ordering = sample.get(f'{node}_ordering')
            if ordering:
                held[(node, ordering)] = sample.get(f'{node}_chain') or []
    out = {}
    for node in followers:
        counts = {cls: 0 for cls in NAMED_TIP_CLASSES}
        rows = []
        for block in ordering_blocks:
            named = block.get('named_input_tip')
            if block.get('unread'):
                cls, depth = 'unread', None
            elif not named:
                cls, depth = 'names_nothing', None
            elif (node, block.get('parent')) not in held:
                cls, depth = 'not_sampled', None
            else:
                chain = held[(node, block['parent'])]
                below_named = ancestry.get(named)
                if not chain:
                    cls, depth = 'held_nothing', None
                elif chain[0] == named:
                    cls, depth = 'equal', 0
                elif named in chain:
                    cls, depth = 'held_more', chain.index(named)
                elif below_named is None:
                    cls, depth = 'named_chain_unknown', None
                elif chain[0] in below_named:
                    cls, depth = 'held_less', below_named.index(chain[0])
                else:
                    cls, depth = 'other_branch', None
            counts[cls] += 1
            rows.append({'height': block.get('height'), 'id': block.get('id'),
                         'rank': block.get('rank'), 'class': cls,
                         'depth': depth})
        depths = sorted(r['depth'] for r in rows if r['class'] == 'held_more')
        out[node] = {'counts': counts, 'blocks': len(rows),
                     'held_more_depths': depths, 'rows': rows}
    return out


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


def _millis(value):
    return value if type(value) in (int, float) else None



# The Scala nodes whose later chains can confirm a lead: the miners and
# the Scala reference follower, which validated what it holds.
SCALA_CHAIN_NODES = ('scala', 'scala2', 'scala3')


# Every input block a Scala miner's log says it mined; one definition,
# `smoke`'s, which the single-miner assertions use too.
mined_input_blocks = smoke.mined_input_blocks


def later_prefix_holder(chain, at, series):
    """A Scala node that, at sample `at` or later inside the window, held
    `chain` (newest first) as a prefix of its own chain, under ANY
    ordering id, or None. Pure. Any ordering id, because a node's read
    route can pair a new ordering id with the previous chain (F15/D8, the
    scala3 stale read)."""
    wanted = list(reversed(chain))
    for j in range(at, min(len(series), at + LATER_CONFIRMATION_SAMPLES + 1)):
        for node in SCALA_CHAIN_NODES:
            held = list(reversed(series[j].get(f'{node}_chain') or []))
            if wanted and held[:len(wanted)] == wanted:
                return {'node': node, 'sample': j}
    return None


def miner_moved_on(series, miner, ordering, chain, at):
    """How `miner` left the history `chain` (newest first) under
    `ordering` at sample `at` or later inside the window, or None. Pure.

    It LEFT the ordering block (its own ordering id changed), or it
    SWITCHED forks under it: its chain there is neither a prefix of
    `chain` nor extends it, read oldest-first. A chain that is still a
    prefix of `chain` (a miner read before it processed the lead) is
    neither.
    """
    wanted = list(reversed(chain))
    for j in range(at, min(len(series), at + LATER_CONFIRMATION_SAMPLES + 1)):
        sample = series[j]
        now = sample.get(f'{miner}_ordering')
        if now and now != ordering:
            return {'how': 'left_ordering_block', 'sample': j, 'to': now}
        held = list(reversed(sample.get(f'{miner}_chain') or []))
        if (now == ordering and held and held[:len(wanted)] != wanted
                and wanted[:len(held)] != held):
            return {'how': 'switched_fork', 'sample': j}
    return None


def miner_held_tip(series, miner, ordering, tip, at):
    """Was `miner` sampled holding a chain that ends at `tip` under
    `ordering`, inside the window up to sample `at`? Pure. A miner mines
    on its own tip, so this is what puts a block it mined on top of the
    chain ending at `tip`."""
    for j in range(max(0, at - LATER_CONFIRMATION_SAMPLES), at + 1):
        sample = series[j]
        if (sample.get(f'{miner}_ordering') == ordering
                and (sample.get(f'{miner}_chain') or [None])[0] == tip):
            return True
    return False


def lead_confirmation(node, ordering, chain, at, carried, series, evidence=None):
    """Why the one-block lead `chain[0]` over reference `node`'s chain
    (`chain` minus its tip) under `ordering` is a real block:
    `(kind, detail)`, or None. Pure.

    In order:

    * `reference_later`: that reference lists it later under the same
      ordering id;
    * `later_prefix`: a miner or the Scala reference follower later holds
      the whole of `chain` as a prefix, under any ordering id;
    * `named_tip`: an ordering block whose parent is `ordering` names it
      as its committed input tip (extension key `0302`);
    * `orphaned_lead`: a miner's log says it mined it, and that miner then
      left `ordering` or switched forks under it inside the window, so the
      block was orphaned before any sample could list it. Reported as
      such, never passed silently.

    The last two prove the block is real but not that it sits on the
    rest of `chain`, so both also require that the miner whose log says
    it mined the block was sampled holding `chain[1:]`'s tip under
    `ordering` (`miner_held_tip`). Without that, a chain stitching one
    miner's real block onto the other's chain would pass.

    `evidence` carries `named` (`{(parent, tip)}`) and `mined_by`
    (`{block: miner node}`). A lead none of these confirms stays
    unconfirmed (rm-B-fork-stockctl-4: one lead of each of the last two
    kinds).
    """
    lead = chain[0]
    if any(at < j <= at + LATER_CONFIRMATION_SAMPLES
           for j in carried.get((node, ordering, lead), ())):
        return ('reference_later', None)
    holder = later_prefix_holder(chain, at, series)
    if holder is not None:
        return ('later_prefix', holder)
    evidence = evidence or {}
    miner = (evidence.get('mined_by') or {}).get(lead)
    if (miner is None or len(chain) < 2
            or not miner_held_tip(series, miner, ordering, chain[1], at)):
        return None
    if (ordering, lead) in (evidence.get('named') or ()):
        return ('named_tip', {'miner': miner})
    moved = miner_moved_on(series, miner, ordering, chain, at)
    if moved is not None:
        return ('orphaned_lead', dict(moved, miner=miner))
    return None


def held_from_restarted_reference(rust_chain, ordering, launch, snapshots):
    """The snapshot a follower chain was held from, or None. Pure.

    Only on positive evidence: a snapshot taken from a reference process
    that has since been replaced (its `launchTime` in this sample differs
    from the snapshot's) shows that process holding this history under
    this ordering block, and the follower's own process is older than the
    snapshot, so it could have received it from there. A reference that
    restarts forgets its in-memory input blocks; a follower that kept
    running holds them as its best chain (rm-B-fork-stockctl-1).
    """
    follower = _millis((launch or {}).get('rust'))
    for snapshot in snapshots or ():
        chain = snapshot.get('chain') or []
        was, now = (_millis(snapshot.get('launch')),
                    _millis((launch or {}).get(snapshot.get('node'))))
        if (snapshot.get('ordering') != ordering or not chain or was is None
                or now is None or now == was or follower is None
                or follower > snapshot.get('at', 0) * 1000):
            continue
        coherent, lead = _is_coherent_with(rust_chain, chain)
        if coherent and lead is None:
            return {'node': snapshot['node'], 'snapshot_at': snapshot.get('at'),
                    'snapshot_launch': was, 'launch_at_sample': now}
    return None


def evaluate_fork_coherence(series, snapshots=(), evidence=None):
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

    A chain that matches nothing in the series is still traced before it
    is called incoherent: if `snapshots` (`reference_snapshots`, taken
    just before the harness restarted a reference) show that a replaced
    reference process held exactly this history, the sample is reported
    under `held_from_restarted_reference` instead
    (`held_from_restarted_reference()` states the rule). Nothing else is
    exempt, and every incoherent sample names the references that
    restarted after the follower started. A one-block lead is confirmed
    only by evidence the block is real (`lead_confirmation()`), and the
    evidence used is counted by kind.
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

    incoherent, unconfirmed_leads, held, judged = [], [], [], 0
    lead_confirmations, orphaned = {}, []
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
            confirmed = lead_confirmation(node, ordering, rust_chain, i,
                                          published, series, evidence)
            if confirmed is not None:
                kind, detail = confirmed
                lead_confirmations[kind] = lead_confirmations.get(kind, 0) + 1
                if kind == 'orphaned_lead':
                    orphaned.append({'sample': i, 'ordering': ordering,
                                     'block': lead, 'reference': node, **detail})
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
            entry = {
                'sample': i, 'ordering': ordering,
                'rust_chain': rust_chain[:8],
                'references_at_this_sample': {node: chain[:8]
                                              for node, chain in at_sample},
                'references_compared': len(peers),
                'window': LATER_CONFIRMATION_SAMPLES,
            }
            launch = sample.get('launch') or {}
            source = held_from_restarted_reference(rust_chain, ordering,
                                                   launch, snapshots)
            if source is not None:
                # Attributed, and reported: the history is one a reference
                # process demonstrably held before it was restarted.
                held.append(dict(entry, held_from=source))
                continue
            follower = _millis(launch.get('rust'))
            entry['references_restarted_since_follower_start'] = [
                node for node in REFERENCE_NODES
                if follower is not None and (_millis(launch.get(node)) or 0)
                > follower]
            incoherent.append(entry)
    return {
        'judged_samples': judged,
        'incoherent_samples': incoherent,
        'unconfirmed_one_block_leads': unconfirmed_leads,
        'held_from_restarted_reference': held,
        'lead_confirmations': lead_confirmations,
        # Leads confirmed only because their miner then left the ordering
        # block or switched forks: real blocks, orphaned. Listed, not hidden.
        'orphaned_leads': orphaned,
        'later_confirmation_samples': LATER_CONFIRMATION_SAMPLES,
    }


def compare_fork_switches(series, evidence=None):
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

    * the chain it left matches a chain some reference published, and
    * the chain it landed on matches a chain some reference published,

    where "matches" is the history rule below.

    A transition to the EMPTY chain is reported separately, as a reset:
    no reference publishes an empty chain, so there is no transition to
    match it against, and a follower that has just restarted produces
    one legitimately. The caller says whether it caused the reset.

    Each end is matched on HISTORY by the coherence rule,
    `_is_coherent_with`: it is a reference's chain, a prefix of one read
    oldest-first, or one block ahead of one with that block confirmed by
    the same reference within the window. So "the follower moved from one
    miner's history to another miner's history" is the only shape that
    passes, which is what a two-miner fork switch IS. A follower that
    invented a block, or stitched two branches, matches nothing.

    Not only the exact list, because the sampler cannot see every length
    a chain passes through: a miner sealing an input block every half
    second grows between two sweeps, and a follower read later in the
    same sweep can hold a length the miner was never sampled at
    (rm-B-fork-2562f-3: the follower left miner 1's 18-block chain, and
    miner 1 was sampled at 17 and then 19). Each match says which kind it
    was, the exact list preferred.

    A transition that applies nothing (the new chain a strict prefix of
    the old one) is a TRUNCATION, reported on its own: it is not a move
    to another history, and a prefix of a published chain must not pass
    as one.
    """
    # Every chain each reference published under each ordering id.
    seen = {}
    for i, sample in enumerate(series):
        for node, ref_ordering, chain in reference_chains(sample):
            if ref_ordering is not None:
                seen.setdefault(ref_ordering, []).append((i, node, list(chain)))

    # Where each reference published each block, per ordering id, so a
    # one-block lead can be confirmed by the reference it led.
    carried = {}
    for i, sample in enumerate(series):
        for node, ref_ordering, chain in reference_chains(sample):
            if ref_ordering is not None:
                for block in chain:
                    carried.setdefault((node, ref_ordering, block), []).append(i)

    rank = {'exact': 0, 'prefix': 1, 'one_ahead_confirmed': 2}

    def published(ordering, chain, at):
        """How a reference published `chain` near sample `at`, by the
        coherence rule (see above), or None."""
        best = None
        for j, node, ref_chain in seen.get(ordering, ()):
            if abs(j - at) > LATER_CONFIRMATION_SAMPLES or not chain:
                continue
            coherent, lead = _is_coherent_with(chain, ref_chain)
            if not coherent:
                continue
            if lead is None:
                kind = 'exact' if ref_chain == list(chain) else 'prefix'
            elif lead_confirmation(node, ordering, list(chain), at, carried,
                                   series, evidence) is not None:
                kind = 'one_ahead_confirmed'
            else:
                continue
            if best is None or rank[kind] < rank[best['match']]:
                best = {'node': node, 'sample': j, 'match': kind}
                if kind == 'exact':
                    return best
        return best

    rust = fork_switches(series, 'rust')
    unmatched, resets, rolled_back_still_held, matched = [], [], [], []
    truncations = []
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
        elif (not switch['applied'] and len(after) < len(before)
              and list(reversed(before))[:len(after)] == list(reversed(after))):
            # Rolled back, applied nothing: the chain it landed on is a
            # strict prefix of the one it left. Not a move to another
            # history, whatever a reference published.
            truncations.append(entry)
        elif left is None or landed is None:
            unmatched.append(entry)
        else:
            matched.append({'index': switch['index'], 'ordering': ordering,
                            'left_a_reference_chain': left,
                            'landed_on_a_reference_chain': landed})
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
        # Every other non-reset switch, with how each end matched.
        'matched_switches': matched,
        # Transitions that rolled back and applied nothing.
        'truncations': truncations,
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

    Pure, so the gate itself can be driven by a probe. Four rules:

    * a reset to the empty chain OUTSIDE the restart the scenario
      performs fails — no miner publishes an empty chain;
    * a non-reset switch that is not a transition between two chains a
      reference published fails;
    * a truncation (rolled back, applied nothing) fails;
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
    truncations = comparison.get('truncations') or []
    truncated = {t['index'] for t in truncations}
    caused = [r for r in resets if r['index'] in restart_window]
    uncaused = [r for r in resets if r['index'] not in restart_window]
    genuine = [s for s in comparison['rust_switches']
               if s['index'] not in reset_indices and s['index'] not in truncated]
    failures, qualifier = [], None
    if uncaused:
        failures.append((
            f'{len(uncaused)} times the follower emptied its input chain outside '
            'the restart this scenario performs — no miner publishes an empty '
            'chain, so that is a chain nobody has', {'sample': uncaused[:5]}))
    if truncations:
        failures.append((
            f'{len(truncations)} times the follower truncated its input chain: '
            'it rolled back blocks and applied none, so the chain it landed on '
            'is a strict prefix of the one it left rather than another history',
            {'sample': truncations[:5]}))
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
                       adjacent_headers=(), known_first=()):
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
    * `known_before_announcement` — a window block with no outcome whose
      announcement the follower dropped because it already held the
      header (`known_first`, from `header_known_first`): by the same
      rule, downloaded by ordinary sync with no decision to report. An
      announced block without that drop and without an outcome is still
      `missing`.
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
    missing, duplicated, not_announced, known_before = [], [], [], []
    known_first = set(known_first or ())
    for height in sorted(unread_heights):
        missing.append({'height': height, 'header': None,
                        'why': 'the reference could not be read at this height'})
    for height, header in sorted(ordering_blocks.items()):
        outcomes = by_header.get(header) or []
        if not outcomes:
            if announced is not None and header not in announced:
                not_announced.append({'height': height, 'header': header})
            elif header in known_first:
                known_before.append({'height': height, 'header': header})
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
            'known_before_announcement': known_before,
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


HEADER_KNOWN_DROP = 'reason=OrderingHeaderKnown'


def header_known_first(log_text):
    """Ordering ids the follower dropped an announcement for because it
    already held the header (`ergo-inputblocks` `DropReason::
    OrderingHeaderKnown`, Scala parity: spec 9.3). Pure. Such a header
    came by ordinary sync first, and no reconstruct-or-download decision
    follows the announcement."""
    ids = set()
    for line in log_text.splitlines():
        if HEADER_KNOWN_DROP not in line:
            continue
        i = line.find('dropped id=')
        if i >= 0:
            ids.add(line[i + len('dropped id='):i + len('dropped id=') + 64])
    return ids


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


# The stages that announce an ordering block, and the outcomes that
# decide it. Kept apart so an id is eligible once however many stages
# (or peers) mention it, and decided once however many times it is
# decided.
SCALA_STAGES = ('entry_announcements', 'gate_announcements')
SCALA_OUTCOMES = ('reconstructed', 'download_missing_tx',
                  'download_root_mismatch', 'skipped_no_chain',
                  'download_no_prev_input_block')

# The ordering-block id every phrase above carries: after "for"
# ("… announcement for <id>", "… fully for <id> as …", "… transactions
# for <id> as …") or after "block" ("On processing ordering block <id>,",
# "… for ordering block <id>, …"). The FIRST such token is the ordering
# block; a later one ("last input block Some(<id>)", "requesting parent
# <id>") never is.
_SCALA_ID = re.compile(r'\b(?:for|block)\s+([0-9a-f]{2,64})\b')


def scala_decisions(lines):
    """Every ordering block a Scala node's log mentions, ONCE per id.

    A follower peered with more than one node hears each announcement
    from every peer, and the holder repeats the synchronizer's entry
    phrase when the announcement reaches it: `.work-r1peer2`'s scala2
    log carries 42 entry lines for 18 ordering blocks. Counting lines
    made the accounting read 41 eligible and 20 unaccounted.

    Returns `(ids, raw, lines_without_id)`: `ids` maps each id, in first
    appearance order, to the stages it passed and the outcomes it was
    given in log order; `raw` is the per-phrase LINE count, kept as
    evidence of the duplication.
    """
    ids, raw, without_id = {}, {field: 0 for field in SCALA_PHRASES}, 0
    for line in lines:
        low = line.lower()
        for field, phrase in SCALA_PHRASES.items():
            if phrase not in low:
                continue
            raw[field] += 1
            match = _SCALA_ID.search(low)
            if match is None:
                # A line that names no id cannot be merged with anything,
                # so it stands for one announcement of its own.
                without_id += 1
                key = f'<no id #{without_id}>'
            else:
                key = match.group(1)
            entry = ids.setdefault(key, {'stages': set(), 'outcomes': []})
            if field in SCALA_OUTCOMES:
                entry['outcomes'].append(field)
            else:
                entry['stages'].add(field)
    return ids, raw, without_id


def scala_accounting(lines):
    """The six numbers from a window of a Scala node's log, per ID.

    The denominator is the SYNCHRONIZER's, not the holder's. At
    62c10315 an announcement passes three stages — the synchronizer's
    entry line, its gate at :1854, and only then
    `ErgoNodeViewHolder.processOrderingBlock` — and the gate at :1865
    requests the full block without the holder ever running. Counting
    the holder's phrases alone made a follower that downloaded 80 of 81
    ordering blocks look like a node that logged nothing at all.

    Every count is of distinct ordering-block ids (`scala_decisions`).
    An id's outcome is its FIRST decision; a repeat of the same decision
    is counted in `repeat_decisions` and a different later decision is
    named in `conflicting_outcomes`, neither added to a bucket.
    """
    out = _empty_accounting(
        'scala log (ErgoNodeViewSynchronizer gate :1854/:1865 and '
        'ErgoNodeViewHolder.processOrderingBlock, 62c10315), '
        'de-duplicated by ordering-block id')
    for field in SCALA_PHRASES:
        out.setdefault(field, 0)
    ids, raw, without_id = scala_decisions(lines)
    repeats, conflicts = 0, {}
    for key, entry in ids.items():
        for stage in entry['stages']:
            out[stage] += 1
        outcomes = entry['outcomes']
        if outcomes:
            out[outcomes[0]] += 1
            repeats += len(outcomes) - 1
            distinct = list(dict.fromkeys(outcomes))
            if len(distinct) > 1:
                conflicts[key] = distinct
    # Every id any stage or outcome names is one eligible announcement:
    # entry precedes the gate, which precedes the holder, and an id is
    # never counted twice.
    out['eligible_announcements'] = len(ids)
    out['raw_line_counts'] = raw
    out['repeat_decisions'] = repeats
    out['conflicting_outcomes'] = conflicts
    out['lines_without_id'] = without_id
    out['log_lines'] = len(lines)
    if not out['eligible_announcements'] and not any(
            out[f] for f in ACCOUNTING_FIELDS):
        # A build that logs none of them is UNKNOWN, not a run of
        # zeroes: the reference half of a ratio has to be measured.
        out['unmatched'] = (
            'none of the phrases appears in this node\'s log for the '
            'window; its reconstruction accounting is UNKNOWN, not zero')
    return _with_ratio(out)


# The waitlist, per ordering block (REVIEW-2563 §3.3 item 6). At
# a1bd938ef `InputBlocksProcessor.scala:901` logs INFO
# `Put input block to disconnected queue: <id>` for every input block
# whose parent the tree does not hold, and returns that parent for a
# download (`ErgoNodeViewHolder` -> `DownloadInputBlock`, whose own line
# is DEBUG) — so each insertion is one parent request as well: the
# round-trip rebuild the pending store exists to remove. The synchronizer's
# `+2` branch logs `On processing <id>, downloading its parent and
# unknown ordering block <parent>` when it asks a peer for the ordering
# block a root announcement names (`:1594`).
WAITLIST_PHRASE = 'put input block to disconnected queue:'
ROOT_PARENT_DOWNLOAD_PHRASE = 'downloading its parent and unknown ordering block'
_WAITLIST_ID = re.compile(r'disconnected queue:\s*([0-9a-f]{2,64})')


def scala_waitlist(lines):
    """Waitlist insertions per ordering block, from one Scala log. Pure.

    The Scala log carries no timestamps, so an insertion is attributed
    to the ordering block whose announcement (the synchronizer's entry
    line, first sighting of its id) precedes it in the log — the period
    in which the node was assembling that block's successor tree.
    Insertions before the first announcement in the window are counted
    as `before_first_ordering_block`, not dropped.
    """
    periods, current, before = [], None, 0
    seen_ordering = set()
    insertions, distinct, root_parent_downloads = 0, set(), 0
    entry = SCALA_PHRASES['entry_announcements']
    for line in lines:
        low = line.lower()
        if entry in low:
            match = _SCALA_ID.search(low)
            key = match.group(1) if match else None
            if key not in seen_ordering:
                seen_ordering.add(key)
                current = {'ordering': key, 'insertions': 0}
                periods.append(current)
            continue
        if ROOT_PARENT_DOWNLOAD_PHRASE in low:
            root_parent_downloads += 1
            continue
        if WAITLIST_PHRASE not in low:
            continue
        insertions += 1
        match = _WAITLIST_ID.search(low)
        if match:
            distinct.add(match.group(1))
        if current is None:
            before += 1
        else:
            current['insertions'] += 1
    per_block = sorted(p['insertions'] for p in periods)
    return {
        'source': 'scala log: InputBlocksProcessor "Put input block to '
                  'disconnected queue" (INFO), split at each ordering-block '
                  'announcement',
        'insertions': insertions,
        'distinct_input_blocks': len(distinct),
        'ordering_blocks': len(periods),
        'before_first_ordering_block': before,
        'per_ordering_block': {
            'p50': smoke.percentile(per_block, 50) if per_block else None,
            'p95': smoke.percentile(per_block, 95) if per_block else None,
            'max': per_block[-1] if per_block else None,
            'mean': (round(sum(per_block) / len(per_block), 3)
                     if per_block else None),
            'blocks_with_any': sum(1 for n in per_block if n),
        },
        'root_parent_downloads': root_parent_downloads,
    }


def scala_root_announcements(lines):
    """Root (`+2`) announcements a Scala follower saw, and how many later
    became a valid sub-block on it (REVIEW-2563 §3.5 "root held vs
    dropped"). Pure; `flood.evaluate_root_flood` with no adversary, so a
    steady or restart run reads the same way a flood window does. On a
    stock build a root that lands was fetched on demand; on a build with
    the pending store it may have been replayed from it.
    """
    from . import flood
    verdict = flood.evaluate_root_flood(lines, [], flood.ROOT_FLOOD_CAPS, ())
    return {key: verdict[key] for key in (
        'honest_roots', 'honest_roots_landed', 'honest_penalties',
        'honest_misbehaviour_penalties',
        'honest_misbehaviour_after_double_application')}


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


def close_measurement_window(ctx):
    """Close the window for EVERY half at one point, once.

    The opening boundary was shared, the closing one was not: the Rust
    event collection stopped where the scenario stopped polling, while
    the Scala logs were read at finalisation, after the peering and
    agreement checks had run, so a Scala follower's accounting covered
    decisions the Rust half never had a chance to make (`.work-r1both3`:
    14 vs 15 Scala decisions from the same start offset). The snapshot
    is the event sequence seen at the close plus every Scala log's line
    count; every later read stops there. Idempotent: a second call
    returns the first snapshot, never a later one.
    """
    snapshot = getattr(ctx, 'measurement_close', None)
    if snapshot is not None:
        return snapshot
    collector = getattr(ctx, 'collector', None)
    if collector is not None:
        collector.poll()
    offsets = getattr(ctx, 'scala_log_offsets', None) or {}
    snapshot = {
        'rust_event_seq': collector.highest_seen if collector is not None
                          else None,
        'scala_log_lines': {node: len(_scala_log_lines(node))
                            for node in offsets},
    }
    ctx.measurement_close = snapshot
    return snapshot


def _scala_window_bounds(ctx, node):
    offset = (getattr(ctx, 'scala_log_offsets', None) or {}).get(node, 0)
    close = getattr(ctx, 'measurement_close', None) or {}
    return offset, (close.get('scala_log_lines') or {}).get(node)


def scala_window_lines(ctx, node):
    """One Scala node's log lines INSIDE the measurement window.

    From the opening offset to the closing snapshot when the window was
    closed. Without a window the whole log is returned — every caller
    then says so in its own evidence rather than presenting a node's
    lifetime as a measured interval.
    """
    offset, end = _scala_window_bounds(ctx, node)
    return _scala_log_lines(node)[offset:end]


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
    # A window that was opened is closed HERE if its scenario did not
    # close it (an early failure), and every half reads up to the same
    # snapshot either way.
    close = (close_measurement_window(ctx) if offsets or
             getattr(ctx, 'collector', None) is not None else None)
    out['closing_boundary'] = close
    for node, role in (ctx.roles or {}).items():
        if node == 'rust':
            collector, watermark = ctx.collector, ctx.collector_watermark
            if collector is not None:
                entry = rust_accounting(collector.window(
                    watermark, (close or {}).get('rust_event_seq')))
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
            offset, end = _scala_window_bounds(ctx, node)
            window = scala_window_lines(ctx, node)
            entry = scala_accounting(window)
            # Over the same window as the five numbers.
            entry['waitlist'] = scala_waitlist(window)
            entry['root_announcements'] = scala_root_announcements(window)
            entry['from_line'] = offset
            entry['to_line'] = end
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
