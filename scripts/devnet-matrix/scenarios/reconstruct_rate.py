"""How often the follower rebuilds an ordering block from input bodies.

This is the measurement of F5. Scala keys an ordering block's input-block
tree by the ANNOUNCED HEADER'S OWN id, so a follower that collected the
tree under the parent's id cannot find it when the block arrives and
falls back to a full download. The rate is the size of the problem.

Both sides are reported: Rust's `ordering_reconstructed` vs
`ordering_reconstruct_fallback` events, and the Scala node's own log
lines for the same choice ("Applying block transactions from
input-blocks" vs "Downloading block transactions fully"), so the port's
rate is stated beside the reference's rather than on its own.
"""
import re
import time

import lifecycle
import smoke
from smoke import Unavailable, api, api_retry

from . import common

NODES = ('scala', 'scala2', 'rust')
ORDERING_BLOCKS = 100
PAYMENTS_PER_BLOCK = 3
PAYMENT_NANOERG = 1_000_000

# The reference FOLLOWER. The reference MINER never makes this decision:
# it generates its blocks locally (`LocallyGeneratedOrderingBlock`), so
# `processOrderingBlock` — the only place either log line is emitted —
# never runs on it. A first run against the miner's log found neither
# phrase and correctly reported the reference side as UNKNOWN; this is
# what makes it knowable.
SCALA2_EXTRA = (
    'ergo.node.mining = false\n'
    'ergo.node.offlineGeneration = false\n'
)

# The reference follower is SEEDED from the miner's data directory
# rather than started cold with the others. Started cold it sat at
# genesis for the whole window and logged no decision at all — two Scala
# nodes cannot dial each other on one host (`getPeerAddress` resolves a
# same-address peer through a UPnP gateway that does not exist), so its
# only possible source is the Rust follower, and it does not ask. With
# the chain already on disk it processes the ordering announcements the
# follower relays, which is where both log lines are emitted.
START_NODES = ('scala', 'rust')
# Seeded from the miner's directory rather than started cold; see above.
# `scala3` is `--reference-follower both`'s second slot and is skipped
# when it is not in the running node set.
SEEDED_NODES = ('scala2', 'scala3')

# Three nodes share 127.0.0.1, and the follower's per-IP admission limit
# is 1 — it gates outbound dial SELECTION as well as inbound admission,
# so without this it holds exactly one of the two Scala nodes and the
# scenario measures nothing. Raised only here; `flood`, which does test
# admission, keeps the default.
RUST_OVERRIDES = (
    ('peers', 'per_ip_limit', '3'),
    ('peers', 'per_subnet_limit', '6'),
)

# The pinned Scala build's two log lines for the same decision. Matched
# loosely (case-insensitive substrings) because a wording change must
# show up as "not found", not as a silent zero.
SCALA_RECONSTRUCTED = 'block transactions from input-blocks'
# TWO download sites, not one. `ErgoNodeViewHolder` logs "Downloading
# block transactions fully …" only for a block that REACHED it; at
# 62c10315 `ErgoNodeViewSynchronizer.scala:1865` requests the full block
# first, whenever the previous input block's transactions are not
# stored, and the holder never runs. Task 2 measured a stock follower
# that took the synchronizer's branch 80 times in 81 announcements and
# the holder's none: with only the holder's phrase the reference half of
# the F5 ratio read as UNKNOWN when it was in fact a measured 0 %.
SCALA_FALLBACK = 'downloading block transactions fully'
SCALA_FALLBACK_GATE = 'as prev input block not found'


def _scala_log_counts(ctx, node='scala2', since_line=0):
    """Count a reference node's reconstruct-vs-download lines.

    Read from the reference FOLLOWER by default, and only from
    `since_line` onwards: counting the whole log compares the port's
    bounded 100-block window against the reference's entire lifetime,
    which is not the same experiment.

    A log that contains NEITHER phrase is reported as unmatched rather
    than as 0/0: the reference's rate is the comparison, and a comparison
    against a phrase the build never logs is not one.
    """
    path = smoke.WORK / f'{node}.log'
    if not path.exists():
        return {'error': f'no Scala log at {path}'}
    lines = path.read_text(errors='replace').splitlines()[since_line:]
    reconstructed = fallback = fallback_gate = 0
    for line in lines:
        low = line.lower()
        if SCALA_RECONSTRUCTED in low:
            reconstructed += 1
        elif SCALA_FALLBACK in low:
            fallback += 1
        elif SCALA_FALLBACK_GATE in low:
            fallback_gate += 1
    fallback += fallback_gate
    decided = reconstructed + fallback
    out = {'node': node, 'reconstructed': reconstructed, 'fallback': fallback,
           'decided': decided,
           'reconstructed_ratio': round(reconstructed / decided, 4) if decided else None,
           'fallback_at_gate': fallback_gate,
           'phrases': [SCALA_RECONSTRUCTED, SCALA_FALLBACK,
                       SCALA_FALLBACK_GATE],
           'window_lines': len(lines), 'from_line': since_line,
           'source': ('ErgoNodeViewHolder.processOrderingBlock:468 '
                      '(reconstruct) and :475/:479 (download), plus the '
                      'ErgoNodeViewSynchronizer:1865 gate that downloads '
                      'without ever reaching the holder, at the pin')}
    if decided == 0:
        out['unmatched'] = (
            'none of the phrases appears in the pinned build\'s log; the Scala '
            'side of the ratio is UNKNOWN, not zero')
        # Whatever the build does log about input blocks, so the report
        # can name the real phrases.
        out['input_block_log_sample'] = [
            line for line in lines
            if re.search(r'input.?block', line, re.I)][-20:]
    return out


def _log_length(node):
    path = smoke.WORK / f'{node}.log'
    try:
        return len(path.read_text(errors='replace').splitlines())
    except OSError:
        return 0


def _fund(ctx):
    """A spendable coin and an address, so the ordering blocks in the
    window CARRY input-chain transactions.

    On an unfunded chain every block is coinbase-only, the input chain
    contributes nothing, and a reconstruction succeeds without
    distinguishing the lookup keys at all — a 100 % rate that says
    nothing about F5.
    """
    deadline = min(ctx.run.deadline, time.monotonic() + 900)
    balance = 0
    while time.monotonic() < deadline:
        try:
            balance = (api('scala', '/wallet/balances') or {}).get('balance') or 0
        except Unavailable:
            balance = 0
        if balance:
            break
        ctx.run.idle(1)
    address = (api_retry('scala', '/wallet/addresses', ctx.run.deadline,
                         what='the miner wallet address') or [None])[0]
    return balance, address


def _pump(ctx, address, sent):
    for _ in range(PAYMENTS_PER_BLOCK):
        try:
            status, txid = smoke.request(
                'scala', '/wallet/payment/send',
                [{'address': address, 'value': PAYMENT_NANOERG}])
        except (OSError, ValueError):
            continue
        if status == 200 and txid:
            sent.append(txid)
    return sent


def _follower_peered_with_miner(ctx):
    """Assertion 1's question, for the two nodes that exist yet.

    `smoke.assertion_1_peering` asks EVERY configured node, and the
    reference follower is not started until the seed — so called first,
    as it was, it failed every attempt with "scala2 /peers/connected
    stayed unavailable" before anything had been measured.
    """
    deadline = min(ctx.run.deadline, time.monotonic() + 120)
    peers = api_retry('rust', '/api/v1/peers', deadline, what='rust /api/v1/peers')
    scala_peer = next((p for p in peers
                       if p.get('addr', '').endswith(str(lifecycle.P2P['scala']))),
                      None)
    ctx.note('1_peering_follower_miner', {'scala_peer_seen_by_rust': scala_peer})
    if scala_peer is None:
        ctx.fail('Rust does not list the Scala miner as a peer')
    elif smoke.parse_version(scala_peer.get('version')) < smoke.REQUIRED_PEER_VERSION:
        ctx.fail(f'the Scala miner speaks {scala_peer.get("version")!r}, below the '
                 'input-block protocol version')


def run(ctx):
    _follower_peered_with_miner(ctx)
    blocks = ctx.args.ordering_blocks or ORDERING_BLOCKS

    # The window must be FUNDED, or a reconstruction succeeds on a
    # coinbase-only block without exercising the lookup key at all.
    balance, address = _fund(ctx)
    ctx.note('funding', {'balance_nano': balance, 'address': address})
    if not balance or not address:
        ctx.fail('no spendable coin on the miner wallet, so the ordering blocks '
                 'would carry nothing but the coinbase and a reconstruction would '
                 'not distinguish the lookup keys — the F5 measurement would be '
                 'vacuous', {'balance_nano': balance, 'address': address})
        return

    # Bring the reference follower up on the miner's chain.
    import campaign
    common.seed_second_miner(ctx, campaign, lifecycle, nodes=SEEDED_NODES)

    collector = common.EventCollector(ctx)
    collector.poll()
    watermark = collector.highest_seen
    # Hand the driver the collector, so the reconstruction accounting it
    # writes for EVERY scenario uses this window — whose completeness is
    # known — rather than a post-hoc read of a ring that has evicted.
    ctx.collector, ctx.collector_watermark = collector, watermark
    scala_from = {node: _log_length(node) for node in ('scala', 'scala2')}
    ctx.note('reference_log_offsets', scala_from)

    # Walk the window, polling the event feed as we go so the ring
    # cannot evict a decision before it is collected, and keeping
    # payments in flight so the blocks carry transactions.
    start = smoke.scala_height(ctx.run)
    target, reached, sent, last = start + blocks, start, [], start
    seen = set()
    while time.monotonic() < ctx.run.deadline:
        collector.poll()
        campaign.drain_utxo_watch(ctx, seen)
        try:
            reached = smoke.scala_height(ctx.run)
        except Unavailable:
            pass
        if reached > last:
            last = reached
            _pump(ctx, address, sent)
        if reached >= target:
            break
        ctx.run.idle(0.5)
    # The miner reaching the target is not the follower having decided
    # the target block: breaking out and reading once left the LAST
    # block's outcome uncollected (height 116 in round 2's attempt 1).
    # Keep polling, bounded, until the follower has applied it.
    settle_deadline = min(ctx.run.deadline, time.monotonic() + 90)
    while time.monotonic() < settle_deadline:
        collector.poll()
        try:
            if (api('rust', '/info') or {}).get('fullHeight', 0) >= reached:
                ctx.run.idle(3)
                collector.poll()
                break
        except Unavailable:
            pass
        ctx.run.idle(1)
    collector.poll()
    ctx.note('reconstruct_rate_window', {
        'start_height': start, 'target': target, 'reached': reached,
        'short_by': max(0, target - reached), 'payments_submitted': len(sent)})
    if reached < target:
        ctx.fail(f'the miner produced {reached - start} of the {blocks} ordering '
                 'blocks the F5 measurement needs (upstream F11); the shortfall '
                 'is reported, never absorbed',
                 {'start_height': start, 'reached': reached})

    # Sequence loss makes the rate unmeasurable, not merely noisy.
    ctx.note('event_collection', collector.summary(watermark))
    if collector.lost_in_window(watermark):
        ctx.fail('the event feed evicted entries between polls, so the '
                 'reconstruct-or-download outcomes of this window are incomplete '
                 'and the rate cannot be computed from them',
                 {'collection': collector.summary(watermark)})

    window = collector.window(watermark)
    reconstructed = [e for e in window if e['kind'] == 'ordering_reconstructed']
    fallback = [e for e in window if e['kind'] == 'ordering_reconstruct_fallback']
    skipped = [e for e in window if e['kind'] == 'ordering_reconstruct_skipped']
    decided = len(reconstructed) + len(fallback) + len(skipped)
    ctx.note('rust_outcomes', {
        'ordering_reconstructed': len(reconstructed),
        'ordering_reconstruct_fallback': len(fallback),
        'ordering_reconstruct_skipped': len(skipped),
        'decided': decided,
        'reconstructed_ratio': round(len(reconstructed) / decided, 4) if decided else None,
        'fallback_reasons': smoke._tally(e.get('detail') for e in fallback),
        'skipped_reasons': smoke._tally(e.get('detail') for e in skipped),
        'reconstruction_keys': smoke._tally(
            e.get('reconstructionKey', e.get('reconstruction_key'))
            for e in reconstructed),
        'reconstructed_orders': smoke._tally(
            e.get('reconstructedOrder', e.get('reconstructed_order'))
            for e in reconstructed),
        'ordering_blocks_in_window': reached - start,
    })
    # Deferred to after reconciliation: the blocks the follower was never
    # announced were downloaded in full without a decision, and a rate
    # that silently dropped them from its denominator would overstate
    # reconstruction.
    # Every ordering block in the window must have produced exactly one
    # outcome, matched BY IDENTITY. Counting was not enough: 96 outcomes
    # for 100 blocks was recorded and not failed.
    heights, unread_heights = {}, []
    for height in range(start + 1, reached + 1):
        try:
            ids = api('scala', f'/blocks/at/{height}') or []
        except Unavailable:
            ids = []
        if ids:
            heights[height] = ids[0]
        else:
            # Skipping it, as before, removed the block from the window
            # without a word; it is now counted as unreported.
            unread_heights.append(height)
    # Which ordering blocks were ANNOUNCED to the follower at all, from
    # its own log — the evidence `reconcile_outcomes` needs before it
    # will attribute a missing outcome to ordinary sync.
    try:
        rust_log = smoke.strip_ansi((smoke.WORK / 'rust.log').read_text(errors='replace'))
    except OSError:
        rust_log = ''
    announced = common.announced_headers(rust_log)
    # The best-chain headers just outside the window: the watermark can
    # straddle the block before `start`, and the settle loop can collect
    # the block after `reached`. Anything else is unmatched.
    adjacent = set()
    for height in (start, reached + 1, reached + 2):
        try:
            ids = api('scala', f'/blocks/at/{height}') or []
        except Unavailable:
            ids = []
        adjacent |= set(ids[:1])
    reconciliation = common.reconcile_outcomes(heights, window, announced=announced,
                                               unread_heights=unread_heights,
                                               adjacent_headers=adjacent)
    ctx.note('outcome_reconciliation', reconciliation)
    if announced is None:
        ctx.fail('the follower log carries no announcement lines, so a block with no '
                 'outcome cannot be told apart from one that was never announced',
                 {'trace_target': 'ergo_node::node::input_blocks::announcements'})
    if reconciliation['missing']:
        ctx.fail(f"{len(reconciliation['missing'])} of {reconciliation['blocks']} "
                 'ordering blocks in the window produced NO reconstruct-or-download '
                 'outcome, so the rate is computed over a window the node did not '
                 'fully report',
                 {'missing': reconciliation['missing'][:20]},
                 ids=[m['header'] for m in reconciliation['missing'][:5]])
    not_announced = len(reconciliation['not_announced'])
    ctx.evidence['rust_outcomes']['not_announced_downloaded_by_ordinary_sync'] = not_announced
    ctx.evidence['rust_outcomes']['reconstructed_over_all_blocks'] = (
        round(len(reconstructed) / (decided + not_announced), 4)
        if decided + not_announced else None)
    if reconciliation['unmatched']:
        ctx.fail(f"{len(reconciliation['unmatched'])} reconstruct-or-download outcomes "
                 'name a header that is not a block of this window (matched by '
                 'identity, never by height)',
                 {'unmatched': reconciliation['unmatched'][:20]})
    if reconciliation['duplicated']:
        ctx.fail(f"{len(reconciliation['duplicated'])} ordering blocks reported more "
                 'than one outcome', {'duplicated': reconciliation['duplicated'][:10]})

    # Both reference nodes over the SAME window: the follower is the one
    # that decides, the miner is recorded beside it to show it decides
    # nothing.
    follower = _scala_log_counts(ctx, 'scala2', scala_from.get('scala2', 0))
    miner = _scala_log_counts(ctx, 'scala', scala_from.get('scala', 0))
    ctx.note('scala_follower', follower)
    ctx.note('scala_miner', miner)

    if decided == 0:
        ctx.fail('the follower made no reconstruct-or-download decision in the '
                 'window, so the F5 rate could not be measured',
                 {'events_in_window': len(window),
                  'ordering_blocks': reached - start})

    # The comparative claim REQUIRES the reference measurement, and on a
    # single host it cannot be obtained: two Scala nodes cannot dial each
    # other (`NetworkController.getPeerAddress` resolves a same-address
    # peer through a UPnP gateway that does not exist), and the Rust
    # follower relays nothing to a peer it has not qualified, so a
    # reference follower here learns the chain by ordinary block
    # download and `processOrderingBlock` — the only place either log
    # line is emitted — never runs on it.
    #
    # That is a limitation of the HOST, not a defect of the node, so it
    # is neither a pass nor a failure. The scenario records NOT MEASURED:
    # the port's rate is measured and reported, the comparison is not.
    if not follower.get('decided'):
        ctx.not_measured(
            'the reference comparison F5 exists to make could not be measured on '
            'this host: the reference follower receives blocks by ordinary sync '
            'rather than by ordering announcement, so processOrderingBlock — the '
            'only place either log line is emitted — never runs on it',
            {'follower': follower, 'miner': miner,
             'code_path': 'scorex NetworkController.getPeerAddress:495; '
                          'ergo-node input_blocks/dispatch.rs peer eligibility'})

    ctx.note('f5', {
        'rust_d5_parent_key': {
            'reconstructed': len(reconstructed), 'fallback': len(fallback),
            'skipped': len(skipped),
            'ratio': round(len(reconstructed) / decided, 4) if decided else None,
            'status': 'measured'},
        'rust_scala_key': {
            'fallbacks': 9,
            'source': 'test-vectors/weak-blocks/findings/2026-09-22-4.json',
            'status': 'measured',
            'note': 'a RUST measurement of the port run with Scala\'s own lookup '
                    'key — NOT a Scala node measurement'},
        'reference_follower': {
            'reconstructed': follower.get('reconstructed'),
            'fallback': follower.get('fallback'),
            'ratio': follower.get('reconstructed_ratio'),
            'status': 'measured' if follower.get('decided') else 'not measured',
            'why': None if follower.get('decided') else
                   'structurally unobtainable on one host; see not_measured'},
        'comparative_claim': (
            'available' if follower.get('decided') else
            'WITHHELD until a reference number exists — the port\'s rate stands '
            'alone and may not be stated as a ratio against Scala'),
    })
    ctx.note('f5_reconstruction_key_split', smoke._tally(
        e.get('reconstructionKey', e.get('reconstruction_key'))
        for e in reconstructed))

    smoke.finalize_agreement(ctx.run, ctx.evidence)
    if ctx.run.height_violations:
        ctx.fail(f'Rust fell more than {smoke.HEIGHT_WINDOW} blocks behind '
                 f'{len(ctx.run.height_violations)} times during the measurement',
                 {'violations': ctx.run.height_violations[:20]})
