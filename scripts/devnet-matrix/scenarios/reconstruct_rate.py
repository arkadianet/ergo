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
SCALA_FALLBACK = 'downloading block transactions fully'


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
    reconstructed = fallback = 0
    for line in lines:
        low = line.lower()
        if SCALA_RECONSTRUCTED in low:
            reconstructed += 1
        elif SCALA_FALLBACK in low:
            fallback += 1
    decided = reconstructed + fallback
    out = {'node': node, 'reconstructed': reconstructed, 'fallback': fallback,
           'decided': decided,
           'reconstructed_ratio': round(reconstructed / decided, 4) if decided else None,
           'phrases': [SCALA_RECONSTRUCTED, SCALA_FALLBACK],
           'window_lines': len(lines), 'from_line': since_line,
           'source': ('ErgoNodeViewHolder.processOrderingBlock:458 (reconstruct) '
                      'and :465/:469 (download), at the pin')}
    if reconstructed == 0 and fallback == 0:
        out['unmatched'] = (
            'neither phrase appears in the pinned build\'s log; the Scala side of '
            'the ratio is UNKNOWN, not zero')
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


def run(ctx):
    smoke.assertion_1_peering(ctx.run, ctx.evidence)
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
    common.seed_second_miner(ctx, campaign, lifecycle)

    collector = common.EventCollector(ctx)
    collector.poll()
    watermark = collector.highest_seen
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
    ctx.note('rust', {
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
    # Every ordering block in the window should have produced exactly one
    # outcome. A shortfall means outcomes went unreported — which is the
    # undercount `ordering_reconstruct_skipped` exists to close.
    ctx.note('outcome_reconciliation', {
        'ordering_blocks': reached - start, 'outcomes': decided,
        'unaccounted': max(0, (reached - start) - decided)})

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

    # The comparative claim REQUIRES the reference measurement. Without
    # it the scenario has one number, not a comparison, and the report
    # may not describe Scala's rate at all.
    if not follower.get('decided'):
        ctx.fail('the reference FOLLOWER logged no reconstruct-or-download '
                 'decision in this window, so the comparison F5 exists to make '
                 'was not measured — the port\'s rate stands alone',
                 {'follower': follower, 'miner': miner})

    ctx.note('f5', {
        'rust_d5_parent_key': {
            'reconstructed': len(reconstructed), 'fallback': len(fallback),
            'ratio': round(len(reconstructed) / decided, 4) if decided else None},
        'reference_follower_scala_key': {
            'reconstructed': follower.get('reconstructed'),
            'fallback': follower.get('fallback'),
            'ratio': follower.get('reconstructed_ratio')},
        'note': 'the third number — the Rust port run with Scala\'s own key — is '
                'the 9 fallbacks recorded in '
                'test-vectors/weak-blocks/findings/2026-09-22-4.json, which is a '
                'RUST measurement, not a Scala one',
    })
    ctx.note('f5_reconstruction_key_split', smoke._tally(
        e.get('reconstructionKey', e.get('reconstruction_key'))
        for e in reconstructed))

    smoke.finalize_agreement(ctx.run, ctx.evidence)
    if ctx.run.height_violations:
        ctx.fail(f'Rust fell more than {smoke.HEIGHT_WINDOW} blocks behind '
                 f'{len(ctx.run.height_violations)} times during the measurement',
                 {'violations': ctx.run.height_violations[:20]})
