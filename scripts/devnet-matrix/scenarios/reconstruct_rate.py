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

import smoke

from . import common

NODES = ('scala', 'scala2', 'rust')
ORDERING_BLOCKS = 100

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

# All three nodes share 127.0.0.1 and the follower's per-IP admission
# limit is 1, so without this it would connect to one of the two Scala
# nodes and the handshake wait would time out.
RUST_OVERRIDES = (
    ('peers', 'per_ip_limit', '2'),
    ('peers', 'per_subnet_limit', '4'),
)

# The pinned Scala build's two log lines for the same decision. Matched
# loosely (case-insensitive substrings) because a wording change must
# show up as "not found", not as a silent zero.
SCALA_RECONSTRUCTED = 'block transactions from input-blocks'
SCALA_FALLBACK = 'downloading block transactions fully'


def _scala_log_counts(ctx, node='scala2'):
    """Count a reference node's reconstruct-vs-download lines.

    Read from the reference FOLLOWER by default. A log that contains
    NEITHER phrase is reported as unmatched rather than as 0/0: the
    reference's rate is the comparison, and a comparison against a phrase
    the build never logs is not one.
    """
    path = smoke.WORK / f'{node}.log'
    if not path.exists():
        return {'error': f'no Scala log at {path}'}
    reconstructed = fallback = 0
    for line in path.read_text(errors='replace').splitlines():
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
           'source': ('ErgoNodeViewHolder.processOrderingBlock:458 (reconstruct) '
                      'and :465/:469 (download), at the pin')}
    if reconstructed == 0 and fallback == 0:
        out['unmatched'] = (
            'neither phrase appears in the pinned build\'s log; the Scala side of '
            'the ratio is UNKNOWN, not zero')
        # Whatever the build does log about input blocks, so the report
        # can name the real phrases.
        out['input_block_log_sample'] = [
            line for line in path.read_text(errors='replace').splitlines()
            if re.search(r'input.?block', line, re.I)][-20:]
    return out


def run(ctx):
    smoke.assertion_1_peering(ctx.run, ctx.evidence)
    blocks = ctx.args.ordering_blocks or ORDERING_BLOCKS
    events_watermark = common.latest_event_seq(ctx)
    start, reached = common.wait_ordering_blocks(ctx, blocks, 'reconstruct_rate')

    events = common.rust_events(ctx)
    window = common.events_after(events, events_watermark)
    reconstructed = [e for e in window if e['kind'] == 'ordering_reconstructed']
    fallback = [e for e in window if e['kind'] == 'ordering_reconstruct_fallback']
    decided = len(reconstructed) + len(fallback)
    ctx.note('rust', {
        'ordering_reconstructed': len(reconstructed),
        'ordering_reconstruct_fallback': len(fallback),
        'decided': decided,
        'reconstructed_ratio': round(len(reconstructed) / decided, 4) if decided else None,
        'fallback_reasons': smoke._tally(e.get('detail') for e in fallback),
        'reconstruction_keys': smoke._tally(
            e.get('reconstructionKey', e.get('reconstruction_key'))
            for e in reconstructed),
        'reconstructed_orders': smoke._tally(
            e.get('reconstructedOrder', e.get('reconstructed_order'))
            for e in reconstructed),
        'ordering_blocks_in_window': reached - start,
    })
    # Both reference nodes: the follower is the one that decides, and
    # the miner is recorded beside it to show that it decides nothing.
    ctx.note('scala_follower', _scala_log_counts(ctx, 'scala2'))
    ctx.note('scala_miner', _scala_log_counts(ctx, 'scala'))

    # The measurement is only a measurement if the window produced
    # decisions. A run in which the node decided nothing has measured
    # nothing, and reporting "100% reconstructed" off zero events would
    # be the worst possible outcome of this scenario.
    if decided == 0:
        ctx.fail('the follower made no reconstruct-or-download decision in the '
                 'window, so the F5 rate could not be measured',
                 {'events_in_window': len(window),
                  'ordering_blocks': reached - start})

    # D5 telemetry is the direct evidence for F5: a reconstruction keyed
    # to `parent` is the port working around Scala keying by `self`.
    keys = smoke._tally(e.get('reconstructionKey', e.get('reconstruction_key'))
                        for e in reconstructed)
    ctx.note('f5_reconstruction_key_split', keys)

    smoke.finalize_agreement(ctx.run, ctx.evidence)
    if ctx.run.height_violations:
        ctx.fail(f'Rust fell more than {smoke.HEIGHT_WINDOW} blocks behind '
                 f'{len(ctx.run.height_violations)} times during the measurement',
                 {'violations': ctx.run.height_violations[:20]})
