"""The fallback path, on purpose.

The M2 gate could only ever observe the reconstruction half: in every
passing run the follower had the input-block bodies it needed. This
scenario takes them away.

Two things have to be true at once, and the first attempt had only one
of them. **The ordering blocks must CARRY input-chain transactions**: on
an unfunded chain every block is coinbase-only, the input chain
contributes nothing, and the rebuild is trivially right no matter what
the follower has forgotten — the first run reconstructed 3 of 3 with a
four-entry transaction cache and 345 `WaitlistFull` drops, because there
was nothing in those blocks to get wrong. So the scenario funds the
chain and keeps a payment in flight through every ordering block.
**And the follower must not be able to hold the tree**: it is stopped,
its data directory is wiped while the miner runs on, and it comes back
with the transaction cache, the staging budget and the per-ordering
record cap squeezed to a few entries.

Then the rebuild is assembled from a strict subset of what the miner
committed, the root does not match, and the node has to download the
block in full.

What has to hold: a fallback fires, and the block the node then applies
at that height is the block Scala has. A fallback that lands anywhere
else is the wrong fallback, and that judgement is smoke.py's
`evaluate_mismatch_recovery`, not a local re-derivation.
"""
import shutil
import time

import lifecycle
import smoke
from smoke import Unavailable, api, api_retry

from . import common

NODES = ('scala', 'rust')
# A miner reward matures at ordering block 11 (`minerRewardDelay = 10`),
# and the workload cannot start before there is a coin to spend.
BLOCKS_BEFORE_EVICTION = 13
BLOCKS_AFTER_EVICTION = 6
# Payments kept in flight per ordering block, so the input chain the
# miner seals is never empty.
PAYMENTS_PER_ROUND = 4
PAYMENT_NANOERG = 1_000_000

# The bounds that starve the reconstruction path (spec §7.4 names, as
# `ergo-node/src/config/toml_sections.rs` spells them):
#
# * `tx_cache_entries` is where the input-block transactions a rebuild
#   would be assembled FROM live. At 4, the cache cannot hold a tree's
#   worth of bodies, so they are evicted before the ordering block that
#   needs them arrives — the eviction this scenario is named for;
# * `staging_bytes_total` bounds delivered-but-unverified bodies, so the
#   node cannot simply re-stage what the cache dropped;
# * `waitlist_entries` back at its crate default, so a disconnected
#   announcement is dropped rather than parked until the rest arrives.
RUST_OVERRIDES = (
    ('input_blocks.bounds', 'tx_cache_entries', '4'),
    ('input_blocks.bounds', 'staging_bytes_total', '4096'),
    ('input_blocks.bounds', 'waitlist_entries', '8'),
    # The tree itself: at 2 records per ordering block the follower can
    # never hold more than a sliver of the ~64 input blocks the miner
    # publishes under one ordering block, so whatever it assembles is a
    # strict subset of what the miner committed to.
    ('input_blocks.bounds', 'records_per_ordering', '2'),
)


def _fund(ctx):
    """A spendable coin and the address to send it to.

    Raises through `Unavailable` rather than returning a sentinel: a
    workload that could not be funded has not been run, and an eviction
    scenario over coinbase-only blocks measures nothing.
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
    ctx.note('funding', {'balance_nano': balance, 'address': address})
    return balance, address


def _pump(ctx, address, sent):
    """Submit a few payments, so the next input block is not empty."""
    for _ in range(PAYMENTS_PER_ROUND):
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
    import campaign

    smoke.assertion_1_peering(ctx.run, ctx.evidence)
    common.wait_ordering_blocks(ctx, BLOCKS_BEFORE_EVICTION, 'pre_eviction')

    balance, address = _fund(ctx)
    if not balance or not address:
        ctx.fail('no spendable coin on the miner wallet, so the ordering blocks '
                 'would carry nothing but the coinbase and the rebuild would be '
                 'trivially right whatever the follower had forgotten',
                 {'balance_nano': balance, 'address': address})
        return
    sent = _pump(ctx, address, [])

    evict_height = smoke.scala_height(ctx.run)
    ctx.note('eviction_height', evict_height)
    ctx.note('bounds_applied', {k: v for _, k, v in RUST_OVERRIDES})

    # Stop the follower and take its input-block bodies away entirely:
    # a fresh data directory, while the miner is already well past the
    # root of the tree it will announce next.
    lifecycle.stop(('rust',))
    shutil.rmtree(ctx.data_root / 'rust', ignore_errors=True)
    campaign.ensure_data_dirs(ctx.data_root, ['rust'])
    lifecycle.spawn('rust')
    ctx.run.started('rust')
    lifecycle.wait_peered()

    # Keep the chain funded across the whole observation window: a
    # payment in flight at every ordering block is what puts input-chain
    # transactions into the blocks whose rebuild is being measured.
    target = evict_height + BLOCKS_AFTER_EVICTION
    last_height = evict_height
    while time.monotonic() < ctx.run.deadline:
        try:
            height = smoke.scala_height(ctx.run)
        except Unavailable:
            ctx.run.idle(1)
            continue
        if height > last_height:
            last_height = height
            _pump(ctx, address, sent)
        if height >= target:
            break
        ctx.run.idle(1)
    ctx.note('workload', {'payments_submitted': len(sent),
                          'ordering_blocks': last_height - evict_height,
                          'target_blocks': BLOCKS_AFTER_EVICTION})
    if last_height < target:
        ctx.fail(f'the miner produced {last_height - evict_height} of the '
                 f'{BLOCKS_AFTER_EVICTION} ordering blocks the eviction window '
                 'needs (upstream F11); the shortfall is reported, never absorbed',
                 {'reached': last_height, 'target': target})

    events = common.rust_events(ctx)
    # No watermark: the node is restarted on a FRESH data directory, so
    # its event feed starts empty and everything in it is post-eviction.
    window = [e for e in events if e['kind'].startswith('ordering_')]
    fallbacks = [e for e in window if e['kind'] == 'ordering_reconstruct_fallback']
    reconstructions = [e for e in window if e['kind'] == 'ordering_reconstructed']
    ctx.note('ordering_outcomes', {
        'ordering_reconstruct_fallback': len(fallbacks),
        'ordering_reconstructed': len(reconstructions),
        'fallback_reasons': smoke._tally(e.get('detail') for e in fallbacks),
        'first_kind': window[0]['kind'] if window else None,
        'first_detail': window[0].get('detail') if window else None,
    })
    if not fallbacks:
        ctx.fail('no ordering block fell back to a full download even with the '
                 'input-block bodies gone and the staging budget squeezed, so the '
                 'fallback path was NOT exercised — the scenario proved nothing',
                 {'events_in_window': len(window),
                  'reconstructions': len(reconstructions),
                  'payments_submitted': len(sent),
                  'rust_log': smoke.rust_log_lines('input_blocks')})

    # Whatever it fell back to has to be Scala's block at that height.
    heights = [e.get('height') for e in window if e.get('height') is not None]
    if not heights:
        ctx.fail('the follower reported no ordering outcome with a height, so the '
                 'fallback could not be checked against Scala',
                 {'window': window[:10]})
        return
    at_height, unread = common.scala_blocks_by_height(ctx, min(heights), max(heights))
    ctx.note('scala_heights_unread', unread)
    if unread:
        ctx.fail(f'Scala could not be read for {len(unread)} of the heights the '
                 'fallback covers, so the recovery cannot be checked against it',
                 {'heights': unread})
    recovery = smoke.evaluate_mismatch_recovery(
        common.ordering_stream(events), at_height)
    ctx.note('mismatch_recovery', recovery)
    for message, evidence in recovery['failures']:
        ctx.fail(message, evidence)

    # And the node has to agree with the miner afterwards.
    deadline = min(ctx.run.deadline, time.monotonic() + 300)
    agreed = False
    while time.monotonic() < deadline:
        try:
            scala = api('scala', '/info') or {}
            rust = api('rust', '/info') or {}
        except Unavailable:
            ctx.run.idle(0.5)
            continue
        if (rust.get('bestFullHeaderId')
                and rust.get('bestFullHeaderId') == scala.get('bestFullHeaderId')):
            agreed = True
            break
        ctx.run.idle(0.5)
    ctx.note('agreed_with_miner_after_fallback', agreed)
    if not agreed:
        ctx.fail('after falling back to full downloads the follower never held the '
                 "miner's tip",
                 {'rust': api_retry('rust', '/info', ctx.run.deadline, what='rust'),
                  'scala': api_retry('scala', '/info', ctx.run.deadline,
                                     what='scala')})
