"""The fallback path, on purpose.

The M2 gate could only ever observe the reconstruction half: in every
passing run the follower had the input-block bodies it needed. This
scenario takes them away. The node is stopped mid-chain, its data
directory is wiped while the miner keeps going, and it is restarted with
the input-block body store bounded to almost nothing — so when the next
ordering block arrives it has no bodies for the announced tree and MUST
download the block in full.

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
BLOCKS_BEFORE_EVICTION = 6
BLOCKS_AFTER_EVICTION = 4

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
)


def run(ctx):
    import campaign

    smoke.assertion_1_peering(ctx.run, ctx.evidence)
    common.wait_ordering_blocks(ctx, BLOCKS_BEFORE_EVICTION, 'pre_eviction')

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

    common.wait_ordering_blocks(ctx, BLOCKS_AFTER_EVICTION, 'post_eviction')

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
