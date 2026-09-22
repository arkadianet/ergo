"""A full-block reorg under the follower, and what it does to the trees.

Two miners split at a common height: miner 1 keeps the public branch,
miner 2 mines a private one with its peers removed. Miner 1 is then
stopped so its branch stalls, miner 2 overtakes it, and both rejoin. The
follower is on the public branch and has to unwind onto the private one.

What the scenario asserts about `OrderingReorg` handling (spec §9.5):

* the node EMITS a reorg — a follower that silently swapped tips has not
  been observed doing the right thing;
* the input-block trees hanging off dropped ordering blocks are pruned:
  after the reorg `/info.bestInputBlock` is either empty or a block
  under the NEW best ordering block, never one under a dropped header;
* the mempool restore is counted: the reorg event carries the
  transactions returned to the pool, and a reorg that returned none from
  blocks that held some is recorded as such.
"""
import os
import time

import lifecycle
import smoke
from smoke import Unavailable, api, api_retry

from . import common

NODES = ('scala', 'scala2', 'rust')
# Blocks to share before the split, blocks the public branch grows after
# it, and how far the private branch must overtake before rejoining.
COMMON_BLOCKS = 6
PUBLIC_BLOCKS_AFTER_SPLIT = 2
PRIVATE_LEAD = 2
PRIVATE_MINING_BUDGET = 900.0

# Each node listens on its own loopback address (see
# `campaign.CAMPAIGN_P2P_HOST`), so the follower's per-IP admission limit
# is not in the way and nothing about the node's production peer limits
# is overridden here.

# Where miner 2 binds while it is isolated. Clearing `knownPeers` only
# stops it DIALLING — the follower has miner 2 in its own `known` list and
# keeps an inbound connection open, which would hand it the private
# branch in real time and there would be no reorg to observe. Moving the
# listener is what actually parts them; the port is outside the
# campaign's own 19570-19572 band and outside every production port.
ISOLATED_P2P_PORT = 19573


def _rewrite_scala2(campaign, ctx, isolated):
    """Point miner 2 at an isolated or a rejoined config.

    Isolation is `knownPeers = []` plus `offlineGeneration`, which is how
    the Scala node mines without waiting for a network. Nothing else
    moves, so the branch it builds is a branch of the same chain.
    """
    path = campaign.CONF / ('rollback-scala2-isolated.conf' if isolated
                            else 'rollback-scala2.conf')
    extra = (f'scorex.network.knownPeers = []\n'
             f'scorex.network.bindAddress = "127.0.0.1:{ISOLATED_P2P_PORT}"\n'
             f'scorex.network.declaredAddress = "127.0.0.1:{ISOLATED_P2P_PORT}"\n'
             f'ergo.node.offlineGeneration = true\n') if isolated else ''
    body = campaign.scala_override('rollback', 'scala2', ctx.nodes,
                                   ctx.data_root / 'scala2')
    path.write_text(body + extra)
    os.environ['SCALA2_CONFIG'] = str(path)
    return path


def run(ctx):
    import campaign

    smoke.assertion_1_peering(ctx.run, ctx.evidence)
    common.wait_ordering_blocks(ctx, COMMON_BLOCKS, 'shared_prefix')
    split_height = smoke.scala_height(ctx.run)
    ctx.note('split_height', split_height)
    ctx.note('isolation', {
        'method': 'miner 2 moves its P2P listener and clears knownPeers',
        'isolated_p2p_port': ISOLATED_P2P_PORT,
        'why': 'clearing knownPeers alone leaves the follower\'s inbound '
               'connection up, and the private branch would never be private',
    })

    # ----- the split -----
    lifecycle.stop(('scala2',))
    _rewrite_scala2(campaign, ctx, isolated=True)
    lifecycle.spawn('scala2')
    ctx.run.started('scala2')
    lifecycle.init_wallet('scala2')

    # The public branch grows a little, so the rejoin is a REORG rather
    # than an extension: a follower that only ever extends has not
    # unwound anything.
    common.wait_ordering_blocks(ctx, PUBLIC_BLOCKS_AFTER_SPLIT, 'public_branch')
    public_height = smoke.scala_height(ctx.run)
    public_tip = (api_retry('rust', '/info', ctx.run.deadline,
                            what='the follower tip before the reorg')
                  .get('bestFullHeaderId'))
    ctx.note('public_branch', {'height': public_height, 'rust_tip': public_tip})

    # ----- the private branch overtakes -----
    lifecycle.stop(('scala',))
    deadline = min(ctx.run.deadline, time.monotonic() + PRIVATE_MINING_BUDGET)
    private_height = None
    while time.monotonic() < deadline:
        try:
            private_height = (api('scala2', '/info') or {}).get('fullHeight') or 0
        except Unavailable:
            private_height = None
        if private_height and private_height >= public_height + PRIVATE_LEAD:
            break
        ctx.run.idle(1)
    ctx.note('private_branch', {'height': private_height,
                               'needed': public_height + PRIVATE_LEAD})
    if not private_height or private_height < public_height + PRIVATE_LEAD:
        ctx.fail('the isolated miner never overtook the public branch, so no reorg '
                 'could be forced (upstream F11 stalls the candidate generator; the '
                 'shortfall is reported, never absorbed)',
                 {'public_height': public_height, 'private_height': private_height})
        return

    # ----- rejoin -----
    events_watermark = common.latest_event_seq(ctx)
    lifecycle.stop(('scala2',))
    _rewrite_scala2(campaign, ctx, isolated=False)
    lifecycle.spawn('scala')
    ctx.run.started('scala')
    lifecycle.spawn('scala2')
    ctx.run.started('scala2')
    lifecycle.wait_peered()

    # The follower has to land on the private branch.
    converge_deadline = min(ctx.run.deadline, time.monotonic() + 600)
    converged = False
    while time.monotonic() < converge_deadline:
        try:
            rust = api('rust', '/info') or {}
            miner = api('scala2', '/info') or {}
        except Unavailable:
            ctx.run.idle(1)
            continue
        if (rust.get('bestFullHeaderId')
                and rust.get('bestFullHeaderId') == miner.get('bestFullHeaderId')):
            converged = True
            break
        ctx.run.idle(1)
    ctx.note('converged_on_private_branch', converged)
    if not converged:
        ctx.fail('the follower never converged on the branch that overtook the one '
                 'it was following',
                 {'rust': api('rust', '/info'), 'scala2': api('scala2', '/info')})

    # ----- what the follower reported -----
    events = common.rust_events(ctx)
    reorgs = [e for e in common.events_after(events, events_watermark)
              if e['kind'] == 'reorg']
    ctx.note('reorg_events', reorgs)
    if not reorgs:
        ctx.fail('the follower switched branches without emitting a reorg, so the '
                 'OrderingReorg path cannot be shown to have run',
                 {'events_tail': events[-30:]})
        return
    deepest = max(reorgs, key=lambda e: e.get('depth') or 0)
    ctx.note('reorg', {
        'depth': deepest.get('depth'),
        'dropped_header_ids': deepest.get('droppedHeaderIds'),
        'returned_txs_total': deepest.get('returnedTxsTotal'),
        'returned_tx_ids': deepest.get('returnedTxIds'),
    })
    if not deepest.get('depth'):
        ctx.fail('the reorg the follower reported has no depth, so nothing was '
                 'unwound', {'reorg': deepest})
    if deepest.get('returnedTxsTotal') is None:
        ctx.fail('the reorg carries no mempool restore count, so the restore cannot '
                 'be checked', {'reorg': deepest})

    # The trees off the dropped branch must be gone: whatever
    # `bestInputBlock` names now has to sit under the NEW best ordering
    # block, and the dropped ordering blocks must not be its parent.
    dropped = set(deepest.get('droppedHeaderIds') or [])
    chain = api_retry('rust', '/blocks/bestInputChain', ctx.run.deadline,
                      what='the follower input chain after the reorg')
    best = api_retry('rust', '/blocks/bestInputBlock', ctx.run.deadline,
                     what='the follower best input block after the reorg')
    ctx.note('after_reorg', {'best_input_chain': chain, 'best_input_block': best})
    if chain.get('bestOrdering') in dropped:
        ctx.fail('after the reorg the input chain is still keyed to an ordering '
                 'block the reorg dropped: the tree was not pruned',
                 {'chain': chain, 'dropped': sorted(dropped)},
                 ids=[chain.get('bestOrdering')])
    if best.get('bestInputBlock') and chain.get('bestOrdering') in dropped:
        ctx.fail('`/info.bestInputBlock` still names a block under a dropped '
                 'ordering block', {'best': best, 'chain': chain})

    status = (api_retry('rust', '/api/v1/status', ctx.run.deadline,
                        what='the follower status after the reorg')
              .get('input_blocks') or {})
    ctx.note('input_blocks_status_after_reorg', status)
