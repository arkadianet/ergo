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

# The second miner is NOT started with the others: it is seeded from
# miner 1's data directory once there is a chain to copy (see
# `common.seed_second_miner`), because the reference node cannot hand the
# chain to a second Scala node on this host.
START_NODES = ('scala', 'rust')

# It mines from the copied tip without waiting to decide it is synced —
# it already holds the chain, and `offlineGeneration = false` would make
# it wait for a peer-driven sync that never completes here.
SCALA2_EXTRA = 'ergo.node.offlineGeneration = true\n'

# Three nodes share 127.0.0.1, and the follower's per-IP admission limit
# is 1 — it gates outbound dial SELECTION as well as inbound admission,
# so without this it holds exactly one of the two Scala nodes and the
# scenario measures nothing. Raised only here; `flood`, which does test
# admission, keeps the default.
RUST_OVERRIDES = (
    ('peers', 'per_ip_limit', '3'),
    ('peers', 'per_subnet_limit', '6'),
)

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

    # Peering is checked AFTER the seed: the second miner does not exist
    # before it, and asking about a node that has not been started is not
    # an observation of anything.
    common.wait_ordering_blocks(ctx, COMMON_BLOCKS, 'shared_prefix')
    # The second miner joins the chain the first has built, so the branch
    # it goes on to mine privately is a branch of the SAME chain.
    common.seed_second_miner(ctx, campaign, lifecycle)
    smoke.assertion_1_peering(ctx.run, ctx.evidence)
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
    # And restart the FOLLOWER. It spent the isolation window dialling
    # the port miner 2 had moved off, so by the rejoin it is several
    # failures into an exponential backoff longer than the convergence
    # budget — attempt 2 never reconnected and never converged. Its data
    # directory is untouched, so it resumes on the public branch it was
    # following, which is exactly the branch that has to be unwound.
    lifecycle.stop(('rust',))
    lifecycle.spawn('rust')
    ctx.run.started('rust')
    ctx.note('follower_restarted_at_rejoin', True)
    # Recorded, not raised. The two miners cannot peer with each other,
    # so the second one's only peer is the follower, and requiring that
    # single connection to be up at one instant aborted a scenario whose
    # real evidence — convergence on the private branch, and the reorg
    # the follower emitted to get there — was still to come.
    try:
        lifecycle.wait_peered(timeout=180)
        rejoined = True
    except RuntimeError as error:
        rejoined = str(error)
    ctx.note('peered_after_rejoin', rejoined)
    connected = common._wait_for_peer_count(ctx, 'rust', 2)
    ctx.note('follower_peers_after_rejoin', connected)

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

    # ----- clearing and pruning, asserted rather than recorded -----
    #
    # Both previous checks hung off `chain.bestOrdering` naming a dropped
    # header, so a route publishing the NEW ordering id beside a STALE
    # input-block tip — with the abandoned trees still retained — passed
    # both. Each property is now asserted on its own terms.
    dropped = set(deepest.get('droppedHeaderIds') or [])
    chain = api_retry('rust', '/blocks/bestInputChain', ctx.run.deadline,
                      what='the follower input chain after the reorg')
    best = api_retry('rust', '/blocks/bestInputBlock', ctx.run.deadline,
                     what='the follower best input block after the reorg')
    info = api_retry('rust', '/info', ctx.run.deadline,
                     what='the follower info after the reorg')
    status = (api_retry('rust', '/api/v1/status', ctx.run.deadline,
                        what='the follower status after the reorg')
              .get('input_blocks') or {})
    ctx.note('after_reorg', {'best_input_chain': chain, 'best_input_block': best,
                             'info_best_input_block': info.get('bestInputBlock')})
    ctx.note('input_blocks_status_after_reorg', status)

    # The miner's own chain for the same ordering block, so a chain the
    # node has relabelled cannot vouch for its own tip.
    miner_chain = None
    try:
        miner = api('scala2', '/blocks/bestInputChain') or {}
        if miner.get('bestOrdering') == chain.get('bestOrdering'):
            miner_chain = miner.get('bestInputBlocks') or []
    except Unavailable:
        miner_chain = None
    ctx.note('miner_chain_for_comparison',
             {'available': miner_chain is not None,
              'length': len(miner_chain or [])})

    verdict = common.evaluate_post_reorg_state(
        chain, info, status, dropped, miner_chain=miner_chain)
    ctx.note('post_reorg_state', verdict['observed'])
    ctx.note('post_reorg_problems', verdict['problems'])
    for problem in verdict['problems']:
        ctx.fail(f"after the reorg: {problem['what']}",
                 {'problem': problem, 'chain': chain, 'info': info,
                  'status': status, 'dropped': sorted(dropped)},
                 ids=[problem.get('tip') or problem.get('bestOrdering') or ''])
