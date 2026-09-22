"""Steady state: 60 ordering blocks against one miner.

The campaign's baseline. Everything the later scenarios perturb is
measured here first, with smoke.py's own evaluators: per-block input-tip
agreement inside the lag bounds, input-chain prefix agreement, mempool
agreement with every Scala-only residue attributed to D1 or F6, and no
penalty of the honest peer.
"""
import time

import smoke
from smoke import Unavailable, api

from . import common

NODES = ('scala', 'rust')
ORDERING_BLOCKS = 60
MEMPOOL_TXS = 20
# Payments kept in flight per ordering block during the window, so the
# input chain the miner seals is never empty and there is something for
# an ordering block to drop.
PAYMENTS_PER_BLOCK = 3
PAYMENT_NANOERG = 1_000_000


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


def _observe_window(ctx, blocks, address):
    """Walk the window ordering block by ordering block, recording what
    each one did to the input chain that preceded it.

    A6 runs ONCE, before the window. Copying its attribution into
    `f6_count` afterwards reported the state of the chain at block 0 as
    though it were the state at block 60: an input-chain transaction
    dropped and lost at block 40 left both pools agreeing at the end,
    and F6 read as zero. This is the per-block accounting that sees it.
    """
    import campaign
    start = smoke.scala_height(ctx.run)
    target, scanned, sent = start + blocks, start, []
    observations, seen = [], set()
    # The transactions of the input blocks on Rust's best input chain,
    # refreshed every poll and captured when an ordering block lands.
    # NOT the sampler's accumulated cache: that holds every input-block
    # transaction the run has ever seen, so every block would appear to
    # drop every transaction of every earlier round — 5,157 phantom
    # losses over 60 blocks in the run that exposed it.
    chain_now = set()
    while time.monotonic() < ctx.run.deadline:
        campaign.drain_utxo_watch(ctx, seen)
        try:
            chain = api('rust', '/blocks/bestInputChain') or {}
            cached = dict(ctx.run.input_block_txids)
            chain_now = {t for bid in (chain.get('bestInputBlocks') or [])
                         for t in cached.get(bid, ())}
        except Unavailable:
            pass
        try:
            height = smoke.scala_height(ctx.run)
        except Unavailable:
            ctx.run.idle(1)
            continue
        while scanned < height:
            scanned += 1
            # The chain THIS ordering block closes, as last observed
            # before it landed.
            applied = set(chain_now)
            try:
                ids = api('scala', f'/blocks/at/{scanned}') or []
                ordering_txids = set()
                header = ids[0] if ids else None
                for hid in ids:
                    block = api('scala', f'/blocks/{hid}')
                    ordering_txids |= {
                        t['id'] for t in block['blockTransactions']['transactions']}
                rust_pool = {t['id'] for t in api('rust', '/transactions/unconfirmed')}
                scala_pool = {t['id'] for t in api('scala', '/transactions/unconfirmed')}
            except (Unavailable, KeyError, TypeError) as error:
                observations.append({'height': scanned, 'unread': str(error)})
                continue
            observations.append({
                'height': scanned, 'ordering_block': header,
                'input_chain_txids': applied, 'ordering_txids': ordering_txids,
                'rust_pool': rust_pool, 'scala_pool': scala_pool,
            })
            # The chain the next block will close starts empty: this one
            # has just been sealed.
            chain_now = set()
            _pump(ctx, address, sent)
        if scanned >= target:
            break
        ctx.run.idle(1)
    return start, scanned, observations, sent


def run(ctx):
    smoke.assertion_1_peering(ctx.run, ctx.evidence)

    # The mempool workload first: it needs a matured miner reward, and
    # waiting for one is time the steady window would otherwise spend
    # idle. Its own samples are part of the same series.
    smoke.assertion_6_mempool(ctx.run, ctx.evidence, MEMPOOL_TXS)

    blocks = ctx.args.ordering_blocks or ORDERING_BLOCKS
    address = ((ctx.evidence.get('6_mempool') or {}).get('address')
               or (api('scala', '/wallet/addresses') or [None])[0])
    start, reached, observations, sent = _observe_window(ctx, blocks, address)
    readable = [o for o in observations if 'unread' not in o]
    unread = [o['height'] for o in observations if 'unread' in o]
    ctx.note('steady_window', {'start_height': start, 'target': start + blocks,
                               'reached': reached,
                               'short_by': max(0, start + blocks - reached),
                               'blocks_accounted': len(readable),
                               'blocks_unread': unread,
                               'payments_submitted': len(sent)})
    if reached < start + blocks:
        ctx.fail(f'the miner produced {reached - start} of the {blocks} ordering '
                 'blocks steady needs (upstream F11 stalls the candidate '
                 'generator); the shortfall is reported, never absorbed',
                 {'start_height': start, 'reached': reached})
    if unread:
        ctx.fail(f'{len(unread)} ordering blocks in the window could not be read, '
                 'so their F6 accounting is missing rather than zero',
                 {'heights': unread})

    # The verdicts, over EVERY sample the run took.
    smoke.finalize_agreement(ctx.run, ctx.evidence)

    # Zero penalties, and the honest peer never dropped. Reused from
    # assertion 5 rather than re-derived: the counters and the peer
    # states are the sampler's, and the bar is the same bar.
    penalties = smoke.rust_log_lines('penalizing peer')
    ctx.note('penalty_log_lines', penalties)
    if penalties or ctx.run.penalty_observations:
        ctx.fail('the honest Scala peer was penalised during steady state',
                 {'log': penalties,
                  'observations': ctx.run.penalty_observations})
    if 'absent' in ctx.run.peer_states:
        ctx.fail("the Scala peer disappeared from Rust's peer list")
    fatal = {r: ctx.run.totals()[r] for r in smoke.FATAL_DROPS
             if ctx.run.totals().get(r)}
    if fatal:
        ctx.fail(f'byte-level disagreement with the Scala peer: {fatal}',
                 {'drops': ctx.run.totals(),
                  'rust_log': smoke.rust_log_lines('input_blocks: dropped')})
    if ctx.run.height_violations:
        ctx.fail(f'Rust fell more than {smoke.HEIGHT_WINDOW} blocks behind '
                 f'{len(ctx.run.height_violations)} times '
                 f'(max gap {ctx.run.max_height_gap})',
                 {'violations': ctx.run.height_violations[:20]})

    # F6, counted PER ORDERING BLOCK across the window.
    f6 = common.evaluate_f6(readable)
    ctx.note('f6_per_block', {
        'blocks': len(f6['blocks']),
        'f6_total': f6['f6_total'],
        'f6_txids': f6['f6_txids'][:20],
        'lost_on_both_total': f6['lost_on_both_total'],
        'lost_on_both_txids': f6['lost_on_both_txids'][:20],
        'per_block': [b for b in f6['blocks'] if b['dropped']][:20],
    })
    ctx.note('f6_count', f6['f6_total'])
    if f6['lost_on_both_total']:
        ctx.fail(f"{f6['lost_on_both_total']} input-chain transactions were dropped "
                 'by an ordering block and are in NEITHER pool and in no later '
                 'block — a loss the two pools agree about, so comparing them '
                 'could never have revealed it',
                 {'txids': f6['lost_on_both_txids'][:20],
                  'blocks': [b for b in f6['blocks'] if b['lost_on_both']][:10]},
                 ids=f6['lost_on_both_txids'][:5])
    # The end-of-run D1/F6 attribution from A6 is kept beside it, as the
    # single-instant view it is.
    mempool = ctx.evidence.get('6_mempool') or {}
    ctx.note('a6_end_of_run_attribution', mempool.get('d1_f6_accounting'))
    ctx.note('d1_count', len((mempool.get('d1_f6_accounting') or {}).get('d1') or []))

    # Whole-chain D3 guard, beside the tip check assertion 2 makes.
    orphans, off_by_ordering = common.chain_members_scala_never_had(ctx.run.series)
    ctx.note('chain_members_scala_never_published', orphans[:20])
    ctx.note('chain_members_seen_under_a_neighbouring_ordering_id',
             len(off_by_ordering))
    if orphans:
        ctx.fail(f'{len(orphans)} blocks were on Rust\'s input chain that Scala '
                 'never published anywhere in the run',
                 {'sample': orphans[:10]},
                 ids=[o['block'] for o in orphans[:5]])
