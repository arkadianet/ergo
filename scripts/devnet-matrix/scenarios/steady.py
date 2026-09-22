"""Steady state: 60 ordering blocks against one miner.

The campaign's baseline. Everything the later scenarios perturb is
measured here first, with smoke.py's own evaluators: per-block input-tip
agreement inside the lag bounds, input-chain prefix agreement, mempool
agreement with every Scala-only residue attributed to D1 or F6, and no
penalty of the honest peer.
"""
import smoke

from . import common

NODES = ('scala', 'rust')
ORDERING_BLOCKS = 60
MEMPOOL_TXS = 20


def run(ctx):
    smoke.assertion_1_peering(ctx.run, ctx.evidence)

    # The mempool workload first: it needs a matured miner reward, and
    # waiting for one is time the steady window would otherwise spend
    # idle. Its own samples are part of the same series.
    smoke.assertion_6_mempool(ctx.run, ctx.evidence, MEMPOOL_TXS)

    blocks = ctx.args.ordering_blocks or ORDERING_BLOCKS
    common.wait_ordering_blocks(ctx, blocks, 'steady')

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

    # F6 is a per-block count in this scenario, not just an end-of-run
    # attribution: how many input-chain transactions the ordering block
    # dropped and the mempool never got back.
    mempool = ctx.evidence.get('6_mempool') or {}
    ctx.note('f6_accounting', mempool.get('d1_f6_accounting'))
    ctx.note('f6_count', len((mempool.get('d1_f6_accounting') or {}).get('f6') or []))
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
