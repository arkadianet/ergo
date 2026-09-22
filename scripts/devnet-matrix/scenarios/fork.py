"""Two miners: competing input-block trees under one ordering block.

The only way to make the follower switch input-chain forks on a private
devnet is to give it two miners. The scenario counts the switches
(`/api/v1/status.input_blocks.forks > 1` at some sample, and the chain
changes the sampler recorded), and checks each against the miner:
a block Rust applied that Scala never had under the same ordering id is
a chain Scala lacks — the D3 sibling-completion guard — and a block Rust
rolled back that Scala kept is a switch Scala never made.
"""
import time

import smoke

from . import common

NODES = ('scala', 'scala2', 'rust')
ORDERING_BLOCKS = 25
# Ordering blocks of shared history before the second miner joins.
SHARED_BLOCKS = 4

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


def run(ctx):
    import campaign
    import lifecycle

    # The second miner does not exist yet, so peering is checked AFTER
    # the seed: asking about a node that has not been started is not an
    # observation of anything.
    common.wait_ordering_blocks(ctx, SHARED_BLOCKS, 'shared_prefix')
    common.seed_second_miner(ctx, campaign, lifecycle)
    smoke.assertion_1_peering(ctx.run, ctx.evidence)

    # Watch `forks` for the whole window: it is an instantaneous count of
    # competing trees retained under the best ordering block, so a
    # scenario that only read it at the end would usually read 1.
    fork_counts, fork_samples = [], []
    blocks = ctx.args.ordering_blocks or ORDERING_BLOCKS
    start = smoke.scala_height(ctx.run)
    target = start + blocks
    reached = start
    while time.monotonic() < ctx.run.deadline:
        try:
            status = smoke.api('rust', '/api/v1/status') or {}
            input_blocks = status.get('input_blocks') or {}
            forks = input_blocks.get('forks')
            if forks is not None:
                fork_counts.append(forks)
                if forks > 1:
                    fork_samples.append({
                        'at': time.time(), 'forks': forks,
                        'best_input_block': input_blocks.get('best_input_block'),
                        'waitlist': input_blocks.get('waitlist')})
            reached = smoke.scala_height(ctx.run)
        except smoke.Unavailable:
            pass
        if reached >= target:
            break
        ctx.run.idle(0.5)

    ctx.note('ordering_window', {'start_height': start, 'target': target,
                                 'reached': reached})
    ctx.note('forks_observed', {
        'samples': len(fork_counts),
        'max': max(fork_counts) if fork_counts else None,
        'samples_above_one': len(fork_samples),
        'sample': fork_samples[:20],
    })
    if reached < target:
        ctx.fail(f'only {reached - start} of {blocks} ordering blocks were mined; '
                 'both miners suffer the upstream F11 cachedCandidate race, and a '
                 'window that did not open cannot be a pass',
                 {'start_height': start, 'reached': reached})

    # The switches themselves, from the sampled chains.
    comparison = common.compare_fork_switches(ctx.run.series)
    ctx.note('fork_switches', {
        'rust': len(comparison['rust_switches']),
        'scala': len(comparison['scala_switches']),
        'rust_sample': comparison['rust_switches'][:20],
        'scala_sample': comparison['scala_switches'][:20],
    })
    if not comparison['rust_switches'] and not fork_samples:
        # Nothing to conclude from. Two miners that never produced a
        # competing tree did not exercise the property, and saying so is
        # the honest outcome — a run that observed no switches has not
        # observed that switches are correct.
        ctx.fail('no input-chain fork switch was observed on Rust and `forks` never '
                 'exceeded 1, so the fork-handling path was never exercised',
                 {'fork_count_samples': len(fork_counts),
                  'max_forks': max(fork_counts) if fork_counts else None,
                  'scala_switches': len(comparison['scala_switches'])})

    if comparison['applied_blocks_scala_never_had']:
        bad = comparison['applied_blocks_scala_never_had']
        ctx.fail(f'{len(bad)} input blocks Rust switched ONTO were never on any '
                 "Scala best input chain for the same ordering block (D3 sibling "
                 'completion invented a chain the miners do not have)',
                 {'sample': bad[:10]}, ids=[b['block'] for b in bad[:5]])
    if comparison['rolled_back_blocks_scala_kept']:
        bad = comparison['rolled_back_blocks_scala_kept']
        ctx.fail(f'{len(bad)} input blocks Rust rolled back were still on Scala\'s '
                 'last observed chain for the same ordering block',
                 {'sample': bad[:10]}, ids=[b['block'] for b in bad[:5]])

    orphans = common.chain_members_scala_never_had(ctx.run.series)
    ctx.note('chain_members_scala_never_had', orphans[:20])
    if orphans:
        ctx.fail(f'{len(orphans)} blocks sat on Rust\'s input chain that no miner '
                 'ever listed under the same ordering block',
                 {'sample': orphans[:10]}, ids=[o['block'] for o in orphans[:5]])

    # Assertions 2 and 3 are NOT evaluated here. Both are defined
    # against ONE miner's best input chain — "every Rust tip must be a
    # block Scala had" — and with two miners the follower may
    # legitimately be on either one's chain, so a single-miner evaluator
    # reports the whole of the other miner's chain as unconfirmed. The
    # two-miner property is the fork comparison above, which reads both.
    ctx.note('agreement_assertions', {
        'evaluated': False,
        'why': 'assertions 2 and 3 are single-miner definitions; with two '
               'miners the follower may be on either chain and the '
               'evaluator has no way to say which is right',
        'samples_retained': len(ctx.run.series),
    })
    penalties = smoke.rust_log_lines('penalizing peer')
    ctx.note('penalty_log_lines', penalties)
    if penalties or ctx.run.penalty_observations:
        ctx.fail('a miner peer was penalised while the input chain was forking',
                 {'log': penalties, 'observations': ctx.run.penalty_observations})
