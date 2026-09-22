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

# Both miners and the follower share 127.0.0.1, and the node's per-IP
# admission limit is 1 (`ergo_p2p::peer_manager::limits::DEFAULT_PER_IP_LIMIT`)
# — it applies to outbound dial SELECTION as well as to inbound
# admission, so the follower would connect to exactly one of the two
# miners and this scenario could never start. Raised to 2, and only for
# the two-miner scenarios: it is an artifact of running a whole network
# on loopback, and it is not what these scenarios measure. The `flood`
# scenario, which DOES test admission, keeps the default.
RUST_OVERRIDES = (
    ('peers', 'per_ip_limit', '2'),
    ('peers', 'per_subnet_limit', '4'),
)


def run(ctx):
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

    # The standing bars still apply while forking.
    smoke.finalize_agreement(ctx.run, ctx.evidence)
    penalties = smoke.rust_log_lines('penalizing peer')
    ctx.note('penalty_log_lines', penalties)
    if penalties or ctx.run.penalty_observations:
        ctx.fail('a miner peer was penalised while the input chain was forking',
                 {'log': penalties, 'observations': ctx.run.penalty_observations})
