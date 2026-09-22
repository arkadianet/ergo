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
    # NOT `assertion_1_peering`: it requires every node to hold a peer at
    # one instant, and the two miners cannot peer with each other here,
    # so the second one's only possible peer is the follower. A momentary
    # gap in that single connection failed a scenario whose own evidence
    # — two peers observed, 554 samples carrying a second tree — showed
    # it had run. `follower_saw_both_miners` below is the check that
    # answers the question this scenario actually asks.

    # Watch `forks` for the whole window: it is an instantaneous count of
    # competing trees retained under the best ordering block, so a
    # scenario that only read it at the end would usually read 1.
    fork_counts, fork_samples = [], []
    peers_seen = ctx.evidence.get('follower_peers_after_seed') or 0
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
            peers_seen = max(peers_seen,
                             len(smoke.api('rust', '/peers/connected') or []))
            reached = smoke.scala_height(ctx.run)
        except smoke.Unavailable:
            pass
        if reached >= target:
            break
        ctx.run.idle(0.5)

    ctx.note('ordering_window', {'start_height': start, 'target': target,
                                 'reached': reached})
    # Did the follower ever actually see both miners? Either a two-peer
    # sighting anywhere in the window or a retained second tree proves
    # it; `forks > 1` is the stronger of the two, because it is the
    # competing tree itself rather than the connection that carried it.
    ctx.note('follower_saw_both_miners', {
        'max_peers_observed': peers_seen,
        'samples_with_more_than_one_tree': len(fork_samples),
    })
    if peers_seen < 2 and not fork_samples:
        ctx.fail('the follower never held two peers and never retained a second '
                 'input-block tree, so it cannot have seen the competing chains '
                 'this scenario exists to produce',
                 {'max_peers_observed': peers_seen})
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

    # The series has to record each reference's OWN ordering id, or the
    # comparison below silently falls back to the shared one and can
    # attribute the second miner's chain to the first miner's block.
    if not common.series_carries_reference_ordering(ctx.run.series):
        ctx.fail('the sample series does not record the second miner\'s own '
                 'ordering id, so its chain cannot be compared coherently',
                 {'samples': len(ctx.run.series)})

    # EVERY sampled chain must be the same HISTORY as some reference's,
    # not merely built from blocks somebody published.
    coherence = common.evaluate_fork_coherence(ctx.run.series)
    ctx.note('chain_coherence', {
        'judged_samples': coherence['judged_samples'],
        'incoherent_samples': len(coherence['incoherent_samples']),
        'unconfirmed_one_block_leads': len(coherence['unconfirmed_one_block_leads']),
        'later_confirmation_samples': coherence['later_confirmation_samples'],
        'incoherent_sample': coherence['incoherent_samples'][:5],
        'unconfirmed_sample': coherence['unconfirmed_one_block_leads'][:5],
    })
    if coherence['incoherent_samples']:
        bad = coherence['incoherent_samples']
        ctx.fail(f"at {len(bad)} samples Rust's input chain was not the same "
                 'history as any miner\'s chain for the same ordering block',
                 {'sample': bad[:5]},
                 ids=[b['rust_chain'][0] for b in bad[:5] if b['rust_chain']])
    if coherence['unconfirmed_one_block_leads']:
        bad = coherence['unconfirmed_one_block_leads']
        ctx.fail(f'{len(bad)} times Rust led the miner by one input block that the '
                 f'miner never went on to publish within '
                 f"{coherence['later_confirmation_samples']} samples",
                 {'sample': bad[:5]},
                 ids=[b['unconfirmed_tip'] for b in bad[:5]])

    # The switches themselves, judged as applied/rolled-back SETS against
    # the chain of the reference the follower landed on.
    comparison = common.compare_fork_switches(ctx.run.series)
    ctx.note('fork_switches', {
        'rust': len(comparison['rust_switches']),
        'scala': len(comparison['scala_switches']),
        'scala2': len(comparison['scala2_switches']),
        'rust_sample': comparison['rust_switches'][:20],
    })
    if comparison['switches_matching_no_reference']:
        bad = comparison['switches_matching_no_reference']
        ctx.fail(f'{len(bad)} fork switches produced a chain matching no miner: '
                 'the blocks applied and rolled back do not correspond to any '
                 'reference chain under the same ordering block',
                 {'sample': bad[:5]})

    # A PASS REQUIRES an observed switch. `forks > 1` proves the follower
    # retained a competing tree, which is the precondition; it does not
    # prove anything about switching between them, and a run that
    # sampled no switch has not judged the switch property at all.
    if not comparison['rust_switches']:
        ctx.note('result_qualifier', 'NOT ESTABLISHED')
        ctx.fail('no input-chain fork switch was observed on Rust, so the switch '
                 'property was never judged — NOT ESTABLISHED, not a pass '
                 f"(forks reached {max(fork_counts) if fork_counts else None} in "
                 f'{len(fork_samples)} samples, so the trees were there)',
                 {'fork_count_samples': len(fork_counts),
                  'max_forks': max(fork_counts) if fork_counts else None,
                  'scala_switches': len(comparison['scala_switches']),
                  'scala2_switches': len(comparison['scala2_switches'])})
    # Rolled-back blocks a miner still holds are TELEMETRY here, not a
    # verdict. The two miners cannot peer with each other, so each keeps
    # its own competing fork indefinitely and every switch the follower
    # makes necessarily rolls back blocks the other one is still
    # holding. What makes a rollback wrong is what replaced it, and that
    # is the check above.
    ctx.note('rolled_back_blocks_still_held_by_a_miner',
             len(comparison['rolled_back_blocks_still_held_by_a_miner']))

    orphans, off_by_ordering = common.chain_members_scala_never_had(ctx.run.series)
    ctx.note('chain_members_no_miner_ever_published', orphans[:20])
    ctx.note('chain_members_seen_under_a_neighbouring_ordering_id',
             {'count': len(off_by_ordering), 'sample': off_by_ordering[:10],
              'reading': 'the reference read route pairs a new bestOrdering '
                         'with the previous chain (F15/D8), so a block both '
                         'miners published lands under a neighbouring id'})
    if orphans:
        ctx.fail(f'{len(orphans)} blocks sat on Rust\'s input chain that NO miner '
                 'ever published anywhere in the run',
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
