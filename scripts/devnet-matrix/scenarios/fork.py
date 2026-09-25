"""Two miners: competing input-block trees under one ordering block.

The only way to make the follower switch input-chain forks on a private
devnet is to give it two miners. The scenario counts the switches
(`/api/v1/status.input_blocks.forks > 1` at some sample, and the chain
changes the sampler recorded), and checks each against the miner:
a block Rust applied that Scala never had under the same ordering id is
a chain Scala lacks — the D3 sibling-completion guard — and a block Rust
rolled back that Scala kept is a switch Scala never made.

The two-miner window is FUNDED: miner 1's wallet matures and splits a
coinbase into a pool of boxes before the second miner is seeded, and on
every ordering block it signs payments, each spending its own pool box,
that are posted to BOTH miners' mempools, so both competing input chains
carry transactions whichever miner wins. That is what makes the
followers' reconstruction accounting over the window (the #2562
committed-prefix question) mean anything: over empty input blocks every
prefix rebuilds the same root. Each ordering block's NAMED input tip is
recorded beside the chain every follower held under its parent
(`named_tip_vs_held`).
"""
import time

import smoke

from . import common

NODES = ('scala', 'scala2', 'rust')
ORDERING_BLOCKS = 25
# Ordering blocks of shared history before the second miner joins.
SHARED_BLOCKS = 4
# Payments per ordering block of the two-miner window, each signed by
# miner 1's wallet and posted to both miners.
PAYMENTS_PER_BLOCK = 3
MINERS = ('scala', 'scala2')

# The second miner is NOT started with the others: it is seeded from
# miner 1's data directory once there is a chain to copy (see
# `common.seed_second_miner`), because the reference node cannot hand the
# chain to a second Scala node on this host.
START_NODES = ('scala', 'rust')
# The second MINER, plus `--reference-follower patched`'s own slot when
# one is asked for; both are seeded the same way.
SEEDED_NODES = ('scala2', 'scala3')

# It mines from the copied tip without waiting to decide it is synced —
# it already holds the chain, and `offlineGeneration = false` would make
# it wait for a peer-driven sync that never completes here.
SCALA2_EXTRA = 'ergo.node.offlineGeneration = true\n'

# Three nodes on one loopback /16 (and Scala's outbound sockets all come
# from 127.0.0.1), and the follower's per-IP admission limit is 1 — it gates outbound dial SELECTION as well as inbound admission,
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
    # The two-miner window has to carry transactions. An unfunded chain
    # seals empty input blocks, and an ordering block over empty input
    # blocks has the same transactions root whichever prefix of them it
    # commits, so every follower rebuilds it from any chain it holds and
    # the reconstruction accounting measures nothing (see `fund_miner`).
    # Miner 1 is funded BEFORE the second miner is seeded, so every block
    # of the window can carry payments, and each payment is posted to both
    # miners: posted to miner 1 alone, it never reached a miner 2 that was
    # winning the race (`pump_payments_to_all`). Each payment spends its
    # own box from a pool split off one coinbase and confirmed before the
    # seed, so it is valid on either miner's chain (`fan_out`).
    balance, address = common.fund_miner(ctx, 'scala')
    ctx.note('funding', {'balance_nano': balance, 'address': address})
    if not balance or not address:
        ctx.fail('no spendable coin on miner 1, so the two-miner window seals '
                 'empty input blocks and any prefix of them rebuilds the same '
                 'root', {'balance_nano': balance, 'address': address})
    blocks = ctx.args.ordering_blocks or ORDERING_BLOCKS
    pool = []
    if balance and address:
        pool = common.fan_out(
            ctx, address, 'scala',
            PAYMENTS_PER_BLOCK * (blocks + common.FANOUT_SPARE_BLOCKS))
        # One block deeper, so the split is not the tip the seed copies.
        common.wait_ordering_blocks(ctx, 1, 'payment_pool_depth')
    pool_size = len(pool)
    sent, refused, forwarded = [], [], {}

    def pump():
        if pool:
            common.pump_payments_to_all(ctx, address, sent, MINERS,
                                        PAYMENTS_PER_BLOCK, rejected=refused,
                                        forwarded=forwarded, pool=pool)

    # The seed restarts the follower, which empties its input chain. The
    # sample range that covers is recorded so the reset it causes is not
    # mistaken for a fork switch — and so a reset OUTSIDE it still is.
    samples_before_seed = len(ctx.run.series)
    common.seed_second_miner(ctx, campaign, lifecycle, nodes=SEEDED_NODES)
    samples_after_seed = len(ctx.run.series)
    # ONE measurement boundary for every follower's reconstruction
    # accounting, opened after the seed (which restarts the Rust follower
    # and so its event ring) and closed when the window ends: the funded
    # two-miner blocks, not the single-miner prefix before them.
    collector = common.EventCollector(ctx)
    ctx.note('reference_log_offsets',
             common.open_measurement_window(ctx, collector))
    watermark = ctx.collector_watermark
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
    start = smoke.scala_height(ctx.run)
    target = start + blocks
    reached = start
    pump()
    while time.monotonic() < ctx.run.deadline:
        collector.poll()
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
            height = smoke.scala_height(ctx.run)
            if height > reached:
                pump()
            reached = height
        except smoke.Unavailable:
            pass
        if reached >= target:
            break
        ctx.run.idle(0.5)
    close = common.close_measurement_window(ctx)
    ctx.note('measurement_close', close)
    ctx.note('event_collection', collector.summary(watermark))
    if collector.lost_in_window(watermark):
        ctx.fail('the event feed evicted entries between polls, so the Rust '
                 'follower\'s reconstruction outcomes in the window are '
                 'incomplete', {'collection': collector.summary(watermark)})
    ctx.note('workload', {'funded_balance_nano': balance,
                          'payment_pool_boxes': pool_size,
                          'payment_pool_left': len(pool),
                          'payments_submitted': len(sent),
                          'payments_refused': len(refused),
                          'refusals': refused[:10],
                          'posted_to_other_miners': forwarded})
    # What each ordering block of the window NAMED as its input tip,
    # against what every follower held under its parent. Read now, while
    # the nodes are up: the named tip lives only in the block's extension.
    ordering_blocks, unread_heights = common.ordering_blocks_between(
        'scala', start + 1, reached)
    ctx.note('ordering_blocks_in_window', {'blocks': ordering_blocks,
                                           'unread_heights': unread_heights})
    followers = [node for node, role in sorted((ctx.roles or {}).items())
                 if not lifecycle.ROLES[role].mines]
    ctx.note('named_tip_vs_held', common.named_tip_vs_held(
        ordering_blocks, list(ctx.run.series), followers))

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
    # Evidence that a block a reference led with is real, beyond the
    # reference listing it later: an ordering block naming it as its
    # input tip, or the reference's own log saying it mined it.
    confirmations = {}
    for node, role in (ctx.roles or {}).items():
        if lifecycle.ROLES[role].mines:
            for block in common.mined_input_blocks(common._scala_log_lines(node)):
                confirmations[block] = 'reference_log'
    for block in ordering_blocks:
        if block.get('named_input_tip'):
            confirmations[block['named_input_tip']] = 'named_tip'
    coherence = common.evaluate_fork_coherence(
        ctx.run.series, ctx.evidence.get('reference_snapshots') or (),
        confirmations)
    ctx.note('chain_coherence', {
        'judged_samples': coherence['judged_samples'],
        'incoherent_samples': len(coherence['incoherent_samples']),
        'unconfirmed_one_block_leads': len(coherence['unconfirmed_one_block_leads']),
        'held_from_restarted_reference': len(
            coherence['held_from_restarted_reference']),
        'lead_confirmations': coherence['lead_confirmations'],
        'later_confirmation_samples': coherence['later_confirmation_samples'],
        'incoherent_sample': coherence['incoherent_samples'][:5],
        'unconfirmed_sample': coherence['unconfirmed_one_block_leads'][:5],
        'held_sample': coherence['held_from_restarted_reference'][:5],
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
    comparison = common.compare_fork_switches(ctx.run.series, confirmations)
    ctx.note('fork_switches', {
        'rust': len(comparison['rust_switches']),
        'scala': len(comparison['scala_switches']),
        'scala2': len(comparison['scala2_switches']),
        'rust_sample': comparison['rust_switches'][:20],
    })
    # Resets to the empty chain are expected inside the restart this
    # scenario performs and unexplained anywhere else; a PASS needs a
    # GENUINE switch, which a reset is not. The rule is
    # `common.judge_fork_switches`, so a probe can drive it.
    restart_window = range(max(0, samples_before_seed - 5),
                           samples_after_seed + common.LATER_CONFIRMATION_SAMPLES)
    judged = common.judge_fork_switches(comparison, restart_window)
    ctx.note('resets_to_the_empty_chain', {
        'during_the_seed_restart': len(judged['resets_caused']),
        'elsewhere': len(judged['resets_uncaused']),
        'restart_sample_window': [restart_window.start, restart_window.stop],
        'sample': judged['resets_uncaused'][:5],
    })
    ctx.note('genuine_fork_switches', judged['genuine_switches'])
    if judged['qualifier']:
        ctx.note('result_qualifier', judged['qualifier'])
    for message, evidence in judged['failures']:
        ctx.fail(message, evidence)
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
