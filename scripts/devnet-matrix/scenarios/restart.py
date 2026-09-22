"""SIGKILL the follower mid-chain and watch it come back.

`kill -9`, not a clean stop: the point is a node that had no chance to
flush anything, which is the shape a crash takes.

The bar is CONVERGENCE, not the fallback. The brief asked for "the first
post-restart ordering block used the fallback"; D7 (transitive waitlist
reconnection) makes that no longer true — a cold-started node can
recover its input chain before the next ordering block arrives, and runs
10 and 11 reconstructed every post-restart block. So the requirement is
that the follower is back on the miner's tip within 3 ordering blocks,
and the reconstruct/fallback split is recorded as telemetry: either
outcome passes. The `evict` scenario is where the fallback path is
required to fire.
"""
import time

import lifecycle
import smoke
from smoke import Unavailable, api, api_retry

from . import common

NODES = ('scala', 'rust')
# `--reference-follower` may add a Scala follower; it is seeded from the
# miner's directory rather than started cold, for the reason
# `reconstruct_rate` states.
START_NODES = ('scala', 'rust')
SEEDED_NODES = ('scala2', 'scala3')
BLOCKS_BEFORE_RESTART = 6
CONVERGENCE_ORDERING_BLOCKS = 3


def run(ctx):
    import campaign
    import lifecycle

    smoke.assertion_1_peering(ctx.run, ctx.evidence)
    # A reference follower, if one was asked for, on the miner's chain
    # before anything is measured against it.
    if set(SEEDED_NODES) & set(lifecycle.NODES):
        common.seed_second_miner(ctx, campaign, lifecycle, nodes=SEEDED_NODES)
    common.wait_ordering_blocks(ctx, BLOCKS_BEFORE_RESTART, 'pre_restart')

    # Fold the drop counters forward: they are per-process, and the
    # restart resets them. `Run` already carries the mechanism.
    before = api_retry('rust', '/api/v1/status', ctx.run.deadline,
                       what='the follower status before the restart')
    ctx.note('status_before_restart', before.get('input_blocks'))
    restart_height = smoke.scala_height(ctx.run)
    # A SIGKILL restarts the process, so its ring restarts at seq 1 and
    # every event in the feed afterwards is post-restart by construction.
    events_before_restart = common.latest_event_seq(ctx)

    killed = campaign.kill_hard('rust')
    ctx.note('killed', {'pid': killed, 'signal': 'SIGKILL',
                        'at_ordering_height': restart_height})
    # One retry. The settle in `kill_hard` is empirical, and losing the
    # whole scenario to a data-directory lock that was a second from
    # being free would be a harness failure reported as a follower one.
    # A SECOND failure is real and is allowed to propagate.
    attempts = []
    try:
        lifecycle.spawn('rust')
    except RuntimeError as error:
        attempts.append(str(error))
        time.sleep(campaign.KILL_SETTLE_SECONDS * 2)
        lifecycle.spawn('rust')
    ctx.note('respawn_attempts', attempts)
    ctx.run.started('rust')
    lifecycle.wait_peered()
    restarted_at = time.monotonic()

    # Convergence means the follower rejoined the miner on a block it had
    # to PROCESS after coming back — not that its store survived the
    # kill. The data directory is intact across a SIGKILL, so the node is
    # already on the miner's tip the moment it finishes loading; a check
    # that accepted that would pass in zero seconds having observed
    # nothing. So the agreement has to be at a height ABOVE the one it
    # died at, and still inside the 3-ordering-block budget.
    target_height = restart_height + CONVERGENCE_ORDERING_BLOCKS
    converged_at_height = None
    resumed_at_death_height = False
    while time.monotonic() < ctx.run.deadline:
        try:
            scala = api('scala', '/info') or {}
            rust = api('rust', '/info') or {}
        except Unavailable:
            ctx.run.idle(0.5)
            continue
        agreed = (rust.get('bestFullHeaderId')
                  and rust.get('bestFullHeaderId') == scala.get('bestFullHeaderId'))
        height = rust.get('fullHeight') or 0
        if agreed and height <= restart_height:
            # Recorded, not credited: it says the store came back, which
            # is worth knowing and is not what this scenario measures.
            resumed_at_death_height = True
        if agreed and height > restart_height:
            converged_at_height = height
            break
        if (scala.get('fullHeight') or 0) > target_height:
            break
        ctx.run.idle(0.5)

    ctx.note('convergence', {
        'restart_height': restart_height,
        'budget_ordering_blocks': CONVERGENCE_ORDERING_BLOCKS,
        'converged_at_height': converged_at_height,
        'resumed_at_the_height_it_died_at': resumed_at_death_height,
        'seconds': round(time.monotonic() - restarted_at, 1),
    })
    if converged_at_height is None:
        ctx.fail(f'the follower did not rejoin the miner\'s tip on a NEW ordering '
                 f'block within {CONVERGENCE_ORDERING_BLOCKS} of a SIGKILL',
                 {'restart_height': restart_height,
                  'scala': api('scala', '/info'), 'rust': api('rust', '/info'),
                  'rust_log': smoke.rust_log_lines('input_blocks')})
    elif converged_at_height > target_height:
        ctx.fail(f'the follower converged only at height {converged_at_height}, '
                 f'past the {CONVERGENCE_ORDERING_BLOCKS}-block budget from '
                 f'{restart_height}', {'converged_at_height': converged_at_height})

    # Telemetry, not a bar (D7).
    events = common.rust_events(ctx)
    window = [e for e in events if e['kind'].startswith('ordering_')]
    first = window[0] if window else None
    reconstructed = sum(1 for e in window if e['kind'] == 'ordering_reconstructed')
    fallback = sum(1 for e in window
                   if e['kind'] == 'ordering_reconstruct_fallback')
    if not window:
        ctx.fail('the follower reported no ordering outcome after the restart, so '
                 'nothing about its recovery was observed',
                 {'events': len(events),
                  'seq_before_restart': events_before_restart,
                  'rust_log': smoke.rust_log_lines('input_blocks')})
    ctx.note('post_restart_ordering_outcomes', {
        'first_kind': first['kind'] if first else None,
        'first_detail': first.get('detail') if first else None,
        'ordering_reconstructed': reconstructed,
        'ordering_reconstruct_fallback': fallback,
        'note': 'D7 lets a cold node recover before the next ordering block; '
                'either outcome passes, and the split is the observation',
        'seq_before_restart': events_before_restart,
    })

    # The recovery itself still has to be CORRECT wherever a mismatch
    # fallback fired: smoke.py's evaluator, not a weaker local one.
    heights = [e.get('height') for e in window if e.get('height') is not None]
    if heights:
        at_height, unread = common.scala_blocks_by_height(
            ctx, min(heights), max(heights))
        ctx.note('scala_heights_unread', unread)
        recovery = smoke.evaluate_mismatch_recovery(
            common.ordering_stream(events), at_height)
        ctx.note('mismatch_recovery', recovery)
        for message, evidence in recovery['failures']:
            ctx.fail(message, evidence)

    smoke.finalize_agreement(ctx.run, ctx.evidence)
