"""SIGKILL the follower mid-chain and watch it come back.

`kill -9`, not a clean stop: the point is a node that had no chance to
flush anything, which is the shape a crash takes.

The bar is CONVERGENCE, not the fallback. The brief asked for "the first
post-restart ordering block used the fallback"; D7 (transitive waitlist
reconnection) makes that no longer true — a cold-started node can
recover its input chain before the next ordering block arrives, and runs
10 and 11 reconstructed every post-restart block.

The chain carries a workload (a funded miner, payments in flight every
ordering block, on both sides of the kill): an unfunded chain seals
coinbase-only input blocks, and a Scala reference follower's lag over
them measured the quiet case (the first two F13 restart runs, 6 unfunded
blocks from genesis). `--ordering-blocks` sets the pre-kill length, and
every follower's lag over the samples after the kill is reported beside
the whole-run numbers (`follower_lag_after_restart`). So the requirement is
that the follower is back on the miner's tip within 3 ordering blocks,
and the reconstruct/fallback split is recorded as telemetry: either
outcome passes. The `evict` scenario is where the fallback path is
required to fire.

`--restart-victim scala-followers` (REVIEW-2563 §3.3 item 2) kills the
Scala reference followers instead — every one in the run, at the same
instant — and leaves the Rust follower and the miner running. It is the
only way to watch a Scala node restart: the #2563 pending store is in
memory and comes back empty, and #2506's processed-tip replay acts on the
reconnect. The bar is the same (each victim back on the miner's tip on a
NEW ordering block within 3), and the telemetry is per victim: its
reconstruction accounting and waitlist over the post-kill log, the time
from respawn to the miner's tip, and its pending store's replay burst
(`smoke.restart_recovery`).
"""
import concurrent.futures
import time

import lifecycle
import smoke
from smoke import Unavailable, api, api_retry

from . import common


def _info_or_error(node):
    """`/info` for failure evidence, never raising.

    A victim that did not come back is exactly the node whose `/info`
    fails; letting that raise would replace the "did not rejoin" failure
    with an `Unavailable` and skip the checks after it.
    """
    try:
        return api(node, '/info')
    except Unavailable as error:
        return {'unavailable': str(error)}


NODES = ('scala', 'rust')
# `--reference-follower` may add a Scala follower; it is seeded from the
# miner's directory rather than started cold, for the reason
# `reconstruct_rate` states.
START_NODES = ('scala', 'rust')
SEEDED_NODES = ('scala2', 'scala3')
BLOCKS_BEFORE_RESTART = 6
CONVERGENCE_ORDERING_BLOCKS = 3
# Funded ordering blocks observed after convergence, so the post-kill lag
# has a window of its own rather than the convergence race alone.
BLOCKS_AFTER_RESTART = 5
PAYMENTS_PER_BLOCK = 3


def lag_after(series, since_epoch_s):
    """Every follower's lag over the samples taken at or after
    `since_epoch_s` (the kill), by smoke's one lag definition. Pure."""
    after = [s for s in series if (s.get('at') or 0) >= since_epoch_s]
    out = {role: smoke.lag_distribution(after, key) for role, key in
           (('rust_follower', 'rust_tip'), ('scala_follower', 'scala2_tip'),
            ('scala_follower_patched', 'scala3_tip'))}
    return dict(out, since_epoch_s=since_epoch_s, samples=len(after))


def post_restart_blocks(ctx):
    """The funded post-kill window: `--post-ordering-blocks`, else 5.

    The re-measure plan wants at least 10 funded blocks after the kill
    (REVIEW-2563 §3.4), so a restart's post-kill lag has a window of its
    own rather than the convergence race alone.
    """
    return getattr(ctx.args, 'post_ordering_blocks', None) or BLOCKS_AFTER_RESTART


def victims_for(restart_victim, running):
    """The nodes one restart kills. Pure.

    `rust` is the M3 scenario. `scala-followers` is every Scala
    reference follower in the run — `scala2` (stock) and `scala3`
    (patched), whichever `--reference-follower` started — so a stock and
    a patched store restart under the same miner at the same moment.
    """
    if restart_victim == 'rust':
        return ('rust',)
    victims = tuple(n for n in SEEDED_NODES if n in running)
    if not victims:
        raise ValueError('--restart-victim scala-followers found no Scala '
                         'follower in the run; add --reference-follower')
    return victims


def _respawn(ctx, campaign, lifecycle, node):
    """Start a killed node again; one retry, as for the Rust victim."""
    attempts = []
    try:
        lifecycle.spawn(node)
    except RuntimeError as error:
        attempts.append(str(error))
        time.sleep(campaign.KILL_SETTLE_SECONDS * 2)
        lifecycle.spawn(node)
    ctx.run.started(node)
    return attempts


def run(ctx):
    import campaign
    import lifecycle

    victim_mode = getattr(ctx.args, 'restart_victim', 'rust') or 'rust'
    if victim_mode != 'rust':
        _run_scala_victims(ctx, campaign, lifecycle)
        return

    # A reference follower, if one was asked for, on the miner's chain
    # before anything is measured against it — and before peering is
    # asserted, because until the seed starts it the node is not there
    # to have peers.
    if set(SEEDED_NODES) & set(lifecycle.NODES):
        common.seed_second_miner(ctx, campaign, lifecycle, nodes=SEEDED_NODES)
    smoke.assertion_1_peering(ctx.run, ctx.evidence)

    balance, address = common.fund_miner(ctx, 'scala')
    sent, refused = [], []

    def pump():
        if balance and address:
            common.pump_payments(ctx, address, sent, 'scala',
                                 PAYMENTS_PER_BLOCK, rejected=refused)

    if not balance:
        ctx.fail('the miner was never funded, so the restart window carried no '
                 'workload and the followers\' lag measured the quiet case',
                 {'balance_nano': balance})
    pre_blocks = ctx.args.ordering_blocks or BLOCKS_BEFORE_RESTART
    pump()
    common.wait_ordering_blocks(ctx, pre_blocks, 'pre_restart', on_block=pump)

    # Fold the drop counters forward: they are per-process, and the
    # restart resets them. `Run` already carries the mechanism.
    before = api_retry('rust', '/api/v1/status', ctx.run.deadline,
                       what='the follower status before the restart')
    ctx.note('status_before_restart', before.get('input_blocks'))
    restart_height = smoke.scala_height(ctx.run)
    # A SIGKILL restarts the process, so its ring restarts at seq 1 and
    # every event in the feed afterwards is post-restart by construction.
    events_before_restart = common.latest_event_seq(ctx)

    killed_at = time.time()
    killed = campaign.kill_hard('rust')
    ctx.note('killed', {'pid': killed, 'signal': 'SIGKILL',
                        'at_ordering_height': restart_height,
                        'at_epoch_s': killed_at})
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
    respawned_at = time.time()
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
    pumped_at = restart_height
    while time.monotonic() < ctx.run.deadline:
        try:
            scala = api('scala', '/info') or {}
            rust = api('rust', '/info') or {}
        except Unavailable:
            ctx.run.idle(0.5)
            continue
        if (scala.get('fullHeight') or 0) > pumped_at:
            pumped_at = scala.get('fullHeight')
            pump()
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
                  'scala': _info_or_error('scala'), 'rust': _info_or_error('rust'),
                  'rust_log': smoke.rust_log_lines('input_blocks')})
    elif converged_at_height > target_height:
        ctx.fail(f'the follower converged only at height {converged_at_height}, '
                 f'past the {CONVERGENCE_ORDERING_BLOCKS}-block budget from '
                 f'{restart_height}', {'converged_at_height': converged_at_height})

    # The post-kill window, carrying the same workload.
    common.wait_ordering_blocks(ctx, post_restart_blocks(ctx), 'post_restart',
                                on_block=pump)
    ctx.note('workload', {'funded_balance_nano': balance,
                          'pre_restart_ordering_blocks': pre_blocks,
                          'payments_submitted': len(sent),
                          'payments_refused': len(refused),
                          'refusals': refused[:10]})

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
    ctx.note('follower_lag_after_restart', lag_after(ctx.run.series, killed_at))
    ctx.note('restart_recovery', {
        'rust': smoke.restart_recovery(ctx.run.series, respawned_at, 'rust')})


def _run_scala_victims(ctx, campaign, lifecycle):
    """The Scala-follower restart. Same shape as the Rust one: a funded
    pre-kill window, a simultaneous SIGKILL, convergence within 3
    ordering blocks on a NEW block, a funded post-kill window."""
    common.seed_second_miner(ctx, campaign, lifecycle, nodes=SEEDED_NODES)
    smoke.assertion_1_peering(ctx.run, ctx.evidence)
    victims = victims_for('scala-followers', lifecycle.NODES)
    ctx.note('restart_victims', {
        node: (ctx.roles or {}).get(node) for node in victims})

    balance, address = common.fund_miner(ctx, 'scala')
    sent, refused = [], []

    def pump():
        if balance and address:
            common.pump_payments(ctx, address, sent, 'scala',
                                 PAYMENTS_PER_BLOCK, rejected=refused)

    if not balance:
        ctx.fail('the miner was never funded, so the restart window carried no '
                 'workload and the followers\' lag measured the quiet case',
                 {'balance_nano': balance})
    pre_blocks = ctx.args.ordering_blocks or BLOCKS_BEFORE_RESTART
    pump()
    common.wait_ordering_blocks(ctx, pre_blocks, 'pre_restart', on_block=pump)

    restart_height = smoke.scala_height(ctx.run)
    # Where each victim's log stood at the kill: the post-restart
    # accounting reads from here (`spawn` appends to the same file).
    log_at_kill = {node: len(common._scala_log_lines(node)) for node in victims}
    before = {}
    for node in victims:
        try:
            info = api(node, '/info') or {}
        except Unavailable as error:
            info = {'error': str(error)}
        before[node] = {'fullHeight': info.get('fullHeight'),
                        'pendingInputAnnouncements':
                            info.get('pendingInputAnnouncements')}
    ctx.note('victims_before_kill', before)

    # The sampler keeps sampling the miner and the Rust follower while the
    # victims are down; they read as down, not as a failed sweep.
    ctx.run.expect_down(victims)
    killed_at = time.time()
    killed = campaign.kill_hard_many(victims)
    ctx.note('killed', {'pids': killed, 'signal': 'SIGKILL',
                        'at_ordering_height': restart_height,
                        'at_epoch_s': killed_at})
    # Respawned CONCURRENTLY, so the stock and the patched follower come
    # back together as they died together: one after the other, the
    # second waited out the first's JVM start (~5 s in the first
    # validation run), and a paired comparison would carry that head start.
    attempts, respawned_at = {}, {}

    def respawn(node):
        attempts[node] = _respawn(ctx, campaign, lifecycle, node)
        respawned_at[node] = time.time()

    with concurrent.futures.ThreadPoolExecutor(len(victims)) as pool:
        for future in [pool.submit(respawn, node) for node in victims]:
            future.result()
    for node in victims:
        # Its wallet is locked again after a restart. A follower does not
        # mine, but it is brought back exactly as it was started.
        lifecycle.init_wallet(node)
    ctx.note('respawn_attempts', attempts)
    ctx.note('respawned_at_epoch_s', respawned_at)
    try:
        lifecycle.wait_peered(names=list(lifecycle.NODES), timeout=120)
        peered = True
    except RuntimeError as error:
        peered = str(error)
    ctx.note('peered_after_respawn', peered)
    restarted_at = time.monotonic()

    # Convergence per victim: its full-block tip equal to the miner's at a
    # height ABOVE the one it died at (a SIGKILL leaves the data directory
    # intact, so agreement at the old height observes nothing).
    target_height = restart_height + CONVERGENCE_ORDERING_BLOCKS
    converged = {node: None for node in victims}
    seconds = {node: None for node in victims}
    pumped_at = restart_height
    while time.monotonic() < ctx.run.deadline and None in converged.values():
        try:
            scala = api('scala', '/info') or {}
        except Unavailable:
            ctx.run.idle(0.5)
            continue
        if (scala.get('fullHeight') or 0) > pumped_at:
            pumped_at = scala.get('fullHeight')
            pump()
        for node in victims:
            if converged[node] is not None:
                continue
            try:
                info = api(node, '/info') or {}
            except Unavailable:
                continue
            height = info.get('fullHeight') or 0
            if (info.get('bestFullHeaderId')
                    and info.get('bestFullHeaderId') == scala.get('bestFullHeaderId')
                    and height > restart_height):
                converged[node] = height
                seconds[node] = round(time.monotonic() - restarted_at, 1)
        if (scala.get('fullHeight') or 0) > target_height:
            break
        ctx.run.idle(0.5)
    ctx.note('convergence', {
        'restart_height': restart_height,
        'budget_ordering_blocks': CONVERGENCE_ORDERING_BLOCKS,
        'converged_at_height': converged,
        'seconds_after_peering': seconds,
    })
    for node in victims:
        if converged[node] is None:
            ctx.fail(f'{node} did not rejoin the miner\'s tip on a NEW ordering '
                     f'block within {CONVERGENCE_ORDERING_BLOCKS} of a SIGKILL',
                     {'restart_height': restart_height,
                      'scala': _info_or_error('scala'),
                      node: _info_or_error(node)})
        elif converged[node] > target_height:
            ctx.fail(f'{node} converged only at height {converged[node]}, past '
                     f'the {CONVERGENCE_ORDERING_BLOCKS}-block budget from '
                     f'{restart_height}', {'converged_at_height': converged[node]})

    common.wait_ordering_blocks(ctx, post_restart_blocks(ctx), 'post_restart',
                                on_block=pump)
    ctx.note('workload', {'funded_balance_nano': balance,
                          'pre_restart_ordering_blocks': pre_blocks,
                          'payments_submitted': len(sent),
                          'payments_refused': len(refused),
                          'refusals': refused[:10]})

    # Per victim, over its post-kill log only: what it decided about each
    # ordering block after coming back, and how often it waitlisted.
    post = {}
    for node in victims:
        window = common._scala_log_lines(node)[log_at_kill[node]:]
        post[node] = {
            'role': (ctx.roles or {}).get(node),
            'from_line': log_at_kill[node],
            'accounting': common.scala_accounting(window),
            'waitlist': common.scala_waitlist(window),
        }
    ctx.note('post_restart_scala_outcomes', post)

    smoke.finalize_agreement(ctx.run, ctx.evidence)
    ctx.note('follower_lag_after_restart', lag_after(ctx.run.series, killed_at))
    ctx.note('restart_recovery', {
        node: smoke.restart_recovery(ctx.run.series, respawned_at[node], node)
        for node in victims})
