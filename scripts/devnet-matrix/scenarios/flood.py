"""The adversarial peer, against the follower only.

`ergo-node/examples/p2p_adversary input_block_flood` connects as a peer
and sends 10,000 syntactically valid input-block announcements at
height + 1, each naming a parent input block nobody has, then 1,000
`InputBlockTransactions` (code 104) deliveries for input blocks nobody
requested. Everything is well-formed on the wire: a malformed frame
would be rejected by the codec and would say nothing about §7.4.

The miner is never a target. What has to hold on the follower:

* every spec §7.4 bound the node publishes stays under its cap;
* resident memory grows by less than the byte caps plus 64 MiB — a
  bounded structure that still pins bytes is not bounded;
* the honest Scala peer is never penalised or dropped;
* the honest chain keeps advancing across the flood.

Afterwards the follower's `peers.redb` is purged: the harness binds each
slot to its own `127.<k>.0.1` and those addresses poison the address
book, starving the next run's dialer.
"""
import subprocess
import time

import smoke
from smoke import Unavailable, api, api_retry

from . import common

# The source address the harness binds its flood connection to
# (`src(210)` = 127.210.0.1). Log lines naming it are how this scenario
# proves the traffic actually reached the processor.
ADVERSARY_SOURCE = '127.210.0.1'

NODES = ('scala', 'rust')
ANNOUNCEMENTS = 10_000
DELIVERIES = 1_000
BLOCKS_BEFORE_FLOOD = 3
BLOCKS_AFTER_FLOOD = 3
PURGE_ADDRESS_BOOK = True

# The §7.4 caps this recipe's follower runs with. `waitlist_entries` is
# raised by `rust-node.toml` (the Scala miner publishes ~64 input blocks
# per ordering block, far above the crate default); everything else is
# the crate default. Stated here so the assertion is against a number a
# reader can check against `ergo-inputblocks/src/bounds.rs`, not against
# whatever the node happens to report.
CAPS = {
    'waitlist': 8192,             # [input_blocks.bounds] waitlist_entries
    'forks': 64,                  # Bounds::forks_per_ordering
    'staged_bytes': 64 * 1024 * 1024,   # Bounds::staging_bytes_total
}
# Resident-memory headroom over the byte caps: allocator slack, the
# JVM-free Rust node's own working set growth, and the log buffers the
# flood fills. A growth beyond this is a leak, not slack.
RSS_HEADROOM_KIB = 64 * 1024


def _adversary_binary():
    """The built harness. Not built here: a compile inside a running
    devnet competes with the node for the machine, and a scenario that
    silently rebuilt would measure a different binary than the campaign
    reported."""
    import lifecycle
    target = smoke.ROOT / 'target' / 'release' / 'examples' / 'p2p_adversary'
    if not target.exists():
        raise RuntimeError(
            f'{target} not built; run `cargo build --release --example '
            f'p2p_adversary -p ergo-node` (node binary: {lifecycle.node_binary()})')
    return target


def run(ctx):
    import campaign
    import lifecycle

    smoke.assertion_1_peering(ctx.run, ctx.evidence)
    common.wait_ordering_blocks(ctx, BLOCKS_BEFORE_FLOOD, 'pre_flood')

    pid = campaign.node_pid('rust')
    rss_before = campaign.rss_kib(pid)
    status_before = campaign.input_block_status()
    height_before = (api_retry('rust', '/info', ctx.run.deadline,
                               what='the follower height before the flood')
                     .get('fullHeight'))
    ctx.note('before_flood', {'pid': pid, 'rss_kib': rss_before,
                              'input_blocks': status_before,
                              'rust_height': height_before})
    if rss_before is None:
        ctx.fail('the follower\'s resident memory could not be read before the '
                 'flood, so the memory bound cannot be checked', {'pid': pid})

    binary = _adversary_binary()
    command = [str(binary),
               f'{lifecycle.P2P_HOST["rust"]}:{lifecycle.P2P["rust"]}', 'devnet',
               f'127.0.0.1:{lifecycle.REST["rust"]}',
               'input_block_flood', str(ANNOUNCEMENTS), str(DELIVERIES)]
    ctx.note('adversary_command', ' '.join(command))
    started = time.monotonic()
    # The harness is bounded by its own frame counts; the timeout is a
    # backstop, and a timeout is recorded rather than swallowed.
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=1800, check=False)
        ctx.note('adversary', {
            'returncode': completed.returncode,
            'seconds': round(time.monotonic() - started, 1),
            'stdout': completed.stdout[-4000:],
            'stderr': completed.stderr[-2000:],
        })
        if completed.returncode != 0:
            ctx.fail('the adversary harness did not deliver its traffic '
                     f'(exit {completed.returncode}), so the flood was not run',
                     {'stdout': completed.stdout[-4000:],
                      'stderr': completed.stderr[-2000:]})
    except subprocess.TimeoutExpired as error:
        ctx.fail('the adversary harness timed out, so the flood is not a complete '
                 'experiment', {'error': str(error)})

    # Peak, not final: the caps bound what the node HOLDS, and a
    # structure that overflowed and then drained would read as compliant
    # from a single reading at the end.
    peak = {key: 0 for key in CAPS}
    peak_rss = rss_before or 0
    watch_deadline = min(ctx.run.deadline, time.monotonic() + 120)
    while time.monotonic() < watch_deadline:
        try:
            status = campaign.input_block_status()
        except Unavailable:
            status = {}
        for key in CAPS:
            value = status.get(key)
            if value is not None:
                peak[key] = max(peak[key], value)
        rss = campaign.rss_kib(pid)
        if rss is not None:
            peak_rss = max(peak_rss, rss)
        ctx.run.idle(0.5)

    status_after = campaign.input_block_status()
    ctx.note('after_flood', {'input_blocks': status_after,
                             'peak_counters': peak,
                             'peak_rss_kib': peak_rss,
                             'rss_before_kib': rss_before})

    # DID IT LAND? A flood the node never read would leave every bound
    # inside its cap for the best possible reason, and this scenario
    # would report that as the node withstanding an attack it never
    # received. The node's own log naming the adversary's source address
    # is the proof, and it is required.
    reached = [line for line in smoke.rust_log_lines(ADVERSARY_SOURCE, limit=20000)
               if ADVERSARY_SOURCE in line]
    ctx.note('flood_reached_the_processor', {
        'source': ADVERSARY_SOURCE,
        'log_lines_naming_it': len(reached),
        'sample': reached[:5],
        'announcements_sent': ANNOUNCEMENTS,
        'note': 'fewer lines than announcements is expected: the node bans the '
                'source once its penalties accumulate, which is the bound '
                'working, and the count is how far it got',
    })
    if not reached:
        ctx.fail('no log line names the adversary, so the flood cannot be shown to '
                 'have reached the node at all — every bound below would then be '
                 'inside its cap for the wrong reason',
                 {'source': ADVERSARY_SOURCE,
                  'adversary_stdout': (ctx.evidence.get('adversary') or {})
                  .get('stdout')})

    common.check_bounds(ctx, {**status_after, **peak}, CAPS, 'flood')
    # WHERE the flood was stopped matters as much as that it was. A
    # bogus announcement carries an invalid PoW solution, so it is
    # refused at the announcement gate and never reaches a staging slot
    # or the waitlist — which is why those counters can stay at zero
    # through 10,000 frames. Recorded explicitly so the report does not
    # read a zero as "the memory bounds were stressed and held".
    ctx.note('where_the_flood_was_stopped', {
        'announcement_gate_rejections_naming_the_adversary': len(reached),
        'peak_waitlist': peak.get('waitlist'),
        'peak_staged_bytes': peak.get('staged_bytes'),
        'reading': 'announcements with an invalid PoW solution are refused '
                   'upstream of the §7.4 memory structures, so a zero here is '
                   'the gate holding, not the memory bounds being exercised',
    })

    # Memory: the byte caps plus headroom.
    if rss_before is not None:
        allowed = (CAPS['staged_bytes'] // 1024) + RSS_HEADROOM_KIB
        growth = peak_rss - rss_before
        ctx.note('rss_growth', {'kib': growth, 'allowed_kib': allowed})
        if growth > allowed:
            ctx.fail(f'the follower\'s resident memory grew {growth} KiB under the '
                     f'flood, past the {allowed} KiB the byte caps plus headroom '
                     'allow', {'rss_before_kib': rss_before,
                               'peak_rss_kib': peak_rss,
                               'input_blocks': status_after})

    # The honest peer, and the honest chain.
    penalties = smoke.rust_log_lines('penalizing peer')
    scala_penalties = [line for line in penalties
                       if str(lifecycle.P2P['scala']) in line]
    ctx.note('penalty_log_lines', penalties)
    ctx.note('penalty_log_lines_naming_the_miner', scala_penalties)
    if scala_penalties or ctx.run.penalty_observations:
        ctx.fail('the honest Scala peer was penalised while an adversary flooded '
                 'the follower',
                 {'log': scala_penalties,
                  'observations': ctx.run.penalty_observations})
    if 'absent' in ctx.run.peer_states:
        ctx.fail('the honest Scala peer was dropped during the flood',
                 {'peer_states': sorted(ctx.run.peer_states)})

    common.wait_ordering_blocks(ctx, BLOCKS_AFTER_FLOOD, 'post_flood')
    height_after = (api_retry('rust', '/info', ctx.run.deadline,
                              what='the follower height after the flood')
                    .get('fullHeight'))
    ctx.note('chain_progress', {'before': height_before, 'after': height_after})
    if (height_after or 0) <= (height_before or 0):
        ctx.fail('the honest chain did not advance on the follower across the flood',
                 {'before': height_before, 'after': height_after,
                  'scala': api('scala', '/info')})

    # Drops are EXPECTED here — that is the bound working — but a
    # byte-level disagreement is not.
    totals = ctx.run.totals()
    ctx.note('drop_totals', totals)
    fatal = {r: totals[r] for r in smoke.FATAL_DROPS if totals.get(r)}
    if fatal:
        ctx.fail(f'byte-level disagreement recorded during the flood: {fatal}',
                 {'drops': totals})
