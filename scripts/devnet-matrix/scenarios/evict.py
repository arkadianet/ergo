"""The reconstruction fallback, forced by a peer that serves wrong bodies.

Three earlier attempts tried to starve the follower of input-block
bodies through configuration and failed, for a reason worth keeping:
the rebuild assembles from the node's MEMPOOL as well as its input-block
cache, so shrinking the cache does not starve it. With D4 and D5 in
place the port simply does not produce a Merkle mismatch against this
miner, and no `[input_blocks.bounds]` lever changes that.

  1. fresh data dir + a 4-entry transaction cache, unfunded chain
     → 3/3 reconstructed. Correct: coinbase-only blocks carry no
     input-chain transactions, so the rebuild cannot be wrong.
  2. the same, funded, plus `records_per_ordering = 2`
     → 0 reconstructions AND 0 fallbacks. The follower held no input
     chain at all, so it never ATTEMPTED a rebuild and took the ordinary
     download silently. (That silence is now its own telemetry event,
     `ordering_reconstruct_skipped`, added to the node for this.)
  3. funded, tree left to form, only the bodies starved
     → 3/3 reconstructed again.

So the lever is a PEER, not a bound. `p2p_adversary
input_block_wrong_body` relays the follower's own input-block
announcements back to it — which registers it as a source — and then
answers the resulting body requests (code 105) with transactions the
announcement does not commit to. The rebuilt transactions root then
cannot match the header's.

What has to hold: a fallback fires with a mismatch reason, and the block
the node applies at that height is the block the miner has. A fallback
that lands anywhere else is the wrong fallback, and that judgement is
smoke.py's `evaluate_mismatch_recovery`, not a local re-derivation.
"""
import subprocess
import time

import lifecycle
import smoke
from smoke import Unavailable, api, api_retry

from . import common

NODES = ('scala', 'rust')
# A miner reward matures at ordering block 11 (`minerRewardDelay = 10`),
# and the workload cannot start before there is a coin to spend.
BLOCKS_BEFORE_ADVERSARY = 13
BLOCKS_UNDER_ADVERSARY = 8
PAYMENTS_PER_BLOCK = 4
PAYMENT_NANOERG = 1_000_000
ADVERSARY_SECONDS = 900
ADVERSARY_SOURCE = '127.211.0.1'

# The reasons that mean "the node refused its own rebuild", as opposed to
# an ingredient it never had. A wrong body produces the first kind: the
# transactions arrive, assemble, and hash to the wrong root.
MISMATCH_REASONS = tuple(smoke.MERKLE_MISMATCH_REASONS)


def _fund(ctx):
    deadline = min(ctx.run.deadline, time.monotonic() + 900)
    balance = 0
    while time.monotonic() < deadline:
        try:
            balance = (api('scala', '/wallet/balances') or {}).get('balance') or 0
        except Unavailable:
            balance = 0
        if balance:
            break
        ctx.run.idle(1)
    address = (api_retry('scala', '/wallet/addresses', ctx.run.deadline,
                         what='the miner wallet address') or [None])[0]
    ctx.note('funding', {'balance_nano': balance, 'address': address})
    return balance, address


def _pump(ctx, address, sent):
    """Keep a payment in flight, so the input chain the miner seals is
    never empty and the ordering blocks carry transactions to get wrong."""
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


def _adversary_binary():
    target = smoke.ROOT / 'target' / 'release' / 'examples' / 'p2p_adversary'
    if not target.exists():
        raise RuntimeError(
            f'{target} not built; run `cargo build --release --example '
            'p2p_adversary -p ergo-node`')
    return target


def run(ctx):
    import campaign

    smoke.assertion_1_peering(ctx.run, ctx.evidence)
    common.wait_ordering_blocks(ctx, BLOCKS_BEFORE_ADVERSARY, 'pre_adversary')

    balance, address = _fund(ctx)
    if not balance or not address:
        ctx.fail('no spendable coin on the miner wallet, so the ordering blocks '
                 'would carry nothing but the coinbase and the rebuild would be '
                 'trivially right whatever bodies it was given',
                 {'balance_nano': balance, 'address': address})
        return
    sent = _pump(ctx, address, [])

    collector = common.EventCollector(ctx)
    collector.poll()
    watermark = collector.highest_seen
    start = smoke.scala_height(ctx.run)

    binary = _adversary_binary()
    command = [str(binary),
               f'{lifecycle.P2P_HOST["rust"]}:{lifecycle.P2P["rust"]}', 'devnet',
               f'127.0.0.1:{lifecycle.REST["rust"]}',
               'input_block_wrong_body', str(ADVERSARY_SECONDS)]
    ctx.note('adversary_command', ' '.join(command))
    adversary = subprocess.Popen(command, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True,
                                 start_new_session=True)
    ctx.note('adversary_pid', adversary.pid)

    target, reached, last, seen = start + BLOCKS_UNDER_ADVERSARY, start, start, set()
    try:
        while time.monotonic() < ctx.run.deadline:
            collector.poll()
            campaign.drain_utxo_watch(ctx, seen)
            try:
                reached = smoke.scala_height(ctx.run)
            except Unavailable:
                pass
            if reached > last:
                last = reached
                _pump(ctx, address, sent)
            if reached >= target:
                break
            ctx.run.idle(0.5)
    finally:
        # By PID, and only ours: the harness is a process this scenario
        # started and nothing else may be signalled.
        if adversary.poll() is None:
            adversary.terminate()
        try:
            stdout, _ = adversary.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            adversary.kill()
            stdout, _ = adversary.communicate()
        ctx.note('adversary', {'returncode': adversary.returncode,
                               'stdout': (stdout or '')[-4000:]})
    collector.poll()

    ctx.note('window', {'start_height': start, 'target': target,
                        'reached': reached, 'payments_submitted': len(sent)})
    if reached < target:
        ctx.fail(f'the miner produced {reached - start} of the '
                 f'{BLOCKS_UNDER_ADVERSARY} ordering blocks the adversary window '
                 'needs (upstream F11); the shortfall is reported, never absorbed',
                 {'reached': reached, 'target': target})

    ctx.note('event_collection', collector.summary(watermark))
    if collector.lost_in_window(watermark):
        ctx.fail('the event feed evicted entries between polls, so the outcomes '
                 'of this window are incomplete',
                 {'collection': collector.summary(watermark)})

    # Did the adversary actually get asked, and answer?
    answered = [line for line in ((ctx.evidence.get('adversary') or {})
                                  .get('stdout') or '').splitlines()
                if 'answered' in line]
    ctx.note('adversary_answered', answered)
    reached_node = [line for line in
                    smoke.rust_log_lines(ADVERSARY_SOURCE, limit=20000)
                    if ADVERSARY_SOURCE in line]
    ctx.note('adversary_seen_by_the_node', {'log_lines': len(reached_node),
                                            'sample': reached_node[:5]})

    window = collector.window(watermark)
    ordering = [e for e in window if e['kind'].startswith('ordering_')]
    fallbacks = [e for e in ordering
                 if e['kind'] == 'ordering_reconstruct_fallback']
    mismatch = [e for e in fallbacks if (e.get('detail') or '') in MISMATCH_REASONS]
    reconstructions = [e for e in ordering if e['kind'] == 'ordering_reconstructed']
    skipped = [e for e in ordering if e['kind'] == 'ordering_reconstruct_skipped']
    ctx.note('ordering_outcomes', {
        'ordering_reconstruct_fallback': len(fallbacks),
        'with_a_mismatch_reason': len(mismatch),
        'ordering_reconstructed': len(reconstructions),
        'ordering_reconstruct_skipped': len(skipped),
        'fallback_reasons': smoke._tally(e.get('detail') for e in fallbacks),
        'skipped_reasons': smoke._tally(e.get('detail') for e in skipped),
    })

    if not mismatch:
        ctx.fail('no ordering block fell back with a Merkle-mismatch reason even '
                 'though a peer was serving bodies the announcements do not commit '
                 'to, so the fallback path was NOT exercised',
                 {'fallbacks': len(fallbacks), 'reconstructions': len(reconstructions),
                  'skipped': len(skipped),
                  'adversary_stdout': (ctx.evidence.get('adversary') or {}).get('stdout'),
                  'rust_log': smoke.rust_log_lines('input_blocks')})

    # Whatever it fell back to has to be the miner's block at that height.
    heights = [e.get('height') for e in ordering if e.get('height') is not None]
    if not heights:
        ctx.fail('the follower reported no ordering outcome with a height, so the '
                 'fallback could not be checked against the miner',
                 {'window': ordering[:10]})
        return
    at_height, unread = common.scala_blocks_by_height(ctx, min(heights), max(heights))
    ctx.note('scala_heights_unread', unread)
    if unread:
        ctx.fail(f'the miner could not be read for {len(unread)} of the heights the '
                 'fallback covers, so the recovery cannot be checked against it',
                 {'heights': unread})
    recovery = smoke.evaluate_mismatch_recovery(
        common.ordering_stream(window), at_height)
    ctx.note('mismatch_recovery', recovery)
    for message, evidence in recovery['failures']:
        ctx.fail(message, evidence)

    # And the node has to agree with the miner afterwards. The adversary
    # is gone by now, so recovery is the only thing left to observe.
    deadline = min(ctx.run.deadline, time.monotonic() + 300)
    agreed = False
    while time.monotonic() < deadline:
        try:
            scala = api('scala', '/info') or {}
            rust = api('rust', '/info') or {}
        except Unavailable:
            ctx.run.idle(0.5)
            continue
        if (rust.get('bestFullHeaderId')
                and rust.get('bestFullHeaderId') == scala.get('bestFullHeaderId')):
            agreed = True
            break
        ctx.run.idle(0.5)
    ctx.note('agreed_with_miner_after_fallback', agreed)
    if not agreed:
        ctx.fail('after falling back to full downloads the follower never held the '
                 "miner's tip",
                 {'rust': api_retry('rust', '/info', ctx.run.deadline, what='rust'),
                  'scala': api_retry('scala', '/info', ctx.run.deadline,
                                     what='scala')})

    # The honest peer must be untouched by any of this.
    penalties = [line for line in smoke.rust_log_lines('penalizing peer', limit=2000)
                 if str(lifecycle.P2P['scala']) in line]
    ctx.note('penalty_log_lines_naming_the_miner', penalties)
    if penalties:
        ctx.fail('the honest miner was penalised while an adversary served wrong '
                 'bodies', {'log': penalties})
