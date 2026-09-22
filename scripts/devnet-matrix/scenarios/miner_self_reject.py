"""What a Scala miner does to its OWN input-block solutions (F11).

Upstream `CandidateGenerator`'s `InputSolutionFound` arm reads
`cachedCandidate.get` without matching the solution to the candidate it
was found against, and clears the cache after every accept
(`CandidateGenerator.scala:270` at 62c10315), so a solution found
against a candidate the generator has since replaced is completed
against the wrong one, fails its own PoW check, and is thrown away with
`Invalid input block! PoW valid: false`.

This scenario MEASURES that, on whichever build `--build` names. It has
no pass criterion, deliberately: "never_sealed = 0" proves nothing on
its own, and a patch is only shown to work by the six denominators of
spec §7a moving together —

  submissions                  solutions the internal miner sent for validation
  replies_success              submissions the generator accepted
  replies_error                submissions it rejected, with a reply
  replies_missing              submissions that got NO reply at all (F11c:
                               a guard failure falls through to a case that
                               matches `AutolykosSolution`, not the wrapped
                               `SolutionFound`, so the sender waits forever)
  pow_failures                 `Invalid input block` — the race itself
  input_blocks_applied         input blocks the node actually applied
  input_blocks_on_winning_chain  of those, the ones that reached the best
                               input chain

A run with `--build stock` is the baseline; the same command with
`--build F11` is the patched arm. Both numbers go in the evidence pair
the F11 finding quotes.
"""
import re
import time

import smoke
from smoke import Unavailable, api, api_retry

from . import common

NODES = ('scala', 'rust')
ORDERING_BLOCKS = 40
PAYMENTS_PER_BLOCK = 3
PAYMENT_NANOERG = 1_000_000

# The pinned build's own lines, with their sources (62c10315). Matched
# as lower-cased substrings so a wording change reads as a zero WITH the
# unmatched-phrase note below, never as a silent measurement.
#
#   ErgoMiningThread.scala:80/:83   a solution is sent for validation
#   ErgoMiningThread.scala:74       StatusReply.Success(()) came back
#   ErgoMiningThread.scala:70       StatusReply.Error came back
#   CandidateGenerator.scala:280    the PoW check the race fails
#   CandidateGenerator.scala:286    the generator answered a submission
#
# `pow_failures` counts the generator's own WARN, not the exception
# text. At 62c10315 EACH failure puts that text on the log TWICE — once
# in the generator's `Processed solution … with the result Error(…)`
# echo and once in the stack trace under `ErgoMiningThread`'s ERROR — so
# a substring as loose as "invalid input block" doubles every failure.
# The text is counted separately as `pow_failure_reply_lines` and
# checked against that measured 2:1, which is the cross-check: a build
# that stops logging both sites is a build these phrases no longer
# describe. Measured on the Task 2 trial at stock 62c10315: 83 WARNs,
# 166 exception-text lines.
PHRASES = {
    'submissions_input': 'found solution for input block, sending it for validation',
    'submissions_ordering': 'found solution for ordering block, sending it for validation',
    'replies_success': 'solution accepted',
    'replies_error': 'accepting solution or preparing candidate did not succeed',
    'pow_failures': 'removing candidate due to invalid input block',
    'pow_failure_reply_lines': 'invalid input block! pow valid',
    'generator_processed': 'processed solution',
}

# `Input-block <id> mined @ height <h>!`
APPLIED = re.compile(r'input-block ([0-9a-f]{64}) mined @ height (\d+)',
                     re.IGNORECASE)


def count(lines):
    """The F11 denominators from one window of a Scala miner's log.

    Pure, so `campaign.py --self-test` can hand it a log that contains
    the race and check the arithmetic — including the case the counting
    exists to expose, a submission with no reply.
    """
    out = {key: 0 for key in PHRASES}
    out['input_blocks_applied'] = 0
    applied_ids = []
    for line in lines:
        low = line.lower()
        for key, phrase in PHRASES.items():
            if phrase in low:
                out[key] += 1
        match = APPLIED.search(low)
        if match:
            out['input_blocks_applied'] += 1
            applied_ids.append(match.group(1))
    out['submissions'] = out['submissions_input'] + out['submissions_ordering']
    out['replies'] = out['replies_success'] + out['replies_error']
    # Both PoW-failure sites have to keep logging: one WARN and two
    # lines of exception text per failure, as measured at 62c10315. A
    # different proportion means the phrases no longer mean what this
    # counting assumes — it is NOT a second, independent count of the
    # failures, and was never reported as one.
    out['pow_failure_lines_per_failure'] = (
        round(out['pow_failure_reply_lines'] / out['pow_failures'], 2)
        if out['pow_failures'] else None)
    out['pow_failure_sites_disagree'] = bool(
        out['pow_failures']
        and out['pow_failure_reply_lines'] != 2 * out['pow_failures'])
    # The F11c evidence: a submission the generator never answered. Not
    # derived by subtraction anywhere else, because a negative would
    # mean the phrases no longer say what this counting assumes.
    out['replies_missing'] = max(0, out['submissions'] - out['replies'])
    out['reply_accounting_inconsistent'] = out['replies'] > out['submissions']
    out['applied_input_block_ids'] = applied_ids
    out['distinct_applied_input_blocks'] = len(set(applied_ids))
    out['log_lines'] = len(lines)
    if not out['submissions']:
        out['unmatched'] = (
            'the miner logged no solution submission in this window; the F11 '
            'denominators are UNKNOWN, not zero — check the phrases against '
            'the build before reading anything into them')
    return out


def result_line(evidence):
    """The one line a measurement scenario prints and the report quotes."""
    miner = (evidence.get('miner') or {})
    chain = (evidence.get('winning_chain') or {})
    build = ((evidence.get('builds') or {}).get('scala_miner_patched')
             or {}).get('build', evidence.get('build', '?'))
    if miner.get('unmatched'):
        return (f'miner_self_reject [{build}]: NOT MEASURED — '
                f'{miner["unmatched"]}')
    rate = (round(miner['pow_failures'] / miner['submissions_input'], 4)
            if miner.get('submissions_input') else None)
    return (
        f'miner_self_reject [{build}]: '
        f'submissions {miner["submissions"]} '
        f'(input {miner["submissions_input"]}, '
        f'ordering {miner["submissions_ordering"]}), '
        f'replies {miner["replies_success"]} ok / {miner["replies_error"]} err / '
        f'{miner["replies_missing"]} missing, '
        f'pow_failures {miner["pow_failures"]}, '
        f'input_blocks_applied {miner["distinct_applied_input_blocks"]}, '
        f'on_winning_chain {chain.get("on_winning_chain", "?")}, '
        f'input pow-failure rate {rate}')


def _fund(ctx):
    """A spendable coin and an address.

    An unfunded chain seals coinbase-only input blocks; the race is
    about candidates being REPLACED, and candidates are replaced when
    transactions arrive, so the window has to carry a workload or it
    measures the quiet case only.
    """
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
    return balance, address


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


def run(ctx):
    import campaign

    smoke.assertion_1_peering(ctx.run, ctx.evidence)
    blocks = ctx.args.ordering_blocks or ORDERING_BLOCKS

    balance, address = _fund(ctx)
    ctx.note('funding', {'balance_nano': balance, 'address': address})
    if not balance or not address:
        ctx.fail('no spendable coin on the miner wallet, so the candidates in '
                 'the window would never be replaced by an arriving '
                 'transaction and the race this measures would not be '
                 'provoked', {'balance_nano': balance, 'address': address})
        return

    # The feed is polled as we go for the same reason every other
    # scenario does it: the ring evicts, and the driver's reconstruction
    # accounting is only a measurement if its window is known complete.
    collector = common.EventCollector(ctx)
    collector.poll()
    ctx.collector, ctx.collector_watermark = collector, collector.highest_seen

    start = smoke.scala_height(ctx.run)
    target, reached, last, sent = start + blocks, start, start, []
    # Every input block the MINER'S OWN best input chain has held at any
    # point in the window. Accumulated rather than read once at the end:
    # the chain resets at each ordering block, so a single final read
    # would see one ordering block's worth of a 40-block window.
    winning = set()
    seen = set()
    while time.monotonic() < ctx.run.deadline:
        collector.poll()
        campaign.drain_utxo_watch(ctx, seen)
        try:
            chain = api('scala', '/blocks/bestInputChain') or {}
            winning.update(chain.get('bestInputBlocks') or [])
        except Unavailable:
            pass
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
    collector.poll()

    ctx.note('window', {
        'start_height': start, 'target': target, 'reached': reached,
        'ordering_blocks': reached - start,
        'short_by': max(0, target - reached),
        'payments_submitted': len(sent)})

    miner = count(common._scala_log_lines('scala'))
    ctx.note('miner', miner)
    applied = set(miner['applied_input_block_ids'])
    ctx.note('winning_chain', {
        'best_input_chain_members_seen': len(winning),
        'on_winning_chain': len(applied & winning),
        'applied_but_never_on_the_chain': sorted(applied - winning)[:20],
        'source': "the miner's own /blocks/bestInputChain, sampled through "
                  'the window and unioned; a chain read once at the end '
                  'covers one ordering block, not the window',
    })
    ctx.note('f11', {
        'measurement_only': 'this scenario has no PASS criterion; the numbers '
                            'are the evidence, and a stock run is what a '
                            'patched run is read against',
        'input_pow_failure_rate': (
            round(miner['pow_failures'] / miner['submissions_input'], 4)
            if miner['submissions_input'] else None),
        'submissions_without_a_reply': miner['replies_missing'],
    })
    ctx.note('result_line', result_line(ctx.evidence))

    # The window not completing is reported; it is not absorbed, and it
    # is not a verdict on the build either.
    if reached < target:
        ctx.note('shortfall', {
            'note': f'the miner produced {reached - start} of the {blocks} '
                    'ordering blocks asked for; the denominators below cover '
                    'the window that actually happened',
            'reached': reached, 'target': target})
    if miner.get('unmatched'):
        ctx.fail('the miner logged no solution submission at all, so the F11 '
                 'denominators were not measured — the phrases this scenario '
                 'counts do not match this build', {'miner': miner})
