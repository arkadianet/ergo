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
  pow_failures                 the generator's input-arm PoW-failure WARN —
                               the race itself (stock or F11 wording)
  input_blocks_applied         input blocks that passed the generator's PoW
                               check and were sent to the node view
  input_blocks_on_winning_chain  of those, the ones that reached the best
                               input chain

A run with `--build stock` is the baseline; the same command with
`--build F11` is the patched arm. Both numbers go in the evidence pair
the F11 finding quotes.
"""
import re
import time

import lifecycle
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
# The PoW failures are counted from the generator's own WARN, not the
# exception text, and in either build's wording (below).
PHRASES = {
    'submissions_input': 'found solution for input block, sending it for validation',
    'submissions_ordering': 'found solution for ordering block, sending it for validation',
    'replies_success': 'solution accepted',
    'replies_error': 'accepting solution or preparing candidate did not succeed',
    'generator_processed': 'processed solution',
}

# One WARN per rejected solution, in the stock (62c10315) or the F11
# (`matrix/F11-candidate-retained-work`) wording. Anchored on the level
# and logger prefix: F11 echoes the same words once more as
# `akka.pattern.StatusReply$ErrorMessage: …` under `ErgoMiningThread`'s
# ERROR, and a bare substring would count every F11 failure twice.
_GENERATOR_WARN = r'WARN org\.ergoplatform\.mining\.CandidateGenerator - '
POW_FAILURE_WARN = {
    # the race itself; `pow_failures` is this arm
    'input': re.compile(
        _GENERATOR_WARN
        + r'(Removing candidate due to invalid input block'   # stock
        r'|No retained candidate matches input solution PoW)'),  # F11
    'ordering': re.compile(
        _GENERATOR_WARN
        + r'(Removing candidates due to invalid block'        # stock
        r'|No retained candidate matches ordering solution PoW)'),  # F11
    # F11 only: retained work found against an ordering parent that has
    # since been replaced
    'stale_parent': re.compile(_GENERATOR_WARN
                               + r'Stale input ordering parent'),
}

# F11's other reply arms. Rejections, each answered with an error reply,
# but not PoW failures, so they are counted by arm and kept apart.
OTHER_REJECTIONS = {
    'already_known': re.compile(
        r'CandidateGenerator - Input block already known: '),
    'pending': re.compile(
        r'CandidateGenerator - Input block pending application: '),
    'already_solved': re.compile(
        r'CandidateGenerator - Ordering block already solved: '),
    'invalid_wrapped': re.compile(
        _GENERATOR_WARN + r'Invalid mining solution'),
    'invalid_unwrapped': re.compile(
        _GENERATOR_WARN + r'Invalid unwrapped mining solution'),
    'pending_timeout': re.compile(
        _GENERATOR_WARN + r'Input processing timed out: '),
    'pending_deferral': re.compile(
        _GENERATOR_WARN + r'Input processing deferral limit reached: '),
}

# The reply text each input-arm PoW failure leaves, per wording. Stock
# puts it on the log TWICE — in the generator's `Processed solution …
# with the result Error(…)` echo and in the stack trace under
# `ErgoMiningThread`'s ERROR (Task 2 trial at stock 62c10315: 83 WARNs,
# 166 text lines). F11 dropped the `Processed solution` line and leaves
# it ONCE, as the `StatusReply$ErrorMessage` line (F11 runs 1-3: 61, 20
# and 16 of each). The expected total is checked against the WARNs as a
# cross-check: a build that stops logging in that proportion is a build
# these patterns no longer describe.
POW_FAILURE_REPLY_TEXT = {
    'stock': (re.compile(r'invalid input block! pow valid', re.IGNORECASE),
              re.compile(_GENERATOR_WARN
                         + r'Removing candidate due to invalid input block'),
              2),
    'f11': (re.compile(r'StatusReply\$ErrorMessage: '
                       r'No retained candidate matches input solution PoW'),
            re.compile(_GENERATOR_WARN
                       + r'No retained candidate matches input solution PoW'),
            1),
}

# An input block the generator passed its PoW check and sent to the node
# view, logged at two sites that name the same block:
#
#   CandidateGenerator.scala:275  `Input-block <id> mined @ height <h>!`
#                                 (62c10315 only; F11's retained-work
#                                 rewrite of `InputSolutionFound` drops it)
#   CandidateGenerator.scala:87   `New input block <id> w. nonce <n>`
#                                 (`sendInputToNodeView`, in every build)
#
# A block is counted once by its id, whichever site logged it. When both
# sites log, their id sets must be the same, because at 62c10315 the
# first line is always followed by the second.
APPLIED_SITES = {
    'mined_at_height': re.compile(
        r'input-block ([0-9a-f]{64}) mined @ height (\d+)', re.IGNORECASE),
    'sent_to_node_view': re.compile(
        r'new input block ([0-9a-f]{64}) w\. nonce', re.IGNORECASE),
}


def count(lines):
    """The F11 denominators from one window of a Scala miner's log.

    Pure, so `campaign.py --self-test` can hand it a log that contains
    the race and check the arithmetic — including the case the counting
    exists to expose, a submission with no reply.
    """
    out = {key: 0 for key in PHRASES}
    warns = {arm: 0 for arm in POW_FAILURE_WARN}
    other = {arm: 0 for arm in OTHER_REJECTIONS}
    reply_text = {build: [0, 0] for build in POW_FAILURE_REPLY_TEXT}
    applied_ids = []
    site_ids = {site: set() for site in APPLIED_SITES}
    for line in lines:
        low = line.lower()
        for key, phrase in PHRASES.items():
            if phrase in low:
                out[key] += 1
        for arm, pattern in POW_FAILURE_WARN.items():
            if pattern.search(line):
                warns[arm] += 1
        for arm, pattern in OTHER_REJECTIONS.items():
            if pattern.search(line):
                other[arm] += 1
        for build, (text, warn, _per) in POW_FAILURE_REPLY_TEXT.items():
            if text.search(line):
                reply_text[build][0] += 1
            if warn.search(line):
                reply_text[build][1] += 1
        for site, pattern in APPLIED_SITES.items():
            match = pattern.search(low)
            if match:
                site_ids[site].add(match.group(1))
                if match.group(1) not in applied_ids:
                    applied_ids.append(match.group(1))
    out['input_blocks_applied'] = len(applied_ids)
    out['applied_site_counts'] = {site: len(ids)
                                  for site, ids in site_ids.items()}
    logging_sites = [ids for ids in site_ids.values() if ids]
    out['applied_sites_disagree'] = (
        len(logging_sites) > 1
        and any(ids != logging_sites[0] for ids in logging_sites[1:]))
    out['submissions'] = out['submissions_input'] + out['submissions_ordering']
    out['replies'] = out['replies_success'] + out['replies_error']
    out['pow_failures'] = warns['input']
    out['pow_failures_ordering'] = warns['ordering']
    out['stale_parent_rejections'] = warns['stale_parent']
    out['other_rejections'] = other
    out['pow_failure_reply_lines'] = sum(
        text for text, _warn in reply_text.values())
    # Both PoW-failure sites have to keep logging, in each wording's
    # measured proportion. A different proportion means the patterns no
    # longer mean what this counting assumes — it is NOT a second,
    # independent count of the failures, and was never reported as one.
    out['pow_failure_lines_per_failure'] = (
        round(out['pow_failure_reply_lines'] / out['pow_failures'], 2)
        if out['pow_failures'] else None)
    # Compared UNCONDITIONALLY. Gating this on a nonzero WARN count
    # reported agreement for the case it exists to catch in the other
    # direction: a build that stops logging the WARN while the reply
    # text survives reads as 0 failures and says nothing is wrong. Zero
    # against zero already agrees.
    out['pow_failure_sites_disagree'] = any(
        text != per * warn
        for (text, warn), (_t, _w, per) in zip(
            reply_text.values(), POW_FAILURE_REPLY_TEXT.values()))
    # Every rejection above is answered with an error reply, which
    # `ErgoMiningThread` logs once in both builds; more rejections than
    # error replies means the patterns overcount.
    rejections = (sum(warns.values()) + sum(other.values()))
    out['rejections_exceed_error_replies'] = (
        rejections > out['replies_error'])
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


def winning_chain_note(applied, winning, reads, failures):
    """How many applied input blocks were SEEN on the winning chain.

    An observed LOWER BOUND, and labelled as one. The best input chain
    is sampled periodically and resets at every ordering block, so a
    block that joined and was replaced between two samples is never
    seen; the count can only understate, never overstate. A read the
    node could not answer used to be skipped in silence, which made a
    run that observed the chain twice look like one that observed it
    throughout — the failures are now counted, and a run in which every
    read failed reports the chain as UNKNOWN rather than as a set of
    blocks that never reached it.
    """
    applied, winning = set(applied), set(winning)
    observed = reads - failures
    out = {
        'best_input_chain_members_seen': len(winning),
        'on_winning_chain': len(applied & winning),
        'on_winning_chain_is_lower_bound': True,
        'applied_but_never_sampled_on_the_chain': sorted(applied - winning)[:20],
        'chain_reads': reads,
        'chain_read_failures': failures,
        'chain_never_observed': observed <= 0,
        'source': "the miner's own /blocks/bestInputChain, sampled through "
                  'the window and unioned; a chain read once at the end '
                  'covers one ordering block, not the window. The chain '
                  'resets at every ordering block and is sampled, not '
                  'followed, so this is an observed lower bound on '
                  'winning-chain membership, never an exact count.',
    }
    if out['chain_never_observed']:
        out['unmatched'] = (
            f'all {reads} best-input-chain reads were unavailable, so '
            'winning-chain membership for this window is UNKNOWN, not zero')
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



def run(ctx):
    import campaign

    smoke.assertion_1_peering(ctx.run, ctx.evidence)
    blocks = ctx.args.ordering_blocks or ORDERING_BLOCKS
    miner_nodes, _followers = common.scala_reference_nodes(
        ctx.roles, lifecycle.ROLES)
    miner_node = miner_nodes[0]
    rejected = []

    balance, address = common.fund_miner(ctx, miner_node)
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
    # ONE boundary for every half of this measurement: the Rust event
    # watermark, the miner's log offset, and the best-chain sampling
    # below all start here. Counting the miner's whole log against a
    # chain sampled from this point made input blocks applied during
    # start-up and funding read as blocks that never reached the winning
    # chain.
    collector = common.EventCollector(ctx)
    offsets = common.open_measurement_window(ctx, collector)
    ctx.note('measurement_window_opened_at', {
        'scala_log_offsets': offsets,
        'rust_event_watermark': ctx.collector_watermark,
        'miner_node': miner_node})

    start = smoke.scala_height(ctx.run)
    target, reached, last, sent = start + blocks, start, start, []
    # Every input block the MINER'S OWN best input chain has held at any
    # point in the window. Accumulated rather than read once at the end:
    # the chain resets at each ordering block, so a single final read
    # would see one ordering block's worth of a 40-block window.
    winning = set()
    chain_read_failures = chain_reads = 0
    seen = set()
    while time.monotonic() < ctx.run.deadline:
        collector.poll()
        campaign.drain_utxo_watch(ctx, seen)
        try:
            chain_reads += 1
            chain = api(miner_node, '/blocks/bestInputChain') or {}
            winning.update(chain.get('bestInputBlocks') or [])
        except Unavailable:
            chain_read_failures += 1
        try:
            reached = smoke.scala_height(ctx.run)
        except Unavailable:
            pass
        if reached > last:
            last = reached
            common.pump_payments(ctx, address, sent, miner_node,
                                 PAYMENTS_PER_BLOCK, PAYMENT_NANOERG,
                                 rejected=rejected)
        if reached >= target:
            break
        ctx.run.idle(0.5)
    # ONE close for the event feed and the miner's log.
    ctx.note('measurement_close', common.close_measurement_window(ctx))

    ctx.note('window', {
        'start_height': start, 'target': target, 'reached': reached,
        'ordering_blocks': reached - start,
        'short_by': max(0, target - reached),
        'payments_submitted': len(sent),
        'payments_refused': len(rejected), 'refusals': rejected[:10]})

    miner = count(common.scala_window_lines(ctx, miner_node))
    ctx.note('miner', miner)
    applied = set(miner['applied_input_block_ids'])
    chain = winning_chain_note(applied, winning, chain_reads,
                               chain_read_failures)
    ctx.note('winning_chain', chain)
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

    # This scenario's own statement of whether the measurement was
    # TAKEN: the window it asked for opened and ran to the end, and the
    # phrases it counts matched this build. The driver turns that into
    # MEASURED or INCOMPLETE — never PASS, which it has no criterion to
    # earn (spec §7a). A short window is not a verdict on the build; it
    # is a measurement that did not happen.
    ctx.note('measurement_complete', bool(
        reached >= target
        and not miner.get('unmatched')
        # One of the six denominators is winning-chain membership; a
        # window whose chain was never readable did not produce it.
        and not chain.get('chain_never_observed')
        # And a build whose two PoW-failure sites no longer agree is a
        # build these phrases do not describe, so the count is not the
        # measurement it claims to be.
        and not miner.get('pow_failure_sites_disagree')))

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
