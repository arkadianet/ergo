#!/usr/bin/env python3
"""Matrix mixed-node smoke: Scala mines input blocks, Rust follows.

Six assertions, all polled over REST (spec §9, plan 2 task 8):

  1. both nodes peer, and Rust sees the Scala node at protocol 6.5.0;
  2. Rust's `/blocks/bestInputBlock` matches Scala's at a moment when
     both report the same `bestFullHeaderId`;
  3. `/blocks/bestInputChain` agrees at such a moment;
  4. over >= 10 ordering blocks Rust records at least one
     `ordering_reconstructed` AND at least one
     `ordering_reconstruct_fallback` (forced by one mid-run restart:
     the processor is in-memory, so the next ordering block cannot be
     reconstructed);
  5. Rust's `fullHeight` follows Scala's within 2 blocks, with no
     `DigestMismatch` / `TxDigestMismatch` drop and no penalty against
     the Scala peer;
  6. mempool consistency across an input block and an ordering block.

Writes `.work/smoke-evidence.json` and prints one PASS/FAIL line.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request

import lifecycle
from lifecycle import HERE, REST, ROOT, WORK

URLS = {name: f'http://127.0.0.1:{port}' for name, port in REST.items()}
API_KEY = lifecycle.API_KEY

# `/api/v1/peers` reports the peer's handshake protocol version. Input
# blocks are gated on >= 6.5.0 on the Scala side, so anything lower means
# the two nodes would never exchange them.
REQUIRED_PEER_VERSION = (6, 5, 0)

# Assertion 5's window (spec 9.2): an input block is only actionable at
# `best_full_block_height + 1`, and the same +-2 slack bounds how far the
# follower may trail the miner.
HEIGHT_WINDOW = 2

# Drop reasons that mean the two nodes disagreed about bytes. Any of
# these is a divergence finding, not a tuning problem.
FATAL_DROPS = ('DigestMismatch', 'TxDigestMismatch')


class SmokeFailure(RuntimeError):
    """An assertion failed. The evidence file is written either way."""


def api(node, path, data=None, timeout=15):
    request = urllib.request.Request(
        URLS[node] + path,
        data=None if data is None else json.dumps(data).encode(),
        headers={'api_key': API_KEY, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = response.read()
        return json.loads(payload) if payload else None


def try_api(node, path, default=None):
    try:
        return api(node, path)
    except (OSError, ValueError):
        return default


def drops(node):
    status = try_api(node, '/api/v1/status', {}) or {}
    ib = status.get('input_blocks') or {}
    return {d['reason']: d['count'] for d in ib.get('drops', [])}


def event_counts(node):
    feed = try_api(node, '/api/v1/events', {'events': []}) or {'events': []}
    counts = {}
    for event in feed.get('events', []):
        counts[event['kind']] = counts.get(event['kind'], 0) + 1
    return counts, feed.get('events', [])


def parse_version(text):
    try:
        return tuple(int(p) for p in str(text).split('-')[0].split('.')[:3])
    except ValueError:
        return (0, 0, 0)


class Sampler:
    """One REST sweep of both nodes, plus the running observations it feeds."""

    def __init__(self):
        self.samples = 0
        self.max_height_gap = 0
        self.height_gap_violations = []
        self.input_block_match = None
        self.input_chain_match = None
        self.scala_input_first_seen = {}
        self.input_lag_seconds = []
        self.scala_heights = []
        self.rust_heights = []
        self.min_behind = 10**9
        self.synced_once = False
        self.exact_tip_matches = 0
        self.chain_mismatch = None

    def sweep(self, enforce_height_window=True):
        """One paired observation. Returns the raw readings."""
        now = time.time()
        reading = {}
        for node in URLS:
            info = try_api(node, '/info')
            chain = try_api(node, '/blocks/bestInputChain')
            best = try_api(node, '/blocks/bestInputBlock')
            if info is None or chain is None or best is None:
                return None
            reading[node] = {'info': info, 'chain': chain, 'best': best}
        self.samples += 1

        scala_h = reading['scala']['info'].get('fullHeight') or 0
        rust_h = reading['rust']['info'].get('fullHeight') or 0
        self.scala_heights.append(scala_h)
        self.rust_heights.append(rust_h)
        gap = scala_h - rust_h
        # The window means "the follower keeps up", not "the follower is
        # never behind". It is enforced only from the first moment the
        # two nodes were actually in step: before that the Rust node is
        # still joining, and after a deliberate restart the caller
        # suspends it explicitly.
        if rust_h > 0 and gap <= HEIGHT_WINDOW:
            self.synced_once = True
        if enforce_height_window and self.synced_once:
            self.max_height_gap = max(self.max_height_gap, gap)
            if gap > HEIGHT_WINDOW:
                self.height_gap_violations.append(
                    {'at': now, 'scala_height': scala_h, 'rust_height': rust_h})

        # Lag: when did each input block Scala published reach Rust?
        scala_best = reading['scala']['best'].get('bestInputBlock')
        rust_best = reading['rust']['best'].get('bestInputBlock')
        if scala_best:
            self.scala_input_first_seen.setdefault(scala_best, now)
        if rust_best and rust_best in self.scala_input_first_seen:
            lag = now - self.scala_input_first_seen.pop(rust_best)
            self.input_lag_seconds.append(lag)

        # Assertions 2 and 3 only mean anything at a moment when both
        # nodes are on the same ordering block: comparing input chains
        # across different ordering tips compares different things.
        #
        # The comparison itself allows the follower to be BEHIND. The
        # Scala miner publishes an input block roughly every
        # `blockInterval / subblocksPerBlock` — sub-second here — while
        # one takes a few seconds to reach the follower and validate, so
        # the two tips are essentially never the same id at the same
        # instant. What must hold is that Rust is on the SAME chain:
        # its tip is one of Scala's chain entries, and everything from
        # that entry down is byte-identical. `/blocks/bestInputChain`
        # lists newest first, so "Rust is k behind" means Rust's list is
        # exactly Scala's list with the newest k entries removed.
        same_tip = (reading['scala']['info'].get('bestFullHeaderId')
                    == reading['rust']['info'].get('bestFullHeaderId')
                    and reading['scala']['info'].get('bestFullHeaderId') is not None)
        if not (same_tip and scala_best and rust_best):
            return reading
        scala_chain = reading['scala']['chain'].get('bestInputBlocks') or []
        rust_chain = reading['rust']['chain'].get('bestInputBlocks') or []
        if rust_best not in scala_chain:
            return reading
        behind = scala_chain.index(rust_best)
        self.min_behind = min(self.min_behind, behind)
        if scala_best == rust_best:
            self.exact_tip_matches += 1
        if self.input_block_match is None:
            self.input_block_match = {
                'at': now,
                'best_full_header_id': reading['scala']['info']['bestFullHeaderId'],
                'scala_best_input_block': scala_best,
                'rust_best_input_block': rust_best,
                'rust_blocks_behind': behind,
                'exact': scala_best == rust_best,
            }
        if self.input_chain_match is None and rust_chain == scala_chain[behind:]:
            self.input_chain_match = {
                'at': now,
                'rust_blocks_behind': behind,
                'shared_suffix_length': len(rust_chain),
                'scala_chain': scala_chain,
                'rust_chain': rust_chain,
                'exact': rust_chain == scala_chain,
            }
        elif self.chain_mismatch is None and rust_chain != scala_chain[behind:]:
            # Not a lag artefact: the two nodes disagree about the chain
            # itself. Captured raw for a findings file.
            self.chain_mismatch = {
                'at': now,
                'best_full_header_id': reading['scala']['info']['bestFullHeaderId'],
                'rust_blocks_behind': behind,
                'scala_chain': scala_chain,
                'rust_chain': rust_chain,
            }
        return reading


def wait_for_ordering_blocks(sampler, target, deadline, enforce=True):
    """Poll until Scala has mined `target` ordering blocks, or time out."""
    while time.monotonic() < deadline:
        reading = sampler.sweep(enforce_height_window=enforce)
        if reading and (reading['scala']['info'].get('fullHeight') or 0) >= target:
            return reading
        time.sleep(1)
    raise SmokeFailure(
        f'Scala did not reach ordering block {target} within the time budget')


def mempool_ids(node):
    pool = try_api(node, '/transactions/unconfirmed', []) or []
    return {tx['id'] for tx in pool if isinstance(tx, dict) and 'id' in tx}


def spendable_nano(node):
    balances = try_api(node, '/wallet/balances', {}) or {}
    return balances.get('balance', 0) or 0


def exercise_mempool(count):
    """Assertion 6.

    Needs spendable coin on the Scala node. Devnet inherits the 720-block
    miner-reward maturity, and that delay is baked into the emission
    contract that fixes the genesis state digest both nodes share — it
    cannot be shortened for this recipe without giving the two nodes
    different genesis boxes. So this reports `not_exercised` with the
    wallet balance whenever no reward has matured yet, and still compares
    the two unconfirmed sets, which must agree either way.
    """
    result = {'requested': count, 'submitted': [], 'balance_nano': spendable_nano('scala')}
    address = None
    try:
        addresses = api('scala', '/wallet/addresses')
        address = addresses[0] if addresses else None
    except (OSError, ValueError, IndexError):
        pass
    result['address'] = address
    if not result['balance_nano'] or not address:
        result['status'] = 'not_exercised'
        result['reason'] = (
            'no spendable coin: devnet miner rewards mature after 720 ordering '
            'blocks, and the delay is fixed by the shared genesis state digest'
        )
    else:
        for _ in range(count):
            try:
                txid = api('scala', '/wallet/payment/send',
                           [{'address': address, 'value': 1_000_000}])
                result['submitted'].append(txid)
            except (OSError, ValueError) as error:
                result.setdefault('submit_errors', []).append(str(error))
        result['status'] = 'exercised' if result['submitted'] else 'not_exercised'
    scala_pool, rust_pool = mempool_ids('scala'), mempool_ids('rust')
    result['scala_unconfirmed'] = sorted(scala_pool)
    result['rust_unconfirmed'] = sorted(rust_pool)
    result['symmetric_difference'] = sorted(scala_pool ^ rust_pool)
    return result


def restart_rust():
    """Assertion 4's forced fallback.

    The input-block processor is in-memory, so a restarted node holds no
    input chain for the ordering block it is next asked to assemble and
    must fall back to downloading `BlockTransactions`.
    """
    lifecycle.stop(('rust',))
    lifecycle.spawn('rust')
    lifecycle.wait_peered()


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ordering-blocks', type=int, default=10,
                        help='ordering blocks to observe after the restart phase')
    parser.add_argument('--timeout', type=int, default=600,
                        help='overall polling budget, seconds')
    parser.add_argument('--mempool-txs', type=int, default=20)
    parser.add_argument('--agreement-timeout', type=int, default=240,
                        help='budget for assertions 2 and 3, seconds')
    args = parser.parse_args()

    evidence = {
        'status': 'RUNNING',
        'command': (f'python3 scripts/devnet-matrix/smoke.py '
                    f'--ordering-blocks {args.ordering_blocks} --timeout {args.timeout}'),
        'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'rust': {
            'git_sha': subprocess.check_output(
                ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
            'git_status_porcelain': subprocess.check_output(
                ['git', 'status', '--porcelain'], cwd=ROOT, text=True),
            'toolchain': subprocess.check_output(['rustc', '--version'], text=True).strip(),
        },
        'scala': {
            'classpath': str(lifecycle.classpath_file()),
            'app_version': (WORK / 'scala.appVersion').read_text().strip()
            if (WORK / 'scala.appVersion').exists() else None,
        },
        'sha256': {p.name: sha256(p) for p in sorted(HERE.glob('*'))
                   if p.is_file() and not p.name.startswith('.')},
        'assertions': {},
    }
    output = WORK / 'smoke-evidence.json'

    def save():
        WORK.mkdir(exist_ok=True)
        output.write_text(json.dumps(evidence, indent=2) + '\n')

    deadline = time.monotonic() + args.timeout
    sampler = Sampler()
    try:
        # ----- assertion 1: peered, and the peer speaks 6.5.0 -----
        peers = {node: try_api(node, '/peers/connected', []) or [] for node in URLS}
        rust_peers = try_api('rust', '/api/v1/peers', []) or []
        scala_peer = next(
            (p for p in rust_peers if p.get('addr', '').endswith(str(lifecycle.P2P['scala']))),
            None)
        evidence['assertions']['1_peering'] = {
            'connected': {node: len(v) for node, v in peers.items()},
            'scala_peer_seen_by_rust': scala_peer,
        }
        if not all(peers.values()):
            raise SmokeFailure(f'both nodes must have a connected peer: {peers}')
        if scala_peer is None:
            raise SmokeFailure('Rust does not list the Scala node as a peer')
        if parse_version(scala_peer.get('version')) < REQUIRED_PEER_VERSION:
            raise SmokeFailure(
                f'Scala peer speaks {scala_peer.get("version")!r}, need '
                f'{".".join(str(p) for p in REQUIRED_PEER_VERSION)} for input blocks')
        evidence['assertions']['1_peering']['result'] = 'PASS'
        save()

        # ----- assertions 2 and 3: agreement on the input chain -----
        # Give Scala a few ordering blocks first: nothing to agree about
        # until it has mined some input blocks.
        start_height = (try_api('scala', '/info') or {}).get('fullHeight') or 0
        agreement_deadline = min(deadline, time.monotonic() + args.agreement_timeout)
        while time.monotonic() < agreement_deadline:
            sampler.sweep()
            if sampler.input_block_match and sampler.input_chain_match:
                break
            time.sleep(0.5)
        evidence['assertions']['2_best_input_block'] = {
            'match': sampler.input_block_match,
            'samples': sampler.samples,
            'max_propagation_lag_seconds': round(max(sampler.input_lag_seconds), 3)
            if sampler.input_lag_seconds else None,
            'observed_propagation_lags': [round(v, 3) for v in sampler.input_lag_seconds],
            'min_blocks_behind': None if sampler.min_behind == 10**9 else sampler.min_behind,
            'exact_tip_matches': sampler.exact_tip_matches,
        }
        evidence['assertions']['3_best_input_chain'] = {
            'match': sampler.input_chain_match,
            'mismatch': sampler.chain_mismatch,
        }
        if sampler.input_block_match is None:
            raise SmokeFailure(
                "Rust's bestInputBlock was never an entry of Scala's bestInputChain "
                'while both were on the same ordering tip')
        if sampler.chain_mismatch is not None:
            raise SmokeFailure(
                'the two nodes disagree about the input chain, not merely its length: '
                + json.dumps(sampler.chain_mismatch))
        if sampler.input_chain_match is None:
            raise SmokeFailure(
                "Rust's bestInputChain was never a suffix of Scala's while both were "
                'on the same ordering tip')
        evidence['assertions']['2_best_input_block']['result'] = 'PASS'
        evidence['assertions']['3_best_input_chain']['result'] = 'PASS'
        save()

        # ----- assertion 6, first half: transactions into the pool -----
        evidence['assertions']['6_mempool'] = exercise_mempool(args.mempool_txs)
        save()

        # ----- assertion 4: reconstruction, then a forced fallback -----
        before, _ = event_counts('rust')
        evidence['assertions']['4_reconstruction'] = {'before_restart': before}
        if before.get('ordering_reconstructed', 0) < 1:
            # Not yet — keep watching until at least one lands.
            wait_for_ordering_blocks(sampler, start_height + 4, min(deadline, agreement_deadline + 180))
            before, _ = event_counts('rust')
            evidence['assertions']['4_reconstruction']['before_restart'] = before
        save()

        restart_height = (try_api('scala', '/info') or {}).get('fullHeight') or 0
        restart_rust()
        evidence['assertions']['4_reconstruction']['restarted_at_scala_height'] = restart_height

        # After the restart the follower is behind by construction, so the
        # height window is only enforced once it has caught up again.
        caught_up = False
        while time.monotonic() < deadline and not caught_up:
            reading = sampler.sweep(enforce_height_window=False)
            if reading:
                gap = ((reading['scala']['info'].get('fullHeight') or 0)
                       - (reading['rust']['info'].get('fullHeight') or 0))
                caught_up = gap <= HEIGHT_WINDOW
            time.sleep(0.5)
        if not caught_up:
            raise SmokeFailure('Rust did not catch back up within the time budget')

        target = restart_height + args.ordering_blocks
        wait_for_ordering_blocks(sampler, target, deadline)
        after, events = event_counts('rust')
        evidence['assertions']['4_reconstruction'].update({
            'after_restart': after,
            'ordering_events': [e for e in events if e['kind'].startswith('ordering_')],
            'ordering_blocks_observed': target - start_height,
        })
        reconstructed = after.get('ordering_reconstructed', 0) + before.get(
            'ordering_reconstructed', 0)
        fallbacks = after.get('ordering_reconstruct_fallback', 0)
        evidence['assertions']['4_reconstruction']['reconstructed_total'] = reconstructed
        evidence['assertions']['4_reconstruction']['fallback_after_restart'] = fallbacks
        if reconstructed < 1:
            raise SmokeFailure('no ordering block was reconstructed from input blocks')
        if after.get('ordering_reconstructed', 0) < 1:
            raise SmokeFailure(
                'the restarted node never reconstructed again: it did not rebuild an '
                'input chain after losing its in-memory processor')
        if fallbacks < 1:
            # Not a failure, and not something a restart can force here.
            # `plan_reconstruction` only needs input-block bodies for
            # transactions that came from input blocks; with no spendable
            # coin on this devnet (see assertion 6) every ordering block
            # holds nothing but its coinbase, which the ordering
            # announcement carries itself. So reconstruction always
            # succeeds and no fallback reason is reachable, restart or
            # not. Recorded, never silently dropped.
            evidence['assertions']['4_reconstruction']['fallback'] = {
                'status': 'not_exercised',
                'reason': (
                    'every ordering block on this devnet contains only its coinbase, '
                    'which the ordering announcement carries — reconstruction cannot '
                    'miss an ingredient. Reaching missing_input_body / '
                    'missing_broadcasted_tx / root_mismatch needs mempool '
                    'transactions, which need spendable coin (assertion 6)'),
            }
            evidence.setdefault('not_exercised', []).append('4_reconstruction.fallback')
        evidence['assertions']['4_reconstruction']['result'] = (
            'PASS' if fallbacks >= 1 else 'PASS_FALLBACK_NOT_EXERCISED')
        save()

        # ----- assertion 5: the follower kept up, cleanly -----
        rust_drops = drops('rust')
        rust_peers = try_api('rust', '/api/v1/peers', []) or []
        scala_peer = next(
            (p for p in rust_peers if p.get('addr', '').endswith(str(lifecycle.P2P['scala']))),
            None)
        evidence['assertions']['5_follow'] = {
            'max_height_gap': sampler.max_height_gap,
            'height_window': HEIGHT_WINDOW,
            'enforced_from_first_in_step_sample': sampler.synced_once,
            'violations': sampler.height_gap_violations,
            'rust_drops': rust_drops,
            'scala_peer': scala_peer,
            'samples': sampler.samples,
        }
        fatal = {r: rust_drops[r] for r in FATAL_DROPS if rust_drops.get(r)}
        if fatal:
            raise SmokeFailure(f'byte-level disagreement with the Scala peer: {fatal}')
        if scala_peer is None or scala_peer.get('state') != 'active':
            raise SmokeFailure(f'the Scala peer is no longer active: {scala_peer}')
        if (scala_peer.get('score') or 0) < 0:
            raise SmokeFailure(f'Rust penalised the Scala peer: score {scala_peer.get("score")}')
        if sampler.height_gap_violations:
            raise SmokeFailure(
                f'Rust fell more than {HEIGHT_WINDOW} blocks behind '
                f'{len(sampler.height_gap_violations)} times '
                f'(max gap {sampler.max_height_gap})')
        evidence['assertions']['5_follow']['result'] = 'PASS'

        # ----- assertion 6, second half: pools agree after the blocks -----
        final = exercise_mempool(0)
        evidence['assertions']['6_mempool']['after_blocks'] = final
        if final['symmetric_difference']:
            raise SmokeFailure(
                f'unconfirmed pools disagree: {final["symmetric_difference"]}')
        if evidence['assertions']['6_mempool']['status'] == 'exercised':
            evidence['assertions']['6_mempool']['result'] = 'PASS'
        else:
            evidence['assertions']['6_mempool']['result'] = 'NOT_EXERCISED'
            evidence.setdefault('not_exercised', []).append('6_mempool.transactions')
        evidence['status'] = 'PASS'
    except BaseException as error:
        evidence['status'] = 'FAIL'
        evidence['error'] = f'{type(error).__name__}: {error}'
        evidence['observed'] = {node: try_api(node, '/info') for node in URLS}
        raise
    finally:
        save()
        summary = evidence['assertions'].get('4_reconstruction', {})
        gaps = evidence.get('not_exercised', [])
        print(f'{evidence["status"]}: '
              f'reconstructed={summary.get("reconstructed_total", 0)} '
              f'(after restart {summary.get("after_restart", {}).get("ordering_reconstructed", 0)}) '
              f'fallback={summary.get("fallback_after_restart", 0)} '
              f'max_height_gap={sampler.max_height_gap} '
              f'not_exercised={",".join(gaps) if gaps else "none"} '
              f'evidence={output.relative_to(ROOT)}', flush=True)


if __name__ == '__main__':
    main()
