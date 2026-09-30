"""Cutoff-bounded admission causes; frame/absence matches are inferences, not packet proof."""
from bisect import bisect_left, bisect_right
from collections import Counter
import math
import re

from relay_measurement import CONNECTION, HEIGHT, ID, RECEIPT, timestamp
from relay_evidence import source_lines

CLASSES = ('a-stale-not-sent', 'a-not-sent-other', 'b-plus2-dropped', 'b-gap-dropped', 'other')
# Half a second spans roughly one A1 input-block cadence, above millisecond log skew.
DELAY_SECONDS = 0.5
MINE = re.compile(rf'Input-block ({ID}) mined|New input block ({ID}) w\. nonce')
PLUS2 = re.compile(rf'On processing ({ID}), downloading its parent')
FRAME = re.compile(r'Received message MessageSpec\(100: SubBlock\)')


def stale(row):
    return (all(row.get(k) is not None for k in ('miner', 'actual', 'tracked'))
            and abs(row['actual'] - row['miner']) <= 2
            and abs(row['tracked'] - row['miner']) > 2)


def episodes(rows, mined):
    runs = []
    current = []
    for row in [*rows, {}]:
        if stale(row):
            current.append(row)
        elif current:
            start, end = current[0]['at'], current[-1]['at']
            ids = sorted(bid for bid, block in mined.items() if start <= block['at'] <= end)
            runs.append({'start': start, 'end': end, 'duration_seconds': end - start,
                         'samples': len(current), 'blocks_mined': len(ids), 'mined_ids': ids})
            current = []
    return runs


def distribution(values):
    values = sorted(values)
    return {'count': len(values), 'min_seconds': min(values, default=None),
            'max_seconds': max(values, default=None),
            'mean_seconds': sum(values) / len(values) if values else None,
            **{f'p{p}_seconds': values[math.ceil(p / 100 * len(values)) - 1] if values else None
               for p in (50, 90, 95, 99)}}


def classify(result, delay_seconds=DELAY_SECONDS, evidence_dir=None):
    """Classify exactly M1's denominator, using captured lines and M2 samples.

    +2 reasons name IDs. Gap reasons require a unique miner frame within
    [-5ms,100ms) of mining, a unique ignore within 20ms, and one block per
    frame. Absence uses the same frame horizon, plus any ID mention or send.
    Stale attribution requires bracketing samples within 2s, stable tracked
    height (or no intervening observed SyncInfo), and an actually near follower.
    """
    if not math.isfinite(delay_seconds) or delay_seconds < 0:
        raise ValueError('delay threshold must be finite and nonnegative')
    logs = source_lines(result, evidence_dir)
    window = result['window']
    mined = {}
    first = next(iter(result['M1'].values()))
    height = int(next(iter(first['per_interval']), 0))
    for number, line in enumerate(logs['scala'], 1):
        h = HEIGHT.search(line)
        if h:
            height = int(h[1])
        m = MINE.search(line)
        if m:
            bid = m[1] or m[2]
            mined.setdefault(bid, {'at': timestamp(line), 'interval': height, 'source_line': number})
    denominator = set(first['missing_ids']) | set(first['received_ids'])
    mined = {bid: block for bid, block in mined.items() if bid in denominator}
    reverse = {(m[2], m[1]) for line in logs['scala'] if (m := CONNECTION.search(line))}
    output = {}
    for node, m1 in result['M1'].items():
        lines = logs.get(node, [])
        frames, ignores, plus, admissions, mentions = [], [], {}, {}, set()
        for number, line in enumerate(lines, 1):
            mentions.update(re.findall(ID, line))
            frame, reason, receipt = FRAME.search(line), PLUS2.search(line), RECEIPT.search(line)
            ignore = 'Ignoring input block at height' in line and '(gap > 2 blocks)' in line
            if not (frame or reason or receipt or ignore):
                continue
            event = {'at': timestamp(line), 'source_line': number}
            pair = CONNECTION.search(line)
            if frame and pair and pair.groups() in reverse:
                frames.append(event)
            if reason and pair and pair.groups() in reverse:
                plus.setdefault(reason[1], event)
            if receipt:
                bid = receipt[1] or receipt[2]
                if bid not in admissions or event['at'] < admissions[bid]['at']:
                    admissions[bid] = event
            if ignore:
                ignores.append(event)
        frames.sort(key=lambda e: e['at'])
        ignores.sort(key=lambda e: e['at'])
        ft, it = [e['at'] for e in frames], [e['at'] for e in ignores]
        # Attribute sends as well: a send without receiver evidence is unresolved.
        pairs = {(m[2], m[1]) for line in lines if (m := CONNECTION.search(line))}
        syncs = sorted(timestamp(line) for line in logs['scala']
                       if 'Received message MessageSpec(65: Sync)' in line
                       and (m := CONNECTION.search(line)) and m.groups() in pairs)
        sends = sorted(timestamp(line) for line in logs['scala']
                       if 'Send message MessageSpec(100: SubBlock)' in line
                       and (m := CONNECTION.search(line)) and m.groups() in pairs)
        available = bool(frames) and bool(pairs)
        candidates = {bid: frames[bisect_left(ft, b['at'] - .005):bisect_left(ft, b['at'] + .1)]
                      for bid, b in mined.items()}
        uses = Counter(e['source_line'] for matches in candidates.values() for e in matches)
        samples = sorted(result['M2'][node]['raw_samples'], key=lambda r: r['at'])
        st = [r['at'] for r in samples]
        details = []
        for bid in m1['missing_ids']:
            block = mined.get(bid)
            label, evidence = 'other', {}
            if block and available:
                at = block['at']
                matches = candidates[bid]
                j = bisect_right(st, at)
                near = samples[max(0, j - 1):j + 1]
                evidence['samples'] = [{k: r.get(k) for k in ('at', 'miner', 'actual', 'tracked')} for r in near]
                if bid in plus:
                    label, evidence['reason'] = 'b-plus2-dropped', plus[bid]
                elif len(matches) == 1 and uses[matches[0]['source_line']] == 1:
                    frame = matches[0]
                    reasons = ignores[bisect_left(it, frame['at']):bisect_right(it, frame['at'] + .02)]
                    evidence['frame'] = frame
                    if len(reasons) == 1:
                        label, evidence['reason'] = 'b-gap-dropped', reasons[0]
                elif not matches and bid not in mentions and not sends[bisect_left(sends, at - .005):bisect_left(sends, at + .1)]:
                    label = 'a-not-sent-other'
                    if (len(near) == 2 and near[0]['at'] <= at <= near[1]['at']
                            and all(abs(r['at'] - at) <= 2 for r in near)
                            and (near[0].get('tracked') == near[1].get('tracked')
                                 or not syncs[bisect_right(syncs, near[0]['at']):bisect_right(syncs, at)])
                            and all(r.get('actual') is not None and r.get('tracked') is not None
                                    and abs(r['actual'] - block['interval']) <= 2
                                    for r in near)
                            and abs(near[0]['tracked'] - block['interval']) > 2):
                        label = 'a-stale-not-sent'
            details.append({'id': bid, 'class': label, 'mined': block, **evidence})
        recovered = []
        for bid in m1['received_ids']:
            if bid in mined and bid in admissions:
                delay = admissions[bid]['at'] - mined[bid]['at']
                if delay > delay_seconds:
                    recovered.append({'id': bid, **mined[bid], 'admission': admissions[bid], 'delay_seconds': delay})
        counts = Counter(b['class'] for b in details)
        output[node] = {'available': available,
                        'never_admitted': {label: counts[label] for label in CLASSES},
                        'blocks': details,
                        'withheld_then_recovered': {
                            'available': bool(lines), 'threshold_seconds': delay_seconds,
                            'distribution': distribution(b['delay_seconds'] for b in recovered),
                            'per_interval': {str(h): distribution(b['delay_seconds'] for b in recovered if b['interval'] == h)
                                             for h in sorted({b['interval'] for b in recovered})},
                            'blocks': sorted(recovered, key=lambda b: b['at'])},
                        'stale_episodes': episodes([r for r in samples if window['start'] <= r['at'] < window['end']], mined)}
    return output


def summary(classification):
    return ' | '.join(f'{node}: causes={m["never_admitted"]} '
                      f'withheld-then-recovered={m["withheld_then_recovered"]["distribution"]["count"]} '
                      f'(>{m["withheld_then_recovered"]["threshold_seconds"]}s; '
                      f'p50/p95/max={m["withheld_then_recovered"]["distribution"]["p50_seconds"]}/'
                      f'{m["withheld_then_recovered"]["distribution"]["p95_seconds"]}/'
                      f'{m["withheld_then_recovered"]["distribution"]["max_seconds"]}s; '
                      f'available={m["withheld_then_recovered"]["available"]}) '
                      f'stale-episodes={[{k: v for k, v in e.items() if k != "mined_ids"} for e in m["stale_episodes"]]} classification-available={m["available"]}'
                      for node, m in classification.items())
