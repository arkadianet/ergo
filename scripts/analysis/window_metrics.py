#!/usr/bin/env python3
"""Full-window metrics for the Phase 0 48 h report (boundary-cut streams).

Computes, from the wall-cut boundary snapshot (see cut_boundary.py):

  node hooks (mainnet-hook, testnet-hook, if present in the cut):
    * tx-flow timings (announce -> body, body -> outcome, announce -> outcome),
      joined by tx id within a process session on the monotonic clock.
    * block_applied.since_first_announce_us distribution (field is µs; stored as ns).
    * header_validated / block_applied missing-duration_us fractions, by session.
  standalone + crawlers:
    * announce composition: the fraction of announced id-occurrences that are
      early-chain (height <= 400, the empty-V2 catch-up set) vs tip (h > 400).
      The early set is identified as the union of ids carried by the 400-id
      catch-up `Inv` batches; tip heights come from `syncinfo_v2` announces.
    * the early-set distinct count and per-id re-announce count (the storm).
    * outbound request bytes/s (peak + mean), to show the 64 KiB/s cap headroom.

Stdlib-only. Reads the four LABEL.jsonl cuts + the MANIFEST for context.

Usage:
  window_metrics.py --indir DIR [--out OUT.json]
"""

import argparse
import json
import os
from collections import defaultdict

EARLY_MAX_HEIGHT = 400  # the catch-up extension covers exactly heights 1..400
ID_BYTES = 32           # a 256-bit modifier id
REQ_OVERHEAD = 8        # message code + length + framing, per RequestModifier


def parse_lines(path):
    """Yield (line_no, record_or_None, raw) with NUL-torn recovery for parsing."""
    with open(path, "rb") as f:
        for i, raw in enumerate(f, 1):
            body = raw.strip()
            if body:
                body = body.lstrip(b"\x00")
            if not body:
                yield i, None, raw
                continue
            try:
                yield i, json.loads(body), raw
            except Exception:
                yield i, None, raw


def pct(xs, q):
    if not xs:
        return None
    xs = sorted(xs)
    if len(xs) == 1:
        return float(xs[0])
    k = (len(xs) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def sessions_of(path):
    """Return the list of session start wall_ms values.

    A session starts at the first record, or at an `observer_start` whose
    mono_ns dropped below the previous *record's* mono_ns. Comparing
    against the previous record (not the previous start) matters because
    observer_start's own mono is the new process's near-zero start clock:
    two consecutive restarts can both have small start monos (e.g. 10 490
    then 13 529) that compare as an *increase*, while both are drops from
    the large monos of the records before them.
    """
    starts = []
    last_mono = None
    first = True
    for _ln, d, _raw in parse_lines(path):
        if d is None:
            continue
        mono = d.get("mono_ns")
        if not isinstance(mono, int):
            continue
        if first:
            starts.append(d.get("wall_ms"))
            first = False
        elif (d.get("event") == "observer_start" and last_mono is not None
              and mono < last_mono):
            starts.append(d.get("wall_ms"))
        last_mono = mono
    return starts


def node_hook_metrics(path):
    starts = sessions_of(path)
    # assign session index by wall (starts are ascending in wall)
    def sess_of(wall):
        idx = 0
        for i, s in enumerate(starts):
            if isinstance(wall, int) and isinstance(s, int) and wall >= s:
                idx = i
        return idx

    tx_first_announce = {}   # (sess, tx_id) -> mono (first announce, type 2)
    tx_body = {}             # (sess, tx_id) -> mono
    tx_outcome = []          # (sess, tx_id, mono, result)
    hv = defaultdict(lambda: [0, 0])   # sess -> [present, missing]
    ba = defaultdict(lambda: [0, 0])
    ba_vals = []             # since_first_announce_us (µs) * 1000 -> ns

    for _ln, d, _raw in parse_lines(path):
        if d is None:
            continue
        ev = d.get("event")
        mono = d.get("mono_ns")
        wall = d.get("wall_ms")
        if not isinstance(mono, int):
            continue
        sess = sess_of(wall)
        if ev == "announce" and d.get("type_id") == 2:
            for txid in (d.get("ids") or []):
                key = (sess, txid)
                if key not in tx_first_announce or mono < tx_first_announce[key]:
                    tx_first_announce[key] = mono
        elif ev == "section_received" and d.get("type_id") == 2:
            txid = d.get("id")
            if txid is not None:
                tx_body[(sess, txid)] = mono
        elif ev == "tx_outcome":
            tx_outcome.append((sess, d.get("tx_id"), mono, d.get("result")))
        elif ev == "header_validated":
            hv[sess][0 if isinstance(d.get("duration_us"), int) else 1] += 1
        elif ev == "block_applied":
            since = d.get("since_first_announce_us")  # microseconds
            ba[sess][0 if isinstance(since, int) else 1] += 1
            if isinstance(since, int):
                ba_vals.append(since * 1000)  # -> ns, so dist()/ms() stay in ns

    ab, bo, ao = [], [], []
    for sess, txid, mono, _res in tx_outcome:
        a = tx_first_announce.get((sess, txid))
        b = tx_body.get((sess, txid))
        if a is not None and b is not None and b >= a:
            ab.append(b - a)
        if b is not None and mono >= b:
            bo.append(mono - b)
        if a is not None and mono >= a:
            ao.append(mono - a)

    def dist(ns_vals):
        if not ns_vals:
            return None
        return {"n": len(ns_vals), "p50_ns": pct(ns_vals, 0.5),
                "p99_ns": pct(ns_vals, 0.99), "max_ns": max(ns_vals)}

    return {
        "sessions": len(starts),
        "tx_flow": {
            "announce_to_body": dist(ab),
            "body_to_outcome": dist(bo),
            "announce_to_outcome": dist(ao),
        },
        "block_applied_since_first_announce_ns": dist(ba_vals),
        "header_validated_duration_by_session": {
            str(i): {"present": hv[i][0], "missing": hv[i][1]} for i in sorted(hv)},
        "block_applied_since_announce_by_session": {
            str(i): {"present": ba[i][0], "missing": ba[i][1]} for i in sorted(ba)},
    }


def announce_composition(path):
    """Return (early_occ, tip_occ, unknown_occ, early_set, per-id early counts,
    inv batch-size histogram)."""
    early_set = set()
    inv_sizes = defaultdict(int)
    tip_height = {}          # id -> max height seen via syncinfo_v2
    early_occ = tip_occ = unknown_occ = 0
    early_per_id = defaultdict(int)

    for _ln, d, _raw in parse_lines(path):
        if d is None:
            continue
        if d.get("event") != "announce":
            continue
        via = d.get("via")
        ids = d.get("ids") or []
        if via == "inv":
            inv_sizes[len(ids)] += 1
            if len(ids) == 400:
                early_set.update(ids)
        elif via == "syncinfo_v2":
            hs = d.get("heights") or []
            for hid, h in zip(ids, hs):
                if isinstance(h, int) and h > tip_height.get(hid, 0):
                    tip_height[hid] = h

    # second pass: classify each id-occurrence
    for _ln, d, _raw in parse_lines(path):
        if d is None or d.get("event") != "announce":
            continue
        for hid in (d.get("ids") or []):
            if hid in early_set:
                early_occ += 1
                early_per_id[hid] += 1
            elif hid in tip_height and tip_height[hid] > EARLY_MAX_HEIGHT:
                tip_occ += 1
            else:
                unknown_occ += 1

    total = early_occ + tip_occ + unknown_occ
    per_id_sorted = sorted(early_per_id.values(), reverse=True)
    return {
        "early_occ": early_occ,
        "tip_occ": tip_occ,
        "unknown_occ": unknown_occ,
        "total_occ": total,
        "early_frac": early_occ / total if total else None,
        "early_distinct": len(early_set),
        "early_per_id_max": per_id_sorted[0] if per_id_sorted else 0,
        "early_per_id_p50": pct(per_id_sorted, 0.5) if per_id_sorted else 0,
        "inv_batch_sizes": dict(sorted(inv_sizes.items())),
    }


def outbound_rate(path):
    """Peak + mean outbound request bytes/s from request_sent records."""
    buckets = defaultdict(int)
    total_bytes = 0
    n_req = 0
    first_wall = last_wall = None
    for _ln, d, _raw in parse_lines(path):
        if d is None or d.get("event") != "request_sent":
            continue
        wall = d.get("wall_ms")
        if not isinstance(wall, int):
            continue
        n = len(d.get("ids") or [])
        b = REQ_OVERHEAD + n * ID_BYTES
        buckets[wall // 1000] += b
        total_bytes += b
        n_req += 1
        first_wall = wall if first_wall is None else min(first_wall, wall)
        last_wall = wall if last_wall is None else max(last_wall, wall)
    peak = max(buckets.values()) if buckets else 0
    span_s = (last_wall - first_wall) / 1000.0 if first_wall and last_wall else 0
    mean = total_bytes / span_s if span_s else 0
    return {"requests": n_req, "total_bytes": total_bytes, "span_s": span_s,
            "peak_bytes_per_s": peak, "mean_bytes_per_s": mean,
            "cap_bytes_per_s": 65536,
            "peak_pct_of_cap": peak / 65536.0 * 100 if buckets else 0}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--indir", required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    res = {}
    for name, fn in (("mainnet_hook", "mainnet-hook.jsonl"),
                     ("testnet_hook", "testnet-hook.jsonl")):
        path = os.path.join(args.indir, fn)
        if os.path.exists(path):
            res[name] = node_hook_metrics(path)
    res.update({
        "standalone": {
            "announce": announce_composition(os.path.join(args.indir, "mainnet-standalone.jsonl")),
            "outbound": outbound_rate(os.path.join(args.indir, "mainnet-standalone.jsonl")),
        },
        "mainnet_crawler": {
            "announce": announce_composition(os.path.join(args.indir, "mainnet-crawler.jsonl")),
            "outbound": outbound_rate(os.path.join(args.indir, "mainnet-crawler.jsonl")),
        },
        "testnet_crawler": {
            "announce": announce_composition(os.path.join(args.indir, "testnet-crawler.jsonl")),
            "outbound": outbound_rate(os.path.join(args.indir, "testnet-crawler.jsonl")),
        },
    })

    def ms(ns):
        return f"{ns / 1e6:.1f} ms" if ns is not None else "n/a"

    for name in ("mainnet_hook", "testnet_hook"):
        if name not in res:
            continue
        print(f"== {name} tx-flow (mono, within session) ==")
        for k in ("announce_to_body", "body_to_outcome", "announce_to_outcome"):
            dd = res[name]["tx_flow"][k]
            if dd:
                print(f"  {k}: n={dd['n']} p50={ms(dd['p50_ns'])} p99={ms(dd['p99_ns'])} max={ms(dd['max_ns'])}")
            else:
                print(f"  {k}: n=0")
        dd = res[name]["block_applied_since_first_announce_ns"]
        if dd:
            print(f"  block_applied.since_first_announce_us: n={dd['n']} p50={ms(dd['p50_ns'])} p99={ms(dd['p99_ns'])} max={ms(dd['max_ns'])}")
        else:
            print(f"  block_applied.since_first_announce_us: n=0")
        print(f"== {name} missing duration_us, by session ==")
        for s, v in res[name]["header_validated_duration_by_session"].items():
            tot = v["present"] + v["missing"]
            print(f"  session {s}: header_validated present={v['present']} missing={v['missing']} ({v['missing']/tot*100:.1f}%)" if tot else f"  session {s}: none")
        for s, v in res[name]["block_applied_since_announce_by_session"].items():
            tot = v["present"] + v["missing"]
            print(f"  session {s}: block_applied present={v['present']} missing={v['missing']} ({(v['missing']/tot*100 if tot else 0):.1f}%)" if tot else f"  session {s}: none")
    for name in ("standalone", "mainnet_crawler", "testnet_crawler"):
        a = res[name]["announce"]
        o = res[name]["outbound"]
        print(f"== {name} ==")
        print(f"  announce id-occurrences: total={a['total_occ']} early(h<=400)={a['early_occ']} "
              f"({a['early_frac']*100:.1f}%) tip={a['tip_occ']} unknown={a['unknown_occ']}")
        print(f"  early set: distinct={a['early_distinct']} per-id re-announce max={a['early_per_id_max']} p50={a['early_per_id_p50']:.0f}")
        print(f"  inv batch sizes: {a['inv_batch_sizes']}")
        print(f"  outbound requests: n={o['requests']} peak={o['peak_bytes_per_s']} B/s "
              f"({o['peak_pct_of_cap']:.1f}% of 64 KiB/s) mean={o['mean_bytes_per_s']:.0f} B/s span={o['span_s']:.0f}s")

    if args.out:
        with open(args.out, "w") as f:
            json.dump(res, f, indent=2)
        print(f"json: {args.out}")


if __name__ == "__main__":
    main()
