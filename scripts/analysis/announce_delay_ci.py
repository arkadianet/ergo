#!/usr/bin/env python3
"""Tip-header announce-delay statistics with bootstrap CIs (step 4, 48 h window).

Metric definition
-----------------
For each full block applied at the tip by the node (the node-hook stream's
`block_applied` event), the **tip-header announce delay** is
`since_first_announce_us`: the time from the FIRST network announce of that
header (an `Inv` or `SyncInfo` v1/v2 receipt, any peer) until the node
applied the block. It is absent when no peer announce was recorded before
apply — for a mining node this is the expected case for locally mined
blocks (the node is the origin of the announce; the first logged announce
is the network echoing it back ~0.3 s later) — or when the announce
predates the current process (restart/reboot) or fell out of the node's
bounded first-announce map. Such blocks are reported separately, not
silently dropped; cross-check against `data/mining-history.json`
(`block_id` + `at_ms` match the `header_id` + `wall_ms` of the
`block_applied` records).

A reorg that re-applies a height with a different header is a distinct tip
event and counts as its own resampling unit.

Sessions / warm-up
------------------
A process session starts at an `observer_start` record or at a mono_ns
reset (a drop of > 10 min, which after the 2026-11-11 16:41 machine reboot
is the only marker, because the reboot's torn write destroyed the
post-reboot `observer_start` records in the node-hook stream). Warm-up:
blocks applied within the first WARMUP_S seconds of a session are reported
both included and excluded; the headline numbers use the excluded set.

Bootstrap
---------
Resampled by block (the resampling unit is one applied block with one
delay value): B resamples of n blocks with replacement, median and p90
(linear interpolation, same convention as summarize.py) per resample,
95 % CI = 2.5/97.5 percentiles of the bootstrap distribution.

Cross-check
-----------
Every announce source (`via=inv`, `via=syncinfo_v1`, `via=syncinfo_v2`) is
also logged as an `announce` event in the same stream, so the node's
internal timer is cross-checked by joining each applied block's header id
to the earliest logged announce of that id within the same process session
(mono_ns resets at every process start).

Usage:
  announce_delay_ci.py [--warmup-secs 300] [--bootstrap 10000] [--seed 20261112]
                       [--mining-history FILE] FILE
"""

import argparse
import datetime
import json
import random
import sys

WARMUP_DEFAULT_S = 300
MONO_RESET_NS = 10 * 60 * 10**9  # >10 min drop = process restart


def pct(xs, q):
    if not xs:
        return None
    xs = sorted(xs)
    if len(xs) == 1:
        return float(xs[0])
    k = (len(xs) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def fmt_ms(us):
    return f"{us / 1000.0:.1f} ms"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--warmup-secs", type=int, default=WARMUP_DEFAULT_S)
    ap.add_argument("--bootstrap", type=int, default=10_000)
    ap.add_argument("--seed", type=int, default=20261112)
    ap.add_argument("--mining-history",
                    help="path to data/mining-history.json; used to label "
                         "absent-delay blocks that were mined locally")
    ap.add_argument("file")
    args = ap.parse_args()

    mined_ids = set()
    if args.mining_history:
        with open(args.mining_history) as f:
            mh = json.load(f)
        for e in mh.get("events", []):
            mined_ids.add(bytes(e["block_id"]).hex())

    # ── pass 1: sessions and block_applied ─────────────────────────────────
    session_starts = []          # (wall_ms, mono_ns, kind)
    last_mono = None
    blocks = []                  # dict per block_applied
    n_lines = 0

    with open(args.file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            n_lines += 1
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            ev = r.get("event")
            mono = r.get("mono_ns")
            wall = r.get("wall_ms")

            # session boundary: observer_start or big mono drop
            if ev == "observer_start" and isinstance(mono, int):
                session_starts.append((wall, mono, "observer_start"))
                last_mono = mono
                continue
            if isinstance(mono, int) and last_mono is not None and last_mono - mono > MONO_RESET_NS:
                session_starts.append((wall, mono, "mono-reset (no observer_start record)"))
            if isinstance(mono, int):
                last_mono = mono

            if ev == "block_applied":
                blocks.append({
                    "id": r.get("header_id"),
                    "height": r.get("height"),
                    "mono": mono,
                    "wall": wall,
                    "since_us": r.get("since_first_announce_us"),
                })

    if not session_starts:
        sys.exit("no sessions found")

    # ── attach session to each block ───────────────────────────────────────
    sess_of_block = []
    for b in blocks:
        s = 0
        for i, (w, m, kind) in enumerate(session_starts, 1):
            if isinstance(w, int) and isinstance(b["wall"], int) and w <= b["wall"]:
                s = i
        sess_of_block.append(s)

    # ── pass 2: per-session first-announce map (no clears) ─────────────────
    first_ann = {}   # (session, hid) -> mono
    cur = 0
    last_mono = None
    with open(args.file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            ev = r.get("event")
            mono = r.get("mono_ns")
            if ev == "observer_start":
                cur += 1
                last_mono = mono
                continue
            if isinstance(mono, int) and last_mono is not None and last_mono - mono > MONO_RESET_NS:
                cur += 1
            if isinstance(mono, int):
                last_mono = mono
            if ev == "announce" and isinstance(mono, int):
                for hid in r.get("ids") or []:
                    k = (cur, hid)
                    if k not in first_ann:
                        first_ann[k] = mono

    # join: earliest logged announce of the header within its session
    for b, s in zip(blocks, sess_of_block):
        fa = first_ann.get((s, b["id"]))
        b["join_us"] = (b["mono"] - fa) / 1000.0 if fa is not None and isinstance(b["mono"], int) else None

    # ── populations ────────────────────────────────────────────────────────
    all_vals = [b["since_us"] for b in blocks if isinstance(b["since_us"], int)]
    missing = [b for b in blocks if not isinstance(b["since_us"], int)]

    warmup_ms = args.warmup_secs * 1000
    steady = []
    for b, s in zip(blocks, sess_of_block):
        sw = session_starts[s - 1][0]
        if isinstance(b["wall"], int) and isinstance(sw, int) and b["wall"] < sw + warmup_ms:
            continue
        if isinstance(b["since_us"], int):
            steady.append(b["since_us"])

    def stats(vals, name):
        if not vals:
            print(f"  {name}: n=0")
            return None
        med = pct(vals, 0.5)
        p90 = pct(vals, 0.9)
        print(f"  {name}: n={len(vals)} median={fmt_ms(med)} p90={fmt_ms(p90)} "
              f"p99={fmt_ms(pct(vals, 0.99))} max={fmt_ms(max(vals))}")
        return med, p90

    print(f"file: {args.file}")
    print(f"lines={n_lines} sessions={len(session_starts)} blocks_applied={len(blocks)}")
    for i, (w, m, kind) in enumerate(session_starts, 1):
        ws = datetime.datetime.fromtimestamp(w / 1000).strftime("%Y-%m-%d %H:%M:%S") if isinstance(w, int) else "?"
        nb = sum(1 for s in sess_of_block if s == i)
        print(f"  session {i}: start {ws} ({kind}) blocks={nb}")

    print(f"since_first_announce_us present: {len(all_vals)}; absent: {len(missing)}")
    for b in missing:
        ws = (datetime.datetime.fromtimestamp(b["wall"] / 1000).strftime("%Y-%m-%d %H:%M:%S")
              if isinstance(b["wall"], int) else "?")
        if mined_ids and str(b["id"]) in mined_ids:
            why = "mined locally — no peer announce precedes apply"
        else:
            why = "no peer announce recorded before apply (predates process or evicted)"
        print(f"    absent: height={b['height']} {ws} id={str(b['id'])[:16]}… ({why})")

    print(f"\n== tip-header announce delay (block_applied.since_first_announce_us) ==")
    stats(all_vals, f"all blocks (11-10 15:29 → boundary)")
    res = stats(steady, f"steady-state (warm-up <{args.warmup_secs}s after each session start excluded)")
    if res is None:
        sys.exit("no steady-state values")
    med_s, p90_s = res

    print(f"\n== cross-check vs logged announce events (same session) ==")
    joined = [b for b in blocks if b["join_us"] is not None]
    print(f"  joined: {len(joined)}/{len(blocks)} blocks (no logged announce in session: {len(blocks) - len(joined)})")
    if joined:
        diffs = [abs(b["since_us"] - b["join_us"]) for b in joined if isinstance(b["since_us"], int)]
        if diffs:
            print(f"  |since_first_announce_us − join|: n={len(diffs)} "
                  f"median={fmt_ms(pct(diffs, 0.5))} p99={fmt_ms(pct(diffs, 0.99))} max={fmt_ms(max(diffs))}")
        # sign: join under-estimates (announce event mono stamped after the map insert)
        under = sum(1 for b in joined if isinstance(b["since_us"], int) and b["join_us"] < b["since_us"])
        both = sum(1 for b in joined if isinstance(b["since_us"], int))
        print(f"  join < since: {under}/{both} (expected: event mono stamped after map insert)")

    # ── bootstrap on the steady-state set, resampled by block ─────────────
    rng = random.Random(args.seed)
    n = len(steady)
    med_boot = [0.0] * args.bootstrap
    p90_boot = [0.0] * args.bootstrap
    svals = sorted(steady)
    for i in range(args.bootstrap):
        sample = [svals[rng.randrange(n)] for _ in range(n)]
        sample.sort()
        med_boot[i] = pct(sample, 0.5)
        p90_boot[i] = pct(sample, 0.9)

    lo_m, hi_m = pct(med_boot, 0.025), pct(med_boot, 0.975)
    lo_90, hi_90 = pct(p90_boot, 0.025), pct(p90_boot, 0.975)
    print(f"\n== bootstrap 95% CIs (B={args.bootstrap}, resampled by block, seed={args.seed}, steady-state n={n}) ==")
    print(f"  median: {fmt_ms(med_s)}  CI [{fmt_ms(lo_m)}, {fmt_ms(hi_m)}]")
    print(f"  p90:    {fmt_ms(p90_s)}  CI [{fmt_ms(lo_90)}, {fmt_ms(hi_90)}]")


if __name__ == "__main__":
    main()
