#!/usr/bin/env python3
"""Phase 0 observation stream summarizer.

Stdlib-only. Reads one or more `ergo-observer/1` JSONL files (standalone
observer, crawler, and node-hook outputs all share the schema) and prints:

  * per-file summary: span, record/event counts, gaps, restarts, peers
  * cross-stream peer-id join rates (grouped by network)
  * clock: configured offset per stream + measured peer-clock skew from
    handshakes + wall-clock regression/future/past anomalies
  * latency distributions: rtt, announce->first-request, section sizes,
    header_validated, block_applied since-first-announce
  * tx outcome breakdowns, incl. UnresolvedInput re-announce resolution
  * crawler dial/learn statistics
  * schema and timing anomalies

Usage:
  summarize.py [--json OUT] FILE...

`mono_ns` is the authoritative duration axis per record; joins across
records within one file use it. Cross-file joins use peer ids, which are
shared-pseudonymised per network by design.
"""

import argparse
import json
import sys
from collections import Counter, defaultdict

SCHEMA = "ergo-observer/1"
ENVELOPE_REQUIRED = ("schema", "vantage", "wall_ms", "mono_ns", "event")

# A mono_ns regression with at least this much wall time across it
# corroborates real downtime (a machine reboot or long stop) even when
# the process's observer_start record did not survive the kill boundary
# (torn write). See the mono_ns rule in main().
WALL_GAP_CORROBORATE_MS = 60_000


def load(path):
    """Yield (line_no, record_or_None, error_or_None, raw)."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            # Torn writes at hard-stop boundaries can leave a leading NUL
            # block in front of an otherwise intact record (2026-11-11
            # machine reboot: node-hook line 651161, mainnet-crawler line
            # 98847). Strip it so the record is parsed and counted.
            line = line.lstrip("\x00")
            if not line:
                continue
            try:
                yield i, json.loads(line), None, line
            except json.JSONDecodeError as e:
                yield i, None, str(e), line


def pct(xs, q):
    if not xs:
        return None
    xs = sorted(xs)
    if len(xs) == 1:
        return float(xs[0])
    k = (len(xs) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def dist(xs, unit="us"):
    if not xs:
        return None
    # unit: the unit of the INPUT values. Output is always ms for
    # time-like units, bytes otherwise.
    div = {"us": 1000.0, "ms": 1.0, "ns": 1_000_000.0, "B": 1.0}[unit]
    out = "ms" if unit in ("us", "ms", "ns") else unit
    return {
        "n": len(xs),
        "min": round(min(xs) / div, 1),
        "p50": round(pct(xs, 0.50) / div, 1),
        "p90": round(pct(xs, 0.90) / div, 1),
        "p99": round(pct(xs, 0.99) / div, 1),
        "max": round(max(xs) / div, 1),
        "mean": round(sum(xs) / len(xs) / div, 1),
        "unit": out,
    }


class File:
    def __init__(self, path):
        self.path = path
        self.records = []          # (mono_ns, record) in file order
        self.raw_lines = []
        self.anomalies = []
        self.events = Counter()
        self.gap_dropped = 0
        self.gap_records = 0
        self.starts = 0
        self.peers = set()
        self.vantage = None
        self.network = None
        self.clock_offset = None
        self.clock_source = None
        self.mono_back = 0
        self.mono_back_max = 0
        self.mono_back_corroborated = 0
        self.wall_back = 0
        self.wall_back_max = 0
        self.future = 0
        self.past = 0
        self.rtts = defaultdict(list)          # type_id -> [rtt_us]
        self.section_sizes = defaultdict(list)  # type_id -> [bytes]
        self.id_mismatch = []
        self.handshake_skew = []               # peer_time - wall (ms)
        self.tx = Counter()                    # (result, source) -> n
        self.tx_reasons = Counter()
        self.tx_ids = defaultdict(dict)        # tx_id -> {first_mono, result, mono}
        self.tx_unresolved = {}                # tx_id -> mono of UnresolvedInput reject
        self.hv_dur = []
        self.ba_since = []
        self.dial = Counter()
        self.dial_connect = []
        self.dial_retried = 0
        self.learned = 0
        self.getpeers = 0
        # Latency joins use mono_ns, which resets at every process
        # restart: they are computed per session (observer_start
        # boundary) and the distributions merged afterwards.
        self.sessions = []
        self._cur = None
        self.ann_to_req = []                   # last announce -> first request (ns)
        self.hv_missing_dur = 0

    def _session(self, rec):
        if rec.get("event") == "observer_start":
            self._cur = {
                "ann_times": defaultdict(list),
                "req_times": defaultdict(list),
            }
            self.sessions.append(self._cur)
        if self._cur is None:
            self._cur = {"ann_times": defaultdict(list), "req_times": defaultdict(list)}
            self.sessions.append(self._cur)
        return self._cur

    def add(self, line_no, rec, err, raw):
        if err is not None:
            self.anomalies.append(f"line {line_no}: bad JSON: {err}")
            return
        sess = self._session(rec)
        for field in ENVELOPE_REQUIRED:
            if field not in rec:
                self.anomalies.append(f"line {line_no}: missing field '{field}'")
                break
        if rec.get("schema") != SCHEMA:
            self.anomalies.append(f"line {line_no}: schema {rec.get('schema')!r}")
        ev = rec.get("event")
        if not isinstance(ev, str):
            self.anomalies.append(f"line {line_no}: no event name")
            return
        self.events[ev] += 1
        mono = rec.get("mono_ns")
        wall = rec.get("wall_ms")
        self.raw_lines.append(raw)
        if self.vantage is None:
            self.vantage = rec.get("vantage")
        peer = rec.get("peer") or {}
        if peer.get("id"):
            self.peers.add(peer["id"])

        # timing anomalies
        if self.records:
            prev_mono, prev_rec = self.records[-1]
            prev_wall = prev_rec.get("wall_ms")
            if isinstance(mono, int) and isinstance(prev_mono, int) and mono < prev_mono:
                self.mono_back += 1
                self.mono_back_max = max(self.mono_back_max, prev_mono - mono)
                if (isinstance(wall, int) and isinstance(prev_wall, int)
                        and wall - prev_wall >= WALL_GAP_CORROBORATE_MS):
                    self.mono_back_corroborated += 1
            if isinstance(wall, int) and isinstance(prev_wall, int) and wall < prev_wall:
                self.wall_back += 1
                self.wall_back_max = max(self.wall_back_max, prev_wall - wall)
        if isinstance(mono, int):
            self.records.append((mono, rec))
        if isinstance(wall, int):
            now = int(__import__("time").time() * 1000)
            if wall > now + 60_000:
                self.future += 1
            if wall < now - 86_400_000 * 30:
                self.past += 1

        if ev == "observer_start":
            self.starts += 1
            self.network = rec.get("network", self.network)
            self.clock_offset = rec.get("clock_offset_ms")
            self.clock_source = rec.get("clock_source")
        elif ev in ("observer_gap", "gap"):  # "gap" predates the 2026-11-11 rename; no such records exist in the dataset
            self.gap_records += 1
            self.gap_dropped += int(rec.get("dropped", 0))
        elif ev == "handshake_ok" and isinstance(rec.get("peer_time_ms"), int):
            if isinstance(wall, int):
                self.handshake_skew.append(rec["peer_time_ms"] - wall)
        elif ev == "rtt" and isinstance(rec.get("rtt_us"), int):
            self.rtts[int(rec.get("type_id", 0))].append(rec["rtt_us"])
        elif ev == "section_received":
            if isinstance(rec.get("bytes"), int):
                self.section_sizes[int(rec.get("type_id", 0))].append(rec["bytes"])
            im = rec.get("id_matches")
            if im is False:
                self.id_mismatch.append((mono, rec.get("block") or {}, peer.get("id")))
        elif ev == "announce":
            ids = rec.get("ids") or []
            if rec.get("count") != len(ids):
                self.anomalies.append(
                    f"line {line_no}: announce count {rec.get('count')} != len(ids) {len(ids)}"
                )
            heights = rec.get("heights")
            if heights is not None and rec.get("via") == "syncinfo_v2" and len(heights) != len(ids):
                self.anomalies.append(
                    f"line {line_no}: syncinfo_v2 heights {len(heights)} != ids {len(ids)}"
                )
            if len(ids) > 1001:
                self.anomalies.append(f"line {line_no}: announce carries {len(ids)} ids (>1001)")
            if isinstance(mono, int):
                keyp = (peer.get("id"), int(rec.get("type_id", 0)))
                for hid in ids:
                    # Peers periodically re-announce tip headers, so keep
                    # every timestamp; the join takes the latest announce
                    # at or before the request.
                    sess["ann_times"][keyp + (hid,)].append(mono)
        elif ev == "request_sent":
            if isinstance(mono, int):
                sess["req_times"][(peer.get("id"), int(rec.get("type_id", 0)))].append(
                    (mono, rec.get("ids") or [])
                )
        elif ev == "tx_outcome":
            tid = rec.get("tx_id")
            self.tx[(rec.get("result"), rec.get("source"))] += 1
            if rec.get("result") == "rejected":
                self.tx_reasons[rec.get("reason") or "<none>"] += 1
                if rec.get("reason") == "UnresolvedInput" and isinstance(mono, int):
                    self.tx_unresolved[tid] = mono
            if rec.get("result") == "admitted" and rec.get("reason"):
                self.anomalies.append(f"line {line_no}: admitted with reason {rec.get('reason')!r}")
            if tid and isinstance(mono, int):
                if tid not in self.tx_ids:
                    self.tx_ids[tid] = {"first": mono, "results": []}
                self.tx_ids[tid]["results"].append((mono, rec.get("result")))
        elif ev == "header_validated":
            d = rec.get("duration_us")
            if isinstance(d, int):
                self.hv_dur.append(d)
            else:
                self.hv_missing_dur += 1
        elif ev == "block_applied":
            d = rec.get("since_first_announce_us")
            if isinstance(d, int):
                self.ba_since.append(d)
        elif ev == "dial_attempt":
            self.dial[rec.get("outcome")] += 1
            if isinstance(rec.get("connect_ms"), int):
                self.dial_connect.append(rec["connect_ms"])
            if int(rec.get("retries", 0)) > 0:
                self.dial_retried += 1
        elif ev == "peer_learned":
            self.learned += 1
        elif ev == "get_peers_received":
            self.getpeers += 1


def finish_latency(f):
    """Latest-announce-at-or-before -> first request_sent containing the id,
    per (peer, type). Computed per process session (mono_ns resets at
    restart) and merged."""
    for sess in f.sessions:
        for (pid, ttype), reqs in sess["req_times"].items():
            for mono, ids in reqs:
                for hid in ids:
                    times = sess["ann_times"].get((pid, ttype, hid))
                    if not times:
                        continue
                    # timestamps are in order; scan back for the latest
                    # one at or before the request
                    for t in reversed(times):
                        if t <= mono:
                            f.ann_to_req.append(mono - t)
                            break


def summarize(files):
    report = {"files": [], "peers": {}, "clock": {}, "anomalies": {}}
    by_network = defaultdict(list)
    for f in files:
        finish_latency(f)
        f.dups = len(f.raw_lines) - len(set(f.raw_lines))
        wall_min = min((r.get("wall_ms") for r in (rec for _, rec in f.records) if isinstance(r.get("wall_ms"), int)), default=None)
        wall_max = max((r.get("wall_ms") for r in (rec for _, rec in f.records) if isinstance(r.get("wall_ms"), int)), default=None)
        span_s = (wall_max - wall_min) / 1000.0 if wall_min is not None and wall_max is not None else None
        entry = {
            "file": f.path,
            "vantage": f.vantage,
            "network": f.network,
            "span_s": round(span_s, 1) if span_s is not None else None,
            "records": len(f.records),
            "events": dict(f.events),
            "peers": len(f.peers),
            "restarts": max(0, f.starts - 1),
            "gap_records": f.gap_records,
            "gap_dropped": f.gap_dropped,
            "duplicate_lines": f.dups,
            "rtt": {str(k): dist(v, "us") for k, v in sorted(f.rtts.items())},
            "announce_to_first_request": dist(f.ann_to_req, "ns"),
            "section_sizes": {
                str(k): dist(v, "B") for k, v in sorted(f.section_sizes.items())
            },
            "header_validated": dist(f.hv_dur, "us"),
            "block_applied_since_announce": dist(f.ba_since, "us"),
            "tx_outcome": {f"{r}/{s}": n for (r, s), n in sorted(f.tx.items())},
            "tx_reject_reasons": dict(f.tx_reasons),
        }
        # UnresolvedInput re-announce resolution
        resolved = []
        for tid, mono in f.tx_unresolved.items():
            info = f.tx_ids.get(tid)
            if not info:
                continue
            for m, res in info["results"]:
                if res == "admitted" and m > mono:
                    resolved.append(m - mono)
                    break
        if resolved:
            entry["unresolved_input_reannounce_admitted"] = dist(resolved, "ns")
        if f.hv_missing_dur:
            entry["header_validated_missing_duration"] = f.hv_missing_dur
        if f.dial or f.learned:
            entry["crawler"] = {
                "dial_outcomes": dict(f.dial),
                "connect_ms": dist(f.dial_connect, "ms"),
                "retried_attempts": f.dial_retried,
                "peers_learned": f.learned,
                "get_peers_received": f.getpeers,
            }
        report["files"].append(entry)
        if f.network:
            by_network[f.network].append(f)
        report["anomalies"][f.path] = {
            "mono_ns_regressions": f.mono_back,
            "mono_ns_max_regression_ns": f.mono_back_max,
            "mono_ns_regressions_corroborated": f.mono_back_corroborated,
            "wall_ms_regressions": f.wall_back,
            "wall_ms_max_regression_ms": f.wall_back_max // 1000,
            "future_records": f.future,
            "old_records": f.past,
            "header_id_mismatches": len(f.id_mismatch),
            "schema_or_shape": f.anomalies[:20],
            "schema_or_shape_count": len(f.anomalies),
        }

    # cross-stream peer join
    for net, fs in by_network.items():
        vantages = {f.vantage or f.path: f for f in fs}
        pairs = []
        names = list(vantages)
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                a, b = vantages[names[i]].peers, vantages[names[j]].peers
                inter = len(a & b)
                union = len(a | b)
                pairs.append({
                    "a": names[i],
                    "b": names[j],
                    "a_peers": len(a),
                    "b_peers": len(b),
                    "shared": inter,
                    "overlap_of_smaller": round(inter / min(len(a), len(b)), 3) if a and b else None,
                    "jaccard": round(inter / union, 3) if union else None,
                })
        report["peers"][net] = pairs

    # clock
    for f in files:
        report["clock"][f.path] = {
            "configured_offset_ms": f.clock_offset,
            "source": f.clock_source,
            "peer_clock_skew_ms": dist(f.handshake_skew, "ms"),
        }
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", metavar="OUT", help="also write the report as JSON")
    ap.add_argument("files", nargs="+")
    args = ap.parse_args()

    files = [File(p) for p in args.files]
    for f in files:
        for line_no, rec, err, raw in load(f.path):
            f.add(line_no, rec, err, raw)

    report = summarize(files)

    for e in report["files"]:
        print(f"== {e['vantage']} ({e['file']})")
        print(f"   network={e['network']} span={e['span_s']}s records={e['records']} peers={e['peers']} restarts={e['restarts']}")
        print(f"   events={e['events']}")
        if e["gap_records"] or e["gap_dropped"]:
            print(f"   GAPS: {e['gap_records']} gap records, {e['gap_dropped']} records dropped")
        if e.get("rtt"):
            for t, d in e["rtt"].items():
                print(f"   rtt type {t}: n={d['n']} p50={d['p50']}ms p99={d['p99']}ms max={d['max']}ms")
        a2r = e.get("announce_to_first_request")
        if a2r:
            print(f"   announce->first-request: n={a2r['n']} p50={a2r['p50']}ms p99={a2r['p99']}ms max={a2r['max']}ms")
        for k, d in e.get("section_sizes", {}).items():
            print(f"   section bytes type {k}: n={d['n']} p50={d['p50']} max={d['max']}")
        hv = e.get("header_validated")
        if hv:
            extra = f" (missing duration: {e['header_validated_missing_duration']})" if e.get("header_validated_missing_duration") else ""
            print(f"   header_validated: n={hv['n']} p50={hv['p50']}ms p99={hv['p99']}ms max={hv['max']}ms{extra}")
        ba = e.get("block_applied_since_announce")
        if ba:
            print(f"   block_applied since announce: n={ba['n']} p50={ba['p50']}ms p99={ba['p99']}ms max={ba['max']}ms")
        if e.get("tx_outcome"):
            print(f"   tx_outcome: {e['tx_outcome']}")
            if e.get("tx_reject_reasons"):
                print(f"   reject reasons: {e['tx_reject_reasons']}")
            u = e.get("unresolved_input_reannounce_admitted")
            if u:
                print(f"   unresolved-input later admitted (re-announce): n={u['n']} p50={u['p50']}ms max={u['max']}ms")
        if e.get("crawler"):
            c = e["crawler"]
            print(f"   crawler: dials={c['dial_outcomes']} learned={c['peers_learned']} retried={c['retried_attempts']}")
            if c.get("connect_ms"):
                print(f"   connect: n={c['connect_ms']['n']} p50={c['connect_ms']['p50']}ms p99={c['connect_ms']['p99']}ms max={c['connect_ms']['max']}ms")
        a = report["anomalies"][e["file"]]
        problems = []
        if a["mono_ns_regressions"]:
            # A mono reset is explained if it is covered by a counted
            # restart (observer_start record) or is corroborated by a
            # wall gap of >= WALL_GAP_CORROBORATE_MS across it (real
            # downtime whose observer_start did not survive, e.g. the
            # 2026-11-11 machine reboot's torn write in the
            # testnet-crawler stream).
            uncorroborated = a["mono_ns_regressions"] - a["mono_ns_regressions_corroborated"]
            if uncorroborated <= e["restarts"]:
                note = (f"explainable: {a['mono_ns_regressions_corroborated']} reset(s) "
                        f"corroborated by wall gap >= "
                        f"{WALL_GAP_CORROBORATE_MS // 1000} s (downtime), "
                        f"{uncorroborated} uncorroborated (<= "
                        f"{e['restarts']} counted restarts)")
            else:
                note = "UNEXPLAINED"
            problems.append(f"mono_ns regressions={a['mono_ns_regressions']} (max {a['mono_ns_max_regression_ns']} ns, {note})")
        if a["wall_ms_regressions"]:
            problems.append(f"wall_ms regressions={a['wall_ms_regressions']} (max {a['wall_ms_max_regression_ms']} ms)")
        if a["future_records"]:
            problems.append(f"future wall_ms={a['future_records']}")
        if a["old_records"]:
            problems.append(f"stale wall_ms={a['old_records']}")
        if a["header_id_mismatches"]:
            problems.append(f"HEADER ID MISMATCHES={a['header_id_mismatches']}")
        if e["duplicate_lines"]:
            problems.append(f"duplicate lines={e['duplicate_lines']}")
        if a["schema_or_shape"]:
            problems.append(f"schema/shape anomalies={a['schema_or_shape_count']}: {a['schema_or_shape'][:3]}")
        print(f"   anomalies: {'; '.join(problems) if problems else 'none'}")
        print()

    for net, pairs in report["peers"].items():
        print(f"== peer-id joins, network={net}")
        for p in pairs:
            print(f"   {p['a']} x {p['b']}: {p['a_peers']} x {p['b_peers']} peers, shared={p['shared']} "
                  f"(overlap of smaller={p['overlap_of_smaller']}, jaccard={p['jaccard']})")
        print()

    print("== clock")
    for path, c in report["clock"].items():
        v = next((e["vantage"] for e in report["files"] if e["file"] == path), path)
        skew = c["peer_clock_skew_ms"]
        sk = f"skew n={skew['n']} p50={skew['p50']}ms p99={skew['p99']}ms" if skew else "skew n/a"
        print(f"   {v}: configured offset={c['configured_offset_ms']} ms ({c['source']}), {sk}")
    print()

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"json report: {args.json}")


if __name__ == "__main__":
    main()
