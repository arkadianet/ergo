#!/usr/bin/env python3
"""Slice-1 memory CSV summariser.

Reads CSVs produced by `ergo-node` with ERGO_MEM_CSV set and prints a
markdown table summary per file. Designed for the slice-1 baseline
report — keep dumb and explicit, no plotting libs.

Usage: scripts/mem_report.py <label1> <csv1> [<label2> <csv2> ...]
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path
from typing import Any


def fmt_kb(n: float | int | None) -> str:
    if n is None:
        return "?"
    v = float(n)
    for unit in ("KB", "MB", "GB"):
        if v < 1024:
            return f"{v:.1f} {unit}"
        v /= 1024
    return f"{v:.1f} TB"


def fmt_bytes(n: float | int | None) -> str:
    if n is None:
        return "?"
    v = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if v < 1024:
            return f"{v:.1f} {unit}"
        v /= 1024
    return f"{v:.1f} TB"


def load(path: Path) -> list[dict[str, Any]]:
    with path.open() as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        for k, v in r.items():
            if k == "sync_phase":
                continue
            try:
                r[k] = int(v)
            except (ValueError, TypeError):
                pass
    return rows


def stat(rows: list[dict], col: str) -> dict[str, int]:
    vs = [r[col] for r in rows]
    sv = sorted(vs)
    return {
        "first": vs[0],
        "last": vs[-1],
        "min": min(vs),
        "max": max(vs),
        "median": sv[len(sv) // 2],
    }


def quartile_growth(rows: list[dict], col: str) -> tuple[int, int]:
    """Return (mean_q1, mean_q4) for early/late comparison."""
    n = len(rows)
    if n < 4:
        return (0, 0)
    q = n // 4
    early = rows[:q]
    late = rows[-q:]
    me = sum(r[col] for r in early) // max(1, len(early))
    ml = sum(r[col] for r in late) // max(1, len(late))
    return (me, ml)


def fmt_section(label: str, rows: list[dict]) -> str:
    if not rows:
        return f"## {label}\n\n_No samples._\n"
    n = len(rows)
    duration_s = (rows[-1]["ts_ms"] - rows[0]["ts_ms"]) / 1000.0
    phases = sorted({r["sync_phase"] for r in rows})
    bh_first, bh_last = rows[0]["best_header"], rows[-1]["best_header"]
    bf_first, bf_last = rows[0]["best_full_block"], rows[-1]["best_full_block"]

    out: list[str] = []
    out.append(f"## {label}\n")
    out.append(f"- samples: **{n}** over **{duration_s:.0f}s**")
    out.append(f"- sync_phase observed: `{', '.join(phases)}`")
    out.append(
        f"- best_header: {bh_first} → **{bh_last}** "
        f"(Δ={bh_last - bh_first})"
    )
    out.append(
        f"- best_full_block: {bf_first} → **{bf_last}** "
        f"(Δ={bf_last - bf_first})"
    )
    out.append("")

    def row(name: str, col: str, fmt) -> str:
        st = stat(rows, col)
        return (
            f"| {name} | {fmt(st['first'])} | {fmt(st['last'])} | "
            f"{fmt(st['min'])} | {fmt(st['max'])} | {fmt(st['median'])} |"
        )

    out.append("| signal | first | last | min | max | median |")
    out.append("|---|---|---|---|---|---|")
    out.append(row("VmRSS", "vm_rss_kb", fmt_kb))
    out.append(row("VmSize", "vm_size_kb", fmt_kb))
    out.append(row("RssAnon", "rss_anon_kb", fmt_kb))
    out.append(row("RssFile", "rss_file_kb", fmt_kb))
    out.append(row("AVL clean bytes", "avl_cache_clean_bytes", fmt_bytes))
    out.append(row("AVL cache capacity", "avl_cache_capacity_bytes", fmt_bytes))
    out.append(row("AVL clean len", "avl_clean_len", str))
    out.append(row("AVL dirty len", "avl_dirty_len", str))
    out.append(row("AVL read count", "avl_read_count", str))
    out.append(row("batch_headers len", "batch_headers_len", str))
    out.append(row("batch_headers bytes", "batch_headers_bytes", fmt_bytes))
    out.append(row("batch_meta len", "batch_meta_len", str))
    out.append(row("header_index len", "header_index_len", str))
    out.append(row("header_index est", "header_index_est_bytes", fmt_bytes))
    out.append(row("last_headers len", "last_headers_len", str))
    out.append(row("last_headers bytes", "last_headers_bytes", fmt_bytes))
    out.append(row("orphan_headers len", "orphan_headers_len", str))
    out.append(row("orphan_headers bytes", "orphan_headers_bytes", fmt_bytes))
    out.append(row("pending_blocks", "pending_blocks_len", str))
    out.append(row("delivery_received", "delivery_received_len", str))
    out.append(row("delivery_inflight", "delivery_inflight_total", str))
    out.append(row("mempool count", "mempool_count", str))
    out.append(row("mempool bytes", "mempool_bytes", fmt_bytes))
    out.append(row("peer count", "peer_count", str))
    out.append(row("known_addresses", "known_addresses_len", str))
    out.append("")

    out.append("### Quartile growth check (early-mean vs late-mean)\n")
    out.append("Flags signals whose late-quartile mean exceeds early-quartile by ≥20% AND the absolute delta is meaningful.\n")
    out.append("| signal | early mean | late mean | Δ% |")
    out.append("|---|---|---|---|")
    growth_cols = [
        ("VmRSS", "vm_rss_kb", fmt_kb),
        ("RssAnon", "rss_anon_kb", fmt_kb),
        ("RssFile", "rss_file_kb", fmt_kb),
        ("AVL clean bytes", "avl_cache_clean_bytes", fmt_bytes),
        ("AVL clean len", "avl_clean_len", str),
        ("header_index est", "header_index_est_bytes", fmt_bytes),
        ("orphan_headers bytes", "orphan_headers_bytes", fmt_bytes),
        ("pending_blocks", "pending_blocks_len", str),
        ("delivery_received", "delivery_received_len", str),
    ]
    for name, col, fmt in growth_cols:
        e, l = quartile_growth(rows, col)
        if e == 0 and l == 0:
            pct = "—"
        elif e == 0:
            pct = "∞"
        else:
            pct = f"{(l - e) * 100 / e:+.1f}%"
        out.append(f"| {name} | {fmt(e)} | {fmt(l)} | {pct} |")
    out.append("")
    return "\n".join(out)


def main(argv: list[str]) -> int:
    if len(argv) < 3 or len(argv) % 2 != 1:
        print(
            "usage: mem_report.py <label1> <csv1> [<label2> <csv2> ...]",
            file=sys.stderr,
        )
        return 2
    pairs = list(zip(argv[1::2], argv[2::2]))
    print("# Slice-1 memory observability — baseline summary\n")
    print(f"_Generated by `scripts/mem_report.py` from {len(pairs)} capture(s)._\n")
    for label, path in pairs:
        p = Path(path)
        if not p.exists():
            print(f"## {label}\n\n_File missing: `{path}`_\n")
            continue
        rows = load(p)
        print(fmt_section(label, rows))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
