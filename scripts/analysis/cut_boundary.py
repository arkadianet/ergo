#!/usr/bin/env python3
"""Cut one or more `ergo-observer/1` JSONL streams at a wall-clock boundary.

Produces a faithful, byte-preserved subset of each input stream: every line
whose `wall_ms` is parseable and `<= --boundary-ms`, plus any unparseable
torn line that sits before the last included parseable line (a hard-stop
torn write at a kill boundary). Leading NUL blocks left by torn writes are
stripped *only for the purpose of reading `wall_ms`*; each line is written
out with its original bytes intact (binary mode), so the cut is a
verifiable subset of the source stream. The analysis tools do their own NUL
recovery when they parse.

A MANIFEST.txt is written alongside the cuts with, per file: input path,
output name, lines in/out, bytes out, sha256 of the cut, first/last
included wall_ms, and the source line numbers of any unparseable lines
carried in the cut.

Stdlib-only.

Usage:
  cut_boundary.py --boundary-ms 1794456120000 --outdir DIR \
      --name mainnet-hook:SRC1 --name mainnet-crawler:SRC2 ...

Each `--name LABEL:SRC` cuts SRC into outdir/LABEL.jsonl.
"""

import argparse
import datetime
import hashlib
import json
import os
import sys
import time


def parse_wall(body: bytes):
    """Return wall_ms from a raw line body (bytes, no trailing newline),
    or None if unparseable. Strips any leading NUL block (torn write)
    before attempting to parse. Does NOT validate the full record."""
    line = body.strip()
    if not line:
        return None
    line = line.lstrip(b"\x00")
    if not line:
        return None
    try:
        rec = json.loads(line)
    except Exception:
        return None
    wall = rec.get("wall_ms")
    return wall if isinstance(wall, int) else None


def cut(src, label, outdir, boundary_ms):
    out_path = os.path.join(outdir, label + ".jsonl")
    h = hashlib.sha256()
    lines_in = 0
    lines_out = 0
    first_wall = None
    last_wall = None
    torn = []  # source line numbers of unparseable lines carried in the cut

    keep = []
    with open(src, "rb") as f:
        for i, raw in enumerate(f, 1):
            lines_in += 1
            body = raw[:-1] if raw.endswith(b"\n") else raw
            wall = parse_wall(body)
            incl = None if wall is None else (wall <= boundary_ms)
            keep.append((i, raw, wall, incl))

    # Include a torn line only if it appears before the last included
    # parseable line (drops a hypothetical post-boundary torn line).
    last_included_idx = -1
    for i, _raw, _wall, incl in keep:
        if incl is True:
            last_included_idx = i

    with open(out_path, "wb") as out:
        for i, raw, wall, incl in keep:
            take = incl if incl is not None else (i < last_included_idx)
            if not take:
                continue
            if not raw.endswith(b"\n"):
                raw = raw + b"\n"
            out.write(raw)
            h.update(raw)
            lines_out += 1
            if wall is not None:
                first_wall = wall if first_wall is None else min(first_wall, wall)
                last_wall = wall if last_wall is None else max(last_wall, wall)
            else:
                torn.append(i)

    return {
        "label": label,
        "src": src,
        "lines_in": lines_in,
        "lines_out": lines_out,
        "bytes_out": os.path.getsize(out_path),
        "sha256": h.hexdigest(),
        "first_wall_ms": first_wall,
        "last_wall_ms": last_wall,
        "torn_lines": torn,
    }


def iso_aest(ms):
    if ms is None:
        return "n/a"
    tz = datetime.timezone(datetime.timedelta(hours=10))
    return datetime.datetime.fromtimestamp(ms / 1000, tz).strftime(
        "%Y-%m-%d %H:%M:%S.%f")[:-3] + " AEST"


def main():
    ap = argparse.ArgumentParser(
        description="Cut ergo-observer/1 JSONL streams at a wall-clock boundary.")
    ap.add_argument("--boundary-ms", type=int, required=True,
                    help="inclusive wall_ms boundary (epoch ms)")
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--name", action="append", required=True, metavar="LABEL:SRC",
                    help="cut SRC into outdir/LABEL.jsonl (repeatable)")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    results = []
    for spec in args.name:
        label, _, src = spec.partition(":")
        if not src:
            sys.exit(f"bad --name {spec!r} (expected LABEL:SRC)")
        results.append(cut(src, label, args.outdir, args.boundary_ms))

    mpath = os.path.join(args.outdir, "MANIFEST.txt")
    with open(mpath, "w", encoding="utf-8") as m:
        m.write(f"boundary wall_ms = {args.boundary_ms} "
                f"({iso_aest(args.boundary_ms)}), inclusive\n")
        m.write(f"generated: {iso_aest(int(time.time() * 1000))}\n")
        m.write("cut rule: include lines with parseable wall_ms <= boundary, "
                "plus torn (unparseable) lines before the last included line\n")
        m.write("bytes preserved verbatim (leading torn-write NUL blocks kept; "
                "analysis tools recover them)\n\n")
        for r in results:
            m.write(f"== {r['label']}\n")
            m.write(f"  src: {r['src']}\n")
            m.write(f"  lines_in: {r['lines_in']}\n")
            m.write(f"  lines_out: {r['lines_out']}\n")
            m.write(f"  bytes_out: {r['bytes_out']}\n")
            m.write(f"  sha256: {r['sha256']}\n")
            m.write(f"  first_wall_ms: {r['first_wall_ms']} "
                    f"({iso_aest(r['first_wall_ms'])})\n")
            m.write(f"  last_wall_ms: {r['last_wall_ms']} "
                    f"({iso_aest(r['last_wall_ms'])})\n")
            m.write(f"  torn_lines (source line no): "
                    f"{r['torn_lines'] if r['torn_lines'] else 'none'}\n\n")

    for r in results:
        print(f"{r['label']}: {r['lines_out']}/{r['lines_in']} lines, "
              f"last_wall={iso_aest(r['last_wall_ms'])}, "
              f"torn={r['torn_lines'] or 'none'}")
    print(f"manifest: {mpath}")


if __name__ == "__main__":
    main()
