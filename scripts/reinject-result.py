#!/usr/bin/env python3
"""Check a saved detector result; unrelated process failures are not findings."""

import argparse
from pathlib import Path
import re
import sys


def detected(kind, surface, exit_code, output):
    if exit_code != 1 or "HARNESS ERROR" in output:
        return False
    surface = re.escape(surface)
    if kind == "canonical":
        # A writer failure after a complete decode also misses the expected bytes.
        return surface == "ergo_tree" and any(
            marker in output for marker in ("[CANONICAL-GATE] FAIL: re-encoded != expected",
                                            "[CANONICAL-GATE] FAIL: re-encode failed"))
    if kind == "panic":
        return re.search(rf"\[BUG\]\s+{surface}:.*PANIC", output) is not None
    if kind == "accept-reject":
        return re.search(rf"\[AcceptReject\]\s+{surface}(?:\s|$)", output) is not None
    if kind == "verify":
        return re.search(rf"\[Canonical\]\s+{surface}(?:\s|$)", output) is not None
    if kind == "reduce":
        return re.search(rf"\[(?:AcceptReject|Canonical)\]\s+{surface}(?:\s|$)", output) is not None
    if kind == "cost":
        if re.search(rf"\[Canonical\]\s+{surface}(?:\s|$)", output) is None:
            return False
        values = re.findall(r'(?:rust|jvm)\s*=\s*Accept\("P:([0-9a-f]+)\|([0-9]+)"\)', output)
        return len(values) == 2 and values[0][0] == values[1][0] and values[0][1] != values[1][1]
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--class", dest="kind", required=True)
    parser.add_argument("--surface", required=True)
    parser.add_argument("--exit-code", type=int, required=True)
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()
    try:
        output = args.log.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        print(f"cannot read detector log: {error}", file=sys.stderr)
        return 2
    return int(not detected(args.kind, args.surface, args.exit_code, output))


if __name__ == "__main__":
    sys.exit(main())
