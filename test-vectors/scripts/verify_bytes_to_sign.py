#!/usr/bin/env python3
"""Compare every saved transaction message against the pinned Scala helper."""

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent


def verify(entries, command):
    if not isinstance(entries, list) or not entries:
        raise ValueError("expected a nonempty transaction array")
    rows = []
    for entry in entries:
        if not isinstance(entry, dict) or any(not isinstance(entry.get(key), str)
                                             for key in ("id", "bytes", "bytesToSign")):
            raise ValueError("each transaction needs id, bytes and bytesToSign strings")
        for key in ("bytes", "bytesToSign"):
            if not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", entry[key]):
                raise ValueError(f"{entry['id']}: {key} must be nonempty hex bytes")
        result = subprocess.run(command, input=entry["bytes"] + "\n", text=True,
                                capture_output=True, timeout=300, check=False)
        actual = result.stdout.strip()
        row = dict(id=entry["id"], bytesToSign=actual, expectedBytesToSign=entry["bytesToSign"])
        if result.returncode or not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", actual):
            row.update(status="ERROR", helperExitCode=result.returncode, helperError=result.stderr)
        else:
            row["status"] = "match" if actual.lower() == entry["bytesToSign"].lower() else "MISMATCH"
        rows.append(row)
    return rows


def write_report(path, data):
    # NamedTemporaryFile creates owner-only files. Keep the replaced report's
    # mode, or give a new report the mode open() would under the umask.
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        umask = os.umask(0)
        os.umask(umask)
        mode = 0o666 & ~umask
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(data, stream, indent=2)
            stream.write("\n")
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        temporary.chmod(mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    if len(sys.argv) != 3:
        raise ValueError("usage: extract_bytes_to_sign.sh <transactions_json> <output_file>")
    scala_cli = os.environ.get("SCALA_CLI", "scala-cli")
    command = [scala_cli, "run", str(HERE / "scala/PrintBytesToSign.scala"), "--server=false"]
    rows = verify(json.loads(Path(sys.argv[1]).read_text()), command)
    write_report(Path(sys.argv[2]), rows)
    failures = sum(row["status"] != "match" for row in rows)
    print(f"Verified {len(rows)} transactions; {failures} mismatches/helper errors", file=sys.stderr)
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
