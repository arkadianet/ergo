#!/usr/bin/env python3
"""Capture all seven Scala mutations against one unchanged reference-node tip."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from verify_bytes_to_sign import write_report

HERE = Path(__file__).resolve().parent
CATEGORIES = {
    "erg_inflation": "MONETARY", "duplicate_inputs": "STRUCTURAL",
    "invalid_proof": "PROOF", "empty_proof_nontrivial": "SCRIPT",
    "no_inputs": "STRUCTURAL", "missing_input_box": "STRUCTURAL",
    "output_value_too_low": "MONETARY",
}


def request(base, path, data=None):
    payload = None if data is None else json.dumps(data).encode()
    req = Request(base.rstrip("/") + path, data=payload,
                  headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=60) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        # Preserve HTTP status; an authentication, infrastructure or malformed
        # response is never silently translated into a consensus rejection.
        return error.code, json.loads(error.read())


def get(base, path):
    status, body = request(base, path)
    if status != 200:
        raise ValueError(f"reference GET {path} returned HTTP {status}")
    return body


def tip(info):
    height, identifier = info.get("fullHeight"), info.get("bestFullHeaderId")
    if not isinstance(height, int) or not isinstance(identifier, str) or not re.fullmatch(r"[0-9a-f]{64}", identifier):
        raise ValueError("reference info needs fullHeight and bestFullHeaderId")
    return height, identifier


def source_box(base, height):
    for number in range(height, max(0, height - 100), -1):
        ids = get(base, f"/blocks/at/{number}")
        if not ids:
            continue
        block = get(base, f"/blocks/{ids[0]}/transactions")
        for transaction in block["transactions"]:
            for output in transaction["outputs"]:
                # A token-free ordinary P2PK box keeps these mutation targets
                # meaningful. A trivial script would accept an empty proof.
                if output["value"] <= 1_000_000 or output["assets"] or not re.fullmatch(r"0008cd[0-9a-f]{66}", output["ergoTree"]):
                    continue
                identifier = output["boxId"]
                status, _ = request(base, f"/utxo/byId/{identifier}")
                if status == 404:
                    continue
                if status != 200:
                    raise ValueError(f"reference UTXO lookup returned HTTP {status}")
                box = get(base, f"/blockchain/box/byId/{identifier}")
                if box.get("boxId") != identifier:
                    raise ValueError("reference source box ID changed")
                return box
    raise ValueError("no eligible unspent P2PK source box in the bounded window")


def mutations(context, command):
    completed = subprocess.run(command, input=json.dumps(context), text=True,
                               capture_output=True, timeout=300, check=True)
    rows = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
    labels = [row.get("label") for row in rows]
    if len(labels) != len(CATEGORIES) or set(labels) != set(CATEGORIES):
        raise ValueError("Scala helper must emit every named mutation exactly once")
    for row in rows:
        if (row.get("category") != CATEGORIES[row["label"]]
                or row.get("height") != context["height"]
                or row.get("sourceBox") != context["sourceBox"]
                or row.get("sourceBoxId") != context["sourceBox"]["boxId"]
                or not isinstance(row.get("txJson"), dict)
                or not re.fullmatch(r"(?:[0-9a-f]{2})+", row.get("txHex", ""))):
            raise ValueError(f"invalid or inconsistent Scala mutation: {row.get('label')}")
    return rows


def capture(base, context, rows, observed_tip):
    results = []
    for row in rows:
        if tip(get(base, "/info")) != observed_tip:
            raise ValueError("reference tip changed before mutation submission")
        status, response = request(base, "/transactions/check", row["txJson"])
        if tip(get(base, "/info")) != observed_tip:
            raise ValueError("reference tip changed during mutation submission")
        detail = response.get("detail") if isinstance(response, dict) else None
        # Scala's structured BadRequest envelope carries error=400, a reason
        # and a concrete validation detail. Reject generic proxy error pages.
        if (status != 400 or not isinstance(response, dict) or response.get("error") != 400
                or not isinstance(response.get("reason"), str)
                or not isinstance(detail, str) or not detail.strip()):
            raise ValueError(f"{row['label']}: expected validation BadRequest, got HTTP {status}: {response}")
        result = dict(row)
        result.update(expectedCategory=row["category"], scalaError=detail,
                      httpStatus=status, referenceResponse=response,
                      referenceTip=observed_tip[1], referenceInfo=context["referenceInfo"],
                      categoryAuthority="mutation target; observed response retained verbatim")
        results.append(result)
    return results


def main():
    if len(sys.argv) != 2:
        raise ValueError("usage: build_rejection_corpus.sh <output_file>")
    base = os.environ.get("NODE_URL", "http://localhost:9053")
    info = get(base, "/info")
    observed_tip = tip(info)
    context = dict(height=observed_tip[0], sourceBox=source_box(base, observed_tip[0]), referenceInfo=info)
    command = [os.environ.get("SCALA_CLI", "scala-cli"), "run",
               str(HERE / "scala/BuildMutations.scala"), "--server=false"]
    rows = mutations(context, command)
    results = capture(base, context, rows, observed_tip)
    write_report(Path(sys.argv[1]), results)
    print(f"Recorded all {len(results)} reference rejections at {observed_tip}", file=sys.stderr)


if __name__ == "__main__":
    main()
