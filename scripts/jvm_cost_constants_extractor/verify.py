#!/usr/bin/env python3
"""Check the tracked JVM capture's integrity; does not close cost-ledger rows."""

import hashlib
import json
from pathlib import Path
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[2]
VECTOR = ROOT / "test-vectors/ergo-sigma/cost-ledger/scala-constants.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def circe(value, depth=0):
    """Match Circe Printer.spaces2, including multiline empty containers."""
    indent = "  " * depth
    child_indent = indent + "  "
    if isinstance(value, dict):
        entries = [json.dumps(key, ensure_ascii=False) + " : " + circe(value[key], depth + 1)
                   for key in sorted(value)]
        opening, closing = "{", "}"
    elif isinstance(value, list):
        entries = [circe(item, depth + 1) for item in value]
        opening, closing = "[", "]"
    else:
        return json.dumps(value, ensure_ascii=False)
    body = (child_indent + (",\n" + child_indent).join(entries) + "\n") if entries else ""
    return opening + "\n" + body + indent + closing


def main():
    raw = VECTOR.read_bytes()
    data = json.loads(raw)
    manifest = data["manifest"]
    payload = {key: value for key, value in data.items() if key != "manifest"}
    require(raw == (circe(data) + "\n").encode(), "Noncanonical JSON")
    require(hashlib.sha256(circe(payload).encode()).hexdigest()
            == manifest["evidence"]["output"]["sha256"], "Payload hash mismatch")
    script = ROOT / manifest["tool"]["script"]
    require(hashlib.sha256(script.read_bytes()).hexdigest()
            == manifest["tool"]["script_sha256"], "Script hash mismatch")
    committed = subprocess.check_output(
        ["git", "show", f'{manifest["tool"]["git_sha"]}:{manifest["tool"]["script"]}'], cwd=ROOT)
    require(committed == script.read_bytes(), "Provenance commit does not contain this script")

    opcodes, methods, containers, constants = (
        data[key] for key in ("opcodes", "methods", "containers", "constants"))
    require([len(opcodes), len(methods), len(containers), len(constants)] == [102, 199, 21, 45],
            "Pinned registry coverage changed; inspect JVM declarations before updating")
    require([op["opcode"] for op in opcodes] == sorted({op["opcode"] for op in opcodes}),
            "Duplicate or unordered opcodes")
    require(all(0 <= op["opcode"] <= 255 for op in opcodes), "Opcode outside byte range")
    container_ids = {container["typeId"] for container in containers}
    require(len(container_ids) == len(containers), "Duplicate container")
    require({container["name"] for container in containers} == {
        "SByteMethods", "SShortMethods", "SIntMethods", "SLongMethods", "SBigIntMethods",
        "SBooleanMethods", "SStringMethods", "SGroupElementMethods", "SSigmaPropMethods",
        "SBoxMethods", "SAvlTreeMethods", "SHeaderMethods", "SPreHeaderMethods", "SGlobalMethods",
        "SContextMethods", "SCollectionMethods", "SOptionMethods", "STupleMethods", "SUnitMethods",
        "SAnyMethods", "SUnsignedBigIntMethods"}, "Missing method container")
    seen = set()
    for method in methods:
        require(method["typeId"] in container_ids, "Orphan method")
        require(method["versions"] == sorted(set(method["versions"])), "Invalid method versions")
        require(method["minVersion"] == min(method["versions"]), "Invalid minimum registry version")
        for version in method["versions"]:
            key = method["typeId"], method["methodId"], version
            require(key not in seen, f"Duplicate versioned method {key}")
            seen.add(key)

    descriptors = [record["costKind"] for record in opcodes + methods]
    descriptors += [record["costKind"] for record in constants.values() if "costKind" in record]
    for descriptor in descriptors:
        kind = descriptor["kind"]
        require(kind in {"Fixed", "PerItem", "TypeBased", "Dynamic", "NotSupported"}, "Unknown cost kind")
        if kind == "Fixed":
            require(isinstance(descriptor["base"], int), "Missing fixed cost")
            require(descriptor["perChunk"] is None and descriptor["chunkSize"] is None, "Invalid fixed cost")
        elif kind == "PerItem":
            require(all(isinstance(descriptor[key], int) for key in ("base", "perChunk", "chunkSize")),
                    "Missing per-item cost")
            require(descriptor["chunkSize"] > 0, "Invalid chunk size")
        else:
            require(all(descriptor[key] is None for key in ("base", "perChunk", "chunkSize")),
                    "Invented fixed parameters for a non-fixed descriptor")

    # Independent source sentinels: sigmastate v6.0.2 Interpreter.scala:522-546;
    # ergo v6.0.2 wallet/interpreter/ErgoInterpreter.scala:96, protocol/Constants.scala:21.
    for name, expected in {"Interpreter.ComputeCommitments_Schnorr": 3400,
                           "Interpreter.ComputeCommitments_DHT": 6450,
                           "Interpreter.Eval_SigmaPropConstant": 50}.items():
        require(constants[name]["costKind"]["base"] == expected, f"Source sentinel mismatch: {name}")
    for name, expected in {"ErgoInterpreter.interpreterInitCost": 10000,
                           "Constants.StorageContractCost": 50,
                           "Interpreter.ProveDlogVerificationCost": 3980,
                           "Interpreter.ProveDHTupleVerificationCost": 7140}.items():
        require(constants[name]["value"] == expected, f"Source sentinel mismatch: {name}")
    for name in ("SigSerializer.ParseChallenge_ProveDlog", "SigSerializer.ParseChallenge_ProveDHT",
                 "SigSerializer.ParsePolynomial", "SigSerializer.EvaluatePolynomial",
                 "FiatShamirTree.ToBytes_Schnorr", "FiatShamirTree.ToBytes_DHT",
                 "FiatShamirTree.ToBytes_ProofTreeConjecture"):
        require(name in constants, f"Missing crypto input: {name}")
    ledger = tomllib.loads((ROOT / "test-vectors/ergo-sigma/cost-ledger/ledger.toml").read_text())
    for excluded in manifest["excluded"]:
        require(all(excluded.get(key) for key in ("name", "scala", "rationale")), "Incomplete exclusion")
        require(any(row["state"] == "N-A" and excluded["name"] in (row["scala"] + row["note"])
                    for row in ledger["rows"]), f'Exclusion lacks an N-A ledger row: {excluded["name"]}')
    count = len(opcodes) + len(methods) + len(constants)
    require(manifest["run"]["selected"] == manifest["run"]["executed"] == count, "Invalid run counts")
    require(manifest["run"]["skipped"] == manifest["run"]["failed"] == 0, "Incomplete capture")
    print(f"PASS: {count} cost records; {len(containers)} containers; {len(seen)} versioned methods; "
          "schema, source sentinels, provenance, hashes, and exclusions verified")


if __name__ == "__main__":
    main()
