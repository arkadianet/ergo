#!/usr/bin/env python3
"""Capture full JVM transaction validation and attach reproducibility metadata."""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path("scripts/jvm_crypto_cost_oracle/CryptoCostOracle.scala")
OUTPUT = Path("test-vectors/scala/multi_input_conjunction_cost.json")
ERGO = Path.home() / "coding/reference/ergo-core/ergo"
SIGMA = Path.home() / "coding/reference/ergo-core/sigmastate-interpreter-v6.0.2"
SOURCE_SHAS = {
    "ergo": "2cdbb8cf09d7ccbc060e1022e3c15bcf6a9991b1",
    "sigmastate": "23dd29f612249c169d09fae9bca76d7cc02e144c",
}


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ergo", type=Path, default=ERGO,
                        help="Ergo v6.0.2 source checkout (configuration resources)")
    parser.add_argument("--sigmastate", type=Path, default=SIGMA,
                        help="sigmastate-interpreter v6.0.2 source checkout")
    args = parser.parse_args()
    source_shas = {}
    for name, checkout in (("ergo", args.ergo), ("sigmastate", args.sigmastate)):
        try:
            revision = command("git", "-C", str(checkout), "rev-parse", "HEAD")
        except (OSError, subprocess.CalledProcessError) as error:
            parser.error(f"{name}: cannot read checkout {checkout}: {error}")
        if revision != SOURCE_SHAS[name]:
            parser.error(f"{name}: expected v6.0.2 commit {SOURCE_SHAS[name]}, got {revision}")
        source_shas[name] = revision
    resources = args.ergo.resolve() / "src/main/resources"
    for name in ("application.conf", "mainnet.conf"):
        if not (resources / name).is_file():
            parser.error(f"missing reference configuration: {resources / name}")
    with tempfile.TemporaryDirectory(prefix=".crypto-oracle-", dir=ROOT) as tmp:
        raw = Path(tmp) / "oracle.json"
        argv = ["scala-cli", "run", str(SCRIPT), "--server=false", "--",
                str(resources), str(raw)]
        subprocess.run(argv, cwd=ROOT, check=True)
        vector = json.loads(raw.read_text())
    inputs = {}
    for case in vector["cases"]:
        inputs[case["name"] + ".tx_bytes"] = sha(bytes.fromhex(case["tx_bytes"]))
        for index, box in enumerate(case["input_boxes"]):
            inputs[f'{case["name"]}.input_boxes[{index}].bytes'] = sha(bytes.fromhex(box["bytes"]))
    scripts = [SCRIPT, Path(__file__).resolve().relative_to(ROOT)]
    manifest = {
        "scala": {
            "ergo_version": "6.0.2", "ergo_wallet_version": "6.0.2",
            "sigmastate_version": "6.0.2", "node_app_version": "not used (standalone JVM)",
            "source_shas": source_shas,
            "artifacts": vector.pop("artifacts"),
        },
        "rust": {"git_sha": command("git", "rev-parse", "HEAD"),
                 "toolchain": command("rustc", "--version"), "features": []},
        "tool": {"script": str(SCRIPT), "git_sha": command("git", "rev-parse", "HEAD"),
                 "working_tree_script_sha256": {str(p): sha((ROOT / p).read_bytes()) for p in scripts},
                 "scala_cli_version": command("scala-cli", "version", "--cli-version"),
                 "jvm_version": vector.pop("jvm")},
        "context": {"network": "synthetic transactions with mainnet chain settings",
                    "height_range": [1000000, 1000000], "accumulated_cost": 0,
                    "max_cost": 1000000, "headers": [],
                    "previous_state_digest": "mainnet genesisStateDigest from reference configuration",
                    **vector["context"]},
        "run": {"command": shlex.join(["python3", *sys.argv]),
                "scala_command": shlex.join(argv[:-1] + ["<temporary output.json>"]),
                "seeds": "Three fresh DLog secrets and fresh prover randomness; replay uses captured public bytes",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "selected": 8, "executed": 8, "skipped": 0, "failed": 0},
        "evidence": {"input_sha256": inputs,
                     "config_sha256": {name: sha((resources / name).read_bytes())
                                       for name in ["application.conf", "mainnet.conf"]},
                     "cases_sha256": sha(json.dumps(vector["cases"], sort_keys=True, separators=(",", ":")).encode()),
                     "output_sha256": "Whole-file hash in multi_input_conjunction_cost.json.sha256 (avoids self-reference)"},
    }
    result = json.dumps({"manifest": manifest, **vector}, indent=2) + "\n"
    (ROOT / OUTPUT).write_text(result)
    (ROOT / (str(OUTPUT) + ".sha256")).write_text(f"{sha(result.encode())}  {OUTPUT}\n")
    print(result, end="")


if __name__ == "__main__":
    main()
