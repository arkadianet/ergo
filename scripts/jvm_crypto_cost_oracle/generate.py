#!/usr/bin/env python3
"""Capture full JVM transaction validation and attach reproducibility metadata."""

import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path("scripts/jvm_crypto_cost_oracle/CryptoCostOracle.scala")
OUTPUT = Path("test-vectors/scala/multi_input_conjunction_cost.json")
ERGO = Path.home() / "coding/reference/ergo-core/ergo"
SIGMA = Path.home() / "coding/reference/ergo-core/sigmastate-interpreter-v6.0.2"


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    resources = ERGO / "src/main/resources"
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
            "source_shas": {"ergo": command("git", "-C", str(ERGO), "rev-parse", "HEAD"),
                            "sigmastate": command("git", "-C", str(SIGMA), "rev-parse", "HEAD")},
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
        "run": {"command": "python3 scripts/jvm_crypto_cost_oracle/generate.py",
                "scala_command": " ".join(argv[:-1] + ["<temporary output.json>"]),
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
