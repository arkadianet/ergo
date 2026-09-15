#!/usr/bin/env bash
# Refresh one ledger fixture from the pinned JVM full-verification oracle.
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
exec python3 - "$@" <<'PY'
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tomllib

root = Path.cwd().resolve()
sys.path.insert(0, str(root / "scripts"))
from cost_fixture_io import read_fixture_text, write_fixture_text
if len(sys.argv) != 2:
    sys.exit("usage: scripts/gen-cost-fixture.sh <fixture.json.gz>")
path = Path(sys.argv[1]).resolve()
if not path.is_relative_to(root / "test-vectors/ergo-sigma/cost-ledger/fixtures"):
    sys.exit("fixture must be inside this worktree's cost-ledger/fixtures directory")
if path.suffix == ".json":
    path = path.with_suffix(".json.gz")
fixture = json.loads(read_fixture_text(path))
ids = fixture.get("ledger")
if not isinstance(ids, list) or not ids or any(not isinstance(i, str) for i in ids):
    sys.exit("fixture must have nonempty ledger ids before running the JVM")
known = {r["id"] for r in tomllib.loads(
    (root / "test-vectors/ergo-sigma/cost-ledger/ledger.toml").read_text())["rows"]}
if any(i not in known for i in ids):
    sys.exit("fixture contains an unknown ledger id")
cases = fixture.get("cases", [fixture])
if not isinstance(cases, list) or not cases:
    sys.exit("fixture cases must be a nonempty array")
requests = [case["request"] for case in cases]
request = requests[0]
if any(r.get("rent", False) for r in requests):
    sys.exit("wallet rent fixtures belong in the transaction runner")
script = "scripts/jvm_evaluated_value_oracle/EvaluatedValueOracle.scala"
command = ["scala-cli", "--skip-cli-updates", "run", script, "--server=false",
           "--suppress-outdated-dependency-warning", "--", "verify"]
request_bytes = "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in requests).encode()
# One response per request, with diagnostics left on stderr.
response_bytes = subprocess.run(command, input=request_bytes, stdout=subprocess.PIPE,
                                check=True).stdout
responses = [json.loads(line) for line in response_bytes.splitlines() if line.strip()]
if len(responses) != len(requests):
    sys.exit("JVM response count differs from request count; fixture unchanged")
for field in ("verdict", "eval_block_cost", "crypto_block_cost", "total_block_cost",
              "failure_class", "rent_block_cost", "rent_path"):
    if any(field not in response for response in responses):
        sys.exit(f"JVM response is missing {field}; fixture unchanged")

def output(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()

def sha(data):
    return hashlib.sha256(data).hexdigest()

revision = output("git", "rev-parse", "HEAD")
generator = "scripts/gen-cost-fixture.sh"
now = datetime.datetime.now(datetime.timezone.utc).isoformat()
manifest = json.loads((root / "test-vectors/ergo-sigma/verify/manifest.json").read_text())
manifest.update(scala_sigmastate="6.0.2", generator=f"{generator}@{revision}", date=now)
manifest["rust"] = {"git_sha": revision, "toolchain": output("rustc", "--version"),
                    "features": ["ergo-sigma/cost-trace", "ergo-validation/test-helpers"]}
manifest["tool"] = {"script": generator, "git_sha": revision,
                    "script_sha256": sha((root / generator).read_bytes()),
                    "oracle_script": script, "oracle_sha256": sha((root / script).read_bytes()),
                    "scala_cli": output("scala-cli", "version"),
                    "scala_directive": "2.12", "jvm": output("java", "-version")}
for r in requests:
    for key in ("pre_header_hex", "activated_version", "tree_version_expected"):
        if r[key] != request[key]:
            sys.exit(f"grouped requests disagree on {key}; fixture unchanged")
pre = bytes.fromhex(request["pre_header_hex"])
manifest["context"] = {"network": "synthetic offline context",
    "height": int.from_bytes(pre[49:53], "big"), "block_version": pre[0],
    "activated_script_version": request["activated_version"],
    "ergo_tree_version": request["tree_version_expected"],
    "voted_params": {str(i): None for i in range(4, 9)}}
manifest["run"] = {"command": " ".join(command), "fixture": str(path.relative_to(root)),
    "timestamp_utc": now, "seeds": None, "selected": len(cases), "executed": len(cases),
    "skipped": 0, "failed": 0}
manifest["evidence"] = {"request_jsonl_sha256": sha(request_bytes),
    "response_jsonl_sha256": sha(response_bytes)}
# Timestamps describe changed evidence, not an identical repeat invocation.
previous = fixture.get("manifest", {})
comparison = json.loads(json.dumps(manifest))
comparison["date"] = previous.get("date")
comparison["run"]["timestamp_utc"] = previous.get("run", {}).get("timestamp_utc")
if (comparison == previous and [case.get("expected") for case in cases] == responses
        and previous.get("date") and previous.get("run", {}).get("timestamp_utc")):
    manifest = comparison
fixture["manifest"] = manifest
for case, response in zip(cases, responses):
    case["expected"] = response
# Complete all oracle and metadata operations before replacing the fixture.
write_fixture_text(path, json.dumps(fixture, indent=2) + "\n")
print(f"{path.relative_to(root)}: selected={len(cases)} executed={len(cases)} skipped=0 failed=0")
PY
