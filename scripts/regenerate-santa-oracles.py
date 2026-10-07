#!/usr/bin/env python3
"""Regenerate all SANTA JVM companions using the pinned 6.0.7 Scala oracles."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scala-cli", default="scala-cli")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env.setdefault("COURSIER_REPOSITORIES", "ivy2Local|https://repo.maven.apache.org/maven2")
    env.setdefault("JAVA_TOOL_OPTIONS", "-XX:ActiveProcessorCount=8")
    results = []
    changes = []
    with tempfile.TemporaryDirectory(prefix="santa-oracle-607-") as workspace:
        for kind, name, corpus in [("wire", "SantaWireOracle", "wire"),
                                   ("tx", "SantaTxOracle", "transaction")]:
            compiled = subprocess.run(
                [args.scala_cli, "run", "--server=false", "--jvm", "system", "--workspace",
                 str(Path(workspace) / kind), str(root / "scripts" / f"santa_{kind}_oracle" / f"{name}.scala"),
                 "--command"], cwd=root, env=env, check=True, text=True, stdout=subprocess.PIPE)
            command = compiled.stdout.splitlines()
            if not command or command[-1] != name:
                raise RuntimeError(f"unexpected Scala CLI command: {command}")
            for path in sorted((root / "test-vectors/santa" / corpus).rglob("*.json")):
                output = subprocess.run(command + [str(path)], cwd=root, env=env,
                                        check=True, text=True, stdout=subprocess.PIPE).stdout
                expected = {e["name"] for e in json.loads(path.read_text())["entries"]}
                lines = output.splitlines()
                actual = dict(line.split("\t", 1) for line in lines)
                if len(lines) != len(expected) or set(actual) != expected:
                    raise RuntimeError(f"incomplete or duplicate oracle coverage: {path}")
                companion = path.with_suffix(".jvm.tsv")
                previous = dict(line.split("\t", 1) for line in companion.read_text().splitlines()) if companion.exists() else {}
                for name, verdict in actual.items():
                    if previous.get(name) != verdict:
                        changes.append((str(path.relative_to(root)), name, previous.get(name), verdict))
                results.append((companion, output))
        # Publish only after every fixture has a successful complete result.
        for companion, output in results:
            companion.write_text(output)
    for path, name, before, after in changes:
        print(f"{path}: {name}: {before} -> {after}")
    print(f"Regenerated {len(results)} companions; {len(changes)} changed verdicts")


if __name__ == "__main__":
    main()
