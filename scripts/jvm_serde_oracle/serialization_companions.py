#!/usr/bin/env python3
"""Regenerate reference serialization companions using the pinned JVM oracles."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    env = os.environ.copy()
    env.setdefault("COURSIER_REPOSITORIES", "ivy2Local|https://repo.maven.apache.org/maven2")
    env.setdefault("JAVA_TOOL_OPTIONS", "-XX:ActiveProcessorCount=4")
    for argument in sys.argv[1:]:
        fixture = Path(argument)
        readers = fixture.name.startswith("readers-")
        script = "SerializationOracle.scala" if readers else "TransactionSerializationOracle.scala"
        with tempfile.TemporaryDirectory(prefix="serialization-607-") as workspace:
            result = subprocess.run(
                ["scala-cli", "run", str(Path(__file__).parent / script),
                 "--server=false", "--jvm", "system", "--workspace", workspace,
                 "--", str(fixture)],
                env=env, check=True, text=True, stdout=subprocess.PIPE,
            )
        if readers:
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            output = "".join("\t".join([
                row["name"], row["result"], str(row["position"]),
                str(row["rule_id"]) if row["rule_id"] is not None else "-",
                row["canonical_hex"] or "-", row["extra"] or "-",
            ]) + "\n" for row in rows)
        else:
            output = result.stdout
        expected_names = [entry["name"] for entry in json.loads(fixture.read_text())["entries"]]
        assert [line.split("\t")[0] for line in output.splitlines()] == expected_names
        fixture.with_suffix(".jvm.tsv").write_text(output)


if __name__ == "__main__":
    main()
