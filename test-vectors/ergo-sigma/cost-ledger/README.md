# Cost fixture storage

Fixtures use `<name>.json.gz`, with the identical JSON schema and bytes inside.
Gzip generation omits the filename and uses `mtime=0` (equivalent to `gzip -n`)
so identical JSON produces byte-stable output. Readers also accept legacy
`.json` files and prefer `.json.gz` when both exist.

Manifest `evidence` SHA-256 hashes cover **uncompressed JSON / JSONL bytes**,
not gzip archives. Existing manifests retain their original command paths and
revision provenance because compression does not regenerate oracle evidence.

Use `scripts/gen-cost-fixture.sh <fixture.json.gz>` to refresh JVM evidence.
Python generators share `scripts/cost_fixture_io.py`, which reads both formats
and atomically writes deterministic gzip. JVM-only `.jvm` evidence stays plain
and remains outside the Rust runner's JSON fixture selection.
