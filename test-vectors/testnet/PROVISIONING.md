# Testnet vector extraction

This directory contains public Scala testnet observations and derived oracle
inputs. `genesis_boxes.json` is embedded by `GenesisParams::testnet()`.
The public configuration currently supplies both the height-1 genesis ID and
boxes; the node's `validate_supported` gate does not require manually changing
`None` fields before startup. Compare any recapture against the configured
network identity before proposing a change to those constants.

## Committed observations

- `initial-context/` records Scala 6.0.3 REST blocks 1, 2, 128 and 1024, genesis
  boxes and independent explorer genesis agreement captured on 2026-10-04.
  It also ships pinned v6.0.5 launch/context source and actual Sigma 6.0.6
  header serialization with dependency hashes. See its README for finite
  reproduction and limits. Height 128 is the first testnet epoch boundary.
- `headers_json/scala_headers_442325_442334.json` contains ten consecutive
  version-4 header responses, preserving their JSON field types.
- `mining_json/scala_candidate_522032.json` is a Scala 6.0.3 candidate response
  captured on 2026-09-03. Its target `b` is a bare JSON number beyond f64's
  exact integer range; the REST JSON consumer uses arbitrary precision.

Bulk ranges are gitignored and must be acquired before running their ignored
consumers. The small committed captures do not establish continuous chain
membership, a complete reference-node execution or full Rust testnet sync.

## Provision a reference node

Use the public testnet profile from Scala v6.0.3 or later; earlier profiles
may describe the retired PaiNet (`:9022`, magic `[2,0,2,3]`). Pin a concrete
upstream revision and dependency graph in the resulting fixture provenance.
From that checkout, build with `sbt -mem 4096 assembly`. The pinned v6.0.5
build uses Scala 2.12, so select its assembly under `target/scala-2.12/`:

```bash
java -jar target/scala-2.12/ergo-*.jar --testnet \
  -c src/main/resources/testnet.conf
```

Confirm the node reports `network: testnet` and the expected genesis ID via
`/info`. The public profile uses REST port 9052; its configured P2P port is
9023. `extraIndex = true` is needed only for indexed address/token extraction.
Wait until the specific heights requested below are available.

## Extract ranges and genesis boxes

The scripts use `NODE_URL`. `extract_headers.sh` also requires a working
`SCALA_CLI` executable and downloads the dependencies declared in its helper;
that graph must be recorded separately from the pinned finite capture above.

```bash
export NODE_URL=http://localhost:9052
export SCALA_CLI=/path/to/scala-cli
cd test-vectors/scripts
./extract_headers.sh 1 1 ../testnet/header_height_1.json
./extract_headers.sh 1 10000 ../testnet/headers_1_10000.json
./extract_utxo_digests.sh 1 1 ../testnet/state_digest_height_1.json
curl --fail --silent --show-error "$NODE_URL/utxo/genesis" \
  > ../testnet/genesis_boxes.json
```

The header and digest scripts each require **start, end, output**. Genesis
boxes come from `/utxo/genesis`; `extract_boxes.sh` consumes a transaction
vector file and is not a height-0 query. The generated height-1 header and
digest files are optional oracle inputs, not runtime startup prerequisites.
Check counts, IDs, complete decoding and independent expected values before
committing regenerated fixtures; script completion alone is not validation.

Fixtures must use an external oracle as required by `CONTRIBUTING.md` and
`docs/compatibility.md`. Record endpoint/version/network/revision, exact input
and output hashes, serializer dependencies and what was actually asserted.
Do not rewrite old launch rows or relabel historical fixture outcomes based
solely on a new public observation.
