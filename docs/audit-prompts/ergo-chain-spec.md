# Audit prompt: ergo-chain-spec

Audit `ergo-chain-spec` as the network-identity and protocol-parameter authority
of a prospective reference-quality Rust Ergo node.

First read `docs/audit-prompts/COMMON.md` and follow its full methodology,
review-only default, evidence standards, reporting format, and coverage ledger.
Then read `CONTRIBUTING.md`, `docs/compatibility.md`, this crate's manifest/root
and `docs/codemap/ergo-chain-spec.md`. Commands and repository-prefixed paths are
relative to the repository root; abbreviated source paths are relative to this crate.
Inventory all crate files and every embedded/cited fixture, test, comment,
document, configuration and extraction script. Verify maps against current code:
the current network selector also includes `Devnet`.

## Mission and trust boundaries

This crate declares which chain the node runs, using pure types, constants and
constructors. Wrong network magic, genesis identity, voting/difficulty schedule,
contract tree or checkpoint can defeat otherwise correct validation.

Distinguish immutable chain identity and consensus parameters from operational
seed peers, local sync readiness thresholds and optional trust shortcuts. A
Scala config citation, a chain capture and a live-peer observation prove
different things. Verify provenance and revision for each claim independently.

Public parameter structs also allow caller-built combinations. Determine which
invariants constructors establish, which consumers assume and which external
configuration boundary checks before use. Do not demand impossible guarantees
from a plain data struct, or excuse unsafe caller assumptions because defaults
are sound.

## Source landmarks and authority

- `ergo-chain-spec/src/lib.rs`: the whole crate, including all inline tests.
- `Network`, `NetworkParams`, `DifficultyParams`, `V2Activation`, `VotingParams`.
- `MonetaryParams`, `ReemissionParams`, `GenesisParams`, `BlockTimingParams`.
- `BootstrapParams`, `ChainSpec`, `EmissionScriptTrees` and contract hex literals.
- `ChainSpec::{mainnet,testnet,devnet,for_network,emission_script_trees}` and all
  narrow `for_network` accessors; examine every constructor rather than assuming
  the aggregate delegates identically.
- `test-vectors/mainnet/genesis_boxes.json`,
  `test-vectors/testnet/genesis_boxes.json` and testnet `PROVISIONING.md`.
- `test-vectors/api/emission/scripts.json` for the captured contract bytes.
- `scripts/devnet-mixed/genesis.conf`, `scala-node.conf`, `rust-node.toml`,
  campaign code and README for the explicitly private-chain overrides.
- Scala config/source revisions cited in crate docs and tests. Resolve the
  actual checked-out/pinned upstream authority when performing the audit;
  historical source paths and line numbers are navigation hints, not proof.

## Network identity and constructors

1. Compare every mainnet/testnet/devnet field against its intended authority:
   network name parsing/display, magic bytes, address prefix, genesis header ID,
   state root, optional re-emission, seeds and checkpoint. Check unknown names,
   case/whitespace policy and consistency with CLI/API callers.
2. Verify testnet reset provenance separately from the old public testnet.
   Retired magic, ports, checkpoint and genesis IDs must not leak through an
   inherited constructor, fallback or stale fixture. Check claims about which
   launch block version is actually consumed downstream, rather than equating
   a config version with the validation launch row.
3. Verify Devnet's private magic, testnet address prefix/genesis boxes, absent
   height-one pin/checkpoint/seeds, large epoch/voting lengths and 20-second
   interval against the campaign's Scala overrides. Trace isolation from public
   network startup, persisted metadata, peer handshakes and NiPoPoW anchoring.
4. Compare aggregate constructors and narrow accessors field by field. Check
   paired values maintained in different groups: desired interval, v2 activation
   height, epoch lengths and look-back count. Identify accidental drift or
   deliberately different notions such as voting versus difficulty epochs.
5. Review all absence semantics. `None` for no EIP-37/v2 transition/re-emission,
   unknown genesis pin or no checkpoint must remain distinguishable from a
   numerical sentinel or an operational override.

## Consensus schedule and arithmetic

- Check initial-difficulty bytes, unsigned big-endian interpretation, leading
  zeros, v1/v2 activation initial difficulty, EIP-37 height and epoch boundary
  conventions. Compare parent-height and child-height consumers.
- Verify `use_last_epochs` with both difficulty regression and NiPoPoW
  connection verification. A duplicated implementation constant needs evidence
  of agreement; the existence of a comment is insufficient.
- Verify vote approval thresholds, inclusive/strict comparisons, voting epoch
  and activation epoch units, multiplication/addition near type limits and
  behavior of caller-built zero-length epochs or impossible parameter sets.
- Check emission schedule units: nanoERG, block heights, fixed-rate period,
  reduction period, founder allocation and miner reward delay. Confirm claims
  that the monetary schedule is inherited unchanged on other networks.
- Check EIP-27 activation/distribution boundaries and all token/NFT IDs.
  Cross-check parsed widths and downstream meaning; similarly named fields
  such as the re-emission start height need precise current documentation.
- Verify freshness-threshold units and product bounds. Determine whether this
  local readiness heuristic is documented as a consensus rule accidentally.
- Trace every duplicated downstream default/network match for disagreement.
  Use concrete call paths to separate a harmful divergence from an intentional
  narrower parameter view.

## Genesis, contracts and checkpoint authority

Verify embedded genesis JSON as shipped content: shape, source network, IDs,
heights, script bytes, token/register values and extraction provenance. Follow
the node's genesis parser/state construction to an independently captured AVL
root. A literal equality test between two Rust constants does not prove genesis
state compatibility.

Check every contract hex literal against the independent emission fixture,
including the exact emission/re-emission/pay-to-re-emission distinction. Parse
the trees with the relevant version/context and verify address consumers use the
correct network. Inspect the defensive identity gate on `emission_script_trees`
for mutated/custom specs; establish which inputs it checks and why. Treat absent
testnet contract evidence and its documented behavior as an explicit coverage
gap, not an invented claim that the network lacks those contracts.

Verify checkpoint height+ID provenance and downstream enforcement: exact-height
pinning, the precise script/cost work skipped and state checks retained. Report
the actual trust assumption. Check that an operational seed update cannot
silently alter genesis/checkpoint authority or imply current peer liveness from
a historical observation.

## Required test and evidence review

- Produce a field-by-field authority table for all three networks, with source
  revision, fixture, units, constructor and consumer. Mark unsupported claims.
- Inspect baseline snapshot tests versus externally anchored parity tests.
  Copying a source literal into an assertion does not add independent evidence.
- Check activation height minus one/at/plus one, vote threshold minus one/at/
  plus one, inherited parameter agreement, absent optional groups and mutated
  spec identity gates using appropriate downstream tests where necessary.
- Review private hex parser panic sites in context: fixed source literals differ
  from runtime config. Confirm every literal decodes to its claimed width.
- Review embedded fixtures, provenance/license documents and regeneration
  instructions for staleness. Do not probe or mutate live networks by default.

```bash
cargo test --locked -p ergo-chain-spec
cargo clippy --locked -p ergo-chain-spec --all-targets --all-features -- -D warnings
cargo doc --locked -p ergo-chain-spec --no-deps
```

## Exit criteria

Deliver the COMMON report and coverage ledger with the complete network/field
authority table and constructor-to-consumer checks. State genesis/contract/
checkpoint verification limits explicitly. Consensus constants, operational
defaults and stale explanatory material must receive distinct conclusions;
no claim of perfect network parity follows merely from frozen snapshot tests.
