# Scala signing oracle — verify-side parity

**Audit reference:** `docs/audit-2.md` C6 / line 162.

**Closure status:** verify-side residuals closed (Phase 8d). Prove-side byte
parity remains deferred — Codex's strict-supervisor review classed it as
prover-implementation-equivalence testing, not consensus-relevant.

## Oracle source

Primary: `reference/sigmastate-interpreter/interpreter/shared/src/test/scala/sigmastate/crypto/SigningSpecification.scala`
— 8 pre-pinned proof-byte vectors:

| # | Vector | Scala line | Proposition shape |
|---|---|---|---|
| 1 | `simple signature test vector` | 15 | `ProveDlog(sk_a)` |
| 2 | `ProveDHT signature test vector` | 35 | `ProveDhTuple(g,h,u,v)` (raw 132B) |
| 3 | `AND signature test vector` | 55 | `AND(ProveDlog(sk_a), ProveDlog(sk_b))` |
| 4 | `OR signature test vector` | 67 | `OR(ProveDlog(sk_a), ProveDlog(sk_b))` |
| 5 | `OR with ProveDHT signature test vector` | 81 | `OR(ProveDlog(sk_a), ProveDhTuple(...))` |
| 6 | `AND with OR signature test vector` | 96 | `AND(ProveDlog(sk_a), OR(ProveDlog(sk_b), ProveDlog(sk_c)))` |
| 7 | `OR with AND signature test vector` | 111 | `OR(ProveDlog(sk_a), AND(ProveDlog(sk_b), ProveDlog(sk_c)))` |
| 8 | `threshold signature test vector` | 126 | `AtLeast(2, ProveDlog(sk_d), ProveDlog(sk_c), ProveDlog(sk_b))` |

Secondary (Phase 8d, captured via `extract-tools/scala-signing-harness/SigningResidualsSpec.scala`):

| # | Vector | Proposition shape | Prover holds |
|---|---|---|---|
| 9  | `or_2_real_first_only`  | `OR(ProveDlog(sk_a), ProveDlog(sk_b))` | only `sk_a` (real-first isolation) |
| 10 | `or_2_real_last_only`   | `OR(ProveDlog(sk_a), ProveDlog(sk_b))` | only `sk_b` (real-last isolation) |
| 11 | `threshold_2_of_5`      | `AtLeast(2, sk_a, sk_b, sk_c, sk_d, sk_e)` | `sk_a` and `sk_e` |

Each vector carries the message bytes, proposition shape, and Scala-produced
signature. The verify-side assertion is: `verify_sigma_proof(prop, signature,
message) == Ok(true)`. The same Scala node that produced these signatures will
broadcast them on the wire; our node must accept them for consensus.

## What this delivers

- **Verify-side byte parity** — our `verify_sigma_proof` accepts the exact
  byte-for-byte signatures Scala produced for these 8 propositions.
- **Composite-tree coverage** — `Cand`, `Cor`, `Cthreshold`, `ProveDhTuple`,
  and nested AND/OR all exercised.
- **Tamper-rejection coverage** — for every vector, two negative tests run:
  one flips a signature byte (must reject), one flips a message byte (must
  reject). This pins that verification is binding to both the proof bytes
  and the message bytes, not happy-path-only.
- **Corpus-count pin** — `proving_scala_oracle.rs` asserts the JSON declares
  `_corpus_count == vectors.len() == 8`. Silent shrinkage fails the test.
- **Per-signature SHA-256 pin** — every `signature_hex` is hashed and
  compared to a `SIGNATURE_DIGESTS` constant baked into the test source.
  Swapping the JSON to a different valid-but-non-Scala proof would still
  verify under our verifier (because any correct proof verifies), but the
  hash check would fail. This is the anti-fixture-swap gate.

## What is NOT covered

These limitations are intentional, documented, and tracked as follow-up work:

1. **Prove-side byte parity.** The audit's original ask was that our prover,
   given the same secret and a deterministically-seeded RNG matching Scala's,
   produce the exact same signature bytes as Scala. sigma-state's
   `SigningSpecification` does not expose the prover's commitment randomness
   (`r` values); reproducing the bytes requires Scala test-harness
   instrumentation to dump those `r` values per signing operation, then
   replaying them through our prover via `OwnCommitment` hints. This is
   multi-day work and is deferred.

   **Consensus-relevance:** the verify side IS the consensus boundary — Scala
   nodes only need to broadcast signatures, and other nodes (Scala or ours)
   only need to verify them. Two correct provers can produce *different* valid
   signatures for the same proposition (because `r` is randomized); rejecting
   one because it doesn't match a specific oracle would be a verifier bug, not
   prover correctness.

2. **Exhaustive byte-position tampering.** The negative tests flip the low
   bit of byte 0 of the signature and of the message; we do not
   exhaustively mutate every byte position.

3. **Threshold k-of-n for n > 5.** Phase 8d covered `2-of-5`. Higher
   arities are not pinned.

The two residuals Codex flagged in 8c — OR single-leaf branch-position
isolation and threshold `2-of-5` — are closed in Phase 8d via vectors 9–11.

## Pubkey provenance and trust chain

The `vectors[].proposition` tree references secrets by `sk_idx` (`a`, `b`,
`c`, `d`). The test derives each `pk_hex` at load time via
`k256::ProjectivePoint::GENERATOR * Scalar::from_be_bytes(sk_dec)` —
RustCrypto's audited secp256k1 primitive, NOT through our `GroupElement`
or `ProveDlog` wrappers (which would be self-oracle smuggling).

The Scala source explicitly pins one mapping:

```
SigningSpecification.scala:22
  Base16.encode(sk.publicImage.pkBytes) shouldBe
    "03cb0d49e4eae7e57059a3da8ac52626d26fc11330af8fb093fa597d8b93deb7b1"
```

The first thing the test does on load is assert that `k256` derivation for
`sk_a_dec` produces exactly that hex string. This anchors the derivation
function against Scala for the remaining secrets — any divergence in
secp256k1 scalar multiplication or SEC1 compression would fail this anchor
test before any signature is verified.

`sk_d_dec` is special: its big-endian byte encoding is only 31 bytes, so the
test left-pads with a single `0x00` to fit the 32-byte secp256k1 scalar repr.
This matches sigma-rust's handling at `signing_spec_tests.rs:404`.

## ProveDhTuple raw bytes

For vectors 2 and 5, `proposition.raw_hex` is the Scala-pinned 132-byte
SEC1-compressed concatenation of `g | h | u | v`. The test prepends the
`SigmaBooleanSerializer` tag byte (`0xCE`) and feeds the full wire through
the production `read_value(reader, &SigmaType::SSigmaProp)` reader in
`ergo-ser` — the same code path a Scala-sent proposition would take across
the wire. Any divergence from Scala's `ProveDHTupleSerializer` would fail
that read (and any wrong reconstruction would fail downstream verification
regardless of pubkey correctness).

## Phase 8d capture (NOT byte-deterministic)

Vectors 9–11 were captured ONCE via
`extract-tools/scala-signing-harness/SigningResidualsSpec.scala`. The exact
bytes pinned in this directory came from the run preserved at
`extract-tools/scala-signing-harness/captured/2026-05-24-vectors-9-11.txt`.

**A re-run will produce DIFFERENT (but still consensus-valid) bytes.**
sigma-state's prover draws fresh secp256k1 randomness on every invocation
(see `reference/sigmastate-interpreter/.../DLogProtocol.scala:68-72`,
`CryptoConstants.scala:35-37`, `ProverInterpreter.scala:298,326,342,397`).
The SHA-256 pins in `ergo-wallet/tests/proving_scala_oracle.rs::SIGNATURE_DIGESTS`
lock the exact captured bytes; without those pins, the verifier would
accept any future valid Scala proof for the same proposition and silently
shift coverage off the pinned bytes.

To regenerate (e.g., after a sigma-state upstream change you want to
re-pin against):

```bash
# 1. Drop the harness into sigma-state's test tree
cp extract-tools/scala-signing-harness/SigningResidualsSpec.scala \
   ../../reference/sigmastate-interpreter/interpreter/shared/src/test/scala/sigmastate/crypto/

# 2. Run via sbt (Scala 2.13, JDK 11+)
cd ../../reference/sigmastate-interpreter
sbt 'interpreterJVM / Test / testOnly sigmastate.crypto.SigningResidualsSpec'

# 3. Paste the new Signature: hex into vectors 9–11's signature_hex
# 4. Recompute SHA-256 of each and update SIGNATURE_DIGESTS in
#    ergo-wallet/tests/proving_scala_oracle.rs
# 5. Add a new transcript file under extract-tools/scala-signing-harness/captured/
```

The harness overrides `secrets: Seq[SigmaProtocolPrivateInput[_]]` on
`ErgoLikeTestProvingInterpreter` so the prover holds only the chosen secret
per case — that's what produces the branch-position-specific OR proofs and
the 2-of-5 threshold proof with a known held-subset. The shape coverage
(real-first vs real-last OR, 2-of-5 threshold) reproduces deterministically
on every run; only the wire bytes vary.

## Live-node oracle (re-capture procedure)

Future Phase 8c expansions (additional vector shapes, OR-last branch
coverage) can capture additional vectors via a Scala test harness with
seeded RNG. The closest existing entry point is the
`printSimpleSignature`/`printThresholdSignature` helpers in
`SigningSpecification.scala:186-218` which already construct propositions
and call `prover.prove(...).get.proof`. Wrapping these in a
deterministic-RNG context and adding additional propositions would yield the
remaining fixtures.

A live Scala node at `localhost:9053` was confirmed reachable during Phase
8c. Its `/wallet/transaction/sign` endpoint requires a 12-field
`ErgoLikeContext` (per `JsonCodecs.scala:440-454`), which is the same blocker
documented under `coll_updated_parity/README.md`. The source-citation
approach above is the available oracle until that JSON construction tooling
exists.
