# Reduced transactions for wallet libraries

`ergo-wallet` provides EIP-43 reduced transaction bytes for EIP-19 cold signing
and EIP-20 ErgoPay. The portable library requires no CLI, file keystore, node,
database or network runtime. Enable `keystore` or `cli` only in hosts that need
them.

## Reduce and sign

Build an `UnsignedTransaction` and resolve its spending and data boxes in
exact transaction order. Supply `tx_context::SigningContext` with the frozen
chain state, original serialized header IDs and active validation settings.
The caller authenticates that snapshot; the library checks its internal
coherence, activation version and participant identities.

`Prover::reduce_transaction` evaluates scripts in that context and returns a
`ReducedTransaction`. It charges transaction initialization, participant and
token access, and script evaluation against the configured block cost limit.
`ReducedInput.cost` is the cumulative running cost, not an independent amount
to sum across inputs. `ReducedTransaction.cost` is the aggregate reduction
cost; crypto verification cost is charged separately before signing.

`ReducedTransaction::to_bytes` produces the SDK wire representation.
`ReducedTransaction::from_bytes(bytes, block_version)` requires the actual
active block version: the format has no separate version byte. Parsing enforces
canonical message bytes, empty input proofs, complete consumption, group-point
validity, size and tree-depth limits. Ordinary node transaction bytes and JSON
unsigned transactions are different formats.

`Prover::sign_reduced` proves the frozen propositions without a chain lookup
or another script evaluation. Trivial true produces an empty proof; DLog,
DH tuple, AND, OR and threshold reductions use the existing proof machinery.
A received reduction is a claim from its producer, not evidence that the
scripts were evaluated correctly or that the transaction is valid on chain.
The host must review the transaction and trust or independently reproduce its
reduction before authorizing a signature. Full structural, economic and chain
validation still belongs to the host/node.

## Multi-party commitments

Use `generate_reduced_commitments_bound` for native signing rounds. The bound
bag commits to both the transaction message and the complete reduced wire
representation. Consume it through `sign_reduced_bound` or
`sign_reduced_partial_bound` once; a changed transaction or changed reduction
rejects before producing a nonce response. Import only public commitments and
use reduced hint extraction to complete the other party's proof.

The low-level unbound hint APIs exist for SDK interoperability. An own nonce
must be used in only one signing round. Reusing it with another challenge can
reveal the private key. Public commitment transport must never carry the
party's secret nonce material.

## Cold transport and interoperability

EIP-19 CSR requests include standard padded Base64 reduced bytes and complete
spending boxes. Its CSR/CSTX QR envelopes chunk the inner JSON and use one-based
page numbers. ErgoPay uses URL-safe Base64 instead. Transport adapters must
preserve context extensions and match the complete input boxes against the
transaction's input IDs and order.

AppKit `SignedTransaction.toBytes()` adds a crypto-cost trailer to the node
transaction bytes. Treat that as an SDK wrapper and parse it explicitly when
interoperating with AppKit; it is not an extra field in the node transaction
format or a universal EIP-19 requirement.

The [oracle guide](../test-vectors/wallet/README.md#reduced-transactions-and-cold-transport)
documents pinned AppKit/sigma-rust versions, real contract fixtures, proof
verification in both directions, and independent QR rendering/scanning.
Those transport harnesses and SDK dependencies are test tooling, not mobile
library dependencies or a public QR/UI API.

Direct `Prover::sign` retains its existing conservative script gate in this
change. Real-context direct signing and service integration are a separate
review under [#612](https://github.com/arkadianet/ergo/issues/612).
