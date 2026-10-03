# ergo-p2p

Transport, wire codecs and peer bookkeeping driven by `ergo-sync`. Workspace
dependencies are `ergo-primitives` and `ergo-ser`; this crate does not establish
consensus validity or cumulative-work fork choice.

## Modules

- `src/lib.rs`: public module map and transport boundary.
- `src/framing.rs`: `MessageFrame`, fixed big-endian framing/checksum, partial
  header/payload parsing, `wire_len` accounting.
- `src/connection.rs`: buffered async TCP reads/writes, metered payload permits,
  admission slots and shared byte budgets; state is retained across cancelled
  reads. `new_with_buffer` accepts post-handshake framed leftovers.
- `src/handshake.rs`: raw `Handshake`, `PeerSpec`, version/feature codecs,
  admission prefix cap and consumed-byte result. PeerSpec also backs gossip.
- `src/message/mod.rs`, `src/message/tests.rs`: message registry and VLQ payload
  codecs, count/type/length bounds and ordinary round-trip regressions.
- `src/types.rs`: modifier-type IDs and typed inventory/body/bootstrap payloads.
- `src/peer.rs`: connection state, negotiated version, scoring and byte counters.
- `src/peer_manager/{mod,limits,routability,tests}.rs`: connection lifecycle,
  self-session detection, IP/subnet limits, seeds, gossip and selection policy.
- `src/address_book/{mod,codec}.rs`: separate advisory `peers.redb`, schema,
  key/value codecs, expiry/routability pruning, best-effort persistence and
  quick-repair write policy. Unrepresentable timestamps are corrupt row errors.
- `src/delivery/{mod,tests}.rs`: counted primary ownership, late/hedge eligibility,
  per-peer caps, hard/soft timeouts, retries and abandonment cleanup.
- `src/assembly.rs`: transactions/extension/optional ADProofs arrival aggregation,
  one completion edge and reverse section index. Production UTXO and digest
  application require shipped proofs; section identities come from
  `ergo_ser::modifier_id`.
- `src/partition.rs`: deterministic per-type request buckets for unique caller
  inputs, rotated peer assignment and deferred overflow.
- `src/throttle.rs`: per-peer message/byte windows; admitted solicited over-cap
  frames are accounted by the NODE dispatch caller.
- `src/sync.rs`: download-window state, receive/send cadence and preliminary
  V1/V2 status comparison. Authoritative fork choice belongs to SYNC/STATE.

## Contracts and evidence

Nonempty frames are `magic[4] || code[1] || length[4 BE i32] || checksum[4] ||
payload`; the checksum is the first four Blake2b256 bytes. Empty payloads omit
the checksum. Payload fields use Scorex VLQ/zigzag. The message limits include
Inv/Modifiers 400, SyncInfo V1 1001 and V2 50 headers. Modifiers encoding rejects
unknown types and overcounts, while preserving the existing size-limited prefix
policy. Decoders bound allocations using available bytes as well as semantic
limits; Connection rejects payloads above its 8 MiB transport cap.

Raw handshake admission bounds the **parsed prefix** at 8096 bytes and returns
its consumed length. Coalesced framed bytes are outside that cap. Handshake
unit regressions cover a large leftover frame and the exact prefix boundary;
`tests/it/wire_tcp_pair.rs` covers framed TCP transport and an explicitly
synthetic code-75 handshake-payload exchange, not the production admission loop.

Delivery counts one current owner per ID. Other asked late/hedge peers remain
eligible until receipt/expiry; disconnect revokes only that peer's allowance.
First receipt clears all allowances and retry/shadow records, duplicates are
ignored, and retry exhaustion returns to Unknown for a later download round.
Abandoned first/second retry counts expire with their type shadows, while
active requests retain their retry cycle. The received FIFO retains 10,000 IDs.
Partitioning assumes deduplicated inputs and does not remove duplicate entries.

Address-book writes use quick-repair to preserve redb allocator metadata for
dirty-open recovery; this is not a physical power-loss guarantee. Recoverable
storage/lock/upgrade errors preserve the original advisory file. Corrupt rows
are counted/skipped, including native-unrepresentable timestamp values.
`tests/it/address_book_persist.rs` proves clean object drop/reopen, not a child
process exit or interrupted write. Native SystemTime bounds vary by platform.

`tests/it/wire_vectors_oracle.rs` consumes the Scala-source fixtures documented
in `test-vectors/ergo-p2p/PROVISIONING.md`: four full frames and one source-derived
V2 payload. These finite fixtures do not establish full legacy-peer exchange or
runtime parity for every supported message. Peer caps/penalties/seeds are local
policy, not authenticated peer identity or a universal eclipse-resistance proof.
