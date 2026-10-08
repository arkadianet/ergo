# Authenticated committed evidence reader candidate

This read-only transport extends the frozen applied-evidence outbox candidate.
It changes no validation, journal mutation, consensus encoding or node pin.
The in-process journal contract and normative digest framing remain in
[applied-evidence-outbox.md](applied-evidence-outbox.md). The earlier document's
remaining-transport statement describes the stage before this reader.

The production node supplies the existing shared redb database and the exact
configured genesis header ID to the reader. It mounts
`GET /api/v1/evidence/committed` only when the actual committed-outbox reader
and `Some(ApiSecurity)` are both configured. Set `applied_evidence_outbox = true`
using the configuration documented for the outbox, and configure the existing
API-key hash. Existing API-key middleware requires the `api_key` request header.
There is no query-key, loopback, anonymous or response-flag authentication.

## Paging contract

The initial request has no cursor. Subsequent requests supply all three
`afterArchiveId`, `afterSequence` and `afterEventHash` query fields exactly as
returned in `nextCursor`. IDs are 64 lowercase hex characters; sequence is a
canonical decimal integer between zero and 2^53−1. A partial cursor, unknown
query field or duplicate query field is refused. `limit` is a canonical decimal
integer from 1 through 16 and defaults to 1. The query is at most 512 bytes.

A successful response has schema `ergo-committed-evidence-page-v1`:

```json
{
  "schema": "ergo-committed-evidence-page-v1",
  "source": {
    "kind": "committedRedbJournal",
    "configuredGenesisAnchor": "<configured genesis ID>"
  },
  "meta": {
    "archiveId": "<journal archive ID>",
    "anchorId": "<journal genesis anchor>",
    "cursor": {"archiveId": "<ID>", "sequence": 1, "eventHash": "<hash>"},
    "branchGeneration": 0,
    "tipId": "<committed canonical full-block ID>",
    "tipHeight": 1,
    "reconstructionRequired": false
  },
  "events": [{"eventJson": "<exact normative JournalEvent JSON string>", "eventHash": "<hash>"}],
  "nextCursor": {"archiveId": "<ID>", "sequence": 1, "eventHash": "<hash>"}
}
```

`eventJson` preserves the pinned `JournalEvent` serialization used by the
outbox hash framing, including its declared field order, captured canonical
native bytes and actual provenance. Decode the outer JSON string once, then
hash its UTF-8 bytes using the outbox framing. Hashing the outer HTTP body or a
parsed-and-reserialized event can produce a different digest. The journal is
an integrity/cursor mechanism, not a signature by a database owner.

Every page comes from one existing `read_committed` redb read snapshot. Its
journal head is checked against canonical chain metadata in that same
snapshot. The API does not consult the snapshot publisher, in-memory overlay,
queued persistence jobs or displayed market records. The configured genesis
anchor must match the committed journal. `meta.cursor` is the journal head;
`nextCursor` acknowledges only the records returned on this page. An empty
page keeps the supplied cursor unchanged.

Intentional gap records remain visible as `capture: null` with `gapReason`
inside `eventJson`; their sticky `reconstructionRequired` flag is preserved.
`checkpointSkipped` and `trustedGenesisAnchor` provenance are preserved and
are not promoted to `full` validation. A service requiring complete full
evidence must refuse these records and reconstruct from its authenticated
genesis policy. A missing/corrupt record, invalid/rewound cursor, mismatched
committed tip or changed archive returns 409 `reconstruction_required` and no
success cursor.

## Bounds and failure behavior

Requests must have an empty body. At most two blocking readers run at once;
additional concurrent reads receive 503 `reader_busy`. Both individual event
serialization and the complete escaped HTTP response have a 16 MiB bound.
An oversized response returns 413 `page_too_large` without a partial page or
cursor advancement. A consumer may reduce `limit` and retry from its previous
durable cursor. An oversized single record requires another reviewed
transport; this route does not truncate evidence. Unavailable storage returns
503 `reader_unavailable`; invalid queries return 400. Responses use
`Cache-Control: no-store`.

The underlying redb durability policy is unchanged. Committed visibility
does not claim that every visible page is already fsynced. A consumer must
atomically persist its registry changes and its own cursor, and refuse a
rewind after node restart.

## Consumer trust boundary and validation

The caller must independently authenticate the configured node endpoint,
transport, genesis anchor, reviewed manifest and activation/native paired
context. The source label and API-key-protected response do not provide a
cryptographic node identity or a review certificate. File exports remain
unverified observations. The service `AppliedEvidenceSource`, registry mapping,
durable cursor integration and pre-submit native validation are separate work.
No actor, node adoption, live market registration or launch parity is implied.

Focused tests use only task-owned temporary databases and the actual merged
router. They cover route absence without reader/security, missing/wrong keys,
strict cursors, bounded bodies/pages, exact journal bytes and genesis anchor,
committed canonical tip, intentional gaps, corrupt/missing rows and queued
persist-job invisibility.

```sh
cargo test --locked --offline -p ergo-api --test committed_evidence_routes
cargo test --locked --offline -p ergo-node --lib committed_evidence_bridge
```
