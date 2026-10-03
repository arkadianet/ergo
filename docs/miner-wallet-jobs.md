# Private wallet maintenance

The node wallet can journal one approved maintenance operation for inclusion
in a block mined by this node. Wallet → Maintenance reviews an exact set of
1–100 input boxes, the destination, earliest height, expiry height, and maximum
attempts before creating the job. The operation never broadcasts publicly.

Supported operations are consolidation into a tracked P2PK receiving address,
renewal of selected owned boxes, and retrieval of selected mining rewards after
they mature. The authenticated API also accepts a fixed payment `TxIntent` with
explicit `boxIds`, zero miner fee, no issuance, and no intentional token burn.
Renewal preserves each recipient, value, tokens, and registers and updates its
creation height. Consolidation preserves all token units and refuses a selection
that cannot fit a single output. Reward retrieval still pays required EIP-27
re-emission obligations; a zero miner fee does not waive those obligations.

Jobs require an initialized, validly scanned wallet. Approved inputs are
reserved from other wallet builds and jobs. The wallet must be unlocked when
preparing the transaction. Locked wallets wait without spending their retry
allowance. The scheduler shares the existing wallet writer: preparation, signing,
lock, cancellation, and shutdown remain serialized.

Each approved job prepares at most one signed transaction. The redb journal
commits its exact signed bytes before private admission. After a crash or an
uncertain submission result, a retry submits those same bytes and transaction
ID. It never builds a second payment from fresh funds. An interrupted unsigned
preparation restores its reservations before the writer accepts commands.
There is at most one preparation/submission attempt per applied height and one
operation per scheduler wake. Mined jobs follow private-queue reorg state.
The scheduler reads one queue metadata snapshot per wake and waits at most one
second for each background metadata, admission, or cancellation request. An
unavailable snapshot preserves pending jobs and their reservations. An uncertain
admission keeps its prepared bytes; only a successful later snapshot showing
absence permits resubmission of those same bytes.

The journal holds at most 256 jobs, pruning the oldest terminal record when
necessary. Each record is bounded to 512 KiB. Signed bytes remain in the node's
journal and are omitted from job API responses. Deadlines and cancellation
retire unpublished private mining work; a transaction already mined cannot be
undone by cancellation. Historical terminal jobs remain visible while retained.

## Authenticated native API

- `GET /api/v1/wallet/mining-jobs` lists owner-only job metadata.
- `POST /api/v1/wallet/mining-jobs` approves one finite operation.
- `POST /api/v1/wallet/mining-jobs/{job_id}/cancel` cancels pending work.

Requests use the normal operator `api_key` header. Responses carry
`Cache-Control: no-store`. The existing public relay minimum fee is unaffected.

Example approval (replace the pinned input ID with a reviewed owned box):

```json
{
  "label": "Renew selected box",
  "task": { "type": "renew", "boxIds": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] },
  "notBeforeHeight": 1800000,
  "expiresAtHeight": 1800720,
  "maxAttempts": 10
}
```
