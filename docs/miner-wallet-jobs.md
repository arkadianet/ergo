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
creation height. Wallet → Maintenance shows each renewal candidate's declared
creation height, its age and the height from which storage rent applies. Rent
counts from that declared height, which can precede the block that included
the box (`declaredCreationHeight` in `GET /api/v1/wallet/boxes`). Consolidation
preserves all token units and refuses a selection that cannot fit a single
output. Reward retrieval still pays required EIP-27 re-emission obligations; a
zero miner fee does not waive those obligations.

Approval builds the job's unsigned transaction and checks it against consensus
structure and the configured transaction size limit, so an operation that could
never sign is refused at once: insufficient funds, zero-fee change below the
minimum box value, an output above the 4,096-byte box limit or below its
minimum value, a transaction above `[mempool] max_tx_size_bytes`, or a renewal
input that is not a tracked P2PK box.

Approving a job requires an initialized, validly scanned and unlocked wallet,
like an intent send: the node later signs the job with the wallet key. The
expiry height may be at most 21,600 blocks (about 30 days) above the chain tip
at approval. Approved inputs are reserved from other wallet builds and jobs.
The wallet must also be unlocked when the job prepares its transaction. A job
waits without spending its attempts while the wallet is locked or its scan is
invalidated, while selected rewards are still maturing, and while the private
queue is unavailable, catching up with the chain, or slow to answer. A reward
retrieval may not start before its rewards mature. The scheduler shares the
existing wallet writer: preparation, signing, lock, cancellation, and shutdown
remain serialized.

Wallet → Maintenance lists each job's operation, schedule, and every payment
recipient and amount, also while the wallet is locked, so pending jobs can be
reviewed or cancelled before unlocking. A due job signs as soon as the wallet
is unlocked, so the wallet status panel lists pending operations and their
payment recipients whenever the lock state changes.

Each approved job prepares at most one signed transaction. The redb journal
commits its exact signed bytes before private admission. After a crash or an
uncertain submission result, a retry submits those same bytes and transaction
ID. It never builds a second payment from fresh funds. An interrupted unsigned
preparation restores its reservations before the writer accepts commands.
There is at most one preparation/submission attempt per applied height and one
operation per scheduler wake. Mined jobs follow private-queue reorg state.
If a pinned input is spent or held by another transaction when the job
prepares, the job fails for good and releases its reservations. It never signs
later, even if a rollback revives that input; approve a new job if the
operation is still wanted. Only an admitted transaction is reported as
conflicted, because a rollback can return that same transaction to the queue.
The scheduler reads one queue metadata snapshot per wake and waits at most one
second for each background metadata, admission, or cancellation request. An
unavailable snapshot holds back only jobs whose transaction may already be
admitted, and only until their deadline: the queue applies the same height
deadline, so expiry never waits for it. A transaction the queue still lists as
unfinished at the deadline height gets one more block for the queue's verdict,
so one mined in its last eligible block is reported as mined, not expired. An
uncertain admission keeps its prepared bytes; only a successful later snapshot
showing absence permits resubmission of those same bytes. When the queue cannot
report a deadline's outcome, the wallet's own chain history, once scanned
through the deadline block, tells a mined job from an expired one.

Jobs need private mining, so a node without `[mining] enabled = true` refuses
approvals. If mining is disabled after approval, pending jobs wait without
signing or spending attempts. The node still loads a private queue file it
finds, so cancelling such a job also withdraws its transaction from that stored
queue, and enabling mining again cannot mine it. A deadline retires the job
locally: the stored transaction can no longer be selected, because the queue
applies the same deadline, but its inputs stay reserved until mining is enabled
again and the queue expires it.

The journal holds at most 256 jobs, pruning the oldest terminal record when
necessary. Each record is bounded to 512 KiB. A signed transaction above the
configured `[mempool] max_tx_size_bytes`, or one whose record would exceed that
bound, is neither journaled nor submitted; the job records the error and counts
the attempt. A failing job never stops the wallet writer; only a job journal
that cannot be read or written does. Signed bytes stay in the journal only
while a job follows the private queue and are omitted from job API responses;
cancellation, expiry and failure delete them, and cancellation and deadlines
withdraw the transaction from private mining. Neither revokes the signature: a
signed transaction stays valid until one of its inputs is spent, so a mined
transaction cannot be undone and any retained copy could still be published. A
queue stored while mining is disabled keeps work admitted earlier and not
cancelled, which can be mined until its deadline once mining is enabled again.
Historical terminal jobs remain visible while retained.

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
