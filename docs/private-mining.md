# Private transactions for your own miner

A mining node can retain signed transactions outside its public mempool and
include them only in candidates for its own miner. Enable mining and configure
the reward key as described in [mining architecture](codemap/ergo-mining.md). The operator API key is
required to submit, inspect, or cancel private transactions.

In the wallet send form, choose **Include only in a block I mine**. The form
starts the miner fee at zero and retains the delivery choice through build,
review, signing, and submission retries. Review the exact recipients, tokens,
change, fee, and expiry before signing. Waiting for your own block can take much
longer than a public transaction. The wallet's private mining queue also accepts
signed transaction hex from an Android wallet or another external signer.

The private queue does not broadcast inventory, populate public mempool views,
serve transaction bytes to peers, or use public mempool revalidation. Once your
block is published, its transactions are visible on-chain. Transactions already
in this node's public mempool, including ones held in its staging area waiting
for a parent, cannot be made private by resubmitting them; the queue rejects
that case. Once queued, every public admission path on this node declines the
transaction: peer relay, API submission, replay after a rollback, and orphan or
package promotion. A wallet or other node can still disclose bytes it already
has, so configure the external signing wallet to avoid broadcasting.

## Zero miner fees

Zero fees are local miner policy, while script, value, token, structure, and cost
validation still apply. The zero-fee builder omits the miner-fee output entirely.
It rejects tokenless dust change that would otherwise silently become a fee;
choose exact inputs or enough change for a valid box. Public admission retains
its configured minimum relay fee.

Zero miner fees do not remove contract requirements, minimum output values, or
re-emission obligations. A signed transaction cannot be edited: if a box it
spends or reads is spent first, it must be rebuilt and signed again.

## Deadlines, input reservations, and rollback

Pending private transactions reserve their spending inputs in the native wallet,
including for ordinary public sends and other private jobs. Automatic input
selection and "Retrieve rewards" skip reserved boxes; naming a reserved box as an
explicit input is refused. Wallet balances still include reserved boxes. Queue entries report
`queued`, `in_candidate`, `mined`, `conflicted`, `cancelled`, or `expired`.
Candidate membership describes the currently served template; it does not imply
a block will be found. Private ordering prefers larger integer priorities, then
submission order, subject to dependency order and candidate policy budgets.

Optional deadlines use either Unix milliseconds (`expires_at_ms`) or the last
eligible block height (`expires_at_height`). The node expires a height-bounded
item when the applied parent reaches that height, so it cannot enter the next
block. It checks expiry before solution acceptance, retires cached templates,
and rejects publication of builds frozen before an operator change. Cancellation
also retires templates before releasing inputs. These are local queue rules;
they do not make a previously signed transaction invalid elsewhere. Cancelled
and expired transactions are no longer kept out of this node's public mempool:
the node never broadcasts them itself, but you can now submit the same signed
bytes for public relay through this node.

The queue survives restart in `private-mining-queue.json` under the node data
directory. New files use owner-only permissions on Unix. Atomic durable writes
happen before admission or input release is acknowledged. Each write goes
through a randomly named temporary file; temporaries left by an interrupted
write are removed when the node next opens the queue. A failed write retains
reservations, and elapsed work is filtered out of new builds. Protect and back up
this file alongside the node's wallet data because it contains signed bytes.
If the node restarts with mining disabled while this file exists, the queue
still loads: its inputs stay reserved and its transactions stay out of public
admission. Nothing in it is mined, confirmed, expired, or cancellable until
mining is enabled again.
The queue is bounded to 1,024 retained records and 16 MiB of transaction bytes.

Applied transaction IDs and their exact block identities determine confirmation.
If a mined block is rolled back and inputs become available, pending work can
return to the queue. A competing spend produces `conflicted`; a rollback can
recover it. Original input IDs stay reserved for conflicted and mined entries
until cancellation or expiry; already-spent IDs do not affect current wallet
selection, while restored inputs are protected immediately after rollback. Cancelled and expired work stays withdrawn across rollback. Deep or
offline history is inspected in bounded batches. If necessary applied history is
unavailable on a pruned node, confirmation classification waits for that history
instead of guessing that a spent input proves your transaction was mined.

## Operator API

All three queue routes require the operator `api_key` header and respond with
owner-only metadata. Queue listing omits signed bytes.

```http
POST /api/v1/mining/private-transactions
api_key: <operator key>
Content-Type: application/json

{
  "signed_transaction_hex": "<signed transaction bytes in hex>",
  "options": {
    "expires_at_ms": 2000000000000,
    "expires_at_height": 2000000,
    "priority": 5,
    "label": "phone-signed payment"
  }
}
```

Use `GET /api/v1/mining/private-transactions` to list lifecycle metadata and
`POST /api/v1/mining/private-transactions/<tx_id>/cancel` to withdraw pending
work. Repeating admission of the same active or mined transaction is idempotent;
a cancelled, expired, or conflicted ID cannot be re-admitted as a fresh item.

Native wallet delivery uses the same queue:

```json
{
  "type": "signed",
  "signedTransaction": { "type": "bytes", "bytes": "<signed hex>" },
  "delivery": "mine_private",
  "privateOptions": { "expires_at_height": 2000000, "priority": 0 }
}
```

Send that request to `POST /api/v1/wallet/transactions/send`. `type: "intent"`
can build and sign using the unlocked node wallet, with a normal native intent
and `fee: "0"`. Omitting `delivery` retains the existing `broadcast` behavior;
`privateOptions` requires explicit `mine_private` delivery. Signed imports do
not require the node wallet to be unlocked, since the external wallet already
provided the signature.
