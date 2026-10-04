# Offline backup, recovery and current-UTXO wallet discovery

Stop the node cleanly before these commands. All paths are positional and the
commands return JSON on stdout, with a nonzero exit status on failure.

```sh
ergo-node doctor /srv/ergo
ergo-node utxo-stats /srv/ergo
ergo-node backup /srv/ergo /backups/ergo-2026-10-04
ergo-node verify-backup /backups/ergo-2026-10-04
ergo-node restore /backups/ergo-2026-10-04 /srv/ergo-restored
```

Backup copies every regular file beneath the data directory, including the
encrypted wallet, config stored there, peer database, indexer, webhook state,
and credential revocations. It rejects symlinks and special files. It detects
redb databases by extension and file header, and holds read-only locks on them
throughout inspection/copy. A running node therefore prevents the operation.
Config or other files outside the data directory are not included. Copy those
separately; review absolute `data_dir`, indexer and logging paths before booting
a restored directory. Logs in the directory are included and can be large.

The versioned `ergo-backup.json` records file sizes and streaming SHA256 hashes,
node version, committed full-block height/ID, state type/root, stored format
versions, and verified logical UTXO statistics. SHA256 detects accidental
corruption; it is not an authenticity signature. Protect the backup as carefully
as the wallet. On Unix every created backup/restore directory is 0700 and files are 0600.

Backup and restore refuse every existing destination, including empty
directories, and require a destination outside the source directory. They build
and verify a temporary copy before publishing the entire directory with one
rename. Staging names are derived from the destination: `.NAME.ergo-backup-staging`
or `.NAME.ergo-restore-staging` in its parent directory. SIGINT (Ctrl-C) and
SIGTERM request cancellation; the command closes its files and removes staging
before exiting. A crash, SIGKILL, or power loss can leave a staging copy containing
wallet secrets, or an empty destination reservation. The next run refuses a stale
staging path and reports its location. Confirm no copy is running, remove the
stale copy and any empty reservation, then retry. A partial restore is never
published as a bootable destination. Restore checks the source,
copied checksums, and copied committed metadata/root before publication. Source
databases and existing destinations are never repaired or replaced.

`doctor` traverses storage pages, checks committed metadata, and, on a UTXO
backend, visits only leaves reachable from the committed AVL root. It recomputes
labels/root, verifies child labels, leaf order and links, height/balance, and box
identities. It reports errors without changing validity flags, chain selection,
or state roots. Digest backends report metadata/storage checks without claiming
UTXO verification. This is an offline integrity inspection, not historical block
revalidation. `utxo-stats` reports live box count, serialized bytes, minimum and
maximum box size, internal-node count/tree height, and total nanoERG as a decimal
string. Dead arena nodes and redb page overhead are excluded.

Restore rolls external delivery and credential state back to the backup date.
Webhook consumers should deduplicate event IDs; check revoked credentials and
delivery cursors before restarting a restored node.

Backups also include `private-mining-queue.json`, `mining-policy.json`,
`mining-history.json`, and the wallet mining job journal in `state.redb`. Restoring
an older backup can recover payments or jobs cancelled since that backup. By
default restore reports pending private transaction metadata and wallet job IDs,
moves the private queue to `private-mining-queue.restored-quarantine.json`, and
moves all job records (including signed bytes) into the
`wallet_mining_jobs_quarantined_v1` table in the restored database. The active
queue and job journal are empty, so the restored node cannot execute this work.
Policy and mining history are preserved. Copied checksums are verified before
these deliberate quarantine changes; committed chain metadata and UTXOs stay
unchanged.

To explicitly confirm that the backup's private work may run again, restore it
to a new destination with `--keep-pending-work`. This keeps the original queue and
job records active. Review the pending work in the restore report before starting
mining. The original backup is always preserved, so quarantined jobs can be
recovered by restoring it again to another new destination with this flag. A
stopped operator can also move the quarantined private queue back to its original
filename after reviewing it. Keep job approvals and their signed transactions
together; do not manually merge job journals. Existing quarantine files are preserved; subsequent copies get a numbered
filename suffix. Restore refuses conflicting quarantined job IDs rather than
replacing them.

## Wallet discovery without historical blocks

Seed restore is available on pruned nodes and marks the wallet incomplete.
Status reports scan invalidation; balance and box reads return the recovery error
until verified discovery publishes. Restore/unlock the wallet and derive
every address you want to track, then stop the node:

```sh
ergo-node wallet-scan-utxo /srv/ergo
# If the chain tip or tracked key set changed since an interrupted scan:
ergo-node wallet-scan-utxo /srv/ergo --restart
```

This rebuilds owned P2PK holdings and canonical mainnet mining rewards using
the current UTXO state. It needs no archived blocks and no unlocked secrets;
persisted tracked public keys are sufficient. It works after snapshot bootstrap
and with block pruning enabled. It requires a UTXO backend. Custom scan
registries currently require the existing historical rescan; discovery refuses
to advance their cursor with incomplete coverage. Discovery also refuses while
any non-terminal wallet mining jobs exist: finish or cancel them first. Their
deadline fallback needs wallet transaction history, which discovery replaces.
Pinned input reservations live in the job journal and are not stored in the box
or transaction rows discovery rebuilds.

The scan saves durable checkpoints every 1,024 boxes or 8 MiB of staged matched
bytes. Interrupting it leaves the visible wallet unchanged. Rerunning verifies
the entire root and resumes staging at the checkpoint; changed tips/keys require
`--restart`. Publication replaces wallet holdings/history and sets the wallet
cursor to the anchor in one transaction only after full verification.

Current UTXOs cannot reconstruct historical transactions, already-spent boxes,
or their inclusion heights. Discovery records `historyComplete: false`; native
wallet status includes `discovery.anchorHeight` and `anchorHeaderId`, plus the
persisted `coveredPubkeys` and any `uncoveredPubkeys` added later. Adding keys
requires discovery again before balances and boxes are available; older coverage
records without a key set also require discovery again. Native box
summaries expose `inclusionHeightKnown: false`; their `creationHeight` is the
first-observed height. Legacy wallet and reserved scan entries return null inclusion height and
confirmation count for discovered boxes, and skip those filters when inclusion
is unknown.
The original serialized box retains its script creation height; reward maturity
uses that script height plus the canonical 720-block delay. Ordinary live wallet
apply/rollback continues after restart. A reorg below the anchor invalidates the
wallet rather than reporting incomplete balances. Run discovery again at the
new tip. A full historical rescan (`fromHeight=0`) on an archive node replaces
this coverage with normal history; partial historical rescans are rejected for
discovered wallets.

These commands change wallet/operator storage only. They do not change
transaction validation, block validity, fork choice, state commitments, or
network consensus rules.
