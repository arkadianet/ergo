//! Phase-2 item 5 — embedded-vs-daemon **shadow harness**.
//!
//! # What this compares
//!
//! The node embeds the wallet: its `StateStore` redb holds the wallet tables
//! and the chain-apply seam writes them inside the *same* redb write
//! transaction as the UTXO mutation. Phase 2 extracted that wallet core into
//! `ergo-wallet-service`, so the standalone daemon runs the *same* service
//! code against its *own* redb, fed by blocks it pulls from the node's
//! `/api/v1/chain/*` HTTP surface. Two code paths, one source of truth.
//!
//! This module proves they agree. It builds the same chain twice over the
//! same block bytes and then compares the **normalized `WalletRead` state** of
//! the two `WalletStore`s field by field. It deliberately does *not* compare
//! daemon DTOs: `/balance`'s `reserved == "0"` and `/status`'s cached tip are
//! documented projections (see `docs/codemap/ergo-walletd.md` §"Known
//! deviations"), so comparing them would report differences that are not
//! divergences. What *is* comparable is the persisted wallet state, because
//! both sides write it through the same `ergo-wallet-service` functions.
//!
//! # The two paths
//!
//! **Embedded** — a real `ergo_state::store::StateStore` in a temp dir, seeded
//! with the real mainnet genesis boxes, advanced by the **production**
//! `StateStore::apply_block` with a real `CheckedBlock` and the real
//! production `WalletApplyHook` (`ergo_node::node::wallet_bridge::WalletStateHook`,
//! hydrated from the store's own `WALLET_TRACKED_PUBKEYS`). The wallet apply
//! lands inside `apply_block`'s own redb write transaction, so the wallet and
//! chain state commit or fail together. Rollback uses the real
//! `StateStore::rollback_to` with the real `RescanGuard`.
//!
//! **Daemon** — a real `RedbWalletStore::open_standalone` in a temp dir,
//! advanced by the real `StandaloneSyncer` over the real
//! `chain_http::HttpChainClient` against the real `ergo-api` chain router
//! (real `ApiSecurity` `api_key` gate, real `Governor`) backed by the
//! **embedded** `StateStore` through ergo-node's real `InProcessChainClient` +
//! `WalletChainAdapter` — the same stack `tests/it/node_api.rs` proves, with
//! one deliberate addition: the make-service installs
//! `ConnectInfo<SocketAddr>`, as `ergo_api::server` does, so the governor can
//! read the peer IP and exempt a loopback daemon. A shadow sweep makes
//! thousands of `blocks-since` calls, and without `ConnectInfo` the governor
//! buckets every caller under one shared "unknown" key and throttles the sweep
//! into a 429 loop that has nothing to do with wallet behaviour. See
//! [`serve_shadow_node_api`].
//!
//! # Why `validate_transaction_parsed`
//!
//! `StateStore::apply_block` takes a `CheckedBlock`, and `CheckedTransaction`
//! has no public constructor — only `validate_transaction` /
//! `validate_transaction_parsed` build one. The harness therefore runs the
//! real `validate_transaction_parsed` with `skip_scripts = true` per
//! transaction (input boxes are resolved from the store's committed UTXO) and
//! assembles the block with the `test-helpers`-gated `CheckedBlock::from_parts`
//! escape hatch, which ergo-validation documents for exactly this. Every
//! *other* check — structural limits, group-element on-curve, canonical
//! encoding, monetary conservation, output-height rules, and the state root
//! the apply asserts against — still runs for real, so the harness cannot
//! smuggle an illegal block past consensus-shaped gates. Only script
//! evaluation is skipped; no wallet-visible field depends on it.
//!
//! This is also why `ergo-validation` is a `[dev-dependencies]` entry: the
//! alternative, `apply_block_unchecked_with_wallet_for_test`, hard-codes
//! `block_txs_owned: Vec::new()` and therefore tracks **no boxes at all**,
//! which would make the box/balance/transaction comparison vacuous.
//!
//! # Cost
//!
//! The expensive tests are `#[ignore]`d so `cargo nextest run --workspace`
//! (the default CI job) never pays for them. Run them with
//! `scripts/shadow-compare.sh` or the dedicated `wallet-shadow` CI job.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::block_transactions::{write_block_transactions, BlockTransactions};
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::header::{read_header, serialize_header, Header};
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::transaction::{read_transaction, transaction_id, write_transaction, Transaction};
use ergo_state::store::StateStore;
use ergo_validation::block::CheckedBlock;
use ergo_validation::context::{ProtocolParams, TransactionContext};
use ergo_validation::header::CheckedHeader;
use ergo_validation::tx::{validate_transaction_parsed, TxValidationCtx, TxValidationRules};
use ergo_validation::CostAccumulator;
use ergo_wallet_service::scan::{ScanRequest, WalletInteraction};
use ergo_wallet_service::{
    BoxProvenance, BoxStatus, RedbWalletStore, RewardKeyResolution, ScanBoxStatus,
    TrackedPubkeyMeta, WalletRead, WalletScanCursor, WalletState, WalletStore,
};

use ergo_walletd::chain_http::HttpChainClient;
use ergo_walletd::config::ApiKey;
use ergo_walletd::sync::{StandaloneSyncer, SyncConfig};
use ergo_walletd::tip::CachedNodeTip;

use crate::node_api::NODE_API_KEY;

/// One non-default, non-weak node API key. Reuses `node_api.rs`'s so the
/// `ApiSecurity` gate is the real one in both modules.
const API_KEY: &[u8] = NODE_API_KEY;

// =========================================================================
// 1. NormalizedSnapshot
// =========================================================================

/// A canonical, order-independent projection of everything `WalletRead` can
/// see that the two paths are expected to agree on.
///
/// Every collection is sorted by a total order before capture, so a diff can
/// only ever mean "a value differs", never "iteration order differs".
/// redb hands rows back in key order, but the *values* here (assets, scans,
/// `wallet_outputs`, `scan_ids`, derivation paths) are `Vec`s whose order is
/// an implementation detail of whichever apply path built them; sorting is
/// what makes the comparison a statement about content.
#[derive(Clone, Debug)]
struct NormalizedSnapshot {
    label: &'static str,
    /// `scan_cursor()` rendered as `height` + `header_id`, so a cursor that
    /// advances to the right height with the wrong identity is caught.
    cursor: Option<(u32, Option<[u8; 32]>)>,
    /// `committed_tip()` as `height` + `header_id`. On the embedded side this
    /// is the node's `chain_state`; standalone it falls back to the durable
    /// cursor. Both must name the same block at a comparison point.
    committed_tip: Option<(u32, [u8; 32])>,
    balance: BalanceSnapshot,
    /// `all_boxes()`, sorted by box id, with status rendered as a string so
    /// maturity (`Immature { matures_at }`) and spend attribution are
    /// compared, not just the discriminant.
    boxes: Vec<BoxSnapshot>,
    /// `unspent_boxes()` sorted by box id. Compared separately from
    /// `all_boxes` so "the boxes agree but the confirmed/unspent *filter*
    /// disagrees" is a distinguishable failure.
    unspent: Vec<[u8; 32]>,
    /// `all_transactions()` sorted by `(block_height, tx_id)`.
    transactions: Vec<TxSnapshot>,
    registry: RegistrySnapshot,
    /// Present only when the harness seeded a registered scan; `None` means
    /// "not seeded", which is not a comparison result.
    scans: Option<ScanSnapshot>,
    /// `tracked_addresses_with_meta()`, sorted by `path_idx`.
    tracked: Vec<TrackedSnapshot>,
    /// `visible_pubkeys()`, sorted by visible index.
    visible: Vec<(u32, [u8; 33])>,
    /// `derivation_head()`.
    derivation_head: u64,
    /// `change_address_pubkey()`.
    change_address: Option<[u8; 33]>,
    /// `scan_invalidated()`. Both paths must end a completed run un-invalidated.
    scan_invalidated: bool,
    /// `resolve_reward_key()` — the EIP-3 reward-key outcome, including the
    /// `Pending` / `Corrupt` discrimination.
    reward_key: RewardSnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct BalanceSnapshot {
    confirmed_nano_ergs: u64,
    immature_nano_ergs: u64,
    /// `BTreeMap<[u8;32], u64>` is already totally ordered; wrapped so the
    /// field order in the diff is stable.
    tokens: Vec<([u8; 32], u64)>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct BoxSnapshot {
    box_id: [u8; 32],
    creation_tx_id: [u8; 32],
    creation_output_index: u16,
    creation_height: u32,
    value: u64,
    assets: Vec<([u8; 32], u64)>,
    /// `"confirmed"` | `"immature:<h>"` | `"spent:<tx>:<height>"`.
    status: String,
    /// `"owned"` | `"miner_reward"` | `"custom:<id>"`.
    provenance: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct TxSnapshot {
    block_height: u32,
    tx_id: [u8; 32],
    block_id: [u8; 32],
    wallet_outputs: Vec<[u8; 32]>,
    wallet_inputs: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct StoredScanSnapshot {
    id: u16,
    /// The persisted JSON, compared as decoded `serde_json::Value` so key
    /// order in the serialized registry row is not a difference. The rows
    /// under test are written by *both* sides from the same bytes, so a raw
    /// string compare would also pass; normalizing to a `Value` means the
    /// comparison survives a future serde field-order change.
    json: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RegistrySnapshot {
    scans: Vec<StoredScanSnapshot>,
    last_used_id: Option<u16>,
    /// `registered_scan_count()` — cheap per-block gate value, compared
    /// because the two apply paths gate scan work on it.
    count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ScanBoxSnapshot {
    scan_id: u16,
    box_id: [u8; 32],
    inclusion_height: u32,
    creation_out_index: u16,
    /// `blake2b256` of the stored `box_bytes`, not the bytes themselves: the
    /// bytes are ~300 B each and the digest is an exact identity check.
    box_bytes_digest: [u8; 32],
    box_bytes_len: usize,
    status: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ScanTxSnapshot {
    block_height: u32,
    tx_id: [u8; 32],
    block_id: [u8; 32],
    scan_ids: Vec<u16>,
    created: Vec<[u8; 32]>,
    spent: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ScanSnapshot {
    boxes: Vec<ScanBoxSnapshot>,
    transactions: Vec<ScanTxSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct TrackedSnapshot {
    path_idx: u64,
    pubkey: [u8; 33],
    derivation_path: Vec<u32>,
    label: String,
    added_at_height: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum RewardSnapshot {
    Ready([u8; 33]),
    Pending,
    Corrupt,
}

impl NormalizedSnapshot {
    /// Read every compared surface out of one `WalletRead` (one redb read
    /// transaction, so the snapshot is internally consistent).
    ///
    /// `scan_id` is `Some` only when the harness seeded a scan; the scan-box
    /// and scan-transaction tables are then compared for real.
    fn capture(label: &'static str, read: &dyn WalletRead, scan_id: Option<u16>) -> Self {
        let cursor = read
            .scan_cursor()
            .expect("scan cursor")
            .map(|WalletScanCursor { height, header_id }| (height, header_id));
        let committed_tip = read.committed_tip().expect("committed tip");
        let balance = read.balance().expect("balance");
        let boxes = read.all_boxes().expect("all boxes");
        let unspent = read.unspent_boxes().expect("unspent boxes");
        let transactions = read.all_transactions().expect("all transactions");
        let registry = read.scan_registry().expect("scan registry");
        let registered_scan_count = read.registered_scan_count().expect("scan count");
        let tracked = read
            .tracked_addresses_with_meta()
            .expect("tracked addresses");
        let visible = read.visible_pubkeys().expect("visible pubkeys");
        let derivation_head = read.derivation_head().expect("derivation head");
        let change_address = read.change_address_pubkey().expect("change address");
        let scan_invalidated = read.scan_invalidated().expect("scan invalidated");
        let reward_key = read.resolve_reward_key().expect("reward key");

        let mut boxes: Vec<BoxSnapshot> = boxes
            .into_iter()
            .map(|wallet_box| BoxSnapshot {
                box_id: wallet_box.box_id,
                creation_tx_id: wallet_box.creation_tx_id,
                creation_output_index: wallet_box.creation_output_index,
                creation_height: wallet_box.creation_height,
                value: wallet_box.value,
                assets: sorted_pairs(wallet_box.assets),
                status: status_text(&wallet_box.status),
                provenance: provenance_text(&wallet_box.provenance),
            })
            .collect();
        boxes.sort();
        let mut unspent: Vec<[u8; 32]> = unspent.iter().map(|b| b.box_id).collect();
        unspent.sort();
        let mut transactions: Vec<TxSnapshot> = transactions
            .into_iter()
            .map(|tx| TxSnapshot {
                block_height: tx.block_height,
                tx_id: tx.tx_id,
                block_id: tx.block_id,
                wallet_outputs: sorted_ids(tx.wallet_outputs),
                wallet_inputs: sorted_ids(tx.wallet_inputs),
            })
            .collect();
        transactions.sort();
        let mut registry_scans: Vec<StoredScanSnapshot> = registry
            .scans
            .into_iter()
            .map(|scan| StoredScanSnapshot {
                id: scan.id,
                json: canonical_json(&scan.json),
            })
            .collect();
        registry_scans.sort();
        let mut tracked: Vec<TrackedSnapshot> = tracked
            .into_iter()
            .map(|meta| TrackedSnapshot {
                path_idx: meta.path_idx,
                pubkey: meta.pubkey,
                derivation_path: meta.derivation_path,
                label: meta.label,
                added_at_height: meta.added_at_height,
            })
            .collect();
        tracked.sort();
        let mut visible = visible;
        visible.sort();

        let scans = scan_id.map(|scan_id| {
            let mut boxes: Vec<ScanBoxSnapshot> = read
                .scan_boxes(scan_id)
                .expect("scan boxes")
                .into_iter()
                .map(|scan_box| ScanBoxSnapshot {
                    scan_id: scan_box.scan_id,
                    box_id: scan_box.box_id,
                    inclusion_height: scan_box.inclusion_height,
                    creation_out_index: scan_box.creation_out_index,
                    box_bytes_digest: *ergo_primitives::digest::blake2b256(&scan_box.box_bytes)
                        .as_bytes(),
                    box_bytes_len: scan_box.box_bytes.len(),
                    status: scan_status_text(&scan_box.status),
                })
                .collect();
            boxes.sort();
            let mut transactions: Vec<ScanTxSnapshot> = read
                .scan_transactions(scan_id)
                .expect("scan transactions")
                .into_iter()
                .map(|record| ScanTxSnapshot {
                    block_height: record.block_height,
                    tx_id: record.tx_id,
                    block_id: record.block_id,
                    scan_ids: {
                        let mut ids = record.scan_ids;
                        ids.sort_unstable();
                        ids.dedup();
                        ids
                    },
                    created: sorted_ids(record.created),
                    spent: sorted_ids(record.spent),
                })
                .collect();
            transactions.sort();
            ScanSnapshot {
                boxes,
                transactions,
            }
        });

        Self {
            label,
            cursor,
            committed_tip,
            balance: BalanceSnapshot {
                confirmed_nano_ergs: balance.confirmed_nano_ergs,
                immature_nano_ergs: balance.immature_nano_ergs,
                tokens: balance.tokens.into_iter().collect(),
            },
            boxes,
            unspent,
            transactions,
            registry: RegistrySnapshot {
                scans: registry_scans,
                last_used_id: registry.last_used_id,
                count: registered_scan_count,
            },
            scans,
            tracked,
            visible,
            derivation_head,
            change_address,
            scan_invalidated,
            reward_key: match reward_key {
                RewardKeyResolution::Ready(pubkey) => RewardSnapshot::Ready(pubkey),
                RewardKeyResolution::Pending => RewardSnapshot::Pending,
                RewardKeyResolution::Corrupt => RewardSnapshot::Corrupt,
            },
        }
    }
}

fn sorted_pairs(pairs: Vec<([u8; 32], u64)>) -> Vec<([u8; 32], u64)> {
    let mut pairs = pairs;
    pairs.sort_unstable();
    pairs
}

fn sorted_ids(mut ids: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    ids.sort_unstable();
    ids
}

fn status_text(status: &BoxStatus) -> String {
    match status {
        BoxStatus::Confirmed => "confirmed".to_string(),
        BoxStatus::Immature { matures_at } => format!("immature:{matures_at}"),
        BoxStatus::Spent {
            spent_in_tx,
            spent_at,
        } => format!("spent:{}:{spent_at}", hex::encode(spent_in_tx)),
    }
}

fn provenance_text(provenance: &BoxProvenance) -> String {
    match provenance {
        BoxProvenance::Owned => "owned".to_string(),
        BoxProvenance::MinerReward => "miner_reward".to_string(),
        BoxProvenance::Custom { scan_id } => format!("custom:{scan_id}"),
    }
}

fn scan_status_text(status: &ScanBoxStatus) -> String {
    match status {
        ScanBoxStatus::Unspent => "unspent".to_string(),
        ScanBoxStatus::Spent {
            spent_in_tx,
            spent_at,
        } => format!("spent:{}:{spent_at}", hex::encode(spent_in_tx)),
    }
}

/// Re-serialize a stored scan row through `serde_json::Value` so a comparison
/// is on decoded content, not on byte-level key order.
fn canonical_json(bytes: &[u8]) -> String {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .unwrap_or_else(|error| panic!("stored scan row is not JSON: {error}"));
    serde_json::to_string(&value).expect("scan row re-serializes")
}

/// A single-line field-level difference, or `None` when the value is equal.
fn field_diff<T: PartialEq + std::fmt::Debug>(path: &str, left: &T, right: &T) -> Option<String> {
    if left == right {
        return None;
    }
    Some(format!("{path}: embedded={left:?} daemon={right:?}"))
}

/// Every field-level difference between two snapshots, in a fixed field
/// order, so a failure is reproducible and a passing run is reproducible too.
///
/// This is the whole oracle. A test that compares "did the balances happen to
/// match" would pass on a wallet that tracks nothing; this compares every
/// compared field and *names* the one that moved.
fn snapshot_diff(left: &NormalizedSnapshot, right: &NormalizedSnapshot) -> Vec<String> {
    let mut diff: Vec<String> = Vec::new();
    macro_rules! push {
        ($entry:expr) => {
            if let Some(entry) = $entry {
                diff.push(entry);
            }
        };
    }
    push!(field_diff("cursor", &left.cursor, &right.cursor));
    push!(field_diff(
        "committed_tip",
        &left.committed_tip,
        &right.committed_tip,
    ));
    push!(field_diff("balance", &left.balance, &right.balance));
    push!(collection_diff("boxes", &left.boxes, &right.boxes));
    push!(collection_diff("unspent", &left.unspent, &right.unspent));
    push!(collection_diff(
        "transactions",
        &left.transactions,
        &right.transactions,
    ));
    push!(field_diff("registry", &left.registry, &right.registry));
    match (&left.scans, &right.scans) {
        (Some(left), Some(right)) => {
            push!(collection_diff("scan_boxes", &left.boxes, &right.boxes));
            push!(collection_diff(
                "scan_transactions",
                &left.transactions,
                &right.transactions,
            ));
        }
        (None, None) => {}
        (left, right) => {
            diff.push(format!(
                "scan seeding: embedded={} daemon={}",
                left.is_some(),
                right.is_some()
            ));
        }
    }
    push!(collection_diff(
        "tracked_keys",
        &left.tracked,
        &right.tracked
    ));
    push!(field_diff("visible_keys", &left.visible, &right.visible));
    push!(field_diff(
        "derivation_head",
        &left.derivation_head,
        &right.derivation_head,
    ));
    push!(field_diff(
        "change_address",
        &left.change_address,
        &right.change_address,
    ));
    push!(field_diff(
        "scan_invalidated",
        &left.scan_invalidated,
        &right.scan_invalidated,
    ));
    push!(field_diff(
        "reward_key",
        &left.reward_key,
        &right.reward_key
    ));
    diff
}

/// Diff two sorted collections as per-element lines, so a one-box difference
/// in a 200-box sweep names the box instead of dumping both vectors.
fn collection_diff<T: PartialEq + std::fmt::Debug>(
    path: &str,
    left: &[T],
    right: &[T],
) -> Option<String> {
    if left == right {
        return None;
    }
    let mut lines = Vec::new();
    for (index, (left, right)) in left.iter().zip(right.iter()).enumerate() {
        if left != right {
            lines.push(format!(
                "{path}[{index}]: embedded={left:?} daemon={right:?}"
            ));
        }
    }
    let only_embedded = left.len().saturating_sub(right.len());
    let only_daemon = right.len().saturating_sub(left.len());
    if left.len() != right.len() {
        lines.push(format!(
            "{path}: length embedded={} daemon={} (only-embedded={only_embedded} \
             only-daemon={only_daemon})",
            left.len(),
            right.len()
        ));
    }
    if lines.is_empty() {
        lines.push(format!("{path}: embedded={left:?} daemon={right:?}"));
    }
    Some(lines.join("\n"))
}

/// The one assertion every shadow test funnels through.
///
/// Reports the full field-level diff (not just the first difference) plus the
/// evidence the harness needs to be worth anything at all: a run that compares
/// zero boxes is not a passing shadow comparison, it is a vacuous one, so a
/// non-zero `min_boxes` floor is asserted whenever the fixture is supposed to
/// produce wallet boxes.
fn assert_shadow_eq(
    context: &str,
    embedded: &NormalizedSnapshot,
    daemon: &NormalizedSnapshot,
    min_boxes: usize,
) {
    let diff = snapshot_diff(embedded, daemon);
    assert!(
        diff.is_empty(),
        "shadow divergence in {context}\n  embedded boxes={} transactions={} \
         balance={:?}\n  daemon   boxes={} transactions={} balance={:?}\n{}",
        embedded.boxes.len(),
        embedded.transactions.len(),
        embedded.balance,
        daemon.boxes.len(),
        daemon.transactions.len(),
        daemon.balance,
        diff.join("\n  ")
    );
    assert!(
        embedded.boxes.len() >= min_boxes,
        "{context} is vacuous: the {} wallet tracked {} boxes, the fixture \
         requires at least {min_boxes}. A shadow comparison that compares nothing \
         passes for the wrong reason.",
        embedded.label,
        embedded.boxes.len()
    );
}

// =========================================================================
// 2. Wallet seed: the tracked keys and the registered scan
// =========================================================================

/// The tracked ("watched") secp256k1 key of the **synthetic** chain, which pays
/// it directly in every block.
///
/// A valid SEC1 compressed point (`0x02` prefix, and `x` satisfies
/// `y² = x³ + 7` with `y` of the right parity), so the synthetic outputs and
/// the miner-reward wrapper the wallet recognizes are real shapes rather than
/// bytes no curve could produce. It is the harness's own key: it is *not*
/// lifted from `test-vectors/mining/reward_boxes/*.json`, so nothing here
/// claims a miner ever used it. Real miner keys are the sweep's business, and
/// the sweep does not use this constant — it watches
/// [`MainnetFixture::reward_pubkey`], a key read out of a real captured reward
/// output in blocks 1..=10.
const TRACKED_PUBKEY: [u8; 33] = [
    0x02, 0x74, 0xe7, 0x29, 0xbb, 0x66, 0x15, 0xcb, 0xda, 0x94, 0xd9, 0xd1, 0x76, 0xa2, 0xf1, 0x52,
    0x50, 0x68, 0xf1, 0x2b, 0x33, 0x0e, 0x38, 0xbb, 0xbf, 0x38, 0x72, 0x32, 0x79, 0x7d, 0xf8, 0x91,
    0xf1,
];

/// A second tracked key that never appears in either chain. Seeded so the
/// tracked/visible/reward-key comparison covers keys that produce no boxes
/// (a wallet that dropped them would otherwise look identical).
const UNUSED_PUBKEY: [u8; 33] = [
    0x03, 0x39, 0xa3, 0x60, 0x13, 0x30, 0x15, 0x97, 0xda, 0xef, 0x41, 0xfb, 0xe5, 0x93, 0xa0, 0x2c,
    0xc5, 0x13, 0xd0, 0xb5, 0x55, 0x27, 0xec, 0x2d, 0xf1, 0x05, 0x0e, 0x2e, 0x8f, 0xf4, 0x9c, 0x85,
    0xc2,
];

/// A third key paid by the synthetic chain but never tracked, so its boxes must
/// be ignored by BOTH apply paths (a box the wallet should not have). A valid
/// SEC1 compressed point, because a key no curve could produce would make the
/// fixture a weaker test than it looks — the "ignore an untracked output"
/// branch is supposed to be about *tracking*, not about an impossible box. It
/// is the harness's own key, not a published address: nothing here claims an
/// owner.
const UNTRACKED_PUBKEY: [u8; 33] = [
    0x03, 0xd2, 0x98, 0xeb, 0xf8, 0x68, 0x36, 0x5f, 0x66, 0x2b, 0xf7, 0x5d, 0xff, 0x69, 0xda, 0x0b,
    0xb2, 0x2e, 0xe7, 0x43, 0xa4, 0x25, 0x61, 0xae, 0x9a, 0xe9, 0x51, 0x64, 0xf3, 0xff, 0x6a, 0x08,
    0x46,
];

/// EIP-3 first-address path with the hardened bits set — the exact path the
/// reward-key resolver matches, so the seed must contain a row at it for
/// `resolve_reward_key` to reach `Ready` on both sides.
const EIP3_FIRST_ADDRESS_PATH: [u32; 5] = [44 | 0x8000_0000, 429 | 0x8000_0000, 0x8000_0000, 0, 0];

/// The synthetic chain's single circulating token id. Also the tracking rule of
/// the seeded scan, so scan-box/scan-transaction rows are non-empty on both
/// sides.
const TOKEN_ID: [u8; 32] = [0x11; 32];

/// Scan id used for the seeded registry row. `9` (mining) and `10`
/// (payments) are reserved by the service, so a user scan starts above them.
const SCAN_ID: u16 = 11;

/// The three tracked-pubkey rows both stores are seeded with, in
/// `derivation_path_index` order.
///
/// `0` is the auto-derived master (empty path — the shape
/// `rebuild_visible_addresses` filters on); `1` is the EIP-3 first address,
/// which is what the reward-key resolver must select; `2` is a plain derived
/// key. Identical bytes on both sides, so any difference in
/// `tracked_addresses_with_meta` is a real divergence.
/// One seeded `WALLET_TRACKED_PUBKEYS` row: `(path_idx, pubkey, derivation
/// path, label, added_at_height)`. Aliased because the same five fields are
/// written into both stores and a bare tuple type is unreadable at the call
/// site.
type TrackedRow = (u64, [u8; 33], Vec<u32>, &'static str, u32);

fn tracked_rows(watched: [u8; 33]) -> Vec<TrackedRow> {
    vec![
        (0, UNUSED_PUBKEY, Vec::new(), "master", 0),
        (1, watched, EIP3_FIRST_ADDRESS_PATH.to_vec(), "", 0),
        (
            2,
            watched,
            vec![44 | 0x8000_0000, 429 | 0x8000_0000, 0x8000_0000, 0, 1],
            "change",
            0,
        ),
    ]
}

/// The one registered scan both stores are seeded with: "any box carrying
/// `TOKEN_ID`". The synthetic chain mints a token box every block, so scan
/// boxes, scan spends, and scan transactions are all exercised.
fn seeded_scan() -> Vec<u8> {
    let scan = ScanRequest {
        scan_name: "shadow-asset".to_string(),
        tracking_rule: ergo_wallet_service::scan::predicate::ScanningPredicate::ContainsAsset {
            asset_id: TOKEN_ID,
        },
        wallet_interaction: Some(WalletInteraction::Shared),
        remove_offchain: Some(true),
    }
    .into_scan(SCAN_ID);
    serde_json::to_vec(&scan).expect("the seeded scan serializes")
}

// =========================================================================
// 3. Chain fixtures
// =========================================================================

/// Canonical mainnet miner-reward ErgoTree layout, byte-for-byte the shape
/// `ergo_wallet::proving::miner_reward::extract_miner_reward_pubkey` matches
/// (7-byte prefix, 33-byte compressed pubkey, 14-byte body) and the shape
/// `test-vectors/mining/reward_boxes/*.json` all carry. Rebuilding it with a
/// chosen key is how the synthetic chain produces a real `Immature` reward
/// box without needing a real miner.
const REWARD_TREE_PREFIX: [u8; 7] = [0x10, 0x02, 0x04, 0xa0, 0x0b, 0x08, 0xcd];
const REWARD_TREE_SUFFIX: [u8; 14] = [
    0xea, 0x02, 0xd1, 0x92, 0xa3, 0x9a, 0x8c, 0xc7, 0xa7, 0x01, 0x73, 0x00, 0x73, 0x01,
];

fn reward_tree_bytes(pubkey: &[u8; 33]) -> Vec<u8> {
    let mut bytes = REWARD_TREE_PREFIX.to_vec();
    bytes.extend_from_slice(pubkey);
    bytes.extend_from_slice(&REWARD_TREE_SUFFIX);
    bytes
}

/// ErgoTree value for raw tree bytes. Round-tripped through
/// `ErgoBoxCandidate` and asserted byte-identical wherever it is used, so a
/// hand-built tree can never silently disagree with the bytes the wallet
/// classifies against `tracked_p2pk_trees`.
fn tree_of(raw: &[u8]) -> ergo_ser::ergo_tree::ErgoTree {
    ergo_ser::ergo_tree::read_ergo_tree(&mut VlqReader::new(raw))
        .unwrap_or_else(|error| panic!("ErgoTree parse failed: {error}"))
}

fn candidate_with_raw_tree(
    value: u64,
    raw_tree: &[u8],
    creation_height: u32,
    tokens: Vec<ergo_ser::token::Token>,
) -> ErgoBoxCandidate {
    let candidate = ErgoBoxCandidate::new(
        value,
        tree_of(raw_tree),
        creation_height,
        tokens,
        AdditionalRegisters::empty(),
    )
    .expect("valid ErgoBoxCandidate");
    assert_eq!(
        candidate.ergo_tree_bytes(),
        raw_tree,
        "the ErgoTree must round-trip byte-exactly: the wallet classifies boxes by \
         raw tree bytes, so a re-serialized tree that differs would be a fixture lie"
    );
    candidate
}

fn p2pk_candidate(
    pubkey: &[u8; 33],
    value: u64,
    creation_height: u32,
    tokens: Vec<ergo_ser::token::Token>,
) -> ErgoBoxCandidate {
    let raw = ergo_ser::address::build_p2pk_tree_bytes(pubkey)
        .unwrap_or_else(|error| panic!("P2PK tree build failed for key: {error:?}"));
    candidate_with_raw_tree(value, &raw, creation_height, tokens)
}

/// A block's wire form, shared by both apply paths.
struct BlockFixture {
    height: u32,
    header: Header,
    header_bytes: Vec<u8>,
    header_id: [u8; 32],
    txs: Vec<Transaction>,
    tx_bytes: Vec<Vec<u8>>,
}

impl BlockFixture {
    /// Persist the header and the `BlockTransactions` section, which is what
    /// ergo-node's `InProcessChainClient` reads to serve `blocks-since`. The
    /// section id is `compute_section_id(TYPE_BLOCK_TRANSACTIONS, header_id,
    /// header.transactions_root)`, computed the same way the client computes
    /// it, so the lookup is an identity rather than a coincidence.
    fn persist_sections(&self, store: &mut StateStore) {
        store
            .store_header(&self.header_id, &self.header_bytes)
            .unwrap();
        let mut writer = VlqWriter::new();
        write_block_transactions(
            &mut writer,
            &BlockTransactions {
                header_id: ModifierId::from_bytes(self.header_id),
                transactions: self.txs.clone(),
            },
        )
        .expect("BlockTransactions serialize");
        let section_id = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            &self.header_id,
            self.header.transactions_root.as_bytes(),
        );
        store
            .store_block_section(&section_id, &writer.result())
            .unwrap();
    }
}

/// Where the harness's blocks come from.
enum ChainPlan {
    /// Real mainnet blocks 1..=`blocks`, from `test-vectors`. Headers (and
    /// therefore block ids and state roots) are the real captured ones, so the
    /// embedded apply's state-root assertion is a real oracle.
    Mainnet { blocks: u32 },
    /// A deterministic synthetic chain of `blocks` blocks derived from a
    /// purpose-built genesis box. Its headers are computed during apply (see
    /// [`EmbeddedSide::prepare`]) because `StateStore::apply_block` asserts the
    /// true post-apply state root.
    Synthetic { blocks: u32 },
}

impl ChainPlan {
    /// The number of blocks the fixture provides. The harness may stop short
    /// of it (a reorg scenario stops at the tip it forks from), so this is an
    /// upper bound, not a target.
    fn blocks(&self) -> u32 {
        match self {
            Self::Mainnet { blocks } | Self::Synthetic { blocks } => *blocks,
        }
    }
}

/// Real mainnet fixture files, loaded once per test.
///
/// `test-vectors/` is repo-relative; integration tests run with the package
/// root as the working directory, which is the same convention the
/// `ergo-state` fixtures use.
struct MainnetFixture {
    headers: Vec<serde_json::Value>,
    txs: Vec<serde_json::Value>,
    genesis: Vec<([u8; 32], Vec<u8>)>,
}

impl MainnetFixture {
    fn load() -> Self {
        let read = |path: &str| {
            std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"))
        };
        let headers: Vec<serde_json::Value> =
            serde_json::from_str(&read("../test-vectors/mainnet/headers_1_2000.json"))
                .expect("headers_1_2000.json parses");
        let txs: Vec<serde_json::Value> =
            serde_json::from_str(&read("../test-vectors/mainnet/transactions_1_1000.json"))
                .expect("transactions_1_1000.json parses");
        let genesis: Vec<serde_json::Value> =
            serde_json::from_str(&read("../test-vectors/mainnet/genesis_boxes.json"))
                .expect("genesis_boxes.json parses");
        let genesis = genesis.iter().map(parse_genesis_box).collect();
        Self {
            headers,
            txs,
            genesis,
        }
    }

    fn block(&self, height: u32) -> BlockFixture {
        let header_json = self
            .headers
            .iter()
            .find(|entry| entry["height"].as_u64() == Some(height as u64))
            .unwrap_or_else(|| panic!("no captured header at height {height}"));
        let header_bytes = hex::decode(header_json["bytes"].as_str().expect("header bytes hex"))
            .expect("header bytes decode");
        let header_id: [u8; 32] = hex::decode(header_json["id"].as_str().expect("header id hex"))
            .expect("header id decode")
            .try_into()
            .expect("header id is 32 bytes");
        let header = read_header(&mut VlqReader::new(&header_bytes)).expect("header parses");
        let tx_json = self
            .txs
            .iter()
            .find(|entry| entry["height"].as_u64() == Some(height as u64))
            .unwrap_or_else(|| panic!("no captured transaction at height {height}"));
        let tx_bytes =
            hex::decode(tx_json["bytes"].as_str().expect("tx bytes hex")).expect("tx bytes decode");
        let txs = vec![read_transaction(&mut VlqReader::new(&tx_bytes)).expect("tx parses")];
        BlockFixture {
            height,
            header,
            header_bytes,
            header_id,
            txs,
            tx_bytes: vec![tx_bytes],
        }
    }

    /// A key a captured block in the sweep range genuinely pays, so the sweep
    /// tracks real boxes instead of nothing.
    ///
    /// Read out of the block data rather than the header: the wallet classifies
    /// a reward box only when
    /// `proving::miner_reward::extract_miner_reward_pubkey` recognizes the
    /// output's tree as the canonical mainnet reward wrapper, so the watched
    /// key is taken from exactly that output. Heights 1..=10 are scanned and
    /// the first recognizable reward output wins; the sweep asserts that at
    /// least one `Immature` box exists, so a fixture that stopped matching
    /// would fail loudly rather than compare two empty wallets.
    fn reward_pubkey(&self) -> [u8; 33] {
        for height in 1..=10u32 {
            for tx in self.block(height).txs {
                for output in &tx.output_candidates {
                    if let Some(pubkey) =
                        ergo_wallet::proving::miner_reward::extract_miner_reward_pubkey(
                            output.ergo_tree_bytes(),
                        )
                    {
                        return pubkey;
                    }
                }
            }
        }
        panic!("no canonical miner-reward output in captured blocks 1..=10")
    }
}

fn parse_genesis_box(entry: &serde_json::Value) -> ([u8; 32], Vec<u8>) {
    let tree_bytes = hex::decode(entry["ergoTree"].as_str().expect("genesis tree hex"))
        .expect("genesis tree bytes");
    let mut registers = Vec::new();
    if let Some(map) = entry
        .get("additionalRegisters")
        .and_then(|value| value.as_object())
    {
        for (name, value) in map {
            let index: usize = name
                .trim_start_matches('R')
                .parse::<usize>()
                .expect("register name is R<number>")
                - 4;
            let raw = hex::decode(value.as_str().expect("register hex")).expect("register bytes");
            let mut reader = VlqReader::new(&raw);
            let (tpe, value) =
                ergo_ser::sigma_value::read_constant(&mut reader).expect("register constant");
            registers.push((index, ergo_ser::register::RegisterValue { tpe, value }));
        }
    }
    registers.sort_by_key(|(index, _)| *index);
    let candidate = ErgoBoxCandidate::new(
        entry["value"].as_u64().expect("genesis value"),
        tree_of(&tree_bytes),
        entry["creationHeight"].as_u64().expect("genesis height") as u32,
        Vec::new(),
        AdditionalRegisters {
            registers: registers.into_iter().map(|(_, value)| value).collect(),
        },
    )
    .expect("genesis candidate");
    let ergo_box = ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes(
            hex::decode(entry["transactionId"].as_str().expect("genesis tx id hex"))
                .expect("genesis tx id bytes")
                .try_into()
                .expect("genesis tx id is 32 bytes"),
        ),
        index: entry["index"].as_u64().expect("genesis index") as u16,
    };
    let box_id = *ergo_box.box_id().expect("genesis box id").as_bytes();
    (
        box_id,
        serialize_ergo_box(&ergo_box).expect("genesis box serializes"),
    )
}

/// Value of the synthetic chain's genesis box and the halving schedule that
/// keeps every block's outputs summing exactly to its inputs.
///
/// Strict ERG conservation (`monetary::check_erg_conservation`) means a
/// synthetic block cannot mint, so the value has to be carried and then
/// split. The split is `carry = total/4`, `reward = total/4`,
/// `untracked = total/8`, `token = total/8`, and the next block spends
/// `carry + untracked + token = total/2`, so the total halves every block.
/// Starting at a power of two keeps every division exact for the depths the
/// synthetic scenarios use (a 64-block chain is `2^58` down to `2^35`).
const SYNTHETIC_GENESIS_VALUE: u64 = 1u64 << 58;

/// Synthetic-chain bookkeeping that must survive across applies inside
/// `EmbeddedSide`: which boxes the next block spends, and the parent header id.
#[derive(Clone)]
struct SyntheticCursor {
    inputs: Vec<[u8; 32]>,
    parent: [u8; 32],
    total: u64,
}

impl SyntheticCursor {
    fn genesis(genesis_box_id: [u8; 32]) -> Self {
        Self {
            inputs: vec![genesis_box_id],
            parent: [0; 32],
            total: SYNTHETIC_GENESIS_VALUE,
        }
    }

    /// The one transaction block `height` carries. Four outputs, chosen to hit
    /// every wallet classification branch:
    /// 0. P2PK to the tracked key — `Owned` / `Confirmed`, spent next block;
    /// 1. the canonical miner-reward tree to the tracked key — `MinerReward` /
    ///    `Immature { matures_at }`, never spent, so maturity is observable;
    /// 2. P2PK to an untracked key — must be ignored by both paths;
    /// 3. P2PK to the tracked key carrying `TOKEN_ID` — the `assets` path and
    ///    the seeded scan's match.
    fn block_tx(&mut self, height: u32) -> (Transaction, Vec<u8>) {
        let total = self.total;
        let carry = total / 4;
        let reward = total / 4;
        let untracked = total / 8;
        let token = total - carry - reward - untracked;
        let outputs = vec![
            p2pk_candidate(&TRACKED_PUBKEY, carry, height, Vec::new()),
            candidate_with_raw_tree(
                reward,
                &reward_tree_bytes(&TRACKED_PUBKEY),
                height,
                Vec::new(),
            ),
            p2pk_candidate(&UNTRACKED_PUBKEY, untracked, height, Vec::new()),
            p2pk_candidate(
                &TRACKED_PUBKEY,
                token,
                height,
                vec![ergo_ser::token::Token {
                    token_id: ergo_ser::token::TokenId::from_bytes(TOKEN_ID),
                    amount: 7,
                }],
            ),
        ];
        let tx = Transaction {
            inputs: self
                .inputs
                .iter()
                .map(|box_id| ergo_ser::input::Input {
                    box_id: Digest32::from_bytes(*box_id),
                    spending_proof: ergo_ser::input::SpendingProof::new(
                        Vec::new(),
                        ergo_ser::input::ContextExtension::empty(),
                    )
                    .expect("valid spending proof"),
                })
                .collect(),
            data_inputs: Vec::new(),
            output_candidates: outputs,
        };
        let mut writer = VlqWriter::new();
        write_transaction(&mut writer, &tx).expect("synthetic transaction serializes");
        let bytes = writer.result();
        // Advance the cursor: the next block spends outputs 0, 2 and 3.
        let transaction_id = ModifierId::from_bytes(
            *transaction_id(&tx)
                .expect("synthetic transaction id")
                .as_bytes(),
        );
        self.inputs = [0usize, 2, 3]
            .iter()
            .map(|index| {
                *ErgoBox {
                    candidate: tx.output_candidates[*index].clone(),
                    transaction_id,
                    index: *index as u16,
                }
                .box_id()
                .expect("synthetic output box id")
                .as_bytes()
            })
            .collect();
        self.total = carry + untracked + token;
        (tx, bytes)
    }
}

// =========================================================================
// 4. The embedded side: real StateStore + real production WalletApplyHook
// =========================================================================

/// A block's wire form plus the `CheckedTransaction`s the production
/// `apply_block` consumes, so the dry run that computes the state root and the
/// apply that asserts it are driven by the *same* validated values.
struct PreparedBlock {
    fixture: BlockFixture,
    checked: Vec<ergo_validation::CheckedTransaction>,
}

/// Every live handle onto the node's redb.
///
/// Grouped because a node restart has to drop *all* of them at once: a
/// `RedbWalletStore` clone shares the store's `Arc<Database>` rather than
/// opening the file again, and redb refuses a second open of a file that is
/// still open anywhere in the process (`DatabaseAlreadyOpen`).
struct EmbeddedFiles {
    store: StateStore,
    /// The node's wallet store: a `RedbWalletStore` over the **same** redb, so
    /// seeding tracked keys and the scan registry writes exactly the tables the
    /// node writes, and `WalletRead` reads the rows the node itself reads.
    wallet_store: Arc<RedbWalletStore>,
    hook: ergo_node::node::wallet_bridge::WalletStateHook,
}

/// The embedded wallet: a real `StateStore` whose redb *is* the wallet
/// database, advanced by the production `StateStore::apply_block` with the
/// production `WalletApplyHook`.
///
/// The hook is ergo-node's own `WalletStateHook` — not a test double — so
/// `tracked_p2pk_trees`, `cached_pubkeys`, `registered_scan_count` and
/// `match_boxes` are the production implementations, including the per-block
/// scan-count gate and the scan registry load from the store.
struct EmbeddedSide {
    path: std::path::PathBuf,
    /// `None` only inside [`EmbeddedSide::restart`], between the drop and the
    /// re-open.
    files: Option<EmbeddedFiles>,
    plan: ChainPlan,
    mainnet: Option<MainnetFixture>,
    synthetic: Option<SyntheticCursor>,
    /// The synthetic cursor's state as of the end of each applied height, so a
    /// rollback can restore it and re-derive the replacement fork from the
    /// ancestor's real inputs. A reorg replays the *same* transactions under
    /// new block ids, so the cursor has to be rewound with the chain.
    synthetic_history: std::collections::BTreeMap<u32, SyntheticCursor>,
}

impl EmbeddedSide {
    fn open(path: &Path, plan: ChainPlan) -> Self {
        // A fenced wallet apply would silently make this side track nothing.
        // Nothing on the daemon path fences, but a previous test in this binary
        // tripping the embedded continuity guard would, and a vacuous
        // comparison is worse than a loud failure.
        assert!(
            !ergo_wallet_service::wallet::wallet_apply_fenced(),
            "the process-wide wallet-apply fence is set before the shadow harness \
             started; a fenced hook would report zero boxes and every shadow \
             assertion would pass for the wrong reason"
        );
        let mainnet = match &plan {
            ChainPlan::Mainnet { .. } => Some(MainnetFixture::load()),
            ChainPlan::Synthetic { .. } => None,
        };
        let mut store = StateStore::open(path).expect("embedded StateStore opens");
        let genesis: Vec<([u8; 32], Vec<u8>)> = match &mainnet {
            Some(fixture) => fixture.genesis.clone(),
            None => synthetic_genesis(),
        };
        store
            .initialize_genesis(&genesis)
            .expect("genesis initializes");
        let wallet_store = Arc::new(RedbWalletStore::new(store.db_arc()));
        let hook = build_hook(&wallet_store);
        let synthetic = match mainnet {
            Some(_) => None,
            None => Some(SyntheticCursor::genesis(synthetic_genesis_box_id())),
        };
        Self {
            path: path.to_path_buf(),
            files: Some(EmbeddedFiles {
                store,
                wallet_store,
                hook,
            }),
            plan,
            mainnet,
            synthetic,
            synthetic_history: std::collections::BTreeMap::new(),
        }
    }

    fn files(&self) -> &EmbeddedFiles {
        self.files.as_ref().expect("the embedded files are open")
    }

    fn files_mut(&mut self) -> &mut EmbeddedFiles {
        self.files.as_mut().expect("the embedded files are open")
    }

    fn store(&self) -> &StateStore {
        &self.files().store
    }

    fn wallet_store(&self) -> &Arc<RedbWalletStore> {
        &self.files().wallet_store
    }

    /// The key the chain actually pays, which is therefore the key the wallet
    /// must watch for the box layer to be non-empty.
    ///
    /// Mainnet: a real miner-reward pubkey lifted out of a captured block's
    /// reward output, so the sweep tracks real `MinerReward` boxes. Synthetic:
    /// [`TRACKED_PUBKEY`], which the synthetic outputs pay directly.
    fn watched_pubkey(&self) -> [u8; 33] {
        match &self.mainnet {
            Some(fixture) => fixture.reward_pubkey(),
            None => TRACKED_PUBKEY,
        }
    }

    fn height(&self) -> u32 {
        self.files().store.height()
    }

    /// The UTXO root after every applied block. `root_digest` takes
    /// `&mut self` (it refreshes the store's in-memory digest cache), so the
    /// harness reads it through this accessor rather than reaching for the
    /// store.
    fn root_digest(&mut self) -> ADDigest {
        self.files_mut().store.root_digest()
    }

    /// A real node restart: every handle onto the redb is dropped and the store
    /// is re-opened from the file, then the hook is rebuilt from the reopened
    /// store's own tracked-pubkey table — the same hydration the node performs
    /// at boot.
    ///
    /// The caller must have torn down the node's `ChainStoreReader` first — it
    /// holds the same `Arc<Database>`, and redb refuses a second open of a file
    /// that is still open anywhere in the process.
    fn restart(&mut self) {
        let height_before = self.height();
        let files = self.files.take().expect("the embedded files are open");
        drop(files);
        let store = StateStore::open(&self.path).expect("embedded StateStore reopens");
        assert_eq!(
            store.height(),
            height_before,
            "a node restart must not move the chain height"
        );
        let wallet_store = Arc::new(RedbWalletStore::new(store.db_arc()));
        let hook = build_hook(&wallet_store);
        self.files = Some(EmbeddedFiles {
            store,
            wallet_store,
            hook,
        });
    }

    /// Seed the tracked-pubkey rows, the visible-address cache, the derivation
    /// head, and (optionally) the scan registry — through the real
    /// `WalletWrite` API, the same one the node's unlock/restore and
    /// `PUT /wallet/scan` paths use.
    fn seed(&mut self, watched: [u8; 33], scan: bool) {
        let mut write = self
            .files_mut()
            .wallet_store
            .begin_write()
            .expect("embedded seed write");
        for (index, pubkey, path, label, added_at) in tracked_rows(watched) {
            write
                .insert_tracked_pubkey(
                    index,
                    pubkey,
                    &TrackedPubkeyMeta {
                        derivation_path: path,
                        derivation_path_label: label.to_string(),
                        added_at_height: added_at,
                    },
                )
                .expect("tracked pubkey insert");
        }
        write
            .rebuild_visible_addresses()
            .expect("visible addresses");
        write.set_derivation_head(3).expect("derivation head");
        if scan {
            write
                .put_scan(SCAN_ID, seeded_scan(), SCAN_ID)
                .expect("scan registry insert");
        }
        write.commit().expect("embedded seed commit");
        let files = self.files_mut();
        files.hook = build_hook(&files.wallet_store);
    }

    /// Apply block `height` through the production embedded seam.
    ///
    /// `nonce` selects the synthetic fork generation and is ignored for mainnet
    /// blocks, whose headers are the captured ones.
    fn apply(&mut self, height: u32, nonce: u8) {
        let prepared = self.prepare(height, nonce);
        prepared
            .fixture
            .persist_sections(&mut self.files_mut().store);
        let checked_header = CheckedHeader::from_persisted_parts(
            &prepared.fixture.header_bytes,
            prepared.fixture.header_id,
            1,
            prepared.fixture.height,
            *prepared.fixture.header.parent_id.as_bytes(),
            prepared.fixture.header.timestamp,
        )
        .expect("CheckedHeader rebuilds from the persisted header bytes");
        let block = CheckedBlock::from_parts(checked_header, prepared.checked);
        let files = self.files_mut();
        files
            .store
            .apply_block(&block, None, Some(&files.hook))
            .unwrap_or_else(|error| panic!("embedded apply at height {height} failed: {error}"));
        assert_eq!(
            files.store.height(),
            height,
            "chain height after the embedded apply"
        );
        if let Some(cursor) = &self.synthetic {
            self.synthetic_history.insert(height, cursor.clone());
        }
    }

    /// Build block `height`'s header, sections and `CheckedTransaction`s.
    ///
    /// Mainnet: the captured fixture, byte for byte. The state root is still
    /// recomputed with the real `candidate_dry_run` and asserted equal to the
    /// root in the captured header, so the harness is checked against a real
    /// oracle rather than only against itself.
    ///
    /// Synthetic: derived here, because `StateStore::apply_block` asserts the
    /// block's declared `state_root` against the *true* post-apply root. That
    /// root is a pure function of the block transactions — the emission
    /// transition classifies transactions but never mints a box — so the
    /// non-mutating `candidate_dry_run` (the same dry run the mining path uses
    /// to stamp a candidate header before the header exists) computes it
    /// before the header can be built. That is the whole reason the harness
    /// does not hand-roll synthetic header bytes.
    fn prepare(&mut self, height: u32, nonce: u8) -> PreparedBlock {
        let tx_bytes = match &self.plan {
            ChainPlan::Mainnet { .. } => {
                self.mainnet
                    .as_ref()
                    .expect("the mainnet plan carries its fixture")
                    .block(height)
                    .tx_bytes
            }
            ChainPlan::Synthetic { .. } => {
                let cursor = self
                    .synthetic
                    .as_mut()
                    .expect("the synthetic plan carries its cursor");
                let (_tx, bytes) = cursor.block_tx(height);
                vec![bytes]
            }
        };
        let parent = match &self.plan {
            ChainPlan::Mainnet { .. } => {
                let fixture = self
                    .mainnet
                    .as_ref()
                    .expect("the mainnet plan carries its fixture")
                    .block(height);
                *fixture.header.parent_id.as_bytes()
            }
            ChainPlan::Synthetic { .. } => {
                self.synthetic
                    .as_ref()
                    .expect("the synthetic plan carries its cursor")
                    .parent
            }
        };

        let reader = self.store().reader_handle();
        let mut parsed = Vec::new();
        for raw in &tx_bytes {
            let tx = read_transaction(&mut VlqReader::new(raw))
                .expect("the block's transaction bytes parse");
            let mut resolved = Vec::new();
            for input in &tx.inputs {
                let bytes = reader
                    .lookup_box(input.box_id.as_bytes())
                    .unwrap_or_else(|error| {
                        panic!("UTXO lookup at height {height} failed: {error}")
                    })
                    .unwrap_or_else(|| {
                        panic!(
                            "input {} of block {height} is not in the committed UTXO",
                            hex::encode(input.box_id.as_bytes())
                        )
                    });
                let mut box_reader = VlqReader::new(&bytes);
                resolved.push(
                    ergo_ser::ergo_box::read_ergo_box(&mut box_reader)
                        .expect("committed UTXO box parses"),
                );
            }
            parsed.push((tx, resolved));
        }

        // Validation context. Every field the checks read comes from the block
        // being applied, so a rule failure here is a real rule failure.
        let (version, timestamp, n_bits, votes): (u8, u64, u32, [u8; 3]) = match &self.plan {
            ChainPlan::Mainnet { .. } => {
                let fixture = self
                    .mainnet
                    .as_ref()
                    .expect("the mainnet plan carries its fixture")
                    .block(height);
                (
                    fixture.header.version,
                    fixture.header.timestamp,
                    fixture.header.n_bits,
                    fixture.header.votes,
                )
            }
            ChainPlan::Synthetic { .. } => (2, 1_000_000 + height as u64, 16842752, [0; 3]),
        };
        let context = TransactionContext {
            height,
            miner_pubkey: match &self.plan {
                ChainPlan::Mainnet { .. } => *self
                    .mainnet
                    .as_ref()
                    .expect("the mainnet plan carries its fixture")
                    .block(height)
                    .header
                    .solution
                    .pk()
                    .as_bytes(),
                ChainPlan::Synthetic { .. } => [2; 33],
            },
            pre_header_timestamp: timestamp,
            activated_script_version: version.saturating_sub(1),
            pre_header_version: version,
            pre_header_parent_id: parent,
            pre_header_n_bits: u64::from(n_bits),
            pre_header_votes: votes,
        };
        let params = ProtocolParams::mainnet_default();
        let mut checked = Vec::new();
        for (index, (tx, resolved)) in parsed.iter().enumerate() {
            let mut cost = CostAccumulator::new(
                ergo_primitives::cost::JitCost::from_block_cost(1_000_000)
                    .expect("the mempool cost cap is a valid JitCost"),
            );
            let mut wrapper = TxValidationCtx {
                ctx: &context,
                params: &params,
                cost: &mut cost,
                last_headers: &[],
                rules: TxValidationRules::default(),
            };
            checked.push(
                validate_transaction_parsed(
                    tx.clone(),
                    &tx_bytes[index],
                    resolved.clone(),
                    Vec::new(),
                    // `skip_scripts = true`: script evaluation cannot change any
                    // wallet-visible field, and a 1000-block sweep would
                    // otherwise pay for full sigma evaluation of real mainnet
                    // coinbase transactions. Every other check — canonical
                    // encoding, structural limits, group-element on-curve,
                    // monetary conservation, output heights — still runs, and
                    // `apply_block` still asserts the real state root.
                    true,
                    &mut wrapper,
                )
                .unwrap_or_else(|error| {
                    panic!("real validate_transaction_parsed rejected block {height}: {error:?}")
                }),
            );
        }

        let (state_root, _proof, _tip) = self
            .files()
            .store
            .candidate_dry_run(&checked)
            .unwrap_or_else(|error| panic!("candidate_dry_run at {height} failed: {error}"));

        let header = match &self.plan {
            ChainPlan::Mainnet { .. } => {
                let fixture = self
                    .mainnet
                    .as_ref()
                    .expect("the mainnet plan carries its fixture")
                    .block(height);
                assert_eq!(
                    state_root, fixture.header.state_root,
                    "candidate_dry_run must reproduce the captured mainnet state root at \
                     height {height}; if it does not, the harness is not driving the real \
                     apply path"
                );
                fixture.header
            }
            ChainPlan::Synthetic { .. } => Header {
                version: 2,
                parent_id: ModifierId::from_bytes(parent),
                ad_proofs_root: Digest32::from_bytes([0; 32]),
                transactions_root: Digest32::from_bytes([0; 32]),
                state_root,
                timestamp: 1_000_000 + height as u64,
                extension_root: Digest32::from_bytes([0; 32]),
                n_bits: 16842752,
                height,
                votes: [0; 3],
                unparsed_bytes: Vec::new(),
                // The solution nonce is the fork selector: bumping it yields a
                // genuinely different header (and therefore block id) for the
                // same transactions, which is exactly what the reorg scenario
                // needs.
                solution: ergo_ser::autolykos::AutolykosSolution::V2 {
                    pk: ergo_primitives::group_element::GroupElement::from([2; 33]),
                    nonce: [nonce; 8],
                },
            },
        };
        let (header_bytes, header_id) = serialize_header(&header).expect("header serializes");
        let header_id: [u8; 32] = *header_id.as_bytes();
        if matches!(self.plan, ChainPlan::Synthetic { .. }) {
            if let Some(cursor) = self.synthetic.as_mut() {
                cursor.parent = header_id;
            }
        }
        PreparedBlock {
            fixture: BlockFixture {
                height,
                header,
                header_bytes,
                header_id,
                txs: parsed.into_iter().map(|(tx, _)| tx).collect(),
                tx_bytes,
            },
            checked,
        }
    }

    /// The production rollback seam: `rollback_to` with the real wallet hook
    /// and ergo-node's real `ProdRescanGuard`, so the wallet tables rewind
    /// inside the same redb transaction as the UTXO.
    fn rollback_to(&mut self, height: u32) {
        // Rewind the synthetic cursor with the chain, before anything can read
        // it: the replacement fork spends the ancestor's outputs, so a stale
        // cursor would ask the dry run to resolve boxes the rollback removed.
        if self.synthetic.is_some() {
            let restored = self
                .synthetic_history
                .get(&height)
                .cloned()
                .unwrap_or_else(|| {
                    panic!("no synthetic cursor state recorded at the rollback target {height}")
                });
            self.synthetic = Some(restored);
        }
        let files = self.files_mut();
        files
            .store
            .rollback_to(
                height,
                Some(&files.hook),
                Some(&ergo_node::wallet_boot::ProdRescanGuard),
            )
            .unwrap_or_else(|error| panic!("embedded rollback to {height} failed: {error}"));
        assert_eq!(
            files.store.height(),
            height,
            "chain height after the embedded rollback"
        );
    }
}

/// Build the real production hook, hydrated from the store's own tracked keys —
/// the same boot-time hydration the node performs before handing the hook to
/// the chain-apply seam.
fn build_hook(store: &Arc<RedbWalletStore>) -> ergo_node::node::wallet_bridge::WalletStateHook {
    let read = store.read().expect("hook hydration read");
    let hydration = ergo_wallet_service::wallet::hydration::HydrationSnapshot::load(read.as_ref())
        .expect("hook hydration snapshot");
    let mut state = WalletState::empty(false);
    state
        .hydrate_from_reader(&hydration, ergo_ser::address::NetworkPrefix::Mainnet)
        .expect("hook hydration from the tracked-pubkey table");
    ergo_node::node::wallet_bridge::WalletStateHook {
        wallet: Arc::new(parking_lot::RwLock::new(state)),
        store: Arc::new(store.as_ref().clone()),
    }
}

/// The synthetic chain's genesis box: a P2PK box to the tracked key carrying
/// the chain's one token id, so block 1 has a real input to spend and strict
/// ERG conservation is satisfiable without minting.
fn synthetic_genesis() -> Vec<([u8; 32], Vec<u8>)> {
    vec![synthetic_genesis_box()]
}

fn synthetic_genesis_box() -> ([u8; 32], Vec<u8>) {
    let candidate = p2pk_candidate(
        &TRACKED_PUBKEY,
        SYNTHETIC_GENESIS_VALUE,
        0,
        vec![ergo_ser::token::Token {
            token_id: ergo_ser::token::TokenId::from_bytes(TOKEN_ID),
            amount: 7,
        }],
    );
    let ergo_box = ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes([0xEE; 32]),
        index: 0,
    };
    let box_id = *ergo_box
        .box_id()
        .expect("synthetic genesis box id")
        .as_bytes();
    (
        box_id,
        serialize_ergo_box(&ergo_box).expect("synthetic genesis serializes"),
    )
}

fn synthetic_genesis_box_id() -> [u8; 32] {
    synthetic_genesis_box().0
}

// =========================================================================
// 5. The daemon side: real standalone store + real syncer over real HTTP
// =========================================================================

/// The daemon wallet: a real `RedbWalletStore::open_standalone` in its own temp
/// directory, advanced by the real `StandaloneSyncer` over the real
/// `chain_http::HttpChainClient` against the real `ergo-api` chain router.
///
/// The syncer is rebuilt per pass rather than cached, so the restart scenario
/// can drop and re-open the store and get a genuinely fresh daemon runtime over
/// the same database file — the same thing a daemon restart does.
struct DaemonSide {
    /// Held only to keep the wallet database's directory alive for the life of
    /// the harness; the daemon restart below re-opens the file, not the dir.
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    node_url: String,
    api_key: Vec<u8>,
    /// `None` only inside [`DaemonSide::restart`], between the drop and the
    /// re-open. redb takes an exclusive `flock` on the file, so the last handle
    /// has to be released *before* the next open or it fails with
    /// `DatabaseAlreadyOpen`.
    store: Option<Arc<RedbWalletStore>>,
}

impl DaemonSide {
    fn store(&self) -> &Arc<RedbWalletStore> {
        self.store.as_ref().expect("the daemon store is open")
    }
}

/// The apply budget: one pass may apply up to `MAX_SYNC_BLOCKS` blocks. The
/// page budget stays at the shipped default of one block per `blocks-since`
/// request, so the harness never asks for a page the daemon would refuse.
const DAEMON_BATCH: u32 = 1_024;

impl DaemonSide {
    fn open(node_url: String, api_key: Vec<u8>) -> Self {
        let dir = tempfile::tempdir().expect("daemon temp dir");
        let path = dir.path().join("wallet.redb");
        let store = Arc::new(RedbWalletStore::open_standalone(&path).expect("standalone store"));
        Self {
            _dir: dir,
            path,
            node_url,
            api_key,
            store: Some(store),
        }
    }

    /// A real daemon restart: every in-process handle onto the wallet database
    /// is dropped and the file re-opened. The temp directory is deliberately
    /// kept alive — the *database* restarts, not its parent.
    fn restart(&mut self) {
        let path = self.path.clone();
        self.store = None;
        self.store = Some(Arc::new(
            RedbWalletStore::open_standalone(&path).expect("daemon store reopens"),
        ));
    }

    /// The real blocking HTTP chain client, built the way `lib::prepare` builds
    /// it: outside any async runtime, with the real `api_key`.
    fn chain(&self) -> Arc<dyn ergo_wallet_service::ChainClient> {
        let client = HttpChainClient::with_timeouts(
            reqwest::Url::parse(&self.node_url).expect("node url parses"),
            ApiKey::from_test(self.api_key.clone()),
            Duration::from_secs(5),
            Duration::from_secs(10),
        )
        .expect("the blocking client builds outside an async runtime");
        Arc::new(client)
    }

    fn syncer(&self) -> StandaloneSyncer {
        let chain = self.chain();
        let service = Arc::new(ergo_wallet_service::WalletService::new(
            self.store().clone(),
            chain.clone(),
        ));
        StandaloneSyncer::new(
            service,
            SyncConfig {
                batch: DAEMON_BATCH,
                page: ergo_walletd::sync::DEFAULT_BLOCKS_PER_PAGE,
                retry_delay: Duration::ZERO,
                max_retry_delay: Duration::ZERO,
            },
            Arc::new(CachedNodeTip::new(chain)),
        )
    }

    /// One real sync pass, for a caller that needs the report rather than just
    /// convergence (the restart scenario asserts that a caught-up pass is a
    /// no-op). Deliberately *not* how [`DaemonSide::sync_until_caught_up`]
    /// works: that one reuses a single syncer, and rebuilding it per pass would
    /// throw away the cached node tip and change what the loop exercises.
    fn caught_up_pass(&self) -> ergo_walletd::sync::SyncReport {
        self.syncer()
            .sync_once()
            .unwrap_or_else(|error| panic!("daemon sync pass failed: {error}"))
    }

    /// Run real sync passes until the daemon reports itself caught up with the
    /// node tip, exactly as the daemon's supervision loop does. Bounded so a
    /// non-converging pass fails loudly instead of hanging the suite.
    fn sync_until_caught_up(&self) -> u32 {
        let syncer = self.syncer();
        let mut passes = 0usize;
        loop {
            let report = syncer
                .sync_once()
                .unwrap_or_else(|error| panic!("daemon sync pass failed: {error}"));
            passes += 1;
            if report.completed {
                return passes as u32;
            }
            assert!(
                report.blocks_processed > 0,
                "the daemon reported an incomplete pass with no progress: {report:?}"
            );
            assert!(
                passes < 4_096,
                "the daemon failed to converge on the node tip after {passes} passes"
            );
        }
    }

    /// Seed the same rows the embedded side is seeded with, through the same
    /// `WalletWrite` API.
    fn seed(&self, watched: [u8; 33], scan: bool) {
        let mut write = self.store().begin_write().expect("daemon seed write");
        for (index, pubkey, path, label, added_at) in tracked_rows(watched) {
            write
                .insert_tracked_pubkey(
                    index,
                    pubkey,
                    &TrackedPubkeyMeta {
                        derivation_path: path,
                        derivation_path_label: label.to_string(),
                        added_at_height: added_at,
                    },
                )
                .expect("daemon tracked pubkey insert");
        }
        write
            .rebuild_visible_addresses()
            .expect("daemon visible addresses");
        write
            .set_derivation_head(3)
            .expect("daemon derivation head");
        if scan {
            write
                .put_scan(SCAN_ID, seeded_scan(), SCAN_ID)
                .expect("daemon scan registry insert");
        }
        write.commit().expect("daemon seed commit");
    }

    /// Mark the wallet for a full rebuild from genesis — the durable state a
    /// rescan request (or a fail-closed fence) leaves behind.
    fn invalidate(&self) {
        self.store()
            .persist_scan_invalidation(true)
            .expect("daemon scan invalidation persists");
    }

    fn prepare_full_rescan(&self) {
        let mut write = self.store().begin_write().expect("daemon rescan write");
        write
            .prepare_rescan(0, true)
            .expect("full rescan preparation");
        write.commit().expect("full rescan preparation commits");
    }
}

// =========================================================================
// 6. The harness
// =========================================================================

/// The real `ergo-api` chain router on a loopback port, served the way
/// `ergo-api`'s own server serves it.
///
/// Same stack `tests/it/node_api.rs` proves: a real `ApiSecurity` `api_key`
/// gate, a real `Governor`, the real `wallet_chain_router`, and ergo-node's
/// real `InProcessChainClient` + `WalletChainAdapter` over the embedded
/// `StateStore`.
///
/// One deliberate difference, and it matters: the make-service installs
/// `ConnectInfo<SocketAddr>`, exactly as `ergo_api::server` does. Without it
/// the governor cannot read the peer IP, so every caller is bucketed under one
/// shared "unknown" key and a shadow sweep — thousands of `blocks-since` calls
/// — gets throttled into a 429 loop that has nothing to do with wallet
/// behaviour. With it, a loopback daemon is exempt on a direct bind, which is
/// the production posture.
struct ShadowNodeApi {
    address: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ShadowNodeApi {
    fn url(&self) -> String {
        format!("http://{}/", self.address)
    }
}

impl Drop for ShadowNodeApi {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Serve the real `ergo-api` chain router over a *cloneable* reader on the
/// embedded store, so it keeps answering across applies, the reorg rollback,
/// and the restart.
fn serve_shadow_node_api(store: &StateStore) -> ShadowNodeApi {
    let security = Arc::new(
        ergo_api::auth::ApiSecurity::new(ergo_api::auth::ApiSecurity::hash_key(API_KEY))
            .expect("valid api_key hash"),
    );
    let governor =
        ergo_api::v1::governor::Governor::new(ergo_api::v1::governor::GovernorConfig::default())
            .expect("valid governor config");
    let chain_client = Arc::new(
        ergo_node::node::wallet_bridge::InProcessChainClient::from_chain_reader(
            store.reader_handle(),
            None::<Arc<dyn ergo_api::NodeSubmit>>,
            false,
            None,
        ),
    );
    let chain: Arc<dyn ergo_api::traits::WalletChain> =
        ergo_node::node::wallet_bridge::WalletChainAdapter::new(chain_client).into_dyn();
    let router = ergo_api::v1::wallet_chain_router(
        ergo_api::v1::WalletChainState::with_chain(chain),
        governor,
        ergo_api::v1::V1AuthConfig::new(Some(security)).into_shared(),
    );
    // Bound before the runtime starts, so the port is known synchronously and
    // the blocking client in the test body never runs inside the server's
    // runtime.
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback bind");
    let address = std_listener.local_addr().expect("bound address");
    std_listener
        .set_nonblocking(true)
        .expect("non-blocking listener");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("node API runtime");
        runtime.block_on(async move {
            let listener =
                tokio::net::TcpListener::from_std(std_listener).expect("reactor handoff");
            let make_service = router.into_make_service_with_connect_info::<SocketAddr>();
            axum::serve(listener, make_service)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("the shadow node API server runs without error");
        });
    });
    ShadowNodeApi {
        address,
        shutdown: Some(shutdown_tx),
        thread: Some(handle),
    }
}

/// One embedded/daemon pair over the same blocks.
struct Shadow {
    _node_dir: tempfile::TempDir,
    /// `None` only between [`Shadow::stop_node`] and the re-serve in the
    /// restart scenario.
    node: Option<ShadowNodeApi>,
    embedded: EmbeddedSide,
    daemon: DaemonSide,
    scan: bool,
}

impl Shadow {
    fn new(plan: ChainPlan, scan: bool) -> Self {
        let node_dir = tempfile::tempdir().expect("node temp dir");
        let embedded = EmbeddedSide::open(&node_dir.path().join("state.redb"), plan);
        // The node API reads a *cloneable* reader over the same redb, so it
        // keeps serving the store across the applies, the rollback, and the
        // restart below — the same property `tests/it/node_api.rs` relies on.
        let node = serve_shadow_node_api(embedded.store());
        let daemon = DaemonSide::open(node.url(), API_KEY.to_vec());
        Self {
            _node_dir: node_dir,
            node: Some(node),
            embedded,
            daemon,
            scan,
        }
    }

    /// Seed both wallets identically, and hand the real tracked key back so a
    /// caller can assert the fixture produced boxes.
    /// Stop serving the node API, releasing the `Arc<Database>` its
    /// `ChainStoreReader` holds so the store can be re-opened. A no-op once
    /// already stopped.
    fn stop_node(&mut self) {
        if let Some(node) = self.node.take() {
            drop(node);
        }
    }

    fn seed(&mut self) {
        let watched = self.embedded.watched_pubkey();
        self.embedded.seed(watched, self.scan);
        self.daemon.seed(watched, self.scan);
    }

    /// Interleave: apply one block on the embedded side, then let the daemon
    /// make real sync passes over HTTP until it is caught up. One block at a
    /// time is the deployment shape (the node and the daemon run
    /// concurrently), and it is what makes an ordering bug between the two
    /// apply paths visible.
    fn advance_to(&mut self, upto: u32, nonce: u8) {
        while self.embedded.height() < upto {
            self.advance_embedded_one(nonce);
            self.daemon.sync_until_caught_up();
        }
        assert_eq!(self.embedded.height(), upto, "embedded chain height");
    }

    /// [`Shadow::advance_to`] plus the full normalized comparison at **every**
    /// applied height, and returns how many heights were compared.
    ///
    /// Comparing only at the tip is a hole, not a stylistic choice: the
    /// divergences this harness exists to catch are transient by construction.
    /// A status the next block promotes, a box only one side re-adds, a durable
    /// flag the next pass reconciles — each of those has vanished by the tip, so
    /// a tip-only sweep would report "the two wallets agree" for a wallet that
    /// never agreed at all. Per-height comparison closes that: the failure
    /// names the *first* height at which the two sides differ.
    ///
    /// The box floor is carried forward instead of being recomputed per height,
    /// which is what makes it a real invariant: once the wallet has tracked a
    /// box at some height, every later height must still have one, so a
    /// comparison that quietly went empty fails at the height it went empty. It
    /// starts at zero because the first heights of a real chain legitimately
    /// track nothing yet.
    fn advance_to_compared(&mut self, upto: u32, nonce: u8, context: &str) -> u32 {
        let mut floor = 0usize;
        let mut compared = 0u32;
        while self.embedded.height() < upto {
            self.advance_embedded_one(nonce);
            self.daemon.sync_until_caught_up();
            let height = self.embedded.height();
            let (embedded, daemon) = self.snapshot_pair();
            assert_shadow_eq(
                &format!("{context} at height {height}"),
                &embedded,
                &daemon,
                floor,
            );
            floor = floor.max(usize::from(!embedded.boxes.is_empty()));
            compared += 1;
        }
        assert_eq!(self.embedded.height(), upto, "embedded chain height");
        compared
    }

    /// Advance the embedded side by exactly one block, with the daemon left
    /// behind on purpose.
    ///
    /// The reorg scenario polls once at the rollback height, then advances
    /// the replacement fork before retrying the daemon's stale cursor.
    fn advance_embedded_one(&mut self, nonce: u8) {
        let next = self.embedded.height() + 1;
        assert!(
            next <= self.embedded.plan.blocks(),
            "height {next} exceeds the fixture's {} blocks",
            self.embedded.plan.blocks()
        );
        self.embedded.apply(next, nonce);
    }

    fn snapshot_pair(&self) -> (NormalizedSnapshot, NormalizedSnapshot) {
        let embedded = NormalizedSnapshot::capture(
            "embedded",
            &*self.embedded.wallet_store().read().expect("embedded read"),
            self.scan.then_some(SCAN_ID),
        );
        let daemon = NormalizedSnapshot::capture(
            "daemon",
            &*self.daemon.store().read().expect("daemon read"),
            self.scan.then_some(SCAN_ID),
        );
        (embedded, daemon)
    }

    fn compare(&self, context: &str, min_boxes: usize) {
        let (embedded, daemon) = self.snapshot_pair();
        assert_shadow_eq(context, &embedded, &daemon, min_boxes);
    }
}

// =========================================================================
// 7. Cheap tests: the comparison oracle itself
// =========================================================================

/// The negative control for the whole harness.
///
/// A shadow suite whose comparator cannot fail is not evidence. This builds
/// two snapshots that differ in exactly one field, mutates the daemon side's
/// copy of that one field, and requires `assert_shadow_eq` to fail — and to
/// name that field. Every field the real scenarios can diverge on is covered,
/// so a future field added to `NormalizedSnapshot` without a negative control
/// shows up as a gap here rather than as a silently-uncompared field.
#[test]
fn shadow_comparator_detects_an_injected_divergence_in_every_compared_field() {
    // The backing temp directories are kept alive for the whole test; the
    // snapshots are fully materialized, but deleting a redb file out from under
    // an open handle is exactly the kind of thing a harness must not do.
    let mut keep: Vec<tempfile::TempDir> = Vec::new();
    let baseline = |label: &'static str, keep: &mut Vec<tempfile::TempDir>| {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap();
        let snapshot = NormalizedSnapshot::capture(label, &*store.read().unwrap(), None);
        keep.push(dir);
        snapshot
    };

    let pristine = baseline("embedded", &mut keep);
    // Self-comparison must be silent, or every scenario below would be noise.
    assert!(snapshot_diff(&pristine, &pristine).is_empty());

    // One field moved at a time. Each entry is
    // `(field label, the mutation)`, applied to a fresh copy of the pristine
    // snapshot, and the required substring the diff must contain.
    /// One negative control: `(label, the single-field mutation, the field the
    /// diff must name)`.
    type Mutation = (
        &'static str,
        Box<dyn Fn(&mut NormalizedSnapshot)>,
        &'static str,
    );
    let mutations: Vec<Mutation> = vec![
        (
            "cursor",
            Box::new(|s: &mut NormalizedSnapshot| s.cursor = Some((7, Some([9; 32])))),
            "cursor",
        ),
        (
            "committed_tip",
            Box::new(|s: &mut NormalizedSnapshot| s.committed_tip = Some((7, [9; 32]))),
            "committed_tip",
        ),
        (
            "balance",
            Box::new(|s: &mut NormalizedSnapshot| s.balance.confirmed_nano_ergs += 1),
            "balance",
        ),
        (
            "boxes",
            Box::new(|s: &mut NormalizedSnapshot| {
                s.boxes.push(BoxSnapshot {
                    box_id: [1; 32],
                    creation_tx_id: [2; 32],
                    creation_output_index: 0,
                    creation_height: 1,
                    value: 1,
                    assets: Vec::new(),
                    status: "confirmed".to_string(),
                    provenance: "owned".to_string(),
                });
            }),
            "boxes",
        ),
        (
            "unspent",
            Box::new(|s: &mut NormalizedSnapshot| s.unspent.push([3; 32])),
            "unspent",
        ),
        (
            "transactions",
            Box::new(|s: &mut NormalizedSnapshot| {
                s.transactions.push(TxSnapshot {
                    block_height: 1,
                    tx_id: [4; 32],
                    block_id: [5; 32],
                    wallet_outputs: Vec::new(),
                    wallet_inputs: Vec::new(),
                });
            }),
            "transactions",
        ),
        (
            "registry",
            Box::new(|s: &mut NormalizedSnapshot| s.registry.last_used_id = Some(77)),
            "registry",
        ),
        (
            "scan boxes",
            Box::new(|s: &mut NormalizedSnapshot| {
                s.scans = Some(ScanSnapshot {
                    boxes: Vec::new(),
                    transactions: vec![ScanTxSnapshot {
                        block_height: 1,
                        tx_id: [6; 32],
                        block_id: [7; 32],
                        scan_ids: vec![11],
                        created: Vec::new(),
                        spent: Vec::new(),
                    }],
                });
            }),
            "scan seeding",
        ),
        (
            "scan boxes (both seeded)",
            Box::new(|s: &mut NormalizedSnapshot| {
                let scans = s
                    .scans
                    .as_mut()
                    .expect("the scan-seeded baseline carries a scan snapshot");
                scans.boxes.push(ScanBoxSnapshot {
                    scan_id: SCAN_ID,
                    box_id: [8; 32],
                    inclusion_height: 1,
                    creation_out_index: 0,
                    box_bytes_digest: [0; 32],
                    box_bytes_len: 10,
                    status: "unspent".to_string(),
                });
            }),
            "scan_boxes",
        ),
        (
            "scan transactions (both seeded)",
            Box::new(|s: &mut NormalizedSnapshot| {
                let scans = s
                    .scans
                    .as_mut()
                    .expect("the scan-seeded baseline carries a scan snapshot");
                scans.transactions.push(ScanTxSnapshot {
                    block_height: 1,
                    tx_id: [6; 32],
                    block_id: [7; 32],
                    scan_ids: vec![SCAN_ID],
                    created: Vec::new(),
                    spent: Vec::new(),
                });
            }),
            "scan_transactions",
        ),
        (
            "tracked_keys",
            Box::new(|s: &mut NormalizedSnapshot| {
                s.tracked.push(TrackedSnapshot {
                    path_idx: 9,
                    pubkey: [0xAB; 33],
                    derivation_path: vec![1],
                    label: "x".to_string(),
                    added_at_height: 0,
                });
            }),
            "tracked_keys",
        ),
        (
            "visible_keys",
            Box::new(|s: &mut NormalizedSnapshot| s.visible.push((1, [0xCD; 33]))),
            "visible_keys",
        ),
        (
            "derivation_head",
            Box::new(|s: &mut NormalizedSnapshot| s.derivation_head = 99),
            "derivation_head",
        ),
        (
            "change_address",
            Box::new(|s: &mut NormalizedSnapshot| s.change_address = Some([0xEF; 33])),
            "change_address",
        ),
        (
            "scan_invalidated",
            Box::new(|s: &mut NormalizedSnapshot| s.scan_invalidated = true),
            "scan_invalidated",
        ),
        (
            "reward_key",
            Box::new(|s: &mut NormalizedSnapshot| s.reward_key = RewardSnapshot::Ready([0x11; 33])),
            "reward_key",
        ),
    ];

    // A second baseline that reports a seeded scan on *both* sides, so the
    // scan-box and scan-transaction comparisons are exercised as content
    // diffs rather than as the "seeding differs" sentinel.
    let mut seeded_baseline = baseline("embedded", &mut keep);
    seeded_baseline.scans = Some(ScanSnapshot {
        boxes: Vec::new(),
        transactions: Vec::new(),
    });

    for (label, mutate, expected_field) in mutations {
        let mut moved = if label.contains("both seeded") {
            let mut moved = seeded_baseline.clone();
            moved.label = "daemon";
            moved
        } else {
            let mut moved = baseline("daemon", &mut keep);
            moved.label = "daemon";
            moved
        };
        let reference = if label.contains("both seeded") {
            &seeded_baseline
        } else {
            &pristine
        };
        mutate(&mut moved);
        let diff = snapshot_diff(reference, &moved);
        assert!(
            !diff.is_empty(),
            "injected divergence in `{label}` was NOT detected: the comparator \
             reported two different snapshots as equal"
        );
        assert!(
            diff.iter().any(|line| line.contains(expected_field)),
            "injected divergence in `{label}` was detected but not attributed to \
             `{expected_field}`; diff was:\n{}",
            diff.join("\n")
        );
    }
}

/// Run `assert_shadow_eq` and report what it said, instead of failing the test.
///
/// A comparison is only worth what its *failures* look like, and the negative
/// controls have to observe a failure rather than produce one, so they run the
/// real gate and catch the panic. Returns the panic message, or `None` when the
/// comparison passed. The snapshots are fully materialized before the call, and
/// nothing here deletes a database out from under an open handle, so unwinding
/// through it is safe.
fn shadow_eq_failure(
    context: &str,
    embedded: &NormalizedSnapshot,
    daemon: &NormalizedSnapshot,
    min_boxes: usize,
) -> Option<String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_shadow_eq(context, embedded, daemon, min_boxes);
    }))
    .err()
    .map(|payload| {
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    })
}

/// The vacuity guard's own negative control.
///
/// `assert_shadow_eq` asserts a non-zero box floor so a comparison that tracks
/// nothing cannot pass. This proves that floor is load-bearing: two snapshots
/// that agree completely but hold zero boxes must still fail.
#[test]
fn shadow_comparator_rejects_a_vacuous_zero_box_comparison() {
    let dir = tempfile::tempdir().unwrap();
    let store = RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap();
    let read = store.read().unwrap();
    let snapshot = NormalizedSnapshot::capture("embedded", &*read, None);
    let message = shadow_eq_failure("zero-box control", &snapshot, &snapshot, 1)
        .expect("two identical zero-box snapshots must still fail the floor");
    assert!(
        message.contains("is vacuous"),
        "the zero-box floor did not fire; the panic was: {message}"
    );
}

// =========================================================================
// 8. Slow tests (all `#[ignore]`d; run by scripts/shadow-compare.sh and the
//    dedicated `wallet-shadow` CI job)
// =========================================================================

/// The digest 1-1000 sweep: the headline shadow scenario.
///
/// Real mainnet blocks 1..=1000 from `test-vectors`, applied one at a time on
/// the embedded side through the production `StateStore::apply_block` +
/// `WalletStateHook`, with the daemon catching up after each block over real
/// HTTP against the real `ergo-api` chain router, and the two sides compared at
/// **every** height — not only at the tip. Every height's state root is the
/// captured one, so a wallet divergence cannot hide behind a chain divergence.
///
/// Cost: 1000 real block applications, ~1000 real sync passes over loopback
/// HTTP, and 1000 full normalized comparisons. That is minutes, not seconds,
/// which is why it is `#[ignore]`d — the default `cargo nextest run
/// --workspace` must stay fast.
#[test]
#[ignore = "shadow sweep over 1000 real mainnet blocks; run via scripts/shadow-compare.sh"]
fn shadow_sweep_digest_1_1000_agrees_embedded_and_daemon() {
    const TIP: u32 = 1_000;
    /// Where the injected divergence below goes in. Far enough that the wallet
    /// already holds boxes and a transaction history, so the injected field is
    /// compared against real state rather than two empty wallets; low enough
    /// that the reconciling rescan the next pass performs replays a hundred
    /// blocks rather than the whole sweep.
    const DIVERGENCE_AT: u32 = 100;
    const CONTEXT: &str = "mainnet digest 1-1000";

    let mut shadow = Shadow::new(ChainPlan::Mainnet { blocks: TIP }, true);
    shadow.seed();
    assert_eq!(
        shadow.advance_to_compared(DIVERGENCE_AT, 0, CONTEXT),
        DIVERGENCE_AT,
        "heights compared before the injection"
    );

    // ----- the mid-sweep injected divergence -----
    //
    // The regression guard for the per-height comparison. The durable
    // `scan_invalidated` flag is a real compared field *and* it is reconciled:
    // the next sync pass clears it. So a divergence injected here is invisible
    // to any comparison
    // made after that pass — a tip-only sweep would finish green for a wallet
    // that spent a pass out of sync. The comparison at the injection height has
    // to see it first, and it has to name the field.
    shadow.daemon.invalidate();
    let (embedded, daemon) = shadow.snapshot_pair();
    let message = shadow_eq_failure(
        &format!("{CONTEXT} at height {DIVERGENCE_AT} with an injected divergence"),
        &embedded,
        &daemon,
        0,
    )
    .expect("the per-height comparison must reject a mid-sweep injected divergence");
    assert!(
        message.contains("scan_invalidated"),
        "the mid-sweep divergence was detected but not attributed to \
         `scan_invalidated`; the panic was: {message}"
    );

    // Explicitly reset the cursor: invalidation alone resumes from that cursor.
    shadow.daemon.prepare_full_rescan();
    let replay = shadow
        .daemon
        .syncer()
        .sync_once()
        .expect("mid-sweep rescan");
    assert_eq!(replay.blocks_processed, DIVERGENCE_AT);
    assert!(replay.completed);

    // Carry on after rebuilding from genesis. Every remaining height is
    // compared again, so a sweep that "repaired"
    // the injected divergence by silently resyncing it away is not accepted.
    assert_eq!(
        shadow.advance_to_compared(TIP, 0, CONTEXT),
        TIP - DIVERGENCE_AT,
        "heights compared after the reconciling pass"
    );
    assert_eq!(shadow.embedded.height(), TIP, "embedded chain height");
    let root = shadow.embedded.root_digest();
    assert_eq!(
        root,
        mainnet_state_root(TIP),
        "the embedded apply must reproduce the captured state root at the tip"
    );

    // The tip comparison the loop already made at height TIP, kept as a floor:
    // it re-states the result with the strict `min_boxes = 1` the carried
    // floor only reaches by the end, so a tip whose snapshot went empty is
    // reported as vacuous rather than as a field diff.
    let (embedded, daemon) = shadow.snapshot_pair();
    assert_shadow_eq(&format!("{CONTEXT} at the tip"), &embedded, &daemon, 1);
    // A real miner-reward box must be present and still immature or promoted,
    // so the maturity comparison is exercised on real data rather than on two
    // wallets that happen to track nothing.
    assert!(
        embedded
            .boxes
            .iter()
            .any(|wallet_box| wallet_box.provenance == "miner_reward"),
        "the sweep tracked no miner-reward box, so the maturity/status \
         comparison is vacuous: {embedded:?}"
    );
    assert!(
        embedded
            .boxes
            .iter()
            .any(|wallet_box| wallet_box.status.starts_with("immature:")),
        "the sweep tracked no immature box, so `promote_matured_boxes` is not \
         being compared: {embedded:?}"
    );
    assert!(
        !embedded.scan_invalidated,
        "a completed sweep must leave the wallet un-invalidated"
    );
}

/// The captured state root at `height`, straight from the fixture file. An
/// independent oracle for the embedded apply: `apply_block` refuses any block
/// whose declared root it cannot reproduce, so this assertion is about the
/// *final* root specifically, after a thousand applications.
fn mainnet_state_root(height: u32) -> ADDigest {
    let path = "../test-vectors/mainnet/utxo_digests_1_1000.json";
    let raw = std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    let digests: Vec<serde_json::Value> =
        serde_json::from_str(&raw).expect("utxo_digests_1_1000.json parses");
    let entry = digests
        .iter()
        .find(|entry| entry["height"].as_u64() == Some(height as u64))
        .unwrap_or_else(|| panic!("no captured state root at height {height}"));
    ADDigest::from_bytes(
        hex::decode(entry["stateRoot"].as_str().expect("stateRoot hex"))
            .expect("stateRoot bytes")
            .try_into()
            .expect("stateRoot is 33 bytes"),
    )
}

/// The small synthetic smoke scenario.
///
/// Same two paths, but a chain the harness builds, so every wallet
/// classification branch is reachable deterministically: `Owned` / `Confirmed`
/// boxes, a `MinerReward` / `Immature` reward box, a `Spent` transition, a
/// token-bearing box (the `assets` and balance-token paths), a box paid to an
/// untracked key that both paths must ignore, and a registered scan that
/// matches the token box — so `WALLET_SCAN_BOXES`, `_INDEX` and `_TXS` are all
/// non-empty on both sides.
#[test]
#[ignore = "shadow synthetic smoke over 12 blocks; run via scripts/shadow-compare.sh"]
fn shadow_synthetic_smoke_agrees_embedded_and_daemon() {
    const BLOCKS: u32 = 12;
    let mut shadow = Shadow::new(ChainPlan::Synthetic { blocks: BLOCKS }, true);
    shadow.seed();
    shadow.advance_to(BLOCKS, 0);

    let (embedded, daemon) = shadow.snapshot_pair();
    // 12 reward boxes + the live carry box + the live token box.
    assert_shadow_eq("synthetic smoke", &embedded, &daemon, 3);

    // The scenario must really cover what it claims, or it is a weaker test
    // than it looks.
    let statuses: Vec<&str> = embedded
        .boxes
        .iter()
        .map(|wallet_box| wallet_box.status.as_str())
        .collect();
    assert!(
        statuses
            .iter()
            .any(|status| status.starts_with("immature:")),
        "no immature box: {statuses:?}"
    );
    assert!(
        statuses.iter().any(|status| status.starts_with("spent:")),
        "no spent box: {statuses:?}"
    );
    assert!(
        statuses.contains(&"confirmed"),
        "no confirmed box: {statuses:?}"
    );
    assert_eq!(
        embedded.balance.tokens.len(),
        1,
        "the token-bearing box must reach the balance: {:?}",
        embedded.balance
    );
    let scans = embedded.scans.as_ref().expect("the scenario seeds a scan");
    assert!(
        !scans.boxes.is_empty() && !scans.transactions.is_empty(),
        "the seeded scan tracked nothing: {scans:?}"
    );
    assert_eq!(
        embedded.reward_key,
        RewardSnapshot::Ready(shadow.embedded.watched_pubkey())
    );
    assert!(!embedded.scan_invalidated);
}

/// A reorg on both sides: the node rolls back with its own `rollback_to` and
/// re-derives the fork with a different solution nonce (so genuinely different
/// block ids), and the daemon must notice the stale cursor, take the node's
/// `Ancestor` answer, rewind to the common ancestor, and follow the
/// replacement fork. Compared at every step: after the original chain, after
/// the embedded rollback, and after both sides have followed the fork.
#[test]
#[ignore = "shadow reorg rollback/re-apply on both sides; run via scripts/shadow-compare.sh"]
fn shadow_reorg_rewinds_and_reapplies_on_both_sides() {
    const BLOCKS: u32 = 10;
    const ANCESTOR: u32 = 6;
    const FORK_NONCE: u8 = 0xA5;

    let mut shadow = Shadow::new(ChainPlan::Synthetic { blocks: BLOCKS }, true);
    shadow.seed();
    shadow.advance_to(BLOCKS, 0);
    shadow.compare("synthetic reorg: before the reorg", 3);
    let original_tip = shadow.embedded.height();
    assert_eq!(original_tip, BLOCKS);

    // The id the node is about to abandon, read from the store's own
    // `chain_index` row at the reorg tip height. Captured *before* the
    // rollback, because re-applying the fork overwrites that row — this is the
    // only moment the abandoned id is readable, and without it there is
    // nothing to compare the fork's tip against, so a fork that silently
    // re-applied the *same* header (a no-op reorg) would satisfy every
    // remaining assertion in this scenario: the daemon's cursor would already
    // match the node's tip, `Ancestor` would never be asked for, and the rewind
    // path the scenario exists to compare would never run.
    let abandoned_tip_id = shadow
        .embedded
        .store()
        .reader_handle()
        .committed_block_id_at_height(original_tip)
        .expect("pre-rollback committed block id read")
        .expect("the original chain has a committed tip at the reorg height");

    // The node reorgs: real `rollback_to` with the real hook and the real
    // `ProdRescanGuard`, so the wallet tables rewind atomically with the UTXO.
    // The daemon is deliberately *not* told — it still believes it is at the
    // old tip, which is exactly the production situation.
    shadow.embedded.rollback_to(ANCESTOR);
    assert_eq!(shadow.embedded.height(), ANCESTOR);
    let error = shadow.daemon.syncer().sync_once().unwrap_err();
    assert!(
        error.retryable(),
        "mid-reorg node tip must be recoverable: {error}"
    );

    // Re-derive the fork. Same transactions, different solution nonce, so the
    // headers — and therefore the block ids the node will now serve — differ
    // from the ones the daemon already applied. Once the replacement fork
    // catches up, retrying the same daemon must take the rewind path.
    while shadow.embedded.height() < BLOCKS {
        shadow.advance_embedded_one(FORK_NONCE);
    }
    assert_eq!(shadow.embedded.height(), BLOCKS);
    shadow.daemon.sync_until_caught_up();
    let forked_tip = shadow
        .embedded
        .store()
        .reader_handle()
        .committed_block_id_at_height(BLOCKS)
        .expect("committed block id read")
        .expect("the fork has a committed tip");
    assert_ne!(
        forked_tip, abandoned_tip_id,
        "the replacement fork's tip at height {BLOCKS} carries the same block id as \
         the chain that was rolled back, so this was not a reorg: the daemon's cursor \
         already matched the node tip, its rewind was never exercised, and the two \
         sides agreeing afterwards proves nothing"
    );

    shadow.compare("synthetic reorg: after both sides followed the fork", 3);
}

/// A node restart and a daemon restart, over the same two databases.
///
/// The node's `StateStore` is dropped and re-opened from disk; the daemon's
/// `RedbWalletStore` is dropped and re-opened from disk. Neither chain height
/// nor either durable cursor may move, and a caught-up pass must then apply
/// **zero** blocks — the property that makes a restart cheap rather than a
/// rescan, and the only way to tell the two apart from the outside.
#[test]
#[ignore = "shadow node + daemon restart; run via scripts/shadow-compare.sh"]
fn shadow_survives_a_node_and_daemon_restart() {
    const BLOCKS: u32 = 8;
    let mut shadow = Shadow::new(ChainPlan::Synthetic { blocks: BLOCKS }, true);
    shadow.seed();
    shadow.advance_to(BLOCKS, 0);
    shadow.compare("restart: before the restart", 3);
    let cursor_before = shadow
        .embedded
        .wallet_store()
        .read()
        .expect("pre-restart embedded read")
        .scan_cursor()
        .expect("pre-restart embedded cursor")
        .expect("pre-restart cursor exists");
    let daemon_cursor_before = shadow
        .daemon
        .store()
        .read()
        .expect("pre-restart daemon read")
        .scan_cursor()
        .expect("pre-restart daemon cursor")
        .expect("pre-restart daemon cursor exists");

    // Restart in dependency order, which is also the real order. The node's
    // `ChainStoreReader` holds the same `Arc<Database>` as the `StateStore`, so
    // the served API has to go away before the store can be re-opened; only
    // then can a new reader be built from the re-opened store.
    shadow.stop_node();
    shadow.embedded.restart();
    shadow.node = Some(serve_shadow_node_api(shadow.embedded.store()));
    // The re-served node binds a fresh ephemeral loopback port, so the daemon
    // is re-pointed at it — the same thing an operator does when a node moves
    // address. Everything else about the daemon is untouched: same database
    // file, same api_key, same sync config.
    shadow.daemon.node_url = shadow
        .node
        .as_ref()
        .expect("the node is being re-served")
        .url();
    shadow.daemon.restart();
    shadow.daemon.sync_until_caught_up();

    let cursor_after = shadow
        .embedded
        .wallet_store()
        .read()
        .expect("post-restart embedded read")
        .scan_cursor()
        .expect("post-restart embedded cursor")
        .expect("post-restart cursor exists");
    assert_eq!(
        cursor_after, cursor_before,
        "a restart must not move the durable cursor"
    );
    let daemon_cursor_after = shadow
        .daemon
        .store()
        .read()
        .expect("post-restart daemon read")
        .scan_cursor()
        .expect("post-restart daemon cursor")
        .expect("post-restart daemon cursor exists");
    assert_eq!(
        daemon_cursor_after, daemon_cursor_before,
        "a daemon restart must not move the daemon's durable cursor"
    );

    // A caught-up pass has to be a genuine no-op, and this is the assertion
    // that says so: the durable cursor is already at the node's tip, so the
    // pass applies *zero* blocks. Without it the restart could pass by
    // silently replaying the chain — the exact cost the cursor exists to avoid,
    // and the one thing that separates a restart from a rescan. `from_height` is
    // the height the pass would fetch *next*, so it pins the other half: the
    // pass resumed at the tip rather than rewinding to genesis.
    let idle = shadow.daemon.caught_up_pass();
    assert!(idle.completed, "a caught-up pass must complete: {idle:?}");
    assert_eq!(
        idle.blocks_processed, 0,
        "a caught-up pass after a restart must apply zero blocks rather than \
         replay: {idle:?}"
    );
    assert_eq!(
        (idle.wallet_height, idle.from_height),
        (BLOCKS, BLOCKS + 1),
        "a caught-up pass must report the unchanged cursor and the next block \
         to fetch, not a rewind: {idle:?}"
    );

    shadow.compare("restart: after both sides restarted", 3);
}

/// Daemon rescan-from-zero: the durable cursor is reset and invalidated.
/// The real `StandaloneSyncer` must rebuild the whole wallet from genesis through the
/// real HTTP path — clearing the flag on success — landing on exactly the state
/// the embedded side reached incrementally.
///
/// This is the scenario that matters most for a `#[ignore]`d suite: the
/// incremental forward path is covered by every other scenario, and this is the
/// one that proves the rebuild is not a different answer.
#[test]
#[ignore = "shadow daemon rescan-from-zero; run via scripts/shadow-compare.sh"]
fn shadow_daemon_rescan_from_zero_reproduces_the_embedded_state() {
    const BLOCKS: u32 = 9;
    let mut shadow = Shadow::new(ChainPlan::Synthetic { blocks: BLOCKS }, true);
    shadow.seed();
    shadow.advance_to(BLOCKS, 0);
    shadow.compare("rescan: before the rescan", 3);

    // Use the full-rescan preparation path, including its durable cursor reset.
    shadow.daemon.prepare_full_rescan();
    assert!(
        shadow
            .daemon
            .store()
            .read()
            .expect("post-invalidate read")
            .scan_invalidated()
            .expect("post-invalidate flag"),
        "the invalidation flag must be durable before the rescan pass"
    );

    // Require actual replay: comparing unchanged state at the tip is vacuous.
    let replay = shadow
        .daemon
        .syncer()
        .sync_once()
        .expect("full rescan pass");
    assert_eq!(replay.blocks_processed, BLOCKS);
    assert_eq!(replay.from_height, 0);
    assert!(replay.completed);
    shadow.compare("rescan: after rebuilding from genesis", 3);

    let read = shadow.daemon.store().read().expect("post-rescan read");
    assert!(
        !read.scan_invalidated().expect("post-rescan flag"),
        "a completed rebuild must clear the invalidation flag"
    );
    assert_eq!(
        read.scan_cursor()
            .expect("post-rescan cursor")
            .expect("post-rescan cursor exists")
            .height,
        BLOCKS
    );
}
