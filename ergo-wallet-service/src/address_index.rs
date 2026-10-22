//! Restore and key backfill from the node's address index.
//!
//! A wallet that follows blocks learns its history by reading every block.
//! When the node runs its address index, the index already knows which blocks
//! touched an address, so the wallet reads only those. The index is used as a
//! pointer, never as a source of truth: each block it names is fetched from
//! the chain, checked against what the index claimed (same block id, the named
//! transaction inside it), and applied through the same classification as a
//! full scan. The result is the balance, boxes and transaction history a full
//! scan with the same keys would have written, and any disagreement between
//! the index and the chain abandons the shortcut so the caller scans instead.
//!
//! Two callers share one routine: the daemon's restore (every tracked key,
//! into a wiped store) and `deriveKey` (one new key, into a populated store).

use std::collections::{BTreeMap, BTreeSet};

use ergo_ser::address::NetworkPrefix;
use thiserror::Error;

use crate::chain::{
    ChainBlock, ChainClientError, ChainCursor, CommittedTip, IndexedTransaction, TxId,
};
use crate::runtime::{WalletService, WalletServiceError};
use crate::wallet::{WalletStoreError, WalletWrite};

/// Consecutive unused addresses after which restore stops looking for more
/// used ones (the BIP-44 gap limit).
pub const GAP_LIMIT: u32 = 20;

/// Most address windows (of [`GAP_LIMIT`] addresses) discovery will walk, so
/// a pathological index cannot keep it deriving forever.
pub const MAX_DISCOVERY_WINDOWS: u32 = 50;

/// Blocks below the shorter of the node tip and the index height that the
/// restore leaves to ordinary block following. The index and the node may
/// disagree about the last few blocks while a reorg settles; scanning them
/// costs a handful of blocks and removes the question.
pub const SEED_MARGIN: u32 = 16;

/// Most blocks backfill will fetch outright because the index does not reach
/// them (the wallet cursor is ahead of the index). Past this the index is too
/// far behind to be worth using.
pub const MAX_UNINDEXED_SPAN: u32 = 1024;

/// Attempts to fetch one block while the node tip keeps moving.
const MAX_STALE_TIP_RETRIES: usize = 5;

/// The consensus mining-reward ErgoTree for `pubkey`, which pays rewards to
/// an address no P2PK lookup finds. Same 54 bytes as
/// `ErgoTreePredef.rewardOutputScript(720, ProveDlog(pubkey))`; the layout is
/// pinned against real mainnet reward boxes in `ergo-mining::reward_script`
/// and recognised by `ergo_wallet::proving::miner_reward`, which this module's
/// tests check it against.
pub fn reward_script(pubkey: &[u8; 33]) -> Vec<u8> {
    const PREFIX: [u8; 7] = [0x10, 0x02, 0x04, 0xa0, 0x0b, 0x08, 0xcd];
    const SUFFIX: [u8; 14] = [
        0xea, 0x02, 0xd1, 0x92, 0xa3, 0x9a, 0x8c, 0xc7, 0xa7, 0x01, 0x73, 0x00, 0x73, 0x01,
    ];
    let mut script = Vec::with_capacity(PREFIX.len() + pubkey.len() + SUFFIX.len());
    script.extend_from_slice(&PREFIX);
    script.extend_from_slice(pubkey);
    script.extend_from_slice(&SUFFIX);
    script
}

/// The two ErgoTrees the wallet matches for a key: the plain P2PK script and
/// the mining-reward script.
pub fn key_trees(pubkey: &[u8; 33]) -> Result<[Vec<u8>; 2], WalletServiceError> {
    let p2pk = ergo_ser::address::build_p2pk_tree_bytes(pubkey).map_err(|error| {
        WalletServiceError::InvalidRequest(format!("tracked pubkey is not valid: {error:?}"))
    })?;
    Ok([p2pk, reward_script(pubkey)])
}

/// How far a backfill reaches.
#[derive(Debug, Clone)]
pub enum BackfillTarget {
    /// A store being seeded from nothing: everything the index has up to a
    /// margin below the tip. The result carries the cursor the store is then
    /// valid at.
    ToTip,
    /// A wallet already valid at this cursor: only blocks up to it, so the
    /// regular sync supplies the rest.
    UpTo(ChainCursor),
}

#[derive(Debug, Error)]
pub enum AddressIndexError {
    /// The node cannot answer from its index, or the index and the chain
    /// disagree. Never "no history": the caller scans the blocks instead.
    #[error("address index unavailable: {0}")]
    Unavailable(String),
    #[error("backfill cancelled")]
    Cancelled,
    /// A node request failed. Retryable kinds are the caller's to retry.
    #[error("chain failure: {0}")]
    Chain(ChainClientError),
    #[error("wallet store failure: {0}")]
    Store(#[from] WalletStoreError),
    #[error("wallet service failure: {0}")]
    Service(#[from] WalletServiceError),
}

impl From<ChainClientError> for AddressIndexError {
    fn from(error: ChainClientError) -> Self {
        match error {
            // The node answering "I cannot" is a reason to scan, not to fail.
            ChainClientError::Unsupported
            | ChainClientError::UnsupportedHistory { .. }
            | ChainClientError::HistoryPruned { .. } => Self::Unavailable(error.to_string()),
            other => Self::Chain(other),
        }
    }
}

/// Which keys the index has seen used, and how far the index had got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyUsage {
    pub indexed_height: u32,
    pub used: Vec<bool>,
}

/// What a backfill applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackfillReport {
    /// The block the written state is valid at: the target cursor for
    /// [`BackfillTarget::UpTo`], the margin-adjusted index height otherwise.
    pub cursor: ChainCursor,
    /// Blocks fetched and applied.
    pub blocks_applied: u32,
}

impl WalletService {
    /// For each pubkey, whether the node's address index has ever seen a
    /// transaction touch its P2PK or mining-reward script. `Ok(None)` when the
    /// node cannot answer from an index.
    pub fn indexed_key_usage(
        &self,
        network: NetworkPrefix,
        pubkeys: &[[u8; 33]],
    ) -> Result<Option<KeyUsage>, AddressIndexError> {
        let mut trees = Vec::with_capacity(pubkeys.len() * 2);
        for pubkey in pubkeys {
            trees.extend(key_trees(pubkey)?);
        }
        let Some(used) = self.chain().addresses_used(network, &trees)? else {
            return Ok(None);
        };
        if used.used.len() != trees.len() {
            return Err(AddressIndexError::Unavailable(
                "address index answered for the wrong number of addresses".to_string(),
            ));
        }
        Ok(Some(KeyUsage {
            indexed_height: used.indexed_height,
            used: used
                .used
                .chunks(2)
                .map(|pair| pair.iter().any(|used| *used))
                .collect(),
        }))
    }

    /// Apply, into `write`, the history of `keys` from the blocks the node's
    /// address index names. The caller commits (or drops) the transaction, so
    /// a failure part-way leaves nothing behind, and finishes the state the
    /// target implies (cursor, maturity promotion).
    ///
    /// `keys` are `(tracked index, pubkey)` pairs, the shape the apply
    /// functions already take.
    pub fn backfill_from_index(
        &self,
        write: &mut dyn WalletWrite,
        network: NetworkPrefix,
        keys: &[(u64, [u8; 33])],
        target: &BackfillTarget,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<BackfillReport, AddressIndexError> {
        let mut trees = Vec::with_capacity(keys.len() * 2);
        let mut p2pk_trees = BTreeSet::new();
        let mut pubkeys = BTreeMap::new();
        for (index, pubkey) in keys {
            let [p2pk, reward] = key_trees(pubkey)?;
            p2pk_trees.insert(p2pk.clone());
            pubkeys.insert(*index, *pubkey);
            trees.push(p2pk);
            trees.push(reward);
        }
        let mut tip = self.chain().committed_tip()?;
        let history = self
            .chain()
            .address_history(network, &trees)?
            .ok_or_else(|| {
                AddressIndexError::Unavailable("the node has no usable address index".to_string())
            })?;
        let safe = history
            .indexed_height
            .min(tip.height)
            .saturating_sub(SEED_MARGIN);
        let last = match target {
            BackfillTarget::ToTip => safe,
            BackfillTarget::UpTo(cursor) => cursor.height,
        };
        if last > tip.height {
            // A node briefly behind the wallet (restart, shallow reorg) is a
            // reason to retry later, not to throw the wallet's history away.
            return Err(AddressIndexError::Chain(ChainClientError::Unavailable(
                "wallet cursor is ahead of the node tip".to_string(),
            )));
        }
        // Heights to read, each with what the index claimed about it. A height
        // the index cannot vouch for (past `safe`) is read with no claim.
        let mut wanted: BTreeMap<u32, Vec<IndexedTransaction>> = BTreeMap::new();
        for transaction in history.transactions {
            if transaction.height <= safe.min(last) {
                wanted
                    .entry(transaction.height)
                    .or_default()
                    .push(transaction);
            }
        }
        if last > safe {
            if last - safe > MAX_UNINDEXED_SPAN {
                return Err(AddressIndexError::Unavailable(format!(
                    "the index is {} blocks behind the wallet",
                    last - safe
                )));
            }
            for height in safe + 1..=last {
                wanted.entry(height).or_default();
            }
        }

        let mut blocks_applied = 0u32;
        let mut last_block_id = None;
        for (height, claimed) in wanted {
            if cancelled() {
                return Err(AddressIndexError::Cancelled);
            }
            let block = self.fetch_block(height, &mut tip)?;
            check_claims(height, &block, &claimed)?;
            if height == last {
                last_block_id = Some(block.block_id);
            }
            let block = self.convert_block(block)?;
            write.backfill_block(height, &p2pk_trees, &pubkeys, &block)?;
            blocks_applied += 1;
        }
        let cursor = match target {
            BackfillTarget::UpTo(cursor) => {
                // The wallet's own position must be on the chain the blocks
                // came from, or what was applied belongs to another fork.
                if cursor.height > 0 {
                    let id = match last_block_id {
                        Some(id) => id,
                        None => self.fetch_block(cursor.height, &mut tip)?.block_id,
                    };
                    if id != cursor.header_id {
                        return Err(AddressIndexError::Unavailable(
                            "wallet cursor is not on the node's best chain".to_string(),
                        ));
                    }
                }
                cursor.clone()
            }
            BackfillTarget::ToTip if last == 0 => ChainCursor::genesis(),
            BackfillTarget::ToTip => ChainCursor {
                height: last,
                header_id: match last_block_id {
                    Some(id) => id,
                    None => self.fetch_block(last, &mut tip)?.block_id,
                },
            },
        };
        write.promote_matured(cursor.height)?;
        Ok(BackfillReport {
            cursor,
            blocks_applied,
        })
    }

    /// One block by height. The node answers only for its exact current tip,
    /// so a tip that moved mid-backfill is re-read and the request repeated;
    /// the claims check on each block is what ties the blocks together.
    fn fetch_block(
        &self,
        height: u32,
        tip: &mut CommittedTip,
    ) -> Result<ChainBlock, AddressIndexError> {
        for _ in 0..MAX_STALE_TIP_RETRIES {
            match self.chain().block_at(height, tip.clone()) {
                Ok(block) => return Ok(block),
                Err(ChainClientError::StaleTip { actual, .. }) => *tip = actual,
                Err(error) => return Err(error.into()),
            }
        }
        Err(AddressIndexError::Unavailable(
            "the node tip kept changing".to_string(),
        ))
    }
}

/// The index named this block and these transactions in it; the chain must
/// agree, or the index is describing a different history.
fn check_claims(
    height: u32,
    block: &ChainBlock,
    claimed: &[IndexedTransaction],
) -> Result<(), AddressIndexError> {
    let ids: BTreeSet<TxId> = block.transactions.iter().map(|tx| tx.tx_id).collect();
    for claim in claimed {
        if claim.block_id != block.block_id || !ids.contains(&claim.tx_id) {
            return Err(AddressIndexError::Unavailable(format!(
                "the address index and the chain disagree at height {height}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBKEY: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    #[test]
    fn the_reward_script_is_the_one_the_wallet_recognises_as_a_miner_reward() {
        let script = reward_script(&PUBKEY);
        assert_eq!(script.len(), 54);
        assert_eq!(
            ergo_wallet::proving::miner_reward::extract_miner_reward_pubkey(&script),
            Some(PUBKEY)
        );
    }

    #[test]
    fn a_key_is_looked_up_by_its_plain_and_its_reward_script() {
        let [p2pk, reward] = key_trees(&PUBKEY).unwrap();
        assert_eq!(
            p2pk,
            ergo_ser::address::build_p2pk_tree_bytes(&PUBKEY).unwrap()
        );
        assert_eq!(reward, reward_script(&PUBKEY));
        assert_ne!(p2pk, reward);
    }
}
