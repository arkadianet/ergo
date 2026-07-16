//! Pre-header + candidate validation context.
//!
//! These types are frozen at the start of candidate generation (step 5
//! of the pipeline) so that all transaction validation that follows sees
//! one coherent set of script-visible context — same `pre_header.*`
//! fields, same `last_headers`, same activated script version.
//!
//! Re-deriving any of these later (e.g. after a soft-fork rule
//! activates mid-generation) would change script behavior across the
//! candidate's own transactions. The freeze is the contract.

use ergo_primitives::digest::ADDigest;
use ergo_ser::header::Header;
use ergo_ser::sigma_value::AvlTreeData;

/// Header fields fixed before mining starts. Mirrors Scala's
/// `PreHeader` (`PreHeader.scala`) minus the AutolykosV2 fields, which
/// only get set after the miner solves the puzzle.
///
/// `votes` is always `[0, 0, 0]` in v1 — automatic voting bit selection
/// is deferred (the design plan documents this as out-of-scope for v1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePreHeader {
    /// Block version. Comes from active protocol parameters
    /// (`active_params.block_version`).
    pub version: u8,
    /// Parent header id at the moment generation started. The
    /// post-dry-run guard at v12 §5 step 14 compares this against the
    /// state's `best_full_block_id` to catch tip-flip races.
    pub parent_id: [u8; 32],
    /// Candidate height (`parent_header.height + 1`).
    pub height: u32,
    /// Candidate timestamp in milliseconds. Computed as
    /// `max(now_ms, parent_header.timestamp + 1)` so the chain time is
    /// monotonic.
    pub timestamp: u64,
    /// Difficulty target encoded as `nBits`. Either the parent's
    /// `n_bits` (non-retarget heights) or the recomputed retarget
    /// at epoch boundaries.
    pub n_bits: u32,
    /// Voting bits. Always `[0, 0, 0]` in v1.
    pub votes: [u8; 3],
    /// 33-byte compressed secp256k1 miner pubkey.
    pub miner_pubkey: [u8; 33],
}

/// All script-visible context frozen at generation time. Threaded
/// through every `validate_transaction` call during candidate
/// assembly, so all transactions see one coherent context.
///
/// The fields exactly mirror what an evaluator would observe via
/// `CONTEXT.{HEIGHT, headers, preHeader, LastBlockUtxoRootHash, ...}`
/// (script.rs:222-238).
#[derive(Debug, Clone)]
pub struct CandidateValidationContext {
    /// Frozen pre-header. Cloned into the final Header at v12 §5 step
    /// 15.
    pub pre_header: CandidatePreHeader,
    /// Derived once from `pre_header.version` and the cumulative
    /// validation settings at the tip. Re-deriving later would change
    /// evaluator behavior.
    pub activated_script_version: u8,
    /// Up to 10 applied headers, tip-first. `[0]` is the parent header. Fewer
    /// than 10 on an early chain and EMPTY for block 1 (genesis), matching the
    /// apply path's `load_last_headers` so build- and apply-time
    /// `CONTEXT.headers` agree. From `StateStore::last_applied_chain_window_10`.
    pub last_headers: Vec<Header>,
    /// AvlTreeData for `CONTEXT.LastBlockUtxoRootHash`, constructed
    /// from `parent_header.state_root` with all-ops-allowed flags and
    /// key_length=32 (matches the existing fallback at
    /// `ergo-validation/src/tx/script.rs:211-221`).
    pub last_block_utxo_root: AvlTreeData,
}

/// UTXO tree enabled-operations flags. Mirror of Scala's
/// `AllOperationsAllowed` for `LastBlockUtxoRootHash`. Pinned `true`
/// for all three: mainnet has never disabled any of them, and the
/// existing script-validation fallback at script.rs:216-220
/// reconstructs the same boolean triple from the parent header's
/// digest. Kept as named constants so a future hard-fork that
/// changes them is a single-file edit.
pub const ERGO_UTXO_INSERT_ALLOWED: bool = true;
pub const ERGO_UTXO_UPDATE_ALLOWED: bool = true;
pub const ERGO_UTXO_REMOVE_ALLOWED: bool = true;
/// Key length for `LastBlockUtxoRootHash`. 32-byte box ids. Signed `i32` to
/// match `AvlTreeData.key_length` (Scala `keyLength: Int`).
pub const ERGO_UTXO_KEY_LENGTH: i32 = 32;

/// Build the AvlTreeData for `CONTEXT.LastBlockUtxoRootHash` given the
/// parent block's state root. Matches the script-validation fallback
/// at script.rs:211-221.
pub fn build_last_block_utxo_root(parent_state_root: ADDigest) -> AvlTreeData {
    AvlTreeData {
        digest: parent_state_root.as_bytes().to_vec(),
        insert_allowed: ERGO_UTXO_INSERT_ALLOWED,
        update_allowed: ERGO_UTXO_UPDATE_ALLOWED,
        remove_allowed: ERGO_UTXO_REMOVE_ALLOWED,
        key_length: ERGO_UTXO_KEY_LENGTH,
        value_length_opt: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::ADDigest;

    // ----- happy path -----

    #[test]
    fn build_last_block_utxo_root_uses_pinned_constants() {
        let digest = ADDigest::from_bytes([0xABu8; 33]);
        let tree = build_last_block_utxo_root(digest);
        assert_eq!(tree.digest.as_slice(), &[0xABu8; 33]);
        assert!(tree.insert_allowed);
        assert!(tree.update_allowed);
        assert!(tree.remove_allowed);
        assert_eq!(tree.key_length, 32);
        assert_eq!(tree.value_length_opt, None);
    }

    #[test]
    fn pre_header_clones_byte_for_byte() {
        let p = CandidatePreHeader {
            version: 3,
            parent_id: [0x42u8; 32],
            height: 1_786_189,
            timestamp: 1_700_000_000_000,
            n_bits: 16_842_752,
            votes: [0, 0, 0],
            miner_pubkey: [0x02u8; 33],
        };
        let clone = p.clone();
        assert_eq!(p, clone);
    }
}
