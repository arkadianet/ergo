//! Block-apply seam for [`super::DigestStateStore`]: the atomic
//! `apply_block_digest` commit plus the `ChainStateRead` /
//! `HeaderSectionStore` / `BlockApply` backend-trait impls (including
//! the `apply_full_block` ADProofs-verify-then-commit forwarding).
//!
//! Sibling of `mod.rs`; pure impl relocation.

use crate::active_params;
use crate::chain::{ChainStateMeta, HeaderMeta};
use crate::store::StateError;
use ergo_validation::{ActiveProtocolParameters, ErgoValidationSettings};

use super::{
    chain_state_internal_invariant, DigestStateStore, CHAIN_STATE_HISTORY, CHAIN_STATE_KEY,
    DIGEST_HISTORY, ROOT_DIGEST_KEY,
};

impl DigestStateStore {
    /// Apply a block in digest mode. Atomically commits
    /// `(DIGEST_HISTORY[prev_height], CHAIN_STATE_HISTORY[prev_height],
    /// STATE_META["root_digest"], CHAIN_STATE_META["chain_state"],
    /// CHAIN_INDEX[new_height], voted_params if epoch boundary)`
    /// inside one redb write_txn.
    ///
    /// Pre-flight: `new_chain_state.best_full_block_height` must be
    /// exactly `self.height() + 1` — digest-mode apply has no
    /// skip-or-replay semantics. The caller (Mode 5 orchestrator)
    /// constructs the full `ChainStateMeta` because the score and
    /// availability fields originate at the header / NiPoPoW layer
    /// the orchestrator owns.
    ///
    /// The caller is also responsible for having already run the
    /// in-memory apply (see `crate::digest_apply::DigestProofVerifier`)
    /// and confirmed `new_root_digest == header.state_root`. This
    /// seam commits only — it does not re-verify the proof.
    pub fn apply_block_digest(
        &mut self,
        new_root_digest: [u8; 33],
        new_chain_state: ChainStateMeta,
        voted_params_row: Option<ActiveProtocolParameters>,
    ) -> Result<(), StateError> {
        let new_height = new_chain_state.best_full_block_height;
        let prev_height = self.height();
        if new_height != prev_height + 1 {
            return Err(StateError::ApplyOutOfOrder {
                expected_next: prev_height + 1,
                got: new_height,
            });
        }
        // Internal fork-choice invariants on the caller-supplied
        // chain state (best_header must lead or equal best_full_block;
        // score is never empty). Full validation of best_header_*
        // against persisted header state needs the header tables this
        // sibling does not own; these cheap invariants catch an
        // obviously-nonsense best-header view at the seam.
        if let Err(reason) = chain_state_internal_invariant(&new_chain_state) {
            return Err(StateError::InvalidPrecondition { what: reason });
        }
        // A co-committed voted-params row must land only at a real
        // epoch boundary and must be keyed to this block's height —
        // the same two-part guard Mode 1's `persist_apply` applies.
        // The first check stops a row at a non-epoch-start height;
        // the second stops a row keyed to the wrong epoch (which
        // `compute_validation_settings_at` would later fold into the
        // wrong active parameters) and also prevents clobbering the
        // genesis row (key 0), since `new_height >= 1` here. These
        // are caller-misuse conditions (`voted_params_row` is an
        // argument, not on-disk data), hence `InvalidPrecondition`.
        if let Some(p) = &voted_params_row {
            if !(new_height.is_multiple_of(self.voting_settings.voting_length) && new_height > 0) {
                return Err(StateError::InvalidPrecondition {
                    what: "voted_params_row supplied at non-epoch-start height",
                });
            }
            if p.epoch_start_height != new_height {
                return Err(StateError::InvalidPrecondition {
                    what: "voted_params_row.epoch_start_height != block height",
                });
            }
        }
        let prev_root = self.root_digest;
        let prev_chain_state_bytes = self.chain_state.serialize();
        let new_chain_state_bytes = new_chain_state.serialize();

        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            // 1. Record the digest we're moving AWAY from at its
            //    height — rollback_to(prev_height) restores from
            //    here.
            let mut history = write_txn.open_table(DIGEST_HISTORY)?;
            history.insert(prev_height as u64, &prev_root[..])?;
            drop(history);

            // 2. Record the chain state we're moving AWAY from,
            //    paired with the digest row. Restored together.
            let mut state_history = write_txn.open_table(CHAIN_STATE_HISTORY)?;
            state_history.insert(prev_height as u64, prev_chain_state_bytes.as_slice())?;
            drop(state_history);

            // 3. Advance STATE_META["root_digest"] to the new value.
            let mut meta = write_txn.open_table(crate::store::STATE_META)?;
            meta.insert(ROOT_DIGEST_KEY, &new_root_digest[..])?;
            drop(meta);

            // 4. Advance CHAIN_STATE_META["chain_state"] —
            //    authoritative chain pointers.
            let mut chain_state_table = write_txn.open_table(crate::store::CHAIN_STATE_META)?;
            chain_state_table.insert(CHAIN_STATE_KEY, new_chain_state_bytes.as_slice())?;
            drop(chain_state_table);

            // 5. Advance CHAIN_INDEX with the new best-block pointer.
            let mut chain_index = write_txn.open_table(crate::store::CHAIN_INDEX)?;
            chain_index.insert(new_height as u64, &new_chain_state.best_full_block_id[..])?;
            drop(chain_index);

            // 6. Optional voted-params row at epoch boundaries.
            //    Same write_txn so a crash before commit rolls the
            //    params row back with the digest.
            if let Some(p) = voted_params_row {
                active_params::insert(&write_txn, &p).map_err(|e| {
                    StateError::VotedParamsWriteFailed {
                        op: "digest-mode apply",
                        height: new_height,
                        source: Box::new(e),
                    }
                })?;
            }
        }
        write_txn.commit()?;

        self.root_digest = new_root_digest;
        self.chain_state = new_chain_state;
        self.refresh_cached_params_post_commit();
        Ok(())
    }
}

impl crate::backend::ChainStateRead for DigestStateStore {
    fn height(&self) -> u32 {
        self.chain_state.best_full_block_height
    }
    fn chain_state_meta(&self) -> ChainStateMeta {
        self.chain_state.clone()
    }
    fn active_params(&self) -> &ActiveProtocolParameters {
        &self.active_params
    }
    fn validation_settings(&self) -> &ErgoValidationSettings {
        &self.validation_settings
    }
    fn read_minimal_full_block_height(&self) -> Result<u32, StateError> {
        // The digest backend does not prune (no Mode-3 retention floor),
        // so every full block down to genesis is retained.
        Ok(1)
    }
}

impl crate::backend::HeaderSectionStore for DigestStateStore {
    fn get_header(&self, header_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        self.headers.get_header(header_id)
    }
    fn get_header_meta(&self, header_id: &[u8; 32]) -> Result<Option<HeaderMeta>, StateError> {
        self.headers.get_header_meta(header_id)
    }
    fn get_header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        self.headers.get_header_id_at_height(height)
    }
    fn get_block_section(&self, modifier_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        // No persist pipeline to drain — the digest store commits header
        // and section writes synchronously, unlike the UTXO backend's
        // batched async commit, so the read sees committed state directly.
        self.headers.get_block_section(modifier_id)
    }
    fn get_section_height(&self, section_id: &[u8; 32]) -> Result<Option<u32>, StateError> {
        self.headers.get_section_height(section_id)
    }
    fn scan_header_chain_range(
        &self,
        lo: u32,
        hi: u32,
    ) -> Result<Vec<(u32, [u8; 32])>, StateError> {
        self.headers.scan_header_chain_range(lo, hi)
    }
    fn store_header(&self, header_id: &[u8; 32], header_bytes: &[u8]) -> Result<(), StateError> {
        self.headers.store_header(header_id, header_bytes)
    }
    fn store_validated_header(
        &mut self,
        header_id: &[u8; 32],
        header_bytes: &[u8],
        meta: &HeaderMeta,
        new_best: Option<(u32, Vec<u8>)>,
    ) -> Result<(), StateError> {
        // `self.chain_state` IS the persisted `ChainStateMeta`, so unlike
        // the UTXO backend there is no `to_persisted()` projection — pass
        // a clone, mirror it back only after the delegate commits.
        let mut cs_meta = self.chain_state.clone();
        let r = self.headers.store_validated_header(
            header_id,
            header_bytes,
            meta,
            new_best,
            &mut cs_meta,
        );
        if r.is_ok() {
            self.chain_state = cs_meta;
        }
        r
    }
    fn store_block_section_typed(
        &self,
        modifier_id: &[u8; 32],
        section_bytes: &[u8],
        section_type: u8,
    ) -> Result<(), StateError> {
        self.headers
            .store_block_section_typed(modifier_id, section_bytes, section_type)
    }
    fn begin_header_batch(&mut self) {
        self.headers.begin_header_batch()
    }
    fn flush_header_batch(&mut self) -> Result<(), StateError> {
        let cs_after = self.chain_state.clone();
        self.headers.flush_header_batch(&cs_after)
    }
    fn mark_session_invalid(&mut self, header_id: [u8; 32]) {
        self.session_invalids.insert(header_id);
    }
    fn invalidate_validation_branch(
        &mut self,
        header_id: [u8; 32],
    ) -> Result<Vec<[u8; 32]>, StateError> {
        // Digest-mode invalidity is session-scoped by contract (a stale local
        // parent root and a definitively bad block are observationally
        // identical here — see `BlockProcessError::DigestApply`), so there is
        // no durable branch flag to persist. The executor's validation-verdict
        // classifier does not route digest apply failures here; this satisfies
        // the shared trait for the non-incident path. Delegate the insert to
        // `mark_session_invalid` so it stays the single source of truth.
        self.mark_session_invalid(header_id);
        Ok(vec![header_id])
    }
    fn is_invalid(&self, header_id: &[u8; 32]) -> Result<bool, StateError> {
        Ok(self.session_invalids.contains(header_id))
    }
    fn reader_handle(&self) -> crate::reader::ChainStoreReader {
        crate::reader::ChainStoreReader::new(self.db.clone())
    }
    fn shutdown_cleanly(&mut self) -> Result<(), StateError> {
        // No persist pipeline to drain.
        Ok(())
    }
}

impl crate::backend::BlockApply for DigestStateStore {
    /// Apply a fully-validated block in digest mode. LINEAR-ONLY: the
    /// block's parent must be the committed tip. The block's ADProofs
    /// section (fetched from the section store, not carried by
    /// `CheckedBlock`) is verified against the parent digest and the
    /// header's `state_root`; the verified root is then committed
    /// atomically via [`Self::apply_block_digest`].
    fn apply_full_block(
        &mut self,
        block: &ergo_validation::block::CheckedBlock,
        voted_params_row: Option<ActiveProtocolParameters>,
        wallet_hook: Option<&dyn crate::wallet::WalletApplyHook>,
    ) -> Result<(), StateError> {
        // The digest backend stores no box arena, so it cannot drive a
        // wallet scan. Mode 5 gates the wallet routes off, so the
        // executor must never attach a hook here; a `Some` is a wiring
        // bug, surfaced loudly rather than silently dropping updates.
        if wallet_hook.is_some() {
            return Err(StateError::InvalidPrecondition {
                what: "digest backend received a wallet hook; Mode 5 has no box arena to scan",
            });
        }

        let header = block.header().header();

        // Linear-only preflight: reject a non-tip parent BEFORE any
        // proof work. Fork / non-tip-parent apply (sourcing the parent
        // root from DIGEST_HISTORY) is deferred. `apply_block_digest`
        // re-checks height at commit; doing it here avoids verifying a
        // proof we would then refuse to commit.
        let prev_height = self.chain_state.best_full_block_height;
        let new_height = header.height;
        if new_height != prev_height + 1 {
            return Err(StateError::ApplyOutOfOrder {
                expected_next: prev_height + 1,
                got: new_height,
            });
        }
        // Linear-only: the block's parent must BE the committed tip.
        // A non-tip parent is a fork / non-tip-parent block, deferred —
        // and crucially NOT invalid. We reject it here, before the
        // verifier (which is always seeded with OUR tip root) can
        // misclassify a foreign-parent block as session-invalid. At
        // genesis both sides are the all-zero genesis-parent sentinel,
        // so this also admits the height-1 block.
        let parent_id = *header.parent_id.as_bytes();
        if parent_id != self.chain_state.best_full_block_id {
            return Err(StateError::DigestNonLinearParent {
                height: new_height,
                expected: hex::encode(self.chain_state.best_full_block_id),
                got: hex::encode(parent_id),
            });
        }

        // Canonical header id via round-trip serialize — derived
        // identically to the verifier's own section-id gate, so the
        // section we look up is the one the gate re-derives.
        let (_, header_id_modifier) = ergo_ser::header::serialize_header(header)
            .map_err(|e| StateError::Serialization(format!("serialize_header: {e:?}")))?;
        let header_id = *header_id_modifier.as_bytes();
        let header_id_hex = hex::encode(header_id);
        let ad_proofs_id = ergo_ser::modifier_id::compute_section_id(
            ergo_ser::modifier_id::TYPE_AD_PROOFS,
            &header_id,
            header.ad_proofs_root.as_bytes(),
        );

        // Fetch the persisted ADProofs section. Absence is
        // data-availability (the proof has not been downloaded/stored
        // yet), NOT block invalidity — do not mark session-invalid.
        let section_bytes = self
            .headers
            .get_block_section(&ad_proofs_id)?
            .ok_or_else(|| StateError::DigestAdProofsSectionMissing {
                header_id: header_id_hex.clone(),
                ad_proofs_id: hex::encode(ad_proofs_id),
            })?;

        // Parse the section envelope and re-enforce the trailing-byte
        // and inner-header-id checks ingress performs, so a persisted
        // blob can never bypass them. A failure here is corruption of
        // our own stored section, not a consensus rejection of the
        // block.
        let mut reader = ergo_primitives::reader::VlqReader::new(&section_bytes);
        let ad_proofs = ergo_ser::ad_proofs::read_ad_proofs(&mut reader).map_err(|e| {
            StateError::DbCorruption {
                table: "block_sections",
                key: hex::encode(ad_proofs_id),
                reason: format!("ADProofs section failed to parse: {e:?}"),
            }
        })?;
        if !reader.is_empty() {
            return Err(StateError::DbCorruption {
                table: "block_sections",
                key: hex::encode(ad_proofs_id),
                reason: format!(
                    "ADProofs section has {} trailing byte(s) after the proof",
                    reader.remaining()
                ),
            });
        }
        if ad_proofs.header_id.as_bytes() != &header_id {
            return Err(StateError::DbCorruption {
                table: "block_sections",
                key: hex::encode(ad_proofs_id),
                reason: format!(
                    "ADProofs section carries header_id {} but is filed under header {header_id_hex}",
                    hex::encode(ad_proofs.header_id.as_bytes()),
                ),
            });
        }

        // Net box changes — Mode 1's exact builder, shared so the
        // digest verifier and the UTXO tree cannot diverge on the same
        // block's change set.
        let (to_remove, to_insert) =
            crate::store::StateStore::build_utxo_changes_checked(block.transactions())?;

        // Data-input lookups, in transaction order (duplicates kept) —
        // the `toLookup` prefix of Scala's `StateChanges.operations`
        // (`toLookup ++ toRemove ++ toAppend`). The ADProofs were
        // generated by replaying these lookups first, so the verifier
        // must consume them first to keep the proof stream aligned.
        let to_lookup: Vec<[u8; 32]> = block
            .transactions()
            .iter()
            .flat_map(|c| {
                c.transaction()
                    .data_inputs
                    .iter()
                    .map(|di| *di.box_id.as_bytes())
            })
            .collect();

        // Parent state root = the committed tip digest (linear path).
        let parent_state_root = self.root_digest();

        // Verify: root-hash gate + section-id gate + parent-seed +
        // lookups-then-removes-asc-then-inserts-asc replay + finalize +
        // cross-check computed == header.state_root. Every rejection is
        // treated as SESSION-scoped: mark the header invalid for this
        // session and refuse the block, without persisting invalidity
        // (the repo invariant is that only PoW invalidity persists).
        let new_root = match crate::digest_apply::DigestProofVerifier::apply_block_in_memory(
            ad_proofs_id,
            &ad_proofs.proof_bytes,
            header,
            &parent_state_root,
            &to_lookup,
            &to_remove,
            &to_insert,
        ) {
            Ok(root) => root,
            Err(e) => {
                self.session_invalids.insert(header_id);
                return Err(StateError::DigestApplyRejected {
                    header_id: header_id_hex,
                    reason: e.to_string(),
                });
            }
        };

        // Linear applicability (height == tip+1 AND parent == tip) was
        // established by the preflights above. Header acceptance has
        // already advanced `best_header_*` (the header is validated
        // before its full block), so applying the full block advances
        // only `best_full_block_*`. `apply_block_digest` enforces
        // height == prev+1, the `best_header >= best_full_block` shape
        // invariant, and epoch-boundary voted-params keying, then
        // commits atomically and refreshes the cached params — it does
        // NOT re-check parent identity, which is why the preflight
        // above owns that gate.
        let mut new_chain_state = self.chain_state.clone();
        new_chain_state.best_full_block_id = header_id;
        new_chain_state.best_full_block_height = new_height;

        self.apply_block_digest(new_root, new_chain_state, voted_params_row)
    }

    fn rollback_to(
        &mut self,
        target_height: u32,
        wallet_hook: Option<&dyn crate::wallet::WalletApplyHook>,
        rescan_guard: Option<&dyn crate::wallet::apply::RescanGuard>,
    ) -> Result<(), StateError> {
        // Same contract as apply: the digest backend has no wallet /
        // rescan pipeline, so a non-`None` hook or guard is a wiring
        // bug rather than something to silently ignore.
        if wallet_hook.is_some() || rescan_guard.is_some() {
            return Err(StateError::InvalidPrecondition {
                what: "digest backend received a wallet hook/rescan guard; Mode 5 has no wallet pipeline",
            });
        }
        DigestStateStore::rollback_to(self, target_height)
    }
}
