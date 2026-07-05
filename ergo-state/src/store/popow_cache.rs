//! NiPoPoW serve + apply surface: PoPow proof construction
//! (`prove_with_db`), the on-disk serve cache (`get_cached` /
//! `set_cached` / `compute_and_cache_dense`), the
//! `PoPowHeader`-by-id / by-height assemblers, the apply-time
//! recompute hook (`maybe_recompute_popow_proof`, called from
//! `apply.rs::apply_utxo_changes`), and the sparse-bootstrap
//! `apply_popow_proof` writer that persists the prefix + suffix
//! header chain.
//!
//! Sibling of `mod.rs`; pure `impl StateStore { ... }` relocation.
//! The atomic-commit envelope inside `apply_popow_proof` is one
//! `begin_write -> all-tables-update -> commit()` and remains a
//! single transactional unit after the move.

#![allow(clippy::too_many_lines)]

use super::*;

impl StateStore {
    /// Read the cached serve-side NiPoPoW proof bytes, if any. Set
    /// by [`Self::compute_and_cache_popow_proof_dense`] or by
    /// future apply-time hooks. Empty/missing on a node that has
    /// never run the compute path (e.g. fresh boot, sparse-mode
    /// nodes — those can't serve per Phase 0 §8.4 anyway).
    pub fn get_cached_popow_proof_bytes(&self) -> Result<Option<Vec<u8>>, StateError> {
        let read_txn = self.db.begin_read()?;
        match read_txn.open_table(STATE_META) {
            Ok(table) => match table.get(Self::CACHED_POPOW_PROOF_KEY)? {
                Some(guard) => Ok(Some(guard.value().to_vec())),
                None => Ok(None),
            },
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Persist `bytes` as the cached NiPoPoW serve-side proof.
    /// One atomic write to `STATE_META`. Overwrites any prior cache.
    pub fn set_cached_popow_proof_bytes(&self, bytes: &[u8]) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut table = write_txn.open_table(STATE_META)?;
            table.insert(Self::CACHED_POPOW_PROOF_KEY, bytes)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Load a `PoPowHeader` for the given `header_id`: header bytes
    /// from `HEADERS`, the matching `Extension` from `BLOCK_SECTIONS`
    /// (keyed by `blake2b(0x68 ++ header_id ++ extension_root)`),
    /// unpack interlinks via `unpack_interlinks`, and build the
    /// batch Merkle proof of the interlinks against the extension
    /// root via `build_popow_header`.
    ///
    /// Returns `Ok(None)` when either the header or its extension is
    /// missing locally (typical on pruned nodes or sparse-mode
    /// prefix). Returns `Ok(Some(_))` for fully-archived headers.
    ///
    /// Scala parity: `ErgoHistoryReader.popowHeader(id)` +
    /// `NipopowAlgos.unpackInterlinks` +
    /// `NipopowAlgos.proofForInterlinkVector`.
    pub fn popow_header_by_id(
        &self,
        header_id: &[u8; 32],
    ) -> Result<Option<ergo_ser::popow_header::PoPowHeader>, StateError> {
        match self.popow_header_by_id_strict(header_id)? {
            PopowByIdLookup::Found(p) => Ok(Some(*p)),
            PopowByIdLookup::HeaderMissing | PopowByIdLookup::ExtensionMissing => Ok(None),
        }
    }

    /// Stricter variant of [`Self::popow_header_by_id`] that
    /// distinguishes the three failure modes so callers can
    /// classify each one correctly:
    ///
    /// - [`PopowByIdLookup::Found`] — header + extension both
    ///   present, popow assembled.
    /// - [`PopowByIdLookup::HeaderMissing`] — HEADERS table has no
    ///   row for `header_id`. Callers that obtained `header_id`
    ///   from `HEADER_CHAIN_INDEX` should treat this as
    ///   cross-table corruption ([`StateError::DbCorruption`]).
    /// - [`PopowByIdLookup::ExtensionMissing`] — header present
    ///   but `BLOCK_SECTIONS` has no extension for it. Callers
    ///   that need extension data should treat this as
    ///   archive-data absence ([`StateError::PopowDataMissing`]).
    pub(crate) fn popow_header_by_id_strict(
        &self,
        header_id: &[u8; 32],
    ) -> Result<PopowByIdLookup, StateError> {
        use ergo_primitives::reader::VlqReader;
        use ergo_ser::extension::read_extension;
        use ergo_ser::header::read_header;
        use ergo_validation::popow::algos::{build_popow_header, unpack_interlinks};

        let header_bytes = match self.get_header(header_id)? {
            Some(b) => b,
            None => return Ok(PopowByIdLookup::HeaderMissing),
        };
        // Each decode site below is a cross-table consistency check on
        // a stored row whose presence has already been confirmed; a
        // decode failure here is corruption of that row, not a
        // codec-edge error. DbCorruption carries the table/key context
        // operators need to identify the corrupt row.
        let header = {
            let mut r = VlqReader::new(&header_bytes);
            read_header(&mut r).map_err(|e| StateError::DbCorruption {
                table: "headers",
                key: hex::encode(header_id),
                reason: format!("popow_header_by_id_strict: header decode: {e}"),
            })?
        };
        let extension_id = ergo_ser::modifier_id::compute_section_id(
            ergo_ser::modifier_id::TYPE_EXTENSION,
            header_id,
            header.extension_root.as_bytes(),
        );
        let ext_bytes = match self.get_block_section(&extension_id)? {
            Some(b) => b,
            None => return Ok(PopowByIdLookup::ExtensionMissing),
        };
        let extension = {
            let mut r = VlqReader::new(&ext_bytes);
            read_extension(&mut r).map_err(|e| StateError::DbCorruption {
                table: "block_sections",
                key: hex::encode(extension_id),
                reason: format!("popow_header_by_id_strict: extension decode: {e}"),
            })?
        };
        let extension_fields: Vec<(Vec<u8>, Vec<u8>)> = extension
            .fields
            .iter()
            .map(|f| (f.key.to_vec(), f.value.clone()))
            .collect();
        let interlinks =
            unpack_interlinks(&extension_fields).map_err(|e| StateError::DbCorruption {
                table: "block_sections",
                key: hex::encode(extension_id),
                reason: format!("popow_header_by_id_strict: unpack_interlinks: {e}"),
            })?;
        let popow = build_popow_header(header, interlinks, &extension_fields).map_err(|e| {
            StateError::DbCorruption {
                table: "block_sections",
                key: hex::encode(extension_id),
                reason: format!("popow_header_by_id_strict: build_popow_header: {e}"),
            }
        })?;
        Ok(PopowByIdLookup::Found(Box::new(popow)))
    }

    /// Load the `PoPowHeader` at the canonical chain height `h`,
    /// looking up the id via `HEADER_CHAIN_INDEX`. Returns `Ok(None)`
    /// when no header exists at that height or its extension is
    /// missing.
    pub fn popow_header_at_height(
        &self,
        h: u32,
    ) -> Result<Option<ergo_ser::popow_header::PoPowHeader>, StateError> {
        let header_id = match self.get_header_id_at_height(h)? {
            Some(id) => id,
            None => return Ok(None),
        };
        self.popow_header_by_id(&header_id)
    }

    /// Scala parity: `NipopowProverWithDbAlgs.collectLevel`. Walks
    /// backward through the interlinks structure at the given
    /// `level`, accumulating popow headers until either
    /// `prev_header.height < anchoring_height` (stop signal) or the
    /// header has no interlinks entry at this level (chain too
    /// shallow at this level).
    fn collect_level(
        &self,
        start_prev_header_id: &ergo_primitives::digest::ModifierId,
        level: usize,
        anchoring_height: u32,
    ) -> Result<Vec<ergo_ser::popow_header::PoPowHeader>, StateError> {
        let mut acc: Vec<ergo_ser::popow_header::PoPowHeader> = Vec::new();
        let mut current_id = *start_prev_header_id.as_bytes();
        loop {
            // Walking interlinks: HEADERS miss = cross-table
            // corruption (the interlink target's header should exist
            // since the interlink pointer was minted from it).
            // ExtensionMissing is the archive-data-absent case
            // (legitimate on Mode 2 / pruned nodes).
            let prev = match self.popow_header_by_id_strict(&current_id)? {
                PopowByIdLookup::Found(p) => *p,
                PopowByIdLookup::HeaderMissing => {
                    return Err(StateError::DbCorruption {
                        table: "headers",
                        key: hex::encode(current_id),
                        reason: "collect_level: interlink target header missing from HEADERS"
                            .to_string(),
                    });
                }
                PopowByIdLookup::ExtensionMissing => {
                    return Err(StateError::PopowDataMissing {
                        what: "collect_level: interlink target extension absent (archive node?)",
                        at: PopowMissingAt::HeaderId(current_id),
                    });
                }
            };
            if prev.header.height < anchoring_height {
                break;
            }
            // Walk to the previous header at this level via interlinks.
            // Scala's `linksWithIndexes(prev).find(_._2 == level).map(_._1)`
            // — tail.reverse.zipWithIndex picks links[len-1-level] (the
            // entry at our `level` index after the reverse).
            let prev_links = &prev.interlinks;
            // links length must be > 1 (the tail is non-empty) and
            // the chosen level index must be in range.
            let next_prev_id_opt: Option<[u8; 32]> = if prev_links.len() > 1 {
                let tail = &prev_links[1..];
                // tail.reverse.zipWithIndex.find(_._2 == level).map(_._1)
                // = tail[tail.len() - 1 - level] if in bounds.
                if level < tail.len() {
                    let idx = tail.len() - 1 - level;
                    Some(*tail[idx].as_bytes())
                } else {
                    None
                }
            } else {
                None
            };
            acc.insert(0, prev);
            match next_prev_id_opt {
                Some(id) => current_id = id,
                None => break,
            }
        }
        Ok(acc)
    }

    /// Construct a NiPoPoW proof using the **interlinks-walk** strategy
    /// (Scala parity: `NipopowProverWithDbAlgs.prove`).
    ///
    /// This is the fast variant. Instead of walking every header and
    /// computing `max_level_of` for each (the in-memory
    /// [`ergo_validation::popow::algos::prove`] path, which costs
    /// O(chain_length) PoW recomputations on mainnet ~1.7M), this
    /// hops backward through the interlinks structure at each level.
    /// The number of hops at level `l` is approximately
    /// `chain_length / 2^l`; with aggressive `anchoringHeight`
    /// pruning across levels the total reads sum to a few hundred
    /// even for full mainnet.
    ///
    /// `header_id_opt = Some(id)` constructs a proof anchored at
    /// `id` as the suffix-head. `None` uses the chain's best header
    /// (offset back by `k` to get the suffix-head).
    ///
    /// Returns `Err` on precondition violation (chain too short,
    /// header lookup miss, malformed extension) or when sparse mode
    /// is in effect (sparse-mode nodes lack extension data and so
    /// cannot serve).
    pub fn prove_with_db(
        &self,
        m: u32,
        k: u32,
        header_id_opt: Option<[u8; 32]>,
    ) -> Result<ergo_ser::popow_proof::NipopowProof, StateError> {
        use ergo_validation::popow::algos::PoPowParams;

        if !matches!(
            self.chain_state.header_availability,
            HeaderAvailability::Dense
        ) {
            return Err(StateError::InvalidPrecondition {
                what: "prove_with_db: store is not in Dense mode",
            });
        }
        if k < 1 {
            return Err(StateError::InvalidPrecondition {
                what: "prove_with_db: k must be >= 1",
            });
        }
        // `m`/`k` are attacker-controlled on the REST path: checked add,
        // or a wrapped sum bypasses this guard (and the `- k + 1` anchor
        // arithmetic below it) in release builds.
        let needed_min = k.checked_add(m).ok_or(StateError::InvalidPrecondition {
            what: "prove_with_db: k + m overflows u32",
        })?;
        if self.chain_state.best_header_height < needed_min {
            return Err(StateError::EarlyIBD {
                needed_min,
                observed: self.chain_state.best_header_height,
            });
        }

        // Suffix selection: either anchored at header_id_opt (with k-1
        // headers after) or the last k headers from the canonical
        // chain. Track provenance so we can route a HEADERS-miss
        // differently for caller-supplied vs internally-derived ids.
        let (suffix_head_id, caller_supplied) = match header_id_opt {
            Some(id) => (id, true),
            None => (
                self.get_header_id_at_height(self.chain_state.best_header_height - k + 1)?
                    .ok_or(StateError::InternalInvariantAt {
                        what: "prove_with_db: suffix-head missing from HEADER_CHAIN_INDEX \
                               (best_header_height >= k+m gate passed; index should be populated)",
                        height: self.chain_state.best_header_height - k + 1,
                    })?,
                false,
            ),
        };
        // HEADERS-miss handling depends on provenance AND canonicity:
        // - internally-derived id (caller_supplied=false): the id
        //   came from HEADER_CHAIN_INDEX above, so HEADERS miss is
        //   unambiguously cross-table corruption. → DbCorruption.
        // - caller-supplied id (caller_supplied=true): ambiguous
        //   between bad anchor and HEADERS losing a row whose id is
        //   in HEADER_CHAIN_INDEX. We disambiguate by scanning
        //   HEADER_CHAIN_INDEX for the id (O(chain_length); error
        //   path only): if found → DbCorruption (real corruption),
        //   if not found → ProveWithDbAnchorNotFound (caller misuse).
        // ExtensionMissing is the same in both cases: legitimate
        // archive-data-absent state.
        let suffix_head = match self.popow_header_by_id_strict(&suffix_head_id)? {
            PopowByIdLookup::Found(p) => *p,
            PopowByIdLookup::HeaderMissing if caller_supplied => {
                match self.find_canonical_height_for_id(&suffix_head_id)? {
                    Some(canonical_h) => {
                        return Err(StateError::DbCorruption {
                            table: "headers",
                            key: hex::encode(suffix_head_id),
                            reason: format!(
                                "prove_with_db: caller-supplied anchor is canonical at h={canonical_h} but missing from HEADERS",
                            ),
                        });
                    }
                    None => {
                        return Err(StateError::ProveWithDbAnchorNotFound {
                            header_id: hex::encode(suffix_head_id),
                        });
                    }
                }
            }
            PopowByIdLookup::HeaderMissing => {
                return Err(StateError::DbCorruption {
                    table: "headers",
                    key: hex::encode(suffix_head_id),
                    reason: "prove_with_db: suffix_head id present in HEADER_CHAIN_INDEX \
                             but missing from HEADERS"
                        .to_string(),
                });
            }
            PopowByIdLookup::ExtensionMissing => {
                return Err(StateError::PopowDataMissing {
                    what: "prove_with_db: suffix_head (extension data not present locally)",
                    at: PopowMissingAt::HeaderId(suffix_head_id),
                });
            }
        };
        // suffix_tail: the k-1 headers immediately after suffix_head.
        let suffix_head_height = suffix_head.header.height;
        let mut suffix_tail: Vec<ergo_ser::header::Header> = Vec::with_capacity((k - 1) as usize);
        for h in (suffix_head_height + 1)..(suffix_head_height + k) {
            let header_id =
                self.get_header_id_at_height(h)?
                    .ok_or(StateError::InternalInvariantAt {
                        what: "prove_with_db: suffix_tail missing from HEADER_CHAIN_INDEX \
                           (index populated through tip by construction)",
                        height: h,
                    })?;
            let header_bytes =
                self.get_header(&header_id)?
                    .ok_or_else(|| StateError::DbCorruption {
                        table: "headers",
                        key: hex::encode(header_id),
                        reason: format!("suffix_tail header missing at h={h}"),
                    })?;
            use ergo_primitives::reader::VlqReader;
            use ergo_ser::header::read_header;
            let mut r = VlqReader::new(&header_bytes);
            // The id came from HEADER_CHAIN_INDEX and HEADERS just
            // confirmed the row exists; a decode failure on that row
            // is cross-table corruption (same shape as
            // last_applied_chain_window_10).
            let header = read_header(&mut r).map_err(|e| StateError::DbCorruption {
                table: "headers",
                key: hex::encode(header_id),
                reason: format!("prove_with_db: suffix_tail header decode at h={h}: {e}"),
            })?;
            suffix_tail.push(header);
        }

        // Prefix construction via interlinks walk + difficulty
        // headers (when continuous = true).
        let mut collected: std::collections::BTreeMap<u32, ergo_ser::popow_header::PoPowHeader> =
            std::collections::BTreeMap::new();

        // Genesis is always in the prefix. The walk is inlined as
        // height → id → popow so each step gets the right typed
        // error:
        // - `HEADER_CHAIN_INDEX` absent in Dense mode is a broken
        //   store invariant, not archive-data missing — the gate at
        //   the top of `prove_with_db` requires Dense, and
        //   `lookup_header_at_height` already treats Dense gaps as
        //   corruption signals. → `InternalInvariantAt`.
        // - `HEADERS` row missing for an id that came from
        //   `HEADER_CHAIN_INDEX` is cross-table corruption. →
        //   `DbCorruption`.
        // - Extension absent in `BLOCK_SECTIONS` is the canonical
        //   archive case: Mode 2 bootstrap (UTXO snapshot install,
        //   historical extensions never downloaded) lands here even
        //   when `blocks_to_keep = -1` advertises an archive role.
        //   Only Mode 1 native-archive nodes synced from genesis
        //   retain the full extension history. → `PopowDataMissing`.
        let genesis_id =
            self.get_header_id_at_height(1)?
                .ok_or(StateError::InternalInvariantAt {
                    what: "prove_with_db: HEADER_CHAIN_INDEX has no row at h=1 (Dense mode \
                       requires the index to be populated through tip)",
                    height: 1,
                })?;
        let genesis_popow = match self.popow_header_by_id_strict(&genesis_id)? {
            PopowByIdLookup::Found(p) => *p,
            PopowByIdLookup::HeaderMissing => {
                return Err(StateError::DbCorruption {
                    table: "headers",
                    key: hex::encode(genesis_id),
                    reason: "prove_with_db: genesis id present in HEADER_CHAIN_INDEX \
                             but missing from HEADERS"
                        .to_string(),
                });
            }
            PopowByIdLookup::ExtensionMissing => {
                return Err(StateError::PopowDataMissing {
                    what: "prove_with_db: genesis extension absent (only a Mode 1 node synced \
                           from genesis can serve; Mode 2 bootstrap leaves the prefix region \
                           without block-section data even if blocks_to_keep = -1)",
                    at: PopowMissingAt::Height(1),
                });
            }
        };
        collected.insert(1, genesis_popow);

        // Difficulty headers needed for continuous-mode validation.
        let chain_config = self.difficulty_params.clone();
        // Scala parity (NipopowProverWithDbAlgs.scala:95): the
        // difficulty-header schedule uses eip37EpochLength
        // UNCONDITIONALLY (`getOrElse`, no activation-height gate) —
        // even for pre-EIP-37 anchors. A height-gated selection here
        // omitted the 128-multiple headers Scala's verifier requires
        // for old anchors (T4 live differential, anchor h=1000).
        let epoch_length = chain_config
            .eip37_epoch_length
            .unwrap_or(chain_config.epoch_length);
        // Difficulty-header enrichment for continuous proofs. Each
        // height is *required* (the proof validator at
        // `ergo-validation::popow::proof::has_valid_difficulty_headers`
        // refuses to verify without them), so a miss must surface as
        // a typed error instead of being silently skipped — the
        // facade's None previously collapsed three distinct causes
        // into one indistinguishable absence.
        for h in difficulty_headers_needed(
            suffix_head_height,
            epoch_length,
            chain_config.use_last_epochs,
        ) {
            if h < suffix_head_height && h > 0 {
                let id =
                    self.get_header_id_at_height(h)?
                        .ok_or(StateError::InternalInvariantAt {
                            what: "prove_with_db: difficulty-header HEADER_CHAIN_INDEX miss \
                               (Dense mode requires the index to be populated through tip)",
                            height: h,
                        })?;
                let ph = match self.popow_header_by_id_strict(&id)? {
                    PopowByIdLookup::Found(p) => *p,
                    PopowByIdLookup::HeaderMissing => {
                        return Err(StateError::DbCorruption {
                            table: "headers",
                            key: hex::encode(id),
                            reason: format!(
                                "prove_with_db: difficulty-header id present in \
                                 HEADER_CHAIN_INDEX but missing from HEADERS (h={h})"
                            ),
                        });
                    }
                    PopowByIdLookup::ExtensionMissing => {
                        return Err(StateError::PopowDataMissing {
                            what: "prove_with_db: difficulty-header extension absent \
                                   (archive node lacks historical block-section data)",
                            at: PopowMissingAt::Height(h),
                        });
                    }
                };
                collected.insert(h, ph);
            }
        }

        // Interlinks walk: for each level from max down to 0,
        // collect headers reachable via interlinks back to the
        // current anchoring height. As each level finishes, advance
        // anchoring to the m-th from the end of the level's walk.
        self.prove_prefix_via_interlinks_walk(&suffix_head, m, &mut collected)?;

        let prefix: Vec<ergo_ser::popow_header::PoPowHeader> = collected.into_values().collect();

        let _params = PoPowParams {
            m,
            k,
            continuous: true,
        };
        Ok(ergo_ser::popow_proof::NipopowProof {
            m,
            k,
            prefix,
            suffix_head,
            suffix_tail,
            continuous: true,
        })
    }

    /// Scala parity: `NipopowProverWithDbAlgs.provePrefix` +
    /// `collectLevel`. Walks each μ-level from the suffix_head's
    /// maximum interlinks level down to 0, collecting popow headers
    /// reachable via the interlinks pointers. Advances
    /// `anchoring_height` after each level so subsequent levels
    /// don't re-collect.
    fn prove_prefix_via_interlinks_walk(
        &self,
        suffix_head: &ergo_ser::popow_header::PoPowHeader,
        m: u32,
        collected: &mut std::collections::BTreeMap<u32, ergo_ser::popow_header::PoPowHeader>,
    ) -> Result<(), StateError> {
        // Scala `linksWithIndexes`: header.interlinks.tail.reverse.zipWithIndex
        // i.e. drop the genesis entry (interlinks[0]), reverse, then
        // pair each with its level index (highest level first → 0
        // last after reverse).
        let links: Vec<(ergo_primitives::digest::ModifierId, usize)> =
            if suffix_head.interlinks.len() > 1 {
                suffix_head
                    .interlinks
                    .iter()
                    .skip(1)
                    .rev()
                    .cloned()
                    .enumerate()
                    .map(|(idx, link)| (link, idx))
                    .collect()
            } else {
                Vec::new()
            };

        // Scala's foldRight over levels: start with initAnchoringHeight = 1
        // (genesis), each level updates anchoring after walking.
        let mut anchoring_height: u32 = 1;
        // Scala iterates `levels.foldRight(initAnchoringHeight)`,
        // which processes levels in REVERSE of the zipWithIndex
        // order — i.e., from highest level down. Our `links` already
        // has level 0 last (after the .reverse.zipWithIndex). Iter
        // in reverse to start from highest.
        for (prev_id, level) in links.iter().rev() {
            let level_headers = self.collect_level(prev_id, *level, anchoring_height)?;
            for ph in &level_headers {
                collected.insert(ph.header.height, ph.clone());
            }
            if (m as usize) < level_headers.len() {
                // Advance anchor to the m-th from the END of this
                // level's walk (matches Scala
                // `levelHeaders(levelHeaders.length - m).height`).
                anchoring_height = level_headers[level_headers.len() - m as usize]
                    .header
                    .height;
            }
            // else: keep previous anchoring_height
        }
        Ok(())
    }

    /// Build a NiPoPoW proof from the locally-stored chain via the
    /// fast interlinks-walk variant and cache the serialized bytes
    /// for serve-side `GetNipopowProof` requests (Part 2 sub-phase 14.10).
    ///
    /// Now backed by [`Self::prove_with_db`] (Scala parity:
    /// `NipopowProverWithDbAlgs.prove`). Number of DB reads is
    /// O(chain_length / 2^level) summed across levels, which lands
    /// at a few hundred even for full mainnet. Compute time:
    /// seconds, not minutes.
    ///
    /// **Preconditions** (returns `Err` otherwise):
    /// - Store must be in `HeaderAvailability::Dense` mode. Sparse-
    ///   mode nodes lack extension data for the prefix and so cannot
    ///   serve proofs (Scala parity: `HeadersProcessor.scala:166-169`).
    /// - `best_header_height >= k + m` (need at least `k + m`
    ///   headers; the prove() function enforces this internally).
    /// - Every height in `[1, best_header_height - k]` must have a
    ///   header in `HEADER_CHAIN_INDEX` AND a corresponding extension
    ///   in `BLOCK_SECTIONS` (Mode 1 full-archive nodes only —
    ///   blocks_to_keep = -1).
    ///
    /// **Performance**: full-chain walk loads every extension and
    /// computes `max_level_of` (PoW hit) for every header. For
    /// mainnet at height ~1.7M this is slow (multi-minute, may need
    /// max_level caching in `HeaderMeta` for production use). For
    /// small chains (testnet, integration tests) it's fast.
    ///
    /// **Suggested invocation pattern**: lazy compute on inbound
    /// `GetNipopowProof` if no cached proof exists, OR triggered
    /// once per snapshot epoch from `apply_block` (the Scala pattern,
    /// `HeadersProcessor.scala:182-194`). Manual API only at this
    /// layer; orchestration is up to the caller.
    pub fn compute_and_cache_popow_proof_dense(
        &mut self,
        m: u32,
        k: u32,
    ) -> Result<usize, StateError> {
        let proof = self.prove_with_db(m, k, None)?;
        let bytes = ergo_ser::popow_proof::serialize_nipopow_proof(&proof)
            .map_err(|e| StateError::Serialization(e.to_string()))?;
        self.set_cached_popow_proof_bytes(&bytes)?;
        Ok(bytes.len())
    }

    pub fn apply_popow_proof(
        &mut self,
        proof: &ergo_ser::popow_proof::NipopowProof,
    ) -> Result<(), StateError> {
        use ergo_ser::difficulty::decode_compact_bits;
        use ergo_ser::header::serialize_header;

        // Precondition: apply only runs in Dense mode (the apply
        // path is the WRITER for PoPowSparse — re-apply on an
        // already-sparse store would clobber). We deliberately do NOT
        // gate on `best_header_height == 0`: normal header sync may
        // race ahead between boot and quorum-met, and the apply path
        // must still run so the chain can jump to the proof's suffix
        // tip. Any sub-suffix headers accepted by the racing normal
        // sync are left in HEADERS/HEADER_META (content-addressed,
        // harmless) but become unreachable via HEADER_CHAIN_INDEX
        // after this apply rewrites the index to the sparse layout.
        if !matches!(
            self.chain_state.header_availability,
            HeaderAvailability::Dense
        ) {
            // Caller-side precondition with runtime context preserved:
            // apply_popow_proof is the PoPowSparse writer; running it
            // from a non-Dense store would clobber. Operator triage
            // wants the actual mode + tip height to see what state the
            // store was in.
            return Err(StateError::ApplyPopowProofWrongMode {
                mode_description: format!("{:?}", self.chain_state.header_availability),
                best_header_height: self.chain_state.best_header_height,
            });
        }

        // Reciprocal precondition (Phase 1b — symmetric to
        // `install_snapshot_state`'s `best_full_block_height > 0`
        // refusal): once `install_snapshot_state` has run, the store
        // is full-state past the snapshot anchor. Running
        // `apply_popow_proof` against that store would downgrade
        // `header_availability` from Dense to PoPowSparse and could
        // persist a `best_header_height` (= suffix_tip_height) below
        // the already-installed `best_full_block_height` — a
        // chain-state invariant violation. The store-level guard
        // refuses this rather than relying on the orchestrator to
        // sequence the writers correctly.
        if self.chain_state.best_full_block_height > 0 {
            return Err(StateError::ApplyPopowProofRefused {
                current_full_block_height: self.chain_state.best_full_block_height,
            });
        }

        // Build the headers_chain in ascending-height order. Same shape
        // Scala's `NipopowProof.headersChain` produces
        // (`NipopowProof.scala:38-42`).
        let mut headers: Vec<ergo_ser::header::Header> =
            proof.prefix.iter().map(|p| p.header.clone()).collect();
        headers.push(proof.suffix_head.header.clone());
        headers.extend(proof.suffix_tail.iter().cloned());
        headers.sort_by_key(|h| h.height);

        if headers.is_empty() {
            // Defense-in-depth: `headers` is built as
            // `prefix ++ [suffix_head] ++ suffix_tail` and
            // `NipopowProof.suffix_head` is non-optional, so this
            // branch is unreachable today. If a future refactor makes
            // `suffix_head` optional or short-circuits the push, this
            // guard surfaces it as our-bug, not caller misuse.
            return Err(StateError::InternalInvariant {
                what: "apply_popow_proof: headers_chain empty after suffix_head merge",
            });
        }

        let k = proof.k;
        let suffix_head_height = proof.suffix_head.header.height;
        let suffix_tail_len = proof.suffix_tail.len() as u32;
        let dense_from = suffix_head_height.saturating_sub(k.saturating_sub(1));
        let dense_to = suffix_head_height.saturating_add(suffix_tail_len);

        // Per-header score map: for sparse prefix headers whose parent
        // is not in the proof, `parent_score = 0` and the row's
        // cumulative_score collapses to the header's own difficulty.
        // Matches Scala `HeadersProcessor.scala:138`:
        //   `score = scoreOf(h.parentId).getOrElse(BigInt(0)) + requiredDifficulty`.
        let mut score_map: std::collections::HashMap<[u8; 32], num_bigint::BigUint> =
            std::collections::HashMap::new();

        let suffix_tip_height = headers.last().unwrap().height;

        let write_txn = crate::begin_write_qr(&self.db)?;
        let new_cs;
        let mut suffix_tip_id = [0u8; 32];
        let mut suffix_tip_score = num_bigint::BigUint::ZERO;
        {
            let mut headers_table = write_txn.open_table(HEADERS)?;
            let mut header_meta_table = write_txn.open_table(HEADER_META)?;
            let mut chain_index_table = write_txn.open_table(HEADER_CHAIN_INDEX)?;
            // HEADERS_BY_HEIGHT mirrors Scala's `heightIdsKey` and
            // backs `/blocks/at/{h}`. Every proof header (dense suffix
            // AND sparse prefix) lands here so a Mode 3 / PoPoW-
            // bootstrapped node returns header ids at the heights it
            // actually has data for. The proof iterates in ascending
            // height with one header per height, so a plain
            // `append_orphan_to_height_index` puts each id at slot 0
            // (the row is empty when the proof apply runs against a
            // fresh chain). On re-apply, the existing row already
            // matches and the helper is a no-op.
            let mut height_idx = write_txn.open_table(HEADERS_BY_HEIGHT)?;

            for header in &headers {
                let (header_bytes, id_modifier) = serialize_header(header)
                    .map_err(|e| StateError::Serialization(e.to_string()))?;
                let id: [u8; 32] = *id_modifier.as_bytes();

                let difficulty = decode_compact_bits(header.n_bits);
                let parent_score = score_map
                    .get(header.parent_id.as_bytes())
                    .cloned()
                    .unwrap_or(num_bigint::BigUint::ZERO);
                let cumulative_score = parent_score + difficulty;
                score_map.insert(id, cumulative_score.clone());

                let meta = HeaderMeta {
                    parent_id: *header.parent_id.as_bytes(),
                    height: header.height,
                    cumulative_score: cumulative_score.to_bytes_be(),
                    pow_validity: 1, // verified by max_level_of during proof validation
                    timestamp: header.timestamp,
                };

                headers_table.insert(id.as_slice(), header_bytes.as_slice())?;
                header_meta_table.insert(id.as_slice(), meta.serialize().as_slice())?;

                // Mode 3 — SECTION_HEIGHT_INDEX participates in the
                // same atomic write_txn so a NiPoPoW-bootstrap DB's
                // dense suffix is serve-gate-ready from first boot.
                // Sparse-prefix headers populate the index too even
                // though their sections will likely never be served
                // (Mode 3 sentinel sits at `dense_from_height` post-
                // bootstrap, so prefix rows fall sub-sentinel and the
                // serve gate denies regardless of presence). Cheap to
                // write, defends against future shape changes.
                {
                    use ergo_ser::modifier_id::{
                        compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
                    };
                    let mut sh_idx = write_txn.open_table(SECTION_HEIGHT_INDEX)?;
                    for (type_byte, root) in [
                        (TYPE_AD_PROOFS, header.ad_proofs_root.as_bytes()),
                        (TYPE_BLOCK_TRANSACTIONS, header.transactions_root.as_bytes()),
                        (TYPE_EXTENSION, header.extension_root.as_bytes()),
                    ] {
                        let section_id = compute_section_id(type_byte, &id, root);
                        sh_idx.insert(section_id.as_slice(), header.height)?;
                    }
                }

                // HEADER_CHAIN_INDEX gets the dense suffix range ONLY —
                // prefix headers are content-addressed in HEADERS / HEADER_META
                // but not height-indexed (Phase 0 §5.1 + §5.2).
                if header.height >= dense_from && header.height <= dense_to {
                    chain_index_table.insert(header.height as u64, id.as_slice())?;
                }

                // HEADERS_BY_HEIGHT covers BOTH the sparse prefix and
                // the dense suffix — `/blocks/at/{h}` should return
                // ids at every height the store knows about, not just
                // the dense range. Use `promote_to_height_index_slot_0`
                // (not `append_orphan_*`) because the proof header IS
                // the canonical id at this height — if normal sync
                // raced ahead and wrote a different id at this height
                // first, the promote overrides slot 0 and demotes the
                // raced id to later. Per-height — no chain walk —
                // because the NiPoPoW proof's sparse prefix isn't a
                // height-contiguous chain, so a parent-walk helper
                // would break on the prefix gap.
                promote_to_height_index_slot_0(&mut height_idx, header.height, &id)?;

                if header.height == suffix_tip_height {
                    suffix_tip_id = id;
                    suffix_tip_score = cumulative_score;
                }
            }

            new_cs = ChainStateMeta {
                best_header_id: suffix_tip_id,
                best_header_height: suffix_tip_height,
                best_header_score: suffix_tip_score.to_bytes_be(),
                // Preserved unchanged — apply_popow_proof does not advance
                // full-block state. The Mode 2 snapshot bootstrap (gated
                // on `best_full_block_height == 0`) remains eligible.
                best_full_block_id: self.chain_state.best_full_block_id,
                best_full_block_height: self.chain_state.best_full_block_height,
                header_availability: HeaderAvailability::PoPowSparse {
                    dense_from_height: dense_from,
                    proof_suffix_height: suffix_head_height,
                },
            };
            let mut chain_meta_table = write_txn.open_table(CHAIN_STATE_META)?;
            chain_meta_table.insert("chain_state", new_cs.serialize().as_slice())?;

            // Mark hci_version=1 so the next reopen does NOT attempt
            // a dense backfill walk against the sparse store.
            let mut state_meta_table = write_txn.open_table(STATE_META)?;
            state_meta_table.insert("hci_version", [1u8].as_slice())?;
        }
        // Mode 3 Phase 1b — co-commit the prune low-water mark at
        // `dense_from_height` (the first dense-coverage height —
        // no `+1`). Writing here is the only point where
        // `dense_from_height` is definitively known; deferring
        // would force a derivation from `header_availability`
        // post-facto and re-introduce the bootstrap-vs-tip
        // ambiguity that the symmetric Mode 2 path solved by
        // writing at install time. Max-style via
        // `advance_minimal_full_block_height_in_txn`, so a prior
        // `install_snapshot_state` having pinned the sentinel
        // higher (e.g. `snapshot_height + 1 > dense_from_height`)
        // is a silent no-op rather than a transaction abort.
        StateStore::advance_minimal_full_block_height_in_txn(&write_txn, dense_from)?;
        write_txn.commit()?;

        // Refresh in-memory chain_state after the atomic commit.
        self.chain_state = ChainState::from_persisted(&new_cs);

        // Anticipated-snapshot-anchor observability. Scala's serve
        // side anchors proofs at `snapshot_height -
        // LastHeadersInContext (=10)` per
        // `HeadersProcessor.scala:179`, so `suffix_head.height ≈
        // next_snapshot - 10`. If Mode 2 later discovers a
        // `snapshot_height` that doesn't match this prediction, the
        // bounded forward catchup needs a larger window than
        // expected — an operator-visible signal. Logging the
        // anticipated anchor here lets a `tail -f` reader confirm
        // parity against Mode 2 discovery downstream.
        let anticipated_snapshot_height = suffix_head_height.saturating_add(10);
        info!(
            suffix_tip_height,
            dense_from,
            dense_to,
            headers_written = headers.len(),
            anticipated_snapshot_height,
            "NiPoPoW proof applied → PoPowSparse mode",
        );

        Ok(())
    }

    /// Apply-time snapshot-epoch hook for the NiPoPoW serve cache.
    /// Fires when
    /// `height % MAKE_SNAPSHOT_EVERY == MAKE_SNAPSHOT_EVERY - 1 - LAST_HEADERS_IN_CONTEXT`
    /// (the same offset Scala uses at `HeadersProcessor.scala:179`).
    /// Mainnet `MAKE_SNAPSHOT_EVERY = 52224`, so triggers at heights
    /// 52213, 104437, 156661, ... (~once per ~3 days at 2-min blocks).
    ///
    /// No-op on sparse-mode stores (no extension data available).
    /// Failure is logged at warn but does NOT propagate — the block
    /// apply already committed.
    pub(super) fn maybe_recompute_popow_proof(&mut self, height: u32) {
        // Mainnet `makeSnapshotEvery` value from Scala
        // `mainnet.conf::chain.makeSnapshotEvery`. Held as a module
        // constant; lift to DifficultyParams when a non-mainnet
        // network requires a different value.
        const MAKE_SNAPSHOT_EVERY: u32 = 52224;
        const LAST_HEADERS_IN_CONTEXT: u32 = 10;
        const PROVE_M: u32 = 6;
        const PROVE_K: u32 = 10;
        let trigger_offset = MAKE_SNAPSHOT_EVERY - 1 - LAST_HEADERS_IN_CONTEXT;
        if !height.is_multiple_of(MAKE_SNAPSHOT_EVERY) {
            if height % MAKE_SNAPSHOT_EVERY != trigger_offset {
                return;
            }
        } else {
            // height % MAKE_SNAPSHOT_EVERY == 0 (edge: epoch
            // boundary); not a trigger.
            return;
        }
        if !matches!(
            self.chain_state.header_availability,
            HeaderAvailability::Dense
        ) {
            return;
        }
        let t0 = std::time::Instant::now();
        match self.compute_and_cache_popow_proof_dense(PROVE_M, PROVE_K) {
            Ok(bytes) => {
                info!(
                    height,
                    bytes,
                    elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0,
                    "NiPoPoW serve-side proof recomputed at snapshot epoch",
                );
            }
            Err(e) => {
                warn!(
                    height,
                    error = %e,
                    elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0,
                    "NiPoPoW serve-side proof recompute failed (apply commit unaffected)",
                );
            }
        }
    }
}
