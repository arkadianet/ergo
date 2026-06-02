//! Authenticated UTXO state for the Ergo Rust node.
//!
//! Sits on top of [`ergo_primitives`], [`ergo_ser`], and
//! [`ergo_validation`]. Provides the redb-backed [`store::StateStore`]
//! that block apply mutates, plus the supporting AVL+ tree
//! implementation and the read-only [`reader::ChainStoreReader`] view
//! used by the API layer and indexer.
//!
//! Module map:
//!
//! * [`store`] — `StateStore`: open / apply_block / rollback / reorg /
//!   genesis seed. Owns the redb `Database` handle and the in-memory
//!   `AvlTree`. The largest module in the crate.
//! * [`avl`] — AVL+ tree primitives: [`avl::node`],
//!   [`avl::tree`], [`avl::arena`] (cached disk arena),
//!   [`avl::digest`] (label / root-hash math), and
//!   [`avl::changelog`] (before-image undo log).
//! * [`reader`] — read-only view over committed state for the API
//!   layer; never holds a write lock on the store.
//! * [`persist`] — background persistence pipeline that batches AVL
//!   writes into a single redb commit and surfaces per-block apply
//!   results.
//! * [`diff`] — block-apply diff computation (added / removed /
//!   changed boxes) used by the indexer.
//! * [`chain`] — chain header index: best-header / best-full-block
//!   tracking and reorg-aware lookups.
//! * [`active_params`] — per-epoch voted-protocol-parameter persistence
//!   wired into the store at epoch boundaries.
//!
//! What is **not** here:
//!
//! * No transaction or block validation logic — that's `ergo-validation`.
//! * No P2P framing or fork-choice orchestration — `ergo-p2p` /
//!   `ergo-sync`.
//! * No mempool / unconfirmed-tx state — `ergo-mempool`.

pub(crate) mod active_params;
pub mod avl;
/// `StateBackend` trait family abstracting the UTXO and digest
/// persistence backends so the action loop can dispatch on
/// `state_type`. `pub(crate)` until the boot dispatch wires it in.
pub(crate) mod backend;
pub mod chain;
pub mod diff;
/// Mode 5 (digest-verifier) apply seam. `pub(crate)` until the
/// boot dispatch wires Mode 5 in from `ergo-node` — at that
/// point the seam needs to widen. Keeping it crate-scoped now
/// prevents external crates from depending on a Mode 5 surface
/// whose oracle coverage is not yet in tree.
pub(crate) mod digest_apply;
/// Mode 5 (digest-verifier) persistence backend — sibling type
/// to `crate::store::StateStore`. `pub(crate)` for the same
/// reason as `digest_apply`: the backend is wired through a
/// later phase's boot dispatch.
pub(crate) mod digest_store;
/// Mode 5 proof-backed `UtxoView` — resolves a block's input boxes
/// from its ADProofs (plus the block's outputs) so the digest backend
/// can run full transaction validation without a box arena.
pub(crate) mod digest_utxo_view;
/// Header + block-section tables extracted from `store::StateStore`
/// so a second backend can embed the same redb-backed header index.
pub(crate) mod header_store;
pub mod persist;
pub mod reader;
pub mod redb_util;
pub mod store;
pub mod wallet;

pub use redb_util::{begin_write_qr, open_with_repair_logging};

/// The state-backend dispatch surface NodeState binds against: the
/// `StateBackendKind` enum (UTXO arena or Mode 5 digest verifier) and
/// the three traits it implements.
pub use backend::{BlockApply, ChainStateRead, HeaderSectionStore, StateBackend, StateBackendKind};
pub use digest_store::DigestStateStore;

/// Mode 5 digest-apply surface the `ergo-sync` block-processing path
/// consumes: the proof verifier (resolves a block's input/data-input
/// boxes from its ADProofs while binding the proof to the header), its
/// error type, the resolved-box collection, and the proof-backed
/// `UtxoView` those boxes feed. Re-exported here because the modules
/// themselves stay `pub(crate)` while Mode 5's oracle coverage is
/// being completed.
pub use digest_apply::{DigestApplyError, DigestProofVerifier, ResolvedBoxes};
pub use digest_utxo_view::DigestUtxoView;

/// Test-only re-exports gated behind the `test-helpers` feature.
/// Not part of the public API.
#[cfg(feature = "test-helpers")]
pub mod test_helpers {
    use crate::store::{StateError, StateStore};
    use ergo_primitives::digest::ADDigest;
    use ergo_ser::transaction::Transaction;
    use ergo_validation::{ActiveProtocolParameters, CheckedTransaction};

    impl StateStore {
        /// Apply transactions without validation type enforcement.
        /// Only available with the `test-helpers` feature.
        pub fn apply_block_unchecked_for_test(
            &mut self,
            height: u32,
            header_id: &[u8; 32],
            expected_state_root: &ADDigest,
            transactions: &[Transaction],
        ) -> Result<(), StateError> {
            self.apply_block_unchecked(height, header_id, expected_state_root, transactions)
        }

        /// Same as `apply_block_unchecked_for_test` but lets the caller
        /// supply a `voted_params_row`, exercising the storage path that
        /// production block_proc uses on epoch-boundary blocks. Used by
        /// `tests/voted_params_lifecycle.rs`.
        pub fn apply_block_unchecked_for_test_with_voted_params(
            &mut self,
            height: u32,
            header_id: &[u8; 32],
            expected_state_root: &ADDigest,
            transactions: &[Transaction],
            voted_params_row: Option<ActiveProtocolParameters>,
        ) -> Result<(), StateError> {
            self.apply_block_unchecked_with_voted_params(
                height,
                header_id,
                expected_state_root,
                transactions,
                voted_params_row,
            )
        }

        /// Apply pre-validated transactions with caller-supplied header fields.
        /// Preserves the pre-CheckedBlock signature so chain-validation tests
        /// that drive `validate_transaction_parsed` in a loop (no real block
        /// header) can still exercise the CheckedTransaction apply path.
        /// Only available with the `test-helpers` feature.
        pub fn apply_block_checked_for_test(
            &mut self,
            height: u32,
            header_id: &[u8; 32],
            expected_state_root: &ADDigest,
            checked: &[CheckedTransaction],
        ) -> Result<(), StateError> {
            self.apply_checked_transactions(
                height,
                header_id,
                expected_state_root,
                checked,
                None,
                None,
            )
        }

        /// Same as `apply_block_checked_for_test` but lets the caller
        /// pass a wallet hook so the sync-path atomic wallet-apply
        /// seam can be exercised end-to-end. Used by the M5 atomic-
        /// commit tests.
        pub fn apply_block_checked_for_test_with_wallet(
            &mut self,
            height: u32,
            header_id: &[u8; 32],
            expected_state_root: &ADDigest,
            checked: &[CheckedTransaction],
            wallet_hook: &dyn crate::wallet::WalletApplyHook,
        ) -> Result<(), StateError> {
            let trees = wallet_hook.tracked_p2pk_trees();
            let pubkeys = wallet_hook.cached_pubkeys();
            let owned = crate::store::build_wallet_block_txs_checked(checked, height)?;
            let payload = crate::store::WalletApplyPayload {
                tracked_p2pk_trees: trees,
                cached_pubkeys: pubkeys,
                block_txs_owned: owned,
            };
            self.apply_checked_transactions(
                height,
                header_id,
                expected_state_root,
                checked,
                None,
                Some(&payload),
            )
        }

        /// Arm the Mode-2 trust-first-epoch sentinel directly. Production
        /// arming happens inside `install_snapshot_state`'s atomic
        /// write_txn (sentinel write co-committed with the chain_state
        /// update). Building a full snapshot in-test would require
        /// manifest + chunks fixtures the store does not yet expose;
        /// this helper writes only the sentinel via the same key the
        /// production path uses, so the open-time read at
        /// `store/open.rs` and the cross-crate consume path see the
        /// identical bytes.
        pub fn arm_mode2_trust_first_epoch_for_test(&mut self) -> Result<(), StateError> {
            self.arm_mode2_trust_first_epoch_internal()
        }

        /// Inject `best_full_block_id` + `best_full_block_height` into
        /// the persisted chain_state, leaving `header_availability` at
        /// its current value (typically Dense for a fresh store). Used
        /// to exercise apply / bootstrap precondition guards that
        /// require best_full > 0 without running a full snapshot
        /// install. Bypasses validation; tests must ensure the
        /// injected state is internally consistent for the property
        /// they assert.
        pub fn set_best_full_block_for_test(
            &mut self,
            id: [u8; 32],
            height: u32,
        ) -> Result<(), StateError> {
            self.set_best_full_block_internal_for_test_helpers(id, height)
        }

        /// Stamp `HEADERS_BY_HEIGHT[height]` slot 0 with the given
        /// `header_id`. Production populates this via the header
        /// validation pipeline (block_proc), which Phase 2a
        /// eviction tests bypass — `store_header` writes
        /// `HEADERS` + `MODIFIER_TYPE_INDEX` +
        /// `SECTION_HEIGHT_INDEX` but not the per-height index.
        /// Eviction reads from HEADERS_BY_HEIGHT to walk every
        /// header_id at a pruned height (Scala parity:
        /// `pruneBlockDataAt` flat-maps over `headerIdsAtHeight`),
        /// so the test fixture must seed this row directly.
        pub fn promote_header_to_height_index_for_test(
            &self,
            height: u32,
            header_id: &[u8; 32],
        ) -> Result<(), StateError> {
            self.promote_header_to_height_index_internal_for_test_helpers(height, header_id)
        }
    }

    use crate::chain::ChainStateMeta;
    use crate::digest_store::DigestStateStore;

    impl DigestStateStore {
        /// Seed the in-memory tip `(root_digest, chain_state)` directly.
        ///
        /// The Mode 5 executor-replay oracle (`ergo-sync`) seeds the digest
        /// store to a committed non-genesis tip so it can apply the corpus's
        /// sub-window without first replaying every block from genesis. The
        /// digest path reads `root_digest()` and `chain_state()` from these
        /// in-memory fields and `apply_block_digest` advances from them, so
        /// seeding them is sufficient to start a linear apply at `tip + 1`.
        /// Bypasses validation: the caller must supply an internally
        /// consistent state (height/parent matching the first applied block).
        pub fn seed_tip_for_test(&mut self, root_digest: [u8; 33], chain_state: ChainStateMeta) {
            self.set_tip_internal_for_test_helpers(root_digest, chain_state);
        }

        /// Insert (or overwrite) a `voted_params` row, then refresh the
        /// cached `active_params` / `validation_settings` from the committed
        /// tip. The replay oracle seeds the epoch-start row carrying the real
        /// mainnet parameters in effect for the window so the digest path's
        /// full validation runs against the parameters mainnet actually used.
        pub fn seed_voted_params_row_for_test(
            &mut self,
            params: &ActiveProtocolParameters,
        ) -> Result<(), StateError> {
            self.insert_voted_params_internal_for_test_helpers(params)
        }

        /// Stamp `HEADER_CHAIN_INDEX[height]` with `header_id` so the digest
        /// path's epoch-vote recompute (`compute_epoch_votes`, which resolves
        /// each prior-epoch header through `get_header_id_at_height`) finds the
        /// row. Production populates this through the header-validation
        /// pipeline; the replay oracle seeds it directly for the prior-epoch
        /// window it stores as orphans (orphan headers carry no best-chain
        /// index entry). The matching `HEADERS` / `HEADER_META` rows must be
        /// stored separately so the index never points at an absent header.
        pub fn seed_header_chain_index_for_test(
            &self,
            height: u32,
            header_id: &[u8; 32],
        ) -> Result<(), StateError> {
            self.set_header_chain_index_internal_for_test_helpers(height, header_id)
        }
    }

    /// Build an AVL+ tree from `pre_state` `(box_id, box_bytes)` entries,
    /// then derive the Mode-1 prover's `(post_state_root, proof_bytes)`
    /// for the given `to_remove` / `to_insert` change set — the exact
    /// witness the production proof producer emits. The Mode 5 genesis
    /// apply path consumes this witness, so an integration test can use
    /// it to manufacture a block's ADProofs section without reaching
    /// into the `pub(crate)` prover. Removes apply before inserts, both
    /// in BTreeMap-ascending key order, matching `apply_change_set_via_prover`.
    pub fn derive_ad_proofs_over_boxes(
        pre_state: &[([u8; 32], Vec<u8>)],
        to_remove: &std::collections::BTreeMap<[u8; 32], ()>,
        to_insert: &std::collections::BTreeMap<[u8; 32], Vec<u8>>,
    ) -> Result<([u8; 33], Vec<u8>), StateError> {
        let mut tree = crate::avl::tree::AvlTree::new();
        for (id, bytes) in pre_state {
            tree.insert(*id, bytes.clone());
        }
        let (root, proof) = crate::store::apply_change_set_via_prover(&tree, to_remove, to_insert)?;
        Ok((*root.as_bytes(), proof))
    }

    use ergo_primitives::reader::VlqReader;
    use ergo_ser::header::{read_header, Header};
    use ergo_ser::popow_header::PoPowHeader;
    use ergo_ser::popow_proof::NipopowProof;

    /// Mainnet headers 1..=8 in hex form. Required to construct a
    /// real `NipopowProof` for tests because the proof verifier
    /// walks the interlink graph and needs valid PoW solutions.
    pub const MAINNET_HEADERS_1_TO_8: &[&str] = &[
        "010000000000000000000000000000000000000000000000000000000000000000766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303f1f6cee9ba2d0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8060117650100000003be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb6602da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0000000030151dc631b7207d4420062aeb54e82b0cfb160ff6ace90ab7754f942c4c3266b",
        "01b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b828b0f6a0e6cb98ed4649c6e4cc00599ae78755324c79a8cec51e94ecca339d7a3a11a92de9c0ba1e95068f39bc1e08afa4ca23dff16de135fac64d0cf7dd1ab6291b70477f591ee8efb8a962d36ddbe3ac57591e39fe45ffb8c51c4939e41980387d9cfe9ba2d6b46bcba6f750f5be67d89679e921b78c277c5546a08cdb0955376fa0ea271e30601176502000000033c46c7fd7085638bf4bc902badb4e5a1942d3251d92d0eddd6fbe5d57e91553703df646d7f6138aede718a2a4f1a76d4125750e8ab496b7a8a25292d07e14cbadb0000000a03d0d0191b06164a2e86a170f0d8ac96cffa2e3312f2f5b0b1c3b1e082b9a0cd",
        "01855fc5c9eed868b43ea2c3df99ec17dd9d903187d891e2365a89b98125c994b2d80fc4ec24e7874760c6e42a8bce13791f15fe7f83d4cd055f614c25527a304b4202efb982197ef2b6629c2202796584a7351bbc0563b27ed35c295e95021b947bb6a177e849e45ce5313ab7fa08e90daed00ceeadec13f271eea500df3e801303e0a9d0e9ba2ddf4ff3b77824042f5c16a5da006c992258bd8574e8429b59cd02fc59ff0d22ce060117650300000002d3a9410ac758ad45dfc85af8626efdacf398439c73977b13064aa8e6c8f2ac880255d213ecba5fd74e52002e08a69a2e5e08378f2e43fbbf3f1130dde976db34260000000900cb491a1b9ac9dbcdf083bb80926012e041c623adb1ed964a80eb10bbb147ac",
        "013ff49e2419f779390a9347e8c3ee6391dd3f9e543c12dabcb0f1ebc8168754f466a0ed18269ae22ff110eafed64e6c45cfe8fdf2815d06ccd98afd4d3bed950492bea47dc72d2bc33e4f5a05cb5ac99876534d23537742e6fbdfd3cea455c81ac5410cbb9dff9a4a98f4c9016a156a6696e609601e8c81e9c19e79816c698e9904d3fbd0e9ba2ddf4ff3b77824042f5c16a5da006c992258bd8574e8429b59cd02fc59ff0d22ce06011765040000000337024f9dd20621ecd32baeee4741130d24797eda8cad0d09c794cb4458c4f2a30369f2e10d3a65b5c275bf5ce7ea5105ca9a5a25f81905305454a1196a2a01d42700000012006a2db91bb1ab362b64b298bd023859869c796a05aa4e66a50f4f374c72240c",
        "01d46df95124a711724990f40299bb166babc56d86de624db48776e2afb80e0302073cd5a1bff88021bfb51d13ecdac28387e6d1afe96d6871f1af20d53c93ff86ccccd693bd6461f094fe0bdf15b8284e4e65183c1a0ef596dfb1c56dfe0c61201803847b5e2d8a4fa6377c4ef47b51bda27b1ba8dda853f9b4f64cd5dc7367aa04ebbed1e9ba2ddf4ff3b77824042f5c16a5da006c992258bd8574e8429b59cd02fc59ff0d22ce0601176505000000027de3a01d95abec7ca4a110a45ca7e22193df9b51229e0fdfeaa19ebebf3f53e6031c96172660c9f068adb6e74e10b4afe17be3ce50837d0d670aadd988e79d2e1e00000015000f94951b87b6f29b3b5c86ee003baa22e10b490045b8046b14c9281d25fd6c",
        "01875aaa0886c229607b3da2440f9cdb12f61ed2a0e56c6a9dd9536ac11079ff038f118c8c15e83b19c467f35ac81ff3d88ea344b4ae88231cb08304cdb1aca961296a3e3d6485b9c32a67d18f09af8758ba5f393bbcb29ed4ddcd6e357877e70f346be81869e254cbb192ee5013a9b48f07fb66e0f809b00a63d92649e12129b704e392d2e9ba2ddf4ff3b77824042f5c16a5da006c992258bd8574e8429b59cd02fc59ff0d22ce0601176506000000022846c4f17a909080d7cb8bcf6217e2139666f420582f04e628a1e1225b4ecf49036066a84d6ab109fd53ee769e7bbb89daf191d883007c5625a9b762c542108b8600000024030068221b48756b6ff480f656a82f94f11d479538d008c412508175748f1b9c",
        "01918d0c4ccb9a26cc69a3250eef1117b07bf843367a25455fd0873349a0821a61c8099d28b23cfe8a56553291318650740775b6d827818eae51ad2b0b23cc049cb96c900bef70956ca7c6b01c6e1aa543d6d50e709f852062287fdfc53e2647f91302a55e568b0075165ea085172f834a60d957c98982a51044a6931ec981ade604cb81d3e9ba2da08b33945a758152368ad5b6e2172bf4e669d04c4c951df483da39079908d107060117650700000003a1b5faf27aab713ac2114b3710fb3cf0af580d95997197435c54da4b332efd6902d2c567d69d65d6d5e621d3c2473bdb2880579eb05728cd0384a58592e6d883540000002703206c871b98190c2204cddab9e205f26bd4c7973e7d6ce2b0070e30fd46cf33",
        "01baffd756f86275213fb4dd9400d1d667d0a35a2ba712af050cf0a6f0dfd799919f779fdeb12596973dcaf413a8af18c1d9138bd3420414cc2d2bdb5db2c2d2e955a45f129a2a11888cb74c3c3664caa9c6ac1c1ce6d712e1fbdc1c387b88af3ee40028aadf914a098ee11a02bfcb2d5bf499c920ebce81e6a3b6c738e5c20273048fc2d3e9ba2da08b33945a758152368ad5b6e2172bf4e669d04c4c951df483da39079908d107060117650800000003149c52fbfac539d818d68eb2856b42a2053452bad123b361d5374320a77dc2bb025a20ba1794773296d1018a7a21599d15b3389b06c60c7094f936fe1fc86d968f0000002901361e821bc66259888997722b41d567a1a33e3387116416fa867c0bc37e34be",
    ];

    fn header_from_hex(hex: &str) -> Header {
        let raw = hex::decode(hex).expect("valid hex");
        let mut r = VlqReader::new(&raw);
        read_header(&mut r).expect("valid header")
    }

    /// k=4 NiPoPoW proof over heights 1..=8 with
    /// `dense_from_height = suffix_head_height - k + 1 = 2`.
    /// Reusable by tests that need a proof shape committed to the
    /// store (e.g. boot-level Mode 4 acceptance against a
    /// `PoPowSparse` chain state).
    ///
    /// Test-grade only: the interlink graph is left empty (no
    /// `interlinks` or `interlinks_proof` populated). `apply_popow_proof`
    /// trusts the caller to have verified the proof first via the
    /// production `is_valid` path. Tests use this fixture to drive
    /// the post-apply persisted state; do not lean on it as
    /// evidence that the verifier accepts the proof.
    pub fn nipopow_proof_dense_from_2() -> NipopowProof {
        let mut headers: Vec<Header> = MAINNET_HEADERS_1_TO_8
            .iter()
            .take(8)
            .map(|h| header_from_hex(h))
            .collect();
        let suffix_tail: Vec<Header> = headers.drain(5..).collect();
        let suffix_head_h = headers.pop().unwrap();
        let prefix: Vec<PoPowHeader> = headers
            .drain(..)
            .map(|h| PoPowHeader {
                header: h,
                interlinks: vec![],
                interlinks_proof: vec![],
            })
            .collect();
        NipopowProof {
            m: 6,
            k: 4,
            prefix,
            suffix_head: PoPowHeader {
                header: suffix_head_h,
                interlinks: vec![],
                interlinks_proof: vec![],
            },
            suffix_tail,
            continuous: true,
        }
    }
}
