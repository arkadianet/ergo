//! Test-only builders for announcements, bodies and a [`ProcessorCtx`].
//!
//! Behind `#[cfg(any(test, feature = "test-support"))]` so the crate's own
//! unit tests and the ported Scala corpus in `tests/it/processor_corpus.rs`
//! share one set of helpers. Not part of the crate's public contract.
//!
//! # Why these headers pass proof-of-work
//!
//! Tests cannot mine. Every header built here carries
//! `n_bits = encode_compact_bits(1)` — difficulty 1 — so the ordinary
//! target is the secp256k1 group order `q` (`get_target = q / difficulty`),
//! and an Autolykos v2 hit is `BigUint(Blake2b256(..))`, i.e. uniform over
//! `[0, 2^256)`. Since `q > 2^256 - 2^129`, a random hit lands at or above
//! the target with probability below `2^-127`: every header built here
//! passes both [`ergo_crypto::pow::verify_pow_solution`] (ordering
//! announcements) and [`ergo_crypto::pow::verify_input_block_pow`] (input
//! blocks) without mining. [`TestCtx::at`] additionally pins
//! `multiplier = Some(i32::MAX)`, whose widening of the input-block target
//! is pinned by ergo-crypto's `max_multiplier_makes_any_v2_header_pass_pow`.
//!
//! The announcement policy used by these tests is
//! `AnnouncementPolicy { strict_field_binding: false }` — but the proofs
//! built here are real batch-merkle proofs over the announced extension
//! fields reducing to the header's `extension_root`, because
//! `validate_announcement_parity` rejects an empty proof (finding F4).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ergo_crypto::merkle::{extension_leaf_digest, extension_root, merkle_proof_by_indices};
use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::batch_merkle_proof::{BatchMerkleProof, ProofEntry, Side};
use ergo_ser::difficulty::encode_compact_bits;
use ergo_ser::header::{serialize_header, Header};
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::input_block::{
    InputBlockAnnouncement, InputBlockFields, OrderingBlockAnnouncement,
    INPUT_BLOCK_ANNOUNCEMENT_INITIAL_VERSION,
};
use ergo_ser::transaction::{transaction_id, write_transaction, Transaction};
use ergo_ser::weak_id::{weak_id_of, witness_id, WeakId};

use crate::processor::{Body, Effect, Event, Processor, ProcessorCtx};
use crate::types::{InputBlockId, OrderingId, PeerTag, TxRef};

/// Difficulty-1 `nBits`: see the module doc for why this makes any v2
/// header pass PoW.
pub fn easy_n_bits() -> u32 {
    encode_compact_bits(&num_bigint::BigUint::from(1u32))
}

/// `nBits` no test header can satisfy — difficulty `2^250`, target ≈ 64.
/// Used by the "invalid PoW penalizes the peer" case.
pub fn impossible_n_bits() -> u32 {
    encode_compact_bits(&(num_bigint::BigUint::from(1u32) << 250))
}

/// A v2 header for `parent` at `height`, made unique by `nonce` (carried
/// in the timestamp, which is part of the header id preimage).
pub fn header(parent: OrderingId, height: u32, nonce: u64, extension_root: [u8; 32]) -> Header {
    Header {
        version: 2,
        parent_id: ModifierId::from_bytes(parent),
        ad_proofs_root: Digest32::from_bytes([0x22; 32]),
        transactions_root: Digest32::from_bytes([0x44; 32]),
        state_root: ADDigest::from_bytes([0x33; 33]),
        timestamp: 1_600_000_000_000 + nonce,
        extension_root: Digest32::from_bytes(extension_root),
        n_bits: easy_n_bits(),
        height,
        votes: [0, 0, 0],
        unparsed_bytes: Vec::new(),
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from_bytes([0x02; 33]),
            nonce: nonce.to_be_bytes(),
        },
    }
}

/// The id of a header (its modifier id) as a plain 32-byte array.
pub fn header_id(h: &Header) -> [u8; 32] {
    *serialize_header(h)
        .expect("test header serializes")
        .1
        .as_bytes()
}

/// The id of an announcement's header.
pub fn ann_id(a: &InputBlockAnnouncement) -> InputBlockId {
    header_id(&a.header)
}

/// A real batch-merkle proof over `fields`' extension entries, together
/// with the extension root they reduce to.
fn proof_for(fields: &InputBlockFields) -> (BatchMerkleProof, [u8; 32]) {
    let entries = fields.extension_fields();
    let kv: Vec<(&[u8], &[u8])> = entries.iter().map(|(k, v)| (&k[..], &v[..])).collect();
    let root = extension_root(&kv);
    // `extension_root` hashes `[k.len()] ++ k ++ v` as the leaf preimage;
    // `merkle_proof_by_indices` takes those same preimages.
    let leaves: Vec<Vec<u8>> = entries
        .iter()
        .map(|(k, v)| {
            let mut leaf = Vec::with_capacity(1 + k.len() + v.len());
            leaf.push(k.len() as u8);
            leaf.extend_from_slice(k);
            leaf.extend_from_slice(v);
            leaf
        })
        .collect();
    let refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
    let indices: Vec<u32> = (0..refs.len() as u32).collect();
    let (proved, entries) =
        merkle_proof_by_indices(&refs, &indices).expect("proof over all leaves exists");
    debug_assert!(proved
        .iter()
        .zip(fields.extension_fields().iter())
        .all(|((_, d), (k, v))| *d == extension_leaf_digest(k, v)));
    let proof = BatchMerkleProof {
        indices: proved,
        proofs: entries
            .into_iter()
            .map(|e| ProofEntry {
                digest: e.digest,
                side: Side::from_byte(e.side),
            })
            .collect(),
    };
    (proof, root)
}

/// The announced `transactionsDigest` for an ordered transaction-id list
/// (Scala `Algos.merkleTreeRoot(txs.map(_.serializedId))`).
pub fn tx_digest(tx_ids: &[[u8; 32]]) -> [u8; 32] {
    let refs: Vec<&[u8]> = tx_ids.iter().map(|i| &i[..]).collect();
    ergo_crypto::merkle::merkle_tree_root(&refs)
}

/// Build an announcement with an explicit transactions digest and weak-id
/// list. The extension proof is real and binds exactly these fields.
pub fn announcement_with(
    parent: OrderingId,
    height: u32,
    nonce: u64,
    prev: Option<InputBlockId>,
    transactions_digest: [u8; 32],
    weak_tx_ids: Option<Vec<WeakId>>,
) -> InputBlockAnnouncement {
    let mut fields = InputBlockFields {
        prev_input_block_id: prev,
        transactions_digest,
        prev_transactions_digest: [0u8; 32],
        proof: BatchMerkleProof {
            indices: Vec::new(),
            proofs: Vec::new(),
        },
    };
    let (proof, root) = proof_for(&fields);
    fields.proof = proof;
    InputBlockAnnouncement {
        version: INPUT_BLOCK_ANNOUNCEMENT_INITIAL_VERSION,
        header: header(parent, height, nonce, root),
        fields,
        weak_tx_ids,
        unparsed_bytes: Vec::new(),
    }
}

/// An announcement that commits to no transactions and announces no weak
/// ids, so the processor requests the id list and waits. This is the
/// shape the ported Scala corpus uses: the test then drives
/// [`Event::TransactionsDelivered`] with an empty body list, mirroring
/// Scala's `applyInputBlockTransactions(id, Seq.empty, state)`.
pub fn announcement(
    parent: OrderingId,
    height: u32,
    nonce: u64,
    prev: Option<InputBlockId>,
) -> InputBlockAnnouncement {
    announcement_with(parent, height, nonce, prev, tx_digest(&[]), None)
}

/// An announcement committing to `bodies` in order, announcing their weak
/// ids.
pub fn announcement_for(
    parent: OrderingId,
    height: u32,
    nonce: u64,
    prev: Option<InputBlockId>,
    bodies: &[Body],
) -> InputBlockAnnouncement {
    let ids: Vec<[u8; 32]> = bodies.iter().map(|b| b.tx_ref.tx_id).collect();
    let weak: Vec<WeakId> = bodies.iter().map(|b| b.weak_id).collect();
    announcement_with(parent, height, nonce, prev, tx_digest(&ids), Some(weak))
}

/// An ordering-block announcement for `parent` at `height` carrying
/// `extension_fields` (its `extension_root` is recomputed to match, so
/// `validate_ordering_announcement` accepts it).
pub fn ordering_announcement(
    parent: OrderingId,
    height: u32,
    nonce: u64,
    extension_fields: Vec<([u8; 2], Vec<u8>)>,
) -> OrderingBlockAnnouncement {
    let kv: Vec<(&[u8], &[u8])> = extension_fields
        .iter()
        .map(|(k, v)| (&k[..], &v[..]))
        .collect();
    let root = extension_root(&kv);
    OrderingBlockAnnouncement {
        version: 1,
        header: header(parent, height, nonce, root),
        non_broadcasted_transactions: Vec::new(),
        broadcasted_transaction_ids: Vec::new(),
        extension_fields,
        unparsed_bytes: Vec::new(),
    }
}

/// A one-input transaction spending box `[seed; 32]` with proof
/// `[witness]`. Two calls differing only in `witness` produce the same
/// `tx_id` with different `witness_id`s — the witness-variant case of
/// spec 7.5.
pub fn tx(seed: u8, witness: u8) -> Transaction {
    Transaction {
        inputs: vec![Input {
            box_id: Digest32::from_bytes([seed; 32]),
            spending_proof: SpendingProof::new(vec![witness], ContextExtension::empty())
                .expect("test proof fits the wire bounds"),
        }],
        data_inputs: Vec::new(),
        output_candidates: Vec::new(),
    }
}

/// A [`Body`] for [`tx`]`(seed, witness)`.
pub fn body(seed: u8, witness: u8) -> Body {
    body_of(tx(seed, witness))
}

/// A [`Body`] wrapping an arbitrary transaction.
pub fn body_of(t: Transaction) -> Body {
    let mut w = VlqWriter::new();
    write_transaction(&mut w, &t).expect("test transaction serializes");
    let bytes: Arc<[u8]> = Arc::from(w.result().into_boxed_slice());
    let tx_id = *transaction_id(&t).expect("test transaction id").as_bytes();
    let wid = witness_id(&t);
    Body {
        tx_ref: TxRef {
            tx_id,
            witness_id: wid,
        },
        weak_id: weak_id_of(&t).expect("test weak id"),
        bytes,
        tx: t,
    }
}

/// A weak-id-indexed stand-in for the node's mempool.
#[derive(Debug, Default, Clone)]
pub struct Mempool {
    by_weak: HashMap<WeakId, Vec<Body>>,
}

impl Mempool {
    /// Add a body, so `lookup` returns it for its weak id.
    pub fn add(&mut self, b: &Body) {
        self.by_weak.entry(b.weak_id).or_default().push(b.clone());
    }

    /// Add a body under an arbitrary weak id. Weak ids are 48 bits and
    /// not collision-resistant; real collisions cannot be constructed
    /// cheaply, so the collision and witness-variant cases of spec 7.5
    /// are exercised by filing a body under someone else's weak id.
    pub fn add_under(&mut self, w: WeakId, b: &Body) {
        self.by_weak.entry(w).or_default().push(b.clone());
    }

    /// Every body sharing `w`'s weak id (spec 7.5 step 1).
    pub fn lookup(&self, w: &WeakId) -> Vec<Body> {
        self.by_weak.get(w).cloned().unwrap_or_default()
    }
}

/// Owns the per-event inputs a [`ProcessorCtx`] borrows, so tests can
/// mutate them between events.
#[derive(Debug, Clone)]
pub struct TestCtx {
    /// Weak-id lookups answered by `ProcessorCtx::mempool_lookup`.
    pub mempool: Mempool,
    /// `ProcessorCtx::utxo_mode`.
    pub utxo_mode: bool,
    /// `ProcessorCtx::full_block_height`.
    pub full_block_height: u32,
    /// `ProcessorCtx::multiplier`.
    pub multiplier: Option<i32>,
    /// Ordering blocks whose transaction section the node already has
    /// (`ProcessorCtx::block_transactions_known`).
    pub known_block_txs: HashSet<OrderingId>,
    /// What `ProcessorCtx::expected_n_bits` answers for every parent.
    pub expected_n_bits: Option<u32>,
}

impl TestCtx {
    /// A context at `full_block_height` with an empty mempool, UTXO mode
    /// on, and the permissive multiplier described in the module doc.
    pub fn at(full_block_height: u32) -> Self {
        Self {
            mempool: Mempool::default(),
            utxo_mode: true,
            full_block_height,
            multiplier: Some(i32::MAX),
            known_block_txs: HashSet::new(),
            expected_n_bits: None,
        }
    }

    /// Run `f` with a borrowed [`ProcessorCtx`] over this state. The
    /// closures a `ProcessorCtx` holds cannot outlive the call, hence
    /// the callback shape.
    pub fn with<R>(&self, f: impl FnOnce(&ProcessorCtx<'_>) -> R) -> R {
        let mempool_lookup = |w: &WeakId| self.mempool.lookup(w);
        let expected_n_bits = |_: &[u8; 32]| self.expected_n_bits;
        let block_transactions_known = |id: &OrderingId| self.known_block_txs.contains(id);
        let ctx = ProcessorCtx {
            multiplier: self.multiplier,
            expected_n_bits: &expected_n_bits,
            mempool_lookup: &mempool_lookup,
            utxo_mode: self.utxo_mode,
            full_block_height: self.full_block_height,
            block_transactions_known: &block_transactions_known,
        };
        f(&ctx)
    }

    /// Feed one event to `p` under this context.
    pub fn handle(&self, p: &mut Processor, ev: Event) -> Vec<Effect> {
        self.with(|c| p.handle(ev, c))
    }
}

/// The peer tag tests use for "some remote peer".
pub const PEER: PeerTag = PeerTag(7);

/// Extract the single [`Effect::Validate`] from `effects`, panicking if
/// there is not exactly one.
pub fn one_validate(effects: &[Effect]) -> (u64, u64, InputBlockId, Vec<TxRef>, Vec<TxRef>) {
    let mut found = None;
    for e in effects {
        if let Effect::Validate {
            job,
            generation,
            input_block_id,
            txs,
            previous,
        } = e
        {
            assert!(found.is_none(), "more than one Validate in {effects:?}");
            found = Some((
                *job,
                *generation,
                *input_block_id,
                txs.clone(),
                previous.clone(),
            ));
        }
    }
    found.unwrap_or_else(|| panic!("no Validate effect in {effects:?}"))
}

/// Answer the single `Validate` in `effects` with `Ok(cost)`.
pub fn validate_ok(p: &mut Processor, ctx: &TestCtx, effects: &[Effect], cost: u64) -> Vec<Effect> {
    let (job, generation, _, _, _) = one_validate(effects);
    ctx.handle(
        p,
        Event::ValidationResult {
            job,
            generation,
            outcome: Ok(cost),
        },
    )
}

/// Answer the single `Validate` in `effects` with a simulated failure.
pub fn validate_err(p: &mut Processor, ctx: &TestCtx, effects: &[Effect]) -> Vec<Effect> {
    let (job, generation, _, _, _) = one_validate(effects);
    ctx.handle(
        p,
        Event::ValidationResult {
            job,
            generation,
            outcome: Err("simulated".to_string()),
        },
    )
}

/// Announce `ann` from [`PEER`] and immediately answer every `Validate`
/// it (and its continuations) produce with `Ok(1)`, returning every
/// effect produced along the way. This is the corpus's stand-in for
/// Scala's `applyInputBlock` + `applyInputBlockTransactions(id, txs, us)`
/// pair when the case does not care about validation outcomes.
pub fn announce_and_apply(
    p: &mut Processor,
    ctx: &TestCtx,
    ann: &InputBlockAnnouncement,
    now: u64,
) -> Vec<Effect> {
    let id = ann_id(ann);
    let mut all = ctx.handle(
        p,
        Event::AnnouncementAccepted {
            ann: ann.clone(),
            from: PEER,
            now: crate::types::Tick(now),
        },
    );
    let mut effects = ctx.handle(
        p,
        Event::TransactionsDelivered {
            input_block_id: id,
            bodies: Vec::new(),
            from: Some(PEER),
            now: crate::types::Tick(now),
        },
    );
    loop {
        let has_validate = effects.iter().any(|e| matches!(e, Effect::Validate { .. }));
        all.extend(effects.clone());
        if !has_validate {
            break;
        }
        effects = validate_ok(p, ctx, &effects, 1);
    }
    all
}
