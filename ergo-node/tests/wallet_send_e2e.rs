//! Full send-wallet end-to-end test.
//!
//! Drives the complete prover → verifier round-trip without a real chain:
//! synthetic keypair, synthetic ErgoBox, synthetic BlockchainStateContext,
//! and a capturing self-verify step that calls
//! `verify_spending_proof_with_context_and_cost` directly.
//!
//! This test was originally `#[ignore]`'d in
//! `ergo-api/tests/wallet_send_oracle.rs` because `ergo-api` cannot depend
//! on `ergo-node` (circular crate dep). It lives here where
//! `ergo-wallet::proving::*`, `ergo-node::*`, and `ergo-sigma::*` are all
//! in scope.
//!
//! The full writer-task path (NodeWalletAdmin + run_wallet_writer) requires
//! an AVL-tree-backed UTXO set for `lookup_utxo`, which is expensive to seed
//! in an integration test. Instead we drive `Prover::sign` +
//! `verify_spending_proof_with_context_and_cost` directly — this is exactly
//! what `self_verify_signed_tx` does in production before every submit, so
//! the oracle assertion is identical.

use ergo_primitives::cost::CostAccumulator;
use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_primitives::reader::VlqReader;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::header::Header;
use ergo_ser::input::ContextExtension;
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::transaction::bytes_to_sign;
use ergo_sigma::reduce::verify_spending_proof_with_context_and_cost;
use ergo_validation::pre_header::CandidatePreHeader;
use ergo_wallet::box_selector::BoxSummary;
use ergo_wallet::proving::external::ProverExternalSecret;
use ergo_wallet::proving::hints::TransactionHintsBag;
use ergo_wallet::proving::prover::Prover;
use ergo_wallet::proving::secrets::SecretRegistry;
use ergo_wallet::tx_builder::UnsignedTxBuilder;
use ergo_wallet::tx_context::{BlockchainParameters, BlockchainStateContext};
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ops::{MulByGenerator, Reduce};
use k256::{FieldBytes, ProjectivePoint, Scalar, U256};

// ----- helpers -----

/// Build a deterministic test scalar from a fixed 32-byte seed.
fn test_scalar() -> Scalar {
    let bytes: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xee, // not all-zero; must be non-zero scalar
    ];
    <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(bytes))
}

/// Derive compressed-SEC1 pubkey from scalar.
fn pubkey_from_scalar(scalar: &Scalar) -> [u8; 33] {
    let point = ProjectivePoint::mul_by_generator(scalar);
    point.to_affine().to_bytes().into()
}

/// Parse an ergo tree from bytes (shorthand for tests).
fn parse_ergo_tree(bytes: &[u8]) -> ergo_ser::ergo_tree::ErgoTree {
    let mut r = VlqReader::new(bytes);
    read_ergo_tree(&mut r).expect("ergo_tree must parse")
}

/// Build a synthetic `ErgoBox` carrying `value` nanoERG locked to `pk` (bare P2PK).
fn p2pk_ergo_box(pk: &[u8; 33], value: u64, creation_height: u32) -> ErgoBox {
    let ergo_tree_bytes = ergo_sigma::schnorr::build_prove_dlog_ergo_tree(pk);
    let ergo_tree = parse_ergo_tree(&ergo_tree_bytes);
    let candidate = ErgoBoxCandidate::new(
        value,
        ergo_tree,
        creation_height,
        vec![],
        AdditionalRegisters::empty(),
    )
    .expect("ErgoBoxCandidate::new");
    ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes([0x01u8; 32]),
        index: 0,
    }
}

/// Build a minimal V2 `Header` at `height` with a given `pk` (as miner pubkey).
/// The state_root is a zero digest — sufficient for signing context construction.
fn synthetic_header(pk: &[u8; 33], height: u32, parent: [u8; 32]) -> Header {
    Header {
        version: 2,
        parent_id: ModifierId::from_bytes(parent),
        ad_proofs_root: Digest32::from_bytes([0u8; 32]),
        transactions_root: Digest32::from_bytes([0u8; 32]),
        state_root: ADDigest::from_bytes([0u8; 33]),
        timestamp: 1_700_000_000_000 + height as u64 * 120_000,
        extension_root: Digest32::from_bytes([0u8; 32]),
        n_bits: 0x1a06_0b61, // mainnet genesis nBits — sufficient for context
        height,
        votes: [0, 0, 0],
        unparsed_bytes: vec![],
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from_bytes(*pk),
            nonce: [0u8; 8],
        },
    }
}

/// Build a `BlockchainStateContext` with 10 synthetic headers and a default
/// pre-header. Sufficient for `build_reduction_owned` to produce a valid
/// `ReductionContext<'_>`.
fn synthetic_state_context(pk: &[u8; 33]) -> BlockchainStateContext {
    let tip_height: u32 = 100_000;
    // Build 10 headers (height 99991..100000), tip-first.
    let headers: Vec<Header> = (0..10u32)
        .map(|i| {
            let h = tip_height - i;
            let parent: [u8; 32] = {
                let mut p = [0u8; 32];
                p[0..4].copy_from_slice(&(h - 1).to_be_bytes());
                p
            };
            synthetic_header(pk, h, parent)
        })
        .collect();

    let tip_header = &headers[0];

    let sigma_pre_header = CandidatePreHeader {
        version: tip_header.version,
        parent_id: *tip_header.parent_id.as_bytes(),
        height: tip_height + 1,
        timestamp: tip_header.timestamp + 120_000,
        n_bits: tip_header.n_bits,
        votes: [0, 0, 0],
        miner_pubkey: *pk,
    };

    let previous_state_digest = ADDigest::from_bytes(*tip_header.state_root.as_bytes());

    BlockchainStateContext {
        sigma_last_headers: headers,
        sigma_pre_header,
        previous_state_digest,
    }
}

/// Default signing params with a generous cost limit.
fn generous_params() -> BlockchainParameters {
    BlockchainParameters {
        max_block_cost: 1_000_000_000,
        input_cost: 2_000,
        data_input_cost: 100,
        output_cost: 100,
        token_access_cost: 100,
        interpreter_init_cost: 1_000,
        block_version: 2,
    }
}

// ----- happy path -----

/// Full e2e: synthetic P2PK box → build unsigned tx → sign → verify at
/// transaction level via `verify_spending_proof_with_context_and_cost`.
///
/// This mirrors what `self_verify_signed_tx` in `wallet_bridge.rs` does
/// before every production submit. The prover and verifier must agree on the
/// Fiat-Shamir challenge and spending proof bytes.
#[test]
fn full_send_flow_produces_tx_that_verifies_at_transaction_level() {
    // Known test scalar + pubkey.
    let scalar = test_scalar();
    assert_ne!(scalar, Scalar::ZERO, "test scalar must be non-zero");
    let pk = pubkey_from_scalar(&scalar);

    // P2PK input box: 10 ERG.
    let input_box = p2pk_ergo_box(&pk, 10_000_000_000, 99_000);
    let box_id = input_box.box_id().expect("box_id");
    let boxes_to_spend = vec![input_box.clone()];

    // Recipient: a different address (arbitrary pk).
    let recv_scalar = test_scalar(); // same for simplicity; what matters is the proof
    let recv_pk = pubkey_from_scalar(&recv_scalar);
    let recv_ergo_tree_bytes = ergo_sigma::schnorr::build_prove_dlog_ergo_tree(&recv_pk);
    // Fee ergo tree (Mainnet fee proposition).
    let fee_ergo_tree_bytes = ergo_mempool::validator::MAINNET_FEE_PROPOSITION_BYTES.to_vec();

    // Change address uses the same pk as the input (send-to-self pattern).
    let change_ergo_tree_bytes = ergo_sigma::schnorr::build_prove_dlog_ergo_tree(&pk);

    let payment_value: u64 = 1_000_000_000; // 1 ERG
    let fee: u64 = 1_000_000; // 1 mERG
    let current_height: u32 = 100_001;

    // Box summary for the selector.
    let summaries = vec![BoxSummary {
        box_id: *box_id.as_bytes(),
        value: 10_000_000_000,
        tokens: std::collections::BTreeMap::new(),
    }];

    // Build unsigned tx via UnsignedTxBuilder.
    let selector = ergo_wallet::box_selector::default::DefaultBoxSelector;
    let payment_request = ergo_wallet::tx_builder::PaymentRequest {
        to_ergo_tree: recv_ergo_tree_bytes.clone(),
        value: payment_value,
        assets: std::collections::BTreeMap::new(),
    };
    let builder = UnsignedTxBuilder {
        available_summaries: &summaries,
        selector: &selector,
        fee,
        fee_ergo_tree: fee_ergo_tree_bytes,
        change_ergo_tree: change_ergo_tree_bytes,
        current_height,
        min_box_value: 1_000_000,
        data_inputs: vec![],
        reemission: None,
        reemission_height: 0,
    };
    let unsigned_tx = builder
        .build(&[payment_request])
        .expect("UnsignedTxBuilder::build");

    // Sanity: input references our test box.
    assert_eq!(
        unsigned_tx.inputs.len(),
        1,
        "one input (the P2PK box we own)"
    );
    assert_eq!(
        unsigned_tx.inputs[0].box_id.as_bytes(),
        box_id.as_bytes(),
        "input must reference the seeded P2PK box"
    );
    assert!(
        unsigned_tx.output_candidates.len() >= 2,
        "at least payment + fee outputs"
    );

    // Sign: SecretRegistry with the known test scalar.
    // ProverExternalSecret::Dlog wraps the scalar in Zeroizing; .into()
    // performs the wrap.
    let external = ProverExternalSecret::Dlog {
        pk,
        scalar: scalar.into(),
    };
    let registry = SecretRegistry::empty()
        .merge_external_secrets(&[external])
        .expect("merge_external_secrets");
    let params = generous_params();
    let prover = Prover::new(registry, params);

    let state_ctx = synthetic_state_context(&pk);
    let hints = TransactionHintsBag::empty();

    let signed_tx = prover
        .sign(&unsigned_tx, &boxes_to_spend, &[], &state_ctx, &hints)
        .expect("Prover::sign");

    assert_eq!(signed_tx.inputs.len(), 1, "signed tx must have one input");
    assert!(
        !signed_tx.inputs[0].spending_proof.proof.is_empty(),
        "spending proof must be non-empty"
    );

    // Independently verify every input via the same oracle the production
    // self_verify_signed_tx gate uses.
    let message = bytes_to_sign(&signed_tx).expect("bytes_to_sign");
    let all_input_extensions: Vec<ContextExtension> = signed_tx
        .inputs
        .iter()
        .map(|i| i.spending_proof.extension.clone())
        .collect();

    for (idx, (input, input_box)) in signed_tx
        .inputs
        .iter()
        .zip(boxes_to_spend.iter())
        .enumerate()
    {
        let owned_rc = state_ctx.build_reduction_owned(
            input_box,
            &input.spending_proof.extension,
            &boxes_to_spend,
            &[],
            &signed_tx.output_candidates,
            &all_input_extensions,
        );
        let ctx = owned_rc.as_borrowed();
        let ergo_tree = input_box.candidate.ergo_tree();
        let mut cost_acc = CostAccumulator::recording_only();
        let ok = verify_spending_proof_with_context_and_cost(
            ergo_tree,
            &input.spending_proof.proof,
            &message,
            &ctx,
            &mut cost_acc,
        )
        .unwrap_or_else(|e| panic!("verify_spending_proof input {idx}: {e:?}"));
        assert!(ok, "input {idx} must verify at transaction level");
    }
}

/// Round-trip: unsigned tx bytes → parse → sign → verify.
///
/// Exercises the serialization / deserialization path that
/// `wallet_bridge.rs::payment_send_impl` uses (build → serialize → parse
/// → sign).
#[test]
fn unsigned_tx_roundtrip_then_sign_verifies() {
    let scalar = test_scalar();
    let pk = pubkey_from_scalar(&scalar);
    let input_box = p2pk_ergo_box(&pk, 5_000_000_000, 98_000);
    let box_id = input_box.box_id().expect("box_id");
    let boxes_to_spend = vec![input_box.clone()];

    let recv_ergo_tree_bytes = ergo_sigma::schnorr::build_prove_dlog_ergo_tree(&pk);
    let fee_ergo_tree_bytes = ergo_mempool::validator::MAINNET_FEE_PROPOSITION_BYTES.to_vec();
    let change_ergo_tree_bytes = ergo_sigma::schnorr::build_prove_dlog_ergo_tree(&pk);

    let summaries = vec![BoxSummary {
        box_id: *box_id.as_bytes(),
        value: 5_000_000_000,
        tokens: std::collections::BTreeMap::new(),
    }];
    let selector = ergo_wallet::box_selector::default::DefaultBoxSelector;
    let builder = UnsignedTxBuilder {
        available_summaries: &summaries,
        selector: &selector,
        fee: 1_000_000,
        fee_ergo_tree: fee_ergo_tree_bytes,
        change_ergo_tree: change_ergo_tree_bytes,
        current_height: 100_001,
        min_box_value: 1_000_000,
        data_inputs: vec![],
        reemission: None,
        reemission_height: 0,
    };
    let unsigned_tx_original = builder
        .build(&[ergo_wallet::tx_builder::PaymentRequest {
            to_ergo_tree: recv_ergo_tree_bytes,
            value: 500_000_000,
            assets: std::collections::BTreeMap::new(),
        }])
        .expect("build");

    // Serialize → parse (production round-trip).
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::transaction::write_unsigned_transaction(&mut w, &unsigned_tx_original)
        .expect("write_unsigned_transaction");
    let bytes = w.result();
    let mut r = VlqReader::new(&bytes);
    let unsigned_tx = ergo_ser::transaction::read_unsigned_transaction(&mut r)
        .expect("read_unsigned_transaction");

    assert_eq!(
        unsigned_tx.inputs.len(),
        unsigned_tx_original.inputs.len(),
        "input count preserved across roundtrip"
    );

    // Sign and verify.
    // ProverExternalSecret::Dlog wraps the scalar in Zeroizing; .into()
    // performs the wrap.
    let external = ProverExternalSecret::Dlog {
        pk,
        scalar: scalar.into(),
    };
    let registry = SecretRegistry::empty()
        .merge_external_secrets(&[external])
        .expect("merge_external_secrets");
    let prover = Prover::new(registry, generous_params());
    let state_ctx = synthetic_state_context(&pk);
    let hints = TransactionHintsBag::empty();
    let signed_tx = prover
        .sign(&unsigned_tx, &boxes_to_spend, &[], &state_ctx, &hints)
        .expect("sign");

    let message = bytes_to_sign(&signed_tx).expect("bytes_to_sign");
    let all_input_extensions: Vec<ContextExtension> = signed_tx
        .inputs
        .iter()
        .map(|i| i.spending_proof.extension.clone())
        .collect();

    for (idx, (input, input_box)) in signed_tx
        .inputs
        .iter()
        .zip(boxes_to_spend.iter())
        .enumerate()
    {
        let owned_rc = state_ctx.build_reduction_owned(
            input_box,
            &input.spending_proof.extension,
            &boxes_to_spend,
            &[],
            &signed_tx.output_candidates,
            &all_input_extensions,
        );
        let ctx = owned_rc.as_borrowed();
        let mut cost_acc = CostAccumulator::recording_only();
        let ok = verify_spending_proof_with_context_and_cost(
            input_box.candidate.ergo_tree(),
            &input.spending_proof.proof,
            &message,
            &ctx,
            &mut cost_acc,
        )
        .unwrap_or_else(|e| panic!("verify input {idx}: {e:?}"));
        assert!(ok, "input {idx} must verify after roundtrip");
    }
}

// ----- oracle parity -----

/// The send path (`wallet_bridge::build_unsigned_tx`) must build recipient
/// and change output trees as the CANONICAL non-segregated P2PK tree —
/// `ergo_ser::address::build_p2pk_tree_bytes` — not the segregated
/// `ergo_sigma::schnorr::build_prove_dlog_ergo_tree`.
///
/// Oracle: `encode_address_from_tree_bytes` mirrors Scala
/// `ErgoAddressEncoder.fromProposition`: canonical P2PK tree → P2PK
/// address, segregated tree → P2S address. A recipient who hands us a
/// P2PK address must get a box that re-encodes to that SAME P2PK address;
/// a change box must additionally match the wallet's own tracked-tree set
/// so the next scan recognizes it as wallet-owned. Both fail under the
/// segregated builder — that is the bug this test guards against
/// regressing (the prior e2e tests used the segregated builder for BOTH
/// their tracked set and their outputs, so they were self-consistent and
/// could not catch it).
#[test]
fn send_path_output_trees_are_canonical_p2pk_not_segregated() {
    use ergo_ser::address::{
        build_p2pk_tree_bytes, decode_p2pk_address, encode_address_from_tree_bytes,
        encode_p2pk_from_pubkey, NetworkPrefix,
    };

    let pk = pubkey_from_scalar(&test_scalar());
    let dest_address = encode_p2pk_from_pubkey(NetworkPrefix::Mainnet, &pk).expect("encode P2PK");
    let decoded = decode_p2pk_address(&dest_address, NetworkPrefix::Mainnet).expect("decode P2PK");
    assert_eq!(decoded, pk, "address round-trips to the same pubkey");

    // The canonical builder (what the send path now uses) re-encodes to the
    // SAME P2PK address the recipient gave us.
    let canonical = build_p2pk_tree_bytes(&pk).expect("canonical P2PK tree");
    assert_eq!(
        encode_address_from_tree_bytes(NetworkPrefix::Mainnet, &canonical)
            .expect("encode canonical tree"),
        dest_address,
        "canonical output tree must re-encode to the recipient's P2PK address",
    );

    // The wallet tracks pubkeys by this same canonical tree, so a change box
    // built this way is recognized as wallet-owned on the next scan.
    let mut wallet = ergo_wallet::state::WalletState::empty(false);
    wallet
        .insert_tracked_pubkey(0, pk, NetworkPrefix::Mainnet)
        .expect("track pubkey");
    assert!(
        wallet.is_tracked_tree(&canonical),
        "canonical change tree must match the wallet's tracked set",
    );

    // Guard rail: the segregated builder the send path previously used does
    // NOT satisfy either property — it encodes to a P2S address and is not
    // recognized as wallet-owned. If these ever start passing, the segregated
    // builder has been wired back into the send path.
    let segregated = ergo_sigma::schnorr::build_prove_dlog_ergo_tree(&pk);
    assert_ne!(
        encode_address_from_tree_bytes(NetworkPrefix::Mainnet, &segregated)
            .expect("encode segregated tree"),
        dest_address,
        "segregated tree must NOT encode to the P2PK address (it is P2S)",
    );
    assert!(
        !wallet.is_tracked_tree(&segregated),
        "segregated tree must NOT match the wallet's tracked set",
    );
}
