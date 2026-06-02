//! Regression: `_with_mode` entry points MUST NOT internally route
//! through submit-default decoders.
//!
//! Pins the decode-mode routing-drift class: a `_with_mode` entry
//! point that internally calls a submit-default helper (e.g.
//! `decode_block_transactions_with_mode` hard-calling `decode_input`
//! instead of `decode_input_with_mode`) silently re-canonicalizes
//! Scala-emitted bytes through the writer and breaks
//! `bytes_to_sign(tx)` parity. Block 836113 / tx[18] / R9
//! (Constant[STuple] register) is the live witness.
//!
//! These tests are *targeted at routing drift* — they prove the
//! mode you ASK for is the mode you GET. The full Merkle invariant
//! lives in `ergo-validation/tests/diagnose_block_836113.rs`.
//!
//! Two lever payloads, both producing detectably different Submit
//! vs Preserve wire bytes:
//!
//! 1. **Constant[STuple(SColl[SByte], SColl[SByte])] register** —
//!    the literal-tuple form Scala's ConstantSerializer emits as
//!    `3c 0e 0e <vals>`. Submit canonicalizes to the
//!    CreateTuple expression form (`86 02 0e <v1> 0e <v2>`).
//!    Preserve must keep `3c 0e 0e ...`.
//!
//! 2. **Non-canonical SBoolean** — value byte `0x05` (or any
//!    non-zero) reads as `true`; Submit canonicalizes to `0x01`,
//!    Preserve keeps the original byte. Used inside
//!    `spendingProof.extension` (and the same trick was already
//!    pinned for registers by `b4_q5_*` in `api_bridge.rs`).
//!
//! If a future refactor re-introduces submit-default routing on any
//! `_with_mode` entry point, the relevant assertion below fails
//! with a precise location.

use std::collections::BTreeMap;

use ergo_primitives::reader::VlqReader;
use ergo_rest_json::{
    decode_block_transactions_with_mode, decode_context_extension_with_mode,
    decode_registers_with_mode, decode_scala_transaction_with_mode, DecodeMode, ScalaFullBlock,
    ScalaOutputInput, ScalaTransaction, ScalaTransactionInput,
};
use ergo_ser::block_transactions::read_block_transactions;
use ergo_ser::transaction::{read_transaction, transaction_id};

// ─── Fixtures ────────────────────────────────────────────────────────

/// Constant[STuple(SColl[SByte], SColl[SByte])] with two empty
/// inner collections. Smallest payload that triggers the
/// CreateTuple canonicalization:
///   - bytes:  `3c 0e 0e 00 00`             (5 bytes, Constant form)
///   - submit: `86 02 0e 00 0e 00`          (6 bytes, CreateTuple form)
const CONSTANT_TUPLE_HEX: &str = "3c0e0e0000";
const SUBMIT_CANONICAL_TUPLE_HEX: &str = "86020e000e00";

/// SBoolean true encoded with a non-canonical value byte. Submit
/// canonicalizes the value byte to `0x01`; Preserve preserves
/// `0x05`. Same trick the `b4_q5_*` tests use in api_bridge.rs.
const NONCANONICAL_SBOOL_HEX: &str = "0105";
const CANONICAL_SBOOL_HEX: &str = "0101";

fn load_block_836113() -> ScalaFullBlock {
    let raw = std::fs::read_to_string("../test-vectors/mainnet/block_836113.json")
        .expect("test-vectors/mainnet/block_836113.json (full Scala block JSON)");
    serde_json::from_str(&raw).expect("ScalaFullBlock parse")
}

fn tx_to_input(tx: &ScalaTransaction) -> ScalaTransactionInput {
    ScalaTransactionInput {
        inputs: tx.inputs.clone(),
        data_inputs: tx.data_inputs.clone(),
        outputs: tx
            .outputs
            .iter()
            .map(|o| ScalaOutputInput {
                value: o.value,
                ergo_tree: o.ergo_tree.clone(),
                assets: o.assets.clone(),
                creation_height: o.creation_height,
                additional_registers: o.additional_registers.clone(),
            })
            .collect(),
    }
}

// ─── Helper-level mode-divergence tests ──────────────────────────────

#[test]
fn decode_registers_with_mode_diverges_on_constant_stuple() {
    let mut regs = BTreeMap::new();
    regs.insert("R4".to_string(), CONSTANT_TUPLE_HEX.to_string());

    let (_, submit) =
        decode_registers_with_mode(&regs, DecodeMode::Submit).expect("Submit register decode");
    let (_, preserve) =
        decode_registers_with_mode(&regs, DecodeMode::Preserve).expect("Preserve register decode");

    assert_ne!(
        submit, preserve,
        "decode_registers_with_mode: Submit and Preserve MUST produce \
         different bytes for Constant[STuple] payloads — otherwise the \
         routing-drift tests below would be vacuous"
    );

    // Wire shape: count(u8=1) || register-bytes
    let mut expected_preserve = vec![0x01u8];
    expected_preserve.extend(hex::decode(CONSTANT_TUPLE_HEX).unwrap());
    assert_eq!(
        preserve, expected_preserve,
        "Preserve mode lost byte-fidelity for Constant[STuple] — \
         decode_registers_with_mode is canonicalizing instead of \
         passing the original wire through"
    );

    let mut expected_submit = vec![0x01u8];
    expected_submit.extend(hex::decode(SUBMIT_CANONICAL_TUPLE_HEX).unwrap());
    assert_eq!(
        submit, expected_submit,
        "Submit mode no longer canonicalizes Constant[STuple] to \
         CreateTuple — if this changed intentionally, update the \
         fixture; if not, write_register_value drifted"
    );
}

#[test]
fn decode_context_extension_with_mode_diverges_on_noncanonical_sbool() {
    let mut ext = indexmap::IndexMap::new();
    ext.insert("0".to_string(), NONCANONICAL_SBOOL_HEX.to_string());

    let (_, submit) = decode_context_extension_with_mode(&ext, DecodeMode::Submit)
        .expect("Submit extension decode");
    let (_, preserve) = decode_context_extension_with_mode(&ext, DecodeMode::Preserve)
        .expect("Preserve extension decode");

    assert_ne!(
        submit, preserve,
        "decode_context_extension_with_mode: Submit must canonicalize \
         non-canonical SBoolean (0105 → 0101); Preserve must preserve \
         the input byte. Equality means the canonicalization is silently \
         disabled."
    );

    // Wire shape: count(u8=1) || key(u8=0) || value_bytes
    let mut expected_preserve = vec![0x01u8, 0x00];
    expected_preserve.extend(hex::decode(NONCANONICAL_SBOOL_HEX).unwrap());
    assert_eq!(
        preserve, expected_preserve,
        "Preserve mode rewrote a non-canonical SBoolean — \
         decode_context_extension_with_mode is canonicalizing on the \
         preserve path"
    );

    let mut expected_submit = vec![0x01u8, 0x00];
    expected_submit.extend(hex::decode(CANONICAL_SBOOL_HEX).unwrap());
    assert_eq!(
        submit, expected_submit,
        "Submit mode no longer canonicalizes non-canonical SBoolean — \
         write_context_extension drifted"
    );
}

// ─── Top-level entry-point routing-drift tests ───────────────────────

#[test]
fn decode_scala_transaction_with_mode_preserve_preserves_block_836113_tx18_id() {
    // tx[18] is the live witness — its R9 holds Constant[STuple]
    // bytes that Submit-mode canonicalization breaks. If
    // decode_scala_transaction_with_mode internally drops the mode
    // (e.g. calls decode_input(si) or decode_output(so) instead of
    // their _with_mode variants), the canonicalization fires and
    // the recomputed tx_id no longer matches Scala's claim.
    let block = load_block_836113();
    let tx = &block.block_transactions.transactions[18];
    let scala_id_hex = tx.id.to_lowercase();
    let input = tx_to_input(tx);

    let bytes =
        decode_scala_transaction_with_mode(&input, DecodeMode::Preserve).expect("Preserve decode");
    let mut r = VlqReader::new(&bytes);
    let parsed = read_transaction(&mut r).expect("re-parse tx wire");
    let computed_hex = hex::encode(transaction_id(&parsed).expect("tx_id").as_bytes());

    assert_eq!(
        computed_hex, scala_id_hex,
        "decode_scala_transaction_with_mode(Preserve) lost byte-fidelity \
         on block 836113 tx[18] — the entry point is routing through a \
         submit-default decoder somewhere in the input/output chain. \
         Audit decode_scala_transaction_with_mode and \
         build_transaction_from_input for stale `decode_input(...)` / \
         `decode_output(...)` / `decode_registers(...)` / \
         `decode_context_extension(...)` calls."
    );
}

#[test]
fn decode_block_transactions_with_mode_preserve_preserves_block_836113_tx18_id() {
    // Regression: this entry point used to hard-call
    // decode_input(si), which dropped the caller's `DecodeMode`. The
    // shared `build_transaction_from_input` funnel removed that drift;
    // this test pins the contract.
    let block = load_block_836113();
    let scala_id_hex = block.block_transactions.transactions[18].id.to_lowercase();

    let bytes =
        decode_block_transactions_with_mode(&block.block_transactions, DecodeMode::Preserve)
            .expect("Preserve block-section decode");
    let mut r = VlqReader::new(&bytes);
    let parsed = read_block_transactions(&mut r).expect("read_block_transactions");
    let computed_hex = hex::encode(
        transaction_id(&parsed.transactions[18])
            .expect("tx_id")
            .as_bytes(),
    );

    assert_eq!(
        computed_hex, scala_id_hex,
        "decode_block_transactions_with_mode(Preserve) lost byte-fidelity \
         on block 836113 tx[18] — the routing-drift class has \
         re-appeared. Verify `decode_block_transactions_with_mode` still \
         funnels every tx through `build_transaction_from_input(_, mode, \
         _)` and not through the submit-default `decode_input` / \
         `decode_output` / `decode_registers` / \
         `decode_context_extension` helpers."
    );
}

#[test]
fn decode_block_transactions_with_mode_submit_does_canonicalize_tx18() {
    // Sanity: prove the routing-drift test above isn't vacuous.
    // If Submit and Preserve both produced Scala's tx_id, the
    // canonicalization would be silently disabled and the test
    // above could pass even on a buggy implementation.
    let block = load_block_836113();
    let scala_id_hex = block.block_transactions.transactions[18].id.to_lowercase();

    let bytes = decode_block_transactions_with_mode(&block.block_transactions, DecodeMode::Submit)
        .expect("Submit block-section decode");
    let mut r = VlqReader::new(&bytes);
    let parsed = read_block_transactions(&mut r).expect("read_block_transactions");
    let computed_hex = hex::encode(
        transaction_id(&parsed.transactions[18])
            .expect("tx_id")
            .as_bytes(),
    );

    assert_ne!(
        computed_hex, scala_id_hex,
        "Submit mode must canonicalize tx[18] R9 (Constant[STuple] → \
         CreateTuple) and produce a tx_id that DIFFERS from Scala's. \
         If equal, the canonicalization is silently disabled and the \
         Preserve-preservation test above is vacuous — fix the \
         fixture or the writer before relying on routing-drift coverage."
    );
}

/// Pins `serde_json::from_str` order preservation through the
/// `ScalaSpendingProof::extension` deserialization. The IndexMap-
/// backed pipeline is correctness-fragile end-to-end:
///
/// 1. Wire JSON object has keys in some order (wallet's insertion
///    order, ≤ 4 case)
/// 2. `serde_json` deserializes into `IndexMap<String, String>` via
///    indexmap's `Deserialize` impl — this MUST preserve JSON
///    document order
/// 3. `decode_context_extension_with_mode` builds wire entries from
///    the IndexMap iteration — which MUST be insertion order
/// 4. `write_context_extension` ≤ 4 branch iterates and emits
///
/// If any link breaks, the final bytes desync from what the wallet
/// signed. This test pins step 2 directly (the bit most likely to
/// silently regress if someone "helpfully" changes the DTO type).
#[test]
fn serde_json_preserves_context_extension_key_order() {
    use ergo_rest_json::types::ScalaSpendingProof;
    // JSON object with keys in INTENTIONALLY non-ascending order.
    // A `BTreeMap<String, String>`-backed DTO would re-sort to
    // `"2","5","8"`; `IndexMap` must yield `"8","2","5"`.
    let json = r#"{
        "proofBytes": "",
        "extension": {
            "8": "0402",
            "2": "0404",
            "5": "0408"
        }
    }"#;
    let parsed: ScalaSpendingProof = serde_json::from_str(json).unwrap();
    let keys: Vec<&str> = parsed.extension.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        vec!["8", "2", "5"],
        "serde_json must populate IndexMap<String, String> in JSON document order; \
         got {keys:?}. If this is ascending, the indexmap serde feature is off or \
         the DTO type drifted back to BTreeMap.",
    );
}
