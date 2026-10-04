//! Same-block box visibility in UTXO-mode full-block validation.
//!
//! Scala's `UtxoState.applyTransactions` resolves inputs and data inputs
//! through `createdOutputs = transactions.flatMap(_.outputs)` before the
//! pre-block state, and `StateChanges.operations` runs every data-input
//! lookup first, where a lookup never fails. A data input may therefore name
//! an output of a later transaction in the same block. A forward spend still
//! fails, because its removal runs before the producing insertion.

use std::collections::HashMap;

use ergo_crypto::merkle::{extension_root, transactions_root};
use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::block_transactions::BlockTransactions;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::extension::{Extension, ExtensionField};
use ergo_ser::header::{read_header, Header};
use ergo_ser::input::{ContextExtension, DataInput, Input, SpendingProof};
use ergo_ser::opcode::Expr;
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
use ergo_ser::transaction::{transaction_id, Transaction};
use ergo_validation::block::{
    validate_full_block, validate_full_block_parallel, BlockValidationContext, BlockValidationError,
};
use ergo_validation::context::{ProtocolParams, UtxoView};
use ergo_validation::error::ValidationError;
use ergo_validation::header::CheckedHeader;

const VALUE: u64 = 1_000_000_000;
const HEIGHT: u32 = 1000;
const HEADER_ID: [u8; 32] = [0x5a; 32];

struct MapUtxo(HashMap<Digest32, ErgoBox>);

impl UtxoView for MapUtxo {
    fn get_box(&self, id: &Digest32) -> Option<ErgoBox> {
        self.0.get(id).cloned()
    }
}

fn true_tree() -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: true,
        constant_segregation: false,
        reserved_header_bits: 0,
        constants: vec![],
        body: Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
        },
    }
}

fn candidate() -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(
        VALUE,
        true_tree(),
        100,
        vec![],
        AdditionalRegisters::empty(),
    )
    .unwrap()
}

fn pre_block_box(fill: u8) -> ErgoBox {
    ErgoBox::new(candidate(), ModifierId::from_bytes([fill; 32]), 0)
}

fn spend(box_id: Digest32) -> Input {
    Input {
        box_id,
        spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
    }
}

fn tx(inputs: Vec<Digest32>, data_inputs: Vec<Digest32>) -> Transaction {
    Transaction {
        output_candidates: inputs.iter().map(|_| candidate()).collect(),
        inputs: inputs.into_iter().map(spend).collect(),
        data_inputs: data_inputs
            .into_iter()
            .map(|box_id| DataInput { box_id })
            .collect(),
    }
}

fn first_output_id(tx: &Transaction) -> Digest32 {
    ErgoBox::new(
        tx.output_candidates[0].clone(),
        transaction_id(tx).unwrap(),
        0,
    )
    .box_id()
    .unwrap()
}

/// Mainnet v1 headers at `HEIGHT - 1` and `HEIGHT`.
fn parent_and_header() -> (Header, Header) {
    #[derive(serde::Deserialize)]
    struct HeaderVec {
        height: u32,
        bytes: String,
    }
    let data = std::fs::read_to_string("../test-vectors/mainnet/headers_1_2000.json").unwrap();
    let vecs: Vec<HeaderVec> = serde_json::from_str(&data).unwrap();
    let header_at = |height: u32| {
        let v = vecs.iter().find(|v| v.height == height).unwrap();
        read_header(&mut VlqReader::new(&hex::decode(&v.bytes).unwrap())).unwrap()
    };
    (header_at(HEIGHT - 1), header_at(HEIGHT))
}

/// Bind `transactions` to a copy of the mainnet header at `HEIGHT` by
/// recomputing its transaction and extension roots, then validate the block
/// on both the sequential and the production (parallel) path.
fn validate_both(
    transactions: Vec<Transaction>,
    utxo: &MapUtxo,
) -> [Result<(), BlockValidationError>; 2] {
    let (parent, mut header) = parent_and_header();
    let tx_ids: Vec<ModifierId> = transactions
        .iter()
        .map(|tx| transaction_id(tx).unwrap())
        .collect();
    let id_refs: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_bytes().as_slice()).collect();
    header.transactions_root = Digest32::from_bytes(transactions_root(&id_refs, None));
    let fields = vec![ExtensionField {
        key: [0x7f, 0x00],
        value: vec![1],
    }];
    header.extension_root = Digest32::from_bytes(extension_root(&[(
        fields[0].key.as_slice(),
        fields[0].value.as_slice(),
    )]));
    let block_transactions = BlockTransactions {
        header_id: ModifierId::from_bytes(HEADER_ID),
        transactions,
    };
    let extension = Extension {
        header_id: ModifierId::from_bytes(HEADER_ID),
        fields,
    };

    let params = ProtocolParams::mainnet_default();
    let checked_parent = CheckedHeader::trust_me(parent, [0x11; 32]);
    let ctx = BlockValidationContext {
        parent: &checked_parent,
        utxo,
        params: &params,
        rule_306_max_block_size: params.max_block_size,
        voting_length: 1024,
        votes_unknown_rule_disabled: false,
        parent_extension: None,
        soft_fork_state: None,
        last_headers: &[],
        script_validation_checkpoint: None,
        reemission: None,
    };
    let sequential = validate_full_block(
        CheckedHeader::trust_me(header.clone(), HEADER_ID),
        &block_transactions,
        &extension,
        &ctx,
    )
    .map(|_| ());
    let parallel = validate_full_block_parallel(
        CheckedHeader::trust_me(header, HEADER_ID),
        &block_transactions,
        &extension,
        &ctx,
    )
    .map(|_| ());
    [sequential, parallel]
}

#[test]
fn data_input_may_name_a_later_transactions_output() {
    let a = pre_block_box(1);
    let b = pre_block_box(2);
    let utxo = MapUtxo(HashMap::from([
        (a.box_id().unwrap(), a.clone()),
        (b.box_id().unwrap(), b.clone()),
    ]));
    let producer = tx(vec![b.box_id().unwrap()], vec![]);
    let reader = tx(vec![a.box_id().unwrap()], vec![first_output_id(&producer)]);

    for result in validate_both(vec![reader, producer], &utxo) {
        assert!(
            result.is_ok(),
            "a forward data read must validate: {result:?}"
        );
    }
}

#[test]
fn input_may_not_spend_a_later_transactions_output() {
    let a = pre_block_box(1);
    let b = pre_block_box(2);
    let utxo = MapUtxo(HashMap::from([
        (a.box_id().unwrap(), a.clone()),
        (b.box_id().unwrap(), b.clone()),
    ]));
    let producer = tx(vec![b.box_id().unwrap()], vec![]);
    let produced = first_output_id(&producer);
    let spender = tx(vec![a.box_id().unwrap(), produced], vec![]);

    for result in validate_both(vec![spender, producer], &utxo) {
        match result {
            Err(BlockValidationError::Transaction {
                index: 0,
                error: ValidationError::InputBoxNotFound { box_id },
            }) => assert_eq!(box_id, hex::encode(produced.as_bytes())),
            other => panic!("a forward spend must not resolve: {other:?}"),
        }
    }
}
