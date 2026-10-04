//! Synthetic full blocks bound to a real mainnet header.
//!
//! Tests choose the transactions, pre-block boxes, header version and
//! protocol parameters; the helpers recompute the transaction and extension
//! roots so the block passes section binding and reaches transaction
//! validation on both the sequential and the production (parallel) path.

use std::collections::HashMap;

use ergo_crypto::autolykos::common::blake2b256;
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
use ergo_validation::header::CheckedHeader;

pub(crate) const VALUE: u64 = 1_000_000_000;
/// Height of the mainnet header every synthetic block reuses.
pub(crate) const HEIGHT: u32 = 1000;
const HEADER_ID: [u8; 32] = [0x5a; 32];

pub(crate) struct MapUtxo(pub(crate) HashMap<Digest32, ErgoBox>);

impl MapUtxo {
    pub(crate) fn of(boxes: &[&ErgoBox]) -> Self {
        Self(
            boxes
                .iter()
                .map(|b| (b.box_id().unwrap(), (*b).clone()))
                .collect(),
        )
    }
}

impl UtxoView for MapUtxo {
    fn get_box(&self, id: &Digest32) -> Option<ErgoBox> {
        self.0.get(id).cloned()
    }
}

/// `sigmaProp(true)` at the given ErgoTree version.
pub(crate) fn true_tree(version: u8) -> ErgoTree {
    ErgoTree {
        version,
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

pub(crate) fn candidate(tree_version: u8, creation_height: u32) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(
        VALUE,
        true_tree(tree_version),
        creation_height,
        vec![],
        AdditionalRegisters::empty(),
    )
    .unwrap()
}

/// A pre-block box with a distinct creating transaction id.
pub(crate) fn pre_block_box(fill: u8, tree_version: u8, creation_height: u32) -> ErgoBox {
    ErgoBox::new(
        candidate(tree_version, creation_height),
        ModifierId::from_bytes([fill; 32]),
        0,
    )
}

/// One `sigmaProp(true)` output at `output_height` per input.
pub(crate) fn tx(
    inputs: Vec<Digest32>,
    data_inputs: Vec<Digest32>,
    output_height: u32,
) -> Transaction {
    Transaction {
        output_candidates: inputs.iter().map(|_| candidate(0, output_height)).collect(),
        inputs: inputs
            .into_iter()
            .map(|box_id| Input {
                box_id,
                spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
            })
            .collect(),
        data_inputs: data_inputs
            .into_iter()
            .map(|box_id| DataInput { box_id })
            .collect(),
    }
}

pub(crate) fn first_output_id(tx: &Transaction) -> Digest32 {
    ErgoBox::new(
        tx.output_candidates[0].clone(),
        transaction_id(tx).unwrap(),
        0,
    )
    .box_id()
    .unwrap()
}

/// Mainnet headers at `HEIGHT - 1` and `HEIGHT`.
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

/// Bind `transactions` to a copy of the mainnet header at `HEIGHT` that
/// claims `header_version` (PoW is not rechecked by full-block validation),
/// recomputing its transaction and extension roots. Validate the block on the
/// sequential and the production (parallel) path under `params`.
pub(crate) fn validate_both(
    transactions: Vec<Transaction>,
    utxo: &MapUtxo,
    header_version: u8,
    params: &ProtocolParams,
) -> [Result<(), BlockValidationError>; 2] {
    let (parent, mut header) = parent_and_header();
    header.version = header_version;
    let tx_ids: Vec<ModifierId> = transactions
        .iter()
        .map(|tx| transaction_id(tx).unwrap())
        .collect();
    let id_refs: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_bytes().as_slice()).collect();
    let witnesses: Vec<Vec<u8>> = transactions
        .iter()
        .map(|tx| {
            let proofs: Vec<u8> = tx
                .inputs
                .iter()
                .flat_map(|input| input.spending_proof.proof.iter().copied())
                .collect();
            blake2b256(&proofs)[1..].to_vec()
        })
        .collect();
    let witness_refs: Vec<&[u8]> = witnesses.iter().map(Vec::as_slice).collect();
    let witness_refs = (header_version >= 2).then_some(witness_refs.as_slice());
    header.transactions_root = Digest32::from_bytes(transactions_root(&id_refs, witness_refs));
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

    let checked_parent = CheckedHeader::trust_me(parent, [0x11; 32]);
    let ctx = BlockValidationContext {
        parent: &checked_parent,
        utxo,
        params,
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
