//! Discover an unspent emission output on the applied parent ancestry.
//! Oracle: test-vectors/ergo-sigma/cost-ledger/emission-discovery.json
//!
//! Blocks may omit emission and may put ordinary transactions first. Discovery
//! follows parent IDs (not the best-header height index) and resolves the matched
//! box against the same committed UTXO view used to build the candidate.

use ergo_primitives::digest::{blake2b256, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::block_transactions::read_block_transactions;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::{read_header, Header};
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
use ergo_state::store::StateError;

use crate::error::MiningError;
use crate::state_view::CandidateStateView;
use ergo_chain_spec::{Network, ReemissionParams};

/// Look up the next emission input using the selected network's contract.
pub fn lookup_tip_emission_box<V: CandidateStateView>(
    view: &V,
    parent_header_id: &[u8; 32],
    network: Network,
    reemission: Option<&ReemissionParams>,
) -> Result<ErgoBox, MiningError> {
    let header = load_header(view, parent_header_id)?;
    lookup_emission_box_from_parent(view, parent_header_id, &header, network, reemission)
}

fn load_header<V: CandidateStateView>(view: &V, id: &[u8; 32]) -> Result<Header, MiningError> {
    let bytes = view
        .get_header_bytes(id)
        .map_err(state_err)?
        .ok_or_else(|| MiningError::StateRead {
            op: "emission_parent_header",
            reason: format!("parent header {} not stored", hex::encode(id)),
        })?;
    read_header(&mut VlqReader::new(&bytes)).map_err(|e| MiningError::Decode {
        op: "emission_parent_header",
        reason: format!("{e:?}"),
    })
}

/// The current networks share the same monetary emission proposition.
/// Read it from the JVM genesis fixture, independently of the miner's key.
fn emission_tree(network: Network) -> Vec<u8> {
    let genesis = ergo_chain_spec::GenesisParams::for_network(network);
    let boxes: serde_json::Value =
        serde_json::from_str(genesis.boxes_json.expect("network genesis boxes"))
            .expect("embedded genesis JSON");
    hex::decode(
        boxes[0]["ergoTree"]
            .as_str()
            .expect("genesis emission tree"),
    )
    .expect("genesis tree hex")
}

fn has_emission_box(
    tx: &ergo_ser::transaction::Transaction,
    height: u32,
    tree: &[u8],
    reemission: Option<&ReemissionParams>,
) -> bool {
    let Some(output) = tx.output_candidates.first() else {
        return false;
    };
    if let Some(reem) = reemission.filter(|r| height > r.activation_height) {
        tx.output_candidates.len() == 2
            && output
                .tokens
                .first()
                .is_some_and(|t| t.token_id == reem.emission_nft_id)
    } else {
        output.ergo_tree_bytes() == tree
    }
}

fn output_box(tx: &ergo_ser::transaction::Transaction) -> Result<ErgoBox, MiningError> {
    let bytes =
        ergo_ser::transaction::bytes_to_sign(tx).map_err(|e| MiningError::IdComputation {
            op: "bytes_to_sign",
            reason: format!("{e:?}"),
        })?;
    Ok(ErgoBox {
        candidate: tx.output_candidates[0].clone(),
        transaction_id: ModifierId::from(blake2b256(&bytes)),
        index: 0,
    })
}

fn box_id(b: &ErgoBox) -> Result<ergo_primitives::digest::Digest32, MiningError> {
    b.box_id().map_err(|e| MiningError::IdComputation {
        op: "emission_box_id",
        reason: format!("{e:?}"),
    })
}

fn genesis_id(network: Network) -> ergo_primitives::digest::Digest32 {
    let genesis = ergo_chain_spec::GenesisParams::for_network(network);
    let boxes: serde_json::Value =
        serde_json::from_str(genesis.boxes_json.expect("network genesis boxes"))
            .expect("embedded genesis JSON");
    let id = hex::decode(boxes[0]["boxId"].as_str().expect("genesis emission id"))
        .expect("genesis id hex");
    ergo_primitives::digest::Digest32::from_bytes(id.try_into().expect("32-byte genesis id"))
}

/// Reconstruct Scala's tracked emission identity along the applied ancestry.
/// The genesis input or unique post-EIP-27 NFT anchors the lineage. Later
/// blocks update it only by spending that identity; unrelated contract outputs
/// cannot replace an unspent tracked box. This uses no best-header index or
/// process-local cache, so rollback and committed snapshots share the same rule.
/// Pre-EIP-27 recovery requires history back to the genesis emission spend.
pub fn lookup_emission_box_from_parent<V: CandidateStateView>(
    view: &V,
    parent_header_id: &[u8; 32],
    parent_header: &Header,
    network: Network,
    reemission: Option<&ReemissionParams>,
) -> Result<ErgoBox, MiningError> {
    let tree = emission_tree(network);
    let genesis = genesis_id(network);
    let mut header = parent_header.clone();
    let mut id = *parent_header_id;
    let mut pending = Vec::new();
    let mut tracked = Some(genesis);
    loop {
        let section_id = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            &id,
            header.transactions_root.as_bytes(),
        );
        let bytes = view
            .block_section(&section_id)
            .map_err(state_err)?
            .ok_or_else(|| MiningError::StateRead {
                op: "emission_block_transactions",
                reason: format!(
                    "BlockTransactions section {} not stored",
                    hex::encode(section_id)
                ),
            })?;
        let bt = read_block_transactions(&mut VlqReader::new(&bytes)).map_err(|e| {
            MiningError::Decode {
                op: "BlockTransactions",
                reason: format!("{e:?}"),
            }
        })?;
        // The NFT is unique: after activation it independently identifies the
        // tracked emission output without replaying pre-activation history.
        if reemission.is_some_and(|r| header.height > r.activation_height) {
            if let Some(tx) = bt
                .transactions
                .iter()
                .find(|tx| has_emission_box(tx, header.height, &tree, reemission))
            {
                tracked = Some(box_id(&output_box(tx)?)?);
                break;
            }
        }
        let genesis_spent = bt
            .transactions
            .iter()
            .any(|tx| tx.inputs.iter().any(|i| i.box_id == genesis));
        pending.push((header.height, bt.transactions));
        if genesis_spent || header.height <= 1 {
            break;
        }
        id = *header.parent_id.as_bytes();
        let parent = load_header(view, &id)?;
        if parent.height.checked_add(1) != Some(header.height) {
            return Err(MiningError::EmissionInvariant {
                op: "emission_box_lookup",
                reason: "nonconsecutive applied ancestry".into(),
            });
        }
        header = parent;
    }
    for (height, txs) in pending.into_iter().rev() {
        tracked = next_emission_id(tracked, &txs, height, &tree, reemission)?;
    }
    tracked
        .and_then(|id| view.get_box(&id))
        .ok_or_else(|| MiningError::EmissionInvariant {
            op: "emission_box_lookup",
            reason: "tracked emission box is absent from committed UTXO state".into(),
        })
}

/// Scala UtxoStateReader.extractEmissionBox: reverse spending search, retain
/// when unspent, and use the first matching transaction for untracked recovery.
fn next_emission_id(
    tracked: Option<ergo_primitives::digest::Digest32>,
    txs: &[ergo_ser::transaction::Transaction],
    height: u32,
    tree: &[u8],
    reemission: Option<&ReemissionParams>,
) -> Result<Option<ergo_primitives::digest::Digest32>, MiningError> {
    let selected = if let Some(id) = tracked {
        match txs
            .iter()
            .rev()
            .find(|tx| tx.inputs.iter().any(|i| i.box_id == id))
        {
            Some(tx) => has_emission_box(tx, height, tree, reemission).then_some(tx),
            None => return Ok(Some(id)),
        }
    } else {
        // Scala filters AFTER find, rather than selecting a later large output.
        txs.iter()
            .find(|tx| has_emission_box(tx, height, tree, reemission))
            .filter(|tx| tx.output_candidates[0].value > 100_000 * 1_000_000_000)
    };
    selected
        .map(|tx| output_box(tx).and_then(|b| box_id(&b)))
        .transpose()
}

fn state_err(e: StateError) -> MiningError {
    MiningError::StateRead {
        op: "emission_box_lookup",
        reason: format!("{e:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::{ADDigest, Digest32};
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::block_transactions::{write_block_transactions_with_version, BlockTransactions};
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::ergo_tree::read_ergo_tree;
    use ergo_ser::header::{serialize_header, Header};
    use ergo_ser::input::{ContextExtension, Input, SpendingProof};
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::transaction::Transaction;
    use ergo_state::store::StateStore;

    // ----- helpers -----

    fn emission_contract() -> (Vec<u8>, ergo_ser::ergo_tree::ErgoTree) {
        let bytes = emission_tree(Network::Devnet);
        let mut r = VlqReader::new(&bytes);
        let tree = read_ergo_tree(&mut r).unwrap();
        (bytes, tree)
    }

    fn synthetic_emission_tx() -> Transaction {
        let (bytes, tree) = emission_contract();
        // Anchor the synthetic history to the known genesis emission identity.
        let input = Input {
            box_id: genesis_id(Network::Devnet),
            spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty()).unwrap(),
        };
        // Two outputs: emission (output[0]) + miner (output[1]).
        let em_out = ErgoBoxCandidate::from_trusted_raw_parts(
            93_409_065_000_000_000u64,
            tree.clone(),
            bytes.clone(),
            1,
            Vec::new(),
            AdditionalRegisters::empty(),
            vec![0x00],
        );
        let miner_out = ErgoBoxCandidate::from_trusted_raw_parts(
            65_000_000_000,
            tree,
            bytes,
            1,
            Vec::new(),
            AdditionalRegisters::empty(),
            vec![0x00],
        );
        Transaction {
            inputs: vec![input],
            data_inputs: Vec::new(),
            output_candidates: vec![em_out, miner_out],
        }
    }

    fn synth_header() -> (Header, ModifierId, [u8; 32]) {
        let mut hdr = Header {
            version: 2,
            parent_id: Digest32::from_bytes([0u8; 32]).into(),
            ad_proofs_root: Digest32::from_bytes([0u8; 32]),
            transactions_root: Digest32::from_bytes([0u8; 32]),
            state_root: ADDigest::from_bytes([0u8; 33]),
            timestamp: 1_700_000_000_000,
            extension_root: Digest32::from_bytes([0u8; 32]),
            n_bits: 0,
            height: 1,
            votes: [0u8; 3],
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
                nonce: [0u8; 8],
            },
        };
        // Synthetic transactions_root: just use the section_digest the
        // reader will expect.
        let tx_root = [0x77u8; 32];
        hdr.transactions_root = Digest32::from_bytes(tx_root);
        let (_bytes, id) = serialize_header(&hdr).unwrap();
        (hdr, id, tx_root)
    }

    fn store_block(store: &StateStore, header: &Header, txs: Vec<Transaction>) -> [u8; 32] {
        let (bytes, id) = serialize_header(header).unwrap();
        store.store_header(id.as_bytes(), &bytes).unwrap();
        let bt = BlockTransactions {
            header_id: id,
            transactions: txs,
        };
        let mut w = VlqWriter::new();
        write_block_transactions_with_version(&mut w, &bt, header.version).unwrap();
        let section = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            id.as_bytes(),
            header.transactions_root.as_bytes(),
        );
        store.store_block_section(&section, &w.result()).unwrap();
        *id.as_bytes()
    }

    fn seed_box(store: &mut StateStore, b: &ErgoBox) {
        let bytes = ergo_ser::ergo_box::serialize_ergo_box(b).unwrap();
        store
            .initialize_genesis(&[(*box_id(b).unwrap().as_bytes(), bytes)])
            .unwrap();
    }

    fn ordinary_tx() -> Transaction {
        let mut tx = synthetic_emission_tx();
        tx.inputs[0].box_id = Digest32::from_bytes([0xaa; 32]);
        let bytes =
            hex::decode("0008cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let tree = read_ergo_tree(&mut VlqReader::new(&bytes)).unwrap();
        tx.output_candidates = vec![ErgoBoxCandidate::new(
            1_000_000_000,
            tree,
            2,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap()];
        tx
    }

    // ----- happy path -----

    #[test]
    fn emission_lookup_funding_and_contract_spam_retains_tracked_box() {
        let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        let emission = synthetic_emission_tx();
        let expected = output_box(&emission).unwrap();
        seed_box(&mut store, &expected);
        let (mut hdr, _, _) = synth_header();
        let first = store_block(&store, &hdr, vec![ordinary_tx(), emission]);
        hdr.height = 2;
        hdr.parent_id = ModifierId::from_bytes(first);
        let mut spam = synthetic_emission_tx();
        spam.inputs[0].box_id = Digest32::from_bytes([0xbb; 32]);
        let tip = store_block(&store, &hdr, vec![ordinary_tx(), spam]);
        let actual = lookup_tip_emission_box(&store, &tip, Network::Devnet, None).unwrap();
        assert_eq!(box_id(&actual).unwrap(), box_id(&expected).unwrap());
    }

    #[test]
    fn emission_lookup_post_activation_funding_retains_nft_box() {
        let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        let reem = ReemissionParams::mainnet();
        let mut emission = synthetic_emission_tx();
        emission.output_candidates[0]
            .tokens
            .push(ergo_ser::token::Token {
                token_id: reem.emission_nft_id,
                amount: 1,
            });
        let expected = output_box(&emission).unwrap();
        seed_box(&mut store, &expected);
        let (mut hdr, _, _) = synth_header();
        hdr.height = reem.activation_height + 1;
        let first = store_block(&store, &hdr, vec![emission]);
        hdr.height += 1;
        hdr.parent_id = ModifierId::from_bytes(first);
        let tip = store_block(&store, &hdr, vec![ordinary_tx()]);
        let actual = lookup_tip_emission_box(&store, &tip, Network::Mainnet, Some(&reem)).unwrap();
        assert_eq!(box_id(&actual).unwrap(), box_id(&expected).unwrap());
    }

    #[test]
    fn emission_tracking_spend_updates_and_exhaustion_clears_identity() {
        let tree = emission_tree(Network::Devnet);
        let tx = synthetic_emission_tx();
        let id = next_emission_id(
            Some(genesis_id(Network::Devnet)),
            std::slice::from_ref(&tx),
            1,
            &tree,
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(id, box_id(&output_box(&tx).unwrap()).unwrap());
        let mut spent = ordinary_tx();
        spent.inputs[0].box_id = id;
        assert_eq!(
            next_emission_id(Some(id), &[spent], 2, &tree, None).unwrap(),
            None
        );
    }

    #[test]
    fn emission_matching_activation_boundary_uses_scala_predicate() {
        let tree = emission_tree(Network::Mainnet);
        let reem = ReemissionParams::mainnet();
        let mut tx = synthetic_emission_tx();
        assert!(has_emission_box(
            &tx,
            reem.activation_height,
            &tree,
            Some(&reem)
        ));
        assert!(!has_emission_box(
            &tx,
            reem.activation_height + 1,
            &tree,
            Some(&reem)
        ));
        tx.output_candidates[0].tokens.push(ergo_ser::token::Token {
            token_id: reem.emission_nft_id,
            amount: 1,
        });
        assert!(has_emission_box(
            &tx,
            reem.activation_height + 1,
            &tree,
            Some(&reem)
        ));
        tx.output_candidates.pop();
        assert!(!has_emission_box(
            &tx,
            reem.activation_height + 1,
            &tree,
            Some(&reem)
        ));
    }

    #[test]
    fn emission_recovery_small_first_match_does_not_select_later_spam() {
        let tree = emission_tree(Network::Devnet);
        let mut small = synthetic_emission_tx();
        small.output_candidates[0].value = 100_000 * 1_000_000_000;
        assert_eq!(
            next_emission_id(None, &[small, synthetic_emission_tx()], 1, &tree, None).unwrap(),
            None
        );
    }

    // ----- error paths -----

    #[test]
    fn emission_lookup_missing_header_returns_error() {
        let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        assert!(lookup_tip_emission_box(&store, &[0; 32], Network::Devnet, None).is_err());
    }

    #[test]
    fn emission_lookup_spent_output_returns_error() {
        let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        let (hdr, _, _) = synth_header();
        let tip = store_block(&store, &hdr, vec![synthetic_emission_tx()]);
        assert!(lookup_tip_emission_box(&store, &tip, Network::Devnet, None).is_err());
    }

    // ----- oracle parity -----

    // ledger: BLOCK-L6-emission-box-discovery
    #[test]
    fn emission_tracking_l6_funding_to_miner_retains_scala_box() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../test-vectors/ergo-sigma/cost-ledger/emission-discovery.json"
        ))
        .unwrap();
        let expected = Digest32::from_bytes(
            hex::decode(fixture["expected_emission_box_id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let txs: Vec<Transaction> = fixture["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tx| Transaction {
                inputs: tx["inputs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|input| Input {
                        box_id: Digest32::from_bytes(
                            hex::decode(input["boxId"].as_str().unwrap())
                                .unwrap()
                                .try_into()
                                .unwrap(),
                        ),
                        spending_proof: SpendingProof::new(
                            hex::decode(input["spendingProof"]["proofBytes"].as_str().unwrap())
                                .unwrap(),
                            ContextExtension::empty(),
                        )
                        .unwrap(),
                    })
                    .collect(),
                data_inputs: vec![],
                output_candidates: tx["outputs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|output| {
                        assert!(output["assets"].as_array().unwrap().is_empty());
                        assert!(output["additionalRegisters"]
                            .as_object()
                            .unwrap()
                            .is_empty());
                        let bytes = hex::decode(output["ergoTree"].as_str().unwrap()).unwrap();
                        let tree = read_ergo_tree(&mut VlqReader::new(&bytes)).unwrap();
                        ErgoBoxCandidate::new(
                            output["value"].as_u64().unwrap(),
                            tree,
                            output["creationHeight"].as_u64().unwrap() as u32,
                            vec![],
                            AdditionalRegisters::empty(),
                        )
                        .unwrap()
                    })
                    .collect(),
            })
            .collect();
        assert_eq!(
            hex::encode(output_box(&txs[0]).unwrap().transaction_id.as_bytes()),
            fixture["transactions"][0]["id"].as_str().unwrap()
        );
        assert_eq!(txs[0].output_candidates[0].value, 1_000_000_000);
        assert_eq!(
            next_emission_id(
                Some(expected),
                &txs,
                723,
                &emission_tree(Network::Devnet),
                None
            )
            .unwrap(),
            Some(expected)
        );
        assert!(!has_emission_box(
            &txs[0],
            723,
            &emission_tree(Network::Devnet),
            None
        ));
    }
}
