//! Discover the emission input from the committed parent's persisted identity.
//! Oracle: test-vectors/ergo-sigma/cost-ledger/emission-discovery.json

use crate::error::MiningError;
use crate::state_view::CandidateStateView;
use ergo_chain_spec::{Network, ReemissionParams};
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::Header;

/// Resolve the committed identity in constant time, including exhaustion.
pub fn lookup_tip_emission_box<V: CandidateStateView>(
    view: &V,
    parent_header_id: &[u8; 32],
    _network: Network,
    _reemission: Option<&ReemissionParams>,
) -> Result<Option<ErgoBox>, MiningError> {
    let identity = view
        .emission_identity(parent_header_id)
        .map_err(|e| MiningError::StateRead {
            op: "emission_identity",
            reason: e.to_string(),
        })?
        .ok_or_else(|| MiningError::StateRead {
            op: "emission_identity",
            reason: "emission metadata unavailable after bounded legacy recovery".into(),
        })?;
    identity
        .map(|id| {
            view.get_box(&id)
                .ok_or_else(|| MiningError::EmissionInvariant {
                    op: "emission_box_lookup",
                    reason: "tracked emission box is absent from committed UTXO state".into(),
                })
        })
        .transpose()
}

/// Candidate path uses the same persisted parent identity as public lookup.
pub fn lookup_emission_box_from_parent<V: CandidateStateView>(
    view: &V,
    parent_header_id: &[u8; 32],
    _parent_header: &Header,
    network: Network,
    reemission: Option<&ReemissionParams>,
) -> Result<Option<ErgoBox>, MiningError> {
    lookup_tip_emission_box(view, parent_header_id, network, reemission)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::ModifierId;
    use ergo_primitives::digest::{ADDigest, Digest32};
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::block_transactions::{write_block_transactions_with_version, BlockTransactions};
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::ergo_tree::read_ergo_tree;
    use ergo_ser::header::{serialize_header, Header};
    use ergo_ser::input::{ContextExtension, Input, SpendingProof};
    use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::transaction::Transaction;
    use ergo_state::store::emission::{
        box_id, emission_tree, genesis_id, has_emission_box, next_emission_id, output_box,
    };
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
        store.recover_emission_identity(id.as_bytes()).unwrap();
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
        assert_eq!(
            box_id(actual.as_ref().unwrap()).unwrap(),
            box_id(&expected).unwrap()
        );
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
        assert_eq!(
            box_id(actual.as_ref().unwrap()).unwrap(),
            box_id(&expected).unwrap()
        );
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

    #[test]
    fn emission_lookup_exhausted_identity_returns_none() {
        let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        let emission = synthetic_emission_tx();
        let mut spent = ordinary_tx();
        spent.inputs[0].box_id = box_id(&output_box(&emission).unwrap()).unwrap();
        let (mut header, _, _) = synth_header();
        let first = store_block(&store, &header, vec![emission]);
        header.height = 2;
        header.parent_id = ModifierId::from_bytes(first);
        let tip = store_block(&store, &header, vec![spent]);
        assert!(lookup_tip_emission_box(&store, &tip, Network::Devnet, None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn emission_matching_noncanonical_encoding_preserves_scala_equality() {
        let canonical = emission_tree(Network::Devnet);
        // Constant-segregated tree: encode its constant count with an extra
        // zero VLQ group. Scala compares the parsed constants and root.
        assert_eq!(canonical[0] & 0x10, 0x10);
        let mut encoded = canonical.clone();
        assert!(encoded[1] < 128);
        encoded[1] |= 0x80;
        encoded.insert(2, 0);
        let parsed = read_ergo_tree(&mut VlqReader::new(&encoded)).unwrap();
        let mut tx = synthetic_emission_tx();
        let old = &tx.output_candidates[0];
        tx.output_candidates[0] = ErgoBoxCandidate::from_trusted_raw_parts(
            old.value,
            parsed,
            encoded.clone(),
            old.creation_height,
            old.tokens.clone(),
            AdditionalRegisters::empty(),
            vec![0],
        );
        assert_ne!(encoded, canonical);
        assert!(has_emission_box(&tx, 1, &canonical, None));
        assert!(next_emission_id(None, &[tx.clone()], 1, &canonical, None)
            .unwrap()
            .is_some());
        encoded[0] |= 0x40;
        let old = &tx.output_candidates[0];
        tx.output_candidates[0] = ErgoBoxCandidate::from_trusted_raw_parts(
            old.value,
            old.ergo_tree().clone(),
            encoded,
            old.creation_height,
            old.tokens.clone(),
            AdditionalRegisters::empty(),
            vec![0],
        );
        assert!(!has_emission_box(&tx, 1, &canonical, None));
    }

    // ----- round-trips -----

    #[test]
    fn emission_lookup_restart_after_omission_retains_identity_without_history() {
        let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let path = dir.path().join("state.redb");
        let mut store = StateStore::open(&path).unwrap();
        let emission = synthetic_emission_tx();
        let expected = output_box(&emission).unwrap();
        seed_box(&mut store, &expected);
        let (mut header, _, _) = synth_header();
        let first = store_block(&store, &header, vec![emission]);
        header.height = 2;
        header.parent_id = ModifierId::from_bytes(first);
        let tip = store_block(&store, &header, vec![ordinary_tx()]);
        let section = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            &tip,
            header.transactions_root.as_bytes(),
        );
        // Corrupt the retained section to prove lookup never replays history.
        store.store_block_section(&section, &[0xff]).unwrap();
        drop(store);
        let store = StateStore::open(&path).unwrap();
        let actual = lookup_tip_emission_box(&store, &tip, Network::Devnet, None)
            .unwrap()
            .unwrap();
        assert_eq!(box_id(&actual).unwrap(), box_id(&expected).unwrap());
        let snapshot = store.committed_snapshot().unwrap().unwrap();
        assert_eq!(
            snapshot.emission_identity(&tip).unwrap(),
            store.emission_identity(&tip).unwrap()
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
