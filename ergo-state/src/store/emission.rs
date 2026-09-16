//! Persisted Scala emission identity, keyed by applied header for rollback.
//! Oracle: ergo v6.0.2 UtxoStateReader.extractEmissionBox
//!
//! Identity rows commit together with undo metadata. Header keys keep competing
//! branches independent; a rollback selects the identity at its restored tip.
//! Legacy recovery is limited to 4096 blocks and 32 MiB of section bytes.

use super::{StateError, StateStore, BLOCK_SECTIONS, HEADERS};
use ergo_chain_spec::{Network, ReemissionParams};
use ergo_primitives::digest::{blake2b256, Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::block_transactions::read_block_transactions;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::read_header;
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
use redb::{ReadableTable, TableDefinition, WriteTransaction};

pub(crate) const EMISSION_IDENTITIES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("emission_identities");

/// Identity serialization / transaction-id computation failure.
#[derive(Debug, thiserror::Error)]
pub enum TrackingError {
    #[error("{op}: {reason}")]
    IdComputation { op: &'static str, reason: String },
}

/// JVM genesis emission proposition for the selected network.
pub fn emission_tree(network: Network) -> Vec<u8> {
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

/// Scala contract / first-token predicate at the activation boundary.
pub fn has_emission_box(
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
        output.ergo_tree_bytes().first() == tree.first()
            && ergo_ser::ergo_tree::read_ergo_tree(&mut VlqReader::new(tree))
                .is_ok_and(|parsed| *output.ergo_tree() == parsed)
    }
}

/// First output with its transaction reference, for a matching transaction.
pub fn output_box(tx: &ergo_ser::transaction::Transaction) -> Result<ErgoBox, TrackingError> {
    let bytes =
        ergo_ser::transaction::bytes_to_sign(tx).map_err(|e| TrackingError::IdComputation {
            op: "bytes_to_sign",
            reason: format!("{e:?}"),
        })?;
    Ok(ErgoBox {
        candidate: tx.output_candidates[0].clone(),
        transaction_id: ModifierId::from(blake2b256(&bytes)),
        index: 0,
    })
}

/// Compute the tracked box identity from its canonical box serialization.
pub fn box_id(b: &ErgoBox) -> Result<ergo_primitives::digest::Digest32, TrackingError> {
    b.box_id().map_err(|e| TrackingError::IdComputation {
        op: "emission_box_id",
        reason: format!("{e:?}"),
    })
}

/// JVM genesis emission identity for lineage recovery.
pub fn genesis_id(network: Network) -> ergo_primitives::digest::Digest32 {
    let genesis = ergo_chain_spec::GenesisParams::for_network(network);
    let boxes: serde_json::Value =
        serde_json::from_str(genesis.boxes_json.expect("network genesis boxes"))
            .expect("embedded genesis JSON");
    let id = hex::decode(boxes[0]["boxId"].as_str().expect("genesis emission id"))
        .expect("genesis id hex");
    ergo_primitives::digest::Digest32::from_bytes(id.try_into().expect("32-byte genesis id"))
}

/// Scala reverse spending search, retention, and filter-after-find recovery.
pub fn next_emission_id(
    tracked: Option<ergo_primitives::digest::Digest32>,
    txs: &[ergo_ser::transaction::Transaction],
    height: u32,
    tree: &[u8],
    reemission: Option<&ReemissionParams>,
) -> Result<Option<ergo_primitives::digest::Digest32>, TrackingError> {
    let summaries = txs
        .iter()
        .map(|tx| {
            let matches = has_emission_box(tx, height, tree, reemission);
            EmissionTransaction::from_transaction(tx, [matches; 3], false)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(next_from_summaries(tracked, &summaries, 0))
}

fn next_from_summaries(
    tracked: Option<Digest32>,
    transactions: &[EmissionTransaction],
    index: usize,
) -> Option<Digest32> {
    let selected = if let Some(id) = tracked {
        match transactions.iter().rev().find(|tx| tx.inputs.contains(&id)) {
            Some(tx) => tx.matches[index].then_some(tx),
            None => return Some(id),
        }
    } else {
        // Scala filters AFTER find, rather than selecting a later large output.
        transactions
            .iter()
            .find(|tx| tx.matches[index])
            .filter(|tx| {
                tx.output
                    .is_some_and(|(_, value)| value > 100_000 * 1_000_000_000)
            })
    };
    selected.and_then(|tx| tx.output.map(|(id, _)| id))
}

#[derive(Clone, Copy)]
struct Identity {
    network: Network,
    id: Option<Digest32>,
}

impl Identity {
    fn encode(self) -> Vec<u8> {
        let mut bytes = vec![match self.network {
            Network::Mainnet => 0,
            Network::Testnet => 1,
            Network::Devnet => 2,
        }];
        if let Some(id) = self.id {
            bytes.extend_from_slice(id.as_bytes());
        }
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, StateError> {
        if bytes.len() != 1 && bytes.len() != 33 {
            return Err(StateError::Serialization(
                "invalid emission identity length".into(),
            ));
        }
        let network = match bytes[0] {
            0 => Network::Mainnet,
            1 => Network::Testnet,
            2 => Network::Devnet,
            _ => return Err(StateError::Serialization("invalid emission network".into())),
        };
        Ok(Self {
            network,
            id: (bytes.len() == 33)
                .then(|| Digest32::from_bytes(bytes[1..].try_into().expect("checked length"))),
        })
    }
}

pub(crate) fn decode_identity(bytes: &[u8]) -> Result<Option<Digest32>, StateError> {
    Ok(Identity::decode(bytes)?.id)
}

pub(crate) fn seed_genesis(
    txn: &WriteTransaction,
    boxes: &[([u8; 32], Vec<u8>)],
) -> Result<(), StateError> {
    for network in [Network::Mainnet, Network::Testnet, Network::Devnet] {
        let id = genesis_id(network);
        if boxes.iter().any(|(box_id, _)| box_id == id.as_bytes()) {
            txn.open_table(EMISSION_IDENTITIES)?.insert(
                [0u8; 32].as_slice(),
                Identity {
                    network,
                    id: Some(id),
                }
                .encode()
                .as_slice(),
            )?;
            break;
        }
    }
    Ok(())
}

/// Compact validated block data carried into either persistence path. Ordinary
/// outputs and proofs are not retained; only input ids and emission matches are
/// needed by Scala's reverse-spend / first-match rules.
#[derive(Clone, Default)]
pub(crate) struct EmissionTransition {
    parent: [u8; 32],
    transactions: Vec<EmissionTransaction>,
}

#[derive(Clone)]
struct EmissionTransaction {
    inputs: Vec<Digest32>,
    matches: [bool; 3],
    nft_anchor: bool,
    output: Option<(Digest32, u64)>,
}

impl EmissionTransaction {
    fn from_transaction(
        tx: &ergo_ser::transaction::Transaction,
        matches: [bool; 3],
        nft_anchor: bool,
    ) -> Result<Self, TrackingError> {
        let output = if matches.iter().any(|matched| *matched) {
            Some((box_id(&output_box(tx)?)?, tx.output_candidates[0].value))
        } else {
            None
        };
        Ok(Self {
            inputs: tx.inputs.iter().map(|input| input.box_id).collect(),
            matches,
            nft_anchor,
            output,
        })
    }
}

const NETWORKS: [Network; 3] = [Network::Mainnet, Network::Testnet, Network::Devnet];

impl EmissionTransition {
    pub(crate) fn prepare<'a>(
        parent: [u8; 32],
        height: u32,
        txs: impl Iterator<Item = &'a ergo_ser::transaction::Transaction>,
    ) -> Result<Self, StateError> {
        let trees = NETWORKS.map(emission_tree);
        let reem = ReemissionParams::mainnet();
        let mut transactions = Vec::new();
        for tx in txs {
            let matches = std::array::from_fn(|i| {
                has_emission_box(tx, height, &trees[i], (i == 0).then_some(&reem))
            });
            transactions.push(
                EmissionTransaction::from_transaction(
                    tx,
                    matches,
                    height > reem.activation_height && matches[0],
                )
                .map_err(tracking_error)?,
            );
        }
        Ok(Self {
            parent,
            transactions,
        })
    }
}

pub(crate) fn persist_transition(
    txn: &WriteTransaction,
    tip: &[u8; 32],
    transition: &EmissionTransition,
) -> Result<(), StateError> {
    let mut table = txn.open_table(EMISSION_IDENTITIES)?;
    let parent = table
        .get(transition.parent.as_slice())?
        .map(|row| Identity::decode(row.value()))
        .transpose()?;
    let mut identity = if let Some(parent) = parent {
        parent
    } else {
        let genesis = NETWORKS.into_iter().find_map(|network| {
            let id = genesis_id(network);
            transition
                .transactions
                .iter()
                .any(|tx| tx.inputs.contains(&id))
                .then_some(Identity {
                    network,
                    id: Some(id),
                })
        });
        if let Some(genesis) = genesis {
            genesis
        } else if let Some(tx) = transition.transactions.iter().find(|tx| tx.nft_anchor) {
            let identity = Identity {
                network: Network::Mainnet,
                id: tx.output.map(|(id, _)| id),
            };
            table.insert(tip.as_slice(), identity.encode().as_slice())?;
            return Ok(());
        } else {
            return Ok(());
        }
    };
    let index = NETWORKS
        .iter()
        .position(|network| *network == identity.network)
        .expect("known network");
    identity.id = next_from_summaries(identity.id, &transition.transactions, index);
    table.insert(tip.as_slice(), identity.encode().as_slice())?;
    Ok(())
}

/// Restart-only recovery retains a bounded historical suffix. Normal apply
/// carries a compact transition directly from the transactions being applied.
fn recover_identity(
    txn: &WriteTransaction,
    tip: &[u8; 32],
    limit: usize,
) -> Result<(), StateError> {
    let mut table = txn.open_table(EMISSION_IDENTITIES)?;
    if table.get(tip.as_slice())?.is_some() {
        return Ok(());
    }
    let headers = txn.open_table(HEADERS)?;
    let sections = txn.open_table(BLOCK_SECTIONS)?;
    let mut pending = Vec::new();
    let mut current = *tip;
    let mut total_bytes = 0usize;
    let mut child_height: Option<u32> = None;
    let mut identity;
    loop {
        if let Some(row) = table.get(current.as_slice())? {
            identity = Identity::decode(row.value())?;
            break;
        }
        if pending.len() >= limit {
            return Ok(());
        }
        let Some(bytes) = headers.get(current.as_slice())? else {
            return Ok(());
        };
        let Ok(header) = read_header(&mut VlqReader::new(bytes.value())) else {
            // Unusable legacy history does not establish an exhausted identity.
            return Ok(());
        };
        if child_height.is_some_and(|child| header.height.checked_add(1) != Some(child)) {
            return Ok(());
        }
        child_height = Some(header.height);
        let section = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            &current,
            header.transactions_root.as_bytes(),
        );
        let Some(bytes) = sections.get(section.as_slice())? else {
            return Ok(());
        };
        total_bytes = total_bytes.saturating_add(bytes.value().len());
        if total_bytes > 32 * 1024 * 1024 {
            return Ok(());
        }
        let Ok(block) = read_block_transactions(&mut VlqReader::new(bytes.value())) else {
            return Ok(());
        };
        let parent = if header.height == 1 {
            [0; 32]
        } else {
            *header.parent_id.as_bytes()
        };
        if let Some(row) = table.get(parent.as_slice())? {
            identity = Identity::decode(row.value())?;
            pending.push((current, header.height, block.transactions));
            break;
        }
        let anchor = [Network::Mainnet, Network::Testnet, Network::Devnet]
            .into_iter()
            .find(|network| {
                let genesis = genesis_id(*network);
                block
                    .transactions
                    .iter()
                    .any(|tx| tx.inputs.iter().any(|i| i.box_id == genesis))
            });
        if let Some(network) = anchor {
            identity = Identity {
                network,
                id: Some(genesis_id(network)),
            };
            pending.push((current, header.height, block.transactions));
            break;
        }
        let reem = ReemissionParams::mainnet();
        if header.height > reem.activation_height {
            if let Some(tx) = block
                .transactions
                .iter()
                .find(|tx| has_emission_box(tx, header.height, &[], Some(&reem)))
            {
                identity = Identity {
                    network: Network::Mainnet,
                    id: Some(
                        box_id(&output_box(tx).map_err(tracking_error)?).map_err(tracking_error)?,
                    ),
                };
                table.insert(current.as_slice(), identity.encode().as_slice())?;
                break;
            }
        }
        let parent = *header.parent_id.as_bytes();
        pending.push((current, header.height, block.transactions));
        current = if header.height == 1 { [0; 32] } else { parent };
    }
    let tree = emission_tree(identity.network);
    let reem = (identity.network == Network::Mainnet).then(ReemissionParams::mainnet);
    for (id, height, txs) in pending.into_iter().rev() {
        identity.id = next_emission_id(identity.id, &txs, height, &tree, reem.as_ref())
            .map_err(tracking_error)?;
        table.insert(id.as_slice(), identity.encode().as_slice())?;
    }
    Ok(())
}

/// Keep the rollback target's identity after its undo row is pruned; retire
/// the immediately preceding canonical identity on the next apply.
pub(crate) fn prune_identity(
    txn: &WriteTransaction,
    prune_below: Option<u32>,
) -> Result<(), StateError> {
    let Some(height) = prune_below
        .and_then(|h| h.checked_sub(1))
        .filter(|h| *h > 0)
    else {
        return Ok(());
    };
    let chain = txn.open_table(super::CHAIN_INDEX)?;
    if let Some(id) = chain.get(height as u64)? {
        txn.open_table(EMISSION_IDENTITIES)?.remove(id.value())?;
    }
    Ok(())
}

fn tracking_error(e: TrackingError) -> StateError {
    StateError::Serialization(e.to_string())
}

impl StateStore {
    /// Bounded migration for a legacy applied tip. Normal applies persist this
    /// row atomically with undo metadata before exposing the new tip.
    pub fn recover_emission_identity(&self, tip: &[u8; 32]) -> Result<(), StateError> {
        let txn = crate::begin_write_qr(&self.db)?;
        recover_identity(&txn, tip, 4096)?;
        txn.commit()?;
        Ok(())
    }

    /// Outer `None` means unavailable legacy metadata; inner `None` means
    /// Scala cleared the identity after its tracked input was consumed.
    pub fn emission_identity(
        &self,
        tip: &[u8; 32],
    ) -> Result<Option<Option<Digest32>>, StateError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(EMISSION_IDENTITIES)?;
        table
            .get(tip.as_slice())?
            .map(|row| decode_identity(row.value()))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::ADDigest;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::block_transactions::{write_block_transactions_with_version, BlockTransactions};
    use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBoxCandidate};
    use ergo_ser::ergo_tree::read_ergo_tree;
    use ergo_ser::header::{serialize_header, Header};
    use ergo_ser::input::{ContextExtension, Input, SpendingProof};
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::transaction::Transaction;

    // ----- helpers -----

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

    fn transaction(input: Digest32, height: u32) -> Transaction {
        let bytes = emission_tree(Network::Devnet);
        let tree = read_ergo_tree(&mut VlqReader::new(&bytes)).unwrap();
        Transaction {
            inputs: vec![Input {
                box_id: input,
                spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate::new(
                1_000_000_000_000_000,
                tree,
                height,
                vec![],
                AdditionalRegisters::empty(),
            )
            .unwrap()],
        }
    }

    fn seeded_store(path: &std::path::Path) -> (StateStore, Digest32) {
        let mut store = StateStore::open(path).unwrap();
        let b = output_box(&transaction(Digest32::from_bytes([0x99; 32]), 0)).unwrap();
        let id = box_id(&b).unwrap();
        store
            .initialize_genesis(&[(*id.as_bytes(), serialize_ergo_box(&b).unwrap())])
            .unwrap();
        let txn = crate::begin_write_qr(&store.db).unwrap();
        txn.open_table(EMISSION_IDENTITIES)
            .unwrap()
            .insert(
                [0u8; 32].as_slice(),
                Identity {
                    network: Network::Devnet,
                    id: Some(id),
                }
                .encode()
                .as_slice(),
            )
            .unwrap();
        txn.commit().unwrap();
        (store, id)
    }

    fn apply(store: &mut StateStore, height: u32, txs: Vec<Transaction>, nonce: u64) -> [u8; 32] {
        let (removes, inserts) =
            StateStore::build_utxo_changes_raw(&txs.iter().collect::<Vec<_>>()).unwrap();
        let (root, _) = super::super::dry_run::apply_change_set_via_prover(
            &store.tree,
            &[],
            &removes,
            &inserts,
        )
        .unwrap();
        let (mut header, _, _) = synth_header();
        header.height = height;
        header.timestamp += nonce;
        header.parent_id = ModifierId::from_bytes(store.chain_state.best_full_block_id);
        header.state_root = root;
        let (bytes, id) = serialize_header(&header).unwrap();
        store.store_header(id.as_bytes(), &bytes).unwrap();
        let mut writer = VlqWriter::new();
        write_block_transactions_with_version(
            &mut writer,
            &BlockTransactions {
                header_id: id,
                transactions: txs.clone(),
            },
            header.version,
        )
        .unwrap();
        let section = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            id.as_bytes(),
            header.transactions_root.as_bytes(),
        );
        store
            .store_block_section(&section, &writer.result())
            .unwrap();
        store
            .apply_block_unchecked(height, id.as_bytes(), &root, &txs)
            .unwrap();
        *id.as_bytes()
    }

    // ----- happy path -----

    #[test]
    fn emission_identity_atomic_apply_and_pipeline_preserve_omission() {
        for pipeline in [false, true] {
            let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
            let (mut store, seed) = seeded_store(&dir.path().join("state.redb"));
            if pipeline {
                store.enable_persist_pipeline(8);
            }
            let tx = transaction(seed, 1);
            let expected = box_id(&output_box(&tx).unwrap()).unwrap();
            apply(&mut store, 1, vec![tx], 1);
            let tip = apply(&mut store, 2, vec![], 2);
            store.flush_persist_pipeline().unwrap();
            assert_eq!(store.emission_identity(&tip).unwrap(), Some(Some(expected)));
            let snapshot = store.committed_snapshot().unwrap().unwrap();
            assert_eq!(
                snapshot.emission_identity(&tip).unwrap(),
                Some(Some(expected))
            );
        }
    }

    #[test]
    fn emission_identity_exhaustion_and_recovery_follow_scala() {
        let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let (mut store, seed) = seeded_store(&dir.path().join("state.redb"));
        let mut tx = transaction(seed, 1);
        tx.output_candidates[0] = ErgoBoxCandidate::new(
            1_000_000_000_000_000,
            read_ergo_tree(&mut VlqReader::new(&[0, 8, 0xd3])).unwrap(),
            1,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap();
        let ordinary = box_id(&output_box(&tx).unwrap()).unwrap();
        let tip = apply(&mut store, 1, vec![tx], 1);
        assert_eq!(store.emission_identity(&tip).unwrap(), Some(None));
        let recovery = transaction(ordinary, 2);
        let expected = box_id(&output_box(&recovery).unwrap()).unwrap();
        let tip = apply(&mut store, 2, vec![recovery], 2);
        assert_eq!(store.emission_identity(&tip).unwrap(), Some(Some(expected)));
    }

    // ----- round-trips -----

    #[test]
    fn emission_identity_reorg_and_reopen_select_competing_branch() {
        let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let path = dir.path().join("state.redb");
        let (mut store, seed) = seeded_store(&path);
        let tx = transaction(seed, 1);
        let common_id = box_id(&output_box(&tx).unwrap()).unwrap();
        let common = apply(&mut store, 1, vec![tx], 1);
        let a = transaction(common_id, 2);
        let a_id = box_id(&output_box(&a).unwrap()).unwrap();
        let branch_a = apply(&mut store, 2, vec![a], 2);
        let old_snapshot = store.committed_snapshot().unwrap().unwrap();
        store.rollback_to(1, None, None).unwrap();
        assert_eq!(store.chain_state.best_full_block_id, common);
        assert_eq!(
            store.emission_identity(&common).unwrap(),
            Some(Some(common_id))
        );
        let branch_b = apply(&mut store, 2, vec![], 3);
        assert_ne!(branch_a, branch_b);
        assert_eq!(
            store.emission_identity(&branch_b).unwrap(),
            Some(Some(common_id))
        );
        assert_eq!(
            old_snapshot.emission_identity(&branch_a).unwrap(),
            Some(Some(a_id))
        );
        drop(old_snapshot);
        drop(store);
        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.chain_state.best_full_block_id, branch_b);
        assert_eq!(
            store.emission_identity(&branch_b).unwrap(),
            Some(Some(common_id))
        );
    }

    #[test]
    fn emission_identity_legacy_restart_recovers_omitted_suffix() {
        let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let path = dir.path().join("state.redb");
        let (mut store, seed) = seeded_store(&path);
        let tx = transaction(seed, 1);
        let expected = box_id(&output_box(&tx).unwrap()).unwrap();
        let first = apply(&mut store, 1, vec![tx], 1);
        let tip = apply(&mut store, 2, vec![], 2);
        let txn = crate::begin_write_qr(&store.db).unwrap();
        {
            let mut table = txn.open_table(EMISSION_IDENTITIES).unwrap();
            table.remove(first.as_slice()).unwrap();
            table.remove(tip.as_slice()).unwrap();
        }
        recover_identity(&txn, &tip, 1).unwrap();
        assert!(txn
            .open_table(EMISSION_IDENTITIES)
            .unwrap()
            .get(tip.as_slice())
            .unwrap()
            .is_none());
        txn.commit().unwrap();
        drop(store);
        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.emission_identity(&tip).unwrap(), Some(Some(expected)));
    }

    // ----- error paths -----

    #[test]
    fn emission_identity_unavailable_history_remains_unknown() {
        let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.recover_emission_identity(&[0x42; 32]).unwrap();
        assert_eq!(store.emission_identity(&[0x42; 32]).unwrap(), None);
    }
}
