//! Operator reads over one committed database transaction. These functions do
//! not repair metadata, select a chain, or alter block-validation rules.

use std::collections::BTreeMap;

use ergo_primitives::{digest::Digest32, reader::VlqReader};
use ergo_ser::ergo_box::{read_ergo_box, ErgoBox};
use ergo_ser::header::{read_header, serialize_header};
use redb::ReadTransaction;
use serde::{Deserialize, Serialize};

use crate::avl::digest::{
    internal_label, leaf_label, root_digest, NEGATIVE_INFINITY_KEY, POSITIVE_INFINITY_KEY,
};
use crate::avl::node::{AvlNode, NULL_NODE};
use crate::chain::ChainStateMeta;
use crate::store::{
    node_from_bytes, StateError, AVL_NODES, CHAIN_INDEX, CHAIN_STATE_META, DATA_DIR_STATE_TYPE_KEY,
    HEADERS, NODE_FORMAT_VERSION_KEY, STATE_META,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceTip {
    pub height: u32,
    pub header_id: String,
    pub header_height: u32,
    pub state_type: Option<String>,
    pub state_root: Option<String>,
    pub format_versions: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoStats {
    pub box_count: u64,
    pub serialized_box_bytes: u64,
    pub min_box_bytes: Option<u64>,
    pub max_box_bytes: Option<u64>,
    pub internal_nodes: u64,
    pub tree_height: u8,
    pub total_value_nano_erg: String,
    pub state_root_verified: bool,
}

fn corrupt(reason: impl Into<String>) -> StateError {
    StateError::DbCorruption {
        table: "operator inspection",
        key: String::new(),
        reason: reason.into(),
    }
}

pub fn inspect_tip(txn: &ReadTransaction) -> Result<MaintenanceTip, StateError> {
    let chain_table = txn.open_table(CHAIN_STATE_META)?;
    let chain_bytes = chain_table
        .get("chain_state")?
        .ok_or_else(|| corrupt("no committed chain state; initialize the node first"))?;
    let chain = ChainStateMeta::deserialize(chain_bytes.value())
        .map_err(|e| corrupt(format!("chain metadata: {e}")))?;
    let mut state_type = chain_table
        .get(DATA_DIR_STATE_TYPE_KEY)?
        .map(|row| {
            std::str::from_utf8(row.value())
                .map(str::to_owned)
                .map_err(|e| corrupt(format!("state type: {e}")))
        })
        .transpose()?;
    if state_type
        .as_deref()
        .is_some_and(|kind| !matches!(kind, "utxo" | "digest" | "digest-verifier"))
    {
        return Err(corrupt("unrecognized data-directory state type"));
    }
    let mut versions = BTreeMap::new();
    let mut state_root = None;
    match txn.open_table(STATE_META) {
        Ok(meta) => {
            if let Some(row) = meta.get("root")? {
                if meta.get("root_digest")?.is_some()
                    || state_type.as_deref() == Some("digest-verifier")
                {
                    return Err(corrupt(
                        "state type or digest markers disagree with UTXO root layout",
                    ));
                }
                let bytes = row.value();
                if bytes.len() != 46 {
                    return Err(corrupt("UTXO root metadata must contain 46 bytes"));
                }
                let height = u32::from_be_bytes(bytes[..4].try_into().unwrap());
                if height != chain.best_full_block_height {
                    return Err(corrupt(
                        "UTXO height disagrees with committed full-block height",
                    ));
                }
                state_root = Some(hex::encode(&bytes[5..38]));
            } else if let Some(row) = meta.get("root_digest")? {
                if state_type
                    .as_deref()
                    .is_some_and(|kind| kind != "digest-verifier")
                {
                    return Err(corrupt(
                        "state type disagrees with digest-verifier root layout",
                    ));
                }
                if row.value().len() != 33 {
                    return Err(corrupt("digest state root must contain 33 bytes"));
                }
                state_root = Some(hex::encode(row.value()));
                // The boot path also infers an unstamped legacy directory
                // from this marker; inspection does so without stamping it.
                state_type.get_or_insert_with(|| "digest-verifier".to_owned());
            }
            for key in [NODE_FORMAT_VERSION_KEY, "hci_version"] {
                if let Some(row) = meta.get(key)? {
                    versions.insert(key.to_string(), hex::encode(row.value()));
                }
            }
        }
        Err(redb::TableError::TableDoesNotExist(_)) => {}
        Err(error) => return Err(error.into()),
    }
    verify_tip_header(
        txn,
        &chain,
        state_root.as_deref(),
        state_type.as_deref() == Some("digest-verifier"),
    )?;
    Ok(MaintenanceTip {
        height: chain.best_full_block_height,
        header_id: hex::encode(chain.best_full_block_id),
        header_height: chain.best_header_height,
        state_type,
        state_root,
        format_versions: versions,
    })
}

/// Identify the verified committed chain for an external wallet operation.
/// A pruned chain uses its persisted emission identity; retained canonical
/// genesis headers are an independent fallback for legacy state databases.
pub fn committed_network(txn: &ReadTransaction) -> Result<ergo_chain_spec::Network, StateError> {
    inspect_tip(txn)?;
    ergo_wallet_service::wallet::migration::source_network(txn).map_err(|error| match error {
        ergo_wallet_service::WalletStoreError::Decode(reason) => {
            StateError::WalletDiscoveryUnavailable(reason)
        }
        error => error.into(),
    })
}

fn verify_tip_header(
    txn: &ReadTransaction,
    chain: &ChainStateMeta,
    state_root: Option<&str>,
    require_index_anchor: bool,
) -> Result<(), StateError> {
    if chain.best_full_block_height == 0 {
        // The committed pre-block-1 state has no corresponding mined header.
        if chain.best_full_block_id != [0; 32] {
            return Err(corrupt("genesis full-block ID must be zero"));
        }
        return Ok(());
    }
    let headers = match txn.open_table(HEADERS) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => {
            return Err(corrupt("committed full-block header is missing"));
        }
        Err(error) => return Err(error.into()),
    };
    let bytes = headers
        .get(chain.best_full_block_id.as_slice())?
        .ok_or_else(|| corrupt("committed full-block header is missing"))?;
    let mut reader = VlqReader::new(bytes.value()).trusted();
    let header = read_header(&mut reader)
        .map_err(|e| corrupt(format!("committed full-block header decode: {e}")))?;
    if reader.remaining() != 0 {
        return Err(corrupt("committed full-block header has trailing bytes"));
    }
    let (_, id) = serialize_header(&header)
        .map_err(|e| corrupt(format!("committed full-block header identity: {e}")))?;
    if id.as_bytes() != &chain.best_full_block_id {
        return Err(corrupt(
            "committed full-block header ID disagrees with its bytes",
        ));
    }
    if header.height != chain.best_full_block_height {
        return Err(corrupt(
            "committed full-block header height disagrees with chain metadata",
        ));
    }
    let header_root = hex::encode(header.state_root.as_bytes());
    if state_root != Some(header_root.as_str()) {
        return Err(corrupt(
            "committed state root disagrees with full-block header",
        ));
    }
    // Older UTXO sparse-history snapshot installs can lack the applied-height
    // index anchor. Digest-verifier apply always writes it atomically, and its
    // open contract rejects a missing anchor; preserve that stronger check.
    match txn.open_table(CHAIN_INDEX) {
        Ok(index) => match index.get(u64::from(chain.best_full_block_height))? {
            Some(row) if row.value() != chain.best_full_block_id.as_slice() => {
                return Err(corrupt(
                    "applied-height index disagrees with committed full-block ID",
                ));
            }
            None if require_index_anchor => {
                return Err(corrupt(
                    "digest-verifier applied-height index anchor is missing",
                ));
            }
            _ => {}
        },
        Err(redb::TableError::TableDoesNotExist(_)) if require_index_anchor => {
            return Err(corrupt(
                "digest-verifier applied-height index anchor is missing",
            ));
        }
        Err(redb::TableError::TableDoesNotExist(_)) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

/// Visit only the leaves reachable from the committed root, in key order.
/// Historical/unreachable arena nodes are excluded. The traversal computes
/// every label, verifies successor links, child labels and tree height, and
/// validates box IDs before returning success. Visitors must stage writes and
/// publish them only after this call succeeds.
pub fn visit_utxos<F>(txn: &ReadTransaction, mut visitor: F) -> Result<UtxoStats, StateError>
where
    F: FnMut(&[u8; 32], &[u8], &ErgoBox) -> Result<(), StateError>,
{
    let tip = inspect_tip(txn)?;
    let table = txn.open_table(STATE_META)?;
    let meta = table
        .get("root")?
        .ok_or_else(|| corrupt("current-UTXO scanning requires a UTXO state backend"))?;
    let bytes = meta.value();
    let expected_height = bytes[4];
    let root_id = u64::from_be_bytes(bytes[38..46].try_into().unwrap());
    if root_id == NULL_NODE {
        return Err(corrupt("committed UTXO root is null"));
    }
    let nodes = txn.open_table(AVL_NODES)?;
    let mut walk = Walk {
        nodes: &nodes,
        visitor: &mut visitor,
        stats: UtxoStats::default(),
        previous_next: None,
        total_value: 0,
    };
    let root = walk.node(root_id, 0)?;
    if root.first_key != NEGATIVE_INFINITY_KEY
        || walk.previous_next != Some(POSITIVE_INFINITY_KEY)
        || root.height != expected_height
    {
        return Err(corrupt(
            "AVL boundary links or tree height disagree with metadata",
        ));
    }
    let calculated = hex::encode(root_digest(&root.label, root.height).as_bytes());
    if tip.state_root.as_deref() != Some(calculated.as_str()) {
        return Err(corrupt(
            "recomputed AVL state root disagrees with committed root",
        ));
    }
    walk.stats.tree_height = root.height;
    walk.stats.total_value_nano_erg = walk.total_value.to_string();
    walk.stats.state_root_verified = true;
    Ok(walk.stats)
}

struct Subtree {
    label: Digest32,
    height: u8,
    first_key: [u8; 32],
}

struct Walk<'a, F> {
    nodes: &'a redb::ReadOnlyTable<u64, &'static [u8]>,
    visitor: &'a mut F,
    stats: UtxoStats,
    previous_next: Option<[u8; 32]>,
    total_value: u128,
}

impl<F> Walk<'_, F>
where
    F: FnMut(&[u8; 32], &[u8], &ErgoBox) -> Result<(), StateError>,
{
    fn node(&mut self, id: u64, depth: u16) -> Result<Subtree, StateError> {
        if id == NULL_NODE || depth > 255 {
            return Err(corrupt("AVL null child, cycle, or excessive depth"));
        }
        let guard = self
            .nodes
            .get(id)?
            .ok_or_else(|| corrupt(format!("missing AVL node {id}")))?;
        let node = node_from_bytes(guard.value())?;
        drop(guard);
        match node {
            AvlNode::Leaf {
                key,
                value,
                next_key,
                ..
            } => {
                if self.previous_next.is_some_and(|expected| expected != key) || key >= next_key {
                    return Err(corrupt(
                        "AVL leaves are unordered or successor links are broken",
                    ));
                }
                self.previous_next = Some(next_key);
                let label = leaf_label(&key, &value, &next_key);
                if key == NEGATIVE_INFINITY_KEY {
                    if !value.is_empty() {
                        return Err(corrupt("AVL sentinel has a nonempty value"));
                    }
                } else {
                    let mut reader = VlqReader::new(&value).trusted();
                    let ergo_box = read_ergo_box(&mut reader)
                        .map_err(|e| corrupt(format!("UTXO box decode: {e}")))?;
                    if reader.remaining() != 0
                        || ergo_box
                            .box_id()
                            .map_err(|e| corrupt(e.to_string()))?
                            .as_bytes()
                            != &key
                    {
                        return Err(corrupt(
                            "UTXO leaf value has trailing bytes or a different box ID",
                        ));
                    }
                    let size = value.len() as u64;
                    self.stats.box_count += 1;
                    self.stats.serialized_box_bytes = self
                        .stats
                        .serialized_box_bytes
                        .checked_add(size)
                        .ok_or_else(|| corrupt("UTXO byte counter overflow"))?;
                    self.stats.min_box_bytes =
                        Some(self.stats.min_box_bytes.map_or(size, |v| v.min(size)));
                    self.stats.max_box_bytes =
                        Some(self.stats.max_box_bytes.map_or(size, |v| v.max(size)));
                    self.total_value = self
                        .total_value
                        .checked_add(u128::from(ergo_box.candidate.value))
                        .ok_or_else(|| corrupt("UTXO value counter overflow"))?;
                    (self.visitor)(&key, &value, &ergo_box)?;
                }
                Ok(Subtree {
                    label,
                    height: 0,
                    first_key: key,
                })
            }
            AvlNode::Internal {
                key,
                left,
                right,
                balance,
                left_label,
                right_label,
                ..
            } => {
                let left = self.node(left, depth + 1)?;
                let right = self.node(right, depth + 1)?;
                if key != right.first_key
                    || i16::from(right.height) - i16::from(left.height) != i16::from(balance)
                    || !(-1..=1).contains(&balance)
                    || left_label.is_some_and(|v| v != left.label)
                    || right_label.is_some_and(|v| v != right.label)
                {
                    return Err(corrupt(
                        "AVL separator, balance, or cached child label mismatch",
                    ));
                }
                self.stats.internal_nodes += 1;
                Ok(Subtree {
                    label: internal_label(balance, &left.label, &right.label),
                    height: left
                        .height
                        .max(right.height)
                        .checked_add(1)
                        .ok_or_else(|| corrupt("AVL height overflow"))?,
                    first_key: left.first_key,
                })
            }
        }
    }
}

/// Give a synthetic positive-height fixture a coherent committed header and
/// applied-height anchor, using the UTXO root already stored in the database.
#[cfg(test)]
pub(crate) fn test_set_tip(db: &redb::Database, height: u32) -> [u8; 32] {
    use redb::ReadableTable;

    assert!(height > 0);
    let txn = crate::begin_write_qr(db).unwrap();
    let mut root = txn
        .open_table(STATE_META)
        .unwrap()
        .get("root")
        .unwrap()
        .unwrap()
        .value()
        .to_vec();
    root[..4].copy_from_slice(&height.to_be_bytes());
    let header = test_header(height, root[5..38].try_into().unwrap());
    let (bytes, id) = serialize_header(&header).unwrap();
    let mut chain = ChainStateMeta::deserialize(
        txn.open_table(CHAIN_STATE_META)
            .unwrap()
            .get("chain_state")
            .unwrap()
            .unwrap()
            .value(),
    )
    .unwrap();
    chain.best_header_height = height;
    chain.best_header_id = *id.as_bytes();
    chain.best_full_block_height = height;
    chain.best_full_block_id = *id.as_bytes();
    txn.open_table(STATE_META)
        .unwrap()
        .insert("root", root.as_slice())
        .unwrap();
    txn.open_table(HEADERS)
        .unwrap()
        .insert(id.as_bytes().as_slice(), bytes.as_slice())
        .unwrap();
    txn.open_table(CHAIN_INDEX)
        .unwrap()
        .insert(u64::from(height), id.as_bytes().as_slice())
        .unwrap();
    txn.open_table(CHAIN_STATE_META)
        .unwrap()
        .insert("chain_state", chain.serialize().as_slice())
        .unwrap();
    txn.commit().unwrap();
    *id.as_bytes()
}

#[cfg(test)]
fn test_header(height: u32, root: [u8; 33]) -> ergo_ser::header::Header {
    use ergo_primitives::digest::{ADDigest, ModifierId};
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::autolykos::AutolykosSolution;
    ergo_ser::header::Header {
        version: 2,
        parent_id: ModifierId::from_bytes([0; 32]),
        ad_proofs_root: Digest32::from_bytes([1; 32]),
        transactions_root: Digest32::from_bytes([2; 32]),
        state_root: ADDigest::from_bytes(root),
        timestamp: 1,
        extension_root: Digest32::from_bytes([3; 32]),
        n_bits: 0x1a01_7660,
        height,
        votes: [0; 3],
        unparsed_bytes: Vec::new(),
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from_bytes(
                hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
            nonce: [0; 8],
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ergo_primitives::digest::ModifierId;
    use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBoxCandidate};
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
    use redb::{Database, ReadableDatabase, ReadableTable, WriteTransaction};

    use crate::store::{node_to_bytes, StateStore};

    use super::*;

    struct Fixture {
        _directory: tempfile::TempDir,
        _store: StateStore,
        db: Arc<Database>,
        boxes: Vec<([u8; 32], Vec<u8>)>,
    }

    impl Fixture {
        fn new(count: u8) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let mut store = StateStore::open(&directory.path().join("state.redb")).unwrap();
            let boxes: Vec<_> = (0..count)
                .map(|i| {
                    let tree = ErgoTree {
                        version: 0,
                        has_size: true,
                        constant_segregation: false,
                        reserved_header_bits: 0,
                        constants: Vec::new(),
                        body: Expr::Const {
                            tpe: SigmaType::SSigmaProp,
                            val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
                        },
                    };
                    let ergo_box = ErgoBox::new(
                        ErgoBoxCandidate::new(
                            1_000_000 + u64::from(i),
                            tree,
                            0,
                            Vec::new(),
                            AdditionalRegisters::empty(),
                        )
                        .unwrap(),
                        ModifierId::from_bytes([i + 1; 32]),
                        u16::from(i),
                    );
                    (
                        *ergo_box.box_id().unwrap().as_bytes(),
                        serialize_ergo_box(&ergo_box).unwrap(),
                    )
                })
                .collect();
            store.initialize_genesis(&boxes).unwrap();
            let db = store.db_arc();
            Self {
                _directory: directory,
                _store: store,
                db,
                boxes,
            }
        }

        fn mutate(&self, mutation: impl FnOnce(&WriteTransaction)) {
            let txn = crate::begin_write_qr(&self.db).unwrap();
            mutation(&txn);
            txn.commit().unwrap();
        }

        fn tip(&self) -> Result<MaintenanceTip, StateError> {
            inspect_tip(&self.db.begin_read().unwrap())
        }

        fn stats(&self) -> Result<UtxoStats, StateError> {
            visit_utxos(&self.db.begin_read().unwrap(), |_, _, _| Ok(()))
        }

        fn root(&self) -> Vec<u8> {
            self.db
                .begin_read()
                .unwrap()
                .open_table(STATE_META)
                .unwrap()
                .get("root")
                .unwrap()
                .unwrap()
                .value()
                .to_vec()
        }

        fn change_root(&self, change: impl FnOnce(&mut Vec<u8>)) {
            let mut root = self.root();
            change(&mut root);
            self.mutate(|txn| {
                txn.open_table(STATE_META)
                    .unwrap()
                    .insert("root", root.as_slice())
                    .unwrap();
            });
        }

        fn change_chain(&self, change: impl FnOnce(&mut ChainStateMeta)) {
            self.mutate(|txn| {
                let mut table = txn.open_table(CHAIN_STATE_META).unwrap();
                let mut chain =
                    ChainStateMeta::deserialize(table.get("chain_state").unwrap().unwrap().value())
                        .unwrap();
                change(&mut chain);
                table
                    .insert("chain_state", chain.serialize().as_slice())
                    .unwrap();
            });
        }

        fn change_node(
            &self,
            choose: impl Fn(&AvlNode) -> bool,
            change: impl FnOnce(&mut AvlNode),
        ) {
            self.mutate(|txn| {
                let mut table = txn.open_table(AVL_NODES).unwrap();
                let (id, mut node) = table
                    .iter()
                    .unwrap()
                    .map(|entry| {
                        let (id, bytes) = entry.unwrap();
                        (id.value(), node_from_bytes(bytes.value()).unwrap())
                    })
                    .find(|(_, node)| choose(node))
                    .unwrap();
                change(&mut node);
                table.insert(id, node_to_bytes(&node).as_slice()).unwrap();
            });
        }
    }

    fn rejected(result: Result<impl std::fmt::Debug, StateError>, expected: &str) {
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains(expected),
            "expected {expected:?}, got {error}"
        );
    }

    #[test]
    fn genesis_and_positive_tip_verify_reachable_boxes_only() {
        let fixture = Fixture::new(7);
        assert_eq!(fixture.tip().unwrap().height, 0);
        let id = test_set_tip(&fixture.db, 1_000);
        assert_eq!(fixture.tip().unwrap().header_id, hex::encode(id));
        fixture.mutate(|txn| {
            txn.open_table(AVL_NODES)
                .unwrap()
                .insert(u64::MAX, b"orphan, not a node".as_slice())
                .unwrap();
        });
        let mut visited = Vec::new();
        let stats = visit_utxos(&fixture.db.begin_read().unwrap(), |key, bytes, ergo_box| {
            assert_eq!(ergo_box.box_id().unwrap().as_bytes(), key);
            visited.push((*key, bytes.to_vec()));
            Ok(())
        })
        .unwrap();
        let mut expected = fixture.boxes.clone();
        expected.sort_unstable_by_key(|(key, _)| *key);
        assert_eq!(visited, expected);
        assert_eq!(stats.box_count, 7);
        assert_eq!(stats.internal_nodes, 7);
        assert_eq!(stats.total_value_nano_erg, "7000021");
        assert_eq!(
            stats.serialized_box_bytes,
            expected.iter().map(|(_, b)| b.len() as u64).sum::<u64>()
        );
        assert!(stats.state_root_verified);
    }

    #[test]
    fn genesis_empty_tree_is_valid_but_nonzero_full_id_is_not() {
        let fixture = Fixture::new(0);
        let stats = fixture.stats().unwrap();
        assert_eq!(stats.box_count, 0);
        assert_eq!(stats.total_value_nano_erg, "0");
        assert_eq!(stats.min_box_bytes, None);
        fixture.change_chain(|chain| chain.best_full_block_id = [1; 32]);
        rejected(fixture.tip(), "genesis full-block ID");
    }

    #[test]
    fn real_digest_backend_tip_reports_persisted_or_inferred_schema() {
        let directory = tempfile::tempdir().unwrap();
        let root = [4; 33];
        let mut store = crate::DigestStateStore::open(
            &directory.path().join("state.redb"),
            ergo_validation::scala_launch(),
            ergo_chain_spec::VotingParams::mainnet(),
            [5; 33],
        )
        .unwrap();
        let db = store.db_arc();
        let header = test_header(1, root);
        let (bytes, id) = serialize_header(&header).unwrap();
        let txn = crate::begin_write_qr(&db).unwrap();
        txn.open_table(HEADERS)
            .unwrap()
            .insert(id.as_bytes().as_slice(), bytes.as_slice())
            .unwrap();
        txn.commit().unwrap();
        store
            .apply_block_digest(
                root,
                ChainStateMeta {
                    best_header_id: *id.as_bytes(),
                    best_header_height: 1,
                    best_header_score: vec![1],
                    best_full_block_id: *id.as_bytes(),
                    best_full_block_height: 1,
                    header_availability: crate::chain::HeaderAvailability::Dense,
                },
                None,
            )
            .unwrap();
        let tip = inspect_tip(&db.begin_read().unwrap()).unwrap();
        assert_eq!(tip.state_type.as_deref(), Some("digest-verifier"));
        assert_eq!(tip.state_root, Some(hex::encode(root)));
        assert_eq!(tip.header_id, hex::encode(id.as_bytes()));
        let txn = crate::begin_write_qr(&db).unwrap();
        txn.open_table(CHAIN_STATE_META)
            .unwrap()
            .remove(DATA_DIR_STATE_TYPE_KEY)
            .unwrap();
        txn.commit().unwrap();
        assert_eq!(inspect_tip(&db.begin_read().unwrap()).unwrap(), tip);
        assert!(db
            .begin_read()
            .unwrap()
            .open_table(CHAIN_STATE_META)
            .unwrap()
            .get(DATA_DIR_STATE_TYPE_KEY)
            .unwrap()
            .is_none());
        let txn = crate::begin_write_qr(&db).unwrap();
        txn.open_table(CHAIN_INDEX).unwrap().remove(1).unwrap();
        txn.commit().unwrap();
        rejected(
            inspect_tip(&db.begin_read().unwrap()),
            "digest-verifier applied-height index anchor is missing",
        );
    }

    #[test]
    fn actual_format_keys_and_state_type_layouts_are_checked() {
        let fixture = Fixture::new(1);
        fixture.mutate(|txn| {
            txn.open_table(CHAIN_STATE_META)
                .unwrap()
                .insert(DATA_DIR_STATE_TYPE_KEY, b"utxo".as_slice())
                .unwrap();
            txn.open_table(STATE_META)
                .unwrap()
                .insert("hci_version", [1].as_slice())
                .unwrap();
        });
        let tip = fixture.tip().unwrap();
        assert_eq!(tip.state_type.as_deref(), Some("utxo"));
        assert_eq!(
            tip.format_versions[NODE_FORMAT_VERSION_KEY],
            hex::encode(crate::store::NODE_FORMAT_V2)
        );
        assert_eq!(tip.format_versions["hci_version"], "01");
        fixture.mutate(|txn| {
            txn.open_table(CHAIN_STATE_META)
                .unwrap()
                .insert(DATA_DIR_STATE_TYPE_KEY, b"digest".as_slice())
                .unwrap();
        });
        // Headers-only mode deliberately shares the UTXO backend's schema.
        assert_eq!(fixture.tip().unwrap().state_type.as_deref(), Some("digest"));
        fixture.mutate(|txn| {
            txn.open_table(CHAIN_STATE_META)
                .unwrap()
                .insert(DATA_DIR_STATE_TYPE_KEY, b"digest-verifier".as_slice())
                .unwrap();
        });
        rejected(fixture.tip(), "disagree with UTXO root layout");
        fixture.mutate(|txn| {
            txn.open_table(CHAIN_STATE_META)
                .unwrap()
                .insert(DATA_DIR_STATE_TYPE_KEY, b"unknown-backend".as_slice())
                .unwrap();
        });
        rejected(fixture.tip(), "unrecognized data-directory state type");

        let fixture = Fixture::new(1);
        fixture.mutate(|txn| {
            txn.open_table(STATE_META)
                .unwrap()
                .insert("root_digest", [1; 33].as_slice())
                .unwrap();
        });
        rejected(fixture.tip(), "disagree with UTXO root layout");
    }

    #[test]
    fn sparse_tip_without_index_anchor_is_accepted_existing_mismatch_is_not() {
        let fixture = Fixture::new(1);
        test_set_tip(&fixture.db, 1_000);
        fixture.mutate(|txn| {
            txn.open_table(CHAIN_INDEX).unwrap().remove(1_000).unwrap();
        });
        assert_eq!(fixture.tip().unwrap().height, 1_000);
        fixture.mutate(|txn| {
            txn.open_table(CHAIN_INDEX)
                .unwrap()
                .insert(1_000, [8; 32].as_slice())
                .unwrap();
        });
        rejected(fixture.tip(), "applied-height index");
    }

    #[test]
    fn tip_requires_stored_header_and_rejects_corrupt_or_trailing_bytes() {
        for (bytes, expected) in [
            (None, "header is missing"),
            (Some(vec![2, 0]), "header decode"),
            (Some(Vec::new()), "header has trailing bytes"),
        ] {
            let fixture = Fixture::new(1);
            let id = test_set_tip(&fixture.db, 10);
            fixture.mutate(|txn| {
                let mut headers = txn.open_table(HEADERS).unwrap();
                match bytes {
                    None => {
                        headers.remove(id.as_slice()).unwrap();
                    }
                    Some(bytes) if bytes.is_empty() => {
                        let mut bytes = headers
                            .get(id.as_slice())
                            .unwrap()
                            .unwrap()
                            .value()
                            .to_vec();
                        bytes.push(0);
                        headers.insert(id.as_slice(), bytes.as_slice()).unwrap();
                    }
                    Some(bytes) => {
                        headers.insert(id.as_slice(), bytes.as_slice()).unwrap();
                    }
                }
            });
            rejected(fixture.tip(), expected);
        }
    }

    #[test]
    fn tip_header_identity_and_height_must_match_chain_metadata() {
        let fixture = Fixture::new(1);
        let id = test_set_tip(&fixture.db, 10);
        fixture.mutate(|txn| {
            let mut table = txn.open_table(HEADERS).unwrap();
            let bytes = table.get(id.as_slice()).unwrap().unwrap().value().to_vec();
            let mut reader = VlqReader::new(&bytes).trusted();
            let mut header = read_header(&mut reader).unwrap();
            header.timestamp += 1;
            let (bytes, _) = serialize_header(&header).unwrap();
            table.insert(id.as_slice(), bytes.as_slice()).unwrap();
        });
        rejected(fixture.tip(), "header ID disagrees");

        let fixture = Fixture::new(1);
        test_set_tip(&fixture.db, 10);
        fixture.change_chain(|chain| chain.best_full_block_height = 11);
        fixture.change_root(|root| root[..4].copy_from_slice(&11u32.to_be_bytes()));
        rejected(fixture.tip(), "header height disagrees");
    }

    #[test]
    fn tip_root_must_match_header_for_both_utxo_and_digest_backends() {
        let fixture = Fixture::new(1);
        test_set_tip(&fixture.db, 10);
        fixture.change_root(|root| root[5] ^= 1);
        rejected(fixture.tip(), "state root disagrees with full-block header");

        let fixture = Fixture::new(1);
        test_set_tip(&fixture.db, 10);
        let root = fixture.root();
        fixture.mutate(|txn| {
            let mut meta = txn.open_table(STATE_META).unwrap();
            meta.remove("root").unwrap();
            meta.insert("root_digest", &root[5..38]).unwrap();
        });
        assert_eq!(fixture.tip().unwrap().height, 10);
        fixture.mutate(|txn| {
            txn.open_table(STATE_META)
                .unwrap()
                .remove("root_digest")
                .unwrap();
        });
        rejected(fixture.tip(), "state root disagrees with full-block header");
    }

    #[test]
    fn malformed_chain_and_root_metadata_are_rejected() {
        let fixture = Fixture::new(1);
        fixture.mutate(|txn| {
            txn.open_table(CHAIN_STATE_META)
                .unwrap()
                .insert("chain_state", [0; 3].as_slice())
                .unwrap();
        });
        rejected(fixture.tip(), "chain metadata");

        let fixture = Fixture::new(1);
        fixture.change_root(|root| {
            root.pop();
        });
        rejected(fixture.stats(), "46 bytes");

        let fixture = Fixture::new(1);
        fixture.change_root(|root| root[..4].copy_from_slice(&1u32.to_be_bytes()));
        rejected(fixture.tip(), "UTXO height disagrees");
    }

    #[test]
    fn missing_null_or_cyclic_reachable_nodes_are_rejected() {
        let fixture = Fixture::new(1);
        let root_id = u64::from_be_bytes(fixture.root()[38..46].try_into().unwrap());
        fixture.mutate(|txn| {
            txn.open_table(AVL_NODES).unwrap().remove(root_id).unwrap();
        });
        rejected(fixture.stats(), "missing AVL node");

        let fixture = Fixture::new(1);
        fixture.change_root(|root| root[38..46].copy_from_slice(&0u64.to_be_bytes()));
        rejected(fixture.stats(), "root is null");

        let fixture = Fixture::new(1);
        let root_id = u64::from_be_bytes(fixture.root()[38..46].try_into().unwrap());
        fixture.change_node(
            |node| matches!(node, AvlNode::Internal { .. }),
            |node| {
                if let AvlNode::Internal { left, .. } = node {
                    *left = root_id;
                }
            },
        );
        rejected(fixture.stats(), "cycle, or excessive depth");
    }

    #[test]
    fn successor_links_sentinel_values_and_tree_height_are_verified() {
        let fixture = Fixture::new(2);
        fixture.change_node(
            |node| matches!(node, AvlNode::Leaf { key, .. } if *key == NEGATIVE_INFINITY_KEY),
            |node| {
                if let AvlNode::Leaf { next_key, .. } = node {
                    *next_key = POSITIVE_INFINITY_KEY;
                }
            },
        );
        rejected(fixture.stats(), "successor links are broken");

        let fixture = Fixture::new(1);
        fixture.change_node(
            |node| matches!(node, AvlNode::Leaf { key, .. } if *key == NEGATIVE_INFINITY_KEY),
            |node| {
                if let AvlNode::Leaf { value, .. } = node {
                    value.push(1);
                }
            },
        );
        rejected(fixture.stats(), "sentinel has a nonempty value");

        let fixture = Fixture::new(1);
        fixture.change_root(|root| root[4] += 1);
        rejected(fixture.stats(), "tree height disagree");
    }

    #[test]
    fn internal_separator_balance_and_cached_child_labels_are_verified() {
        for change in 0..3 {
            let fixture = Fixture::new(2);
            fixture.change_node(
                |node| matches!(node, AvlNode::Internal { .. }),
                |node| {
                    if let AvlNode::Internal {
                        key,
                        balance,
                        left_label,
                        ..
                    } = node
                    {
                        match change {
                            0 => *key = [4; 32],
                            1 => *balance = if *balance == 0 { 1 } else { 0 },
                            _ => *left_label = Some(Digest32::from_bytes([9; 32])),
                        }
                    }
                },
            );
            rejected(
                fixture.stats(),
                "separator, balance, or cached child label mismatch",
            );
        }
    }

    #[test]
    fn corrupt_box_bytes_box_identity_and_recomputed_root_are_rejected() {
        for trailing in [false, true] {
            let fixture = Fixture::new(1);
            fixture.change_node(
                |node| matches!(node, AvlNode::Leaf { key, .. } if *key != NEGATIVE_INFINITY_KEY),
                |node| {
                    if let AvlNode::Leaf { value, .. } = node {
                        if trailing {
                            value.push(0);
                        } else {
                            value.clear();
                        }
                    }
                },
            );
            rejected(
                fixture.stats(),
                if trailing {
                    "trailing bytes or a different box ID"
                } else {
                    "UTXO box decode"
                },
            );
        }

        let fixture = Fixture::new(1);
        fixture.change_node(
            |node| matches!(node, AvlNode::Leaf { key, .. } if *key != NEGATIVE_INFINITY_KEY),
            |node| {
                if let AvlNode::Leaf { value, .. } = node {
                    let mut reader = VlqReader::new(value).trusted();
                    let mut ergo_box = read_ergo_box(&mut reader).unwrap();
                    ergo_box.candidate.value += 1;
                    *value = serialize_ergo_box(&ergo_box).unwrap();
                }
            },
        );
        rejected(fixture.stats(), "trailing bytes or a different box ID");

        let fixture = Fixture::new(1);
        fixture.change_root(|root| root[5] ^= 1);
        rejected(fixture.stats(), "recomputed AVL state root");
    }
}
