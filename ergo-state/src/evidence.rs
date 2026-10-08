//! Opt-in, non-consensus applied-block journal. Only committed redb snapshots
//! are observable; queued persist jobs are never advertised as committed.
//!
//! This is local authenticated provenance, not a public cryptographic oracle.
//! A deployment must authenticate the node/transport and bind its chain manifest.

use crate::store::{StateError, StateStore};
use ergo_primitives::digest::{blake2b256, ADDigest};
use ergo_primitives::writer::VlqWriter;
use ergo_ser::{ergo_box::serialize_ergo_box, transaction::write_transaction};
use ergo_validation::{block::CheckedBlock, ActiveProtocolParameters, ErgoValidationSettings};
use redb::{Database, ReadableTable, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("applied_evidence_meta_v1");
const EVENTS: TableDefinition<u64, &[u8]> = TableDefinition::new("applied_evidence_events_v1");
const CANONICAL: TableDefinition<u32, u64> = TableDefinition::new("applied_evidence_canonical_v1");
const MAX_GENERATION: u64 = (1 << 53) - 1;

fn error(message: impl std::fmt::Display) -> StateError {
    StateError::AppliedEvidence {
        detail: message.to_string(),
    }
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, StateError> {
    serde_json::to_vec(value).map_err(error)
}
fn decode<T: for<'a> Deserialize<'a>>(bytes: &[u8]) -> Result<T, StateError> {
    serde_json::from_slice(bytes).map_err(error)
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(blake2b256(bytes).as_bytes())
}
fn framed(tag: &[u8], pieces: &[&[u8]]) -> Vec<u8> {
    let mut result = tag.to_vec();
    for piece in pieces {
        result.extend_from_slice(&(piece.len() as u64).to_be_bytes());
        result.extend_from_slice(piece);
    }
    result
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Provenance {
    Full,
    CheckpointSkipped {
        checkpoint_height: u32,
        checkpoint_id: String,
    },
    TrustedGenesisAnchor {
        anchor_id: String,
    },
    Unobserved {
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedBox {
    pub input_index: u32,
    pub box_id: String,
    pub bytes_hex: String,
    pub origin: BoxOrigin,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum BoxOrigin {
    PreBlock,
    EarlierOutput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputExtension {
    pub input_index: u32,
    pub bytes_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionEvidence {
    pub transaction_index: u32,
    pub transaction_id: String,
    pub signed_bytes_hex: String,
    pub context_extensions: Vec<InputExtension>,
    pub resolved_inputs: Vec<ResolvedBox>,
    pub resolved_data_inputs: Vec<ResolvedBox>,
}

/// Fields are private: production callers cannot manufacture `Full` from raw
/// transactions. `checked` consumes the validation-issued checked-type view.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapturedBlock {
    schema: String,
    block_id: String,
    parent_id: String,
    height: u32,
    header_bytes_hex: String,
    parent_state_root: String,
    state_root: String,
    provenance: Provenance,
    parameters_digest: String,
    rules_digest: String,
    active_parameters_bytes_hex: String,
    effective_parameters_bytes_hex: String,
    predecessor_rule_update_bytes_hex: String,
    target_sigma_rule_update_bytes_hex: String,
    transactions: Vec<TransactionEvidence>,
}

fn effective_parameter_bytes(active: &ActiveProtocolParameters) -> Vec<u8> {
    let p = ergo_validation::context::ProtocolParams::from_active(active);
    let mut bytes = Vec::new();
    for value in [
        p.min_value_per_byte,
        p.max_block_cost,
        u64::from(p.max_block_size),
        u64::from(p.max_box_size),
        u64::from(p.max_tokens_per_box),
        p.input_cost,
        p.data_input_cost,
        p.output_cost,
        p.token_access_cost,
        p.storage_fee_factor as u64,
        u64::from(p.storage_period),
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes
}

fn fingerprints(
    active: &ActiveProtocolParameters,
    predecessor: &ErgoValidationSettings,
) -> Result<(String, String, String, String, String), StateError> {
    let params = active.serialize().map_err(error)?;
    let previous = predecessor.update_from_initial.serialize();
    let sigma = ergo_validation::voting::validation_settings::ErgoValidationSettingsUpdate {
        rules_to_disable: Vec::new(),
        status_updates: active.activated_update.status_updates.clone(),
    }
    .serialize();
    // This binds the exact target-epoch active row (including block-version)
    // and distinguishes predecessor node rule gates from target Sigma statuses.
    Ok((
        hash(&framed(
            b"ergo/applied-evidence/parameters/v1\0",
            &[&params, &effective_parameter_bytes(active)],
        )),
        hash(&framed(
            b"ergo/applied-evidence/rules/v1\0",
            &[&previous, &sigma],
        )),
        hex::encode(params),
        hex::encode(previous),
        hex::encode(sigma),
    ))
}

fn tx_evidence(
    index: u32,
    tx: &ergo_ser::transaction::Transaction,
    id: &[u8; 32],
    inputs: &[ergo_ser::ergo_box::ErgoBox],
    data: &[ergo_ser::ergo_box::ErgoBox],
) -> Result<TransactionEvidence, StateError> {
    tx_evidence_with_origins(index, tx, id, inputs, data, &HashSet::new())
}
fn tx_evidence_with_origins(
    index: u32,
    tx: &ergo_ser::transaction::Transaction,
    id: &[u8; 32],
    inputs: &[ergo_ser::ergo_box::ErgoBox],
    data: &[ergo_ser::ergo_box::ErgoBox],
    prefix_outputs: &HashSet<[u8; 32]>,
) -> Result<TransactionEvidence, StateError> {
    let mut writer = VlqWriter::new();
    write_transaction(&mut writer, tx).map_err(error)?;
    let boxes = |items: &[ergo_ser::ergo_box::ErgoBox]| -> Result<Vec<ResolvedBox>, StateError> {
        items
            .iter()
            .enumerate()
            .map(|(index, b)| {
                let id = *b.box_id().map_err(error)?.as_bytes();
                Ok(ResolvedBox {
                    input_index: u32::try_from(index).map_err(error)?,
                    box_id: hex::encode(id),
                    bytes_hex: hex::encode(serialize_ergo_box(b).map_err(error)?),
                    origin: if prefix_outputs.contains(&id) {
                        BoxOrigin::EarlierOutput
                    } else {
                        BoxOrigin::PreBlock
                    },
                })
            })
            .collect()
    };
    Ok(TransactionEvidence {
        transaction_index: index,
        transaction_id: hex::encode(id),
        signed_bytes_hex: hex::encode(writer.as_slice()),
        context_extensions: tx
            .inputs
            .iter()
            .enumerate()
            .map(|(index, input)| {
                Ok(InputExtension {
                    input_index: u32::try_from(index).map_err(error)?,
                    bytes_hex: hex::encode(input.spending_proof.extension_bytes()),
                })
            })
            .collect::<Result<_, StateError>>()?,
        resolved_inputs: boxes(inputs)?,
        resolved_data_inputs: boxes(data)?,
    })
}

impl CapturedBlock {
    pub fn checked(
        block: &CheckedBlock,
        header_bytes: &[u8],
        parent_root: &ADDigest,
        target_active: &ActiveProtocolParameters,
        predecessor_rules: &ErgoValidationSettings,
        checkpoint: Option<(u32, [u8; 32])>,
    ) -> Result<Self, StateError> {
        let header = block.header();
        if blake2b256(header_bytes).as_bytes() != header.header_id() {
            return Err(error("header binding mismatch"));
        }
        let (
            parameters_digest,
            rules_digest,
            active_parameters_bytes_hex,
            predecessor_rule_update_bytes_hex,
            target_sigma_rule_update_bytes_hex,
        ) = fingerprints(target_active, predecessor_rules)?;
        let provenance = match checkpoint {
            Some((h, id)) if header.height() <= h => Provenance::CheckpointSkipped {
                checkpoint_height: h,
                checkpoint_id: hex::encode(id),
            },
            _ => Provenance::Full,
        };
        // Prefix membership labels origin only. Resolution already happened in
        // the production validator. Keep spent prefix outputs here: data inputs
        // see earlier-created boxes even after an earlier transaction spent them.
        let mut prefix_outputs = HashSet::new();
        let mut transactions = Vec::with_capacity(block.transactions().len());
        for (index, checked) in block.transactions().iter().enumerate() {
            transactions.push(tx_evidence_with_origins(
                u32::try_from(index).map_err(error)?,
                checked.transaction(),
                checked.tx_id(),
                checked.resolved_inputs(),
                checked.resolved_data_inputs(),
                &prefix_outputs,
            )?);
            for (output_index, candidate) in
                checked.transaction().output_candidates.iter().enumerate()
            {
                let output = ergo_ser::ergo_box::ErgoBox {
                    candidate: candidate.clone(),
                    transaction_id: ergo_primitives::digest::ModifierId::from_bytes(
                        *checked.tx_id(),
                    ),
                    index: u16::try_from(output_index).map_err(error)?,
                };
                prefix_outputs.insert(*output.box_id().map_err(error)?.as_bytes());
            }
        }
        Ok(Self {
            schema: "ergo-applied-evidence-v1".into(),
            block_id: hex::encode(header.header_id()),
            parent_id: hex::encode(header.header().parent_id.as_bytes()),
            height: header.height(),
            header_bytes_hex: hex::encode(header_bytes),
            parent_state_root: hex::encode(parent_root.as_bytes()),
            state_root: hex::encode(header.header().state_root.as_bytes()),
            provenance,
            parameters_digest,
            rules_digest,
            active_parameters_bytes_hex,
            effective_parameters_bytes_hex: hex::encode(effective_parameter_bytes(target_active)),
            predecessor_rule_update_bytes_hex,
            target_sigma_rule_update_bytes_hex,
            transactions,
        })
    }

    /// Genesis is explicitly trusted by a configured header ID, never described
    /// as a fully script-validated ordinary block. No resolved-input claim.
    pub fn trusted_genesis(
        header_bytes: &[u8],
        parent_root: &ADDigest,
        transactions: &[ergo_ser::transaction::Transaction],
        anchor: [u8; 32],
        active: &ActiveProtocolParameters,
        rules: &ErgoValidationSettings,
    ) -> Result<Self, StateError> {
        let mut reader = ergo_primitives::reader::VlqReader::new(header_bytes);
        let header = ergo_ser::header::read_header(&mut reader).map_err(error)?;
        if reader.position() != header_bytes.len()
            || header.height != 1
            || header.parent_id.as_bytes() != &[0; 32]
            || blake2b256(header_bytes).as_bytes() != &anchor
        {
            return Err(error("genesis does not match configured trusted anchor"));
        }
        let (
            parameters_digest,
            rules_digest,
            active_parameters_bytes_hex,
            predecessor_rule_update_bytes_hex,
            target_sigma_rule_update_bytes_hex,
        ) = fingerprints(active, rules)?;
        Ok(Self {
            schema: "ergo-applied-evidence-v1".into(),
            block_id: hex::encode(anchor),
            parent_id: hex::encode([0; 32]),
            height: 1,
            header_bytes_hex: hex::encode(header_bytes),
            parent_state_root: hex::encode(parent_root.as_bytes()),
            state_root: hex::encode(header.state_root.as_bytes()),
            provenance: Provenance::TrustedGenesisAnchor {
                anchor_id: hex::encode(anchor),
            },
            parameters_digest,
            rules_digest,
            active_parameters_bytes_hex,
            effective_parameters_bytes_hex: hex::encode(effective_parameter_bytes(active)),
            predecessor_rule_update_bytes_hex,
            target_sigma_rule_update_bytes_hex,
            transactions: transactions
                .iter()
                .enumerate()
                .map(|(index, tx)| {
                    let id = blake2b256(&ergo_ser::transaction::bytes_to_sign(tx).map_err(error)?);
                    tx_evidence(
                        u32::try_from(index).map_err(error)?,
                        tx,
                        id.as_bytes(),
                        &[],
                        &[],
                    )
                })
                .collect::<Result<_, _>>()?,
        })
    }
    pub(crate) fn bind(
        &self,
        height: u32,
        id: &[u8; 32],
        parent: &ADDigest,
        root: &ADDigest,
    ) -> Result<(), StateError> {
        if self.height != height
            || self.block_id != hex::encode(id)
            || self.parent_state_root != hex::encode(parent.as_bytes())
            || self.state_root != hex::encode(root.as_bytes())
        {
            return Err(error("capture does not bind actual applied mutation"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Cursor {
    pub archive_id: String,
    pub sequence: u64,
    pub event_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalEvent {
    pub sequence: u64,
    pub branch_generation: u64,
    pub previous_hash: String,
    pub operation: String,
    pub height: u32,
    pub block_id: String,
    pub capture: Option<serde_json::Value>,
    pub gap_reason: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredEvent {
    pub event: JournalEvent,
    pub event_hash: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalMeta {
    pub archive_id: String,
    pub anchor_id: String,
    pub cursor: Cursor,
    pub branch_generation: u64,
    pub tip_id: String,
    pub tip_height: u32,
    pub reconstruction_required: bool,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommittedPage {
    pub meta: JournalMeta,
    pub events: Vec<StoredEvent>,
    pub next_cursor: Cursor,
}

fn append(
    txn: &WriteTransaction,
    meta: &mut JournalMeta,
    event: JournalEvent,
) -> Result<u64, StateError> {
    let sequence = event.sequence;
    let event_hash = hash(&framed(
        b"ergo/applied-evidence/event/v1\0",
        &[&encode(&event)?],
    ));
    let record = encode(&StoredEvent {
        event,
        event_hash: event_hash.clone(),
    })?;
    let mut events = txn.open_table(EVENTS)?;
    if events.insert(sequence, record.as_slice())?.is_some() {
        return Err(error("journal sequence collision"));
    }
    meta.cursor = Cursor {
        archive_id: meta.archive_id.clone(),
        sequence,
        event_hash,
    };
    Ok(sequence)
}
fn load_meta(txn: &WriteTransaction) -> Result<JournalMeta, StateError> {
    let table = txn.open_table(META)?;
    let value = table
        .get("meta")?
        .ok_or_else(|| error("missing journal metadata; reconstruction required"))?;
    let meta: JournalMeta = decode(value.value())?;
    validate_meta(&meta)?;
    Ok(meta)
}
fn validate_meta(meta: &JournalMeta) -> Result<(), StateError> {
    if meta.branch_generation > MAX_GENERATION
        || meta.cursor.sequence > MAX_GENERATION
        || meta.cursor.archive_id != meta.archive_id
        || meta.tip_height > i32::MAX as u32
    {
        return Err(error("invalid journal metadata; reconstruction required"));
    }
    for id in [
        &meta.archive_id,
        &meta.anchor_id,
        &meta.cursor.event_hash,
        &meta.tip_id,
    ] {
        if hex::decode(id).map_err(error)?.len() != 32 || id.to_ascii_lowercase() != *id {
            return Err(error("invalid metadata digest"));
        }
    }
    Ok(())
}
fn save_meta(txn: &WriteTransaction, meta: &JournalMeta) -> Result<(), StateError> {
    txn.open_table(META)?
        .insert("meta", encode(meta)?.as_slice())?;
    Ok(())
}

pub(crate) fn persist_apply(
    txn: &WriteTransaction,
    recording: bool,
    height: u32,
    id: &[u8; 32],
    capture: Option<&CapturedBlock>,
) -> Result<(), StateError> {
    if !recording {
        return Ok(());
    }
    let mut meta = load_meta(txn)?;
    if let Some(capture) = capture {
        if capture.height != height || capture.block_id != hex::encode(id) {
            return Err(error("outbox capture block binding mismatch"));
        }
        if height == 1
            && !matches!(&capture.provenance, Provenance::TrustedGenesisAnchor { anchor_id } if anchor_id == &meta.anchor_id)
        {
            return Err(error(
                "height-one capture must be an explicit configured genesis anchor",
            ));
        }
    }
    let gap = capture.is_none()
        || height != meta.tip_height.saturating_add(1)
        || capture.is_some_and(|c| {
            c.parent_id != meta.tip_id
                || matches!(
                    c.provenance,
                    Provenance::CheckpointSkipped { .. } | Provenance::Unobserved { .. }
                )
        });
    if gap {
        meta.reconstruction_required = true;
    }
    if meta.cursor.sequence == MAX_GENERATION {
        return Err(error("sequence exceeds exact JSON integer range"));
    }
    let sequence = meta
        .cursor
        .sequence
        .checked_add(1)
        .ok_or_else(|| error("sequence overflow"))?;
    let branch_generation = meta.branch_generation;
    let previous_hash = meta.cursor.event_hash.clone();
    let seq = append(
        txn,
        &mut meta,
        JournalEvent {
            sequence,
            branch_generation,
            previous_hash,
            operation: "apply".into(),
            height,
            block_id: hex::encode(id),
            capture: capture
                .map(serde_json::to_value)
                .transpose()
                .map_err(error)?,
            gap_reason: gap.then(|| "missing, skipped or discontinuous applied evidence".into()),
        },
    )?;
    txn.open_table(CANONICAL)?.insert(height, seq)?;
    meta.tip_id = hex::encode(id);
    meta.tip_height = height;
    save_meta(txn, &meta)
}
pub(crate) fn persist_rollback(
    txn: &WriteTransaction,
    recording: bool,
    height: u32,
    id: &[u8; 32],
) -> Result<(), StateError> {
    if !recording {
        return Ok(());
    }
    let mut meta = load_meta(txn)?;
    if meta.branch_generation == MAX_GENERATION {
        return Err(error("branch generation overflow"));
    }
    meta.branch_generation += 1;
    if meta.cursor.sequence == MAX_GENERATION {
        return Err(error("sequence exceeds exact JSON integer range"));
    }
    let sequence = meta
        .cursor
        .sequence
        .checked_add(1)
        .ok_or_else(|| error("sequence overflow"))?;
    let branch_generation = meta.branch_generation;
    let previous_hash = meta.cursor.event_hash.clone();
    append(
        txn,
        &mut meta,
        JournalEvent {
            sequence,
            branch_generation,
            previous_hash,
            operation: "rollback".into(),
            height,
            block_id: hex::encode(id),
            capture: None,
            gap_reason: None,
        },
    )?;
    let mut canonical = txn.open_table(CANONICAL)?;
    let remove: Vec<u32> = canonical
        .range((height.saturating_add(1))..)?
        .map(|r| r.map(|(k, _)| k.value()))
        .collect::<Result<_, _>>()?;
    for key in remove {
        canonical.remove(key)?;
    }
    meta.tip_id = hex::encode(id);
    meta.tip_height = height;
    save_meta(txn, &meta)
}

pub(crate) fn recording_exists(db: &Database) -> Result<bool, StateError> {
    let txn = db.begin_read()?;
    match txn.open_table(META) {
        Ok(table) => {
            let value = table
                .get("meta")?
                .ok_or_else(|| error("journal metadata missing; reconstruction required"))?;
            let meta: JournalMeta = decode(value.value())?;
            validate_meta(&meta)?;
            Ok(true)
        }
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

impl StateStore {
    /// Opt in before pipeline startup. A late start is durably marked incomplete;
    /// enabling cannot turn historical archive observations into verified data.
    pub fn enable_applied_evidence(&mut self, anchor: [u8; 32]) -> Result<(), StateError> {
        self.flush_persist_pipeline()?;
        let height = self.height();
        let parent_root = self.root_digest();
        let tip_id = hex::encode(self.chain_state().best_full_block_id);
        let db = self.db_arc();
        let txn = crate::begin_write_qr(&db)?;
        if self.evidence_recording {
            if load_meta(&txn)?.anchor_id != hex::encode(anchor) {
                return Err(error("journal anchor mismatch"));
            }
        } else {
            let archive_id = hash(&framed(
                b"ergo/applied-evidence/archive/v1\0",
                &[&anchor, &height.to_be_bytes(), parent_root.as_bytes()],
            ));
            let zero = hex::encode([0; 32]);
            save_meta(
                &txn,
                &JournalMeta {
                    archive_id: archive_id.clone(),
                    anchor_id: hex::encode(anchor),
                    cursor: Cursor {
                        archive_id,
                        sequence: 0,
                        event_hash: zero,
                    },
                    branch_generation: 0,
                    tip_id,
                    tip_height: height,
                    reconstruction_required: height != 0,
                },
            )?;
        }
        txn.open_table(EVENTS)?;
        txn.open_table(CANONICAL)?;
        txn.commit()?;
        self.evidence_recording = true;
        self.evidence_anchor = Some(anchor);
        Ok(())
    }
    pub fn applied_evidence_anchor(&self) -> Option<[u8; 32]> {
        self.evidence_anchor
    }
    pub fn apply_observed_block(
        &mut self,
        block: &CheckedBlock,
        voted: Option<ActiveProtocolParameters>,
        wallet: Option<&dyn crate::wallet::WalletApplyHook>,
        capture: CapturedBlock,
    ) -> Result<(), StateError> {
        if self.evidence_anchor.is_none() {
            return Err(error("capture is not enabled"));
        }
        let (parameters, rules, _, _, _) = fingerprints(
            voted.as_ref().unwrap_or(self.active_params()),
            self.validation_settings(),
        )?;
        if capture.parameters_digest != parameters
            || capture.rules_digest != rules
            || capture.height == 1
            || matches!(
                capture.provenance,
                Provenance::TrustedGenesisAnchor { .. } | Provenance::Unobserved { .. }
            )
        {
            return Err(error(
                "capture execution parameters, rules or provenance mismatch",
            ));
        }
        self.pending_evidence = Some(capture);
        let result = self.apply_block(block, voted, wallet);
        self.pending_evidence = None;
        result
    }
    pub fn apply_observed_genesis(
        &mut self,
        id: &[u8; 32],
        root: &ADDigest,
        txs: &[ergo_ser::transaction::Transaction],
        capture: CapturedBlock,
    ) -> Result<(), StateError> {
        if self.evidence_anchor != Some(*id)
            || !matches!(capture.provenance, Provenance::TrustedGenesisAnchor { .. })
        {
            return Err(error("genesis anchor capture is not enabled"));
        }
        let (parameters, rules, _, _, _) =
            fingerprints(self.active_params(), self.validation_settings())?;
        if capture.parameters_digest != parameters || capture.rules_digest != rules {
            return Err(error("genesis execution parameters or rules mismatch"));
        }
        self.pending_evidence = Some(capture);
        let result = self.apply_genesis(id, root, txs);
        self.pending_evidence = None;
        result
    }
}

/// One committed snapshot, with cursor rewind/gap/corruption refusal. Returns
/// retained branch events (including rollbacks), never just a latest-tip cache.
pub fn read_committed(
    db: &Database,
    after: Option<&Cursor>,
    limit: usize,
) -> Result<CommittedPage, StateError> {
    if !(1..=1000).contains(&limit) {
        return Err(error("page limit must be 1..1000"));
    }
    let txn = db.begin_read()?;
    let table = txn.open_table(META).map_err(error)?;
    let value = table
        .get("meta")?
        .ok_or_else(|| error("journal unavailable"))?;
    let meta: JournalMeta = decode(value.value())?;
    validate_meta(&meta)?;
    // Bind to the canonical full-block tip in the SAME committed snapshot.
    let chain = txn.open_table(crate::store::CHAIN_STATE_META)?;
    let chain_bytes = chain
        .get("chain_state")?
        .ok_or_else(|| error("chain metadata unavailable"))?;
    let chain = crate::chain::ChainStateMeta::deserialize(chain_bytes.value()).map_err(error)?;
    if chain.best_full_block_height != meta.tip_height
        || hex::encode(chain.best_full_block_id) != meta.tip_id
    {
        return Err(error(
            "canonical tip bypassed journal; reconstruction required",
        ));
    }
    let events_table = txn.open_table(EVENTS).map_err(error)?;
    let mut cursor = after.cloned().unwrap_or(Cursor {
        archive_id: meta.archive_id.clone(),
        sequence: 0,
        event_hash: hex::encode([0; 32]),
    });
    if cursor.archive_id != meta.archive_id || cursor.sequence > meta.cursor.sequence {
        return Err(error(
            "cursor rewound or archive changed; reconstruction required",
        ));
    }
    if cursor.sequence > 0 {
        let previous = events_table
            .get(cursor.sequence)?
            .ok_or_else(|| error("cursor record missing; reconstruction required"))?;
        let record: StoredEvent = decode(previous.value())?;
        if record.event_hash != cursor.event_hash
            || hash(&framed(
                b"ergo/applied-evidence/event/v1\0",
                &[&encode(&record.event)?],
            )) != record.event_hash
        {
            return Err(error("cursor record corrupt; reconstruction required"));
        }
    } else if cursor.event_hash != hex::encode([0; 32]) {
        return Err(error("invalid initial cursor"));
    }
    let mut events = Vec::new();
    for _ in 0..limit {
        if cursor.sequence == meta.cursor.sequence {
            break;
        }
        let sequence = cursor
            .sequence
            .checked_add(1)
            .ok_or_else(|| error("cursor overflow"))?;
        let value = events_table
            .get(sequence)?
            .ok_or_else(|| error("journal gap; reconstruction required"))?;
        let record: StoredEvent = decode(value.value())?;
        if record.event.sequence != sequence
            || record.event.previous_hash != cursor.event_hash
            || record.event.branch_generation > MAX_GENERATION
            || hash(&framed(
                b"ergo/applied-evidence/event/v1\0",
                &[&encode(&record.event)?],
            )) != record.event_hash
        {
            return Err(error("journal corruption; reconstruction required"));
        }
        cursor.sequence = sequence;
        cursor.event_hash = record.event_hash.clone();
        events.push(record);
    }
    if cursor.sequence == meta.cursor.sequence && cursor != meta.cursor {
        return Err(error("metadata cursor corruption"));
    }
    Ok(CommittedPage {
        meta,
        events,
        next_cursor: cursor,
    })
}

#[cfg(test)]
mod tests;
