//! Ergo `ValidationSettings` — disabled rules + status updates that
//! soft-forks vote into effect.
//!
//! Mirrors `ergo-core/.../settings/ErgoValidationSettings.scala` and
//! `ergo-core/.../settings/ErgoValidationSettingsUpdate.scala`.
//! Rule status codec mirrors
//! `sigmastate-interpreter/.../validation/RuleStatusSerializer.scala`.
//!
//! Wire-format codec for `ErgoValidationSettings` and the per-epoch
//! `ErgoValidationSettingsUpdate` blob persisted alongside voted
//! protocol parameters.

use std::collections::BTreeSet;

use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

/// Sigma's `FirstRuleId` constant (`sigma/validation/ValidationRules.scala`).
/// Used by `ReplacedRule` and `ChangedRule` codec to encode rule ids
/// as offsets from this base.
pub const FIRST_RULE_ID: u16 = 1000;

/// Scala `Extension.ValidationRulesPrefix` (`Extension.scala:72`).
/// Distinct from `SystemParametersPrefix = 0x00`. Extension entries
/// with this prefix carry a chunked `ErgoValidationSettings`
/// serialization (each entry value is a slice of the full byte string,
/// ordered by `key[1]`).
pub const VALIDATION_RULES_PREFIX: u8 = 0x02;

/// Parse the cumulative `ErgoValidationSettingsUpdate` from a block's
/// extension. Mirrors Scala
/// `ErgoValidationSettings.parseExtension(extension)`
/// (`ErgoValidationSettings.scala:111-122`):
///
/// 1. Filter extension fields to those with `key[0] == 0x02`.
/// 2. Sort by `key[1]` (the chunk index).
/// 3. Concatenate `value` bytes in chunk order.
/// 4. Deserialize as `ErgoValidationSettingsUpdate` (the
///    cumulative-from-initial update). If no `0x02` entries are
///    present, return `empty()` (= initial settings).
pub fn parse_validation_settings_update(
    extension: &ergo_ser::extension::Extension,
) -> Result<ErgoValidationSettingsUpdate, ValidationSettingsCodecError> {
    let mut chunks: Vec<(u8, &[u8])> = extension
        .fields
        .iter()
        .filter(|f| f.key[0] == VALIDATION_RULES_PREFIX)
        .map(|f| (f.key[1], f.value.as_slice()))
        .collect();
    if chunks.is_empty() {
        return Ok(ErgoValidationSettingsUpdate::empty());
    }
    chunks.sort_by_key(|(idx, _)| *idx);
    let mut buf = Vec::new();
    for (_, v) in &chunks {
        buf.extend_from_slice(v);
    }
    ErgoValidationSettingsUpdate::deserialize(&buf)
}

/// Maximum bytes per extension field value — Scala caps `putUByte(length)`
/// at 255 (`ergo-ser/src/extension.rs`). A cumulative settings blob longer
/// than this is split across consecutive `0x02` chunk entries.
const EXTENSION_FIELD_VALUE_MAX: usize = 255;

/// Serialize a cumulative `ErgoValidationSettingsUpdate` into its block-
/// extension fields — the inverse of [`parse_validation_settings_update`],
/// mirroring Scala `ErgoValidationSettings.toExtensionCandidate`
/// (`ErgoValidationSettings.scala:101-109`).
///
/// An EMPTY update (no disabled rules, no status updates) yields NO fields —
/// the absence of any `0x02` entry is how the parser encodes "initial
/// settings". A non-empty update is serialized to one byte string and split
/// into `0x02`-prefixed chunks of at most [`EXTENSION_FIELD_VALUE_MAX`] bytes,
/// keyed by ascending chunk index in `key[1]`. The parser concatenates chunks
/// in index order before deserializing, so the chunk boundary is not consensus-
/// relevant — only the concatenation is — but the chunking keeps each field
/// within the 255-byte wire limit.
pub fn validation_settings_update_to_extension_fields(
    update: &ErgoValidationSettingsUpdate,
) -> Vec<([u8; 2], Vec<u8>)> {
    if update.rules_to_disable.is_empty() && update.status_updates.is_empty() {
        return Vec::new();
    }
    let bytes = update.serialize();
    bytes
        .chunks(EXTENSION_FIELD_VALUE_MAX)
        .enumerate()
        .map(|(idx, chunk)| {
            // Chunk index lives in key[1]; the parser sorts by it. A cumulative
            // update large enough to exceed 255 chunks (u8 index) cannot occur
            // for any real validation-settings table, so the cast is safe.
            ([VALIDATION_RULES_PREFIX, idx as u8], chunk.to_vec())
        })
        .collect()
}

/// Status of a single validation rule. Mirrors sigma's `RuleStatus`
/// (`sigma/validation/RuleStatus.scala`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleStatus {
    /// Default status — rule is registered and active.
    Enabled,
    /// Rule is disabled by a soft-fork.
    Disabled,
    /// Rule is replaced by another rule (atomic swap by id offset
    /// from `FirstRuleId`).
    Replaced(u16),
    /// Rule's parameters have been changed; opaque payload bytes.
    Changed(Vec<u8>),
}

impl RuleStatus {
    pub fn status_code(&self) -> u8 {
        match self {
            RuleStatus::Enabled => 1,
            RuleStatus::Disabled => 2,
            RuleStatus::Replaced(_) => 3,
            RuleStatus::Changed(_) => 4,
        }
    }
}

/// Cumulative validation settings, mirroring Scala
/// `ErgoValidationSettings` (`ErgoValidationSettings.scala`). Holds
/// the *cumulative update-from-initial* — i.e., everything that has
/// been activated on top of the initial validation rule set. Scala's
/// `equals` is defined as `p.updateFromInitial == updateFromInitial`
/// (`ErgoValidationSettings.scala:90`); our equality follows.
///
/// `validation_settings_at(H)` (in ergo-state) folds every row's
/// `activated_update` into `update_from_initial` via
/// `ErgoValidationSettingsUpdate.merged`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ErgoValidationSettings {
    pub update_from_initial: ErgoValidationSettingsUpdate,
}

impl ErgoValidationSettings {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Cumulative `rules_to_disable` from initial. Convenience accessor
    /// for code that wants the disabled-rules set.
    pub fn disabled_rules(&self) -> &[u16] {
        &self.update_from_initial.rules_to_disable
    }

    /// Cumulative `status_updates` from initial. Convenience accessor.
    pub fn status_updates(&self) -> &[(u16, RuleStatus)] {
        &self.update_from_initial.status_updates
    }

    /// Apply an `ErgoValidationSettingsUpdate` on top of the current
    /// cumulative state. Mirrors
    /// `ErgoValidationSettings.scala:43-49 updated(u)` modulo the
    /// underlying representation: Scala materializes `rules` and
    /// `sigmaSettings` derived from `updateFromInitial` for runtime
    /// gating; we keep just the cumulative update and derive the
    /// disabled-rules set on demand. Equality lines up because
    /// Scala's `equals` is on `updateFromInitial`.
    pub fn updated(&self, update: &ErgoValidationSettingsUpdate) -> Self {
        Self {
            update_from_initial: self.update_from_initial.merged(update),
        }
    }

    /// True iff `rule_id` is in `update_from_initial.rules_to_disable`
    /// OR has a `Disabled` status update.
    pub fn is_rule_disabled(&self, rule_id: u16) -> bool {
        if self.update_from_initial.rules_to_disable.contains(&rule_id) {
            return true;
        }
        matches!(
            self.update_from_initial
                .status_updates
                .iter()
                .find(|(id, _)| *id == rule_id)
                .map(|(_, s)| s),
            Some(RuleStatus::Disabled)
        )
    }
}

/// A single update bundle, stored at a `voted_params` row in
/// `proposed_update` and `activated_update`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ErgoValidationSettingsUpdate {
    pub rules_to_disable: Vec<u16>,
    pub status_updates: Vec<(u16, RuleStatus)>,
}

impl ErgoValidationSettingsUpdate {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Mirrors Scala `ErgoValidationSettingsUpdate.++` (line 11-16):
    /// merge rules_to_disable (distinct, sorted), and merge
    /// status_updates such that `that` replaces existing entries with
    /// the same rule id, distinct ids accumulate.
    pub fn merged(&self, that: &Self) -> Self {
        let mut rules: BTreeSet<u16> = self.rules_to_disable.iter().copied().collect();
        rules.extend(that.rules_to_disable.iter().copied());
        let rules_to_disable: Vec<u16> = rules.into_iter().collect();

        // Drop any of self's status updates whose ids appear in `that`,
        // then append `that`'s. Sort by id at the end for determinism.
        let mut merged: Vec<(u16, RuleStatus)> = self
            .status_updates
            .iter()
            .filter(|(id, _)| !that.status_updates.iter().any(|(id2, _)| id2 == id))
            .cloned()
            .collect();
        merged.extend(that.status_updates.iter().cloned());
        merged.sort_by_key(|(id, _)| *id);
        Self {
            rules_to_disable,
            status_updates: merged,
        }
    }

    /// Serialize the update to bytes per
    /// `ErgoValidationSettingsUpdateSerializer`
    /// (`ErgoValidationSettingsUpdate.scala:23-58`):
    ///
    /// ```text
    /// VLQ-u32 disabled_rules_num
    /// { VLQ-u16 rule_id } * disabled_rules_num
    /// VLQ-u32 status_updates_num
    /// { VLQ-u16 (rule_id - FIRST_RULE_ID), RuleStatus } * status_updates_num
    /// ```
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = VlqWriter::new();
        write_validation_settings_update(&mut w, self);
        w.result()
    }

    /// Parse an update from a CONSENSUS value (a block-extension field value).
    /// Mirrors the JVM `ErgoValidationSettingsUpdateSerializer.parse`, which
    /// reads exactly the declared counts and does NOT assert end-of-input —
    /// trailing bytes in the surrounding entry-value envelope are ignored.
    /// Use [`Self::deserialize_exact`] for our own length-framed STORAGE
    /// blobs, where trailing bytes inside the declared length signal
    /// corruption and must be rejected.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ValidationSettingsCodecError> {
        let mut r = VlqReader::new(bytes);
        read_validation_settings_update(&mut r)
    }

    /// Strict parse for our own STORAGE format: the input slice must be
    /// EXACTLY one serialized update with no trailing bytes. `active_params`
    /// length-frames each persisted update blob, so leftover bytes inside the
    /// declared length mean a corrupt/noncanonical row — reject them. (The
    /// JVM has no analog because it never persists these as standalone
    /// length-prefixed blobs; this is an arkadianet storage-integrity check,
    /// not a consensus rule.)
    pub fn deserialize_exact(bytes: &[u8]) -> Result<Self, ValidationSettingsCodecError> {
        let mut r = VlqReader::new(bytes);
        let v = read_validation_settings_update(&mut r)?;
        if !r.is_empty() {
            return Err(ValidationSettingsCodecError::TrailingBytes);
        }
        Ok(v)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationSettingsCodecError {
    #[error("validation_settings: read error: {0:?}")]
    Read(ReadError),
    /// A length-framed STORAGE blob contained trailing bytes after a complete
    /// update (corruption). Only [`ErgoValidationSettingsUpdate::deserialize_exact`]
    /// raises this; the lenient consensus [`ErgoValidationSettingsUpdate::deserialize`]
    /// ignores trailing bytes (JVM parity).
    #[error("validation_settings: trailing bytes after decode")]
    TrailingBytes,
    /// Scala `require(rulesSpec.get(rd).forall(_.mayBeDisabled))`
    /// (`ErgoValidationSettingsUpdate.scala:47-50`): a disable update targets
    /// a known rule whose `mayBeDisabled = false`. Rejected (accept-invalid
    /// parity with the JVM `IllegalArgumentException`).
    #[error("validation_settings: rule {rule_id} may not be disabled")]
    RuleNotDisableable { rule_id: u16 },
}

impl PartialEq for ValidationSettingsCodecError {
    fn eq(&self, other: &Self) -> bool {
        use ValidationSettingsCodecError::*;
        match (self, other) {
            // ReadError doesn't implement PartialEq; compare the error
            // discriminant + Debug-formatted message instead. Acceptable
            // for test assertions; not used on consensus paths.
            (Read(a), Read(b)) => format!("{a:?}") == format!("{b:?}"),
            (TrailingBytes, TrailingBytes) => true,
            (RuleNotDisableable { rule_id: a }, RuleNotDisableable { rule_id: b }) => a == b,
            _ => false,
        }
    }
}

impl Eq for ValidationSettingsCodecError {}

impl From<ReadError> for ValidationSettingsCodecError {
    fn from(e: ReadError) -> Self {
        ValidationSettingsCodecError::Read(e)
    }
}

pub fn write_validation_settings_update(w: &mut VlqWriter, u: &ErgoValidationSettingsUpdate) {
    // `rules_to_disable` is encoded as raw u16 ids per Scala
    // `ErgoValidationSettingsUpdate.scala:32` — no offset against
    // FIRST_RULE_ID applies on this side of the wire.
    w.put_u32(u.rules_to_disable.len() as u32);
    for r in &u.rules_to_disable {
        w.put_u16(*r);
    }
    // `status_updates` is encoded as `(rule_id - FIRST_RULE_ID, status)`
    // per Scala `ErgoValidationSettingsUpdate.scala:36`. The
    // protocol-level invariant `rule_id >= FIRST_RULE_ID` is enforced
    // here rather than silently saturating to zero — that would round-
    // trip a bogus rule id back through the read side. Constructing an
    // `ErgoValidationSettingsUpdate` with `rule_id < FIRST_RULE_ID` is
    // a programmer bug.
    w.put_u32(u.status_updates.len() as u32);
    for (rule_id, status) in &u.status_updates {
        assert!(
            *rule_id >= FIRST_RULE_ID,
            "status_updates rule id {rule_id} below FirstRuleId ({FIRST_RULE_ID})",
        );
        let offset = rule_id - FIRST_RULE_ID;
        w.put_u16(offset);
        write_rule_status(w, status);
    }
}

/// Rule ids whose `mayBeDisabled = false` in Scala
/// `ValidationRules.rulesSpec` (ergo-core 6.0.x). A disable update targeting
/// any of these is rejected (`ErgoValidationSettingsUpdate.scala:47-50`
/// `require(rulesSpec.get(rd).forall(_.mayBeDisabled))`); ids NOT listed
/// (the 22 `mayBeDisabled=true` rules + any id unknown to the spec) are
/// disableable. Mechanically extracted by joining the `val <name>: Short = N`
/// definitions with each `<name> -> RuleStatus(... mayBeDisabled = false)`
/// entry in ValidationRules.scala — 42 ids, kept sorted for readability.
const RULES_NOT_DISABLEABLE: [u16; 42] = [
    100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 112, 113, 114, 115, 116, 117, 119, 122, 200,
    201, 203, 204, 205, 206, 207, 208, 209, 210, 211, 213, 214, 216, 300, 301, 302, 303, 304, 305,
    307, 403, 500, 501,
];

/// Scala `0 until n.toInt` collection length: a negative `n` (the
/// two's-complement wrap of a `getUInt` value above `i32::MAX`) yields an
/// empty range, i.e. zero entries.
fn count_to_len(n: i32) -> usize {
    if n < 0 {
        0
    } else {
        n as usize
    }
}

pub fn read_validation_settings_update(
    r: &mut VlqReader<'_>,
) -> Result<ErgoValidationSettingsUpdate, ValidationSettingsCodecError> {
    // Scala reads both counts as `r.getUInt().toInt` (NOT getUIntExact):
    // a value above i32::MAX wraps two's-complement negative, and the
    // subsequent `0 until n` is an empty Range. So 0xFFFFFFFF -> -1 -> 0
    // entries. Mirror with the wrapping helper + clamp-negative-to-zero.
    // (Don't pre-size the Vec from the untrusted count — a large positive
    // count would otherwise force a huge allocation before the read EOFs.)
    let disabled_n = count_to_len(r.get_uint_to_i32()?);
    let mut rules_to_disable = Vec::new();
    for _ in 0..disabled_n {
        rules_to_disable.push(r.get_u16()?);
    }
    // Scala reads all disabled ids, then `disabledRules.foreach { rd =>
    // require(rulesSpec.get(rd).forall(_.mayBeDisabled), ...) }`: reject a
    // disable of a known non-disableable rule (e.g. 102 txManyInputs).
    for &rd in &rules_to_disable {
        if RULES_NOT_DISABLEABLE.contains(&rd) {
            return Err(ValidationSettingsCodecError::RuleNotDisableable { rule_id: rd });
        }
    }
    let status_n = count_to_len(r.get_uint_to_i32()?);
    let mut status_updates = Vec::new();
    for _ in 0..status_n {
        let offset = r.get_u16()?;
        let status = read_rule_status(r)?;
        let rule_id = FIRST_RULE_ID.saturating_add(offset);
        status_updates.push((rule_id, status));
    }
    Ok(ErgoValidationSettingsUpdate {
        rules_to_disable,
        status_updates,
    })
}

/// Serialize a `RuleStatus` per `RuleStatusSerializer`
/// (`sigmastate-interpreter/.../validation/RuleStatusSerializer.scala`):
///
/// ```text
/// VLQ-u16 dataSize
/// u8      statusCode
/// dataBytes (length = dataSize)
/// ```
fn write_rule_status(w: &mut VlqWriter, s: &RuleStatus) {
    match s {
        RuleStatus::Enabled | RuleStatus::Disabled => {
            w.put_u16(0);
            w.put_u8(s.status_code());
        }
        RuleStatus::Replaced(new_rule_id) => {
            assert!(
                *new_rule_id >= FIRST_RULE_ID,
                "RuleStatus::Replaced new_rule_id {new_rule_id} below FirstRuleId ({FIRST_RULE_ID})",
            );
            let ofs = new_rule_id - FIRST_RULE_ID;
            // Measure VLQ-encoded size of `ofs` written via put_u16.
            let mut probe = VlqWriter::new();
            probe.put_u16(ofs);
            let data_size = probe.result().len();
            w.put_u16(data_size as u16);
            w.put_u8(s.status_code());
            w.put_u16(ofs);
        }
        RuleStatus::Changed(data) => {
            w.put_u16(data.len() as u16);
            w.put_u8(s.status_code());
            w.put_bytes(data);
        }
    }
}

fn read_rule_status(r: &mut VlqReader<'_>) -> Result<RuleStatus, ValidationSettingsCodecError> {
    let data_size = r.get_u16()? as usize;
    let status_code = r.get_u8()?;
    match status_code {
        1 => Ok(RuleStatus::Enabled),
        2 => Ok(RuleStatus::Disabled),
        3 => {
            // Read VLQ-encoded offset (data_size is the byte count).
            // The byte count guards the codec but we read the value as VLQ.
            let ofs = r.get_u16()?;
            let new_rule_id = FIRST_RULE_ID.saturating_add(ofs);
            Ok(RuleStatus::Replaced(new_rule_id))
        }
        4 => {
            let bytes = r.get_bytes(data_size)?.to_vec();
            Ok(RuleStatus::Changed(bytes))
        }
        // Unrecognized status codes: skip data_size bytes and treat as
        // ReplacedRule(0) per Scala fallback (`RuleStatusSerializer.scala:55-57`).
        _ => {
            let _ = r.get_bytes(data_size)?;
            Ok(RuleStatus::Replaced(FIRST_RULE_ID))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_roundtrip() {
        let u = ErgoValidationSettingsUpdate::empty();
        let bytes = u.serialize();
        let back = ErgoValidationSettingsUpdate::deserialize(&bytes).unwrap();
        assert_eq!(u, back);
    }

    #[test]
    fn rule_409_disabled_roundtrip() {
        let u = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![409],
            status_updates: vec![],
        };
        let bytes = u.serialize();
        let back = ErgoValidationSettingsUpdate::deserialize(&bytes).unwrap();
        assert_eq!(u, back);
    }

    #[test]
    fn enabled_status_roundtrip() {
        let u = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![],
            status_updates: vec![(1234, RuleStatus::Enabled)],
        };
        let bytes = u.serialize();
        let back = ErgoValidationSettingsUpdate::deserialize(&bytes).unwrap();
        assert_eq!(u, back);
    }

    #[test]
    fn disabled_status_roundtrip() {
        let u = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![],
            status_updates: vec![(1234, RuleStatus::Disabled)],
        };
        let bytes = u.serialize();
        let back = ErgoValidationSettingsUpdate::deserialize(&bytes).unwrap();
        assert_eq!(u, back);
    }

    #[test]
    fn replaced_status_roundtrip() {
        let u = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![],
            status_updates: vec![(1234, RuleStatus::Replaced(2000))],
        };
        let bytes = u.serialize();
        let back = ErgoValidationSettingsUpdate::deserialize(&bytes).unwrap();
        assert_eq!(u, back);
    }

    #[test]
    fn changed_status_roundtrip() {
        let u = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![],
            status_updates: vec![(1234, RuleStatus::Changed(vec![0xCA, 0xFE, 0xBA, 0xBE]))],
        };
        let bytes = u.serialize();
        let back = ErgoValidationSettingsUpdate::deserialize(&bytes).unwrap();
        assert_eq!(u, back);
    }

    #[test]
    fn combined_update_roundtrip() {
        let u = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![409, 215],
            status_updates: vec![
                (1100, RuleStatus::Enabled),
                (1200, RuleStatus::Disabled),
                (1300, RuleStatus::Replaced(2500)),
                (1400, RuleStatus::Changed(b"hello".to_vec())),
            ],
        };
        let bytes = u.serialize();
        let back = ErgoValidationSettingsUpdate::deserialize(&bytes).unwrap();
        assert_eq!(u, back);
    }

    #[test]
    fn deserialize_rejects_non_disableable_rule() {
        // Rule 102 (txManyInputs) has mayBeDisabled=false; a disable update
        // targeting it must be rejected, matching Scala's `require`. SANTA
        // chain: hostile-mandatory-rule-update (proposed_update 016600).
        let u = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![102],
            status_updates: vec![],
        };
        let bytes = u.serialize();
        let err = ErgoValidationSettingsUpdate::deserialize(&bytes).unwrap_err();
        assert_eq!(
            err,
            ValidationSettingsCodecError::RuleNotDisableable { rule_id: 102 }
        );
    }

    #[test]
    fn deserialize_allows_disableable_and_unknown_rules() {
        // Rule 215 (mayBeDisabled=true) and an unknown rule id are both
        // accepted (Scala `rulesSpec.get(rd).forall(_.mayBeDisabled)` is true
        // when the rule is unknown — `forall` on None).
        for rid in [215u16, 9999u16] {
            let u = ErgoValidationSettingsUpdate {
                rules_to_disable: vec![rid],
                status_updates: vec![],
            };
            let bytes = u.serialize();
            ErgoValidationSettingsUpdate::deserialize(&bytes)
                .unwrap_or_else(|e| panic!("rule {rid} must be disableable: {e:?}"));
        }
    }

    #[test]
    fn deserialize_ignores_trailing_bytes() {
        // The JVM ErgoValidationSettingsUpdateSerializer.parse reads exactly
        // the declared counts and never asserts end-of-input, so trailing
        // bytes in the surrounding entry-value envelope are ignored (SANTA
        // chain entry status-trailing-bytes-canonicalized: 016f00deadbeef ->
        // decodes to a 1-disabled-rule update, deadbeef dropped). Our decoder
        // previously rejected this (reject-valid).
        let u = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![111],
            status_updates: vec![],
        };
        let mut bytes = u.serialize(); // = 016f00
        bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let back = ErgoValidationSettingsUpdate::deserialize(&bytes)
            .expect("trailing bytes must be ignored, matching the JVM");
        assert_eq!(back, u);
    }

    #[test]
    fn deserialize_exact_rejects_trailing_bytes() {
        // The strict STORAGE path must reject trailing bytes inside a
        // length-framed blob (corruption), even though the lenient consensus
        // `deserialize` ignores them.
        let u = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![111],
            status_updates: vec![],
        };
        let mut bytes = u.serialize();
        bytes.extend_from_slice(&[0xde, 0xad]);
        // lenient: accepts
        assert!(ErgoValidationSettingsUpdate::deserialize(&bytes).is_ok());
        // strict: rejects
        let err = ErgoValidationSettingsUpdate::deserialize_exact(&bytes).unwrap_err();
        assert_eq!(err, ValidationSettingsCodecError::TrailingBytes);
    }

    #[test]
    fn deserialize_disabled_count_wraps_to_empty() {
        // disabled_rules_num = 0xFFFFFFFF: JVM getUInt().toInt = -1, `0 until
        // -1` is empty -> empty update. We previously errored ValueTooLarge
        // (getUIntExact i32::MAX bound). SANTA: status-count-wrap-rules.
        let bytes = [0xff, 0xff, 0xff, 0xff, 0x0f, 0x00]; // disabled=0xFFFFFFFF, status=0
        let back = ErgoValidationSettingsUpdate::deserialize(&bytes)
            .expect("0xFFFFFFFF count wraps to an empty range, not an error");
        assert_eq!(back, ErgoValidationSettingsUpdate::empty());
    }

    #[test]
    fn deserialize_status_count_wraps_to_empty() {
        // status_updates_num = 0xFFFFFFFF wraps to -1 -> empty range.
        // SANTA: status-count-wrap-status (00ffffffff0f).
        let bytes = [0x00, 0xff, 0xff, 0xff, 0xff, 0x0f]; // disabled=0, status=0xFFFFFFFF
        let back = ErgoValidationSettingsUpdate::deserialize(&bytes)
            .expect("0xFFFFFFFF status count wraps to an empty range");
        assert_eq!(back, ErgoValidationSettingsUpdate::empty());
    }

    #[test]
    fn updated_merges_disabled_rules_and_status_updates() {
        let base = ErgoValidationSettings {
            update_from_initial: ErgoValidationSettingsUpdate {
                rules_to_disable: vec![100],
                status_updates: vec![(200, RuleStatus::Enabled)],
            },
        };
        let update = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![100, 300], // overlap on 100
            status_updates: vec![
                (200, RuleStatus::Disabled), // overrides
                (400, RuleStatus::Replaced(2000)),
            ],
        };
        let result = base.updated(&update);
        // disabled_rules: union, deduped, sorted
        assert_eq!(result.disabled_rules(), &[100, 300][..]);
        // status_updates: 200 overridden, 400 added (sorted by id)
        assert_eq!(
            result.status_updates(),
            &[
                (200, RuleStatus::Disabled),
                (400, RuleStatus::Replaced(2000)),
            ][..]
        );
    }

    #[test]
    fn merged_combines_two_updates() {
        let a = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![100],
            status_updates: vec![(200, RuleStatus::Enabled)],
        };
        let b = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![100, 300], // overlap
            status_updates: vec![(200, RuleStatus::Disabled), (400, RuleStatus::Enabled)],
        };
        let m = a.merged(&b);
        // rules_to_disable distinct + sorted
        assert_eq!(m.rules_to_disable, vec![100, 300]);
        // status_updates: 200 from b overrides 200 from a, 400 added
        // Sorted by id.
        assert_eq!(
            m.status_updates,
            vec![(200, RuleStatus::Disabled), (400, RuleStatus::Enabled),]
        );
    }

    #[test]
    fn is_rule_disabled_via_disabled_rules_set() {
        let s = ErgoValidationSettings {
            update_from_initial: ErgoValidationSettingsUpdate {
                rules_to_disable: vec![409],
                status_updates: vec![],
            },
        };
        assert!(s.is_rule_disabled(409));
        assert!(!s.is_rule_disabled(414));
    }

    #[test]
    fn is_rule_disabled_via_status_update() {
        let s = ErgoValidationSettings {
            update_from_initial: ErgoValidationSettingsUpdate {
                rules_to_disable: vec![],
                status_updates: vec![(409u16, RuleStatus::Disabled)],
            },
        };
        assert!(s.is_rule_disabled(409));
        assert!(!s.is_rule_disabled(414));
    }
}
