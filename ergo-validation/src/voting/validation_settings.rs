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

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ValidationSettingsCodecError> {
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
    #[error("validation_settings: trailing bytes after decode")]
    TrailingBytes,
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

pub fn read_validation_settings_update(
    r: &mut VlqReader<'_>,
) -> Result<ErgoValidationSettingsUpdate, ValidationSettingsCodecError> {
    let disabled_n = r.get_u32_exact()? as usize;
    let mut rules_to_disable = Vec::with_capacity(disabled_n);
    for _ in 0..disabled_n {
        rules_to_disable.push(r.get_u16()?);
    }
    let status_n = r.get_u32_exact()? as usize;
    let mut status_updates = Vec::with_capacity(status_n);
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
    fn deserialize_rejects_trailing_bytes() {
        let u = ErgoValidationSettingsUpdate::empty();
        let mut bytes = u.serialize();
        bytes.push(0xAB);
        let err = ErgoValidationSettingsUpdate::deserialize(&bytes).unwrap_err();
        assert_eq!(err, ValidationSettingsCodecError::TrailingBytes);
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
