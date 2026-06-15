//! Active protocol parameters parsed from a block's `Extension` at an
//! epoch-start block.
//!
//! Validation against the recomputed-from-votes set (Scala's
//! `exMatchParameters` / `exMatchParameters60`) lives in
//! [`crate::voting::extension_validation`]; this module owns the
//! parser, the persistence codec, and the launch-time defaults.

use ergo_chain_spec::Network;
use ergo_ser::extension::Extension;

use crate::voting::validation_settings::{
    ErgoValidationSettingsUpdate, ValidationSettingsCodecError,
};

/// Scala `Extension.SystemParametersPrefix` (`extension/Extension.scala:59`).
pub const SYSTEM_PARAMETERS_PREFIX: u8 = 0x00;

/// Scala `Parameters.SoftForkDisablingRulesKey` low byte
/// (`settings/Parameters.scala`). The value at this id is a serialized
/// `ErgoValidationSettingsUpdate`, not an `Int`, so it is parsed
/// separately from the numeric parameter map.
pub const SOFT_FORK_DISABLING_RULES_ID: u8 = 124;

mod ids {
    pub const STORAGE_FEE_FACTOR: u8 = 1;
    pub const MIN_VALUE_PER_BYTE: u8 = 2;
    pub const MAX_BLOCK_SIZE: u8 = 3;
    pub const MAX_BLOCK_COST: u8 = 4;
    pub const TOKEN_ACCESS_COST: u8 = 5;
    pub const INPUT_COST: u8 = 6;
    pub const DATA_INPUT_COST: u8 = 7;
    pub const OUTPUT_COST: u8 = 8;
    pub const SUBBLOCKS_PER_BLOCK: u8 = 9;
    pub const BLOCK_VERSION: u8 = 123;
}

/// Per-epoch active protocol parameters as written into block extension
/// at epoch starts and read by `/info.parameters`.
///
/// `block_version` is `u8` because Scala stores the low byte of the
/// `Int` value at id 123 (`Parameters.scala` `blockVersion`). Other
/// fields are `i32` to match Scala's `Int` and the on-disk codec.
///
/// `subblocks_per_block` is optional: pre-EIP37 epochs do not write
/// id 9 into the extension.
///
/// `extra` preserves any `(id, value)` pairs from the parameter prefix
/// that we do not specifically recognize (currently soft-fork voting
/// keys 120-122 during voting windows, plus any future ids). They are
/// stored verbatim so round-trip serialization is byte-stable and the
/// node forward-compatibly carries new param ids that are not yet
/// surfaced via `/info`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveProtocolParameters {
    /// Epoch boundary height these parameters take effect from.
    pub epoch_start_height: u32,
    /// Block-format version (low byte of parameter id 123).
    pub block_version: u8,
    /// `storage_fee_factor` — nanoErg per byte per storage period.
    pub storage_fee_factor: i32,
    /// `min_value_per_byte` for box minimum-value enforcement.
    pub min_value_per_byte: i32,
    /// `max_block_size` (bytes).
    pub max_block_size: i32,
    /// `max_block_cost` (block cost units).
    pub max_block_cost: i32,
    /// Per token access cost charged during script evaluation.
    pub token_access_cost: i32,
    /// Per input cost.
    pub input_cost: i32,
    /// Per data input cost.
    pub data_input_cost: i32,
    /// Per output cost.
    pub output_cost: i32,
    /// Subblocks per block. `None` for pre-EIP-37 epochs where id 9 is
    /// not written into the extension.
    pub subblocks_per_block: Option<i32>,
    /// Catch-all for parameter ids that aren't surfaced as named
    /// fields. Currently includes the soft-fork voting keys 120-122
    /// during voting windows. Preserved verbatim so round-trip
    /// serialization is byte-stable and the node forward-compatibly
    /// carries new ids before they are surfaced via `/info.parameters`.
    pub extra: Vec<(u8, i32)>,
    /// `proposedUpdate` parsed from extension key `(0x00, 124)` —
    /// the soft-fork validation-settings update proposed at this
    /// epoch. Empty when no update is proposed (the `(0x00, 124)`
    /// blob can itself be `0x0000`, encoding an empty update).
    pub proposed_update: ErgoValidationSettingsUpdate,
    /// `activatedUpdate` produced by the soft-fork state machine at
    /// this epoch (`Parameters.scala:140-147`). Equals
    /// `proposed_update` from the activation epoch's first block when
    /// the soft-fork window completes successfully; else empty.
    /// **Set by `compute_next_params`, not by the parser** — the
    /// parser leaves this empty.
    pub activated_update: ErgoValidationSettingsUpdate,
}

/// Failures raised by [`parse_active_params`] / [`ActiveProtocolParameters::serialize`] /
/// [`ActiveProtocolParameters::deserialize`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ActiveParamsError {
    /// Extension carried no `(0x00, *)` parameter entries.
    #[error("extension parameter map is empty")]
    EmptyMap,
    /// A numeric-parameter entry's value field was not exactly 4 bytes.
    #[error("parameter id {0} value length {1} != 4")]
    BadValueLength(u8, usize),
    /// Same parameter id appeared twice in the extension.
    #[error("duplicate parameter id {0}")]
    DuplicateId(u8),
    /// One of the required parameter ids was absent from the extension.
    #[error("missing required parameter id {0}")]
    MissingRequired(u8),
    /// `extra` carries an id that collides with a named parameter.
    #[error("extra entry uses reserved id {0}")]
    ExtraReservesNamedId(u8),
    /// `extra` contains the same id twice.
    #[error("extra entry has duplicate id {0}")]
    ExtraDuplicateId(u8),
    /// Persistence-codec input was truncated.
    #[error("codec: unexpected end of input")]
    UnexpectedEof,
    /// Persistence-codec input had trailing bytes after a clean parse.
    #[error("codec: trailing bytes after decode")]
    TrailingBytes,
    /// Same id appeared twice in the persisted form.
    #[error("codec: duplicate id {0} in serialized form")]
    CodecDuplicateId(u8),
    /// `block_version` did not fit in a `u8` (the low byte of id 123).
    #[error("codec: block_version {0} out of range [0, 255]")]
    BlockVersionOutOfRange(i32),
    /// A non-negativity-constrained voted parameter is negative. The
    /// constrained ids are `storage_fee_factor`, `min_value_per_byte`,
    /// `max_block_size`, `max_block_cost`, `token_access_cost`,
    /// `input_cost`, `data_input_cost`, and `output_cost`. Scala's
    /// voting arithmetic produces only non-negative values for these,
    /// so negatives only reach this codec via storage corruption or a
    /// bug in the voted-params writer. Failing here at the parse /
    /// persisted-codec boundary keeps `ProtocolParams::from_active`
    /// infallible per spec `2026-04-28-voted-parameters-phase2.md` §8.1.
    #[error("non-negativity-constrained parameter id {id} value {value} is negative")]
    NegativeProtocolParam {
        /// Numeric parameter id (1..=8 in the named-id space).
        id: u8,
        /// Persisted i32 value.
        value: i32,
    },
    /// Underlying `ErgoValidationSettingsUpdate` codec error.
    #[error("validation_settings codec: {0}")]
    ValidationSettings(#[from] ValidationSettingsCodecError),
}

/// Mainnet launch parameters. Mirrors Scala `MainnetLaunchParameters`
/// (`settings/LaunchParameters.scala`). Used as the height-0 row in
/// `voted_params` so the snapshot read path always finds *some* row.
pub fn scala_launch_mainnet() -> ActiveProtocolParameters {
    ActiveProtocolParameters {
        epoch_start_height: 0,
        block_version: 1,
        storage_fee_factor: 1_250_000,
        min_value_per_byte: 360,
        max_block_size: 524_288,
        max_block_cost: 1_000_000,
        token_access_cost: 100,
        input_cost: 2_000,
        data_input_cost: 100,
        output_cost: 100,
        subblocks_per_block: None,
        extra: Vec::new(),
        proposed_update: ErgoValidationSettingsUpdate::empty(),
        activated_update: ErgoValidationSettingsUpdate::empty(),
    }
}

/// Testnet launch parameters. Mirrors Scala `TestnetLaunchParameters`
/// (`settings/LaunchParameters.scala`), which is byte-identical to
/// `MainnetLaunchParameters`: `height = 0`, `parametersTable =
/// Parameters.DefaultParameters` (so `BlockVersion = 1`), and
/// `proposedUpdate = ErgoValidationSettingsUpdate.empty`. The two
/// network-specific Scala objects exist as named symbols only — they
/// carry no differing data. The validation rules that are disabled on
/// mainnet today (e.g. 215, 409) reached that state through real
/// soft-fork voting on the live mainnet chain, never via a seeded
/// launch row. The Scala objects that DO override `BlockVersion` at
/// genesis are `DevnetLaunchParameters` (= 50) and
/// `Devnet60LaunchParameters` (= 60), neither of which is the public
/// testnet.
pub fn scala_launch_testnet() -> ActiveProtocolParameters {
    scala_launch_mainnet()
}

/// Launch parameters for the given network. Production callers that
/// hold a `Network` should use this; consumers without network
/// context (most tests) can keep calling [`scala_launch`].
pub fn scala_launch_for_network(net: Network) -> ActiveProtocolParameters {
    match net {
        Network::Mainnet => scala_launch_mainnet(),
        Network::Testnet => scala_launch_testnet(),
    }
}

/// Backwards-compatible alias for [`scala_launch_mainnet`]. Kept so
/// existing test fixtures and snapshot-init paths that don't carry a
/// `Network` keep producing the original mainnet launch row.
pub fn scala_launch() -> ActiveProtocolParameters {
    scala_launch_mainnet()
}

/// Parse the active protocol parameter set from a block's extension at
/// an epoch-start height.
///
/// Mirrors Scala `Parameters.parseExtension` (`Parameters.scala:372-390`):
/// numeric params from `key[0] == 0x00 && key[1] != 124` (4-byte BE
/// int values); `proposed_update` from `key == (0x00, 124)` decoded as
/// `ErgoValidationSettingsUpdate`. Rejects an empty map.
pub fn parse_active_params(
    extension: &Extension,
    epoch_start_height: u32,
) -> Result<ActiveProtocolParameters, ActiveParamsError> {
    let mut by_id: std::collections::BTreeMap<u8, i32> = std::collections::BTreeMap::new();
    let mut proposed_update = ErgoValidationSettingsUpdate::empty();
    let mut saw_proposed_update = false;

    for field in &extension.fields {
        if field.key[0] != SYSTEM_PARAMETERS_PREFIX {
            continue;
        }
        let id = field.key[1];
        if id == SOFT_FORK_DISABLING_RULES_ID {
            // Scala `Parameters.parseExtension` decodes this via
            // `ErgoValidationSettingsUpdateSerializer.parseBytesTry`
            // and silently uses `empty` on parse failure
            // (`Parameters.scala:382-387`). We surface the parse
            // error instead — this is consensus state.
            if saw_proposed_update {
                return Err(ActiveParamsError::DuplicateId(id));
            }
            saw_proposed_update = true;
            proposed_update = ErgoValidationSettingsUpdate::deserialize(&field.value)?;
            continue;
        }
        if field.value.len() != 4 {
            return Err(ActiveParamsError::BadValueLength(id, field.value.len()));
        }
        let v = i32::from_be_bytes(
            field.value[..]
                .try_into()
                .expect("len == 4 verified by the BadValueLength guard above"),
        );
        if by_id.insert(id, v).is_some() {
            return Err(ActiveParamsError::DuplicateId(id));
        }
    }

    if by_id.is_empty() {
        return Err(ActiveParamsError::EmptyMap);
    }

    let take_required = |m: &mut std::collections::BTreeMap<u8, i32>, id: u8| {
        m.remove(&id).ok_or(ActiveParamsError::MissingRequired(id))
    };
    // Non-negativity-constrained fields: parser fail-closes so
    // `ProtocolParams::from_active` stays infallible per
    // `2026-04-28-voted-parameters-phase2.md` §8.1. Scala emits only
    // non-negative values for these ids; a negative here can only come
    // from storage corruption or a producer bug.
    let take_required_nonneg = |m: &mut std::collections::BTreeMap<u8, i32>, id: u8| {
        let v = m
            .remove(&id)
            .ok_or(ActiveParamsError::MissingRequired(id))?;
        if v < 0 {
            return Err(ActiveParamsError::NegativeProtocolParam { id, value: v });
        }
        Ok(v)
    };

    let storage_fee_factor = take_required_nonneg(&mut by_id, ids::STORAGE_FEE_FACTOR)?;
    let min_value_per_byte = take_required_nonneg(&mut by_id, ids::MIN_VALUE_PER_BYTE)?;
    let max_block_size = take_required_nonneg(&mut by_id, ids::MAX_BLOCK_SIZE)?;
    let max_block_cost = take_required_nonneg(&mut by_id, ids::MAX_BLOCK_COST)?;
    let token_access_cost = take_required_nonneg(&mut by_id, ids::TOKEN_ACCESS_COST)?;
    let input_cost = take_required_nonneg(&mut by_id, ids::INPUT_COST)?;
    let data_input_cost = take_required_nonneg(&mut by_id, ids::DATA_INPUT_COST)?;
    let output_cost = take_required_nonneg(&mut by_id, ids::OUTPUT_COST)?;
    let block_version_i32 = take_required(&mut by_id, ids::BLOCK_VERSION)?;
    let subblocks_per_block = by_id.remove(&ids::SUBBLOCKS_PER_BLOCK);

    let extra: Vec<(u8, i32)> = by_id.into_iter().collect();

    Ok(ActiveProtocolParameters {
        epoch_start_height,
        block_version: block_version_i32 as u8,
        storage_fee_factor,
        min_value_per_byte,
        max_block_size,
        max_block_cost,
        token_access_cost,
        input_cost,
        data_input_cost,
        output_cost,
        subblocks_per_block,
        extra,
        proposed_update,
        // The state machine sets this; parser leaves it empty.
        activated_update: ErgoValidationSettingsUpdate::empty(),
    })
}

/// Serialize an active parameter set into its block-extension fields — the
/// exact inverse of [`parse_active_params`], mirroring Scala
/// `Parameters.toExtensionCandidate` (`Parameters.scala:351-370`).
///
/// Emits, with the [`SYSTEM_PARAMETERS_PREFIX`] (`0x00`) prefix:
/// * the eight required numeric params (ids 1..=8) and `block_version`
///   (id 123) as 4-byte big-endian `i32`;
/// * `subblocks_per_block` (id 9) when present (post-EIP37 epochs);
/// * every `extra` `(id, value)` pair (e.g. soft-fork state ids 121/122);
/// * `proposed_update` at id 124 ([`SOFT_FORK_DISABLING_RULES_ID`]) as a
///   serialized `ErgoValidationSettingsUpdate` — ALWAYS present, even when
///   empty (`0x0000`), matching Scala.
///
/// Fields are emitted in a fixed, deterministic order (ids 1..=8, 9, 123,
/// extras ascending, 124) so two builds of the same epoch produce byte-
/// identical extensions (required for the off-loop/on-loop candidate parity).
/// Field order does not affect consensus validity — peers re-parse the set
/// order-independently — but determinism is required for the parity guarantee.
pub fn active_params_to_extension_fields(
    params: &ActiveProtocolParameters,
) -> Vec<([u8; 2], Vec<u8>)> {
    let p = SYSTEM_PARAMETERS_PREFIX;
    let be = |v: i32| v.to_be_bytes().to_vec();
    let mut out: Vec<([u8; 2], Vec<u8>)> = vec![
        ([p, ids::STORAGE_FEE_FACTOR], be(params.storage_fee_factor)),
        ([p, ids::MIN_VALUE_PER_BYTE], be(params.min_value_per_byte)),
        ([p, ids::MAX_BLOCK_SIZE], be(params.max_block_size)),
        ([p, ids::MAX_BLOCK_COST], be(params.max_block_cost)),
        ([p, ids::TOKEN_ACCESS_COST], be(params.token_access_cost)),
        ([p, ids::INPUT_COST], be(params.input_cost)),
        ([p, ids::DATA_INPUT_COST], be(params.data_input_cost)),
        ([p, ids::OUTPUT_COST], be(params.output_cost)),
    ];
    if let Some(v) = params.subblocks_per_block {
        out.push(([p, ids::SUBBLOCKS_PER_BLOCK], be(v)));
    }
    out.push(([p, ids::BLOCK_VERSION], be(params.block_version as i32)));
    // `extra` carries non-numeric-but-i32 keys the parser preserved (soft-fork
    // state 121/122, any forward-compatible ids). Ascending for determinism.
    let mut extras = params.extra.clone();
    extras.sort_by_key(|(id, _)| *id);
    for (id, value) in extras {
        out.push(([p, id], be(value)));
    }
    out.push((
        [p, SOFT_FORK_DISABLING_RULES_ID],
        params.proposed_update.serialize(),
    ));
    out
}

/// `softForkStartingHeight` (id 122) and `softForkVotesCollected` (id
/// 121) accessors. The soft-fork voting state machine reads these
/// without lifting them out of `extra`, so the persisted codec stays
/// stable and these stay forward-compatibly grouped with other
/// non-numeric soft-fork voting keys.
impl ActiveProtocolParameters {
    /// Read the soft-fork starting height (id 122) if present in `extra`.
    pub fn soft_fork_starting_height(&self) -> Option<i32> {
        self.extra
            .iter()
            .find_map(|(id, v)| (*id == 122).then_some(*v))
    }

    /// Read the running soft-fork vote tally (id 121) if present in `extra`.
    pub fn soft_fork_votes_collected(&self) -> Option<i32> {
        self.extra
            .iter()
            .find_map(|(id, v)| (*id == 121).then_some(*v))
    }
}

impl ActiveProtocolParameters {
    /// Encode for storage in the `voted_params` redb table.
    ///
    /// Format (`[proposed]`):
    /// ```text
    /// u32   epoch_start_height (BE)
    /// u8    field_count        // total ids written
    /// { u8 id, i32 value (BE) } * field_count
    /// ```
    ///
    /// Validate that `extra` does not collide with any named parameter
    /// id and contains no internal duplicates. The codec's deserialize
    /// path rejects duplicate ids; without this check, a caller-supplied
    /// `extra` could produce a row that is unreadable on the next open.
    pub fn validate(&self) -> Result<(), ActiveParamsError> {
        const RESERVED: &[u8] = &[
            ids::STORAGE_FEE_FACTOR,
            ids::MIN_VALUE_PER_BYTE,
            ids::MAX_BLOCK_SIZE,
            ids::MAX_BLOCK_COST,
            ids::TOKEN_ACCESS_COST,
            ids::INPUT_COST,
            ids::DATA_INPUT_COST,
            ids::OUTPUT_COST,
            ids::SUBBLOCKS_PER_BLOCK,
            ids::BLOCK_VERSION,
        ];
        let mut seen = std::collections::BTreeSet::<u8>::new();
        for (id, _) in &self.extra {
            if RESERVED.contains(id) {
                return Err(ActiveParamsError::ExtraReservesNamedId(*id));
            }
            if !seen.insert(*id) {
                return Err(ActiveParamsError::ExtraDuplicateId(*id));
            }
        }
        Ok(())
    }

    /// Encode for storage. Returns an error if the type's invariant is
    /// violated (`extra` colliding with a reserved id, or duplicates in
    /// `extra`); see [`Self::validate`].
    ///
    /// Wire format **v2** (current writer):
    ///
    /// ```text
    /// u32 epoch_start_height (BE)
    /// u8  field_count
    /// { u8 id, i32 value (BE) } * field_count
    /// u32 proposed_update_blob_len (BE)
    /// { u8 } * proposed_update_blob_len
    /// u32 activated_update_blob_len (BE)
    /// { u8 } * activated_update_blob_len
    /// ```
    ///
    /// An earlier wire format (v1) omitted the trailing update blobs.
    /// [`Self::deserialize`] auto-detects: if the body length matches
    /// the v1 exact-length invariant, it decodes as v1 with empty
    /// update blobs; otherwise it expects the v2 trailing fields.
    /// New writes always emit v2.
    ///
    /// Internal format only — never sent on the wire.
    pub fn serialize(&self) -> Result<Vec<u8>, ActiveParamsError> {
        self.validate()?;

        let extra_len = self.extra.len();
        let mut entries: Vec<(u8, i32)> = Vec::with_capacity(11 + extra_len);
        entries.push((ids::STORAGE_FEE_FACTOR, self.storage_fee_factor));
        entries.push((ids::MIN_VALUE_PER_BYTE, self.min_value_per_byte));
        entries.push((ids::MAX_BLOCK_SIZE, self.max_block_size));
        entries.push((ids::MAX_BLOCK_COST, self.max_block_cost));
        entries.push((ids::TOKEN_ACCESS_COST, self.token_access_cost));
        entries.push((ids::INPUT_COST, self.input_cost));
        entries.push((ids::DATA_INPUT_COST, self.data_input_cost));
        entries.push((ids::OUTPUT_COST, self.output_cost));
        if let Some(v) = self.subblocks_per_block {
            entries.push((ids::SUBBLOCKS_PER_BLOCK, v));
        }
        entries.push((ids::BLOCK_VERSION, self.block_version as i32));
        entries.extend(self.extra.iter().copied());
        entries.sort_by_key(|(id, _)| *id);

        let count: u8 = entries.len() as u8;
        let proposed_blob = self.proposed_update.serialize();
        let activated_blob = self.activated_update.serialize();
        let mut out = Vec::with_capacity(
            4 + 1 + entries.len() * 5 + 4 + proposed_blob.len() + 4 + activated_blob.len(),
        );
        out.extend_from_slice(&self.epoch_start_height.to_be_bytes());
        out.push(count);
        for (id, v) in entries {
            out.push(id);
            out.extend_from_slice(&v.to_be_bytes());
        }
        // v2 trailing: proposed_update + activated_update length-prefixed.
        out.extend_from_slice(&(proposed_blob.len() as u32).to_be_bytes());
        out.extend_from_slice(&proposed_blob);
        out.extend_from_slice(&(activated_blob.len() as u32).to_be_bytes());
        out.extend_from_slice(&activated_blob);
        Ok(out)
    }

    /// Decode a record produced by `serialize`. Auto-detects v1 vs v2
    /// based on whether the body matches the v1 exact-length invariant
    /// or has v2 trailing fields.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ActiveParamsError> {
        if bytes.len() < 5 {
            return Err(ActiveParamsError::UnexpectedEof);
        }
        let epoch_start_height = u32::from_be_bytes(
            bytes[0..4]
                .try_into()
                .expect("4-byte slice to [u8; 4] is infallible"),
        );
        let count = bytes[4] as usize;
        let body_start = 5usize;
        let entries_end = body_start + count * 5;
        if bytes.len() < entries_end {
            return Err(ActiveParamsError::UnexpectedEof);
        }
        let body = &bytes[body_start..entries_end];

        // v1 body length is exactly count * 5; v2 has trailing
        // length-prefixed update blobs.
        let trailing = &bytes[entries_end..];
        let (proposed_update, activated_update) = if trailing.is_empty() {
            // v1 wire format: no update blobs persisted.
            (
                ErgoValidationSettingsUpdate::empty(),
                ErgoValidationSettingsUpdate::empty(),
            )
        } else {
            // v2: parse proposed_update + activated_update.
            if trailing.len() < 4 {
                return Err(ActiveParamsError::UnexpectedEof);
            }
            let proposed_len = u32::from_be_bytes(
                trailing[0..4]
                    .try_into()
                    .expect("4-byte slice to [u8; 4] is infallible"),
            ) as usize;
            let proposed_end = 4 + proposed_len;
            if trailing.len() < proposed_end + 4 {
                return Err(ActiveParamsError::UnexpectedEof);
            }
            let proposed =
                ErgoValidationSettingsUpdate::deserialize_exact(&trailing[4..proposed_end])?;
            let activated_len_offset = proposed_end;
            let activated_len = u32::from_be_bytes(
                trailing[activated_len_offset..activated_len_offset + 4]
                    .try_into()
                    .expect("4-byte slice to [u8; 4] is infallible"),
            ) as usize;
            let activated_start = activated_len_offset + 4;
            let activated_end = activated_start + activated_len;
            if trailing.len() < activated_end {
                return Err(ActiveParamsError::UnexpectedEof);
            }
            let activated = ErgoValidationSettingsUpdate::deserialize_exact(
                &trailing[activated_start..activated_end],
            )?;
            if trailing.len() != activated_end {
                return Err(ActiveParamsError::TrailingBytes);
            }
            (proposed, activated)
        };

        let mut by_id: std::collections::BTreeMap<u8, i32> = std::collections::BTreeMap::new();
        for chunk in body.chunks_exact(5) {
            let id = chunk[0];
            let v = i32::from_be_bytes(
                chunk[1..5]
                    .try_into()
                    .expect("4-byte slice to [u8; 4] is infallible"),
            );
            if by_id.insert(id, v).is_some() {
                return Err(ActiveParamsError::CodecDuplicateId(id));
            }
        }

        let mut take = |id: u8| {
            by_id
                .remove(&id)
                .ok_or(ActiveParamsError::MissingRequired(id))
        };
        // Non-negativity-constrained fields fail-close at the codec
        // boundary so `ProtocolParams::from_active` stays infallible
        // (spec §8.1). Same contract as parse_active_params.
        let mut take_nonneg = |id: u8| -> Result<i32, ActiveParamsError> {
            let v = take(id)?;
            if v < 0 {
                return Err(ActiveParamsError::NegativeProtocolParam { id, value: v });
            }
            Ok(v)
        };
        let storage_fee_factor = take_nonneg(ids::STORAGE_FEE_FACTOR)?;
        let min_value_per_byte = take_nonneg(ids::MIN_VALUE_PER_BYTE)?;
        let max_block_size = take_nonneg(ids::MAX_BLOCK_SIZE)?;
        let max_block_cost = take_nonneg(ids::MAX_BLOCK_COST)?;
        let token_access_cost = take_nonneg(ids::TOKEN_ACCESS_COST)?;
        let input_cost = take_nonneg(ids::INPUT_COST)?;
        let data_input_cost = take_nonneg(ids::DATA_INPUT_COST)?;
        let output_cost = take_nonneg(ids::OUTPUT_COST)?;
        let block_version_i32 = take(ids::BLOCK_VERSION)?;
        // On parse-from-extension we silently truncate to match Scala's
        // `.toByte`; on decode-from-DB the row is ours, and an out-of-range
        // value means corruption. Fail loud.
        if !(0..=255).contains(&block_version_i32) {
            return Err(ActiveParamsError::BlockVersionOutOfRange(block_version_i32));
        }
        let subblocks_per_block = by_id.remove(&ids::SUBBLOCKS_PER_BLOCK);
        let extra: Vec<(u8, i32)> = by_id.into_iter().collect();

        Ok(Self {
            epoch_start_height,
            block_version: block_version_i32 as u8,
            storage_fee_factor,
            min_value_per_byte,
            max_block_size,
            max_block_cost,
            token_access_cost,
            input_cost,
            data_input_cost,
            output_cost,
            subblocks_per_block,
            extra,
            proposed_update,
            activated_update,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::ModifierId;
    use ergo_ser::extension::ExtensionField;

    fn ext_with(fields: Vec<([u8; 2], Vec<u8>)>) -> Extension {
        Extension {
            header_id: ModifierId::from_bytes([0u8; 32]),
            fields: fields
                .into_iter()
                .map(|(k, v)| ExtensionField { key: k, value: v })
                .collect(),
        }
    }

    fn be_i32(v: i32) -> Vec<u8> {
        v.to_be_bytes().to_vec()
    }

    fn full_required_set() -> Vec<([u8; 2], Vec<u8>)> {
        vec![
            ([0x00, 1], be_i32(1_250_000)),
            ([0x00, 2], be_i32(360)),
            ([0x00, 3], be_i32(524_288)),
            ([0x00, 4], be_i32(1_000_000)),
            ([0x00, 5], be_i32(100)),
            ([0x00, 6], be_i32(2_000)),
            ([0x00, 7], be_i32(100)),
            ([0x00, 8], be_i32(100)),
            ([0x00, 123], be_i32(1)),
        ]
    }

    #[test]
    fn parse_required_only() {
        let ext = ext_with(full_required_set());
        let p = parse_active_params(&ext, 1024).unwrap();
        assert_eq!(p.epoch_start_height, 1024);
        assert_eq!(p.block_version, 1);
        assert_eq!(p.storage_fee_factor, 1_250_000);
        assert_eq!(p.min_value_per_byte, 360);
        assert_eq!(p.max_block_size, 524_288);
        assert_eq!(p.max_block_cost, 1_000_000);
        assert_eq!(p.token_access_cost, 100);
        assert_eq!(p.input_cost, 2_000);
        assert_eq!(p.data_input_cost, 100);
        assert_eq!(p.output_cost, 100);
        assert!(p.subblocks_per_block.is_none());
        assert!(p.extra.is_empty());
    }

    #[test]
    fn parse_with_subblocks_post_eip37() {
        let mut fields = full_required_set();
        fields.push(([0x00, 9], be_i32(30)));
        let p = parse_active_params(&ext_with(fields), 1_772_544).unwrap();
        assert_eq!(p.subblocks_per_block, Some(30));
    }

    #[test]
    fn parse_lifts_softfork_disabling_rules_into_proposed_update() {
        // Key (0x00, 124) is parsed as ErgoValidationSettingsUpdate
        // rather than filtered. An empty update (0x00 0x00 → 0
        // disabled_rules + 0 status_updates) round-trips to
        // `proposed_update == empty`.
        let mut fields = full_required_set();
        fields.push(([0x00, 124], vec![0x00, 0x00]));
        let p = parse_active_params(&ext_with(fields), 1024).unwrap();
        assert!(p.extra.is_empty());
        assert_eq!(
            p.proposed_update,
            crate::voting::validation_settings::ErgoValidationSettingsUpdate::empty()
        );
    }

    #[test]
    fn parse_lifts_rule_409_disabled_into_proposed_update() {
        let mut fields = full_required_set();
        let update = crate::voting::validation_settings::ErgoValidationSettingsUpdate {
            rules_to_disable: vec![409],
            status_updates: vec![],
        };
        fields.push(([0x00, 124], update.serialize()));
        let p = parse_active_params(&ext_with(fields), 1024).unwrap();
        assert!(p.proposed_update.rules_to_disable.contains(&409));
    }

    #[test]
    fn parse_rejects_malformed_softfork_disabling_rules_value() {
        let mut fields = full_required_set();
        // Bytes that don't decode as ErgoValidationSettingsUpdate
        // (continuation bit set without termination).
        fields.push(([0x00, 124], vec![0xCA, 0xFE]));
        let err = parse_active_params(&ext_with(fields), 1024).unwrap_err();
        assert!(matches!(err, ActiveParamsError::ValidationSettings(_)));
    }

    #[test]
    fn parse_preserves_softfork_voting_keys_as_extra() {
        let mut fields = full_required_set();
        fields.push(([0x00, 120], be_i32(7))); // SoftFork
        fields.push(([0x00, 121], be_i32(42))); // SoftForkVotesCollected
        fields.push(([0x00, 122], be_i32(900_000))); // SoftForkStartingHeight
        let p = parse_active_params(&ext_with(fields), 700_416).unwrap();
        assert_eq!(p.extra, vec![(120, 7), (121, 42), (122, 900_000)]);
    }

    #[test]
    fn parse_ignores_non_system_prefix() {
        let mut fields = full_required_set();
        fields.push(([0x01, 1], be_i32(99))); // wrong prefix → not a param
        let p = parse_active_params(&ext_with(fields), 1024).unwrap();
        assert!(p.extra.is_empty());
    }

    #[test]
    fn parse_rejects_bad_value_length() {
        let mut fields = full_required_set();
        // Replace storage_fee_factor with a 3-byte value
        fields[0] = ([0x00, 1], vec![0x00, 0x01, 0x02]);
        let err = parse_active_params(&ext_with(fields), 1024).unwrap_err();
        assert_eq!(err, ActiveParamsError::BadValueLength(1, 3));
    }

    #[test]
    fn parse_rejects_duplicate_id() {
        let mut fields = full_required_set();
        fields.push(([0x00, 1], be_i32(99)));
        let err = parse_active_params(&ext_with(fields), 1024).unwrap_err();
        assert_eq!(err, ActiveParamsError::DuplicateId(1));
    }

    #[test]
    fn parse_rejects_missing_required() {
        let mut fields = full_required_set();
        fields.remove(0); // drop storage_fee_factor (id=1)
        let err = parse_active_params(&ext_with(fields), 1024).unwrap_err();
        assert_eq!(err, ActiveParamsError::MissingRequired(1));
    }

    #[test]
    fn parse_rejects_empty_map() {
        let ext = ext_with(vec![]);
        let err = parse_active_params(&ext, 1024).unwrap_err();
        assert_eq!(err, ActiveParamsError::EmptyMap);
    }

    #[test]
    fn codec_roundtrip_required_only() {
        let p = parse_active_params(&ext_with(full_required_set()), 1024).unwrap();
        let bytes = p.serialize().unwrap();
        let back = ActiveProtocolParameters::deserialize(&bytes).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn codec_roundtrip_with_subblocks_and_extras() {
        let mut fields = full_required_set();
        fields.push(([0x00, 9], be_i32(30)));
        fields.push(([0x00, 120], be_i32(7)));
        fields.push(([0x00, 121], be_i32(42)));
        let p = parse_active_params(&ext_with(fields), 1_772_544).unwrap();
        let bytes = p.serialize().unwrap();
        let back = ActiveProtocolParameters::deserialize(&bytes).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn codec_roundtrip_scala_launch() {
        let p = scala_launch();
        let bytes = p.serialize().unwrap();
        let back = ActiveProtocolParameters::deserialize(&bytes).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn codec_rejects_truncated_input() {
        let bytes = vec![0u8; 4]; // missing field_count
        let err = ActiveProtocolParameters::deserialize(&bytes).unwrap_err();
        assert_eq!(err, ActiveParamsError::UnexpectedEof);
    }

    #[test]
    fn codec_rejects_trailing_bytes() {
        let p = scala_launch();
        let mut bytes = p.serialize().unwrap();
        bytes.push(0xAB);
        let err = ActiveProtocolParameters::deserialize(&bytes).unwrap_err();
        assert_eq!(err, ActiveParamsError::TrailingBytes);
    }

    #[test]
    fn codec_rejects_duplicate_id_on_decode() {
        // Hand-craft a v1-format payload with a duplicate id.
        let p = scala_launch();
        let mut entries: Vec<(u8, i32)> = vec![
            (1, p.storage_fee_factor),
            (2, p.min_value_per_byte),
            (3, p.max_block_size),
            (4, p.max_block_cost),
            (5, p.token_access_cost),
            (6, p.input_cost),
            (7, p.data_input_cost),
            (8, p.output_cost),
            (123, p.block_version as i32),
        ];
        entries.push((1, 99)); // duplicate id 1
        let count = entries.len() as u8;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&p.epoch_start_height.to_be_bytes());
        bytes.push(count);
        for (id, v) in entries {
            bytes.push(id);
            bytes.extend_from_slice(&v.to_be_bytes());
        }
        // No v2 trailing — this is a v1-format payload (auto-detected
        // because trailing is empty).
        let err = ActiveProtocolParameters::deserialize(&bytes).unwrap_err();
        assert_eq!(err, ActiveParamsError::CodecDuplicateId(1));
    }

    #[test]
    fn serialize_is_deterministic_ascending_ids() {
        let mut fields = full_required_set();
        fields.push(([0x00, 9], be_i32(30)));
        fields.push(([0x00, 122], be_i32(900_000)));
        let p = parse_active_params(&ext_with(fields), 1_772_544).unwrap();

        let bytes = p.serialize().unwrap();
        // Read the count byte at offset 4, then walk count*5 entry
        // bytes starting at 5. v2 trailing fields follow the entries.
        let count = bytes[4] as usize;
        let entries_end = 5 + count * 5;
        let body = &bytes[5..entries_end];
        let ids: Vec<u8> = body.chunks_exact(5).map(|c| c[0]).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
        assert_eq!(ids, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 122, 123]);
    }

    #[test]
    fn codec_v2_persists_proposed_and_activated_updates() {
        let mut p = scala_launch();
        p.proposed_update = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![409],
            status_updates: vec![],
        };
        p.activated_update = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![409],
            status_updates: vec![],
        };
        let bytes = p.serialize().unwrap();
        let back = ActiveProtocolParameters::deserialize(&bytes).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn codec_v1_legacy_decodes_with_empty_updates() {
        // Hand-craft a v1-format payload (no trailing update blobs).
        let p = scala_launch();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&p.epoch_start_height.to_be_bytes());
        bytes.push(9); // 9 entries: ids 1-8 + 123
        for (id, v) in [
            (1, p.storage_fee_factor),
            (2, p.min_value_per_byte),
            (3, p.max_block_size),
            (4, p.max_block_cost),
            (5, p.token_access_cost),
            (6, p.input_cost),
            (7, p.data_input_cost),
            (8, p.output_cost),
            (123, p.block_version as i32),
        ] {
            bytes.push(id);
            bytes.extend_from_slice(&v.to_be_bytes());
        }
        // No trailing — v1.
        let back = ActiveProtocolParameters::deserialize(&bytes).unwrap();
        assert_eq!(back.proposed_update, ErgoValidationSettingsUpdate::empty());
        assert_eq!(back.activated_update, ErgoValidationSettingsUpdate::empty());
        assert_eq!(back.input_cost, p.input_cost);
    }

    #[test]
    fn validate_rejects_extra_with_reserved_id() {
        let mut p = scala_launch();
        p.extra = vec![(1, 999_999)]; // id 1 is storage_fee_factor
        let err = p.serialize().unwrap_err();
        assert_eq!(err, ActiveParamsError::ExtraReservesNamedId(1));
    }

    #[test]
    fn validate_rejects_extra_with_internal_duplicate() {
        let mut p = scala_launch();
        p.extra = vec![(120, 1), (120, 2)];
        let err = p.serialize().unwrap_err();
        assert_eq!(err, ActiveParamsError::ExtraDuplicateId(120));
    }

    #[test]
    fn deserialize_rejects_block_version_out_of_range() {
        // Hand-craft a row where block_version (id=123) holds 256 (== 0x100)
        let bytes = {
            let mut p = scala_launch();
            p.block_version = 1;
            let mut wire = p.serialize().unwrap();
            // Replace the i32 bytes for id 123 with 0x00000100 (== 256)
            // wire layout: 4-byte height + 1-byte count + entries.
            // Locate id 123 entry.
            let count = wire[4] as usize;
            for i in 0..count {
                let off = 5 + i * 5;
                if wire[off] == 123 {
                    wire[off + 1..off + 5].copy_from_slice(&256i32.to_be_bytes());
                    break;
                }
            }
            wire
        };
        let err = ActiveProtocolParameters::deserialize(&bytes).unwrap_err();
        assert_eq!(err, ActiveParamsError::BlockVersionOutOfRange(256));
    }

    #[test]
    fn deserialize_rejects_negative_cost_bearing_param() {
        // Storage corruption case: a row has a negative i32 in a
        // cost-bearing slot. The codec must reject at this boundary so
        // `ProtocolParams::from_active` can stay infallible (§8.1).
        let bytes = {
            let mut wire = scala_launch().serialize().unwrap();
            // Find input_cost (id=6) and overwrite its i32 with -1.
            let count = wire[4] as usize;
            for i in 0..count {
                let off = 5 + i * 5;
                if wire[off] == ids::INPUT_COST {
                    wire[off + 1..off + 5].copy_from_slice(&(-1i32).to_be_bytes());
                    break;
                }
            }
            wire
        };
        let err = ActiveProtocolParameters::deserialize(&bytes).unwrap_err();
        assert_eq!(
            err,
            ActiveParamsError::NegativeProtocolParam {
                id: ids::INPUT_COST,
                value: -1
            },
        );
    }

    #[test]
    fn parse_active_params_rejects_negative_cost_bearing_param() {
        // Same shape but on the extension-parse path: a `(0x00, id=6)`
        // entry whose 4-byte BE value is negative must be rejected at
        // the parse boundary, not silently widened to a u64 downstream.
        let mut fields = full_required_set();
        for (key, value) in fields.iter_mut() {
            if *key == [SYSTEM_PARAMETERS_PREFIX, ids::INPUT_COST] {
                *value = (-7i32).to_be_bytes().to_vec();
            }
        }
        let ext = ext_with(fields);
        let err = parse_active_params(&ext, 1024).unwrap_err();
        assert_eq!(
            err,
            ActiveParamsError::NegativeProtocolParam {
                id: ids::INPUT_COST,
                value: -7
            },
        );
    }

    #[test]
    fn parse_truncates_block_version_to_low_byte_matching_scala() {
        // Scala stores Int but reduces to .toByte; mirror that on parse.
        let mut fields = full_required_set();
        // Replace block_version entry with 0x00000102 — low byte = 2
        fields.last_mut().unwrap().1 = be_i32(0x0000_0102);
        let p = parse_active_params(&ext_with(fields), 1024).unwrap();
        assert_eq!(p.block_version, 2);
    }

    /// Real Scala-validated epoch-start fixture.
    ///
    /// Block 417792 (epoch 408 * 1024) lives in
    /// `test-vectors/mainnet/blocks_417785_417800.json`. Its extension
    /// carries the parameter set Scala reports for that epoch.
    /// Hand-decoded values from the fixture's hex blobs:
    /// - id 1 (storage_fee_factor) = 0x001312D0 = 1_250_000
    /// - id 2 (min_value_per_byte) = 0x00000168 =       360
    /// - id 3 (max_block_size)     = 0x001364E1 = 1_271_009
    /// - id 4 (max_block_cost)     = 0x0048C570 = 4_769_136
    /// - id 5 (token_access_cost)  = 0x00000064 =       100
    /// - id 6 (input_cost)         = 0x000007D0 =     2_000
    /// - id 7 (data_input_cost)    = 0x00000064 =       100
    /// - id 8 (output_cost)        = 0x00000064 =       100
    /// - id 123 (block_version)    = 0x00000002 =         2
    /// - id 124 (validation-settings update) → filtered out (2-byte value)
    ///
    /// No id 9 (pre-EIP37). No soft-fork voting keys (120-122).
    #[test]
    fn parse_real_fixture_block_417792() {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-vectors/mainnet/blocks_417785_417800.json"
        ))
        .expect("missing test fixture; rerun cost-vector extraction");
        let blocks: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let block = blocks
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["height"].as_u64() == Some(417_792))
            .expect("block 417792 not in fixture");

        let mut fields: Vec<ExtensionField> = Vec::new();
        for f in block["extension"]["fields"].as_array().unwrap() {
            let key_hex = f[0].as_str().unwrap();
            let val_hex = f[1].as_str().unwrap();
            let key_bytes = hex::decode(key_hex).unwrap();
            let value = hex::decode(val_hex).unwrap();
            fields.push(ExtensionField {
                key: [key_bytes[0], key_bytes[1]],
                value,
            });
        }
        let ext = Extension {
            header_id: ModifierId::from_bytes([0u8; 32]),
            fields,
        };

        let p = parse_active_params(&ext, 417_792).unwrap();

        assert_eq!(p.epoch_start_height, 417_792);
        assert_eq!(p.storage_fee_factor, 1_250_000);
        assert_eq!(p.min_value_per_byte, 360);
        assert_eq!(p.max_block_size, 1_271_009);
        assert_eq!(p.max_block_cost, 4_769_136);
        assert_eq!(p.token_access_cost, 100);
        assert_eq!(p.input_cost, 2_000);
        assert_eq!(p.data_input_cost, 100);
        assert_eq!(p.output_cost, 100);
        assert_eq!(p.block_version, 2);
        assert!(p.subblocks_per_block.is_none());
        assert!(
            p.extra.is_empty(),
            "expected no soft-fork voting keys at h=417792, got {:?}",
            p.extra
        );

        // Round-trip through our codec.
        let bytes = p.serialize().unwrap();
        let back = ActiveProtocolParameters::deserialize(&bytes).unwrap();
        assert_eq!(p, back);
    }

    // ----- launch oracle parity -----

    #[test]
    fn scala_launch_testnet_matches_mainnet() {
        // Scala `TestnetLaunchParameters` is byte-identical to
        // `MainnetLaunchParameters` (see
        // `ergo-core/src/main/scala/org/ergoplatform/settings/LaunchParameters.scala`).
        // A regression that re-introduces a divergent testnet launch row
        // would re-create the h=1024 `exMatchValidationSettings` rejection
        // that surfaces only after `--network testnet` actually applies
        // real blocks.
        assert_eq!(scala_launch_testnet(), scala_launch_mainnet());
    }

    #[test]
    fn scala_launch_for_network_returns_mainnet_row_on_both_arms() {
        // Same data on both arms today; this pins the invariant so a
        // future intentional divergence (e.g. devnet-style block version
        // override) has to update this test deliberately.
        let m = scala_launch_for_network(Network::Mainnet);
        let t = scala_launch_for_network(Network::Testnet);
        assert_eq!(m, t);
        assert_eq!(m.block_version, 1);
        assert_eq!(m.proposed_update.rules_to_disable, Vec::<u16>::new());
        assert!(m.proposed_update.status_updates.is_empty());
        assert_eq!(m.activated_update.rules_to_disable, Vec::<u16>::new());
        assert!(m.activated_update.status_updates.is_empty());
    }
}
