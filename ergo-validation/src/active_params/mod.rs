//! Active protocol parameters parsed from a block's `Extension` at an
//! epoch-start block.
//!
//! Validation against the recomputed-from-votes set (Scala's
//! `exMatchParameters` / `exMatchParameters60`) lives in
//! [`crate::voting::extension_validation`]; this module owns the
//! parser, the persistence codec, and the launch-time defaults.
//!
//! - [`launch`] — `scala_launch*` mainnet/testnet launch-time defaults.
//! - [`extension_codec`] — `parse_active_params` /
//!   `active_params_to_extension_fields`, the block-extension wire
//!   format (a genuinely different format from the redb persist codec
//!   below, despite encoding the same struct).
//! - [`persist_codec`] — `validate`/`serialize`/`deserialize`, the redb
//!   storage wire format. Kept together deliberately: `deserialize`
//!   documents matching the exact byte-shape `serialize` produces
//!   (v1/v2 auto-detection).

mod extension_codec;
mod launch;
mod persist_codec;

pub use extension_codec::{active_params_to_extension_fields, parse_active_params};
pub use launch::{
    scala_launch, scala_launch_for_network, scala_launch_mainnet, scala_launch_testnet,
};

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
    /// infallible.
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
