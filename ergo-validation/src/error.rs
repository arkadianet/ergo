use thiserror::Error;

/// Every consensus-relevant rejection reason produced by the
/// transaction / block / header validators.
///
/// Variants are organized into five groups by the failure phase:
/// deserialization, structural (stateless), state-dependent (UTXO
/// resolution), monetary, script, and cost-budget. Each carries the
/// minimum context the API / mempool layers need to map onto
/// Scala-parity error envelopes.
#[derive(Debug, Error)]
pub enum ValidationError {
    // --- Deserialization ---
    /// Bytes failed to parse into the expected wire form.
    #[error("deserialization failed: {0}")]
    Deserialization(String),
    /// Bytes parsed but did not survive a re-serialize round-trip — the
    /// input was non-canonical (e.g. an over-long VLQ).
    #[error("canonical form violated: reserialized bytes differ from input")]
    NonCanonical,

    // --- Structural (stateless) ---
    /// Transaction has zero inputs.
    #[error("transaction has no inputs")]
    NoInputs,
    /// Same `box_id` appears more than once in `inputs`.
    #[error("duplicate input box ID at index {index}")]
    DuplicateInput {
        /// First repeating index.
        index: usize,
    },
    /// Scala `txManyInputs` (rule 102) — input count exceeds
    /// `Short.MaxValue = 32_767`. Wire codec accepts up to
    /// `u16::MAX = 65_535`; validator enforces Scala's tighter cap.
    #[error("transaction has too many inputs: {count} > {max} (rule 102)")]
    TooManyInputs {
        /// Number of inputs the transaction declares.
        count: usize,
        /// Scala-parity cap (`Short.MaxValue`).
        max: usize,
    },
    /// Scala `txManyDataInputs` (rule 103) — data-input count exceeds
    /// `Short.MaxValue`. Same wire-vs-validator gap as
    /// [`Self::TooManyInputs`].
    #[error("transaction has too many data inputs: {count} > {max} (rule 103)")]
    TooManyDataInputs {
        /// Number of data inputs the transaction declares.
        count: usize,
        /// Scala-parity cap (`Short.MaxValue`).
        max: usize,
    },
    /// Scala `txManyOutputs` (rule 104) — output candidate count
    /// exceeds `Short.MaxValue`. Same wire-vs-validator gap as
    /// [`Self::TooManyInputs`].
    #[error("transaction has too many outputs: {count} > {max} (rule 104)")]
    TooManyOutputs {
        /// Number of output candidates the transaction declares.
        count: usize,
        /// Scala-parity cap (`Short.MaxValue`).
        max: usize,
    },
    /// Output `value` is below the per-byte minimum required by
    /// `ProtocolParams::min_value_per_byte`.
    #[error("output {index}: value {value} below minimum {min}")]
    OutputValueTooLow {
        /// Output index inside the transaction.
        index: usize,
        /// Actual value (nanoErg).
        value: u64,
        /// Minimum required (nanoErg).
        min: u64,
    },
    /// Output carries more tokens than `ProtocolParams::max_tokens_per_box`.
    #[error("output {index}: {count} tokens exceeds maximum {max}")]
    TooManyTokens {
        /// Output index inside the transaction.
        index: usize,
        /// Token count carried.
        count: usize,
        /// Per-box token cap.
        max: u8,
    },
    /// Serialized output box exceeds `ProtocolParams::max_box_size`.
    #[error("output {index}: box size {size} exceeds maximum {max}")]
    BoxTooLarge {
        /// Output index inside the transaction.
        index: usize,
        /// Serialized size in bytes.
        size: usize,
        /// Per-box size cap.
        max: u32,
    },
    /// Scala `txBoxPropositionSize` (rule 121) — output's
    /// `propositionBytes` (serialized `ergo_tree`) exceeds the sigma-
    /// state `MaxPropositionBytes` constant (4_096 bytes).
    #[error("output {index}: proposition size {size} exceeds maximum {max} (rule 121)")]
    PropositionTooLarge {
        /// Output index inside the transaction.
        index: usize,
        /// Serialized ergo_tree length in bytes.
        size: usize,
        /// Sigma-state cap (`MaxPropositionBytes`).
        max: usize,
    },
    /// Scala `txFuture` (rule 112) — output's `creation_height`
    /// exceeds the block being validated. An output cannot claim it
    /// was created at a future height.
    #[error("output {index}: creation_height {creation_height} > block height {block_height} (rule 112)")]
    OutputFromFuture {
        /// Output index inside the transaction.
        index: usize,
        /// Claimed creation height of the output.
        creation_height: u32,
        /// Height of the block being validated.
        block_height: u32,
    },
    /// Scala `txMonotonicHeight` (rule 124) — at block version
    /// `> Header.HardeningVersion (=2)`, every output's
    /// `creation_height` must be at least the maximum
    /// `creation_height` across all spent input boxes. Soft-fork-
    /// gated: v1 and v2 blocks treat this rule as a no-op.
    #[error("output {index}: creation_height {creation_height} < max input creation_height {max_input_height} (rule 124)")]
    OutputCreationHeightBelowInputs {
        /// Output index inside the transaction.
        index: usize,
        /// Claimed creation height of the output.
        creation_height: u32,
        /// Maximum `creation_height` across the spending inputs'
        /// resolved boxes.
        max_input_height: u32,
    },

    // --- State-dependent (UTXO resolution) ---
    /// A spending input references a box that the UTXO view does not
    /// know about.
    #[error("input box not found in UTXO set: {box_id}")]
    InputBoxNotFound {
        /// Hex-encoded missing `box_id`.
        box_id: String,
    },
    /// A data input references a box that the UTXO view does not know
    /// about.
    #[error("data input box not found in UTXO set: {box_id}")]
    DataInputBoxNotFound {
        /// Hex-encoded missing `box_id`.
        box_id: String,
    },
    /// The number of resolved spending-input boxes does not match the
    /// number of declared inputs (boxes were resolved out-of-band).
    #[error("resolved inputs mismatch: expected {expected} inputs, got {got}")]
    ResolvedInputsMismatch {
        /// Inputs declared by the transaction.
        expected: usize,
        /// Resolved boxes the caller supplied.
        got: usize,
    },
    /// A resolved spending-input box's id doesn't match the declared
    /// input's `box_id`.
    #[error("resolved input {index}: box ID mismatch (expected {expected})")]
    ResolvedInputIdMismatch {
        /// Input index inside the transaction.
        index: usize,
        /// Hex-encoded `box_id` the input declared.
        expected: String,
    },
    /// The number of resolved data-input boxes does not match the
    /// number of declared data inputs.
    #[error("resolved data inputs mismatch: expected {expected} data inputs, got {got}")]
    ResolvedDataInputsMismatch {
        /// Data inputs declared by the transaction.
        expected: usize,
        /// Resolved boxes the caller supplied.
        got: usize,
    },
    /// A resolved data-input box's id doesn't match the declared data
    /// input's `box_id`.
    #[error("resolved data input {index}: box ID mismatch (expected {expected})")]
    ResolvedDataInputIdMismatch {
        /// Data input index inside the transaction.
        index: usize,
        /// Hex-encoded `box_id` the data input declared.
        expected: String,
    },

    // --- Monetary ---
    /// Sum of nanoErg in inputs does not equal sum in outputs.
    #[error("ERG not conserved: inputs={inputs}, outputs={outputs}")]
    ErgNotConserved {
        /// Total input nanoErg.
        inputs: u64,
        /// Total output nanoErg.
        outputs: u64,
    },
    /// A non-minted token's output amount exceeds its input amount.
    #[error("token {token_id}: output amount {output} exceeds input amount {input}")]
    TokenNotConserved {
        /// Hex-encoded token id.
        token_id: String,
        /// Total input amount of this token.
        input: u64,
        /// Total output amount of this token.
        output: u64,
    },
    /// A token claims to be newly minted but its id does not equal
    /// `inputs[0].box_id` (the only valid mint source).
    #[error("invalid token minting: {token_id} is not inputs[0].boxId")]
    InvalidMinting {
        /// Hex-encoded mint-claiming token id.
        token_id: String,
    },

    // --- Script ---
    /// Script evaluation produced an evaluator-level error.
    #[error("input {index}: script evaluation failed: {reason}")]
    ScriptError {
        /// Failing input index.
        index: usize,
        /// Evaluator error message.
        reason: String,
    },
    /// Script reduced cleanly but the spending proof did not verify.
    #[error("input {index}: spending proof verification failed")]
    ProofFailed {
        /// Failing input index.
        index: usize,
    },

    // --- Cost (only when enforce == true) ---
    /// Cumulative JIT cost exceeded the per-block / per-transaction limit.
    #[error("cost limit exceeded: {current} > {limit}")]
    CostExceeded {
        /// Cost reached at the moment of rejection (JitCost units).
        current: u64,
        /// Active limit (JitCost units).
        limit: u64,
    },
    /// JitCost arithmetic exceeded the Scala `Int.MaxValue` bound that
    /// JitCost mirrors (see `cost.rs` `SCALA_INT_MAX`). Unreachable for
    /// honest current mainnet input — the protocol cap on
    /// `max_block_cost` is ~45× below the bound (pin test in
    /// `cost.rs` enforces the safety margin) — but the structured error
    /// means consensus rejects offending input cleanly rather than
    /// panicking the node.
    #[error("JitCost arithmetic overflow: {0}")]
    JitCostOverflow(String),

    // --- Internal (validator implementation invariant) ---
    /// A validator-internal invariant was violated. Distinct from
    /// consensus rejection: this signals a bug in the validator itself
    /// (e.g. parallel and sequential paths disagreeing). Returned
    /// rather than panicked so a worker pool failure cannot tank the
    /// node mid-block, but treated as a hard error by callers.
    #[error("internal validator invariant violated: {0}")]
    InternalInvariantViolated(&'static str),
}
