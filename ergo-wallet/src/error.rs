//! Error type for the wallet crate.
//!
//! One variant per failure class so callers can pattern-match on the
//! kind without parsing strings. Display impls are operator-readable;
//! never include private-key material in any error.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    /// BIP39 mnemonic could not be parsed or failed its checksum.
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    /// Mnemonic word count is not one of {12, 15, 18, 21, 24}.
    #[error("unsupported mnemonic word count: {0} (allowed: 12, 15, 18, 21, 24)")]
    UnsupportedWordCount(usize),

    /// BIP32 derivation path failed to parse.
    #[error("invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    /// secp256k1 scalar overflow during BIP32 child derivation. Per BIP32
    /// spec, the caller should retry with the next index when this
    /// happens; in HD wallets the probability is cosmologically small.
    #[error("derivation produced an invalid scalar (caller should advance index)")]
    InvalidDerivedScalar,

    /// Pubkey decoding failed (wrong length, off-curve point, or invalid encoding).
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Hex decoding failed.
    #[error("invalid hex: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    /// AES-256-GCM encryption failed (key/IV problem or input too large).
    /// In practice this should never fire — encrypt under a freshly
    /// derived key + random IV cannot fail except on truly malformed
    /// inputs. If you see it, treat as a programming bug.
    #[error("encryption failed: {0}")]
    Encryption(String),

    /// AES-256-GCM decryption failed: ciphertext tampered, wrong password,
    /// or corrupt secret file. Indistinguishable failure modes by design
    /// (timing-safe authTag verification).
    #[error("decryption failed (wrong password or corrupt secret file)")]
    Decryption,

    /// Secret-file I/O or JSON parsing failed.
    #[error("secret file error: {0}")]
    SecretFile(String),

    /// Wallet operation requires an unlocked wallet but the wallet is
    /// currently locked. Returned by routes that need access to the
    /// master secret (deriveKey, getPrivateKey, signing paths).
    #[error("wallet locked")]
    WalletLocked,

    /// Wallet operation requires an initialized wallet but no secret
    /// file exists at `<data_dir>/wallet/*.json`.
    #[error("wallet uninitialized — call POST /wallet/init or /wallet/restore first")]
    WalletUninitialized,

    /// Restoring a wallet from a mnemonic requires the chain to be
    /// fully archived (`blocks_to_keep = -1`). Pruned nodes can't
    /// rescan from genesis. Matches Scala
    /// `ErgoWalletService.scala:336-337`.
    #[error("wallet_restore_pruning_unsupported")]
    RestorePruningUnsupported,

    /// Change address points at an untracked pubkey (deliberate spec
    /// divergence from Scala). Caller should hit
    /// POST /wallet/updateChangeAddress with a tracked address.
    #[error("change_address_untracked — call /wallet/updateChangeAddress with a tracked pubkey")]
    ChangeAddressUntracked,

    /// Proof generation failed — typically a secret key is missing for
    /// a required sigma branch (e.g., trying to prove ProveDlog(pk) when
    /// the wallet doesn't hold the secret for `pk`).
    #[error("missing secret key for proving: {0}")]
    MissingSecret(String),

    /// Box selection failed: insufficient funds, no token coverage, or
    /// no valid selection exists. Maps to REST `400 reason: "insufficient_funds"`.
    #[error("box selection failed: {0}")]
    BoxSelection(String),

    /// Transaction building failed at the structural level — usually a
    /// fee/change calculation produced negative ERG or violated minBoxValue.
    #[error("tx building failed: {0}")]
    TxBuild(String),

    /// Proof produced is invalid against its own proposition. Indicates
    /// a bug in the prover (should never fire if implementation is correct).
    #[error("internal: produced proof failed self-verification (proof bug)")]
    SelfVerifyFailed,

    /// Multi-sig proof tree structure does not match the expected sigma
    /// proposition shape (e.g., wrong AND/OR arity, wrong leaf type).
    #[error("multi-sig: proof tree structure mismatch: {0}")]
    MultiSigProofStructure(String),

    /// The real-secret pubkey supplied by this wallet was not found in
    /// the combined multi-sig proof tree. Indicates a mismatch between
    /// the signer set and the sigma proposition.
    #[error("multi-sig: real-secret pubkey not found in proof tree: {0}")]
    MultiSigSecretNotProven(String),

    /// A derivation path that is already being tracked was submitted
    /// again. The string is the rendered BIP32 path (e.g. `m/44'/429'/0'/0/5`).
    #[error("derivation: path already tracked: {0}")]
    DerivationPathExists(String),

    /// The per-path key limit has been reached. HD wallets impose a
    /// ceiling on keys per path to bound scan complexity.
    #[error("derivation: max keys per path reached ({0})")]
    DerivationMaxKeys(u64),

    /// The wallet has no derivable head — either it is locked or it has
    /// not been initialized with a master secret.
    #[error("derivation: no derivable head — wallet must be unlocked + initialized")]
    DerivationNoHead,
}
