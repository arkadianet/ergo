use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalletAdminError {
    Uninitialized,
    Locked,
    InvalidMnemonic,
    WrongPassword,
    RestorePruningUnsupported,
    ChangeAddressUntracked,
    BadRequest(String),
    StaleChainTip(String),
    Internal(String),
    Forbidden(String),
    WalletExists,
    DerivationPathExists,
    AddressNotTracked,
    RescanUnavailable(String),
    SensitiveOpDisabled,
    AcknowledgementRequired,
    RateLimited,
    BoxNotFound,
    UnsupportedScript,
    MissingSecret,
    UnsupportedIntent,
    ReemissionObligationUnmet(String),
    InsufficientFunds(String),
    ReemissionSpendNotAllowed(String),
    TokenBurnNotAllowed(String),
    TxNotFound,
}

pub type WalletError = WalletAdminError;
pub type WalletAdminErrorKind = WalletAdminError;

impl WalletAdminError {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Uninitialized => "wallet_uninitialized",
            Self::Locked => "wallet_locked",
            Self::InvalidMnemonic => "invalid_mnemonic",
            Self::WrongPassword => "wrong_password",
            Self::RestorePruningUnsupported => "wallet_restore_pruning_unsupported",
            Self::ChangeAddressUntracked => "change_address_untracked",
            Self::BadRequest(_) => "bad_request",
            Self::StaleChainTip(_) => "stale_chain_tip",
            Self::Internal(_) => "internal",
            Self::Forbidden(_) => "forbidden",
            Self::WalletExists => "wallet_exists",
            Self::DerivationPathExists => "derivation_path_exists",
            Self::AddressNotTracked => "address_not_found",
            Self::RescanUnavailable(_) => "rescan_unavailable",
            Self::SensitiveOpDisabled => "sensitive_op_disabled",
            Self::AcknowledgementRequired => "acknowledgement_required",
            Self::RateLimited => "rate_limited",
            Self::BoxNotFound => "box_not_found",
            Self::UnsupportedScript => "unsupported_script",
            Self::MissingSecret => "missing_secret",
            Self::UnsupportedIntent => "unsupported_intent",
            Self::ReemissionObligationUnmet(_) => "reemission_obligation_unmet",
            Self::InsufficientFunds(_) => "insufficient_funds",
            Self::ReemissionSpendNotAllowed(_) => "reemission_spend_not_allowed",
            Self::TokenBurnNotAllowed(_) => "token_burn_not_allowed",
            Self::TxNotFound => "tx_not_found",
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::BadRequest(d)
            | Self::StaleChainTip(d)
            | Self::Internal(d)
            | Self::Forbidden(d)
            | Self::RescanUnavailable(d)
            | Self::ReemissionObligationUnmet(d)
            | Self::InsufficientFunds(d)
            | Self::ReemissionSpendNotAllowed(d)
            | Self::TokenBurnNotAllowed(d) => Some(d),
            _ => None,
        }
    }
}

impl fmt::Display for WalletAdminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uninitialized => f.write_str("wallet uninitialized"),
            Self::Locked => f.write_str("wallet locked"),
            Self::InvalidMnemonic => f.write_str("invalid mnemonic"),
            Self::WrongPassword => f.write_str("wrong password"),
            Self::RestorePruningUnsupported => f.write_str("pruning unsupported for restore"),
            Self::ChangeAddressUntracked => f.write_str("change address untracked"),
            Self::BadRequest(value) => write!(f, "bad request: {value}"),
            Self::StaleChainTip(value) => write!(f, "stale chain tip: {value}"),
            Self::Internal(value) => write!(f, "internal: {value}"),
            Self::Forbidden(value) => write!(f, "forbidden: {value}"),
            Self::WalletExists => f.write_str("wallet already exists"),
            Self::DerivationPathExists => f.write_str("derivation path already exists"),
            Self::AddressNotTracked => f.write_str("address not tracked"),
            Self::RescanUnavailable(value) => write!(f, "rescan unavailable: {value}"),
            Self::SensitiveOpDisabled => f.write_str("sensitive operation disabled"),
            Self::AcknowledgementRequired => f.write_str("acknowledgement required"),
            Self::RateLimited => f.write_str("rate limited"),
            Self::BoxNotFound => f.write_str("box not found"),
            Self::UnsupportedScript => f.write_str("unsupported script"),
            Self::MissingSecret => f.write_str("missing secret"),
            Self::UnsupportedIntent => f.write_str("unsupported intent"),
            Self::ReemissionObligationUnmet(value) => {
                write!(f, "re-emission obligation unmet: {value}")
            }
            Self::InsufficientFunds(value) => write!(f, "insufficient funds: {value}"),
            Self::ReemissionSpendNotAllowed(value) => {
                write!(f, "re-emission spend not allowed: {value}")
            }
            Self::TokenBurnNotAllowed(value) => write!(f, "token burn not allowed: {value}"),
            Self::TxNotFound => f.write_str("transaction not found"),
        }
    }
}

impl std::error::Error for WalletAdminError {}
