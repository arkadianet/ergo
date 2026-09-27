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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletErrorSurface {
    Scala,
    NativeV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletErrorStatus {
    pub status: u16,
    pub reason: &'static str,
    pub detail: Option<String>,
}

impl WalletErrorStatus {
    pub fn status_code(&self) -> u16 {
        self.status
    }
}

impl WalletErrorSurface {
    pub const SCALA_COMPATIBLE: Self = Self::Scala;
    pub const NATIVE_V1: Self = Self::NativeV1;

    pub fn map(&self, error: &WalletAdminError) -> WalletErrorStatus {
        let reason = match self {
            Self::Scala => match error {
                WalletAdminError::Uninitialized => "wallet_uninitialized",
                WalletAdminError::Locked => "wallet_locked",
                WalletAdminError::InvalidMnemonic => "invalid_mnemonic",
                WalletAdminError::WrongPassword => "wrong_password",
                WalletAdminError::RestorePruningUnsupported => "wallet_restore_pruning_unsupported",
                WalletAdminError::ChangeAddressUntracked => "change_address_untracked",
                WalletAdminError::BadRequest(_) => "bad_request",
                WalletAdminError::StaleChainTip(_) => "stale_chain_tip",
                WalletAdminError::Internal(_) => "internal",
                WalletAdminError::Forbidden(_) => "forbidden",
                WalletAdminError::WalletExists => "wallet_exists",
                WalletAdminError::DerivationPathExists => "derivation_path_exists",
                WalletAdminError::AddressNotTracked => "address_not_found",
                WalletAdminError::RescanUnavailable(_) => "rescan_unavailable",
                WalletAdminError::SensitiveOpDisabled => "sensitive_op_disabled",
                WalletAdminError::AcknowledgementRequired => "acknowledgement_required",
                WalletAdminError::RateLimited => "rate_limited",
                WalletAdminError::BoxNotFound => "box_not_found",
                WalletAdminError::UnsupportedScript => "unsupported_script",
                WalletAdminError::MissingSecret => "missing_secret",
                WalletAdminError::UnsupportedIntent => "unsupported_intent",
                WalletAdminError::ReemissionObligationUnmet(_) => "reemission_obligation_unmet",
                WalletAdminError::InsufficientFunds(_) => "insufficient_funds",
                WalletAdminError::ReemissionSpendNotAllowed(_) => "reemission_spend_not_allowed",
                WalletAdminError::TokenBurnNotAllowed(_) => "token_burn_not_allowed",
                WalletAdminError::TxNotFound => "tx_not_found",
            },
            Self::NativeV1 => match error {
                WalletAdminError::Uninitialized => "wallet_uninitialized",
                WalletAdminError::Locked => "wallet_locked",
                WalletAdminError::InvalidMnemonic => "invalid_mnemonic",
                WalletAdminError::WrongPassword => "wrong_password",
                WalletAdminError::RestorePruningUnsupported => "pruning_unsupported",
                WalletAdminError::ChangeAddressUntracked => "change_address_untracked",
                WalletAdminError::BadRequest(_) => "bad_request",
                WalletAdminError::StaleChainTip(_) => "stale_chain_tip",
                WalletAdminError::Internal(_) => "internal",
                WalletAdminError::Forbidden(_) => "sensitive_op_disabled",
                WalletAdminError::WalletExists => "wallet_exists",
                WalletAdminError::DerivationPathExists => "derivation_path_exists",
                WalletAdminError::AddressNotTracked => "address_not_found",
                WalletAdminError::RescanUnavailable(_) => "rescan_unavailable",
                WalletAdminError::SensitiveOpDisabled => "sensitive_op_disabled",
                WalletAdminError::AcknowledgementRequired => "acknowledgement_required",
                WalletAdminError::RateLimited => "rate_limited",
                WalletAdminError::BoxNotFound => "box_not_found",
                WalletAdminError::UnsupportedScript => "unsupported_script",
                WalletAdminError::MissingSecret => "missing_secret",
                WalletAdminError::UnsupportedIntent => "unsupported_intent",
                WalletAdminError::ReemissionObligationUnmet(_) => "reemission_obligation_unmet",
                WalletAdminError::InsufficientFunds(_) => "insufficient_funds",
                WalletAdminError::ReemissionSpendNotAllowed(_) => "reemission_spend_not_allowed",
                WalletAdminError::TokenBurnNotAllowed(_) => "token_burn_not_allowed",
                WalletAdminError::TxNotFound => "tx_not_found",
            },
        };
        let detail = match (self, error) {
            (Self::Scala, _) => error.detail().map(ToOwned::to_owned),
            (Self::NativeV1, WalletAdminError::Forbidden(_)) => None,
            (Self::NativeV1, _) => error.detail().map(ToOwned::to_owned),
        };
        let status = match self {
            Self::Scala => match error {
                WalletAdminError::WrongPassword => 401,
                WalletAdminError::StaleChainTip(_) | WalletAdminError::RescanUnavailable(_) => 409,
                WalletAdminError::Internal(_) => 500,
                WalletAdminError::Forbidden(_) | WalletAdminError::SensitiveOpDisabled => 403,
                WalletAdminError::AddressNotTracked
                | WalletAdminError::BoxNotFound
                | WalletAdminError::TxNotFound => 404,
                WalletAdminError::RateLimited => 429,
                WalletAdminError::UnsupportedScript
                | WalletAdminError::MissingSecret
                | WalletAdminError::UnsupportedIntent
                | WalletAdminError::ReemissionObligationUnmet(_)
                | WalletAdminError::InsufficientFunds(_)
                | WalletAdminError::ReemissionSpendNotAllowed(_)
                | WalletAdminError::TokenBurnNotAllowed(_) => 422,
                _ => 400,
            },
            Self::NativeV1 => match error {
                WalletAdminError::Uninitialized
                | WalletAdminError::Locked
                | WalletAdminError::RestorePruningUnsupported
                | WalletAdminError::StaleChainTip(_)
                | WalletAdminError::RescanUnavailable(_)
                | WalletAdminError::WalletExists
                | WalletAdminError::DerivationPathExists => 409,
                WalletAdminError::WrongPassword => 401,
                WalletAdminError::Internal(_) => 500,
                WalletAdminError::Forbidden(_) | WalletAdminError::SensitiveOpDisabled => 403,
                WalletAdminError::AddressNotTracked
                | WalletAdminError::BoxNotFound
                | WalletAdminError::TxNotFound => 404,
                WalletAdminError::RateLimited => 429,
                WalletAdminError::ChangeAddressUntracked
                | WalletAdminError::UnsupportedScript
                | WalletAdminError::MissingSecret
                | WalletAdminError::UnsupportedIntent
                | WalletAdminError::ReemissionObligationUnmet(_)
                | WalletAdminError::InsufficientFunds(_)
                | WalletAdminError::ReemissionSpendNotAllowed(_)
                | WalletAdminError::TokenBurnNotAllowed(_) => 422,
                _ => 400,
            },
        };
        WalletErrorStatus {
            status,
            reason,
            detail,
        }
    }

    pub fn status(&self, error: &WalletAdminError) -> u16 {
        self.map(error).status
    }

    pub fn reason(&self, error: &WalletAdminError) -> &'static str {
        self.map(error).reason
    }

    pub fn detail(&self, error: &WalletAdminError) -> Option<String> {
        self.map(error).detail
    }

    pub fn scala(error: &WalletAdminError) -> WalletErrorStatus {
        Self::Scala.map(error)
    }

    pub fn native_v1(error: &WalletAdminError) -> WalletErrorStatus {
        Self::NativeV1.map(error)
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surfaces_preserve_their_different_statuses_and_reasons() {
        let error = WalletAdminError::Locked;
        assert_eq!(WalletErrorSurface::Scala.status(&error), 400);
        assert_eq!(WalletErrorSurface::NativeV1.status(&error), 409);
        let restore = WalletAdminError::RestorePruningUnsupported;
        assert_eq!(
            WalletErrorSurface::Scala.reason(&restore),
            "wallet_restore_pruning_unsupported"
        );
        assert_eq!(
            WalletErrorSurface::NativeV1.reason(&restore),
            "pruning_unsupported"
        );
    }

    #[test]
    fn native_mapping_owns_detail_without_forbidden_internal_text() {
        let error = WalletAdminError::Internal("db".to_string());
        let mapped = WalletErrorSurface::NativeV1.map(&error);
        assert_eq!(mapped.status, 500);
        assert_eq!(mapped.detail.as_deref(), Some("db"));
        let forbidden = WalletAdminError::Forbidden("private".to_string());
        assert!(WalletErrorSurface::NativeV1
            .map(&forbidden)
            .detail
            .is_none());
    }
}
