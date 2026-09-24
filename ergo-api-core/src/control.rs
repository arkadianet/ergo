use std::collections::BTreeMap;
use std::net::SocketAddr;

use crate::error::{ServiceError, ServiceResult};

pub trait ShutdownControl: Send + Sync + 'static {
    fn request_shutdown(&self);
}

#[allow(clippy::result_large_err)]
pub trait PeerDialer: Send + Sync + 'static {
    fn request_dial(&self, address: SocketAddr) -> ServiceResult<()>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VotingError {
    #[error("mining is disabled")]
    MiningDisabled,
    #[error("parameter {parameter_id} is not votable")]
    NotVotable { parameter_id: u8 },
    #[error("parameter {parameter_id} target {target} is outside [{min}, {max}]")]
    OutOfRange {
        parameter_id: u8,
        target: i64,
        min: i64,
        max: i64,
    },
    #[error("voting control is unavailable")]
    Unavailable,
    #[error("voting update failed: {0}")]
    Internal(String),
}

impl From<VotingError> for ServiceError {
    fn from(error: VotingError) -> Self {
        match error {
            VotingError::MiningDisabled => Self::conflict("mining_disabled", error.to_string()),
            VotingError::NotVotable { parameter_id } => {
                Self::validation("parameter_not_votable", error.to_string())
                    .with_detail(format!("parameter_id={parameter_id}"))
            }
            VotingError::OutOfRange {
                parameter_id,
                target,
                min,
                max,
            } => Self::validation("voting_target_out_of_range", error.to_string()).with_detail(
                format!("parameter_id={parameter_id};target={target};min={min};max={max}"),
            ),
            VotingError::Unavailable => Self::unavailable("voting_unavailable", error.to_string()),
            VotingError::Internal(detail) => Self::new(
                crate::error::ErrorKind::Internal,
                "voting_update_failed",
                "voting preferences could not be updated",
            )
            .with_detail(detail),
        }
    }
}

pub trait VotingControl: Send + Sync + 'static {
    fn replace_targets(&self, targets: BTreeMap<u8, i64>) -> Result<(), VotingError>;
}

impl ServiceError {
    fn conflict(
        code: impl Into<std::borrow::Cow<'static, str>>,
        message: impl Into<std::borrow::Cow<'static, str>>,
    ) -> Self {
        Self::new(crate::error::ErrorKind::Conflict, code, message)
    }
}
