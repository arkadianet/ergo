use std::time::Duration;

use ergo_api_core::error::{ServiceError, ServiceResult};

use super::NativeState;

pub const MAX_PAGE_SIZE: u32 = 1_000;
pub const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_COMPUTE_CONCURRENCY: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub default_page_size: u32,
    pub max_page_size: u32,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub request_timeout: Duration,
    pub compute_concurrency: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            default_page_size: 50,
            max_page_size: 500,
            max_request_bytes: 2 * 1024 * 1024,
            max_response_bytes: 8 * 1024 * 1024,
            request_timeout: Duration::from_secs(15),
            compute_concurrency: 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeConfigError {
    ZeroPageSize,
    DefaultPageTooLarge,
    PageSizeLimit,
    ZeroByteLimit,
    RequestByteLimit,
    ResponseByteLimit,
    ZeroTimeout,
    ZeroConcurrency,
    ConcurrencyLimit,
}

impl std::fmt::Display for RuntimeConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroPageSize => f.write_str("default page size must be greater than zero"),
            Self::DefaultPageTooLarge => {
                f.write_str("default page size must not exceed max page size")
            }
            Self::PageSizeLimit => f.write_str("max page size exceeds the hard limit"),
            Self::ZeroByteLimit => {
                f.write_str("request and response limits must be greater than zero")
            }
            Self::RequestByteLimit => f.write_str("request byte limit exceeds the hard limit"),
            Self::ResponseByteLimit => f.write_str("response byte limit exceeds the hard limit"),
            Self::ZeroTimeout => f.write_str("request timeout must be greater than zero"),
            Self::ZeroConcurrency => f.write_str("compute concurrency must be greater than zero"),
            Self::ConcurrencyLimit => f.write_str("compute concurrency exceeds the hard limit"),
        }
    }
}

impl std::error::Error for RuntimeConfigError {}

impl RuntimeConfig {
    pub fn validate(&self) -> Result<(), RuntimeConfigError> {
        if self.default_page_size == 0 {
            return Err(RuntimeConfigError::ZeroPageSize);
        }
        if self.default_page_size > self.max_page_size {
            return Err(RuntimeConfigError::DefaultPageTooLarge);
        }
        if self.max_page_size > MAX_PAGE_SIZE {
            return Err(RuntimeConfigError::PageSizeLimit);
        }
        if self.max_request_bytes == 0 || self.max_response_bytes == 0 {
            return Err(RuntimeConfigError::ZeroByteLimit);
        }
        if self.max_request_bytes > MAX_REQUEST_BYTES {
            return Err(RuntimeConfigError::RequestByteLimit);
        }
        if self.max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(RuntimeConfigError::ResponseByteLimit);
        }
        if self.request_timeout.is_zero() {
            return Err(RuntimeConfigError::ZeroTimeout);
        }
        if self.compute_concurrency == 0 {
            return Err(RuntimeConfigError::ZeroConcurrency);
        }
        if self.compute_concurrency > MAX_COMPUTE_CONCURRENCY {
            return Err(RuntimeConfigError::ConcurrencyLimit);
        }
        Ok(())
    }
}

pub struct NativeRuntime {
    state: NativeState,
    config: RuntimeConfig,
}

impl NativeRuntime {
    #[allow(clippy::result_large_err)]
    pub fn build(state: NativeState, config: RuntimeConfig) -> ServiceResult<Self> {
        config.validate().map_err(|error| {
            ServiceError::validation("invalid_runtime_config", error.to_string())
        })?;
        let state = state.with_runtime_config(config.clone());
        Ok(Self { state, config })
    }

    pub fn state(&self) -> &NativeState {
        &self.state
    }

    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    pub fn into_parts(self) -> (NativeState, RuntimeConfig) {
        (self.state, self.config)
    }

    pub fn router(&self) -> axum::Router {
        super::router(self.state.clone())
    }
}

impl Clone for NativeRuntime {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            config: self.config.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_runtime_config_is_valid() {
        assert!(RuntimeConfig::default().validate().is_ok());
    }

    #[test]
    fn runtime_config_rejects_invalid_limits() {
        let config = RuntimeConfig {
            max_page_size: 0,
            ..RuntimeConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(RuntimeConfigError::DefaultPageTooLarge)
        );

        let config = RuntimeConfig {
            max_page_size: MAX_PAGE_SIZE + 1,
            ..RuntimeConfig::default()
        };
        assert_eq!(config.validate(), Err(RuntimeConfigError::PageSizeLimit));
    }
}
