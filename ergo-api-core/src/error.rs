use std::borrow::Cow;
use std::fmt;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Validation,
    PayloadTooLarge,
    NotFound,
    Conflict,
    Unauthenticated,
    Forbidden,
    Unavailable,
    Overloaded,
    RateLimited,
    Timeout,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendFailure {
    operation: &'static str,
    detail: String,
}

impl BackendFailure {
    pub fn new(operation: &'static str, detail: impl Into<String>) -> Self {
        Self {
            operation,
            detail: detail.into(),
        }
    }

    pub fn operation(&self) -> &'static str {
        self.operation
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for BackendFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.operation, self.detail)
    }
}

impl std::error::Error for BackendFailure {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    kind: ErrorKind,
    code: Cow<'static, str>,
    message: Cow<'static, str>,
    detail: Option<Cow<'static, str>>,
    retry_after: Option<Duration>,
    failure: Option<BackendFailure>,
}

impl ServiceError {
    pub fn new(
        kind: ErrorKind,
        code: impl Into<Cow<'static, str>>,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            kind,
            code: code.into(),
            message: message.into(),
            detail: None,
            retry_after: None,
            failure: None,
        }
    }

    pub fn validation(
        code: impl Into<Cow<'static, str>>,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(ErrorKind::Validation, code, message)
    }

    pub fn payload_too_large(
        code: impl Into<Cow<'static, str>>,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(ErrorKind::PayloadTooLarge, code, message)
    }

    pub fn not_found(
        code: impl Into<Cow<'static, str>>,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(ErrorKind::NotFound, code, message)
    }

    pub fn unavailable(
        code: impl Into<Cow<'static, str>>,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(ErrorKind::Unavailable, code, message)
    }

    pub fn overloaded(
        code: impl Into<Cow<'static, str>>,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(ErrorKind::Overloaded, code, message)
    }

    pub fn internal(
        code: impl Into<Cow<'static, str>>,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(ErrorKind::Internal, code, message)
    }

    pub fn with_detail(mut self, detail: impl Into<Cow<'static, str>>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_retry_after(mut self, retry_after: Duration) -> Self {
        self.retry_after = Some(retry_after);
        self
    }

    pub fn with_failure(mut self, failure: BackendFailure) -> Self {
        self.failure = Some(failure);
        self
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    pub fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    pub fn failure(&self) -> Option<&BackendFailure> {
        self.failure.as_ref()
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message.as_ref())
    }
}

impl std::error::Error for ServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure
            .as_ref()
            .map(|failure| failure as &(dyn std::error::Error + 'static))
    }
}

pub type ServiceResult<T> = Result<T, ServiceError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_fields_survive_internal_failure() {
        let error = ServiceError::unavailable("store_unavailable", "chain reads are unavailable")
            .with_retry_after(Duration::from_secs(2))
            .with_failure(BackendFailure::new("read_block", "redb write failure"));
        assert_eq!(error.kind(), ErrorKind::Unavailable);
        assert_eq!(error.code(), "store_unavailable");
        assert_eq!(error.retry_after(), Some(Duration::from_secs(2)));
        assert!(error.failure().is_some());
    }
}
