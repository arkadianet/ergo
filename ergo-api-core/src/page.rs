use std::num::NonZeroU32;

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("cursor is empty or exceeds the maximum length")]
pub struct CursorError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor(String);

impl Cursor {
    pub fn new(value: impl Into<String>) -> Result<Self, CursorError> {
        let value = value.into();
        if value.is_empty() || value.len() > 1024 {
            return Err(CursorError);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("page limit must be greater than zero")]
pub struct PageLimitError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageRequest {
    limit: NonZeroU32,
    cursor: Option<Cursor>,
}

impl PageRequest {
    pub fn new(limit: u32, cursor: Option<Cursor>) -> Result<Self, PageLimitError> {
        Ok(Self {
            limit: NonZeroU32::new(limit).ok_or(PageLimitError)?,
            cursor,
        })
    }

    pub fn limit(&self) -> u32 {
        self.limit.get()
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SnapshotRevision(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<Cursor>,
    pub total: Option<u64>,
    pub as_of: Option<SnapshotRevision>,
}

impl<T> Page<T> {
    pub fn new(
        items: Vec<T>,
        next_cursor: Option<Cursor>,
        total: Option<u64>,
        as_of: Option<SnapshotRevision>,
    ) -> Self {
        Self {
            items,
            next_cursor,
            total,
            as_of,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_request_rejects_zero_limit() {
        assert!(PageRequest::new(0, None).is_err());
    }

    #[test]
    fn cursor_rejects_empty_and_oversized_values() {
        assert!(Cursor::new("").is_err());
        assert!(Cursor::new("x".repeat(1025)).is_err());
    }
}
