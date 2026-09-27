use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletStoreError {
    #[error("wallet store database error: {0}")]
    Database(#[source] Box<redb::Error>),
    #[error("wallet store decode error: {0}")]
    Decode(String),
}

impl WalletStoreError {
    pub fn decode(message: impl Into<String>) -> Self {
        Self::Decode(message.into())
    }
}

impl From<redb::Error> for WalletStoreError {
    fn from(error: redb::Error) -> Self {
        Self::Database(Box::new(error))
    }
}

impl From<WalletStoreError> for redb::Error {
    fn from(error: WalletStoreError) -> Self {
        match error {
            WalletStoreError::Database(error) => *error,
            WalletStoreError::Decode(message) => redb::Error::Io(std::io::Error::other(message)),
        }
    }
}

macro_rules! impl_wallet_store_error_from {
    ($($error:ty),+ $(,)?) => {
        $(
            impl From<$error> for WalletStoreError {
                fn from(error: $error) -> Self {
                    Self::Database(Box::new(error.into()))
                }
            }
        )+
    };
}

impl_wallet_store_error_from!(
    redb::StorageError,
    redb::TableError,
    redb::DatabaseError,
    redb::TransactionError,
    redb::CommitError,
);
