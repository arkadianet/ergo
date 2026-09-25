pub mod chain;
pub mod error;
pub mod native;
pub mod scala;

pub use chain::*;
pub use error::{WalletAdminError, WalletAdminErrorKind, WalletError};
pub use native::dto;
pub use native::dto::*;
pub use native::error::NativeWalletError;

pub mod wallet {
    pub mod chain {
        pub use crate::chain::*;
    }
    pub mod native {
        pub use crate::native::*;
    }
    pub mod scala {
        pub use crate::scala::*;
    }
}
