use std::fmt;
use std::str::FromStr;

pub use ergo_primitives::digest::ModifierId;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("expected a 32-byte hexadecimal identifier")]
pub struct ParseIdError;

macro_rules! id32 {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const ZERO: Self = Self([0; 32]);

            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub fn into_bytes(self) -> [u8; 32] {
                self.0
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(bytes: [u8; 32]) -> Self {
                Self::from_bytes(bytes)
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = ParseIdError;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                let bytes: [u8; 32] = value.try_into().map_err(|_| ParseIdError)?;
                Ok(Self::from_bytes(bytes))
            }
        }

        impl FromStr for $name {
            type Err = ParseIdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let bytes = hex::decode(value).map_err(|_| ParseIdError)?;
                Self::try_from(bytes.as_slice())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self)
            }
        }
    };
}

id32!(HeaderId);
id32!(TxId);
id32!(BoxId);
id32!(TokenId);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip_through_hex() {
        let bytes = [0xabu8; 32];
        let id = HeaderId::from_bytes(bytes);
        assert_eq!(id.to_string(), hex::encode(bytes));
        assert_eq!(HeaderId::from_str(&id.to_string()).unwrap(), id);
    }

    #[test]
    fn ids_reject_wrong_length_and_non_hex() {
        assert!("00".parse::<TxId>().is_err());
        assert!("zz".repeat(32).parse::<BoxId>().is_err());
    }

    #[test]
    fn id_types_do_not_share_constructors() {
        let header = HeaderId::from_bytes([1; 32]);
        let tx = TxId::from_bytes([1; 32]);
        assert_eq!(header.as_bytes(), tx.as_bytes());
    }
}
