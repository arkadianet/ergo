use serde::Deserialize;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkType {
    MainNet,
    TestNet,
    DevNet,
}

impl FromStr for NetworkType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mainnet" => Ok(Self::MainNet),
            "testnet" => Ok(Self::TestNet),
            "devnet" => Ok(Self::DevNet),
            _ => Err(format!("unknown network type: {s}")),
        }
    }
}

impl NetworkType {
    /// Network address prefix byte (0 = mainnet, 16 = testnet, 32 = devnet)
    pub fn address_prefix(self) -> u8 {
        match self {
            Self::MainNet => 0,
            Self::TestNet => 16,
            Self::DevNet => 32,
        }
    }

    /// P2P magic bytes identifying the network
    pub fn magic_bytes(self) -> [u8; 4] {
        match self {
            Self::MainNet => [1, 0, 2, 4],
            Self::TestNet => [2, 0, 2, 3],
            Self::DevNet => [2, 2, 2, 2],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mainnet() {
        assert_eq!(NetworkType::from_str("mainnet"), Ok(NetworkType::MainNet));
    }

    #[test]
    fn parse_testnet() {
        assert_eq!(NetworkType::from_str("testnet"), Ok(NetworkType::TestNet));
    }

    #[test]
    fn parse_devnet() {
        assert_eq!(NetworkType::from_str("devnet"), Ok(NetworkType::DevNet));
    }

    #[test]
    fn mainnet_address_prefix() {
        assert_eq!(NetworkType::MainNet.address_prefix(), 0);
    }

    #[test]
    fn testnet_address_prefix() {
        assert_eq!(NetworkType::TestNet.address_prefix(), 16);
    }

    #[test]
    fn magic_bytes_mainnet() {
        assert_eq!(NetworkType::MainNet.magic_bytes(), [1, 0, 2, 4]);
    }

    #[test]
    fn magic_bytes_testnet() {
        assert_eq!(NetworkType::TestNet.magic_bytes(), [2, 0, 2, 3]);
    }
}
