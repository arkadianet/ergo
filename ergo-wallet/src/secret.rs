//! `SecretKey` enum — the kinds of secrets the wallet can hold.
//!
//! Currently only `Dlog` (discrete log on secp256k1, i.e. the standard
//! P2PK secret) is implemented. `Dht` (Diffie-Hellman tuple, used for
//! oracle/DEX contracts) is not yet supported.

use crate::extended_key::ExtendedSecretKey;

/// Secret material the wallet holds. The variant determines which
/// sigma-protocol proof can be produced.
#[derive(Debug, Clone)]
pub enum SecretKey {
    /// Schnorr-style secret: x such that P = G*x. Backs `P2PK(ProveDlog(P))`.
    Dlog(ExtendedSecretKey),
    // Dht { ... } can be added when DHT-secret signing is implemented.
}

impl SecretKey {
    /// Extract the corresponding compressed SEC1 pubkey (33 bytes).
    pub fn public_key_bytes(&self) -> [u8; 33] {
        match self {
            Self::Dlog(xsk) => xsk.public_key().compressed_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derivation::DerivationPath;
    use crate::mnemonic::Mnemonic;
    // Use full module paths instead of root re-exports: these types
    // are not yet re-exported from the crate root.

    #[test]
    fn dlog_secret_yields_compressed_pubkey() {
        let m = Mnemonic::import(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let seed = m.to_seed("");
        let master = ExtendedSecretKey::derive_master_key(&seed, false).unwrap();
        let path = DerivationPath::eip3_first_address();
        let leaf = master.derive_at_path(&path).unwrap();
        let sk = SecretKey::Dlog(leaf);

        let pk_bytes = sk.public_key_bytes();
        // Sanity: 33-byte compressed key starts with 02 or 03.
        assert!(
            pk_bytes[0] == 0x02 || pk_bytes[0] == 0x03,
            "compressed pubkey first byte must be 02 or 03 (got {:#04x})",
            pk_bytes[0],
        );
    }
}
