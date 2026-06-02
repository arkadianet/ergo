//! Pubkey → P2PK address helper. Thin wrapper over
//! `ergo_ser::address::encode_p2pk_from_pubkey` — keeps the wallet's
//! public API self-contained without re-implementing the address
//! codec. We additionally validate the input bytes are a valid
//! SEC1-compressed secp256k1 point before encoding, so off-curve
//! bytes can't slip through and produce unspendable P2PK addresses.
//!
//! **Note**: we deliberately do NOT route through
//! `ergo_sigma::schnorr::build_prove_dlog_ergo_tree`, which builds
//! a **segregated-constants** ErgoTree (header 0x10 + constant
//! placeholder body); that shape would fail `encode_address`'s
//! P2PK detection and silently encode P2S, which is unspendable by
//! every other Ergo wallet. The direct `encode_p2pk_from_pubkey`
//! helper at `ergo-ser/src/address.rs:275` is the correct path.

use crate::error::WalletError;
use ergo_ser::address::{encode_p2pk_from_pubkey, NetworkPrefix};

/// Render a 33-byte compressed pubkey as a base58 P2PK address.
pub fn pubkey_to_p2pk_address(
    pubkey_bytes: &[u8; 33],
    network: NetworkPrefix,
) -> Result<String, WalletError> {
    // Validate the input is a real SEC1-compressed secp256k1 point
    // before encoding. Without this, arbitrary 33-byte hex passed to
    // `address --pubkey <hex>` would produce a "plausible-looking"
    // P2PK address from off-curve bytes — funds sent there would be
    // permanently unspendable. The `encode_p2pk_from_pubkey` helper
    // in `ergo-ser` only checks length, not curve membership.
    k256::PublicKey::from_sec1_bytes(pubkey_bytes).map_err(|_| {
        WalletError::InvalidPublicKey("not a valid SEC1-compressed secp256k1 point".to_string())
    })?;
    encode_p2pk_from_pubkey(network, pubkey_bytes)
        .map_err(|e| WalletError::InvalidPublicKey(format!("p2pk encode failed: {e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn known_mnemonic_yields_p2pk_address_starting_with_9_on_mainnet() {
        // Mainnet P2PK addresses base58-encode to a string starting with '9'.
        // Any HD pubkey we derive from a known mnemonic must produce
        // an address with this prefix.
        // Full module paths — re-exports land in Task 38, not earlier.
        use crate::derivation::DerivationPath;
        use crate::extended_key::ExtendedSecretKey;
        use crate::mnemonic::Mnemonic;

        let m = Mnemonic::import(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let seed = m.to_seed("");
        let master = ExtendedSecretKey::derive_master_key(&seed, false).unwrap();
        let leaf = master
            .derive_at_path(&DerivationPath::eip3_first_address())
            .unwrap();
        let pk = leaf.public_key().compressed_bytes();

        let addr =
            pubkey_to_p2pk_address(&pk, NetworkPrefix::Mainnet).expect("p2pk render must succeed");
        assert!(
            addr.starts_with('9'),
            "mainnet P2PK address must start with '9', got {addr:?}",
        );
    }

    // ----- error paths -----

    #[test]
    fn invalid_curve_point_rejected() {
        // All-zero compressed pubkey: leading 0x00 isn't a valid SEC1
        // marker (must be 02 or 03), so k256::PublicKey::from_sec1_bytes
        // rejects it. Without our curve check, the encoder would
        // happily produce a P2PK address from these bytes.
        let zero_pk = [0u8; 33];
        let err = pubkey_to_p2pk_address(&zero_pk, NetworkPrefix::Mainnet)
            .expect_err("off-curve bytes must reject");
        assert!(
            matches!(err, WalletError::InvalidPublicKey(_)),
            "expected InvalidPublicKey, got {err:?}",
        );
    }

    #[test]
    fn valid_curve_point_accepted() {
        // BIP32 Vector 1 master pubkey (compressed) — known-valid.
        let bip32_v1_master_pk: [u8; 33] =
            hex::decode("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
                .unwrap()
                .try_into()
                .unwrap();
        let addr = pubkey_to_p2pk_address(&bip32_v1_master_pk, NetworkPrefix::Mainnet)
            .expect("known-valid pubkey must encode");
        assert!(addr.starts_with('9'), "mainnet P2PK starts with 9");
    }
}
