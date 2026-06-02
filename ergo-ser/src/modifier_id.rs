//! Block-section modifier IDs.
//!
//! Per the Ergo P2P protocol spec Section 9 (and Scala
//! `NonHeaderBlockSection.computeIdBytes`), every non-header block
//! section is identified by a 32-byte modifier ID derived from:
//!
//! ```text
//! section_id = blake2b256(type_id_byte || header_id[32] || section_digest[32])
//! ```
//!
//! The 65-byte preimage is fixed-layout and must agree byte-for-byte
//! with Scala — any drift here means peers reject our
//! `RequestModifier` answers and we reject theirs.
//!
//! The protocol-level identity (type constants, hash recipe,
//! `ExpectedSections` projection over a header's three roots) lives
//! here in `ergo-ser` so that every consumer — validation, state,
//! mining, sync, p2p — can derive section IDs without depending on
//! the P2P transport crate. The runtime aggregator that tracks which
//! sections have arrived per pending header (`AssemblyTracker`) is a
//! P2P concern and stays in `ergo-p2p/src/assembly.rs`.

use ergo_primitives::digest::blake2b256;

/// Modifier type IDs for block sections [protocol].
pub const TYPE_HEADER: u8 = 101;
pub const TYPE_BLOCK_TRANSACTIONS: u8 = 102;
pub const TYPE_AD_PROOFS: u8 = 104;
pub const TYPE_EXTENSION: u8 = 108;

/// Compute a non-header block section's modifier ID.
///
/// `section_id = blake2b256(type_id_byte || header_id_bytes || section_digest)`
///
/// Matches Scala `NonHeaderBlockSection.computeIdBytes`. The
/// blake2b256 hash is applied to the concatenation of (type_id,
/// header_id, digest).
pub fn compute_section_id(
    type_id: u8,
    header_id: &[u8; 32],
    section_digest: &[u8; 32],
) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(1 + 32 + 32);
    preimage.push(type_id);
    preimage.extend_from_slice(header_id);
    preimage.extend_from_slice(section_digest);
    *blake2b256(&preimage).as_bytes()
}

/// Expected section IDs for a header (computed from header fields).
#[derive(Debug, Clone)]
pub struct ExpectedSections {
    pub header_id: [u8; 32],
    pub transactions_id: [u8; 32],
    pub extension_id: [u8; 32],
    /// ADProofs ID (only needed in digest mode, but computed for completeness).
    pub ad_proofs_id: [u8; 32],
}

impl ExpectedSections {
    /// Compute expected section IDs from header fields.
    pub fn from_header(
        header_id: &[u8; 32],
        transactions_root: &[u8; 32],
        extension_root: &[u8; 32],
        ad_proofs_root: &[u8; 32],
    ) -> Self {
        Self {
            header_id: *header_id,
            transactions_id: compute_section_id(
                TYPE_BLOCK_TRANSACTIONS,
                header_id,
                transactions_root,
            ),
            extension_id: compute_section_id(TYPE_EXTENSION, header_id, extension_root),
            ad_proofs_id: compute_section_id(TYPE_AD_PROOFS, header_id, ad_proofs_root),
        }
    }

    /// Section IDs required for a full block in UTXO mode.
    pub fn required_for_utxo_mode(&self) -> [&[u8; 32]; 2] {
        [&self.transactions_id, &self.extension_id]
    }

    /// All section IDs (for digest mode).
    pub fn all_section_ids(&self) -> [&[u8; 32]; 3] {
        [
            &self.transactions_id,
            &self.extension_id,
            &self.ad_proofs_id,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn mk(v: u8) -> [u8; 32] {
        [v; 32]
    }

    fn unhex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            let hi = u8::from_str_radix(&s[i * 2..i * 2 + 1], 16).unwrap();
            let lo = u8::from_str_radix(&s[i * 2 + 1..i * 2 + 2], 16).unwrap();
            out[i] = (hi << 4) | lo;
        }
        out
    }

    fn enhex(bytes: &[u8; 32]) -> String {
        let mut s = String::with_capacity(64);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // ----- happy path -----

    #[test]
    fn compute_section_id_deterministic_and_type_distinct() {
        let header_id = mk(1);
        let tx_root = mk(2);
        let id1 = compute_section_id(TYPE_BLOCK_TRANSACTIONS, &header_id, &tx_root);
        let id2 = compute_section_id(TYPE_BLOCK_TRANSACTIONS, &header_id, &tx_root);
        assert_eq!(id1, id2);
        let id3 = compute_section_id(TYPE_EXTENSION, &header_id, &tx_root);
        assert_ne!(id1, id3, "different type byte must produce different ID");
    }

    #[test]
    fn expected_sections_from_header_derives_all_three_ids() {
        let header_id = mk(0x10);
        let tx_root = mk(0x20);
        let ext_root = mk(0x30);
        let ad_proofs_root = mk(0x40);
        let exp = ExpectedSections::from_header(&header_id, &tx_root, &ext_root, &ad_proofs_root);
        assert_eq!(exp.header_id, header_id);
        assert_eq!(
            exp.transactions_id,
            compute_section_id(TYPE_BLOCK_TRANSACTIONS, &header_id, &tx_root),
        );
        assert_eq!(
            exp.extension_id,
            compute_section_id(TYPE_EXTENSION, &header_id, &ext_root),
        );
        assert_eq!(
            exp.ad_proofs_id,
            compute_section_id(TYPE_AD_PROOFS, &header_id, &ad_proofs_root),
        );
        // UTXO mode requires (tx, ext); digest mode includes ad-proofs.
        assert_eq!(
            exp.required_for_utxo_mode(),
            [&exp.transactions_id, &exp.extension_id],
        );
        assert_eq!(
            exp.all_section_ids(),
            [&exp.transactions_id, &exp.extension_id, &exp.ad_proofs_id],
        );
    }

    // ----- oracle parity -----

    /// Scala-oracle parity check for `compute_section_id`. Vectors
    /// captured from a Scala mainnet node at height 1,775,616 via
    /// `GET /blocks/at/1775616` → `GET /blocks/{header_id}`. This pins
    /// the hash + byte-order rule against real Scala bytes — the
    /// precondition for peers responding to our `RequestModifier`.
    #[test]
    fn compute_section_id_matches_scala_mainnet_oracle_at_1775616() {
        let header_id = unhex("920b804116315b59b6ba37787a3211b14247154d68261c70ac20da2c7aba8a82");
        let tx_root = unhex("0eb34d61063a1da0cef6ade29ccb02449bd555dd2ab5a4db3bcc08060d9c1dc9");
        let expected_tx_id =
            unhex("72a6664991262d4b3dc948a48dd8cd97447a29261dd7a1c725dfc992d1423103");

        let computed = compute_section_id(TYPE_BLOCK_TRANSACTIONS, &header_id, &tx_root);
        assert_eq!(
            enhex(&computed),
            enhex(&expected_tx_id),
            "BlockTransactions modifier_id must match Scala oracle at mainnet height 1,775,616",
        );
    }

    #[test]
    fn compute_section_id_matches_scala_ad_proofs_oracle_at_1775616() {
        let header_id = unhex("920b804116315b59b6ba37787a3211b14247154d68261c70ac20da2c7aba8a82");
        let ad_proofs_root =
            unhex("ab8ce33d0517e0a015a5986a48ad32232d3190116796557c6233df9318fea721");
        let expected_ad_id =
            unhex("6630ec4ef02cd9d9a39810de1e671478fb2e11c5aa5b714b49f259119a3e7b04");

        let computed = compute_section_id(TYPE_AD_PROOFS, &header_id, &ad_proofs_root);
        assert_eq!(
            enhex(&computed),
            enhex(&expected_ad_id),
            "ADProofs modifier_id must match Scala oracle at mainnet height 1,775,616",
        );
    }
}
