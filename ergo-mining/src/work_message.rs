//! Typed work-message and solution inputs for the external-miner protocol.
//!
//! These are the consensus-bearing values `ergo-mining` works with. The JSON
//! wire shapes (`WorkMessageJson` / `AutolykosSolutionJson`) live in
//! `ergo-rest-json` and are marshalled to/from these types at the node's
//! mining bridge, so this crate carries no JSON / presentation dependency.

use num_bigint::BigUint;

use crate::error::MiningError;

/// Work message handed to an external miner: everything needed to mine an
/// Autolykos v2 solution against the current candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkMessage {
    /// Blake2b256 of `serialize_header_without_pow(header)` — the message the
    /// miner hashes with their nonce to compute the Autolykos v2 hit.
    pub msg: [u8; 32],
    /// Mining target; a solution's hit must be `<= target`.
    pub target: BigUint,
    /// Candidate block height.
    pub height: u32,
    /// Compressed secp256k1 miner pubkey the candidate was built for.
    pub pk: [u8; 33],
}

/// Autolykos v2 solution posted by an external miner, decoded to typed form.
/// `pk == None` means "use the candidate's miner pubkey" — Scala's
/// inject-miner-pk-on-accept path (`CandidateGenerator.scala:202-207`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinerSolution {
    /// 8-byte nonce.
    pub nonce: [u8; 8],
    /// Optional miner-pubkey override.
    pub pk: Option<[u8; 33]>,
}

impl MinerSolution {
    /// Decode a solution from its hex-encoded wire fields (`n` nonce, optional
    /// `pk`). The node's mining bridge feeds the strings out of the inbound
    /// `AutolykosSolutionJson`; keeping the decode here lets `ergo-mining` own
    /// the field/length error semantics while staying free of the JSON DTOs.
    pub fn from_hex(n: &str, pk: Option<&str>) -> Result<Self, MiningError> {
        let nonce_bytes = hex::decode(n).map_err(|source| MiningError::HexDecode {
            field: "nonce",
            source,
        })?;
        let nonce: [u8; 8] =
            nonce_bytes
                .as_slice()
                .try_into()
                .map_err(|_| MiningError::WrongLength {
                    field: "nonce",
                    expected: 8,
                    got: nonce_bytes.len(),
                })?;
        let pk = match pk {
            Some(pk_hex) => {
                let raw = hex::decode(pk_hex).map_err(|source| MiningError::HexDecode {
                    field: "pk",
                    source,
                })?;
                Some(
                    raw.as_slice()
                        .try_into()
                        .map_err(|_| MiningError::WrongLength {
                            field: "pk",
                            expected: 33,
                            got: raw.len(),
                        })?,
                )
            }
            None => None,
        };
        Ok(Self { nonce, pk })
    }
}
