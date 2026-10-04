//! `TransactionHintsBag` ↔ `TxHintsBagDto` converters.
//!
//! These live here (not in ergo-api) because ergo-api has no ergo-wallet dep.
//! The ergo-api layer uses the opaque `SigmaBooleanJson` for the `image` field;
//! here we convert to/from the canonical JSON shape used by Scala/sigma-rust:
//!   ProveDlog  → { "type": "proveDlog", "h": "<33-byte-hex>" }
//!   ProveDHTuple → { "type": "proveDhTuple", "g": "...", "h": "...", "u": "...", "v": "..." }
//!   Other      → { "type": "other" }
//!
//! For `from_dto`, the `image` field is only used to reconstruct the `SigmaBoolean`
//! for hint matching inside the prover; we parse it from the tagged JSON object.

use ergo_wallet_protocol::WalletAdminError;

/// Serialize a `SigmaBoolean` to the `SigmaBooleanJson` wire shape.
pub(crate) fn sigma_boolean_to_json(
    sb: &ergo_ser::sigma_value::SigmaBoolean,
) -> ergo_wallet_protocol::scala::sending::SigmaBooleanJson {
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet_protocol::scala::sending::SigmaBooleanJson;
    use serde_json::{json, Value};

    let inner: Value = match sb {
        SigmaBoolean::ProveDlog(ge) => json!({
            "type": "proveDlog",
            "h": hex::encode(ge.as_bytes()),
        }),
        SigmaBoolean::ProveDHTuple { g, h, u, v } => json!({
            "type": "proveDhTuple",
            "g": hex::encode(g.as_bytes()),
            "h": hex::encode(h.as_bytes()),
            "u": hex::encode(u.as_bytes()),
            "v": hex::encode(v.as_bytes()),
        }),
        SigmaBoolean::TrivialProp(b) => json!({ "type": "trivialProp", "condition": b }),
        SigmaBoolean::Cand(children) => json!({
            "type": "cand",
            "args": children.iter().map(|c| sigma_boolean_to_json(c).inner).collect::<Vec<_>>(),
        }),
        SigmaBoolean::Cor(children) => json!({
            "type": "cor",
            "args": children.iter().map(|c| sigma_boolean_to_json(c).inner).collect::<Vec<_>>(),
        }),
        SigmaBoolean::Cthreshold { k, children } => json!({
            "type": "cthreshold",
            "k": k,
            "args": children.iter().map(|c| sigma_boolean_to_json(c).inner).collect::<Vec<_>>(),
        }),
    };
    SigmaBooleanJson { inner }
}

/// Parse a `SigmaBooleanJson` back to a `SigmaBoolean`.
/// Returns `Err` for unrecognised shapes.
pub(crate) fn sigma_boolean_from_json(
    json: &ergo_wallet_protocol::scala::sending::SigmaBooleanJson,
) -> Result<ergo_ser::sigma_value::SigmaBoolean, WalletAdminError> {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;

    let obj = json.inner.as_object().ok_or_else(|| {
        WalletAdminError::Internal("SigmaBooleanJson: expected JSON object".into())
    })?;
    let typ = obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WalletAdminError::Internal("SigmaBooleanJson: missing 'type'".into()))?;

    fn decode_ge(
        obj: &serde_json::Map<String, serde_json::Value>,
        field: &str,
    ) -> Result<GroupElement, WalletAdminError> {
        let hex_str = obj.get(field).and_then(|v| v.as_str()).ok_or_else(|| {
            WalletAdminError::Internal(format!("SigmaBooleanJson: missing '{field}'"))
        })?;
        let bytes: [u8; 33] = hex::decode(hex_str)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| {
                WalletAdminError::Internal(format!("SigmaBooleanJson: bad point hex for '{field}'"))
            })?;
        Ok(GroupElement::from_bytes(bytes))
    }

    match typ {
        "proveDlog" => Ok(SigmaBoolean::ProveDlog(decode_ge(obj, "h")?)),
        "proveDhTuple" => Ok(SigmaBoolean::ProveDHTuple {
            g: decode_ge(obj, "g")?,
            h: decode_ge(obj, "h")?,
            u: decode_ge(obj, "u")?,
            v: decode_ge(obj, "v")?,
        }),
        other => Err(WalletAdminError::Internal(format!(
            "SigmaBooleanJson: unknown type '{other}'"
        ))),
    }
}

/// Serialize a `FirstProverMessage` to its `FirstProverMessageJson` wire shape.
pub(crate) fn fpm_to_json(
    fpm: &ergo_wallet::proving::hints::FirstProverMessage,
) -> ergo_wallet_protocol::scala::sending::FirstProverMessageJson {
    use ergo_wallet::proving::hints::FirstProverMessage;
    use ergo_wallet_protocol::scala::sending::FirstProverMessageJson;

    match fpm {
        FirstProverMessage::Schnorr(a) => FirstProverMessageJson::Dlog { a: hex::encode(a) },
        FirstProverMessage::DhTuple { a, b } => FirstProverMessageJson::DhTuple {
            a: hex::encode(a),
            b: hex::encode(b),
        },
    }
}

/// Parse a `FirstProverMessageJson` back to `FirstProverMessage`.
pub(crate) fn fpm_from_json(
    json: &ergo_wallet_protocol::scala::sending::FirstProverMessageJson,
) -> Result<ergo_wallet::proving::hints::FirstProverMessage, WalletAdminError> {
    use ergo_wallet::proving::hints::FirstProverMessage;
    use ergo_wallet_protocol::scala::sending::FirstProverMessageJson;

    fn decode_pt(hex_str: &str, label: &str) -> Result<[u8; 33], WalletAdminError> {
        hex::decode(hex_str)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| {
                WalletAdminError::Internal(format!(
                    "FirstProverMessageJson: bad point hex for '{label}'"
                ))
            })
    }

    match json {
        FirstProverMessageJson::Dlog { a } => Ok(FirstProverMessage::Schnorr(decode_pt(a, "a")?)),
        FirstProverMessageJson::DhTuple { a, b } => Ok(FirstProverMessage::DhTuple {
            a: decode_pt(a, "a")?,
            b: decode_pt(b, "b")?,
        }),
    }
}

/// Convert a `TransactionHintsBag` to its `TxHintsBagDto` wire representation.
///
/// Partitions each per-input bag into (secret, public) using the same
/// semantics as `HintsBag::partition`: `OwnCommitment` goes into
/// `secret_hints`, everything else into `public_hints`.
pub(crate) fn tx_hints_bag_to_dto(
    bag: &ergo_wallet::proving::hints::TransactionHintsBag,
) -> ergo_wallet_protocol::scala::sending::TxHintsBagDto {
    use ergo_wallet::proving::hints::Hint;
    use ergo_wallet_protocol::scala::sending::node_position_to_str;
    use ergo_wallet_protocol::scala::sending::{HintDto, TxHintsBagDto};
    use std::collections::BTreeMap;

    fn hint_to_dto(hint: &Hint) -> HintDto {
        match hint {
            Hint::OwnCommitment(oc) => HintDto::OwnCommitment {
                image: sigma_boolean_to_json(&oc.image),
                secret: hex::encode(&oc.secret_randomness[..]),
                commitment: fpm_to_json(&oc.commitment),
                position: node_position_to_str(&oc.position.positions),
            },
            Hint::RealCommitment(rc) => HintDto::RealCommitment {
                image: sigma_boolean_to_json(&rc.image),
                commitment: fpm_to_json(&rc.commitment),
                position: node_position_to_str(&rc.position.positions),
            },
            Hint::SimulatedCommitment(sc) => HintDto::SimulatedCommitment {
                image: sigma_boolean_to_json(&sc.image),
                commitment: fpm_to_json(&sc.commitment),
                challenge: hex::encode(sc.challenge),
                position: node_position_to_str(&sc.position.positions),
            },
            Hint::RealSecretProof(rsp) => HintDto::RealSecretProof {
                image: sigma_boolean_to_json(&rsp.image),
                challenge: hex::encode(rsp.challenge),
                response: hex::encode(rsp.response),
                position: node_position_to_str(&rsp.position.positions),
            },
            Hint::SimulatedSecretProof(ssp) => HintDto::SimulatedSecretProof {
                image: sigma_boolean_to_json(&ssp.image),
                challenge: hex::encode(ssp.challenge),
                response: hex::encode(ssp.response),
                position: node_position_to_str(&ssp.position.positions),
            },
        }
    }

    let mut secret_hints: BTreeMap<String, Vec<HintDto>> = BTreeMap::new();
    let mut public_hints: BTreeMap<String, Vec<HintDto>> = BTreeMap::new();

    // secret_hints from the bag's secret_hints map.
    for (idx, hints_bag) in &bag.secret_hints {
        let dtos: Vec<HintDto> = hints_bag.hints.iter().map(hint_to_dto).collect();
        if !dtos.is_empty() {
            secret_hints.insert(idx.to_string(), dtos);
        }
    }

    // public_hints from the bag's public_hints map.
    for (idx, hints_bag) in &bag.public_hints {
        let dtos: Vec<HintDto> = hints_bag.hints.iter().map(hint_to_dto).collect();
        if !dtos.is_empty() {
            public_hints.insert(idx.to_string(), dtos);
        }
    }

    TxHintsBagDto {
        secret_hints,
        public_hints,
    }
}

/// Convert a `TxHintsBagDto` back to a `TransactionHintsBag`.
///
/// Called by `transaction_sign_impl` to thread operator-supplied hints into
/// the prover. The `image` field is parsed so the prover can match hints
/// by proposition at sign time.
pub(crate) fn tx_hints_bag_from_dto(
    dto: &ergo_wallet_protocol::scala::sending::TxHintsBagDto,
) -> Result<ergo_wallet::proving::hints::TransactionHintsBag, WalletAdminError> {
    use ergo_wallet::proving::hints::{
        Hint, HintsBag, OwnCommitment, RealCommitment, RealSecretProof, SimulatedCommitment,
        SimulatedSecretProof, TransactionHintsBag,
    };
    use ergo_wallet::proving::node_position::NodePosition;
    use ergo_wallet_protocol::scala::sending::{node_position_from_str, HintDto};

    fn parse_challenge(hex_str: &str) -> Result<[u8; 24], WalletAdminError> {
        hex::decode(hex_str)
            .ok()
            .and_then(|v| v.try_into().ok())
            // Public value (Fiat-Shamir challenge), but report length only —
            // error strings reach the node log via the API boundary, and
            // echoing arbitrary caller hex there is needless noise.
            .ok_or_else(|| {
                WalletAdminError::Internal(format!(
                    "hint challenge: invalid hex (expected 48 hex chars / 24 bytes, got {} chars)",
                    hex_str.len()
                ))
            })
    }

    fn parse_response(hex_str: &str) -> Result<[u8; 32], WalletAdminError> {
        hex::decode(hex_str)
            .ok()
            .and_then(|v| v.try_into().ok())
            // Public value (Schnorr response z), but report length only for
            // the same log-hygiene reason as `parse_challenge`.
            .ok_or_else(|| {
                WalletAdminError::Internal(format!(
                    "hint response: invalid hex (expected 64 hex chars / 32 bytes, got {} chars)",
                    hex_str.len()
                ))
            })
    }

    fn parse_secret(hex_str: &str) -> Result<[u8; 32], WalletAdminError> {
        hex::decode(hex_str)
            .ok()
            .and_then(|v| v.try_into().ok())
            // Never interpolate the value — this is the OwnCommitment secret
            // randomness. Report only the structural fault.
            .ok_or_else(|| {
                WalletAdminError::Internal(format!(
                    "hint secret: invalid hex (expected 64 hex chars / 32 bytes, got {} chars)",
                    hex_str.len()
                ))
            })
    }

    fn dto_to_hint(h: &HintDto) -> Result<Hint, WalletAdminError> {
        match h {
            HintDto::OwnCommitment {
                image,
                secret,
                commitment,
                position,
            } => {
                let sb = sigma_boolean_from_json(image)?;
                let pos = NodePosition {
                    positions: node_position_from_str(position)
                        .map_err(|e| WalletAdminError::Internal(format!("bad position: {e}")))?,
                };
                Ok(Hint::OwnCommitment(OwnCommitment {
                    image: sb,
                    secret_randomness: parse_secret(secret)?.into(),
                    commitment: fpm_from_json(commitment)?,
                    position: pos,
                }))
            }
            HintDto::RealCommitment {
                image,
                commitment,
                position,
            } => {
                let sb = sigma_boolean_from_json(image)?;
                let pos = NodePosition {
                    positions: node_position_from_str(position)
                        .map_err(|e| WalletAdminError::Internal(format!("bad position: {e}")))?,
                };
                Ok(Hint::RealCommitment(RealCommitment {
                    image: sb,
                    commitment: fpm_from_json(commitment)?,
                    position: pos,
                }))
            }
            HintDto::SimulatedCommitment {
                image,
                commitment,
                challenge,
                position,
            } => {
                let sb = sigma_boolean_from_json(image)?;
                let pos = NodePosition {
                    positions: node_position_from_str(position)
                        .map_err(|e| WalletAdminError::Internal(format!("bad position: {e}")))?,
                };
                Ok(Hint::SimulatedCommitment(SimulatedCommitment {
                    image: sb,
                    commitment: fpm_from_json(commitment)?,
                    challenge: parse_challenge(challenge)?,
                    position: pos,
                }))
            }
            HintDto::RealSecretProof {
                image,
                challenge,
                response,
                position,
            } => {
                let sb = sigma_boolean_from_json(image)?;
                let pos = NodePosition {
                    positions: node_position_from_str(position)
                        .map_err(|e| WalletAdminError::Internal(format!("bad position: {e}")))?,
                };
                Ok(Hint::RealSecretProof(RealSecretProof {
                    image: sb,
                    challenge: parse_challenge(challenge)?,
                    response: parse_response(response)?,
                    position: pos,
                }))
            }
            HintDto::SimulatedSecretProof {
                image,
                challenge,
                response,
                position,
            } => {
                let sb = sigma_boolean_from_json(image)?;
                let pos = NodePosition {
                    positions: node_position_from_str(position)
                        .map_err(|e| WalletAdminError::Internal(format!("bad position: {e}")))?,
                };
                Ok(Hint::SimulatedSecretProof(SimulatedSecretProof {
                    image: sb,
                    challenge: parse_challenge(challenge)?,
                    response: parse_response(response)?,
                    position: pos,
                }))
            }
        }
    }

    // Validate the caller's public designation before decoding any secret
    // nonce. add_for_input partitions by variant, which otherwise silently
    // imports a secret supplied in the public-only transport bucket.
    if dto
        .public_hints
        .values()
        .flatten()
        .any(|hint| matches!(hint, HintDto::OwnCommitment { .. }))
    {
        return Err(WalletAdminError::BadRequest(
            "publicHints cannot contain cmtWithSecret; place private commitments in secretHints"
                .into(),
        ));
    }

    let mut tbag = TransactionHintsBag::empty();

    // Secret hints (OwnCommitment) → secret_hints in TransactionHintsBag.
    for (idx_str, hints_list) in &dto.secret_hints {
        let idx: u32 = idx_str
            .parse()
            .map_err(|_| WalletAdminError::Internal(format!("bad input index: {idx_str}")))?;
        let mut bag = HintsBag::empty();
        for h in hints_list {
            bag.add(dto_to_hint(h)?);
        }
        // Use add_for_input (preserves existing) — mirrors Scala addHintsForInput.
        tbag.add_for_input(idx, bag);
    }

    // Public hints → public_hints in TransactionHintsBag.
    for (idx_str, hints_list) in &dto.public_hints {
        let idx: u32 = idx_str
            .parse()
            .map_err(|_| WalletAdminError::Internal(format!("bad input index: {idx_str}")))?;
        let mut bag = HintsBag::empty();
        for h in hints_list {
            bag.add(dto_to_hint(h)?);
        }
        tbag.add_for_input(idx, bag);
    }

    Ok(tbag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_wallet_protocol::scala::sending::{
        FirstProverMessageJson, HintDto, SigmaBooleanJson, TxHintsBagDto,
    };

    fn own_hint() -> HintDto {
        let point = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        HintDto::OwnCommitment {
            image: SigmaBooleanJson {
                inner: serde_json::json!({"type": "proveDlog", "h": point}),
            },
            secret: "ab".repeat(32),
            commitment: FirstProverMessageJson::Dlog { a: point.into() },
            position: "0".into(),
        }
    }

    #[test]
    fn public_bucket_rejects_private_commitments_before_decoding() {
        let mut dto = TxHintsBagDto::default();
        let mut hint = own_hint();
        if let HintDto::OwnCommitment { image, .. } = &mut hint {
            image.inner = serde_json::Value::Null;
        }
        dto.public_hints.insert("0".into(), vec![hint]);
        let error = tx_hints_bag_from_dto(&dto).unwrap_err();
        assert!(matches!(error, WalletAdminError::BadRequest(_)));
        assert!(!error.to_string().contains(&"ab".repeat(32)));
    }

    #[test]
    fn explicit_private_commitments_and_public_commitments_roundtrip() {
        let own = own_hint();
        let HintDto::OwnCommitment {
            image,
            commitment,
            position,
            ..
        } = &own
        else {
            unreachable!()
        };
        let public = HintDto::RealCommitment {
            image: image.clone(),
            commitment: commitment.clone(),
            position: position.clone(),
        };
        let mut dto = TxHintsBagDto::default();
        dto.secret_hints.insert("0".into(), vec![own]);
        dto.public_hints.insert("0".into(), vec![public]);
        let internal = tx_hints_bag_from_dto(&dto).unwrap();
        assert_eq!(tx_hints_bag_to_dto(&internal), dto);
    }
}
