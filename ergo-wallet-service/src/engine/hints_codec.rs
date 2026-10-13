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
///
/// With `custody`, each `OwnCommitment`'s secret nonce is deposited there,
/// bound to its input index and public commitment, and its `secret` field
/// carries the single-use handle instead. Without it the nonce is written out
/// as hex (the Scala wire form; only for `multisig_nonces = "caller"` and for
/// bags that hold no `OwnCommitment`, such as `extractHints` output).
pub(crate) fn tx_hints_bag_to_dto(
    bag: &ergo_wallet::proving::hints::TransactionHintsBag,
    custody: Option<&dyn super::NonceCustody>,
) -> ergo_wallet_protocol::scala::sending::TxHintsBagDto {
    use ergo_wallet::proving::hints::{Hint, RealCommitment};
    use ergo_wallet_protocol::scala::sending::node_position_to_str;
    use ergo_wallet_protocol::scala::sending::{HintDto, TxHintsBagDto};
    use std::collections::BTreeMap;

    let hint_to_dto = |input: u32, hint: &Hint| -> HintDto {
        match hint {
            Hint::OwnCommitment(oc) => HintDto::OwnCommitment {
                image: sigma_boolean_to_json(&oc.image),
                secret: match custody {
                    Some(custody) => custody.deposit(
                        oc.secret_randomness.clone(),
                        super::NonceBinding {
                            input,
                            commitment: RealCommitment {
                                image: oc.image.clone(),
                                commitment: oc.commitment.clone(),
                                position: oc.position.clone(),
                            },
                        },
                    ),
                    None => hex::encode(&oc.secret_randomness[..]),
                },
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
    };

    let mut secret_hints: BTreeMap<String, Vec<HintDto>> = BTreeMap::new();
    let mut public_hints: BTreeMap<String, Vec<HintDto>> = BTreeMap::new();

    // secret_hints from the bag's secret_hints map.
    for (idx, hints_bag) in &bag.secret_hints {
        let dtos: Vec<HintDto> = hints_bag
            .hints
            .iter()
            .map(|hint| hint_to_dto(*idx, hint))
            .collect();
        if !dtos.is_empty() {
            secret_hints.insert(idx.to_string(), dtos);
        }
    }

    // public_hints from the bag's public_hints map.
    for (idx, hints_bag) in &bag.public_hints {
        let dtos: Vec<HintDto> = hints_bag
            .hints
            .iter()
            .map(|hint| hint_to_dto(*idx, hint))
            .collect();
        if !dtos.is_empty() {
            public_hints.insert(idx.to_string(), dtos);
        }
    }

    TxHintsBagDto {
        secret_hints,
        public_hints,
    }
}

/// How [`tx_hints_bag_from_dto`] resolves the secret nonce of a
/// `cmtWithSecret` (`OwnCommitment`) hint.
///
/// `Default` is the Scala form with no caller keys.
#[derive(Clone, Copy, Default)]
pub(crate) struct OwnNoncePolicy<'a> {
    /// Daemon-held nonces issued by `generateCommitments`. `None` is the
    /// Scala form (`multisig_nonces = "caller"`): a hex nonce is accepted for
    /// any key and a handle is refused.
    pub custody: Option<&'a dyn super::NonceCustody>,
    /// Images whose secret the caller supplied in this same request
    /// (`externalSecrets`). With custody, a hex nonce is accepted for these
    /// keys only: the caller already holds the key, so the nonce reveals
    /// nothing new.
    pub caller_images: &'a [ergo_ser::sigma_value::SigmaBoolean],
}

/// Convert a `TxHintsBagDto` back to a `TransactionHintsBag`.
///
/// Called by `transaction_sign_impl` to thread operator-supplied hints into
/// the prover. The `image` field is parsed so the prover can match hints
/// by proposition at sign time.
///
/// A `cmtWithSecret` hint's nonce comes from `policy`: a custody handle is
/// withdrawn for the input and public commitment it sits next to, and is
/// consumed whether or not signing then succeeds. With custody, a hex nonce
/// is refused unless its key is in `policy.caller_images`: a caller who picks
/// or replays the nonce for a wallet key learns that key from the signature.
pub(crate) fn tx_hints_bag_from_dto(
    dto: &ergo_wallet_protocol::scala::sending::TxHintsBagDto,
    policy: OwnNoncePolicy<'_>,
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

    let own_secret = |secret: &str,
                      binding: super::NonceBinding|
     -> Result<zeroize::Zeroizing<[u8; 32]>, WalletAdminError> {
        let handle = secret.starts_with(super::NONCE_HANDLE_PREFIX);
        match (handle, policy.custody) {
            (true, Some(custody)) => {
                custody
                    .withdraw(secret, &binding)
                    .map_err(|refusal| match refusal {
                        super::NonceRefusal::Unavailable => WalletAdminError::BadRequest(
                            "unknown, expired or already used commitment handle; generate new \
                             commitments"
                                .into(),
                        ),
                        super::NonceRefusal::WrongCommitment => WalletAdminError::BadRequest(
                            "commitment handle was issued for another input or commitment; it \
                             is now used up, generate new commitments"
                                .into(),
                        ),
                    })
            }
            (true, None) => Err(WalletAdminError::BadRequest(
                "commitment handles require nonce custody".into(),
            )),
            (false, Some(_)) if !policy.caller_images.contains(&binding.commitment.image) => {
                Err(WalletAdminError::BadRequest(
                    "caller-supplied secret nonces are refused; pass the commitment handle \
                     returned by generateCommitments (a hex nonce is accepted only for a key \
                     supplied in externalSecrets)"
                        .into(),
                ))
            }
            (false, _) => parse_secret(secret).map(zeroize::Zeroizing::new),
        }
    };

    let dto_to_hint = |input: u32, h: &HintDto| -> Result<Hint, WalletAdminError> {
        match h {
            HintDto::OwnCommitment {
                image,
                secret,
                commitment,
                position,
            } => {
                let public = RealCommitment {
                    image: sigma_boolean_from_json(image)?,
                    commitment: fpm_from_json(commitment)?,
                    position: NodePosition {
                        positions: node_position_from_str(position).map_err(|e| {
                            WalletAdminError::Internal(format!("bad position: {e}"))
                        })?,
                    },
                };
                let binding = super::NonceBinding {
                    input,
                    commitment: public.clone(),
                };
                Ok(Hint::OwnCommitment(OwnCommitment {
                    secret_randomness: own_secret(secret, binding)?,
                    image: public.image,
                    commitment: public.commitment,
                    position: public.position,
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
    };

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
            bag.add(dto_to_hint(idx, h)?);
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
            bag.add(dto_to_hint(idx, h)?);
        }
        tbag.add_for_input(idx, bag);
    }

    Ok(tbag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{NonceBinding, NonceCustody, NonceRefusal, NONCE_HANDLE_PREFIX};
    use ergo_wallet_protocol::scala::sending::{
        FirstProverMessageJson, HintDto, SigmaBooleanJson, TxHintsBagDto,
    };

    const POINT: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn own_hint() -> HintDto {
        HintDto::OwnCommitment {
            image: SigmaBooleanJson {
                inner: serde_json::json!({"type": "proveDlog", "h": POINT}),
            },
            secret: "ab".repeat(32),
            commitment: FirstProverMessageJson::Dlog { a: POINT.into() },
            position: "0".into(),
        }
    }

    fn own_bag() -> TxHintsBagDto {
        let mut dto = TxHintsBagDto::default();
        dto.secret_hints.insert("0".into(), vec![own_hint()]);
        dto
    }

    fn secret_of(dto: &TxHintsBagDto) -> &str {
        let HintDto::OwnCommitment { secret, .. } = &dto.secret_hints["0"][0] else {
            panic!("own commitment expected");
        };
        secret
    }

    /// A minimal custodian with the binding and single-use contract.
    #[derive(Default)]
    struct Vault(std::sync::Mutex<std::collections::BTreeMap<String, ([u8; 32], NonceBinding)>>);

    impl NonceCustody for Vault {
        fn deposit(&self, nonce: zeroize::Zeroizing<[u8; 32]>, binding: NonceBinding) -> String {
            let mut map = self.0.lock().unwrap();
            let handle = format!("{NONCE_HANDLE_PREFIX}{}", map.len());
            map.insert(handle.clone(), (*nonce, binding));
            handle
        }
        fn withdraw(
            &self,
            handle: &str,
            binding: &NonceBinding,
        ) -> Result<zeroize::Zeroizing<[u8; 32]>, NonceRefusal> {
            let (nonce, issued) = self
                .0
                .lock()
                .unwrap()
                .remove(handle)
                .ok_or(NonceRefusal::Unavailable)?;
            if issued != *binding {
                return Err(NonceRefusal::WrongCommitment);
            }
            Ok(zeroize::Zeroizing::new(nonce))
        }
        fn clear(&self) {
            self.0.lock().unwrap().clear();
        }
    }

    fn custody(vault: &Vault) -> OwnNoncePolicy<'_> {
        OwnNoncePolicy {
            custody: Some(vault),
            caller_images: &[],
        }
    }

    /// The internal bag of [`own_bag`], decoded in the Scala form.
    fn internal_own_bag() -> ergo_wallet::proving::hints::TransactionHintsBag {
        tx_hints_bag_from_dto(&own_bag(), OwnNoncePolicy::default()).unwrap()
    }

    #[test]
    fn public_bucket_rejects_private_commitments_before_decoding() {
        let mut dto = TxHintsBagDto::default();
        let mut hint = own_hint();
        if let HintDto::OwnCommitment { image, .. } = &mut hint {
            image.inner = serde_json::Value::Null;
        }
        dto.public_hints.insert("0".into(), vec![hint]);
        let error = tx_hints_bag_from_dto(&dto, OwnNoncePolicy::default()).unwrap_err();
        assert!(matches!(error, WalletAdminError::BadRequest(_)));
        assert!(!error.to_string().contains(&"ab".repeat(32)));
    }

    #[test]
    fn explicit_private_commitments_and_public_commitments_roundtrip_in_caller_form() {
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
        let internal = tx_hints_bag_from_dto(&dto, OwnNoncePolicy::default()).unwrap();
        assert_eq!(tx_hints_bag_to_dto(&internal, None), dto);
    }

    #[test]
    fn custody_returns_a_single_use_handle_and_never_the_nonce() {
        let vault = Vault::default();
        let wire = tx_hints_bag_to_dto(&internal_own_bag(), Some(&vault));
        let json = serde_json::to_string(&wire).unwrap();
        assert!(
            !json.contains(&"ab".repeat(32)),
            "the nonce must not leave: {json}"
        );
        assert!(!format!("{wire:?}").contains(&"ab".repeat(32)));
        assert!(secret_of(&wire).starts_with(NONCE_HANDLE_PREFIX));
        // Without custody a handle is refused rather than parsed.
        assert!(matches!(
            tx_hints_bag_from_dto(&wire, OwnNoncePolicy::default()),
            Err(WalletAdminError::BadRequest(_))
        ));
        // The handle resolves to the nonce once.
        let resolved = tx_hints_bag_from_dto(&wire, custody(&vault)).unwrap();
        assert_eq!(tx_hints_bag_to_dto(&resolved, None), own_bag());
        assert!(matches!(
            tx_hints_bag_from_dto(&wire, custody(&vault)),
            Err(WalletAdminError::BadRequest(message)) if message.contains("already used")
        ));
    }

    #[test]
    fn handle_moved_to_another_input_is_refused_and_consumed() {
        let vault = Vault::default();
        let wire = tx_hints_bag_to_dto(&internal_own_bag(), Some(&vault));
        let mut moved = TxHintsBagDto::default();
        moved
            .secret_hints
            .insert("1".into(), wire.secret_hints["0"].clone());
        let error = tx_hints_bag_from_dto(&moved, custody(&vault)).unwrap_err();
        assert!(
            matches!(&error, WalletAdminError::BadRequest(m) if m.contains("another input")),
            "{error:?}"
        );
        assert!(
            tx_hints_bag_from_dto(&wire, custody(&vault)).is_err(),
            "the refused attempt used the handle up"
        );
    }

    #[test]
    fn handle_paired_with_another_commitment_is_refused() {
        let vault = Vault::default();
        let mut wire = tx_hints_bag_to_dto(&internal_own_bag(), Some(&vault));
        let other = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        if let Some(HintDto::OwnCommitment { commitment, .. }) = wire
            .secret_hints
            .get_mut("0")
            .and_then(|hints| hints.first_mut())
        {
            *commitment = FirstProverMessageJson::Dlog { a: other.into() };
        }
        let error = tx_hints_bag_from_dto(&wire, custody(&vault)).unwrap_err();
        assert!(
            matches!(&error, WalletAdminError::BadRequest(m) if m.contains("another input or commitment")),
            "{error:?}"
        );
    }

    #[test]
    fn caller_supplied_nonce_is_refused_with_custody_without_revealing_it() {
        let vault = Vault::default();
        let error = tx_hints_bag_from_dto(&own_bag(), custody(&vault)).unwrap_err();
        let WalletAdminError::BadRequest(message) = &error else {
            panic!("expected a client error, got {error:?}");
        };
        assert!(message.contains("caller-supplied secret nonces are refused"));
        assert!(!message.contains(&"ab".repeat(32)));
        assert!(!format!("{error:?}").contains(&"ab".repeat(32)));
    }

    #[test]
    fn caller_supplied_nonce_is_accepted_for_a_key_supplied_in_the_same_request() {
        let vault = Vault::default();
        let image = ergo_ser::sigma_value::SigmaBoolean::ProveDlog(
            ergo_primitives::group_element::GroupElement::from_bytes(
                hex::decode(POINT).unwrap().try_into().unwrap(),
            ),
        );
        let policy = OwnNoncePolicy {
            custody: Some(&vault),
            caller_images: std::slice::from_ref(&image),
        };
        let internal = tx_hints_bag_from_dto(&own_bag(), policy).unwrap();
        assert_eq!(tx_hints_bag_to_dto(&internal, None), own_bag());
    }

    #[test]
    fn unknown_handle_is_refused_in_either_form() {
        let mut dto = own_bag();
        if let Some(HintDto::OwnCommitment { secret, .. }) = dto
            .secret_hints
            .get_mut("0")
            .and_then(|hints| hints.first_mut())
        {
            *secret = format!("{NONCE_HANDLE_PREFIX}{}", "00".repeat(16));
        }
        let vault = Vault::default();
        for policy in [OwnNoncePolicy::default(), custody(&vault)] {
            assert!(matches!(
                tx_hints_bag_from_dto(&dto, policy),
                Err(WalletAdminError::BadRequest(_))
            ));
        }
    }

    #[test]
    fn one_handle_presented_twice_in_a_request_is_refused() {
        let vault = Vault::default();
        let mut wire = tx_hints_bag_to_dto(&internal_own_bag(), Some(&vault));
        let hint = wire.secret_hints["0"][0].clone();
        wire.secret_hints.get_mut("0").unwrap().push(hint);
        assert!(matches!(
            tx_hints_bag_from_dto(&wire, custody(&vault)),
            Err(WalletAdminError::BadRequest(m)) if m.contains("already used")
        ));
    }
}
