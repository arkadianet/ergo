//! Native `/api/v1/wallet/*` response DTOs.
//!
//! Factual-only, built for permanence (see `dev-docs/native-wallet-v1-design.md`):
//! money and token amounts are decimal **strings** (JSON numbers lose precision
//! above 2^53); status/provenance/scope are **tagged unions** `{type:"…"}`; lean
//! summaries extend additively. These are distinct from the Scala-compat
//! `super::super::types` DTOs — neither is reused or mutated.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// A token amount. `amount` is a decimal string (token amounts can exceed 2^53).
/// `deny_unknown_fields` so this stays strict when nested inside request DTOs
/// (e.g. `OutputIntent::payment.assets`, `SelectTarget.assets`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WalletAssetDto {
    /// 32-byte token id, hex.
    pub token_id: String,
    /// Decimal-string amount.
    pub amount: String,
}

/// nanoErg breakdown — all decimal strings.
///
/// Invariant: `available == confirmed.saturating_sub(reserved)` **always**; and
/// `available + reserved == confirmed` iff `reserved <= confirmed`, otherwise
/// `available == 0` and `reserved > confirmed` (flagged by
/// [`ReemissionInfoDto::reserved_exceeds_confirmed`]). `reserved` is never clamped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NanoErgBreakdownDto {
    /// Gross sum of mature (`Confirmed`) box values.
    pub confirmed: String,
    /// `confirmed − reserved` (saturating). The factual spendable figure.
    pub available: String,
    /// EIP-27 re-emission holdback estimate (see [`ReemissionInfoDto`]).
    pub reserved: String,
    /// Sum of immature (mining-reward maturity-window) box values; separate.
    pub immature: String,
}

/// EIP-27 re-emission reserve detail. `null` off EIP-27 nets or below activation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReemissionInfoDto {
    /// 32-byte re-emission token id, hex.
    pub token_id: String,
    /// Re-emission tokens held across the wallet's confirmed boxes; `== reserved`
    /// 1:1 (1 nanoErg/token).
    pub reserved_token_amount: String,
    /// Number of confirmed wallet boxes carrying the re-emission token. This is the
    /// shared obligation's box count — it counts every token-carrying input once the
    /// rule is triggered, not only the floor reward boxes that trigger it.
    pub reserved_box_count: u32,
    /// `reserved > confirmed` — the pathological case where the holdback exceeds
    /// mature ERG (then `available == 0`).
    pub reserved_exceeds_confirmed: bool,
}

/// Scope of an unconfirmed delta. Tagged; `singleHop` is the only reachable
/// variant today (`fullOffChainRegistry` is reserved, additive).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ScopeDto {
    /// Single-hop mempool overlay (pool outputs to the wallet + pool spends of
    /// confirmed wallet boxes); does not net chains within the pool.
    SingleHop,
}

/// A labeled single-hop unconfirmed delta. Present only with
/// `?includeUnconfirmed=true`; **never folded** into `confirmed`/`available`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UnconfirmedDeltaDto {
    /// What the delta covers.
    pub scope: ScopeDto,
    /// nanoErg arriving in pending pool outputs to the wallet (decimal string).
    pub incoming_nano_erg: String,
    /// nanoErg leaving via confirmed wallet boxes a pool tx already spends.
    pub outgoing_nano_erg: String,
    /// `incoming − outgoing`, signed decimal string.
    pub net_nano_erg: String,
}

/// `GET /api/v1/wallet/balance` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletBalanceDto {
    /// `asOf` — the wallet scan height of the single read snapshot this body
    /// was computed from.
    pub height: u32,
    /// nanoErg breakdown.
    pub nano_erg: NanoErgBreakdownDto,
    /// Confirmed token balances (the re-emission token is omitted — it is
    /// accounted for solely by `reserved`/`reemission`).
    pub assets: Vec<WalletAssetDto>,
    /// EIP-27 reserve detail, or `null` off EIP-27 nets / below activation.
    /// Serialized as `null` (not omitted) so the field's presence is stable.
    pub reemission: Option<ReemissionInfoDto>,
    /// Labeled unconfirmed delta, or `null` unless `?includeUnconfirmed=true`.
    pub unconfirmed: Option<UnconfirmedDeltaDto>,
}

// ----- status & lifecycle -----

/// The network this wallet is on (from `cfg.network`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum NetworkDto {
    Mainnet,
    Testnet,
}

/// Wallet rescan lifecycle phase. `running` is a real full-rebuild-in-progress
/// state; `unavailable` is returned only on a backend that cannot replay blocks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum RescanStateDto {
    Idle,
    #[serde(rename_all = "camelCase")]
    Running {
        from_height: u32,
    },
    #[serde(rename_all = "camelCase")]
    Unavailable {
        detail: String,
    },
}

/// `GET /api/v1/wallet/status` — wallet state snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletStatusDto {
    /// A wallet exists (seed stored), independent of lock state.
    pub initialized: bool,
    /// The in-memory master key is NOT loaded.
    pub locked: bool,
    /// Height the wallet has scanned through (the read snapshot's `asOf`).
    pub scan_height: u32,
    /// Chain frontier height (so a client can compute the sync gap).
    pub tip_height: u32,
    /// Current change address, or `null` when unset (never `""`). Surfaced even
    /// while locked — it is read from the persisted change-address state, not the
    /// in-memory key.
    pub change_address: Option<String>,
    /// The network this wallet is on.
    pub network: NetworkDto,
    /// EIP-27 is active for the next wallet spend (`cfg.reemission` set AND
    /// `tip+1 > activation`) — the same inputs as the balance `reserved` trigger.
    pub eip27_active: bool,
    /// Rescan lifecycle phase.
    pub rescan: RescanStateDto,
    /// The wallet scan was invalidated (balances/addresses may be stale until a rescan).
    pub scan_invalidated: bool,
}

// ----- addresses -----

/// A tracked wallet address with its derivation metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletAddressDto {
    /// The encoded P2PK address for this network.
    pub address: String,
    /// BIP32 derivation path, e.g. `m/44'/429'/0'/0/0`.
    pub derivation_path: String,
    /// Monotonic tracked-pubkey index (insertion / derivation order). `u64` to
    /// match the storage `TrackedAddressMeta.path_idx` exactly — narrowing to
    /// `u32` would silently alias distinct addresses past `u32::MAX`.
    pub index: u64,
    /// Operator label, or `null` when unset.
    pub label: Option<String>,
    /// Height at which this pubkey was first tracked.
    pub added_at_height: u32,
}

/// Paged tracked-address list. `total` = full count, `asOf` = scan height, both
/// from the same read snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AddressPage {
    pub items: Vec<WalletAddressDto>,
    pub total: u32,
    pub as_of: u32,
}

// ----- boxes -----

/// Lifecycle status of a wallet box. Tagged; lean (no full box rendering).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum BoxStatusDto {
    Confirmed,
    #[serde(rename_all = "camelCase")]
    Immature {
        matures_at_height: u32,
    },
    #[serde(rename_all = "camelCase")]
    Spent {
        tx_id: String,
        height: u32,
    },
}

/// How a wallet box was classified at apply time. Tagged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum BoxProvenanceDto {
    Owned,
    MinerReward,
    #[serde(rename_all = "camelCase")]
    Custom {
        scan_id: u16,
    },
}

/// A lean wallet box summary — no ergoTree/registers/address (full hydration is
/// an additive follow-up, never a reshape of this summary).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletBoxSummary {
    pub box_id: String,
    /// Box value in nanoErg (decimal string).
    pub value: String,
    pub assets: Vec<WalletAssetDto>,
    pub creation_tx_id: String,
    pub creation_output_index: u16,
    pub creation_height: u32,
    pub status: BoxStatusDto,
    pub provenance: BoxProvenanceDto,
}

/// Paged wallet-box list, ordered `(creationHeight desc, boxId asc)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BoxPage {
    pub items: Vec<WalletBoxSummary>,
    pub total: u32,
    pub as_of: u32,
}

// ----- transactions -----

/// A lean wallet-transaction summary — references only (no full IO/fee/bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletTransactionSummary {
    pub tx_id: String,
    pub block_id: String,
    pub block_height: u32,
    pub wallet_input_box_ids: Vec<String>,
    pub wallet_output_box_ids: Vec<String>,
}

/// Paged wallet-transaction list, ordered `(blockHeight desc, txId asc)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TxPage {
    pub items: Vec<WalletTransactionSummary>,
    pub total: u32,
    pub as_of: u32,
}

// ----- lifecycle (requests/responses) -----

/// `POST /api/v1/wallet/unlock` request. `pass` is body-only, never logged.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnlockRequest {
    /// Wallet password.
    pub pass: String,
}

/// `POST /api/v1/wallet/mnemonic/verify` request. Body-only secrets, never logged.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MnemonicVerifyRequest {
    /// Candidate recovery phrase to compare against the persisted seed.
    pub mnemonic: String,
    /// BIP39 passphrase (empty if none).
    #[serde(default)]
    pub mnemonic_pass: String,
}

/// `POST /api/v1/wallet/mnemonic/verify` result. `matched=false` is a factual
/// answer, not an error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MnemonicVerifyResult {
    pub matched: bool,
}

/// `POST /api/v1/wallet/init` request. Secrets body-only, never logged.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InitRequest {
    /// Wallet password.
    pub pass: String,
    /// BIP39 passphrase (empty if none).
    #[serde(default)]
    pub mnemonic_pass: String,
    /// Mnemonic word count: one of 12/15/18/21/24.
    #[serde(default = "default_strength")]
    pub strength: u16,
}

fn default_strength() -> u16 {
    24
}

/// `POST /api/v1/wallet/init` response — the generated mnemonic, returned ONCE
/// (no-store; the page is the only place it should ever live).
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InitResponse {
    pub mnemonic: String,
}

/// Key-derivation mode for `restore` (tagged). Required — no default (the
/// legacy-default trap is deliberately removed). Manual `Deserialize` so unknown
/// sibling fields are rejected (serde can't `deny_unknown_fields` an
/// internally-tagged enum).
#[derive(Clone, Debug, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum DerivationMode {
    /// Modern EIP-3 derivation.
    Eip3,
    /// Pre-1627 derivation (matches an old CLI restore).
    LegacyPre1627,
}

impl<'de> Deserialize<'de> for DerivationMode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Tagged {
            #[serde(rename = "type")]
            ty: String,
        }
        let t = Tagged::deserialize(d)?;
        match t.ty.as_str() {
            "eip3" => Ok(DerivationMode::Eip3),
            "legacyPre1627" => Ok(DerivationMode::LegacyPre1627),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["eip3", "legacyPre1627"],
            )),
        }
    }
}

/// `POST /api/v1/wallet/restore` request. Secrets body-only, never logged.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreRequest {
    /// Recovery phrase.
    pub mnemonic: String,
    /// BIP39 passphrase (empty if none).
    #[serde(default)]
    pub mnemonic_pass: String,
    /// Wallet password.
    pub pass: String,
    /// Required derivation mode.
    pub derivation: DerivationMode,
}

/// `POST /api/v1/wallet/addresses` (derive) request (tagged). `next` derives the
/// next sequential key; `path` derives at an explicit BIP32 path. Manual
/// `Deserialize` so unknown sibling fields are rejected and each variant's fields
/// are validated (serde can't `deny_unknown_fields` an internally-tagged enum).
#[derive(Clone, Debug, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum DeriveKeyRequest {
    Next,
    #[serde(rename_all = "camelCase")]
    Path {
        derivation_path: String,
    },
}

impl<'de> Deserialize<'de> for DeriveKeyRequest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Raw {
            #[serde(rename = "type")]
            ty: String,
            #[serde(default)]
            derivation_path: Option<String>,
        }
        let r = Raw::deserialize(d)?;
        match r.ty.as_str() {
            "next" => match r.derivation_path {
                None => Ok(DeriveKeyRequest::Next),
                Some(_) => Err(serde::de::Error::custom(
                    "`next` does not take a derivationPath",
                )),
            },
            "path" => {
                let derivation_path = r
                    .derivation_path
                    .ok_or_else(|| serde::de::Error::missing_field("derivationPath"))?;
                Ok(DeriveKeyRequest::Path { derivation_path })
            }
            other => Err(serde::de::Error::unknown_variant(other, &["next", "path"])),
        }
    }
}

/// `POST /api/v1/wallet/addresses` (derive) response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DerivedAddress {
    /// Encoded P2PK address for the derived key.
    pub address: String,
    /// BIP32 derivation path of the derived key.
    pub derivation_path: String,
    /// Address index — the last path component.
    pub index: u32,
}

/// `GET /api/v1/wallet/change-address` response. `null` when unset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChangeAddressDto {
    pub address: Option<String>,
}

/// `PUT /api/v1/wallet/change-address` request.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetChangeAddressRequest {
    /// The address to use for change — must be a tracked P2PK on this network.
    pub address: String,
}

/// `POST /api/v1/wallet/rescan` request (body optional; defaults to a full rebuild).
#[derive(Clone, Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RescanRequest {
    /// Height to rescan from (0 = full rebuild).
    #[serde(default)]
    pub from_height: u32,
}

// ----- transaction construction (§3.5) -----

/// Wire representation of a transaction (unsigned or signed), tagged (P2-1). Only
/// `bytes` (hex of the serialized tx) is active today; `{type:"json"}` is reserved
/// (additive). One shape everywhere a tx crosses the wire — `build` output, `sign`
/// in/out, `send`, multisig in/out — never a second composition form. Manual
/// `Deserialize` so unknown sibling fields are rejected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum TxRepr {
    /// Hex of the serialized transaction bytes.
    Bytes {
        /// Lowercase hex of the serialized transaction.
        bytes: String,
    },
}

impl TxRepr {
    /// The hex payload (the only field of the only active variant).
    pub fn bytes_hex(&self) -> &str {
        match self {
            TxRepr::Bytes { bytes } => bytes,
        }
    }

    /// Wrap raw serialized bytes as a `TxRepr::Bytes`.
    pub fn from_bytes(raw: &[u8]) -> Self {
        TxRepr::Bytes {
            bytes: hex::encode(raw),
        }
    }
}

impl<'de> Deserialize<'de> for TxRepr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Raw {
            #[serde(rename = "type")]
            ty: String,
            #[serde(default)]
            bytes: Option<String>,
        }
        let r = Raw::deserialize(d)?;
        match r.ty.as_str() {
            "bytes" => {
                let bytes = r
                    .bytes
                    .ok_or_else(|| serde::de::Error::missing_field("bytes"))?;
                Ok(TxRepr::Bytes { bytes })
            }
            other => Err(serde::de::Error::unknown_variant(other, &["bytes"])),
        }
    }
}

/// One requested output of a [`TxIntent`], tagged. `payment` (+ optional
/// assets/registers) and `burn` are load-bearing; `mint` and `payment.registers`
/// are valid shapes that ship `unsupported_intent(422)` until builder support
/// lands (P2-5 — a later 422→200 for the same well-formed request, not a behavior
/// change). Manual `Deserialize` so unknown sibling fields and cross-variant field
/// leakage are rejected.
#[derive(Clone, Debug, PartialEq, Serialize, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum OutputIntent {
    /// Pay `value` nanoErg (+ optional `assets`/`registers`) to `address`.
    #[serde(rename_all = "camelCase")]
    Payment {
        /// Recipient address (P2PK or P2S for this network).
        address: String,
        /// nanoErg to send (decimal string).
        value: String,
        /// Tokens to send alongside.
        #[serde(default)]
        assets: Vec<WalletAssetDto>,
        /// Non-default registers (R4..R9), hex-encoded constants. `unsupported_intent` until wired.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        registers: Option<std::collections::BTreeMap<String, String>>,
    },
    /// Mint a new token to `address`. `unsupported_intent` until wired.
    #[serde(rename_all = "camelCase")]
    Mint {
        /// Recipient of the minted token.
        address: String,
        /// Amount to mint (decimal string).
        amount: String,
        /// Optional EIP-4 token name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// Optional EIP-4 decimals.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decimals: Option<u8>,
        /// Optional EIP-4 description.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    /// Destroy a token surplus (no output keeps these). Requires `allowTokenBurn`.
    #[serde(rename_all = "camelCase")]
    Burn {
        /// Tokens to burn (≥1).
        assets: Vec<WalletAssetDto>,
    },
}

impl<'de> Deserialize<'de> for OutputIntent {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Raw {
            #[serde(rename = "type")]
            ty: String,
            address: Option<String>,
            value: Option<String>,
            assets: Option<Vec<WalletAssetDto>>,
            registers: Option<std::collections::BTreeMap<String, String>>,
            amount: Option<String>,
            name: Option<String>,
            decimals: Option<u8>,
            description: Option<String>,
        }
        // Reject a field that belongs to a different variant (cross-variant leak),
        // matching the strict tagged-enum convention used by `DeriveKeyRequest`.
        fn forbid<E: serde::de::Error>(present: bool, field: &str, ty: &str) -> Result<(), E> {
            if present {
                Err(E::custom(format!("`{ty}` output does not take `{field}`")))
            } else {
                Ok(())
            }
        }
        let r = Raw::deserialize(d)?;
        match r.ty.as_str() {
            "payment" => {
                forbid::<D::Error>(r.amount.is_some(), "amount", "payment")?;
                forbid::<D::Error>(r.name.is_some(), "name", "payment")?;
                forbid::<D::Error>(r.decimals.is_some(), "decimals", "payment")?;
                forbid::<D::Error>(r.description.is_some(), "description", "payment")?;
                Ok(OutputIntent::Payment {
                    address: r
                        .address
                        .ok_or_else(|| D::Error::missing_field("address"))?,
                    value: r.value.ok_or_else(|| D::Error::missing_field("value"))?,
                    assets: r.assets.unwrap_or_default(),
                    registers: r.registers,
                })
            }
            "mint" => {
                forbid::<D::Error>(r.value.is_some(), "value", "mint")?;
                forbid::<D::Error>(r.assets.is_some(), "assets", "mint")?;
                forbid::<D::Error>(r.registers.is_some(), "registers", "mint")?;
                Ok(OutputIntent::Mint {
                    address: r
                        .address
                        .ok_or_else(|| D::Error::missing_field("address"))?,
                    amount: r.amount.ok_or_else(|| D::Error::missing_field("amount"))?,
                    name: r.name,
                    decimals: r.decimals,
                    description: r.description,
                })
            }
            "burn" => {
                forbid::<D::Error>(r.address.is_some(), "address", "burn")?;
                forbid::<D::Error>(r.value.is_some(), "value", "burn")?;
                forbid::<D::Error>(r.registers.is_some(), "registers", "burn")?;
                forbid::<D::Error>(r.amount.is_some(), "amount", "burn")?;
                forbid::<D::Error>(r.name.is_some(), "name", "burn")?;
                forbid::<D::Error>(r.decimals.is_some(), "decimals", "burn")?;
                forbid::<D::Error>(r.description.is_some(), "description", "burn")?;
                let assets = r.assets.ok_or_else(|| D::Error::missing_field("assets"))?;
                if assets.is_empty() {
                    return Err(D::Error::custom("`burn` requires at least one asset"));
                }
                Ok(OutputIntent::Burn { assets })
            }
            other => Err(D::Error::unknown_variant(
                other,
                &["payment", "mint", "burn"],
            )),
        }
    }
}

/// Where a [`TxIntent`]/[`BoxSelectRequest`] draws its inputs from, tagged.
/// `auto` = wallet box selection (the default); `boxIds` = explicit wallet box
/// ids; `boxes` = explicit serialized boxes (hex). Manual `Deserialize` for strict
/// rejection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum InputSource {
    /// Automatic wallet box selection.
    #[serde(rename_all = "camelCase")]
    Auto {
        /// Minimum confirmations a candidate box must have (`-1` = include pool).
        #[serde(default)]
        min_confirmations: i64,
        /// Box ids to exclude from selection.
        #[serde(default)]
        exclude_box_ids: Vec<String>,
    },
    /// Explicit wallet box ids.
    #[serde(rename_all = "camelCase")]
    BoxIds {
        /// 32-byte box ids, hex.
        box_ids: Vec<String>,
    },
    /// Explicit serialized boxes, hex.
    #[serde(rename_all = "camelCase")]
    Boxes {
        /// Serialized `ErgoBox` bytes, hex.
        boxes_hex: Vec<String>,
    },
}

impl Default for InputSource {
    fn default() -> Self {
        InputSource::Auto {
            min_confirmations: 0,
            exclude_box_ids: Vec::new(),
        }
    }
}

impl<'de> Deserialize<'de> for InputSource {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Raw {
            #[serde(rename = "type")]
            ty: String,
            min_confirmations: Option<i64>,
            exclude_box_ids: Option<Vec<String>>,
            box_ids: Option<Vec<String>>,
            boxes_hex: Option<Vec<String>>,
        }
        let r = Raw::deserialize(d)?;
        let extra = |a: bool, b: bool, c: bool| a || b || c;
        match r.ty.as_str() {
            "auto" => {
                if extra(r.box_ids.is_some(), r.boxes_hex.is_some(), false) {
                    return Err(D::Error::custom(
                        "`auto` takes only minConfirmations/excludeBoxIds",
                    ));
                }
                Ok(InputSource::Auto {
                    min_confirmations: r.min_confirmations.unwrap_or(0),
                    exclude_box_ids: r.exclude_box_ids.unwrap_or_default(),
                })
            }
            "boxIds" => {
                if extra(
                    r.min_confirmations.is_some(),
                    r.exclude_box_ids.is_some(),
                    r.boxes_hex.is_some(),
                ) {
                    return Err(D::Error::custom("`boxIds` takes only boxIds"));
                }
                Ok(InputSource::BoxIds {
                    box_ids: r.box_ids.ok_or_else(|| D::Error::missing_field("boxIds"))?,
                })
            }
            "boxes" => {
                if extra(
                    r.min_confirmations.is_some(),
                    r.exclude_box_ids.is_some(),
                    r.box_ids.is_some(),
                ) {
                    return Err(D::Error::custom("`boxes` takes only boxesHex"));
                }
                Ok(InputSource::Boxes {
                    boxes_hex: r
                        .boxes_hex
                        .ok_or_else(|| D::Error::missing_field("boxesHex"))?,
                })
            }
            other => Err(D::Error::unknown_variant(
                other,
                &["auto", "boxIds", "boxes"],
            )),
        }
    }
}

/// Where a [`TxIntent`] draws its data inputs from, tagged (default: empty `boxIds`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum DataInputSource {
    /// Explicit data-input box ids.
    #[serde(rename_all = "camelCase")]
    BoxIds {
        /// 32-byte box ids, hex.
        box_ids: Vec<String>,
    },
    /// Explicit serialized data-input boxes, hex.
    #[serde(rename_all = "camelCase")]
    Boxes {
        /// Serialized `ErgoBox` bytes, hex.
        boxes_hex: Vec<String>,
    },
}

impl Default for DataInputSource {
    fn default() -> Self {
        DataInputSource::BoxIds {
            box_ids: Vec::new(),
        }
    }
}

impl<'de> Deserialize<'de> for DataInputSource {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Raw {
            #[serde(rename = "type")]
            ty: String,
            box_ids: Option<Vec<String>>,
            boxes_hex: Option<Vec<String>>,
        }
        let r = Raw::deserialize(d)?;
        match r.ty.as_str() {
            "boxIds" => {
                if r.boxes_hex.is_some() {
                    return Err(D::Error::custom("`boxIds` takes only boxIds"));
                }
                Ok(DataInputSource::BoxIds {
                    box_ids: r.box_ids.ok_or_else(|| D::Error::missing_field("boxIds"))?,
                })
            }
            "boxes" => {
                if r.box_ids.is_some() {
                    return Err(D::Error::custom("`boxes` takes only boxesHex"));
                }
                Ok(DataInputSource::Boxes {
                    boxes_hex: r
                        .boxes_hex
                        .ok_or_else(|| D::Error::missing_field("boxesHex"))?,
                })
            }
            other => Err(D::Error::unknown_variant(other, &["boxIds", "boxes"])),
        }
    }
}

/// `POST /api/v1/wallet/transactions/build` request (also `send.intent`). At least
/// one output. `fee` `null` uses `MIN_FEE`; `changeAddress` `null` uses the
/// persisted change address. `allowReemissionSpend`/`allowTokenBurn` default
/// `false` (fail-closed against accidental reward-box spend / token loss).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TxIntent {
    /// Requested outputs (≥1; validated by the handler).
    pub outputs: Vec<OutputIntent>,
    /// Miner fee in nanoErg (decimal string); `null` → `MIN_FEE`.
    #[serde(default)]
    pub fee: Option<String>,
    /// Where inputs come from (default: `auto`).
    #[serde(default)]
    pub inputs: InputSource,
    /// Where data inputs come from (default: empty `boxIds`).
    #[serde(default)]
    pub data_inputs: DataInputSource,
    /// Change address; `null` → persisted change address.
    #[serde(default)]
    pub change_address: Option<String>,
    /// Permit spending a reward box carrying the re-emission token.
    #[serde(default)]
    pub allow_reemission_spend: bool,
    /// Permit dropping (burning) a non-re-emission token surplus. RESERVED: the
    /// current builder never drops a non-re-emission token (any surplus always
    /// becomes change), so this flag has no effect yet; it gates the deferred
    /// `burn` output intent (which ships `unsupported_intent` until wired).
    #[serde(default)]
    pub allow_token_burn: bool,
}

/// `POST /api/v1/wallet/boxes/select` target — what the selection must cover.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectTarget {
    /// nanoErg the selection must cover (decimal string).
    pub nano_erg: String,
    /// Tokens the selection must cover.
    #[serde(default)]
    pub assets: Vec<WalletAssetDto>,
}

/// `POST /api/v1/wallet/boxes/select` request.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoxSelectRequest {
    /// What to cover.
    pub target: SelectTarget,
    /// Where to draw inputs from (default: `auto`).
    #[serde(default)]
    pub inputs: InputSource,
    /// Change address; `null` → persisted change address.
    #[serde(default)]
    pub change_address: Option<String>,
    /// Permit selecting a reward box carrying the re-emission token.
    #[serde(default)]
    pub allow_reemission_spend: bool,
}

/// A selected input box (lean; additive fields later).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SelectedBoxRef {
    /// 32-byte box id, hex.
    pub box_id: String,
    /// Box value, nanoErg (decimal string).
    pub value: String,
    /// Tokens the box carries.
    pub assets: Vec<WalletAssetDto>,
}

/// The real computed change of a selection/build (replaces the Scala synthetic
/// placeholder).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChangePlan {
    /// Change nanoErg (decimal string).
    pub nano_erg: String,
    /// Change tokens.
    pub assets: Vec<WalletAssetDto>,
}

/// The EIP-27 re-emission burn a selection/build incurs. Present (non-null) only
/// when the selected inputs trigger the burn; computed exactly from the selected
/// inputs via `reemission_obligation_core`, never the wallet-wide estimate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReemissionBurn {
    /// 32-byte re-emission token id, hex.
    pub token_id: String,
    /// Re-emission tokens burned (decimal string).
    pub tokens_burned: String,
    /// nanoErg routed to the pay-to-reemission contract (= `tokensBurned`).
    pub nano_erg_routed: String,
}

/// `POST /api/v1/wallet/boxes/select` response — a real dry-run plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BoxSelectResponse {
    /// Boxes the selector chose.
    pub inputs_selected: Vec<SelectedBoxRef>,
    /// The real computed change.
    pub change: ChangePlan,
    /// EIP-27 burn the selection incurs, or `null`.
    pub reemission_burn: Option<ReemissionBurn>,
    /// Wallet height the read was taken at.
    pub as_of: u32,
}

/// `POST /api/v1/wallet/transactions/build` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BuildTxResponse {
    /// The built unsigned transaction.
    pub unsigned_transaction: TxRepr,
    /// Boxes selected as inputs.
    pub inputs_selected: Vec<SelectedBoxRef>,
    /// Change outputs (real values), if any.
    pub change_outputs: Vec<ChangePlan>,
    /// Miner fee, nanoErg (decimal string).
    pub fee: String,
    /// EIP-27 burn the build incurs, or `null`.
    pub reemission_burn: Option<ReemissionBurn>,
    /// Wallet height the inputs were read at.
    pub as_of: u32,
}

/// An externally-supplied prover secret (tagged). SENSITIVE: body-only, never
/// logged (the `Debug` impl redacts the scalar). `secret` is a 32-byte big-endian
/// hex scalar for both members; the DH-tuple member adds its four compressed SEC1
/// group elements. Manual `Deserialize` for strict rejection. Deliberately NOT
/// `Serialize` — it is request-only, and deriving `Serialize` would route the raw
/// scalar straight to JSON, defeating the `Debug` redaction.
#[derive(Clone, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ExternalSecret {
    /// Discrete-log secret.
    Dlog {
        /// 32-byte big-endian hex scalar (SENSITIVE).
        secret: String,
    },
    /// Diffie-Hellman tuple secret.
    #[serde(rename_all = "camelCase")]
    DhTuple {
        /// Compressed SEC1 generator point, hex.
        g: String,
        /// Compressed SEC1 `h` point, hex.
        h: String,
        /// Compressed SEC1 `u` point, hex.
        u: String,
        /// Compressed SEC1 `v` point, hex.
        v: String,
        /// 32-byte big-endian hex scalar (SENSITIVE).
        secret: String,
    },
}

impl std::fmt::Debug for ExternalSecret {
    // Redact: an `ExternalSecret` carries raw private-key material; never let it
    // reach a log via `{:?}`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExternalSecret::Dlog { .. } => f.write_str("ExternalSecret::Dlog(<redacted>)"),
            ExternalSecret::DhTuple { .. } => f.write_str("ExternalSecret::DhTuple(<redacted>)"),
        }
    }
}

impl<'de> Deserialize<'de> for ExternalSecret {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Raw {
            #[serde(rename = "type")]
            ty: String,
            g: Option<String>,
            h: Option<String>,
            u: Option<String>,
            v: Option<String>,
            secret: Option<String>,
        }
        let r = Raw::deserialize(d)?;
        let secret = r.secret.ok_or_else(|| D::Error::missing_field("secret"))?;
        match r.ty.as_str() {
            "dlog" => {
                if r.g.is_some() || r.h.is_some() || r.u.is_some() || r.v.is_some() {
                    return Err(D::Error::custom("`dlog` takes only `secret`"));
                }
                Ok(ExternalSecret::Dlog { secret })
            }
            "dhTuple" => Ok(ExternalSecret::DhTuple {
                g: r.g.ok_or_else(|| D::Error::missing_field("g"))?,
                h: r.h.ok_or_else(|| D::Error::missing_field("h"))?,
                u: r.u.ok_or_else(|| D::Error::missing_field("u"))?,
                v: r.v.ok_or_else(|| D::Error::missing_field("v"))?,
                secret,
            }),
            other => Err(D::Error::unknown_variant(other, &["dlog", "dhTuple"])),
        }
    }
}

/// `POST /api/v1/wallet/transactions/sign` request. Signs a caller-supplied
/// unsigned tx. Runs no `Locked` precondition: it succeeds while locked when
/// `externalSecrets` cover every input; otherwise the prover's missing-secret →
/// `missing_secret(422)`. The EIP-27 self-verify gate runs before emitting.
#[derive(Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignTxRequest {
    /// The unsigned transaction to sign.
    pub unsigned_transaction: TxRepr,
    /// Externally-supplied prover secrets (default `[]`).
    #[serde(default)]
    pub external_secrets: Vec<ExternalSecret>,
}

// `SignTxRequest` carries `ExternalSecret` (secret material); redact under `{:?}`.
impl std::fmt::Debug for SignTxRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignTxRequest")
            .field("unsigned_transaction", &self.unsigned_transaction)
            .field("external_secrets", &self.external_secrets.len())
            .finish()
    }
}

/// `POST /api/v1/wallet/transactions/sign` response. `Cache-Control: no-store`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SignTxResponse {
    /// The signed transaction.
    pub signed_transaction: TxRepr,
    /// 32-byte transaction id, hex.
    pub tx_id: String,
}

/// `POST /api/v1/wallet/transactions/send` request (tagged). `intent` builds +
/// signs with the wallet's own secrets (needs unlock); `signed` submits a
/// caller-supplied signed tx (no unlock). Manual `Deserialize` for strictness.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SendTxRequest {
    /// Build + sign + send from an intent.
    Intent {
        /// The transaction intent.
        intent: TxIntent,
    },
    /// Send a pre-signed transaction.
    #[serde(rename_all = "camelCase")]
    Signed {
        /// The signed transaction.
        signed_transaction: TxRepr,
    },
}

impl<'de> Deserialize<'de> for SendTxRequest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Raw {
            #[serde(rename = "type")]
            ty: String,
            intent: Option<TxIntent>,
            signed_transaction: Option<TxRepr>,
        }
        let r = Raw::deserialize(d)?;
        match r.ty.as_str() {
            "intent" => {
                if r.signed_transaction.is_some() {
                    return Err(D::Error::custom(
                        "`intent` does not take `signedTransaction`",
                    ));
                }
                Ok(SendTxRequest::Intent {
                    intent: r.intent.ok_or_else(|| D::Error::missing_field("intent"))?,
                })
            }
            "signed" => {
                if r.intent.is_some() {
                    return Err(D::Error::custom("`signed` does not take `intent`"));
                }
                Ok(SendTxRequest::Signed {
                    signed_transaction: r
                        .signed_transaction
                        .ok_or_else(|| D::Error::missing_field("signedTransaction"))?,
                })
            }
            other => Err(D::Error::unknown_variant(other, &["intent", "signed"])),
        }
    }
}

/// `POST /api/v1/wallet/transactions/send` response. `accepted` is `true` both on
/// a fresh submission and on an idempotent re-send of an already-known tx.
/// `transaction` is the lean summary only when a confirmed wallet row exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SendTxResponse {
    /// 32-byte transaction id, hex.
    pub tx_id: String,
    /// Whether the tx is accepted (fresh submit or known-tx idempotent re-send).
    pub accepted: bool,
    /// The wallet tx summary when a confirmed row exists, else `null`.
    pub transaction: Option<WalletTransactionSummary>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn sample(reemission: Option<ReemissionInfoDto>) -> WalletBalanceDto {
        WalletBalanceDto {
            height: 1_811_103,
            nano_erg: NanoErgBreakdownDto {
                confirmed: "45000000000".to_string(),
                available: "9000000000".to_string(),
                reserved: "36000000000".to_string(),
                immature: "3000000000".to_string(),
            },
            assets: vec![WalletAssetDto {
                token_id: "ab".repeat(32),
                amount: "1000".to_string(),
            }],
            reemission,
            unconfirmed: None,
        }
    }

    // ----- round-trips -----

    #[test]
    fn balance_dto_round_trips() {
        let original = sample(Some(ReemissionInfoDto {
            token_id: "cd".repeat(32),
            reserved_token_amount: "36000000000".to_string(),
            reserved_box_count: 3,
            reserved_exceeds_confirmed: false,
        }));
        let json = serde_json::to_string(&original).unwrap();
        let back: WalletBalanceDto = serde_json::from_str(&json).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn amounts_serialize_as_strings_never_numbers() {
        // Money + token amounts MUST be JSON strings (no precision loss above 2^53).
        let v = serde_json::to_value(sample(None)).unwrap();
        assert!(v["nanoErg"]["confirmed"].is_string());
        assert!(v["nanoErg"]["available"].is_string());
        assert!(v["nanoErg"]["reserved"].is_string());
        assert!(v["nanoErg"]["immature"].is_string());
        assert!(v["assets"][0]["amount"].is_string());
    }

    #[test]
    fn null_fields_serialize_as_null_not_omitted() {
        // `reemission`/`unconfirmed` are stable, present-as-null fields.
        let v = serde_json::to_value(sample(None)).unwrap();
        assert!(v.get("reemission").is_some_and(serde_json::Value::is_null));
        assert!(v.get("unconfirmed").is_some_and(serde_json::Value::is_null));
    }

    #[test]
    fn scope_is_tagged_single_hop() {
        let v = serde_json::to_value(ScopeDto::SingleHop).unwrap();
        assert_eq!(v, serde_json::json!({ "type": "singleHop" }));
    }

    #[test]
    fn unknown_field_is_rejected_on_assets() {
        // WalletAssetDto round-trips; an unknown discriminator/extra is not silently
        // accepted by the tagged scope union.
        let bad = serde_json::json!({ "type": "doubleHop" });
        assert!(serde_json::from_value::<ScopeDto>(bad).is_err());
    }

    // ----- tagged-union wire shapes (per-variant fields must be camelCase) -----

    #[test]
    fn box_status_wire_shapes() {
        assert_eq!(
            serde_json::to_value(BoxStatusDto::Confirmed).unwrap(),
            serde_json::json!({ "type": "confirmed" }),
        );
        assert_eq!(
            serde_json::to_value(BoxStatusDto::Immature {
                matures_at_height: 720
            })
            .unwrap(),
            serde_json::json!({ "type": "immature", "maturesAtHeight": 720 }),
        );
        assert_eq!(
            serde_json::to_value(BoxStatusDto::Spent {
                tx_id: "ab".to_string(),
                height: 5
            })
            .unwrap(),
            serde_json::json!({ "type": "spent", "txId": "ab", "height": 5 }),
        );
    }

    #[test]
    fn provenance_wire_shapes() {
        assert_eq!(
            serde_json::to_value(BoxProvenanceDto::MinerReward).unwrap(),
            serde_json::json!({ "type": "minerReward" }),
        );
        assert_eq!(
            serde_json::to_value(BoxProvenanceDto::Custom { scan_id: 9 }).unwrap(),
            serde_json::json!({ "type": "custom", "scanId": 9 }),
        );
    }

    #[test]
    fn network_and_rescan_wire_shapes() {
        assert_eq!(
            serde_json::to_value(NetworkDto::Mainnet).unwrap(),
            serde_json::json!({ "type": "mainnet" }),
        );
        assert_eq!(
            serde_json::to_value(RescanStateDto::Idle).unwrap(),
            serde_json::json!({ "type": "idle" }),
        );
        assert_eq!(
            serde_json::to_value(RescanStateDto::Running { from_height: 100 }).unwrap(),
            serde_json::json!({ "type": "running", "fromHeight": 100 }),
        );
        assert_eq!(
            serde_json::to_value(RescanStateDto::Unavailable {
                detail: "pruned".to_string()
            })
            .unwrap(),
            serde_json::json!({ "type": "unavailable", "detail": "pruned" }),
        );
    }

    #[test]
    fn page_envelopes_carry_as_of() {
        let v = serde_json::to_value(AddressPage {
            items: vec![],
            total: 0,
            as_of: 42,
        })
        .unwrap();
        assert_eq!(v["asOf"], 42);
        assert_eq!(v["total"], 0);
    }

    #[test]
    fn box_summary_round_trips() {
        let b = WalletBoxSummary {
            box_id: "aa".repeat(32),
            value: "1000".to_string(),
            assets: vec![],
            creation_tx_id: "bb".repeat(32),
            creation_output_index: 2,
            creation_height: 5,
            status: BoxStatusDto::Confirmed,
            provenance: BoxProvenanceDto::Owned,
        };
        let back: WalletBoxSummary =
            serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
        assert_eq!(b, back);
        // value is a string, not a number.
        assert!(serde_json::to_value(&b).unwrap()["value"].is_string());
    }

    #[test]
    fn status_dto_round_trips() {
        let s = WalletStatusDto {
            initialized: true,
            locked: false,
            scan_height: 10,
            tip_height: 12,
            change_address: None,
            network: NetworkDto::Mainnet,
            eip27_active: true,
            rescan: RescanStateDto::Idle,
            scan_invalidated: false,
        };
        let back: WalletStatusDto =
            serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(s, back);
        // changeAddress serializes as null (present, not omitted).
        let v = serde_json::to_value(&s).unwrap();
        assert!(v
            .get("changeAddress")
            .is_some_and(serde_json::Value::is_null));
    }

    #[test]
    fn lifecycle_dto_shapes() {
        // matched is a plain bool result.
        assert_eq!(
            serde_json::to_value(MnemonicVerifyResult { matched: true }).unwrap(),
            serde_json::json!({ "matched": true }),
        );
        // UnlockRequest rejects unknown fields (deny_unknown_fields).
        assert!(serde_json::from_str::<UnlockRequest>(r#"{"pass":"x"}"#).is_ok());
        assert!(serde_json::from_str::<UnlockRequest>(r#"{"pass":"x","extra":1}"#).is_err());
        // mnemonicPass defaults to "".
        let r: MnemonicVerifyRequest = serde_json::from_str(r#"{"mnemonic":"a b c"}"#).unwrap();
        assert_eq!(r.mnemonic_pass, "");
    }

    #[test]
    fn init_restore_dto_shapes() {
        // InitRequest: strength defaults to 24; unknown field rejected.
        let r: InitRequest = serde_json::from_str(r#"{"pass":"x"}"#).unwrap();
        assert_eq!(r.strength, 24);
        assert!(serde_json::from_str::<InitRequest>(r#"{"pass":"x","bogus":1}"#).is_err());
        // RestoreRequest requires `derivation` (no default — kills the legacy trap).
        assert!(serde_json::from_str::<RestoreRequest>(r#"{"mnemonic":"a","pass":"x"}"#).is_err());
        let rr: RestoreRequest =
            serde_json::from_str(r#"{"mnemonic":"a","pass":"x","derivation":{"type":"eip3"}}"#)
                .unwrap();
        assert!(matches!(rr.derivation, DerivationMode::Eip3));
        let rr2: RestoreRequest = serde_json::from_str(
            r#"{"mnemonic":"a","pass":"x","derivation":{"type":"legacyPre1627"}}"#,
        )
        .unwrap();
        assert!(matches!(rr2.derivation, DerivationMode::LegacyPre1627));
    }

    #[test]
    fn keys_dto_shapes() {
        // DeriveKeyRequest is tagged next|path.
        let n: DeriveKeyRequest = serde_json::from_str(r#"{"type":"next"}"#).unwrap();
        assert!(matches!(n, DeriveKeyRequest::Next));
        let p: DeriveKeyRequest =
            serde_json::from_str(r#"{"type":"path","derivationPath":"m/44'/429'/0'/0/3"}"#)
                .unwrap();
        assert!(matches!(p, DeriveKeyRequest::Path { .. }));
        // ChangeAddressDto serializes null (present, not omitted).
        let v = serde_json::to_value(ChangeAddressDto { address: None }).unwrap();
        assert!(v.get("address").is_some_and(serde_json::Value::is_null));
        // RescanRequest defaults fromHeight=0; rejects unknown fields.
        let r: RescanRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(r.from_height, 0);
        assert!(serde_json::from_str::<RescanRequest>(r#"{"bogus":1}"#).is_err());
        // Tagged request enums reject unknown sibling fields (manual Deserialize).
        assert!(serde_json::from_str::<DeriveKeyRequest>(r#"{"type":"next","bogus":1}"#).is_err());
        assert!(serde_json::from_str::<DerivationMode>(r#"{"type":"eip3","bogus":1}"#).is_err());
        // `next` rejects a stray derivationPath; `path` requires it.
        assert!(serde_json::from_str::<DeriveKeyRequest>(
            r#"{"type":"next","derivationPath":"m/0"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<DeriveKeyRequest>(r#"{"type":"path"}"#).is_err());
        // Unknown discriminator rejected.
        assert!(serde_json::from_str::<DerivationMode>(r#"{"type":"bogus"}"#).is_err());
    }

    // ----- transaction construction DTOs (§3.5) -----

    #[test]
    fn tx_repr_round_trips_and_is_tagged() {
        let t = TxRepr::from_bytes(&[0xde, 0xad, 0xbe, 0xef]);
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v, serde_json::json!({"type": "bytes", "bytes": "deadbeef"}));
        let back: TxRepr = serde_json::from_value(v).unwrap();
        assert_eq!(t, back);
        assert_eq!(back.bytes_hex(), "deadbeef");
        // Unknown discriminator + unknown sibling field rejected.
        assert!(serde_json::from_str::<TxRepr>(r#"{"type":"json"}"#).is_err());
        assert!(serde_json::from_str::<TxRepr>(r#"{"type":"bytes","bytes":"00","x":1}"#).is_err());
        assert!(serde_json::from_str::<TxRepr>(r#"{"type":"bytes"}"#).is_err());
    }

    #[test]
    fn output_intent_tagged_and_strict() {
        // payment with assets parses; fields are camelCase.
        let p: OutputIntent = serde_json::from_str(
            r#"{"type":"payment","address":"9xyz","value":"1000000000","assets":[]}"#,
        )
        .unwrap();
        assert!(matches!(p, OutputIntent::Payment { .. }));
        // burn requires ≥1 asset.
        assert!(serde_json::from_str::<OutputIntent>(r#"{"type":"burn","assets":[]}"#).is_err());
        let b: OutputIntent =
            serde_json::from_str(r#"{"type":"burn","assets":[{"tokenId":"ab","amount":"5"}]}"#)
                .unwrap();
        assert!(matches!(b, OutputIntent::Burn { .. }));
        // Cross-variant field leakage rejected: payment with mint's `amount`.
        assert!(serde_json::from_str::<OutputIntent>(
            r#"{"type":"payment","address":"9x","value":"1","amount":"2"}"#
        )
        .is_err());
        // Unknown field + unknown variant rejected.
        assert!(serde_json::from_str::<OutputIntent>(
            r#"{"type":"payment","address":"9x","value":"1","bogus":1}"#
        )
        .is_err());
        assert!(serde_json::from_str::<OutputIntent>(r#"{"type":"swap"}"#).is_err());
    }

    #[test]
    fn input_source_defaults_to_auto_and_is_strict() {
        // Default (field absent in TxIntent) is auto.
        assert!(matches!(InputSource::default(), InputSource::Auto { .. }));
        let a: InputSource = serde_json::from_str(r#"{"type":"auto"}"#).unwrap();
        assert!(matches!(
            a,
            InputSource::Auto {
                min_confirmations: 0,
                ..
            }
        ));
        let ids: InputSource =
            serde_json::from_str(r#"{"type":"boxIds","boxIds":["ab"]}"#).unwrap();
        assert!(matches!(ids, InputSource::BoxIds { .. }));
        // `auto` must not carry boxIds; `boxIds` must not carry minConfirmations.
        assert!(serde_json::from_str::<InputSource>(r#"{"type":"auto","boxIds":["ab"]}"#).is_err());
        assert!(serde_json::from_str::<InputSource>(
            r#"{"type":"boxIds","boxIds":["ab"],"minConfirmations":1}"#
        )
        .is_err());
        // DataInputSource default is empty boxIds.
        assert!(matches!(
            DataInputSource::default(),
            DataInputSource::BoxIds { .. }
        ));
    }

    #[test]
    fn tx_intent_defaults_and_strictness() {
        // Minimal intent: outputs only; inputs default auto, flags default false.
        let i: TxIntent = serde_json::from_str(
            r#"{"outputs":[{"type":"payment","address":"9x","value":"1000000000"}]}"#,
        )
        .unwrap();
        assert!(matches!(i.inputs, InputSource::Auto { .. }));
        assert!(!i.allow_reemission_spend);
        assert!(!i.allow_token_burn);
        assert!(i.fee.is_none());
        assert!(i.change_address.is_none());
        // Unknown top-level field rejected.
        assert!(serde_json::from_str::<TxIntent>(r#"{"outputs":[],"bogus":1}"#).is_err());
    }

    #[test]
    fn select_and_build_response_shapes_use_decimal_strings() {
        let resp = BoxSelectResponse {
            inputs_selected: vec![SelectedBoxRef {
                box_id: "ab".repeat(32),
                value: "15000000000".to_string(),
                assets: vec![],
            }],
            change: ChangePlan {
                nano_erg: "1999000000".to_string(),
                assets: vec![],
            },
            reemission_burn: Some(ReemissionBurn {
                token_id: "cd".repeat(32),
                tokens_burned: "12000000000".to_string(),
                nano_erg_routed: "12000000000".to_string(),
            }),
            as_of: 1_811_103,
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert!(v["inputsSelected"][0]["value"].is_string());
        assert!(v["change"]["nanoErg"].is_string());
        assert!(v["reemissionBurn"]["nanoErgRouted"].is_string());
        let back: BoxSelectResponse = serde_json::from_value(v).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn external_secret_tagged_strict_and_redacts() {
        let d: ExternalSecret = serde_json::from_str(r#"{"type":"dlog","secret":"ab"}"#).unwrap();
        assert!(matches!(d, ExternalSecret::Dlog { .. }));
        // Debug must NOT leak the secret material.
        assert_eq!(format!("{d:?}"), "ExternalSecret::Dlog(<redacted>)");
        let dh: ExternalSecret = serde_json::from_str(
            r#"{"type":"dhTuple","g":"01","h":"02","u":"03","v":"04","secret":"ab"}"#,
        )
        .unwrap();
        assert!(matches!(dh, ExternalSecret::DhTuple { .. }));
        // `dlog` may not carry DH-tuple fields; `secret` is required; unknown variant rejected.
        assert!(serde_json::from_str::<ExternalSecret>(
            r#"{"type":"dlog","secret":"ab","g":"01"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ExternalSecret>(r#"{"type":"dlog"}"#).is_err());
        assert!(
            serde_json::from_str::<ExternalSecret>(r#"{"type":"schnorr","secret":"ab"}"#).is_err()
        );
    }

    #[test]
    fn sign_request_strict_and_defaults_externals() {
        let r: SignTxRequest =
            serde_json::from_str(r#"{"unsignedTransaction":{"type":"bytes","bytes":"00"}}"#)
                .unwrap();
        assert!(r.external_secrets.is_empty());
        // Unknown field rejected.
        assert!(serde_json::from_str::<SignTxRequest>(
            r#"{"unsignedTransaction":{"type":"bytes","bytes":"00"},"bogus":1}"#
        )
        .is_err());
    }

    #[test]
    fn send_request_tagged_intent_or_signed() {
        let s: SendTxRequest = serde_json::from_str(
            r#"{"type":"signed","signedTransaction":{"type":"bytes","bytes":"00"}}"#,
        )
        .unwrap();
        assert!(matches!(s, SendTxRequest::Signed { .. }));
        let i: SendTxRequest = serde_json::from_str(
            r#"{"type":"intent","intent":{"outputs":[{"type":"payment","address":"9x","value":"1"}]}}"#,
        )
        .unwrap();
        assert!(matches!(i, SendTxRequest::Intent { .. }));
        // Cross-variant field + unknown variant rejected.
        assert!(serde_json::from_str::<SendTxRequest>(
            r#"{"type":"signed","intent":{"outputs":[]},"signedTransaction":{"type":"bytes","bytes":"00"}}"#
        )
        .is_err());
        assert!(serde_json::from_str::<SendTxRequest>(r#"{"type":"broadcast"}"#).is_err());
    }

    #[test]
    fn send_response_shape() {
        let v = serde_json::to_value(SendTxResponse {
            tx_id: "ab".repeat(32),
            accepted: true,
            transaction: None,
        })
        .unwrap();
        assert_eq!(v["accepted"], serde_json::json!(true));
        assert!(v.get("transaction").is_some_and(serde_json::Value::is_null));
    }
}
