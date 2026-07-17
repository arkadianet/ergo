//! DTOs for `POST /api/v1/wallet/rewards/retrieve` (EIP-27-correct
//! matured mining-reward sweep).

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// ----- retrieve matured mining rewards (EIP-27-correct sweep) -----

/// `POST /api/v1/wallet/rewards/retrieve` request. Sweeps all matured
/// (Confirmed) miner-reward boxes into one P2PK output, burning the re-emission
/// token and routing its ERG to pay-to-reemission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetrieveRewardsRequest {
    /// Destination for the swept ERG + non-re-emission tokens. MUST be a tracked
    /// wallet address (the sweep routes funds there as change). `null`/omitted →
    /// the wallet's current change address.
    #[serde(default)]
    pub destination: Option<String>,
    /// Miner fee in nanoErg (decimal string). `null`/omitted → the wallet default
    /// minimum fee.
    #[serde(default)]
    pub fee: Option<String>,
    /// Exact reward box ids (hex) to sweep — PIN the input set returned by a
    /// preview so execute spends the same boxes the user confirmed. When omitted,
    /// the server selects the oldest matured reward boxes (up to the per-sweep
    /// cap). Every id MUST still be a matured, unspent miner-reward box or the
    /// request is rejected.
    #[serde(default)]
    pub box_ids: Option<Vec<String>>,
    /// `true` → build + report the breakdown WITHOUT signing/submitting (preview).
    /// `false` → execute: sign, self-verify (incl. EIP-27), and submit. Unknown
    /// keys are rejected (`deny_unknown_fields`) so a misspelled `dryRun` cannot
    /// silently execute a sweep the caller intended only to preview.
    #[serde(default)]
    pub dry_run: bool,
}

/// A non-re-emission token carried through a sweep to the destination output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SweptTokenDto {
    /// 32-byte token id, hex.
    pub token_id: String,
    /// Token amount (decimal string).
    pub amount: String,
}

/// `POST /api/v1/wallet/rewards/retrieve` response (preview or executed). All
/// nanoErg fields are decimal strings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveRewardsResultDto {
    /// Matured reward boxes swept.
    pub box_count: u32,
    /// The exact reward box ids (hex) this sweep spends. Pass these back as
    /// `boxIds` on the execute call to pin the input set the preview showed.
    pub box_ids: Vec<String>,
    /// Matured reward boxes NOT included this round (over the per-sweep cap). Run
    /// the sweep again to retrieve them. `0` when everything matured was swept.
    pub remaining: u32,
    /// Gross matured ERG across those boxes.
    pub gross_erg: String,
    /// nanoErg routed to the pay-to-reemission contract (= re-emission tokens burned).
    pub reemission_paid: String,
    /// Miner fee.
    pub fee: String,
    /// Net ERG delivered to the destination (`gross − fee − reemission`).
    pub net_to_destination: String,
    /// Non-re-emission tokens carried to the destination output.
    pub other_tokens: Vec<SweptTokenDto>,
    /// Destination address the sweep pays to.
    pub destination: String,
    /// Submitted transaction id, or `null` on a dry-run (preview).
    pub tx_id: Option<String>,
}
