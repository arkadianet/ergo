//! Boot-time configuration of the wallet engine.

/// Network + operator-flag + EIP-27 + admission-limit config supplied at
/// boot by the embedding process.
#[derive(Debug, Clone)]
pub struct WalletEngineConfig {
    pub network: ergo_ser::address::NetworkPrefix,
    /// `[wallet] expose_private_keys`: gates `POST /wallet/getPrivateKey`.
    /// `false` (default) returns 403 Forbidden; `true` allows the
    /// route to return the derived secret scalar.
    pub expose_private_keys: bool,
    /// EIP-27 re-emission rule inputs for this network (`None` off EIP-27
    /// nets, e.g. testnet, where `ChainSpec::reemission` is `None`). Built at
    /// boot from `build_reemission_rules(&config.chain_spec)` — the same source
    /// the block/mempool validator uses, so the wallet's re-emission reserve
    /// estimate and burn-aware builder share one trigger/token-id/floor with
    /// consensus. When `None`, the wallet surfaces no re-emission reserve.
    pub reemission: Option<ergo_validation::ReemissionRuleInputs>,
    /// `[mempool] min_relay_fee_nano_erg` — the local relay-fee floor. A tx built
    /// below it is rejected by submit before validation, so fee defaults derive
    /// from `max(MIN_FEE, this)` and overrides below it are rejected (keeps the
    /// reward-sweep preview/execute contract honest under non-default configs).
    pub min_relay_fee_nano_erg: u64,
    /// `[mempool] max_tx_size_bytes` — the local admission tx-size cap. The
    /// reward sweep bounds its built tx against this so a preview can't approve a
    /// sweep the submit path rejects as `too_big` under a lowered config.
    pub max_tx_size_bytes: usize,
}
