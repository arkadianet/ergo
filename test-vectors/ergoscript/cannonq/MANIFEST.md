# CannonQ Sigma-Rust ErgoScript Corpus

**License**: CC0 1.0 Universal (Public Domain)

**Source Repository**: `cannonQ/sigma-rust` (branch: ergoscript-compiler-working)

**Vendoring Date**: 2026-07-03

## Manifest

This directory contains two categories of ErgoScript source contracts:

### 1. Significant-15 Fixtures (`significant15/`)

Fifteen real-world, publicly audited protocol contracts from the Ergo ecosystem,
used as end-to-end test fixtures for compiler correctness and parity.

| Filename | Protocol | Upstream Provenance | Upstream Commit |
|---|---|---|---|
| `chaincash_reserve.es` | ChainCash reserve | `cannonQ/chaincash @ contracts/onchain/reserve.es` | b942d125 |
| `dexy_bank_full.es` | Dexy/USE bank | `/tmp/dexy-stable-pr/contracts/bank/bank.es` (full upstream keystone) | — |
| `duckpools_child_interest.es` | DuckPools Lending | `cannonQ/lend-protocol-contracts @ contracts/pools/RSN-POOL/childInterest.md` | 63b49a05 |
| `ergomixer_fullmix.es` | ErgoMixer | `cannonQ/ergoMixBack @ mixer/app/mixinterface/TokenErgoMix.scala :: fullMixScript` | 6f1241d9 |
| `ergoraffle_active.es` | ErgoRaffle | `cannonQ/raffle-backend @ RaffleContract.scala :: raffleActiveScript` | cc882e4b |
| `gluon_box_guard.es` | Gluon Gold | `cannonQ/Gluon-Ergo-Contracts @ GluonWBoxGuardScript.es` | 3e71f9f4 |
| `oracle_refresh.es` | Oracle Pool v2 | `kettlebell/eips @ eip-0023/contracts/refresh_contract.es` | — |
| `paideia_stake_state.es` | Paideia DAO | `cannonQ/paideia-contracts @ staking/ergoscript/latest/stakeState.es` | 55961530 |
| `phoenix_hodlerg_bank_full.es` | Phoenix HodlERG | Full keystone, 157 lines | — |
| `rosen_event_trigger.es` | Rosen Bridge | `cannonQ/contract @ src/main/scala/rosen/bridge/scripts/EventTrigger.es` | 0cda684a |
| `sigmao_option.es` | SigmaO | `~/working-files/p2p-options-contracts/contracts/Option-SigmaO.es`, 253 lines | — |
| `sigmausd_bank.es` | SigmaUSD/AgeUSD | `cannonQ/Djed-Ergo @ ageusd-smart-contracts/v0.4/AgeUSD.scala :: bankScript` | e810b195 |
| `skyharbor_v1_erg.es` | SkyHarbor | `V1_ErgEditsAndOffersV1.md` script block (ERG-denominated) | — |
| `spectrum_n2t_pool.es` | Spectrum DEX | `cannonQ/ergo-dex @ contracts/amm/cfmm/v1/n2t/Pool.sc` | 8fe94e1f |
| `spectrum_t2t_pool.es` | Spectrum DEX | `cannonQ/ergo-dex @ contracts/amm/cfmm/v1/t2t/Pool.sc` | 8fe94e1f |

### 2. Ecosystem Corpus (`ecosystem/`)

Fourteen additional contracts extracted from the CannonQ fork's compiler test suite
(`src/compiler.rs::ecosystem_corpus()`), providing coverage of SigmaFi, SkyHarbor,
DuckPools, and Lilium protocols.

| Filename | Protocol | Source Line Range | Type |
|---|---|---|---|
| `sigmafi_bond_erg.es` | SigmaFi | 6918–6958 | lending bond (ERG collateral) |
| `sigmafi_bond_token.es` | SigmaFi | 6960–7003 | lending bond (token collateral) |
| `sigmafi_exp_bond_erg.es` | SigmaFi | 7005–7053 | exponential lending bond (ERG) |
| `sigmafi_open_order_erg.es` | SigmaFi | 7055–7146 | loan origination order (ERG) |
| `sigmafi_open_order_token.es` | SigmaFi | 7147–7249 | loan origination order (token) |
| `skyharbor_sigusd_v1.es` | SkyHarbor | 7250–7290 | NFT sales with royalties |
| `duckpools_erg_repayment.es` | DuckPools | 7291–7329 | loan repayment verification |
| `duckpools_erg_parent_interest.es` | DuckPools | 7425–7519 | interest rate aggregation (parent) |
| `duckpools_erg_proxy_borrow.es` | DuckPools | 7520–7605 | borrow request proxy |
| `lilium_collection_issuer.es` | Lilium | 7606–7618 | NFT collection issuer |
| `lilium_collection_issuance.es` | Lilium | 7619–7632 | NFT issuance state transition |
| `lilium_premint_issuer.es` | Lilium | 7633–7654 | pre-mint contract |
| `lilium_whitelist_issuer.es` | Lilium | 7655–7676 | whitelist minting |
| `lilium_sale_lp.es` | Lilium | 7677–7756 | NFT sale/launch pad |

**Note**: DuckPools ERG InterestRate (7330–7424) is intentionally skipped in the source
due to deeply nested BigInt polynomial expressions causing CSE stack overflow.

---

## Critical Caveats

1. **Sources Only**: These files contain **source text only**. NO byte-expected hex values are
   included. The original cannonQ fork extracted these contracts with byte-match expectations
   pinned against node **v6.1.2**. Our oracles use **v6.0.2** — bytes must be **re-derived
   by our own oracles** before used in parity vectors or test assertions.

2. **Intended Consumers**: These sources are intended for:
   - M3 (Typer) — corpus for type-checking validation and comparison with Scala
   - M4+ (CSE/Optimizer) — inputs to common subexpression elimination and code quality testing
   - **Not yet wired into any test suite** — M3 will integrate them.

3. **License**: All contracts are CC0-licensed or contributed by their authors under
   compatible licenses (confirmed via cannonQ fork's MANIFEST). No attribution required.

4. **Extraction Methodology**: Ecosystem contracts were extracted via raw string literal
   unescaping from `src/compiler.rs`. Newlines and whitespace preserved as-is from source.

---

## Usage

For test writers consuming this corpus:

- **Significant-15**: expected to compile byte-for-byte identically to reference Scala
  (after re-derivation against our oracle node)
- **Ecosystem**: expected to type-check and compile without errors; byte parity TBD

See `dev-docs/m2-recon/m2-harvest.md` for detailed context.
