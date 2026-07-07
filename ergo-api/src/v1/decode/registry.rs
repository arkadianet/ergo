//! The protocol registry — the extensible matcher table that turns a box into a
//! recognized protocol (`v1-api-design.md` §4.3; semantic-decode fragment §2).
//!
//! A box is matched by one of three keys, tried in priority order:
//! 1. an **identifying token** (a singleton NFT the box holds — the most robust
//!    key: it survives contract-version script changes);
//! 2. a **template hash** (`template_hash_from_bytes` — the contract *shape*,
//!    independent of embedded constants; matches every instance of a
//!    parameterized contract);
//! 3. a **tree hash** (`tree_hash_from_bytes` — exact whole-tree match).
//!
//! Adding a protocol = append one [`ProtocolEntry`] with its matchers (+ a
//! family decoder + a `test-vectors/decode/` oracle). No route or envelope
//! change. **Honesty rule:** an entry is only marked `decodable` when it has a
//! verified matcher key AND a real family decoder. Protocols whose exact
//! register/token layout is not yet verified from source are registered as
//! discoverable stubs (`matchers: &[]`, `decodable: false`) — they appear in
//! `GET /api/v1/protocols` for roadmap visibility but never falsely match a box
//! or emit fabricated state.

/// Which key a matcher compares against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    /// The box holds a known singleton NFT (`token_id`).
    IdentifyingToken,
    /// `template_hash_from_bytes(ergo_tree)` — contract shape.
    TemplateHash,
    /// `tree_hash_from_bytes(ergo_tree)` — exact whole tree.
    TreeHash,
}

impl MatchKind {
    /// The lowercase wire spelling surfaced as `matched_by`.
    pub fn wire(self) -> &'static str {
        match self {
            MatchKind::IdentifyingToken => "identifying_token",
            MatchKind::TemplateHash => "template_hash",
            MatchKind::TreeHash => "tree_hash",
        }
    }
}

/// The protocol family — governs which decoded-`state` schema is emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolFamily {
    Bank,
    AmmPool,
    Lending,
    Rent,
    Insurance,
    OptionContract,
}

impl ProtocolFamily {
    /// The lowercase wire spelling (`family`).
    pub fn wire(self) -> &'static str {
        match self {
            ProtocolFamily::Bank => "bank",
            ProtocolFamily::AmmPool => "amm_pool",
            ProtocolFamily::Lending => "lending",
            ProtocolFamily::Rent => "rent",
            ProtocolFamily::Insurance => "insurance",
            ProtocolFamily::OptionContract => "option",
        }
    }
}

/// Which family renderer produces the `state` object for a matched box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderId {
    /// The SigmaUSD / AgeUSD bank box (register + token layout verified).
    SigmaUsdBank,
}

/// One matcher rule: a key of `kind`, the `box_role` it identifies, and the
/// family decoder that renders its state.
#[derive(Debug, Clone, Copy)]
pub struct ContractMatcher {
    pub kind: MatchKind,
    /// Unprefixed lowercase hex — a `token_id`, `template_hash`, or `tree_hash`.
    pub key: &'static str,
    pub box_role: &'static str,
    pub decoder: DecoderId,
}

/// One registered protocol — a stable slug, a family, and its matcher set.
#[derive(Debug, Clone, Copy)]
pub struct ProtocolEntry {
    /// Stable slug (the glossary name): `sigmausd`, `spectrum`, …
    pub id: &'static str,
    pub name: &'static str,
    pub family: ProtocolFamily,
    pub version: &'static str,
    pub matchers: &'static [ContractMatcher],
    pub reference: &'static str,
    /// `true` iff this protocol has a verified matcher AND a real decoder.
    /// `false` for discoverable stubs (layout not yet verified from source).
    pub decodable: bool,
    /// Honest status note — spells out what "recognized" means for a stub.
    pub note: &'static str,
}

// ----- verified matcher keys (grounded 2026-07 vs mainnet token metadata) ----

/// SigmaUSD v2 bank singleton NFT — the identifying token of the bank box.
const SIGUSD_V2_BANK_NFT: &str = "7d672d1def471720ca5b1dd6a56b48a83db78f5510c2a48800a5e2588f43c9e5";
/// SigmaUSD v2 stablecoin (SigUSD) token id.
pub const SIGUSD_V2_SC_TOKEN: &str =
    "03faf2cb329f2e90d6d23b58d91bbb6c046aa143261cc21f52fbe2824bfcbf04";
/// SigmaUSD v2 reservecoin (SigRSV) token id.
pub const SIGUSD_V2_RC_TOKEN: &str =
    "003bd19d0187117f130b62e1bcab0939929ff5c7709f843c5c4dd158949285d0";

const SIGUSD_MATCHERS: &[ContractMatcher] = &[ContractMatcher {
    kind: MatchKind::IdentifyingToken,
    key: SIGUSD_V2_BANK_NFT,
    box_role: "bank",
    decoder: DecoderId::SigmaUsdBank,
}];

/// The static registry. Order is stable (it is the `GET /api/v1/protocols`
/// listing order). SigmaUSD is fully decodable; the rest are discoverable
/// stubs until their layouts are verified + oracle-tested.
pub static REGISTRY: &[ProtocolEntry] = &[
    ProtocolEntry {
        id: "sigmausd",
        name: "SigmaUSD",
        family: ProtocolFamily::Bank,
        version: "v2",
        matchers: SIGUSD_MATCHERS,
        reference: "https://sigmausd.io",
        decodable: true,
        note: "bank reserve + circulating counts decoded from value/R4/R5; \
               oracle-rate-derived prices are intentionally omitted (they \
               require the ERG/USD oracle-pool data-input, not a single box)",
    },
    ProtocolEntry {
        id: "spectrum",
        name: "Spectrum Finance",
        family: ProtocolFamily::AmmPool,
        version: "v1",
        matchers: &[],
        reference: "https://spectrum.fi",
        decodable: false,
        note: "recognized; full AMM-pool decode TODO (pool template hashes + \
               reserve/LP register layout not yet verified from source)",
    },
    ProtocolEntry {
        id: "dexy",
        name: "Dexy",
        family: ProtocolFamily::Bank,
        version: "v1",
        matchers: &[],
        reference: "https://github.com/kushti/dexy",
        decodable: false,
        note: "recognized; full bank/LP decode TODO (bank NFT + register \
               layout not yet verified from source)",
    },
    ProtocolEntry {
        id: "duckpools",
        name: "Duckpools",
        family: ProtocolFamily::Lending,
        version: "v1",
        matchers: &[],
        reference: "https://duckpools.io",
        decodable: false,
        note: "recognized; full lending-pool decode TODO (pool token + \
               register layout not yet verified from source)",
    },
    ProtocolEntry {
        id: "rent",
        name: "Storage Rent Collector",
        family: ProtocolFamily::Rent,
        version: "v1",
        matchers: &[],
        reference: "dev-docs/demurrage",
        decodable: false,
        note: "recognized; rent-maturity decode TODO (reuse the storage-rent \
               math surface so numbers agree with /state/storage-rent/*)",
    },
    ProtocolEntry {
        id: "hillberger",
        name: "Hillberger Capital",
        family: ProtocolFamily::Insurance,
        version: "v1",
        matchers: &[],
        reference: "internal",
        decodable: false,
        note: "recognized; policy/option decode TODO (layouts come from the \
               contracts-first repo, not verified here)",
    },
];

/// The outcome of a successful registry match against a box.
#[derive(Debug, Clone, Copy)]
pub struct RegistryMatch {
    pub entry: &'static ProtocolEntry,
    pub matcher: &'static ContractMatcher,
    pub matched_by: MatchKind,
    /// `exact` for token/tree-hash keys, `template` for a shape-only match.
    pub confidence: &'static str,
}

/// Look the box up in the registry. `token_ids` are the box's asset token ids
/// (unprefixed hex); `template_hash_hex` / `tree_hash_hex` are the box's
/// contract keys (unprefixed hex, `None` when the tree failed to hash).
///
/// Priority: identifying-token first (most robust), then template hash, then
/// tree hash — matching the fragment's key precedence. Bounded: at most a
/// linear pass over the small static registry, no scan, no evaluation.
pub fn match_box(
    token_ids: &[&str],
    template_hash_hex: Option<&str>,
    tree_hash_hex: Option<&str>,
) -> Option<RegistryMatch> {
    // Pass 1: identifying tokens (highest confidence).
    for entry in REGISTRY {
        for matcher in entry.matchers {
            if matcher.kind == MatchKind::IdentifyingToken && token_ids.contains(&matcher.key) {
                return Some(RegistryMatch {
                    entry,
                    matcher,
                    matched_by: MatchKind::IdentifyingToken,
                    confidence: "exact",
                });
            }
        }
    }
    // Pass 2: template hash (shape-only → `template` confidence).
    if let Some(th) = template_hash_hex {
        for entry in REGISTRY {
            for matcher in entry.matchers {
                if matcher.kind == MatchKind::TemplateHash && matcher.key == th {
                    return Some(RegistryMatch {
                        entry,
                        matcher,
                        matched_by: MatchKind::TemplateHash,
                        confidence: "template",
                    });
                }
            }
        }
    }
    // Pass 3: exact tree hash.
    if let Some(tr) = tree_hash_hex {
        for entry in REGISTRY {
            for matcher in entry.matchers {
                if matcher.kind == MatchKind::TreeHash && matcher.key == tr {
                    return Some(RegistryMatch {
                        entry,
                        matcher,
                        matched_by: MatchKind::TreeHash,
                        confidence: "exact",
                    });
                }
            }
        }
    }
    None
}

/// Find a registry entry by its stable slug (backs `GET /protocols/{id}`).
pub fn entry_by_id(id: &str) -> Option<&'static ProtocolEntry> {
    REGISTRY.iter().find(|e| e.id == id)
}
