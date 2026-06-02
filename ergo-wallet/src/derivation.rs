//! BIP32 / BIP44 derivation paths with Ergo-specific constants.
//!
//! Path syntax: `m/44'/429'/0'/0/0` (BIP44 layout, Ergo coin type 429).
//! Components ending in `'` are hardened (index ≥ 2^31).

use crate::error::WalletError;

/// BIP44 hardened-index bit. Indices ≥ `HARDENED_OFFSET` are hardened
/// derivations (child can sign without parent secret); indices below
/// are non-hardened (child pubkey is derivable from parent pubkey).
pub const HARDENED_OFFSET: u32 = 0x8000_0000;

/// Ergo's BIP44 coin type, registered at
/// https://github.com/satoshilabs/slips/blob/master/slip-0044.md.
/// Used as the second component of a BIP44 derivation: `m/44'/429'/...`.
pub const ERGO_COIN_TYPE: u32 = 429;

/// A parsed BIP32/BIP44 derivation path. Components are stored as the
/// raw u32 with hardened-flag already applied (so `44'` is stored as
/// `0x8000_002C`, not as `(44, hardened: true)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationPath {
    components: Vec<u32>,
}

impl DerivationPath {
    /// Borrow the raw component slice (hardened-flag already applied).
    pub fn components(&self) -> &[u32] {
        &self.components
    }

    /// True when the path is the root (`m`) — no derivations.
    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    /// Construct from a raw u32 component slice (hardened flag already applied).
    pub fn from_components(components: Vec<u32>) -> Self {
        Self { components }
    }

    /// Canonical EIP-3 first-address path: `m/44'/429'/0'/0/0`.
    /// Used by new wallets (post Ergo block 417792 / Sigma 5.0).
    pub fn eip3_first_address() -> Self {
        Self::from_components(vec![
            HARDENED_OFFSET | 44,
            HARDENED_OFFSET | ERGO_COIN_TYPE,
            HARDENED_OFFSET,
            0,
            0,
        ])
    }

    /// Pre-EIP-3 first-address path: `m/1`. Used by wallets created
    /// before Ergo EIP-3 landed — those wallets derived their first
    /// address at the old non-BIP44 path. Restoring such a wallet
    /// requires honouring this path or the user's funds won't be
    /// visible. Confirmed against Scala
    /// `DerivationPathSpec.scala:90` (`preEip3DerivationPath =
    /// DerivationPath(Array(0, 1), publicBranch = false)`) and
    /// against `DerivationPathSpec.scala:62-65` (mnemonic "liar
    /// exercise..." with `usePreEip3Derivation = true` →
    /// first address `9h7f11AC9RMHkhFbXg46XfYHq3HNnb1A9UtMmMYo6hAuQzWxVWu`).
    ///
    /// **Orthogonality note**: `usePreEip3Derivation` (this path
    /// switch) is independent of `usePre1627KeyDerivation` (the
    /// master-key derivation algorithm switch). A wallet can use any
    /// combination of the two flags.
    pub fn pre_eip3_first_address() -> Self {
        Self::from_components(vec![1])
    }
}

impl std::str::FromStr for DerivationPath {
    type Err = WalletError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Scala-parity: accept "m", "m/", "M", "M/", "m/...", "M/...".
        // `M` is the public-branch marker per BIP32; xpub-only derivation
        // is not yet implemented, so M and m parse identically (same
        // `components`, no public-branch flag stored).
        // Scala DerivationPathSpec.scala:101 expects `m/` to succeed
        // as an empty path; DerivationPathSpec.scala:125 expects
        // uppercase `M/...` to parse without error.
        let s = s.trim();
        if s == "m" || s == "M" || s == "m/" || s == "M/" {
            return Ok(Self {
                components: Vec::new(),
            });
        }
        let rest = s
            .strip_prefix("m/")
            .or_else(|| s.strip_prefix("M/"))
            .ok_or_else(|| {
                WalletError::InvalidDerivationPath(format!(
                    "path must start with `m`, `M`, `m/`, or `M/`, got {s:?}",
                ))
            })?;

        let mut components = Vec::new();
        for token in rest.split('/') {
            if token.is_empty() {
                return Err(WalletError::InvalidDerivationPath(format!(
                    "empty path component in {s:?}",
                )));
            }
            // Hardened-suffix marker: only `'` accepted, matching
            // Scala / sigma-rust. BIP32 spec also allows `h` but
            // neither reference accepts it, so we don't either —
            // keeps Scala-parity strict.
            let (digits, hardened) = if let Some(d) = token.strip_suffix('\'') {
                (d, true)
            } else {
                (token, false)
            };
            let idx: u32 = digits.parse().map_err(|_| {
                WalletError::InvalidDerivationPath(format!(
                    "non-numeric component {token:?} in {s:?}",
                ))
            })?;
            if idx >= HARDENED_OFFSET {
                return Err(WalletError::InvalidDerivationPath(format!(
                    "component {idx} >= 2^31 in {s:?}; use hardened marker `'` instead",
                )));
            }
            components.push(if hardened { HARDENED_OFFSET | idx } else { idx });
        }
        Ok(Self { components })
    }
}

impl std::fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Root prints as `m/` to round-trip with Scala's
        // `DerivationPath.fromEncoded("m/").get` form. Non-root paths
        // print as `m/c0/c1/...` (no trailing slash).
        if self.components.is_empty() {
            return f.write_str("m/");
        }
        f.write_str("m")?;
        for &c in &self.components {
            if c >= HARDENED_OFFSET {
                write!(f, "/{}'", c - HARDENED_OFFSET)?;
            } else {
                write!(f, "/{c}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn parse_root_m() {
        let p: DerivationPath = "m".parse().expect("root must parse");
        assert!(p.is_root());
        assert_eq!(p.components(), &[] as &[u32]);
    }

    #[test]
    fn parse_root_variants_match_scala() {
        // Scala DerivationPathSpec.scala:101 / 125 expects all four
        // root forms to parse identically (empty path).
        for s in ["m", "M", "m/", "M/"] {
            let p: DerivationPath = s
                .parse()
                .unwrap_or_else(|e| panic!("root form {s:?} must parse: {e:?}"));
            assert!(p.is_root(), "{s:?} should be root");
        }
    }

    #[test]
    fn parse_uppercase_m_path_matches_lowercase() {
        // Scala DerivationPathSpec.scala:125 uses uppercase M to mark
        // the public branch; we treat it identically to lowercase for
        // parsing purposes (xpub-only derivation is not implemented).
        let lower: DerivationPath = "m/44'/429'/0'/0/0".parse().unwrap();
        let upper: DerivationPath = "M/44'/429'/0'/0/0".parse().unwrap();
        assert_eq!(lower.components(), upper.components());
    }

    #[test]
    fn parse_ergo_first_address_path() {
        // The canonical EIP-3 first-address path: m/44'/429'/0'/0/0.
        let p: DerivationPath = "m/44'/429'/0'/0/0"
            .parse()
            .expect("standard path must parse");
        assert_eq!(
            p.components(),
            &[
                HARDENED_OFFSET | 44,  // 44'
                HARDENED_OFFSET | 429, // 429' (Ergo coin type)
                HARDENED_OFFSET,       // 0' (account)
                0,                     // 0  (change=external)
                0,                     // 0  (address index)
            ],
        );
    }

    #[test]
    fn ergo_post_eip3_first_address_path_is_m_44_429_0h_0_0() {
        let p = DerivationPath::eip3_first_address();
        assert_eq!(format!("{p}"), "m/44'/429'/0'/0/0");
    }

    #[test]
    fn display_root_outputs_m_slash_for_scala_roundtrip() {
        // Scala DerivationPath.fromEncoded("m/").get → root.
        // We must print root as "m/" so format/parse round-trips
        // through Scala's canonical form.
        let root: DerivationPath = "m/".parse().unwrap();
        assert_eq!(format!("{root}"), "m/");
        // And "m" → root → "m/" canonicalises consistently.
        let from_short: DerivationPath = "m".parse().unwrap();
        assert_eq!(format!("{from_short}"), "m/");
    }

    #[test]
    fn ergo_pre_eip3_first_address_path_is_m_1() {
        // Pre-EIP-3 wallets derived their first address at the old
        // `m/1` path. This is documented in Scala
        // `DerivationPathSpec.scala:90`:
        //     DerivationPath(Array(0, 1), publicBranch = false)
        //         shouldBe wallet.Constants.preEip3DerivationPath
        // (Scala's `Array(0, 1)` is internal representation; the
        //  external string form is `m/1`.)
        //
        // Importantly, `usePreEip3Derivation` (path-shape switch) is
        // ORTHOGONAL to `usePre1627KeyDerivation` (master-key switch).
        // A wallet can use either combination of the two flags.
        let p = DerivationPath::pre_eip3_first_address();
        assert_eq!(format!("{p}"), "m/1");
    }

    // ----- error paths -----

    #[test]
    fn parse_garbage_returns_invalid() {
        let err = "not-a-path"
            .parse::<DerivationPath>()
            .expect_err("garbage must reject");
        assert!(matches!(err, WalletError::InvalidDerivationPath(_)));
    }

    #[test]
    fn parse_path_without_m_prefix_rejects() {
        let err = "44'/429'/0'/0/0"
            .parse::<DerivationPath>()
            .expect_err("missing m must reject");
        assert!(matches!(err, WalletError::InvalidDerivationPath(_)));
    }
}
