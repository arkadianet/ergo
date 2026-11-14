//! Message signing for named, domain-separated schemes.
//!
//! The wallet signs a message, not a transaction, only for a scheme it knows.
//! Each scheme builds the signed bytes itself from typed fields, and those
//! bytes always begin with that scheme's protocol domain. There is no mode that
//! signs caller-chosen bytes or a caller-chosen hash.
//!
//! Both schemes are Schnorr signatures over secp256k1 with a 33-byte
//! commitment `a = g^k` and a 32-byte response `z = k + e·x mod n`; a verifier
//! checks `g^z == a · Q^e`. They differ in the challenge `e`:
//!
//! - [`MAKER_QUOTE_V1`]: `m = "kadia-dex/maker-quote/v1" ‖ vaultBoxId ‖ side ‖
//!   priceNum ‖ priceDen ‖ minIn ‖ maxIn ‖ expiryHeight ‖ execFee` (each field an
//!   8-byte big-endian signed integer, 112 bytes in all) and
//!   `e = blake2b256(DOMAIN ‖ a ‖ Q ‖ m)`.
//! - [`ROSEN_INTENTS_QUOTE_V1`]: `h = blake2b256(quote)`, where `quote` is the
//!   canonical Rosen Intents quote encoding (it begins with
//!   `"rosen-intents/quote"` and version 1), and `e = blake2b256(a ‖ h ‖ Q)`.
//!
//! **Why a signature cannot be reused elsewhere.**
//! - Between the two schemes: the maker challenge's preimage begins with the
//!   24 ASCII bytes of its domain; the Rosen challenge's preimage begins with a
//!   compressed point (`0x02`/`0x03`), and its message is a hash of bytes that
//!   begin with the Rosen domain. The wallet computes both preimages itself, so
//!   a caller cannot make one scheme's challenge equal the other's.
//! - Against transaction proofs: an Ergo spending proof uses a 192-bit
//!   Fiat–Shamir challenge over the serialized proof tree and the transaction
//!   bytes, and is encoded as `e ‖ z`, not `a ‖ z`. Neither scheme's challenge
//!   is computed over transaction bytes, so no message signature verifies as a
//!   spending proof, and the endpoint never signs a transaction.
//! - Against other protocols: a verifier accepts only messages that begin with
//!   (or hash bytes that begin with) its own domain, and the wallet refuses to
//!   sign anything that does not parse as that scheme's message.
//!
//! **Nonces.** Deterministic, as BIP-340 derives them:
//! `k = blake2b512(NONCE_DOMAIN ‖ x ‖ Q ‖ msg) mod n`, with a nonce domain per
//! scheme. Two different messages never share a nonce, the same key in two
//! schemes never shares one, and signing does not depend on an RNG. For the
//! maker scheme this is exactly the reference signer's construction, so its
//! published vectors reproduce byte for byte.
use blake2::digest::consts::U32;
use blake2::{Blake2b, Blake2b512, Digest};
use ergo_wallet_protocol::native::dto::{
    MakerQuoteMessageDto, RosenQuoteMessageDto, SignMessageRequest, SignMessageResponse,
};
use ergo_wallet_protocol::WalletAdminError;
use k256::elliptic_curve::bigint::U512;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, ProjectivePoint, Scalar, Sec1Point, U256};
use zeroize::Zeroizing;

type Blake2b256 = Blake2b<U32>;

/// Scheme name: Kadia DEX maker-vault quotes.
pub const MAKER_QUOTE_V1: &str = "kadia-maker-quote-v1";
/// Scheme name: Rosen Intents quotes (Basis-style Schnorr over the quote hash).
pub const ROSEN_INTENTS_QUOTE_V1: &str = "rosen-intents-quote-v1";
/// Every scheme this wallet signs.
pub const SCHEMES: [&str; 2] = [MAKER_QUOTE_V1, ROSEN_INTENTS_QUOTE_V1];

/// The maker scheme's domain (the vault contract hard-codes these bytes).
pub const MAKER_DOMAIN: &[u8] = b"kadia-dex/maker-quote/v1";
/// The maker scheme's nonce domain (the reference signer's).
pub const MAKER_NONCE_DOMAIN: &[u8] = b"kadia-dex/maker-quote-nonce/v1";

/// The Rosen Intents quote domain (the first 19 bytes of every quote).
pub const ROSEN_DOMAIN: &[u8] = b"rosen-intents/quote";
/// The only Rosen Intents quote encoding version this scheme signs.
pub const ROSEN_VERSION: u8 = 1;
/// The Rosen scheme's nonce domain (this wallet's own).
pub const ROSEN_NONCE_DOMAIN: &[u8] = b"ergo-walletd/rosen-intents-quote-nonce/v1";
const ROSEN_HEAD_LEN: usize = 224;
const ROSEN_MAX_LEN: usize = 1024;
const ROSEN_MAX_UI_FEE_BPS: u16 = 10_000;

/// Largest amount a maker quote may carry (the vault's cap, 2^62).
const MAKER_CAP: i64 = 1 << 62;

/// Why a message was refused. Every variant is a caller error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageError {
    UnknownScheme(String),
    Invalid(String),
}

impl std::fmt::Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownScheme(s) => write!(
                f,
                "unknown signing scheme {s:?}; supported: {}",
                SCHEMES.join(", ")
            ),
            Self::Invalid(m) => f.write_str(m),
        }
    }
}

fn invalid<T>(m: impl Into<String>) -> Result<T, MessageError> {
    Err(MessageError::Invalid(m.into()))
}

/// A maker-vault quote, the fields in the order the contract reads them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MakerQuote {
    pub vault_box_id: [u8; 32],
    pub side: i64,
    pub price_num: i64,
    pub price_den: i64,
    pub min_in: i64,
    pub max_in: i64,
    pub expiry_height: i64,
    pub exec_fee: i64,
}

impl MakerQuote {
    /// The vault's own range checks, so the wallet never signs a quote the
    /// vault can't fill. Price and expiry policy (reference price, quote life,
    /// fee ceiling) is the caller's: the wallet has no market data.
    pub fn validate(&self) -> Result<(), MessageError> {
        if !(self.side == 0 || self.side == 1) {
            return invalid("side must be 0 or 1");
        }
        if self.price_num <= 0
            || self.price_num > MAKER_CAP
            || self.price_den <= 0
            || self.price_den > MAKER_CAP
        {
            return invalid("need 0 < priceNum, priceDen ≤ 2^62");
        }
        if self.min_in <= 0 || self.min_in > self.max_in || self.max_in > MAKER_CAP {
            return invalid("need 0 < minIn ≤ maxIn ≤ 2^62");
        }
        if self.expiry_height <= 0 {
            return invalid("expiryHeight must be positive");
        }
        if self.exec_fee < 0 {
            return invalid("execFee must be non-negative");
        }
        Ok(())
    }

    /// The signed message `m` (112 bytes).
    pub fn message(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(MAKER_DOMAIN.len() + 32 + 7 * 8);
        m.extend_from_slice(MAKER_DOMAIN);
        m.extend_from_slice(&self.vault_box_id);
        for f in [
            self.side,
            self.price_num,
            self.price_den,
            self.min_in,
            self.max_in,
            self.expiry_height,
            self.exec_fee,
        ] {
            m.extend_from_slice(&f.to_be_bytes());
        }
        m
    }
}

/// Check that `b` is one canonical version-1 Rosen Intents quote for
/// `network` (the address prefix byte, `0x00` mainnet or `0x10` testnet), and
/// return its hash, the message the scheme signs.
///
/// Canonical means what the quote encoder writes: the 224-byte head, then six
/// non-empty length-prefixed UTF-8 strings and nothing after them; non-zero
/// amounts that fit a signed long; a UI fee of at most 100 %, with an all-zero
/// fee script hash when there is no fee.
pub fn rosen_quote_hash(b: &[u8], network: u8) -> Result<[u8; 32], MessageError> {
    if b.len() <= ROSEN_HEAD_LEN {
        return invalid("a Rosen Intents quote is longer than its 224-byte head");
    }
    if b.len() > ROSEN_MAX_LEN {
        return invalid("a Rosen Intents quote is at most 1024 bytes");
    }
    if &b[..ROSEN_DOMAIN.len()] != ROSEN_DOMAIN {
        return invalid("the quote does not begin with the rosen-intents/quote domain");
    }
    if b[19] != ROSEN_VERSION {
        return invalid(format!("unsupported quote version {}", b[19]));
    }
    if b[20] != network {
        return invalid("the quote is for another network");
    }
    if b[53] > 1 {
        return invalid("leg must be 0 or 1");
    }
    let u64at = |o: usize| u64::from_be_bytes(b[o..o + 8].try_into().expect("8 bytes"));
    for o in [54, 166, 174] {
        let v = u64at(o);
        if v == 0 || v > i64::MAX as u64 {
            return invalid("amounts must be positive and fit a signed long");
        }
    }
    if u64at(62) > i64::MAX as u64 || u64at(216) > i64::MAX as u64 {
        return invalid("timestamp and nonce must fit a signed long");
    }
    let ui_fee_bps = u16::from_be_bytes([b[182], b[183]]);
    if ui_fee_bps > ROSEN_MAX_UI_FEE_BPS {
        return invalid("uiFeeBps is at most 10000");
    }
    if ui_fee_bps == 0 && b[184..216].iter().any(|x| *x != 0) {
        return invalid("a UI fee script hash without a UI fee");
    }
    let mut p = ROSEN_HEAD_LEN;
    for _ in 0..6 {
        if b.len() < p + 2 {
            return invalid("the quote's strings are truncated");
        }
        let n = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
        p += 2;
        if n == 0 || b.len() < p + n || std::str::from_utf8(&b[p..p + n]).is_err() {
            return invalid("each quote string is non-empty UTF-8");
        }
        p += n;
    }
    if p != b.len() {
        return invalid("trailing bytes after the quote's strings");
    }
    Ok(blake2b256(b))
}

/// A Schnorr signature: commitment `a` (compressed point) and response `z`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchnorrSig {
    pub a: [u8; 33],
    pub z: [u8; 32],
}

impl SchnorrSig {
    /// `a ‖ z`, 65 bytes (the Rosen vault reads this form).
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..33].copy_from_slice(&self.a);
        out[33..].copy_from_slice(&self.z);
        out
    }
}

pub fn blake2b256(b: &[u8]) -> [u8; 32] {
    Blake2b256::digest(b).into()
}

fn compressed(p: &ProjectivePoint) -> [u8; 33] {
    p.to_affine()
        .to_sec1_point(true)
        .as_bytes()
        .try_into()
        .expect("33-byte compressed point")
}

/// `Q = g^x`, compressed.
pub fn public_key(x: &Scalar) -> [u8; 33] {
    compressed(&(ProjectivePoint::GENERATOR * x))
}

fn nonce(
    domain: &[u8],
    x: &Scalar,
    q: &[u8; 33],
    msg: &[u8],
) -> Result<Zeroizing<Scalar>, MessageError> {
    let sk = Zeroizing::new(<[u8; 32]>::from(x.to_repr()));
    let mut h = Blake2b512::new();
    h.update(domain);
    h.update(sk.as_slice());
    h.update(q);
    h.update(msg);
    let wide = Zeroizing::new(<[u8; 64]>::from(h.finalize()));
    let k = Zeroizing::new(<Scalar as Reduce<U512>>::reduce(&U512::from_be_slice(
        wide.as_slice(),
    )));
    if bool::from(k.is_zero()) {
        // Probability 2^-256; refused rather than retried.
        return invalid("derived a zero nonce");
    }
    Ok(k)
}

fn e_scalar(e: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce(&U256::from_be_slice(e))
}

fn schnorr(
    nonce_domain: &[u8],
    x: &Scalar,
    msg: &[u8],
    challenge: impl Fn(&[u8; 33], &[u8; 33]) -> [u8; 32],
) -> Result<SchnorrSig, MessageError> {
    if bool::from(x.is_zero()) {
        return invalid("zero signing key");
    }
    let q = public_key(x);
    let k = nonce(nonce_domain, x, &q, msg)?;
    let a = compressed(&(ProjectivePoint::GENERATOR * *k));
    let e = challenge(&a, &q);
    let z = *k + e_scalar(&e) * x;
    Ok(SchnorrSig {
        a,
        z: z.to_repr().into(),
    })
}

/// The maker challenge `e = blake2b256(DOMAIN ‖ a ‖ Q ‖ m)`.
pub fn maker_challenge(a: &[u8; 33], q: &[u8; 33], m: &[u8]) -> [u8; 32] {
    let mut h = Blake2b256::new();
    h.update(MAKER_DOMAIN);
    h.update(a);
    h.update(q);
    h.update(m);
    h.finalize().into()
}

/// The Rosen challenge `e = blake2b256(a ‖ h ‖ Q)`.
pub fn rosen_challenge(a: &[u8; 33], h: &[u8; 32], q: &[u8; 33]) -> [u8; 32] {
    let mut d = Blake2b256::new();
    d.update(a);
    d.update(h);
    d.update(q);
    d.finalize().into()
}

/// Sign a maker quote with key `x`, after the vault's range checks.
pub fn sign_maker_quote(x: &Scalar, quote: &MakerQuote) -> Result<SchnorrSig, MessageError> {
    quote.validate()?;
    let m = quote.message();
    schnorr(MAKER_NONCE_DOMAIN, x, &m, |a, q| maker_challenge(a, q, &m))
}

/// Sign the hash of a checked Rosen Intents quote with key `x`.
pub fn sign_rosen_quote(
    x: &Scalar,
    quote: &[u8],
    network: u8,
) -> Result<(SchnorrSig, [u8; 32]), MessageError> {
    let h = rosen_quote_hash(quote, network)?;
    let sig = schnorr(ROSEN_NONCE_DOMAIN, x, &h, |a, q| rosen_challenge(a, &h, q))?;
    Ok((sig, h))
}

fn point(b: &[u8; 33]) -> Option<ProjectivePoint> {
    let ep = Sec1Point::from_bytes(b).ok()?;
    Option::<AffinePoint>::from(AffinePoint::from_sec1_point(&ep)).map(Into::into)
}

fn verify_with(q: &[u8; 33], sig: &SchnorrSig, e: &[u8; 32]) -> bool {
    let (Some(a), Some(qp)) = (point(&sig.a), point(q)) else {
        return false;
    };
    let Some(z) = Option::<Scalar>::from(Scalar::from_repr(sig.z.into())) else {
        return false;
    };
    if a == ProjectivePoint::IDENTITY {
        return false;
    }
    ProjectivePoint::GENERATOR * z == a + qp * e_scalar(e)
}

/// Verify a maker-quote signature as the vault does.
pub fn verify_maker_quote(q: &[u8; 33], quote: &MakerQuote, sig: &SchnorrSig) -> bool {
    let m = quote.message();
    verify_with(q, sig, &maker_challenge(&sig.a, q, &m))
}

/// Verify a Rosen quote-hash signature as the vault does.
pub fn verify_rosen_quote(q: &[u8; 33], h: &[u8; 32], sig: &SchnorrSig) -> bool {
    verify_with(q, sig, &rosen_challenge(&sig.a, h, q))
}

/// The wallet's spending keys, which sign messages only with `allowSpendKey`:
/// the master key, the first address (EIP-3 and pre-EIP-3 paths), and the
/// change key.
fn is_spend_key(path: &[u32], pubkey: &[u8; 33], change: Option<&[u8; 33]>) -> bool {
    use ergo_wallet::derivation::DerivationPath;
    path.is_empty()
        || path == DerivationPath::eip3_first_address().components()
        || path == [1]
        || change == Some(pubkey)
}

fn parse_message<T: serde::de::DeserializeOwned>(
    v: serde_json::Value,
) -> Result<T, WalletAdminError> {
    serde_json::from_value(v).map_err(|e| WalletAdminError::BadRequest(format!("message: {e}")))
}

fn hex_n<const N: usize>(field: &str, s: &str) -> Result<[u8; N], WalletAdminError> {
    hex::decode(s)
        .ok()
        .and_then(|b| <[u8; N]>::try_from(b).ok())
        .ok_or_else(|| WalletAdminError::BadRequest(format!("{field}: expected {N} bytes hex")))
}

impl From<MessageError> for WalletAdminError {
    fn from(e: MessageError) -> Self {
        WalletAdminError::BadRequest(e.to_string())
    }
}

impl super::WalletEngine {
    /// `POST /api/v1/wallet/messages/sign`: sign one message of a named
    /// scheme with a tracked wallet key. Needs the wallet unlocked. Nothing
    /// secret is returned or logged; the derived key is wiped on return.
    pub fn sign_message(
        &self,
        request: SignMessageRequest,
    ) -> Result<SignMessageResponse, WalletAdminError> {
        // The scheme first, so an unknown one is refused before any key work.
        if !SCHEMES.contains(&request.scheme.as_str()) {
            return Err(MessageError::UnknownScheme(request.scheme).into());
        }
        let network = self.config.network;
        let storage = self.storage.read();
        let unlocked = storage.unlocked().ok_or(WalletAdminError::Locked)?;

        let tracked = self
            .store
            .read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            .tracked_pubkeys_with_paths()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let (pubkey, path) = match (&request.key.address, &request.key.path) {
            (Some(address), None) => {
                let pk = ergo_ser::address::decode_p2pk_address(address, network).map_err(|e| {
                    WalletAdminError::BadRequest(format!("bad address {address}: {e}"))
                })?;
                tracked
                    .into_iter()
                    .find(|(_, k, _)| *k == pk)
                    .map(|(_, k, p)| (k, p))
                    .ok_or(WalletAdminError::AddressNotTracked)?
            }
            (None, Some(path)) => {
                let want: ergo_wallet::derivation::DerivationPath = path
                    .parse()
                    .map_err(|e| WalletAdminError::BadRequest(format!("bad path {path}: {e}")))?;
                tracked
                    .into_iter()
                    .find(|(_, _, p)| p.as_slice() == want.components())
                    .map(|(_, k, p)| (k, p))
                    .ok_or(WalletAdminError::AddressNotTracked)?
            }
            _ => {
                return Err(WalletAdminError::BadRequest(
                    "key: give exactly one of address or path".into(),
                ))
            }
        };

        let change = self
            .state
            .read()
            .change_address()
            .and_then(|a| ergo_ser::address::decode_p2pk_address(a, network).ok());
        if !request.allow_spend_key && is_spend_key(&path, &pubkey, change.as_ref()) {
            return Err(WalletAdminError::Forbidden(
                "this key holds the wallet's funds (first or change key); use a separate \
                 derived key, or set allowSpendKey"
                    .into(),
            ));
        }

        let x = Zeroizing::new(
            unlocked
                .master
                .derive_scalar_for_pubkey(
                    &ergo_wallet::derivation::DerivationPath::from_components(path),
                    &pubkey,
                )
                .map_err(|e| WalletAdminError::Internal(format!("signMessage: {e}")))?,
        );
        drop(storage);

        let (sig, signed) = match request.scheme.as_str() {
            MAKER_QUOTE_V1 => {
                let m: MakerQuoteMessageDto = parse_message(request.message)?;
                let quote = MakerQuote {
                    vault_box_id: hex_n("vaultBoxId", &m.vault_box_id)?,
                    side: m.side,
                    price_num: m.price_num,
                    price_den: m.price_den,
                    min_in: m.min_in,
                    max_in: m.max_in,
                    expiry_height: m.expiry_height,
                    exec_fee: m.exec_fee,
                };
                (sign_maker_quote(&x, &quote)?, quote.message())
            }
            ROSEN_INTENTS_QUOTE_V1 => {
                let m: RosenQuoteMessageDto = parse_message(request.message)?;
                let bytes = hex::decode(&m.quote)
                    .map_err(|e| WalletAdminError::BadRequest(format!("quote: {e}")))?;
                let (sig, h) = sign_rosen_quote(&x, &bytes, network as u8)?;
                (sig, h.to_vec())
            }
            _ => unreachable!("scheme checked above"),
        };
        let address = ergo_wallet::address::pubkey_to_p2pk_address(&pubkey, network)
            .map_err(|e| WalletAdminError::Internal(format!("signMessage: {e}")))?;
        Ok(SignMessageResponse {
            scheme: request.scheme,
            address,
            public_key: hex::encode(pubkey),
            a: hex::encode(sig.a),
            z: hex::encode(sig.z),
            signature: hex::encode(sig.to_bytes()),
            signed_message: hex::encode(signed),
        })
    }
}

#[cfg(test)]
#[path = "message_sign_tests.rs"]
mod tests;
