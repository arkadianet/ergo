//! Message-signing schemes against their reference vectors and against the
//! contracts' own signature checks, run by this repository's compiler and
//! evaluator.
use super::*;
use ergo_compiler::{compile, NetworkPrefix, ScriptEnv};
use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::reader::VlqReader;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaBoolean, SigmaValue};
use ergo_sigma::evaluator::{reduce_expr_with_cost, ReductionContext};

const TESTNET: u8 = 0x10;

fn scalar(hex32: &str) -> Scalar {
    let b: [u8; 32] = hex::decode(hex32).unwrap().try_into().unwrap();
    Option::<Scalar>::from(Scalar::from_repr(b.into())).unwrap()
}

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

/// The reference maker-quote signer's published vectors: key, vault box id,
/// quote fields, and the expected `Q`, `a`, `z`.
/// `(sk, vaultBoxId, fields, Q, a, z)`.
type MakerVector = (
    &'static str,
    &'static str,
    [i64; 7],
    &'static str,
    &'static str,
    &'static str,
);
const MAKER_VECTORS: [MakerVector; 3] = [
    (
        "1100000000000000000000000000000000000000000000000000000000000001",
        "0101010101010101010101010101010101010101010101010101010101010101",
        [0, 1005, 2000, 1000, 1_000_000_000, 1_200_010, 1_000_000],
        "02100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494",
        "02d4dbbf3e60f308093290109813b5bba23e7c6fc75eac00b7ee77ad2ba2defa55",
        "b74f912a181844faae10020c0e8264e0d695161782286e85d937321be64ca01d",
    ),
    (
        "1100000000000000000000000000000000000000000000000000000000000009",
        "0909090909090909090909090909090909090909090909090909090909090909",
        [1, 1005, 2000, 1000, 1_000_000_000, 1_200_010, 0],
        "0328c8bbeb1069df538d60c4478fb31c9e82e99a37734261565bd03073ed9acc72",
        "02eda50328ce730c8ed764149282f885332196f7e12fe67c5bc42c826ed772bac5",
        "ce929339b5fc97faf74cad2856e193cb154ea776a6b74450a74b42d1f13a830f",
    ),
    (
        "11000000000000000000000000000000000000000000000000000000000000c8",
        "c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8",
        [0, 1005, 2000, 1000, 1_000_000_000, 1_200_010, 7],
        "0218a16359ae209eb7bd5f71ed40276ce919e9fcd50f7a6bf055cba9e68ac5c032",
        "032b36975b168c940d00e997908a21468ad1833a712b613ac5a438aa2eeb9bba33",
        "fdb758f2bd51d2599874d5871398a7554f90cd10250d38c1dd72d49a63608b3b",
    ),
];

fn maker_quote(id: &str, f: [i64; 7]) -> MakerQuote {
    MakerQuote {
        vault_box_id: h32(id),
        side: f[0],
        price_num: f[1],
        price_den: f[2],
        min_in: f[3],
        max_in: f[4],
        expiry_height: f[5],
        exec_fee: f[6],
    }
}

/// The maker vault's signature check, verbatim from the contract except that
/// the quote key and `SELF.id` come from context variables 4 and 5 (the
/// contract reads them from R4 and the box itself).
const MAKER_VERIFIER: &str = r#"{
  val qO = getVar[Coll[Byte]](1)
  val aO = getVar[Coll[Byte]](2)
  val zO = getVar[Coll[Byte]](3)
  val keyO = getVar[Coll[Byte]](4)
  val selfId = getVar[Coll[Byte]](5).get
  sigmaProp(qO.get.size == 56 && aO.get.size == 33 && keyO.get.size == 33 && zO.get.size == 32 && {
    val qb = qO.get
    val domain = fromBase16("6b616469612d6465782f6d616b65722d71756f74652f7631")  // kadia-dex/maker-quote/v1
    val key = decodePoint(keyO.get)
    val a = decodePoint(aO.get)
    val m = domain ++ selfId ++ qb
    val e = Global.fromBigEndianBytes[UnsignedBigInt](blake2b256(domain ++ aO.get ++ keyO.get ++ m))
    val z = Global.fromBigEndianBytes[UnsignedBigInt](zO.get)
    val n = Global.fromBigEndianBytes[UnsignedBigInt](fromBase16("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"))
    z < n && aO.get != fromBase16("000000000000000000000000000000000000000000000000000000000000000000") &&
    groupGenerator.expUnsigned(z) == a.multiply(key.expUnsigned(e))
  })
}"#;

/// The Rosen Intents vault's quote-signature check, verbatim from the
/// contract's open action except that `Q` comes from context variable 4 (the
/// contract reads it from R4).
const ROSEN_VERIFIER: &str = r#"{
  val quote = getVar[Coll[Byte]](1).get
  val sig = getVar[Coll[Byte]](2).get
  val q = decodePoint(getVar[Coll[Byte]](4).get)
  val h = blake2b256(quote)
  val head = quote.slice(0, 224)
  val aB = sig.slice(0, 33)
  val e = Global.fromBigEndianBytes[UnsignedBigInt](blake2b256(aB ++ h ++ q.getEncoded))
  val z = Global.fromBigEndianBytes[UnsignedBigInt](sig.slice(33, 65))
  sigmaProp(quote.size > 224 && sig.size == 65 &&
    head.slice(0, 19) == fromBase16("726f73656e2d696e74656e74732f71756f7465") &&
    head(19) == 1.toByte &&
    groupGenerator.expUnsigned(z) == decodePoint(aB).multiply(q.expUnsigned(e)))
}"#;

/// Compile `src` and reduce it with the given context variables, as the node
/// evaluates a script after the 6.0 activation. An evaluation error counts as
/// a refusal.
fn script_accepts(src: &str, vars: &[(u8, &[u8])]) -> bool {
    let compiled = compile(&ScriptEnv::new(), src, 3, NetworkPrefix::Testnet)
        .unwrap_or_else(|e| panic!("compile: {e:?}"));
    let mut reader = VlqReader::new(&compiled.tree_bytes).with_activated_script_version(3);
    let tree = ergo_ser::ergo_tree::read_ergo_tree(&mut reader).unwrap();
    let mut ctx = ReductionContext::minimal_v6(1_000_000, 1);
    ctx.ergo_tree_version = tree.version;
    for (id, bytes) in vars {
        ctx.extension.insert(
            *id,
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(CollValue::Bytes(bytes.to_vec())),
            ),
        );
    }
    let mut cost = CostAccumulator::new(JitCost::from_jit(10_000_000));
    matches!(
        reduce_expr_with_cost(&tree.body, &ctx, &tree.constants, &mut cost),
        Ok(SigmaBoolean::TrivialProp(true))
    )
}

fn maker_contract_accepts(q: &[u8; 33], quote: &MakerQuote, sig: &SchnorrSig) -> bool {
    let m = quote.message();
    script_accepts(
        MAKER_VERIFIER,
        &[
            (1, &m[MAKER_DOMAIN.len() + 32..]),
            (2, &sig.a),
            (3, &sig.z),
            (4, q),
            (5, &quote.vault_box_id),
        ],
    )
}

fn rosen_contract_accepts(q: &[u8; 33], quote: &[u8], sig: &SchnorrSig) -> bool {
    script_accepts(ROSEN_VERIFIER, &[(1, quote), (2, &sig.to_bytes()), (4, q)])
}

/// The Rosen Intents reference sample quote (testnet), 384 bytes.
fn rosen_sample() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(ROSEN_DOMAIN);
    b.push(1);
    b.push(TESTNET);
    b.extend_from_slice(&[0x11; 32]); // vault id
    b.push(0); // leg: source
    b.extend_from_slice(&100_000_000u64.to_be_bytes()); // vault amount
    b.extend_from_slice(&1_793_000_000_000u64.to_be_bytes()); // timestamp
    b.extend_from_slice(&[0x22; 32]); // source pool
    b.extend_from_slice(&[0x33; 32]); // dest pool
    b.extend_from_slice(&[0x44; 32]); // payout script hash
    b.extend_from_slice(&100_000_000u64.to_be_bytes()); // amount send
    b.extend_from_slice(&290_000_000_000u64.to_be_bytes()); // min receive
    b.extend_from_slice(&15u16.to_be_bytes()); // UI fee bps
    b.extend_from_slice(&[0x55; 32]); // UI fee script hash
    b.extend_from_slice(&1u64.to_be_bytes()); // nonce
    assert_eq!(b.len(), 224);
    for s in [
        "ethereum",
        "0x1111111111111111111111111111111111111111",
        "0xdac17f958d2ee523a2206206994597c13d831ec7",
        "monero",
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx",
        "native",
    ] {
        b.extend_from_slice(&(s.len() as u16).to_be_bytes());
        b.extend_from_slice(s.as_bytes());
    }
    b
}

#[test]
fn maker_signatures_match_the_reference_signer_byte_for_byte() {
    for (sk, id, fields, q, a, z) in MAKER_VECTORS {
        let x = scalar(sk);
        assert_eq!(hex::encode(public_key(&x)), q);
        let quote = maker_quote(id, fields);
        assert_eq!(quote.message().len(), 112);
        let sig = sign_maker_quote(&x, &quote).unwrap();
        assert_eq!(hex::encode(sig.a), a);
        assert_eq!(hex::encode(sig.z), z);
        assert!(verify_maker_quote(&public_key(&x), &quote, &sig));
    }
}

#[test]
fn the_maker_vault_check_accepts_wallet_signatures_and_refuses_tampering() {
    let (sk, id, fields, ..) = MAKER_VECTORS[0];
    let x = scalar(sk);
    let q = public_key(&x);
    let quote = maker_quote(id, fields);
    let sig = sign_maker_quote(&x, &quote).unwrap();
    assert!(maker_contract_accepts(&q, &quote, &sig));

    // The wrong key.
    let other = public_key(&scalar(MAKER_VECTORS[1].0));
    assert!(!maker_contract_accepts(&other, &quote, &sig));
    // Another vault box.
    let mut moved = quote;
    moved.vault_box_id = [0x02; 32];
    assert!(!maker_contract_accepts(&q, &moved, &sig));
    // Any changed field.
    for i in 0..7 {
        let mut f = fields;
        f[i] += 1;
        assert!(
            !maker_contract_accepts(&q, &maker_quote(id, f), &sig),
            "field {i}"
        );
    }
    // A response that is not reduced mod n.
    let mut big = sig;
    big.z = [0xff; 32];
    assert!(!maker_contract_accepts(&q, &quote, &big));
}

#[test]
fn maker_quotes_outside_the_vaults_ranges_are_refused() {
    let x = scalar(MAKER_VECTORS[0].0);
    let id = MAKER_VECTORS[0].1;
    for f in [
        [2, 1005, 2000, 1000, 1_000_000_000, 1_200_010, 0],
        [0, 0, 2000, 1000, 1_000_000_000, 1_200_010, 0],
        [0, 1005, -1, 1000, 1_000_000_000, 1_200_010, 0],
        [0, 1005, 2000, 0, 1_000_000_000, 1_200_010, 0],
        [0, 1005, 2000, 10, 9, 1_200_010, 0],
        [0, 1005, 2000, 1, (1 << 62) + 1, 1_200_010, 0],
        [0, 1005, 2000, 1, 2, 0, 0],
        [0, 1005, 2000, 1, 2, 1_200_010, -1],
    ] {
        assert!(
            matches!(
                sign_maker_quote(&x, &maker_quote(id, f)),
                Err(MessageError::Invalid(_))
            ),
            "{f:?}"
        );
    }
}

#[test]
fn rosen_sample_hashes_to_the_reference_vector() {
    let b = rosen_sample();
    assert_eq!(b.len(), 384);
    assert_eq!(
        hex::encode(rosen_quote_hash(&b, TESTNET).unwrap()),
        "7a80b7ea1cec190978632c63e8b7579dceb12c594184ce6e7881742e8df212d0"
    );
}

#[test]
fn the_rosen_vault_check_accepts_wallet_signatures_and_refuses_tampering() {
    let x = scalar(MAKER_VECTORS[2].0);
    let q = public_key(&x);
    let b = rosen_sample();
    let (sig, h) = sign_rosen_quote(&x, &b, TESTNET).unwrap();
    assert_eq!(h, blake2b256(&b));
    assert!(verify_rosen_quote(&q, &h, &sig));
    assert!(rosen_contract_accepts(&q, &b, &sig));
    // Deterministic: the same key and quote give the same signature.
    assert_eq!(sign_rosen_quote(&x, &b, TESTNET).unwrap().0, sig);

    let other = public_key(&scalar(MAKER_VECTORS[0].0));
    assert!(!rosen_contract_accepts(&other, &b, &sig));
    let mut changed = b.clone();
    changed[60] ^= 1; // the vault amount
    assert!(!rosen_contract_accepts(&q, &changed, &sig));
}

#[test]
fn rosen_quotes_must_be_canonical_and_for_this_network() {
    let b = rosen_sample();
    let refused = |bytes: &[u8], network: u8| rosen_quote_hash(bytes, network).is_err();
    assert!(!refused(&b, TESTNET));
    assert!(refused(&b, 0x00), "another network");
    // A bare 32-byte hash is never signed.
    assert!(refused(&blake2b256(&b), TESTNET));
    let mut domain = b.clone();
    domain[0] ^= 1;
    assert!(refused(&domain, TESTNET));
    let mut version = b.clone();
    version[19] = 2;
    assert!(refused(&version, TESTNET));
    let mut leg = b.clone();
    leg[53] = 2;
    assert!(refused(&leg, TESTNET));
    let mut zero = b.clone();
    zero[54..62].copy_from_slice(&0u64.to_be_bytes());
    assert!(refused(&zero, TESTNET));
    let mut fee = b.clone();
    fee[182..184].copy_from_slice(&10_001u16.to_be_bytes());
    assert!(refused(&fee, TESTNET));
    let mut no_fee = b.clone();
    no_fee[182..184].copy_from_slice(&0u16.to_be_bytes());
    assert!(refused(&no_fee, TESTNET), "a fee script without a fee");
    let mut trailing = b.clone();
    trailing.push(0);
    assert!(refused(&trailing, TESTNET));
    assert!(refused(&b[..b.len() - 1], TESTNET));
    assert!(refused(&b[..224], TESTNET));
    let mut long = b[..224].to_vec();
    for _ in 0..6 {
        long.extend_from_slice(&200u16.to_be_bytes());
        long.extend_from_slice(&[b'x'; 200]);
    }
    assert!(refused(&long, TESTNET), "over 1024 bytes");
}

#[test]
fn signatures_do_not_cross_schemes() {
    let x = scalar(MAKER_VECTORS[0].0);
    let q = public_key(&x);
    let (sk, id, fields, ..) = MAKER_VECTORS[0];
    assert_eq!(scalar(sk), x);
    let quote = maker_quote(id, fields);
    let maker = sign_maker_quote(&x, &quote).unwrap();
    let b = rosen_sample();
    let (rosen, h) = sign_rosen_quote(&x, &b, TESTNET).unwrap();
    // Same key, different nonces.
    assert_ne!(maker.a, rosen.a);
    // Neither verifies under the other scheme's challenge, whatever message
    // the other scheme is shown.
    assert!(!verify_rosen_quote(&q, &h, &maker));
    let m: [u8; 32] = blake2b256(&quote.message());
    assert!(!verify_rosen_quote(&q, &m, &maker));
    assert!(!verify_maker_quote(&q, &quote, &rosen));
    assert!(!rosen_contract_accepts(&q, &b, &maker));
    assert!(!maker_contract_accepts(&q, &quote, &rosen));
}
