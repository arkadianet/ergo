//! Complete master bytes and descendant addresses from pinned Scala 6.0.6.
use ergo_ser::address::NetworkPrefix;
use ergo_wallet::{DerivationPath, ExtendedSecretKey, ExtendedSecretKeyLegacy};

// ----- helpers -----

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../test-vectors/wallet/leading-zero-master/scala_6_0_6.json"
    ))
    .unwrap()
}

// ----- oracle parity -----

#[test]
fn public_master_types_match_scala_leading_zero_seed_and_complete_paths() {
    let fixture = fixture();
    let seed = hex::decode(fixture["seed"].as_str().unwrap()).unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let path: DerivationPath = vector["path"].as_str().unwrap().parse().unwrap();
        let (secret, chain_code, public_key) = match vector["mode"].as_str().unwrap() {
            "modern" => {
                let key = ExtendedSecretKey::derive_master_key(&seed)
                    .unwrap()
                    .derive_at_path(&path)
                    .unwrap();
                (
                    hex::encode(key.secret_bytes()),
                    hex::encode(key.public_key().chain_code()),
                    key.public_key().compressed_bytes(),
                )
            }
            mode => {
                let master = match mode {
                    "legacy" => ExtendedSecretKeyLegacy::derive_master_key(&seed),
                    "legacy-rust-trimmed-master" => {
                        ExtendedSecretKeyLegacy::derive_master_key_legacy_rust(&seed)
                    }
                    _ => panic!("unrecognized fixture mode"),
                }
                .unwrap();
                let key = master.derive_at_path(&path).unwrap();
                (
                    hex::encode(key.secret_bytes()),
                    hex::encode(key.chain_code()),
                    key.public_key().unwrap().compressed_bytes(),
                )
            }
        };
        assert_eq!(secret, vector["secret"], "{vector}");
        assert_eq!(chain_code, vector["chainCode"], "{vector}");
        assert_eq!(hex::encode(public_key), vector["publicKey"], "{vector}");
        assert_eq!(
            ergo_wallet::address::pubkey_to_p2pk_address(&public_key, NetworkPrefix::Mainnet)
                .unwrap(),
            vector["address"],
            "{vector}"
        );
    }
}

#[test]
fn encrypted_legacy_seed_unlock_uses_complete_master_before_eip3_derivation() {
    let fixture = fixture();
    let seed = hex::decode(fixture["seed"].as_str().unwrap()).unwrap();
    let salt = [0x29; 32];
    let iv = [0x39; 12];
    let password = "public-leading-zero-seed-test";
    let key = ergo_wallet::encryption::derive_key_pbkdf2(password.as_bytes(), &salt, 128_000);
    let (ciphertext, tag) = ergo_wallet::encryption::encrypt(&key, &iv, &seed).unwrap();
    let encrypted = serde_json::json!({
        "cipherText": hex::encode(ciphertext), "salt": hex::encode(salt), "iv": hex::encode(iv), "authTag": hex::encode(tag),
        "cipherParams": { "prf": "HmacSHA512", "c": 128000, "dkLen": 256 }, "usePre1627KeyDerivation": true
    });
    let temporary = tempfile::tempdir().unwrap();
    std::fs::write(
        temporary.path().join("public-vector.json"),
        encrypted.to_string(),
    )
    .unwrap();
    let mut storage = ergo_wallet::SecretStorage::open(temporary.path().to_path_buf());
    storage.unlock(password).unwrap();
    let path = DerivationPath::eip3_first_address();
    let public_key = storage
        .unlocked()
        .unwrap()
        .master
        .derive_pubkey_at_path(&path)
        .unwrap();
    let expected = fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["mode"] == "legacy" && v["path"] == path.to_string())
        .unwrap();
    assert_eq!(hex::encode(public_key), expected["publicKey"]);
}
