//! Offline parser fuzz (Phase 0 codec/fuzz work).
//!
//! Phase 0 constraint: adversarial/fuzz input goes only to the offline
//! parsers (or a private local reference node) — never to the public
//! network. This suite is the offline half: proptest feeds random,
//! truncated, and corrupted bytes to every `ergo-p2p` deserializer and
//! asserts the safety property: **no panics, ever**. Returning `Ok` or
//! `Err` is the only acceptable behaviour; a panic fails the test.
//!
//! Where a codec round-trips, we additionally assert
//! serialize → deserialize → re-serialize byte identity and run a
//! truncation sweep (every prefix of a valid serialization), which
//! surfaces off-by-ones and missing length checks before allocation.
//!
//! Scala-anchored vectors live in `wire_vectors_oracle.rs`; this suite
//! is complementary, not anchored — it explores the malformed-input
//! space that fixed vectors cannot.

use ergo_p2p::framing::{
    deserialize_frame, serialize_frame, MessageFrame, MAINNET_MAGIC, TESTNET_MAGIC,
};
use ergo_p2p::handshake::{
    deserialize_handshake, serialize_handshake, DeclaredAddress, Handshake, PeerFeature, PeerSpec,
    Version,
};
use ergo_p2p::message::{
    deserialize_get_manifest, deserialize_get_nipopow_proof, deserialize_get_peers,
    deserialize_get_snapshots_info, deserialize_get_utxo_chunk, deserialize_inv,
    deserialize_manifest, deserialize_modifiers, deserialize_nipopow_proof, deserialize_peers,
    deserialize_snapshots_info, deserialize_sync_info, deserialize_utxo_chunk, serialize_inv,
    serialize_modifiers, serialize_sync_info, SyncInfo,
};
use ergo_p2p::types::{InvData, ModifiersData};
use proptest::prelude::*;

fn random_bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=max)
}

fn id32() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

fn ascii_string(min: usize, max: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(0x20u8..=0x7e, min..=max)
        .prop_map(|v| v.into_iter().map(|c| c as char).collect())
}

fn feature_strategy() -> impl Strategy<Value = PeerFeature> {
    proptest::prop_oneof![
        (prop::array::uniform4(any::<u8>()), any::<u32>())
            .prop_map(|(addr, port)| PeerFeature::LocalAddress { addr, port }),
        (prop::array::uniform4(any::<u8>()), any::<i64>())
            .prop_map(|(magic, session_id)| PeerFeature::SessionId { magic, session_id }),
        (
            any::<u8>(),
            any::<bool>(),
            any::<Option<i32>>(),
            any::<i32>()
        )
            .prop_map(|(state_type, verify_tx, nipopow, blocks_to_keep)| {
                PeerFeature::Mode {
                    state_type,
                    verify_tx,
                    nipopow,
                    blocks_to_keep,
                }
            }),
        ascii_string(1, 100).prop_map(|url| PeerFeature::RestApiUrl { url }),
        (any::<u8>(), random_bytes(64))
            .prop_map(|(feature_id, data)| PeerFeature::Unknown { feature_id, data }),
    ]
}

fn declared_addr_strategy() -> impl Strategy<Value = Option<DeclaredAddress>> {
    proptest::prop_oneof![
        Just(None),
        (prop::array::uniform4(any::<u8>()), any::<u32>()).prop_map(|(addr, port)| Some(
            DeclaredAddress {
                addr: addr.to_vec(),
                port
            }
        )),
        (prop::array::uniform16(any::<u8>()), any::<u32>()).prop_map(|(addr, port)| Some(
            DeclaredAddress {
                addr: addr.to_vec(),
                port
            }
        )),
    ]
}

/// Feed every prefix of `bytes` (lengths 0..=bytes.len()) to `f`.
/// Off-by-one and missing length-check bugs manifest as panics here.
fn truncation_sweep(bytes: &[u8], mut f: impl FnMut(&[u8])) {
    for cut in 0..=bytes.len() {
        f(&bytes[..cut]);
    }
}

proptest! {
    // ---- framing ----

    #[test]
    fn frame_never_panics_on_random_bytes(
        magic in prop::sample::select(&[MAINNET_MAGIC, TESTNET_MAGIC]),
        data in random_bytes(4096),
    ) {
        let _ = deserialize_frame(&magic, &data);
    }

    #[test]
    fn frame_roundtrips_and_survives_truncation(
        code in any::<u8>(),
        payload in random_bytes(1500),
    ) {
        let frame = MessageFrame { code, payload: payload.clone() };
        let bytes = serialize_frame(&MAINNET_MAGIC, &frame);
        let (back, consumed) =
            deserialize_frame(&MAINNET_MAGIC, &bytes).unwrap().unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(back.code, code);
        assert_eq!(back.payload, payload);
        truncation_sweep(&bytes, |prefix| {
            let _ = deserialize_frame(&MAINNET_MAGIC, prefix);
        });
    }

    // ---- handshake ----

    #[test]
    fn handshake_never_panics_on_random_bytes(data in random_bytes(2048)) {
        let _ = deserialize_handshake(&data);
    }

    #[test]
    fn handshake_roundtrips_and_survives_truncation(
        time in any::<u64>(),
        agent in ascii_string(1, 300),
        major in any::<u8>(),
        minor in any::<u8>(),
        patch in any::<u8>(),
        node_name in ascii_string(0, 300),
        declared in declared_addr_strategy(),
        features in prop::collection::vec(feature_strategy(), 0..=8),
    ) {
        let hs = Handshake {
            time,
            peer_spec: PeerSpec {
                agent_name: agent,
                version: Version { major, minor, patch },
                node_name,
                declared_address: declared,
                features,
            },
        };
        let bytes = serialize_handshake(&hs);
        truncation_sweep(&bytes, |prefix| {
            let _ = deserialize_handshake(prefix);
        });
        // The full form must parse; re-serialization is byte-identical.
        // This also covers the codec's silent-capping paths, each of which
        // keeps serialize idempotent: >255-byte names truncate, >127
        // features drop, and LocalAddress/declared ports above i32::MAX cap
        // (the parse side enforces that bound via `get_u32_exact`, mirroring
        // Scala's `getUInt().toIntExact`).
        let back = deserialize_handshake(&bytes).expect("full handshake must parse");
        assert_eq!(back.time, time);
        assert_eq!(serialize_handshake(&back), bytes);
    }

    // ---- message payload parsers ----

    #[test]
    fn message_parsers_never_panic_on_random_bytes(data in random_bytes(2048)) {
        let _ = deserialize_get_peers(&data);
        let _ = deserialize_inv(&data);
        let _ = deserialize_modifiers(&data);
        let _ = deserialize_peers(&data, 64);
        let _ = deserialize_peers(&data, 0);
        let _ = deserialize_sync_info(&data);
        let _ = deserialize_get_snapshots_info(&data);
        let _ = deserialize_snapshots_info(&data);
        let _ = deserialize_get_manifest(&data);
        let _ = deserialize_manifest(&data);
        let _ = deserialize_get_utxo_chunk(&data);
        let _ = deserialize_utxo_chunk(&data);
        let _ = deserialize_get_nipopow_proof(&data);
        let _ = deserialize_nipopow_proof(&data);
    }

    #[test]
    fn inv_roundtrips_and_survives_truncation(
        pair in (any::<u8>(), 1usize..=100)
            .prop_flat_map(|(type_id, count)| {
                (Just((type_id, count)), prop::collection::vec(id32(), count))
            }),
    ) {
        let ((type_id, count), ids) = pair;
        let data = InvData { type_id, ids };
        let bytes = serialize_inv(&data).unwrap();
        let back = deserialize_inv(&bytes).unwrap();
        assert_eq!(back.type_id, type_id);
        assert_eq!(back.ids.len(), count);
        truncation_sweep(&bytes, |prefix| {
            let _ = deserialize_inv(prefix);
        });
    }

    #[test]
    fn sync_info_v1_roundtrips_and_survives_truncation(
        pair in (1usize..=500).prop_flat_map(move |count| {
            (Just(count), prop::collection::vec(id32(), count))
        }),
    ) {
        let (count, ids) = pair;
        let info = SyncInfo::V1 { header_ids: ids };
        let bytes = serialize_sync_info(&info).unwrap();
        match deserialize_sync_info(&bytes).unwrap() {
            SyncInfo::V1 { header_ids } => assert_eq!(header_ids.len(), count),
            other => panic!("expected V1, got {other:?}"),
        }
        truncation_sweep(&bytes, |prefix| {
            let _ = deserialize_sync_info(prefix);
        });
    }

    #[test]
    fn sync_info_v2_roundtrips_and_survives_truncation(
        headers in prop::collection::vec(random_bytes(999), 1..=50),
    ) {
        let info = SyncInfo::V2 { headers: headers.clone() };
        let bytes = serialize_sync_info(&info).unwrap();
        match deserialize_sync_info(&bytes).unwrap() {
            SyncInfo::V2 { headers: back } => assert_eq!(back, headers),
            other => panic!("expected V2, got {other:?}"),
        }
        truncation_sweep(&bytes, |prefix| {
            let _ = deserialize_sync_info(prefix);
        });
    }

    #[test]
    fn modifiers_roundtrip_and_survive_truncation(
        pair in prop::sample::select(&[2u8, 101, 102, 104, 108])
            .prop_flat_map(move |type_id| {
                (1usize..=8).prop_flat_map(move |count| {
                    (Just((type_id, count)), prop::collection::vec((id32(), random_bytes(512)), count))
                })
            }),
    ) {
        let ((type_id, count), modifiers) = pair;
        let data = ModifiersData { type_id, modifiers };
        let bytes = serialize_modifiers(&data).unwrap();
        let back = deserialize_modifiers(&bytes).unwrap();
        assert_eq!(back.type_id, type_id);
        assert_eq!(back.modifiers.len(), count);
        truncation_sweep(&bytes, |prefix| {
            let _ = deserialize_modifiers(prefix);
        });
    }
}
