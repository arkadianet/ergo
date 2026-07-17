use super::{ids, ActiveParamsError, ActiveProtocolParameters};
use crate::voting::validation_settings::ErgoValidationSettingsUpdate;

/// Encode for storage in the `voted_params` redb table.
///
/// Format (`[proposed]`):
/// ```text
/// u32   epoch_start_height (BE)
/// u8    field_count        // total ids written
/// { u8 id, i32 value (BE) } * field_count
/// ```
///
/// Validate that `extra` does not collide with any named parameter
/// id and contains no internal duplicates. The codec's deserialize
/// path rejects duplicate ids; without this check, a caller-supplied
/// `extra` could produce a row that is unreadable on the next open.
impl ActiveProtocolParameters {
    pub fn validate(&self) -> Result<(), ActiveParamsError> {
        const RESERVED: &[u8] = &[
            ids::STORAGE_FEE_FACTOR,
            ids::MIN_VALUE_PER_BYTE,
            ids::MAX_BLOCK_SIZE,
            ids::MAX_BLOCK_COST,
            ids::TOKEN_ACCESS_COST,
            ids::INPUT_COST,
            ids::DATA_INPUT_COST,
            ids::OUTPUT_COST,
            ids::SUBBLOCKS_PER_BLOCK,
            ids::BLOCK_VERSION,
        ];
        let mut seen = std::collections::BTreeSet::<u8>::new();
        for (id, _) in &self.extra {
            if RESERVED.contains(id) {
                return Err(ActiveParamsError::ExtraReservesNamedId(*id));
            }
            if !seen.insert(*id) {
                return Err(ActiveParamsError::ExtraDuplicateId(*id));
            }
        }
        Ok(())
    }

    /// Encode for storage. Returns an error if the type's invariant is
    /// violated (`extra` colliding with a reserved id, or duplicates in
    /// `extra`); see [`Self::validate`].
    ///
    /// Wire format **v2** (current writer):
    ///
    /// ```text
    /// u32 epoch_start_height (BE)
    /// u8  field_count
    /// { u8 id, i32 value (BE) } * field_count
    /// u32 proposed_update_blob_len (BE)
    /// { u8 } * proposed_update_blob_len
    /// u32 activated_update_blob_len (BE)
    /// { u8 } * activated_update_blob_len
    /// ```
    ///
    /// An earlier wire format (v1) omitted the trailing update blobs.
    /// [`Self::deserialize`] auto-detects: if the body length matches
    /// the v1 exact-length invariant, it decodes as v1 with empty
    /// update blobs; otherwise it expects the v2 trailing fields.
    /// New writes always emit v2.
    ///
    /// Internal format only — never sent on the wire.
    pub fn serialize(&self) -> Result<Vec<u8>, ActiveParamsError> {
        self.validate()?;

        let extra_len = self.extra.len();
        let mut entries: Vec<(u8, i32)> = Vec::with_capacity(11 + extra_len);
        entries.push((ids::STORAGE_FEE_FACTOR, self.storage_fee_factor));
        entries.push((ids::MIN_VALUE_PER_BYTE, self.min_value_per_byte));
        entries.push((ids::MAX_BLOCK_SIZE, self.max_block_size));
        entries.push((ids::MAX_BLOCK_COST, self.max_block_cost));
        entries.push((ids::TOKEN_ACCESS_COST, self.token_access_cost));
        entries.push((ids::INPUT_COST, self.input_cost));
        entries.push((ids::DATA_INPUT_COST, self.data_input_cost));
        entries.push((ids::OUTPUT_COST, self.output_cost));
        if let Some(v) = self.subblocks_per_block {
            entries.push((ids::SUBBLOCKS_PER_BLOCK, v));
        }
        entries.push((ids::BLOCK_VERSION, self.block_version as i32));
        entries.extend(self.extra.iter().copied());
        entries.sort_by_key(|(id, _)| *id);

        let count: u8 = entries.len() as u8;
        let proposed_blob = self.proposed_update.serialize();
        let activated_blob = self.activated_update.serialize();
        let mut out = Vec::with_capacity(
            4 + 1 + entries.len() * 5 + 4 + proposed_blob.len() + 4 + activated_blob.len(),
        );
        out.extend_from_slice(&self.epoch_start_height.to_be_bytes());
        out.push(count);
        for (id, v) in entries {
            out.push(id);
            out.extend_from_slice(&v.to_be_bytes());
        }
        // v2 trailing: proposed_update + activated_update length-prefixed.
        out.extend_from_slice(&(proposed_blob.len() as u32).to_be_bytes());
        out.extend_from_slice(&proposed_blob);
        out.extend_from_slice(&(activated_blob.len() as u32).to_be_bytes());
        out.extend_from_slice(&activated_blob);
        Ok(out)
    }

    /// Decode a record produced by `serialize`. Auto-detects v1 vs v2
    /// based on whether the body matches the v1 exact-length invariant
    /// or has v2 trailing fields.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ActiveParamsError> {
        if bytes.len() < 5 {
            return Err(ActiveParamsError::UnexpectedEof);
        }
        let epoch_start_height = u32::from_be_bytes(
            bytes[0..4]
                .try_into()
                .expect("4-byte slice to [u8; 4] is infallible"),
        );
        let count = bytes[4] as usize;
        let body_start = 5usize;
        let entries_end = body_start + count * 5;
        if bytes.len() < entries_end {
            return Err(ActiveParamsError::UnexpectedEof);
        }
        let body = &bytes[body_start..entries_end];

        // v1 body length is exactly count * 5; v2 has trailing
        // length-prefixed update blobs.
        let trailing = &bytes[entries_end..];
        let (proposed_update, activated_update) = if trailing.is_empty() {
            // v1 wire format: no update blobs persisted.
            (
                ErgoValidationSettingsUpdate::empty(),
                ErgoValidationSettingsUpdate::empty(),
            )
        } else {
            // v2: parse proposed_update + activated_update.
            if trailing.len() < 4 {
                return Err(ActiveParamsError::UnexpectedEof);
            }
            let proposed_len = u32::from_be_bytes(
                trailing[0..4]
                    .try_into()
                    .expect("4-byte slice to [u8; 4] is infallible"),
            ) as usize;
            let proposed_end = 4 + proposed_len;
            if trailing.len() < proposed_end + 4 {
                return Err(ActiveParamsError::UnexpectedEof);
            }
            let proposed =
                ErgoValidationSettingsUpdate::deserialize_exact(&trailing[4..proposed_end])?;
            let activated_len_offset = proposed_end;
            let activated_len = u32::from_be_bytes(
                trailing[activated_len_offset..activated_len_offset + 4]
                    .try_into()
                    .expect("4-byte slice to [u8; 4] is infallible"),
            ) as usize;
            let activated_start = activated_len_offset + 4;
            let activated_end = activated_start + activated_len;
            if trailing.len() < activated_end {
                return Err(ActiveParamsError::UnexpectedEof);
            }
            let activated = ErgoValidationSettingsUpdate::deserialize_exact(
                &trailing[activated_start..activated_end],
            )?;
            if trailing.len() != activated_end {
                return Err(ActiveParamsError::TrailingBytes);
            }
            (proposed, activated)
        };

        let mut by_id: std::collections::BTreeMap<u8, i32> = std::collections::BTreeMap::new();
        for chunk in body.chunks_exact(5) {
            let id = chunk[0];
            let v = i32::from_be_bytes(
                chunk[1..5]
                    .try_into()
                    .expect("4-byte slice to [u8; 4] is infallible"),
            );
            if by_id.insert(id, v).is_some() {
                return Err(ActiveParamsError::CodecDuplicateId(id));
            }
        }

        let mut take = |id: u8| {
            by_id
                .remove(&id)
                .ok_or(ActiveParamsError::MissingRequired(id))
        };
        // Non-negativity-constrained fields fail-close at the codec
        // boundary so `ProtocolParams::from_active` stays infallible.
        // Same contract as parse_active_params.
        let mut take_nonneg = |id: u8| -> Result<i32, ActiveParamsError> {
            let v = take(id)?;
            if v < 0 {
                return Err(ActiveParamsError::NegativeProtocolParam { id, value: v });
            }
            Ok(v)
        };
        let storage_fee_factor = take_nonneg(ids::STORAGE_FEE_FACTOR)?;
        let min_value_per_byte = take_nonneg(ids::MIN_VALUE_PER_BYTE)?;
        let max_block_size = take_nonneg(ids::MAX_BLOCK_SIZE)?;
        let max_block_cost = take_nonneg(ids::MAX_BLOCK_COST)?;
        let token_access_cost = take_nonneg(ids::TOKEN_ACCESS_COST)?;
        let input_cost = take_nonneg(ids::INPUT_COST)?;
        let data_input_cost = take_nonneg(ids::DATA_INPUT_COST)?;
        let output_cost = take_nonneg(ids::OUTPUT_COST)?;
        let block_version_i32 = take(ids::BLOCK_VERSION)?;
        // On parse-from-extension we silently truncate to match Scala's
        // `.toByte`; on decode-from-DB the row is ours, and an out-of-range
        // value means corruption. Fail loud.
        if !(0..=255).contains(&block_version_i32) {
            return Err(ActiveParamsError::BlockVersionOutOfRange(block_version_i32));
        }
        let subblocks_per_block = by_id.remove(&ids::SUBBLOCKS_PER_BLOCK);
        let extra: Vec<(u8, i32)> = by_id.into_iter().collect();

        Ok(Self {
            epoch_start_height,
            block_version: block_version_i32 as u8,
            storage_fee_factor,
            min_value_per_byte,
            max_block_size,
            max_block_cost,
            token_access_cost,
            input_cost,
            data_input_cost,
            output_cost,
            subblocks_per_block,
            extra,
            proposed_update,
            activated_update,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::extension_codec::parse_active_params;
    use super::super::ids;
    use super::*;
    use crate::active_params::launch::scala_launch;
    use ergo_primitives::digest::ModifierId;
    use ergo_ser::extension::{Extension, ExtensionField};

    fn ext_with(fields: Vec<([u8; 2], Vec<u8>)>) -> Extension {
        Extension {
            header_id: ModifierId::from_bytes([0u8; 32]),
            fields: fields
                .into_iter()
                .map(|(k, v)| ExtensionField { key: k, value: v })
                .collect(),
        }
    }

    fn be_i32(v: i32) -> Vec<u8> {
        v.to_be_bytes().to_vec()
    }

    fn full_required_set() -> Vec<([u8; 2], Vec<u8>)> {
        vec![
            ([0x00, 1], be_i32(1_250_000)),
            ([0x00, 2], be_i32(360)),
            ([0x00, 3], be_i32(524_288)),
            ([0x00, 4], be_i32(1_000_000)),
            ([0x00, 5], be_i32(100)),
            ([0x00, 6], be_i32(2_000)),
            ([0x00, 7], be_i32(100)),
            ([0x00, 8], be_i32(100)),
            ([0x00, 123], be_i32(1)),
        ]
    }

    #[test]
    fn codec_roundtrip_required_only() {
        let p = parse_active_params(&ext_with(full_required_set()), 1024).unwrap();
        let bytes = p.serialize().unwrap();
        let back = ActiveProtocolParameters::deserialize(&bytes).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn codec_roundtrip_with_subblocks_and_extras() {
        let mut fields = full_required_set();
        fields.push(([0x00, 9], be_i32(30)));
        fields.push(([0x00, 120], be_i32(7)));
        fields.push(([0x00, 121], be_i32(42)));
        let p = parse_active_params(&ext_with(fields), 1_772_544).unwrap();
        let bytes = p.serialize().unwrap();
        let back = ActiveProtocolParameters::deserialize(&bytes).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn codec_roundtrip_scala_launch() {
        let p = scala_launch();
        let bytes = p.serialize().unwrap();
        let back = ActiveProtocolParameters::deserialize(&bytes).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn codec_rejects_truncated_input() {
        let bytes = vec![0u8; 4]; // missing field_count
        let err = ActiveProtocolParameters::deserialize(&bytes).unwrap_err();
        assert_eq!(err, ActiveParamsError::UnexpectedEof);
    }

    #[test]
    fn codec_rejects_trailing_bytes() {
        let p = scala_launch();
        let mut bytes = p.serialize().unwrap();
        bytes.push(0xAB);
        let err = ActiveProtocolParameters::deserialize(&bytes).unwrap_err();
        assert_eq!(err, ActiveParamsError::TrailingBytes);
    }

    #[test]
    fn codec_rejects_duplicate_id_on_decode() {
        // Hand-craft a v1-format payload with a duplicate id.
        let p = scala_launch();
        let mut entries: Vec<(u8, i32)> = vec![
            (1, p.storage_fee_factor),
            (2, p.min_value_per_byte),
            (3, p.max_block_size),
            (4, p.max_block_cost),
            (5, p.token_access_cost),
            (6, p.input_cost),
            (7, p.data_input_cost),
            (8, p.output_cost),
            (123, p.block_version as i32),
        ];
        entries.push((1, 99)); // duplicate id 1
        let count = entries.len() as u8;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&p.epoch_start_height.to_be_bytes());
        bytes.push(count);
        for (id, v) in entries {
            bytes.push(id);
            bytes.extend_from_slice(&v.to_be_bytes());
        }
        // No v2 trailing — this is a v1-format payload (auto-detected
        // because trailing is empty).
        let err = ActiveProtocolParameters::deserialize(&bytes).unwrap_err();
        assert_eq!(err, ActiveParamsError::CodecDuplicateId(1));
    }

    #[test]
    fn serialize_is_deterministic_ascending_ids() {
        let mut fields = full_required_set();
        fields.push(([0x00, 9], be_i32(30)));
        fields.push(([0x00, 122], be_i32(900_000)));
        let p = parse_active_params(&ext_with(fields), 1_772_544).unwrap();

        let bytes = p.serialize().unwrap();
        // Read the count byte at offset 4, then walk count*5 entry
        // bytes starting at 5. v2 trailing fields follow the entries.
        let count = bytes[4] as usize;
        let entries_end = 5 + count * 5;
        let body = &bytes[5..entries_end];
        let ids: Vec<u8> = body.chunks_exact(5).map(|c| c[0]).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
        assert_eq!(ids, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 122, 123]);
    }

    #[test]
    fn codec_v2_persists_proposed_and_activated_updates() {
        let mut p = scala_launch();
        p.proposed_update = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![409],
            status_updates: vec![],
        };
        p.activated_update = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![409],
            status_updates: vec![],
        };
        let bytes = p.serialize().unwrap();
        let back = ActiveProtocolParameters::deserialize(&bytes).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn codec_v1_legacy_decodes_with_empty_updates() {
        // Hand-craft a v1-format payload (no trailing update blobs).
        let p = scala_launch();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&p.epoch_start_height.to_be_bytes());
        bytes.push(9); // 9 entries: ids 1-8 + 123
        for (id, v) in [
            (1, p.storage_fee_factor),
            (2, p.min_value_per_byte),
            (3, p.max_block_size),
            (4, p.max_block_cost),
            (5, p.token_access_cost),
            (6, p.input_cost),
            (7, p.data_input_cost),
            (8, p.output_cost),
            (123, p.block_version as i32),
        ] {
            bytes.push(id);
            bytes.extend_from_slice(&v.to_be_bytes());
        }
        // No trailing — v1.
        let back = ActiveProtocolParameters::deserialize(&bytes).unwrap();
        assert_eq!(back.proposed_update, ErgoValidationSettingsUpdate::empty());
        assert_eq!(back.activated_update, ErgoValidationSettingsUpdate::empty());
        assert_eq!(back.input_cost, p.input_cost);
    }

    #[test]
    fn validate_rejects_extra_with_reserved_id() {
        let mut p = scala_launch();
        p.extra = vec![(1, 999_999)]; // id 1 is storage_fee_factor
        let err = p.serialize().unwrap_err();
        assert_eq!(err, ActiveParamsError::ExtraReservesNamedId(1));
    }

    #[test]
    fn validate_rejects_extra_with_internal_duplicate() {
        let mut p = scala_launch();
        p.extra = vec![(120, 1), (120, 2)];
        let err = p.serialize().unwrap_err();
        assert_eq!(err, ActiveParamsError::ExtraDuplicateId(120));
    }

    #[test]
    fn deserialize_rejects_block_version_out_of_range() {
        // Hand-craft a row where block_version (id=123) holds 256 (== 0x100)
        let bytes = {
            let mut p = scala_launch();
            p.block_version = 1;
            let mut wire = p.serialize().unwrap();
            // Replace the i32 bytes for id 123 with 0x00000100 (== 256)
            // wire layout: 4-byte height + 1-byte count + entries.
            // Locate id 123 entry.
            let count = wire[4] as usize;
            for i in 0..count {
                let off = 5 + i * 5;
                if wire[off] == 123 {
                    wire[off + 1..off + 5].copy_from_slice(&256i32.to_be_bytes());
                    break;
                }
            }
            wire
        };
        let err = ActiveProtocolParameters::deserialize(&bytes).unwrap_err();
        assert_eq!(err, ActiveParamsError::BlockVersionOutOfRange(256));
    }

    #[test]
    fn deserialize_rejects_negative_cost_bearing_param() {
        // Storage corruption case: a row has a negative i32 in a
        // cost-bearing slot. The codec must reject at this boundary so
        // `ProtocolParams::from_active` can stay infallible.
        let bytes = {
            let mut wire = scala_launch().serialize().unwrap();
            // Find input_cost (id=6) and overwrite its i32 with -1.
            let count = wire[4] as usize;
            for i in 0..count {
                let off = 5 + i * 5;
                if wire[off] == ids::INPUT_COST {
                    wire[off + 1..off + 5].copy_from_slice(&(-1i32).to_be_bytes());
                    break;
                }
            }
            wire
        };
        let err = ActiveProtocolParameters::deserialize(&bytes).unwrap_err();
        assert_eq!(
            err,
            ActiveParamsError::NegativeProtocolParam {
                id: ids::INPUT_COST,
                value: -1
            },
        );
    }
}
