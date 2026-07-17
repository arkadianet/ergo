//! `AvlTree` value codec: 33-byte digest, mutability flags, and the
//! Scala-parity wrapping `keyLength` / `valueLengthOpt` reads.

use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use super::AvlTreeData;

// -- AvlTree serialization --

pub(super) fn write_avl_tree(w: &mut VlqWriter, avl: &AvlTreeData) {
    // Raw digest bytes, NO length prefix (Scala AvlTreeData.serializer:
    // `putBytes(digest.toArray)`). Wire-derived / literal trees always carry a
    // 33-byte digest, so the emitted bytes are unchanged from the old fixed
    // `ADDigest`; a runtime updateDigest result is consumed in-memory and never
    // re-serialized to the AvlTree wire.
    w.put_bytes(&avl.digest);
    let flags = (avl.insert_allowed as u8)
        | ((avl.update_allowed as u8) << 1)
        | ((avl.remove_allowed as u8) << 2);
    w.put_u8(flags);
    // Write the signed length back through the unsigned VLQ codec (round-trips
    // the original bytes for a wrapped-negative length). Scala's putUInt would
    // throw on a negative length; that only matters for re-serializing an
    // already-invalid tree, which is out of scope here.
    w.put_u32(avl.key_length as u32);
    // Scala: w.putOption(data.valueLengthOpt)(_.putUInt(_))
    match avl.value_length_opt {
        None => w.put_u8(0),
        Some(len) => {
            w.put_u8(1);
            w.put_u32(len as u32);
        }
    }
}

pub(super) fn read_avl_tree(r: &mut VlqReader) -> Result<AvlTreeData, ReadError> {
    // Wire digest is ALWAYS a fixed 33 bytes (Scala AvlTreeData.parse reads
    // `getBytes(DigestSize=33)`, no length prefix); store as a Vec. A
    // length-prefixed read would fork.
    let digest = r.get_array::<33>()?.to_vec();

    let flags = r.get_u8()?;
    let insert_allowed = flags & 0x01 != 0;
    let update_allowed = flags & 0x02 != 0;
    let remove_allowed = flags & 0x04 != 0;

    // Scala AvlTreeData.parse: keyLength = r.getUInt().toInt — a length above
    // i32::MAX WRAPS to a negative Int (the deserializer succeeds with
    // invalid-but-parseable AvlTreeData), it is NOT rejected. (Previously
    // get_u32_exact rejected it, erroring the whole tree.)
    let key_length = r.get_uint_to_i32()?;
    // Scala: r.getOption(r.getUInt().toInt) — reads 1-byte flag, then optional VLQ uint
    let has_value_length = r.get_u8()?;
    let value_length_opt = if has_value_length != 0 {
        Some(r.get_uint_to_i32()?)
    } else {
        None
    };

    Ok(AvlTreeData {
        digest,
        insert_allowed,
        update_allowed,
        remove_allowed,
        key_length,
        value_length_opt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma_type::SigmaType;
    use crate::sigma_value::{read_value, write_value, SigmaValue};

    // ----- helpers -----

    fn roundtrip_value(tpe: &SigmaType, val: &SigmaValue) {
        let mut w = VlqWriter::new();
        write_value(&mut w, tpe, val).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_value(&mut r, tpe).unwrap();
        assert!(r.is_empty(), "leftover bytes for {tpe:?}");
        assert_eq!(&decoded, val);
    }

    // ===== 5. AvlTree roundtrips =====

    /// Scala `AvlTreeData.parse`: `keyLength = r.getUInt().toInt` — a length
    /// encoding above `i32::MAX` WRAPS to a negative `Int` and the deserializer
    /// SUCCEEDS with invalid-but-parseable `AvlTreeData` (it is NOT rejected,
    /// as `getUIntExact` would). Same for `valueLengthOpt`.
    #[test]
    fn read_avl_tree_wraps_lengths_above_i32_max() {
        let mut w = VlqWriter::new();
        w.put_bytes(&[0x07u8; 33]); // 33-byte digest
        w.put_u8(0x07); // flags: insert/update/remove allowed
        w.put_u32(0x8000_0000); // keyLength = 2^31 -> i32::MIN
        w.put_u8(0x01); // valueLengthOpt present
        w.put_u32(0xFFFF_FFFF); // valueLengthOpt = 2^32-1 -> -1
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        match read_value(&mut r, &SigmaType::SAvlTree)
            .expect("AvlTree must parse (not reject) a wrapped keyLength/valueLengthOpt")
        {
            SigmaValue::AvlTree(avl) => {
                assert_eq!(avl.key_length, i32::MIN, "keyLength 2^31 wraps to i32::MIN");
                assert_eq!(
                    avl.value_length_opt,
                    Some(-1),
                    "valueLengthOpt 2^32-1 wraps to -1"
                );
            }
            other => panic!("expected AvlTree, got {other:?}"),
        }
        assert!(r.is_empty(), "all bytes consumed");
    }

    #[test]
    fn roundtrip_avl_tree_with_value_length() {
        let avl = AvlTreeData {
            digest: vec![0xAB; 33],
            insert_allowed: true,
            update_allowed: false,
            remove_allowed: true,
            key_length: 32,
            value_length_opt: Some(8),
        };
        roundtrip_value(&SigmaType::SAvlTree, &SigmaValue::AvlTree(avl));
    }

    #[test]
    fn roundtrip_avl_tree_without_value_length() {
        let avl = AvlTreeData {
            digest: vec![0xCD; 33],
            insert_allowed: false,
            update_allowed: true,
            remove_allowed: false,
            key_length: 64,
            value_length_opt: None,
        };
        roundtrip_value(&SigmaType::SAvlTree, &SigmaValue::AvlTree(avl));
    }
}
