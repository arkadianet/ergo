//! Collection value codecs — bit-packed `Coll[Boolean]`, raw-byte
//! `Coll[Byte]`, generic collections — and the `Option` value codec.

use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;
use crate::sigma_type::SigmaType;

use super::{read_value_at_depth, write_value, CollValue, SigmaValue};

// -- Collection serialization --

pub(super) fn write_coll(
    w: &mut VlqWriter,
    elem_type: &SigmaType,
    coll: &CollValue,
) -> Result<(), WriteError> {
    // Scala writes Coll length as a u16 across all element-type
    // specializations; >65535-element collections silently wrap on
    // `as u16`. Cap once for all three branches.
    let len_for_cap = match coll {
        CollValue::BoolBits(b) => b.len(),
        CollValue::Bytes(b) => b.len(),
        CollValue::Values(v) => v.len(),
    };
    assert!(
        len_for_cap <= u16::MAX as usize,
        "Coll length too large for Scala wire format: {len_for_cap} (max 65535)",
    );
    match (elem_type, coll) {
        (SigmaType::SBoolean, CollValue::BoolBits(bits)) => {
            w.put_u16(bits.len() as u16);
            write_bits(w, bits);
        }
        (SigmaType::SByte, CollValue::Bytes(bytes)) => {
            w.put_u16(bytes.len() as u16);
            w.put_bytes(bytes);
        }
        (_, CollValue::Values(vals)) => {
            w.put_u16(vals.len() as u16);
            for v in vals {
                write_value(w, elem_type, v)?;
            }
        }
        _ => {
            return Err(WriteError::InvalidData(format!(
                "collection type/value mismatch: elem_type={elem_type:?}"
            )));
        }
    }
    Ok(())
}

pub(super) fn read_coll(
    r: &mut VlqReader,
    elem_type: &SigmaType,
    depth: usize,
) -> Result<CollValue, ReadError> {
    let count = r.get_u16()? as usize;
    match elem_type {
        SigmaType::SBoolean => {
            let bits = read_bits(r, count)?;
            Ok(CollValue::BoolBits(bits))
        }
        SigmaType::SByte => {
            let bytes = r.get_bytes(count)?;
            Ok(CollValue::Bytes(bytes.to_vec()))
        }
        _ => {
            let mut vals = Vec::with_capacity(count);
            for _ in 0..count {
                vals.push(read_value_at_depth(r, elem_type, depth + 1)?);
            }
            Ok(CollValue::Values(vals))
        }
    }
}

// -- Bit-packing for Coll[Boolean] --

fn write_bits(w: &mut VlqWriter, bits: &[bool]) {
    let byte_count = bits.len().div_ceil(8);
    for i in 0..byte_count {
        let mut byte = 0u8;
        for bit_idx in 0..8 {
            let flat_idx = i * 8 + bit_idx;
            if flat_idx < bits.len() && bits[flat_idx] {
                byte |= 1 << bit_idx; // LSB-first (matches Scala)
            }
        }
        w.put_u8(byte);
    }
}

fn read_bits(r: &mut VlqReader, count: usize) -> Result<Vec<bool>, ReadError> {
    let byte_count = count.div_ceil(8);
    let bytes = r.get_bytes(byte_count)?;
    let mut bits = Vec::with_capacity(count);
    for i in 0..count {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        bits.push((bytes[byte_idx] >> bit_idx) & 1 == 1); // LSB-first (matches Scala)
    }
    Ok(bits)
}

// -- Option serialization --

pub(super) fn write_option(
    w: &mut VlqWriter,
    elem_type: &SigmaType,
    opt: &Option<Box<SigmaValue>>,
) -> Result<(), WriteError> {
    match opt {
        None => w.put_u8(0x00),
        Some(val) => {
            w.put_u8(0x01);
            write_value(w, elem_type, val)?;
        }
    }
    Ok(())
}

pub(super) fn read_option(
    r: &mut VlqReader,
    elem_type: &SigmaType,
    depth: usize,
) -> Result<Option<Box<SigmaValue>>, ReadError> {
    // scorex VLQReader.getOption: `if (tag != 0) Some(getValue) else None`.
    // ANY nonzero discriminant byte (not just 0x01) is Some; only 0x00 is
    // None. The SOption data path delegates to this reader, so e.g. tag 0x02
    // deserializes as Some(value).
    let tag = r.get_u8()?;
    if tag == 0 {
        Ok(None)
    } else {
        let val = read_value_at_depth(r, elem_type, depth + 1)?;
        Ok(Some(Box::new(val)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma_value::read_value;

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

    /// scorex `VLQReader.getOption` reads one discriminant byte and treats
    /// ANY nonzero value as `Some` (`if (tag != 0) Some(getValue) else None`)
    /// — only `0x00` is `None`. We previously rejected any tag other than
    /// 0x00/0x01.
    #[test]
    fn read_option_treats_any_nonzero_tag_as_some() {
        let tpe = SigmaType::SOption(Box::new(SigmaType::SInt));
        // Encode Some(Int 5): write_option emits discriminant 0x01 + payload.
        let mut w = VlqWriter::new();
        write_value(
            &mut w,
            &tpe,
            &SigmaValue::Opt(Some(Box::new(SigmaValue::Int(5)))),
        )
        .unwrap();
        let mut bytes = w.result();
        assert_eq!(bytes[0], 0x01, "Some writes discriminant 0x01");

        // Flip the discriminant to 0x02 — scorex still reads it as Some.
        bytes[0] = 0x02;
        let mut r = VlqReader::new(&bytes);
        let decoded = read_value(&mut r, &tpe).unwrap();
        assert!(r.is_empty(), "option read must consume all bytes");
        assert_eq!(
            decoded,
            SigmaValue::Opt(Some(Box::new(SigmaValue::Int(5)))),
            "any nonzero Option discriminant must decode as Some",
        );

        // 0x00 still decodes as None.
        let mut r0 = VlqReader::new(&[0x00]);
        assert_eq!(
            read_value(&mut r0, &tpe).unwrap(),
            SigmaValue::Opt(None),
            "0x00 discriminant is None",
        );
    }

    // ===== 3. Collection roundtrips =====

    #[test]
    fn roundtrip_coll_byte() {
        let coll = CollValue::Bytes(vec![0x01, 0x02, 0xFF, 0x00]);
        roundtrip_value(
            &SigmaType::SColl(Box::new(SigmaType::SByte)),
            &SigmaValue::Coll(coll),
        );
    }

    #[test]
    fn roundtrip_coll_byte_empty() {
        let coll = CollValue::Bytes(vec![]);
        roundtrip_value(
            &SigmaType::SColl(Box::new(SigmaType::SByte)),
            &SigmaValue::Coll(coll),
        );
    }

    #[test]
    fn roundtrip_coll_int() {
        let coll = CollValue::Values(vec![
            SigmaValue::Int(1),
            SigmaValue::Int(-42),
            SigmaValue::Int(i32::MAX),
        ]);
        roundtrip_value(
            &SigmaType::SColl(Box::new(SigmaType::SInt)),
            &SigmaValue::Coll(coll),
        );
    }

    #[test]
    fn roundtrip_coll_boolean_bitpacked() {
        let bits = vec![true, false, true, true, false, false, true, false, true];
        let coll = CollValue::BoolBits(bits);
        roundtrip_value(
            &SigmaType::SColl(Box::new(SigmaType::SBoolean)),
            &SigmaValue::Coll(coll),
        );
    }

    #[test]
    fn roundtrip_coll_boolean_exact_byte_boundary() {
        let bits = vec![true, false, true, false, true, false, true, false]; // exactly 8
        let coll = CollValue::BoolBits(bits);
        roundtrip_value(
            &SigmaType::SColl(Box::new(SigmaType::SBoolean)),
            &SigmaValue::Coll(coll),
        );
    }

    #[test]
    fn roundtrip_coll_boolean_empty() {
        let coll = CollValue::BoolBits(vec![]);
        roundtrip_value(
            &SigmaType::SColl(Box::new(SigmaType::SBoolean)),
            &SigmaValue::Coll(coll),
        );
    }

    // ===== 4. Nested roundtrips =====

    #[test]
    fn roundtrip_coll_coll_byte() {
        let inner1 = SigmaValue::Coll(CollValue::Bytes(vec![0x01, 0x02]));
        let inner2 = SigmaValue::Coll(CollValue::Bytes(vec![0x03]));
        let coll = CollValue::Values(vec![inner1, inner2]);
        let tpe = SigmaType::SColl(Box::new(SigmaType::SColl(Box::new(SigmaType::SByte))));
        roundtrip_value(&tpe, &SigmaValue::Coll(coll));
    }

    #[test]
    fn roundtrip_option_int_some() {
        let tpe = SigmaType::SOption(Box::new(SigmaType::SInt));
        let val = SigmaValue::Opt(Some(Box::new(SigmaValue::Int(42))));
        roundtrip_value(&tpe, &val);
    }

    #[test]
    fn roundtrip_option_int_none() {
        let tpe = SigmaType::SOption(Box::new(SigmaType::SInt));
        let val = SigmaValue::Opt(None);
        roundtrip_value(&tpe, &val);
    }

    #[test]
    fn golden_bit_packing() {
        // 9 bools: [T,F,T,T,F,F,T,F, T]  — LSB-first packing
        // byte 0: bits 0-7 → 0b_0100_1101 = 0x4D
        // byte 1: bit 8 → 0b_0000_0001 = 0x01
        let mut w = VlqWriter::new();
        let bits = vec![true, false, true, true, false, false, true, false, true];
        write_bits(&mut w, &bits);
        assert_eq!(w.result(), [0x4D, 0x01]);
    }
}
