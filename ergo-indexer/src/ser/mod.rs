//! Wire-format serializers for indexed records, mirroring Scala's
//! `org.ergoplatform.nodeView.history.extra.ExtraIndexSerializer`.
//!
//! Each submodule covers one tag. Encoding rules (verified against the
//! disassembled `scorex.util.serialization.{Writer, VLQWriter}`
//! bytecode):
//! - `i32`/`i64` → VLQ-zigzag (`put_i32` / `put_i64` on `VlqWriter`).
//! - `u16` → unsigned VLQ (`put_u16`).
//! - `u8` → fixed 1 byte (`put_u8`).
//! - `Opt[X]` → 1-byte boolean marker (0 / 1) + body when present.
//! - 32-byte ids are written raw (no length prefix) since the length
//!   is a fixed schema constant.
//!
//! Tests in each submodule pin the exact byte sequences and roundtrip
//! equivalence.

pub mod boxes;
pub mod txs;

use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;
use ergo_ser::WriteError;

/// Scala `Writer.putBoolean(opt.isDefined)` followed by the body
/// when present. We reuse `put_u8` so the wire layout is the single
/// `0x00 | 0x01` discriminator byte the persisted form expects.
pub(crate) fn write_opt<T, F>(
    w: &mut VlqWriter,
    opt: Option<&T>,
    write_body: F,
) -> Result<(), WriteError>
where
    F: FnOnce(&mut VlqWriter, &T) -> Result<(), WriteError>,
{
    match opt {
        Some(v) => {
            w.put_u8(1);
            write_body(w, v)
        }
        None => {
            w.put_u8(0);
            Ok(())
        }
    }
}

pub(crate) fn read_opt<T, F>(r: &mut VlqReader, read_body: F) -> Result<Option<T>, ReadError>
where
    F: FnOnce(&mut VlqReader) -> Result<T, ReadError>,
{
    match r.get_u8()? {
        0 => Ok(None),
        1 => Ok(Some(read_body(r)?)),
        other => Err(ReadError::InvalidData(format!(
            "indexer Opt marker: expected 0 or 1, got {other}"
        ))),
    }
}
