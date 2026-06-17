//! Byte-exact port of the JVM's `new String(bytes, StandardCharsets.UTF_8)`
//! lossy UTF-8 decode, used by the Scala reference node when reading
//! `STypeVar` names (`TypeSerializer.scala:204`) and `SString` values
//! (`CoreDataSerializer.scala:104-110`).
//!
//! Why not `String::from_utf8_lossy`: the two decoders DISAGREE on the
//! replacement count for some ill-formed input. Rust follows the WHATWG /
//! Unicode "maximal subpart" recommendation; the JDK's `sun.nio.cs.UTF_8`
//! decoder does not apply the WHATWG range restriction on the *second* byte
//! of an `ED..` sequence — it tentatively decodes the three bytes, finds a
//! surrogate, and emits a SINGLE U+FFFD consuming all three. WHATWG/Rust
//! emit three. e.g. `ed a0 80`: JVM → 1× U+FFFD, Rust → 3× U+FFFD.
//!
//! Consensus relevance: the node hashes the *original* wire bytes for box
//! and transaction ids (so the decoded string never re-enters a consensus
//! hash), but a decoded `SString` value is `EQ`-compared and length-costed
//! at script evaluation, so the decoded codepoints MUST agree with the Scala
//! node byte-for-byte. This module is the parity point.
//!
//! Expected values in the test module come from the actual JVM (Corretto 17
//! `new String(bytes, UTF_8)`), never from this function — see the
//! `----- oracle parity -----` section.

const REPL: char = '\u{FFFD}';

/// Decode `bytes` exactly as the JVM's `new String(bytes, UTF_8)` does:
/// well-formed sequences decode normally, every ill-formed subsequence is
/// replaced by U+FFFD with the JDK decoder's replacement counting.
pub fn decode(bytes: &[u8]) -> String {
    let n = bytes.len();
    let mut out = String::with_capacity(n);
    let mut i = 0;
    while i < n {
        let b1 = bytes[i];
        if b1 < 0x80 {
            out.push(b1 as char);
            i += 1;
        } else if b1 >> 5 == 0b110 {
            // 2-byte lead 0xc0..=0xdf
            if b1 < 0xc2 {
                // 0xc0/0xc1 are always overlong → malformed length 1
                out.push(REPL);
                i += 1;
            } else if i + 1 >= n {
                // truncated at end of input → single replacement
                out.push(REPL);
                i = n;
            } else {
                let b2 = bytes[i + 1];
                if !is_cont(b2) {
                    out.push(REPL);
                    i += 1;
                } else {
                    let cp = ((b1 as u32 & 0x1f) << 6) | (b2 as u32 & 0x3f);
                    out.push(char::from_u32(cp).unwrap());
                    i += 2;
                }
            }
        } else if b1 >> 4 == 0b1110 {
            // 3-byte lead 0xe0..=0xef
            let rem = n - i;
            if rem < 3 {
                // truncated: JDK reports malformed length 1 only if the
                // available second byte is already invalid, else underflow
                // (single replacement consuming the remainder).
                if rem == 2 && is_malformed3_2(b1, bytes[i + 1]) {
                    out.push(REPL);
                    i += 1;
                } else {
                    out.push(REPL);
                    i = n;
                }
            } else {
                let b2 = bytes[i + 1];
                let b3 = bytes[i + 2];
                if is_malformed3(b1, b2, b3) {
                    // length = 1 if b1==E0 with overlong b2, or b2 non-cont; else 2
                    let consumed = if (b1 == 0xe0 && (b2 & 0xe0) == 0x80) || !is_cont(b2) {
                        1
                    } else {
                        2
                    };
                    out.push(REPL);
                    i += consumed;
                } else {
                    let cp =
                        ((b1 as u32 & 0x0f) << 12) | ((b2 as u32 & 0x3f) << 6) | (b3 as u32 & 0x3f);
                    if (0xd800..=0xdfff).contains(&cp) {
                        // tentatively-decoded surrogate → one replacement, 3 bytes
                        out.push(REPL);
                        i += 3;
                    } else {
                        out.push(char::from_u32(cp).unwrap());
                        i += 3;
                    }
                }
            }
        } else if b1 >> 3 == 0b11110 {
            // 4-byte lead 0xf0..=0xf7 (incl. the always-invalid 0xf5..=0xf7)
            let rem = n - i;
            if rem < 4 {
                if rem >= 2 && is_malformed4_2(b1, bytes[i + 1]) {
                    out.push(REPL);
                    i += 1;
                } else if rem >= 3 && !is_cont(bytes[i + 2]) {
                    out.push(REPL);
                    i += 2;
                } else {
                    out.push(REPL);
                    i = n;
                }
            } else {
                let b2 = bytes[i + 1];
                let b3 = bytes[i + 2];
                let b4 = bytes[i + 3];
                if is_malformed4_2(b1, b2) {
                    out.push(REPL);
                    i += 1;
                } else if !is_cont(b3) {
                    out.push(REPL);
                    i += 2;
                } else if !is_cont(b4) {
                    out.push(REPL);
                    i += 3;
                } else {
                    let cp = ((b1 as u32 & 0x07) << 18)
                        | ((b2 as u32 & 0x3f) << 12)
                        | ((b3 as u32 & 0x3f) << 6)
                        | (b4 as u32 & 0x3f);
                    out.push(char::from_u32(cp).unwrap());
                    i += 4;
                }
            }
        } else {
            // lone continuation 0x80..=0xbf or invalid lead 0xf8..=0xff
            out.push(REPL);
            i += 1;
        }
    }
    out
}

#[inline]
fn is_cont(b: u8) -> bool {
    b & 0xc0 == 0x80
}

/// JDK `isMalformed3_2`: validity of the first two bytes of a 3-byte sequence.
#[inline]
fn is_malformed3_2(b1: u8, b2: u8) -> bool {
    (b1 == 0xe0 && (b2 & 0xe0) == 0x80) || !is_cont(b2)
}

/// JDK `isMalformed3`: full 3-byte form check (excluding the surrogate test,
/// which the caller applies on the decoded code point).
#[inline]
fn is_malformed3(b1: u8, b2: u8, b3: u8) -> bool {
    (b1 == 0xe0 && (b2 & 0xe0) == 0x80) || !is_cont(b2) || !is_cont(b3)
}

/// JDK `isMalformed4_2`: validity of the first two bytes of a 4-byte
/// sequence, incl. the F0 overlong and F4 (> U+10FFFF) range limits and the
/// always-invalid 0xf5..=0xf7 leads.
#[inline]
fn is_malformed4_2(b1: u8, b2: u8) -> bool {
    b1 > 0xf4
        || (b1 == 0xf0 && !(0x90..=0xbf).contains(&b2))
        || (b1 == 0xf4 && (b2 & 0xf0) != 0x80)
        || !is_cont(b2)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn dec_hex(input_hex: &str) -> String {
        let s = decode(&hx(input_hex));
        s.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    // ----- happy path -----

    #[test]
    fn well_formed_ascii_and_multibyte_pass_through() {
        for (input, expected) in [
            ("", ""),
            ("54", "54"),
            ("c3a9", "c3a9"),
            ("e282ac", "e282ac"),
            ("f09f9880", "f09f9880"),
            ("c280", "c280"),
            ("dfbf", "dfbf"),
            ("e0a080", "e0a080"),
            ("efbfbf", "efbfbf"),
            ("ec8080", "ec8080"),
            ("f0908080", "f0908080"),
            ("f48fbfbf", "f48fbfbf"),
        ] {
            assert_eq!(dec_hex(input), expected, "input {input}");
        }
    }

    // ----- oracle parity -----
    //
    // Expected outputs are the UTF-8 re-encoding of `new String(bytes, UTF_8)`
    // produced by Corretto JDK 17 (the JVM the Scala reference node runs on).
    // They are NOT derived from `decode` — they pin Rust to the JVM's exact
    // ill-formed-sequence replacement counting. Includes the 5 routed SANTA
    // `STypeVar.name_utf8_roundtrip` names (ff/e282/c080/eda080/61ff62).

    #[test]
    fn jvm_lossy_replacement_matches_corretto17_oracle() {
        let oracle = [
            // (input bytes, JVM new String(...).getBytes(UTF_8))
            ("ff", "efbfbd"),
            ("e282", "efbfbd"),
            ("c080", "efbfbdefbfbd"),
            ("eda080", "efbfbd"),
            ("61ff62", "61efbfbd62"),
            ("c1bf", "efbfbdefbfbd"),
            ("e08080", "efbfbdefbfbdefbfbd"),
            ("f0808080", "efbfbdefbfbdefbfbdefbfbd"),
            ("eda0bd", "efbfbd"),
            ("edbfbf", "efbfbd"),
            ("edb080", "efbfbd"),
            ("c3", "efbfbd"),
            ("f09f", "efbfbd"),
            ("f09f98", "efbfbd"),
            ("e2", "efbfbd"),
            ("80", "efbfbd"),
            ("bf", "efbfbd"),
            ("8080", "efbfbdefbfbd"),
            ("fe", "efbfbd"),
            ("f8", "efbfbd"),
            ("c0", "efbfbd"),
            ("c1", "efbfbd"),
            ("f5808080", "efbfbdefbfbdefbfbdefbfbd"),
            ("e09f80", "efbfbdefbfbdefbfbd"),
            ("f4908080", "efbfbdefbfbdefbfbdefbfbd"),
            ("6180620063", "61efbfbd620063"),
            // incomplete-lead-then-non-continuation boundaries
            ("e241", "efbfbd41"),
            ("e28241", "efbfbd41"),
            ("c341", "efbfbd41"),
            ("f09f41", "efbfbd41"),
            ("f041", "efbfbd41"),
            ("e041", "efbfbd41"),
            ("ed41", "efbfbd41"),
            ("eda041", "efbfbd41"),
            ("f4418080", "efbfbd41efbfbdefbfbd"),
            ("e0419f", "efbfbd41efbfbd"),
            ("f09f9841", "efbfbd41"),
            ("c2", "efbfbd"),
            ("edff", "efbfbdefbfbd"),
            ("f490", "efbfbdefbfbd"),
            ("f4", "efbfbd"),
            ("fbbfbfbfbf", "efbfbdefbfbdefbfbdefbfbdefbfbd"),
        ];
        for (input, expected) in oracle {
            assert_eq!(dec_hex(input), expected, "JVM parity for input {input}");
        }
    }
}
