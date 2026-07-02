//! Source positions. Mirrors sigma.ast.SourceContext (SourceContext.scala:13-34):
//! the parser records a single start index per node; line/col are derived on
//! demand, 1-based, counting UTF-16 code units (JVM String indices).

/// Byte offset into the original source text.
pub type Pos = u32;

/// Exact port of `SourceContext.fromParserIndex` (SourceContext.scala:13-34).
///
/// `pos` is a byte offset; it is converted to a UTF-16 code-unit index first
/// because the Scala algorithm operates on JVM string indices. Lines are split
/// like `scala.io.Source.getLines`: terminator is `\n`, an immediately
/// preceding `\r` is stripped, a trailing terminator yields no extra empty
/// line — i.e. exactly Rust's `str::lines()`.
pub fn line_col(src: &str, pos: Pos) -> (u32, u32) {
    let pos = pos as usize;
    // Byte offset -> UTF-16 code-unit index.
    // Sum the UTF-16 widths of every char whose byte start precedes `pos`.
    // deviation: for positions past the string end (pos > src.len()), add the
    // excess byte count 1-for-1; this matches Scala's direct JVM-String-index
    // arithmetic for the ASCII "past-end" positions that fastparse can produce,
    // and is unreachable for non-ASCII inputs in practice (token positions
    // satisfy pos <= src.len()).
    let utf16_sum: usize = src
        .char_indices()
        .take_while(|(b, _)| *b < pos)
        .map(|(_, c)| c.len_utf16())
        .sum();
    let index = utf16_sum + pos.saturating_sub(src.len());

    let lines: Vec<&str> = src.lines().collect();
    if lines.is_empty() {
        return (0, 0); // SourceContext.scala:15-16
    }
    // scanLeft ranges: line0 = (0, len0), line_{i} = (prev_end+1, prev_end+1+len_i),
    // end INCLUSIVE in the membership check (SourceContext.scala:18-25).
    let mut start = 0usize;
    for (i, line) in lines.iter().enumerate() {
        let end = start + line.chars().map(char::len_utf16).sum::<usize>();
        if index >= start && index <= end {
            return ((i + 1) as u32, (index - start + 1) as u32);
        }
        start = end + 1;
    }
    // Fallback quirk (SourceContext.scala:26-33): 0-based line count, len-1 col.
    // deviation: Scala's `lastLine.length - 1` is an Int and can be -1 for an
    // empty last line (e.g. input="\n"); clamp to 0 because our return type is u32.
    let last = lines[lines.len() - 1];
    (
        (lines.len() - 1) as u32,
        (last.chars().map(char::len_utf16).sum::<usize>().max(1) - 1) as u32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn line_col_simple_first_line_is_one_based() {
        // SourceContext.scala:13-27: line 1, col = index - start + 1
        assert_eq!(line_col("abc", 0), (1, 1));
        assert_eq!(line_col("abc", 2), (1, 3));
    }

    #[test]
    fn line_col_index_at_line_end_maps_into_that_line() {
        // Scala range check is `index >= start && index <= end` (inclusive end),
        // so the newline position / one-past-line-end belongs to that line.
        // "(10" len 3, index 3 -> (1, 4). This is what makes fail("(10",1,4) pass.
        assert_eq!(line_col("(10", 3), (1, 4));
        // "ab\ncd": index 2 is the '\n' -> line 1 col 3; index 3 = 'c' -> line 2 col 1.
        assert_eq!(line_col("ab\ncd", 2), (1, 3));
        assert_eq!(line_col("ab\ncd", 3), (2, 1));
    }

    #[test]
    fn line_col_crlf_counts_scala_getlines_semantics() {
        // Scala Source.getLines strips \r before \n; line lengths exclude the \r,
        // and the scanLeft adds +1 per line regardless of terminator width.
        // Port bug-for-bug: "ab\r\ncd" lines = ["ab","cd"], ranges (0,2),(3,5).
        // Byte index of 'c' is 4 -> UTF-16 index is 4 -> NOT in (3,5)? It is: 3<=4<=5 -> line 2, col 2.
        // (The \r shifts real offsets; Scala is off-by-one here and so are we.)
        assert_eq!(line_col("ab\r\ncd", 4), (2, 2));
    }

    #[test]
    fn line_col_non_ascii_counts_utf16_units() {
        // Scala String indices are UTF-16 code units. '€' is 1 UTF-16 unit, 3 UTF-8 bytes.
        // Byte pos 3 (after '€') must report col 2, not col 4.
        assert_eq!(line_col("€x", 3), (1, 2));
    }

    // ----- error paths -----

    #[test]
    fn line_col_empty_input_is_zero_zero() {
        // SourceContext.scala:15-16
        assert_eq!(line_col("", 0), (0, 0));
    }

    #[test]
    fn line_col_past_end_fallback_uses_scala_quirk_values() {
        // SourceContext.scala:26-33 fallback: line = lines.len()-1 (0-based!),
        // col = lastLine.len()-1. Reachable only when index > last line's end+...
        // "a" has range (0,1); index 2 is past -> (0, 0) per the quirk
        // (lines.len()-1 = 0, lastLine.len()-1 = 0). Preserve verbatim.
        assert_eq!(line_col("a", 2), (0, 0));
    }
}
