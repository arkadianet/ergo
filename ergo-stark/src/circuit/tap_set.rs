//! The recursion circuit's `TapSet` — a faithful port of the reference
//! sigmastate `CircuitTapSet` (mirror of risc0-zkp 3.0.4 `src/taps.rs`
//! `TapData` / `TapSet`, extracted via the public `CIRCUIT.get_taps()`).
//!
//! The tap layout drives which sampled trace evaluations feed the constraint
//! interpreter: `verify_validity` walks registers in order, evaluating each
//! register's `coeff_u` slice at `z · back_one^back(i)` for every one of its
//! backs. Group ids follow upstream: 0 = accum, 1 = code, 2 = data
//! (risc0-zkp 3.0.4 `src/adapter.rs`).
//!
//! Consensus-critical: the parsed tap set must match the reference table
//! byte-for-byte (indices, offsets, rotations/backs, combo back-sets). Pinned
//! by the extracted `circuit_taps.tsv` oracle, per the oracle-parity rule.

/// One tap row: column `offset` of register group `group`, read `back` rows
/// behind the current row, belonging to DEEP-ALI combo `combo`; `skip` = the
/// number of taps in this tap's register (repeated on every tap of the
/// register, exactly as upstream stores it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CircuitTap {
    pub group: i32,
    pub offset: i32,
    pub back: i32,
    pub combo: i32,
    pub skip: i32,
}

/// One register — a run of taps sharing `(group, offset, combo)`, differing
/// only in `back`. This is the granularity the verifier consumes: the eval_u
/// loop evaluates the register's coeff slice at each of its `size` backs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TapRegister {
    pub group: i32,
    pub offset: i32,
    pub combo: i32,
    pub backs: Vec<i32>,
}

impl TapRegister {
    /// Number of taps (backs) in this register.
    pub fn size(&self) -> usize {
        self.backs.len()
    }

    /// The `i`-th back rotation of this register.
    pub fn back(&self, i: usize) -> i32 {
        self.backs[i]
    }
}

/// The recursion circuit's `TapSet`, parsed from `circuit_taps.tsv`.
///
/// Group `g`'s taps are rows `[group_begin(g), group_begin(g+1))`;
/// `group_size(g)` is its column count (the Merkle-leaf row width). Combo
/// `c`'s back-set is `combo_taps[combo_begin(c)..combo_begin(c+1)]`. Fields are
/// exposed for indexed consumption and must not be mutated.
#[derive(Clone, Debug)]
pub struct CircuitTapSet {
    group_names: Vec<String>,
    group_begin: Vec<i32>,
    group_size: Vec<i32>,
    reg_count: i32,
    combos_count: i32,
    combo_begin: Vec<i32>,
    combo_taps: Vec<i32>,
    tot_combo_backs: i32,
    taps: Vec<CircuitTap>,
    regs: Vec<TapRegister>,
}

impl CircuitTapSet {
    /// Register-group names in id order (`accum`, `code`, `data`).
    pub fn group_names(&self) -> &[String] {
        &self.group_names
    }
    /// Group boundary row indices, `group_count + 1` entries starting at 0.
    pub fn group_begin(&self) -> &[i32] {
        &self.group_begin
    }
    /// Per-group column count (Merkle-leaf row width).
    pub fn group_size(&self) -> &[i32] {
        &self.group_size
    }
    /// Number of registers derived from the tap table.
    pub fn reg_count(&self) -> i32 {
        self.reg_count
    }
    /// Number of DEEP-ALI combos.
    pub fn combos_count(&self) -> i32 {
        self.combos_count
    }
    /// Combo boundary indices into [`combo_taps`](Self::combo_taps).
    pub fn combo_begin(&self) -> &[i32] {
        &self.combo_begin
    }
    /// Flat combo back-sets, sliced by [`combo_begin`](Self::combo_begin).
    pub fn combo_taps(&self) -> &[i32] {
        &self.combo_taps
    }
    /// Total number of combo backs (length of `combo_taps`).
    pub fn tot_combo_backs(&self) -> i32 {
        self.tot_combo_backs
    }
    /// All taps in canonical order.
    pub fn taps(&self) -> &[CircuitTap] {
        &self.taps
    }
    /// All registers in canonical order.
    pub fn regs(&self) -> &[TapRegister] {
        &self.regs
    }

    /// Total number of taps.
    pub fn tap_size(&self) -> usize {
        self.taps.len()
    }
    /// Number of register groups.
    pub fn group_count(&self) -> usize {
        self.group_names.len()
    }
    /// Number of taps in group `g`.
    pub fn group_tap_count(&self, g: usize) -> i32 {
        self.group_begin[g + 1] - self.group_begin[g]
    }

    /// Parse `circuit_taps.tsv` content. Total: malformed input yields `Err`,
    /// never panics. Validates the register structure (the `skip` walk), tap
    /// ordering against `group_begin`, offsets against `group_size`, and each
    /// register's back-list against its combo's back-set.
    pub fn parse(content: &str) -> Result<CircuitTapSet, String> {
        use std::collections::HashMap;

        let mut meta: HashMap<String, String> = HashMap::new();
        let mut taps: Vec<CircuitTap> = Vec::new();

        for line in content.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            match f[0] {
                "meta" => {
                    if f.len() != 3 {
                        return Err(format!("circuit_taps: bad meta row: {line}"));
                    }
                    if meta.contains_key(f[1]) {
                        return Err(format!("circuit_taps: duplicate meta '{}'", f[1]));
                    }
                    meta.insert(f[1].to_string(), f[2].to_string());
                }
                "tap" => {
                    if f.len() != 7 {
                        return Err(format!("circuit_taps: bad tap row: {line}"));
                    }
                    let idx = parse_i32("circuit_taps", f[1])?;
                    if idx != taps.len() as i32 {
                        return Err(format!(
                            "circuit_taps: tap index {idx} out of order (expected {})",
                            taps.len()
                        ));
                    }
                    taps.push(CircuitTap {
                        group: parse_i32("circuit_taps", f[2])?,
                        offset: parse_i32("circuit_taps", f[3])?,
                        back: parse_i32("circuit_taps", f[4])?,
                        combo: parse_i32("circuit_taps", f[5])?,
                        skip: parse_i32("circuit_taps", f[6])?,
                    });
                }
                other => return Err(format!("circuit_taps: unknown row kind '{other}'")),
            }
        }

        let required = [
            "group_names",
            "group_begin",
            "group_size",
            "reg_count",
            "combos_count",
            "combo_begin",
            "combo_taps",
            "tot_combo_backs",
        ];
        let missing: Vec<&str> = required
            .iter()
            .copied()
            .filter(|k| !meta.contains_key(*k))
            .collect();
        if !missing.is_empty() {
            return Err(format!("circuit_taps: missing meta {}", missing.join(", ")));
        }

        let ints = |key: &str| -> Result<Vec<i32>, String> {
            meta[key]
                .split(',')
                .map(|s| parse_i32("circuit_taps", s))
                .collect()
        };

        let group_names: Vec<String> = meta["group_names"].split(',').map(str::to_string).collect();
        let group_begin = ints("group_begin")?;
        let group_size = ints("group_size")?;
        let reg_count = parse_i32("circuit_taps", &meta["reg_count"])?;
        let combos_count = parse_i32("circuit_taps", &meta["combos_count"])?;
        let combo_begin = ints("combo_begin")?;
        let combo_taps = ints("combo_taps")?;
        let tot_combo_backs = parse_i32("circuit_taps", &meta["tot_combo_backs"])?;

        let tap_len = taps.len() as i32;
        let g = group_names.len();
        {
            let mut distinct = group_names.clone();
            distinct.sort();
            distinct.dedup();
            if g == 0 || group_names.iter().any(|n| n.is_empty()) || distinct.len() != g {
                return Err(
                    "circuit_taps: group_names must be nonempty and pairwise distinct".to_string(),
                );
            }
        }
        if group_begin.len() != g + 1 || group_begin[0] != 0 {
            return Err(format!(
                "circuit_taps: group_begin must have {} entries starting at 0",
                g + 1
            ));
        }
        if group_size.len() != g {
            return Err(format!("circuit_taps: group_size must have {g} entries"));
        }
        for boundary in 0..g {
            if group_begin[boundary] < 0
                || group_begin[boundary] > tap_len
                || group_begin[boundary + 1] < group_begin[boundary]
                || group_begin[boundary + 1] > tap_len
            {
                return Err(format!(
                    "circuit_taps: group_begin is out of range or non-monotone at {boundary}"
                ));
            }
            if group_size[boundary] <= 0 {
                return Err(format!(
                    "circuit_taps: group_size({boundary}) must be positive"
                ));
            }
        }
        if group_begin[g] != tap_len {
            return Err(format!(
                "circuit_taps: group_begin ends at {} but {} taps parsed",
                group_begin[g], tap_len
            ));
        }
        if reg_count < 0 {
            return Err(format!(
                "circuit_taps: reg_count must be nonnegative, got {reg_count}"
            ));
        }
        if combos_count <= 0
            || combo_begin.is_empty()
            || combos_count != combo_begin.len() as i32 - 1
            || combo_begin[0] != 0
        {
            return Err("circuit_taps: combo_begin must contain one initial zero plus one end per positive combo count".to_string());
        }
        let combo_taps_len = combo_taps.len() as i32;
        for combo in 0..combos_count as usize {
            let begin = combo_begin[combo];
            let end = combo_begin[combo + 1];
            if begin < 0 || begin > combo_taps_len || end <= begin || end > combo_taps_len {
                return Err(format!(
                    "circuit_taps: combo_begin is out of range or non-increasing at {combo}"
                ));
            }
        }
        if combo_begin[combos_count as usize] != combo_taps_len {
            return Err(format!(
                "circuit_taps: combo_begin ends at {} but {} combo taps",
                combo_begin[combos_count as usize], combo_taps_len
            ));
        }
        if tot_combo_backs < 0 || combo_taps_len != tot_combo_backs {
            return Err(format!(
                "circuit_taps: {combo_taps_len} combo taps but tot_combo_backs={tot_combo_backs}"
            ));
        }
        for (i, &ct) in combo_taps.iter().enumerate() {
            if ct < 0 {
                return Err(format!("circuit_taps: combo tap {i} is negative"));
            }
        }

        // Per-tap validation against group boundaries and column counts.
        for (i, t) in taps.iter().enumerate() {
            if t.group < 0 || t.group >= g as i32 {
                return Err(format!(
                    "circuit_taps: tap {i}: group {} not in [0, {g})",
                    t.group
                ));
            }
            let grp = t.group as usize;
            if (i as i32) < group_begin[grp] || (i as i32) >= group_begin[grp + 1] {
                return Err(format!(
                    "circuit_taps: tap {i}: group {} inconsistent with group_begin",
                    t.group
                ));
            }
            if t.offset < 0 || t.offset >= group_size[grp] {
                return Err(format!(
                    "circuit_taps: tap {i}: offset {} not in [0, {})",
                    t.offset, group_size[grp]
                ));
            }
            if t.combo < 0 || t.combo >= combos_count {
                return Err(format!(
                    "circuit_taps: tap {i}: combo {} not in [0, {combos_count})",
                    t.combo
                ));
            }
            if t.back < 0 {
                return Err(format!(
                    "circuit_taps: tap {i}: back {} is negative",
                    t.back
                ));
            }
            if t.skip < 1 {
                return Err(format!("circuit_taps: tap {i}: skip {} < 1", t.skip));
            }
        }

        // Register walk (upstream RegisterIter): a register starts at row 0 and
        // every `skip` rows thereafter; its taps must agree on
        // group/offset/combo/skip, and its back-list must equal its combo's
        // back-set.
        let mut regs: Vec<TapRegister> = Vec::new();
        let mut i = 0usize;
        while i < taps.len() {
            let head = taps[i];
            let skip = head.skip as usize;
            if head.skip > (taps.len() - i) as i32 {
                return Err(format!(
                    "circuit_taps: register at tap {i} overruns the table (skip {})",
                    head.skip
                ));
            }
            let mut backs = Vec::with_capacity(skip);
            for j in 0..skip {
                let t = taps[i + j];
                if t.group != head.group
                    || t.offset != head.offset
                    || t.combo != head.combo
                    || t.skip != head.skip
                {
                    return Err(format!(
                        "circuit_taps: tap {} disagrees with its register head at {i}",
                        i + j
                    ));
                }
                backs.push(t.back);
            }
            let cb = combo_begin[head.combo as usize] as usize;
            let ce = combo_begin[head.combo as usize + 1] as usize;
            let combo_backs = &combo_taps[cb..ce];
            if backs.as_slice() != combo_backs {
                return Err(format!(
                    "circuit_taps: register at tap {i}: backs {:?} != combo {} backs {:?}",
                    backs, head.combo, combo_backs
                ));
            }
            regs.push(TapRegister {
                group: head.group,
                offset: head.offset,
                combo: head.combo,
                backs,
            });
            i += skip;
        }
        if regs.len() as i32 != reg_count {
            return Err(format!(
                "circuit_taps: {} registers derived but meta reg_count={reg_count}",
                regs.len()
            ));
        }

        Ok(CircuitTapSet {
            group_names,
            group_begin,
            group_size,
            reg_count,
            combos_count,
            combo_begin,
            combo_taps,
            tot_combo_backs,
            taps,
            regs,
        })
    }
}

/// Parse a signed decimal, mapping a parse failure to the loader's `Err`
/// convention (mirrors the Scala `NumberFormatException` -> `Left` boundary).
fn parse_i32(ctx: &str, s: &str) -> Result<i32, String> {
    s.parse::<i32>()
        .map_err(|_| format!("{ctx}: bad number: '{s}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    const TAPS_TSV: &str = include_str!("../../../test-vectors/ergo-stark/circuit_taps.tsv");

    /// Replace a full line (mirrors the Scala tests' line-rewrite helper).
    fn rewrite(from: &str, to: &str) -> String {
        TAPS_TSV
            .lines()
            .map(|l| if l == from { to } else { l })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Replace a `meta\t<key>\t...` line's value.
    fn replace_meta(key: &str, value: &str) -> String {
        let prefix = format!("meta\t{key}\t");
        TAPS_TSV
            .lines()
            .map(|l| {
                if l.starts_with(&prefix) {
                    format!("meta\t{key}\t{value}")
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    // ----- happy path -----

    #[test]
    fn taps_loader_matches_the_extracted_recursion_tapset() {
        let ts = CircuitTapSet::parse(TAPS_TSV).expect("taps parse");
        assert_eq!(ts.tap_size(), 643);
        assert_eq!(ts.reg_count(), 163);
        assert_eq!(ts.regs().len(), 163);
        assert_eq!(ts.group_names(), ["accum", "code", "data"]);
        assert_eq!(ts.group_begin(), [0, 16, 39, 643]);
        assert_eq!(ts.group_size(), [12, 23, 128]);
        assert_eq!(ts.group_tap_count(0), 16);
        assert_eq!(ts.group_tap_count(1), 23);
        assert_eq!(ts.group_tap_count(2), 604);
        assert_eq!(ts.combos_count(), 5);
        assert_eq!(ts.combo_begin(), [0, 1, 3, 9, 15, 20]);
        assert_eq!(
            ts.combo_taps(),
            [0, 0, 1, 0, 1, 2, 3, 4, 68, 0, 1, 2, 7, 15, 16, 0, 2, 7, 15, 16]
        );
        assert_eq!(ts.tot_combo_backs(), 20);
        // Registers cover the taps exactly, in order, sized by their skip.
        assert_eq!(ts.regs().iter().map(TapRegister::size).sum::<usize>(), 643);
        // Register back-lists are exactly what the eval_u loop consumes: pin the
        // first accum register (backs 0,1) and every code register (back 0).
        assert_eq!(ts.regs()[0].backs, [0, 1]);
        for r in ts.regs().iter().filter(|r| r.group == 1) {
            assert_eq!(r.backs, [0]);
        }
    }

    // ----- error paths -----

    #[test]
    fn taps_loader_rejects_malformed_rows_with_err() {
        // Offset outside the group's column count.
        assert!(CircuitTapSet::parse(&rewrite(
            "tap\t16\t1\t0\t0\t0\t1",
            "tap\t16\t1\t23\t0\t0\t1"
        ))
        .is_err());
        // Broken register run: skip overrun at the last tap.
        let overrun = TAPS_TSV
            .lines()
            .map(|l| {
                if l.starts_with("tap\t642\t") {
                    let mut s = l.to_string();
                    s.pop();
                    s.push('9');
                    s
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(CircuitTapSet::parse(&overrun).is_err());
        // Dropped tap: group_begin no longer matches.
        let dropped = TAPS_TSV
            .lines()
            .filter(|l| !l.starts_with("tap\t642\t"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(CircuitTapSet::parse(&dropped).is_err());
        // Range checks before any copy/allocation.
        assert!(CircuitTapSet::parse(&replace_meta("combo_begin", "0,-1,3,9,15,20")).is_err());
        assert!(CircuitTapSet::parse(&replace_meta("combo_begin", "0,3,2,9,15,20")).is_err());
        assert!(CircuitTapSet::parse(&replace_meta("group_begin", "0,16,10,643")).is_err());
        assert!(CircuitTapSet::parse(&replace_meta("combos_count", "-1")).is_err());
        // Negative back.
        let neg_back = rewrite("tap\t0\t0\t0\t0\t1\t2", "tap\t0\t0\t0\t-1\t1\t2");
        assert!(CircuitTapSet::parse(&neg_back).is_err());
    }
}
