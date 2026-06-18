//! Deterministic seeded PRNG (SplitMix64). No external dependency so a
//! reported `(seed, iter)` pair reproduces an identical input on any machine.

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }

    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        // SplitMix64 (Steele, Lea, Flood). Public-domain reference constants.
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n` (n must be non-zero).
    #[inline]
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    #[inline]
    pub fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }

    #[inline]
    pub fn coin(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    /// Inclusive range `[lo, hi]`.
    #[inline]
    pub fn range(&mut self, lo: usize, hi: usize) -> usize {
        debug_assert!(lo <= hi);
        lo + self.below(hi - lo + 1)
    }
}
