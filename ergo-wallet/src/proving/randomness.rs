//! Proving-time randomness abstraction.

use k256::Scalar;

pub trait ProvingRng {
    fn sample_scalar(&mut self) -> Scalar;
    fn sample_challenge(&mut self) -> [u8; 24];
}

pub struct OsRngBackend;

impl ProvingRng for OsRngBackend {
    fn sample_scalar(&mut self) -> Scalar {
        use k256::elliptic_curve::ops::Reduce;
        use rand::RngCore;
        loop {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            let s = <Scalar as Reduce<k256::U256>>::reduce_bytes(&bytes.into());
            if s != Scalar::ZERO {
                return s;
            }
        }
    }

    fn sample_challenge(&mut self) -> [u8; 24] {
        use rand::RngCore;
        let mut out = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut out);
        out
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub struct Sha256DerivedRng {
    seed: [u8; 32],
    counter: u32,
}

#[cfg(any(test, feature = "test-utils"))]
impl Sha256DerivedRng {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0 }
    }

    fn next_bytes(&mut self, len: usize) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let mut hasher = Sha256::new();
            hasher.update(self.seed);
            hasher.update(self.counter.to_be_bytes());
            out.extend_from_slice(&hasher.finalize());
            self.counter += 1;
        }
        out.truncate(len);
        out
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl ProvingRng for Sha256DerivedRng {
    fn sample_scalar(&mut self) -> Scalar {
        use k256::elliptic_curve::ops::Reduce;
        loop {
            let bytes = self.next_bytes(32);
            let arr: [u8; 32] = bytes.try_into().unwrap();
            let s = <Scalar as Reduce<k256::U256>>::reduce_bytes(&arr.into());
            if s != Scalar::ZERO {
                return s;
            }
        }
    }

    fn sample_challenge(&mut self) -> [u8; 24] {
        let bytes = self.next_bytes(24);
        let mut out = [0u8; 24];
        out.copy_from_slice(&bytes);
        out
    }
}
