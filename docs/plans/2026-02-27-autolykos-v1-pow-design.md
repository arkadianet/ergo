# Autolykos v1 PoW Verification + SyncInfo V2 Fix — Design

## Problem

The Rust Ergo node cannot sync from genesis because `validate_pow` rejects all v1 headers (heights 0–417,791) with `Err(UnsupportedVersion(1))`. The Scala node always verifies v1 PoW — there is no checkpoint skip for PoW. Additionally, SyncInfo V2 header ordering is inverted relative to Scala convention, causing incorrect peer height detection.

## Solution

Port the Autolykos v1 EC-based PoW verification from the old Rust node (`/home/rkadias/coding/git/ergo-rust-node/crates/ergo-consensus/src/autolykos.rs`) into our `ergo-consensus/src/autolykos.rs`. Fix SyncInfo V2 ordering to match Scala (newest-first).

## Autolykos v1 Algorithm

V1 verification checks the EC equation: **w^f == g^d * pk**

Given a header with solution {pk, w, nonce, d}:

1. Compute `target = GROUP_ORDER / decode_compact_bits(nBits)`
2. Check `d < target`
3. Check `pk` and `w` are valid secp256k1 points (not infinity)
4. Compute `msg = blake2b256(header_bytes_without_pow)`
5. Compute `seed = msg || nonce`
6. Compute `indices = genIndexes(H(seed), N_BASE)` — 32 indices in [0, 2^26)
7. For each index j, compute `e_j = hashModQ(j_be32 || M || pk_bytes || msg || w_bytes)`
8. Compute `f = (e_0 + e_1 + ... + e_31) mod q`
9. Verify: `exponentiate(w, f) == exponentiate(g, d) * pk`

### Key differences from v2

| Aspect | v1 | v2 |
|--------|----|----|
| Verification | EC equation: `w^f == g^d * pk` | Hash comparison: `hit < target` |
| Solution fields | pk, w, nonce, d (all used) | pk, nonce (w/d ignored) |
| Index generation | `genIndexes(H(seed), N)` — hash seed first | `genIndexes(seed, N)` — seed used directly |
| Element generation | `hashModQ(idx \|\| M \|\| pk \|\| msg \|\| w)` | `H(idx \|\| height \|\| M)[1..]` |
| N parameter | Always N_BASE (2^26) | Grows 5% per epoch after height 614,400 |

### hashModQ (rejection sampling)

```
validRange = (2^256 / q) * q
hashModQ(input):
    hash = blake2b256(input)
    bi = BigUint(hash)
    if bi < validRange: return bi % q
    else: hashModQ(hash)  // recurse with hash as new input
```

This ensures uniform distribution in [0, q). Already implemented in our autolykos.rs.

## Architecture

### Dependencies

Add `k256` and `ergo-chain-types` as direct dependencies of `ergo-consensus`. Both are already transitive deps via `ergo-lib`, so no new downloads — just making them explicit.

- `ergo-chain-types`: `EcPoint`, `ec_point::{generator, exponentiate, is_identity}`
- `k256`: `Scalar`, `U256`, `elliptic_curve::ops::Reduce`
- `sigma-ser`: `ScorexSerializable` trait for `EcPoint::scorex_parse_bytes`

### Type Adaptation

Our `AutolykosSolution` stores raw bytes:
```rust
pub struct AutolykosSolution {
    pub miner_pk: [u8; 33],  // compressed SEC1 point
    pub w: [u8; 33],         // compressed SEC1 point
    pub nonce: [u8; 8],
    pub d: Vec<u8>,          // big-endian unsigned integer
}
```

For v1 verification:
- `miner_pk` and `w` bytes are used directly in hash inputs (no serialization needed)
- Parse `miner_pk`/`w` → `EcPoint` via `scorex_parse_bytes` only for final EC equation
- Parse `d` → `BigUint` via `BigUint::from_bytes_be`

### Code Changes

**`crates/ergo-consensus/src/autolykos.rs`:**
- Modify `validate_pow()` to branch on version: v1 → `validate_pow_v1()`, v2 → existing path
- Add `validate_pow_v1(header)` — full v1 verification
- Add `gen_indexes_v1(seed, n)` — hash-then-slide (vs v2's direct slide)
- Add `calculate_f_v1(indices, msg, pk_bytes, w_bytes)` — sum of hashModQ elements
- `hash_mod_q()`, `biguint_to_scalar()`, `VALID_RANGE`, `GROUP_ORDER` already exist

**`crates/ergo-consensus/Cargo.toml`:**
- Add `k256` and `ergo-chain-types` as direct deps

### SyncInfo V2 Ordering

**Problem:** Scala sends SyncInfo V2 headers newest-first (offsets `[0, 16, 128, 512]` from tip). Our code sends oldest-first and uses `.last()` to read the tip. Both directions are wrong:
- Scala peers use `head` (first) as our tip → they see our oldest header
- We use `.last()` on Scala's list → we see their oldest offset header (512 blocks behind)

**Fix:**
- `persistent_sync.rs`: Reverse iteration order → newest-first
- `message_handler.rs`: `.last()` → `.first()` for tip extraction

## Testing

- Capture a real v1 mainnet header binary fixture from a Scala node (similar to existing v2 fixtures at heights 500K, 614K, 1M)
- Test `validate_pow` passes for v1 fixture
- Test `validate_pow` fails for v1 fixture with mutated nonce
- Test `gen_indexes_v1` produces 32 indices in range [0, N_BASE)
- Test `hash_mod_q` returns value in [0, q)
- Test SyncInfo V2 ordering: first element is highest height
