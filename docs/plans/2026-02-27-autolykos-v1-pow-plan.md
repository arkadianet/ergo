# Autolykos v1 PoW Verification + SyncInfo V2 Fix — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable the Rust Ergo node to sync from genesis by implementing Autolykos v1 PoW verification and fixing SyncInfo V2 header ordering.

**Architecture:** Port v1 EC-based PoW verification (`w^f == g^d * pk`) into `ergo-consensus/src/autolykos.rs` using `k256`/`ergo-chain-types` for secp256k1 operations. Fix SyncInfo V2 to send/read headers newest-first matching Scala convention.

**Tech Stack:** k256 0.13 (secp256k1), ergo-chain-types (EcPoint), blake2, num-bigint

---

## Context

The Rust Ergo node connects to peers but rejects all v1 headers (heights 0–417,791) because `validate_pow` returns `Err(UnsupportedVersion(1))`. The Scala node always verifies v1 PoW with the full EC equation — there is no checkpoint skip for PoW. The old Rust node at `/home/rkadias/coding/git/ergo-rust-node/crates/ergo-consensus/src/autolykos.rs` has a complete v1 implementation to reference.

Key files:
- Current autolykos: `crates/ergo-consensus/src/autolykos.rs` — v2-only, has `hash_mod_q`, `Q`, `M` already
- Current Cargo.toml: `crates/ergo-consensus/Cargo.toml` — needs `k256`, `ergo-chain-types` added
- Old Rust v1 impl: `/home/rkadias/coding/git/ergo-rust-node/crates/ergo-consensus/src/autolykos.rs` — lines 244-521
- Scala reference: `/home/rkadias/coding/reference_materials/ergo-master/ergo-core/src/main/scala/org/ergoplatform/mining/AutolykosPowScheme.scala`
- SyncInfo build: `crates/ergo-network/src/persistent_sync.rs:59-94`
- SyncInfo handler: `crates/ergo-network/src/message_handler.rs:298-315`
- Header type: `crates/ergo-types/src/header.rs` — `AutolykosSolution { miner_pk: [u8;33], w: [u8;33], nonce: [u8;8], d: Vec<u8> }`
- Header tests: `crates/ergo-testkit/src/header_vectors.rs` — pattern for v2 test vectors

---

### Task 1: Add EC Dependencies

**Files:**
- Modify: `crates/ergo-consensus/Cargo.toml`

**What:** Add `k256` and `ergo-chain-types` as direct dependencies. Both are already transitive deps via `ergo-lib`, so this just makes them explicit. Also add `sigma-ser` version that matches our `ergo-lib 0.28` ecosystem for `ScorexSerializable` trait.

**Step 1: Add dependencies to Cargo.toml**

Add these lines to `[dependencies]` in `crates/ergo-consensus/Cargo.toml`:

```toml
k256 = { version = "0.13", features = ["ecdsa"] }
ergo-chain-types = { git = "https://github.com/ergoplatform/sigma-rust.git", rev = "3a5377d54233" }
```

The `rev` must match the one in the workspace `Cargo.toml` (line 47). The `ergo-chain-types` crate provides `EcPoint`, `ec_point::{generator, exponentiate, is_identity}`, and `ScorexSerializable` for parsing compressed EC points.

**Step 2: Verify it compiles**

```bash
cargo check -p ergo-consensus
```

Expected: compiles with no errors (deps already in lockfile as transitive).

**Step 3: Commit**

```bash
cargo test -p ergo-consensus
git add crates/ergo-consensus/Cargo.toml
git commit -m "chore(ergo-consensus): add k256 and ergo-chain-types as direct deps for v1 PoW"
```

---

### Task 2: Implement v1 PoW Verification

**Files:**
- Modify: `crates/ergo-consensus/src/autolykos.rs`

**What:** Add the v1 verification path to `validate_pow` and all v1-specific helper functions. Port from the old Rust node, adapting to our `Header` type (raw byte arrays instead of sigma-rust's `EcPoint` types).

**Step 1: Add imports**

At the top of `autolykos.rs`, add these imports after the existing ones:

```rust
use ergo_chain_types::{ec_point, EcPoint};
use k256::{elliptic_curve::ops::Reduce, Scalar, U256};
use sigma_ser::ScorexSerializable;
```

**Step 2: Add `VALID_RANGE` constant**

Add after the `M` constant (around line 63):

```rust
/// Valid range for hashModQ rejection sampling.
/// This is (2^256 / q) * q — the largest number <= 2^256 divisible by q.
static VALID_RANGE: LazyLock<BigUint> = LazyLock::new(|| {
    let two_256 = BigUint::from(1u8) << 256;
    (&two_256 / &*Q) * &*Q
});
```

**Step 3: Add `hash_mod_q` function**

Add after the constants section:

```rust
/// Compute Blake2b256 hash and reduce mod q (group order).
/// Uses rejection sampling to ensure uniform distribution.
/// Used in Autolykos v1 for element generation.
fn hash_mod_q(input: &[u8]) -> BigUint {
    let mut current_input = input.to_vec();
    loop {
        let mut hasher = Blake2b256::new();
        hasher.update(&current_input);
        let hash: [u8; 32] = hasher.finalize().into();
        let bi = BigUint::from_bytes_be(&hash);
        if bi < *VALID_RANGE {
            return bi % &*Q;
        }
        current_input = hash.to_vec();
    }
}
```

**Step 4: Add `biguint_to_scalar` function**

```rust
/// Convert BigUint to k256 Scalar, reducing mod group order.
fn biguint_to_scalar(value: &BigUint) -> Scalar {
    let mut arr = [0u8; 32];
    let bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        let reduced = value % &*Q;
        let b = reduced.to_bytes_be();
        arr[32 - b.len()..].copy_from_slice(&b);
    } else {
        arr[32 - bytes.len()..].copy_from_slice(&bytes);
    }
    Scalar::reduce(U256::from_be_slice(&arr))
}
```

**Step 5: Add `parse_ec_point` helper**

```rust
/// Parse a compressed SEC1 EC point (33 bytes) into an EcPoint.
fn parse_ec_point(bytes: &[u8; 33]) -> Result<EcPoint, AutolykosError> {
    EcPoint::scorex_parse_bytes(bytes).map_err(|e| AutolykosError::InvalidPow {
        hit: format!("EC point parse error: {}", e),
        target: String::new(),
    })
}
```

**Step 6: Add `gen_indexes_v1` function**

V1 hashes the seed first, then applies the sliding window (v2 uses the seed directly as the sliding window input):

```rust
/// Generate K (32) indices for v1: hash seed first, then sliding window.
///
/// Unlike v2 which uses the seed directly, v1 computes H(seed) first,
/// extends to 35 bytes, then extracts indices via sliding 4-byte window.
fn gen_indexes_v1(seed: &[u8], n: u32) -> Vec<u32> {
    let mut hasher = Blake2b256::new();
    hasher.update(seed);
    let hash: [u8; 32] = hasher.finalize().into();

    // extendedHash = hash ++ hash[0..3] => 35 bytes
    let mut extended = [0u8; 35];
    extended[..32].copy_from_slice(&hash);
    extended[32..35].copy_from_slice(&hash[..3]);

    let n_big = BigUint::from(n);
    (0..K)
        .map(|i| {
            let val = BigUint::from_bytes_be(&extended[i..i + 4]);
            let idx = val % &n_big;
            idx.to_u32_digits().first().copied().unwrap_or(0)
        })
        .collect()
}
```

**Step 7: Add `calculate_f_v1` function**

```rust
/// Calculate f for v1: sum of hashModQ(idx || M || pk || msg || w) mod q.
fn calculate_f_v1(
    indices: &[u32],
    msg: &[u8; 32],
    pk_bytes: &[u8; 33],
    w_bytes: &[u8; 33],
) -> BigUint {
    let mut sum = BigUint::ZERO;
    for &idx in indices {
        let idx_bytes = idx.to_be_bytes();
        let mut input = Vec::with_capacity(4 + M.len() + 33 + 32 + 33);
        input.extend_from_slice(&idx_bytes);
        input.extend_from_slice(&M);
        input.extend_from_slice(pk_bytes);
        input.extend_from_slice(msg);
        input.extend_from_slice(w_bytes);
        sum += hash_mod_q(&input);
    }
    sum % &*Q
}
```

**Step 8: Add `validate_pow_v1` function**

```rust
/// Validate Autolykos v1 PoW: verify EC equation w^f == g^d * pk.
fn validate_pow_v1(header: &Header) -> Result<(), AutolykosError> {
    let sol = &header.pow_solution;

    // Parse d from raw bytes to BigUint
    let d = BigUint::from_bytes_be(&sol.d);

    // Compute target = Q / difficulty
    let target = get_b(header.n_bits);

    // Check d < target
    if d >= target {
        return Err(AutolykosError::InvalidPow {
            hit: d.to_string(),
            target: target.to_string(),
        });
    }

    // Parse EC points from compressed bytes
    let pk = parse_ec_point(&sol.miner_pk)?;
    let w = parse_ec_point(&sol.w)?;

    // Check neither is identity (infinity)
    if ec_point::is_identity(&pk) || ec_point::is_identity(&w) {
        return Err(AutolykosError::InvalidPow {
            hit: "identity point".to_string(),
            target: String::new(),
        });
    }

    // msg = H(header_without_pow)
    let header_bytes = serialize_header_without_pow(header);
    let msg = blake2b256(&header_bytes);

    // seed = msg || nonce
    let mut seed = Vec::with_capacity(32 + 8);
    seed.extend_from_slice(&msg);
    seed.extend_from_slice(&sol.nonce);

    // Generate 32 indices
    let indices = gen_indexes_v1(&seed, N_BASE);

    // Calculate f = sum of hashModQ elements mod q
    let f = calculate_f_v1(&indices, &msg, &sol.miner_pk, &sol.w);

    // Convert to scalars for EC operations
    let f_scalar = biguint_to_scalar(&f);
    let d_scalar = biguint_to_scalar(&d);

    // Verify: w^f == g^d * pk
    let left = ec_point::exponentiate(&w, &f_scalar);
    let g = ec_point::generator();
    let g_d = ec_point::exponentiate(&g, &d_scalar);
    // EcPoint Mul trait is point addition in multiplicative group notation
    let right = g_d * pk;

    if left == right {
        Ok(())
    } else {
        Err(AutolykosError::InvalidPow {
            hit: "EC equation w^f != g^d * pk".to_string(),
            target: String::new(),
        })
    }
}
```

**Step 9: Modify `validate_pow` to branch on version**

Replace the existing `validate_pow` function:

```rust
pub fn validate_pow(header: &Header) -> Result<(), AutolykosError> {
    if header.version < 2 {
        validate_pow_v1(header)
    } else {
        let hit = hit_for_version2(header);
        let target = get_b(header.n_bits);

        if hit < target {
            Ok(())
        } else {
            Err(AutolykosError::InvalidPow {
                hit: hit.to_string(),
                target: target.to_string(),
            })
        }
    }
}
```

Remove the `UnsupportedVersion` variant from `AutolykosError` since it's no longer used.

**Step 10: Verify compilation**

```bash
cargo check -p ergo-consensus
```

**Step 11: Run existing tests**

```bash
cargo test -p ergo-consensus
```

All existing v2 tests must still pass. The `UnsupportedVersion` removal may require updating any test that checked for that error variant.

**Step 12: Commit**

```bash
cargo test -p ergo-consensus
git add crates/ergo-consensus/src/autolykos.rs
git commit -m "feat(consensus): implement Autolykos v1 PoW verification with EC equation check"
```

---

### Task 3: Add v1 PoW Unit Tests

**Files:**
- Modify: `crates/ergo-consensus/src/autolykos.rs` (test module)

**What:** Add unit tests for all v1 helper functions and the full verification path. Since we can't easily capture a real v1 header fixture without a running Scala node, we test components individually and verify the math.

**Step 1: Add `hash_mod_q` test**

In the `#[cfg(test)] mod tests` section:

```rust
#[test]
fn test_hash_mod_q_within_range() {
    let input = b"test input for hashModQ";
    let result = hash_mod_q(input);
    assert!(result < *Q, "hashModQ result must be < q");
    assert!(!result.is_zero(), "hashModQ result should be non-zero for non-trivial input");
}

#[test]
fn test_hash_mod_q_deterministic() {
    let input = b"determinism check";
    let r1 = hash_mod_q(input);
    let r2 = hash_mod_q(input);
    assert_eq!(r1, r2);
}
```

**Step 2: Add `gen_indexes_v1` test**

```rust
#[test]
fn test_gen_indexes_v1_count_and_range() {
    let seed = [0xABu8; 40]; // seed = msg(32) || nonce(8)
    let indices = gen_indexes_v1(&seed, N_BASE);
    assert_eq!(indices.len(), K);
    for &idx in &indices {
        assert!(idx < N_BASE, "v1 index {} must be < N_BASE {}", idx, N_BASE);
    }
}

#[test]
fn test_gen_indexes_v1_differs_from_v2() {
    // v1 hashes the seed first; v2 uses seed directly as sliding window input.
    // With the same 32-byte input, results should differ.
    let seed32: [u8; 32] = [0x42; 32];
    let v2_indices = gen_indexes(&seed32, N_BASE);
    // For v1, we pass the same bytes (though v1 seed is typically 40 bytes)
    let v1_indices = gen_indexes_v1(&seed32, N_BASE);
    assert_ne!(v1_indices, v2_indices, "v1 and v2 index generation should differ");
}
```

**Step 3: Add `biguint_to_scalar` test**

```rust
#[test]
fn test_biguint_to_scalar_roundtrip() {
    let value = BigUint::from(42u32);
    let scalar = biguint_to_scalar(&value);
    // Scalar should be non-zero
    assert_ne!(scalar, Scalar::ZERO);
}

#[test]
fn test_biguint_to_scalar_large_value() {
    // Value larger than group order should be reduced
    let large = &*Q + BigUint::from(1u32);
    let scalar = biguint_to_scalar(&large);
    let one_scalar = biguint_to_scalar(&BigUint::from(1u32));
    assert_eq!(scalar, one_scalar, "Q+1 mod Q should equal 1");
}
```

**Step 4: Add `validate_pow_v1` rejects bad d test**

```rust
#[test]
fn test_v1_pow_rejects_d_above_target() {
    let mut header = Header::default_for_test();
    header.version = 1;
    header.n_bits = 0x01010000; // minimal difficulty
    // Set d to a very large value (should exceed target)
    header.pow_solution.d = vec![0xFF; 32];
    let result = validate_pow(&header);
    assert!(result.is_err(), "v1 PoW should reject when d >= target");
}
```

**Step 5: Run tests**

```bash
cargo test -p ergo-consensus
```

**Step 6: Commit**

```bash
git add crates/ergo-consensus/src/autolykos.rs
git commit -m "test(consensus): add unit tests for Autolykos v1 PoW helpers"
```

---

### Task 4: Add v1 Header Test Vector

**Files:**
- Modify: `crates/ergo-testkit/src/header_vectors.rs`

**What:** Add a real mainnet v1 header test vector. Fetch from the Ergo Explorer API (height 1 or another early block) and construct the header struct with all fields. Verify `validate_pow` passes. Also test with a mutated nonce to verify rejection.

**Step 1: Fetch a v1 header from Ergo Explorer**

Use the Ergo Explorer API to get a v1 mainnet header. For example, height 1:
```
https://api.ergoplatform.com/api/v1/blocks/headers?offset=0&limit=2
```

Or a specific block:
```
https://api.ergoplatform.com/api/v1/blocks/{headerId}
```

The genesis block (height 1) or any block before height 417,792 will be v1. Extract:
- `version` (must be 1)
- `parentId`, `adProofsRoot`, `transactionsRoot`, `stateRoot`, `extensionHash`
- `timestamp`, `nBits`, `height`, `votes`
- `powSolutions.pk` (33 bytes hex), `powSolutions.w` (33 bytes hex), `powSolutions.n` (8 bytes hex), `powSolutions.d` (variable hex)

**Step 2: Add the test vector function**

In `header_vectors.rs`, add a function like the existing `mainnet_header_500001()`:

```rust
fn mainnet_header_v1_HEIGHTHERE() -> Header {
    Header {
        version: 1,
        parent_id: ModifierId(hex_to_array("...")),
        // ... all fields from Explorer API ...
        pow_solution: AutolykosSolution {
            miner_pk: hex_to_array("..."),
            w: hex_to_array("..."),
            nonce: hex_to_array("..."),
            d: hex::decode("...").unwrap(),
        },
    }
}
```

**Step 3: Add PoW validation test**

```rust
#[test]
fn header_v1_pow_valid() {
    let header = mainnet_header_v1_HEIGHTHERE();
    autolykos::validate_pow(&header)
        .expect("PoW validation should pass for mainnet v1 block");
}

#[test]
fn header_v1_mutated_nonce_fails() {
    let mut header = mainnet_header_v1_HEIGHTHERE();
    header.pow_solution.nonce[0] ^= 0xFF;
    let result = autolykos::validate_pow(&header);
    assert!(result.is_err(), "PoW should fail for tampered v1 nonce");
}
```

**Step 4: Run tests**

```bash
cargo test -p ergo-testkit -- header_v1
```

**Step 5: Commit**

```bash
git add crates/ergo-testkit/src/header_vectors.rs
git commit -m "test(testkit): add mainnet v1 header test vector for Autolykos v1 PoW"
```

---

### Task 5: Fix SyncInfo V2 Ordering

**Files:**
- Modify: `crates/ergo-network/src/persistent_sync.rs:81-93`
- Modify: `crates/ergo-network/src/message_handler.rs:298-315`

**What:** Fix two issues:
1. We send headers oldest-first; Scala sends newest-first. Scala peers use `head` (first element) as our tip, so they see our oldest header instead of our best.
2. We use `.last()` to read the tip from incoming SyncInfo; Scala sends newest-first so `.last()` gives us the oldest offset header (up to 512 blocks behind their real tip).

**Step 1: Fix `build_sync_info_persistent` to send newest-first**

In `crates/ergo-network/src/persistent_sync.rs`, change the iteration at line 82 from ascending to descending:

```rust
// Before:
for h in start..=best_height {

// After:
// Iterate newest-first matching Scala convention where the first
// element is the chain tip (Scala peers use `head` to read our tip).
for h in (start..=best_height).rev() {
```

**Step 2: Fix `handle_sync_info` to read tip from first element**

In `crates/ergo-network/src/message_handler.rs`, change `.last()` to `.first()` in two places (lines 301 and 309):

```rust
// Before (line 301):
.last()

// After:
.first()
```

```rust
// Before (line 309):
v2.last_headers.last().map(|h| {

// After:
v2.last_headers.first().map(|h| {
```

**Step 3: Check for other `.last()` usages on SyncInfo headers**

Search the codebase for other places that access `last_headers.last()`:

```bash
grep -rn "last_headers.last\|last_headers\[" crates/
```

Fix any others found to use `.first()` for tip access or iterate correctly for the newest-first ordering.

**Step 4: Update persistent_sync tests**

In `persistent_sync.rs` tests, the `sync_info_many_headers` test checks `v2.last_headers.len() == 10`. The length is unchanged, but if any test checks ordering (e.g., `last_headers[0].height`), update it to expect newest-first.

**Step 5: Run tests**

```bash
cargo test -p ergo-network
```

**Step 6: Commit**

```bash
git add crates/ergo-network/src/persistent_sync.rs crates/ergo-network/src/message_handler.rs
git commit -m "fix(network): send SyncInfo V2 headers newest-first matching Scala convention"
```

---

### Task 6: Workspace Validation

**Files:** None (verification only)

**Step 1: Full test suite**

```bash
cargo test --workspace
```

Expected: all tests pass (should be ~1,380+).

**Step 2: Clippy**

```bash
cargo clippy --workspace -- -D warnings
```

Expected: 0 warnings.

**Step 3: Release build**

```bash
cargo build --release --features wallet
```

Expected: clean build.

**Step 4: Quick sync test (optional)**

Start the node fresh and verify it begins syncing v1 headers:

```bash
rm -rf .ergo
cargo run --release -- --config config/ergo-mainnet.toml
```

Watch logs for:
- `headers_height` increasing past 0
- No `UnsupportedVersion` errors
- Headers progressing through v1 heights (0-417,791)

---

## Task Dependencies

```
Task 1 (add deps) — independent, must be first
Task 2 (v1 verification) — depends on Task 1
Task 3 (v1 unit tests) — depends on Task 2
Task 4 (v1 header vector) — depends on Task 2
Task 5 (SyncInfo fix) — independent of Tasks 2-4
Task 6 (validation) — after all above
```

**Execution order:** Task 1 → Task 2 → Tasks 3, 4, 5 in parallel → Task 6
