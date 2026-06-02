# SBigInt 32-byte length cap parity

**Audit reference:** `docs/audit-2.md` M12 / line 283 (SBigInt length cap parity).

## Oracle source

Primary: `reference/sigmastate-interpreter/core/shared/src/main/scala/sigma/data/CoreDataSerializer.scala`.

The relevant constant `MaxBigIntSizeInBytes = 32` gates `deserializeBigInt`:

```scala
def deserializeBigInt(r: Reader): BigInteger = {
  val size = r.getUShort()
  if (size > MaxBigIntSizeInBytes) sys.error(...)
  val bytes = r.getBytes(size)
  new BigInteger(bytes)
}
```

Scala's `BigInteger(bytes)` (Java stdlib) interprets `bytes` as a
big-endian signed two's-complement integer. Result range:
`[-2^255, 2^255)` for the 32-byte cap.

Asymmetry: `+2^255` requires 33 bytes in signed encoding (a leading
`0x00` to keep the sign bit clear), so the cap rejects it. `-2^255`
fits in 32 bytes (`0x80 0x00 ... 0x00`), so the cap accepts it.

## Wire format

`putUShort(len) | bytes`. `putUShort` is Scorex's VLQ-encoded
unsigned short, NOT a fixed 2-byte big-endian u16. Values < 128
encode to a single byte; ≥ 128 use continuation bits.

## Golden wire bytes

| Value | Signed encoding | VLQ length prefix | Full wire bytes |
|---|---|---|---|
| `0` | `[]` (empty per `len == 0` early-return) | `0x00` | `0x00` |
| `1` | `[0x01]` | `0x01` | `0x01 0x01` |
| `-1` | `[0xFF]` | `0x01` | `0x01 0xFF` |
| `-2^255` | `[0x80, 0; 31]` (32 bytes) | `0x20` (= 32) | `0x20 0x80 0x00 (x31)` (33 bytes total) |
| `2^255 - 1` | `[0x7F, 0xFF; 31]` (32 bytes) | `0x20` | `0x20 0x7F 0xFF (x31)` |
| `+2^255` | 33 bytes (sign-extension byte) | — | **rejected by writer** (`SBigInt value too long`) |

These bytes are derived from the Scala `CoreDataSerializer` contract,
not from our writer's output. The Rust writer's output must match.
Pinned in `ergo-ser/src/sigma_value.rs::tests::bigint_golden_wire_bytes_for_minus_two_pow_255`.

## Boundary tests

| Test | Direction | Expected |
|---|---|---|
| len=0 | read | `BigInt(0)` (existing `roundtrip_bigint`) |
| len=32, top bit set (0x80 prefix) | read | negative `BigInt` (`bigint_accepts_32_byte_signed_value_with_top_bit_set_as_negative`) |
| len=33 | read | `InvalidData("SBigInt value too long")` (`bigint_rejects_oversize_on_read`) |
| len=65535 | read | `InvalidData` **before** alloc (`bigint_rejects_huge_size_on_read_before_alloc`) |
| 32-byte BigInt | write | accept (`bigint_accepts_32_byte_value_on_write`) |
| 33-byte BigInt (+2^255) | write | `InvalidData` (`bigint_rejects_33_byte_value_on_write`) |
| -2^255 golden wire | write+read | bytes match `0x20 0x80 0x00 (x31)` (`bigint_golden_wire_bytes_for_minus_two_pow_255`) |

## What is NOT covered by Phase 8b

- **End-to-end v6 interpreter exercise of `SGlobal.serialize[SBigInt]`** —
  requires building a v6 ErgoTree literal that calls
  `SGlobal.serialize(bigInt)`, then dispatching through the method-call
  path. Codex r1 asked for this; the routing is mechanical (the write
  rejection propagates through `WriteError` → caller's `?`), but the
  test fixture infrastructure is larger than Phase 8b's scope.
- **Live Scala node oracle capture via `/script/executeWithContext`** —
  same `ErgoLikeContext` JSON construction blocker as Phase 8a
  (12 required fields per `JsonCodecs.scala:440-454`). The
  source-citation oracle above is the available proof.
- **Mainnet corpus scan for >32-byte SBigInt usage** — would prove no
  historical block is invalidated by the new cap. Not run; relies on
  the indirect evidence that the project's existing mainnet sync
  milestone (`ergo-rust-node-checklist.md:502`) operated correctly with
  the (overly-permissive) old reader, implying no honest block carries
  >32-byte SBigInt.
