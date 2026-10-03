# ergo-rest-json

**Purpose:** Shared Scala-compatible REST JSON shapes and conversion through the
production wire codecs. Parsing JSON does not establish transaction validity,
proof validity or authenticated chain provenance.

**Workspace dependencies:** ergo-primitives and ergo-ser.
**Consumers:** ergo-api, ergo-node, ergo-difftest and validation tests.

## Start here

- `src/lib.rs` re-exports `decode` and `types`; mining DTOs use the `mining` module.
- `src/types.rs` defines the block, transaction, output and proof DTOs, plus exact
  nonnegative numeric conversion. Derived IDs and sizes on submit DTOs are ignored.
- `src/decode.rs` defines `DecodeMode`, field validation, independent value
  framing, section conversion and full-block header-ID consistency checks.
- `src/mining.rs` defines work messages, PoW solutions, reward responses and the
  decimal BigInt helpers shared with header decoding.

## Conversion policy

Every mode parses its inputs. Callers choose serialization policy independently
of how they obtained or validated those inputs.

| Surface | Submit | Preserve |
|---|---|---|
| ErgoTree | Parse, reject unsupported/unparsed trees, retain received bytes | Parse structurally, allow readable opaque soft-fork representation, retain received bytes |
| Additional registers | Decode each value independently, then write its parsed form | Decode each value independently and retain its consumed prefix |
| Spending-proof context extension | Cache canonical parsed writer bytes | Validate the raw aggregate and cache canonical parsed writer bytes |
| Standalone context helper | Return canonical writer bytes | Return independently consumed value prefixes in Scala map order |

`decode_ergo_tree_canonicalize_with_mode` retains the original tree bytes; its
historical name does not imply a writer round trip. Submit acceptance gates
are distinct from consensus validation. Preserve does not authenticate a box
or bypass structural parsing.

Each register/context JSON field has its own value reader, matching the pinned
SDK decoder. Unused suffix bytes are tolerated and omitted. A truncated field
cannot borrow bytes from its neighbor, and a suffix cannot become another key
or value when fields are joined. The resulting aggregate must be fully consumed.
The register writer preserves ConstantTuple, CreateTuple and ConcreteCollection
node forms; scalar encodings can normalize. Preserve retains the consumed scalar
spelling as well.

Output conversion constructs candidates with the selected tree/register byte
policy. Parsed whole-box cached identity and newly sealed candidate identity
are separate `ergo-ser` contracts. JSON conversion is not a general promise to
preserve every input spelling in transaction or box IDs.

## Fields and bounds

- `additionalRegisters` must contain dense R4..R9 names starting at R4.
- Context-extension decimal keys fit a byte; duplicate byte keys are rejected.
  At most 127 entries fit the Scala signed-byte count. Up to four entries retain
  JSON insertion order; larger maps use Scala 2.12 HAMT iteration order.
- Magnitude fields accept exact integral decimal/exponent notation in JSON
  numbers or numeric strings. Nonzero negative or fractional values are rejected;
  negative zero is accepted as zero. Conversion never rounds through a float.
- Output value and token amount fields must also fit Scala `Long.MAX_VALUE`,
  including DTOs constructed directly in Rust. Monetary rules are validated later.
- Nonzero BigInt conversion has the pinned Circe 2^18 decimal-digit bound, checked
  before exponent expansion. Zero does not require scale expansion.
- `nBits` must fit u32. Digest/ID, state root, votes, public key and nonce fields
  are length-checked before conversion to fixed-size representations.
- Header version 1 uses the V1 PoW solution; later versions use V2. The V1 `d`
  field accepts an exact nonnegative number/string magnitude and serializes it
  with the signed two's-complement leading-zero convention.
- Full-block conversion requires each present section's `headerId` to match the
  computed header ID before returning its wire bytes.

## Entry points and evidence

`decode_scala_transaction(_with_mode)` and the block-transaction decoder share
`build_transaction_from_input`. `decode_input_with_mode` uses checked
`SpendingProof` constructors. `decode_registers_with_mode` and
`decode_context_extension_with_mode` return parsed values plus mode-specific
aggregate bytes. Header, extension and AD-proof conversion feed
`decode_scala_full_block`, which returns `DecodedFullBlock`.

Tests under `tests/it/` cover modes, numeric bounds and independent field framing.
`test-vectors/ergo-rest-json/json-contracts/` retains actual pinned SDK numeric,
canonical-write and consumed-prefix observations with command/dependency/source
hashes. Header fixtures and the node's existing `b4_*` tests cover additional
captured conversion paths. These finite fixtures do not establish full-chain
acceptance parity.

Mining DTOs retain the Scala `msg`, `b`, `h`, `pk` and `proof` field conventions;
optional node fields default when absent. Served-job metrics reflect frozen
selection/trimming results, with exact nanoERG fee strings and block-cost units.
Reading those metrics does not trigger another validation or scan.
