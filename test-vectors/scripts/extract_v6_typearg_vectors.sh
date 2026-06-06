#!/usr/bin/env bash
set -euo pipefail

# Re-extract the v6 explicit-type-arg oracle vectors from a Scala node.
#
# Usage: NODE_URL=http://127.0.0.1:9099 API_KEY=hello \
#        ./extract_v6_typearg_vectors.sh > vectors.tsv
#
# Compiles the six hasExplicitTypeArgs method shapes (plus the
# literal-index getReg control) via POST /script/p2sAddress with
# treeVersion=3, base58-decodes each returned P2S address locally
# (strip the 0x03 mainnet-P2S prefix and 4-byte checksum), and emits
# one `name<TAB>address<TAB>tree_hex` line per vector for diffing
# against test-vectors/scala/sigma/v6_methodcall_typeargs_v0_header/
# golden_vectors.json.
#
# The node does not need to be synced — compilation is chain-state
# independent. /script/addressToBytes cannot do the decode step: it
# rejects these sizeless v0-header trees when the node's version
# context lacks v6 methods (see the fixture README). Requires python.

NODE_URL="${NODE_URL:-http://127.0.0.1:9053}"
API_KEY="${API_KEY:?set API_KEY to the node api_key}"

SOURCES=(
    "deserializeTo_106_4|sigmaProp(Global.deserializeTo[Header](INPUTS(0).R4[Coll[Byte]].get).height > 100)"
    "fromBigEndianBytes_106_5|sigmaProp(Global.fromBigEndianBytes[Long](INPUTS(0).R4[Coll[Byte]].get) > 0L)"
    "some_106_9|sigmaProp(Global.some[Int](100).isDefined)"
    "none_106_10|sigmaProp(Global.none[Int]().isEmpty)"
    "getReg_99_19_dynamic|sigmaProp(SELF.getReg[Int](INPUTS.size).isDefined)"
    "getVarFromInput_101_12|sigmaProp(CONTEXT.getVarFromInput[Int](0, 1).isDefined)"
    "getReg_literal_control|sigmaProp(SELF.getReg[Int](4).isDefined)"
)

b58_to_tree_hex() {
    python - "$1" <<'PYEOF'
import sys
ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
s = sys.argv[1]
n = 0
for ch in s:
    n = n * 58 + ALPHA.index(ch)
raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
prefix, content = raw[0], raw[1:-4]
assert prefix == 0x03, f"expected mainnet P2S prefix 0x03, got {prefix:#04x}"
print(content.hex())
PYEOF
}

for entry in "${SOURCES[@]}"; do
    name="${entry%%|*}"
    source="${entry#*|}"
    address=$(curl -sf -X POST "$NODE_URL/script/p2sAddress" \
        -H "api_key: $API_KEY" -H "Content-Type: application/json" \
        -d "{\"source\": \"$source\", \"treeVersion\": 3}" |
        python -c "import sys, json; print(json.load(sys.stdin)['address'])")
    tree_hex=$(b58_to_tree_hex "$address")
    printf '%s\t%s\t%s\n' "$name" "$address" "$tree_hex"
done
