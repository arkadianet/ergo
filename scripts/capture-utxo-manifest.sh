#!/usr/bin/env bash
# Capture raw Scala ManifestSerializer bytes over P2P and the matching REST header.
# Usage: capture-utxo-manifest.sh <node-url> <height> <p2p-host> <p2p-port> [out-file]
# Example (Scala testnet):
#   scripts/capture-utxo-manifest.sh http://127.0.0.1:9062 522239 127.0.0.1 9020
# Requires Python 3; no Rust serializer is used. The node must advertise the
# height in /utxo/getSnapshotsInfo (ergo.node.utxo.storingUtxoSnapshots > 0).
# Scala UtxoApiRoute.scala:29-30 exposes snapshot metadata only; raw bytes need
# GetManifest (BasicMessagesRepo.scala:118-156). A sibling .bin file contains
# the unmodified ManifestSerializer bytes, without the P2P length prefix.
# The JSON records the header, source, Scala version, checksum and command.
set -euo pipefail
exec python3 "$(dirname "$(realpath "$0")")/capture-utxo-manifest.py" "$@"
