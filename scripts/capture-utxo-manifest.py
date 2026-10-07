#!/usr/bin/env python3
"""Capture an external snapshot oracle; serialize only P2P requests, never a tree."""

import argparse
import datetime
import hashlib
import io
import json
from pathlib import Path
import secrets
import shlex
import socket
import struct
import sys
import time
import urllib.request


def vlq(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def read_exact(stream, size):
    result = bytearray()
    while len(result) < size:
        chunk = stream.read(size - len(result))
        if not chunk:
            raise ValueError("truncated P2P response")
        result.extend(chunk)
    return bytes(result)


def read_vlq(stream):
    result = 0
    for shift in range(0, 64, 7):
        byte = read_exact(stream, 1)[0]
        result |= (byte & 127) << shift
        if byte < 128:
            return result
    raise ValueError("oversized VLQ")


def short_string(value):
    encoded = value.encode()
    return bytes([len(encoded)]) + encoded


def receive_handshake(stream, magic):
    # Scala ergo-core/.../network/PeerSpec.scala:76-94. Read exactly one
    # handshake so a coalesced first message remains available to the framer.
    read_vlq(stream)
    agent = read_exact(stream, read_exact(stream, 1)[0]).decode()
    version = list(read_exact(stream, 3))
    name = read_exact(stream, read_exact(stream, 1)[0]).decode()
    if read_exact(stream, 1)[0]:
        read_exact(stream, read_exact(stream, 1)[0] - 4)
        read_vlq(stream)
    for _ in range(read_exact(stream, 1)[0]):
        feature_id = read_exact(stream, 1)[0]
        feature = read_exact(stream, read_vlq(stream))
        if feature_id == 3 and feature[:4] != magic:
            raise ValueError("peer handshake network differs from REST node")
    return {"agent": agent, "version": version, "name": name}


def capture_manifest(host, port, magic, manifest_id, get):
    # Scala HandshakeSerializer + PeerSpecSerializer; feature 3 is a session
    # ID (network magic and a zigzag/VLQ Long). No listening address advertised.
    session = magic + vlq(secrets.randbits(63) << 1)
    client_name = "snapshot-oracle-" + secrets.token_hex(8)
    handshake = (
        vlq(int(time.time() * 1000))
        + short_string("manifest-capture")
        + bytes([6, 0, 3])
        + short_string(client_name)
        + bytes([0, 1, 3])
        + vlq(len(session))
        + session
    )
    # Scala BasicMessagesRepo.scala:118-156: GetManifest code 78 takes a
    # raw 32-byte ID; Manifest code 79 wraps bytes with a VLQ UInt length.
    checksum = hashlib.blake2b(manifest_id, digest_size=32).digest()[:4]
    request = magic + bytes([78]) + struct.pack(">I", 32) + checksum + manifest_id
    with socket.create_connection((host, port), timeout=15) as sock:
        with sock.makefile("rb") as stream:
            sock.sendall(handshake)
            peer = receive_handshake(stream, magic)
            # Scala scorex/core/network/PeerConnectionHandler.scala:92-102
            # consumes an entire TCP read as a handshake, dropping coalesced
            # message bytes. Wait until REST observes our unique peer name;
            # this also confirms REST and P2P belong to the same node.
            ready_deadline = time.monotonic() + 10
            while not any(p["name"] == client_name for p in get("/peers/connected")):
                if time.monotonic() >= ready_deadline:
                    raise ValueError("REST node did not observe the P2P handshake")
                time.sleep(0.1)
            sock.sendall(request)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                frame = read_exact(stream, 9)
                if frame[:4] != magic:
                    raise ValueError("wrong network magic in response")
                size = struct.unpack(">I", frame[5:])[0]
                if size > 4_000_000:
                    raise ValueError("oversized P2P response")
                checksum = read_exact(stream, 4) if size else b""
                payload = read_exact(stream, size)
                if size and hashlib.blake2b(payload, digest_size=32).digest()[:4] != checksum:
                    raise ValueError("P2P response checksum mismatch")
                if frame[4] == 79:
                    body = io.BytesIO(payload)
                    manifest = read_exact(body, read_vlq(body))
                    if body.read():
                        raise ValueError("trailing Manifest message bytes")
                    return manifest, peer
    raise ValueError("peer did not return a manifest before deadline")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("node_url", help="Scala REST base URL")
    parser.add_argument("height", type=int, help="advertised snapshot height")
    parser.add_argument("p2p_host", help="P2P address of the same Scala node")
    parser.add_argument("p2p_port", type=int)
    parser.add_argument("out_file", nargs="?", type=Path)
    args = parser.parse_args()
    base = args.node_url.rstrip("/")

    def get(path):
        with urllib.request.urlopen(base + path, timeout=15) as response:
            return json.load(response)

    info = get("/info")
    network = info["network"]
    # Scala src/main/resources/{mainnet,testnet}.conf:125,91.
    magic = {"mainnet": bytes([1, 0, 2, 4]), "testnet": bytes([2, 3, 2, 3])}[network]
    snapshots = get("/utxo/getSnapshotsInfo")["availableManifests"]
    manifest_hex = snapshots.get(str(args.height))
    if manifest_hex is None:
        raise ValueError(f"no manifest at height {args.height}; available: {snapshots}")
    manifest_id = bytes.fromhex(manifest_hex)
    if len(manifest_id) != 32:
        raise ValueError("manifest ID must be 32 bytes")
    header_ids = get(f"/blocks/at/{args.height}")
    # At a fork, select the header whose state root matches the advertised ID.
    headers = [get(f"/blocks/{header_id}/header") for header_id in header_ids]
    header = next(h for h in headers if h["stateRoot"][:64] == manifest_hex)
    root = bytes.fromhex(header["stateRoot"])
    if len(root) != 33 or header["height"] != args.height:
        raise ValueError("invalid snapshot header")
    manifest, peer = capture_manifest(args.p2p_host, args.p2p_port, magic, manifest_id, get)
    # Scala avldb/.../serialization/ManifestSerializer.scala:17-19,35-41:
    # byte 0 is rootHeight, independently obtained from the served manifest.
    if len(manifest) < 2 or manifest[0] != root[32]:
        raise ValueError("manifest rootHeight differs from header stateRoot byte 32")
    repo = Path(__file__).resolve().parent.parent
    out = args.out_file or repo / f"test-vectors/{network}/utxo_snapshot_manifest_{args.height}.json"
    binary = out.with_suffix(".bin")
    fixture = {
        "height": args.height,
        "manifest_id": manifest_hex,
        "header_id": header["id"],
        "state_root": header["stateRoot"],
        "header": header,
        "source": base,
        "p2p_source": f"{args.p2p_host}:{args.p2p_port}",
        "scala_version": info["appVersion"],
        "peer": peer,
        "network": network,
        "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "command": shlex.join(["scripts/capture-utxo-manifest.sh", *sys.argv[1:]]),
        "manifest_file": binary.name,
        "manifest_length": len(manifest),
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    binary.write_bytes(manifest)
    out.write_text(json.dumps(fixture, indent=2) + "\n")
    print(f"Captured {len(manifest)} Scala manifest bytes to {binary}; metadata: {out}")


if __name__ == "__main__":
    main()
