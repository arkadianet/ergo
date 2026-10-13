#!/usr/bin/env python3
"""Compare independently regenerated SDK reductions; proof nonces may differ."""
import argparse
import json


NONCE_DEPENDENT = (
    "scala_proofs",
    "scala_signed_hex",
    "appkit_signed_hex",
    "cold_response",
    "cstx_qr_low_pages",
)


def normalized(path):
    with open(path, encoding="utf-8") as source:
        data = json.load(source)
    for row in data["cases"]:
        for field in NONCE_DEPENDENT:
            del row[field]
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture")
    parser.add_argument("regenerated")
    args = parser.parse_args()
    if normalized(args.fixture) != normalized(args.regenerated):
        raise SystemExit("Scala SDK reduced transaction bytes, transport or costs changed")
    print("Scala SDK reduced bytes, transport and costs match")


if __name__ == "__main__":
    main()
