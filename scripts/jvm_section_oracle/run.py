#!/usr/bin/env python3
"""Regenerate section storage fixtures against the pinned, unmodified assembly."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
JAR_SHA = '8616f4051335cf3b7ee3f3099821b7b27b1913bcd8bb5957ed7fc42dde26e9fa'


def vlq(number):
    result = bytearray()
    while number >= 128:
        result.append((number & 127) | 128)
        number >>= 7
    result.append(number)
    return result.hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java', required=True)
    parser.add_argument('--jar', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--reflect', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if hashlib.sha256(args.jar.read_bytes()).hexdigest() != JAR_SHA:
        parser.error('assembly does not match the pinned Ergo 6.0.7 artifact')
    source = ROOT / 'scripts/jvm_section_oracle/SectionOracle.scala'
    vectors = json.loads((ROOT / 'test-vectors/scala/canonical_extension_and_group_element.json').read_text())
    transactions = [(case['label'], case['tx_wire_hex']) for case in vectors['transactions']]
    prefix = '01' + '01' * 32 + '00'
    output = '000001c0843d10010101d17300000000'
    for label, point in [('group_zero_lead_garbage', '00' + 'aa' * 32),
                         ('group_identity_zero', '00' * 33)]:
        transactions.append((label, prefix + '010107' + point + output))
    wires = [(f'{label}_v{version}', '11' * 32 +
              (vlq(10000000 + version) if version > 1 else '') + '01' + tx)
             for version in (1, 4) for label, tx in transactions]
    with tempfile.TemporaryDirectory(prefix='ergo-section-classes-') as directory:
        classpath = os.pathsep.join(map(str, [args.compiler.resolve(), args.reflect.resolve(), args.jar.resolve()]))
        subprocess.run([args.java, '-cp', classpath, 'scala.tools.nsc.Main', '-usejavacp',
                        '-d', directory, str(source)], check=True)

        def evaluate(cases):
            result = subprocess.run([args.java, '-cp', directory + os.pathsep + str(args.jar.resolve()),
                                     'SectionOracle'], input=''.join(f'{label} {wire}\n' for label, wire in cases),
                                    capture_output=True, text=True, check=True, cwd=directory)
            records = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{"label"')]
            if len(records) != len(cases):
                raise RuntimeError(f'incomplete oracle output: {result.stdout}\n{result.stderr}')
            return records

        first = evaluate(wires)
        headers = {}
        # Synthetic headers commit to the oracle's root. They are not mined:
        # tests start at section reception after header validation.
        genesis = bytes.fromhex(json.loads((ROOT / 'test-vectors/mainnet/headers_1_10.json').read_text())[0]['bytes'])
        for index, record in enumerate(first):
            if not record['accepted']:
                continue
            version = record['block_version']
            root = bytes.fromhex(record['transactions_root'])
            if version == 1:
                raw = genesis[:65] + root + genesis[97:]
            else:
                raw = (bytes([version]) + bytes(64) + root + bytes(33) + bytes([1]) + bytes(32) +
                       bytes(4) + bytes([2]) + bytes(3) + bytes([0]) +
                       bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798') + bytes(8))
            header_id = hashlib.blake2b(raw, digest_size=32).hexdigest()
            label, wire = wires[index]
            wires[index] = (label, header_id + wire[64:])
            headers[label] = raw.hex()
        records = evaluate(wires)
        for record in records:
            if record['accepted']:
                record['header_hex'] = headers[record['label']]
                assert record['stored_hex'] == record['canonical_hex'] == record['served_hex']
    fixture = {
        'reference': {'release': 'v6.0.7', 'commit': '3a6b00d37e3bda2b36447a922606b4ca5a09568f',
                      'jar_url': 'https://github.com/ergoplatform/ergo/releases/download/v6.0.7/ergo-6.0.7.jar',
                      'jar_sha256': JAR_SHA, 'scala': '2.12.20', 'java': 'Java 17',
                      'oracle_source': str(source.relative_to(ROOT)),
                      'oracle_sha256': hashlib.sha256(source.read_bytes()).hexdigest()},
        'scope': 'Synthetic transactions: parser and authenticated section acceptance, production history storage/serving and REST JSON; no claim of a valid spent UTXO, mined header or full block.',
        'cases': records}
    args.output.write_text(json.dumps(fixture, indent=2) + '\n')
    print(f'{len(records)} section cases captured in {args.output}')


if __name__ == '__main__':
    main()
