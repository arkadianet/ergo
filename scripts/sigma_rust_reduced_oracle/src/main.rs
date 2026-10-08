//! Independent sigma-rust parity, cross-verification and actual QR image roundtrips.
//! This separate workspace keeps reference SDK / QR dependencies out of the wallet.
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE},
    Engine,
};
use ergo_lib::{
    chain::transaction::{reduced::ReducedTransaction, Transaction},
    ergotree_interpreter::sigma_protocol::verifier::verify_signature,
    ergotree_ir::{chain::ergo_box::ErgoBox, serialization::SigmaSerializable},
};
use qrcode::{Color, EcLevel, QrCode};
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn qr_scan(payload: &str) -> String {
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M).unwrap();
    let modules = code.width();
    let scale = 4;
    let border = 4;
    let width = (modules + 2 * border) * scale;
    let mut pixels = vec![255; width * width];
    for y in 0..modules {
        for x in 0..modules {
            if code[(x, y)] == Color::Dark {
                for dy in 0..scale {
                    for dx in 0..scale {
                        pixels[((y + border) * scale + dy) * width + (x + border) * scale + dx] = 0;
                    }
                }
            }
        }
    }
    let mut scanner = quircs::Quirc::default();
    let mut results = scanner.identify(width, width, &pixels);
    let decoded = results
        .next()
        .expect("QR must be detected")
        .unwrap()
        .decode()
        .unwrap();
    assert!(results.next().is_none());
    assert_eq!(decoded.payload, payload.as_bytes());
    String::from_utf8(decoded.payload).unwrap()
}

fn scan_pages(pages: &[Value], direction: &str) -> Value {
    let mut parts = BTreeMap::new();
    for raw in pages.iter().rev() {
        // Camera scan order need not equal page order.
        let scanned = qr_scan(raw.as_str().unwrap());
        let page: Value = serde_json::from_str(&scanned).unwrap();
        let p = page["p"].as_u64().unwrap_or(1) as usize;
        let n = page["n"].as_u64().unwrap_or(1) as usize;
        assert_eq!(n, pages.len());
        assert!((1..=n).contains(&p));
        assert!(parts
            .insert(p, page[direction].as_str().unwrap().to_string())
            .is_none());
    }
    let inner = parts.values().cloned().collect::<String>();
    serde_json::from_str(&inner).unwrap()
}

fn appkit_signed_bytes(transaction: &[u8], cost: u64) -> Vec<u8> {
    let mut bytes = transaction.to_vec();
    let mut n = u32::try_from(cost).unwrap();
    while n >= 128 {
        bytes.push((n as u8 & 127) | 128);
        n >>= 7;
    }
    bytes.push(n as u8);
    bytes
}

fn check_signed(reduced: &ReducedTransaction, bytes: &[u8]) {
    let signed = Transaction::sigma_parse_bytes(bytes).unwrap();
    assert_eq!(signed.sigma_serialize_bytes().unwrap(), bytes);
    let message = reduced.unsigned_tx.bytes_to_sign().unwrap();
    assert_eq!(signed.bytes_to_sign().unwrap(), message);
    assert_eq!(signed.id(), reduced.unsigned_tx.id());
    let inputs = reduced.reduced_inputs();
    assert_eq!(signed.inputs.len(), inputs.len());
    for (input, reduction) in signed.inputs.as_vec().iter().zip(inputs.as_vec()) {
        assert_eq!(input.spending_proof.extension, reduction.extension);
        assert!(verify_signature(
            reduction.sigma_prop.clone(),
            &message,
            input.spending_proof.proof.as_ref()
        )
        .unwrap());
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("fixture path");
    let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    for row in fixture["cases"].as_array().unwrap() {
        let bytes = hex::decode(row["reduced_hex"].as_str().unwrap()).unwrap();
        let reduced = ReducedTransaction::sigma_parse_bytes(&bytes).unwrap();
        assert_eq!(
            reduced.sigma_serialize_bytes().unwrap(),
            bytes,
            "{}",
            row["name"]
        );
        let inputs = reduced.reduced_inputs();
        assert_eq!(inputs.len(), row["sigma_hex"].as_array().unwrap().len());
        for ((input, sigma), cost) in inputs
            .as_vec()
            .iter()
            .zip(row["sigma_hex"].as_array().unwrap())
            .zip(row["input_costs"].as_array().unwrap())
        {
            assert_eq!(
                hex::encode(input.sigma_prop.sigma_serialize_bytes().unwrap()),
                sigma.as_str().unwrap()
            );
            assert_eq!(input.cost, cost.as_u64().unwrap());
        }
        let message = reduced.unsigned_tx.bytes_to_sign().unwrap();
        assert_eq!(
            hex::encode(&message),
            row["unsigned_message_hex"].as_str().unwrap()
        );
        assert_eq!(
            reduced.unsigned_tx.id().to_string(),
            row["transaction_id"].as_str().unwrap()
        );

        let request = scan_pages(row["csr_qr_low_pages"].as_array().unwrap(), "CSR");
        assert_eq!(
            STANDARD
                .decode(request["reducedTx"].as_str().unwrap())
                .unwrap(),
            bytes
        );
        assert_eq!(
            request["inputs"].as_array().unwrap().len(),
            reduced.unsigned_tx.inputs.len()
        );
        for ((encoded, input), fixture_box) in request["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .zip(reduced.unsigned_tx.inputs.as_vec())
            .zip(row["input_boxes"].as_array().unwrap())
        {
            let box_bytes = STANDARD.decode(encoded.as_str().unwrap()).unwrap();
            assert_eq!(hex::encode(&box_bytes), fixture_box.as_str().unwrap());
            let b = ErgoBox::sigma_parse_bytes(&box_bytes).unwrap();
            assert_eq!(b.sigma_serialize_bytes().unwrap(), box_bytes);
            assert_eq!(b.box_id(), input.box_id);
        }
        let response = scan_pages(row["cstx_qr_low_pages"].as_array().unwrap(), "CSTX");
        let signed_bytes = STANDARD
            .decode(response["signedTx"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            hex::encode(&signed_bytes),
            row["appkit_signed_hex"].as_str().unwrap()
        );
        let raw_signed = hex::decode(row["scala_signed_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            appkit_signed_bytes(&raw_signed, row["crypto_cost"].as_u64().unwrap()),
            signed_bytes
        );
        check_signed(&reduced, &raw_signed);

        let uri = qr_scan(row["ergopay_uri"].as_str().unwrap());
        let ergo_pay_bytes = URL_SAFE
            .decode(uri.strip_prefix("ergopay:").unwrap())
            .unwrap();
        assert_eq!(ergo_pay_bytes, bytes);
        let dynamic_request: Value =
            serde_json::from_str(&row["ergopay_request"].to_string()).unwrap();
        assert_eq!(
            URL_SAFE
                .decode(dynamic_request["reducedTx"].as_str().unwrap())
                .unwrap(),
            bytes
        );
        println!(
            "sigma-rust wire, costs, AppKit proof and CSR/CSTX/ErgoPay QR roundtrip {}",
            row["name"]
        );
    }
    if let Some(path) = args.next() {
        let rows: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for row in rows.as_array().unwrap() {
            let reduced = ReducedTransaction::sigma_parse_bytes(
                &hex::decode(row["reduced_hex"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            let signed = hex::decode(row["signed_hex"].as_str().unwrap()).unwrap();
            check_signed(&reduced, &signed);
            // Test the reverse full-transaction EIP19 response, not a detached proof array.
            let appkit_bytes = hex::decode(row["appkit_signed_hex"].as_str().unwrap()).unwrap();
            assert_eq!(
                appkit_signed_bytes(&signed, row["crypto_cost"].as_u64().unwrap()),
                appkit_bytes
            );
            let inner = json!({"signedTx": STANDARD.encode(&appkit_bytes)}).to_string();
            let chunks: Vec<_> = inner.as_bytes().chunks(366).collect();
            let pages: Vec<_> = chunks
                .iter()
                .enumerate()
                .map(|(i, bytes)| {
                    let payload = std::str::from_utf8(bytes).unwrap();
                    Value::String(
                        if chunks.len() == 1 {
                            json!({"CSTX":payload})
                        } else {
                            json!({"CSTX":payload,"n":chunks.len(),"p":i+1})
                        }
                        .to_string(),
                    )
                })
                .collect();
            let response = scan_pages(&pages, "CSTX");
            assert_eq!(
                STANDARD
                    .decode(response["signedTx"].as_str().unwrap())
                    .unwrap(),
                appkit_bytes
            );
            println!("sigma-rust verifies Rust signed response {}", row["name"]);
        }
    }
}
