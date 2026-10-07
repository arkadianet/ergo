//! Reproducible wire-codec microbenchmark over committed mainnet boxes.

use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{box_id_with, parse_ergo_box_bytes, serialize_ergo_box};
use std::{hint::black_box, time::Instant};

fn main() {
    let repeats = std::env::args()
        .nth(1)
        .map(|n| n.parse::<usize>().expect("positive repeat count"))
        .unwrap_or(1000)
        .max(1);
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../test-vectors/mainnet/boxes_1759500.json"
    ))
    .unwrap();
    let corpus: Vec<_> = vectors
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            let bytes = hex::decode(v["bytes"].as_str().unwrap()).unwrap();
            let tree = hex::decode(v["ergoTree"].as_str().unwrap()).unwrap();
            let parsed = parse_ergo_box_bytes(&bytes, &tree).unwrap();
            assert_eq!(serialize_ergo_box(&parsed).unwrap(), bytes);
            (bytes, tree, parsed)
        })
        .collect();
    let bytes: usize = corpus.iter().map(|(bytes, _, _)| bytes.len()).sum();
    println!(
        "sample,boxes,corpus_bytes,repeats,parse_ns_per_box,write_ns_per_box,scratch_id_ns_per_box"
    );
    for sample in 0..6 {
        let started = Instant::now();
        for _ in 0..repeats {
            for (bytes, tree, _) in &corpus {
                black_box(parse_ergo_box_bytes(black_box(bytes), black_box(tree)).unwrap());
            }
        }
        let parse_ns = started.elapsed().as_nanos() / (repeats * corpus.len()) as u128;
        let started = Instant::now();
        for _ in 0..repeats {
            for (_, _, parsed) in &corpus {
                black_box(serialize_ergo_box(black_box(parsed)).unwrap());
            }
        }
        let write_ns = started.elapsed().as_nanos() / (repeats * corpus.len()) as u128;
        let mut scratch = VlqWriter::new();
        let started = Instant::now();
        for _ in 0..repeats {
            for (_, _, parsed) in &corpus {
                black_box(box_id_with(&mut scratch, black_box(parsed)).unwrap());
            }
        }
        let id_ns = started.elapsed().as_nanos() / (repeats * corpus.len()) as u128;
        if sample > 0 {
            println!(
                "{sample},{},{bytes},{repeats},{parse_ns},{write_ns},{id_ns}",
                corpus.len()
            );
        }
    }
}
