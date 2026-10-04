use super::*;
use crate::apply::{apply_block, apply_block_with_derivation, IndexerBlock};
use crate::scratch::BlockApplyScratch;
use crate::store::{IndexerMeta, IndexerStore, OpenOutcome};
use crate::token::IndexedToken;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::register::{AdditionalRegisters, RegisterId, RegisterValue};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaValue};
use ergo_ser::token::Token;
use ergo_ser::transaction::{transaction_id, Transaction};
use redb::{TableDefinition, TableHandle};
use std::collections::BTreeMap;

// These are the pre-ccbb8f81 and pre-4a7823be derivations, used DURING
// block apply so both output appends and subsequent input spends use v2.
fn old_template(bytes: &[u8]) -> Result<Option<Digest32>, IndexerError> {
    let tree = read_ergo_tree(&mut VlqReader::new(bytes)).unwrap();
    if matches!(tree.body, Expr::Unparsed(_)) {
        Ok(None)
    } else {
        template_hash_for_box_bytes(bytes)
    }
}

fn old_token(box_id: &Digest32, token: &Token, regs: &AdditionalRegisters) -> IndexedToken {
    let text = |id| match regs.get(id).map(|r| &r.value) {
        Some(SigmaValue::Coll(CollValue::Bytes(bytes))) => {
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => String::new(),
    };
    let mut record = IndexedToken::from_box(box_id, token, regs);
    record.name = Some(text(RegisterId::R4));
    record.description = Some(text(RegisterId::R5));
    record.decimals = Some(match regs.get(RegisterId::R6).map(|r| &r.value) {
        Some(SigmaValue::Coll(CollValue::Bytes(bytes))) => std::str::from_utf8(bytes)
            .ok()
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(0),
        Some(SigmaValue::Int(n)) => *n,
        _ => 0,
    });
    record
}

fn candidate(tree: &str, regs: AdditionalRegisters, tokens: Vec<Token>) -> ErgoBoxCandidate {
    let bytes = hex::decode(tree).unwrap();
    let tree = read_ergo_tree(&mut VlqReader::new(&bytes)).unwrap();
    ErgoBoxCandidate::new(1_000_000, tree, 1, tokens, regs).unwrap()
}

fn input(id: Digest32) -> Input {
    Input {
        box_id: id,
        spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
    }
}

fn box_id(tx: &Transaction, index: u16) -> Digest32 {
    ErgoBox {
        candidate: tx.output_candidates[index as usize].clone(),
        transaction_id: transaction_id(tx).unwrap(),
        index,
    }
    .box_id()
    .unwrap()
}

fn blocks() -> Vec<Vec<Transaction>> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../test-vectors/ergo-indexer/token-text/stdout.json"
    ))
    .unwrap();
    let mut genesis = Vec::new();
    for (i, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        let regs = AdditionalRegisters {
            registers: (0..3)
                .map(|_| RegisterValue {
                    tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
                    value: SigmaValue::Coll(CollValue::Bytes(bytes.clone())),
                })
                .collect(),
        };
        let id = Digest32::from_bytes([i as u8 + 1; 32]);
        genesis.push(Transaction {
            inputs: vec![input(id)],
            data_inputs: vec![],
            output_candidates: vec![candidate(
                "0008d3",
                regs,
                vec![Token {
                    token_id: id,
                    amount: 100,
                }],
            )],
        });
    }
    // 1,100 wrapped outputs force two spills. The v4 wrap's cached template
    // is the same 08d3 as ordinary v0 trees, exercising merge/interleaving.
    let mut outputs = Vec::new();
    for i in 0..1100 {
        outputs.push(candidate(
            if i % 3 == 0 { "0008d3" } else { "0c0208d3" },
            AdditionalRegisters::empty(),
            vec![],
        ));
    }
    // Captured mainnet h=1,702,686 output tree, inside our undo window.
    outputs.push(candidate("092f0204a00b08cd021dde34603426402615658f1d970cfa7c7bd92ac81a8b16ee20427901040404040004020504040402", AdditionalRegisters::empty(), vec![]));
    let wrapped_tx = Transaction {
        inputs: vec![input(Digest32::from_bytes([99; 32]))],
        data_inputs: vec![],
        output_candidates: outputs,
    };
    let spend = Transaction {
        inputs: [1, 511, 514, 1099, 1100]
            .into_iter()
            .map(|i| input(box_id(&wrapped_tx, i)))
            .collect(),
        data_inputs: vec![],
        output_candidates: vec![candidate("0c0208d3", AdditionalRegisters::empty(), vec![])],
    };
    genesis.push(wrapped_tx);
    let third = Transaction {
        inputs: vec![input(box_id(&spend, 0))],
        data_inputs: vec![],
        output_candidates: vec![candidate("0c0208d3", AdditionalRegisters::empty(), vec![])],
    };
    vec![genesis, vec![spend], vec![third]]
}

fn block(txs: &[Transaction], height: usize) -> IndexerBlock<'_> {
    IndexerBlock {
        height: height as i32,
        header_id: Digest32::from_bytes([height as u8; 32]),
        transactions: txs,
    }
}

fn build(path: &std::path::Path, blocks: &[Vec<Transaction>], legacy: bool) -> IndexerStore {
    let (store, _) = IndexerStore::open(path).unwrap();
    let mut checkpoint = IndexerMeta::empty();
    for (i, txs) in blocks.iter().enumerate() {
        let b = block(txs, i + 1);
        checkpoint = if legacy {
            let write = store.begin_write().unwrap();
            let applied = apply_block_with_derivation(
                &write,
                store.rollback_window(),
                &checkpoint,
                &b,
                &mut BlockApplyScratch::new(),
                old_template,
                old_token,
            )
            .unwrap();
            write.commit().unwrap();
            applied.meta
        } else {
            apply_block(&store, &checkpoint, &b).unwrap()
        };
    }
    if legacy {
        let write = store.begin_write().unwrap();
        meta::write_schema_version(&write, 2).unwrap();
        write.commit().unwrap();
    }
    store
}

type Rows = BTreeMap<String, Vec<(Vec<u8>, Vec<u8>)>>;
fn snapshot(store: &IndexerStore) -> Rows {
    let read = store.db.begin_read().unwrap();
    read.list_tables()
        .unwrap()
        .map(|handle| {
            let name = handle.name().to_owned();
            let rows = match name.as_str() {
                "indexer_meta" => read
                    .open_table(super::super::tables::INDEXER_META)
                    .unwrap()
                    .iter()
                    .unwrap()
                    .map(|r| {
                        let (k, v) = r.unwrap();
                        (k.value().as_bytes().to_vec(), v.value().to_vec())
                    })
                    .collect(),
                "indexer_undo" => read
                    .open_table(INDEXER_UNDO)
                    .unwrap()
                    .iter()
                    .unwrap()
                    .map(|r| {
                        let (k, v) = r.unwrap();
                        (k.value().to_be_bytes().to_vec(), v.value().to_vec())
                    })
                    .collect(),
                "unspent_by_creation_height" => read
                    .open_table(super::super::storage_rent::UNSPENT_BY_CREATION_HEIGHT)
                    .unwrap()
                    .iter()
                    .unwrap()
                    .map(|r| {
                        let (k, v) = r.unwrap();
                        let (height, index) = k.value();
                        (
                            [
                                height.to_be_bytes().as_slice(),
                                index.to_be_bytes().as_slice(),
                            ]
                            .concat(),
                            v.value().to_vec(),
                        )
                    })
                    .collect(),
                _ => read
                    .open_table(TableDefinition::<&[u8], &[u8]>::new(&name))
                    .unwrap()
                    .iter()
                    .unwrap()
                    .map(|r| {
                        let (k, v) = r.unwrap();
                        (k.value().to_vec(), v.value().to_vec())
                    })
                    .collect(),
            };
            (name, rows)
        })
        .collect()
}

#[test]
fn schema_two_migration_matches_every_table() {
    let tmp = tempfile::tempdir().unwrap();
    let blocks = blocks();
    let fresh = build(&tmp.path().join("fresh.redb"), &blocks, false);
    let path = tmp.path().join("legacy.redb");
    let legacy = build(&path, &blocks, true);
    assert_ne!(snapshot(&legacy), snapshot(&fresh));
    drop(legacy);
    let (migrated, outcome) = IndexerStore::open(&path).unwrap();
    assert_eq!(
        outcome,
        OpenOutcome::Migrated {
            previous_version: 2
        }
    );
    assert_eq!(snapshot(&migrated), snapshot(&fresh));
}

#[test]
fn schema_two_rollback_matches_fresh_across_migrated_blocks() {
    let tmp = tempfile::tempdir().unwrap();
    let blocks = blocks();
    let fresh = build(&tmp.path().join("fresh.redb"), &blocks, false);
    let path = tmp.path().join("legacy.redb");
    drop(build(&path, &blocks, true));
    let (migrated, _) = IndexerStore::open(&path).unwrap();
    for i in (0..blocks.len()).rev() {
        let b = block(&blocks[i], i + 1);
        for store in [&migrated, &fresh] {
            crate::rollback::rollback_one_block(store, &store.read_meta().unwrap(), &b).unwrap();
        }
        assert_eq!(
            snapshot(&migrated),
            snapshot(&fresh),
            "rollback height {}",
            i + 1
        );
    }
}

#[test]
fn schema_two_migration_failure_is_atomic_and_open_rebuilds_corruption() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("legacy.redb");
    let store = build(&path, &blocks(), true);
    let before_rows = snapshot(&store);
    let before_bytes = std::fs::read(&path).unwrap();
    let mut writes = 0;
    let result = migrate_observed(&store.db, &mut || {
        writes += 1;
        if writes == 2 {
            Err(invalid("injected failure after metadata writes"))
        } else {
            Ok(())
        }
    });
    assert!(result.is_err());
    assert_eq!(writes, 2);
    assert_eq!(snapshot(&store), before_rows);
    assert_eq!(std::fs::read(&path).unwrap(), before_bytes);
    drop(store);
    let (rebuilt, outcome) = IndexerStore::open_with_migration(&path, 1024 * 1024, |db| {
        migrate_observed(db, &mut || Err(invalid("injected open migration failure")))
    })
    .unwrap();
    assert_eq!(
        outcome,
        OpenOutcome::WipedAndRecreated {
            previous_version: 2
        }
    );
    assert_eq!(rebuilt.read_meta().unwrap(), IndexerMeta::empty());
}

#[test]
fn schema_two_missing_or_undecodable_issuing_box_rebuilds() {
    for missing in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("legacy.redb");
        let store = build(&path, &blocks(), true);
        // Make the migration persistently unserviceable: its issuing
        // box cannot be decoded. Open must rebuild rather than publish schema 3.
        let issuing = store
            .read_token(&Digest32::from_bytes([2; 32]))
            .unwrap()
            .unwrap()
            .creating_box_id
            .unwrap();
        let write = store.begin_write().unwrap();
        {
            let mut boxes = write.open_table(INDEXED_BOX).unwrap();
            if missing {
                boxes.remove(issuing.as_bytes().as_slice()).unwrap();
            } else {
                boxes
                    .insert(issuing.as_bytes().as_slice(), [0xff].as_slice())
                    .unwrap();
            }
        }
        write.commit().unwrap();
        drop(store);
        let (rebuilt, outcome) = IndexerStore::open(&path).unwrap();
        assert_eq!(
            outcome,
            OpenOutcome::WipedAndRecreated {
                previous_version: 2
            }
        );
        assert_eq!(rebuilt.read_meta().unwrap(), IndexerMeta::empty());
    }
}
