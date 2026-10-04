use super::*;
use std::time::Instant;

// ----- helpers -----

fn id(byte: u8) -> TxId {
    TxId::from_bytes([byte; 32])
}

fn pool() -> Mempool {
    Mempool::new(MempoolConfig::default(), Box::new(crate::ByCost))
}

// ----- happy path -----

#[test]
fn failed_tx_invalidate_pooled_parent_removes_family_and_revokes_broadcast() {
    let mut pool = pool();
    for byte in 1..=3 {
        pool.pool_mut()
            .insert(Entry::new(
                id(byte),
                vec![byte].into(),
                vec![],
                vec![id(byte + 10)],
                if byte == 2 { vec![id(1)] } else { vec![] },
                1,
                1,
                1,
                1,
                TxSource::Api,
            ))
            .unwrap();
    }
    let revision = pool.revision();
    let actions = pool.invalidate(id(1), Instant::now());
    assert!(!pool.contains(&id(1)));
    assert!(!pool.contains(&id(2)));
    assert!(pool.contains(&id(3)));
    assert!(pool.is_invalidated(&id(1)));
    assert!(!pool.is_invalidated(&id(2)));
    assert!(pool.revision() > revision);
    assert!(actions.iter().any(|action| matches!(action, MempoolAction::RevokeBroadcast { tx_ids } if tx_ids.contains(&id(1)) && tx_ids.contains(&id(2)))));
}

// ----- round-trips -----

// ----- error paths -----

#[test]
fn failed_tx_invalidate_absent_transaction_leaves_cache_and_revision_unchanged() {
    let mut pool = pool();
    let revision = pool.revision();
    assert!(pool.invalidate(id(1), Instant::now()).is_empty());
    assert!(!pool.is_invalidated(&id(1)));
    assert_eq!(pool.revision(), revision);
}

// ----- oracle parity -----
