use ergo_ser::modifier_id::ExpectedSections;
use ergo_sync::coordinator::SyncCoordinator;
use std::time::Instant;

#[test]
fn applying_blocks_cleans_siblings_but_keeps_future_headers() {
    let peer = ([127, 0, 0, 1], 9030).into();
    let mut coordinator = SyncCoordinator::new(0);
    coordinator.sync_state_mut().mark_headers_chain_synced();
    let now = Instant::now();
    let future = [255; 32];
    coordinator.on_header_validated(
        peer,
        future,
        1001,
        1,
        ExpectedSections::from_header(&future, &[0; 32], &[0; 32], &[0; 32]),
        now,
    );
    for height in 1u32..=1000 {
        let mut main = [0; 32];
        main[..4].copy_from_slice(&height.to_be_bytes());
        let mut side = main;
        side[4] = 1;
        let sections = ExpectedSections::from_header(&side, &[0; 32], &[0; 32], &[0; 32]);
        for id in [main, side] {
            coordinator.on_header_validated(
                peer,
                id,
                height,
                1,
                ExpectedSections::from_header(&id, &[0; 32], &[0; 32], &[0; 32]),
                now,
            );
        }
        coordinator.on_block_applied(main, height);
        assert!(coordinator
            .assembly_mut()
            .identify_section(&sections.transactions_id)
            .is_none());
        assert_eq!(coordinator.assembly_mut().pending_count(), 1);
    }
    // Rollback then re-application must preserve the same cleanup contract.
    coordinator.on_block_applied([0; 32], 999);
    let side = [42; 32];
    coordinator.on_header_validated(
        peer,
        side,
        1000,
        1,
        ExpectedSections::from_header(&side, &[0; 32], &[0; 32], &[0; 32]),
        now,
    );
    coordinator.on_block_applied([1; 32], 1000);
    assert_eq!(coordinator.sync_state().pending_blocks_len(), 1);
    coordinator.on_block_applied(future, 1001);
    assert_eq!(coordinator.assembly_mut().pending_count(), 0);
}
