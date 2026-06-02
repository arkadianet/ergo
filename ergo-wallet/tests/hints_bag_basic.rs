//! HintsBag + TransactionHintsBag basic operations.

use ergo_primitives::group_element::GroupElement;
use ergo_ser::sigma_value::SigmaBoolean;
use ergo_wallet::proving::hints::*;
use ergo_wallet::proving::node_position::NodePosition;

fn dummy_dlog_pk(seed: u8) -> SigmaBoolean {
    let mut pk = [0u8; 33];
    pk[0] = 0x02; // even-y compressed
    pk[1] = seed;
    SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk))
}

fn dummy_own_commitment(seed: u8) -> Hint {
    let mut pt = [0u8; 33];
    pt[0] = 0x02;
    pt[1] = seed;
    Hint::OwnCommitment(OwnCommitment {
        image: dummy_dlog_pk(seed),
        secret_randomness: [seed; 32],
        commitment: FirstProverMessage::Schnorr(pt),
        position: NodePosition::crypto_tree_prefix(),
    })
}

fn dummy_real_commitment(seed: u8) -> Hint {
    let mut pt = [0u8; 33];
    pt[0] = 0x02;
    pt[1] = seed;
    Hint::RealCommitment(RealCommitment {
        image: dummy_dlog_pk(seed),
        commitment: FirstProverMessage::Schnorr(pt),
        position: NodePosition::crypto_tree_prefix(),
    })
}

// ----- happy path -----

#[test]
fn empty_bag_has_no_hints() {
    let b = HintsBag::empty();
    assert!(b.hints.is_empty());
}

#[test]
fn add_hint_appends_to_bag() {
    let mut b = HintsBag::empty();
    b.add(dummy_own_commitment(0x01));
    b.add(dummy_real_commitment(0x02));
    assert_eq!(b.hints.len(), 2);
}

// ----- round-trips -----

#[test]
fn partition_separates_own_commitment_from_public() {
    let mut b = HintsBag::empty();
    b.add(dummy_own_commitment(0x01));
    b.add(dummy_real_commitment(0x02));
    b.add(dummy_own_commitment(0x03));
    let (secret, public) = b.partition();
    assert_eq!(secret.hints.len(), 2, "two OwnCommitments → secret");
    assert_eq!(public.hints.len(), 1, "one RealCommitment → public");
}

#[test]
fn transaction_bag_replace_for_input_partitions() {
    let mut tbag = TransactionHintsBag::empty();
    let mut bag_in_0 = HintsBag::empty();
    bag_in_0.add(dummy_own_commitment(0x01));
    bag_in_0.add(dummy_real_commitment(0x02));
    tbag.replace_for_input(0, bag_in_0);
    assert_eq!(tbag.secret_hints[&0].hints.len(), 1);
    assert_eq!(tbag.public_hints[&0].hints.len(), 1);
}

#[test]
fn all_for_input_merges_secret_and_public() {
    let mut tbag = TransactionHintsBag::empty();
    let mut bag = HintsBag::empty();
    bag.add(dummy_own_commitment(0x01));
    bag.add(dummy_real_commitment(0x02));
    tbag.replace_for_input(5, bag);
    let merged = tbag.all_for_input(5);
    assert_eq!(merged.hints.len(), 2);
}

#[test]
fn add_for_input_preserves_existing() {
    let mut tbag = TransactionHintsBag::empty();
    let mut first = HintsBag::empty();
    first.add(dummy_own_commitment(0x01));
    tbag.add_for_input(0, first);
    let mut second = HintsBag::empty();
    second.add(dummy_real_commitment(0x02));
    tbag.add_for_input(0, second);
    // Total for input 0: 1 secret + 1 public = 2.
    assert_eq!(tbag.all_for_input(0).hints.len(), 2);
}

#[test]
fn empty_transaction_bag_for_unknown_input_is_empty() {
    let tbag = TransactionHintsBag::empty();
    assert!(tbag.all_for_input(99).hints.is_empty());
}

// ----- round-trips -----

#[test]
fn first_prover_message_schnorr_and_dh_tuple_partition_correctly() {
    // Construct Schnorr and DhTuple FirstProverMessage variants,
    // add them to a bag, and verify partition puts OwnCommitment in secret.
    let schnorr_pt = {
        let mut p = [0u8; 33];
        p[0] = 0x02;
        p[1] = 0xAA;
        p
    };
    let dht_a = {
        let mut p = [0u8; 33];
        p[0] = 0x02;
        p[1] = 0xBB;
        p
    };
    let dht_b = {
        let mut p = [0u8; 33];
        p[0] = 0x03;
        p[1] = 0xCC;
        p
    };

    let own_schnorr = Hint::OwnCommitment(OwnCommitment {
        image: dummy_dlog_pk(0xAA),
        secret_randomness: [0xAA; 32],
        commitment: FirstProverMessage::Schnorr(schnorr_pt),
        position: NodePosition::crypto_tree_prefix(),
    });
    let own_dht = Hint::OwnCommitment(OwnCommitment {
        image: dummy_dlog_pk(0xBB),
        secret_randomness: [0xBB; 32],
        commitment: FirstProverMessage::DhTuple { a: dht_a, b: dht_b },
        position: NodePosition {
            positions: vec![1, 0],
        },
    });
    let real_cmt = Hint::RealCommitment(RealCommitment {
        image: dummy_dlog_pk(0xCC),
        commitment: FirstProverMessage::Schnorr(schnorr_pt),
        position: NodePosition::crypto_tree_prefix(),
    });

    let mut bag = HintsBag::empty();
    bag.add(own_schnorr);
    bag.add(own_dht);
    bag.add(real_cmt);

    let (secret, public) = bag.partition();
    assert_eq!(
        secret.hints.len(),
        2,
        "both OwnCommitments go to secret bucket"
    );
    assert_eq!(
        public.hints.len(),
        1,
        "RealCommitment goes to public bucket"
    );
    assert!(
        matches!(&secret.hints[0], Hint::OwnCommitment(o) if matches!(o.commitment, FirstProverMessage::Schnorr(_))),
        "first secret is Schnorr OwnCommitment"
    );
    assert!(
        matches!(&secret.hints[1], Hint::OwnCommitment(o) if matches!(o.commitment, FirstProverMessage::DhTuple { .. })),
        "second secret is DhTuple OwnCommitment"
    );
}
