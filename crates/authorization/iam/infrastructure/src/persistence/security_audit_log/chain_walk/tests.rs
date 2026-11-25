use iam_domain::{
    AuditChainHead, AuditHash, ChainBreak, ChainBreakCause, ChainVerification, SecurityAuditEventId,
};

use super::{ChainWalk, Link};

const ID: &str = "0190f2a8-7b3c-7d4e-8f00-000000000001";

fn id() -> SecurityAuditEventId {
    SecurityAuditEventId::parse(ID).unwrap()
}

fn hash(byte: u8) -> Vec<u8> {
    vec![byte; AuditHash::LENGTH]
}

fn anchor(seq: i64, byte: u8) -> AuditChainHead {
    AuditChainHead::new(seq, AuditHash::new(&hash(byte)).unwrap()).unwrap()
}

/// A record whose digest agrees with its hash.
fn link<'a>(seq: i64, prev: &'a [u8], own: &'a [u8]) -> Link<'a> {
    Link {
        seq,
        id: id(),
        prev_hash: prev,
        hash: own,
        digest: Some(own),
    }
}

#[test]
fn an_empty_chain_is_valid_with_no_record_checked() {
    let walk = ChainWalk::new(&[]);

    assert_eq!(walk.finish(), ChainVerification::valid(0));
}

#[test]
fn records_that_link_and_digest_correctly_are_valid() {
    let genesis = hash(0);
    let (one, two) = (hash(1), hash(2));
    let mut walk = ChainWalk::new(&[]);

    assert_eq!(walk.step(&link(1, &genesis, &one)), None);
    assert_eq!(walk.last_seq(), 1);
    assert_eq!(walk.step(&link(2, &one, &two)), None);

    assert_eq!(walk.last_seq(), 2);
    assert_eq!(walk.finish(), ChainVerification::valid(2));
}

#[test]
fn a_record_whose_digest_differs_from_its_hash_breaks_the_chain_at_that_record() {
    let genesis = hash(0);
    let (one, other) = (hash(1), hash(9));
    let mut walk = ChainWalk::new(&[]);
    let altered = Link {
        digest: Some(&other),
        ..link(1, &genesis, &one)
    };

    let broken = walk.step(&altered).unwrap();

    assert_eq!(
        broken,
        ChainBreak::new(1, Some(id()), ChainBreakCause::Digest)
    );
    assert_eq!(walk.broken(broken), ChainVerification::invalid(1, broken));
}

#[test]
fn a_record_that_does_not_follow_the_previous_hash_breaks_the_link() {
    let (one, two, stray) = (hash(1), hash(2), hash(7));
    let genesis = hash(0);
    let mut walk = ChainWalk::new(&[]);
    walk.step(&link(1, &genesis, &one));

    let broken = walk.step(&link(2, &stray, &two)).unwrap();

    assert_eq!(broken.cause(), ChainBreakCause::Link);
    assert_eq!(broken.seq(), 2);
}

#[test]
fn a_missing_sequence_number_is_a_gap() {
    let genesis = hash(0);
    let one = hash(1);
    let mut walk = ChainWalk::new(&[]);

    let broken = walk.step(&link(2, &genesis, &one)).unwrap();

    assert_eq!(broken.cause(), ChainBreakCause::Gap);
}

#[test]
fn a_record_that_cannot_be_read_back_is_unreadable() {
    let genesis = hash(0);
    let one = hash(1);
    let mut walk = ChainWalk::new(&[]);

    let broken = walk
        .step(&Link {
            digest: None,
            ..link(1, &genesis, &one)
        })
        .unwrap();

    assert_eq!(broken.cause(), ChainBreakCause::Unreadable);
}

#[test]
fn a_rewritten_chain_fails_at_the_anchored_record_although_every_digest_holds() {
    let genesis = hash(0);
    let (one, two) = (hash(1), hash(2));
    let anchors = [anchor(2, 5)];
    let mut walk = ChainWalk::new(&anchors);
    assert_eq!(walk.step(&link(1, &genesis, &one)), None);

    let broken = walk.step(&link(2, &one, &two)).unwrap();

    assert_eq!(
        broken,
        ChainBreak::new(2, Some(id()), ChainBreakCause::Anchor)
    );
}

#[test]
fn a_matching_anchor_keeps_the_chain_valid() {
    let genesis = hash(0);
    let one = hash(1);
    let anchors = [anchor(1, 1)];
    let mut walk = ChainWalk::new(&anchors);

    assert_eq!(walk.step(&link(1, &genesis, &one)), None);

    assert_eq!(walk.finish(), ChainVerification::valid(1));
}

#[test]
fn the_nearest_anchor_beyond_the_chain_means_records_were_removed() {
    let genesis = hash(0);
    let one = hash(1);
    let anchors = [anchor(9, 3), anchor(4, 3), anchor(1, 1)];
    let mut walk = ChainWalk::new(&anchors);
    walk.step(&link(1, &genesis, &one));

    assert_eq!(
        walk.finish(),
        ChainVerification::invalid(1, ChainBreak::new(4, None, ChainBreakCause::AnchorMissing))
    );
}
