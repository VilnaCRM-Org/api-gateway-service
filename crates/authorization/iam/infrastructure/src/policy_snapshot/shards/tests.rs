use iam_domain::{PolicyHead, PolicyState, PolicyVersion};

use super::*;

fn key(number: u32) -> StateKey {
    StateKey::parse(&format!("upstream/service-{number}")).unwrap()
}

fn entry(version: i64) -> Entry {
    Entry {
        version: PolicyVersion::new(version).unwrap(),
        state: PolicyState::Head(PolicyHead {
            version: PolicyVersion::new(version).unwrap(),
            digest: PolicyDigestValue::ZERO,
        }),
        hash: PolicyDigestValue::ZERO,
        derived: Derived::Nothing,
    }
}

#[test]
fn a_write_that_no_snapshot_shares_copies_nothing() {
    let mut shards = Shards::new();
    shards.insert(key(1), entry(1));
    shards.insert(key(1), entry(2));

    assert_eq!(shards.copies(), 0);
    assert_eq!(
        shards.get(&key(1)).map(|entry| entry.version.value()),
        Some(2)
    );
}

#[test]
fn a_shard_shared_with_a_snapshot_is_cloned_once_however_often_it_is_written() {
    let mut shards = Shards::new();
    shards.insert(key(1), entry(1));
    let published = shards.clone();

    shards.insert(key(1), entry(2));
    shards.insert(key(1), entry(3));
    shards.remove(&key(1));

    assert_eq!(shards.take_copies(), 1);
    assert_eq!(shards.take_copies(), 0);
    assert!(shards.get(&key(1)).is_none());
    assert_eq!(
        published.get(&key(1)).map(|entry| entry.version.value()),
        Some(1)
    );
}

#[test]
fn removing_an_absent_key_clones_nothing() {
    let mut shards = Shards::new();
    let _published = shards.clone();

    assert!(shards.remove(&key(9)).is_none());
    assert_eq!(shards.copies(), 0);
}

#[test]
fn it_iterates_over_every_live_entry() {
    let mut shards = Shards::new();
    (0..20).for_each(|number| shards.insert(key(number), entry(1)));

    assert_eq!(shards.iter().count(), 20);
}

#[test]
fn a_key_whose_shard_is_missing_is_not_stored() {
    let mut shards = Shards {
        shards: Vec::new(),
        copies: 0,
    };

    shards.insert(key(1), entry(1));

    assert!(shards.get(&key(1)).is_none());
    assert_eq!(shards.copies(), 0);
}
