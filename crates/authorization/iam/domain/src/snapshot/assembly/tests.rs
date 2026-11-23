use proptest::collection::vec;
use proptest::prelude::*;

use super::*;

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

fn digest(byte: u8) -> PolicyDigestValue {
    PolicyDigestValue::from_bytes([byte; PolicyDigestValue::LENGTH])
}

fn record(version_number: i64, seq: u32, count: u32) -> VersionedRecord {
    VersionedRecord {
        key: StateKey::GlobalRevocation,
        payload: Some(format!("payload {seq}")),
        version: version(version_number),
        seq,
        count,
        digest_after: digest(u8::try_from(seq).unwrap()),
        log_epoch: LogEpoch::new(1).unwrap(),
        relay_epoch: RelayEpoch::new(1).unwrap(),
    }
}

#[test]
fn a_version_is_incomplete_until_all_its_records_are_present() {
    let mut assembly = VersionAssembly::new(version(1));
    assert_eq!(
        assembly.completeness(),
        Completeness::Incomplete { missing: None }
    );

    assert_eq!(assembly.offer(record(1, 2, 3)), Offer::Added);
    assert_eq!(
        assembly.completeness(),
        Completeness::Incomplete { missing: Some(2) }
    );
    assert_eq!(assembly.offer(record(1, 1, 3)), Offer::Added);
    assert_eq!(assembly.offer(record(1, 3, 3)), Offer::Added);

    assert_eq!(assembly.completeness(), Completeness::Complete);
    assert_eq!(assembly.last().map(|last| last.seq), Some(3));
}

#[test]
fn a_duplicate_is_dropped_and_a_takeover_with_a_higher_relay_epoch_is_a_duplicate() {
    let mut assembly = VersionAssembly::new(version(1));
    assembly.offer(record(1, 1, 2));
    let mut again = record(1, 1, 2);
    again.relay_epoch = RelayEpoch::new(2).unwrap();

    assert_eq!(assembly.offer(again), Offer::Duplicate);
    assert_eq!(assembly.records().len(), 1);
}

#[test]
fn a_record_of_the_same_position_with_other_content_conflicts() {
    let mut assembly = VersionAssembly::new(version(1));
    assembly.offer(record(1, 1, 2));
    let mut other = record(1, 1, 2);
    other.digest_after = digest(99);

    assert_eq!(assembly.offer(other), Offer::Conflicting);
}

#[test]
fn records_of_another_version_or_with_invalid_framing_are_foreign() {
    let mut assembly = VersionAssembly::new(version(1));

    assert_eq!(assembly.offer(record(2, 1, 1)), Offer::Foreign);
    assert_eq!(assembly.offer(record(1, 0, 2)), Offer::Foreign);
    assert_eq!(assembly.offer(record(1, 3, 2)), Offer::Foreign);
    assert_eq!(assembly.offer(record(1, 1, 2)), Offer::Added);
    assert_eq!(assembly.offer(record(1, 2, 3)), Offer::Foreign);
}

#[test]
fn it_reports_the_highest_epochs_it_saw() {
    let mut assembly = VersionAssembly::new(version(1));
    let mut first = record(1, 1, 2);
    first.relay_epoch = RelayEpoch::new(3).unwrap();
    assembly.offer(first);
    assembly.offer(record(1, 2, 2));

    assert_eq!(assembly.relay_epoch(), Some(RelayEpoch::new(3).unwrap()));
    assert_eq!(assembly.log_epoch(), Some(LogEpoch::new(1).unwrap()));
    assert_eq!(assembly.version(), version(1));
}

/// The position, from 1, that an arbitrary index takes among `count` records.
fn seq_of(index: u32, count: u32) -> u32 {
    index.checked_rem(count).unwrap().checked_add(1).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn the_outcome_does_not_depend_on_the_order_within_a_version(
        count in 1_u32..12,
        order in Just((0_u32..24).collect::<Vec<_>>()).prop_shuffle(),
        repeats in vec(0_u32..12, 0..8),
        held in 0_u32..12,
    ) {
        let held = held.min(count);
        let wanted: Vec<u32> = order
            .iter()
            .map(|index| seq_of(*index, count))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .filter(|seq| *seq <= held)
            .collect();
        let mut shuffled: Vec<u32> = order.iter().map(|index| seq_of(*index, count)).filter(|seq| *seq <= held).collect();
        shuffled.extend(repeats.iter().map(|index| seq_of(*index, count)).filter(|seq| *seq <= held));
        let mut sorted = shuffled.clone();
        sorted.sort_unstable();

        let mut random_order = VersionAssembly::new(version(1));
        for seq in &shuffled {
            random_order.offer(record(1, *seq, count));
        }
        let mut sorted_order = VersionAssembly::new(version(1));
        for seq in &sorted {
            sorted_order.offer(record(1, *seq, count));
        }

        let seqs = |assembly: &VersionAssembly| assembly.records().iter().map(|r| r.seq).collect::<Vec<_>>();
        prop_assert_eq!(seqs(&random_order), seqs(&sorted_order));
        prop_assert_eq!(random_order.completeness(), sorted_order.completeness());
        let complete = wanted.len() == usize::try_from(count).unwrap();
        prop_assert_eq!(seqs(&random_order), wanted);
        prop_assert_eq!(random_order.completeness() == Completeness::Complete, complete);
    }
}
