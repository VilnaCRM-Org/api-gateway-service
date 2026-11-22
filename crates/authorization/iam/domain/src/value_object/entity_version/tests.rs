use proptest::prelude::any;
use rstest::rstest;

use super::EntityVersion;
use crate::error::{InvalidIamValue, VersionConflict};

fn version(value: i64) -> EntityVersion {
    EntityVersion::new(value).unwrap()
}

#[rstest]
#[case(1)]
#[case(2)]
#[case(i64::MAX)]
fn accepts_every_positive_value(#[case] value: i64) {
    assert_eq!(
        EntityVersion::new(value).map(EntityVersion::value),
        Ok(value)
    );
}

#[rstest]
#[case(0)]
#[case(-1)]
#[case(i64::MIN)]
fn rejects_zero_and_negative_values(#[case] value: i64) {
    assert_eq!(
        EntityVersion::new(value),
        Err(InvalidIamValue::EntityVersionRange)
    );
}

#[test]
fn starts_at_one_and_counts_up() {
    assert_eq!(EntityVersion::INITIAL.value(), 1);
    assert_eq!(EntityVersion::INITIAL.next(), Ok(version(2)));
    assert_eq!(version(41).next(), Ok(version(42)));
}

#[test]
fn refuses_to_count_past_the_largest_version() {
    assert_eq!(
        version(i64::MAX).next(),
        Err(InvalidIamValue::EntityVersionRange)
    );
}

#[test]
fn an_equal_expected_version_passes() {
    assert_eq!(version(3).check(Some(version(3))), Ok(()));
}

#[test]
fn a_missing_expected_version_is_a_missing_conflict() {
    assert_eq!(version(3).check(None), Err(VersionConflict::Missing));
}

#[rstest]
#[case(2)]
#[case(4)]
fn a_different_expected_version_is_a_stale_conflict(#[case] expected: i64) {
    assert_eq!(
        version(3).check(Some(version(expected))),
        Err(VersionConflict::Stale {
            expected: version(expected),
            current: version(3),
        })
    );
}

#[test]
fn versions_are_ordered_by_their_number() {
    assert!(version(1) < version(2));
}

proptest::proptest! {
    #[test]
    fn accepts_exactly_the_positive_values(value in any::<i64>()) {
        let expected = if value >= 1 {
            Ok(value)
        } else {
            Err(InvalidIamValue::EntityVersionRange)
        };

        proptest::prop_assert_eq!(EntityVersion::new(value).map(EntityVersion::value), expected);
    }

    #[test]
    fn passes_only_the_current_version(current in 1..=i64::MAX, expected in 1..=i64::MAX) {
        let result = version(current).check(Some(version(expected)));

        proptest::prop_assert_eq!(result.is_ok(), current == expected);
    }
}
