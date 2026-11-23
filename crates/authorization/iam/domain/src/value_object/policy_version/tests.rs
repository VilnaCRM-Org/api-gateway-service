use proptest::prelude::any;
use rstest::rstest;

use super::PolicyVersion;
use crate::error::InvalidIamValue;

#[rstest]
#[case(0)]
#[case(1)]
#[case(i64::MAX)]
fn accepts_zero_and_every_positive_value(#[case] value: i64) {
    assert_eq!(
        PolicyVersion::new(value).map(PolicyVersion::value),
        Ok(value)
    );
}

#[rstest]
#[case(-1)]
#[case(i64::MIN)]
fn rejects_a_negative_value(#[case] value: i64) {
    assert_eq!(
        PolicyVersion::new(value),
        Err(InvalidIamValue::PolicyVersionNegative)
    );
}

#[test]
fn values_are_ordered_by_their_number() {
    assert!(PolicyVersion::new(1).unwrap() < PolicyVersion::new(2).unwrap());
    assert_eq!(
        PolicyVersion::new(7).unwrap(),
        PolicyVersion::new(7).unwrap()
    );
}

proptest::proptest! {
    #[test]
    fn accepts_exactly_the_non_negative_values_and_returns_them(value in any::<i64>()) {
        let expected = if value < 0 {
            Err(InvalidIamValue::PolicyVersionNegative)
        } else {
            Ok(value)
        };

        proptest::prop_assert_eq!(PolicyVersion::new(value).map(PolicyVersion::value), expected);
    }
}

#[test]
fn zero_is_the_value_zero() {
    assert_eq!(PolicyVersion::ZERO.value(), 0);
    assert_eq!(PolicyVersion::new(0), Ok(PolicyVersion::ZERO));
}
