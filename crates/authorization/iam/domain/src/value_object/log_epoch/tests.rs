use proptest::prelude::any;
use rstest::rstest;

use super::LogEpoch;
use crate::error::InvalidIamValue;

#[rstest]
#[case(0)]
#[case(1)]
#[case(i64::MAX)]
fn accepts_zero_and_every_positive_value(#[case] value: i64) {
    assert_eq!(LogEpoch::new(value).map(LogEpoch::value), Ok(value));
}

#[rstest]
#[case(-1)]
#[case(i64::MIN)]
fn rejects_a_negative_value(#[case] value: i64) {
    assert_eq!(LogEpoch::new(value), Err(InvalidIamValue::LogEpochNegative));
}

#[test]
fn values_are_ordered_by_their_number() {
    assert!(LogEpoch::new(1).unwrap() < LogEpoch::new(2).unwrap());
    assert_eq!(LogEpoch::new(7).unwrap(), LogEpoch::new(7).unwrap());
}

proptest::proptest! {
    #[test]
    fn accepts_exactly_the_non_negative_values_and_returns_them(value in any::<i64>()) {
        let expected = if value < 0 {
            Err(InvalidIamValue::LogEpochNegative)
        } else {
            Ok(value)
        };

        proptest::prop_assert_eq!(LogEpoch::new(value).map(LogEpoch::value), expected);
    }
}

#[test]
fn zero_is_the_value_zero() {
    assert_eq!(LogEpoch::ZERO.value(), 0);
    assert_eq!(LogEpoch::new(0), Ok(LogEpoch::ZERO));
}
