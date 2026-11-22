use proptest::prelude::any;
use rstest::rstest;

use super::PolicyDigestValue;
use crate::error::InvalidIamValue;

#[test]
fn the_length_is_16_bytes() {
    assert_eq!(PolicyDigestValue::LENGTH, 16);
}

#[test]
fn keeps_the_16_bytes_it_was_built_from() {
    let bytes: Vec<u8> = (1..=16).collect();

    let digest = PolicyDigestValue::new(&bytes).unwrap();

    assert_eq!(digest.as_bytes().as_slice(), bytes.as_slice());
}

#[rstest]
#[case(0)]
#[case(15)]
#[case(17)]
#[case(32)]
fn rejects_any_other_length(#[case] length: usize) {
    assert_eq!(
        PolicyDigestValue::new(&vec![0; length]),
        Err(InvalidIamValue::PolicyDigestLength)
    );
}

#[test]
fn digests_of_different_bytes_differ() {
    let zeros = PolicyDigestValue::new(&[0; 16]).unwrap();
    let ones = PolicyDigestValue::new(&[1; 16]).unwrap();

    assert_ne!(zeros, ones);
    assert_eq!(zeros, PolicyDigestValue::new(&[0; 16]).unwrap());
}

proptest::proptest! {
    #[test]
    fn accepts_exactly_16_bytes_and_returns_them(
        bytes in proptest::collection::vec(any::<u8>(), 0..40)
    ) {
        let expected = if bytes.len() == 16 {
            Ok(bytes.clone())
        } else {
            Err(InvalidIamValue::PolicyDigestLength)
        };

        let actual = PolicyDigestValue::new(&bytes).map(|digest| digest.as_bytes().to_vec());

        proptest::prop_assert_eq!(actual, expected);
    }
}
