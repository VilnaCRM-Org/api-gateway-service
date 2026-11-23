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

#[test]
fn combining_is_the_exclusive_or_with_zero_as_identity() {
    let left = PolicyDigestValue::new(&[0b1010; 16]).unwrap();
    let right = PolicyDigestValue::new(&[0b0110; 16]).unwrap();

    assert_eq!(left.combined(right).as_bytes(), &[0b1100; 16]);
    assert_eq!(left.combined(PolicyDigestValue::ZERO), left);
    assert_eq!(left.combined(left), PolicyDigestValue::ZERO);
    assert_eq!(left.combined(right), right.combined(left));
}

#[test]
fn the_hexadecimal_form_round_trips() {
    let bytes: Vec<u8> = (0..16).map(|index| index * 17).collect();
    let digest = PolicyDigestValue::new(&bytes).unwrap();

    assert_eq!(digest.to_hex(), "00112233445566778899aabbccddeeff");
    assert_eq!(PolicyDigestValue::from_hex(&digest.to_hex()), Ok(digest));
    assert_eq!(
        PolicyDigestValue::from_bytes([0xab; 16]).to_hex(),
        "ab".repeat(16)
    );
}

#[rstest]
#[case::short("00")]
#[case::long(&"0".repeat(34))]
#[case::upper_case(&"AB".repeat(16))]
#[case::not_hexadecimal(&"zz".repeat(16))]
#[case::plus_sign(&"+f".repeat(16))]
fn a_text_that_is_not_32_lower_case_hexadecimal_characters_is_refused(#[case] text: &str) {
    assert_eq!(
        PolicyDigestValue::from_hex(text),
        Err(InvalidIamValue::PolicyDigestLength)
    );
}
