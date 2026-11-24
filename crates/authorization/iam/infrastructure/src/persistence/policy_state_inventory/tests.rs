use iam_domain::{InvalidIamValue, RepositoryError};

use super::{parameter, subject_kind, unusable};

#[test]
fn a_known_subject_kind_keeps_its_stored_text() {
    assert_eq!(subject_kind("user").unwrap(), "user");
    assert_eq!(subject_kind("service").unwrap(), "service");
}

#[test]
fn an_unknown_subject_kind_is_unusable_data() {
    let error = subject_kind("robot").unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[test]
fn a_stored_value_that_breaks_an_invariant_is_an_unavailable_repository() {
    let error = unusable(InvalidIamValue::SubjectKind);

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[test]
fn an_offset_beyond_the_signed_range_is_cut_to_the_largest_number() {
    assert_eq!(parameter(7), 7);
    assert_eq!(parameter(u64::MAX), i64::MAX);
}
