use std::error::Error as _;

use rstest::rstest;

use super::*;

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

#[test]
fn a_valid_row_is_restored_with_both_columns() {
    let locked = restore(&EpochRow {
        version: 3,
        log_epoch: 5,
    })
    .unwrap();

    assert_eq!(locked.version, version(3));
    assert_eq!(locked.log_epoch.value(), 5);
}

#[rstest]
#[case::negative_version(EpochRow { version: -1, log_epoch: 0 })]
#[case::negative_log_epoch(EpochRow { version: 0, log_epoch: -1 })]
fn a_row_that_breaks_an_invariant_is_unavailable(#[case] row: EpochRow) {
    let error = restore(&row).err().unwrap();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert_eq!(
        error.source().unwrap().to_string(),
        "This value must be 0 or greater."
    );
}

#[test]
fn statements_that_hold_pass_and_one_that_does_not_is_a_conflict() {
    let holds = ChangeStatement::ExpectPolicyVersion(version(4));
    let stale = ChangeStatement::ExpectPolicyVersion(version(3));

    assert!(check(&[], version(4)).is_ok());
    assert!(check(std::slice::from_ref(&holds), version(4)).is_ok());
    assert!(matches!(
        check(&[holds, stale], version(4)),
        Err(RepositoryError::Conflict)
    ));
}

#[test]
fn a_time_in_microseconds_becomes_a_timestamp_until_the_year_9999() {
    let stored = timestamp(1_700_000_000_123_456).unwrap();
    let error = timestamp(253_402_300_800_000_000).err().unwrap();

    assert_eq!(stored.unix_timestamp(), 1_700_000_000);
    assert_eq!(stored.microsecond(), 123_456);
    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert_eq!(
        error.source().unwrap().to_string(),
        InvalidIamValue::AuditTimestamp.to_string()
    );
}

#[test]
fn an_event_that_cannot_be_encoded_is_unavailable_with_its_cause() {
    let error = unencodable(InvalidEventEnvelope::TooLarge);

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert_eq!(
        error.source().unwrap().to_string(),
        "The encoded event must be at most 65536 bytes."
    );
}

#[test]
fn a_missing_row_is_unavailable() {
    let error = translate(sqlx::Error::RowNotFound);

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[test]
fn the_events_topic_is_iam_events_v1() {
    assert_eq!(EVENTS_TOPIC, "iam.events.v1");
}
