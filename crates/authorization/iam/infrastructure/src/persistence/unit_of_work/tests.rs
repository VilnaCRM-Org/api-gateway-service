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

#[test]
fn the_window_starts_24_hours_before_the_creation_time() {
    assert_eq!(
        window_start(timestamp(1_800_000_000_000_000).unwrap()),
        timestamp(1_799_913_600_000_000).unwrap()
    );
}

#[test]
fn no_affected_row_is_a_duplicate_key() {
    assert!(matches!(
        inserted_or_replaced(0),
        Err(RepositoryError::AlreadyExists)
    ));
}

#[test]
fn one_affected_row_is_a_written_key() {
    assert!(inserted_or_replaced(1).is_ok());
}

#[test]
fn the_window_starts_at_the_unix_epoch_within_24_hours_of_it() {
    assert_eq!(
        window_start(timestamp(3_600_000_000).unwrap()),
        OffsetDateTime::UNIX_EPOCH
    );
}

#[test]
fn a_key_row_expires_records_created_24_hours_before_it() {
    let change = test_support::unit_of_work::iam_change(
        &mut test_support::seed::TestRng::from_seed(11),
        iam_domain::DecisionEffect::Affected,
        0,
    );
    let record = change.idempotency_record().unwrap();
    let created_at = timestamp(1_800_000_000_000_000).unwrap();

    let row = KeyRow::of(&record, created_at);

    assert_eq!(row.created_at, created_at);
    assert_eq!(
        row.expired_before,
        timestamp(1_799_913_600_000_000).unwrap()
    );
    assert_eq!(row.actor, record.actor().to_string());
    assert_eq!(row.key, record.key().as_str());
    assert_eq!(
        row.request_digest,
        record.request_digest().as_bytes().to_vec()
    );
    assert_eq!(row.change_id, record.change_id().as_uuid().as_uuid());
}
