use std::time::{Duration, SystemTime};

use iam_domain::{BulkKind, BulkStatus, RepositoryError};
use rstest::rstest;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;

use super::{BulkOperationRow, count, records, restore, version};

const OPERATION: &str = "01890a5d-ac96-774b-bcce-b302099a8058";

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn row() -> BulkOperationRow {
    BulkOperationRow {
        id: SqlUuid::parse_str(OPERATION).unwrap(),
        kind: "role_deletion".to_owned(),
        status: "running".to_owned(),
        total_records: 2_500,
        applied_records: 1_000,
        first_version: Some(11),
        last_version: Some(11),
        requester: "system:startup".to_owned(),
        error: None,
        created_at: OffsetDateTime::from(at(1_700_000_000)),
        updated_at: OffsetDateTime::from(at(1_700_000_100)),
    }
}

#[test]
fn a_valid_row_is_restored_with_every_column() {
    let operation = restore(row()).unwrap();

    let parts = operation.parts();
    assert_eq!(parts.id.to_string(), OPERATION);
    assert_eq!(parts.kind, BulkKind::RoleDeletion);
    assert_eq!(parts.status, BulkStatus::Running);
    assert_eq!(parts.total_records, 2_500);
    assert_eq!(parts.applied_records, 1_000);
    assert_eq!(parts.first_version.unwrap().value(), 11);
    assert_eq!(parts.last_version.unwrap().value(), 11);
    assert_eq!(parts.requester.to_string(), "system:startup");
    assert_eq!(parts.created_at, at(1_700_000_000));
    assert_eq!(parts.updated_at, at(1_700_000_100));
}

fn unusable(row: BulkOperationRow) {
    assert!(matches!(
        restore(row).unwrap_err(),
        RepositoryError::Unavailable(_)
    ));
}

#[rstest]
#[case::kind(|row: &mut BulkOperationRow| row.kind = "bulk".to_owned())]
#[case::status(|row: &mut BulkOperationRow| row.status = "done".to_owned())]
#[case::total(|row: &mut BulkOperationRow| row.total_records = -1)]
#[case::applied(|row: &mut BulkOperationRow| row.applied_records = -1)]
#[case::version(|row: &mut BulkOperationRow| row.first_version = Some(-1))]
#[case::requester(|row: &mut BulkOperationRow| row.requester = "nobody".to_owned())]
#[case::progress(|row: &mut BulkOperationRow| row.applied_records = 9_999)]
fn a_row_the_domain_refuses_is_unusable_data(#[case] damage: fn(&mut BulkOperationRow)) {
    let mut broken = row();
    damage(&mut broken);

    unusable(broken);
}

#[test]
fn counts_and_versions_convert_within_their_ranges() {
    assert_eq!(count(7).unwrap(), 7);
    assert!(count(u64::MAX).is_err());
    assert_eq!(records(7).unwrap(), 7);
    assert!(records(-1).is_err());
    assert_eq!(version(None).unwrap(), None);
    assert_eq!(version(Some(3)).unwrap().unwrap().value(), 3);
    assert!(version(Some(-3)).is_err());
}
