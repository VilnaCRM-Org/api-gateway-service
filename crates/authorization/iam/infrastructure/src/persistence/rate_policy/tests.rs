use std::time::{Duration, SystemTime};

use iam_domain::{EntityVersion, RateFallback, RateKeyKind, RepositoryError};
use rstest::rstest;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;

use super::{RatePolicyRow, restore};

const POLICY: &str = "6c3f0d2b-8e4a-4b7c-9d1e-2f3a4b5c6d7e";

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn row() -> RatePolicyRow {
    RatePolicyRow {
        id: SqlUuid::parse_str(POLICY).unwrap(),
        name: "per-ip".to_owned(),
        key_kind: "subject_route".to_owned(),
        request_limit: 100,
        period_seconds: 60,
        burst: 10,
        fallback: "full".to_owned(),
        version: 2,
        created_at: OffsetDateTime::from(at(1_700_000_000)),
        updated_at: OffsetDateTime::from(at(1_700_000_100)),
    }
}

#[test]
fn a_valid_row_is_restored_with_every_column() {
    let parts = restore(row()).unwrap();

    assert_eq!(parts.id.to_string(), POLICY);
    assert_eq!(parts.fields.name(), "per-ip");
    assert_eq!(parts.fields.key_kind(), RateKeyKind::SubjectRoute);
    assert_eq!(parts.fields.limit(), 100);
    assert_eq!(parts.fields.period_seconds(), 60);
    assert_eq!(parts.fields.burst(), 10);
    assert_eq!(parts.fields.fallback(), RateFallback::Full);
    assert_eq!(parts.version, EntityVersion::new(2).unwrap());
    assert_eq!(parts.created_at, at(1_700_000_000));
    assert_eq!(parts.updated_at, at(1_700_000_100));
    assert_eq!(parts.deleted_at, None);
}

#[rstest]
#[case::unknown_key_kind(RatePolicyRow { key_kind: "user".to_owned(), ..row() })]
#[case::unknown_fallback(RatePolicyRow { fallback: "half".to_owned(), ..row() })]
#[case::zero_limit(RatePolicyRow { request_limit: 0, ..row() })]
#[case::version_below_one(RatePolicyRow { version: 0, ..row() })]
fn a_row_that_breaks_an_invariant_is_unavailable(#[case] row: RatePolicyRow) {
    assert!(matches!(restore(row), Err(RepositoryError::Unavailable(_))));
}
