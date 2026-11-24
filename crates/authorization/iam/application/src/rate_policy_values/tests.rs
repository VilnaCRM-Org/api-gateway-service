use std::time::{Duration, SystemTime};

use iam_domain::{EntityVersion, RateFallback, RateKeyKind, RatePolicyId, RatePolicyParts};

use super::{RatePolicyPatch, RatePolicyValues, period_ms_of, summary_of};
use crate::error::IamError;

const POLICY: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ae";

fn values() -> RatePolicyValues {
    RatePolicyValues {
        name: "per-subject".to_owned(),
        key_kind: RateKeyKind::SubjectRoute,
        limit: 100,
        period_ms: 60_000,
        burst: 20,
        fallback: RateFallback::Divided,
    }
}

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn violations_of(error: IamError) -> Vec<(String, String)> {
    let IamError::Invalid(violations) = error else {
        panic!("violations expected: {error:?}");
    };
    violations
        .into_iter()
        .map(|violation| (violation.property_path, violation.code))
        .collect()
}

#[test]
fn valid_values_become_fields_with_the_period_in_whole_seconds() {
    let fields = values().into_fields().unwrap();

    assert_eq!(fields.name(), "per-subject");
    assert_eq!(fields.key_kind(), RateKeyKind::SubjectRoute);
    assert_eq!(fields.limit(), 100);
    assert_eq!(fields.period_seconds(), 60);
    assert_eq!(fields.burst(), 20);
    assert_eq!(fields.fallback(), RateFallback::Divided);
    assert_eq!(period_ms_of(&fields), 60_000);
    assert_eq!(RatePolicyValues::of(&fields), values());
}

#[test]
fn every_violation_is_reported_in_order_with_the_period_under_its_request_name() {
    let invalid = RatePolicyValues {
        name: String::new(),
        limit: 0,
        period_ms: 1_500,
        burst: -1,
        ..values()
    };

    let found = violations_of(invalid.into_fields().unwrap_err());

    assert_eq!(
        found,
        [
            ("name".to_owned(), "length".to_owned()),
            ("limit".to_owned(), "range".to_owned()),
            ("periodMs".to_owned(), "range".to_owned()),
            ("burst".to_owned(), "range".to_owned()),
        ]
    );
}

#[test]
fn a_period_that_is_zero_negative_or_too_long_is_refused() {
    for period_ms in [0, -1_000, 4_294_967_296_000] {
        let invalid = RatePolicyValues {
            period_ms,
            ..values()
        };

        let found = violations_of(invalid.into_fields().unwrap_err());

        assert_eq!(found, [("periodMs".to_owned(), "range".to_owned())]);
    }
}

#[test]
fn a_patch_changes_only_the_members_it_names() {
    let current = values().into_fields().unwrap();
    let patch = RatePolicyPatch {
        limit: Some(200),
        fallback: Some(RateFallback::Full),
        ..RatePolicyPatch::default()
    };

    let applied = patch.applied_to(&current);

    assert_eq!(
        applied,
        RatePolicyValues {
            limit: 200,
            fallback: RateFallback::Full,
            ..values()
        }
    );
    assert_eq!(
        RatePolicyPatch::default().applied_to(&current),
        values(),
        "an empty patch keeps every member"
    );
}

#[test]
fn the_summary_keeps_the_configuration_without_the_name() {
    let parts = RatePolicyParts {
        id: RatePolicyId::parse(POLICY).unwrap(),
        fields: values().into_fields().unwrap(),
        version: EntityVersion::new(3).unwrap(),
        created_at: at(),
        updated_at: at(),
        deleted_at: None,
    };

    assert_eq!(
        summary_of(&parts),
        "key=subject_route limit=100 periodMs=60000 burst=20 fallback=divided version=3"
    );
}
