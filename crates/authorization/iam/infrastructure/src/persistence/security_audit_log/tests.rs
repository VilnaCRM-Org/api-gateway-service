use std::error::Error as _;

use rstest::rstest;
use test_support::log::LogRecorder;

use super::*;

const ID: &str = "0190f2a8-7b3c-7d4e-8f00-000000000001";
const USER: &str = "0190f2a8-7b3c-7d4e-8f00-123456789abc";
const PROJECT: &str = "0190f2a8-7b3c-7d4e-8f00-00000000000f";
const MICROS: i64 = 1_700_000_000_123_456;

fn row() -> Row {
    Row {
        seq: 3,
        id: SqlUuid::parse_str(ID).unwrap(),
        occurred_at_micros: MICROS,
        actor: format!("user:{USER}"),
        caller_service: Some("core".to_owned()),
        action: "role.create".to_owned(),
        target_type: "role".to_owned(),
        target_id: "r-1".to_owned(),
        scope: Some(format!("project:{PROJECT}")),
        before_summary: Some("name=readers".to_owned()),
        after_summary: Some("name=writers".to_owned()),
        idempotency_key: Some("key-1".to_owned()),
        outcome: "committed".to_owned(),
        reason: Some("forbidden".to_owned()),
        policy_version: Some(42),
        request_id: Some("req-9".to_owned()),
        prev_hash: vec![1; 32],
        hash: vec![2; 32],
    }
}

fn sparse_row() -> Row {
    Row {
        caller_service: None,
        scope: None,
        before_summary: None,
        after_summary: None,
        idempotency_key: None,
        outcome: "rejected".to_owned(),
        reason: None,
        policy_version: None,
        request_id: None,
        ..row()
    }
}

#[test]
fn a_valid_row_is_restored_with_every_column() {
    let stored = restore(&row()).unwrap();
    let parts = stored.event().parts();

    assert_eq!(stored.seq(), 3);
    assert_eq!(stored.prev_hash().as_bytes(), &[1; 32]);
    assert_eq!(stored.hash().as_bytes(), &[2; 32]);
    assert_eq!(stored.event().occurred_at_micros(), MICROS);
    assert_eq!(parts.id.to_string(), ID);
    assert_eq!(parts.actor.to_string(), format!("user:{USER}"));
    assert_eq!(parts.caller_service.as_ref().unwrap().as_str(), "core");
    assert_eq!(parts.action.as_str(), "role.create");
    assert_eq!(parts.target.target_type(), "role");
    assert_eq!(parts.target.target_id(), "r-1");
    assert_eq!(
        parts.scope.unwrap().to_string(),
        format!("project:{PROJECT}")
    );
    assert_eq!(parts.before.as_ref().unwrap().as_str(), "name=readers");
    assert_eq!(parts.after.as_ref().unwrap().as_str(), "name=writers");
    assert_eq!(parts.idempotency_key.as_ref().unwrap().as_str(), "key-1");
    assert_eq!(parts.outcome, AuditOutcome::Committed);
    assert_eq!(parts.reason.as_ref().unwrap().as_str(), "forbidden");
    assert_eq!(parts.policy_version.unwrap().value(), 42);
    assert_eq!(parts.request_id.as_ref().unwrap().as_str(), "req-9");
}

#[test]
fn a_row_without_optional_values_is_restored_without_them() {
    let stored = restore(&sparse_row()).unwrap();
    let parts = stored.event().parts();

    assert_eq!(parts.caller_service, None);
    assert_eq!(parts.scope, None);
    assert_eq!(parts.before, None);
    assert_eq!(parts.after, None);
    assert_eq!(parts.idempotency_key, None);
    assert_eq!(parts.outcome, AuditOutcome::Rejected);
    assert_eq!(parts.reason, None);
    assert_eq!(parts.policy_version, None);
    assert_eq!(parts.request_id, None);
}

#[rstest]
#[case::actor(Row { actor: "nobody".to_owned(), ..row() }, InvalidIamValue::ActorFormat)]
#[case::caller(Row { caller_service: Some("Core".to_owned()), ..row() }, InvalidIamValue::ServiceNamePattern)]
#[case::action(Row { action: "create".to_owned(), ..row() }, InvalidIamValue::AuditActionFormat)]
#[case::target_type(Row { target_type: "Role".to_owned(), ..row() }, InvalidIamValue::AuditTargetType)]
#[case::target_id(Row { target_id: String::new(), ..row() }, InvalidIamValue::AuditTargetId)]
#[case::scope(Row { scope: Some("tenant".to_owned()), ..row() }, InvalidIamValue::ScopeKind)]
#[case::before(Row { before_summary: Some(String::new()), ..row() }, InvalidIamValue::AuditSummaryFormat)]
#[case::after(Row { after_summary: Some("a\nb".to_owned()), ..row() }, InvalidIamValue::AuditSummaryFormat)]
#[case::idempotency_key(Row { idempotency_key: Some(String::new()), ..row() }, InvalidIamValue::IdempotencyKeyFormat)]
#[case::outcome(Row { outcome: "maybe".to_owned(), ..row() }, InvalidIamValue::AuditOutcome)]
#[case::reason(Row { reason: Some("Forbidden".to_owned()), ..row() }, InvalidIamValue::AuditReasonFormat)]
#[case::policy_version(Row { policy_version: Some(-1), ..row() }, InvalidIamValue::PolicyVersionNegative)]
#[case::request_id(Row { request_id: Some(String::new()), ..row() }, InvalidIamValue::RequestIdFormat)]
#[case::occurred_at(Row { occurred_at_micros: -1, ..row() }, InvalidIamValue::AuditTimestamp)]
#[case::prev_hash(Row { prev_hash: vec![1; 31], ..row() }, InvalidIamValue::AuditHashLength)]
#[case::hash(Row { hash: vec![2; 33], ..row() }, InvalidIamValue::AuditHashLength)]
#[case::seq(Row { seq: 0, ..row() }, InvalidIamValue::AuditSequence)]
fn a_row_that_breaks_a_domain_invariant_is_unavailable(
    #[case] row: Row,
    #[case] cause: InvalidIamValue,
) {
    let error = restore(&row).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert_eq!(error.source().unwrap().to_string(), cause.to_string());
}

#[test]
fn a_valid_head_row_is_restored() {
    let head = restore_head(&HeadRow {
        seq: 7,
        hash: vec![9; 32],
    })
    .unwrap();

    assert_eq!(head.seq(), 7);
    assert_eq!(head.hash().as_bytes(), &[9; 32]);
}

#[rstest]
#[case(HeadRow { seq: -1, hash: vec![0; 32] })]
#[case(HeadRow { seq: 0, hash: vec![0; 16] })]
fn a_head_row_that_breaks_an_invariant_is_unavailable(#[case] row: HeadRow) {
    let error = restore_head(&row).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[test]
fn a_missing_row_is_not_found() {
    assert!(matches!(
        translate(sqlx::Error::RowNotFound),
        RepositoryError::NotFound
    ));
}

#[test]
fn any_other_database_error_is_unavailable() {
    let error = translate(sqlx::Error::PoolTimedOut);

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert!(error.source().is_some());
}

#[test]
fn every_error_of_a_read_is_unavailable() {
    for error in [sqlx::Error::RowNotFound, sqlx::Error::PoolTimedOut] {
        assert!(matches!(
            unavailable(error),
            RepositoryError::Unavailable(_)
        ));
    }
}

#[test]
fn an_absent_optional_value_is_empty_text() {
    assert_eq!(optional(None), "");
    assert_eq!(optional(Some("core")), "core");
    assert_eq!(text(None), "");
    assert_eq!(text(Some("core")), "core");
}

#[test]
fn the_columns_carry_absent_values_as_empty_text_in_statement_order() {
    let full = restore(&row()).unwrap();
    let sparse = restore(&sparse_row()).unwrap();

    let columns = Columns::of(full.event());
    let empty = Columns::of(sparse.event());

    assert_eq!(columns.id.to_string(), ID);
    assert_eq!(columns.occurred_at_micros, MICROS);
    assert_eq!(columns.policy_version, Some(42));
    assert_eq!(
        columns.texts,
        vec![
            format!("user:{USER}"),
            "core".to_owned(),
            "role.create".to_owned(),
            "role".to_owned(),
            "r-1".to_owned(),
            format!("project:{PROJECT}"),
            "name=readers".to_owned(),
            "name=writers".to_owned(),
            "key-1".to_owned(),
            "committed".to_owned(),
            "forbidden".to_owned(),
            "req-9".to_owned(),
            full.event().canonical_form(),
        ]
    );
    assert_eq!(empty.policy_version, None);
    for index in [1, 5, 6, 7, 8, 10, 11] {
        assert_eq!(empty.texts[index], "", "{index}");
    }
}

#[test]
fn an_emitted_record_is_one_info_event_with_target_audit_and_every_value() {
    let (recorder, _guard) = LogRecorder::install();
    let stored = restore(&row()).unwrap();

    emit(&stored);

    let lines = recorder.lines();
    assert_eq!(lines.len(), 1);
    let line = lines.first().unwrap();
    assert_eq!(line.level, tracing::Level::INFO);
    assert_eq!(line.target, "audit");
    assert_eq!(line.message, AUDIT_MESSAGE);
    let expected = [
        ("event_name", "iam.security_audit.recorded".to_owned()),
        ("seq", "3".to_owned()),
        ("id", ID.to_owned()),
        ("occurred_at_micros", MICROS.to_string()),
        ("actor", format!("user:{USER}")),
        ("caller_service", "core".to_owned()),
        ("action", "role.create".to_owned()),
        ("target_type", "role".to_owned()),
        ("target_id", "r-1".to_owned()),
        ("scope", format!("project:{PROJECT}")),
        ("before_summary", "name=readers".to_owned()),
        ("after_summary", "name=writers".to_owned()),
        ("idempotency_key", "key-1".to_owned()),
        ("outcome", "committed".to_owned()),
        ("reason", "forbidden".to_owned()),
        ("policy_version", "42".to_owned()),
        ("request_id", "req-9".to_owned()),
        ("hash", "02".repeat(32)),
    ];
    for (name, value) in expected {
        assert_eq!(line.field(name), Some(value.as_str()), "{name}");
    }
}

#[test]
fn an_emitted_record_writes_absent_values_as_empty_text() {
    let (recorder, _guard) = LogRecorder::install();
    let stored = restore(&sparse_row()).unwrap();

    emit(&stored);

    let line = recorder.lines().pop().unwrap();
    for name in [
        "caller_service",
        "scope",
        "before_summary",
        "after_summary",
        "idempotency_key",
        "reason",
        "policy_version",
        "request_id",
    ] {
        assert_eq!(line.field(name), Some(""), "{name}");
    }
}

#[test]
fn a_page_whose_digests_are_not_one_per_record_is_unavailable() {
    let digests = vec![vec![1_u8], vec![2_u8]];

    assert_eq!(aligned(digests.clone(), 2).unwrap(), digests);
    for records in [1, 3] {
        assert!(matches!(
            aligned(digests.clone(), records),
            Err(RepositoryError::Unavailable(_))
        ));
    }
}
